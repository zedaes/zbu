use chrono::Local;
use hmac::Hmac;
use openssl::symm::{Cipher, encrypt_aead};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zstd::stream::write::Encoder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

const PBKDF2_ITERATIONS: u32 = 10_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const COMPRESSION_LEVEL: i32 = 1;
const CHUNK_SIZE: usize = 8 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn compress_and_encrypt_direct(source: &Path, output: &Path, password: &str, pb: &ProgressBar) -> io::Result<()> {
    let mut salt = [0u8; SALT_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);

    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);

    let output_file = File::create(output)?;
    let mut writer = std::io::BufWriter::new(output_file);
    
    writer.write_all(&salt)?;
    writer.write_all(&nonce)?;
    
    let temp_compressed = output.with_extension("tmp.zst");
    
    pb.set_message("Compressing...");
    let compressed_size = if source.is_file() {
        compress_file_direct(source, &temp_compressed, pb)?
    } else {
        compress_dir_direct(source, &temp_compressed, pb)?
    };
    
    pb.set_message("Encrypting...");
    pb.set_length(compressed_size);
    pb.set_position(0);
    
    let mut compressed_file = File::open(&temp_compressed)?;
    let mut data = Vec::new();
    compressed_file.read_to_end(&mut data)?;
    pb.set_position(compressed_size);
    
    let cipher = Cipher::aes_256_gcm();
    let mut tag = vec![0u8; TAG_LENGTH];
    
    let ciphertext = encrypt_aead(cipher, &key, Some(&nonce), &[], &data, &mut tag)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    writer.write_all(&ciphertext)?;
    writer.write_all(&tag)?;
    
    fs::remove_file(&temp_compressed)?;
    
    Ok(())
}

fn compress_file_direct(source: &Path, output: &Path, pb: &ProgressBar) -> io::Result<u64> {
    let mut input_file = File::open(source)?;
    let input_size = input_file.metadata()?.len();
    let output_file = File::create(output)?;
    let mut encoder = Encoder::new(output_file, COMPRESSION_LEVEL)?;

    pb.set_length(input_size);
    pb.set_position(0);

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let n = input_file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buffer[..n])?;
        pb.inc(n as u64);
    }

    encoder.finish()?;
    Ok(fs::metadata(output)?.len())
}

fn compress_dir_direct(source: &Path, output: &Path, pb: &ProgressBar) -> io::Result<u64> {
    let files = collect_files(source, source)?;
    let total_size: u64 = files.iter()
        .filter_map(|(path, _)| fs::metadata(path).ok())
        .map(|m| m.len())
        .sum();
    
    pb.set_length(total_size);
    pb.set_position(0);
    
    let output_file = File::create(output)?;
    let mut encoder = Encoder::new(output_file, COMPRESSION_LEVEL)?;
    
    let processed = Arc::new(AtomicU64::new(0));
    
    const BATCH_SIZE: usize = 100;
    
    for batch in files.chunks(BATCH_SIZE) {
        let chunks: Vec<Vec<u8>> = batch.par_iter()
            .filter_map(|(path, rel_path)| {
                compress_file_to_bytes(path, rel_path, &processed, pb).ok()
            })
            .collect();
        
        for chunk in chunks {
            encoder.write_all(&chunk)?;
        }
    }
    
    encoder.finish()?;
    Ok(fs::metadata(output)?.len())
}

fn collect_files(base: &Path, current: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let mut files = Vec::new();
    
    if current.is_file() {
        let rel = current.strip_prefix(base)
            .unwrap_or(current)
            .to_string_lossy()
            .to_string();
        files.push((current.to_path_buf(), rel));
        return Ok(files);
    }
    
    for entry in fs::read_dir(current)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let path = entry.path();
        
        if path.is_file() {
            let rel = path.strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            files.push((path, rel));
        } else if path.is_dir() {
            files.extend(collect_files(base, &path)?);
        }
    }
    
    Ok(files)
}

fn compress_file_to_bytes(path: &Path, rel_path: &str, processed: &Arc<AtomicU64>, pb: &ProgressBar) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    
    buffer.extend_from_slice(format!("FILE:{}\n", rel_path.len()).as_bytes());
    buffer.extend_from_slice(rel_path.as_bytes());
    
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();
    
    buffer.extend_from_slice(&size.to_le_bytes());
    
    let mut file_data = Vec::with_capacity(size.min(CHUNK_SIZE as u64) as usize);
    let mut chunk = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        file_data.extend_from_slice(&chunk[..n]);
    }
    buffer.extend_from_slice(&file_data);
    
    processed.fetch_add(size, Ordering::Relaxed);
    pb.set_position(processed.load(Ordering::Relaxed));
    
    Ok(buffer)
}

fn calculate_dir_size(dir: &Path) -> u64 {
    let mut size = 0u64;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = fs::metadata(&path) {
                    size += metadata.len();
                }
            } else if path.is_dir() {
                size += calculate_dir_size(&path);
            }
        }
    }
    size
}

pub fn run_encrypt(source_path: &str, backup_dir: &str, password: &str) -> io::Result<()> {
    let source = Path::new(source_path);
    let backup_dir = Path::new(backup_dir);

    if !source.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Source path does not exist: {}", source_path),
        ));
    }
    
    if password.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Password must be at least 8 characters long",
        ));
    }

    if !backup_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Backup directory does not exist: {}", backup_dir.display()),
        ));
    }
    
    let backup_metadata = fs::metadata(backup_dir)?;
    if !backup_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Backup path must be a directory",
        ));
    }

    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let source_name = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "backup".to_string());
    
    let backup_file_name = format!("{}_{}.zbu", source_name, timestamp);
    let backup_path = backup_dir.join(backup_file_name);

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
            .unwrap()
            .progress_chars("━━╾"),
    );

    let original_size = if source.is_file() {
        fs::metadata(source)?.len()
    } else {
        calculate_dir_size(source)
    };

    compress_and_encrypt_direct(source, &backup_path, password, &pb)?;
    
    let final_size = fs::metadata(&backup_path)?.len();
    let ratio = (final_size as f64 / original_size as f64) * 100.0;

    pb.finish_with_message("Complete!");

    println!("\n✓ Backup created: {}", backup_path.display());
    println!("  {} → {} ({:.1}%)", 
        format_bytes(original_size), 
        format_bytes(final_size), 
        ratio
    );

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}


