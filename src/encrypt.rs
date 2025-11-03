use chrono::Local;
use hmac::Hmac;
use openssl::symm::{Cipher, encrypt_aead};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use zstd::stream::write::Encoder;
use indicatif::{ProgressBar, ProgressStyle};

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
    let output_file = File::create(output)?;
    let mut encoder = Encoder::new(output_file, COMPRESSION_LEVEL)?;
    
    let total_size = calculate_dir_size(source);
    pb.set_length(total_size);
    pb.set_position(0);
    
    compress_dir_contents(&mut encoder, source, source, pb)?;
    
    encoder.finish()?;
    Ok(fs::metadata(output)?.len())
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

fn compress_dir_contents(encoder: &mut Encoder<File>, base: &Path, current: &Path, pb: &ProgressBar) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let path = entry.path();
        
        if path.is_file() {
            if let Ok(mut file) = File::open(&path) {
                let relative = path.strip_prefix(base)
                    .unwrap_or(&path)
                    .to_string_lossy();
                
                encoder.write_all(format!("FILE:{}\n", relative.len()).as_bytes())?;
                encoder.write_all(relative.as_bytes())?;
                
                if let Ok(metadata) = file.metadata() {
                    let size = metadata.len();
                    encoder.write_all(&size.to_le_bytes())?;
                    
                    let mut buffer = vec![0u8; CHUNK_SIZE];
                    let mut remaining = size;
                    while remaining > 0 {
                        let to_read = remaining.min(CHUNK_SIZE as u64) as usize;
                        if let Ok(n) = file.read(&mut buffer[..to_read]) {
                            if n == 0 {
                                break;
                            }
                            encoder.write_all(&buffer[..n])?;
                            pb.inc(n as u64);
                            remaining -= n as u64;
                        } else {
                            break;
                        }
                    }
                }
            }
        } else if path.is_dir() {
            compress_dir_contents(encoder, base, &path, pb)?;
        }
    }
    Ok(())
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
    
    let backup_file_name = format!("{}_{}.backup", source_name, timestamp);
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


