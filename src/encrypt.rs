use chrono::Local;
use hmac::Hmac;
use openssl::symm::{Cipher, encrypt_aead};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use zstd::stream::write::Encoder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

const PBKDF2_ITERATIONS: u32 = 10_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const COMPRESSION_LEVEL: i32 = 3;
const CHUNK_SIZE: usize = 64 * 1024 * 1024;
const IO_BUFFER_SIZE: usize = 1024 * 1024;
const FILE_MAGIC: &[u8; 4] = b"ZBU\x01";

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn compress_and_encrypt_streaming(source: &Path, output: &Path, password: &str, pb: &ProgressBar) -> io::Result<()> {
    let mut salt = [0u8; SALT_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);

    let output_file = File::create(output)?;
    let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);

    writer.write_all(FILE_MAGIC)?;
    writer.write_all(&salt)?;

    let chunks_count_pos = (FILE_MAGIC.len() + SALT_LENGTH) as u64;
    writer.write_all(&0u32.to_le_bytes())?;

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

    let mut compressed_file = BufReader::with_capacity(IO_BUFFER_SIZE, File::open(&temp_compressed)?);
    let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_counter = 0u32;
    let cipher = Cipher::aes_256_gcm();

    loop {
        let mut total_read = 0;
        while total_read < CHUNK_SIZE {
            match compressed_file.read(&mut chunk_buffer[total_read..]) {
                Ok(0) => break, // EOF
                Ok(n) => total_read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        if total_read == 0 {
            break;
        }

        let chunk_data = &chunk_buffer[..total_read];

        let mut nonce = [0u8; NONCE_LENGTH];
        rand::rng().fill_bytes(&mut nonce);

        let mut tag = vec![0u8; TAG_LENGTH];
        let ciphertext = encrypt_aead(cipher, &key, Some(&nonce), &[], chunk_data, &mut tag)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&nonce)?;
        writer.write_all(&ciphertext)?;
        writer.write_all(&tag)?;

        chunk_counter += 1;
        pb.inc(total_read as u64);
    }

    writer.flush()?;
    drop(writer);

    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(output)?;
    file.seek(io::SeekFrom::Start(chunks_count_pos))?;
    file.write_all(&chunk_counter.to_le_bytes())?;

    fs::remove_file(&temp_compressed)?;

    Ok(())
}

fn compress_file_direct(source: &Path, output: &Path, pb: &ProgressBar) -> io::Result<u64> {
    let input_file = File::open(source)?;
    let input_size = input_file.metadata()?.len();

    pb.set_length(input_size);
    pb.set_position(0);

    let output_file = File::create(output)?;
    let buf_writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);
    let mut encoder = Encoder::new(buf_writer, COMPRESSION_LEVEL)?;

    let file_name = source.file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file name"))?
        .to_string_lossy();

    encoder.write_all(format!("FILE:{}\n", file_name.len()).as_bytes())?;
    encoder.write_all(file_name.as_bytes())?;
    encoder.write_all(&input_size.to_le_bytes())?;

    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, input_file);
    let mut buffer = vec![0u8; IO_BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
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
    let total_size: u64 = files.par_iter()
        .filter_map(|(path, _)| fs::metadata(path).ok())
        .map(|m| m.len())
        .sum();

    pb.set_length(total_size);
    pb.set_position(0);

    let output_file = File::create(output)?;
    let buf_writer = BufWriter::with_capacity(IO_BUFFER_SIZE * 4, output_file);
    let mut encoder = Encoder::new(buf_writer, COMPRESSION_LEVEL)?;

    // Process files sequentially to avoid massive memory consumption
    for (path, rel_path) in files.iter() {
        if let Err(e) = write_file_to_encoder(path, rel_path, &mut encoder, pb) {
            eprintln!("Warning: Failed to process {}: {}", path.display(), e);
            continue;
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

    let entries: Vec<_> = fs::read_dir(current)?
        .filter_map(|entry| entry.ok())
        .collect();

    let (dirs, file_entries): (Vec<_>, Vec<_>) = entries.into_iter()
        .partition(|e| e.path().is_dir());

    for entry in file_entries {
        let path = entry.path();
        let rel = path.strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        files.push((path, rel));
    }

    for dir_entry in dirs {
        files.extend(collect_files(base, &dir_entry.path())?);
    }

    Ok(files)
}

fn write_file_to_encoder<W: Write>(
    path: &Path,
    rel_path: &str,
    encoder: &mut W,
    pb: &ProgressBar,
) -> io::Result<()> {
    // Write file header
    encoder.write_all(format!("FILE:{}\n", rel_path.len()).as_bytes())?;
    encoder.write_all(rel_path.as_bytes())?;

    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    encoder.write_all(&size.to_le_bytes())?;

    // Stream file contents directly to encoder without buffering entire file in memory
    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
    let mut chunk = vec![0u8; IO_BUFFER_SIZE];

    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&chunk[..n])?;
        pb.inc(n as u64);
    }

    Ok(())
}

fn calculate_dir_size(dir: &Path) -> u64 {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
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
        pb.set_message("Calculating size...");
        calculate_dir_size(source)
    };

    compress_and_encrypt_streaming(source, &backup_path, password, &pb)?;

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

use std::io::Seek;
