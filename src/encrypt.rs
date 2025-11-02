use chrono::Local;
use hmac::Hmac;
use openssl::symm::{Cipher, encrypt_aead};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use tar;
use zstd::stream::write::Encoder;
use indicatif::{ProgressBar, ProgressStyle};

const PBKDF2_ITERATIONS: u32 = 10_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const COMPRESSION_LEVEL: i32 = 1;
const CHUNK_SIZE: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn create_tarball_to_file(source: &Path, output: &Path) -> io::Result<()> {
    let file = File::create(output)?;
    let mut ar = tar::Builder::new(file);

    if source.is_dir() {
        ar.append_dir_all(
            source.file_name().unwrap_or_default(),
            source,
        )?;
    } else {
        ar.append_path_with_name(source, source.file_name().unwrap_or_default())?;
    }

    ar.finish()?;
    Ok(())
}

fn compress_file(input: &Path, output: &Path) -> io::Result<()> {
    let mut input_file = File::open(input)?;
    let output_file = File::create(output)?;
    let mut encoder = Encoder::new(output_file, COMPRESSION_LEVEL)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let n = input_file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buffer[..n])?;
    }

    encoder.finish()?;
    Ok(())
}

fn encrypt_file(input: &Path, output: &mut impl Write, key: &[u8], nonce: &[u8]) -> io::Result<()> {
    let mut input_file = File::open(input)?;
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    let cipher = Cipher::aes_256_gcm();
    let mut tag = vec![0u8; TAG_LENGTH];
    
    let ciphertext = encrypt_aead(cipher, key, Some(nonce), &[], &data, &mut tag)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    output.write_all(&ciphertext)?;
    output.write_all(&tag)?;

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
        fs::create_dir_all(backup_dir)?;
    }

    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let source_name = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "backup".to_string());
    
    let backup_file_name = format!("{}_{}.backup", source_name, timestamp);
    let backup_path = backup_dir.join(backup_file_name);

    let pb = ProgressBar::new(3);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━━╾"),
    );

    pb.set_message("Creating archive...");
    let temp_tar = std::env::temp_dir().join(format!("zbu_temp_{}.tar", timestamp));
    create_tarball_to_file(source, &temp_tar)?;
    let tar_size = fs::metadata(&temp_tar)?.len();
    pb.inc(1);

    pb.set_message("Compressing...");
    let temp_compressed = std::env::temp_dir().join(format!("zbu_temp_{}.zst", timestamp));
    compress_file(&temp_tar, &temp_compressed)?;
    let compressed_size = fs::metadata(&temp_compressed)?.len();
    fs::remove_file(&temp_tar)?;
    pb.inc(1);

    pb.set_message("Encrypting...");
    let mut salt = [0u8; SALT_LENGTH];
    rand::rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt);

    let mut nonce = [0u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);

    let output_file = fs::File::create(&backup_path)?;
    let mut writer = std::io::BufWriter::new(output_file);
    
    writer.write_all(&salt)?;
    writer.write_all(&nonce)?;
    
    encrypt_file(&temp_compressed, &mut writer, &key, &nonce)?;
    fs::remove_file(&temp_compressed)?;
    pb.inc(1);

    pb.finish_with_message("Complete!");

    let ratio = (compressed_size as f64 / tar_size as f64) * 100.0;

    println!("\n✓ Backup created: {}", backup_path.display());
    println!("  {} → {} ({:.1}%)", 
        format_bytes(tar_size), 
        format_bytes(compressed_size), 
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


