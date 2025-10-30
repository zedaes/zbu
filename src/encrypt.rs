use chrono::Local;
use hmac::Hmac;
use openssl::symm::{encrypt_aead, Cipher};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tar;
use zstd::bulk::compress;

const PBKDF2_ITERATIONS: u32 = 600_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const COMPRESSION_LEVEL: i32 = 19;

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
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

    println!("Creating archive...");
    let tar_data = create_tarball(source)?;
    
    println!("Compressing data...");
    let original_size = tar_data.len();
    let compressed_data = compress(&tar_data, COMPRESSION_LEVEL)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Compression error: {:?}", e)))?;

    let compressed_size = compressed_data.len();
    if compressed_size > 0 && original_size > 0 {
        let ratio = (compressed_size as f64 / original_size as f64) * 100.0;
        println!("Compressed to {:.1}% of original size", ratio);
    }

    println!("Encrypting data...");
    let encrypted_data = encrypt_data_with_password(&compressed_data, password)?;

    let source_name = source
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "backup".to_string());
    
    let backup_file_name = format!("{}_{}.backup", source_name, timestamp);
    let backup_path = backup_dir.join(backup_file_name);

    println!("Writing backup file...");
    let mut file = fs::File::create(&backup_path)?;
    file.write_all(&encrypted_data)?;

    println!("Backup created successfully: {}", backup_path.display());
    println!("   Original size: {} bytes", tar_data.len());
    println!("   Compressed size: {} bytes", compressed_data.len());
    println!("   Encrypted size: {} bytes", encrypted_data.len());

    Ok(())
}

fn create_tarball(source: &Path) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut tar_builder = tar::Builder::new(&mut buf);
        if source.is_file() {
            tar_builder.append_path(source)?;
        } else if source.is_dir() {
            tar_builder.append_dir_all(".", source)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Source is neither file nor directory",
            ));
        }
        tar_builder.finish()?;
    }
    Ok(buf)
}

fn encrypt_data_with_password(data: &[u8], password: &str) -> io::Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt);

    let cipher = Cipher::aes_256_gcm();
    let mut nonce = [0u8; NONCE_LENGTH];
    rand::thread_rng().fill_bytes(&mut nonce);

    let mut tag = vec![0u8; TAG_LENGTH];
    let ciphertext = encrypt_aead(cipher, &key, Some(&nonce), &[], data, &mut tag)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e)))?;

    let mut encrypted_blob = Vec::with_capacity(salt.len() + nonce.len() + tag.len() + ciphertext.len());
    encrypted_blob.extend_from_slice(&salt);
    encrypted_blob.extend_from_slice(&nonce);
    encrypted_blob.extend_from_slice(&tag);
    encrypted_blob.extend_from_slice(&ciphertext);

    Ok(encrypted_blob)
}
