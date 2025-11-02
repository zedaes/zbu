use hmac::Hmac;
use openssl::symm::{decrypt_aead, Cipher};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use tar;
use zstd::stream::read::Decoder;
use indicatif::{ProgressBar, ProgressStyle};

const PBKDF2_ITERATIONS: u32 = 10_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const CHUNK_SIZE: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn decompress_file(input: &Path, output: &Path) -> io::Result<()> {
    let input_file = File::open(input)?;
    let mut decoder = Decoder::new(input_file)?;
    
    let mut output_file = File::create(output)?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    
    loop {
        let n = decoder.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        output_file.write_all(&buffer[..n])?;
    }
    
    Ok(())
}

fn decrypt_file(input: &mut impl Read, output: &Path, key: &[u8], nonce: &[u8]) -> io::Result<()> {
    let mut ciphertext = Vec::new();
    input.read_to_end(&mut ciphertext)?;

    if ciphertext.len() < TAG_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data too short",
        ));
    }

    let tag_start = ciphertext.len() - TAG_LENGTH;
    let tag = &ciphertext[tag_start..];
    let encrypted = &ciphertext[..tag_start];

    let cipher = Cipher::aes_256_gcm();
    let plaintext = decrypt_aead(cipher, key, Some(nonce), &[], encrypted, tag)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let mut output_file = File::create(output)?;
    output_file.write_all(&plaintext)?;

    Ok(())
}

pub fn run_decrypt(
    backup_file_path: &str,
    output_dir_path: &str,
    password: &str,
) -> io::Result<()> {
    let backup_file = Path::new(backup_file_path);
    let output_dir = Path::new(output_dir_path);

    if !backup_file.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Backup file does not exist: {}", backup_file_path),
        ));
    }

    if !backup_file.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Backup path must be a file",
        ));
    }

    let pb = ProgressBar::new(3);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━━╾"),
    );

    pb.set_message("Reading file...");
    let mut file = File::open(backup_file)?;
    
    let file_size = file.metadata()?.len();
    let min_size = (SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH) as u64;
    if file_size < min_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "File is too small to be a valid backup (minimum {} bytes required)",
                min_size
            ),
        ));
    }

    let mut salt = [0u8; SALT_LENGTH];
    let mut nonce = [0u8; NONCE_LENGTH];
    file.read_exact(&mut salt)?;
    file.read_exact(&mut nonce)?;

    let key = derive_key(password, &salt);
    pb.inc(1);

    pb.set_message("Decrypting...");
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let temp_decrypted = std::env::temp_dir().join(format!("zbu_decrypt_{}.zst", timestamp));
    
    decrypt_file(&mut file, &temp_decrypted, &key, &nonce)?;
    pb.inc(1);

    pb.set_message("Extracting...");
    let temp_decompressed = std::env::temp_dir().join(format!("zbu_decompress_{}.tar", timestamp));
    decompress_file(&temp_decrypted, &temp_decompressed)?;
    
    fs::remove_file(&temp_decrypted)?;

    let tar_file = File::open(&temp_decompressed)?;
    let mut archive = tar::Archive::new(tar_file);

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    archive.unpack(output_dir)?;
    
    fs::remove_file(&temp_decompressed)?;
    pb.inc(1);

    pb.finish_with_message("Complete!");

    println!("\n✓ Restored to: {}", output_dir.display());

    Ok(())
}
