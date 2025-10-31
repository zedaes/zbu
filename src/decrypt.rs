use hmac::Hmac;
use openssl::symm::{decrypt_aead, Cipher};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use tar;
use zstd::bulk::decompress;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const MAX_DECOMPRESSED_SIZE: usize = 50_000_000;

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
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

    println!("Reading backup file...");
    let mut file = File::open(backup_file)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    let min_size = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH;
    if encrypted_data.len() < min_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "File is too small to be a valid backup (minimum {} bytes required)",
                min_size
            ),
        ));
    }

    let salt = &encrypted_data[..SALT_LENGTH];
    let nonce = &encrypted_data[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH];
    let tag = &encrypted_data[SALT_LENGTH + NONCE_LENGTH..SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH];
    let ciphertext = &encrypted_data[SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH..];

    let key = derive_key(password, salt);

    println!("Decrypting data...");
    let decrypted_data = decrypt_aead(Cipher::aes_256_gcm(), &key, Some(nonce), &[], ciphertext, tag).map_err(
        |e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Decryption failed - incorrect password or corrupted file: {:?}", e),
            )
        },
    )?;

    println!("Decompressing data...");
    let decompressed_data = decompress(&decrypted_data, MAX_DECOMPRESSED_SIZE).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Decompression error: {:?}", e),
        )
    })?;

    println!("Extracting files...");
    let mut archive = tar::Archive::new(&decompressed_data[..]);
    fs::create_dir_all(output_dir)?;
    archive.unpack(output_dir)?;

    println!("Backup restored successfully: {}", output_dir.display());
    println!("   Encrypted size: {} bytes", encrypted_data.len());
    println!("   Compressed size: {} bytes", decrypted_data.len());
    println!("   Extracted size: {} bytes", decompressed_data.len());

    Ok(())
}
