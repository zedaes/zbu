use chrono::Local;
use hmac::Hmac;
use openssl::symm::{encrypt, Cipher};
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tar;
use zstd::bulk::compress;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32; // 256-bit AES key

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
            "Source path does not exist",
        ));
    }
    if !backup_dir.exists() {
        fs::create_dir_all(backup_dir)?;
    }

    let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();

    let tar_data = create_tarball(source)?;
    let compressed_data = compress(&tar_data, 22)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Compression error: {:?}", e)))?;

    let encrypted_data = encrypt_data_with_password(&compressed_data, password)?;

    let backup_file_name = format!(
        "{}_{}.backup",
        source.file_name().unwrap().to_string_lossy(),
        timestamp
    );

    let backup_path = backup_dir.join(backup_file_name);
    let mut file = fs::File::create(&backup_path)?;
    file.write_all(&encrypted_data)?;

    println!(
        "Encrypted & compressed backup created: {}",
        backup_path.display()
    );

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
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt);

    let cipher = Cipher::aes_256_gcm();
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = encrypt(cipher, &key, Some(&nonce), data)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption error: {:?}", e)))?;

    // Store salt + nonce + ciphertext
    let mut encrypted_blob = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    encrypted_blob.extend_from_slice(&salt);
    encrypted_blob.extend_from_slice(&nonce);
    encrypted_blob.extend_from_slice(&ciphertext);

    Ok(encrypted_blob)
}
