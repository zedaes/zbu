use hmac::Hmac;
use openssl::symm::{decrypt, Cipher};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use tar;
use zstd::bulk::decompress;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_LENGTH: usize = 32; // 256-bit AES key

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

    let mut file = File::open(backup_file)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    if encrypted_data.len() < 16 + 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Encrypted data too short",
        ));
    }

    let salt = &encrypted_data[..16];
    let nonce = &encrypted_data[16..28];
    let ciphertext = &encrypted_data[28..];

    let key = derive_key(password, salt);

    let decrypted_data = decrypt(Cipher::aes_256_gcm(), &key, Some(nonce), ciphertext)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption error: {:?}", e)))?;

    let decompressed_data = decompress(&decrypted_data, 50_000_000).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Decompression error: {:?}", e),
        )
    })?;

    let mut archive = tar::Archive::new(&decompressed_data[..]);
    fs::create_dir_all(output_dir)?;
    archive.unpack(output_dir)?;

    println!("Backup decrypted and restored to: {}", output_dir.display());

    Ok(())
}
