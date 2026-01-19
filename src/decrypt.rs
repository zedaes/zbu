use hmac::Hmac;
use openssl::symm::{decrypt_aead, Cipher};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write, BufReader, BufWriter};
use std::path::Path;
use zstd::stream::read::Decoder;
use indicatif::{ProgressBar, ProgressStyle};

const PBKDF2_ITERATIONS: u32 = 10_000;
const KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const IO_BUFFER_SIZE: usize = 1024 * 1024;
const FILE_MAGIC: &[u8; 4] = b"ZBU\x01";

type HmacSha256 = Hmac<Sha256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    let _ = pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

fn decrypt_and_decompress_legacy(
    input_file: &mut BufReader<File>,
    output_dir: &Path,
    key: &[u8],
    nonce: &[u8],
    pb: &ProgressBar,
) -> io::Result<()> {
    pb.set_message("Decrypting (legacy format)...");

    let mut ciphertext = Vec::new();
    input_file.read_to_end(&mut ciphertext)?;

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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;

    pb.set_message("Decompressing...");
    let mut decoder = Decoder::new(plaintext.as_slice())?;

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    extract_files(&mut decoder, output_dir)?;

    Ok(())
}

fn decrypt_and_decompress_streaming(
    input_file: &mut BufReader<File>,
    output_dir: &Path,
    key: &[u8],
    total_chunks: u32,
    pb: &ProgressBar,
) -> io::Result<()> {
    pb.set_message("Decrypting and decompressing...");
    pb.set_length(total_chunks as u64);
    pb.set_position(0);

    let cipher = Cipher::aes_256_gcm();

    let temp_dir = std::env::temp_dir();
    let temp_decompressed = temp_dir.join(format!("zbu_decrypt_{}.tmp", std::process::id()));

    let temp_file = File::create(&temp_decompressed)?;
    let mut temp_writer = BufWriter::with_capacity(IO_BUFFER_SIZE, temp_file);

    for _ in 0..total_chunks {
        let mut chunk_size_bytes = [0u8; 4];
        input_file.read_exact(&mut chunk_size_bytes)?;
        let chunk_size = u32::from_le_bytes(chunk_size_bytes) as usize;

        let mut nonce = [0u8; NONCE_LENGTH];
        input_file.read_exact(&mut nonce)?;

        let mut ciphertext = vec![0u8; chunk_size];
        input_file.read_exact(&mut ciphertext)?;

        let mut tag = [0u8; TAG_LENGTH];
        input_file.read_exact(&mut tag)?;

        let plaintext = decrypt_aead(cipher, key, Some(&nonce), &[], &ciphertext, &tag)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))?;

        temp_writer.write_all(&plaintext)?;
        pb.inc(1);
    }

    temp_writer.flush()?;
    drop(temp_writer);

    pb.set_message("Extracting files...");

    let temp_file = File::open(&temp_decompressed)?;
    let temp_reader = BufReader::with_capacity(IO_BUFFER_SIZE, temp_file);
    let mut decoder = Decoder::new(temp_reader)?;

    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    extract_files(&mut decoder, output_dir)?;

    fs::remove_file(&temp_decompressed)?;

    Ok(())
}

fn extract_files<R: Read>(decoder: &mut R, output_dir: &Path) -> io::Result<()> {
    let mut buffer = vec![0u8; IO_BUFFER_SIZE];

    loop {
        let mut header = [0u8; 5];
        match decoder.read_exact(&mut header) {
            Ok(_) => {},
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }

        if &header != b"FILE:" {
            break;
        }

        let mut path_len_str = String::new();
        loop {
            let mut byte = [0u8; 1];
            decoder.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                break;
            }
            path_len_str.push(byte[0] as char);
        }

        let path_len: usize = path_len_str.parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid path length"))?;

        let mut path_bytes = vec![0u8; path_len];
        decoder.read_exact(&mut path_bytes)?;
        let relative_path = String::from_utf8_lossy(&path_bytes);

        let mut size_bytes = [0u8; 8];
        decoder.read_exact(&mut size_bytes)?;
        let file_size = u64::from_le_bytes(size_bytes);

        let output_path = output_dir.join(relative_path.as_ref());
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let output_file = File::create(&output_path)?;
        let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);
        let mut remaining = file_size;

        while remaining > 0 {
            let to_read = remaining.min(IO_BUFFER_SIZE as u64) as usize;
            let n = decoder.read(&mut buffer[..to_read])?;
            if n == 0 {
                break;
            }
            writer.write_all(&buffer[..n])?;
            remaining -= n as u64;
        }

        writer.flush()?;
    }

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

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("━━╾"),
    );

    pb.set_message("Reading backup file...");
    let file = File::open(backup_file)?;
    let file_size = file.metadata()?.len();

    let min_size = (SALT_LENGTH + 4) as u64; 
    if file_size < min_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "File is too small to be a valid backup (minimum {} bytes required)",
                min_size
            ),
        ));
    }

    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);

    let mut magic_or_salt_start = [0u8; 4];
    reader.read_exact(&mut magic_or_salt_start)?;

    if &magic_or_salt_start == FILE_MAGIC {
        pb.set_message("Detected new format");

        let mut salt = [0u8; SALT_LENGTH];
        reader.read_exact(&mut salt)?;

        let mut chunks_count_bytes = [0u8; 4];
        reader.read_exact(&mut chunks_count_bytes)?;
        let total_chunks = u32::from_le_bytes(chunks_count_bytes);

        if total_chunks == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid backup file: no chunks found",
            ));
        }

        let key = derive_key(password, &salt);
        decrypt_and_decompress_streaming(&mut reader, output_dir, &key, total_chunks, &pb)?;
    } else {
        pb.set_message("Detected legacy format");

        let mut salt = [0u8; SALT_LENGTH];
        salt[0..4].copy_from_slice(&magic_or_salt_start);
        reader.read_exact(&mut salt[4..])?;

        let mut nonce = [0u8; NONCE_LENGTH];
        reader.read_exact(&mut nonce)?;

        let key = derive_key(password, &salt);
        decrypt_and_decompress_legacy(&mut reader, output_dir, &key, &nonce, &pb)?;
    }

    pb.finish_with_message("Complete!");

    println!("\n✓ Restored to: {}", output_dir.display());

    Ok(())
}
