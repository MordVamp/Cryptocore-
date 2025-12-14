use std::fs;
use std::path::{Path, PathBuf};
use crate::error::{CryptoCoreError, Result};
use crate::Operation;

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        CryptoCoreError::FileError(format!("Failed to read file {}: {}", path.display(), e))
    })
}

pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            CryptoCoreError::FileError(format!("Failed to create directories: {}", e))
        })?;
    }
    
    fs::write(path, data).map_err(|e| {
        CryptoCoreError::FileError(format!("Failed to write file {}: {}", path.display(), e))
    })
}

pub fn derive_output_path(input_path: &Path, operation: &Operation) -> PathBuf {
    match operation {
        Operation::Encrypt => input_path.with_extension("enc"),
        Operation::Decrypt => {
            let stem = input_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("decrypted");
            input_path.with_file_name(format!("{}.dec", stem))
        }
    }
}

// GCM-specific IV (nonce) handling
pub fn generate_gcm_nonce() -> [u8; 12] {
    let nonce_bytes = crate::core::crypto::csprng::Csprng::generate_random_bytes(12)
        .expect("Failed to generate nonce");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes[..12]);
    nonce
}

// Read file with GCM format: nonce (12) || ciphertext || tag (16)
pub fn read_file_with_gcm_format(path: &Path) -> Result<(Vec<u8>, [u8; 12], [u8; 16])> {
    let data = read_file(path)?;
    
    if data.len() < 12 + 16 {
        return Err(CryptoCoreError::FileError(
            "File is too short for GCM format (needs at least 28 bytes)".to_string()
        ));
    }
    
    // Extract nonce (first 12 bytes)
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[..12]);
    
    // Extract tag (last 16 bytes)
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&data[data.len() - 16..]);
    
    // Ciphertext is everything in between
    let ciphertext = data[12..data.len() - 16].to_vec();
    
    Ok((ciphertext, nonce, tag))
}

// Write file with GCM format: nonce (12) || ciphertext || tag (16)
pub fn write_file_with_gcm_format(path: &Path, nonce: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<()> {
    if nonce.len() != 12 {
        return Err(CryptoCoreError::InvalidArgument(
            "GCM nonce must be 12 bytes".to_string()
        ));
    }
    
    if tag.len() != 16 {
        return Err(CryptoCoreError::InvalidArgument(
            "GCM tag must be 16 bytes".to_string()
        ));
    }
    
    let mut combined = Vec::with_capacity(nonce.len() + ciphertext.len() + tag.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    
    write_file(path, &combined)
}

// Existing IV handling functions (for non-GCM modes)
pub fn generate_iv() -> [u8; 16] {
    let iv_bytes = crate::core::crypto::csprng::Csprng::generate_random_bytes(16)
        .expect("Failed to generate IV");
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_bytes);
    iv
}

pub fn read_file_with_iv(path: &Path) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let data = read_file(path)?;
    
    if data.len() < 16 {
        return Err(CryptoCoreError::FileError(
            "File is too short to contain IV".to_string()
        ));
    }
    
    let iv = Some(data[..16].to_vec());
    let content = data[16..].to_vec();
    
    Ok((content, iv))
}

pub fn write_file_with_iv(path: &Path, iv: &[u8], data: &[u8]) -> Result<()> {
    let mut combined = Vec::with_capacity(iv.len() + data.len());
    combined.extend_from_slice(iv);
    combined.extend_from_slice(data);
    write_file(path, &combined)
}