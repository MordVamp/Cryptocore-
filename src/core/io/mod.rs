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

// IV handling functions
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).expect("Failed to generate random IV");
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