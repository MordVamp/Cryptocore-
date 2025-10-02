use std::fs;
use std::path::{Path, PathBuf};
use crate::error::{CryptoCoreError, Result};
use crate::cli::Operation;

pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| {
        CryptoCoreError::FileError(format!("Failed to read file {}: {}", path.display(), e))
    })
}

pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
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