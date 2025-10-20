pub mod aes;
pub mod modes;
pub mod traits;
use crate::core::crypto::traits::Cipher;
use crate::error::Result;
use modes::BlockMode;

// Переименовали enum чтобы избежать конфликта имен
pub enum CipherInstance {
    AesEcb(aes::AesCipher),
    BlockMode(BlockMode),
}

impl CipherInstance {
    pub fn new(algorithm: &str, mode: &str, key: &[u8], iv: Option<&[u8]>) -> Result<Self> {
        match (algorithm.to_lowercase().as_str(), mode.to_lowercase().as_str()) {
            ("aes", "ecb") => Ok(Self::AesEcb(aes::AesCipher::new(key)?)),
            ("aes", mode_name) if ["cbc", "cfb", "ofb", "ctr"].contains(&mode_name) => {
                let iv = iv.ok_or_else(|| {
                    crate::error::CryptoCoreError::InvalidArgument(
                        "IV is required for this mode".to_string()
                    )
                })?;
                Ok(Self::BlockMode(BlockMode::new(mode_name, key, iv)?))
            }
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                format!("Unsupported algorithm or mode: {} {}", algorithm, mode)
            )),
        }
    }

    // Реализуем методы encrypt и decrypt для enum CipherInstance
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AesEcb(cipher) => cipher.encrypt(data),
            Self::BlockMode(mode) => mode.encrypt(data),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AesEcb(cipher) => cipher.decrypt(data),
            Self::BlockMode(mode) => mode.decrypt(data),
        }
    }
}

pub fn create_cipher(algorithm: &str, mode: &str, key: &[u8], iv: Option<&[u8]>) -> Result<CipherInstance> {
    CipherInstance::new(algorithm, mode, key, iv)
}