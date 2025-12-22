
pub mod aes;
pub mod csprng;
pub mod hash;
pub mod mac;
pub mod modes;
pub mod traits;
pub mod aead;
pub mod kdf;  // Add KDF module

use crate::error::Result;
use crate::core::crypto::traits::Cipher;
use modes::BlockMode;

pub enum CipherInstance {
    AesEcb(aes::AesCipher),
    BlockMode(BlockMode),
    AeadMode(Box<dyn aead::Aead>),
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
            ("aes", "gcm") => {
                // GCM is an AEAD mode
                let gcm = modes::gcm::Gcm::new(key)?;
                Ok(Self::AeadMode(Box::new(gcm)))
            }
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                format!("Unsupported algorithm or mode: {} {}", algorithm, mode)
            )),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AesEcb(cipher) => cipher.encrypt(data),
            Self::BlockMode(mode) => mode.encrypt(data),
            Self::AeadMode(_) => {
                // AEAD modes require additional parameters
                Err(crate::error::CryptoCoreError::InvalidArgument(
                    "AEAD encryption requires AAD and nonce parameters".to_string()
                ))
            }
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AesEcb(cipher) => cipher.decrypt(data),
            Self::BlockMode(mode) => mode.decrypt(data),
            Self::AeadMode(_) => {
                // AEAD modes require additional parameters
                Err(crate::error::CryptoCoreError::InvalidArgument(
                    "AEAD decryption requires AAD, nonce, and tag parameters".to_string()
                ))
            }
        }
    }
    
    // AEAD-specific methods
    pub fn encrypt_aead(&self, data: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self {
            Self::AeadMode(aead) => aead.encrypt(data, aad, nonce),
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                "AEAD operations only supported for AEAD modes".to_string()
            )),
        }
    }
    
    pub fn decrypt_aead(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::AeadMode(aead) => aead.decrypt(ciphertext, aad, nonce, tag),
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                "AEAD operations only supported for AEAD modes".to_string()
            )),
        }
    }
}

pub fn create_cipher(algorithm: &str, mode: &str, key: &[u8], iv: Option<&[u8]>) -> Result<CipherInstance> {
    CipherInstance::new(algorithm, mode, key, iv)
}
