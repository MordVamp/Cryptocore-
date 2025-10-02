use aes::Aes128;
use cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use cipher::generic_array::{GenericArray, typenum::U16};
use crate::error::{CryptoCoreError, Result};

pub struct AesCipher {
    cipher: Aes128,
}

impl AesCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(CryptoCoreError::InvalidKey(
                "AES-128 requires exactly 16 bytes key".to_string(),
            ));
        }

        let key_array = GenericArray::from_slice(key);
        let cipher = Aes128::new(key_array);
        Ok(AesCipher { cipher })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let block_size = 16;
        let padded_data = self.pad_data(data, block_size)?;
        let mut result = Vec::with_capacity(padded_data.len());
        
        for chunk in padded_data.chunks(block_size) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        
        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            return Err(CryptoCoreError::Crypto(
                "Ciphertext length must be a multiple of 16 bytes".to_string(),
            ));
        }

        let mut result = Vec::with_capacity(data.len());
        
        for chunk in data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            self.cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        
        self.unpad_data(&result)
    }

    fn pad_data(&self, data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        let mut padded = data.to_vec();
        let pad_len = block_size - (data.len() % block_size);
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        Ok(padded)
    }

    fn unpad_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        let pad_byte = data[data.len() - 1];
        let pad_len = pad_byte as usize;
        
        if pad_len == 0 || pad_len > 16 || data.len() < pad_len {
            return Err(CryptoCoreError::PaddingError("Invalid padding".to_string()));
        }
        
        // Verify padding bytes
        for i in (data.len() - pad_len)..data.len() {
            if data[i] != pad_byte {
                return Err(CryptoCoreError::PaddingError("Invalid padding bytes".to_string()));
            }
        }
        
        Ok(data[..data.len() - pad_len].to_vec())
    }
}

pub fn create_cipher(algorithm: &str, key: &[u8]) -> Result<AesCipher> {
    match algorithm.to_lowercase().as_str() {
        "aes" => AesCipher::new(key),
        _ => Err(CryptoCoreError::InvalidArgument(
            format!("Unsupported algorithm: {}", algorithm),
        )),
    }
}