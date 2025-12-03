use crate::core::crypto::aes::AesCipher;
use crate::error::{CryptoCoreError, Result};

const BLOCK_SIZE: usize = 16;

pub struct Cmac {
    cipher: AesCipher,
    k1: [u8; 16],
    k2: [u8; 16],
    buffer: Vec<u8>,
    state: [u8; 16],
}

impl Cmac {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(CryptoCoreError::InvalidArgument(
                "AES-CMAC requires exactly 16-byte key".to_string()
            ));
        }
        
        let cipher = AesCipher::new(key)?;
        
        // Generate subkeys
        let zero = [0u8; 16];
        let l = cipher.encrypt_block(&zero)?;
        let (k1, k2) = Self::generate_subkeys(&l);
        
        Ok(Self {
            cipher,
            k1,
            k2,
            buffer: Vec::new(),
            state: [0u8; 16],
        })
    }
    
    fn generate_subkeys(l: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        
        // Generate K1 by left shifting L
        let mut carry = 0u16;
        for i in (0..16).rev() {
            let val = (l[i] as u16) << 1 | carry;
            k1[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        if (l[0] & 0x80) != 0 {
            k1[15] ^= 0x87;
        }
        
        // Generate K2 by left shifting K1
        carry = 0u16;
        for i in (0..16).rev() {
            let val = (k1[i] as u16) << 1 | carry;
            k2[i] = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        if (k1[0] & 0x80) != 0 {
            k2[15] ^= 0x87;
        }
        
        (k1, k2)
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    
    pub fn finalize(mut self) -> Result<[u8; 16]> {
        let is_complete = self.buffer.len() % 16 == 0 && !self.buffer.is_empty();
        let is_empty = self.buffer.is_empty();
        
        // Handle padding if needed
        if !is_empty && !is_complete {
            // Pad with 0x80 followed by zeros
            let pad_len = 16 - (self.buffer.len() % 16);
            self.buffer.push(0x80);
            self.buffer.extend(std::iter::repeat(0u8).take(pad_len - 1));
        }
        
        // Split into blocks
        let block_count = if is_empty { 1 } else { (self.buffer.len() + 15) / 16 };
        let mut blocks = Vec::with_capacity(block_count);
        
        if is_empty {
            // Empty message: single block of zeros
            blocks.push([0u8; 16]);
        } else {
            for i in 0..block_count {
                let start = i * 16;
                let end = std::cmp::min(start + 16, self.buffer.len());
                let mut block = [0u8; 16];
                block[..end - start].copy_from_slice(&self.buffer[start..end]);
                blocks.push(block);
            }
        }
        
        // Process blocks in CBC mode
        let mut state = [0u8; 16];
        
        for (i, block) in blocks.iter().enumerate() {
            let mut processed = *block;
            
            // For the last block
            if i == blocks.len() - 1 {
                if is_empty {
                    // Empty message: XOR with K2
                    for j in 0..16 {
                        processed[j] ^= self.k2[j];
                    }
                } else if is_complete {
                    // Complete block: XOR with K1
                    for j in 0..16 {
                        processed[j] ^= self.k1[j];
                    }
                } else {
                    // Padded block: XOR with K2
                    for j in 0..16 {
                        processed[j] ^= self.k2[j];
                    }
                }
            }
            
            // XOR with previous state
            for j in 0..16 {
                processed[j] ^= state[j];
            }
            
            // Encrypt
            state = self.cipher.encrypt_block(&processed)?;
        }
        
        Ok(state)
    }
    
    pub fn compute(key: &[u8], message: &[u8]) -> Result<[u8; 16]> {
        let mut cmac = Self::new(key)?;
        cmac.update(message);
        cmac.finalize()
    }
    
    pub fn compute_file(key: &[u8], path: &std::path::Path) -> Result<[u8; 16]> {
        use std::fs::File;
        use std::io::Read;
        
        let mut cmac = Self::new(key)?;
        let mut file = File::open(path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to open file: {}", e)))?;
        
        let mut buffer = [0u8; 4096];
        loop {
            let n = file.read(&mut buffer)
                .map_err(|e| CryptoCoreError::FileError(format!("Failed to read file: {}", e)))?;
            if n == 0 {
                break;
            }
            cmac.update(&buffer[..n]);
        }
        
        cmac.finalize()
    }
    
    pub fn verify(key: &[u8], message: &[u8], expected_cmac: &[u8]) -> Result<bool> {
        let computed = Self::compute(key, message)?;
        Ok(computed.as_slice() == expected_cmac)
    }
    
    pub fn verify_file(key: &[u8], path: &std::path::Path, expected_cmac: &[u8]) -> Result<bool> {
        let computed = Self::compute_file(key, path)?;
        Ok(computed.as_slice() == expected_cmac)
    }
}