use crate::error::Result;

pub trait Aead {
    /// Encrypt plaintext with associated data
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    
    /// Decrypt ciphertext with associated data
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>>;
    
    /// Get the nonce size required by this AEAD
    fn nonce_size(&self) -> usize;
    
    /// Get the tag size produced by this AEAD
    fn tag_size(&self) -> usize;
}