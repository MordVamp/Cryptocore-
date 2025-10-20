use crate::error::Result;

pub trait Cipher {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn block_size(&self) -> usize;
    fn requires_padding(&self) -> bool {
        true
    }
}