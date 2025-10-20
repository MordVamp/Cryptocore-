pub mod cbc;
pub mod cfb;
pub mod ofb;
pub mod ctr;

use crate::error::Result;
use super::traits::Cipher;  // Импортируем трейт

pub enum BlockMode {
    Cbc(cbc::CbcMode),
    Cfb(cfb::CfbMode),
    Ofb(ofb::OfbMode),
    Ctr(ctr::CtrMode),
}

impl BlockMode {
    pub fn new(mode_name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        match mode_name.to_lowercase().as_str() {
            "cbc" => Ok(Self::Cbc(cbc::CbcMode::new(key, iv)?)),
            "cfb" => Ok(Self::Cfb(cfb::CfbMode::new(key, iv)?)),
            "ofb" => Ok(Self::Ofb(ofb::OfbMode::new(key, iv)?)),
            "ctr" => Ok(Self::Ctr(ctr::CtrMode::new(key, iv)?)),
            _ => Err(crate::error::CryptoCoreError::InvalidArgument(
                format!("Unsupported mode: {}", mode_name)
            )),
        }
    }
}

// Реализуем трейт Cipher для BlockMode
impl Cipher for BlockMode {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Cbc(cipher) => cipher.encrypt(data),
            Self::Cfb(cipher) => cipher.encrypt(data),
            Self::Ofb(cipher) => cipher.encrypt(data),
            Self::Ctr(cipher) => cipher.encrypt(data),
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Cbc(cipher) => cipher.decrypt(data),
            Self::Cfb(cipher) => cipher.decrypt(data),
            Self::Ofb(cipher) => cipher.decrypt(data),
            Self::Ctr(cipher) => cipher.decrypt(data),
        }
    }

    fn block_size(&self) -> usize {
        16
    }

    fn requires_padding(&self) -> bool {
        match self {
            Self::Cbc(_) => true,
            Self::Cfb(_) | Self::Ofb(_) | Self::Ctr(_) => false,
        }
    }
}