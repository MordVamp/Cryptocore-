#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let hash = hasher.finalize();
        assert_eq!(hex::encode(hash), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let cipher = Cipher::new(key);
        let data = b"hello world!";
        let iv = [0u8; 16];
        
        let encrypted = cipher.encrypt(data, &iv);
        let decrypted = cipher.decrypt(&encrypted);
        assert_eq!(&decrypted[..data.len()], data);
    }
}