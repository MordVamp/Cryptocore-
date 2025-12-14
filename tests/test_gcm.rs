#[cfg(test)]
mod tests {
    use cryptocore::core::crypto::modes::gcm::Gcm;
    use hex;
    
    #[test]
    fn test_gcm_basic_encryption_decryption() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let gcm = Gcm::new(&key).unwrap();
        
        let plaintext = b"Hello GCM World!";
        let aad = b"associated data";
        let nonce = hex::decode("000000000000000000000000").unwrap();
        
        // Encrypt
        let (ciphertext, tag) = gcm.encrypt(plaintext, aad, &nonce).unwrap();
        
        // Decrypt
        let decrypted = gcm.decrypt(&ciphertext, aad, &nonce, &tag).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_gcm_aad_tamper_failure() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let gcm = Gcm::new(&key).unwrap();
        
        let plaintext = b"Secret message";
        let aad_correct = b"correct aad";
        let aad_wrong = b"wrong aad";
        let nonce = hex::decode("000000000000000000000000").unwrap();
        
        // Encrypt with correct AAD
        let (ciphertext, tag) = gcm.encrypt(plaintext, aad_correct, &nonce).unwrap();
        
        // Try to decrypt with wrong AAD - should fail
        let result = gcm.decrypt(&ciphertext, aad_wrong, &nonce, &tag);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }
    
    #[test]
    fn test_gcm_ciphertext_tamper_failure() {
        let key = hex::decode("00000000000000000000000000000000").unwrap();
        let gcm = Gcm::new(&key).unwrap();
        
        let plaintext = b"Another secret";
        let aad = b"aad";
        let nonce = hex::decode("000000000000000000000000").unwrap();
        
        // Encrypt
        let (mut ciphertext, tag) = gcm.encrypt(plaintext, aad, &nonce).unwrap();
        
        // Tamper with ciphertext
        ciphertext[0] ^= 0x01; // Flip one bit
        
        // Try to decrypt tampered ciphertext - should fail
        let result = gcm.decrypt(&ciphertext, aad, &nonce, &tag);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }
}