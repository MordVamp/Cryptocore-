
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
        // Updated to match actual error message
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
        // Updated to match actual error message
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }
    #[test]
    fn test_gcm_nonce_reuse_issues() {
        let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let gcm = Gcm::new(&key).unwrap();
        
        let nonce = hex::decode("000000000000000000000000").unwrap();
        let aad = b"additional authenticated data";
        
        let plaintext1 = b"First secret message";
        let (ciphertext1, tag1) = gcm.encrypt(plaintext1, aad, &nonce).unwrap();
        
        let plaintext2 = b"Second secret message";
        let (ciphertext2, tag2) = gcm.encrypt(plaintext2, aad, &nonce).unwrap();
        
        // With the same nonce and key, CTR mode will generate same keystream
        // So ciphertexts should be different if plaintexts are different
        // But tags should be different even if we had same ciphertext
        assert_ne!(ciphertext1, ciphertext2, "Ciphertexts should be different with same nonce but different plaintexts");
        assert_ne!(tag1, tag2, "Tags should be different");
        
        let decrypted1 = gcm.decrypt(&ciphertext1, aad, &nonce, &tag1).unwrap();
        let decrypted2 = gcm.decrypt(&ciphertext2, aad, &nonce, &tag2).unwrap();
        
        assert_eq!(plaintext1, decrypted1.as_slice());
        assert_eq!(plaintext2, decrypted2.as_slice());
        
        let result = gcm.decrypt(&ciphertext2, aad, &nonce, &tag1);
        assert!(result.is_err(), "Using wrong tag should fail");
    }
    
    #[test]
    fn test_gcm_empty_data() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let gcm = Gcm::new(&key).unwrap();
        
        let nonce = hex::decode("0102030405060708090a0b0c").unwrap();
        
        
        let empty_plaintext = b"";
        let aad1 = b"some aad";
        let (ciphertext1, tag1) = gcm.encrypt(empty_plaintext, aad1, &nonce).unwrap();
        let decrypted1 = gcm.decrypt(&ciphertext1, aad1, &nonce, &tag1).unwrap();
        assert_eq!(empty_plaintext, decrypted1.as_slice());
        
        
        let plaintext2 = b"Non-empty plaintext";
        let empty_aad = b"";
        let (ciphertext2, tag2) = gcm.encrypt(plaintext2, empty_aad, &nonce).unwrap();
        let decrypted2 = gcm.decrypt(&ciphertext2, empty_aad, &nonce, &tag2).unwrap();
        assert_eq!(plaintext2, decrypted2.as_slice());
        
        
        let (ciphertext3, tag3) = gcm.encrypt(b"", b"", &nonce).unwrap();
        let decrypted3 = gcm.decrypt(&ciphertext3, b"", &nonce, &tag3).unwrap();
        assert_eq!(b"", decrypted3.as_slice());
    }
}
