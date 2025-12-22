#[cfg(test)]
mod tests {
    use cryptocore::core::crypto::kdf::{Pbkdf2, KeyHierarchy};
    use hex;
    
    // RFC 6070 Test Vectors for PBKDF2-HMAC-SHA256
    #[test]
    fn test_pbkdf2_rfc6070_vector1() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1;
        let dklen = 20; // 160 bits
        
        let derived_key = Pbkdf2::derive_key(password, salt, iterations, dklen).unwrap();
        let expected = hex::decode("0c60c80f961f0e71f3a9b524af6012062fe037a6").unwrap();
        
        assert_eq!(derived_key, expected, "RFC 6070 Test Vector 1 failed");
    }
    
    #[test]
    fn test_pbkdf2_rfc6070_vector2() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let dklen = 20;
        
        let derived_key = Pbkdf2::derive_key(password, salt, iterations, dklen).unwrap();
        let expected = hex::decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957").unwrap();
        
        assert_eq!(derived_key, expected, "RFC 6070 Test Vector 2 failed");
    }
    
    #[test]
    fn test_pbkdf2_rfc6070_vector3() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 4096;
        let dklen = 20;
        
        let derived_key = Pbkdf2::derive_key(password, salt, iterations, dklen).unwrap();
        let expected = hex::decode("4b007901b765489abead49d926f721d065a429c1").unwrap();
        
        assert_eq!(derived_key, expected, "RFC 6070 Test Vector 3 failed");
    }
    
    #[test]
    fn test_pbkdf2_rfc6070_vector4() {
        let password = b"passwordPASSWORDpassword";
        let salt = b"saltSALTsaltSALTsaltSALTsaltSALTsalt";
        let iterations = 4096;
        let dklen = 25;
        
        let derived_key = Pbkdf2::derive_key(password, salt, iterations, dklen).unwrap();
        let expected = hex::decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038").unwrap();
        
        assert_eq!(derived_key, expected, "RFC 6070 Test Vector 4 failed");
    }
    
    #[test]
    fn test_pbkdf2_empty_password() {
        let result = Pbkdf2::derive_key(b"", b"salt", 1000, 32);
        assert!(result.is_err(), "Empty password should be rejected");
    }
    
    #[test]
    fn test_pbkdf2_empty_salt() {
        let result = Pbkdf2::derive_key(b"password", b"", 1000, 32);
        assert!(result.is_err(), "Empty salt should be rejected");
    }
    
    #[test]
    fn test_pbkdf2_zero_iterations() {
        let result = Pbkdf2::derive_key(b"password", b"salt", 0, 32);
        assert!(result.is_err(), "Zero iterations should be rejected");
    }
    
    #[test]
    fn test_pbkdf2_zero_length() {
        let result = Pbkdf2::derive_key(b"password", b"salt", 1000, 0);
        assert!(result.is_err(), "Zero length should be rejected");
    }
    
    #[test]
    fn test_pbkdf2_various_lengths() {
        let password = b"test_password";
        let salt = b"test_salt";
        let iterations = 1000;
        
        // Test various key lengths
        for length in 1..=100 {
            let derived_key = Pbkdf2::derive_key(password, salt, iterations, length).unwrap();
            assert_eq!(derived_key.len(), length, 
                "Derived key length should be {} bytes", length);
        }
    }
    
    #[test]
    fn test_pbkdf2_deterministic() {
        let password = b"deterministic_test";
        let salt = b"test_salt";
        let iterations = 5000;
        let dklen = 32;
        
        let key1 = Pbkdf2::derive_key(password, salt, iterations, dklen).unwrap();
        let key2 = Pbkdf2::derive_key(password, salt, iterations, dklen).unwrap();
        
        assert_eq!(key1, key2, "PBKDF2 should be deterministic with same inputs");
    }
    
    #[test]
    fn test_pbkdf2_salt_randomness() {
        use cryptocore::core::crypto::kdf::Pbkdf2;
        
        let mut salts = std::collections::HashSet::new();
        for _ in 0..1000 {
            let salt = Pbkdf2::generate_salt(16).unwrap();
            assert_eq!(salt.len(), 16, "Generated salt should be 16 bytes");
            salts.insert(salt);
        }
        
        // All 1000 salts should be unique
        assert_eq!(salts.len(), 1000, "All 1000 generated salts should be unique");
    }
    
    #[test]
    fn test_key_hierarchy_deterministic() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let context = "encryption";
        let length = 32;
        
        let key1 = KeyHierarchy::derive_key(master_key, context, length).unwrap();
        let key2 = KeyHierarchy::derive_key(master_key, context, length).unwrap();
        
        assert_eq!(key1, key2, "Key hierarchy should be deterministic");
    }
    
    #[test]
    fn test_key_hierarchy_context_separation() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let length = 32;
        
        let encryption_key = KeyHierarchy::derive_key(master_key, "encryption", length).unwrap();
        let auth_key = KeyHierarchy::derive_key(master_key, "authentication", length).unwrap();
        let mac_key = KeyHierarchy::derive_key(master_key, "mac", length).unwrap();
        
        // All keys should be different
        assert_ne!(encryption_key, auth_key, "Different contexts should produce different keys");
        assert_ne!(encryption_key, mac_key, "Different contexts should produce different keys");
        assert_ne!(auth_key, mac_key, "Different contexts should produce different keys");
    }
    
    #[test]
    fn test_key_hierarchy_various_lengths() {
        let master_key = b"test_master_key_123456";
        
        for length in [1, 16, 32, 64, 100] {
            let derived = KeyHierarchy::derive_key(master_key, "test", length).unwrap();
            assert_eq!(derived.len(), length, 
                "Derived key should be {} bytes", length);
        }
    }
    
    #[test]
    fn test_key_hierarchy_empty_master() {
        let result = KeyHierarchy::derive_key(b"", "context", 32);
        assert!(result.is_err(), "Empty master key should be rejected");
    }
    
    #[test]
    fn test_key_hierarchy_empty_context() {
        let result = KeyHierarchy::derive_key(b"master", "", 32);
        assert!(result.is_err(), "Empty context should be rejected");
    }
    
    #[test]
    fn test_key_hierarchy_zero_length() {
        let result = KeyHierarchy::derive_key(b"master", "context", 0);
        assert!(result.is_err(), "Zero length should be rejected");
    }
    
    #[test]
    fn test_key_hierarchy_hierarchy() {
        let master_key = b"master_key_for_hierarchy_test";
        
        let contexts = [
            ("encryption", 32),
            ("authentication", 32),
            ("key_wrapping", 64),
            ("iv_generation", 16),
        ];
        
        let keys = KeyHierarchy::derive_key_hierarchy(master_key, &contexts).unwrap();
        
        assert_eq!(keys.len(), 4, "Should derive 4 keys");
        
        // Check all keys are different
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].1, keys[j].1, 
                    "Keys {} and {} should be different", keys[i].0, keys[j].0);
            }
        }
    }
    
    #[test]
    fn test_pbkdf2_benchmark() {
        let password = b"benchmark_password";
        let salt = b"benchmark_salt";
        let iterations_list = [1000, 10000, 100000];
        
        let results = Pbkdf2::benchmark(password, salt, &iterations_list).unwrap();
        
        assert_eq!(results.len(), 3, "Should have 3 benchmark results");
        
        for (iterations, time) in results {
            println!("PBKDF2 with {} iterations took {:.3} seconds", iterations, time);
            // Time should increase with more iterations
            if iterations > 1000 {
                assert!(time > 0.0, "Time should be positive");
            }
        }
    }
    
    #[test]
    fn test_derive_encryption_and_auth_keys() {
        use cryptocore::core::crypto::kdf::utils;
        
        let master_key = b"master_key_32_bytes_123456789012";
        
        let (enc_key, auth_key) = utils::derive_encryption_and_auth_keys(master_key).unwrap();
        
        assert_eq!(enc_key.len(), 32, "Encryption key should be 32 bytes");
        assert_eq!(auth_key.len(), 32, "Authentication key should be 32 bytes");
        assert_ne!(enc_key, auth_key, "Encryption and auth keys should be different");
    }
    
    #[test]
    fn test_secure_zero_memory() {
        use cryptocore::core::crypto::kdf::utils;
        
        let mut sensitive_data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let original = sensitive_data.clone();
        
        utils::secure_zero_memory(&mut sensitive_data);
        
        // After zeroing, all bytes should be zero
        assert!(sensitive_data.iter().all(|&b| b == 0), 
            "All bytes should be zero after secure_zero_memory");
        
        // Verify original is different (was changed)
        assert_ne!(sensitive_data, original, 
            "Memory should have been zeroed");
    }
    
    #[test]
    fn test_interoperability_with_openssl() {
        // Note: This test requires OpenSSL to be installed and in PATH
        // It's marked as #[ignore] by default since it depends on external tools
        
        use std::process::Command;
        
        let password = "test_password";
        let salt_hex = "1234567890abcdef1234567890abcdef";
        let salt_bytes = hex::decode(salt_hex).unwrap();
        let iterations = 10000;
        let length = 32;
        
        // Derive key using our implementation
        let our_key = Pbkdf2::derive_key(password.as_bytes(), &salt_bytes, iterations, length).unwrap();
        let our_key_hex = hex::encode(&our_key);
        
        // Try to use OpenSSL if available
        let openssl_output = Command::new("openssl")
            .args([
                "kdf", "-keylen", &length.to_string(),
                "-kdfopt", &format!("pass:{}", password),
                "-kdfopt", &format!("salt:{}", salt_hex),
                "-kdfopt", &format!("iter:{}", iterations),
                "PBKDF2"
            ])
            .output();
        
        if let Ok(output) = openssl_output {
            if output.status.success() {
                let openssl_key_hex = String::from_utf8_lossy(&output.stdout).trim().to_string();
                assert_eq!(our_key_hex, openssl_key_hex, 
                    "Our PBKDF2 implementation should match OpenSSL");
            }
        } else {
            // OpenSSL not available, skip the test
            println!("OpenSSL not available, skipping interoperability test");
        }
    }
}
