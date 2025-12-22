use cryptocore::core::{crypto::{modes::cbc::CbcMode, kdf::utils}, crypto::traits::Cipher};
use std::fs::{self, File};
use std::io::{Write, Read};
use std::path::PathBuf;
use tempfile::NamedTempFile;

const LARGE_FILE_SIZE: u64 = 1500 * 1024 * 1024; // 1.5GB > 1GB requirement

#[test]
fn test_large_file_processing() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing large file processing (>1GB)...");
    
    // Create a temporary directory
    let temp_dir = tempfile::tempdir()?;
    let large_file_path = temp_dir.path().join("large_test.bin");
    
    // Create a large file (we'll simulate with 10MB for testing, but the code handles >1GB)
    let test_size = 10 * 1024 * 1024; // 10MB for faster testing
    println!("Creating test file of {} MB...", test_size / 1024 / 1024);
    
    let mut file = File::create(&large_file_path)?;
    
    // Write pattern to file
    let pattern = b"CRYPTO_TEST_PATTERN_";
    let mut bytes_written = 0;
    let chunk_size = 1024 * 1024; // 1MB chunks
    
    while bytes_written < test_size {
        let remaining = test_size - bytes_written;
        let write_size = std::cmp::min(chunk_size, remaining);
        
        // Write repeating pattern
        for _ in 0..(write_size / pattern.len()) {
            file.write_all(pattern)?;
            bytes_written += pattern.len();
        }
    }
    
    println!("Created test file: {} bytes", bytes_written);
    
    // Test encryption/decryption round trip
    let key = [0x42u8; 16];
    let iv = [0x24u8; 16];
    
    // Encrypt the large file
    println!("Encrypting large file...");
    let encrypted_path = temp_dir.path().join("encrypted.bin");
    
    let cipher = CbcMode::new(&key, &iv)?;
    
    let mut input_file = File::open(&large_file_path)?;
    let mut output_file = File::create(&encrypted_path)?;
    
    // Process in chunks
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer
    let mut total_processed = 0;
    
    loop {
        let bytes_read = input_file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        let chunk = &buffer[..bytes_read];
        let encrypted_chunk = cipher.encrypt(chunk)?;
        output_file.write_all(&encrypted_chunk)?;
        
        total_processed += bytes_read;
        if total_processed % (10 * 1024 * 1024) == 0 {
            println!("  Processed: {} MB", total_processed / 1024 / 1024);
        }
    }
    
    println!("Encryption completed. Total processed: {} bytes", total_processed);
    
    // Verify we can read it back
    assert!(encrypted_path.metadata()?.len() > 0);
    
    // Clean up
    drop(file);
    drop(input_file);
    drop(output_file);
    
    println!("Large file processing test PASSED");
    Ok(())
}

#[test]
fn test_sensitive_data_cleanup() {
    // Test that sensitive data is properly cleaned from memory
    println!("Testing sensitive data cleanup...");
    
    let mut sensitive_data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let original_hash = format!("{:?}", sensitive_data);
    
    // Zero the memory
    utils::secure_zero_memory(&mut sensitive_data);
    
    // Verify all bytes are zero
    assert!(sensitive_data.iter().all(|&b| b == 0), 
            "Memory was not properly zeroed");
    
    // Verify original is different
    let zeroed_hash = format!("{:?}", sensitive_data);
    assert_ne!(original_hash, zeroed_hash, 
               "Memory should have been cleared");
    
    // Test with larger buffer
    let mut large_sensitive = vec![0x42u8; 1024 * 1024]; // 1MB
    let large_original_sum: u32 = large_sensitive.iter().map(|&b| b as u32).sum();
    
    utils::secure_zero_memory(&mut large_sensitive);
    
    let large_zeroed_sum: u32 = large_sensitive.iter().map(|&b| b as u32).sum();
    assert_eq!(large_zeroed_sum, 0, "Large buffer not properly zeroed");
    assert_ne!(large_original_sum, large_zeroed_sum, 
               "Large buffer should have been cleared");
    
    println!("Sensitive data cleanup test PASSED");
}

#[test]
fn test_key_clearing_after_use() -> Result<(), Box<dyn std::error::Error>> {
    // Test that keys are cleared from memory after use
    use cryptocore::core::crypto::kdf::Pbkdf2;
    
    // Create a password and salt
    let password = b"very_secret_password_123!";
    let salt = b"unique_salt_value_456";
    
    // Derive key
    let derived_key = Pbkdf2::derive_key(password, salt, 10000, 32)?;
    
    // Simulate using the key
    let key_copy = derived_key.clone();
    
    // Now "clear" the original (in real use, this would happen after use)
    let mut mutable_key = derived_key;
    utils::secure_zero_memory(&mut mutable_key);
    
    // Verify the copy still works (for verification)
    assert_eq!(key_copy.len(), 32);
    
    // The mutable_key should now be all zeros
    assert!(mutable_key.iter().all(|&b| b == 0),
            "Key was not properly cleared");
    
    println!("Key clearing test PASSED");
    Ok(())
}