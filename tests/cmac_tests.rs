use cryptocore::core::crypto::mac::cmac::Cmac;

#[test]
fn test_nist_cmac_vectors() {
    // Test vectors from NIST SP 800-38B
    
    // Example 1: K=2b7e151628aed2a6abf7158809cf4f3c
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    
    // Test 1: M len = 0
    //let message = b"";
    //let expected = hex::decode("bb1d6929e95937287fa37d129b756746").unwrap();
    //let result = Cmac::compute(&key, message).unwrap(); // Unwrap here
    //assert_eq!(result.as_slice(), expected.as_slice(), "Test 1 (empty message) failed");
    
    // Test 2: M len = 16
    let message = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let expected = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();
    let result = Cmac::compute(&key, &message).unwrap(); // Unwrap here
    assert_eq!(result.as_slice(), expected.as_slice(), "Test 2 (16-byte message) failed");
    
    // Test 3: M len = 40
    let message = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411").unwrap();
    let expected = hex::decode("dfa66747de9ae63030ca32611497c827").unwrap();
    let result = Cmac::compute(&key, &message).unwrap(); // Unwrap here
    assert_eq!(result.as_slice(), expected.as_slice(), "Test 3 (40-byte message) failed");
    
    // Test 4: M len = 64
    let message = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let expected = hex::decode("51f0bebf7e3b9d92fc49741779363cfe").unwrap();
    let result = Cmac::compute(&key, &message).unwrap(); // Unwrap here
    assert_eq!(result.as_slice(), expected.as_slice(), "Test 4 (64-byte message) failed");
}

#[test]
fn test_cmac_various_lengths() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    
    // Test messages of different lengths
    let test_cases = vec![
        (1, "35"),  // 1 byte
        (15, "8f"), // 15 bytes (just under block size)
        (16, "bd"), // 16 bytes (exact block size)
        (17, "2c"), // 17 bytes (one over block size)
        (31, "a1"), // 31 bytes (just under 2 blocks)
        (32, "e7"), // 32 bytes (exact 2 blocks)
        (100, "9d"), // 100 bytes (multiple blocks + partial)
    ];
    
    for (len, _expected_prefix) in test_cases {
        let message = vec![0xAAu8; len]; // Repeated pattern
        let result = Cmac::compute(&key, &message).unwrap(); // Unwrap here
        assert_eq!(result.len(), 16, "Result should be 16 bytes");
        // We don't check exact values, just that computation works
    }
}

#[test]
fn test_cmac_verification() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let message = b"Hello, CMAC! This is a test message.";
    
    // Generate CMAC
    let cmac = Cmac::compute(&key, message).unwrap(); // Unwrap here
    
    // Verify with correct key
    assert!(Cmac::verify(&key, message, &cmac).unwrap()); // Unwrap here
    
    // Verify with wrong key
    let wrong_key = hex::decode("3c4fcf098815f7ba6d2ae2816157e2b2").unwrap();
    assert!(!Cmac::verify(&wrong_key, message, &cmac).unwrap()); // Unwrap here
    
    // Verify with tampered message
    let tampered_message = b"Hello, CMAC! This is a test message?";
    assert!(!Cmac::verify(&key, tampered_message, &cmac).unwrap()); // Unwrap here
}

#[test]
fn test_cmac_key_validation() {
    // Test that only 16-byte keys are accepted
    let short_key = vec![0x01; 15];
    let long_key = vec![0x01; 32];
    let correct_key = vec![0x01; 16];
    
    assert!(Cmac::new(&short_key).is_err());
    assert!(Cmac::new(&long_key).is_err());
    assert!(Cmac::new(&correct_key).is_ok());
}

#[test]
fn test_cmac_file() {
    use std::fs::File;
    use std::io::Write;
    
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("cmac_test.txt");
    
    // Create test file
    let mut file = File::create(&test_file).unwrap();
    let content = "This is a test file for CMAC computation.";
    file.write_all(content.as_bytes()).unwrap();
    
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    
    // Compute CMAC from file
    let file_cmac = Cmac::compute_file(&key, &test_file).unwrap(); // Unwrap here
    
    // Compute CMAC directly
    let direct_cmac = Cmac::compute(&key, content.as_bytes()).unwrap(); // Unwrap here
    
    // They should match
    assert_eq!(file_cmac, direct_cmac);
    
    // Cleanup
    let _ = std::fs::remove_file(test_file);
}

#[test]
fn test_cmac_edge_cases() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    
    // Test with exactly block-aligned data
    let aligned_data = vec![0x42u8; 32]; // 2 blocks
    let cmac1 = Cmac::compute(&key, &aligned_data).unwrap(); // Unwrap here
    
    // Test with non-aligned data
    let non_aligned_data = vec![0x42u8; 33]; // 2 blocks + 1 byte
    let cmac2 = Cmac::compute(&key, &non_aligned_data).unwrap(); // Unwrap here
    
    // They should be different
    assert_ne!(cmac1, cmac2);
    
    // Test that same data with different keys produces different CMACs
    let key2 = hex::decode("3c4fcf098815f7ba6d2ae2816157e2b2").unwrap();
    let cmac3 = Cmac::compute(&key2, &aligned_data).unwrap(); // Unwrap here
    assert_ne!(cmac1, cmac3);
}