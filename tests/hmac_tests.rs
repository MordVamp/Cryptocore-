use cryptocore::core::crypto::mac::hmac::Hmac;

#[test]
fn test_rfc_4231_vectors() {
    // Test case 1 from RFC 4231
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let data = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    
    let hmac = Hmac::compute(&key, data);
    assert_eq!(hex::encode(hmac), expected);
    
    // Test case 2 - CORRECTED VALUES
    let key = b"Jefe".to_vec();
    let data = b"what do ya want for nothing?";
    // Correct expected value from RFC 4231
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    
    let hmac = Hmac::compute(&key, data);
    assert_eq!(hex::encode(hmac), expected);
    
    // Additional test case 3 from RFC 4231
    let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let data = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
    let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
    
    let hmac = Hmac::compute(&key, &data);
    assert_eq!(hex::encode(hmac), expected);
}

#[test]
fn test_key_sizes() {
    // Short key
    let key = vec![0x01, 0x02, 0x03];
    let data = b"Test data";
    let hmac1 = Hmac::compute(&key, data);
    
    // Long key (should be hashed)
    let mut long_key = vec![0u8; 100];
    long_key[0] = 0x01;
    long_key[1] = 0x02;
    long_key[2] = 0x03;
    let hmac2 = Hmac::compute(&long_key, data);
    
    assert_ne!(hex::encode(hmac1), hex::encode(hmac2));
}

#[test]
fn test_verification() {
    let key = vec![0x01, 0x02, 0x03, 0x04];
    let data = b"Hello, World!";
    
    let hmac = Hmac::compute(&key, data);
    
    // Correct verification
    assert!(Hmac::verify(&key, data, &hmac));
    
    // Wrong key
    let wrong_key = vec![0x05, 0x06, 0x07, 0x08];
    assert!(!Hmac::verify(&wrong_key, data, &hmac));
    
    // Tampered data
    let tampered_data = b"Hello, World?";
    assert!(!Hmac::verify(&key, tampered_data, &hmac));
}

#[test]
fn test_empty_file() {
    use std::fs::File;
    use std::io::Write;
    
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("empty_test.txt");
    
    // Create empty file
    File::create(&test_file).unwrap();
    
    let key = vec![0x01, 0x02, 0x03];
    let result = Hmac::compute_file(&key, &test_file).unwrap();
    
    // Should compute without error
    assert_eq!(result.len(), 32);
    
    // Cleanup
    let _ = std::fs::remove_file(test_file);
}