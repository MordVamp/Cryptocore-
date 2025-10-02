use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

#[test]
fn test_encrypt_decrypt_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Hello, CryptoCore! This is a test message.";
    let key = "00112233445566778899aabbccddeeff";
    
    // Write test file
    fs::write("test_plain.txt", plaintext)?;
    
    // Encrypt
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "--algorithm", "aes",
        "--mode", "ecb", 
        "--encrypt",
        "--key", &format!("@{}", key),
        "--input", "test_plain.txt",
        "--output", "test_cipher.bin"
    ])
    .assert()
    .success();
    
    // Decrypt  
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "--algorithm", "aes",
        "--mode", "ecb",
        "--decrypt", 
        "--key", &format!("@{}", key),
        "--input", "test_cipher.bin",
        "--output", "test_decrypted.txt"
    ])
    .assert()
    .success();
    
    // Verify round-trip
    let decrypted = fs::read_to_string("test_decrypted.txt")?;
    assert_eq!(plaintext, decrypted);
    
    // Cleanup
    fs::remove_file("test_plain.txt")?;
    fs::remove_file("test_cipher.bin")?;
    fs::remove_file("test_decrypted.txt")?;
    
    Ok(())
}

#[test]
fn test_missing_operation() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "--algorithm", "aes",
        "--mode", "ecb",
        "--key", "@00112233445566778899aabbccddeeff",
        "--input", "test.txt"
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("Either --encrypt or --decrypt must be specified"));
    
    Ok(())
}

#[test]
fn test_invalid_key_length() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "--algorithm", "aes", 
        "--mode", "ecb",
        "--encrypt",
        "--key", "@001122",  // Too short
        "--input", "test.txt"
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("Key must be 16 bytes"));
    
    Ok(())
}