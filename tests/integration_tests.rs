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
// fn test_missing_operation() -> Result<(), Box<dyn std::error::Error>> {
//     let mut cmd = Command::cargo_bin("cryptocore")?;
//     cmd.args(&[
//         "--algorithm", "aes",
//         "--mode", "ecb",
//         "--key", "@00112233445566778899aabbccddeeff",
//         "--input", "test.txt"
//     ])
//     .assert()
//     .failure()
//     .stderr(predicate::str::contains("Either --encrypt or --decrypt must be specified"));
    
//     Ok(())
// }

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
#[test]
fn test_cli_hmac_generation() {
    use std::process::Command;
    use std::fs::File;
    use std::io::Write;
    
    // Create test file
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_hmac.txt");
    let mut file = File::create(&test_file).unwrap();
    writeln!(file, "Hello, HMAC!").unwrap();
    
    // Test HMAC generation
    let output = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--hmac", 
               "--key", "00112233445566778899aabbccddeeff",
               "--input", test_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(output.status.success());
    let output_str = String::from_utf8_lossy(&output.stdout);
    assert!(output_str.contains("  ")); // Should contain HMAC and filename
    
    // Cleanup
    let _ = std::fs::remove_file(test_file);
}

#[test]
fn test_cli_hmac_verification() {
    use std::process::Command;
    use std::fs::File;
    use std::io::Write;
    
    // Create test file and HMAC
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_verify.txt");
    let hmac_file = temp_dir.join("test_verify.hmac");
    
    let mut file = File::create(&test_file).unwrap();
    writeln!(file, "Original content").unwrap();
    
    // First generate HMAC
    let hmac_output = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--hmac", 
               "--key", "00112233445566778899aabbccddeeff",
               "--input", test_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(hmac_output.status.success());
    
    // Write HMAC to file
    let mut hmac_f = File::create(&hmac_file).unwrap();
    hmac_f.write_all(&hmac_output.stdout).unwrap();
    
    // Now verify
    let verify_output = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--hmac", 
               "--key", "00112233445566778899aabbccddeeff",
               "--input", test_file.to_str().unwrap(),
               "--verify", hmac_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(verify_output.status.success());
    assert!(String::from_utf8_lossy(&verify_output.stdout).contains("[OK]"));
    
    // Cleanup
    let _ = std::fs::remove_file(test_file);
    let _ = std::fs::remove_file(hmac_file);
}
#[test]
fn test_cli_cmac_generation() {
    use std::process::Command;
    use std::fs::File;
    use std::io::Write;
    
    // Create test file
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_cmac.txt");
    let mut file = File::create(&test_file).unwrap();
    writeln!(file, "Hello, CMAC!").unwrap();
    
    // Test CMAC generation
    let output = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--cmac", 
               "--key", "2b7e151628aed2a6abf7158809cf4f3c",
               "--input", test_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(output.status.success());
    let output_str = String::from_utf8_lossy(&output.stdout);
    // Output should be 32 hex chars (16 bytes) + space + filename
    let parts: Vec<&str> = output_str.trim().split_whitespace().collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[1], test_file.to_str().unwrap());
    assert_eq!(parts[0].len(), 32); // 16 bytes in hex
    
    // Cleanup
    let _ = std::fs::remove_file(test_file);
}

#[test]
fn test_cli_cmac_verification() {
    use std::process::Command;
    use std::fs::File;
    use std::io::Write;
    
    // Create test file and CMAC
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("test_cmac_verify.txt");
    let cmac_file = temp_dir.join("test_cmac_verify.cmac");
    
    let mut file = File::create(&test_file).unwrap();
    writeln!(file, "Original content for CMAC").unwrap();
    
    // First generate CMAC
    let cmac_output = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--cmac", 
               "--key", "2b7e151628aed2a6abf7158809cf4f3c",
               "--input", test_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(cmac_output.status.success());
    
    // Write CMAC to file
    let mut cmac_f = File::create(&cmac_file).unwrap();
    cmac_f.write_all(&cmac_output.stdout).unwrap();
    
    // Now verify
    let verify_output = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--cmac", 
               "--key", "2b7e151628aed2a6abf7158809cf4f3c",
               "--input", test_file.to_str().unwrap(),
               "--verify", cmac_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(verify_output.status.success());
    assert!(String::from_utf8_lossy(&verify_output.stdout).contains("[OK]"));
    
    // Test with wrong key (should fail)
    let wrong_verify = Command::new("cargo")
        .args(["run", "--", "dgst", "--algorithm", "sha256", "--cmac", 
               "--key", "00000000000000000000000000000000", // Wrong key
               "--input", test_file.to_str().unwrap(),
               "--verify", cmac_file.to_str().unwrap()])
        .output()
        .expect("Failed to execute command");
    
    assert!(!wrong_verify.status.success());
    assert!(String::from_utf8_lossy(&wrong_verify.stderr).contains("[ERROR]"));
    
    // Cleanup
    let _ = std::fs::remove_file(test_file);
    let _ = std::fs::remove_file(cmac_file);
}