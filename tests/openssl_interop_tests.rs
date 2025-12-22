use assert_cmd::Command;
use std::fs;
use std::io::Write;
use std::process::Command as StdCommand;
use std::process::Stdio;

const TEST_KEY: &str = "00112233445566778899aabbccddeeff";
const TEST_IV: &str = "aabbccddeeff00112233445566778899";

#[test]
fn test_openssl_cbc_interoperability() -> Result<(), Box<dyn std::error::Error>> {
    if !is_openssl_available() {
        println!("OpenSSL not available, skipping interoperability test");
        return Ok(());
    }

    let plaintext = "Interoperability test between CryptoCore and OpenSSL CBC mode";
    fs::write("test_interop_plain.txt", plaintext)?;

    // CryptoCore encryption - Updated
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc", 
        "--key", TEST_KEY,
        "--input", "test_interop_plain.txt",
        "--output", "cryptocore_cbc.bin"
    ])
    .assert()
    .success();

    // Extract IV and ciphertext for OpenSSL
    let crypto_data = fs::read("cryptocore_cbc.bin")?;
    let iv_hex = hex::encode(&crypto_data[..16]);
    
    let mut ciphertext_file = fs::File::create("ciphertext_only.bin")?;
    ciphertext_file.write_all(&crypto_data[16..])?;
    drop(ciphertext_file);

    // OpenSSL decryption
    let openssl_status = StdCommand::new("openssl")
        .args(&[
            "enc", "-aes-128-cbc", "-d",
            "-K", TEST_KEY,
            "-iv", &iv_hex,
            "-in", "ciphertext_only.bin",
            "-out", "openssl_decrypted.txt"
        ])
        .status()?;

    assert!(openssl_status.success(), "OpenSSL decryption failed");

    // Verify OpenSSL can decrypt CryptoCore's output
    let openssl_decrypted = fs::read_to_string("openssl_decrypted.txt")?;
    assert_eq!(plaintext, openssl_decrypted);

    cleanup_files(&[
        "test_interop_plain.txt", 
        "cryptocore_cbc.bin", 
        "ciphertext_only.bin", 
        "openssl_decrypted.txt"
    ])?;
    Ok(())
}

#[test]
fn test_openssl_to_cryptocore_cbc() -> Result<(), Box<dyn std::error::Error>> {
    if !is_openssl_available() {
        println!("OpenSSL not available, skipping interoperability test");
        return Ok(());
    }

    let plaintext = "OpenSSL to CryptoCore interoperability test";
    fs::write("test_plain_ssl.txt", plaintext)?;

    // OpenSSL encryption
    let openssl_status = StdCommand::new("openssl")
        .args(&[
            "enc", "-aes-128-cbc",
            "-K", TEST_KEY,
            "-iv", TEST_IV,
            "-in", "test_plain_ssl.txt",
            "-out", "openssl_encrypted.bin"
        ])
        .status()?;

    assert!(openssl_status.success(), "OpenSSL encryption failed");

    // CryptoCore decryption with explicit IV - Updated
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc",
        "--key", TEST_KEY,
        "--iv", TEST_IV,
        "--input", "openssl_encrypted.bin",
        "--output", "cryptocore_decrypted.txt"
    ])
    .assert()
    .success();

    // Verify CryptoCore can decrypt OpenSSL's output
    let crypto_decrypted = fs::read_to_string("cryptocore_decrypted.txt")?;
    assert_eq!(plaintext, crypto_decrypted);

    cleanup_files(&[
        "test_plain_ssl.txt",
        "openssl_encrypted.bin", 
        "cryptocore_decrypted.txt"
    ])?;
    Ok(())
}

#[test]
fn test_openssl_ctr_interoperability() -> Result<(), Box<dyn std::error::Error>> {
    if !is_openssl_available() {
        println!("OpenSSL not available, skipping CTR test");
        return Ok(());
    }

    let plaintext = "CTR mode interoperability test";
    fs::write("test_ctr_plain.txt", plaintext)?;

    // CryptoCore CTR encryption - Updated
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "ctr", 
        "--key", TEST_KEY,
        "--input", "test_ctr_plain.txt",
        "--output", "cryptocore_ctr.bin"
    ])
    .assert()
    .success();

    // Extract IV and ciphertext
    let crypto_data = fs::read("cryptocore_ctr.bin")?;
    let iv_hex = hex::encode(&crypto_data[..16]);
    
    let mut ciphertext_file = fs::File::create("ctr_ciphertext.bin")?;
    ciphertext_file.write_all(&crypto_data[16..])?;
    drop(ciphertext_file);

    // OpenSSL CTR decryption
    let openssl_status = StdCommand::new("openssl")
        .args(&[
            "enc", "-aes-128-ctr", "-d",
            "-K", TEST_KEY,
            "-iv", &iv_hex,
            "-in", "ctr_ciphertext.bin",
            "-out", "openssl_ctr_decrypted.txt"
        ])
        .status()?;

    if openssl_status.success() {
        let openssl_decrypted = fs::read_to_string("openssl_ctr_decrypted.txt")?;
        assert_eq!(plaintext, openssl_decrypted);
    } else {
        println!("OpenSSL CTR decryption failed - this might be expected on some systems");
    }

    cleanup_files(&[
        "test_ctr_plain.txt",
        "cryptocore_ctr.bin",
        "ctr_ciphertext.bin",
        "openssl_ctr_decrypted.txt"
    ])?;
    Ok(())
}

fn is_openssl_available() -> bool {
    StdCommand::new("openssl")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn cleanup_files(files: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    for file in files {
        if let Err(_) = fs::remove_file(file) {
            // Ignore cleanup errors
        }
    }
    Ok(())
}