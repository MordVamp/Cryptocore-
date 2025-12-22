
use cryptocore::{cli, Operation, Result, CryptoCoreError};
use cryptocore::core::{io, crypto, crypto::hash, crypto::mac, crypto::kdf};
use std::fs;

fn main() -> Result<()> {
    let config = match cli::parse_args() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = run(config) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn run(config: cli::CliConfig) -> Result<()> {
    match config.operation_type {
        cli::OperationType::EncryptDecrypt { 
            algorithm, mode, operation, key, iv, input_file, output_file, aad 
        } => {
            run_encryption(algorithm, mode, operation, key, iv, input_file, output_file, aad)
        }
        cli::OperationType::Digest { algorithm, input_file, output_file, hmac, key, verify, cmac } => {
            run_digest(algorithm, input_file, output_file, hmac, key, verify, cmac)
        }
        cli::OperationType::Derive { 
            password, password_file, password_env, salt, iterations, length, algorithm, output 
        } => {
            run_derive(password, password_file, password_env, salt, iterations, length, algorithm, output)
        }
    }
}

fn run_encryption(
    algorithm: String,
    mode: String,
    operation: Operation,
    key: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
    input_file: std::path::PathBuf,
    output_file: Option<std::path::PathBuf>,
    aad: Option<Vec<u8>>,
) -> Result<()> {
    let is_gcm = mode.to_lowercase() == "gcm";
    let mode_requires_iv = !matches!(mode.to_lowercase().as_str(), "ecb") || is_gcm;
    
    // Fix: Proper key handling with pattern matching
    let (key, generated_key_hex) = match &key {
        Some(provided_key) => (provided_key.clone(), None),
        None => {
            if operation == Operation::Encrypt {
                // Generate key using your CSPRNG
                let new_key = crypto::csprng::Csprng::generate_random_bytes(16)?;
                let key_hex = hex::encode(&new_key);
                println!("Generated random key: {}", key_hex);
                (new_key, Some(key_hex))
            } else {
                return Err(CryptoCoreError::ConfigError(
                    "Key is required for decryption".to_string()
                ));
            }
        }
    };

    // Handle AAD (default to empty if not provided)
    let aad_bytes = aad.unwrap_or_default();
    
    // Special handling for GCM mode
    if is_gcm {
        return run_gcm_operation(
            &key, operation, &aad_bytes, iv, input_file, output_file, generated_key_hex
        );
    }

    // Handle IV based on operation and mode for non-GCM modes
    let (input_data, iv) = if mode_requires_iv {
        match operation {
            Operation::Encrypt => {
                // Generate random IV for encryption
                let iv_bytes = io::generate_iv();
                let input_data = io::read_file(&input_file)?;
                (input_data, Some(iv_bytes.to_vec()))
            }
            Operation::Decrypt => {
                // Use provided IV or read from file
                if let Some(provided_iv) = iv {
                    let input_data = io::read_file(&input_file)?;
                    (input_data, Some(provided_iv))
                } else {
                    // Read IV from beginning of file
                    let (input_data, file_iv) = io::read_file_with_iv(&input_file)?;
                    (input_data, file_iv)
                }
            }
        }
    } else {
        // ECB mode doesn't use IV
        let input_data = io::read_file(&input_file)?;
        (input_data, None)
    };

    // Create cipher
    let cipher = crypto::create_cipher(
        &algorithm,
        &mode,
        &key,  // Use the extracted key
        iv.as_deref(),
    )?;

    // Perform operation
    let output_data = match operation {
        Operation::Encrypt => cipher.encrypt(&input_data)?,
        Operation::Decrypt => cipher.decrypt(&input_data)?,
    };

    // Determine output path
    let output_path = output_file
        .unwrap_or_else(|| io::derive_output_path(&input_file, &operation));

    // Write output file (with IV for encryption in modes that use IV)
    if mode_requires_iv && operation == Operation::Encrypt {
        if let Some(ref iv_ref) = iv {
            io::write_file_with_iv(&output_path, iv_ref, &output_data)?;
        } else {
            io::write_file(&output_path, &output_data)?;
        }
    } else {
        io::write_file(&output_path, &output_data)?;
    }

    println!("Operation completed successfully!");
    println!("Output: {}", output_path.display());
    
    // Print key info if it was generated
    if let Some(key_hex) = generated_key_hex {
        println!("Important: Save this key for decryption: {}", key_hex);
    }

    // Print IV info for encryption
    if mode_requires_iv && operation == Operation::Encrypt {
        if let Some(ref iv_ref) = iv {
            println!("IV (hex): {}", hex::encode(iv_ref));
            println!("Note: IV has been prepended to the output file");
        }
    }

    Ok(())
}

// NEW: Key derivation function
fn run_derive(
    password: Option<Vec<u8>>,
    password_file: Option<std::path::PathBuf>,
    password_env: Option<String>,
    salt: Option<Vec<u8>>,
    iterations: u32,
    length: usize,
    algorithm: String,
    output: Option<std::path::PathBuf>,
) -> Result<()> {
    // Get password bytes
    let password_bytes = password.unwrap_or_else(|| {
        // This should not happen as we validated in CLI parser
        eprintln!("Error: No password provided");
        std::process::exit(1);
    });
    
    // Generate or use provided salt
    let salt_bytes = if let Some(s) = salt {
        s
    } else {
        // Generate random 16-byte salt
        println!("Generating random 16-byte salt...");
        crypto::kdf::Pbkdf2::generate_salt(16)?
    };
    
    // Display parameters
    println!("Key Derivation Parameters:");
    println!("  Algorithm: {}", algorithm);
    println!("  Iterations: {}", iterations);
    println!("  Key Length: {} bytes ({} bits)", length, length * 8);
    println!("  Salt Length: {} bytes", salt_bytes.len());
    println!("  Salt (hex): {}", hex::encode(&salt_bytes));
    
    // Measure performance
    let start = std::time::Instant::now();
    
    // Derive key using PBKDF2
    let derived_key = if algorithm.to_lowercase() == "pbkdf2" {
        crypto::kdf::Pbkdf2::derive_key(&password_bytes, &salt_bytes, iterations, length)?
    } else {
        return Err(CryptoCoreError::ConfigError(
            format!("Unsupported KDF algorithm: {}", algorithm)
        ));
    };
    
    let duration = start.elapsed();
    
    // Display results
    println!("\nDerivation completed in {:.3} seconds", duration.as_secs_f64());
    println!("Derived Key (hex): {}", hex::encode(&derived_key));
    println!("Output Format: KEY_HEX SALT_HEX");
    
    // If output file specified, write key as binary
    if let Some(output_path) = output {
        io::write_file(&output_path, &derived_key)?;
        println!("Key written to: {} (binary format)", output_path.display());
    } else {
        // Print to stdout in required format: KEY_HEX SALT_HEX
        println!("{} {}", hex::encode(&derived_key), hex::encode(&salt_bytes));
    }
    
    // Security: Clear sensitive data from memory
    let mut password_mut = password_bytes;
    let mut salt_mut = salt_bytes.clone();
    let mut key_mut = derived_key;
    
    crypto::kdf::utils::secure_zero_memory(&mut password_mut);
    crypto::kdf::utils::secure_zero_memory(&mut salt_mut);
    crypto::kdf::utils::secure_zero_memory(&mut key_mut);
    
    // Add security recommendations
    println!("\nSecurity Recommendations:");
    if iterations < 100000 {
        println!("  ⚠️  Warning: Iteration count {} is below recommended minimum of 100,000", iterations);
        println!("  Consider increasing iterations for better security against brute-force attacks");
    }
    if salt_bytes.len() < 16 {
        println!("  ⚠️  Warning: Salt length {} bytes is below recommended 16 bytes", salt_bytes.len());
    }
    if length < 32 {
        println!("  ⚠️  Warning: Key length {} bytes is below recommended 32 bytes (256 bits)", length);
    }
    
    Ok(())
}

fn run_gcm_operation(
    key: &[u8],
    operation: Operation,
    aad: &[u8],
    iv: Option<Vec<u8>>,
    input_file: std::path::PathBuf,
    output_file: Option<std::path::PathBuf>,
    generated_key_hex: Option<String>,
) -> Result<()> {
    use cryptocore::core::crypto::modes::gcm::Gcm;
    
    // Create GCM instance
    let gcm = Gcm::new(key)?;
    
    // Determine output path
    let output_path = output_file
        .unwrap_or_else(|| io::derive_output_path(&input_file, &operation));
    
    match operation {
        Operation::Encrypt => {
            // Generate or use provided nonce
            let nonce = if let Some(provided_nonce) = iv {
                if provided_nonce.len() != 12 {
                    return Err(CryptoCoreError::ConfigError(
                        "GCM nonce must be 12 bytes".to_string()
                    ));
                }
                provided_nonce
            } else {
                // Generate random 12-byte nonce
                let nonce_bytes = Gcm::generate_nonce();
                nonce_bytes.to_vec()
            };
            
            println!("GCM Encryption with {} bytes of AAD", aad.len());
            if !aad.is_empty() {
                println!("AAD (hex): {}", hex::encode(aad));
            }
            println!("Nonce (hex): {}", hex::encode(&nonce));
            
            // Read input file
            let plaintext = io::read_file(&input_file)?;
            
            // Encrypt with GCM
            let (ciphertext, tag) = gcm.encrypt(&plaintext, aad, &nonce)?;
            
            // Combine nonce + ciphertext + tag for output
            let mut output_data = Vec::with_capacity(nonce.len() + ciphertext.len() + tag.len());
            output_data.extend_from_slice(&nonce);
            output_data.extend_from_slice(&ciphertext);
            output_data.extend_from_slice(&tag);
            
            // Write output file
            io::write_file(&output_path, &output_data)?;
            
            println!("Encryption completed successfully!");
            println!("Output: {}", output_path.display());
            println!("Tag (hex): {}", hex::encode(&tag));
            println!("Format: [12-byte nonce] || [ciphertext] || [16-byte tag]");
        }
        
        Operation::Decrypt => {
            println!("GCM Decryption with {} bytes of AAD", aad.len());
            if !aad.is_empty() {
                println!("AAD (hex): {}", hex::encode(aad));
            }
            
            // Read input file
            let encrypted_data = io::read_file(&input_file)?;
            
            if encrypted_data.len() < 12 + 16 {  // Need at least nonce + tag
                return Err(CryptoCoreError::FileError(
                    "Input file too short for GCM format".to_string()
                ));
            }
            
            // Parse: nonce (12 bytes) || ciphertext || tag (16 bytes)
            let nonce = &encrypted_data[..12];
            let tag_start = encrypted_data.len() - 16;
            let tag = &encrypted_data[tag_start..];
            let ciphertext = &encrypted_data[12..tag_start];
            
            // Use provided nonce (if any) instead of reading from file
            let decryption_nonce = iv.as_deref().unwrap_or(nonce);
            
            println!("Nonce from file (hex): {}", hex::encode(nonce));
            println!("Tag from file (hex): {}", hex::encode(tag));
            
            if let Some(provided_nonce) = &iv {
                println!("Using provided nonce instead of file nonce");
                println!("Provided nonce (hex): {}", hex::encode(provided_nonce));
            }
            
            // Try to decrypt with catastrophic failure on authentication error
            match gcm.decrypt(ciphertext, aad, decryption_nonce, tag) {
                Ok(plaintext) => {
                    // Authentication successful, write output
                    io::write_file(&output_path, &plaintext)?;
                    
                    println!("[OK] Decryption completed successfully!");
                    println!("Output: {}", output_path.display());
                }
                Err(e) => {
                    // Authentication failed - catastrophic failure
                    eprintln!("[ERROR] Authentication failed: {}", e);
                    eprintln!("Possible causes: wrong key, wrong AAD, tampered ciphertext, or wrong nonce");
                    
                    // Clean up output file if it was created
                    if output_path.exists() {
                        let _ = std::fs::remove_file(&output_path);
                    }
                    
                    return Err(e);
                }
            }
        }
    }
    
    // Print key info if it was generated
    if let Some(key_hex) = generated_key_hex {
        println!("Important: Save this key for decryption: {}", key_hex);
    }
    
    Ok(())
}

fn run_digest(
    algorithm: String,
    input_file: std::path::PathBuf,
    output_file: Option<std::path::PathBuf>,
    hmac: bool,
    key: Option<Vec<u8>>,
    verify: Option<std::path::PathBuf>,
    cmac: bool,
) -> Result<()> {
    if hmac || cmac {
        let key = key.ok_or(CryptoCoreError::ConfigError(
            "Key is required for HMAC/CMAC".to_string()
        ))?;
        
        let mac_type = if hmac { "hmac" } else { "cmac" };
        
        // Validate key length for CMAC
        if cmac && key.len() != 16 {
            return Err(CryptoCoreError::ConfigError(
                "AES-CMAC requires exactly 16-byte key".to_string()
            ));
        }
        
        // Compute MAC
        let mac = crypto::mac::Mac::new(mac_type, &key)?;
        let mac_value = mac.compute_file(&input_file)?;
        let mac_hex = hex::encode(&mac_value);
        
        // Verify if requested
        if let Some(verify_file) = verify {
            let expected_content = fs::read_to_string(&verify_file)
                .map_err(|e| CryptoCoreError::FileError(format!("Failed to read verify file: {}", e)))?;
            
            // Parse expected MAC (format: MAC_VALUE INPUT_FILE_PATH)
            let expected_parts: Vec<&str> = expected_content.split_whitespace().collect();
            let expected_mac_hex = expected_parts.get(0)
                .ok_or(CryptoCoreError::ConfigError("Invalid MAC file format".to_string()))?;
            
            // Decode hex to bytes for comparison
            let expected_mac = hex::decode(expected_mac_hex)
                .map_err(|e| CryptoCoreError::HexError(e))?;
            
            let is_valid = mac.verify_file(&input_file, &expected_mac)?;
            
            if is_valid {
                println!("[OK] {} verification successful", 
                         if hmac { "HMAC" } else { "CMAC" });
                std::process::exit(0);
            } else {
                eprintln!("[ERROR] {} verification failed", 
                          if hmac { "HMAC" } else { "CMAC" });
                std::process::exit(1);
            }
        } else {
            // Output MAC
            let mac_name = if hmac { "HMAC" } else { "CMAC" };
            let output_text = format!("{}  {}", mac_hex, input_file.display());
            
            if let Some(output_path) = output_file {
                io::write_file(&output_path, output_text.as_bytes())?;
                println!("{} written to: {}", mac_name, output_path.display());
            } else {
                println!("{}", output_text);
            }
            
            // Additional info for CMAC
            if cmac {
                println!("Note: CMAC uses AES-128 with 16-byte key");
            }
        }
    } else {
        // Regular hash (existing code)
        let hash_algorithm = hash::HashAlgorithm::from_str(&algorithm)?;
        let hash_value = hash_algorithm.compute_file_hash(&input_file)?;
        
        let output_text = format!("{}  {}", hash_value, input_file.display());
        
        if let Some(output_path) = output_file {
            io::write_file(&output_path, output_text.as_bytes())?;
            println!("Hash written to: {}", output_path.display());
        } else {
            println!("{}", output_text);
        }
    }
    
    Ok(())
}
