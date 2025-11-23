use cryptocore::{cli, Operation, Result, CryptoCoreError};
use cryptocore::core::{io, crypto, crypto::hash};

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
        cli::OperationType::EncryptDecrypt { algorithm, mode, operation, key, iv, input_file, output_file } => {
            run_encryption(algorithm, mode, operation, key, iv, input_file, output_file)
        }
        cli::OperationType::Digest { algorithm, input_file, output_file } => {
            run_digest(algorithm, input_file, output_file)
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
) -> Result<()> {
    let mode_requires_iv = !matches!(mode.to_lowercase().as_str(), "ecb");
    
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

    // Handle IV based on operation and mode
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

// New hash function
fn run_digest(
    algorithm: String,
    input_file: std::path::PathBuf,
    output_file: Option<std::path::PathBuf>,
) -> Result<()> {
    let hash_algorithm = hash::HashAlgorithm::from_str(&algorithm)?;
    let hash_value = hash_algorithm.compute_file_hash(&input_file)?;
    
    let output_text = format!("{}  {}", hash_value, input_file.display());
    
    if let Some(output_path) = output_file {
        io::write_file(&output_path, output_text.as_bytes())?;
        println!("Hash written to: {}", output_path.display());
    } else {
        println!("{}", output_text);
    }
    
    Ok(())
}