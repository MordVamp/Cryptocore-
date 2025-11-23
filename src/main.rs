use cryptocore::{cli, Operation, Result};
use cryptocore::core::{io, crypto};
use cryptocore::{CryptoCoreError};  // Added CryptoCoreError
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
    let mode_requires_iv = !matches!(config.mode.to_lowercase().as_str(), "ecb");
    
    // Fix: Proper key handling with pattern matching
    let (key, generated_key_hex) = match &config.key {
        Some(provided_key) => (provided_key.clone(), None),
        None => {
            if config.operation == Operation::Encrypt {
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
        match config.operation {
            Operation::Encrypt => {
                // Generate random IV for encryption
                let iv_bytes = io::generate_iv();
                let input_data = io::read_file(&config.input_file)?;
                (input_data, Some(iv_bytes.to_vec()))
            }
            Operation::Decrypt => {
                // Use provided IV or read from file
                if let Some(provided_iv) = config.iv {
                    let input_data = io::read_file(&config.input_file)?;
                    (input_data, Some(provided_iv))
                } else {
                    // Read IV from beginning of file
                    let (input_data, file_iv) = io::read_file_with_iv(&config.input_file)?;
                    (input_data, file_iv)
                }
            }
        }
    } else {
        // ECB mode doesn't use IV
        let input_data = io::read_file(&config.input_file)?;
        (input_data, None)
    };

    // Create cipher
    let cipher = crypto::create_cipher(
        &config.algorithm,
        &config.mode,
        &key,  // Use the extracted key
        iv.as_deref(),
    )?;

    // Perform operation
    let output_data = match config.operation {
        Operation::Encrypt => cipher.encrypt(&input_data)?,
        Operation::Decrypt => cipher.decrypt(&input_data)?,
    };

    // Determine output path
    let output_path = config.output_file
        .unwrap_or_else(|| io::derive_output_path(&config.input_file, &config.operation));

    // Write output file (with IV for encryption in modes that use IV)
    if mode_requires_iv && config.operation == Operation::Encrypt {
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
    if mode_requires_iv && config.operation == Operation::Encrypt {
        if let Some(ref iv_ref) = iv {
            println!("IV (hex): {}", hex::encode(iv_ref));
            println!("Note: IV has been prepended to the output file");
        }
    }

    Ok(())
}
