use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use crate::Operation;

#[derive(Debug)]
pub struct CliConfig {
    pub operation_type: OperationType,
}

#[derive(Debug)]
pub enum OperationType {
    EncryptDecrypt {
        algorithm: String,
        mode: String,
        operation: Operation,
        key: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
        input_file: PathBuf,
        output_file: Option<PathBuf>,
    },
    Digest {
        algorithm: String,
        input_file: PathBuf,
        output_file: Option<PathBuf>,
    },
}

pub fn parse_args() -> Result<CliConfig, Box<dyn std::error::Error>> {
    let matches = Command::new("cryptocore")
        .version("0.1.0")
        .about("Cryptographic tool for encryption and hashing operations")
        .arg(
            Arg::new("algorithm")
                .long("algorithm")
                .value_name("ALGORITHM")
                .required(true)
                .value_parser(["aes", "sha256", "sha3-256"])
                .help("Cryptographic algorithm (aes for encryption, sha256/sha3-256 for hashing)"),
        )
        .arg(
            Arg::new("mode")
                .long("mode")
                .value_name("MODE")
                .required(false)
                .value_parser(["ecb", "cbc", "cfb", "ofb", "ctr"])
                .help("Mode of operation (for encryption only)"),
        )
        .arg(
            Arg::new("encrypt")
                .long("encrypt")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(&["decrypt", "dgst"])
                .help("Perform encryption"),
        )
        .arg(
            Arg::new("decrypt")
                .long("decrypt")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(&["encrypt", "dgst"])
                .help("Perform decryption"),
        )
        .arg(
            Arg::new("dgst")
                .long("dgst")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(&["encrypt", "decrypt", "mode", "key", "iv"])
                .help("Compute message digest (hash)"),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .value_name("KEY")
                .required(false)
                .value_parser(parse_key)
                .help("Encryption key as hexadecimal string (optional for encryption)"),
        )
        .arg(
            Arg::new("iv")
                .long("iv")
                .value_name("IV")
                .value_parser(parse_iv)
                .help("Initialization vector as hexadecimal string (for decryption only)"),
        )
        .arg(
            Arg::new("input")
                .long("input")
                .value_name("INPUT_FILE")
                .required(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Input file path"),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("OUTPUT_FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Output file path (optional)"),
        )
        .get_matches();

    // Determine operation type
    if matches.get_flag("dgst") {
        // Hash operation
        let algorithm = matches.get_one::<String>("algorithm").unwrap().to_string();
        
        if !["sha256", "sha3-256"].contains(&algorithm.as_str()) {
            return Err("For hashing, algorithm must be sha256 or sha3-256".into());
        }

        Ok(CliConfig {
            operation_type: OperationType::Digest {
                algorithm,
                input_file: matches.get_one::<PathBuf>("input").unwrap().clone(),
                output_file: matches.get_one::<PathBuf>("output").cloned(),
            }
        })
    } else {
        // Encryption/decryption operation
        let operation = if matches.get_flag("encrypt") {
            Operation::Encrypt
        } else if matches.get_flag("decrypt") {
            Operation::Decrypt
        } else {
            return Err("Either --encrypt, --decrypt, or --dgst must be specified".into());
        };

        let algorithm = matches.get_one::<String>("algorithm").unwrap().to_string();
        
        if algorithm != "aes" {
            return Err("For encryption/decryption, algorithm must be 'aes'".into());
        }

        let mode = matches.get_one::<String>("mode")
            .ok_or("Mode is required for encryption/decryption")?
            .to_string();

        // Validate key usage
        let key = matches.get_one::<Vec<u8>>("key").cloned();
        if key.is_none() && operation == Operation::Decrypt {
            return Err("Key is required for decryption".into());
        }

        // Validate IV usage
        let iv = matches.get_one::<Vec<u8>>("iv").cloned();
        if let Some(ref _iv_vec) = iv {
            if operation == Operation::Encrypt {
                eprintln!("Warning: --iv is ignored during encryption. Using randomly generated IV.");
            }
        }

        Ok(CliConfig {
            operation_type: OperationType::EncryptDecrypt {
                algorithm,
                mode,
                operation,
                key,
                iv,
                input_file: matches.get_one::<PathBuf>("input").unwrap().clone(),
                output_file: matches.get_one::<PathBuf>("output").cloned(),
            }
        })
    }
}

fn parse_key(s: &str) -> Result<Vec<u8>, String> {
    let key_str = s.trim_start_matches('@');
    
    if key_str.len() != 32 {
        return Err("Key must be 16 bytes (32 hex characters)".into());
    }

    hex::decode(key_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

fn parse_iv(s: &str) -> Result<Vec<u8>, String> {
    let iv_str = s.trim_start_matches('@');
    
    if iv_str.len() != 32 {
        return Err("IV must be 16 bytes (32 hex characters)".into());
    }

    hex::decode(iv_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}