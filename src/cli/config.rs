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
        aad: Option<Vec<u8>>,  // Add AAD field
    },
    Digest {
        algorithm: String,
        input_file: PathBuf,
        output_file: Option<PathBuf>,
        hmac: bool,
        key: Option<Vec<u8>>,
        verify: Option<PathBuf>,
        cmac: bool,
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
                .value_parser(["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"])  // Add "gcm"
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
                .conflicts_with_all(&["encrypt", "decrypt", "mode"])
                .help("Compute message digest (hash)"),
        )
        .arg(
            Arg::new("hmac")
                .long("hmac")
                .action(ArgAction::SetTrue)
                .requires("key")
                .conflicts_with("cmac")
                .help("Enable HMAC mode"),
        )
        .arg(
            Arg::new("cmac")
                .long("cmac")
                .action(ArgAction::SetTrue)
                .requires("key")
                .conflicts_with("hmac")
                .help("Enable AES-CMAC mode (bonus)"),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .value_name("KEY")
                .required(false)
                .value_parser(parse_key_hex)
                .help("Key as hexadecimal string (for HMAC/CMAC or encryption)"),
        )
        .arg(
            Arg::new("iv")
                .long("iv")
                .value_name("IV")
                .value_parser(parse_iv)
                .help("Initialization vector as hexadecimal string (for encryption only)"),
        )
        .arg(
            Arg::new("aad")  // NEW: Associated Data argument
                .long("aad")
                .value_name("AAD")
                .required(false)
                .value_parser(parse_aad)
                .help("Associated Data as hexadecimal string (for GCM mode only)"),
        )
        .arg(
            Arg::new("verify")
                .long("verify")
                .value_name("VERIFY_FILE")
                .value_parser(clap::value_parser!(PathBuf))
                .help("File containing expected HMAC for verification"),
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
        let hmac = matches.get_flag("hmac");
        let cmac = matches.get_flag("cmac");
        let key = matches.get_one::<Vec<u8>>("key").cloned();
        let verify = matches.get_one::<PathBuf>("verify").cloned();
        
        // Validate
        if hmac || cmac {
            if !["sha256"].contains(&algorithm.as_str()) {
                return Err("For HMAC, algorithm must be sha256".into());
            }
            
            if key.is_none() {
                return Err("Key is required for HMAC/CMAC".into());
            }
        } else {
            if !["sha256", "sha3-256"].contains(&algorithm.as_str()) {
                return Err("For hashing, algorithm must be sha256 or sha3-256".into());
            }
        }

        Ok(CliConfig {
            operation_type: OperationType::Digest {
                algorithm,
                input_file: matches.get_one::<PathBuf>("input").unwrap().clone(),
                output_file: matches.get_one::<PathBuf>("output").cloned(),
                hmac,
                key,
                verify,
                cmac,
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

        // Get AAD for GCM mode
        let aad = matches.get_one::<Vec<u8>>("aad").cloned();
        
        // Validate AAD usage
        if aad.is_some() && mode != "gcm" {
            return Err("--aad is only supported for GCM mode".into());
        }
        
        if mode == "gcm" && operation == Operation::Decrypt && aad.is_none() {
            eprintln!("Warning: Decrypting GCM without --aad. If AAD was used during encryption, decryption will fail.");
        }

        // Validate key usage
        let key = matches.get_one::<Vec<u8>>("key").cloned();
        if key.is_none() && operation == Operation::Decrypt {
            return Err("Key is required for decryption".into());
        }

        // Validate IV usage based on mode
        let iv = matches.get_one::<Vec<u8>>("iv").cloned();
        
        // GCM-specific IV (nonce) validation
        if mode == "gcm" {
            if let Some(ref iv_vec) = iv {
                // For GCM, nonce should be 12 bytes (96 bits)
                if iv_vec.len() != 12 && !iv_vec.is_empty() {
                    return Err("For GCM mode, IV (nonce) must be 12 bytes (96 bits) or omitted for random generation".into());
                }
            }
            
            if operation == Operation::Encrypt && iv.is_some() {
                eprintln!("Warning: Providing --iv for GCM encryption is not recommended. Using provided nonce (security risk if reused!).");
            }
        } else {
            // For non-GCM modes, validate IV length
            if let Some(ref iv_vec) = iv {
                if iv_vec.len() != 16 {
                    return Err("IV must be 16 bytes for non-GCM modes".into());
                }
            }
        }

        // Warn about IV usage in encryption for non-GCM modes
        if let Some(ref _iv_vec) = iv {
            if operation == Operation::Encrypt && mode != "gcm" {
                eprintln!("Warning: --iv is ignored during encryption for non-GCM modes. Using randomly generated IV.");
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
                aad,  // Add AAD to the config
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

fn parse_key_hex(s: &str) -> Result<Vec<u8>, String> {
    let key_str = s.trim_start_matches('@');
    hex::decode(key_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

fn parse_iv(s: &str) -> Result<Vec<u8>, String> {
    let iv_str = s.trim_start_matches('@');
    
    // Accept different lengths for different modes
    if iv_str.len() != 24 && iv_str.len() != 32 {
        return Err("IV must be 12 bytes (24 hex chars) for GCM or 16 bytes (32 hex chars) for other modes".into());
    }

    hex::decode(iv_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

// NEW: Parse AAD (Associated Data)
fn parse_aad(s: &str) -> Result<Vec<u8>, String> {
    let aad_str = s.trim_start_matches('@');
    
    if aad_str.is_empty() {
        // Empty AAD is valid (treated as empty byte array)
        return Ok(Vec::new());
    }
    
    hex::decode(aad_str)
        .map_err(|e| format!("Invalid hex string for AAD: {}", e))
}