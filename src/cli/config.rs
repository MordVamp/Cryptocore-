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
        aad: Option<Vec<u8>>,
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
    Derive {
        password: Option<Vec<u8>>,
        password_file: Option<PathBuf>,
        password_env: Option<String>,
        salt: Option<Vec<u8>>,
        iterations: u32,
        length: usize,
        algorithm: String,
        output: Option<PathBuf>,
    },
}

pub fn parse_args() -> Result<CliConfig, Box<dyn std::error::Error>> {
    let matches = Command::new("cryptocore")
        .version("0.1.0")
        .about("Cryptographic tool for encryption and hashing operations")
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a file")
                .arg(Arg::new("algorithm")
                    .long("algorithm")
                    .value_name("ALGORITHM")
                    .required(true)
                    .help("Encryption algorithm (aes)"))
                .arg(Arg::new("mode")
                    .long("mode")
                    .value_name("MODE")
                    .required(true)
                    .help("Encryption mode (ecb, cbc, cfb, ofb, ctr, gcm)"))
                .arg(Arg::new("key")
                    .long("key")
                    .value_name("KEY")
                    .value_parser(parse_key_hex)
                    .help("Encryption key as hex string (16, 24, or 32 bytes for AES)"))
                .arg(Arg::new("iv")
                    .long("iv")
                    .value_name("IV")
                    .value_parser(parse_iv)
                    .help("IV/nonce as hex string (16 bytes for modes except GCM, 12 bytes for GCM)"))
                .arg(Arg::new("aad")
                    .long("aad")
                    .value_name("AAD")
                    .value_parser(parse_aad)
                    .help("Additional authenticated data for GCM mode (hex string)"))
                .arg(Arg::new("input")
                    .long("input")
                    .value_name("INPUT_FILE")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Input file to encrypt"))
                .arg(Arg::new("output")
                    .long("output")
                    .value_name("OUTPUT_FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Output file (default: input.enc)"))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt a file")
                .arg(Arg::new("algorithm")
                    .long("algorithm")
                    .value_name("ALGORITHM")
                    .required(true)
                    .help("Encryption algorithm (aes)"))
                .arg(Arg::new("mode")
                    .long("mode")
                    .value_name("MODE")
                    .required(true)
                    .help("Encryption mode (ecb, cbc, cfb, ofb, ctr, gcm)"))
                .arg(Arg::new("key")
                    .long("key")
                    .value_name("KEY")
                    .value_parser(parse_key_hex)
                    .required(true)
                    .help("Encryption key as hex string"))
                .arg(Arg::new("iv")
                    .long("iv")
                    .value_name("IV")
                    .value_parser(parse_iv)
                    .help("IV/nonce as hex string (required if not in file)"))
                .arg(Arg::new("aad")
                    .long("aad")
                    .value_name("AAD")
                    .value_parser(parse_aad)
                    .help("Additional authenticated data for GCM mode (hex string)"))
                .arg(Arg::new("input")
                    .long("input")
                    .value_name("INPUT_FILE")
                    .required(true)
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Input file to decrypt"))
                .arg(Arg::new("output")
                    .long("output")
                    .value_name("OUTPUT_FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Output file (default: input.dec)"))
        )
        .subcommand(
            Command::new("mac")
                .about("Message Authentication Codes")
                .subcommand(
                    Command::new("hmac")
                        .about("Generate or verify HMAC")
                        .arg(Arg::new("key")
                            .long("key")
                            .value_name("KEY")
                            .value_parser(parse_key_hex)
                            .required(true)
                            .help("Key as hex string (any length for HMAC)"))
                        .arg(Arg::new("algorithm")
                            .long("algorithm")
                            .value_name("ALGORITHM")
                            .default_value("sha256")
                            .help("Hash algorithm (sha256)"))
                        .arg(Arg::new("input")
                            .long("input")
                            .value_name("INPUT_FILE")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf))
                            .help("Input file"))
                        .arg(Arg::new("output")
                            .long("output")
                            .value_name("OUTPUT_FILE")
                            .value_parser(clap::value_parser!(PathBuf))
                            .help("Output file for MAC"))
                        .arg(Arg::new("verify")
                            .long("verify")
                            .value_name("MAC_FILE")
                            .value_parser(clap::value_parser!(PathBuf))
                            .help("Verify against MAC file"))
                )
                .subcommand(
                    Command::new("cmac")
                        .about("Generate or verify CMAC")
                        .arg(Arg::new("key")
                            .long("key")
                            .value_name("KEY")
                            .value_parser(parse_key_hex)
                            .required(true)
                            .help("Key as hex string (must be 16 bytes for CMAC)"))
                        .arg(Arg::new("input")
                            .long("input")
                            .value_name("INPUT_FILE")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf))
                            .help("Input file"))
                        .arg(Arg::new("output")
                            .long("output")
                            .value_name("OUTPUT_FILE")
                            .value_parser(clap::value_parser!(PathBuf))
                            .help("Output file for MAC"))
                        .arg(Arg::new("verify")
                            .long("verify")
                            .value_name("MAC_FILE")
                            .value_parser(clap::value_parser!(PathBuf))
                            .help("Verify against MAC file"))
                )
        )
        .subcommand(
            Command::new("derive")
                .about("Key derivation")
                .arg(Arg::new("password")
                    .long("password")
                    .value_name("PASSWORD")
                    .help("Password string for key derivation"))
                .arg(Arg::new("password-file")
                    .long("password-file")
                    .value_name("PASSWORD_FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("File containing password for key derivation"))
                .arg(Arg::new("password-env")
                    .long("password-env")
                    .value_name("PASSWORD_ENV")
                    .help("Environment variable containing password for key derivation"))
                .arg(Arg::new("salt")
                    .long("salt")
                    .value_name("SALT")
                    .value_parser(parse_key_hex)
                    .help("Salt as hexadecimal string for key derivation"))
                .arg(Arg::new("iterations")
                    .long("iterations")
                    .value_name("ITERATIONS")
                    .value_parser(clap::value_parser!(u32))
                    .default_value("100000")
                    .help("Iteration count for key derivation"))
                .arg(Arg::new("length")
                    .long("length")
                    .value_name("LENGTH")
                    .value_parser(clap::value_parser!(usize))
                    .default_value("32")
                    .help("Derived key length in bytes"))
                .arg(Arg::new("algorithm")
                    .long("algorithm")
                    .value_name("KDF_ALGORITHM")
                    .value_parser(["pbkdf2"])
                    .default_value("pbkdf2")
                    .help("Key derivation algorithm"))
                .arg(Arg::new("output")
                    .long("output")
                    .value_name("OUTPUT_FILE")
                    .value_parser(clap::value_parser!(PathBuf))
                    .help("Output file for derived key"))
        )
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let algorithm = sub_matches.get_one::<String>("algorithm").unwrap().to_string();
            let mode = sub_matches.get_one::<String>("mode").unwrap().to_string();
            
            // Validate algorithm
            if algorithm != "aes" {
                return Err("For encryption, algorithm must be 'aes'".into());
            }
            
            let key = sub_matches.get_one::<Vec<u8>>("key").cloned();
            let iv = sub_matches.get_one::<Vec<u8>>("iv").cloned();
            let aad = sub_matches.get_one::<Vec<u8>>("aad").cloned();
            
            Ok(CliConfig {
                operation_type: OperationType::EncryptDecrypt {
                    algorithm,
                    mode,
                    operation: Operation::Encrypt,
                    key,
                    iv,
                    input_file: sub_matches.get_one::<PathBuf>("input").unwrap().clone(),
                    output_file: sub_matches.get_one::<PathBuf>("output").cloned(),
                    aad,
                }
            })
        }
        Some(("decrypt", sub_matches)) => {
            let algorithm = sub_matches.get_one::<String>("algorithm").unwrap().to_string();
            let mode = sub_matches.get_one::<String>("mode").unwrap().to_string();
            
            if algorithm != "aes" {
                return Err("For decryption, algorithm must be 'aes'".into());
            }
            
            let key = sub_matches.get_one::<Vec<u8>>("key").cloned()
                .ok_or("Key is required for decryption")?;
            let iv = sub_matches.get_one::<Vec<u8>>("iv").cloned();
            let aad = sub_matches.get_one::<Vec<u8>>("aad").cloned();
            
            Ok(CliConfig {
                operation_type: OperationType::EncryptDecrypt {
                    algorithm,
                    mode,
                    operation: Operation::Decrypt,
                    key: Some(key),
                    iv,
                    input_file: sub_matches.get_one::<PathBuf>("input").unwrap().clone(),
                    output_file: sub_matches.get_one::<PathBuf>("output").cloned(),
                    aad,
                }
            })
        }
        Some(("mac", mac_matches)) => {
            match mac_matches.subcommand() {
                Some(("hmac", hmac_matches)) => {
                    let algorithm = hmac_matches.get_one::<String>("algorithm").unwrap().to_string();
                    let key = hmac_matches.get_one::<Vec<u8>>("key").cloned()
                        .ok_or("Key is required for HMAC")?;
                    let verify = hmac_matches.get_one::<PathBuf>("verify").cloned();
                    
                    Ok(CliConfig {
                        operation_type: OperationType::Digest {
                            algorithm,
                            input_file: hmac_matches.get_one::<PathBuf>("input").unwrap().clone(),
                            output_file: hmac_matches.get_one::<PathBuf>("output").cloned(),
                            hmac: true,
                            key: Some(key),
                            verify,
                            cmac: false,
                        }
                    })
                }
                Some(("cmac", cmac_matches)) => {
                    let key = cmac_matches.get_one::<Vec<u8>>("key").cloned()
                        .ok_or("Key is required for CMAC")?;
                    
                    // Validate key length for CMAC
                    if key.len() != 16 {
                        return Err("AES-CMAC requires exactly 16-byte key".into());
                    }
                    
                    let verify = cmac_matches.get_one::<PathBuf>("verify").cloned();
                    
                    Ok(CliConfig {
                        operation_type: OperationType::Digest {
                            algorithm: "sha256".to_string(), // CMAC uses AES, not SHA
                            input_file: cmac_matches.get_one::<PathBuf>("input").unwrap().clone(),
                            output_file: cmac_matches.get_one::<PathBuf>("output").cloned(),
                            hmac: false,
                            key: Some(key),
                            verify,
                            cmac: true,
                        }
                    })
                }
                _ => Err("Must specify 'hmac' or 'cmac' subcommand".into())
            }
        }
        Some(("derive", derive_matches)) => {
            // Handle password input
            let password = if let Some(pass) = derive_matches.get_one::<String>("password") {
                Some(pass.as_bytes().to_vec())
            } else if let Some(file) = derive_matches.get_one::<PathBuf>("password-file") {
                Some(std::fs::read(file).map_err(|e| format!("Failed to read password file: {}", e))?)
            } else if let Some(env_var) = derive_matches.get_one::<String>("password-env") {
                Some(std::env::var(env_var)
                    .map_err(|e| format!("Failed to read environment variable {}: {}", env_var, e))?
                    .as_bytes()
                    .to_vec())
            } else {
                return Err("One of --password, --password-file, or --password-env must be specified".into());
            };
            
            Ok(CliConfig {
                operation_type: OperationType::Derive {
                    password,
                    password_file: derive_matches.get_one::<PathBuf>("password-file").cloned(),
                    password_env: derive_matches.get_one::<String>("password-env").cloned(),
                    salt: derive_matches.get_one::<Vec<u8>>("salt").cloned(),
                    iterations: *derive_matches.get_one::<u32>("iterations").unwrap_or(&100000),
                    length: *derive_matches.get_one::<usize>("length").unwrap_or(&32),
                    algorithm: derive_matches.get_one::<String>("algorithm").unwrap().to_string(),
                    output: derive_matches.get_one::<PathBuf>("output").cloned(),
                }
            })
        }
        _ => Err("Must specify one of: encrypt, decrypt, mac, derive".into())
    }
}

fn parse_key_hex(s: &str) -> Result<Vec<u8>, String> {
    let key_str = s.trim_start_matches('@');
    hex::decode(key_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

fn parse_iv(s: &str) -> Result<Vec<u8>, String> {
    let iv_str = s.trim_start_matches('@');
    hex::decode(iv_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}

fn parse_aad(s: &str) -> Result<Vec<u8>, String> {
    let aad_str = s.trim_start_matches('@');
    hex::decode(aad_str)
        .map_err(|e| format!("Invalid hex string for AAD: {}", e))
}