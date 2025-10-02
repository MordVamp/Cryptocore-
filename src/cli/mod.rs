use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;

#[derive(Debug)]
pub struct CliConfig {
    pub algorithm: String,
    pub mode: String,
    pub operation: Operation,
    pub key: Vec<u8>,
    pub input_file: PathBuf,
    pub output_file: Option<PathBuf>,
}

#[derive(Debug, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

pub fn parse_args() -> Result<CliConfig, Box<dyn std::error::Error>> {
    let matches = Command::new("cryptocore")
        .version("0.1.0")
        .about("Cryptographic tool for block cipher operations")
        .arg(
            Arg::new("algorithm")
                .long("algorithm")
                .value_name("ALGORITHM")
                .required(true)
                .value_parser(["aes"])
                .help("Cryptographic algorithm (currently only 'aes')"),
        )
        .arg(
            Arg::new("mode")
                .long("mode")
                .value_name("MODE")
                .required(true)
                .value_parser(["ecb"])
                .help("Mode of operation (currently only 'ecb')"),
        )
        .arg(
            Arg::new("encrypt")
                .long("encrypt")
                .action(ArgAction::SetTrue)
                .conflicts_with("decrypt")
                .help("Perform encryption"),
        )
        .arg(
            Arg::new("decrypt")
                .long("decrypt")
                .action(ArgAction::SetTrue)
                .conflicts_with("encrypt")
                .help("Perform decryption"),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .value_name("KEY")
                .required(true)
                .value_parser(parse_key)
                .help("Encryption key as hexadecimal string (e.g., @00112233445566778899aabbccddeeff)"),
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

    // Validate operation
    let encrypt = matches.get_flag("encrypt");
    let decrypt = matches.get_flag("decrypt");
    
    if !encrypt && !decrypt {
        return Err("Either --encrypt or --decrypt must be specified".into());
    }

    let operation = if encrypt { Operation::Encrypt } else { Operation::Decrypt };

    let config = CliConfig {
        algorithm: matches.get_one::<String>("algorithm").unwrap().to_string(),
        mode: matches.get_one::<String>("mode").unwrap().to_string(),
        operation,
        key: matches.get_one::<Vec<u8>>("key").unwrap().clone(),
        input_file: matches.get_one::<PathBuf>("input").unwrap().clone(),
        output_file: matches.get_one::<PathBuf>("output").cloned(),
    };

    Ok(config)
}

fn parse_key(s: &str) -> Result<Vec<u8>, String> {
    let key_str = s.trim_start_matches('@');
    
    if key_str.len() != 32 {
        return Err("Key must be 16 bytes (32 hex characters)".into());
    }

    hex::decode(key_str)
        .map_err(|e| format!("Invalid hex string: {}", e))
}