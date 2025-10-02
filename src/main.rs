use cryptocore::{cli,Result};
use cryptocore::core::{io,crypto};

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
    // Read input file
    let input_data = io::read_file(&config.input_file)?;

    // Create cipher
    let mut cipher = crypto::create_cipher(&config.algorithm, &config.key)?;

    // Perform operation
    let output_data = match config.operation {
        cli::Operation::Encrypt => cipher.encrypt(&input_data)?,
        cli::Operation::Decrypt => cipher.decrypt(&input_data)?,
    };

    // Determine output path
    let output_path = config.output_file
        .unwrap_or_else(|| io::derive_output_path(&config.input_file, &config.operation));

    // Write output file
    io::write_file(&output_path, &output_data)?;

    println!("Operation completed successfully!");
    println!("Output: {}", output_path.display());

    Ok(())
}