# CryptoCore

A command-line tool for cryptographic operations using block ciphers in ECB mode.

## Features

- AES-128 encryption and decryption
- Modes: ECB, CBC, CFB, OFB, CTR
- PKCS#7 padding
- Hexadecimal key input
- File-based I/O


### Prerequisites

- Rust 1.70 or higher
- Cargo (Rust's package manager)

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd cryptocore

# Build the project
cargo build --release

# The binary will be available at target/release/cryptocore

# Some basic usage examples

./target/release/cryptocore --algorithm aes --mode ecb --encrypt     --key @00102030405060708090a0b0c0d0e00f     --input plaintext.txt     --output ciphertext.bin

./target/release/cryptocore --algorithm aes --mode ecb --decrypt     --key @00102030405060708090a0b0c0d0e00f     --input ciphertext.bin     --output decrypted.txt