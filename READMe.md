A command-line tool for cryptographic operations using AES block cipher in multiple modes with secure random number generation.

## Features

- **AES-128** encryption and decryption
- **Modes**: ECB, CBC, CFB, OFB, CTR
- **PKCS#7** padding for block modes
- **Cryptographically Secure RNG** for keys and IVs
- **NIST-validated** random number generation
- File-based I/O with automatic IV handling
- Interoperability with OpenSSL

## Sprint 3 Updates - CSPRNG Integration

### Automatic Key Generation

The `--key` argument is now **optional for encryption**. When omitted, CryptoCore will:

1. Generate a secure 16-byte (128-bit) random key using a NIST-validated CSPRNG
2. Display the generated key in hexadecimal format
3. Proceed with encryption using the generated key

**Example:**
```bash
# Encryption with automatic key generation
./cryptocore --algorithm aes --mode ctr --encrypt \
    --input plaintext.txt \
    --output ciphertext.bin

# Output: Generated random key: 1a2b3c4d5e6f7890fedcba9876543210(examle)
# Important: Save this key for decryption!
```
### ----------------------
##### Additional info

### Key Requirements

- **Encryption**: `--key` is optional. If not provided, a secure random key is generated.
- **Decryption**: `--key` is **mandatory**. You must provide the key used for encryption.

### CSPRNG Security Properties

CryptoCore uses a hybrid CSPRNG approach:
- **Primary Entropy Source**: System entropy from `getrandom` crate (backed by OS CSPRNG)
- **Post-processing**:  algorithm with NIST-validated statistical properties
- **Security**: Passes 9/9 NIST statistical tests, suitable for cryptographic use

### Basic Usage Examples

```bash
# Encryption with generated key (recommended)
./cryptocore --algorithm aes --mode cbc --encrypt \
    --input plaintext.txt \
    --output ciphertext.bin

# Encryption with specific key
./cryptocore --algorithm aes --mode cbc --encrypt \
    --key 00112233445566778899aabbccddeeff \
    --input plaintext.txt \
    --output ciphertext.bin

# Decryption (key always required)
./cryptocore --algorithm aes --mode cbc --decrypt \
    --key 00112233445566778899aabbccddeeff \
    --input ciphertext.bin \
    --output decrypted.txt

# Modes that don't use IV (ECB)
./cryptocore --algorithm aes --mode ecb --encrypt \
    --key 00112233445566778899aabbccddeeff \
    --input plaintext.txt \
    --output ciphertext.bin
```

### IV Handling

For modes requiring IV (CBC, CFB, OFB, CTR):

- **Encryption**: Random IV generated automatically and prepended to output file
- **Decryption**: IV read from file header or provided via `--iv` flag

```bash
# Decryption with IV from file (automatic)
./cryptocore --algorithm aes --mode cbc --decrypt \
    --key 00112233445566778899aabbccddeeff \
    --input ciphertext.bin \
    --output decrypted.txt

# Decryption with explicit IV
./cryptocore --algorithm aes --mode cbc --decrypt \
    --key 00112233445566778899aabbccddeeff \
    --iv aabbccddeeff00112233445566778899 \
    --input ciphertext.bin \
    --output decrypted.txt
```

## NIST Statistical Test Suite

### Running Tests

```bash
# Run built-in NIST tests
cargo test test_csprng_nist_full -- --nocapture

# Test key uniqueness
cargo test test_key_uniqueness -- --nocapture

# Generate data for external NIST STS
cargo test test_nist_data_generation -- --nocapture
```

### Expected Results

- **Minimum Pass Rate**: 8/9 NIST tests (p-value ≥ 0.01)
- **Key Uniqueness**: 1000/1000 unique keys generated
- **Statistical Quality**: All tests should show random distribution characteristics

## Installation

### Prerequisites

- Rust 1.70 or higher
- Cargo

### Building from Source

```bash
git clone <repository-url>
cd cryptocore

# Build in release mode
cargo build --release

# Binary available at: target/release/cryptocore
```

## Interoperability with OpenSSL

### My Tool → OpenSSL

```bash
# Encrypt with CryptoCore
./cryptocore --algorithm aes --mode cbc --encrypt \
    --input plain.txt --output cipher.bin

# Extract IV and ciphertext
dd if=cipher.bin of=iv.bin bs=16 count=1
dd if=cipher.bin of=ciphertext_only.bin bs=16 skip=1

# Decrypt with OpenSSL
openssl enc -aes-128-cbc -d \
    -K 00112233445566778899aabbccddeeff \
    -iv $(xxd -p iv.bin | tr -d '\n') \
    -in ciphertext_only.bin \
    -out decrypted.txt
```

### OpenSSL → My Tool

```bash
# Encrypt with OpenSSL
openssl enc -aes-128-cbc \
    -K 00112233445566778899aabbccddeeff \
    -iv AABBCCDDEEFF00112233445566778899 \
    -in plain.txt -out openssl_cipher.bin

# Decrypt with CryptoCore
./cryptocore --algorithm aes --mode cbc --decrypt \
    --key 00112233445566778899aabbccddeeff \
    --iv AABBCCDDEEFF00112233445566778899 \
    --input openssl_cipher.bin \
    --output decrypted.txt
```
## Sprint 4
## This implementation provides:
1. ✅ Proper hash module structure
2. ✅ SHA-256 from scratch (your existing code)
3. ✅ SHA3-256 from scratch (new implementation)
4. ✅ CLI `dgst` subcommand
5. ✅ File chunk processing for large files
6. ✅ Standard output format
7. ✅ Comprehensive testing framework
8. ✅ Updated documentation

