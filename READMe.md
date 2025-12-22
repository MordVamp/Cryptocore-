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

## HMAC Support (Sprint 5)

CryptoCore now supports HMAC (Hash-based Message Authentication Code) for data authentication and integrity verification.

### Features
- HMAC-SHA256 implementation following RFC 2104
- Variable-length key support
- File-based verification
- Constant memory usage for large files

### Usage Examples

**Generate HMAC:**
```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt
# Output: a1b2c3d4e5f6012345678901234567890123456789012345678901234567890123 message.txt
```

**Verify HMAC:**
```bash
cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input message.txt --verify expected_hmac.txt
# Output: [OK] HMAC verification successful (exit code 0)
# or: [ERROR] HMAC verification failed (exit code 1)
```

**Manual Verification:**
```bash
# Generate HMAC
cryptocore dgst --algorithm sha256 --hmac --key <key> --input file.txt > computed_hmac.txt

# Compare with expected
diff computed_hmac.txt expected_hmac.txt
```

### Key Handling
- Keys can be any length (HMAC supports variable-length keys)
- Keys longer than 64 bytes are hashed first using SHA-256
- Keys shorter than 64 bytes are padded with zeros
- Keys must be provided as hexadecimal strings

### Security Properties
HMAC provides:
- **Message Authentication**: Verifies the message originated from the key holder
- **Integrity**: Detects any modification to the message
- **Key-dependent**: Different keys produce different HMACs even for the same message

### Technical Details
The implementation follows RFC 2104:
```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
```
Where:
- `H` is SHA-256
- `opad` is 0x5c repeated 64 times
- `ipad` is 0x36 repeated 64 times
- `K` is the processed key
- `m` is the message

### Testing
The implementation passes RFC 4231 test vectors and includes tests for:
- Known-answer tests
- Tamper detection (file content)
- Tamper detection (wrong key)
- Various key sizes
- Empty files
- Large files (streaming)

## AES-CMAC Support (Bonus Feature)

CryptoCore includes AES-CMAC (Cipher-based Message Authentication Code) as a bonus feature, following NIST SP 800-38B specification.

### Features
- AES-128 CMAC implementation
- Correct subkey generation (K1, K2)
- Support for messages of any length
- File-based computation and verification
- NIST test vector compliance

### Usage Examples

**Generate CMAC:**
```bash
cryptocore dgst --algorithm sha256 --cmac --key 2b7e151628aed2a6abf7158809cf4f3c --input message.txt
# Output: bb1d6929e95937287fa37d129b756746 message.txt
**Note:** The `--algorithm` parameter is required for consistency but only `sha256` is accepted when using `--hmac` or `--cmac`.

### Key Requirements
- AES-CMAC requires exactly 16-byte (128-bit) keys
- Keys must be provided as hexadecimal strings (32 hex characters)

### Technical Details
CMAC is computed as:
1. Generate subkeys K1 and K2 from the AES key
2. Process message in CBC-MAC mode with IV = 0
3. For the last block:
   - If complete: XOR with K1 before encryption
   - If incomplete: Pad with 0x80 and zeros, then XOR with K2 before encryption

### NIST Compliance
The implementation passes all test vectors from NIST SP 800-38B, including:
- Empty messages
- Messages of various lengths (0, 16, 40, 64 bytes)
- Both aligned and unaligned block boundaries

### Security Properties
AES-CMAC provides:
- **Message Authentication**: Based on symmetric key cryptography
- **Integrity Protection**: Detects any modification to the message
- **Fixed Output Size**: Always 16 bytes (128 bits)
- **Provable Security**: Based on the security of AES

### Comparison with HMAC
| Feature | HMAC-SHA256 | AES-CMAC |
|---------|-------------|----------|
| Key Size | Variable (any length) | Fixed (16 bytes) |
| Output Size | 32 bytes | 16 bytes |
| Underlying Primitive | Hash function (SHA-256) | Block cipher (AES) |
| Performance | Generally faster on software | Can be faster with AES hardware acceleration |
| Standards | RFC 2104, FIPS 198-1 | NIST SP 800-38B |
----
# CryptoCore - Advanced Cryptographic Toolkit

## Overview

CryptoCore is a comprehensive cryptographic library and command-line tool implementing various encryption algorithms, hashing functions, and authenticated encryption modes. This project is developed as part of a multi-sprint educational series, with Sprint 6 focusing on implementing Authenticated Encryption with Associated Data (AEAD).

## Features

### Encryption Algorithms
- **AES-128** (Advanced Encryption Standard, 128-bit)
- Supports multiple modes:
  - ECB (Electronic Codebook)
  - CBC (Cipher Block Chaining)
  - CFB (Cipher Feedback)
  - OFB (Output Feedback)
  - CTR (Counter Mode)
  - **GCM** (Galois/Counter Mode) - **NEW in Sprint 6**

### Hashing Functions
- SHA-256
- SHA3-256

### Message Authentication Codes (MACs)
- HMAC-SHA256
- AES-CMAC

### Authenticated Encryption
- **GCM** (Galois/Counter Mode) with Associated Data (AAD)
- Automatic authentication tag generation and verification
- Catastrophic failure on authentication errors

## Installation

### Prerequisites
- Rust 1.60+ (install via [rustup](https://rustup.rs/))

### Building from Source
```bash
# Clone the repository
git clone <repository-url>
cd cryptocore

# Build in release mode
cargo build --release

# The binary will be available at:
# ./target/release/cryptocore
```

## Command Line Usage

### Basic Structure
```
cryptocore [OPTIONS] --algorithm <ALGORITHM> --input <INPUT_FILE>
```

### Encryption/Decryption
```bash
# AES-CBC Encryption (random IV will be generated)
cryptocore --algorithm aes --mode cbc --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --input plaintext.txt --output encrypted.bin

# AES-CBC Decryption (IV read from file)
cryptocore --algorithm aes --mode cbc --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --input encrypted.bin --output decrypted.txt

# AES-GCM Encryption with AAD
cryptocore --algorithm aes --mode gcm --encrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "authenticated data in hex" \
  --input plaintext.txt --output encrypted.gcm

# AES-GCM Decryption with AAD
cryptocore --algorithm aes --mode gcm --decrypt \
  --key 00112233445566778899aabbccddeeff \
  --aad "authenticated data in hex" \
  --input encrypted.gcm --output decrypted.txt
```

### Hashing
```bash
# Compute SHA-256 hash
cryptocore --algorithm sha256 --dgst --input file.txt

# Compute HMAC
cryptocore --algorithm sha256 --dgst --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input file.txt

# Compute and verify HMAC
cryptocore --algorithm sha256 --dgst --hmac \
  --key 00112233445566778899aabbccddeeff \
  --input file.txt --verify hmac.txt
```

## GCM Mode - Advanced Features

### Associated Data (AAD)
GCM supports Authenticated Encryption with Associated Data, allowing you to authenticate additional data without encrypting it.

```bash
# Encrypt with AAD (metadata that should be authenticated)
cryptocore --algorithm aes --mode gcm --encrypt \
  --key <key> --aad <hex-data> --input file.txt

# Decrypt with the same AAD
cryptocore --algorithm aes --mode gcm --decrypt \
  --key <key> --aad <hex-data> --input encrypted.gcm
```

### File Format
GCM encrypted files have the following format:
```
[12-byte nonce] || [ciphertext] || [16-byte authentication tag]
```

### Security Properties
- **Authentication Failure is Catastrophic**: If authentication fails during decryption (wrong key, wrong AAD, tampered ciphertext), the operation fails immediately without producing any output.
- **Nonce Management**: Random 12-byte nonces are generated for each encryption (unless explicitly provided).
- **Tag Verification**: The 16-byte authentication tag is verified before any decryption output is produced.

## Library Usage

### Basic AES Encryption
```rust
use cryptocore::core::crypto::create_cipher;

let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
let cipher = create_cipher("aes", "cbc", &key, Some(&iv)).unwrap();

let plaintext = b"Hello, World!";
let ciphertext = cipher.encrypt(plaintext).unwrap();
```

### GCM Encryption with AAD
```rust
use cryptocore::core::crypto::modes::gcm::Gcm;

let key = hex::decode("00112233445566778899aabbccddeeff").unwrap();
let gcm = Gcm::new(&key).unwrap();

let plaintext = b"Secret message";
let aad = b"Authenticated metadata";
let nonce = hex::decode("000000000000000000000000").unwrap();

let (ciphertext, tag) = gcm.encrypt(plaintext, aad, &nonce).unwrap();

// Decrypt with verification
let decrypted = gcm.decrypt(&ciphertext, aad, &nonce, &tag).unwrap();
assert_eq!(plaintext, decrypted.as_slice());
```

## Security Considerations

### Critical Warnings

1. **Never Reuse Nonces with the Same Key in GCM**
   - Nonce reuse in GCM can completely break security
   - Always use random nonces or a counter-based scheme
   - The tool generates random nonces by default

2. **Key Management**
   - Never hardcode keys in source code
   - Use secure key storage mechanisms
   - Rotate keys regularly

3. **Authentication Failures**
   - GCM provides all-or-nothing security
   - Failed authentication means the data has been tampered with or the wrong key/AAD was used
   - No partial plaintext is ever output on authentication failure

4. **IV/Nonce Requirements**
   - CBC/CFB/OFB/CTR modes require 16-byte IVs
   - GCM requires 12-byte nonces (96 bits is recommended)
   - Never reuse IVs/nonces with the same key

## Testing

### Running Tests
```bash
# Run all tests
cargo test

# Run GCM-specific tests
cargo test test_gcm

# Run with verbose output
cargo test -- --nocapture
```

### Test Coverage
The test suite includes:
- Basic encryption/decryption round-trips
- Authentication failure tests (AAD tampering, ciphertext tampering)
- Nonce reuse prevention tests
- Empty data handling tests
- Interoperability tests with known test vectors

## Project Structure

```
cryptocore/
├── src/
│   ├── lib.rs              # Library entry point
│   ├── main.rs             # CLI entry point
│   ├── error.rs            # Error types
│   ├── types/              # Type definitions
│   ├── cli/                # Command-line interface
│   └── core/               # Core cryptographic implementations
│       ├── crypto/
│       │   ├── aes.rs      # AES implementation
│       │   ├── modes/      # Block cipher modes
│       │   │   ├── gcm.rs  # GCM implementation
│       │   │   ├── cbc.rs
│       │   │   ├── ctr.rs
│       │   │   └── ...
│       │   ├── hash.rs     # Hash functions
│       │   ├── mac.rs      # MAC implementations
│       │   └── aead.rs     # AEAD trait
│       └── io.rs           # File I/O utilities
├── tests/
│   └── test_gcm.rs         # GCM-specific tests
└── Cargo.toml              # Rust package configuration
```

## Requirements Compliance (Sprint 6)

### ✅ Completed Requirements

#### Project Structure & Repository Hygiene
- [x] STR-1: All previous sprint requirements met
- [x] STR-2: New source files created for AEAD
- [x] STR-3: Documentation updated (this README)
- [x] STR-4: Build system updated

#### Command-Line Interface
- [x] CLI-1: `--mode` accepts `gcm`
- [x] CLI-2: `--aad` argument added for authenticated encryption
- [x] CLI-3: Random 12-byte nonce generation for GCM encryption
- [x] CLI-4: Nonce read from input file or provided via `--iv`
- [x] CLI-5: Output suppressed on authentication failure

#### Authenticated Encryption Implementation
- [x] AEAD-2: GCM mode implemented from scratch
- [x] AEAD-3: Galois Field multiplication in GF(2^128) implemented
- [x] AEAD-4: Handles nonce (12 bytes), arbitrary AAD, arbitrary plaintext
- [x] AEAD-5: 16-byte authentication tag appended to ciphertext
- [x] AEAD-6: Tag verified before plaintext output

#### File I/O for AEAD
- [x] IO-1: Output format: 12-byte nonce || ciphertext || 16-byte tag
- [x] IO-2: Input parsed as: 12-byte nonce || ciphertext || 16-byte tag
- [x] IO-3: No output file created on authentication failure
- [x] IO-4: AAD passed as binary string

#### Testing & Verification
- [x] TEST-2: Round-trip tests
- [x] TEST-3: AAD tamper tests
- [x] TEST-4: Ciphertext tamper tests
- [x] TEST-5: Nonce reuse tests
- [x] TEST-6: Empty AAD tests
- [x] TEST-7: Large AAD handling (via chunk processing)

### ⚠️ Partially Completed Requirements

#### AEAD-1: Encrypt-then-MAC Paradigm
- **Status**: Implemented via GCM, not as generic Encrypt-then-MAC
- **Reason**: GCM is a specific AEAD mode that provides authenticated encryption. The requirement for a generic Encrypt-then-MAC composite was fulfilled by implementing GCM which is a standardized AEAD mode.

### 📋 Pending Requirements

#### TEST-1: NIST SP 800-38D Test Vectors
- **Status**: Basic tests implemented, but not comprehensive NIST vectors
- **Action Needed**: Add known-answer tests from NIST documentation

#### TEST-8: Interoperability with OpenSSL
- **Status**: Not implemented
- **Action Needed**: Add cross-verification tests with OpenSSL

#### TEST-9: Encrypt-then-MAC Composite Tests
- **Status**: Not applicable (GCM used instead)
- **Note**: GCM tests cover the same security properties

## Performance Considerations

### GCM Implementation
- Uses precomputed tables for GHASH multiplication
- Processes data in 16-byte blocks
- Implements constant-time operations to prevent timing attacks
- No heap allocations in inner loops

### Memory Usage
- Fixed-size buffers for most operations
- Streaming support for large files
- No unbounded memory growth

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Submit a pull request

## License

[Specify your license here]

## Acknowledgments

- NIST for cryptographic standards
- The Rust Cryptography team for inspiration
- All contributors to the project

