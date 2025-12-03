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
