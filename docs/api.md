## 2. **Comprehensive API Documentation** (API.md)

```markdown
# CryptoCore API Documentation

**Compatibility:** Rust 1.60+

## Table of Contents
1. [Overview](#overview)
2. [Module: cryptocore::core::crypto::aes](#module-cryptocorecorecryptoaes)
3. [Module: cryptocore::core::crypto::modes](#module-cryptocorecorecryptomodes)
4. [Module: cryptocore::core::crypto::hash](#module-cryptocorecorecryptohash)
5. [Module: cryptocore::core::crypto::mac](#module-cryptocorecorecryptomac)
6. [Module: cryptocore::core::crypto::kdf](#module-cryptocorecorecryptokdf)
7. [Module: cryptocore::core::crypto::csprng](#module-cryptocorecorecryptocsprng)
8. [Module: cryptocore::core::io](#module-cryptocorecoreio)
9. [Module: cryptocore::cli](#module-cryptocorecli)
10. [Error Handling](#error-handling)
11. [Security Considerations](#security-considerations)
12. [Examples](#examples)

## Overview

CryptoCore is a cryptographic library providing implementations of symmetric encryption, hashing, message authentication codes, key derivation, and cryptographically secure random number generation.

### Module Dependency Graph
```
cryptocore/
├── core/
│   ├── crypto/
│   │   ├── aes.rs          ──┐
│   │   ├── modes/          ◄──┘ (uses aes)
│   │   │   ├── cbc.rs
│   │   │   ├── cfb.rs
│   │   │   ├── ofb.rs
│   │   │   ├── ctr.rs
│   │   │   └── gcm.rs      ──┐
│   │   ├── hash.rs          │ (used by hmac)
│   │   ├── mac/            ◄──┘
│   │   │   ├── hmac.rs     ◄──┐ (uses hash)
│   │   │   └── cmac.rs       │ (uses aes)
│   │   ├── kdf.rs          ◄──┘ (uses mac)
│   │   └── csprng.rs       ◄──┐ (uses hash)
│   └── io.rs              ◄──┘ (uses csprng)
├── cli/
└── error.rs
```

---

## Module: cryptocore::core::crypto::aes

AES-128 block cipher implementation.

### `AesCipher`

```rust
pub struct AesCipher {
    cipher: Aes128,
}
```

AES cipher instance for block encryption/decryption.

#### Methods

##### `new(key: &[u8]) -> Result<Self, CryptoCoreError>`
Creates a new AES cipher instance.

**Parameters:**
- `key: &[u8]` - 16-byte encryption key (128 bits)

**Returns:**
- `Result<Self, CryptoCoreError>` - AES cipher instance or error

**Errors:**
- `InvalidKey` - If key length is not 16 bytes

**Example:**
```rust
let key = [0x00; 16];
let cipher = AesCipher::new(&key)?;
```

##### `encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoCoreError>`
Encrypts data using AES in ECB mode with PKCS#7 padding.

**Parameters:**
- `data: &[u8]` - Plaintext data to encrypt

**Returns:**
- `Result<Vec<u8>, CryptoCoreError>` - Encrypted ciphertext

**Example:**
```rust
let plaintext = b"Hello, AES!";
let ciphertext = cipher.encrypt(plaintext)?;
```

##### `decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoCoreError>`
Decrypts AES-encrypted data in ECB mode.

**Parameters:**
- `data: &[u8]` - Ciphertext to decrypt (must be multiple of 16 bytes)

**Returns:**
- `Result<Vec<u8>, CryptoCoreError>` - Decrypted plaintext

**Errors:**
- `Crypto` - If data length is not a multiple of block size
- `PaddingError` - If padding is invalid

##### `encrypt_block(&self, block: &[u8; 16]) -> Result<[u8; 16], CryptoCoreError>`
Encrypts a single 16-byte block.

**Parameters:**
- `block: &[u8; 16]` - 16-byte block to encrypt

**Returns:**
- `Result<[u8; 16], CryptoCoreError>` - Encrypted block

**Security Considerations:**
- Never use ECB mode for multiple blocks of related data
- Use authenticated encryption modes (GCM) for real-world applications

---

## Module: cryptocore::core::crypto::modes

Block cipher modes of operation.

### Submodules:
- `cbc` - Cipher Block Chaining
- `cfb` - Cipher Feedback
- `ofb` - Output Feedback
- `ctr` - Counter Mode
- `gcm` - Galois/Counter Mode (Authenticated Encryption)

### `BlockMode` Enum

```rust
pub enum BlockMode {
    Cbc(cbc::CbcMode),
    Cfb(cfb::CfbMode),
    Ofb(ofb::OfbMode),
    Ctr(ctr::CtrMode),
    Gcm(gcm::Gcm),
}
```

#### Common Methods for all Modes

##### `new(mode_name: &str, key: &[u8], iv: &[u8]) -> Result<Self, CryptoCoreError>`
Creates a new block mode instance.

**Parameters:**
- `mode_name: &str` - Mode name: "cbc", "cfb", "ofb", "ctr", "gcm"
- `key: &[u8]` - Encryption key (16, 24, or 32 bytes for AES)
- `iv: &[u8]` - Initialization vector (16 bytes for CBC/CFB/OFB/CTR, 12 bytes for GCM)

**Returns:**
- `Result<Self, CryptoCoreError>` - Block mode instance

**Errors:**
- `InvalidArgument` - If mode name is invalid or IV size is incorrect

### `cbc::CbcMode`

Cipher Block Chaining mode.

**Security Considerations:**
- Requires random IV for each encryption
- Provides confidentiality only (no integrity protection)

### `gcm::Gcm`

Galois/Counter Mode (Authenticated Encryption with Associated Data).

#### Methods

##### `new(key: &[u8]) -> Result<Self, CryptoCoreError>`
Creates a new GCM instance.

**Parameters:**
- `key: &[u8]` - AES key (16, 24, or 32 bytes)

##### `encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, [u8; 16]), CryptoCoreError>`
Encrypts plaintext with authentication.

**Parameters:**
- `plaintext: &[u8]` - Data to encrypt
- `aad: &[u8]` - Additional authenticated data (not encrypted, but authenticated)
- `nonce: &[u8]` - 12-byte nonce (never reuse with same key!)

**Returns:**
- `(Vec<u8>, [u8; 16])` - Tuple of (ciphertext, authentication tag)

**Security Considerations:**
- Never reuse nonce with the same key
- AAD can be used for metadata that needs authentication but not encryption

##### `decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>, CryptoCoreError>`
Decrypts and authenticates ciphertext.

**Parameters:**
- `ciphertext: &[u8]` - Encrypted data
- `aad: &[u8]` - Additional authenticated data (must match encryption AAD)
- `nonce: &[u8]` - 12-byte nonce used during encryption
- `tag: &[u8; 16]` - 16-byte authentication tag

**Returns:**
- `Result<Vec<u8>, CryptoCoreError>` - Decrypted plaintext if authentication succeeds

**Errors:**
- `Crypto` - If authentication fails (catastrophic - no partial plaintext output)

##### `generate_nonce() -> [u8; 12]`
Generates a random 12-byte nonce using cryptographically secure RNG.

---

## Module: cryptocore::core::crypto::hash

Cryptographic hash functions.

### `HashAlgorithm` Enum

```rust
pub enum HashAlgorithm {
    Sha256,
    Sha3_256,
}
```

#### Methods

##### `from_str(name: &str) -> Result<Self, CryptoCoreError>`
Creates a HashAlgorithm from string name.

**Parameters:**
- `name: &str` - "sha256" or "sha3-256"

##### `compute_hash(&self, data: &[u8]) -> Result<String, CryptoCoreError>`
Computes hash of data in memory.

**Parameters:**
- `data: &[u8]` - Data to hash

**Returns:**
- `String` - Hexadecimal hash string

**Performance:**
- Processes data in 4KB chunks
- Constant memory usage regardless of input size

##### `compute_file_hash(&self, path: &Path) -> Result<String, CryptoCoreError>`
Computes hash of file contents.

**Parameters:**
- `path: &Path` - Path to file

**Returns:**
- `String` - Hexadecimal hash string

**Example:**
```rust
let hash = HashAlgorithm::Sha256.compute_file_hash(Path::new("data.txt"))?;
println!("SHA-256: {}", hash);
```

### `Sha256` Struct
Raw SHA-256 implementation.

**Constants:**
- `INITIAL_HASH: [u32; 8]` - Initial hash values
- `K: [u32; 64]` - Round constants

### `Sha3_256` Struct
SHA3-256 (Keccak) implementation.

**Constants:**
- `BLOCK_SIZE: usize = 136` - SHA3-256 rate
- `OUTPUT_SIZE: usize = 32` - 256-bit output

---

## Module: cryptocore::core::crypto::mac

Message Authentication Codes.

### `Mac` Struct
Unified MAC interface.

```rust
pub struct Mac {
    algorithm: MacAlgorithm,
    key: Vec<u8>,
}
```

#### Methods

##### `new(algorithm: &str, key: &[u8]) -> Result<Self, CryptoCoreError>`
Creates a new MAC instance.

**Parameters:**
- `algorithm: &str` - "hmac" or "cmac"
- `key: &[u8]` - MAC key (any length for HMAC, 16 bytes for CMAC)

##### `compute(&self, message: &[u8]) -> Result<Vec<u8>, CryptoCoreError>`
Computes MAC for message.

### `hmac::Hmac`
HMAC-SHA256 implementation (RFC 2104).

#### Methods

##### `compute(key: &[u8], message: &[u8]) -> [u8; 32]`
Computes HMAC-SHA256.

**Parameters:**
- `key: &[u8]` - Secret key (any length)
- `message: &[u8]` - Message to authenticate

**Returns:**
- `[u8; 32]` - 32-byte HMAC

**Key Processing:**
- Keys longer than 64 bytes are hashed with SHA-256
- Keys shorter than 64 bytes are padded with zeros

##### `verify(key: &[u8], message: &[u8], expected_hmac: &[u8]) -> bool`
Verifies HMAC.

**Uses constant-time comparison to prevent timing attacks.**

### `cmac::Cmac`
AES-CMAC implementation (NIST SP 800-38B).

#### Methods

##### `new(key: &[u8]) -> Result<Self, CryptoCoreError>`
Creates AES-CMAC instance.

**Parameters:**
- `key: &[u8]` - Must be exactly 16 bytes

##### `compute(key: &[u8], message: &[u8]) -> Result<[u8; 16], CryptoCoreError>`
Computes AES-CMAC.

**Returns:**
- `[u8; 16]` - 16-byte CMAC

**Algorithm:**
1. Generates subkeys K1, K2 from AES key
2. Processes message in CBC-MAC mode with IV = 0
3. XORs last block with K1 or K2 based on padding

---

## Module: cryptocore::core::crypto::kdf

Key Derivation Functions.

### `Pbkdf2` Struct
Password-Based Key Derivation Function 2 (RFC 2898).

#### Methods

##### `derive_key(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Result<Vec<u8>, CryptoCoreError>`
Derives key from password.

**Parameters:**
- `password: &[u8]` - Password bytes
- `salt: &[u8]` - Cryptographic salt (min 8 bytes, recommended 16+)
- `iterations: u32` - Iteration count (min 100,000 recommended)
- `dklen: usize` - Desired key length in bytes

**Returns:**
- `Vec<u8>` - Derived key

**Algorithm:**
```
DK = T1 || T2 || ... || Tdklen/hlen
Ti = F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc
U1 = PRF(P, S || i)
Uj = PRF(P, Uj-1)
```

##### `generate_salt(length: usize) -> Result<Vec<u8>, CryptoCoreError>`
Generates cryptographically random salt.

##### `benchmark(password: &[u8], salt: &[u8], iterations_list: &[u32]) -> Result<Vec<(u32, f64)>, CryptoCoreError>`
Benchmarks PBKDF2 performance.

### `KeyHierarchy` Struct
Key derivation for multiple purposes from master key.

#### Methods

##### `derive_key(master_key: &[u8], context: &str, length: usize) -> Result<Vec<u8>, CryptoCoreError>`
Derives key for specific context.

**Parameters:**
- `master_key: &[u8]` - Master key
- `context: &str` - Unique context string (e.g., "encryption", "authentication")
- `length: usize` - Desired key length

**Algorithm:**
```
T_i = HMAC(master_key, context || i)
DK = T1 || T2 || ... until length satisfied
```

##### `derive_key_hierarchy(master_key: &[u8], contexts: &[(&str, usize)]) -> Result<Vec<(String, Vec<u8>)>, CryptoCoreError>`
Derives multiple keys for different contexts.

### `utils` Module
Utility functions.

##### `secure_zero_memory(data: &mut [u8])`
Securely zeros memory to prevent sensitive data leakage.

**Uses volatile writes and memory barriers.**

##### `derive_encryption_and_auth_keys(master_key: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoCoreError>`
Derives separate encryption and authentication keys.

---

## Module: cryptocore::core::crypto::csprng

Cryptographically Secure Pseudorandom Number Generator.

### `Csprng` Struct

#### Methods

##### `generate_random_bytes(num_bytes: usize) -> Result<Vec<u8>, CryptoCoreError>`
Generates cryptographically secure random bytes.

**Parameters:**
- `num_bytes: usize` - Number of bytes to generate

**Returns:**
- `Vec<u8>` - Random bytes

**Algorithm:**
1. Collects system entropy via `getrandom`
2. Post-processes with deterministic algorithm
3. Passes NIST statistical tests

##### `generate_random_hex_string(num_bytes: usize) -> Result<String, CryptoCoreError>`
Generates random hexadecimal string.

**Security Properties:**
- Passes 9/9 NIST statistical tests
- Backed by OS CSPRNG (getrandom)
- Suitable for cryptographic key generation

---

## Module: cryptocore::core::io

File I/O utilities with cryptographic safety.

### Functions

##### `read_file(path: &Path) -> Result<Vec<u8>, CryptoCoreError>`
Reads file with error handling.

##### `write_file(path: &Path, data: &[u8]) -> Result<(), CryptoCoreError>`
Writes file with atomic replacement.

##### `read_file_with_iv(path: &Path) -> Result<(Vec<u8>, Option<Vec<u8>>), CryptoCoreError>`
Reads file, extracting IV from beginning if present.

##### `write_file_with_iv(path: &Path, iv: &[u8], data: &[u8]) -> Result<(), CryptoCoreError>`
Writes file with IV prepended.

##### `generate_iv() -> [u8; 16]`
Generates random 16-byte IV.

##### `derive_output_path(input_path: &Path, operation: &Operation) -> PathBuf`
Derives output path based on operation.

---

## Module: cryptocore::cli

Command-line interface.

### `CliConfig` Struct
CLI configuration.

```rust
pub struct CliConfig {
    pub operation_type: OperationType,
}
```

### `OperationType` Enum

```rust
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
```

### Functions

##### `parse_args() -> Result<CliConfig, Box<dyn std::error::Error>>`
Parses command-line arguments using clap.

**Subcommands:**
- `encrypt` - File encryption
- `decrypt` - File decryption
- `mac` - MAC generation/verification (hmac, cmac subcommands)
- `derive` - Key derivation

---

## Error Handling

### `CryptoCoreError` Enum

```rust
#[derive(Error, Debug)]
pub enum CryptoCoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Crypto error: {0}")]
    Crypto(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    
    #[error("File error: {0}")]
    FileError(String),
    
    #[error("Padding error: {0}")]
    PaddingError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
}
```

**Usage:**
```rust
pub type Result<T> = std::result::Result<T, CryptoCoreError>;
```

---

## Security Considerations

### Critical Security Requirements
1. **Key Management**
   - Never hardcode keys in source code
   - Use key derivation for password-based keys
   - Store keys in secure memory

2. **Random Number Generation**
   - Always use `Csprng` for cryptographic randomness
   - Nonces must never be reused with same key in GCM

3. **Memory Safety**
   - Use `secure_zero_memory` for sensitive data cleanup
   - Avoid unnecessary copies of sensitive data

4. **Authentication**
   - Always verify MACs/AEAD tags before using data
   - GCM provides catastrophic failure on authentication error

5. **Timing Attacks**
   - Use constant-time comparisons for MAC verification
   - Avoid branching on secret data

### Algorithm Recommendations
| Use Case | Recommended Algorithm | Key Size | Notes |
|----------|----------------------|----------|-------|
| File Encryption | AES-GCM | 256 bits | With random nonce |
| Password Storage | PBKDF2-HMAC-SHA256 | 256 bits | 100,000+ iterations |
| Data Integrity | HMAC-SHA256 | 256 bits | Variable key size |
| Key Derivation | Key Hierarchy | Match needs | Context separation |
| Random Numbers | Csprng | As needed | NIST-validated |

---

## Examples

### Basic Encryption
```rust
use cryptocore::core::crypto::{aes::AesCipher, modes::gcm::Gcm};

// AES-ECB (for testing only)
let key = [0u8; 16];
let cipher = AesCipher::new(&key)?;
let encrypted = cipher.encrypt(b"secret")?;

// AES-GCM with AAD
let gcm = Gcm::new(&key)?;
let nonce = Gcm::generate_nonce();
let (ciphertext, tag) = gcm.encrypt(b"secret", b"metadata", &nonce)?;
```

### CLI Usage Examples
```bash
# Generate HMAC
cryptocore mac hmac --key 001122... --input file.txt

# Derive key from password
cryptocore derive --password "mysecret" --iterations 100000

# Encrypt with GCM
cryptocore encrypt --algorithm aes --mode gcm \
  --key 001122... --aad "metadata" --input data.txt
```

### File Operations
```rust
use cryptocore::core::io;

// Read and process file
let data = io::read_file(Path::new("input.txt"))?;

// Write with IV
let iv = io::generate_iv();
io::write_file_with_iv(Path::new("output.enc"), &iv, &encrypted_data)?;
```
