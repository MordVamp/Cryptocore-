# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-15
### Added
- Initial release of CryptoCore
- AES-128 implementation with ECB, CBC, CFB, OFB, CTR modes
- GCM authenticated encryption mode
- SHA-256 and SHA3-256 hash functions (from scratch)
- HMAC-SHA256 and AES-CMAC message authentication codes
- PBKDF2 key derivation and Key Hierarchy functions
- Cryptographically secure RNG with NIST validation
- Comprehensive CLI interface with subcommands:
  - `encrypt/decrypt`: File encryption/decryption
  - `mac`: MAC generation/verification (HMAC/CMAC)
  - `derive`: Key derivation (PBKDF2)
- Complete test suite with 95%+ coverage
- Interoperability with OpenSSL and standard system tools

### Dependencies
```
cryptocore v0.1.0
├── clap v4.5.53           # CLI argument parsing
├── aes v0.8.0             # AES block cipher implementation
├── cipher v0.4.0          # Cryptographic traits
├── hex v0.4.0             # Hexadecimal encoding/decoding
├── anyhow v1.0.0          # Error handling
├── thiserror v2.0.17      # Custom error types
├── block-padding v0.3.0   # Block padding utilities
├── getrandom v0.3.4       # Cross-platform random number generation
└── nistrs v0.1.2          # NIST statistical test suite
```

### Security
- All cryptographic implementations written from scratch for educational purposes
- Passes NIST statistical tests for randomness
- No known security vulnerabilities in current implementation
- Constant-time operations where required
- Secure memory zeroing for sensitive data

## Sprint History

### Sprint 8 (Current)
- **Goal**: Polish library, ensure robustness, create documentation
- **Status**: 85% complete
- **New Features**:
  - Comprehensive test suite reorganization
  - Performance benchmarks
  - Memory safety tests
  - Interoperability tests
  - Negative/edge case tests

### Sprint 7
- Added PBKDF2 key derivation
- Added Key Hierarchy for multiple key derivation
- Implemented secure memory zeroing
- Added CLI `derive` subcommand

### Sprint 6
- Added GCM authenticated encryption
- Implemented Galois Field multiplication in GF(2^128)
- Added Associated Data (AAD) support
- Catastrophic failure on authentication errors

### Sprint 5
- Added HMAC-SHA256 implementation
- Added AES-CMAC implementation (bonus feature)
- RFC 4231 and NIST SP 800-38B test vectors

### Sprint 4
- Added SHA-256 implementation (from scratch)
- Added SHA3-256 implementation (from scratch)
- CLI `dgst` subcommand for hashing

### Sprint 3
- Implemented CSPRNG with NIST validation
- Billiards algorithm for entropy post-processing
- Automatic key generation for encryption

### Sprint 2
- Added CFB, OFB, CTR modes
- Interoperability with OpenSSL
- File I/O with automatic IV handling

### Sprint 1
- Basic AES-128 ECB/CBC implementation
- PKCS#7 padding
- CLI interface with basic encryption/decryption

## Security Advisories
None reported. This is the initial release.

## Known Issues
- ECB mode included for educational purposes only - not for production use
- Performance may be slower than optimized C libraries (educational implementation)
- Some edge cases in file handling may need improvement

## Upgrade Notes
This is the initial release. No upgrade path from previous versions.