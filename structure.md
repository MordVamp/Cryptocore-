cryptocore/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── cli/
│   │   ├── mod.rs
│   │   └── config.rs
│   ├── core/
│   │   ├── mod.rs
│   │   ├── crypto/
│   │   │   ├── mod.rs
│   │   │   ├── aes.rs
│   │   │   ├── csprng.rs
│   │   │   ├── traits.rs
│   │   │   ├── hash/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── sha256.rs
│   │   │   │   └── sha3_256.rs
│   │   │   └── modes/
│   │   │       ├── mod.rs
│   │   │       ├── cbc.rs
│   │   │       ├── cfb.rs
│   │   │       ├── ofb.rs
│   │   │       └── ctr.rs
│   │   └── io/
│   │       └── mod.rs
│   ├── error.rs
│   └── types/
│       ├── mod.rs
│       └── operation.rs
└── tests/
    ├── integration_tests.rs
    ├── modes_tests.rs
    ├── openssl_interop_tests.rs
    └── test_nist.rs