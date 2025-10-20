cryptocore/
├── Cargo.toml
├── README.md
├─── src/
│    ├── main.rs
│    ├── lib.rs
│    ├── cli/
│    │   ├── mod.rs
│    │   └── config.rs
│    ├── core/
│    │   ├── mod.rs
│    │   ├── crypto/
│    │   │   ├── mod.rs
│    │   │   ├── cipher.rs
│    │   │   ├── aes.rs
│    │   │   ├── modes/
│    │   │   │   ├── mod.rs
│    │   │   │   ├── cbc.rs
│    │   │   │   ├── cfb.rs
│    │   │   │   ├── ofb.rs
│    │   │   │   └── ctr.rs
│    │   │   └── traits.rs
│    │   └── io/
│    │       ├── mod.rs
│    │       └── file_ops.rs
│    ├── error.rs
│    └── types/
│        ├── mod.rs
│        └── operation.rs
├── tests/
│   └── integration_tests.rs
└── examples/
    └── basic_usage.rs