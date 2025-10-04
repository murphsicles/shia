# Shia - The BSV BEEF Protocol Reference Implementation 🚀

![Rust](https://img.shields.io/badge/rust-edition%202024-orange)
[![Crates.io](https://img.shields.io/crates/v/shia.svg)](https://crates.io/crates/shia)
[![Dependencies](https://deps.rs/repo/github/murphsicles/shia/status.svg)](https://deps.rs/repo/github/murphsicles/shia)
[![CI](https://img.shields.io/github/actions/workflow/status/murphsicles/shia/ci.yml?branch=main)](https://github.com/murphsicles/shia/actions/workflows/ci.yml)

A Rust crate implementing the BSV BEEF (Background Evaluation Extended Format) protocol (BRC-62) for Simplified Payment Verification (SPV) on Bitcoin SV. It supports parsing, serialization, building from transaction DAGs, and verification of transactions with Merkle proofs using BUMP (BRC-74). Designed for integration into BSV wallet stacks, with script evaluation via the `rust-sv` crate.

## Features 🔧

- **Parsing & Serialization**: Deserialize from hex/binary and serialize BEEF data.
- **Building**: Construct BEEF from subject transaction, ancestors, and bump proofs with topological sorting for DAGs.
- **Verification**: Full SPV validation including Merkle root checks, UTXO tracking, value balance, and script execution (P2PKH, multisig, etc.).
- **Atomic BEEF Support**: Optional atomicity for focused validation (BRC-95).
- **Dependencies**: Integrates with `rust-sv` for BSV-specific script VM and transaction handling.

## Installation 📦

Add to your `Cargo.toml`:

```toml
[dependencies]
shia = "0.1.0"
```

For development (from GitHub):

```toml
[dependencies]
shia = { git = "https://github.com/murphsicles/shia" }
```

Requires Rust 1.82+ for edition 2024 features.

## Usage 📖

### Basic Parsing
```rust
use shia::Beef;

let beef_hex = "f1c6c3ef..."; // Your BEEF hex
let beef = Beef::from_hex(beef_hex).expect("Valid BEEF");
println!("{:?}", beef);
```

### Building BEEF
```rust
use shia::{Beef, Transaction, Bump};
use std::collections::HashMap;

let subject_tx = Transaction::from_raw(&your_tx_bytes).unwrap();
let ancestors = HashMap::new(); // txid -> Transaction
let bump_map = HashMap::new(); // txid -> Bump
let beef = Beef::build(subject_tx, ancestors, bump_map, false).unwrap(); // Non-atomic
let serialized = beef.serialize().unwrap();
```

### Verification
```rust
struct MyHeadersClient; // Implement BlockHeadersClient trait
impl shia::BlockHeadersClient for MyHeadersClient {
    fn is_valid_root_for_height(&self, root: [u8; 32], height: u64) -> bool {
        // Check against your block headers
        true
    }
}

let mock_client = MyHeadersClient;
beef.verify(&mock_client).expect("Valid BEEF");
```

### Script Evaluation
The crate uses `rust-sv` for BSV script verification. Extend `Transaction::verify_scripts` for custom checkers if needed.

## Structure 📁

- `Transaction`: Custom BSV tx struct with parsing and hashing.
- `Bump`: BRC-74 Merkle proof structure for inclusion verification.
- `Beef`: Main BEEF struct with atomic support.
- `BlockHeadersClient`: Trait for header validation (implement your own).

## Tests 🧪

Run with `cargo test`. Tests cover parsing, serialization, building, verification, and script eval with sample BSV txs. CI runs on GitHub Actions for stability.

## Dependencies 📚

- `byteorder`, `hex`, `thiserror`, `anyhow`, `sha2`: Core utilities.
- `sv`: BSV-specific tx/script handling (GitHub dependency).

## License 📄

MIT License. See [LICENSE](LICENSE) for details.

## Contributing 🤝

Fork the repo, create a feature branch, and submit a PR. Issues welcome at [GitHub](https://github.com/murphsicles/shia/issues).

## Contact 📧

[murphsicles](https://github.com/murphsicles) – Built for BSV wallet innovation!
