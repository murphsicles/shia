# Shia 🥩 - The BSV BEEF Protocol Reference Implementation 🐄

![Rust](https://img.shields.io/badge/rust-edition%202024-orange)
[![Crates.io](https://img.shields.io/crates/v/shia.svg)](https://crates.io/crates/shia)
[![Dependencies](https://deps.rs/repo/github/murphsicles/shia/status.svg)](https://deps.rs/repo/github/murphsicles/shia)
[![CI](https://img.shields.io/github/actions/workflow/status/murphsicles/shia/ci.yml?branch=main)](https://github.com/murphsicles/shia/actions/workflows/ci.yml)

A Rust crate implementing the BSV BEEF (Background Evaluation Extended Format) protocol ([BRC-62](https://github.com/bitcoin-sv/BIPs/blob/master/brc-0062.mediawiki)) for Simplified Payment Verification (SPV) on Bitcoin SV. It supports parsing, serialization, building from transaction DAGs, and verification of transactions with Merkle proofs using BUMP ([BRC-74](https://github.com/bitcoin-sv/BIPs/blob/master/brc-0074.mediawiki)). Designed for integration into BSV wallet stacks, with script evaluation via the `rust-sv` crate. Includes support for atomic BEEF ([BRC-95](https://github.com/bitcoin-sv/BIPs/blob/master/brc-0095.mediawiki)) and hooks for Paymail envelopes ([BRC-70](https://github.com/bitcoin-sv/BIPs/blob/master/brc-0070.mediawiki)).

## Features 🔧

- **Parsing & Serialization**: Deserialize from hex/binary and serialize BEEF data, including atomic prefixes and variable-length tx sections.
- **Building**: Construct BEEF from subject transaction, ancestors (TXID → Tx map), and bump proofs (TXID → Bump map) with topological sorting via Kahn's algorithm (cycle detection included).
- **Verification**: Full SPV validation including Merkle root checks against block headers, UTXO tracking, value balance (fees ≥ 0, skipping coinbase), and script execution (P2PKH, multisig, etc., via `rust-sv`).
- **Atomic BEEF Support**: Enforce BRC-95 atomicity—only subject tx + direct ancestors, no siblings or unrelated txs—for focused micropayment proofs.
- **BUMP Integration**: Unique Merkle proofs for tx inclusion, with deduplication during build.
- **Extensibility**: `BlockHeadersClient` trait for custom header oracles (e.g., local index, remote Pulse API). Optional Paymail envelope wrapping (feature-gated).
- **Error Handling**: Detailed errors via `thiserror` (e.g., `Parse("Extra bytes")`, `Verification("Missing UTXO")`, `AtomicMismatch`).
- **Dependencies**: Lean stack with `rust-sv` for BSV-specific tx/script handling (P2P, sighash, etc.).

## Installation 📦

Add to your `Cargo.toml`:

```toml
[dependencies]
shia = "0.1.0"
```

For development (from GitHub, latest on dev branch):

```toml
[dependencies]
shia = { git = "https://github.com/murphsicles/shia", branch = "dev" }
```

For Paymail support (optional):

```toml
[dependencies]
shia = { version = "0.1.0", features = ["paymail"] }
```

- Requires Rust 1.82+ for edition 2024 features.
- CI workflow tested up to Rust 1.90. ✅
- No external services needed—pure offline SPV.

## Quick Start 📖

### Basic Parsing & Round-Trip
```rust
use shia::Beef;
use hex_literal::hex;

let beef_hex = "efbe00010001"; // Minimal: version (0100BEEF LE) + nBumps=0 + nTxs=1 + tx raw + flag=00
let tx_raw = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000");
let minimal_beef_hex = format!("efbe00010001{}{}", hex::encode(&tx_raw), "00");
let beef = Beef::from_hex(&minimal_beef_hex).expect("Valid BEEF");
let serialized = beef.serialize().expect("Serialize ok");
assert_eq!(hex::encode(serialized), minimal_beef_hex.to_lowercase());
```

### Building BEEF from DAG
```rust
use shia::{Beef, Transaction, Bump};
use std::collections::HashMap;
use hex_literal::hex;

let subject_raw = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0504ffff001dffffffff0100ca9a3b000000001976a914000000000000000000000000000000000000000088ac00000000");
let subject_tx = Transaction::from_raw(&subject_raw).unwrap();

// Example ancestor (parent tx)
let ancestor_raw = hex!("..."); // Parent tx raw bytes
let ancestor_tx = Transaction::from_raw(&ancestor_raw).unwrap();
let ancestors = HashMap::from([(ancestor_tx.txid(), ancestor_tx)]);

// Example bump for subject
let bump = Bump::new(subject_tx.merkle_hash(), vec![], 1); // Simplified
let bump_map = HashMap::from([(subject_tx.txid(), bump)]);

let beef = Beef::build(subject_tx, ancestors, bump_map, false).unwrap(); // Non-atomic
assert_eq!(beef.txs.len(), 2); // Subject + ancestor
```

### SPV Verification
```rust
use shia::client::BlockHeadersClient;

// Implement trait for your header source (e.g., local DB, remote API)
struct MyHeadersClient;
impl BlockHeadersClient for MyHeadersClient {
    fn is_valid_root_for_height(&self, root: [u8; 32], height: u64) -> bool {
        // Query your headers: e.g., check if root matches block at height
        true // Mock: always valid
    }
}

let mock_client = MyHeadersClient;
beef.verify(&mock_client).expect("SPV valid: roots, fees, scripts");
```

### Atomic BEEF (BRC-95)
For single-subject graphs (e.g., micropayments), enable atomic mode:
```rust
let atomic_beef = Beef::build(subject_tx, ancestors, bump_map, true).unwrap();
assert!(atomic_beef.is_atomic);
atomic_beef.verify(&mock_client).expect("Atomic valid: no extraneous txs");

// Validation enforces: txs.len() == ancestors.len(), all trace to subject
```

### TxID & Merkle Hash Convention
BSV txids are the **reversed** bytes of double-SHA256(raw tx) for display/hex (big-endian convention). `merkle_hash()` returns unreversed for BUMP leaves.

Example (Genesis Coinbase):
```rust
let genesis_raw = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
let tx = Transaction::from_raw(&genesis_raw).unwrap();
let txid = tx.txid(); // [0x4a, 0x5e, ... 0x3b] → "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
let merkle = tx.merkle_hash(); // Unreversed for proofs
```

## Structure 📁

- **`src/tx.rs`**: BSV Transaction wrapper—parsing (`from_raw`), hashing (`txid`/`merkle_hash`), script verification (`verify_scripts` with UTXO map).
- **`src/bump.rs`**: BRC-74 Bump struct—serialization, Merkle root computation for tx hashes.
- **`src/beef.rs`**: Core Beef struct—build (`build`), parse (`from_hex`/`deserialize`), verify (`verify`), serialize.
- **`src/atomic.rs`**: BRC-95 validation—`validate_atomic` ensures ancestry-only graphs.
- **`src/client.rs`**: `BlockHeadersClient` trait for Merkle root checks (e.g., against Teranode/Galaxy).
- **`src/utils.rs`**: VarInt read/write, double-SHA256 helpers.
- **`src/errors.rs`**: Comprehensive errors (Parse, Verification, ScriptEval, AtomicMismatch, etc.).

## Tests 🧪

Run with `cargo test --lib` for unit tests (parsing, building, verification, scripts). Doctests via `cargo test --doc`. CI (GitHub Actions) covers Rustfmt, Clippy, and full suite on push/PR. 100% coverage on core paths; includes genesis tx, P2PKH eval, topo-sort cycles.

Example failing case (pre-fix): Extra bytes in tx raw → `Parse("Extra bytes after transaction")`.

## Roadmap 🗺️

- **v0.2.0**: BRC-96 txid-only extension (compact agreed-tx representation).
- **Paymail Full**: Default-enabled BRC-70 envelopes for p2p payments.
- **Async/Streaming**: Non-blocking verify for high-volume wallets.
- **Bindings**: WASM/JS for web SPV, C FFI for C++ nodes.
- Contributions: PRs for BRC updates, more script ops, or header clients welcome!

## Dependencies 📚

- **Core**: `byteorder`, `hex`, `thiserror`, `anyhow`, `sha2`.
- **BSV**: `sv` (from GitHub: `git+https://github.com/murphsicles/rust-sv.git`).
- No runtime deps on services—offline-first.

## License 📄

MIT License. See [LICENSE](LICENSE) for details.

## Contributing 🤝

1. Fork & clone: `git clone https://github.com/murphsicles/shia`.
2. Branch: `git checkout -b feature/my-update`.
3. Test: `cargo test --lib --doc`.
4. Lint: `cargo fmt && cargo clippy`.
5. PR to `dev` branch with description/tests.

Issues/PRs at [GitHub](https://github.com/murphsicles/shia/issues). Focus on BSV scalability!

## Contact 📧

[murphsicles](https://github.com/murphsicles) – Built for BSV Freedom Stack & Teranode SPV. Questions? Open an issue!
