# oxidrive

Self-hosted, end-to-end encrypted file and photo sync — an open-source alternative to
Proton Drive. The server stores only encrypted data: it can read neither file contents nor
file names or folder structure.

**Status: early development.** Milestone 1 is the Rust foundation — cryptography, chunking,
formats, the sync engine, the server and a headless daemon with a CLI. Nothing is usable yet.

## Crates

| crate | purpose |
|---|---|
| `oxisoft-drive-crypto` | keys, envelopes, AEAD, signatures, hybrid post-quantum key wrapping |
| `oxisoft-drive-chunking` | keyed content-defined chunking, padding, chunk objects |
| `oxisoft-drive-proto` | wire and storage formats |
| `oxisoft-drive-core` | sans-I/O sync engine |
| `oxisoft-drive-client` | client runtime: file system, watcher, network, index, keystores |
| `oxisoft-drive-daemon` | `oxidrived` background sync daemon and `oxidrive` CLI |
| `oxisoft-drive-server` | `oxidrive-server` |

## Running a server

See [docs/server.md](docs/server.md): configuration, TLS, PostgreSQL, accounts, backup and
restore.

## Development

Requires the Rust toolchain pinned in `rust-toolchain.toml` (installed automatically by
rustup) and these tools: `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `cargo-machete`,
`taplo`, `actionlint`, `zizmor`.

```sh
cargo xtask ci     # exactly what CI runs; must pass with zero warnings
cargo xtask test   # lints and tests only
cargo xtask deny   # vulnerability, licence and source check
```

## License

[AGPL-3.0-or-later](LICENSE).
