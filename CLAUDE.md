# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workspace layout

Hickory DNS is a Cargo workspace (resolver = "2", MSRV 1.88) of DNS libraries plus the `hickory-dns` server binary.

- `crates/proto` — lowest-level DNS message encoding/decoding and transports. Everything depends on this.
- `crates/resolver` — stub resolver (CNAME chasing, caching) abstracted over async runtimes; Tokio by default.
- `crates/server` — authoritative server library used by the `hickory-dns` binary; zone hosting, recursion, forwarding.
- `crates/net` — shared networking primitives.
- `bin/` — the `hickory-dns` server binary (`bin/src/hickory-dns.rs`, with config parsing in `bin/src/config/`).
- `util/` — CLI utilities (e.g. `resolve`, DNSSEC tools).
- `tests/integration-tests`, `tests/test-support`, `tests/test-data` — cross-crate integration tests, shared test helpers, and fixtures (certs, zones, `test_configs/*.toml`).
- `conformance/` — Docker-based interop test suite that runs hickory-dns against BIND and Unbound; excluded from the main workspace.
- `fuzz/` — `cargo-fuzz` targets; excluded from the main workspace (built with its own `Cargo.lock`).

See `ARCHITECTURE.md` for the historical rationale (e.g. why some hand-rolled `Future` state machines remain).

## Cryptography provider feature flags

Anything needing crypto (DNSSEC, DoT, DoH, DoQ, DoH3) is feature-gated and **must** pick a backend: `aws-lc-rs` or `ring`. Features come in matched pairs, e.g.:

- `tls-aws-lc-rs` / `tls-ring`
- `https-aws-lc-rs` / `https-ring`
- `quic-aws-lc-rs` / `quic-ring`
- `h3-aws-lc-rs` / `h3-ring`
- `dnssec-aws-lc-rs` / `dnssec-ring`

When adding a feature that needs crypto, mirror this pairing rather than introducing a single feature.

## Commands

The canonical task runner is [`just`](https://github.com/casey/just); recipes use `cargo ws exec` (cargo-workspaces) to fan out across crates.

- `just` — check + build + test all crates with default features.
- `just all-features` / `just no-default-features` / `just std` — same matrix with different feature sets.
- `just tls-aws-lc-rs` / `just dnssec-ring` / etc. — per-feature matrices (see `justfile` for the full list; each one ignores crates that don't apply).
- `just clippy` — clippy with `-D warnings` across `--all-features`, `--no-default-features`, and default features, plus the fuzz crate.
- `just fmt` — `cargo fmt -- --check` across the workspace and the fuzz crate.
- `just audit` — `cargo audit --deny warnings` on the workspace and `fuzz/Cargo.lock`.
- `just cleanliness` — clippy + fmt + audit.
- `just coverage` / `just coverage-html` / `just coverage-lcov` — coverage via `cargo +nightly llvm-cov` (pinned nightly date in `justfile`).
- `just generate-test-certs` — regenerate the TLS fixtures under `tests/test-data/` (test certs expire yearly).
- `just conformance` / `just conformance-hickory` / `just conformance-bind` / `just conformance-unbound` — Docker-based conformance suite. Uncommitted changes are **not** picked up by `conformance-hickory`; commit first.

Plain cargo equivalents work too:

- Build / test one crate: `cargo test -p hickory-proto`, `cargo test -p hickory-server --all-features`.
- Run a single test: `cargo test -p hickory-resolver name::of::test -- --nocapture`.
- Run the server: `cargo run -p hickory-dns -- -c path/to/named.toml -d` (default config path is `/etc/named.toml`; `--validate` parses the config and exits; `-z` overrides the zone-file root directory).

The fuzz crate has its own `Cargo.toml` and `Cargo.lock`; build it with `--manifest-path fuzz/Cargo.toml`.

## Server config

The `hickory-dns` binary is config-driven. Parsing lives in `bin/src/config/mod.rs`; example/test configurations live in `tests/test-data/test_configs/` and are the best reference when changing config schema. Use `hickory-dns --validate -c <path>` to dry-run a config.

## Project conventions

- No panics: the project explicitly aims for panic-free code with proper `Result` handling (see README "Goals"). Avoid `unwrap`/`expect` in non-test code.
- Stable Rust only.
- Crate versions in `[workspace.dependencies]` are pinned with `=` between sibling hickory crates — bump them together.
- When touching DNSSEC, TLS, or HTTPS code, run the matching `just <feature>` recipe; clippy and tests behave differently per feature set.
