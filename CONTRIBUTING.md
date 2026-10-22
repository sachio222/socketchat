# Contributing to Socketchat

Thank you for helping. This page covers how to build and test Socketchat, how the code is laid out, how reviews work, and two rules every change follows: no home-made cryptography, and careful dependencies. Everyone who takes part follows the [code of conduct](CODE_OF_CONDUCT.md). If you want a bigger project to work on, [ROADMAP.md](ROADMAP.md) lists planned work.

## Build and test

You need the Rust toolchain from [rustup.rs](https://rustup.rs), version 1.91 or newer; `rust-toolchain.toml` picks Rust 1.98.1, the version CI and releases build with, and rustup installs it the first time you build here. On Linux, install the OpenSSL headers that SQLCipher (the encrypted local database) builds against:

```
sudo apt install build-essential pkg-config libssl-dev
```

Run every test with one command:

```
cargo test --workspace
```

The tests in `crates/socketchat-testkit` start real servers on free ports, with several headless clients talking to them over TLS. No setup is needed beyond the command above. Dependencies compile with optimization even in debug builds, because the post-quantum cryptography and Argon2 are too slow without it, so the first build takes several minutes.

Screen tests in `crates/socketchat-tui` compare rendered screens to snapshot files. If you change the screen on purpose, check each new snapshot line by line, then accept them with `INSTA_UPDATE=always cargo test -p socketchat-tui`.

The frame decoder has a fuzz target. With a nightly toolchain and `cargo install cargo-fuzz`:

```
cargo fuzz run frame_decoder
```

`scripts/idle-memory.sh` and `scripts/startup-time.sh` measure a release build against the performance targets in [docs/design.md](docs/design.md).

## Lint

Continuous integration runs these on every pull request, and a pull request must pass all of them:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
```

`cargo deny` checks dependencies for known vulnerabilities, licenses and sources, using `deny.toml`. Install it with `cargo install cargo-deny`.

When a pull request changes `Cargo.lock` or `scripts/crate-age-allow.txt`, continuous integration also runs:

```
sh scripts/crate-age-check.sh
```

It fails when `Cargo.lock` holds a library released less than 30 days ago, unless `scripts/crate-age-allow.txt` names that exact version with the reason. It asks crates.io about one library a second, so a full run takes several minutes. `sh scripts/crate-age-check.sh --since <an older Cargo.lock>` checks only the versions that file does not have.

## Crate map

| Crate | Job |
|---|---|
| `socketchat-proto` | Wire messages, framing and the invite link format. No cryptography and no I/O. |
| `socketchat-core` | The client engine with no screen: keys, MLS groups through OpenMLS, invites, verification, file encryption, encrypted local storage, and the connection to the server. |
| `socketchat-server` | The relay server: accounts, mailboxes, group logs, checks on group changes, invites, the file store and retention. |
| `socketchat-tui` | The terminal chat screen on top of `socketchat-core`, built with ratatui and crossterm. |
| `socketchat-testkit` | Test helpers that start a real server and headless clients, plus every integration test that needs both. |
| `socketchat` | The binary: the chat screen, `server` subcommands, and a few commands for scripts. |

[docs/architecture.md](docs/architecture.md) explains how they fit together, and [docs/protocol.md](docs/protocol.md) describes the bytes on the wire.

## How reviews work

- Keep pull requests small: one change, one reason. A large change is easier to review as a series.
- Write tests first. A new feature comes with tests that show it working against a real server where that applies.
- For a bug fix, first add a test that fails because of the bug, then fix the code so it passes. Reviewers check that the test fails without the fix.
- Explain any change to what the server stores or sees, and update [SECURITY.md](SECURITY.md) in the same pull request. Every security claim in the docs must match the code.

## No home-made cryptography

Every cryptographic primitive and protocol in Socketchat comes from a reviewed library or a published standard. A pull request that adds home-made cryptography will be declined.

This counts as home-made:

- your own cipher, hash, MAC, signature scheme, key exchange or random number generator;
- your own implementation of a standard primitive, when a reviewed library already has one;
- a new way of combining primitives where a standard construction exists, such as your own encryption mode or key derivation;
- changing how MLS works beyond what OpenMLS exposes.

This is fine: calling reviewed libraries in the way their documentation describes, using standard constructions such as HMAC-SHA256 or XChaCha20-Poly1305 STREAM, and adding a context string to a signature so it cannot be reused for another purpose, as `crates/socketchat-core/src/keys.rs` does.

If you are unsure, open an issue before you write the code.

## Dependencies

- A new crate, or a new version of one, must be at least 30 days old and widely used, with active maintainers. `sh scripts/crate-age-check.sh` checks the age (see "Lint").
- Pin versions in the workspace `Cargo.toml` and say in the pull request why the crate is needed.
- Flag any crate that runs code at build time beyond normal compiling, fetches anything over the network while building, or adds native libraries.
- `cargo deny check` must pass. An advisory may be ignored in `deny.toml` only with a written reason that explains why it does not apply.
