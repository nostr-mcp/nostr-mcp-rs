# nostr-mcp-rs

Rust workspace for shared Nostr MCP utilities and a reference MCP tools server.

## Crates

- `nostr-mcp-core`: core storage, keys, relays, events, metadata, follows, polls, groups, and publishing helpers.
- `nostr-mcp-tools`: rmcp-based MCP tool server built on `nostr-mcp-core`.

## Toolchain

This repo pins Rust via `rust-toolchain.toml`.

## Build

```sh
cargo build
```

## Tests

```sh
cargo test -p nostr-mcp-core
cargo test -p nostr-mcp-tools
```

## Features

- `keyring`: enable OS keyring integration for secret storage.

Example:

```sh
cargo build -p nostr-mcp-tools --features keyring
```

## License

Unlicense. See `LICENSE`.
