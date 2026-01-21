# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust-based WebAssembly plugin for the Extism platform that integrates with the Torbox API for torrent/usenet searching and instant download functionality. The plugin is used as part of a larger media management system (redseat).

## Build Commands

```bash
# Debug build
cargo build --target wasm32-unknown-unknown

# Release build
cargo build --target wasm32-unknown-unknown --release
```

Output: `target/wasm32-unknown-unknown/{debug|release}/redseat_plugin_torbox.wasm`

## Testing

Tests are run via the Extism CLI using JSON input files in the repository root:

```bash
# Test lookup function (Unix/macOS)
cat ./lookupinput.json | extism call ./target/wasm32-unknown-unknown/debug/redseat_plugin_torbox.wasm --allow-host '*' --log-level=info --wasi lookup --stdin

# Test process function (Windows PowerShell)
Get-Content -Raw -Path .\processinput.json | extism call target\wasm32-unknown-unknown\debug\redseat_plugin_torbox.wasm --allow-host '*' --log-level=info --wasi process --stdin

# Test request_permanent function
Get-Content -Raw -Path .\permanentinput.json | extism call target\wasm32-unknown-unknown\debug\redseat_plugin_torbox.wasm --allow-host '*' --log-level=info --wasi request_permanent --stdin
```

Test input files: `lookupinput.json`, `process.json`, `permanentinput.json`

## Architecture

Single-file library (`src/lib.rs`) with four exported plugin functions:

- **`infos()`** - Returns plugin metadata (name, capabilities, version)
- **`check_instant()`** - Checks if a torrent is available for instant download via Torbox cache
- **`process()`** - Processes magnet links and `torbox://` URLs into download requests
- **`request_permanent()`** - Handles permanent download requests with file selection for multi-file torrents
- **`lookup()`** - Searches Torbox API for torrents by movie/episode metadata (IMDB, TMDB, TVDB IDs)

### URL Handling

- Magnet links: `magnet:?xt=urn:btih:{hash}` - standard BitTorrent magnet format
- Internal URLs: `torbox://` - plugin-specific URLs with `_TOKEN_` placeholder for authentication
- BTIH hashes may be in hex (40 chars) or base32 (32 chars) format; the code normalizes to lowercase hex

### Authentication

Bearer token authentication via `credential.password` field in request JSON.

### Key Dependencies

- `extism-pdk` - Extism Plugin Development Kit for WASM
- `rs-plugin-common-interfaces` - Shared interfaces for redseat plugins
- `serde` - JSON serialization/deserialization

## Release Process

Automated via GitHub Actions (`.github/workflows/release.yml`). Bumping the version in `Cargo.toml` on main branch triggers a release build and creates a GitHub release with the WASM artifact.
