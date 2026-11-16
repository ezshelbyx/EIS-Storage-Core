# EIS Storage Core

Shared Rust library for storage operations across the E.I.S Storage Suite.

## Overview

EIS Storage Core provides low-level storage and USB device operations used by all E.I.S applications.

## Modules

| Module | Description |
|--------|-------------|
| `device` | USB device discovery and identification |
| `storage` | Storage volume enumeration and capacity detection |
| `crypto` | SHA-256, hashing, verification |
| `safety` | Destructive operation guards and device validation |
| `io` | Block device I/O (read-only by default) |

## Safety

- Read-only by default
- No formatting, wiping, or partitioning without explicit authorization
- Fail-closed capacity detection

## Build

```bash
cargo build
cargo test
```

## Roadmap

- [ ] M01: Core device discovery
- [ ] M02: Storage volume enumeration
- [ ] M03: SHA-256 hashing
- [ ] M04: Safety guards
- [ ] M05: JNI bridge
- [ ] M06: FFI for desktop
