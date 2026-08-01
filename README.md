# KernAid

KernAid is an evidence-first machine diagnosis and repair platform. This repository implements the Phase 0 feasibility spike from `KERNAID_PRODUCT_AND_REPO_MASTERPLAN.md`.

The current vertical slice is deliberately safe: start a session, collect a normalized read-only Linux snapshot, ask a deterministic fake provider for a diagnosis, validate an R0 plan through Core, and export an auditable JSON/Markdown report. No target mutation is implemented.

## Quick start

Requirements: Rust stable (pinned by `rust-toolchain.toml`), Node 22, pnpm 9, and `just`.

```bash
just bootstrap
just check
just test
just run-desk
```

`just test-observe` copies a disposable fixture, runs the collector, then byte-compares the fixture tree. It never accepts a physical block-device path.

## Trust boundaries

The React UI talks only to a `SessionDriver`. Providers return diagnosis proposals and cannot reach the broker. Core validates plans and policy. The broker accepts an allowlisted typed envelope; in Phase 0 its only action is `system.observe.noop`.

See [architecture](docs/architecture/phase-0.md), [security policy](SECURITY.md), and the masterplan copied into `docs/`.

## Current limitations

- Fake provider only; API and Codex bridges are placeholders.
- Linux fixture collector only; host collection is not enabled by default.
- Rescue image, encrypted persistence, QEMU boot, and real hardware validation remain external release gates.
- Tauri bundle requires platform prerequisites and has not been built in this bootstrap environment.
