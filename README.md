# KernAid

KernAid is an evidence-first machine diagnosis and repair platform. This repository implements the Phase 0 feasibility spike from `KERNAID_PRODUCT_AND_REPO_MASTERPLAN.md`.

The current vertical slice is deliberately safe: start a session, collect a normalized read-only host snapshot, run deterministic offline diagnostic rules, validate an R0 plan through Core, and export a downloadable, hashed JSON report. No target mutation is implemented.

## Quick start

Requirements: Rust stable (pinned by `rust-toolchain.toml`), Node 24.18.0, pnpm 9, and `just`.

```bash
just bootstrap
just check
just test
just run-desk
```

`just test-observe` copies a disposable fixture, runs the collector, then byte-compares the fixture tree. It never accepts a physical block-device path.

CI produces engineering-preview desktop installers for Windows, Linux, Intel macOS and Apple-silicon macOS, plus a separate amd64 hybrid BIOS/UEFI Rescue ISO. Download them from the successful GitHub Actions run artifacts. Production distribution still requires Windows code signing and Apple signing/notarization.

## Use in the workshop

- **PC that does not boot:** download the `KernAid-Rescue-amd64` artifact, verify the included SHA-256 file, write the ISO to a USB drive, disable Secure Boot for this engineering preview, and boot the PC from USB. KernAid opens automatically in the live desktop.
- **Windows, Linux or macOS that does boot:** download that operating system's desktop artifact, install it, and launch KernAid like a normal application. It collects only the fixed, read-only inventory commands exposed by the native shell.
- **Do not use on customer data as a repair tool yet:** the current workflow diagnoses and stages an R0 no-write plan. It deliberately cannot execute real repairs.

The Rescue artifact is rebuilt and boot-tested without a target disk in QEMU using both legacy BIOS and UEFI firmware. Secure Boot and physical-machine compatibility remain release gates, not claimed capabilities.

## Trust boundaries

The React UI talks only to a `SessionDriver`. Providers return diagnosis proposals and cannot reach the broker. Core validates plans and policy. The broker accepts an allowlisted typed envelope; in Phase 0 its only action is `system.observe.noop`.

See [architecture](docs/architecture/phase-0.md), [security policy](SECURITY.md), and the masterplan copied into `docs/`.

## Current limitations

- Deterministic offline rules only; API and Codex bridges are placeholders.
- Native host inventory is read-only and intentionally limited; diagnosis still uses the normalized fixture flow.
- Encrypted persistence, Secure Boot, physical-machine validation and actual repair actions remain release gates.
- Desktop artifacts are unsigned engineering previews.
