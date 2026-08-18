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

- **PC that does not boot (controlled engineering preview):** download the
  catalog-authorized `KernAid-Rescue-amd64` image, verify it, and use the
  catalog-enforcing Linux writer in `tools/make-device` to create the USB. The
  currently active writer v1 copies and verifies only the ISO prefix and does
  not provision the persistent vault; physical USB boot and firmware remain
  unqualified. On a successful boot, select the
  installed-system candidate in the left rail, and keep Secure Boot disabled
  for this engineering preview. The target is re-scanned before every session;
  target selection itself remains metadata-only. When **Diagnostica** starts,
  the qualified helper can inspect a direct leaf ext4 or NTFS installation
  read-only. For a Windows partition on GPT it also inspects exactly one
  unmounted direct-sibling FAT EFI System Partition, when uniquely qualified,
  and returns only fixed boot-marker booleans. No repair or unlock is attempted.
- **Windows, Linux or macOS that does boot:** download that operating system's desktop artifact, install it, and launch KernAid like a normal application. Windows and macOS startup collect only a fast, derived target identity; the deeper P0 collection starts once when **Diagnostica** is selected. macOS queries only the current-user `launchd` table and safe-boot integer, and explicitly reports system `launchd`, software-update availability, system-event analysis, and login/background-item counts as unqualified instead of inventing results. The fixed commands do not request repairs, although native Windows tools such as DISM may still update their own operating-system logs.
- **Optional Resident OpenAI reasoning:** configure the public
  `resident-default` profile from the hidden native TTY prompts of
  `kernaid-provider-key configure`, then explicitly select OpenAI in Desk. The
  companion is a separate, platform-matched workflow artifact and is not yet
  included in the desktop installer or added to `PATH`; extract it and run it
  from its download directory as described in the operator guide.
  The key stays in the OS credential store/backend; the webview receives only
  presence status and can request idempotent logout. Strict local packs reduce
  the complete OS corpus to a provider-neutral proposal before the bounded
  60-second HTTPS request; raw collector content is never sent. Offline rules
  remain the startup/default provider and require no account or network.
- **Do not use on customer data as a repair tool yet:** the current workflow diagnoses and stages an R0 no-write plan. It deliberately cannot execute real repairs.

The Rescue artifact is rebuilt and boot-tested in QEMU using both legacy BIOS
and UEFI firmware. Each test attaches only disposable target images, including
one same-disk GPT Windows fixture with NTFS and EFI partitions, requires the
local UI service and API to become ready, and verifies that each complete target
image is byte-identical before and after boot. A separate privileged two-boot
lifecycle qualifies an exact revision only when both BIOS and UEFI jobs pass;
it exercises the shipping Python UI server's strict same-origin HTTP-to-AF_UNIX
provider relay with provider networking disabled. It does not exercise Chromium
rendering, live provider TLS, a real account, Secure Boot, or physical media.

## Trust boundaries

The React UI talks only to a `SessionDriver`. Providers return diagnosis proposals and cannot reach the broker. Core validates plans and policy. The broker accepts an allowlisted typed envelope; in Phase 0 its only action is `system.observe.noop`.

See the [operator guide](docs/operator-guide.md), [architecture](docs/architecture/phase-0.md), [security policy](SECURITY.md), and the complete [masterplan](docs/MASTERPLAN.md).

## Current limitations

- Resident mode has one bounded diagnosis-only OpenAI Responses adapter plus
  deterministic offline rules. Rescue includes feature-gated persistent-vault,
  executor and loopback UI-server relay plumbing; an exact image is virtually
  qualified only when both privileged BIOS and UEFI lifecycle jobs pass. The
  active physical writer does not provision that vault, and live TLS with a
  real account, physical-media qualification and the isolated Codex CLI bridge
  remain incomplete.
- Native host inventory is intentionally limited and has no mutation or repair handler. Windows SFC is explicitly reported as `not-run-unqualified` until a locale-independent result adapter and physical qualification exist. macOS likewise leaves system-domain `launchd`, update freshness, incident counts, and login/background-item counts explicitly unqualified until observation-only sources are physically qualified. KernAid does not turn absent, stale or ambiguous data into a clean result.
- Promotion of encrypted Rescue persistence to trusted physical media, Secure
  Boot, physical-machine validation and actual repair actions remain release
  gates.
- Desktop artifacts are unsigned engineering previews.
