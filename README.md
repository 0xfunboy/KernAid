# KernAid

KernAid is an evidence-first machine diagnosis and repair platform. This repository implements the Rescue, Desk and Enterprise vertical slices described in the [masterplan](docs/MASTERPLAN.md) under the active [seven-day RC execution plan](docs/RC_EXECUTION_PLAN.md). For the concise, date-stamped distinction between what works now and what remains unqualified, start with [Current status](docs/CURRENT_STATUS.md). For a compact map of the product, repository, build host and release flow, see the [Project map](docs/PROJECT_MAP.md). Fleet operators and integrators should use the [Enterprise engineering guide](docs/ENTERPRISE.md).

The current Phase 0 engineering vertical slice is deliberately safe: start a session, collect a normalized read-only host snapshot, run deterministic offline diagnostic rules, validate an R0 plan through Core, and produce a hashed JSON report. Resident Desk exposes that machine-readable JSON as the authoritative session artifact: it is a signed envelope when secure audit is active and an explicitly unsigned JSON artifact otherwise. Desk also derives a human-readable Markdown copy, always labeled unsigned; it is for reading and does not replace the JSON artifact or prove authenticity. In Rescue, when the encrypted Vault is unlocked before Desk starts, the JSON report and its audit sequence are persisted as a signed envelope and can be exported later from the native TTY companion. The default/stable product has no production mutation handler. Current source contains separate private, feature-gated `fstab`, `crypttab`, ext4 and resolver-link candidates, but none is promoted or supported on customer data. See [Current status](docs/CURRENT_STATUS.md) for the exact latest workflow evidence. On Linux, a separate opt-in `fixture-repair-lab` Desk build sends one complete, explicitly approved repair and separately approved rollback through the standard SessionDriver, Agent Gateway, Core transaction states and typed broker against an internally created disposable fixture. It is absent from normal builds and Rescue and cannot select a host path, disk or production target.

## Quick start

Requirements: Rust stable (pinned by `rust-toolchain.toml`), Node 24.18.0, pnpm 9, and `just`.

On Debian or Ubuntu development hosts, install the native linker and Tauri
prerequisites used by CI before running the commands below:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libwebkit2gtk-4.1-dev curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

```bash
just bootstrap
just check
just test
just run-desk
```

To exercise the closed repair cycle on Linux without touching the host target,
run `just run-desk-fixture`. The panel is compiled only into that development
build and uses a fresh temporary fixture and journal on every launch.

`just test-observe` runs against the repository-owned Linux fixture and compares
every file path and byte before and after collection. It never accepts a
physical block-device path.

The CI workflows produce engineering-preview desktop installers for Windows,
Linux, Intel macOS and Apple-silicon macOS, plus separate amd64 hybrid BIOS/UEFI
diagnosis and repair Rescue images. Current diagnosis source commit
`6e9742e5b0c4397728dde80e9a0a91a09214f7cd` passed [CI run
33486399168](https://github.com/0xfunboy/KernAid/actions/runs/33486399168)
and the complete four-platform [Desktop run
33486399165](https://github.com/0xfunboy/KernAid/actions/runs/33486399165).
Rescue run `33486399275` passed its build and integrated BIOS/UEFI boot and
USB-style two-boot matrix, but failed the separate UEFI Vault lifecycle
readiness gate. It is therefore a private physical-test candidate, not a
promoted release. Production distribution still requires Windows code signing
and Apple signing/notarization.

## Use in the workshop

- **PC that does not boot (controlled engineering preview):** use only an exact
  diagnosis image whose adjacent checksum you have verified. The authenticated
  site exposes the exact run `33486399275` physical-test ISO from `6e9742e`,
  1,307,344,896 bytes, SHA-256
  `8a971474335846495903d2a314145e3cb3a04fdb930405461eb215bbc66c46da`.
  It is not catalog-authorized or promoted because its UEFI Vault lifecycle
  stopped at `stage=readiness code=not-ready`; use it only to retest physical
  boot, graphics, input and diagnosis on non-customer hardware. On Windows,
  write it with Rufus in DD mode to a factory-new or disposable USB of at least
  32,000,000,000 bytes. Keep Secure Boot disabled for this engineering test.
  Start with the normal branded entry and use **KernAid Rescue - Compatibility
  graphics** only when needed. Exact commands and release evidence live in
  [Current status](docs/CURRENT_STATUS.md) and the [operator
  guide](docs/operator-guide.md).
- **Windows, Linux or macOS that does boot:** the complete unsigned packaging
  matrix from commit `6e9742e5b0c4397728dde80e9a0a91a09214f7cd`
  passed [Desktop run 33486399165](https://github.com/0xfunboy/KernAid/actions/runs/33486399165)
  for Windows x86-64, Linux x86-64, Intel macOS and Apple-silicon macOS.
  Installers remain engineering previews: CI packaging is not physical
  installation, publisher signing or complete GUI qualification. The package
  gate rejects inclusion of the separately distributed credential companion.
  Windows and macOS startup collect only a fast derived target identity; deeper
  P0 collection starts once when **Diagnostica** is selected. After diagnosis,
  retain JSON as the authoritative machine-readable artifact; Markdown is an
  explicitly unsigned reading copy.
- **Linux machine inventory:** Resident and Rescue use the same bounded Rust
  collector for CPU count/model, total RAM, firmware boot mode, selected public
  DMI model fields, and normalized PCI/USB class/vendor/product IDs. It excludes
  serial numbers, UUIDs, asset tags, bus addresses and arbitrary paths, and
  reports each source as complete, partial, truncated, unavailable or invalid
  instead of converting missing data into a healthy result.
- **Optional Resident reasoning:** the current Desk integration can configure
  the public `resident-default` profile from the hidden native TTY prompts of
  `kernaid-provider-key configure`, optionally adding `--provider anthropic` or
  `--provider gemini`, then explicitly select the configured provider in Desk. The
  companion is a separate, platform-matched workflow artifact. Current source
  builds it from a package outside the Tauri crate, and the Desktop workflow
  fails if package inspection finds it inside a Desk installer. Use only a
  post-change run where that gate passed; extract the companion and run it from
  its download directory as described in the operator guide.
  Each provider key stays in its independently purpose-bound OS credential
  store record; the webview receives only presence status and can request
  idempotent logout. Strict local packs reduce
  the complete OS corpus to a provider-neutral proposal before the bounded
  60-second HTTPS request; raw collector content is never sent. Offline rules
  remain the startup/default provider and require no account or network.
  Anthropic Messages and Gemini Interactions are now wired into the Resident
  Desk selector through native Tauri commands. They send the same
  provider-neutral, evidence-bound diagnosis projection, request strict JSON,
  expose no tools or broker access, reject redirects and foreign evidence IDs,
  and load keys only inside the native runtime from independently
  purpose-bound OS credential records. The WebView receives presence-only
  status and sanitized proposals. Packaging passed Desktop run `33486399165`;
  real vendor accounts and live API behavior remain external qualification
  gates. Rescue remains Offline/OpenAI only.
- **Do not use on customer data as a repair tool yet:** the current workflow diagnoses and stages an R0 no-write plan. It deliberately cannot execute real repairs.

Qualified Rescue candidates pass three separate QEMU gates under both legacy
BIOS and UEFI. The ordinary boot smoke requires the local UI and API, the
shipping Tauri/WebKitGTK shell and descendant renderer, a visible branded
framebuffer, a real keyboard event, and byte-identical disposable targets. A
USB-style gate then boots the same raw image twice and verifies its pinned
layout and persistent vault without altering the ISO prefix or unrelated target
regions. Finally, privileged lifecycle jobs exercise the shipping Python UI
server's strict same-origin HTTP-to-AF_UNIX provider relay with provider
networking disabled. Raw screenshots are never published. These gates do not
exercise live provider TLS, a real account, physical Secure Boot, or physical
media. The
current workflow and downloadable-artifact status is tracked in
[Current status](docs/CURRENT_STATUS.md); do not infer that every `main` commit
has produced a publishable ISO.

The private repair candidate has a separate, narrower workflow. Source contains
four off-default actions. Its consolidated exact-image harness reuses one
provisioned Rescue/Vault base across isolated scenario copies: the `fstab`
apply/failure/recovery matrix, `crypttab` apply plus fresh explicit rollback,
ext4 preen plus a clean read-only postcheck, and exact resolver-link
restoration. All four corresponding Fleet intents reach the local Rescue
boundary but cannot bypass a fresh target/evidence-bound local approval. The
adapter contract passed its disposable four-action approval/broker/Vault test;
that does not qualify a shipping ISO. Repair run `33482972849` on commit
`01cf8fe` failed at the UEFI crypttab provider-proof step; no qualified Repair
ISO or publisher was produced, and the candidate remains unavailable.
Power-loss, physical USB, hardware, firmware, Secure Boot and customer-data
gates remain open.

Fleet Resident source now has explicit one-shot enrollment on Linux, Windows
and macOS: it creates or loads the platform-bound native device identity, signs
the fixed `/v1/enrollments` request, consumes the one-use token only after an
accepted response and requires the persisted public binding before normal
service startup. Native package workflows inspect the exact staged artifact,
prove startup remains disabled, exercise the fail-closed no-anchor path and
  clean up. The current packages from commit `fe3c940d525f5c1c2ecd8123bdb100cd3280b908`
  passed Linux run [33471097700](https://github.com/0xfunboy/KernAid/actions/runs/33471097700),
  Windows run [33471100838](https://github.com/0xfunboy/KernAid/actions/runs/33471100838)
  and macOS run [33471099291](https://github.com/0xfunboy/KernAid/actions/runs/33471099291).
Those automated gates include the explicit enrollment contract but do not
replace publisher signing, hardware-backed key-store behavior or a physical
endpoint-to-production-Fleet qualification.

The Fleet control plane's focused disposable cryptographic E2E is green on the
current source: enterprise license, one-use token and signed enrollment,
policy, entitlement, update, typed work-order claim/result, service receipt,
audit and console-session boundaries all passed against temporary SQLite only.
The signed scheduled backup is active, and its independent verify/restore drill
passed to a disposable destination without overwriting the live database.

The live internal Fleet service is schema v13. Its closed work-order catalog
contains all four Rescue repair identifiers, but the stable image still contains
no repair surface and no repair action is promoted.

Signed Fleet policy now recognizes the closed provider-mode catalog
`offline`, `openai_api`, `openai_compatible`, `anthropic_api`, `gemini_api` and
`enterprise`. Policy can only remove modes from the device's local allowlist;
it cannot enable an unsupported adapter or grant broker authority.

## Trust boundaries

The React UI talks only to a `SessionDriver`. Providers return diagnosis proposals and cannot reach the broker. Core validates plans and policy. The default production broker accepts an allowlisted typed envelope; in Phase 0 its only action is `system.observe.noop`.

See [Current status](docs/CURRENT_STATUS.md), the [operator guide](docs/operator-guide.md), [Enterprise guide](docs/ENTERPRISE.md), [architecture](docs/architecture/phase-0.md), [security policy](SECURITY.md), and the complete [masterplan](docs/MASTERPLAN.md).

## Current limitations

- Shipping Resident Desk has bounded diagnosis-only OpenAI Responses,
  Anthropic Messages and Gemini Interactions integrations plus deterministic
  offline rules. All three remote providers are native, tool-free and
  credential-isolated; only live real-account qualification remains open.
  Rescue includes feature-gated
  persistent-vault, signed-report, executor and loopback UI-server relay
  plumbing; an exact image is virtually qualified only after the full Rescue
  workflow passes, including both privileged BIOS and UEFI lifecycle jobs. The
  writer can provision that vault only for an exact catalog-authorized image on
  factory-new controlled-lab media.
  The Rescue report relay is loopback/internal-only. Current-source run
  `33486399275` failed UEFI Vault lifecycle readiness, so its downloadable
  physical-test candidate makes no signed-report or persistence claim.
  Real-account Codex authorization, live provider TLS and physical-media
  qualification remain incomplete.
- Native production host inventory has no mutation or repair handler; the
  opt-in fixture lab is not a production host path. The parameter-free Linux
  hardware command, schema and packaging are virtually exercised, and the CI
  gate requires complete core CPU/RAM facts. DMI/PCI/USB shapes have shared
  fixture coverage, while physical hardware compatibility remains a release
  gate. Windows SFC is explicitly reported as
  `not-run-unqualified` until a locale-independent result adapter and physical
  qualification exist. macOS likewise leaves system-domain `launchd`, update
  freshness, incident counts, and login/background-item counts explicitly
  unqualified until observation-only sources are physically qualified. KernAid
  does not turn absent, stale or ambiguous data into a clean result.
- Promotion of encrypted Rescue persistence to trusted physical media, Secure
  Boot, physical-machine validation and actual repair actions remain release
  gates.
- Desktop artifacts are unsigned engineering previews.
