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

The CI workflows are configured to produce engineering-preview desktop installers for Windows, Linux, Intel macOS and Apple-silicon macOS, plus a separate amd64 hybrid BIOS/UEFI Rescue ISO. A build is usable only when its exact workflow and qualification gates pass; see [Current status](docs/CURRENT_STATUS.md) before downloading an artifact. Production distribution still requires Windows code signing and Apple signing/notarization.

## Use in the workshop

- **PC that does not boot (controlled engineering preview):** the private area
  exposes the exact stable retail Rescue candidate identified in
  [Current status](docs/CURRENT_STATUS.md) only for first physical-boot
  qualification. Verify its checksum and, on Windows, write it with Rufus in
  DD mode to a factory-new or disposable USB of at least 32 GB. The trusted v2
  catalog revision 8 authorizes only this exact ISO, so the Linux writer can
  verify, copy and provision its encrypted vault. Rufus only writes the
  qualified zero-state retail image; first live boot provisions the Vault after
  local passphrase confirmation.
  The promoted immutable internal release is `0.1.0-internal.6`: artifact
  `ci-33330139973-1`, built from commit
  `5db47001fad2a3814d90837bcdcea545b2da0fa9` by Rescue run `33330139973`
  attempt 1.
  Its exact ISO is `1,223,540,736` bytes with SHA-256
  `fe8d54d8e154f6a4712c65855b5dffdcb31dddeac0d3a03c299d606f87a16000`;
  the compressed retail image is `1,191,669,060` bytes with SHA-256
  `efc5d4d0c428d0f7a992eb21154c4243c5566d7c85d6481e174c43cac909aa9b`.
  Release Channel v1 sequence 6 binds those files in a canonical manifest with
  SHA-256 `11d15af0ef07b78760f468f3302cd398255c072dba0920b868c967f53206e674`.
  The stable build compiled with repair disabled and passed the shipping-image
  gate proving that repair UI, handlers, units and write surfaces are absent.
  It replaces the retired `0d61eac` physical-test candidate, which reached
  Xorg on an Intel PC but painted only a black frame and movable pointer. Start
  with the normal branded boot entry; if it cannot establish a usable display,
  reboot and select **KernAid Rescue - Compatibility graphics**.
  Physical USB boot and firmware remain unqualified. On a successful boot,
  select the
  installed-system candidate in the left rail, and keep Secure Boot disabled
  for this engineering preview. The target is re-scanned before every session;
  target selection itself remains metadata-only. When **Diagnostica** starts,
  the qualified helper can inspect a direct leaf ext4 or NTFS installation
  read-only. For a Windows partition on GPT it also inspects exactly one
  unmounted direct-sibling FAT EFI System Partition, when uniquely qualified,
  and returns only fixed boot-marker booleans. No repair or unlock is attempted.
  Linux P0 snapshot parity between Resident and Rescue v1 is limited to content
  on the root filesystem. If the installation's `fstab` declares a separate
  mount at or below `/etc` (including `/etc/machine-id`), `/boot` (including
  `/boot/efi`), `/efi`, `/usr`, or `/var`, KernAid marks the corpus unsupported
  and blocks diagnosis; multi-mount parity is not claimed.
  The signed persistent-report path requires a Vault provisioned by the Linux
  v2 writer or retail first boot: unlock it from the native TTY before Desk
  initializes. After diagnosis, use
  `kernaid-rescue-vaultctl report-list` and
  `kernaid-rescue-vaultctl report-export RP-...` to place a verified envelope
  at `/home/kernaid/KernAid-Reports/<id>.signed.json`. The stable
  `0.1.0-internal.6` ISO passed persistence, retrieval and fixed-path
  signed-envelope export on that same artifact under virtual BIOS and UEFI.
  Physical USB behavior remains a separate qualification gate.
  A newer diagnosis-only ISO from commit `aa8255a`, Rescue run `33455599335`,
  is separately available in the authenticated area for controlled physical
  boot/UI investigation. Its core build, branded UI/input, BIOS/UEFI Secure
  Boot and USB-style two-boot gates passed, but all three Vault jobs failed at
  `firstboot-confirmation`. It does not replace this stable image. The repair
  candidate remains private, unavailable and unpromoted; current exact evidence
  is maintained in
  [Current status](docs/CURRENT_STATUS.md).
  The follow-up `be88efa` cut is still being evaluated by Rescue run
  `33459542561`, Desktop run `33459542555` and repair run `33459558782`; no
  outcome is claimed while those workflows remain in progress.
- **Windows, Linux or macOS that does boot:** use the matching unsigned artifact from immutable release `0.1.0-internal.6`, built by Desktop run `33330140025` attempt 1 from the same exact source as Rescue. All four platform jobs and their package-inspection gates passed. Install it and launch KernAid like a normal application; CI packaging is not physical installation or complete GUI qualification. The gate rejects Desk packages containing the separately distributed credential companion. Windows and macOS startup collect only a fast, derived target identity; the deeper P0 collection starts once when **Diagnostica** is selected. macOS queries only the current-user `launchd` table and safe-boot integer, and explicitly reports system `launchd`, software-update availability, system-event analysis, and login/background-item counts as unqualified instead of inventing results. The fixed commands do not request repairs, although native Windows tools such as DISM may still update their own operating-system logs. After diagnosis, retain the JSON as the authoritative machine-readable artifact; the additional Markdown download is an explicitly unsigned reading copy.
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
  Separately, Agent Gateway now exports bounded one-shot Anthropic Messages
  and Gemini Interactions adapters. They send the same provider-neutral,
  evidence-bound diagnosis projection, request strict JSON, expose no tools or
  broker access, reject redirects and foreign evidence IDs, and obtain API
  keys only from a runtime secret supplier. They are library implementations,
  not yet wired into the shipping Desk/Rescue selector or qualified against
  live vendor accounts.
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

The private repair candidate has a separate, narrower workflow. Source now
contains four off-default actions. Its consolidated exact-image harness now
reuses one provisioned Rescue/Vault base across isolated scenario copies: the
existing `fstab` apply/failure/recovery matrix, `crypttab` apply plus fresh
explicit rollback, ext4 preen plus a clean read-only postcheck, and exact
resolver-link restoration. This is implemented qualification logic, not a
successful remote workflow or a promoted ISO. All four corresponding Fleet
repair intents also reach this local Rescue boundary, but cannot bypass a fresh
target/evidence-bound local approval. Repair run `33459558782` from commit
`be88efa` is in progress and has no claimed outcome. Power-loss, physical USB,
hardware, firmware, Secure Boot and customer-data gates remain open.

Fleet Resident workflow source also contains native staged package-lifecycle
gates. Linux inspects and runs the exact built `.deb` once in an isolated root;
Windows registers the packaged executable as an on-demand `LocalService`,
proves it remains stopped, exercises the fail-closed one-shot path and
uninstalls it; the native macOS matrix leg verifies disabled LaunchAgent
settings, exercises the same no-anchor failure and cleans up. These checks use
no enrollment identity or signing key. The exact automated lifecycle passed in
Linux run `33459558805`, Windows run `33459558875` and macOS run
`33459559165`. Those green package gates do not replace signing, real
enrollment, native secret-store or physical endpoint qualification.

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

- Shipping Resident Desk still has one bounded diagnosis-only OpenAI Responses
  integration plus deterministic offline rules. The tool-free Anthropic and
  Gemini adapters exist in Agent Gateway source but are not yet wired into a
  product selector or remotely qualified. Rescue includes feature-gated
  persistent-vault, signed-report, executor and loopback UI-server relay
  plumbing; an exact image is virtually qualified only after the full Rescue
  workflow passes, including both privileged BIOS and UEFI lifecycle jobs. The
  v2 writer can provision that vault only for an exact catalog-authorized image
  on factory-new controlled-lab media; revision 8 authorizes the exact current
  internally qualified candidate.
  The Rescue report relay is loopback/internal-only; the exact current image
  passed its signed-report shipping lifecycle under virtual BIOS and UEFI.
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
