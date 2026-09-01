# KernAid current status

Last updated: 1 September 2026

This page separates the product vision from what the repository can safely do
today. The short version is: **the stable customer image is still a
diagnosis-only engineering preview; repair and Enterprise capabilities are
implemented in separate off-default candidates and must clear their remaining
qualification gates before they become supported customer paths.**

## Product in one minute

KernAid is an evidence-first platform for diagnosing and eventually repairing
computers through a controlled workflow:

```text
Observe → Diagnose → Plan → Approve → Repair → Verify → Roll back if needed
```

The model never receives a privileged raw shell. Collectors produce bounded,
typed evidence; Core validates plans and policy; only a narrow broker may ever
perform an approved mutation. Phase 0 deliberately stops before production
mutation.

The product family has four active engineering surfaces:

- **KernAid Desk** runs inside a working Windows, Linux or macOS installation.
- **KernAid Rescue** is an amd64 bootable environment for a machine whose
  installed operating system does not start.

- **KernAid Fleet** enrolls and inventories managed devices, distributes
  restrictive policy, entitlements and updates, operates typed work orders and
  tracks signed incident cases.
- **KernAid Media Creator** is an off-default Windows writer for an exact
  catalog-authorized retail image and disposable USB target.

Signed production releases, physical Secure Boot qualification, WinPE and
production promotion of repair packs remain open milestones.

## What works now

| Area                                             | Current engineering state                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Desk UI                                          | Tauri/React desktop shell with Windows, Linux, Intel macOS and Apple-silicon macOS build targets                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Rescue UI                                        | Branded Tauri/WebKitGTK shell in the Debian live image, with explicit runtime/readiness gates                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Target handling                                  | Candidate discovery and explicit target selection; target filesystems remain read-only                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Evidence                                         | Normalized Linux, Windows and macOS diagnosis inputs, bounded hardware/storage/filesystem/boot observations and provenance framing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Diagnosis                                        | Deterministic offline rules plus bounded optional Resident OpenAI Responses, Anthropic Messages and Gemini Interactions integrations. All three are wired into the Desk selector through native Tauri commands. Desk exposes only closed provider modes, presence-only status and sanitized proposals; credentials, fixed HTTPS transport and vendor parsing stay native. The adapters have no tools, broker or fallback. A provider remains disabled until its independently purpose-bound OS credential is provisioned. Packaging is green; live vendor-account qualification remains external. Rescue remains Offline/OpenAI only.                                                                                                            |
| Planning                                         | Typed R0 no-write plan validated by Core                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Reporting                                        | Resident Desk exposes authoritative machine-readable JSON: a signed envelope when secure audit is active, otherwise an explicitly unsigned hashed JSON artifact. It also derives an always-unsigned human-readable Markdown copy that does not replace the JSON. Rescue can persist the exact signed JSON report plus audit sequence in the Vault and export it through the native TTY companion                                                                                                                                                                                                                                                                                                                                                 |
| Rescue credential boundary                       | Isolated credential vault and fail-closed Codex login/status/logout bridge; it does not run prompts or diagnoses                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Rescue provider plumbing                         | Feature-gated OpenAI executor and loopback relay are implemented, but live TLS and a real-account lifecycle are not yet qualified                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Exact-image harness                              | Disposable QEMU fixtures, byte-level mutation checks, BIOS/UEFI boot and two-boot USB/Vault coverage. Diagnosis run `33486399275` on `6e9742e` passed its integrated build/boot/USB matrix but failed UEFI Vault readiness. Repair run `33482972849` on `01cf8fe` failed at `uefi:crypttab-lifecycle` (`provider-proof/command-failed`); neither ISO was promoted.                                                                                                                                                                                                                                                                                                                       |
| Repair experiment                                | Linux-only feature-gated Desk lab for one typed R2 repair and separately approved rollback on an internal temporary fixture. It now traverses the standard `SessionDriver`, Agent Gateway, explicit Core transaction states and typed broker; it remains absent from normal/Rescue builds and disconnected from production targets                                                                                                                                                                                                                                                                                                                                                                                                               |
| Feature-gated Rescue repair candidate            | Off-default `fstab`, `crypttab`, ext4 and resolver-link recovery actions traverse the closed UI/Core/broker boundary. They bind a descriptor-retained target, reserve evidence on a distinct authenticated Vault, require typed single-use approval, verify the result and expose rollback or truthful manual reconciliation. The stable image excludes every repair surface.                                                                                                                                                                                                                                                                                                                                                                    |
| `fstab` recovery                                 | `linux.fstab.disable-missing-uuid.v1` atomically disables only a freshly proven missing, non-critical ext4 UUID entry and supports exact restore, automatic restore and restart reconciliation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `crypttab` recovery                              | `linux.crypttab.disable-missing-uuid.v1` rejects critical mappings, external key sources, ambiguity and mandatory `fstab` consumers; the candidate includes Vault reservation, atomic execution, verification, UI, exact rollback and restart reconciliation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ext4 recovery                                    | `linux.ext4.fsck-preen-with-undo.v1` is an R3, unmounted-target action using bounded `e2fsck -p -f -z`, read-only verification and same-boot `e2undo`; it explicitly stops for manual reconciliation when exact recovery cannot be proved.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Resolver-link recovery                           | `linux.network.restore-resolver-link.v1` restores only the fixed resolver symlink after proving exactly one supported resolver, preserves the exact missing/link pre-state in the Vault and never starts or restarts a service.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Fleet control plane                              | Live internal schema v13: signed enrollment/inventory/audit/policy/entitlement/update delivery, secure browser sessions, RBAC, typed Linux, Windows and macOS work orders, incident cases and service receipts. The v13 closed work-order catalog admits all four Rescue repair identifiers while preserving the approval, lease and device bindings. Offline Ed25519 commercial licensing is active for the internal tenant; expiry, revocation, seat limits and clock rollback fail closed for paid operations.                                                                                                                                                                                                                                |
| Fleet disposable E2E                             | The focused current-source run passed 7/7 real HTTP control-plane cases on temporary SQLite with Node.js 24.18.0: commercial license, one-use enrollment token, Ed25519 enrollment, signed policy and update pulls, entitlement-governed work-order claim/result with verified service receipts, signed audit listing and CSRF-bound console session. The four-action Fleet-to-Rescue approval/broker/Vault contract passed 1/1 and the Desk approval boundary passed 2/2. No live Fleet state was mutated.                                                                                                                                                                                                                                      |
| Fleet provider policy                            | Signed policy uses the closed modes `offline`, `openai_api`, `openai_compatible`, `anthropic_api`, `gemini_api` and `enterprise`. A mode is usable only when both local capability and signed policy allow it; policy cannot create an unsupported adapter or broker authority.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Fleet backup                                     | The live SQLite service has a scheduled, signed three-file backup bundle. The online copy is converted from WAL mode into one standalone database before its canonical manifest is signed; offline verify/restore reject tampering, wrong keys, sidecars, symlinks and overwrite. The scheduled service and an independent verify/restore drill to a disposable destination are green; the drill never overwrote the active database.                                                                                                                                                                                                                                                                                                            |
| Linux Fleet Resident                             | A disabled-by-default amd64 `.deb` packages signed sync, the three closed Linux R0 diagnostic work orders, signed update staging and the UEFI/systemd-boot A/B activator. Installation does not enroll, enable, change boot state or reboot.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Windows Fleet Resident                           | A separate off-default `LocalService` worker admits only `windows.p0.diagnose.v1@1`, retains digest-only idempotent state and exposes an explicitly unsigned deployment-bundle workflow. It installs on demand and never auto-starts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| macOS Fleet Resident                             | A separate off-default LaunchAgent worker admits only `macos.p0.diagnose.v1@1`, reuses the bounded native Desk collector and retains digest-only idempotent state. Its Intel and Apple-silicon workflow bundles remain explicitly unsigned and unnotarized.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Native Resident enrollment and package lifecycle | Linux, Windows and macOS now have explicit one-shot enrollment using a native device identity, a fixed signed request, single-use token consumption after acceptance and a required persisted public binding before normal startup. Exact staged artifacts from `fe3c940` passed Linux run `33471097700`, Windows run `33471100838` and macOS run `33471099291`: enrollment/claim/result contract inspection, disabled startup, intentional no-anchor fail-closed run and cleanup. Windows additionally proved an on-demand stopped `LocalService`; macOS proved no LaunchAgent was loaded. These are unsigned engineering builds; publisher signing, physical key-store behavior and an endpoint-to-production-Fleet run remain external gates. |
| Rescue Fleet adapter                             | The private candidate maps all four closed Fleet repair intents (`fstab`, `crypttab`, ext4 preen/undo and resolver-link restoration) to their exact local action. Execution still requires a fresh local approval bound to device, lease, action, plan, target and evidence before the existing Core/Broker/Vault path is reached. Fleet cannot execute a repair remotely.                                                                                                                                                                                                                                                                                                                                                                       |
| Signed A/B activation                            | The off-default Linux activator admits only a signed, already staged inactive slot on locally provisioned UEFI/systemd-boot A/B systems. It persists before `bootctl`, uses one-shot boot, promotes or records fallback, retains offline rollback and never repartitions or reboots. BIOS/GRUB fails closed.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Windows Media Creator                            | The native wizard consumes one exact Ed25519-signed release bundle, lists only qualified removable whole disks, requires exact erase confirmation, streams the XZ image and performs full readback SHA-256. Its workflow output remains an explicitly unsigned EXE/ZIP until Authenticode is applied externally.                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Private software catalog                         | The authenticated project site serves the reviewed Media Creator and current Linux, Windows and dual-architecture macOS Resident engineering artifacts. Resident provenance is pinned to `fe3c940` and runs `33471097700`, `33471100838` and `33471099291`, with exact bytes, checksum, qualification and unsigned status. Each route remains independently fail-closed if its reviewed file or metadata is absent. ISO metadata is changed only after explicit terminal review and promotion.                                                                                                                                                                                                                                                   |
| Rescue first boot                                | The zero-p3 implementation provisions the canonical LUKS2/ext4 Vault, seeds its identity and provider home, closes it and verifies the locked profile. Run `33486399275` passed the integrated image/USB matrix but its separate UEFI lifecycle did not reach readiness, so this exact image has no persistence qualification.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Release channel                                  | Canonical Release Channel v1, anti-rollback links and strict verification are implemented. `internal.7` was correctly not dispatched because run `33486399275` failed a required lifecycle gate. Stable `internal.6` remains unchanged; the newer ISO is offered only as a clearly marked private physical-test candidate.                                                                                                                                                                                                                                                                                                                                                                                                                        |

The canonical repository is
[`0xfunboy/KernAid`](https://github.com/0xfunboy/KernAid), branch `main`.
Temporary integration worktrees are not product branches and should not be
treated as a newer release.

## What does not work yet

- There is no mutation handler in the default/stable product and no supported
  customer-machine repair path. All real handlers remain explicitly
  feature-gated in the private candidate until an exact image passes the full
  recovery matrix and physical qualification.
- Current diagnosis source passed CI, Desktop packaging and the integrated
  build/boot/USB matrix, but failed the separate UEFI Vault readiness gate.
  Repair failed independently at the UEFI crypttab provider-proof step. Neither
  image is a promoted repair or persistence-capable release.
- Repair Vault retention, crash-safe compaction and pending-transaction
  reconciliation are implemented. Customer retention policy, destructive
  power-loss recovery and physical separate-device behavior remain promotion
  gates.
- The fixture lab's exported webview artifact is deliberately marked volatile
  and unsigned because the closed native bridge does not expose its signed
  broker envelope. It is development evidence, not a release receipt.
- Physical USB boot has not been qualified. The authenticated site may expose a
  separately labeled physical-test candidate, but that availability is not a
  trusted-catalog entry or release qualification.
- The first reported physical boot of the previous diagnosis-only RC on an
  Intel Core i5-6200-class PC reached Xorg/Matchbox but showed only a black
  desktop and movable pointer. That is a failed physical qualification, not a
  pass. The image used WebKitGTK 2.52.6 together with the obsolete
  `WEBKIT_DISABLE_DMABUF_RENDERER=1` path. The current candidate replaces it
  with shared-memory transport and CPU rasterization, disables the ephemeral
  Mesa shader cache, adds a compatibility-graphics boot entry and replaces the
  Debian boot artwork with KernAid branding. Physical retest is still required
  before claiming physical hardware qualification.
- Secure Boot is not qualified.
- Desktop installers are unsigned engineering previews.
- The Linux Resident `.deb`, Windows Resident ZIP, macOS Resident bundles and
  Windows Media Creator ZIP are engineering packaging paths, not released
  customer installers. The current Resident packages passed their automated
  native workflows in Linux run `33471097700`, Windows run `33471100838` and
  macOS run `33471099291`, including the explicit enrollment contract,
  disabled startup, an intentional no-anchor fail-closed execution and
  cleanup. Linux repository/package signing, Windows Authenticode, macOS
  Developer ID/notarization, physical key-store behavior and physical endpoint
  qualification remain open.
- The Linux A/B activator requires a separately provisioned and qualified pair
  of bootable slots and UKIs. Its source implementation is not evidence that a
  customer device can be safely updated or rolled back.
- The Resident credential companion remains a separate Cargo package and
  workflow artifact. Desktop run `33486399165` inspected DEB, RPM, AppImage,
  macOS APP/DMG and Windows MSI/NSIS output and all four platform jobs passed
  the gate that rejects companion inclusion. Physical install and complete GUI
  qualification remain open.
- The human-readable Markdown report is always unsigned. Its displayed hash
  protects local integrity only; authenticity, when available, belongs to the
  signed machine-readable JSON envelope. An unsigned JSON report likewise does
  not prove signer identity.
- Rescue provider login with a real account, live TLS and physical encrypted
  persistence are incomplete release gates.
- Anthropic and Gemini diagnosis adapters and their signed Fleet policy modes
  are wired into Resident Desk, but no real vendor account or live API has been
  qualified. They remain tool-free diagnosis adapters and grant no repair
  authority.
- The signed Rescue report HTTP relay remains internal loopback plumbing, not a
  public API. Current-source exact-image qualification, physical USB and
  recovery behavior are not yet complete.
- The USB writer can copy, verify and provision only an exact
  catalog-authorized image. This is not physical-hardware qualification.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The current integrated diagnosis source cut is commit
[`6e9742e5b0c4397728dde80e9a0a91a09214f7cd`](https://github.com/0xfunboy/KernAid/commit/6e9742e5b0c4397728dde80e9a0a91a09214f7cd):

| Gate          | Exact status at this documentation cut                                                                                                                                                                 |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Source CI     | [Run 33486399168](https://github.com/0xfunboy/KernAid/actions/runs/33486399168), **success**                                                                                                           |
| Desktop       | [Run 33486399165](https://github.com/0xfunboy/KernAid/actions/runs/33486399165), **success**: Windows x86-64, Linux x86-64, macOS x86-64 and macOS aarch64 packaging plus provider-companion exclusion |
| Diagnosis ISO | [Rescue run 33486399275](https://github.com/0xfunboy/KernAid/actions/runs/33486399275), integrated build/boot/USB matrix **success**; UEFI Vault lifecycle **failure** at readiness; no promotion       |
| Repair ISO    | [Repair run 33482972849](https://github.com/0xfunboy/KernAid/actions/runs/33482972849), **failure** at `uefi:crypttab-lifecycle`; qualified release skipped                                           |

The exact diagnostic physical-test candidate is `KernAid-Rescue-amd64.iso`,
artifact version `ci-33486399275-1`, `1,307,344,896` bytes, SHA-256
`8a971474335846495903d2a314145e3cb3a04fdb930405461eb215bbc66c46da`.
It passed build, ABI, diagnosis-only surface exclusion, ordinary BIOS/UEFI
boot and USB-style two-boot BIOS/UEFI on the same digest. It is downloadable
privately only for physical boot/UI/diagnosis testing and is not stable,
catalog-authorized or Vault-qualified. Stable `0.1.0-internal.6` remains
unchanged. The BIOS lifecycle and native-prompt jobs were cancelled after the
irreversible UEFI failure because they could no longer qualify or promote the
cohort. BIOS lifecycle produced no final evidence; cancellation cleanup of the
native-prompt job emitted only the non-qualifying marker
`stage=output code=invalid`.

The Desktop workflow produced 13 non-expired engineering artifacts covering
the four Desk targets and their separate native provider-key companions. These
are unsigned preview packages; artifact availability is not publisher signing,
physical installation or release promotion.

### Native Resident packages

The current reviewed Resident source is
[`fe3c940d525f5c1c2ecd8123bdb100cd3280b908`](https://github.com/0xfunboy/KernAid/commit/fe3c940d525f5c1c2ecd8123bdb100cd3280b908):

| Platform                    | Workflow evidence                                                                        | Boundary                                                                                                                              |
| --------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Linux amd64                 | [Run 33471097700](https://github.com/0xfunboy/KernAid/actions/runs/33471097700), success | Disabled-by-default DEB, closed claim/result engine and explicit enrollment bootstrap contract                                        |
| Windows x86-64              | [Run 33471100838](https://github.com/0xfunboy/KernAid/actions/runs/33471100838), success | Unsigned ZIP, on-demand stopped `LocalService`, explicit enrollment contract and cleanup                                              |
| macOS Intel + Apple silicon | [Run 33471099291](https://github.com/0xfunboy/KernAid/actions/runs/33471099291), success | Unsigned/unnotarized bundles, disabled LaunchAgent, explicit enrollment contract on the native leg and deterministic combined catalog |

The source implementation creates or loads the native identity only during an
explicit bootstrap, signs the fixed enrollment request, consumes a token only
after acceptance and blocks normal service startup without the matching public
enrollment binding. The automated workflows do not qualify publisher signing,
hardware-backed secret storage or a physical production endpoint.

### Fleet operational evidence

- The focused disposable cryptographic E2E remains green: 7/7 selected
  control-plane cases, 1/1 four-action Rescue adapter case and 2/2 Desk approval
  boundary cases. Every control-plane database was a temporary SQLite file and
  was removed after the test.
- The scheduled signed schema-v13 backup service is active. Its latest observed
  execution completed successfully, independently verified the retained bundle
  and left the live WAL database untouched.
- The offline verify/restore drill is green against a disposable destination;
  overwrite, tamper, wrong-key, sidecar and symlink paths remain fail-closed.
- These software gates do not replace physical endpoint, identity-store,
  publisher-signing or provider-account evidence.

## Immediate next gates

1. Use Rescue run `33486399275` only as the authenticated physical-test
   candidate. Do not promote it: UEFI Vault lifecycle readiness failed and
   `internal.7` was not dispatched.
2. Repair run `33482972849` failed at the UEFI crypttab provider-proof step.
   Keep the candidate unavailable; its correction and rerun are paused by the
   owner rather than folded into this diagnosis-release closeout.
3. The staged native Resident lifecycle and explicit enrollment contract are
   green in runs `33471097700`, `33471100838` and `33471099291`. Next qualify
   native key stores and the closed enrollment/R0 work-order lifecycle on
   physical Linux, Windows and macOS endpoints; qualify the Media Creator
   erase/write/readback flow separately on disposable USB.
4. Boot the resulting exact diagnostic image from physical USB on a small
   hardware matrix using the [physical USB qualification
   runbook](runbooks/physical-usb-qualification.md), and record firmware,
   storage, network and UI evidence.
5. Finish the real-account Rescue provider/vault lifecycle using the
   [two-boot qualification runbook](runbooks/real-provider-qualification.md),
   without exposing or copying either provider credential store.
6. Qualify the repair candidate on disposable two-device physical hardware,
   including unplug/reboot/power-loss recovery.
7. Qualify physical Secure Boot, publisher signing/notarization and the
   consumer/update path on top of Release Channel v1.

Keep the repair candidate unpromoted until the virtual failure/recovery,
physical USB and Secure Boot matrices pass.

## Where to look

- [Repository overview](../README.md)
- [Phase 0 architecture](architecture/phase-0.md)
- [Operator guide](operator-guide.md)
- [Physical USB qualification runbook](runbooks/physical-usb-qualification.md)
- [Product and architecture masterplan](MASTERPLAN.md)
- [Security policy](../SECURITY.md)
- [Private/public project-site operations](../site/README.md)

When this page conflicts with a broad future-looking statement in the
masterplan, this page is authoritative for current shipping status.
