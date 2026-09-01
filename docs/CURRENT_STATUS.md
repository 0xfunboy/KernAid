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

| Area | Current engineering state |
| --- | --- |
| Desk UI | Tauri/React desktop shell with Windows, Linux, Intel macOS and Apple-silicon macOS build targets |
| Rescue UI | Branded Tauri/WebKitGTK shell in the Debian live image, with explicit runtime/readiness gates |
| Target handling | Candidate discovery and explicit target selection; target filesystems remain read-only |
| Evidence | Normalized Linux, Windows and macOS diagnosis inputs, bounded hardware/storage/filesystem/boot observations and provenance framing |
| Diagnosis | Deterministic offline rules plus bounded optional Resident OpenAI, Anthropic Messages and Gemini Interactions integrations. Desk exposes only closed provider modes, presence-only status and sanitized proposals over Tauri IPC; credentials, fixed HTTPS transport and vendor response parsing remain native. The adapters have no tools, broker or fallback. Anthropic/Gemini buttons remain disabled until their independently purpose-bound OS-keyring credential is provisioned, and live vendor-account qualification remains external. Rescue remains Offline/OpenAI only. |
| Planning | Typed R0 no-write plan validated by Core |
| Reporting | Resident Desk exposes authoritative machine-readable JSON: a signed envelope when secure audit is active, otherwise an explicitly unsigned hashed JSON artifact. It also derives an always-unsigned human-readable Markdown copy that does not replace the JSON. Rescue can persist the exact signed JSON report plus audit sequence in the Vault and export it through the native TTY companion |
| Rescue credential boundary | Isolated credential vault and fail-closed Codex login/status/logout bridge; it does not run prompts or diagnoses |
| Rescue provider plumbing | Feature-gated OpenAI executor and loopback relay are implemented, but live TLS and a real-account lifecycle are not yet qualified |
| Exact-image harness | Disposable QEMU fixtures, byte-level mutation checks, BIOS/UEFI boot and two-boot USB/Vault coverage. Current source extends one shared-base repair batch across isolated copies for the `fstab` apply/failure/recovery matrix, `crypttab` apply and fresh explicit rollback, ext4 preen and clean read-only postcheck, and exact resolver-link restoration. The extended batch has no recorded green remote run yet. |
| Repair experiment | Linux-only feature-gated Desk lab for one typed R2 repair and separately approved rollback on an internal temporary fixture. It now traverses the standard `SessionDriver`, Agent Gateway, explicit Core transaction states and typed broker; it remains absent from normal/Rescue builds and disconnected from production targets |
| Feature-gated Rescue repair candidate | Off-default `fstab`, `crypttab`, ext4 and resolver-link recovery actions traverse the closed UI/Core/broker boundary. They bind a descriptor-retained target, reserve evidence on a distinct authenticated Vault, require typed single-use approval, verify the result and expose rollback or truthful manual reconciliation. The stable image excludes every repair surface. |
| `fstab` recovery | `linux.fstab.disable-missing-uuid.v1` atomically disables only a freshly proven missing, non-critical ext4 UUID entry and supports exact restore, automatic restore and restart reconciliation. |
| `crypttab` recovery | `linux.crypttab.disable-missing-uuid.v1` rejects critical mappings, external key sources, ambiguity and mandatory `fstab` consumers; the candidate includes Vault reservation, atomic execution, verification, UI, exact rollback and restart reconciliation. |
| ext4 recovery | `linux.ext4.fsck-preen-with-undo.v1` is an R3, unmounted-target action using bounded `e2fsck -p -f -z`, read-only verification and same-boot `e2undo`; it explicitly stops for manual reconciliation when exact recovery cannot be proved. |
| Resolver-link recovery | `linux.network.restore-resolver-link.v1` restores only the fixed resolver symlink after proving exactly one supported resolver, preserves the exact missing/link pre-state in the Vault and never starts or restarts a service. |
| Fleet control plane | Live internal schema v13: signed enrollment/inventory/audit/policy/entitlement/update delivery, secure browser sessions, RBAC, typed Linux, Windows and macOS work orders, incident cases and service receipts. The v13 closed work-order catalog admits all four Rescue repair identifiers while preserving the approval, lease and device bindings. Offline Ed25519 commercial licensing is active for the internal tenant; expiry, revocation, seat limits and clock rollback fail closed for paid operations. |
| Fleet provider policy | Signed policy uses the closed modes `offline`, `openai_api`, `openai_compatible`, `anthropic_api`, `gemini_api` and `enterprise`. A mode is usable only when both local capability and signed policy allow it; policy cannot create an unsupported adapter or broker authority. |
| Fleet backup | The live SQLite service has a scheduled, signed three-file backup bundle. The online copy is converted from WAL mode into one standalone database before its canonical manifest is signed; offline verify/restore reject tampering, wrong keys, sidecars, symlinks and overwrite. |
| Linux Fleet Resident | A disabled-by-default amd64 `.deb` packages signed sync, the three closed Linux R0 diagnostic work orders, signed update staging and the UEFI/systemd-boot A/B activator. Installation does not enroll, enable, change boot state or reboot. |
| Windows Fleet Resident | A separate off-default `LocalService` worker admits only `windows.p0.diagnose.v1@1`, retains digest-only idempotent state and exposes an explicitly unsigned deployment-bundle workflow. It installs on demand and never auto-starts. |
| macOS Fleet Resident | A separate off-default LaunchAgent worker admits only `macos.p0.diagnose.v1@1`, reuses the bounded native Desk collector and retains digest-only idempotent state. Its Intel and Apple-silicon workflow bundles remain explicitly unsigned and unnotarized. |
| Native Resident package lifecycle | The exact staged Linux `.deb`, Windows ZIP and native-architecture macOS bundles passed their automated native lifecycle gates in runs `33459558805`, `33459558875` and `33459559165`: fixed claim/result contract, disabled startup, one intentional no-trust-anchor fail-closed run and cleanup. Windows additionally proved an on-demand stopped `LocalService`; macOS proved no LaunchAgent was loaded. The artifacts remain unsigned engineering builds and these gates do not qualify real enrollment, native secret storage or physical endpoints. |
| Rescue Fleet adapter | The private candidate maps all four closed Fleet repair intents (`fstab`, `crypttab`, ext4 preen/undo and resolver-link restoration) to their exact local action. Execution still requires a fresh local approval bound to device, lease, action, plan, target and evidence before the existing Core/Broker/Vault path is reached. Fleet cannot execute a repair remotely. |
| Signed A/B activation | The off-default Linux activator admits only a signed, already staged inactive slot on locally provisioned UEFI/systemd-boot A/B systems. It persists before `bootctl`, uses one-shot boot, promotes or records fallback, retains offline rollback and never repartitions or reboots. BIOS/GRUB fails closed. |
| Windows Media Creator | The native wizard consumes one exact Ed25519-signed release bundle, lists only qualified removable whole disks, requires exact erase confirmation, streams the XZ image and performs full readback SHA-256. Its workflow output remains an explicitly unsigned EXE/ZIP until Authenticode is applied externally. |
| Private software catalog | The authenticated project site serves the reviewed Media Creator and the latest native-lifecycle-qualified Linux, Windows and dual-architecture macOS Resident engineering artifacts from runs `33454416574`, `33459558805`, `33459558875` and `33459559165`, with exact provenance, bytes, checksum, qualification and unsigned status. Each route remains independently fail-closed if its reviewed file or metadata is absent. |
| Rescue first boot | The promoted image provisions an all-zero p3 into the canonical LUKS2/ext4 Vault, seeds its identity and Codex home, closes it and verifies the locked profile; the exact flow passed two-boot BIOS/UEFI QEMU qualification |
| Release channel | Canonical Release Channel v1, anti-rollback links, strict verification and immutable internal prerelease `0.1.0-internal.6` are active through sequence 6; this is not an automatic updater or signed production channel |

The canonical repository is
[`0xfunboy/KernAid`](https://github.com/0xfunboy/KernAid), branch `main`.
Temporary integration worktrees are not product branches and should not be
treated as a newer release.

## What does not work yet

- There is no mutation handler in the default/stable product and no supported
  customer-machine repair path. All real handlers remain explicitly
  feature-gated in the private candidate until an exact image passes the full
  recovery matrix and physical qualification.
- The private repair build contains the dedicated repair account,
  socket-activated control plane, UI, executor, startup recovery barrier and
  separate read/write helpers. Implemented source is not qualification: its
  consolidated exact-image run must finish every apply, rollback, fault and
  restart scenario before publication.
- Repair Vault retention, crash-safe compaction and pending-transaction
  reconciliation are implemented; customer retention policy and destructive
  power-loss qualification remain promotion gates.
- Rescue zero-p3 first boot has exact-image BIOS/UEFI QEMU evidence, but no
  physical USB or firmware qualification evidence yet.
- The fixture lab's exported webview artifact is deliberately marked volatile
  and unsigned because the closed native bridge does not expose its signed
  broker envelope. It is development evidence, not a release receipt.
- Physical USB boot has not been qualified. The diagnosis-only stable image from
  commit `5db4700` completed every normal virtual gate in Rescue run
  `33330139973`. A newer diagnostic ISO from run `33455599335`, commit
  `aa8255a`, is available only in the authenticated area for controlled boot/UI
  investigation; it is not a promoted or Vault-qualified replacement for the
  stable image.
- The first reported physical boot of the previous diagnosis-only RC on an
  Intel Core i5-6200-class PC reached Xorg/Matchbox but showed only a black
  desktop and movable pointer. That is a failed physical qualification, not a
  pass. The image used WebKitGTK 2.52.6 together with the obsolete
  `WEBKIT_DISABLE_DMABUF_RENDERER=1` path. The current candidate replaces it
  with shared-memory transport and CPU rasterization, disables the ephemeral
  Mesa shader cache, adds a compatibility-graphics boot entry and replaces the
  Debian boot artwork with KernAid branding. Physical retest is still required
  before claiming physical hardware qualification.
- Rescue run `33455599335` passed its build, ABI, SBOM, shipping-surface,
  framebuffer/WebKit, keyboard, BIOS, UEFI Secure Boot and USB-style two-boot
  gates. Its BIOS/UEFI Vault lifecycle and native-prompt jobs all stopped at
  the same `firstboot-confirmation` timeout, so qualification was skipped. A
  subsequent input-pacing correction is included in source commit `be88efa`;
  Rescue run `33459542561` is still in progress and has no claimed outcome.
- Secure Boot is not qualified.
- Desktop installers are unsigned engineering previews.
- The Linux Resident `.deb`, Windows Resident ZIP, macOS Resident bundles and
  Windows Media Creator ZIP are engineering packaging paths, not released
  customer installers. The exact Resident packages passed their automated
  native lifecycle workflows in Linux run `33459558805`, Windows run
  `33459558875` and macOS run `33459559165`, including disabled startup, an
  intentional no-anchor fail-closed execution and cleanup. Real identity,
  enrollment, native secret stores, Linux repository/package signing, Windows
  Authenticode, macOS Developer ID signing/notarization and physical endpoint
  qualification remain open.
- The Linux A/B activator requires a separately provisioned and qualified pair
  of bootable slots and UKIs. Its source implementation is not evidence that a
  customer device can be safely updated or rolled back.
- In the current source, the Resident credential companion is a separate Cargo
  package and separate workflow artifact. The Desktop workflow now inspects
  DEB, RPM, AppImage, macOS APP/DMG and Windows MSI/NSIS output and fails if the
  companion appears inside an installer. All four platform jobs passed this
  gate in Desktop run `33330140025` attempt 1, and those exact artifacts were
  published in immutable internal release `0.1.0-internal.6`; physical install
  and complete GUI qualification remain open.
- The human-readable Markdown report is always unsigned. Its displayed hash
  protects local integrity only; authenticity, when available, belongs to the
  signed machine-readable JSON envelope. An unsigned JSON report likewise does
  not prove signer identity.
- Rescue provider login with a real account, live TLS and physical encrypted
  persistence are incomplete release gates.
- Anthropic and Gemini diagnosis adapters and their signed Fleet policy modes
  are implemented in source, but they have no shipping product selector,
  provisioned vendor credentials or live-API qualification. They remain
  tool-free diagnosis adapters and grant no repair authority.
- The signed Rescue report HTTP relay remains internal loopback plumbing, not a
  public API. Its virtual shipping-image gate has passed, but physical USB and
  recovery behavior are not yet qualified.
- The v2 USB writer can copy, verify and provision an exact catalog-authorized
  image. Catalog revision 8 authorizes only the exact internally qualified
  candidate documented below; this is not physical-hardware qualification.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The authenticated project area continues to serve the virtually qualified
stable diagnosis-only release built from commit
[`5db47001fad2a3814d90837bcdcea545b2da0fa9`](https://github.com/0xfunboy/KernAid/commit/5db47001fad2a3814d90837bcdcea545b2da0fa9):

| Field | Exact value |
| --- | --- |
| Internal release | [`0.1.0-internal.6`](https://github.com/0xfunboy/KernAid/releases/tag/kernaid-internal-v0.1.0-internal.6), immutable sequence 6 |
| Artifact version | `ci-33330139973-1` |
| ISO size | `1,223,540,736` bytes |
| ISO SHA-256 | `fe8d54d8e154f6a4712c65855b5dffdcb31dddeac0d3a03c299d606f87a16000` |
| Retail `.img.xz` size | `1,191,669,060` bytes; expands to `32,000,000,000` bytes |
| Retail `.img.xz` SHA-256 | `efc5d4d0c428d0f7a992eb21154c4243c5566d7c85d6481e174c43cac909aa9b` |
| Release Channel v1 manifest SHA-256 | `11d15af0ef07b78760f468f3302cd398255c072dba0920b868c967f53206e674` |
| Rescue workflow | [Run 33330139973, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33330139973): [build/smoke 99307132991](https://github.com/0xfunboy/KernAid/actions/runs/33330139973/job/99307132991), [BIOS lifecycle 99312347700](https://github.com/0xfunboy/KernAid/actions/runs/33330139973/job/99312347700), [UEFI lifecycle 99312347679](https://github.com/0xfunboy/KernAid/actions/runs/33330139973/job/99312347679), [qualified release 99314609977](https://github.com/0xfunboy/KernAid/actions/runs/33330139973/job/99314609977); all jobs passed |
| Desk workflow | [Run 33330140025, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33330140025), all four diagnosis-only platform jobs passed from the same source commit |
| Immutable publisher | [Release Channel run 33334176867, job 99317982512](https://github.com/0xfunboy/KernAid/actions/runs/33334176867/job/99317982512), success |

That run successfully built the hybrid ISO, validated shipping binaries and
SBOM, passed ordinary BIOS/UEFI QEMU smoke with the shipping WebKit process,
visible branded framebuffer and keyboard input, and passed the BIOS/UEFI
two-boot USB-style layout and persistent LUKS2/ext4 Vault checks with
byte-identical disposable targets. Both final privileged lifecycle jobs
provisioned the zero-state Vault, verified stable identity across boot, passed
the bounded Codex offline signed-out path using its persistent Vault home, and
passed the signed-report persist, list, get, cross-boot signer and fixed-path
export path on the same artifact. The exact locally verified catalog entry is
now the sole image authorized by trusted catalog v2 revision 8. The stable ISO
also passed the explicit packaging gate that rejects repair UI, handlers,
write-capable units and other repair surfaces. The final
qualification job also bound the ISO, checksum, retail image, catalog entry,
SBOM and lifecycle evidence into one canonical manifest and attested both the
ISO and retail image. Its GitHub/Sigstore ISO build-provenance and ISO/retail
custom qualification attestations were independently verified before
promotion. This is an **internally and virtually qualified candidate**, not a
production release or proof that the reported physical display failure is
fixed.

### Newer diagnostic candidate — not promoted

The authenticated area separately exposes the exact ISO from
[Rescue run 33455599335](https://github.com/0xfunboy/KernAid/actions/runs/33455599335),
source commit
[`aa8255ac3837d8ec458b682e9704ffe085347a08`](https://github.com/0xfunboy/KernAid/commit/aa8255ac3837d8ec458b682e9704ffe085347a08):

| Field | Exact value |
| --- | --- |
| Artifact version | `ci-33455599335-1` |
| ISO size | `1,307,344,896` bytes |
| ISO SHA-256 | `0d69b27b1b79edf9017538c3742cae97fa59960f2992a2dba7caec6620997449` |
| Passed | Build, ABI, stable-surface exclusion, SBOM, QEMU BIOS, UEFI Secure Boot, WebKit framebuffer, keyboard input and USB-style two-boot BIOS/UEFI |
| Failed | BIOS Vault lifecycle, UEFI Vault lifecycle and BIOS native prompt: common `firstboot-confirmation` timeout |
| Qualification | `qualified-release` skipped; no catalog or Release Channel promotion |

Use this ISO only on non-customer hardware and a disposable USB to investigate
physical boot and UI. Do not rely on its Vault provisioning. It has no retail
image in the private area and does not replace `0.1.0-internal.6` or trusted
catalog v2 revision 8. The input-pacing correction in commit `be88efa` belongs
to a later build and cannot retroactively qualify this ISO.

### Current integrated qualification batch — in progress

Commit
[`be88efab849365f4d3e7431e110ebd318e8d67a8`](https://github.com/0xfunboy/KernAid/commit/be88efab849365f4d3e7431e110ebd318e8d67a8)
is currently being evaluated by
[Rescue run 33459542561](https://github.com/0xfunboy/KernAid/actions/runs/33459542561),
[Desktop run 33459542555](https://github.com/0xfunboy/KernAid/actions/runs/33459542555)
and
[repair run 33459558782](https://github.com/0xfunboy/KernAid/actions/runs/33459558782).
All three are in progress at this status cut. Their presence is not evidence
of success, and none authorizes promotion until its complete required matrix
finishes green and the exact artifacts are independently reviewed.

### Retired physical-test candidate

The earlier failed physical-test release
[`0.1.0-internal.2`](https://github.com/0xfunboy/KernAid/releases/tag/kernaid-internal-v0.1.0-internal.2),
built from commit
[`0d61eac1a5e4819dedb8b2243f53599de69eba32`](https://github.com/0xfunboy/KernAid/commit/0d61eac1a5e4819dedb8b2243f53599de69eba32)
by [Rescue run 33150274347](https://github.com/0xfunboy/KernAid/actions/runs/33150274347),
is retained only as immutable virtual-qualification evidence. Its ISO SHA-256
is `ca152712c7f7002024868efc707c71c32b7c1bd648cd42ed20bb245be8d90312`.
It is retired from the trusted catalog and private download area because its
first Intel physical boot produced the black WebKit frame described above. Do
not serve, redistribute or reuse it for the physical test.

New `main` candidates must pass the same final fail-closed qualification job,
then have their manifest, checksum and attestations independently verified.
No newer workflow artifact replaces the candidate listed above until another
explicit catalog and private-site promotion is completed.

### Private repair candidate

Current source contains four independent off-default actions: `fstab`,
`crypttab`, ext4 preen/undo and resolver-link restoration. It also contains the
local Rescue adapter for each corresponding closed Fleet repair intent. None
is present in the stable image, and no current-source repair image has passed
and been promoted through the full exact-image matrix. The current harness
reuses one provisioned Rescue/Vault/target base through isolated sparse copies
and covers the existing `fstab` apply/failure/recovery matrix, `crypttab` apply
plus fresh explicit rollback, ext4 preen plus clean read-only verification, and
resolver apply plus exact symlink restoration. That source-level extension was
added after the historical run below; no green remote run or promoted repair
image proves it. The table therefore remains evidence for the last separately
reviewed image, not the status of current source. Repair run `33459558782` is
evaluating the new batch and remains in progress; no result is claimed here.

| Field | Exact value |
| --- | --- |
| Workflow | [Repair candidate run 33306646523, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306646523), **failure** |
| Virtual boot smoke | BIOS pass; UEFI pass |
| Virtual apply | BIOS pass; UEFI pass for `linux.fstab.disable-missing-uuid.v1` |
| Failed gate | UEFI post-commit rollback, sanitized marker `repair-rollback-service-ready` |
| Not executed | UEFI restart reconciliation, skipped after the rollback failure |
| Channel | Not promoted and unavailable through the product site/Release Channel; the formal candidate ISO publish step was skipped, while a one-day Actions forensics artifact retained ISO and checksum only for CI investigation |

The retained historical apply gates used disposable direct-leaf ext4 targets and a
distinct LUKS2/ext4 Vault, retained typed single-use approval, verified exact
final `fstab` bytes, left the unrelated sentinel unchanged and proved the ISO
prefix immutable. The overall workflow still failed. It does not qualify
rollback, restart reconciliation, automatic restore, fault injection, process
termination, destructive power loss, physical USB, hardware, firmware, Secure
Boot, customer data or production use. No repair-candidate ISO from this run is
promoted or available through the product site or Release Channel. The
temporary one-day Actions forensics artifact is investigation evidence, not a
trusted distribution channel.

The stable retail candidate above is exposed privately only to unblock the
first physical boot test. On Windows, verify the retail `.img.xz` checksum and
select that compressed image directly in Rufus; if prompted, use DD mode on a
factory-new or disposable USB of at least 32 GB. Keep Secure Boot disabled and
use non-customer hardware. Rufus only writes the qualified zero-state image;
the first live boot asks for a new passphrase and provisions the encrypted
Vault in place. This is still not a supported repair medium.

The latest complete unsigned Desk packaging matrix was built from the stable
source commit in [Desktop run 33330140025, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33330140025).
Linux x86-64, Windows x86-64, Intel macOS and Apple-silicon macOS packaging all
passed, including the package gates that exclude repair UI and the separately
distributed credential companion. Those artifacts are part of immutable
release `0.1.0-internal.6`; signing, notarization, physical installation and
complete GUI qualification remain open.

## Immediate next gates

1. Let Rescue run `33459542561` complete; promote nothing unless build, boot,
   two-boot, native prompt and both Vault lifecycle jobs pass on the same exact
   image.
2. Let repair run `33459558782` complete and retain one green exact-image run
   before treating its four scenarios as virtually qualified; then keep
   destructive power-loss and physical recovery as separate gates.
3. The staged native Resident lifecycle is green in runs `33459558805`,
   `33459558875` and `33459559165`. Next qualify real service identity,
   enrollment, native secret stores and the closed R0 work-order lifecycle on
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
