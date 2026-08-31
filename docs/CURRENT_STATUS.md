# KernAid current status

Last updated: 31 August 2026

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

The product family has two active engineering surfaces:

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
| Diagnosis | Deterministic offline rules plus a bounded optional Resident OpenAI reasoning adapter |
| Planning | Typed R0 no-write plan validated by Core |
| Reporting | Resident Desk exposes authoritative machine-readable JSON: a signed envelope when secure audit is active, otherwise an explicitly unsigned hashed JSON artifact. It also derives an always-unsigned human-readable Markdown copy that does not replace the JSON. Rescue can persist the exact signed JSON report plus audit sequence in the Vault and export it through the native TTY companion |
| Rescue credential boundary | Isolated credential vault and fail-closed Codex login/status/logout bridge; it does not run prompts or diagnoses |
| Rescue provider plumbing | Feature-gated OpenAI executor and loopback relay are implemented, but live TLS and a real-account lifecycle are not yet qualified |
| Virtual testing | Disposable QEMU fixtures, byte-level mutation checks, BIOS/UEFI boot, two-boot USB/Vault coverage and one consolidated repair batch that reuses a provisioned base across isolated scenario copies |
| Repair experiment | Linux-only feature-gated Desk lab for one typed R2 repair and separately approved rollback on an internal temporary fixture. It now traverses the standard `SessionDriver`, Agent Gateway, explicit Core transaction states and typed broker; it remains absent from normal/Rescue builds and disconnected from production targets |
| Feature-gated Rescue repair candidate | Off-default `fstab`, `crypttab` and ext4 recovery actions traverse the closed UI/Core/broker boundary. They bind a descriptor-retained target, reserve evidence on a distinct authenticated Vault, require typed single-use approval, verify the result and expose rollback or truthful manual reconciliation. The stable image excludes every repair surface. |
| `fstab` recovery | `linux.fstab.disable-missing-uuid.v1` atomically disables only a freshly proven missing, non-critical ext4 UUID entry and supports exact restore, automatic restore and restart reconciliation. |
| `crypttab` recovery | `linux.crypttab.disable-missing-uuid.v1` rejects critical mappings, external key sources, ambiguity and mandatory `fstab` consumers; the candidate includes Vault reservation, atomic execution, verification, UI, exact rollback and restart reconciliation. |
| ext4 recovery | `linux.ext4.fsck-preen-with-undo.v1` is an R3, unmounted-target action using bounded `e2fsck -p -f -z`, read-only verification and same-boot `e2undo`; it explicitly stops for manual reconciliation when exact recovery cannot be proved. |
| Fleet control plane | Live internal schema v10: signed enrollment/inventory/audit/policy/entitlement/update delivery, RBAC, typed work orders, leases/results, tenant-isolated incident cases, immutable canonical closure reports and signed service receipts. |
| Fleet Resident | Installable off-default Linux services perform signed synchronization and closed-catalog diagnostic work orders for filesystem, storage and boot-path health. Fleet supplies intent only and cannot bypass local policy, entitlement or approval. |
| Windows Media Creator | Source and workflow implement removable-whole-disk discovery, system/boot/ambiguous-device rejection, exact confirmation, catalog/qualification binding, streamed XZ write, flush and full readback SHA-256. Authenticode and physical USB evidence remain external gates. |
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
  `33330139973` and is the active candidate for a controlled physical retest on
  a factory-new or disposable USB and non-customer hardware.
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
- The signed Rescue report HTTP relay remains internal loopback plumbing, not a
  public API. Its virtual shipping-image gate has passed, but physical USB and
  recovery behavior are not yet qualified.
- The v2 USB writer can copy, verify and provision an exact catalog-authorized
  image. Catalog revision 8 authorizes only the exact internally qualified
  candidate documented below; this is not physical-hardware qualification.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The private project area serves one controlled physical-qualification
candidate built from commit
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

The last documented terminal separate repair candidate run used commit
[`64db3bcf4050df01e96e1b55e08750b6957df801`](https://github.com/0xfunboy/KernAid/commit/64db3bcf4050df01e96e1b55e08750b6957df801).
It does **not** replace the stable retail image or promoted diagnosis-only
internal release above.

A later requalification attempt, [run 33334118587](https://github.com/0xfunboy/KernAid/actions/runs/33334118587),
is evaluated separately. This page intentionally makes no pass/fail claim for
that run until its complete terminal evidence is reviewed; it has not replaced
or modified the stable diagnosis-only release.

| Field | Exact value |
| --- | --- |
| Workflow | [Repair candidate run 33306646523, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306646523), **failure** |
| Virtual boot smoke | BIOS pass; UEFI pass |
| Virtual apply | BIOS pass; UEFI pass for `linux.fstab.disable-missing-uuid.v1` |
| Failed gate | UEFI post-commit rollback, sanitized marker `repair-rollback-service-ready` |
| Not executed | UEFI restart reconciliation, skipped after the rollback failure |
| Channel | Not promoted and unavailable through the product site/Release Channel; the formal candidate ISO publish step was skipped, while a one-day Actions forensics artifact retained ISO and checksum only for CI investigation |

The successful apply gates used disposable direct-leaf ext4 targets and a
distinct LUKS2/ext4 Vault, retained typed single-use approval, verified exact
final `fstab` bytes, left the unrelated sentinel unchanged and proved the ISO
prefix immutable. The overall workflow still failed. It does not qualify
rollback, restart reconciliation, automatic restore, fault injection, process
termination, destructive power loss, physical USB, hardware, firmware, Secure
Boot, customer data or production use. No repair-candidate ISO from this run is
promoted or available through the product site or Release Channel. The
temporary one-day Actions forensics artifact is investigation evidence, not a
trusted distribution channel.

The current retail candidate above is exposed privately only to unblock the
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

1. Boot the exact `5db4700` image from physical USB on a small hardware matrix
   using the [physical USB qualification
   runbook](runbooks/physical-usb-qualification.md), and record firmware,
   storage, network and UI evidence.
2. Finish the real-account Rescue provider/vault lifecycle using the
   [two-boot qualification runbook](runbooks/real-provider-qualification.md),
   without exposing or copying either provider credential store.
3. Fix and qualify one exact repair candidate through post-commit rollback,
   automatic restore, injected faults, interrupted processes, restart/reboot
   reconciliation and destructive power-loss recovery on disposable targets.
4. Qualify the repair candidate on disposable two-device physical hardware,
   including unplug/reboot/power-loss recovery.
5. Qualify Secure Boot and signed release delivery.
6. Add and qualify the signed consumer/update path on top of the verified
   internal Release Channel v1 sequence.

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
