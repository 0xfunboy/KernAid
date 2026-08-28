# KernAid current status

Last updated: 28 August 2026

This page separates the product vision from what the repository can safely do
today. The short version is: **the default KernAid Phase 0 product path is a
substantial diagnosis-only engineering preview, not yet a production repair
product.**

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

KernAid One, signed releases, Secure Boot support, production repair packs,
WinPE Companion and Fleet management remain later milestones.

## What works now

| Area | Current engineering state |
| --- | --- |
| Desk UI | Tauri/React desktop shell with Windows, Linux, Intel macOS and Apple-silicon macOS build targets |
| Rescue UI | Branded Tauri/WebKitGTK shell in the Debian live image, with explicit runtime/readiness gates |
| Target handling | Candidate discovery and explicit target selection; target filesystems remain read-only |
| Evidence | Normalized Linux snapshots, bounded hardware inventory and provenance framing |
| Diagnosis | Deterministic offline rules plus a bounded optional Resident OpenAI reasoning adapter |
| Planning | Typed R0 no-write plan validated by Core |
| Reporting | Resident Desk downloads a hashed JSON report; Rescue can persist the exact report plus audit sequence as a signed Vault envelope and export it through the native TTY companion |
| Rescue credential boundary | Isolated credential vault and fail-closed Codex login/status/logout bridge; it does not run prompts or diagnoses |
| Rescue provider plumbing | Feature-gated OpenAI executor and loopback relay are implemented, but live TLS and a real-account lifecycle are not yet qualified |
| Virtual testing | Disposable QEMU fixtures, byte-level mutation checks, BIOS/UEFI boot and two-boot USB/vault coverage |
| Repair experiment | Linux-only feature-gated Desk lab for one typed R2 repair and separately approved rollback on an internal temporary fixture. It now traverses the standard `SessionDriver`, Agent Gateway, explicit Core transaction states and typed broker; it remains absent from normal/Rescue builds and disconnected from production targets |
| Disabled Rescue repair candidate | A typed ext4-only contract, read-only preview, immutable target/Vault/evidence-bound transaction plan and separate Core/policy approval boundary exist for disabling one `fstab` entry whose UUID is proven missing. There is no trusted broker handler or I/O, so it cannot mutate a Rescue target |
| Rescue first boot | The promoted image provisions an all-zero p3 into the canonical LUKS2/ext4 Vault, seeds its identity and Codex home, closes it and verifies the locked profile; the exact flow passed two-boot BIOS/UEFI QEMU qualification |
| Release channel | Canonical Release Channel v1, anti-rollback links, strict verification and an immutable internal prerelease are active through sequence 2; this is not an automatic updater or signed production channel |

The canonical repository is
[`0xfunboy/KernAid`](https://github.com/0xfunboy/KernAid), branch `main`.
Temporary integration worktrees are not product branches and should not be
treated as a newer release.

## What does not work yet

- There are no production mutation handlers and no real customer-machine
  repair path.
- The disabled Rescue `fstab` candidate stops after its typed contract,
  read-only preview, immutable plan and approval admission; no trusted broker
  preflight, Vault backup or execution handler exists.
- Rescue zero-p3 first boot has exact-image BIOS/UEFI QEMU evidence, but no
  physical USB or firmware qualification evidence yet.
- The fixture lab's exported webview artifact is deliberately marked volatile
  and unsigned because the closed native bridge does not expose its signed
  broker envelope. It is development evidence, not a release receipt.
- Physical USB boot has not been qualified. The current private candidate may
  be used only for a controlled first-boot test on a factory-new or disposable
  USB and non-customer hardware.
- Secure Boot is not qualified.
- Desktop installers are unsigned engineering previews.
- Rescue provider login with a real account, live TLS and physical encrypted
  persistence are incomplete release gates.
- The signed Rescue report HTTP relay remains internal loopback plumbing, not a
  public API. Its virtual shipping-image gate has passed, but physical USB and
  recovery behavior are not yet qualified.
- The v2 USB writer can copy, verify and provision an exact catalog-authorized
  image. Catalog revision 4 authorizes only the exact internally qualified
  candidate documented below; this is not physical-hardware qualification.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The private project area serves one controlled physical-qualification
candidate built from commit
[`0d61eac1a5e4819dedb8b2243f53599de69eba32`](https://github.com/0xfunboy/KernAid/commit/0d61eac1a5e4819dedb8b2243f53599de69eba32):

| Field | Exact value |
| --- | --- |
| Internal release | [`0.1.0-internal.2`](https://github.com/0xfunboy/KernAid/releases/tag/kernaid-internal-v0.1.0-internal.2), sequence 2 |
| Artifact version | `ci-33150274347-1` |
| ISO size | `1,223,540,736` bytes |
| ISO SHA-256 | `ca152712c7f7002024868efc707c71c32b7c1bd648cd42ed20bb245be8d90312` |
| Retail `.img.xz` size | `1,191,404,728` bytes; expands to `32,000,000,000` bytes |
| Retail `.img.xz` SHA-256 | `831afc42cea102274242f76c82b30dda7c1476870a7cf90b8813668d4729574c` |
| Qualification manifest SHA-256 | `b5ccabaedb2805b231c4ef83314793680cc1371decbf9526d715ef97c35f468e` |
| Workflow | [Rescue run 33150274347](https://github.com/0xfunboy/KernAid/actions/runs/33150274347) |

That run successfully built the hybrid ISO, validated shipping binaries and
SBOM, passed ordinary BIOS/UEFI QEMU smoke, and passed the BIOS/UEFI two-boot
USB-style layout and persistent LUKS2/ext4 vault checks with byte-identical
disposable targets. Both final privileged lifecycle jobs provisioned the
zero-state Vault, verified stable identity across boot, passed the bounded
Codex offline signed-out path using its persistent Vault home, and passed the
signed-report persist, list, get, cross-boot signer and fixed-path export path
on the same artifact. The exact locally verified catalog entry is now the sole
image authorized by trusted catalog v2 revision 4. The final qualification job also bound the ISO,
checksum, catalog entry, SBOM and lifecycle evidence into one canonical
manifest. Both its GitHub/Sigstore build-provenance and custom qualification
attestations were independently verified before promotion. This is an
**internally and virtually qualified candidate**, not a production release.

New `main` candidates must pass the same final fail-closed qualification job,
then have their manifest, checksum and attestations independently verified.
No newer workflow artifact replaces the candidate listed above until another
explicit catalog and private-site promotion is completed.

The candidate is exposed privately only to unblock the first physical boot
test. On Windows, verify the retail `.img.xz` checksum and select that compressed
image directly in Rufus; if prompted, use DD mode on a factory-new or
disposable USB of at least 32 GB. Keep Secure Boot disabled and use non-customer
hardware. Rufus only writes the qualified zero-state image; the first live boot
asks for a new passphrase and provisions the encrypted Vault in place. This is
still not a supported repair medium.

The latest complete unsigned Desk packaging matrix was built from the same
commit in [Desktop run 33145692864](https://github.com/0xfunboy/KernAid/actions/runs/33145692864).
Linux x86-64, Windows x86-64, Intel macOS and Apple-silicon macOS packaging all
passed; signing, notarization and physical-machine qualification remain open.

## Immediate next gates

1. Boot that exact image from physical USB on a small hardware matrix and
   record firmware, storage, network and UI evidence.
2. Finish the real-account Rescue provider/vault lifecycle without exposing or
   copying the CLI credential store.
3. Qualify Secure Boot and signed release delivery.
4. Add the feature-gated Rescue broker preflight that independently resolves
   the target and Vault, rebuilds the immutable plan and consumes the exact
   approval; then add separate-device backup, execution, verification and
   rollback. Keep mutation disabled until the complete safety case passes.
5. Add and qualify the signed consumer/update path on top of the verified
   internal Release Channel v1 sequence.

## Where to look

- [Repository overview](../README.md)
- [Phase 0 architecture](architecture/phase-0.md)
- [Operator guide](operator-guide.md)
- [Product and architecture masterplan](MASTERPLAN.md)
- [Security policy](../SECURITY.md)
- [Private/public project-site operations](../site/README.md)

When this page conflicts with a broad future-looking statement in the
masterplan, this page is authoritative for current shipping status.
