# KernAid current status

Last updated: 26 August 2026

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
| Reporting | Downloadable JSON report with a content hash |
| Rescue credential boundary | Isolated credential vault and fail-closed Codex login/status/logout bridge; it does not run prompts or diagnoses |
| Rescue provider plumbing | Feature-gated OpenAI executor and loopback relay are implemented, but live TLS and a real-account lifecycle are not yet qualified |
| Virtual testing | Disposable QEMU fixtures, byte-level mutation checks, BIOS/UEFI boot and two-boot USB/vault coverage |
| Repair experiment | Linux-only feature-gated Desk lab for one typed R2 repair, verification and separately approved rollback on an internal temporary fixture; absent from normal/Rescue builds and disconnected from production targets |

The canonical repository is
[`0xfunboy/KernAid`](https://github.com/0xfunboy/KernAid), branch `main`.
Temporary integration worktrees are not product branches and should not be
treated as a newer release.

## What does not work yet

- There are no production mutation handlers and no real customer-machine
  repair path.
- Physical USB boot has not been qualified. The current private candidate may
  be used only for a controlled first-boot test on a factory-new or disposable
  USB and non-customer hardware.
- Secure Boot is not qualified.
- Desktop installers are unsigned engineering previews.
- Rescue provider login with a real account, live TLS and physical encrypted
  persistence are incomplete release gates.
- The v2 USB writer can copy, verify and provision an exact catalog-authorized
  image, but the current v2 catalog is empty and rejects the private candidate.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The private project area serves one controlled physical-qualification
candidate built from commit
[`e9340bbe98fa73a0398cde12010a260b3a7951af`](https://github.com/0xfunboy/KernAid/commit/e9340bbe98fa73a0398cde12010a260b3a7951af):

| Field | Exact value |
| --- | --- |
| Artifact version | `ci-32915064704-1` |
| Size | `1,221,148,672` bytes |
| SHA-256 | `f89e4cc59465268d857d6d13b3ec5884112b1d432e990f02cfe7e520875f0ecb` |
| Workflow | [Rescue run 32915064704](https://github.com/0xfunboy/KernAid/actions/runs/32915064704) |

That run successfully built the hybrid ISO, validated shipping binaries and
SBOM, passed ordinary BIOS/UEFI QEMU smoke, and passed the BIOS/UEFI two-boot
USB-style layout and persistent LUKS2/ext4 vault checks with byte-identical
disposable targets. Both final privileged lifecycle jobs failed at the local
Codex status bridge (`provider-proof / codex-status-transport`). Therefore the
workflow is red, the trusted v2 catalog remains at revision zero with no
authorized images, and this artifact is **not a release**.

The candidate is exposed privately only to unblock the first physical boot
test. On Windows, verify the exact checksum and use Rufus in DD mode on a
factory-new or disposable USB of at least 32 GB. Keep Secure Boot disabled,
use non-customer hardware, and do not treat that manual write as encrypted-vault
provisioning or as a supported repair medium.

## Immediate next gates

1. Fix the bounded local Codex status bridge and get both privileged
   vault-lifecycle jobs green on the same revision.
2. Promote one exact ISO into the trusted catalog only after its full
   virtual qualification succeeds.
3. Boot that exact image from physical USB on a small hardware matrix and
   record firmware, storage, network and UI evidence.
4. Finish the real-account Rescue provider/vault lifecycle without exposing or
   copying the CLI credential store.
5. Define the first production repair action with typed preconditions, backup,
   explicit approval, verification and rollback; keep it disabled until the
   complete safety case passes.
6. Add signing/notarization and a repeatable release channel for Desk and
   Rescue artifacts.

## Where to look

- [Repository overview](../README.md)
- [Phase 0 architecture](architecture/phase-0.md)
- [Operator guide](operator-guide.md)
- [Product and architecture masterplan](MASTERPLAN.md)
- [Security policy](../SECURITY.md)
- [Private/public project-site operations](../site/README.md)

When this page conflicts with a broad future-looking statement in the
masterplan, this page is authoritative for current shipping status.
