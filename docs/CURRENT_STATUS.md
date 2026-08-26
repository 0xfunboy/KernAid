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
| Reporting | Resident Desk downloads a hashed JSON report; Rescue can persist the exact report plus audit sequence as a signed Vault envelope and export it through the native TTY companion |
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
- The signed Rescue report HTTP relay remains internal loopback plumbing, not a
  public API. Its virtual shipping-image gate has passed, but physical USB and
  recovery behavior are not yet qualified.
- The v2 USB writer can copy, verify and provision an exact catalog-authorized
  image. Catalog revision 2 authorizes only the exact internally qualified
  candidate documented below; this is not physical-hardware qualification.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The private project area serves one controlled physical-qualification
candidate built from commit
[`2767a196c977d3b6f21418c20bd80131b1bcb3e6`](https://github.com/0xfunboy/KernAid/commit/2767a196c977d3b6f21418c20bd80131b1bcb3e6):

| Field | Exact value |
| --- | --- |
| Artifact version | `ci-32939869047-1` |
| Size | `1,221,148,672` bytes |
| SHA-256 | `9376269567869026bd34ab050fcfcba1f5c5633b97ec827b23916a1635322fb6` |
| Workflow | [Rescue run 32939869047](https://github.com/0xfunboy/KernAid/actions/runs/32939869047) |

That run successfully built the hybrid ISO, validated shipping binaries and
SBOM, passed ordinary BIOS/UEFI QEMU smoke, and passed the BIOS/UEFI two-boot
USB-style layout and persistent LUKS2/ext4 vault checks with byte-identical
disposable targets. Both final privileged lifecycle jobs also passed the
bounded Codex offline signed-out path and the signed-report persist, list, get,
cross-boot signer and fixed-path export path on the same artifact. The exact
locally verified catalog entry is now the sole image authorized by trusted
catalog v2 revision 2. This is an **internally and virtually qualified
candidate**, not a production release.

The candidate is exposed privately only to unblock the first physical boot
test. On Windows, verify the exact checksum and use Rufus in DD mode on a
factory-new or disposable USB of at least 32 GB. Keep Secure Boot disabled,
use non-customer hardware, and do not treat that manual write as encrypted-vault
provisioning or as a supported repair medium.

The latest complete unsigned Desk packaging matrix was built from commit
[`ad86e11330b3a5f97b8e01677a2e5c50e1ae1f1c`](https://github.com/0xfunboy/KernAid/commit/ad86e11330b3a5f97b8e01677a2e5c50e1ae1f1c)
in [Desktop run 32935382680](https://github.com/0xfunboy/KernAid/actions/runs/32935382680).
Linux x86-64, Windows x86-64, Intel macOS and Apple-silicon macOS packaging all
passed; signing, notarization and physical-machine qualification remain open.

## Immediate next gates

1. Boot that exact image from physical USB on a small hardware matrix and
   record firmware, storage, network and UI evidence.
2. Finish the real-account Rescue provider/vault lifecycle without exposing or
   copying the CLI credential store.
3. Qualify Secure Boot and signed release delivery.
4. Define the first production repair action with typed preconditions, backup,
   explicit approval, verification and rollback; keep it disabled until the
   complete safety case passes.
5. Add a repeatable release channel for Desk and Rescue artifacts.

## Where to look

- [Repository overview](../README.md)
- [Phase 0 architecture](architecture/phase-0.md)
- [Operator guide](operator-guide.md)
- [Product and architecture masterplan](MASTERPLAN.md)
- [Security policy](../SECURITY.md)
- [Private/public project-site operations](../site/README.md)

When this page conflicts with a broad future-looking statement in the
masterplan, this page is authoritative for current shipping status.
