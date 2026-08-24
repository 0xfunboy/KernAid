# KernAid current status

Last updated: 24 August 2026

This page separates the product vision from what the repository can safely do
today. The short version is: **KernAid Phase 0 is a substantial diagnosis-only
engineering preview, not yet a production repair product.**

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
| Rescue security | Isolated credential-vault and fail-closed Codex login/status/logout bridge plumbing; it does not yet run prompts or diagnoses |
| Virtual testing | Disposable QEMU fixtures, mutation checks and BIOS/UEFI workflow coverage |
| Repair experiment | Linux-only feature-gated Desk lab for one typed R2 repair, verification and separately approved rollback on an internal temporary fixture; absent from normal/Rescue builds and disconnected from production targets |

The canonical repository is `/home/funboy/kernaid`, branch `main`. Temporary
integration worktrees are not product branches and should not be treated as a
newer release.

## What does not work yet

- There are no production mutation handlers and no real customer-machine
  repair path.
- Physical USB boot has not been qualified. Do not write the current preview
  ISO to a customer or irreplaceable device.
- Secure Boot is not qualified.
- Desktop installers are unsigned engineering previews.
- Rescue provider login with a real account, live TLS and physical encrypted
  persistence are incomplete release gates.
- The active USB writer copies and verifies an exact catalog-authorized image,
  but the current catalogs do not authorize the private preview ISO.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The previous `main` baseline was commit `2703c94`. Its
[general CI run](https://github.com/0xfunboy/KernAid/actions/runs/32454125905)
passed, while its
[Rescue run](https://github.com/0xfunboy/KernAid/actions/runs/32454125800)
stopped in the BIOS QEMU smoke stage, before UEFI, privileged vault lifecycle,
catalog generation and ISO publication. The follow-up in this repository makes
the QEMU network probe bind deterministically and extends the bounded firmware
marker wait; the new Rescue workflow result must pass before any newer ISO is
called publishable.

The ISO currently available in the private project area is an older engineering
artifact sourced from commit `b843178`. Its SHA-256 is published beside it and
its download supports resume, but it is **not present in the trusted v2 catalog**
and is therefore a laboratory artifact only. It is not a physical-media
release.

## Immediate next gates

1. Get the Rescue workflow green on the current `main` revision for BIOS, UEFI
   and both privileged vault-lifecycle jobs with byte-identical disposable
   targets.
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
