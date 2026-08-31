# KernAid seven-day RC execution plan

This is the active delivery plan. Product scope and safety boundaries remain
defined by [MASTERPLAN.md](MASTERPLAN.md); exact shipped behavior remains
defined by [CURRENT_STATUS.md](CURRENT_STATUS.md).

## Target

Produce one downloadable, installable and internally qualified release
candidate covering the consumer Rescue/Desk experience and the enterprise
Fleet workflow within seven active AI-development days.

KernAid may diagnose failing hardware, preserve evidence, protect data and
coordinate replacement or recovery. Software cannot physically repair a dead
drive, broken board, connector or other damaged component, and the product must
never claim otherwise.

## Execution rules

- Develop and integrate in vertical batches; do not rebuild an ISO for every
  micro-change.
- During development run static checks and only tests directly affected by the
  change.
- Run one combined Rescue/Desktop/repair matrix per integrated milestone.
- Reuse green evidence when neither code nor inputs for that gate changed.
- Keep approval, typed actions, evidence, backup, verification and rollback
  fail-closed even when optimizing delivery time.
- Use Node.js `24.18.0` exactly.
- Commit and push progressive, coherent batches to `0xfunboy/KernAid` as
  `0xfunboy <0xfunboy@gmail.com>`.

## Delivery sequence

| Active day | Integrated outcome |
| --- | --- |
| 1–2 | Boot branding, physical-rendering fallback, Vault/first-boot fixes, CI budget and one new diagnosis candidate |
| 3 | One combined Rescue BIOS/UEFI, encrypted two-boot, Desktop packaging and repair-candidate cycle |
| 4–5 | High-value bounded repair packs plus governed Fleet work orders, device client, console, policy, licensing, audit and updates |
| 6 | Installable Resident services, trusted catalog, public/private site, operator and recovery documentation |
| 7 | Final integrated qualification, exact artifact promotion and release-candidate publication |

## RC completion gate

- Consumer download, checksum and writer instructions point to the same exact
  qualified image.
- Rescue boots through the tested BIOS/UEFI matrix and reaches a usable branded
  UI with console fallback.
- Desk artifacts exist for the declared Windows, Linux and macOS targets.
- Diagnosis stays useful offline; provider failure cannot block local evidence.
- Every enabled mutation has a closed action identifier, explicit approval,
  target binding, before evidence, verification and a truthful recovery state.
- Fleet can enroll a device, distribute policy/licensing/update intent, issue a
  typed work order, lease it to the intended device, ingest its signed result
  and show the audit trail.
- Public claims, private downloads, manifests, docs and binaries agree on the
  same commit and qualification evidence.

Physical USB, code-signing/notarization credentials, real provider accounts and
representative hardware are requested only when their external evidence becomes
the last remaining gate.
