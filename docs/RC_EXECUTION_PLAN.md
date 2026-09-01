# KernAid seven-day RC execution plan

This plan is prepared for the next execution window and is currently paused
after the diagnosis-release/site/documentation closeout requested by the
owner. Resume it with the
[AI product-completion directive](AI_PRODUCT_COMPLETION_DIRECTIVE.md).
Product scope and safety boundaries remain defined by
[MASTERPLAN.md](MASTERPLAN.md); exact shipped behavior remains defined by
[CURRENT_STATUS.md](CURRENT_STATUS.md).

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

Workstreams run in parallel; the day column is a deadline, not a serialized
queue.

| Deadline | Integrated outcome |
| --- | --- |
| Today | Qualify and promote the current diagnosis ISO, update the trusted catalog and authenticated site, and publish one unambiguous Windows download path. |
| Day 2 | Close the consumer Rescue/Desk journey: guided diagnosis, offline fallback, Vault, report export, Media Creator and recovery instructions. |
| Day 4 | Promote the four bounded Linux Rescue repairs after their combined apply/failure/rollback matrix; finish the corresponding approval and recovery UX. |
| Day 5 | Close the Enterprise software loop across onboarding, Resident identity, restrictive policy, licensing, work orders, local approval, signed result, incidents, updates and audit. |
| Day 6 | Complete the installable Linux/Windows/macOS Resident packages, Windows-native repair expansion and the customer-buildable WinPE companion path that Microsoft licensing permits. |
| Day 7 | Run one final integrated matrix, publish the consumer and Enterprise RC artifacts, update the commercial/private site and freeze exact operator documentation. |

## Checkpoint — 1 September 2026

The closed diagnosis cohort is exact source commit
`6e9742e5b0c4397728dde80e9a0a91a09214f7cd`. CI run `33486399168` and Desktop
run `33486399165` succeeded. Rescue run `33486399275` passed build, shipping
surface exclusion, ordinary BIOS/UEFI and USB-style two-boot BIOS/UEFI, but its
separate UEFI Vault lifecycle failed readiness. `internal.7` was not dispatched;
the remaining BIOS lifecycle/native-prompt jobs were cancelled after that
irreversible result, and the exact ISO is retained only as a private
physical-test candidate. This cut
serializes initial inventory and target discovery and preserves truthful
`unsupported` optional SMART/NVMe evidence instead of blocking diagnosis.

The exact current repair candidate is commit
`01cf8fe981971ea9c1b3fa82d1f90de744a0d3ad`, Repair run `33482972849`. The
consolidated batch failed at `uefi:crypttab-lifecycle` with the exact marker
`stage=provider-proof code=command-failed`; no qualified ISO or publisher was
produced. Per the owner stop request, this candidate is recorded but not fixed
or rerun in the current closeout.

Integrated in current source, but still off-default or awaiting exact-image
qualification:

- four off-default Rescue repair actions plus a local-only Fleet-to-Rescue
  adapter for all four corresponding closed intents; every repair still
  requires fresh target/evidence-bound approval;
- a disabled-by-default Linux Resident `.deb` containing sync, R0 work orders,
  signed update staging and the UEFI/systemd-boot A/B activator;
- the off-default Windows R0 Resident and its explicitly unsigned deployment
  ZIP workflow;
- the off-default macOS R0 Resident and its explicitly unsigned/unnotarized
  Intel and Apple-silicon bundle workflow;
- the Windows Media Creator wizard, which verifies an offline-signed exact
  release bundle while its EXE/ZIP remains unsigned pending Authenticode;
- live Fleet schema v13 with active offline commercial licensing and scheduled
  signed, WAL-safe, independently verified backup bundles; and
- a gated private software catalog that now publishes the reviewed Media
  Creator and Linux, Windows and dual-architecture macOS Resident engineering
  artifacts with exact provenance, digest, qualification and unsigned-state
  metadata.

The reviewed Resident source is `fe3c940d525f5c1c2ecd8123bdb100cd3280b908`.
Linux run `33471097700`, Windows run `33471100838` and macOS run `33471099291`
are green. The native services expose explicit one-shot enrollment: a
platform-bound identity signs the fixed request, a one-use token is consumed
only after acceptance, and normal startup requires the persisted public
binding. The workflows verify that contract, disabled startup, the fail-closed
no-anchor path and cleanup. Packages remain unsigned; physical key-store,
publisher-signing and endpoint-to-production-Fleet evidence remain external.

The stable download remains `0.1.0-internal.6` because the diagnosis cohort did
not satisfy every Vault gate. Run `33486399275` is exposed separately and
truthfully as physical-test input; it is not trusted-catalog or Release Channel
promotion. Further feature work and reruns are paused after the current
site/documentation closeout, per the owner stop request.

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
