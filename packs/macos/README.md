# macOS Resident P0 diagnostic pack

This crate is a Phase 0, read-only diagnostic corpus for a running macOS host.
It contains no mutation handler, privileged helper, command runner, filesystem
access, arbitrary shell, or recovery-key workflow. It only parses bounded byte
slices supplied by a platform collector that is outside this crate.

The corpus version is `macos-resident-p0.1`. A report is emitted only when all
eight evidence documents are present, use projection schema `1.0`, declare
`queryComplete: true`, and pass strict range and consistency checks. Each
document carries a caller-assigned SessionDriver evidence ID matching `E-*`;
all eight IDs must be valid and unique. “Complete” means only that the eight
projections were parsed. A zero-finding report explicitly says that it is not
a health certification.

## Collector and evidence contract

| Fixed collector | Evidence ID | Read-only source for the future native collector |
| --- | --- | --- |
| `macos.storage.inventory` | caller-assigned, valid unique `E-*` | `system_profiler SPStorageDataType -json -detailLevel mini`, normalized to device class and SMART availability/state |
| `macos.apfs.capacity` | caller-assigned, valid unique `E-*` | `diskutil apfs list -plist`, `diskutil info -plist /`, and FileVault status through fixed native calls |
| `macos.launchd.state` | caller-assigned, valid unique `E-*` | bounded `launchctl print` projections for system and current GUI domains |
| `macos.network.state` | caller-assigned, valid unique `E-*` | bounded `scutil --nwi`, `route -n get default`, and `scutil --dns` projections |
| `macos.software-update.state` | caller-assigned, valid unique `E-*` | native software-update availability projection; integration must prove that collection does not mutate the target |
| `macos.system-events.summary` | caller-assigned, valid unique `E-*` | a bounded Unified Log/crash-summary window with counts only |
| `macos.startup.state` | caller-assigned, valid unique `E-*` | safe-boot state plus bounded Background Task Management/login-item counts |
| `macos.snapshots.inventory` | caller-assigned, valid unique `E-*` | bounded local APFS snapshot inventory with count and oldest age only |

The command names above document provenance, not a shell interface. A platform
adapter must invoke fixed executable paths with fixed arguments, an empty or
allowlisted environment, deadlines, bounded output, and explicit truncation
failure. It must normalize locally and set `queryComplete: true` only after
every required source completed successfully. It must never interpolate input
from a provider or an observed log into a command.

The update source intentionally remains a release gate: if a macOS version has
no proven observation-only API, that projection must fail closed instead of
running a command that may change update caches. The pack remains useful as a
tested corpus, but native collection support must not be claimed until this
gate is closed on physical Intel and Apple-silicon Macs.

## Deterministic rules

Rules cover internal storage hardware failure, critically low root APFS space,
snapshot/space correlation, repeated launchd failures, absent network
interface/default route/DNS, pending security or restart-required updates,
kernel panic/watchdog/repeated-crash signals, safe mode, blocked background
items, and unusually high login-item volume. Findings contain only fixed text,
fixed rule IDs, the validated caller evidence IDs bound to their allowlisted
collectors, and fixed next-collector IDs. Device names, service labels,
usernames, paths, log messages, update titles, and other untrusted strings are
deliberately absent from the projection schema.

`fixtures/diagnostics` contains synthetic, secret-free healthy, incident, and
adversarial projections. The adversarial corpus covers explicit partial state,
capacity inconsistency, unknown fields, and a prompt-injection string. The
unknown string is rejected and can never enter a finding or provider proposal.

## CLI

`kernaid-macos-diagnose` accepts one bounded JSON request on standard input and
returns a provider-neutral proposal on standard output. The request must have
exactly eight documents:

```json
{
  "schemaVersion": "1.0",
  "evidence": [
    {
      "id": "E-SESSION-7-COLLECTOR-1",
      "collector": "macos.storage.inventory",
      "content": "{...the JSON projection...}"
    }
  ]
}
```

The abbreviated example is not executable because omission is intentionally an
error. Exit codes are `2` for bounded-input failure, `3` for request-contract
failure, `4` for rejected diagnostic evidence, and `5` for output failure.

## Support boundary

- Resident macOS only; this does not diagnose an offline APFS installation.
- No FileVault unlock or recovery-key handling.
- No Disk Utility repair, `fsck_apfs`, snapshot deletion, update installation,
  launchd changes, login-item changes, NVRAM changes, or network changes.
- No Apple-silicon boot-media claim and no Intel/T2 external-boot claim.
- Native collection, signing/notarization, macOS-version qualification, and
  physical-machine zero-write observation tests remain mandatory support gates.
