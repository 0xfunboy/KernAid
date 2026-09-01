# macOS Resident P0 diagnostic pack

This crate is a Phase 0, read-only diagnostic corpus for a running macOS host.
It contains no mutation handler, privileged helper, command runner, filesystem
access, arbitrary shell, or recovery-key workflow. It only parses bounded byte
slices supplied by a platform collector that is outside this crate.

The corpus version is `macos-resident-p0.2`. A report is emitted only when all
eight evidence documents are present, use projection schema `1.0`, declare
`queryComplete: true`, and pass strict range and consistency checks. Each
document carries a caller-assigned SessionDriver evidence ID matching `E-*`;
all eight IDs must be valid and unique. “Complete” means only that the eight
projection documents and their declared query states were parsed. It does not
mean every diagnostic scope ran. Unqualified scopes produce fixed limitation
findings, and every proposal explicitly says that it is not a health
certification.

## Collector and evidence contract

| Fixed collector               | Evidence ID                         | Read-only source used by KernAid Desk                                                                                          |
| ----------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `macos.storage.inventory`     | caller-assigned, valid unique `E-*` | `system_profiler SPStorageDataType -json -detailLevel full`, normalized to device class and nullable medium/SMART state         |
| `macos.apfs.capacity`         | caller-assigned, valid unique `E-*` | `diskutil apfs list -plist` and `diskutil info -plist /`, including typed FileVault fields when the plist exposes them         |
| `macos.launchd.state`         | caller-assigned, valid unique `E-*` | bounded `/bin/launchctl list` for the current user domain; system scope is explicitly `not-run-unqualified`                    |
| `macos.network.state`         | caller-assigned, valid unique `E-*` | bounded `scutil --nwi`, `route -n get default`, and `scutil --dns` projections                                                 |
| `macos.software-update.state` | caller-assigned, valid unique `E-*` | no command or cache read; execution is `not-run-unqualified` and the stale-cache query state remains explicit                  |
| `macos.system-events.summary` | caller-assigned, valid unique `E-*` | no Unified Log query; execution/query are `not-run-unqualified` and incident counts are `null`                                 |
| `macos.startup.state`         | caller-assigned, valid unique `E-*` | `/usr/sbin/sysctl -n kern.safeboot`; login/background-item scopes are `not-run-unqualified` and their counts are `null`         |
| `macos.snapshots.inventory`   | caller-assigned, valid unique `E-*` | bounded `tmutil listlocalsnapshotdates /`, reduced to count and oldest age without retaining names                             |

The command names above document provenance, not a shell interface. A platform
adapter must invoke fixed executable paths with fixed arguments, an empty or
allowlisted environment, deadlines, bounded output, and explicit truncation
failure. It must normalize locally. `queryComplete: true` means the projection
document completely and honestly records both executed and deliberately
unqualified scopes; typed query-state fields are authoritative. It must never
interpolate input from a provider or observed data into a command.

The public `resident` module is the single fixed path/argument and projection
normalization contract reused by Desk and the off-default Fleet Resident.
Process execution remains in those platform adapters and cannot be selected by
a diagnostic request or work order.

The Desk adapter follows that contract and never forwards raw command output to
the UI. It also derives a hashed storage identity from the same bounded
`system_profiler` document and rejects the diagnostic run if the quick identity
and full collection differ. The two non-corpus startup observations are
normalized JSON too.

The launchd collector uses only the documented tabular `launchctl list` output
in the current user's launchd context. It requires the exact header, decimal PID
or `-`, a numeric last-exit status or `-` when launchd has no status, and one
bounded tab-delimited label. A running PID must carry `-`; a stopped job may carry `-`
or its numeric status. Labels are
validated but discarded. It never queries or invents system-domain services,
signing state, or consecutive-failure counts.

The update projection never invokes `softwareupdate` and never interprets the
potentially absent or stale software-update preferences cache. The events
projection similarly does not equate process log lines with incidents. Both
emit explicit limitations until a zero-write, freshness-preserving source and
incident-deduplication contract have been physically qualified.

The startup projection invokes only numeric `sysctl -n kern.safeboot`. It does
not invoke or parse the human-readable `sfltool dumpbtm` output. Login-item and
background-item states therefore remain explicit limitations with `null`
counts until a stable read-only schema is qualified.

## Deterministic rules

Rules cover internal storage hardware failure, critically low root APFS space,
snapshot/space correlation, nonzero last-exit status in the queried user
launchd scope, absent network interface/default route/DNS, and safe mode. This
P0 corpus accepts only the explicit unqualified update, event, system-launchd,
login-item, and background-item states described above; it cannot emit update
availability, incident-count, or item-count conclusions.
Findings contain only fixed text, fixed rule IDs, the validated caller evidence
IDs bound to their allowlisted collectors, and fixed next-collector IDs. Device
names, service labels, usernames, paths, log messages, update titles, and other
untrusted strings are deliberately absent from the projection schema.

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
- The desktop workflow runs one fail-closed native-source probe on its macOS
  host before packaging. Intel/Apple-silicon customer-hardware zero-write
  tests, macOS-version qualification, and signing/notarization remain mandatory
  support gates.
