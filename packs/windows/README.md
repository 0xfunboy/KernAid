# Windows P0 diagnostic pack

`kernaid-windows-pack` is a Phase 0, diagnosis-only Resident/WinPE corpus. It
turns eleven normalized Windows observations into deterministic findings and a
provider-neutral diagnosis proposal. The crate has no host filesystem or
process API: it cannot run PowerShell, DISM, SFC, `bcdedit`, or any mutation.

An upstream native collector must produce the projections below from fixed,
observation/check-only APIs or commands. It must not expose a general command
field or a repair mode; native Windows tools may still update their own logs. All
eleven documents are mandatory and each body is limited to 1 MiB. Collector
identifiers are fixed. Evidence IDs are assigned by the session (for example,
`E-1` or `E-WIN-EVENT-LOG`), must match `E-[A-Za-z0-9-]+`, are limited to 128
bytes, and must be unique within the evaluation. Findings retain the actual ID
assigned to their source:

| Collector | Fixture evidence ID | Normalized observation |
| --- | --- | --- |
| `windows.event-log.window` | `E-WIN-EVENT-LOG` | 168-hour System/Application projection with native `recordId`, without messages |
| `windows.reliability.records` | `E-WIN-RELIABILITY` | 168-hour Reliability projection with native log/record identity and nullable product name |
| `windows.component-store.check-health` | `E-WIN-COMPONENT-STORE` | read-only component-store check state |
| `windows.sfc.verify-only` | `E-WIN-SFC-VERIFY` | explicit execution state: a qualified `/verifyonly` result or `not-run-unqualified`, never a repair mode |
| `windows.update.state` | `E-WIN-UPDATE` | reboot signals, scan state, and 168-hour failed-update IDs/HRESULTs |
| `windows.services.state` | `E-WIN-SERVICES` | complete service start/state/exit-code projection, including Boot/System and pending enum values |
| `windows.network.state` | `E-WIN-NETWORK` | complete adapters, routes, and DNS bindings; zero adapters is valid evidence |
| `windows.drivers.state` | `E-WIN-DRIVERS` | complete present-device status/signature inventory and 168-hour change projection |
| `windows.bitlocker.state` | `E-WIN-BITLOCKER` | drive-letter volume protection/lock/conversion state only; key protectors and recovery material are forbidden |
| `windows.boot.state` | `E-WIN-BOOT` | normalized firmware/boot-manager/loader presence |
| `windows.volumes.state` | `E-WIN-VOLUMES` | complete drive-letter capacity/free-space projection |

The evidence IDs shown in the table belong to the synthetic corpus; they are
not protocol constants. The normalized adapter is responsible for
locale-independent values and for setting a completion flag/state only after
the defined projection finishes without truncation. A false completion flag,
partial source, unknown JSON field, inconsistent cross-field state, duplicate
native record, malformed timestamp/address/GUID, invalid or duplicate evidence
ID, oversized input, or missing collector rejects the whole evaluation. An
unavailable typed API state creates an explicit inconclusive finding; it is
never treated as a healthy result.

Source-specific identity and correlation rules are also fail-closed:

- Event rows are limited to the `System` and `Application` logs and deduplicated
  by case-insensitive log name plus native Event Record ID. Equal payloads with
  distinct Record IDs remain distinct events.
- Reliability rows use `LogFile`, `RecordNumber`, and `TimeGenerated` as their
  identity. `ProductName: null` is valid, and an unavailable Reliability API is
  an explicit finding rather than an empty history.
- Routes require a canonical network prefix and matching destination/next-hop
  address families. A multicast next hop is rejected. Unspecified next hops
  (`0.0.0.0` or `::`) are accepted only as Windows on-link sentinels.
- DNS servers must be real parsed addresses and cannot be unspecified or
  multicast. Loopback DNS (`127.0.0.0/8` or `::1`) is intentionally accepted
  because a local stub resolver or filtering proxy can be the usable resolver.
- Route rows and recent driver/update changes use normalized semantic keys;
  duplicates reject the source before counts or correlation rules run.
- The BitLocker projection deliberately contains only volumes with drive
  letters and requires exactly one OS volume. Its OS drive letter must match
  the system drive from `windows.volumes.state`, case-insensitively. Every OS
  conversion state other than fully encrypted is an explicit finding;
  encryption/decryption paused states and rounded 0/100 progress values are
  represented directly. Unlettered reserved volumes are outside this bounded
  projection, not silently represented as empty drive letters.
- Start/continue/pause/stop-pending service values are accepted observations,
  not failures by themselves. A future stalled-transition rule requires a
  bounded recheck of checkpoint and wait-hint data.

Observed provider names, product names, device IDs, and change identifiers are
untrusted data. They are validated and counted but never copied into finding
summaries, rule IDs, follow-up collector IDs, or diagnosis text. Event messages,
service display names, BitLocker protectors, user paths, and recovery keys are
outside the schema and therefore rejected.

## CLI contract

`kernaid-windows-diagnose` reads one bounded JSON request from standard input:

```json
{
  "schemaVersion": "1.0",
  "evidence": [
    {
      "id": "E-WIN-EVENT-LOG",
      "collector": "windows.event-log.window",
      "content": "{...normalized JSON...}"
    }
  ]
}
```

The array must contain exactly one document for every collector in the table.
Output is a single `WindowsDiagnosisProposal` JSON object. With findings, its
evidence list is the canonical union of finding-bound IDs and its diagnosis
contains only fixed rule IDs/summaries; with no finding, all complete source IDs
remain attached. Exit code `2` is a
bounded input failure, `3` is an invalid request envelope, `4` is rejected
diagnostic evidence, and `5` is an output failure. Error output is fixed text
and never echoes observations.

## Deterministic rules

The `windows-p0.1` corpus covers critical/repeated events, Reliability failures,
component-store and system-file integrity, Windows Update pending/failure
signals, automatic service failures, route/DNS/adapter availability, driver
problem/signature state, BitLocker OS-volume protection and conversion, boot configuration,
and system-volume free space. Findings are canonically ordered and contain only
fixed summaries plus exact evidence bindings. A complete baseline with no rule
match says only that this corpus found no deterministic incident; it does not
claim that Windows, hardware, or user data is healthy.

## Verification and remaining platform gates

The synthetic corpus exercises the parsers and CLI on any Rust build host. It
does not by itself establish native Windows support. Before integration can be
claimed, the fixed collector adapter must be implemented and validated on
native Windows 11 and WinPE fixtures, including localized systems, BitLocker
on/off/suspended states, interrupted enumeration, standard-user permissions,
command/API deadlines, and before/after write monitoring. DISM/SFC/BCD repair,
service changes, update changes, driver changes, and BitLocker operations remain
out of scope for Phase 0.
