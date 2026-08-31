# Linux storage health v1

KernAid Resident and Rescue use the same no-argument
`kernaid-linux-storage-health` collector. It enumerates physical disks through
one fixed `lsblk --json --nodeps --output NAME,TYPE` invocation. For each
strictly validated kernel disk name it may call only fixed absolute
`smartctl --json=c --all /dev/<name>` and, for NVMe names, `nvme smart-log
--output-format=json /dev/<name>`. It never accepts a command, path or device
selector from the UI, provider or report.

Each child process has a four-second timeout, null input, a cleared environment
with a fixed locale/path, and separately drained 64 KiB stdout/stderr limits.
Raw output is parsed in memory and discarded. The published document contains
only the matching normalized `disk-N` reference and, when available:

- overall health pass/fail;
- NVMe critical warning and media-error counters;
- temperature;
- available spare percentage; and
- percentage used.

Serial numbers, WWNs, kernel names, `/dev` paths, model strings and raw JSON are
excluded by the Rust type, browser parser, JSON Schema, privileged-helper
boundary and readiness checks. The same lexical disk ordering used by the
Rescue target scan binds `disk-N` to an already normalized target reference.

Rules are deterministic and closed: `healthy`, `degraded`, `failing`,
`unsupported`, or `permission-unavailable`. A failing or degraded drive adds a
fixed backup-and-replacement finding to the local diagnosis and signed report.
KernAid does not offer or claim a software repair for physical media. Missing
tools, malformed output and insufficient privilege degrade to an unavailable
state and never imply health.

Rescue packages `smartmontools` and `nvme-cli` and executes the collector through
the root-owned offline inspector. Resident calls the same library directly.
Storage evidence is additive: failure to obtain it cannot block the existing
OS diagnosis corpus, but the report explicitly requests or records the missing
telemetry. Raw storage telemetry is not sent to the Rescue OpenAI provider; the
locally validated result is merged deterministically after provider output.

Fixture and static tests cover healthy and failing SATA/NVMe payloads,
malformed/oversized responses, unavailable tools, permission errors and secret
canaries. These tests do not qualify vendor firmware or physical drives; that
remains a hardware-lab release gate.
