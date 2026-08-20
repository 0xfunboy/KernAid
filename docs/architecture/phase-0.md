# Phase 0 architecture

```text
Desk UI -> SessionDriver -> Agent Gateway -> Provider
                          -> Core -> Policy -> typed Broker
                          -> Evidence / journal
```

Provider output is an untrusted proposal. It cannot call the broker. Core links claims to evidence, validates action metadata, and admits only R0 in this phase. The fake broker recognizes only `system.observe.noop`, checks the target fingerprint, and rejects repeated or decreasing sequence numbers.

The Resident Linux fixture collector accepts exactly one directory and reads
metadata only. Rescue has a separate one-shot, descriptor-bound inspector for
qualified disposable block-image targets; it uses fixed read-only mount policy
and emits a bounded normalized corpus tagged `observed-untrusted`. Neither
collector grants provider output access to the broker.

## Implemented acceptance checks

- Unknown broker actions are rejected.
- R1–R4 plans are rejected by Phase 0 policy.
- Provider diagnoses require evidence IDs.
- Seeded API-shaped secrets are redacted.
- Fixture file hashes are identical before and after Observe collection.
- Linux Resident and Rescue expose one shared normalized CPU, RAM, firmware,
  DMI, PCI and USB collector with per-source status and no serial, UUID, asset
  tag, bus-address or caller-path fields. Its published schema is
  `linux-hardware-inventory.schema.json`.
- Rescue includes the exact supply-chain-verified Codex CLI and a one-request,
  non-root authentication bridge. Its closed grammar is device login, status,
  and logout only; it receives an exclusive descriptor-bound `CODEX_HOME` from
  the unlocked vault, disables the CLI's PATH/tool aliases, and never opens
  `auth.json`.
- Fake-CLI tests cover persistent state across bridge restarts, logout, raw
  output suppression, home tamper, executable tamper, and exact CLI arguments.
  The privileged QEMU lifecycle additionally requires an offline signed-out
  status through the shipping client, bridge, vault lease, and pinned real CLI.

## Open release gates

The repository now defines legacy-BIOS/UEFI QEMU boot gates, a feature-gated
encrypted Rescue vault/provider lifecycle, and closed signed-report library
primitives. An exact Rescue image is virtually qualified only when both
privileged lifecycle jobs pass. The shipping peer allowlist exposes the Codex
role only to the fixed non-root authentication unit and only for an exclusive
home lease; Application audit/report, Codex prompt execution, model selection,
target access, and broker access remain absent. Secure Boot,
browser-renderer/WebKit/GPU compatibility, a completed Codex device login with
a real enabled account, live provider TLS, and physical hardware/media support
remain open release gates.
