# IPC protocol

Shared versioned envelopes require session identity, approval identity where applicable, target fingerprint, and monotonic sequence. JSON Schemas under `packages/schemas` are the wire-contract source during Phase 0.

## Rescue vault v1alpha1

`rescue_vault` defines the closed contract for a future root-owned local vault
service. The service transport is AF_UNIX `SOCK_SEQPACKET`; one datagram is one
strict UTF-8 JSON object of at most 64 KiB. The request envelope is exactly:

```json
{
  "apiVersion": "kernaid.dev/rescue-vault/v1alpha1",
  "requestId": "R-12345678-1234-1234-1234-123456789abc",
  "expectedStateVersion": 0,
  "operation": "vault.status",
  "payload": {}
}
```

Duplicate or unknown fields, an unknown operation/version, invalid identifiers,
and trailing JSON are protocol violations. Syntax/version violations close the
connection instead of reflecting attacker-controlled input. Responses contain
the same request ID and operation, the authoritative `stateVersion`, and either
a typed payload or one token from the closed error enum. There is no free-form
error message, command, device, mount path, provider secret, or report body in
JSON.

Both state-version fields are bounded by `Number.MAX_SAFE_INTEGER`
(`9_007_199_254_740_991`). A future daemon must seed a fresh epoch from a
CSPRNG value of at most 52 bits and use checked increments. It increments once
when entering `unlocking`/`locking` and again when completing the transition.
The closed states are `absent`, `unprovisioned`, `locked`, `unlocking`,
`unlocked`, `locking`, and `faulted-reboot-required`. Only `vault.status` is
allowed while faulted; every other operation returns `REBOOT_REQUIRED`.

The server derives the caller PID and UID with `SO_PEERCRED` on the connected
seqpacket socket. `PeerAllowlist` maps two distinct non-root UIDs to
`companion` and `agent`; neither identity is accepted from JSON.

| Operation | Allowed caller | Request FD | Success FD |
| --- | --- | --- | --- |
| `vault.status` | companion, agent | 0 | 0 |
| `vault.unlock` | companion | 1 passphrase pipe | 0 |
| `vault.lock` | companion | 0 | 0 |
| `provider.openai.configure` | companion | 1 API-key pipe | 0 |
| `provider.status` | companion, agent | 0 | 0 |
| `provider.logout` | companion | 0 | 0 |
| `provider.openai.borrow` | agent | 0 | 1 one-shot API-key pipe |
| `provider.codex.home_lease` | agent | 0 | 1 `O_PATH` directory |
| `audit.append` | agent | 0 | 0 |
| `report.persist` | agent | 1 SessionReport JSON pipe | 0 |
| `report.list` | companion, agent | 0 | 0 |
| `report.get` | companion, agent | 0 | 1 signed-report-envelope pipe |

SCM_RIGHTS count, file type, PIPEFS filesystem identity, access mode, CLOEXEC
state, declared type, and declared size are checked together. Only anonymous
PIPEFS read ends already marked CLOEXEC are accepted; a named FIFO is rejected
even though its inode type is FIFO. Pipe consumers must later read exactly the
declared byte count and then EOF within their own deadline. Error responses
carry no descriptor. `provider.codex.home_lease` accepts only an `O_PATH`
directory descriptor, never its pathname.

A borrow/home-lease connection remains open for the lifetime of the lease and
is bound to the authenticated Agent PID. Socket close plus pidfd process exit
mark release. On `vault.lock`, the daemon answers `BUSY`, terminates only its
dedicated Agent process, and waits for pidfd-confirmed exit and lease release
before locking. An initial daemon that cannot yet supply an OpenAI key may
answer `provider.openai.borrow` with `PROVIDER_UNCONFIGURED` and no descriptor.

Passphrase pipes are limited to 12–1024 non-NUL bytes, matching vault writer
v2. After the exact-size read the handler must attempt one further read, prove
EOF, and call `validate_passphrase_read`; short, extra, NUL-containing or
non-EOF input is rejected. OpenAI key pipes are limited to 1–512 bytes. After
the exact-size/EOF read, the
handler must apply `validate_openai_api_key_bytes`: every byte must be visible
ASCII `0x21..=0x7e`, matching the shipping native credential-store policy.

Report persistence has two deliberately separate byte domains. The input
`session-report-json-pipe` carries at most 1 MiB and `payloadSha256`
authenticates those exact input bytes. Before appending to the journal or
signing anything, the daemon must read exactly the declared size plus EOF,
verify that hash, require UTF-8, reject duplicate fields and trailing data,
and validate the complete `session-report` schema. It signs only that accepted
document with the fixed `application/json` payload media type. This prevents
the service from becoming a generic signing oracle.

After signing, storage and every response summary describe the authenticated
serialized envelope via `envelopeSize` and `envelopeSha256`; `report.get`
returns only a `signed-report-envelope-pipe`, capped separately at 1.5 MiB.
SessionReport input and signed-envelope output descriptor types are never
interchangeable.

`audit.append` accepts only the authenticated Agent's own session lifecycle
claims (`agent-session-start`, `agent-diagnosis-complete`, and
`agent-session-end`). They remain attributed to that SO_PEERCRED identity. The
Agent cannot submit vault, provider-secret, or report-persistence audit events;
the daemon records those privileged facts internally after it performs and
verifies the corresponding operation. Agent sequences are bounded by the
journal ceiling of 1,000,000 entries.

Decode failures without a fully validated version/request ID/state
version/operation are close-only. Only authenticated role or descriptor
rejections retain a `RejectedRequestContext`, which makes the otherwise closed
`NOT_AUTHORIZED`, `FD_REQUIRED`, and `FD_FORBIDDEN` responses reachable without
reflecting untrusted correlation data.

This crate currently provides the codec, authorization and FD contract only.
It does not create a listening socket, daemon, vault mount, unlock flow, secret
store, provider process, or UI endpoint.
