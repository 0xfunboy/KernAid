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
when entering a vault or provider mutation and again when completing the
transition. The typed client decoder therefore accepts a successful
`vault.unlock`, `vault.lock`, `provider.openai.configure`, or `provider.logout`
response only when its `stateVersion` is exactly the request's
`expectedStateVersion + 2`; status and error responses remain authoritative
within the general safe-integer bound.
The closed states are `absent`, `unprovisioned`, `locked`, `unlocking`,
`unlocked`, `locking`, and `faulted-reboot-required`. Only `vault.status` is
allowed while faulted; every other operation returns `REBOOT_REQUIRED`.

The server derives the caller PID and UID with `SO_PEERCRED` on the connected
seqpacket socket. `PeerAllowlist` maps one non-root UID to `companion` and
optional, purpose-specific non-root UIDs to the `application`, `openai`, and
`codex` Agent roles; neither identity nor role is accepted from JSON. Its
builder rejects root, a UID shared by two roles, a role assigned twice, and
any Agent UID equal to the companion UID. There is no fallback Agent role. A
companion-only allowlist is available for deployments that do not yet run an
Agent identity. Authentication returns a non-cloneable borrowed connection
capability, not a copyable identity assertion. Requests and rejection contexts
carry a private per-authentication token and kernel socket identity; responses
can be sent only through the capability that received that record.

The Linux transport helpers require a connected, non-listening AF_UNIX
`SOCK_SEQPACKET` socket whose descriptor has `CLOEXEC`, plus a caller-supplied
hard monotonic deadline. They use nonblocking `sendmsg`/`recvmsg` with bounded
`poll`, reject truncated records, truncated ancillary data, recognized
credentials control messages, and more than one passed descriptor, and receive
descriptors with `CLOEXEC` set. Sends use `MSG_NOSIGNAL` and must complete one
whole record. Received descriptors are owned and close on every rejection
path. The raw record functions and decoders are crate-private. The only public
exchange methods are on connection capabilities: the client first
authenticates the server as UID 0 with `SO_PEERCRED`, and the server first
authenticates the allowlisted peer. Every authentication, send, and receive
boundary revalidates socket type, connection state, kernel identity, and
`CLOEXEC`. Linux reports both an orderly peer shutdown and a zero-length
`SOCK_SEQPACKET` record as a zero-byte receive, including when an empty record
is immediately followed by shutdown. A live empty record is rejected as a
framing violation. A zero-byte receive accompanied by hangup, or whose peer
state cannot be classified within the current receive deadline, is reported
as a separate ambiguity: it is eligible for bounded fresh-status
reconciliation only after a valid mutation request was sent, never for status
or request decoding. A queued successor remains available to the next receive,
and any descriptors duplicated while peeking are closed.

Every receiving endpoint must keep ancillary-generating options not modelled
by `rustix` 1.1 disabled: notably `SO_PASSPIDFD`, `SO_PASSSEC`, and socket
timestamping. `rustix` filters unknown control-message kinds before this crate
can observe them; a generated `SCM_PIDFD` would otherwise leave an unowned
descriptor. The daemon inherits this policy from its root-owned listener, and
the client creates its endpoint with these options disabled. The shipping
systemd socket configuration must preserve this default-off precondition and
its tests must reject any future opt-in.

| Operation | Allowed caller | Request FD | Success FD |
| --- | --- | --- | --- |
| `vault.status` | companion, application, openai, codex | 0 | 0 |
| `vault.unlock` | companion | 1 passphrase pipe | 0 |
| `vault.lock` | companion | 0 | 0 |
| `provider.openai.configure` | companion | 1 API-key pipe | 0 |
| `provider.status` | companion, application, openai, codex | 0 | 0 |
| `provider.logout` | companion; codex only when `provider=codex` | 0 | 0 |
| `provider.openai.borrow` | openai | 0 | 1 one-shot API-key pipe |
| `provider.codex.home_lease` | codex | 0 | 1 `O_PATH` directory |
| `audit.append` | application | 0 | 0 |
| `report.persist` | application | 1 SessionReport JSON pipe | 0 |
| `report.list` | companion, application | 0 | 0 |
| `report.get` | companion, application | 0 | 1 signed-report-envelope pipe |

SCM_RIGHTS count, file type, PIPEFS filesystem identity, access mode, CLOEXEC
state, declared type, and declared size are checked together. Only anonymous
PIPEFS read ends already marked CLOEXEC are accepted; a named FIFO is rejected
even though its inode type is FIFO. Pipe consumers must later read exactly the
declared byte count and then EOF within their own deadline. Error responses
carry no descriptor. `provider.codex.home_lease` accepts only an `O_PATH`
directory descriptor, never its pathname.

A borrow connection remains open for the lifetime of the lease. The daemon
acquires its process identity only with `SO_PEERPIDFD` on that accepted,
authenticated Agent socket; it never converts the numeric `SO_PEERCRED` PID
into a pidfd. It registers Pending before worker dispatch. Normal release or
revocation requires full socket HUP, pidfd exit, and publication that every
supervisor-owned credential output FD has been closed. On `vault.lock`, stop,
fault, handoff ambiguity, or expiry, the supervisor signals only that exact
pidfd and waits all three factors before worker lock, unmount, or lifecycle
marker disarm. An unconfigured daemon answers `provider.openai.borrow` with
`PROVIDER_UNCONFIGURED` and no descriptor as a definite no-secret outcome.

The feature-gated daemon constructs only companion and OpenAI Agent mappings
and enables this OpenAI borrow only for `Agent(OpenAi)`. The supervisor creates
an anonymous nonblocking pipe, gives only its write end to the worker,
validates the private `Ready` result without reading credential bytes, and
sends the read end with `SCM_RIGHTS` while holding the lifecycle linearization
barrier against lock/revoke. Pending handoff, established lease, and
revocation have separate absolute bounds; ambiguous worker or send outcomes
revoke rather than free early. Application and Codex roles, Codex status/home
lease/logout requests, and audit/report operations remain disabled before
worker dispatch.

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

This protocol crate provides the codec, authorization and FD contract plus
strict Linux record transport and typed client request/response helpers; it
does not itself create a listener, daemon, mount, store, provider process, or
UI endpoint. The feature-gated implementation in `kernaid-rescue-secrets`
enables vault lifecycle, provider configuration lifecycle (`provider.status`,
`provider.openai.configure`, and OpenAI `provider.logout`), plus the leased
OpenAI Agent `provider.openai.borrow` path. The separate one-shot executor is
the only consumer and fixes its TLS destination and Responses codec. The
shipping daemon has no Application or Codex UID mapping and rejects their
typed protocol operations before state, marker, or worker handling. Codex
home/logout/status effects, audit/report operations, and generic network or UI
command surfaces remain disabled.
