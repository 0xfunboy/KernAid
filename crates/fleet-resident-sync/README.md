# KernAid Fleet Linux Resident sync

This crate provides the off-default `kernaid-fleet-resident-sync` executable.
Build it explicitly with:

```sh
cargo build --release -p kernaid-fleet-resident-sync --features linux-resident
```

The process is a systemd **user** service because the existing `resident-v1`
device identity lives in the user's Linux Secret Service keyring. It never
creates or replaces that identity. It opens a separate private Fleet state
directory, loads the already-protected identity, and drives the durable
`fleet-coordinator` inventory/audit outboxes and signed policy/entitlement
pulls. There is no remote-command route or repair authority.

Configuration is strict JSON; see `deploy/fleet-resident/config.example.json`.
It contains only public endpoint/state/trust-anchor paths. The one-time
enrollment token is read from a separate mode-0600 file, is never logged or
persisted, and is removed only after a matching HTTPS enrollment response and
durable enrollment journal commit. The journal binds endpoint, tenant and
key-derived device ID; any later mismatch fails closed.

Every post-enrollment response must include
`X-KernAid-Fleet-Receipt: <base64url-no-pad canonical receipt>`. The receipt is
the signed `dev.kernaid.fleet.service-receipt.v1` contract documented by
`fleet-coordinator`. HTTPS success without that receipt never acknowledges an
outbox row or applies a pull. The current control plane must enable this
receipt header/service signing key before this off-default service is enabled.

The transport accepts only one configured HTTPS origin, disables redirects
and proxies, uses fixed Fleet routes, bounds requests/responses and enforces
connect/request timeouts. Logs contain only fixed status/error codes and
aggregate counts—never endpoint URLs, tenant/device IDs, token bytes, nonces,
signatures, response bodies or key material.

The service collects only a minimized self-inventory: hashed Linux machine ID,
architecture, bounded `/etc/os-release` display name, unknown health, and zero
finding counts. Existing signed audit rows are uploaded; this process does not
copy Desk's separate audit database. A future Resident in-process integration
may enqueue Fleet audit drafts directly through the coordinator boundary.
