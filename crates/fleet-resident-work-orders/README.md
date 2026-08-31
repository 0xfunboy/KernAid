# KernAid Fleet Resident work orders

This crate is the device-side, transport-neutral state machine for typed Fleet
work orders. It accepts only the closed action catalog defined by
`kernaid-fleet-client`; it never accepts command lines and never invokes a
shell.

## Wire contract

A `ResidentWorkOrderTransport` implementation must use only these fixed routes:

- `POST /v1/work-order-claims` with an exact canonical
  `dev.kernaid.fleet.work-order-claim-request.v1` body;
- `POST /v1/work-order-results` with an exact canonical, device-signed
  `dev.kernaid.fleet.work-order-result.v1` body.

The transport must disable redirects, proxies and unbounded responses. It
passes the response body and the decoded canonical bytes from
`X-KernAid-Fleet-Receipt` to the engine. The engine verifies the external
service receipt anchor, tenant/device binding, request and response digests,
and the monotonic receipt checkpoint before continuing.

## Durable flow

The owner-only canonical journal persists each boundary before the next side
effect:

`claim pending -> lease ready -> execution pending -> result pending -> idle`

Claim and result retries reuse the exact signed bytes. Local execution receives
a deterministic `execution_id`; `execute_or_recover` must persist and use it as
an idempotency key. An expired lease after execution becomes an explicit
recovery-required state and is never executed again blindly.

## Authorization and handoff

The caller supplies current `FleetCapabilities`, every applicable verified
Fleet policy, the local risk floor and the Resident platform. The engine
intersects them and fails closed. A repair requires both the organizational
approval delivered by Fleet and a separate fresh `BoundLocalApproval` bound to
the work order, lease, action/version, execution, plan and target digests.

`linux.fstab.disable-missing-uuid.v1` is compiled off by default. A Rescue
integration must explicitly enable `rescue-fstab-handoff` and connect the typed
handoff to the existing gated Core/Broker execution path. Enabling the feature
does not bypass policy, entitlement, local approval or lease validation.

The device identity is supplied in memory for signing and is never serialized
to the journal. Results contain only an outcome and digest; raw output, logs,
tokens and approval secrets are not persisted or uploaded by this crate.

## Linux service (off by default)

Build the separate Resident service explicitly:

```sh
cargo build --release -p kernaid-fleet-resident-work-orders --features linux-service
```

The binary is absent from normal workspace and Desk builds. Its systemd user
deployment is under `deploy/fleet-resident-work-orders/` and is never enabled
by installation. It loads the existing `resident-v1` identity from the native
OS secret store, reads signed policy and entitlement state from the Fleet
runtime, and polls only the two fixed work-order routes over HTTPS with no
redirect or proxy support.

The Linux adapter dispatches only `linux.filesystem.health.v1`,
`linux.storage.health.v1` and `linux.boot-critical-path.v1` to their existing
fixed-command, bounded collectors.
It persists only execution bindings and result digests for restart recovery.
The Rescue fstab write action is not connected to this process: remote tenant
approval can never substitute for a fresh local Vault approval or the
Core/Broker policy and entitlement boundary.
