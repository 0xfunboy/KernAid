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
integration must explicitly enable `rescue-fstab-handoff`. That feature exposes
`RescueFleetRepairAdapter`, whose only broker output is the existing fixed
`repair.status`, `repair.fstab.prepare`, `repair.fstab.approve` and
`repair.fstab.cancel` protocol. The supplied `RescueRepairBroker` implementation
must terminate at the authenticated local `kernaid-rescue-repaird` seqpacket
service; it must not proxy a caller-selected endpoint. Core, Broker and Vault
therefore remain the only write-authority path.

The adapter persists an owner-only intent before any broker exchange. Desk can
read the minimized `dev.kernaid.fleet.rescue-repair-intent.v1` view and submit
only three canonical, unknown-field-rejecting operations:

- `stage`: echoes the work-order binding and supplies the already validated,
  path-free local Rescue target claims;
- `approve`: echoes device, work order, lease, action/version, execution, plan,
  target and evidence digests, plus a fresh local approval (maximum age 120
  seconds) and the exact typed confirmation;
- `reject`: echoes the same intent and evidence digest, cancels the local Vault
  reservation, and makes the Fleet result terminally `rejected`.

The candidate Desk surface is `/api/rescue/fleet-repair`: `GET` returns the
canonical intent (or 204 when absent), and `POST` passes one of the canonical
operations above to the adapter. The relay must retain its existing same-origin
and peer-authentication controls. The shipping Desk remains unchanged because
the candidate entry is still selected only by `KERNAID_REPAIR_CANDIDATE=1`.

The adapter writes `execution pending` before repaird approval. On restart it
queries repaird state before retrying, so an uncertain write is recovered and
never blindly repeated. Its terminal receipt contains opaque IDs and digests
only; exact replay returns the retained digest without another broker call.
Enabling the feature never bypasses Fleet policy/entitlement, organizational
approval, the fresh local Desk approval, Core admission, Broker validation or
Vault backup reservation.

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

## Windows x86-64 service (off by default)

Build the separate Windows executable explicitly:

```sh
cargo build --release --target x86_64-pc-windows-gnu \
  -p kernaid-fleet-resident-work-orders --features windows-service \
  --bin kernaid-fleet-resident-windows
```

It exposes native `install`, `start`, `stop` and `uninstall` service-control
commands and installs with SCM start type `OnDemand`; installation never
starts or auto-enables it. The service account is `LocalService`, with no
password embedded in the binary, configuration or SCM arguments. Deployment
files and the exact acceptance boundary are in
`deploy/fleet-resident-windows/`.

The only Windows action is `windows.p0.diagnose.v1@1` (diagnosis, R0). Its
eleven collectors, programs, arguments, PowerShell bodies and time limits are
compile-time constants shared with Desk through `kernaid-windows-pack`.
Neither a work order nor configuration can select a command, argument, script,
collector or target path. Raw collector output stays in memory; the durable
execution state and signed Fleet result contain only a SHA-256 digest. A
completed execution is replayed without recollection after restart, while an
uncertain mismatched pending record fails closed.

## macOS Intel and Apple silicon service (off by default)

Build the separate native executable explicitly:

```sh
cargo build --release --target aarch64-apple-darwin \
  -p kernaid-fleet-resident-work-orders --features macos-service \
  --bin kernaid-fleet-resident-macos
```

The only macOS action is `macos.p0.diagnose.v1@1` (diagnosis, R0). Desk and
Fleet Resident share the same eight fixed native command/normalization
contracts from `kernaid-macos-pack`. Network input cannot select or alter a
program, argument, environment, timeout, collector, path or output limit. Raw
native output stays in memory; durable replay stores only exact execution
bindings and the terminal digest.

The per-user launchd template, strict public configuration and install/disable
instructions are under `deploy/fleet-resident-macos/`. Installation never
loads or enables the LaunchAgent. CI builds separate Intel and Apple-silicon
development bundles named `UNSIGNED-UNNOTARIZED`; Developer ID signing,
notarization and physical qualification remain release gates.
