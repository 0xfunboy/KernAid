# KernAid Enterprise engineering guide

Last updated: 31 August 2026

This page is the short map of the Enterprise product surface. It distinguishes
implemented code from deployment and qualification work. The long-term product
definition remains in [MASTERPLAN.md](MASTERPLAN.md); exact release evidence
remains in [CURRENT_STATUS.md](CURRENT_STATUS.md).

## Product boundary

KernAid Enterprise adds centralized inventory, restrictive policy, licensing
and audit to the same local safety model used by Desk and Rescue. Fleet is not
a remote shell and it cannot create repair authority. A device still requires
typed evidence, the local policy floor, the applicable approval, backup,
verification and rollback for every mutation.

```text
Device identity ──signed enrollment──> Fleet registry
       │
       ├──signed minimal inventory────> Asset view
       ├<─centrally signed policy────── Tenant restrictions
       └──local Core/Broker────────────> Typed action only
```

Fleet intentionally receives normalized identifiers, health state, finding
counts and digests. Raw diagnostics, provider credentials, device seeds,
recovery keys and unrestricted command output are outside its v1 inventory
schema.

## Implemented components

| Path | Responsibility | Current boundary |
| --- | --- | --- |
| `crates/fleet-client` | Canonical Ed25519 enrollment and per-asset inventory envelopes | Offline/transport-neutral; reuses the existing protected device identity |
| `crates/fleet-runtime` | Durable SQLite outbox and monotonic inventory sequencing | Local protected state; no transport credential storage |
| `packages/fleet-schemas` | Matching Node.js wire validation and canonical signing bytes | Strict bounded v1 schemas |
| `services/fleet-control-plane` | Tenant registry, one-time enrollment, signed inventory ingestion, revocation and asset/device APIs | Loopback HTTP origin intended for a TLS reverse proxy or Cloudflare Tunnel |
| `apps/fleet-console` | Same-origin operator inventory and enrollment UI | Internal engineering console; tenant admin token remains in browser session storage only |
| `crates/fleet-policy` | Centrally signed, offline-capable restrictive policy bundle | Can only narrow local permission; diagnostics and an already-started rollback remain available |
| `crates/fleet-audit` | Canonical signed audit events and tamper-evident chain checkpoints | Digest-only offline/device protocol; central ingestion is still an RC gate |
| `crates/entitlements` | Signed offline entitlements and revocation checkpoints | Paid capabilities degrade without disabling diagnostics, report export or rollback |

The control plane binds every enrolled `KA-…` device ID to the raw Ed25519
public key encoded in its canonical SPKI. Enrollment tokens are random,
hash-only, expiring and consumed atomically with device creation. Inventory is
verified against the enrolled key; per-device sequence replay, cross-tenant
access and revoked devices fail closed. The database persists multiple assets
and contains no enrollment or administrator token in plaintext.

## Current API

| Method and route | Authentication | Purpose |
| --- | --- | --- |
| `GET /healthz` | None; expose only through operational health policy | Process/database health |
| `POST /v1/tenants` | Fleet root bearer token | Create a tenant and return its one-time-visible admin token |
| `POST /v1/tenants/:tenantId/enrollment-tokens` | Tenant admin bearer token | Create one expiring device enrollment token |
| `POST /v1/enrollments` | Signed request plus one-time token | Bind the device identity to the tenant |
| `POST /v1/inventories` | Enrolled-device Ed25519 signature | Submit one privacy-minimized asset envelope |
| `GET /v1/tenants/:tenantId/devices` | Tenant admin bearer token | List tenant devices |
| `GET /v1/tenants/:tenantId/assets` | Tenant admin bearer token | List current tenant assets |
| `POST /v1/tenants/:tenantId/devices/:deviceId/revoke` | Tenant admin bearer token | Revoke future device submissions |
| `GET /console/` | Same origin | Serve the static operator console when configured |

The service accepts no arbitrary command, script, filesystem path or broker
request. Adding one would violate the Enterprise trust boundary.

## Local engineering run

Use the repository-pinned Node.js `24.18.0`:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @kernaid/fleet-control-plane build
```

Create a random root token outside the repository and make it owner-readable
only. Point the service at that file and a protected state directory:

```bash
install -d -m 700 "$HOME/.local/state/kernaid-fleet"
openssl rand -hex 32 > "$HOME/.local/state/kernaid-fleet/root-token"
chmod 600 "$HOME/.local/state/kernaid-fleet/root-token"

KERNAID_FLEET_ROOT_TOKEN_FILE="$HOME/.local/state/kernaid-fleet/root-token" \
KERNAID_FLEET_DB_PATH="$HOME/.local/state/kernaid-fleet/fleet.sqlite3" \
FLEET_CONSOLE_DIR="$PWD/apps/fleet-console" \
corepack pnpm --filter @kernaid/fleet-control-plane start
```

The default listener is `127.0.0.1:7341`. Keep it on loopback and terminate
public TLS at the reviewed reverse proxy/tunnel. Do not put root or tenant
tokens in source, images, command history, URLs or browser persistent storage.

## Policy and entitlement invariants

- Fleet policy is signed by an external tenant trust anchor and contains no
  embedded public key.
- A greater signed revision advances the checkpoint; an exact replay is
  idempotent; rollback or same-revision substitution is rejected.
- Fleet intersects with the local safety floor. It cannot allow an unknown
  action, raise the local risk ceiling or remove a required local approval.
- Expired/offline policy blocks new repairs but not local diagnostics or an
  already-started rollback that is needed to restore safety.
- Entitlement expiry or revocation disables paid Fleet/update/repair access as
  configured, while diagnostics, report export and rollback remain available.

## Remaining Enterprise RC gates

The following are not yet complete merely because the schemas and registry
exist:

1. wire the device runtime into Desk and Rescue lifecycle services;
2. add authenticated signed policy distribution and persistent device policy
   checkpoints;
3. ingest and report the signed, chained audit stream without raw evidence;
4. connect entitlement verification to product feature gates and issuance;
5. stage signed A/B updates with canary rings, revocation and automatic
   rollback;
6. deploy the private control plane and console behind the existing protected
   origin, then qualify backup/restore and tenant recovery;
7. qualify the actual repair packs on disposable virtual and physical targets.

Fleet enrollment or a green dashboard is not proof that a repair action is
safe. Each action remains independently off-default until its exact executor,
rollback and qualification evidence are complete.
