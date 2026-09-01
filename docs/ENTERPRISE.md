# KernAid Enterprise engineering guide

Last updated: 1 September 2026

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

| Path                                | Responsibility                                                                                     | Current boundary                                                                                 |
| ----------------------------------- | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `crates/fleet-client`               | Canonical Ed25519 enrollment, inventory and signed work-order claim/result envelopes               | Offline/transport-neutral; reuses the existing protected device identity                         |
| `crates/fleet-runtime`              | Durable SQLite outbox, inventory sequencing and verified entitlement state                         | External vendor anchor; paid features fail closed while diagnosis/export/rollback stay available |
| `packages/fleet-schemas`            | Matching Node.js wire validation and canonical signing bytes                                       | Strict bounded v1 schemas                                                                        |
| `services/fleet-control-plane`      | Tenant registry, signed device traffic, governance, work orders, incidents and commercial licensing | Live loopback origin at schema v12 behind the internal TLS tunnel                                |
| `apps/fleet-console`                | Same-origin inventory, governance, work-order, incident and license UI                               | Short-lived server-memory session, Secure cookie and CSRF; no persistent browser bearer token    |
| `crates/fleet-policy`               | Offline policy issuer and signed, offline-capable restrictive bundle                               | Server receives no seed; policy can only narrow local permission                                 |
| `crates/fleet-audit`                | Canonical signed audit events and tamper-evident chain checkpoints                                 | Digest-only device protocol with central signature, sequence and chain verification              |
| `crates/entitlements`               | Signed offline entitlements and revocation checkpoints                                             | Paid capabilities degrade without disabling diagnostics, report export or rollback               |
| `crates/update-client`              | Signed A/B release admission, offline issuer and boot-state planner                                | External trust anchor, monotonic manifests, ring/rollout/time gates and failed-boot rollback     |
| `crates/fleet-resident-update`      | HTTPS update staging plus local UEFI/systemd-boot A/B activation                                   | Off-default; inactive-slot only, one-shot boot, fallback/offline rollback; never reboots          |
| `tools/fleet-onboarding`            | Guided tenant creation and short-lived one-device provisioning bundle                              | Off-default CLI; owner-only files, no token output, shell, signing, or remote-command capability |
| `crates/fleet-resident-work-orders` | Durable allowlisted device-side work-order client                                                  | Off-default; Fleet intent never replaces fresh local Core/broker approval                        |
| `deploy/fleet-resident-linux`       | Disabled-by-default amd64 Debian package for sync, work orders, staging and A/B activation          | Does not enroll, enable services, alter boot state or reboot during installation                 |
| `deploy/fleet-resident-windows`     | On-demand Windows `LocalService` deployment for `windows.p0.diagnose.v1@1`                          | R0/digest-only; CI ZIP is explicitly unsigned and needs Authenticode/native qualification        |
| `deploy/fleet-resident-macos`       | Off-default LaunchAgent deployment for `macos.p0.diagnose.v1@1` on Intel and Apple silicon          | R0/digest-only; CI bundles are explicitly unsigned/unnotarized and need native qualification     |
| `deploy/fleet`                      | Signed online SQLite backup, offline verification/restore and persistent schedule                   | WAL-safe standalone three-file bundle signed by the provisioned service-receipt key              |

The control plane binds every enrolled `KA-…` device ID to the raw Ed25519
public key encoded in its canonical SPKI. Enrollment tokens are random,
hash-only, expiring and consumed atomically with device creation. Inventory is
verified against the enrolled key; per-device sequence replay, cross-tenant
access and revoked devices fail closed. The database persists multiple assets
and contains no enrollment or administrator token in plaintext.

## Current API

| Method and route                                      | Authentication                                      | Purpose                                                     |
| ----------------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------------- |
| `GET /healthz`                                        | None; expose only through operational health policy | Process/database health                                     |
| `POST /v1/tenants`                                    | Fleet root bearer token                             | Create a tenant and return its one-time-visible admin token |
| `POST /v1/admin/enterprise-licenses/import`            | Fleet root bearer token                             | Verify and import one offline-signed tenant license       |
| `GET /v1/admin/enterprise-licenses/:tenantId`          | Fleet root bearer token                             | Inspect commercial status, seats and digest-only audit    |
| `POST /v1/admin/enterprise-licenses/revoke`            | Fleet root bearer token                             | Revoke the exact current commercial license               |
| `POST /v1/tenants/:tenantId/enrollment-tokens`        | Tenant admin bearer token                           | Create one expiring device enrollment token                 |
| `POST /v1/enrollments`                                | Signed request plus one-time token                  | Bind the device identity to the tenant                      |
| `POST /v1/inventories`                                | Enrolled-device Ed25519 signature                   | Submit one privacy-minimized asset envelope                 |
| `POST /v1/audit-events`                               | Enrolled-device Ed25519 signature                   | Append one canonical digest-only chained event              |
| `POST /v1/policy-pulls`                               | Enrolled-device Ed25519 signature                   | Return only signed policy bundles applicable to that device |
| `POST /v1/tenants/:tenantId/policy-trust-anchor`      | Tenant admin bearer token                           | Set the tenant policy public key exactly once               |
| `POST /v1/tenants/:tenantId/policies`                 | Tenant admin bearer token                           | Verify and publish an already-signed canonical policy       |
| `POST /v1/entitlement-pulls`                          | Enrolled-device Ed25519 signature                   | Return applicable vendor-signed entitlement state           |
| `POST /v1/update-pulls`                               | Enrolled-device Ed25519 signature                   | Return only applicable vendor-signed update manifests       |
| `POST /v1/work-order-claims`                          | Enrolled-device Ed25519 signature                   | Lease one eligible typed order                              |
| `POST /v1/work-order-results`                         | Enrolled-device Ed25519 signature                   | Commit one digest-only terminal result                      |
| `POST /v1/tenants/:tenantId/entitlements`             | Tenant admin bearer token                           | Verify and publish an offline vendor-signed entitlement     |
| `POST /v1/tenants/:tenantId/entitlement-revocations`  | Tenant admin bearer token                           | Verify and publish the monotonic signed revocation list     |
| `POST /v1/tenants/:tenantId/update-manifests`         | Tenant admin bearer token                           | Verify and publish an offline vendor-signed update           |
| `GET /v1/tenants/:tenantId/enterprise-license`        | Tenant operator or admin                            | Minimized license status and seat usage                      |
| `GET /v1/tenants/:tenantId/devices`                   | Tenant admin bearer token                           | List tenant devices                                         |
| `GET /v1/tenants/:tenantId/assets`                    | Tenant admin bearer token                           | List current tenant assets                                  |
| `GET /v1/tenants/:tenantId/audit-events`              | Tenant admin bearer token                           | List bounded minimized audit events                         |
| `GET /v1/tenants/:tenantId/work-orders`               | Tenant operator or admin                            | List bounded tenant work-order state                        |
| `POST /v1/tenants/:tenantId/work-orders`              | Tenant operator or admin                            | Queue one closed-catalog typed action                       |
| `POST /v1/tenants/:tenantId/work-orders/:id/approve`  | Tenant admin                                        | Approve one organizational write intent                     |
| `POST /v1/tenants/:tenantId/work-orders/:id/cancel`   | Tenant operator or admin                            | Cancel an unleased order                                    |
| `GET /v1/tenants/:tenantId/work-order-events`         | Tenant operator or admin                            | List digest-only state transitions                          |
| `GET /v1/tenants/:tenantId/incident-cases`            | Tenant operator or admin                            | List tenant-isolated operational cases                      |
| `POST /v1/tenants/:tenantId/incident-cases`           | Tenant operator or admin                            | Open a case from one enrolled device or asset               |
| `POST /v1/tenants/:tenantId/incident-cases/:id/update` | Tenant operator or admin                            | Change bounded status, severity or assignee                  |
| `POST /v1/tenants/:tenantId/incident-cases/:id/work-orders` | Tenant operator or admin                       | Link a typed work order and its digest-only state            |
| `POST /v1/tenants/:tenantId/incident-cases/:id/close` | Tenant admin                                        | Seal a canonical closure report and signed service receipt  |
| `GET /v1/tenants/:tenantId/incident-case-events`      | Tenant operator or admin                            | List the minimized incident timeline                        |
| `POST /v1/tenants/:tenantId/devices/:deviceId/revoke` | Tenant admin bearer token                           | Revoke future device submissions                            |
| `GET /console/`                                       | Same origin                                         | Serve the static operator console when configured           |

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

For tenant and first-device provisioning, use the off-default
[Fleet onboarding wizard](../tools/fleet-onboarding/README.md). It checks
`/healthz`, creates the tenant, stores its non-recoverable admin credential in
a separate owner-only file, and emits a distinct short-lived single-use device
bundle without printing any token value.

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

The internal control plane is running at `https://fleet.funboy.eu.cc/` through
a loopback-only persistent user service. The live database is schema v12 and
has one active, non-revoked offline-signed Enterprise license for the internal
tenant. Fleet receives only public entitlement, update and commercial trust
anchors; all issuer private keys remain outside its filesystem view.

The live service also has a persistent scheduled backup. Each online SQLite
copy is forced into standalone journal mode, checked for integrity/foreign-key
violations, bound into a canonical manifest and signed with the existing
service-receipt Ed25519 key. The latest schema-v12 bundle was independently
verified offline on 1 September 2026. Root and tenant credentials remain
owner-only and outside source control.

The remaining RC work is:

1. run and review the exact Linux `.deb` and unsigned Windows deployment-bundle
   workflows, then qualify installation, service identity and work-order
   lifecycle on their declared systems;
2. qualify the Linux UEFI/systemd-boot A/B activator on a disposable two-slot
   system and bind it to one exact signed release; BIOS/GRUB remains unsupported;
3. qualify the local Rescue Fleet `fstab` adapter end to end. Fleet may deliver
   intent, but Desk must still collect a fresh target/evidence-bound approval
   before Core/Broker/Vault can mutate anything;
4. qualify the existing native Intel/Apple-silicon macOS Resident bundles and
   complete publisher signing, notarization/Authenticode, production
   Access/rate-limit policy and physical endpoint evidence;
5. qualify each actual repair pack on disposable virtual and physical targets.

Fleet enrollment or a green dashboard is not proof that a repair action is
safe. Each action remains independently off-default until its exact executor,
rollback and qualification evidence are complete.
