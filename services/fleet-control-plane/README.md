# KernAid Fleet control plane v1

The Fleet control plane enrolls KernAid devices and retains their signed,
privacy-bounded inventory summaries. It is a Node.js 24.18.0 HTTP service with
SQLite persistence and no external runtime dependency beyond the local
`@kernaid/fleet-schemas` workspace package.

It deliberately has no remote command, shell, repair execution, raw diagnostic
upload or arbitrary metadata API.

## Trust boundaries

- A root bearer token creates a tenant. It is read from a private file and is
  never stored in SQLite.
- Tenant creation returns its admin token once. Only the domain-separated
  SHA-256 token hash is persisted.
- Tenant access credentials are hash-only, tenant-bound and carry exactly one
  role: `admin` or `operator`. Admins manage credentials and signed governance
  inputs; operators manage enrollment, visibility and device revocation.
- Every request made with an identified tenant credential records a bounded,
  durable authorization decision containing only credential ID, role, action,
  target and outcome. Cross-tenant attempts and revoked/underprivileged
  credentials fail closed without storing tokens, IP addresses or headers.
- A tenant operator creates short-lived, single-use enrollment tokens. Only
  their hashes are persisted.
- Enrollment verifies expiry, tenant binding, clock window, canonical Ed25519
  SPKI, key-derived device ID and the domain-separated signature before one
  transaction inserts the device and consumes the token.
- Every inventory envelope is verified against the enrolled tenant/device key.
  A revoked device is rejected before replay processing.
- Every audit event is verified with the enrolled device key using the nested
  Rust `DeviceIdentity::sign_report` framing. Revoked and cross-tenant devices
  fail closed.
- Audit sequence and previous-event digest are contiguous per device/session.
  Exact retries are idempotent; gaps, forks and superseded replays are rejected
  transactionally and the chain tail survives restart.
- Sequence is monotonic per device. Retrying the current byte-identical signed
  envelope is idempotent; another envelope at that sequence or an older
  sequence is rejected.
- Tenant admin lookup, device listing, asset listing and revocation are scoped
  by both the URL tenant ID and that tenant's token hash.
- A tenant admin may set exactly one Ed25519 policy trust anchor. Only its
  public SPKI is stored; the control plane has no signing endpoint and never
  receives a seed or private key.
- Policy publication accepts only canonical bundles already signed by that
  anchor. Revision is monotonic per policy ID; exact replay is idempotent and
  rollback or same-revision substitution is rejected transactionally.
- Policy pulls are signed by the enrolled device key, time-bounded, and
  nonce-replay protected with a short-lived hash. Revoked and cross-tenant
  identities fail before lookup, and SQLite returns only matching assignments.
- Entitlement and revocation publication accepts only byte-canonical documents
  already signed by the offline issuer. Its raw Ed25519 public key is loaded
  from a file outside SQLite; this service has no issuer private key, seed or
  signing endpoint. Checkpoints are monotonic and exact replay is idempotent.
- Entitlement pulls are signed by the enrolled device key, time-bounded and
  nonce-replay protected. The response contains only documents assigning that
  exact device plus its tenant-scoped signed revocation checkpoint.
- Update publication accepts only canonical manifests already signed by the
  externally provisioned vendor anchor. The per-tenant sequence checkpoint is
  monotonic; exact replay is idempotent and substitution fails closed. No
  private vendor key or signing endpoint exists here.
- Update pulls are signed and nonce-protected device requests. Results are
  filtered by platform, architecture, ring, time and deterministic rollout;
  every returned manifest remains independently verifiable on the device.
- Successful inventory, audit, policy-pull and entitlement-pull responses carry
  `X-KernAid-Fleet-Receipt`: canonical receipt JSON encoded as unpadded
  base64url and signed by an externally provisioned Ed25519 service key. The
  receipt binds tenant, device, operation, the exact request/response SHA-256
  digests and a durable per-device sequence. Exact retries return the retained
  response and receipt; revoked, cross-tenant or tampered requests never do.
- The service receipt private key is loaded from an owner-only PKCS#8 DER file.
  Its matching raw public anchor is loaded separately, verified at startup and
  pinned in SQLite by digest. Key mismatch or unplanned rotation fails closed.

## API

All POST bodies use `Content-Type: application/json`, reject unknown fields,
and are limited to 64 KiB, except canonical policy publication at 1 MiB.
Entitlement and revocation publication must be exact compact canonical JSON
and is bounded to 64 KiB, matching the Rust verifier.

| Method | Route                                                           | Authorization          | Result                                       |
| ------ | --------------------------------------------------------------- | ---------------------- | -------------------------------------------- |
| `GET`  | `/healthz`                                                      | Public                 | SQLite liveness                              |
| `POST` | `/v1/tenants`                                                   | Root bearer            | One-time `tenantId`, `adminToken`            |
| `GET`  | `/v1/tenants/:tenantId/access-credentials`                      | Admin                  | List credential metadata, never tokens       |
| `POST` | `/v1/tenants/:tenantId/access-credentials`                      | Admin                  | Create one-time-visible role token           |
| `POST` | `/v1/tenants/:tenantId/access-credentials/:credentialId/revoke` | Admin                  | Revoke one credential                        |
| `GET`  | `/v1/tenants/:tenantId/access-audit`                            | Admin                  | Last 256 authorization decisions             |
| `POST` | `/v1/tenants/:tenantId/enrollment-tokens`                       | Operator or admin      | One-time `enrollmentToken`, `expiresAt`      |
| `POST` | `/v1/enrollments`                                               | Signed public request  | Enroll a device                              |
| `POST` | `/v1/inventories`                                               | Signed device envelope | Insert or idempotently acknowledge inventory |
| `POST` | `/v1/audit-events`                                              | Signed device envelope | Append or idempotently acknowledge audit     |
| `POST` | `/v1/policy-pulls`                                              | Signed device request  | Return only applicable signed bundles        |
| `POST` | `/v1/entitlement-pulls`                                         | Signed device request  | Return assigned signed entitlements          |
| `POST` | `/v1/update-pulls`                                              | Signed device request  | Return applicable vendor-signed manifests    |
| `POST` | `/v1/tenants/:tenantId/policy-trust-anchor`                     | Admin                  | Set tenant Ed25519 public anchor once        |
| `POST` | `/v1/tenants/:tenantId/policies`                                | Admin                  | Verify and publish a pre-signed bundle       |
| `POST` | `/v1/tenants/:tenantId/entitlements`                            | Admin                  | Verify/publish offline-signed entitlement    |
| `POST` | `/v1/tenants/:tenantId/entitlement-revocations`                 | Admin                  | Publish signed revocation checkpoint         |
| `POST` | `/v1/tenants/:tenantId/update-manifests`                        | Admin                  | Verify/publish vendor-signed manifest        |
| `GET`  | `/v1/tenants/:tenantId/policies`                                | Operator or admin      | Minimized policy status                      |
| `GET`  | `/v1/tenants/:tenantId/entitlements`                            | Operator or admin      | Minimized entitlement/revocation status      |
| `GET`  | `/v1/tenants/:tenantId/update-manifests`                        | Operator or admin      | Minimized update-channel status              |
| `GET`  | `/v1/tenants/:tenantId/devices`                                 | Operator or admin      | `{ items: [...] }` device registry           |
| `GET`  | `/v1/tenants/:tenantId/assets`                                  | Operator or admin      | `{ items: [...] }` latest aggregate assets   |
| `GET`  | `/v1/tenants/:tenantId/audit-events`                            | Operator or admin      | Bounded `{ items: [...] }` digest-only audit |
| `POST` | `/v1/tenants/:tenantId/devices/:deviceId/revoke`                | Operator or admin      | Permanently revoke ingestion                 |

Tenant creation takes an exact empty object. Enrollment-token creation takes:

```json
{ "expiresInSeconds": 300 }
```

An admin creates a delegated credential with an exact body such as:

```json
{ "label": "Field operations", "role": "operator" }
```

The `accessToken` appears only in the creation response. Lists and audit events
contain its opaque credential ID, never the token or token hash. A credential
cannot revoke itself, and the final active admin cannot be removed.

The enrollment, inventory and audit bodies are the exact signed structures
described in
[`@kernaid/fleet-schemas`](../../packages/fleet-schemas/README.md). Inventory
accepts one signed envelope per asset so each asset retains independent signed
provenance. Audit POST bodies must be byte-identical canonical JSON. List
responses expose only protocol fields, aggregate counts and audit digests;
they never expose public keys, token hashes, raw content or stored signatures.

Policy publication requires byte-exact canonical JSON and is bounded to the
same 1 MiB limit as the Rust policy crate. Pull responses contain
`{schema,tenantId,deviceId,items}`; every item remains independently signed and
must pass the device's durable `PolicyCheckpoint`. The server cannot turn a
policy into execution authority.

Entitlement pull responses contain
`{schema,tenantId,deviceId,entitlements,revocations}`. Each document remains
independently signed by the offline issuer and must be verified on-device with
`kernaid-entitlements` and its durable checkpoint. The server stores only
canonical document bytes and monotonic sequence/digest checkpoints; it cannot
mint or expand an entitlement.

Update pull responses contain
`{schema,tenantId,deviceId,platform,architecture,updateRing,items}`. The echoed
target and ring bind the response context, while each item must still pass the
device's vendor-signature verification, durable checkpoint, entitlement,
policy and inactive-target staging gates. Fleet never downloads artifacts or
activates a boot target.

The three tenant governance GET routes return only bounded operational
metadata needed by the console: IDs, revisions/sequences, assignment counts,
capability names, target/ring and validity windows. They omit signatures,
public keys, artifact descriptors and stored canonical document bytes.

## Run locally

Use exactly Node.js 24.18.0 and the repository-pinned pnpm 9.15.9.

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @kernaid/fleet-control-plane build

install -d -m 700 "$PWD/.local/fleet"
openssl rand -hex 32 > "$PWD/.local/fleet/root-token"
chmod 600 "$PWD/.local/fleet/root-token"

# Copy only the offline issuer's public-key file here (never its seed).
install -m 644 /secure-export/entitlement.public \
  "$PWD/.local/fleet/entitlement.public"
install -m 644 /secure-export/update-vendor.public \
  "$PWD/.local/fleet/update-vendor.public"

# Create a Fleet service receipt key outside the repository. Distribute only
# receipt.public to Resident devices as their receipt trust anchor.
openssl genpkey -algorithm Ed25519 -outform DER \
  -out "$PWD/.local/fleet/receipt-signing-key.pk8"
chmod 600 "$PWD/.local/fleet/receipt-signing-key.pk8"
node --input-type=module -e \
  'import{readFileSync,writeFileSync}from"node:fs";import{createPrivateKey,createPublicKey}from"node:crypto";const k=createPrivateKey({key:readFileSync(process.argv[1]),format:"der",type:"pkcs8"});const d=Buffer.from(createPublicKey(k).export({format:"der",type:"spki"}));writeFileSync(process.argv[2],d.subarray(-32).toString("base64url")+"\n")' \
  "$PWD/.local/fleet/receipt-signing-key.pk8" \
  "$PWD/.local/fleet/receipt.public"

export KERNAID_FLEET_ROOT_TOKEN_FILE="$PWD/.local/fleet/root-token"
export KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE="$PWD/.local/fleet/entitlement.public"
export KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE="$PWD/.local/fleet/update-vendor.public"
export KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE="$PWD/.local/fleet/receipt-signing-key.pk8"
export KERNAID_FLEET_SERVICE_RECEIPT_TRUST_ANCHOR_FILE="$PWD/.local/fleet/receipt.public"
export KERNAID_FLEET_DB_PATH="$PWD/.local/fleet/fleet.sqlite"
export KERNAID_FLEET_HOST="127.0.0.1"
export KERNAID_FLEET_PORT="7341"
node services/fleet-control-plane/dist/main.js
```

Optional settings:

- `KERNAID_FLEET_ENROLLMENT_CLOCK_SKEW_MS` defaults to `300000` and is bounded
  to 1 second through 1 hour.
- `FLEET_CONSOLE_DIR` mounts an existing static console directory at
  `/console/`. Files are resolved against the real directory, bounded to 10
  MiB and served with a restrictive CSP. Point it to `apps/fleet-console` when
  that workspace is installed.

The default listener is loopback-only. Put it behind an authenticated TLS
reverse proxy for any non-local deployment; do not expose plaintext HTTP or
the root token to a browser. The SQLite file is forced to mode `0600`, while
its state directory should remain `0700` because WAL files are created beside
it.

For the hardened single-node container and loopback-only Compose deployment,
see [`deploy/fleet`](../../deploy/fleet/README.md).

## Operator flow

For the guided, off-default path, use the
[Fleet onboarding wizard](../../tools/fleet-onboarding/README.md). It performs
health/preflight, reads secrets only from owner-only files, creates the tenant
and short-lived single-use device bundle, and retains the one-time-visible
admin credential separately without printing either token. The equivalent
manual protocol is:

1. Read the root token locally and call `POST /v1/tenants` with `{}`. Retain the
   returned admin token in the tenant secret store; it cannot be recovered.
2. Retain the bootstrap admin for governance. Create separate `operator`
   credentials for routine enrollment, inventory, audit and revocation work.
3. Open the console at `/console/`, enter the tenant ID and the appropriate
   tenant token, then create a short-lived enrollment token.
4. Give that token and tenant ID to exactly one KernAid client. The client owns
   its Ed25519 key and submits the signed enrollment request.
5. Use the console or list APIs to monitor signed asset summaries and revoke a
   lost or retired identity.
6. Generate the tenant policy key offline. Set its public SPKI once, sign each
   canonical policy outside this service, then publish the signed bundle. Keep
   the private key in the organization signing system.
7. Provision the vendor entitlement issuer's raw public key through
   `KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE`. A tenant admin may publish
   documents produced by that offline issuer, but cannot sign one here.
8. Provision the vendor update issuer's raw public key through
   `KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE`. Publish only canonical manifests
   signed offline; devices independently verify and admit them before staging.
9. Provision a dedicated Ed25519 receipt key pair. Keep its PKCS#8 private key
   readable only by Fleet and install the matching raw public anchor in each
   Resident. Back up the private key with the database: changing either side
   without an explicit migration makes synchronization fail closed.

## Verification

```bash
corepack pnpm --filter @kernaid/fleet-schemas test
corepack pnpm --filter @kernaid/fleet-control-plane test
corepack pnpm --filter @kernaid/fleet-control-plane check
corepack pnpm --filter @kernaid/fleet-control-plane lint
```

The focused API suite covers cross-tenant denial, token expiry/reuse, key-ID
binding, signature tampering, replay/idempotency, multi-asset retention,
revocation, audit gaps/forks, unknown/private field rejection, hash-only
secrets, policy assignment isolation, policy rollback/conflict, restart
persistence, entitlement assignment/replay/tamper/rollback/revocation, update
target/ring filtering, update anti-rollback/replay, exact signed service
receipts, receipt key/anchor mismatch, durable receipt sequence, SQLite
v3-to-v7 migration, tenant role enforcement, credential revocation,
cross-tenant denial, authorization audit/restart and optional same-origin
console serving.
