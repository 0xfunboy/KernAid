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
- A tenant admin creates short-lived, single-use enrollment tokens. Only their
  hashes are persisted.
- Enrollment verifies expiry, tenant binding, clock window, canonical Ed25519
  SPKI, key-derived device ID and the domain-separated signature before one
  transaction inserts the device and consumes the token.
- Every inventory envelope is verified against the enrolled tenant/device key.
  A revoked device is rejected before replay processing.
- Sequence is monotonic per device. Retrying the current byte-identical signed
  envelope is idempotent; another envelope at that sequence or an older
  sequence is rejected.
- Tenant admin lookup, device listing, asset listing and revocation are scoped
  by both the URL tenant ID and that tenant's token hash.

## API

All POST bodies use `Content-Type: application/json`, reject unknown fields,
and are limited to 64 KiB.

| Method | Route                                            | Authorization          | Result                                       |
| ------ | ------------------------------------------------ | ---------------------- | -------------------------------------------- |
| `GET`  | `/healthz`                                       | Public                 | SQLite liveness                              |
| `POST` | `/v1/tenants`                                    | Root bearer            | One-time `tenantId`, `adminToken`            |
| `POST` | `/v1/tenants/:tenantId/enrollment-tokens`        | Tenant bearer          | One-time `enrollmentToken`, `expiresAt`      |
| `POST` | `/v1/enrollments`                                | Signed public request  | Enroll a device                              |
| `POST` | `/v1/inventories`                                | Signed device envelope | Insert or idempotently acknowledge inventory |
| `GET`  | `/v1/tenants/:tenantId/devices`                  | Tenant bearer          | `{ items: [...] }` device registry           |
| `GET`  | `/v1/tenants/:tenantId/assets`                   | Tenant bearer          | `{ items: [...] }` latest aggregate assets   |
| `POST` | `/v1/tenants/:tenantId/devices/:deviceId/revoke` | Tenant bearer          | Permanently revoke ingestion                 |

Tenant creation takes an exact empty object. Enrollment-token creation takes:

```json
{ "expiresInSeconds": 300 }
```

The enrollment and inventory bodies are the exact signed structures described
in [`@kernaid/fleet-schemas`](../../packages/fleet-schemas/README.md). Inventory
accepts one signed envelope per asset so each asset retains independent signed
provenance. List responses expose only protocol fields and aggregate counts;
they never expose public keys, token hashes or stored envelope signatures.

## Run locally

Use exactly Node.js 24.18.0 and the repository-pinned pnpm 9.15.9.

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm --filter @kernaid/fleet-control-plane build

install -d -m 700 "$PWD/.local/fleet"
openssl rand -hex 32 > "$PWD/.local/fleet/root-token"
chmod 600 "$PWD/.local/fleet/root-token"

export KERNAID_FLEET_ROOT_TOKEN_FILE="$PWD/.local/fleet/root-token"
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

## Operator flow

1. Read the root token locally and call `POST /v1/tenants` with `{}`. Retain the
   returned admin token in the tenant secret store; it cannot be recovered.
2. Open the console at `/console/`, enter the tenant ID and admin token, then
   create a short-lived enrollment token.
3. Give that token and tenant ID to exactly one KernAid client. The client owns
   its Ed25519 key and submits the signed enrollment request.
4. Use the console or list APIs to monitor signed asset summaries and revoke a
   lost or retired identity.

## Verification

```bash
corepack pnpm --filter @kernaid/fleet-schemas test
corepack pnpm --filter @kernaid/fleet-control-plane test
corepack pnpm --filter @kernaid/fleet-control-plane check
corepack pnpm --filter @kernaid/fleet-control-plane lint
```

The focused API suite covers cross-tenant denial, token expiry/reuse, key-ID
binding, signature tampering, replay/idempotency, multi-asset retention,
revocation, unknown/private field rejection, hash-only secrets, restart
persistence, health and optional same-origin console serving.
