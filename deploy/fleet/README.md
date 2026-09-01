# KernAid Fleet minimal deployment

This directory runs the Fleet control plane and operator console on one origin.
It is intentionally a single-service, single-node deployment: Node.js 24.18.0,
SQLite, a private root-token file and no remote-command surface.

## Security profile

- Both image stages pin `node:24.18.0-bookworm-slim` and its multi-platform
  [official image digest](https://hub.docker.com/_/node/tags?name=24.18.0-bookworm-slim);
  pnpm is pinned to 9.15.9.
- The runtime process is UID/GID `1000`, drops all capabilities and enables
  `no-new-privileges`.
- The root filesystem is read-only. Only the named SQLite volume and a small
  `/tmp` tmpfs are writable.
- The root token is mounted as a Docker secret at
  `/run/secrets/kernaid_fleet_root_token`. Its value is never an environment
  variable, image layer, Compose value or console setting.
- The Fleet service receipt key is mounted as a second Docker secret. Its
  matching raw public anchor is a read-only config distributed to Resident
  devices; startup rejects a mismatch or an anchor change for an existing DB.
- The entitlement issuer's raw Ed25519 public key is mounted as a read-only
  config. Its offline private key/seed never enters this host or database.
- The vendor update issuer's raw Ed25519 public key is mounted separately as a
  read-only config. The update private key and artifacts never enter Fleet.
- Port 7341 is published only on host loopback. The Docker network is internal.
- `/console/` and the API share an origin, so no permissive CORS policy is
  needed.
- Console bearer credentials are exchanged once for a 15-minute session kept
  only in process memory. The browser cookie is Secure, HttpOnly, SameSite
  Strict and CSRF-bound; logout, expiry, credential revocation and restart
  invalidate it.
- Every production backup is a private three-file bundle containing the
  standalone SQLite image, a bounded canonical manifest and a detached
  Ed25519 signature made with the already provisioned service-receipt key. The
  signing key is read only from its owner-only PKCS#8 file; key material is
  never accepted through arguments, environment variables or standard input.

This is a production-like minimum, not a high-availability layout. The bundled
database lifecycle tool uses SQLite's online backup API, validates integrity,
foreign keys and the minimum Fleet schema, rejects symlinks and never
overwrites an existing destination.

## First start

Use Docker Engine with the Compose v2 plugin. Create the secret outside the
repository; do not paste it into `.env`, Compose or shell history.

```bash
install -d -m 700 /absolute/private/fleet-secrets
openssl rand -hex 32 > /absolute/private/fleet-secrets/root-token
chmod 400 /absolute/private/fleet-secrets/root-token
install -m 444 /secure-export/entitlement.public \
  /absolute/private/fleet-secrets/entitlement.public
install -m 444 /secure-export/update-vendor.public \
  /absolute/private/fleet-secrets/update-vendor.public
install -m 444 /secure-export/commercial.public \
  /absolute/private/fleet-secrets/commercial.public
openssl genpkey -algorithm Ed25519 -outform DER \
  -out /absolute/private/fleet-secrets/receipt-signing-key.pk8
chmod 400 /absolute/private/fleet-secrets/receipt-signing-key.pk8
node --input-type=module -e \
  'import{readFileSync,writeFileSync}from"node:fs";import{createPrivateKey,createPublicKey}from"node:crypto";const k=createPrivateKey({key:readFileSync(process.argv[1]),format:"der",type:"pkcs8"});const d=Buffer.from(createPublicKey(k).export({format:"der",type:"spki"}));writeFileSync(process.argv[2],d.subarray(-32).toString("base64url")+"\n")' \
  /absolute/private/fleet-secrets/receipt-signing-key.pk8 \
  /absolute/private/fleet-secrets/receipt.public
chmod 444 /absolute/private/fleet-secrets/receipt.public

export KERNAID_FLEET_ROOT_TOKEN_FILE=/absolute/private/fleet-secrets/root-token
export KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE=/absolute/private/fleet-secrets/receipt-signing-key.pk8
export KERNAID_FLEET_SERVICE_RECEIPT_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/receipt.public
export KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/entitlement.public
export KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/update-vendor.public
export KERNAID_FLEET_ENTERPRISE_LICENSE_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/commercial.public
export KERNAID_FLEET_ENTERPRISE_LICENSE_KEY_ID=vendor-2026-01
docker compose -f deploy/fleet/compose.yaml build --pull
docker compose -f deploy/fleet/compose.yaml up -d
docker compose -f deploy/fleet/compose.yaml ps
curl --fail --silent http://127.0.0.1:7341/healthz
```

The secret must be a regular, non-symlink file containing 32–512 unpadded
base64url characters. The Compose service requests UID/GID `1000` and mode
`0400`. Some non-Docker Compose implementations ignore secret ownership
metadata for file-backed secrets; in that case make the host file owned and
readable by UID 1000 rather than weakening its mode.

To use another loopback port, set `KERNAID_FLEET_BIND_PORT`. Do not change the
internal port because the image healthcheck intentionally probes 7341.

The loopback HTTP endpoint is suitable for health checks and the reverse-proxy
upstream. Open the console only through its HTTPS hostname: its Secure cookie
is intentionally unavailable at `http://127.0.0.1:7341/console/`. The root
token is used only by a local operator request to create a tenant; the console
takes the returned tenant ID and tenant admin/operator token once, never the
root token.

`KERNAID_FLEET_CONSOLE_SESSION_TTL_SECONDS` may override the 900-second default
within the enforced 60–3600 second range.

## Cloudflare Tunnel

Keep Compose bound to `127.0.0.1`; run `cloudflared` on the host and route one
hostname to the loopback service. The tunnel credentials are separate from the
KernAid root token.

```yaml
ingress:
  - hostname: fleet.example.com
    service: http://127.0.0.1:7341
  - service: http_status:404
```

Protect `/console/*` and tenant-admin routes under `/v1/tenants/*` with an
identity-aware access policy. Signed devices still need non-interactive HTTPS
access to enrollment, inventory, audit, policy-pull, entitlement-pull and update-pull
routes, so do not put an interactive login in front of them. Keep root tenant creation additionally
restricted to an operator path or local request. Apply rate limiting to public
device endpoints without logging Authorization headers or request bodies.

After changing tunnel ingress, validate the tunnel configuration before
restarting `cloudflared`. The final catch-all rule is required so unmatched
hostnames fail closed.

```bash
cloudflared tunnel ingress validate
cloudflared tunnel ingress rule https://fleet.example.com/console/
```

Cloudflare documents both the required catch-all and these validation commands
in its [locally managed tunnel configuration guide](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/).
For the admin split, create path-specific self-hosted Access applications as
described in the official [application paths guide](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/).

## Other reverse proxies

Terminate TLS at the proxy and forward to `http://127.0.0.1:7341`. Preserve the
original host, disable request-body and Authorization-header logging, and do
not rewrite `/console/` or `/v1/`. Apply authentication by path as described
above rather than exposing tenant administration anonymously.

The service does not trust forwarding headers for authorization, so proxy
identity is defense in depth; Fleet bearer and Ed25519 checks remain mandatory.
Never bind container port 7341 to `0.0.0.0` merely to reach a host-local proxy.

## Update and rollback

Build an immutable image from a reviewed commit, then record its digest before
deployment. Stop the old container cleanly so SQLite checkpoints its WAL. Take
a volume snapshot, deploy the new digest, and require `/healthz` plus console
loading before removing the previous image. Rollback uses the previous image
digest and the compatible volume snapshot.

## Backup and restore drill

Create a consistent signed bundle while the service is running. The bundle
directory contains exactly `fleet.sqlite`, `manifest.json` and `manifest.sig`.
The canonical manifest schema is
`dev.kernaid.fleet.database-backup-manifest.v1`; it binds the exact database
SHA-256 and byte count, SQLite `user_version`, complete sorted table inventory
and RFC 3339 creation time. Its Ed25519 input is:

Schema v11 adds commercial-license, retained-clock, seat and digest-only audit
tables without changing this backup format. Online backup, verify and restore
therefore cover the licensing state and preserve its exact schema version.

```text
kernaid:fleet:database-backup:v1\0 || canonical manifest JSON
```

All paths must be absolute, canonical and non-symlink. Database, private key,
bundle and restored files must be owner-only; bundle/recovery parent
directories must be mode `0700`. The public anchor may be world-readable but
must not be writable by group or other. New destinations must not exist.
Private key content is never a CLI argument: the final parameter below is only
the path to the existing owner-only service key file.

```bash
node deploy/fleet/database-lifecycle.mjs backup \
  /absolute/state/fleet.sqlite \
  /absolute/backups/fleet-20260831T120000.000Z-manual.backup \
  /absolute/private/fleet-secrets/receipt-signing-key.pk8
node deploy/fleet/database-lifecycle.mjs verify \
  /absolute/backups/fleet-20260831T120000.000Z-manual.backup \
  /absolute/private/fleet-secrets/receipt.public
```

`verify` is fully offline and requires both the manifest signature and public
trust anchor before hashing or accepting the database. For a recovery drill,
restore exact attested bytes into a new file, never over the active database:

```bash
node deploy/fleet/database-lifecycle.mjs restore \
  /absolute/backups/fleet-20260831T120000.000Z-manual.backup \
  /absolute/private/fleet-secrets/receipt.public \
  /absolute/recovery/fleet-restored.sqlite
```

`inspect <live-database>` remains available only for local SQLite health and
schema inspection. It is explicitly not a signed backup verification mode;
`verify` and `restore` never accept a bare legacy database.

Stop Fleet, point `KERNAID_FLEET_DB_PATH` at the verified restored file, start
Fleet and require `/healthz`, tenant authentication and inventory visibility.
Keep the previous database untouched until that validation succeeds. The root
token is intentionally outside SQLite and must be backed up through the
deployment secret store, not copied into a database archive.

For a single-node deployment, `scheduled-backup.mjs` creates the signed bundle,
then independently verifies it with the public anchor before considering
rotation. Every retained bundle is reverified first. Rotation renames an
obsolete directory out of the active namespace before deleting its three
members, so DB/manifest/signature are treated as one logical unit. A failed,
tampered or wrong-key new bundle is removed without deleting any previously
verified backup:

```bash
node deploy/fleet/scheduled-backup.mjs \
  /absolute/state/fleet.sqlite /absolute/private/backups 14 \
  /absolute/private/fleet-secrets/receipt-signing-key.pk8 \
  /absolute/private/fleet-secrets/receipt.public
```

The example units in `deploy/fleet/systemd/` run that command daily with a
persistent timer. Adapt only the absolute installation/state paths, keep the
database read-only to the backup service and make its dedicated backup
directory mode `0700`. Install the service key mode `0400` and public anchor
mode `0444` at the absolute paths shown in the unit, or adapt those paths
without moving key material into environment variables.

## Targeted verification

```bash
node deploy/fleet/verify-deployment.mjs
node --test deploy/fleet/backup-lifecycle.test.mjs
node deploy/fleet/database-lifecycle.mjs inspect /absolute/state/fleet.sqlite
pnpm --filter @kernaid/fleet-control-plane build
pnpm --filter @kernaid/fleet-console check
KERNAID_FLEET_ROOT_TOKEN_FILE=/absolute/private/fleet-secrets/root-token \
KERNAID_FLEET_SERVICE_RECEIPT_SIGNING_KEY_FILE=/absolute/private/fleet-secrets/receipt-signing-key.pk8 \
KERNAID_FLEET_SERVICE_RECEIPT_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/receipt.public \
KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/entitlement.public \
KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/update-vendor.public \
KERNAID_FLEET_ENTERPRISE_LICENSE_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/commercial.public \
KERNAID_FLEET_ENTERPRISE_LICENSE_KEY_ID=vendor-2026-01 \
  docker compose -f deploy/fleet/compose.yaml config --quiet
docker build --file deploy/fleet/Dockerfile --tag kernaid/fleet-control-plane:local .
```

`verify-deployment.mjs` checks the pin, non-root runtime, loopback bind,
read-only filesystem, root/receipt secret paths, receipt public anchor,
internal network, volume and console mount.
The last two commands require Docker and must run on the build/deployment host.
