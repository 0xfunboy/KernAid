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
- The entitlement issuer's raw Ed25519 public key is mounted as a read-only
  config. Its offline private key/seed never enters this host or database.
- The vendor update issuer's raw Ed25519 public key is mounted separately as a
  read-only config. The update private key and artifacts never enter Fleet.
- Port 7341 is published only on host loopback. The Docker network is internal.
- `/console/` and the API share an origin, so no permissive CORS policy is
  needed.

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

export KERNAID_FLEET_ROOT_TOKEN_FILE=/absolute/private/fleet-secrets/root-token
export KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/entitlement.public
export KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/update-vendor.public
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

The console is available at `http://127.0.0.1:7341/console/`. The root token is
used only by a local operator request to create a tenant; the console takes the
returned tenant ID and one-time admin token, never the root token.

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

Create a consistent backup while the service is running. Both the source and
the existing parent directory must be canonical, non-symlink paths; database
files must be owner-only. The destination must not exist:

```bash
node deploy/fleet/database-lifecycle.mjs backup \
  /absolute/state/fleet.sqlite /absolute/backups/fleet-2026-08-31.sqlite
node deploy/fleet/database-lifecycle.mjs verify \
  /absolute/backups/fleet-2026-08-31.sqlite
```

For a recovery drill, restore into a new file, never over the active database:

```bash
node deploy/fleet/database-lifecycle.mjs restore \
  /absolute/backups/fleet-2026-08-31.sqlite \
  /absolute/recovery/fleet-restored.sqlite
```

Stop Fleet, point `KERNAID_FLEET_DB_PATH` at the verified restored file, start
Fleet and require `/healthz`, tenant authentication and inventory visibility.
Keep the previous database untouched until that validation succeeds. The root
token is intentionally outside SQLite and must be backed up through the
deployment secret store, not copied into a database archive.

For a single-node deployment, `scheduled-backup.mjs` wraps the same verified
online-backup boundary and retains only exact owner-only backup files. It
creates and verifies the new backup before rotating an exact bounded set; a
failed backup never removes an older copy:

```bash
node deploy/fleet/scheduled-backup.mjs \
  /absolute/state/fleet.sqlite /absolute/private/backups 14
```

The example units in `deploy/fleet/systemd/` run that command daily with a
persistent timer. Adapt only the absolute installation/state paths, keep the
database read-only to the backup service and make its dedicated backup
directory mode `0700`.

## Targeted verification

```bash
node deploy/fleet/verify-deployment.mjs
node deploy/fleet/database-lifecycle.mjs verify /absolute/state/fleet.sqlite
pnpm --filter @kernaid/fleet-control-plane build
pnpm --filter @kernaid/fleet-console check
KERNAID_FLEET_ROOT_TOKEN_FILE=/absolute/private/fleet-secrets/root-token \
KERNAID_FLEET_ENTITLEMENT_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/entitlement.public \
KERNAID_FLEET_UPDATE_TRUST_ANCHOR_FILE=/absolute/private/fleet-secrets/update-vendor.public \
  docker compose -f deploy/fleet/compose.yaml config --quiet
docker build --file deploy/fleet/Dockerfile --tag kernaid/fleet-control-plane:local .
```

`verify-deployment.mjs` checks the pin, non-root runtime, loopback bind,
read-only filesystem, secret path, internal network, volume and console mount.
The last two commands require Docker and must run on the build/deployment host.
