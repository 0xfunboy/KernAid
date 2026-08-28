# KernAid project site

This directory is the canonical, dependency-free source for the KernAid public
project site and its private engineering-artifact area. It is deliberately
small: one Node.js HTTP server, server-rendered HTML, CSS, the existing KernAid
SVG mark, and one reviewed metadata file.

The audience split, claim boundaries and independent Retail/Enterprise visual
systems are defined in [`DESIGN_ARCHITECTURE.md`](DESIGN_ARCHITECTURE.md).

The site does not promote artifacts. A file remains an internal candidate until
the repository trust catalog and the applicable qualification gates explicitly
authorize it.

## Routes

| Route | Access | Purpose |
| --- | --- | --- |
| `/`, `/retail.css`, `/mark.svg` | Public | Simple consumer product journey and planned single-use offer |
| `/enterprise/`, `/enterprise.css` | Public | Enterprise platform, governance and Design Partner model |
| `/styles.css` | Public asset | Isolated styling for login and authenticated distribution |
| `/healthz` | Public | Minimal process health response |
| `/private/login` | Public | Form login, without browser Basic Auth |
| `/private/` | Authenticated | Candidate provenance, retail-first downloads, qualification and checksums |
| `/private/downloads/retail` | Authenticated | Range-capable compressed Windows/Rufus image download |
| `/private/downloads/retail-checksum` | Authenticated | SHA-256 sidecar generated for the retail image |
| `/private/downloads/iso` | Authenticated | Range-capable ISO download |
| `/private/downloads/checksum` | Authenticated | SHA-256 sidecar generated for the ISO |
| `/private/downloads/repair-candidate` | Authenticated | Range-capable, separately gated experimental repair-candidate ISO |
| `/private/downloads/repair-candidate-checksum` | Authenticated | SHA-256 sidecar generated for the repair candidate |
| `/private/logout` | Authenticated | Session revocation |

Successful login creates a random, in-memory session with a 12-hour lifetime.
The cookie is scoped to `/private` and carries `Secure`, `HttpOnly` and
`SameSite=Strict`. Restarting the process invalidates all sessions. Repeated
failed logins from one client are temporarily throttled.

## Configuration

The server requires Node.js 24 or newer and has no package dependencies.

| Variable | Required | Default |
| --- | --- | --- |
| `KAID_HOST` | No | `127.0.0.1` |
| `KAID_PORT` | No | `3210` |
| `KAID_USERNAME` | No | `funboy` |
| `KAID_AUTH_FILE` | No | `~/.config/kaid-site/password` |
| `KAID_RETAIL_PATH` | Yes for the primary Windows/Rufus download | No default |
| `KAID_RETAIL_SHA256_PATH` | No | `${KAID_RETAIL_PATH}.sha256` |
| `KAID_ISO_PATH` | Yes for downloads | No default |
| `KAID_ISO_SHA256_PATH` | No | `${KAID_ISO_PATH}.sha256` |
| `KAID_REPAIR_CANDIDATE_PATH` | No; required only to expose the repair candidate | No default |
| `KAID_REPAIR_CANDIDATE_SHA256_PATH` | No | `${KAID_REPAIR_CANDIDATE_PATH}.sha256` |

The authentication file must contain one non-empty password. Keep it and any
Cloudflare tunnel credentials outside the repository with owner-only
permissions. The server reads the password once at startup and never logs it.

No artifact is loaded into memory. At process start the server opens the retail
image, stable ISO and separately configured repair-candidate ISO without
following a final symlink, verifies owner-only permissions, hashes every byte
against its configured sidecar and keeps those exact file descriptors pinned
for downloads. A missing path or mismatch leaves only that artifact unavailable.
Operators and users must still verify each downloaded file using its sidecar.

Keep the private artifact directory owner-only (`0700`) and the ISO, checksum
and metadata files owner-readable only (`0600`). Web authentication is not a
substitute for local filesystem permissions.

## Content and artifact updates

`content.json` contains only reviewed, non-secret release metadata. When the
candidate changes, update together:

1. source commit and CI artifact version;
2. workflow URL;
3. both download and checksum presentation names;
4. qualification statement and warning;
5. configured retail image and ISO with their matching checksum sidecars;
6. repair-candidate metadata and files separately, without changing the stable
   release paths or promoting the candidate.

`content.json` and all verified artifact snapshots are loaded once at process
start, so restart the site process after changing release metadata or a
configured artifact path.

Do not soften the warning based only on the existence of a workflow artifact.
The exact candidate named in `content.json` must have passed hybrid ISO build,
ordinary BIOS/UEFI smoke, zero-state first boot, USB-style two-boot and both
privileged persistent-vault lifecycle jobs on the same bytes. Its release
manifest and attestations must then be independently verified before the
retail image and ISO are staged together. It remains an internal engineering
candidate: private availability is limited to controlled physical qualification
on factory-new or disposable USB and non-customer hardware until physical USB,
Secure Boot and real-account/TLS gates are recorded.

Each download remains independently fail-closed with `503` until its exact file,
matching sidecar and environment path are all present. This allows the stable
ISO and retail image to remain available when the repair candidate is absent,
without weakening any artifact boundary. Candidate availability never changes
its explicit non-qualified, non-promoted status.

## Local validation

Syntax check:

```bash
node --check site/server.mjs
```

Start a local instance with the operator-owned files already provisioned:

```bash
KAID_PORT=3211 \
KAID_AUTH_FILE=/path/to/password \
KAID_RETAIL_PATH=/path/to/KernAid-Rescue-amd64-retail.img.xz \
KAID_ISO_PATH=/path/to/KernAid-Rescue-amd64.iso \
KAID_REPAIR_CANDIDATE_PATH=/path/to/KernAid-Rescue-amd64-repair-candidate.iso \
node site/server.mjs
```

Expected HTTP behavior:

```text
GET  /                                  200
GET  /private/ without a session        303 -> /private/login
POST /private/login with valid data      303 + Secure session cookie
GET  /private/ with the session          200
GET  /private/downloads/retail Range 0-0 206, one byte
GET  /private/downloads/iso Range 0-0    206, one byte
GET  /private/downloads/repair-candidate Range 0-0
                                              206, one byte when configured; 503 otherwise
POST /private/logout                     303 + expired session cookie
```

Use the public HTTPS origin for browser login because the session cookie is
intentionally `Secure`. Loopback HTTP is suitable for header-level smoke tests.

## Operations boundary

This directory contains no password, tunnel token, systemd unit or deployment
script. The existing user services and Cloudflare named tunnel are operational
configuration and must remain outside Git. Point or copy the deployed site to
this canonical source only through the reviewed operator workflow, then check
the public home, private redirect, authenticated range response, process health
and tunnel health.
