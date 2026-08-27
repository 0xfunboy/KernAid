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
| `/private/` | Authenticated | Candidate provenance, qualification and checksum |
| `/private/downloads/iso` | Authenticated | Range-capable ISO download |
| `/private/downloads/checksum` | Authenticated | SHA-256 sidecar generated from the configured checksum |
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
| `KAID_ISO_PATH` | Yes for downloads | No default |
| `KAID_ISO_SHA256_PATH` | No | `${KAID_ISO_PATH}.sha256` |

The authentication file must contain one non-empty password. Keep it and any
Cloudflare tunnel credentials outside the repository with owner-only
permissions. The server reads the password once at startup and never logs it.

The ISO is not loaded into memory. At process start the server opens it without
following a final symlink, verifies owner-only permissions, hashes every byte
against the configured sidecar and keeps that exact file descriptor pinned for
downloads. A mismatch leaves the artifact unavailable. Operators and users
must still verify the downloaded file using the sidecar.

Keep the private artifact directory owner-only (`0700`) and the ISO, checksum
and metadata files owner-readable only (`0600`). Web authentication is not a
substitute for local filesystem permissions.

## Content and artifact updates

`content.json` contains only reviewed, non-secret release metadata. When the
candidate changes, update together:

1. source commit and CI artifact version;
2. workflow URL;
3. qualification statement and warning;
4. configured ISO and matching checksum sidecar.

`content.json` and the verified artifact snapshot are loaded once at process
start, so restart `kaid-site.service` after changing release metadata or the
configured artifact path.

Do not soften the warning based only on the existence of a workflow artifact.
For the current `015ee8f` candidate, the hybrid ISO, ordinary BIOS/UEFI QEMU
smoke, USB-style two-boot and both privileged persistent-vault lifecycle jobs
passed on the same exact artifact. Its locally re-derived entry matched the CI
artifact and trusted catalog v2 revision 3 now authorizes only that image. The
same lifecycle proved signed-report persistence, retrieval and fixed-path
export under both virtual firmware modes. It is still not a production release:
private availability is limited to
controlled first-boot qualification on factory-new or disposable USB and
non-customer hardware until physical USB, Secure Boot and real-account/TLS
gates are recorded.

## Local validation

Syntax check:

```bash
node --check site/server.mjs
```

Start a local instance with the operator-owned files already provisioned:

```bash
KAID_PORT=3211 \
KAID_AUTH_FILE=/path/to/password \
KAID_ISO_PATH=/path/to/KernAid-Rescue-amd64.iso \
node site/server.mjs
```

Expected HTTP behavior:

```text
GET  /                                  200
GET  /private/ without a session        303 -> /private/login
POST /private/login with valid data      303 + Secure session cookie
GET  /private/ with the session          200
GET  /private/downloads/iso Range 0-0    206, one byte
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
