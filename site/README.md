# KernAid project site

This directory is the canonical, dependency-free source for the KernAid public
project site and its private engineering-artifact area. It is deliberately
small: one Node.js HTTP server, server-rendered HTML, CSS, the existing KernAid
SVG mark, and one reviewed metadata file.

The site does not promote artifacts. A file remains an internal candidate until
the repository trust catalog and the applicable qualification gates explicitly
authorize it.

## Routes

| Route | Access | Purpose |
| --- | --- | --- |
| `/`, `/styles.css`, `/mark.svg` | Public | Product, architecture and honest project status |
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

The ISO is not loaded into memory. Its size and modification time come from
`stat`; the expected SHA-256 comes from the configured sidecar. The server reads
these values when rendering the private page and when starting a download, so
replacing an artifact does not require editing HTML. It does not hash the full
ISO on every request: operators and users must verify the downloaded file using
the sidecar.

## Content and artifact updates

`content.json` contains only reviewed, non-secret release metadata. When the
candidate changes, update together:

1. source commit and CI artifact version;
2. workflow URL;
3. qualification statement and warning;
4. configured ISO and matching checksum sidecar.

Do not soften the warning based only on the existence of a workflow artifact.
For the current `b843178` candidate, BIOS/UEFI QEMU smoke evidence exists, but
the vault lifecycle gate failed and the trusted v2 catalog is empty. It is not
a release and is not qualified for writing or booting on physical USB media.

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
