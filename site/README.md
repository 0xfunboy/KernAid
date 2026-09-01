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
| `/private/downloads/diagnostic-candidate-iso` | Authenticated | Range-capable, separately pinned diagnosis-only physical-test candidate ISO |
| `/private/downloads/diagnostic-candidate-iso-checksum` | Authenticated | SHA-256 sidecar generated for the diagnostic candidate ISO |
| `/private/downloads/diagnostic-candidate-retail` | Authenticated | Optional range-capable retail image from the same diagnostic candidate run |
| `/private/downloads/diagnostic-candidate-retail-checksum` | Authenticated | Optional SHA-256 sidecar for that retail image |
| `/private/downloads/repair-candidate` | Authenticated | Range-capable, separately gated experimental repair-candidate ISO |
| `/private/downloads/repair-candidate-checksum` | Authenticated | SHA-256 sidecar generated for the repair candidate |
| `/private/downloads/windows-media-creator` | Authenticated | Optional range-capable Windows Media Creator ZIP bundle |
| `/private/downloads/windows-media-creator-checksum` | Authenticated | SHA-256 sidecar generated for the Media Creator bundle |
| `/private/downloads/linux-fleet-resident` | Authenticated | Optional range-capable Linux Fleet Resident DEB package |
| `/private/downloads/linux-fleet-resident-checksum` | Authenticated | SHA-256 sidecar generated for the Linux Resident package |
| `/private/downloads/windows-fleet-resident` | Authenticated | Optional range-capable Windows Fleet Resident deployment bundle |
| `/private/downloads/windows-fleet-resident-checksum` | Authenticated | SHA-256 sidecar generated for the Windows Resident bundle |
| `/private/downloads/macos-fleet-resident` | Authenticated | Reserved, fail-closed macOS Resident package route |
| `/private/downloads/macos-fleet-resident-checksum` | Authenticated | Reserved, fail-closed macOS Resident checksum route |
| `/private/logout` | Authenticated | Session revocation |

Successful login creates a random, in-memory session with a 12-hour lifetime.
The cookie is scoped to `/private` and carries `Secure`, `HttpOnly` and
`SameSite=Strict`. Restarting the process invalidates all sessions. Repeated
failed logins from one client are temporarily throttled.

## Configuration

The server requires the repository-pinned Node.js 24.18.0 and has no package
dependencies.

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
| `KAID_DIAGNOSTIC_CANDIDATE_ISO_PATH` | No; required only to expose the diagnostic physical-test candidate | No default |
| `KAID_DIAGNOSTIC_CANDIDATE_ISO_SHA256_PATH` | No | `${KAID_DIAGNOSTIC_CANDIDATE_ISO_PATH}.sha256` |
| `KAID_DIAGNOSTIC_CANDIDATE_RETAIL_PATH` | No; only when the exact run produced a retail image | No default |
| `KAID_DIAGNOSTIC_CANDIDATE_RETAIL_SHA256_PATH` | No | `${KAID_DIAGNOSTIC_CANDIDATE_RETAIL_PATH}.sha256` |
| `KAID_REPAIR_CANDIDATE_PATH` | No; required only to expose the repair candidate | No default |
| `KAID_REPAIR_CANDIDATE_SHA256_PATH` | No | `${KAID_REPAIR_CANDIDATE_PATH}.sha256` |
| `KAID_WINDOWS_MEDIA_CREATOR_PATH` | No; required only after the exact bundle is enabled in `content.json` | No default |
| `KAID_WINDOWS_MEDIA_CREATOR_SHA256_PATH` | No | `${KAID_WINDOWS_MEDIA_CREATOR_PATH}.sha256` |
| `KAID_LINUX_FLEET_RESIDENT_PATH` | No; required only after the exact DEB is enabled in `content.json` | No default |
| `KAID_LINUX_FLEET_RESIDENT_SHA256_PATH` | No | `${KAID_LINUX_FLEET_RESIDENT_PATH}.sha256` |
| `KAID_WINDOWS_FLEET_RESIDENT_PATH` | No; required only after the exact bundle is enabled in `content.json` | No default |
| `KAID_WINDOWS_FLEET_RESIDENT_SHA256_PATH` | No | `${KAID_WINDOWS_FLEET_RESIDENT_PATH}.sha256` |
| `KAID_MACOS_FLEET_RESIDENT_PATH` | No; required only after an exact macOS multi-architecture catalog is reviewed | No default |
| `KAID_MACOS_FLEET_RESIDENT_SHA256_PATH` | No | `${KAID_MACOS_FLEET_RESIDENT_PATH}.sha256` |

The authentication file must contain one non-empty password. Keep it and any
Cloudflare tunnel credentials outside the repository with owner-only
permissions. The server reads the password once at startup and never logs it.

No artifact is loaded into memory. At process start the server opens the retail
image, stable ISO and separately configured diagnostic/repair candidates without
following a final symlink, verifies owner-only permissions, hashes every byte
against its configured sidecar and keeps those exact file descriptors pinned
for downloads. Every stable or candidate artifact must also match the reviewed
byte size and SHA-256 recorded in `content.json`; a sidecar alone cannot switch
the served artifact. A missing path or mismatch leaves only that artifact
unavailable. Candidate environment variables are optional, so omitting them
does not affect the stable internal.6 downloads. Operators and users must still
verify each downloaded file using its sidecar.

Software downloads use the same pinned-file, owner-only, range-capable path.
They have an additional catalog gate: an environment variable cannot expose a
package while its `software.*.available` flag is false. Enabling one requires a
full 40-character source commit, the exact GitHub Actions run URL and ID,
artifact version, safe presentation filenames, byte size, lowercase SHA-256,
qualification text, warning text and an explicit `unsigned` or `signed` state.
A signed state additionally requires an HTTPS evidence URL. Until all fields
are reviewed, artifact fields remain JSON `null` and the route returns `404`.
If the metadata is enabled but the configured file, permissions, sidecar, size
or digest is wrong, the route returns `503`.

Keep the private artifact directory owner-only (`0700`) and the ISO, checksum
and metadata files owner-readable only (`0600`). Web authentication is not a
substitute for local filesystem permissions.

## Content and artifact updates

`content.json` contains only reviewed, non-secret release metadata. When the
candidate changes, update together:

1. source commit and CI artifact version;
2. workflow URL;
3. both download and checksum presentation names;
4. exact reviewed byte sizes and SHA-256 values for the retail image and ISO;
5. qualification statement and warning;
6. configured retail image and ISO with their matching checksum sidecars;
7. diagnostic physical-test candidate metadata and files separately, including
   its failed gate and exact passing coverage, without changing the stable paths;
8. repair-candidate metadata and files separately, without changing the stable
   release paths or promoting the candidate.
9. each software package independently: change `available` only in the same
   review that records its exact commit, workflow run, version, filenames,
   bytes, SHA-256, qualification boundary and signature state;
10. publisher-signature evidence separately from the SHA-256 sidecar. Never
    describe an unsigned Windows build as signed, or a macOS package as
    notarized, solely because its workflow and checksum passed.

`content.json` and all verified artifact snapshots are loaded once at process
start, so restart the site process after changing release metadata or a
configured artifact path.

Do not soften the stable-release warning based only on the existence of a
workflow artifact. The exact diagnosis-only release named in `content.json`
must have passed hybrid ISO build, ordinary BIOS/UEFI smoke, zero-state first
boot, USB-style two-boot and both privileged persistent-vault lifecycle jobs on
the same bytes. Its release manifest and attestations must then be independently
verified before the retail image and ISO are staged together. It remains an
internal engineering candidate: private availability is limited to controlled
physical qualification on factory-new or disposable USB and non-customer
hardware until physical USB, Secure Boot and real-account/TLS gates are
recorded.

The diagnostic physical-test candidate is independent from the stable release
and trusted catalogs. Private availability means only that the exact ISO is
offered for controlled physical investigation. Its card must name every known
failed gate. A successful build plus BIOS, UEFI, two-boot and Vault lifecycle
evidence does not erase a failed native Vault prompt gate and does not qualify
or promote the candidate.

The repair candidate has an independent, stricter boundary. It may be exposed
only in the authenticated lab area after one exact image passes every virtual
boot, apply, rollback and restart-reconciliation step in its dedicated workflow.
That private download is hardware-qualification input, not stable promotion:
the repair image remains outside the trusted stable catalog, Release Channel
and public product until the remaining fault, physical power-loss, Secure Boot
and explicit release-policy gates are recorded.

Each enabled download remains independently fail-closed with `503` until its
exact file, matching sidecar and environment path are all present. Stable and
candidate artifacts additionally require exact equality with their reviewed
size and digest in `content.json`. A candidate explicitly disabled in
`content.json` returns `404`; enabling it does not weaken this equality check.
This allows the stable ISO and retail image to remain available when either
candidate is absent. Candidate availability never changes its explicit
non-qualified, non-promoted status.

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
KAID_DIAGNOSTIC_CANDIDATE_ISO_PATH=/path/to/KernAid-Rescue-amd64-diagnostic-candidate.iso \
KAID_REPAIR_CANDIDATE_PATH=/path/to/KernAid-Rescue-amd64-repair-candidate.iso \
KAID_WINDOWS_MEDIA_CREATOR_PATH=/path/to/KernAid-Media-Creator-windows-x86_64.zip \
KAID_LINUX_FLEET_RESIDENT_PATH=/path/to/kernaid-fleet-resident_amd64.deb \
KAID_WINDOWS_FLEET_RESIDENT_PATH=/path/to/KernAid-Fleet-Resident-windows-x86_64.zip \
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
GET  /private/downloads/diagnostic-candidate-iso Range 0-0
                                              503 when not configured;
                                              206, one byte when exact
GET  /private/downloads/diagnostic-candidate-retail Range 0-0
                                              404 when not produced;
                                              206, one byte when exact
GET  /private/downloads/repair-candidate Range 0-0
                                              404 when disabled; 503 if enabled but invalid;
                                              206, one byte when enabled and exact
GET  /private/downloads/windows-media-creator Range 0-0
                                              404 while catalog-disabled;
                                              503 if enabled but invalid;
                                              206, one byte when enabled and exact
GET  /private/downloads/linux-fleet-resident Range 0-0
                                              404 while catalog-disabled;
                                              503 if enabled but invalid;
                                              206, one byte when enabled and exact
GET  /private/downloads/windows-fleet-resident Range 0-0
                                              404 while catalog-disabled;
                                              503 if enabled but invalid;
                                              206, one byte when enabled and exact
GET  /private/downloads/macos-fleet-resident Range 0-0
                                              404 until a reviewed artifact exists
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
