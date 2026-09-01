# KernAid Media Creator for Windows

KernAid Media Creator is an off-default, native Windows x86-64 wizard for
turning one authorized KernAid Rescue release into a verified USB drive. It is
designed for a non-technical user: choose the release, choose the USB, confirm
the erase, wait for writing and full readback verification, then finish.

The app never accepts a disk path or shows fixed/internal disks as choices. It
enumerates Windows storage itself and permits only a unique whole removable USB
device that is at least 32 GB and is not boot, system, offline, ambiguous, or
read-only. Windows requests administrator approval through the embedded
application manifest. The chosen device and all safety properties are probed
again immediately before raw access.

## Release bundle consumed by the wizard

The file picker accepts exactly
`KernAid-Rescue-amd64.media-bundle.json`. Its folder must contain these fixed
sibling names from one qualified Rescue release:

- `KernAid-Rescue-amd64.catalog-entry-v2.json`
- `KernAid-Rescue-amd64.qualified.json`
- `KernAid-Rescue-amd64-retail.json`
- `KernAid-Rescue-amd64-retail.img.xz`

The manifest schema is `dev.kernaid.media-release-bundle.v1`. It binds the
artifact version and the exact filename, byte count, and lowercase SHA-256 of
every member. Unknown fields, alternate filenames, non-canonical JSON, mixed
versions, tampered bytes, and an unqualified image all fail closed.

An offline release issuer signs the UTF-8 bytes
`kernaid:media-release-bundle:v1\0 || canonical_json(unsigned_manifest)` with
Ed25519. Canonical JSON is compact, recursively lexicographically key-sorted,
and preserves array order. `signature` is canonical unpadded base64url. `keyId`
is `sha256:` followed by the lowercase SHA-256 of the raw 32-byte public key.
The private key is never used by this app, its workflow, or this repository.

The matching raw public key is embedded at build time from the public
`KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR` value (canonical unpadded base64url). A
manifest cannot introduce or replace its own trust anchor. The app also checks
the existing embedded trusted Rescue catalog, qualification evidence, release
origin, layout, and image hashes.

## Build

On a Windows developer machine with Rust 1.88.0 and the Windows SDK available:

```powershell
$env:KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR = "<approved raw Ed25519 public key, base64url>"
cargo build --locked --release -p kernaid-media-creator-windows `
  --features windows-wizard --target x86_64-pc-windows-msvc
```

The GitHub workflow cross-builds the GNU x86-64 target and emits one
deterministically named publish set:

- `KernAid-Media-Creator-windows-x86_64-v<version>-UNSIGNED.zip`, containing
  the EXE, its canonical package manifest, and the release-gate notice;
- a SHA-256 sidecar for that ZIP;
- a bounded canonical download descriptor with filename, version, size,
  architecture, and SHA-256 for direct site integration.

The repository variable is a public verification key, not a secret. A missing
or malformed key stops the build. The ZIP is deliberately marked `UNSIGNED`:
Microsoft Authenticode signing and verification remain an external release
gate. The workflow does not claim or fabricate that signature. Qualification
on a real disposable USB is also required before public distribution.

## Runtime behavior

The wizard hashes the complete compressed image before opening the selected
USB, streams the exact 32 GB image, flushes it, reads the entire image back, and
compares SHA-256. Closing is blocked while write or verification is active. A
successful result is reported clearly; an optional digest-only creation report
is written beside the selected bundle when that folder is writable.

If a write or readback fails, treat that USB as incomplete and start over. No
network request, PowerShell command, arbitrary shell command, signing key, or
automatic execution is present in the app.
