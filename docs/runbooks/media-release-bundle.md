# Issue a Media Creator release bundle offline

This procedure creates the signed local manifest consumed by KernAid Media
Creator for Windows. Perform key generation and signing on an offline trusted
Linux host. Never put the seed in Git, GitHub Actions, repository variables,
the download site, Fleet, or the Windows application.

## One-time key setup

Build the issuer from the reviewed release source, then generate an Ed25519
seed and its public trust anchor:

```sh
cargo build --locked --release -p kernaid-media-creator-core \
  --bin kernaid-media-bundle-issuer
umask 077
target/release/kernaid-media-bundle-issuer generate-key \
  /secure/offline/kernaid-media.seed \
  /secure/offline/kernaid-media.public
```

The seed is canonical unpadded base64url and is created with mode `0600`. Keep
its encrypted offline backup separately. The public file is the canonical raw
32-byte Ed25519 key encoded as unpadded base64url; provide only this public
value as `KERNAID_MEDIA_BUNDLE_TRUST_ANCHOR` when building the Windows Media
Creator.

To derive the public value again without changing files:

```sh
target/release/kernaid-media-bundle-issuer public-key \
  /secure/offline/kernaid-media.seed
```

Key rotation requires a new reviewed Media Creator build with the new public
anchor. A build trusts exactly its embedded anchor.

## Issue one qualified release

Place exactly these already-qualified, fixed-name files in a real directory
(not a symlink):

- `KernAid-Rescue-amd64.catalog-entry-v2.json`
- `KernAid-Rescue-amd64.qualified.json`
- `KernAid-Rescue-amd64-retail.json`
- `KernAid-Rescue-amd64-retail.img.xz`

Then run:

```sh
target/release/kernaid-media-bundle-issuer issue-bundle \
  /secure/offline/kernaid-media.seed \
  /secure/staging/qualified-release
```

The command hashes the complete bounded image, validates the catalog entry,
qualification and retail metadata as one coherent release, and writes
`KernAid-Rescue-amd64.media-bundle.json`. Inputs and seed must be regular
non-symlink files; the seed must deny group and other access. The output uses
create-new semantics and is flushed to durable storage, so an existing file is
never overwritten. Move an obsolete output aside explicitly before reissuing.

Before persistence, the issuer feeds its own signed result through the same
`authorize_release_bundle` boundary used by Media Creator. The signature is
Ed25519 over the exact bytes
`kernaid:media-release-bundle:v1\0 || canonical_json(unsigned_manifest)`.
Canonical JSON is compact, recursively lexicographically key-sorted, and keeps
array order. Every descriptor carries the exact filename, byte count and
lowercase SHA-256; `keyId` is the lowercase SHA-256 of the raw public key.

Publish the five release files together. Publish the public trust anchor only
through the reviewed application build path. Do not publish or copy the seed
to any online release host.
