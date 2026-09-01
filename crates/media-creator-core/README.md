# KernAid Media Creator core

This crate is the transport-neutral destructive-write boundary for the Windows
retail Media Creator. It validates the existing Rescue catalog v2,
qualification manifest, retail metadata, archive filename/size/SHA-256, exact
decompressed length/SHA-256, target eligibility and full readback SHA-256.

`authorize_release_bundle` is the public boundary for local release input. It
requires one canonical `dev.kernaid.media-release-bundle.v1` manifest signed by
an offline Ed25519 issuer whose raw public key is supplied independently. The
signature covers the domain `kernaid:media-release-bundle:v1\0` followed
directly by recursive lexicographic canonical JSON without `signature`. The
manifest binds the exact fixed catalog-entry, qualification, retail metadata,
and retail archive descriptors. Unknown fields and cross-version/mixed-member
input are rejected.

The core never accepts a block-device path. A platform backend must enumerate
whole removable USB disks, retain an opaque snapshot, and re-probe the selected
disk before opening it exclusively. Only an exact `ERASE KERNAID USB <id>`
confirmation can create a `ConfirmedSelection`.

`create_media_with_progress` reports bounded archive-validation, USB-writing,
and full-readback phases without exposing a path. Archive validation completes
before the backend may open a target.

`CreationReport` contains only public artifact/disk metadata and digests. It
does not contain a Windows device path, source path, token, key, or raw log.

The Windows executable is deliberately off-default and lives in
`apps/media-creator-windows`. Microsoft code signing and qualification on a
physical disposable USB device are release gates outside this repository.
