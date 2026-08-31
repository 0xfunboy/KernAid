# KernAid Media Creator core

This crate is the transport-neutral destructive-write boundary for the Windows
retail Media Creator. It validates the existing Rescue catalog v2,
qualification manifest, retail metadata, archive filename/size/SHA-256, exact
decompressed length/SHA-256, target eligibility and full readback SHA-256.

The core never accepts a block-device path. A platform backend must enumerate
whole removable USB disks, retain an opaque snapshot, and re-probe the selected
disk before opening it exclusively. Only an exact `ERASE KERNAID USB <id>`
confirmation can create a `ConfirmedSelection`.

`CreationReport` contains only public artifact/disk metadata and digests. It
does not contain a Windows device path, source path, token, key, or raw log.

The Windows executable is deliberately off-default and lives in
`apps/media-creator-windows`. Microsoft code signing and qualification on a
physical disposable USB device are release gates outside this repository.
