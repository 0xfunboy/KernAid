# KernAid Media Creator for Windows

An off-default, Windows x86-64 CLI wizard for writing the qualified 32 GB
KernAid retail `.img.xz` to a removable USB disk.

Build explicitly:

```text
cargo build --locked --release -p kernaid-media-creator-windows \
  --features windows-cli --target x86_64-pc-windows-msvc
```

Run from a terminal the operator has already opened as Administrator:

```text
kernaid-media-creator.exe \
  --image KernAid-Rescue-amd64-retail.img.xz \
  --catalog-entry KernAid-Rescue-amd64.catalog-entry-v2.json \
  --qualification KernAid-Rescue-amd64.qualified.json \
  --metadata KernAid-Rescue-amd64-retail.json \
  --report KernAid-Media-Creation-report.json
```

The executable does not elevate itself, run PowerShell, accept a
`PhysicalDrive` path, download content, auto-run, or contain signing keys. It
queries Windows storage inventory directly, permits only unambiguous whole
removable USB disks, rejects boot/system/read-only disks, locks and dismounts
their mounted volumes, then revalidates the enumeration identity before raw
access. The destructive action requires the exact phrase printed by the
wizard. The archive is verified before opening the disk and the complete raw
write is flushed and read back with SHA-256.

The executable produced by CI is intentionally unsigned. Microsoft Authenticode
code signing and a real, disposable physical-USB qualification run are external
release gates and must be completed before public distribution.
