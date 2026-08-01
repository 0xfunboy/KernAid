# Linux pack

`kernaid-linux-inventory` is restricted to directory fixtures and emits names, sizes, and readonly permission state. It does not read file contents or mutate the target. Host hardware collectors will be added as separate typed collectors after sandboxing and redaction tests exist.

The library also contains the first controlled repair transaction from the masterplan: preview, backup, fingerprint re-check, explicit approval, resource lock, atomic replacement, validation and rollback for a known broken `fstab` entry. It refuses every target without the exact disposable-fixture marker and is not connected to the production broker or UI. Tests prove rollback restores the original bytes, stale fingerprints write nothing, and unmarked targets are rejected.
