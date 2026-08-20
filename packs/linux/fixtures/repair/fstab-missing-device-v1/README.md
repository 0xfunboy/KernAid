# Reversible fstab fixture

This fixture is intentionally disposable and is copied to a temporary tree by
the `fixture-repair-lab` tests. Its root filesystem UUID exists in the checked
read-only Linux P0 inventory; `UUID=missing-data` does not. The pinned repair
comments that one required entry, and the explicit rollback restores this file
byte-for-byte.

The repository copy is never mutated by tests. The backup vault and journal
are created as separate temporary directories.
