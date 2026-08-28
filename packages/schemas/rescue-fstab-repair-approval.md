# Rescue fstab repair approval candidate

`rescue-fstab-repair-approval.schema.json` is a closed R2 approval envelope
for the single candidate resource `rescue:selected-linux-root:etc/fstab`. It
does not replace or extend the generic `Approval` v1 contract.

Before execution, the trusted consumer must compare the session, plan,
sequence, plan hash, target fingerprint and target snapshot with the currently
staged repair. Any mismatch, stale sequence, changed target or confirmation
other than `DISABILITA VOCE FSTAB` must fail closed. Schema validity alone does
not authorize a write or enable the production candidate.
