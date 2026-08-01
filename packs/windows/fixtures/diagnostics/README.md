# Windows diagnostic corpus fixtures

All fixtures are synthetic and contain no provider credentials, recovery keys,
personal paths, or customer event messages.

- `healthy/` is a complete normalized Windows 11 baseline. “Healthy” is only a
  fixture label; the report deliberately makes no whole-system health claim.
- `incidents/` supplies one or two deterministic signals for every P0 source:
  critical events, hardware reliability records, repairable component-store
  corruption, SFC violations, failed/pending updates, stopped services, missing
  route/DNS, driver problems, suspended BitLocker protection, incomplete boot
  configuration, and an exhausted system volume.
- `adversarial/` proves that control characters and forbidden BitLocker secret
  fields fail closed, while instruction-like observed text cannot enter a
  finding or proposal.

The dates, addresses (`192.0.2.0/24`, `2001:db8::/32`), IDs, and hardware names
are documentation-only synthetic values.
