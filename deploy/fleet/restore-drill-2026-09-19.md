# Fleet schema-v13 signed restore evidence

Verified on 19 September 2026 at 01:34:13 UTC using Node.js `v24.18.0`.
This closes the current-schema offline verification/disposable-restore
software gate, not the production disaster-recovery qualification.

## Provenance

The existing persistent user backup service last completed successfully on
18 September 2026 at 02:35:19 UTC. Its configured source is the deployed Fleet
database; its configured destination contained 14 retained scheduled bundles.
The latest bundle was used without creating another live backup or reading
the service's private signing key.

| Field                                     | Recorded value                                                     |
| ----------------------------------------- | ------------------------------------------------------------------ |
| Bundle                                    | `fleet-20260918T023519.797Z-1673096.backup`                        |
| Signed creation time                      | `2026-09-18T02:35:19.882Z`                                         |
| Manifest schema                           | `dev.kernaid.fleet.database-backup-manifest.v1`                    |
| SQLite schema / table count               | `user_version=13` / `32`                                           |
| Database size                             | `405504` bytes                                                     |
| Database SHA-256                          | `458f6a1ec0c9436389f35e39e09718bb8dc9cefdd04b10d7bcb1ec89782f2459` |
| Manifest SHA-256                          | `8e8a422c10517e75a5c9581bb63d101d44d1b040baaae84e41ec86142ee6223e` |
| Detached signature file SHA-256           | `fcc98a82c1cfea4a71b1ba9fb2d25aa914f1fdd09e552ef603ff0869deecf046` |
| Raw 32-byte public receipt anchor SHA-256 | `f1934a21181930d20462ed33b359dc57592b1366cf34069dd5d91e4786c4ade7` |
| Verification checkout base revision       | `7e992fd9ad0546c7b668e66bccf0f48282a0a5e7`                         |
| `database-lifecycle.mjs` SHA-256          | `e7c8b6ce9dd1c14bc0b624ac79abe20537d5f771483436e18aa89e846af9b505` |

The public anchor was the independently provisioned file configured by the
running Fleet service and the scheduled backup service, not an anchor supplied
inside the bundle. The signed manifest attests database bytes, schema/table
inventory and creation time; it does not attest a source-code revision.

## Checks and outcome

- `database-lifecycle.mjs verify` accepted the canonical manifest and its
  Ed25519 signature against the deployed public receipt anchor, the database
  digest/size, `quick_check`, foreign keys and complete signed table inventory.
- `database-lifecycle.mjs restore` wrote only a new `0600` SQLite file in a
  fresh `0700` directory created with `mktemp -d` under `/tmp`. The restored
  bytes matched the signed source database exactly.
- A separate read-only SQLite connection returned full `integrity_check=ok`,
  zero foreign-key failures, `user_version=13`, 32 matching table names and
  standalone `journal_mode=delete`.
- Repeating restore to the existing destination failed with
  `destination already exists`; its bytes remained unchanged.
- The live loopback `/healthz` returned `{"status":"ok"}` before and after.
  No live database/configuration was changed, no service was restarted and no
  tenant/API mutation was submitted.
- `node --test deploy/fleet/backup-lifecycle.test.mjs` passed all three focused
  tests after correcting a stale version assertion (expected 10 while the
  fixture used 11). The minimal synthetic fixture and verify/restore assertions
  now explicitly exercise version 13; the real 32-table coverage comes from
  the deployed bundle drill above.
- The disposable restored database and its empty parent directory were removed
  after verification. The original signed bundle remains untouched. No token,
  private key, tenant/device identifier or database row is retained here.

## Remaining operational qualification

This drill did not start a second Fleet instance or cut over the live service.
Clean-host recovery of the matching root/tenant credentials and service key,
authenticated tenant/inventory visibility after recovery, off-host backup
durability and measured recovery time/point objectives remain unqualified.
Perform those checks only in a separately authorized recovery environment;
never overwrite the running database for a drill. Scheduled rotation will
eventually remove this source bundle, so these digests are evidence references,
not a durable off-host backup or a guarantee that the bundle remains available.
