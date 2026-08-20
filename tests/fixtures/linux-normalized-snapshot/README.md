# Linux normalized snapshot v1 fixture

`healthy/root` and `multi-fs/root` are the only arbitrary roots accepted by the repository parity
tools. Production Resident collection opens `/` internally; production Rescue
collection still obtains its root only from the opaque selected-target flow and
the private, read-only, no-replay mount namespace.

Both modes must project `expected/snapshot.v1.json` byte-for-byte after
canonical serialization and must bind its domain-separated SHA-256 from
`expected/snapshot.v1.sha256`. Their envelopes intentionally differ only in
`capture`; the normalized `snapshot` and `snapshotSha256` must match.

The local gate is `tests/integration/linux-snapshot-parity.sh`. It runs both
language implementations against the fixed fixture and proves that contents,
directory topology, modes, sizes, mtimes, and ctimes did not change.

The QEMU promotion gate is a second phase because it requires the promoted b19
Rescue ISO. It must collect this same fixture once through the Resident command
and once through the selected-installed-target Rescue API, then apply the same
snapshot/hash comparison and verify the Rescue capture claims. Passing the
local gate alone does not attest physical media read-only behavior, firmware
coverage, or a promoted ISO artifact.

`healthy` is a single-root-filesystem topology. `multi-fs` deliberately
declares separate `/boot`, `/usr`, and `/var` filesystems and contains
placeholder data beneath those mountpoints; both collectors skip that data and
mark the normalized corpus unsupported for v1 admission.
