# KernAid Fleet Resident Update v1

Off-default Linux service for downloading and staging Enterprise updates. It
connects the existing device identity, Fleet entitlement/policy cache and
`kernaid-update-client` without adding boot activation authority.

## Boundary

One cycle performs exactly these steps:

1. load the existing `resident-v1` Ed25519 identity (never create or serialize
   a replacement);
2. read external public anchors and the device-bound Fleet runtime;
3. require the current `Updates` entitlement and intersect the local update
   ring with every retained signed policy (an invalid/out-of-window policy
   yields `Hold`);
4. POST a canonical signed device request only to `/v1/update-pulls`;
5. verify response tenant/device/platform/architecture/ring binding and every
   vendor-signed manifest, validity window, deterministic rollout and monotonic
   sequence;
6. download only the signed HTTPS artifact with redirects and all proxy sources
   disabled, fixed connect/whole-request timeouts and exact `Content-Length`;
7. stream through `ArtifactStager` to a locally configured, caller-preopened
   inactive target and persist its receipt;
8. persist a privacy-minimized device-signed staging audit receipt with digests
   and `bootActivation: not_armed`;
9. persist a path-free activation candidate derived only from the admitted
   signed update and the exact-byte `StagingReceipt`.

The manifest cannot select a device path or slot. The stager has no generic
HTTP operation, bearer token, signing seed, shell executor, bootloader call or
remote-command surface. Logs contain only a stable status/error code and safe
release metadata. A completed stage exits and waits for the separately built,
installed and enabled local activator. Creating the candidate does not change
the staging audit receipt: its `bootActivation` remains `not_armed`.

## Build and run

The binary is absent from default builds. Enable it explicitly on the target:

```sh
cargo build --locked -p kernaid-fleet-resident-update --features linux-resident

target/debug/kernaid-fleet-resident-update \
  --config /etc/kernaid/resident-update.json --once
```

Omit `--once` for polling. The service still exits after successfully staging
one update because this v1 deliberately cannot arm it. Use the same enrolled
tenant/device runtime populated by Resident Fleet sync. Public anchor files may
be `0644` but must not be group/other writable; the state directory is forced
to owner-only mode and single-instance locked.

[`config.example.json`](config.example.json) is strict: unknown fields fail,
paths are absolute and distinct, intervals/timeouts are bounded, and there is
no token, proxy or boot action field. `activeSlot` is local trusted state; the
configured `inactiveTargetFile` must be its opposite A/B target. The stager
checks that relationship before writing.

[`config.ab.example.json`](config.ab.example.json) is the production A/B mode.
It provisions both fixed local targets and omits `activeSlot`: on every cycle
the Linux adapter requires exactly one fixed `kernaid.slot=a|b` marker from
`/proc/cmdline` and opens only the opposite target with `O_NOFOLLOW`. Mixing the
legacy single-target fields with A/B fields, omitting either target, or using a
duplicate/unknown marker is rejected.

## Optional systemd-boot A/B activator

The activator is a second, off-default binary and a root system service:

```sh
cargo build --locked --release -p kernaid-fleet-resident-update \
  --features linux-resident,linux-systemd-boot-activator
```

It supports only UEFI systems where `bootctl is-installed` succeeds. BIOS,
GRUB, missing/ambiguous `kernaid.slot=` markers and any non-systemd-boot host
fail closed. The only accepted entries are the preinstalled
`kernaid-slot-a.conf` and `kernaid-slot-b.conf`; each must contain exactly one
matching `kernaid.slot=a` or `kernaid.slot=b` option. Commands and paths are
compiled in and the strict enablement config contains no override fields.

Before changing the bootloader, the activator durably persists its transition.
It keeps the running slot as the persistent default and arms the staged slot as
a one-shot. On the next boot it either promotes the observed target or records
that systemd-boot returned to the known-good slot. Terminal activation receipts
are archived locally, the staging/audit receipts are released or archived, and
the network-free `--rollback` operation can re-arm the retained known-good slot.
The root-owned state directory and the stager lock are revalidated before use.

This tranche intentionally does not implement BIOS/GRUB activation. It also
does not create boot entries, repartition disks, synthesize kernel arguments or
restart the machine. A provisioner must install and qualify both A/B UKIs and
their fixed entries before enabling the unit.

## Durable output and recovery

Under `stateDirectory` the service retains:

- `manifest-checkpoint.cjson`: monotonic vendor-manifest admission;
- `staging/`: exact-write intent or completed staging receipt;
- `update-audit-receipt.cjson`: device-signed minimized completion evidence.
- `boot-activation-candidate.cjson`: path-free, receipt-bound local hand-off;
- `boot-activation-state.cjson`: persisted-before-mutation boot transition;
- `boot-activation-receipt-*.cjson`: terminal local activation archive.

A truncated, extra-byte or digest-mismatched stream cleans regular-file target
residue and retains enough checkpoint state for an exact retry. A lower
manifest or different same-sequence manifest remains rejected after restart.
A byte-identical completed restart does not contact the network or rewrite the
target. State corruption fails closed.

## Focused checks

```sh
cargo test -p kernaid-fleet-client update_pull
cargo test -p kernaid-fleet-resident-update
cargo clippy -p kernaid-fleet-client -p kernaid-fleet-resident-update \
  --all-targets --features linux-resident,linux-systemd-boot-activator -- -D warnings
```
