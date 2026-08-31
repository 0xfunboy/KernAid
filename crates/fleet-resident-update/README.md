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
8. persist a privacy-minimized device-signed audit receipt with digests and
   `bootActivation: not_armed`.

The manifest cannot select a device path or slot. The process has no generic
HTTP operation, bearer token, signing seed, shell executor, bootloader call or
remote-command surface. Logs contain only a stable status/error code and safe
release metadata. A completed stage exits and waits for the separate, future
boot-planner integration.

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

## Durable output and recovery

Under `stateDirectory` the service retains:

- `manifest-checkpoint.cjson`: monotonic vendor-manifest admission;
- `staging/`: exact-write intent or completed staging receipt;
- `update-audit-receipt.cjson`: device-signed minimized completion evidence.

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
  --all-targets --features linux-resident -- -D warnings
```

