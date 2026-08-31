# Linux Resident signed-update deployment

This user service packages the existing off-default update stager without
granting boot activation or arbitrary filesystem authority.

1. Build `kernaid-fleet-resident-update` with `--features linux-resident` and
   install it at `/usr/libexec/kernaid-fleet-resident-update`.
2. Install `config.example.json` as
   `~/.config/kernaid/fleet-update.json`, replacing every `/home/example`
   value with the enrolled user's absolute home path.
3. Install the public update, entitlement and policy anchors as regular files
   that are not group/other writable.
4. Pre-create the configured inactive slot as a regular owner-only file with
   the exact capacity required by the signed update manifest. The active slot
   and inactive filename are local configuration; Fleet cannot choose either.
5. Install the unit under `~/.config/systemd/user/`, reload systemd and start
   it once before enabling it.

The process uses the same `resident-v1` identity and Fleet runtime populated by
Resident sync. It downloads only a vendor-signed, device/ring/rollout-matching
HTTPS artifact, stages it with exact size and SHA-256 verification, and writes
a signed minimized receipt. A successful stage exits with
`bootActivation=not_armed`; a separate qualified local activator is required
before an A/B system slot can become bootable.

```sh
cargo build --locked --release -p kernaid-fleet-resident-update \
  --features linux-resident
systemctl --user daemon-reload
systemctl --user start kernaid-fleet-resident-update
systemctl --user enable kernaid-fleet-resident-update
```

Do not configure a live root filesystem, active boot slot, device symlink or
customer block device as the inactive target. This engineering deployment is
for a pre-created disposable staging file until the local A/B activator is
qualified.
