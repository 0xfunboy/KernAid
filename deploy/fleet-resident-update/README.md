# Linux Resident signed-update deployment

The update stager and privileged A/B activator remain separate executables and
services. Staging never grants boot activation or arbitrary filesystem
authority; the activator never accepts network input, paths or commands.

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
5. For staging-only engineering use, install the unit under
   `~/.config/systemd/user/`, reload systemd and start it once before enabling
   it.

The process uses the same `resident-v1` identity and Fleet runtime populated by
Resident sync. It downloads only a vendor-signed, device/ring/rollout-matching
HTTPS artifact, stages it with exact size and SHA-256 verification, and writes
a signed minimized receipt. A successful stage exits with
`bootActivation=not_armed`. That value never changes: activation has a separate
local receipt.

```sh
cargo build --locked --release -p kernaid-fleet-resident-update \
  --features linux-resident
systemctl --user daemon-reload
systemctl --user start kernaid-fleet-resident-update
systemctl --user enable kernaid-fleet-resident-update
```

Do not configure a live root filesystem, active boot slot, device symlink or
customer block device as the inactive target. This engineering deployment is
for a pre-created disposable staging file.

## Qualified UEFI A/B installation

The production activator is deliberately absent from default builds and is
supported only with systemd-boot on UEFI. Build with both features and install
`kernaid-fleet-resident-activator` at `/usr/libexec/`.

Provisioning must happen locally and must complete all of these steps before
the activator is enabled:

1. create real, independently bootable A and B system slots and two UKIs;
2. install the supplied entry templates as exactly
   `/boot/loader/entries/kernaid-slot-a.conf` and
   `/boot/loader/entries/kernaid-slot-b.conf`, adjusting only the locally
   provisioned UKI lines and retaining the fixed slot marker;
3. ensure both entries and `/usr/bin/bootctl` are root-owned and not
   group/other writable, then boot each entry manually once;
4. run staging under the same root trust boundary with
   `stateDirectory=/var/lib/kernaid/fleet-resident-update`; every object there
   must remain root-owned and not group/other writable. Use
   `config.ab.example.json` so the fixed kernel slot marker selects only the
   opposite preconfigured UKI target;
5. install `fleet-resident-activator.example.json` as the root-owned
   `/etc/kernaid/fleet-resident-activator.json`;
6. install the `.service` and `.path` units, run `systemctl daemon-reload`, and
   enable both only after the device-specific A/B qualification succeeds.

`kernaid-fleet-resident-update-system.service` is the matching root-scoped
stager unit for the A/B config. Enroll its `resident-v1` identity and Fleet
runtime in that same system identity context before enabling it; do not reuse
the engineering user unit with the root-owned activation journal.

```sh
systemctl enable --now kernaid-fleet-resident-activator.path
systemctl enable kernaid-fleet-resident-activator.service
```

The service persists `prepared` before its first `bootctl` write, leaves the
known-good slot as default, and selects the target only with `set-oneshot`.
After a target boot it promotes that target; after a failed trial it observes
the return to known-good and archives a fallback receipt. It does not reboot.

Local offline rollback after a successful promotion is explicit and takes no
path, entry or slot argument:

```sh
systemctl stop kernaid-fleet-resident-activator.path
systemctl start kernaid-fleet-resident-rollback.service
systemctl start kernaid-fleet-resident-activator.path
```

BIOS/GRUB, a missing or duplicated `kernaid.slot=` marker, mutable/untrusted
state, absent staging receipt, mismatched receipt binding or unqualified entry
causes a closed failure before boot selection. The activator never creates an
entry, changes a kernel command line, restarts a service or reboots the host.
