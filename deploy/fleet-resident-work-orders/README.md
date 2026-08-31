# Fleet Resident typed work-order service

This is a separate, off-default package. It is not part of KernAid Desk and
installation does not enable or start it.

## Install

1. Build with `cargo build --release -p kernaid-fleet-resident-work-orders
   --features linux-service` and install only the resulting binary as
   `/usr/libexec/kernaid-fleet-resident-work-orders`.
2. Install `kernaid-fleet-resident-work-orders.service` in
   `~/.config/systemd/user/` and copy `config.example.json` to
   `~/.config/kernaid/fleet-work-orders.json` with site-specific public values.
3. Keep the work-order state directory owner-only (0700). The runtime state
   file must be the device-bound Fleet runtime already maintained by the
   Resident sync service. Install the three Ed25519 anchors as canonical
   base64url-no-pad public files not writable by another user.
4. Verify once with
   `/usr/libexec/kernaid-fleet-resident-work-orders --config
   ~/.config/kernaid/fleet-work-orders.json --once`.
5. Run `systemctl --user daemon-reload` and start the unit manually. Enable it
   only after site acceptance with `systemctl --user enable
   kernaid-fleet-resident-work-orders.service`.

The packaged service uses the existing `resident-v1` identity from Linux
Secret Service; it never creates or exports an identity. The transport has
only the fixed claim/result endpoints, accepts no bearer token and logs only
fixed status codes. Offline connect/TLS/timeout failures use bounded
exponential backoff while exact signed claim/result bytes remain in the
owner-only protocol journal.

Only the read-only filesystem- and storage-health action IDs are connected.
The systemd process has no repair IPC, shell, arbitrary arguments or target
path surface. Rescue Vault identity and write approval remain in the separate
Rescue application boundary. A future Rescue adapter must load the existing
identity from the encrypted Vault and still pass fresh local approval,
policy, entitlement, target and plan binding through Core/Broker; this Linux
unit cannot provide or bypass those conditions.

The unit permits reads needed by the fixed health collectors and write access
only to its work-order state plus the existing protected Fleet SQLite
directory (SQLite requires its adjacent journal files even for this verified
runtime view). If either location changes, replace the two exact
`ReadWritePaths` entries; do not broaden them or add device capabilities.
