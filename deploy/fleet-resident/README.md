# Linux Resident deployment

This integration is intentionally off by default.

1. Build with `--features linux-resident` and install the binary at
   `/usr/libexec/kernaid-fleet-resident-sync`.
2. Copy the example config to `~/.config/kernaid/fleet-resident.json`, replace
   every example value, and make the configured state directory mode 0700.
3. Install the three raw Ed25519 public anchors as canonical base64url-no-pad
   files. They are public data but must not be writable by another user.
4. Ask the tenant administrator for a short-lived enrollment token, write only
   that token plus an optional final newline to the configured mode-0600 token
   file, then run the service once with `--initialize-identity --once`.
   This explicit first run creates the non-exportable `resident-v1` identity
   only when it is absent, enrolls it and removes the token only after the
   matching response and durable enrollment commit. Normal service startup
   never creates or replaces an identity. Close Desk first: bootstrap acquires
   the same canonical Resident lock and fails closed while Desk is running.
5. Install the unit in `~/.config/systemd/user/`, run `systemctl --user daemon-reload`,
   and first verify with `systemctl --user start kernaid-fleet-resident-sync`.
   Enable it only after the Fleet endpoint emits signed receipt headers.

The unit assumes the example state-directory location. Change `ReadWritePaths`
when using another absolute directory. Linux Secret Service and its session
bus must be available to the user service. A missing/locked identity, missing
anchor, enrollment mismatch, unsigned success response or state corruption
terminates the cycle without deleting queued work.
