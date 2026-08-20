# Rescue Codex authentication bridge

This crate is the shipping, authentication-only boundary around the exact
Codex CLI pinned by `rescue/codex/codex-cli.lock.json`. It accepts only three
closed operations:

- `device-login` invokes exactly `codex login --device-auth`;
- `status` invokes exactly `codex login status` and returns presence only;
- `logout` invokes exactly `codex logout`.

The socket-activated server runs as the dedicated, non-root `kernaid-codex`
identity. For one request it leases the pre-provisioned Codex home from the
unlocked encrypted Rescue vault, binds the lease to its complete systemd
cgroup, verifies the pinned root-owned executable by descriptor, and gives the
child only that descriptor-backed `CODEX_HOME`. The bridge never opens or
serializes `auth.json`; it validates only its type, ownership, mode, link count,
and size. `TMPDIR=/` activates the pinned CLI's own refusal to create PATH/tool
aliases under `CODEX_HOME`; the read-only system root also cannot become a
fallback temp store. CLI output is reduced to a fixed status vocabulary plus
the one-time device URL/code. Raw stdout, stderr, CLI errors, and credential
bytes never cross the bridge.

While an authentication command is running, the bridge observes client socket
hangup every 25 ms. Client loss terminates the complete CLI process group,
re-attests the leased home, and closes the lease instead of retaining a busy
device-login operation until its 16-minute command deadline.

The live user calls `/usr/bin/kernaid-codex-auth`. No Codex prompt or agent run
is exposed in Phase 0, and neither this client nor the Codex process has access
to the repair broker or target block devices. Real-account device login remains
a human/external qualification gate.
