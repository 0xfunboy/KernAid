# KernAid Fleet Resident for macOS

This is a separate, off-default Enterprise component for Intel and Apple
silicon Macs. It is not part of Desk, does not expose a repair surface, and
copying the bundle does not load, enable, or start its LaunchAgent.

## Package and provision

1. Select the artifact matching the Mac CPU. CI artifacts named
   `UNSIGNED-UNNOTARIZED` are internal development inputs only. Do not deploy
   them to customer machines or bypass Gatekeeper.
2. After Developer ID signing and notarization, install the binary for the
   enrolled user at the exact absolute path recorded in the plist. Keep its
   directory owner-only and the executable non-writable by other users.
3. Copy `config.example.json` to `config.json`; replace `REPLACE_USER`, the
   public tenant, HTTPS origin, absolute state paths, and public trust-anchor
   paths. The strict JSON accepts no command, arguments, script, collector,
   token, key, or writable target.
4. Provision the existing enrolled `resident-v1` identity in that user's
   native macOS secret store. Provision the signed Fleet runtime and the three
   base64url-no-pad Ed25519 public anchors at the configured paths. The
   Resident never creates, exports, prints, or writes a seed.
5. Keep the Resident state directory `0700`. Keep config and anchors owned by
   the enrolled user and not group/world writable. The runtime directory must
   permit its SQLite journal files but no broader filesystem writes.

Run one acceptance cycle in that user's GUI session before installing the
LaunchAgent:

```sh
"$HOME/Library/Application Support/KernAid/Fleet Resident/kernaid-fleet-resident-macos" \
  --config "$HOME/Library/Application Support/KernAid/Fleet Resident/config.json" \
  --once
```

## Disabled-by-default launchd lifecycle

Replace both `REPLACE_USER` values in the plist with the exact short user name,
validate it with `plutil -lint`, then copy it to:

```text
~/Library/LaunchAgents/io.kernaid.fleet-resident-macos.plist
```

Installation stops there. After site acceptance, the enrolled user may opt in
explicitly:

```sh
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/io.kernaid.fleet-resident-macos.plist"
launchctl enable "gui/$(id -u)/io.kernaid.fleet-resident-macos"
launchctl kickstart "gui/$(id -u)/io.kernaid.fleet-resident-macos"
```

Disable and unload it with:

```sh
launchctl disable "gui/$(id -u)/io.kernaid.fleet-resident-macos"
launchctl bootout "gui/$(id -u)/io.kernaid.fleet-resident-macos"
```

The LaunchAgent is intentional: the bounded launchd diagnostic is qualified
only for the current user domain and the identity is user-bound. Do not convert
this plist into a root LaunchDaemon.

## Closed execution boundary

The service polls only fixed HTTPS claim/result routes with redirects and
proxies disabled. It admits only `macos.p0.diagnose.v1@1` at R0. Native
programs, arguments, environment, deadlines and byte limits are compile-time
constants shared with Desk through `kernaid-macos-pack`; raw output stays in
memory. Durable state and signed Fleet results retain only opaque bindings and
a SHA-256 digest. No FileVault unlock, APFS mutation, `fsck`, snapshot deletion,
update installation, launchd change, NVRAM change, network change, shell, or
caller-selected path is reachable.

Developer ID signing, notarization, LaunchAgent/Keychain acceptance, supported
macOS-version qualification, and physical Intel plus Apple-silicon runs remain
external release gates.
