# KernAid Fleet Resident for macOS

This is a separate, off-default Enterprise component for Intel and Apple
silicon Macs. It is not part of Desk, does not expose a repair surface, and
copying the bundle does not load, enable, or start its LaunchAgent.

## Site-ready multi-architecture bundle

The `fleet-resident-macos` workflow first builds separate Apple-silicon and
Intel development archives. Only after both matrix jobs succeed, a final
fail-closed job downloads them and emits one site publish set:

- `KernAid-Fleet-Resident-macos-multiarch-v<version>-UNSIGNED-UNNOTARIZED.zip`;
- a portable SHA-256 sidecar for that ZIP; and
- a canonical `dev.kernaid.fleet-resident-macos.download.v1` descriptor.

The ZIP contains both architecture-specific `.tar.gz` files, a portable
basename-only SHA-256 sidecar for each, and the canonical
`KernAid-Fleet-Resident-macos.catalog.json` manifest. The catalog schema is
`dev.kernaid.fleet-resident-macos.catalog.v1`; it binds the workspace version,
full source commit, canonical repository, workflow run ID and attempt, exact
filename/architecture/byte count/SHA-256 for both archives, and the explicit
`unsigned-unnotarized` signature state. Canonical JSON is UTF-8 without a
trailing newline, with recursively sorted keys, compact separators and fixed
array order (`aarch64`, then `x86_64`).

The aggregation job requires exactly the two named input artifacts and exactly
one archive plus sidecar in each. It rehashes both outer archives, requires
portable sidecars, validates the complete tar inventory and every inner
`SHA256SUMS` entry, then reopens the deterministic ZIP before upload. Missing,
extra, symlinked, malformed or mismatched input fails the job. The resulting
ZIP is a two-architecture container, not a universal/fat Mach-O binary.

The publish set remains internal. Its checksum and manifest provide integrity
and provenance, not Developer ID authenticity or Apple notarization. The site
must label it unsigned and unnotarized until external signing, notarization and
physical acceptance evidence exist.

## Package and provision

1. Verify the multi-architecture ZIP against its adjacent sidecar, open it and
   select the enclosed archive matching the Mac CPU. Verify that archive with
   its own adjacent sidecar. Files named `UNSIGNED-UNNOTARIZED` are internal
   development inputs only. Do not deploy them to customer machines or bypass
   Gatekeeper.
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
