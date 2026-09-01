# KernAid Fleet Resident for Windows x86-64

This is a separate, off-default Enterprise component. It is not part of Desk,
does not install a repair surface, and installation neither starts the service
nor changes it to automatic start.

## Package and provision

1. Place the code-signed `kernaid-fleet-resident-windows.exe` in an
   administrator-owned, non-user-writable installation directory. Do not run
   the unsigned CI artifact outside development.
2. Copy `config.example.json` to an administrator-owned path under
   `C:\ProgramData\KernAid`. Replace only its public tenant, HTTPS origin,
   absolute state paths and public trust-anchor paths. The JSON accepts no
   token value, command, arguments, script, collector selector or secret.
3. Put a short-lived enrollment token, and only that token plus an optional
   final newline, at `enrollmentTokenFile`. The installer must grant only
   `LocalService` and administrators access. The strict public JSON contains
   the path, never the token.
4. Put the base64url-no-pad Ed25519 public anchors at the configured paths.
   Enrollment refuses to create an identity if any trust anchor is absent or
   malformed. Put the verified Fleet runtime database in place after the
   control plane has issued the signed initial policy and entitlement state.
5. Grant `LocalService` read access to config and anchors, and read/write
   access only to the Resident state directory and
   Fleet runtime database directory. SQLite also needs its adjacent journal
   files. ACL creation belongs to the signed installer/MSI; the Resident never
   shells out to PowerShell or another installer.

## Native service lifecycle

Run these from an elevated terminal, using absolute paths:

```text
kernaid-fleet-resident-windows.exe install --config C:\ProgramData\KernAid\fleet-resident-windows.json
kernaid-fleet-resident-windows.exe enroll
kernaid-fleet-resident-windows.exe start
kernaid-fleet-resident-windows.exe stop
kernaid-fleet-resident-windows.exe uninstall
```

`install` validates the public configuration and registers
`KernAidFleetResidentWindows` as an on-demand `LocalService` process without
starting it. `enroll` is a separate one-shot SCM start: under the exact service
account it takes the Resident locks, creates `resident-v1` only when absent,
signs the HTTPS enrollment, durably binds endpoint/tenant/device, deletes the
token only after that commit, then stops. It never prints or writes the seed.
Normal `start` never creates or enrolls an identity and fails closed without
the exact enrollment journal, public anchors, and signed runtime. For a
pre-service acceptance check under the same provisioned account, use
`run-once --config <absolute-config-path>`.

## Closed execution boundary

The service polls only HTTPS `POST /v1/work-order-claims` and
`POST /v1/work-order-results`, with proxy use and redirects disabled. It admits
only `windows.p0.diagnose.v1@1`, reusing the fixed, bounded Windows P0
collectors. A tenant cannot supply a command, argument, path or raw payload.
Policy and Fleet entitlement are evaluated before the local handoff. State is
durable and idempotent; signed results contain only outcome plus digest, never
raw logs, PII, token, key seed or diagnostic content.

Code signing, MSI ACL validation, SCM lifecycle validation on physical Windows
x86-64, and a real enrolled-device acceptance run are external release gates.

The development workflow now reuses the already assembled unsigned ZIP on a
native Windows runner. In an ephemeral staging directory it verifies the
packaged claim/result contract, registers the service as on-demand
`LocalService`, proves installation did not start it, exercises `run-once`
until the deliberately absent public anchors fail closed, then uses the
product's `uninstall` command and verifies complete SCM and file cleanup. No
enrollment credential, device identity, private key or test signature is
provided; this does not replace the external release gates above.
