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
   token, command, arguments, script, collector selector or secret.
3. Provision the existing enrolled `resident-v1` identity in the native
   Windows secret store for the `LocalService` account. The explicit first
   `start --initialize-identity` option may create that account-bound identity,
   but enrollment and signed runtime bootstrap must still be completed through
   the approved onboarding channel. No seed is printed or written to disk.
4. Put the verified Fleet runtime database and base64url-no-pad Ed25519 public
   anchors at the configured paths. Grant `LocalService` read access to config
   and anchors, and read/write access only to the Resident state directory and
   Fleet runtime database directory. SQLite also needs its adjacent journal
   files. ACL creation belongs to the signed installer/MSI; the Resident never
   shells out to PowerShell or another installer.

## Native service lifecycle

Run these from an elevated terminal, using absolute paths:

```text
kernaid-fleet-resident-windows.exe install --config C:\ProgramData\KernAid\fleet-resident-windows.json
kernaid-fleet-resident-windows.exe start
kernaid-fleet-resident-windows.exe stop
kernaid-fleet-resident-windows.exe uninstall
```

`install` validates the public configuration and registers
`KernAidFleetResidentWindows` as an on-demand `LocalService` process. `start`
is always explicit; there is no auto-run or embedded credential. For a
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
