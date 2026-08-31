# KernAid Fleet onboarding wizard

This off-default operator CLI creates a Fleet tenant and a short-lived,
single-use device enrollment bundle without putting a bearer token in shell
arguments, URLs, browser storage, logs, or source control. It uses the existing
Fleet HTTP API and has no shell, remote-command, signing, or device-key surface.

Use exactly Node.js `24.18.0`. The tool is intentionally outside the pnpm
workspace and is never run by the repository's default build or test scripts.

## One-time tenant onboarding

The root token must be in a regular, non-symlink, current-user-owned file with
no group/other permissions. The wizard creates the output directory as `0700`
when needed and refuses symbolic-link traversal or existing output files.

First run the read-only API preflight. It performs `GET /healthz`, validates
the local root-token boundary, and reserves no token or tenant server-side:

```bash
node tools/fleet-onboarding/cli.mjs preflight \
  --endpoint https://fleet.example.com \
  --root-token-file /absolute/private/fleet/root-token \
  --output-dir /absolute/private/tenants/acme
```

Then run the guided operation. Omit `--yes` on a terminal to receive the final
confirmation prompt:

```bash
node tools/fleet-onboarding/cli.mjs onboard \
  --endpoint https://fleet.example.com \
  --root-token-file /absolute/private/fleet/root-token \
  --output-dir /absolute/private/tenants/acme \
  --expires-in 300 \
  --yes
```

The wizard never prints token values. It creates two non-overwriting `0600`
files atomically:

- `tenant-admin.json` stays in the operator secret store. It contains the
  tenant admin credential returned only once by Fleet, but never the root
  token.
- `device-enrollment.json` contains only the canonical Fleet endpoint, tenant
  ID, one-time enrollment token, expiry, and `singleUse: true`. Transfer it to
  exactly one intended device over the organization's protected provisioning
  channel, then remove that transferred copy after successful enrollment.

If token creation fails after tenant creation, the CLI reports only the saved
admin-credential path. The credential remains usable to recover with `token`;
the secret value is never emitted.

## Additional device bundle

Each device receives a distinct short-lived token. Generate another bundle
from the saved tenant admin credential:

```bash
node tools/fleet-onboarding/cli.mjs token \
  --admin-credential-file /absolute/private/tenants/acme/tenant-admin.json \
  --bundle-file /absolute/private/tenants/acme/device-02-enrollment.json \
  --expires-in 300 \
  --yes
```

Enrollment expiry is deliberately bounded to 60-900 seconds even though the
server supports a broader administrative maximum. Remote endpoints require
HTTPS. Plain HTTP is accepted only for the exact `localhost`, `127.0.0.1`, or
`[::1]` loopback host. Redirects fail closed so bearer credentials are never
forwarded to another origin.

## Focused verification

```bash
node tools/fleet-onboarding/cli.mjs --help
node --check tools/fleet-onboarding/cli.mjs
node --test tools/fleet-onboarding/test/onboarding.test.mjs
node tools/fleet-onboarding/verify.mjs
```

The tests use a mocked Fetch transport. They create no tenant on a real Fleet
service and contain no production credential.
