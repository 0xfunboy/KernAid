# KernAid Fleet Console

Static, same-origin operator console for the Fleet control plane. It provides
tenant-scoped inventory, minimized signed audit history, device revocation and
one-time enrollment without any remote-command surface. Its governance view
shows minimized policy, entitlement and update state and publishes only final
documents already signed by offline issuers.

Serve this directory at `/console/` and the control plane API at the same
origin. To use another origin, set the `kernaid-api-base` meta value and apply a
strict matching CORS policy server-side.

The administrator token is retained in `sessionStorage`, never `localStorage`,
and is not included in URLs or logs. Enrollment tokens are shown once and are
never persisted by the console.

Expected routes:

- `GET /healthz`
- `GET /v1/tenants/:tenantId/devices`
- `GET /v1/tenants/:tenantId/assets`
- `GET /v1/tenants/:tenantId/audit-events`
- `GET /v1/tenants/:tenantId/policies`
- `GET /v1/tenants/:tenantId/entitlements`
- `GET /v1/tenants/:tenantId/update-manifests`
- `POST /v1/tenants/:tenantId/enrollment-tokens`
- `POST /v1/tenants/:tenantId/devices/:deviceId/revoke`
- `POST /v1/tenants/:tenantId/policies`
- `POST /v1/tenants/:tenantId/entitlements`
- `POST /v1/tenants/:tenantId/entitlement-revocations`
- `POST /v1/tenants/:tenantId/update-manifests`

Audit is refreshed concurrently with devices and assets. It shows only the
control plane's bounded event identifiers, state, risk and digest-chain fields;
the browser copies those fields through an explicit allowlist and has no
raw-content view. All dynamic values are rendered with DOM `textContent` and
are never injected as HTML.

Publish inputs are byte-bounded, parsed as strict JSON, checked for secret-key
fields and canonicalized locally before upload. The console never signs,
retains or displays a private key. The control plane performs authoritative
schema, tenant, signature and monotonic-checkpoint verification.
