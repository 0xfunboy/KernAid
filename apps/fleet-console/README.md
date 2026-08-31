# KernAid Fleet Console

Static, same-origin operator console for the Fleet control plane. It provides
tenant-scoped inventory, device revocation and one-time enrollment without any
remote-command surface.

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
- `POST /v1/tenants/:tenantId/enrollment-tokens`
- `POST /v1/tenants/:tenantId/devices/:deviceId/revoke`

All dynamic values are rendered with DOM `textContent`; signed inventory is
never injected as HTML.
