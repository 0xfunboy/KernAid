# KernAid Fleet Console

Static, same-origin operator console for the Fleet control plane. It provides
tenant-scoped inventory, minimized signed audit history, device revocation and
one-time enrollment without any remote-command surface. Its governance view
shows minimized policy, entitlement and update state and publishes only final
documents already signed by offline issuers.

The Work orders view is an operational tenant-scoped surface for a closed,
versioned action catalog. Operators can create diagnostics, administrators can
approve write intents, and either role can cancel an unleased order. There are
no command, argument, path, script or raw-output fields. Policy, entitlement,
lease, minimized result and digest-only transition audit state are visible in
one view.

The Incident cases view opens bounded records from an enrolled device or
observed asset, links compatible typed work orders, tracks severity/status and
an operational team/queue label, and closes a case with a canonical signed
report. It never accepts raw evidence, personal notes, names, email addresses,
commands or arguments. Closure is administrator-only; operators can create,
update and link cases.

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
- `GET /v1/tenants/:tenantId/work-orders`
- `GET /v1/tenants/:tenantId/work-order-events`
- `GET /v1/tenants/:tenantId/incident-cases`
- `GET /v1/tenants/:tenantId/incident-case-events`
- `POST /v1/tenants/:tenantId/enrollment-tokens`
- `POST /v1/tenants/:tenantId/devices/:deviceId/revoke`
- `POST /v1/tenants/:tenantId/policies`
- `POST /v1/tenants/:tenantId/entitlements`
- `POST /v1/tenants/:tenantId/entitlement-revocations`
- `POST /v1/tenants/:tenantId/update-manifests`
- `POST /v1/tenants/:tenantId/work-orders`
- `POST /v1/tenants/:tenantId/work-orders/:workOrderId/approve`
- `POST /v1/tenants/:tenantId/work-orders/:workOrderId/cancel`
- `POST /v1/tenants/:tenantId/incident-cases`
- `POST /v1/tenants/:tenantId/incident-cases/:caseId/update`
- `POST /v1/tenants/:tenantId/incident-cases/:caseId/work-orders`
- `POST /v1/tenants/:tenantId/incident-cases/:caseId/close`

The downloaded incident report is the exact canonical JSON returned at
closure. Its SHA-256 digest is bound to the displayed Ed25519 service receipt;
the console does not modify or re-sign it.

For write actions, tenant administrator approval authorizes delivery only. It
does not replace the independent local Core approval bound to the actual plan,
target and lease. The control plane returns signed claim/result receipts to the
device. The console shows their protocol state but intentionally neither
receives nor retains the raw receipt or device signature.

Audit is refreshed concurrently with devices and assets. It shows only the
control plane's bounded event identifiers, state, risk and digest-chain fields;
the browser copies those fields through an explicit allowlist and has no
raw-content view. All dynamic values are rendered with DOM `textContent` and
are never injected as HTML.

Publish inputs are byte-bounded, parsed as strict JSON, checked for secret-key
fields and canonicalized locally before upload. The console never signs,
retains or displays a private key. The control plane performs authoritative
schema, tenant, signature and monotonic-checkpoint verification.
