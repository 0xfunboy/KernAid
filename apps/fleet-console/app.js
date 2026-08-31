import { boundedSignedDocument } from "./publish-document.js";
import {
  assertMinimizedIncidentCase,
  canonicalIncidentReport,
  closeIncidentPayload,
  createIncidentPayload,
  incidentOutcomes,
  incidentSeverities,
  incidentStatuses,
  linkIncidentPayload,
  updateIncidentPayload,
} from "./incident-case-ui.js";
import {
  assertMinimizedWorkOrder,
  createWorkOrderPayload,
  workOrderActions,
  workOrderActionsForPlatform,
  workOrderControls,
  workOrderReadiness,
  workOrderReceiptState,
} from "./work-order-ui.js";

const apiBase =
  document
    .querySelector('meta[name="kernaid-api-base"]')
    ?.content.replace(/\/$/, "") ?? "";
const state = {
  tenantId: sessionStorage.getItem("kernaid.fleet.tenant") ?? "",
  token: sessionStorage.getItem("kernaid.fleet.admin-token") ?? "",
  devices: [],
  assets: [],
  auditEvents: [],
  auditError: "",
  policies: [],
  policyAnchorConfigured: false,
  entitlements: [],
  entitlementRevocations: null,
  updates: [],
  governanceError: "",
  workOrders: [],
  workOrderEvents: [],
  workOrderError: "",
  incidents: [],
  incidentEvents: [],
  incidentError: "",
  activeIncident: null,
  view: "overview",
};

const publishKinds = {
  policy: {
    title: "Publish signed policy",
    copy: "The tenant binding, revision and offline policy signature are verified by the control plane.",
    path: "policies",
    maximumBytes: 1024 * 1024,
    schema: "dev.kernaid.fleet.policy-bundle.v1",
    tenantPath: ["tenantId"],
  },
  entitlement: {
    title: "Publish signed entitlement",
    copy: "Only a final entitlement envelope produced by the offline commercial issuer is accepted.",
    path: "entitlements",
    maximumBytes: 64 * 1024,
    schema: "dev.kernaid.entitlement.v1",
    tenantPath: ["claims", "tenantId"],
    schemaPath: ["claims", "schema"],
  },
  revocations: {
    title: "Publish revocation checkpoint",
    copy: "Revocation sequence rollback and same-sequence substitution fail closed.",
    path: "entitlement-revocations",
    maximumBytes: 64 * 1024,
    schema: "dev.kernaid.entitlement-revocations.v1",
    schemaPath: ["claims", "schema"],
  },
  update: {
    title: "Publish signed update manifest",
    copy: "Fleet distributes vendor-signed metadata only. Devices still verify, admit and stage the artifact independently.",
    path: "update-manifests",
    maximumBytes: 64 * 1024,
    schema: "dev.kernaid.update.manifest.v1",
  },
};
let activePublishKind = null;

const elements = {
  login: document.querySelector("#login-dialog"),
  loginForm: document.querySelector("#login-form"),
  loginError: document.querySelector("#login-error"),
  tenantInput: document.querySelector("#tenant-input"),
  tokenInput: document.querySelector("#token-input"),
  enrollment: document.querySelector("#enrollment-dialog"),
  enrollmentClose: document.querySelector("#enrollment-close"),
  enrollmentForm: document.querySelector("#enrollment-form"),
  enrollmentError: document.querySelector("#enrollment-error"),
  tokenResult: document.querySelector("#token-result"),
  enrollmentToken: document.querySelector("#enrollment-token"),
  tokenExpiry: document.querySelector("#token-expiry"),
  copyToken: document.querySelector("#copy-token"),
  deviceRows: document.querySelector("#device-rows"),
  assetRows: document.querySelector("#asset-rows"),
  auditRows: document.querySelector("#audit-rows"),
  deviceFilter: document.querySelector("#device-filter"),
  assetFilter: document.querySelector("#asset-filter"),
  auditFilter: document.querySelector("#audit-filter"),
  auditEmpty: document.querySelector("#audit-empty"),
  auditError: document.querySelector("#audit-error"),
  auditErrorMessage: document.querySelector("#audit-error-message"),
  governanceError: document.querySelector("#governance-error"),
  policyStatusList: document.querySelector("#policy-status-list"),
  entitlementStatusList: document.querySelector("#entitlement-status-list"),
  updateStatusList: document.querySelector("#update-status-list"),
  workOrderRows: document.querySelector("#work-order-rows"),
  workOrderEvents: document.querySelector("#work-order-events"),
  workOrderFilter: document.querySelector("#work-order-filter"),
  workOrderError: document.querySelector("#work-order-error"),
  workOrderDialog: document.querySelector("#work-order-dialog"),
  workOrderForm: document.querySelector("#work-order-form"),
  workOrderFormError: document.querySelector("#work-order-form-error"),
  workOrderDevice: document.querySelector("#work-order-device"),
  workOrderAction: document.querySelector("#work-order-action"),
  workOrderLifetime: document.querySelector("#work-order-lifetime"),
  workOrderSubmit: document.querySelector("#work-order-submit"),
  workOrderApprovalWarning: document.querySelector(
    "#work-order-approval-warning",
  ),
  incidentRows: document.querySelector("#incident-rows"),
  incidentEvents: document.querySelector("#incident-events"),
  incidentFilter: document.querySelector("#incident-filter"),
  incidentError: document.querySelector("#incident-error"),
  incidentDialog: document.querySelector("#incident-dialog"),
  incidentForm: document.querySelector("#incident-form"),
  incidentFormError: document.querySelector("#incident-form-error"),
  incidentSource: document.querySelector("#incident-source"),
  incidentSeverity: document.querySelector("#incident-severity"),
  incidentAssignee: document.querySelector("#incident-assignee"),
  incidentUpdateDialog: document.querySelector("#incident-update-dialog"),
  incidentUpdateForm: document.querySelector("#incident-update-form"),
  incidentUpdateError: document.querySelector("#incident-update-error"),
  incidentUpdateStatus: document.querySelector("#incident-update-status"),
  incidentUpdateSeverity: document.querySelector("#incident-update-severity"),
  incidentUpdateAssignee: document.querySelector("#incident-update-assignee"),
  incidentLinkDialog: document.querySelector("#incident-link-dialog"),
  incidentLinkForm: document.querySelector("#incident-link-form"),
  incidentLinkError: document.querySelector("#incident-link-error"),
  incidentLinkOrder: document.querySelector("#incident-link-order"),
  incidentCloseDialog: document.querySelector("#incident-close-dialog"),
  incidentCloseForm: document.querySelector("#incident-close-form"),
  incidentCloseError: document.querySelector("#incident-close-error"),
  incidentOutcome: document.querySelector("#incident-outcome"),
  publish: document.querySelector("#publish-dialog"),
  publishClose: document.querySelector("#publish-close"),
  publishForm: document.querySelector("#publish-form"),
  publishTitle: document.querySelector("#publish-title"),
  publishCopy: document.querySelector("#publish-copy"),
  publishDocument: document.querySelector("#publish-document"),
  publishLimit: document.querySelector("#publish-limit"),
  publishError: document.querySelector("#publish-error"),
  toast: document.querySelector("#toast"),
};

function text(tag, value, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value ?? "—";
  return node;
}

function cell(...children) {
  const node = document.createElement("td");
  node.append(...children);
  return node;
}

function short(value, head = 8) {
  if (typeof value !== "string" || value.length <= head + 5)
    return value ?? "—";
  return `${value.slice(0, head)}…${value.slice(-4)}`;
}

function date(value) {
  if (!value) return "Never";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf())
    ? "Unknown"
    : new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(parsed);
}

function setBusy(button, busy) {
  button.disabled = busy;
  button.setAttribute("aria-busy", String(busy));
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12_000);
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  if (options.body) headers.set("Content-Type", "application/json");
  try {
    const response = await fetch(`${apiBase}${path}`, {
      ...options,
      headers,
      signal: controller.signal,
      cache: "no-store",
      credentials: "same-origin",
    });
    const contentType = response.headers.get("content-type") ?? "";
    const payload = contentType.includes("application/json")
      ? await response.json()
      : null;
    if (!response.ok) {
      const code =
        typeof payload?.error === "string" ? payload.error : undefined;
      const error = new Error(
        friendlyApiError(code, response.status) ??
          payload?.error?.message ??
          payload?.message ??
          `Request failed (${response.status})`,
      );
      error.status = response.status;
      error.code = code;
      throw error;
    }
    return payload;
  } finally {
    clearTimeout(timer);
  }
}

function friendlyApiError(code, status) {
  const messages = {
    invalid_request:
      "The document is not a closed canonical Fleet document. Check its schema and fields.",
    invalid_signature:
      "Signature verification failed. Publish the untouched document from the offline issuer.",
    tenant_mismatch: "The signed document belongs to another tenant.",
    policy_trust_anchor_not_set:
      "Configure the tenant policy public anchor before publishing a policy.",
    policy_revision_rollback:
      "Policy revision rejected: a newer revision is already active.",
    policy_revision_conflict:
      "Policy revision rejected: that revision already contains different bytes.",
    entitlement_sequence_rollback:
      "Entitlement sequence rejected: a newer checkpoint already exists.",
    entitlement_sequence_conflict:
      "Entitlement sequence rejected: that sequence already contains different bytes.",
    update_sequence_rollback:
      "Update sequence rejected: a newer vendor manifest already exists.",
    update_sequence_conflict:
      "Update sequence rejected: that sequence already contains different bytes.",
    unsupported_action: "That typed action is not supported by this server.",
    unsupported_action_version:
      "The selected action version is not supported by this server.",
    invalid_work_order_expiry: "Choose a work-order lifetime up to seven days.",
    target_not_found: "The selected device is no longer enrolled.",
    action_platform_mismatch:
      "The selected action is not available on that device runtime.",
    work_order_not_authorized:
      "Signed policy or entitlement does not authorize this action for the selected device.",
    work_order_state_conflict:
      "The work order changed state. Refresh and try again.",
    incident_case_replay:
      "That request identifier already belongs to a different case.",
    incident_case_state_conflict:
      "The incident changed state. Refresh and try again.",
    incident_case_source_not_found:
      "The selected device or asset is no longer available.",
    incident_case_mismatch: "The incident identifier does not match the path.",
    device_revoked: "The selected device has been revoked.",
  };
  if (code && messages[code]) return messages[code];
  if (status === 401 || status === 403)
    return "This tenant session is not authorized for the request.";
  if (status === 413) return "The signed document exceeds its size limit.";
  return undefined;
}

async function health() {
  try {
    await request("/healthz");
    document.querySelector("#connection-dot").classList.add("online");
    document.querySelector("#connection-label").textContent = "Operational";
  } catch {
    document.querySelector("#connection-dot").classList.remove("online");
    document.querySelector("#connection-label").textContent = "Unavailable";
  }
}

function items(payload) {
  return Array.isArray(payload?.items) ? payload.items : [];
}

function auditItems(payload) {
  return items(payload)
    .filter(
      (event) =>
        event !== null && typeof event === "object" && !Array.isArray(event),
    )
    .map((event) => ({
      deviceId: event.deviceId,
      sessionId: event.sessionId,
      eventId: event.eventId,
      sequence: event.sequence,
      previousEventSha256: event.previousEventSha256,
      eventSha256: event.eventSha256,
      occurredAt: event.occurredAt,
      receivedAt: event.receivedAt,
      kind: event.kind,
      outcome: event.outcome,
      risk: event.risk,
      actionId: event.actionId,
    }));
}

function workOrderItems(payload) {
  return items(payload)
    .filter(
      (order) =>
        order !== null && typeof order === "object" && !Array.isArray(order),
    )
    .map((order) => assertMinimizedWorkOrder(order));
}

function workOrderEventItems(payload) {
  return items(payload)
    .filter(
      (event) =>
        event !== null && typeof event === "object" && !Array.isArray(event),
    )
    .map((event) => ({
      tenantId: event.tenantId,
      sequence: event.sequence,
      workOrderId: event.workOrderId,
      occurredAt: event.occurredAt,
      kind: event.kind,
      actorType: event.actorType,
      actorId: event.actorId,
      status: event.status,
      detailSha256: event.detailSha256,
    }));
}

function incidentItems(payload) {
  return items(payload)
    .filter(
      (incident) =>
        incident !== null &&
        typeof incident === "object" &&
        !Array.isArray(incident),
    )
    .map((incident) => assertMinimizedIncidentCase(incident));
}

function incidentEventItems(payload) {
  return items(payload)
    .filter(
      (event) =>
        event !== null && typeof event === "object" && !Array.isArray(event),
    )
    .map((event) => ({
      tenantId: event.tenantId,
      sequence: event.sequence,
      caseId: event.caseId,
      occurredAt: event.occurredAt,
      kind: event.kind,
      actorType: event.actorType,
      actorId: event.actorId,
      status: event.status,
      detailSha256: event.detailSha256,
    }));
}

async function loadFleet() {
  if (!state.tenantId || !state.token) return false;
  const encodedTenant = encodeURIComponent(state.tenantId);
  const [
    devicesResult,
    assetsResult,
    auditResult,
    policiesResult,
    entitlementsResult,
    updatesResult,
    workOrdersResult,
    workOrderEventsResult,
    incidentsResult,
    incidentEventsResult,
  ] = await Promise.allSettled([
    request(`/v1/tenants/${encodedTenant}/devices`),
    request(`/v1/tenants/${encodedTenant}/assets`),
    request(`/v1/tenants/${encodedTenant}/audit-events`),
    request(`/v1/tenants/${encodedTenant}/policies`),
    request(`/v1/tenants/${encodedTenant}/entitlements`),
    request(`/v1/tenants/${encodedTenant}/update-manifests`),
    request(`/v1/tenants/${encodedTenant}/work-orders`),
    request(`/v1/tenants/${encodedTenant}/work-order-events`),
    request(`/v1/tenants/${encodedTenant}/incident-cases`),
    request(`/v1/tenants/${encodedTenant}/incident-case-events`),
  ]);
  if (devicesResult.status === "rejected") throw devicesResult.reason;
  if (assetsResult.status === "rejected") throw assetsResult.reason;
  for (const result of [
    auditResult,
    policiesResult,
    entitlementsResult,
    updatesResult,
    workOrdersResult,
    workOrderEventsResult,
    incidentsResult,
    incidentEventsResult,
  ]) {
    if (
      result.status === "rejected" &&
      [401, 403].includes(result.reason?.status)
    ) {
      throw result.reason;
    }
  }

  state.devices = items(devicesResult.value);
  state.assets = items(assetsResult.value);
  state.auditEvents =
    auditResult.status === "fulfilled" ? auditItems(auditResult.value) : [];
  state.auditError =
    auditResult.status === "rejected"
      ? auditErrorMessage(auditResult.reason)
      : "";
  state.policies =
    policiesResult.status === "fulfilled" ? items(policiesResult.value) : [];
  state.policyAnchorConfigured =
    policiesResult.status === "fulfilled" &&
    policiesResult.value?.trustAnchorConfigured === true;
  state.entitlements =
    entitlementsResult.status === "fulfilled"
      ? items(entitlementsResult.value)
      : [];
  state.entitlementRevocations =
    entitlementsResult.status === "fulfilled"
      ? (entitlementsResult.value?.revocations ?? null)
      : null;
  state.updates =
    updatesResult.status === "fulfilled" ? items(updatesResult.value) : [];
  try {
    state.workOrders =
      workOrdersResult.status === "fulfilled"
        ? workOrderItems(workOrdersResult.value)
        : [];
    state.workOrderEvents =
      workOrderEventsResult.status === "fulfilled"
        ? workOrderEventItems(workOrderEventsResult.value)
        : [];
    state.workOrderError = workOrderErrorMessage([
      workOrdersResult,
      workOrderEventsResult,
    ]);
  } catch {
    state.workOrders = [];
    state.workOrderEvents = [];
    state.workOrderError =
      "Work-order data violated the minimized console boundary.";
  }
  try {
    state.incidents =
      incidentsResult.status === "fulfilled"
        ? incidentItems(incidentsResult.value)
        : [];
    state.incidentEvents =
      incidentEventsResult.status === "fulfilled"
        ? incidentEventItems(incidentEventsResult.value)
        : [];
    state.incidentError = incidentErrorMessage([
      incidentsResult,
      incidentEventsResult,
    ]);
  } catch {
    state.incidents = [];
    state.incidentEvents = [];
    state.incidentError =
      "Incident data violated the digest-only console boundary.";
  }
  state.governanceError = governanceErrorMessage([
    policiesResult,
    entitlementsResult,
    updatesResult,
  ]);
  render();
  return (
    state.auditError === "" &&
    state.governanceError === "" &&
    state.workOrderError === "" &&
    state.incidentError === ""
  );
}

function auditErrorMessage(error) {
  if (error?.status === 404) {
    return "This control plane does not expose the tenant audit endpoint yet.";
  }
  return "Signed audit events could not be loaded. Refresh to retry.";
}

function governanceErrorMessage(results) {
  const failed = results.filter((result) => result.status === "rejected");
  if (failed.length === 0) return "";
  if (failed.every((result) => result.reason?.status === 404)) {
    return "Governance status is unavailable on this control-plane version.";
  }
  return "One or more governance domains could not be loaded. Refresh to retry.";
}

function workOrderErrorMessage(results) {
  const failed = results.filter((result) => result.status === "rejected");
  if (failed.length === 0) return "";
  if (failed.every((result) => result.reason?.status === 404)) {
    return "Work orders are unavailable on this control-plane version.";
  }
  return "Work-order state could not be loaded. Refresh to retry.";
}

function incidentErrorMessage(results) {
  const failed = results.filter((result) => result.status === "rejected");
  if (failed.length === 0) return "";
  if (failed.every((result) => result.reason?.status === 404)) {
    return "Incident cases are unavailable on this control-plane version.";
  }
  return "Incident case state could not be loaded. Refresh to retry.";
}

function render() {
  document.querySelector("#tenant-chip").textContent =
    state.tenantId || "No tenant";
  document.querySelector("#metric-devices").textContent = String(
    state.devices.length,
  );
  document.querySelector("#metric-assets").textContent = String(
    state.assets.length,
  );
  const revoked = state.devices.filter(
    (device) => device.status === "revoked",
  ).length;
  const attention = state.assets.filter((asset) =>
    ["attention", "required_action"].includes(asset.health),
  ).length;
  document.querySelector("#metric-revoked").textContent = String(revoked);
  document.querySelector("#metric-attention").textContent = String(attention);
  document.querySelector("#metric-devices-detail").textContent =
    `${state.devices.length - revoked} active identities`;
  renderDevices();
  renderAssets();
  renderAudit();
  renderGovernance();
  renderWorkOrders();
  renderIncidents();
  applyView();
}

function renderDevices() {
  const query = elements.deviceFilter.value.trim().toLowerCase();
  const devices = state.devices.filter((device) =>
    JSON.stringify([device.deviceId, device.platform, device.agentVersion])
      .toLowerCase()
      .includes(query),
  );
  elements.deviceRows.replaceChildren();
  for (const device of devices) {
    const row = document.createElement("tr");
    const identity = document.createElement("span");
    identity.append(
      text("strong", device.displayName || short(device.deviceId)),
      text("small", short(device.deviceId, 12)),
    );
    const status = text(
      "span",
      device.status ?? "active",
      `status ${device.status ?? "active"}`,
    );
    const action = document.createElement("button");
    action.className = "row-action";
    action.type = "button";
    action.textContent = device.status === "revoked" ? "Revoked" : "Revoke";
    action.disabled = device.status === "revoked";
    action.addEventListener("click", () => revokeDevice(device.deviceId));
    row.append(
      cell(identity),
      cell(
        text("strong", device.platform ?? "unknown"),
        text("small", device.agentVersion ?? "—"),
      ),
      cell(text("span", String(device.lastSequence ?? 0))),
      cell(text("span", date(device.lastSeenAt ?? device.enrolledAt))),
      cell(status),
      cell(action),
    );
    elements.deviceRows.append(row);
  }
  document.querySelector("#devices-empty").hidden = devices.length !== 0;
  elements.deviceRows.closest("table").hidden = devices.length === 0;
}

function renderAssets() {
  const query = elements.assetFilter.value.trim().toLowerCase();
  const assets = state.assets.filter((asset) =>
    JSON.stringify([
      asset.assetId,
      asset.platform,
      asset.osRelease,
      asset.deviceId,
    ])
      .toLowerCase()
      .includes(query),
  );
  elements.assetRows.replaceChildren();
  for (const asset of assets) {
    const row = document.createElement("tr");
    const findingCount = Object.values(asset.findingCounts ?? {}).reduce(
      (total, value) => total + (Number(value) || 0),
      0,
    );
    row.append(
      cell(
        text("strong", asset.assetId),
        text("small", short(asset.targetFingerprint, 12)),
      ),
      cell(
        text("strong", asset.platform ?? "unknown"),
        text(
          "small",
          [asset.architecture, asset.osRelease].filter(Boolean).join(" · "),
        ),
      ),
      cell(
        text(
          "span",
          String(asset.health ?? "unknown").replaceAll("_", " "),
          `status ${asset.health ?? "unknown"}`,
        ),
      ),
      cell(text("span", String(findingCount))),
      cell(text("span", date(asset.observedAt))),
      cell(text("span", short(asset.deviceId, 9))),
    );
    elements.assetRows.append(row);
  }
  document.querySelector("#assets-empty").hidden = assets.length !== 0;
  elements.assetRows.closest("table").hidden = assets.length === 0;
}

function renderAudit() {
  const query = elements.auditFilter.value.trim().toLowerCase();
  const events = state.auditEvents.filter((event) =>
    JSON.stringify([
      event.eventId,
      event.kind,
      event.outcome,
      event.risk,
      event.actionId,
      event.deviceId,
      event.sessionId,
    ])
      .toLowerCase()
      .includes(query),
  );
  elements.auditRows.replaceChildren();
  for (const event of events) {
    const row = document.createElement("tr");
    row.append(
      cell(
        text("strong", date(event.occurredAt)),
        text("small", `Received ${date(event.receivedAt)}`),
      ),
      cell(
        text("strong", String(event.kind ?? "unknown").replaceAll("_", " ")),
        text("small", short(event.eventId, 15)),
      ),
      cell(
        text("strong", short(event.deviceId, 12)),
        text("small", short(event.sessionId, 15)),
      ),
      cell(
        text(
          "span",
          String(event.outcome ?? "unknown"),
          `status audit-outcome ${event.outcome ?? "unknown"}`,
        ),
      ),
      cell(
        text("strong", event.risk ?? "No risk"),
        text("small", event.actionId ? short(event.actionId, 15) : "No action"),
      ),
      cell(
        text(
          "strong",
          `#${event.sequence ?? "—"} · ${short(event.eventSha256, 10)}`,
        ),
        text(
          "small",
          event.previousEventSha256
            ? `Prev ${short(event.previousEventSha256, 10)}`
            : "Chain origin",
        ),
      ),
    );
    elements.auditRows.append(row);
  }

  const failed = state.auditError !== "";
  elements.auditError.hidden = !failed;
  elements.auditErrorMessage.textContent = state.auditError;
  elements.auditEmpty.hidden = failed || events.length !== 0;
  elements.auditRows.closest("table").hidden = failed || events.length === 0;
}

function renderGovernance() {
  elements.governanceError.hidden = state.governanceError === "";
  elements.governanceError.textContent = state.governanceError;

  document.querySelector("#policy-count").textContent = String(
    state.policies.length,
  );
  const anchorState = document.querySelector("#policy-anchor-state");
  anchorState.textContent = state.policyAnchorConfigured
    ? "Anchor configured"
    : "Anchor required";
  anchorState.className = `domain-state ${state.policyAnchorConfigured ? "ready" : "missing"}`;
  renderDocumentList(
    elements.policyStatusList,
    state.policies,
    (policy) => ({
      title: policy.policyId ?? "Unknown policy",
      detail: [
        policy.maxRisk,
        policy.updateRing,
        policy.assignmentScope === "all"
          ? "all devices"
          : `${policy.assignedDeviceCount ?? 0} devices`,
        lifecycle(policy.expiresAtUnix),
      ]
        .filter(Boolean)
        .join(" · "),
      sequence: `r${policy.revision ?? "—"}`,
    }),
    "No policy published",
  );

  document.querySelector("#entitlement-count").textContent = String(
    state.entitlements.length,
  );
  const entitlementState = document.querySelector("#entitlement-state");
  entitlementState.textContent =
    state.entitlements.length === 0 ? "No entitlement" : "Issuer verified";
  entitlementState.className = `domain-state ${state.entitlements.length === 0 ? "missing" : "ready"}`;
  document.querySelector("#revocation-state").textContent =
    state.entitlementRevocations === null
      ? "No revocation checkpoint"
      : `Revocations seq ${state.entitlementRevocations.sequence} · ${state.entitlementRevocations.revokedCount} IDs`;
  renderDocumentList(
    elements.entitlementStatusList,
    state.entitlements,
    (entitlement) => ({
      title: entitlement.entitlementId ?? "Unknown entitlement",
      detail: [
        entitlement.plan,
        `${entitlement.assignedDeviceCount ?? 0}/${entitlement.maxToolDevices ?? 0} devices`,
        lifecycle(entitlement.graceUntilUnix),
      ]
        .filter(Boolean)
        .join(" · "),
      sequence: `s${entitlement.sequence ?? "—"}`,
    }),
    "No entitlement published",
  );

  document.querySelector("#update-count").textContent = String(
    state.updates.length,
  );
  renderDocumentList(
    elements.updateStatusList,
    state.updates,
    (update) => ({
      title: `${update.releaseVersion ?? update.releaseId ?? "Unknown release"}`,
      detail: [
        update.platform,
        update.architecture,
        update.releaseRing,
        update.emergencyRollback ? "rollback" : lifecycle(update.expiresAtUnix),
      ]
        .filter(Boolean)
        .join(" · "),
      sequence: `s${update.sequence ?? "—"}`,
    }),
    "No update manifest published",
  );
}

function renderWorkOrders() {
  const query = elements.workOrderFilter.value.trim().toLowerCase();
  const orders = state.workOrders.filter((order) =>
    JSON.stringify([
      order.workOrderId,
      order.requestId,
      order.targetDeviceId,
      order.actionId,
      order.status,
      order.kind,
      order.risk,
    ])
      .toLowerCase()
      .includes(query),
  );

  elements.workOrderError.hidden = state.workOrderError === "";
  elements.workOrderError.textContent = state.workOrderError;
  document.querySelector("#work-order-policy-state").textContent =
    state.policies.length === 0
      ? "No published candidate"
      : `${state.policies.length} signed candidate${state.policies.length === 1 ? "" : "s"}`;
  document.querySelector("#work-order-entitlement-state").textContent =
    state.entitlements.length === 0
      ? "No published candidate"
      : `${state.entitlements.length} issuer-verified candidate${state.entitlements.length === 1 ? "" : "s"}`;

  for (const [status, metric] of [
    ["pending_approval", "#wo-pending"],
    ["queued", "#wo-queued"],
    ["leased", "#wo-leased"],
    ["succeeded", "#wo-completed"],
  ]) {
    document.querySelector(metric).textContent = String(
      state.workOrders.filter((order) => order.status === status).length,
    );
  }

  elements.workOrderRows.replaceChildren();
  for (const order of orders) {
    const row = document.createElement("tr");
    const action = workOrderActions[order.actionId];
    const approval = order.approval;
    const lease = order.lease;
    const result = order.result;
    const controls = workOrderControls(order);
    const actions = document.createElement("div");
    actions.className = "work-order-actions";

    if (controls.canApprove) {
      actions.append(
        workOrderActionButton("Approve", "approve", () =>
          approveWorkOrder(order),
        ),
      );
    }
    if (controls.canCancel) {
      actions.append(
        workOrderActionButton("Cancel", "cancel", () => cancelWorkOrder(order)),
      );
    }
    if (!controls.canApprove && !controls.canCancel) {
      actions.append(text("span", "Locked", "work-order-locked"));
    }

    const receipt = text(
      "small",
      workOrderReceiptState(order),
      "receipt-state",
    );
    receipt.title =
      "The signed service receipt is delivered to the device and is not exposed or retained by this console.";

    row.append(
      cell(
        text("strong", action?.label ?? order.actionId),
        text(
          "small",
          `${order.actionId} · v${order.actionVersion ?? "—"} · ${short(order.targetDeviceId, 12)}`,
        ),
      ),
      cell(
        text(
          "span",
          String(order.status).replaceAll("_", " "),
          `status ${order.status}`,
        ),
        text("small", `${order.kind} · ${order.risk}`),
      ),
      cell(
        text(
          "strong",
          approval
            ? "Approved"
            : order.localApprovalRequired
              ? "Admin required"
              : "Not required",
        ),
        text(
          "small",
          approval
            ? `${short(approval.approvedByCredentialId, 12)} · ${date(approval.approvedAt)}`
            : order.localApprovalRequired
              ? "Delivery remains blocked"
              : "Read-only action",
        ),
      ),
      cell(
        text("strong", lease ? short(lease.leaseId, 12) : "Not leased"),
        text(
          "small",
          lease
            ? `${date(lease.leasedAt)} → ${date(lease.leaseExpiresAt)}`
            : "Awaiting device claim",
        ),
      ),
      cell(
        text("strong", result?.outcome ?? "No result"),
        text(
          "small",
          result
            ? `${short(result.resultSha256, 12)} · ${date(result.completedAt)}`
            : "Digest pending",
        ),
        receipt,
      ),
      cell(
        text("strong", date(order.expiresAt)),
        text("small", `Created ${date(order.createdAt)}`),
      ),
      cell(actions),
    );
    elements.workOrderRows.append(row);
  }

  const failed = state.workOrderError !== "";
  document.querySelector("#work-orders-empty").hidden =
    failed || orders.length !== 0;
  elements.workOrderRows.closest("table").hidden =
    failed || orders.length === 0;
  renderWorkOrderEvents(query);
}

function renderWorkOrderEvents(query) {
  const events = state.workOrderEvents.filter((event) =>
    JSON.stringify([
      event.workOrderId,
      event.kind,
      event.actorType,
      event.actorId,
      event.status,
    ])
      .toLowerCase()
      .includes(query),
  );
  elements.workOrderEvents.replaceChildren();
  for (const event of events.slice(0, 80)) {
    const node = document.createElement("article");
    node.className = "work-order-event";
    node.append(
      text("span", `#${event.sequence ?? "—"}`, "event-sequence"),
      text("strong", String(event.kind ?? "unknown").replaceAll("_", " ")),
      text(
        "small",
        `${short(event.workOrderId, 13)} · ${event.actorType ?? "unknown"} ${short(event.actorId, 10)}`,
      ),
      text("span", String(event.status ?? "unknown").replaceAll("_", " ")),
      text("small", date(event.occurredAt)),
      text(
        "code",
        event.detailSha256 ? short(event.detailSha256, 15) : "No detail digest",
      ),
    );
    elements.workOrderEvents.append(node);
  }
  document.querySelector("#work-order-events-empty").hidden =
    state.workOrderError !== "" || events.length !== 0;
}

function renderIncidents() {
  const query = elements.incidentFilter.value.trim().toLowerCase();
  const incidents = state.incidents.filter((incident) =>
    JSON.stringify([
      incident.caseId,
      incident.source.deviceId,
      incident.source.assetId,
      incident.severity,
      incident.status,
      incident.assigneeLabel,
      incident.closure?.outcome,
    ])
      .toLowerCase()
      .includes(query),
  );

  elements.incidentError.hidden = state.incidentError === "";
  elements.incidentError.textContent = state.incidentError;
  for (const [selector, count] of [
    [
      "#incident-open",
      state.incidents.filter((item) => item.status === "open"),
    ],
    [
      "#incident-active",
      state.incidents.filter((item) =>
        ["investigating", "monitoring"].includes(item.status),
      ),
    ],
    [
      "#incident-critical",
      state.incidents.filter(
        (item) => item.severity === "critical" && item.status !== "closed",
      ),
    ],
    [
      "#incident-closed",
      state.incidents.filter((item) => item.status === "closed"),
    ],
  ]) {
    document.querySelector(selector).textContent = String(count.length);
  }

  elements.incidentRows.replaceChildren();
  for (const incident of incidents) {
    const row = document.createElement("tr");
    const sourceId = incident.source.deviceId ?? incident.source.assetId;
    const sourceKind = incident.source.deviceId ? "device" : "asset";
    const linked = document.createElement("div");
    linked.className = "incident-links";
    if (incident.workOrders.length === 0) {
      linked.append(text("small", "No linked work orders"));
    } else {
      for (const order of incident.workOrders.slice(0, 4)) {
        linked.append(
          text(
            "strong",
            `${workOrderActions[order.actionId]?.label ?? order.actionId} · ${String(order.status).replaceAll("_", " ")}`,
          ),
          text(
            "code",
            `state ${short(order.stateSha256, 13)}${order.resultSha256 ? ` · result ${short(order.resultSha256, 13)}` : ""}`,
          ),
        );
      }
    }

    const closure = document.createElement("div");
    closure.className = "incident-closure";
    if (incident.closure) {
      closure.append(
        text("strong", incident.closure.outcome.replaceAll("_", " ")),
        text("code", `report ${short(incident.closure.reportSha256, 14)}`),
        text(
          "code",
          `receipt #${incident.closure.serviceReceipt.sequence} · ${short(incident.closure.serviceReceipt.signature, 14)}`,
        ),
      );
      const download = workOrderActionButton(
        "Download report",
        "download",
        () => downloadIncidentReport(incident),
      );
      closure.append(download);
    } else {
      closure.append(text("small", "Open — no final report"));
    }

    const actions = document.createElement("div");
    actions.className = "work-order-actions";
    if (incident.status !== "closed") {
      actions.append(
        workOrderActionButton("Update", "update", () =>
          openIncidentUpdate(incident),
        ),
        workOrderActionButton("Link order", "link", () =>
          openIncidentLink(incident),
        ),
        workOrderActionButton("Close", "approve", () =>
          openIncidentClose(incident),
        ),
      );
    } else {
      actions.append(text("span", "Sealed", "work-order-locked"));
    }

    row.append(
      cell(
        text("strong", incident.caseId),
        text("small", `${sourceKind} · ${short(sourceId, 18)}`),
      ),
      cell(
        text("span", incident.severity, `severity ${incident.severity}`),
        text(
          "small",
          String(incident.status).replaceAll("_", " "),
          `status ${incident.status}`,
        ),
      ),
      cell(
        text("strong", incident.assigneeLabel ?? "Unassigned"),
        text("small", `Updated ${date(incident.updatedAt)}`),
      ),
      cell(linked),
      cell(closure),
      cell(actions),
    );
    elements.incidentRows.append(row);
  }

  const failed = state.incidentError !== "";
  document.querySelector("#incidents-empty").hidden =
    failed || incidents.length !== 0;
  elements.incidentRows.closest("table").hidden =
    failed || incidents.length === 0;
  renderIncidentEvents(query);
}

function renderIncidentEvents(query) {
  const events = state.incidentEvents.filter((event) =>
    JSON.stringify([
      event.caseId,
      event.kind,
      event.actorType,
      event.actorId,
      event.status,
    ])
      .toLowerCase()
      .includes(query),
  );
  elements.incidentEvents.replaceChildren();
  for (const event of events.slice(0, 80)) {
    const node = document.createElement("article");
    node.className = "work-order-event incident-event";
    node.append(
      text("span", `#${event.sequence ?? "—"}`, "event-sequence"),
      text("strong", String(event.kind ?? "unknown").replaceAll("_", " ")),
      text(
        "small",
        `${short(event.caseId, 13)} · ${event.actorType ?? "unknown"} ${short(event.actorId, 10)}`,
      ),
      text("span", String(event.status ?? "unknown").replaceAll("_", " ")),
      text("small", date(event.occurredAt)),
      text("code", `detail ${short(event.detailSha256, 15)}`),
    );
    elements.incidentEvents.append(node);
  }
  document.querySelector("#incident-events-empty").hidden =
    state.incidentError !== "" || events.length !== 0;
}

function downloadIncidentReport(incident) {
  const canonical = canonicalIncidentReport(incident.closure.report);
  const blob = new Blob([canonical], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${incident.caseId}.incident-report.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function workOrderActionButton(label, kind, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = `row-action ${kind}`;
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function renderDocumentList(element, documents, describe, emptyMessage) {
  element.replaceChildren();
  if (documents.length === 0) {
    const empty = text("li", emptyMessage, "empty-line");
    element.append(empty);
    return;
  }
  for (const document of documents.slice(0, 3)) {
    const description = describe(document);
    const item = documentNode(description);
    element.append(item);
  }
}

function documentNode(description) {
  const item = document.createElement("li");
  item.append(
    text("strong", description.title),
    text("small", description.detail),
    text("span", description.sequence, "document-sequence"),
  );
  return item;
}

function lifecycle(timestamp) {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) return "unknown";
  if (timestamp * 1000 <= Date.now()) return "expired";
  return `until ${date(timestamp * 1000)}`;
}

function applyView() {
  const titles = {
    overview: "Fleet overview",
    devices: "Enrolled devices",
    assets: "Observed assets",
    audit: "Tenant audit",
    workorders: "Diagnosis & repair work orders",
    incidents: "Incident cases",
    governance: "Fleet governance",
    enrollment: "Device enrollment",
  };
  document.querySelector("#view-title").textContent = titles[state.view];
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    panel.hidden = !panel.dataset.panel.split(" ").includes(state.view);
  });
  document
    .querySelectorAll(".nav-item")
    .forEach((button) =>
      button.classList.toggle("active", button.dataset.view === state.view),
    );
  if (state.view === "enrollment") elements.enrollment.showModal();
}

function populateSelect(select, values, selected) {
  select.replaceChildren();
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = String(value).replaceAll("_", " ");
    option.selected = value === selected;
    select.append(option);
  }
}

function openIncident() {
  elements.incidentFormError.textContent = "";
  elements.incidentSource.replaceChildren();
  for (const device of state.devices.filter(
    (candidate) => candidate.status !== "revoked",
  )) {
    const option = document.createElement("option");
    option.value = `device:${device.deviceId}`;
    option.textContent = `Device · ${device.displayName || short(device.deviceId, 18)}`;
    elements.incidentSource.append(option);
  }
  for (const asset of state.assets) {
    const option = document.createElement("option");
    option.value = `asset:${asset.assetId}`;
    option.textContent = `Asset · ${asset.assetId}`;
    elements.incidentSource.append(option);
  }
  populateSelect(elements.incidentSeverity, incidentSeverities, "medium");
  elements.incidentAssignee.value = "";
  elements.incidentSource.disabled = elements.incidentSource.length === 0;
  elements.incidentDialog.showModal();
}

function openIncidentUpdate(incident) {
  state.activeIncident = incident;
  elements.incidentUpdateError.textContent = "";
  populateSelect(
    elements.incidentUpdateStatus,
    incidentStatuses,
    incident.status,
  );
  populateSelect(
    elements.incidentUpdateSeverity,
    incidentSeverities,
    incident.severity,
  );
  elements.incidentUpdateAssignee.value = incident.assigneeLabel ?? "";
  elements.incidentUpdateDialog.showModal();
}

function openIncidentLink(incident) {
  state.activeIncident = incident;
  elements.incidentLinkError.textContent = "";
  elements.incidentLinkOrder.replaceChildren();
  const linkedIds = new Set(
    incident.workOrders.map((workOrder) => workOrder.workOrderId),
  );
  const sourceDeviceId = incident.source.deviceId;
  for (const order of state.workOrders.filter(
    (candidate) =>
      sourceDeviceId &&
      candidate.targetDeviceId === sourceDeviceId &&
      !linkedIds.has(candidate.workOrderId),
  )) {
    const option = document.createElement("option");
    option.value = order.workOrderId;
    option.textContent = `${workOrderActions[order.actionId]?.label ?? order.actionId} · ${String(order.status).replaceAll("_", " ")} · ${short(order.workOrderId, 13)}`;
    elements.incidentLinkOrder.append(option);
  }
  elements.incidentLinkOrder.disabled = elements.incidentLinkOrder.length === 0;
  elements.incidentLinkDialog.showModal();
}

function openIncidentClose(incident) {
  state.activeIncident = incident;
  elements.incidentCloseError.textContent = "";
  populateSelect(elements.incidentOutcome, incidentOutcomes, "resolved");
  elements.incidentCloseDialog.showModal();
}

function openWorkOrder() {
  elements.workOrderFormError.textContent = "";
  elements.workOrderDevice.replaceChildren();
  const devices = state.devices.filter((device) => device.status !== "revoked");
  for (const device of devices) {
    const option = document.createElement("option");
    option.value = device.deviceId;
    option.dataset.platform = device.platform ?? "unknown";
    option.textContent = `${device.displayName || short(device.deviceId, 12)} · ${device.platform ?? "unknown"}`;
    elements.workOrderDevice.append(option);
  }
  elements.workOrderDevice.disabled = devices.length === 0;
  refreshWorkOrderActions();
  elements.workOrderDialog.showModal();
}

function selectedWorkOrderDevice() {
  const option = elements.workOrderDevice.selectedOptions[0];
  if (!option) return null;
  return { deviceId: option.value, platform: option.dataset.platform };
}

function refreshWorkOrderActions() {
  const device = selectedWorkOrderDevice();
  const previous = elements.workOrderAction.value;
  elements.workOrderAction.replaceChildren();
  for (const action of workOrderActionsForPlatform(device?.platform)) {
    const option = document.createElement("option");
    option.value = action.actionId;
    option.textContent = `${action.label} · ${action.kind} ${action.risk} · v${action.version}`;
    elements.workOrderAction.append(option);
  }
  if (
    [...elements.workOrderAction.options].some(
      (item) => item.value === previous,
    )
  ) {
    elements.workOrderAction.value = previous;
  }
  refreshWorkOrderPreflight();
}

function refreshWorkOrderPreflight() {
  const device = selectedWorkOrderDevice();
  const actionId = elements.workOrderAction.value;
  const readiness = workOrderReadiness({
    actionId,
    platform: device?.platform,
    policyCount: state.policies.length,
    entitlements: state.entitlements,
  });
  for (const [id, ready] of [
    ["#wo-check-platform", readiness.platformReady],
    ["#wo-check-policy", readiness.policyReady],
    ["#wo-check-entitlement", readiness.entitlementReady],
  ]) {
    const node = document.querySelector(id);
    node.className = ready ? "ready" : "missing";
    node.textContent = ready ? "✓" : "!";
  }
  elements.workOrderApprovalWarning.hidden =
    workOrderActions[actionId]?.localApprovalRequired !== true;
  elements.workOrderSubmit.disabled = !readiness.canSubmit;
  elements.workOrderSubmit.title = readiness.canSubmit
    ? "The server will authoritatively verify exact assignment and scope."
    : "Publish an applicable signed policy and entitlement first.";
}

async function approveWorkOrder(order) {
  if (
    !window.confirm(
      `Approve delivery of ${order.actionId} to ${order.targetDeviceId}? This does not replace the device's local Core approval.`,
    )
  ) {
    return;
  }
  try {
    const payload = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/work-orders/${encodeURIComponent(order.workOrderId)}/approve`,
      { method: "POST", body: JSON.stringify({ decision: "approve" }) },
    );
    notify(
      payload?.idempotent ? "Approval already recorded" : "Work order approved",
    );
    await loadFleet();
  } catch (error) {
    notify(error.message, true);
  }
}

async function cancelWorkOrder(order) {
  if (!window.confirm(`Cancel work order ${order.workOrderId}?`)) return;
  try {
    const payload = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/work-orders/${encodeURIComponent(order.workOrderId)}/cancel`,
      { method: "POST", body: JSON.stringify({}) },
    );
    notify(
      payload?.idempotent
        ? "Cancellation already recorded"
        : "Work order cancelled",
    );
    await loadFleet();
  } catch (error) {
    notify(error.message, true);
  }
}

async function revokeDevice(deviceId) {
  if (
    !window.confirm(
      `Revoke ${deviceId}? Future signed inventories from this identity will be rejected.`,
    )
  )
    return;
  try {
    await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/devices/${encodeURIComponent(deviceId)}/revoke`,
      { method: "POST" },
    );
    notify("Device revoked");
    await loadFleet();
  } catch (error) {
    notify(error.message, true);
  }
}

function notify(message, failure = false) {
  elements.toast.textContent = message;
  elements.toast.style.borderColor = failure ? "var(--red)" : "";
  elements.toast.classList.add("show");
  setTimeout(() => elements.toast.classList.remove("show"), 2800);
}

function clearSession() {
  state.token = "";
  state.tenantId = "";
  state.devices = [];
  state.assets = [];
  state.auditEvents = [];
  state.auditError = "";
  state.policies = [];
  state.policyAnchorConfigured = false;
  state.entitlements = [];
  state.entitlementRevocations = null;
  state.updates = [];
  state.governanceError = "";
  state.workOrders = [];
  state.workOrderEvents = [];
  state.workOrderError = "";
  state.incidents = [];
  state.incidentEvents = [];
  state.incidentError = "";
  state.activeIncident = null;
  sessionStorage.removeItem("kernaid.fleet.tenant");
  sessionStorage.removeItem("kernaid.fleet.admin-token");
  elements.tokenInput.value = "";
  render();
  elements.login.showModal();
}

elements.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements.loginForm.querySelector("button[type=submit]");
  const previous = { tenantId: state.tenantId, token: state.token };
  state.tenantId = elements.tenantInput.value.trim();
  state.token = elements.tokenInput.value;
  elements.loginError.textContent = "";
  setBusy(button, true);
  try {
    await loadFleet();
    sessionStorage.setItem("kernaid.fleet.tenant", state.tenantId);
    sessionStorage.setItem("kernaid.fleet.admin-token", state.token);
    elements.login.close();
  } catch (error) {
    state.tenantId = previous.tenantId;
    state.token = previous.token;
    elements.loginError.textContent =
      error.status === 401 || error.status === 403
        ? "Tenant or administrator token is not valid."
        : error.message;
  } finally {
    setBusy(button, false);
  }
});

elements.enrollmentForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements.enrollmentForm.querySelector("button[type=submit]");
  elements.enrollmentError.textContent = "";
  elements.tokenResult.hidden = true;
  setBusy(button, true);
  try {
    const payload = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/enrollment-tokens`,
      {
        method: "POST",
        body: JSON.stringify({
          expiresInSeconds: Number(document.querySelector("#ttl-input").value),
        }),
      },
    );
    elements.enrollmentToken.textContent = payload.enrollmentToken;
    elements.tokenExpiry.textContent = `Expires ${date(payload.expiresAt)}`;
    elements.tokenResult.hidden = false;
  } catch (error) {
    elements.enrollmentError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

elements.copyToken.addEventListener("click", async () => {
  const token = elements.enrollmentToken.textContent;
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
    notify("Enrollment token copied");
  } catch {
    notify("Clipboard permission denied", true);
  }
});
elements.enrollmentClose.addEventListener("click", () =>
  elements.enrollment.close(),
);

elements.workOrderForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const device = selectedWorkOrderDevice();
  elements.workOrderFormError.textContent = "";
  setBusy(elements.workOrderSubmit, true);
  try {
    const payload = createWorkOrderPayload({
      requestId: `ui_${crypto.randomUUID().replaceAll("-", "")}`,
      targetDeviceId: device?.deviceId,
      platform: device?.platform,
      actionId: elements.workOrderAction.value,
      lifetimeSeconds: Number(elements.workOrderLifetime.value),
      nowMs: Date.now(),
    });
    const result = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/work-orders`,
      { method: "POST", body: JSON.stringify(payload) },
    );
    elements.workOrderDialog.close();
    notify(
      result?.idempotent
        ? "Work order already queued"
        : result?.status === "pending_approval"
          ? "Repair intent created — administrator approval required"
          : "Diagnostic work order queued",
    );
    await loadFleet();
  } catch (error) {
    elements.workOrderFormError.textContent = error.message;
  } finally {
    setBusy(elements.workOrderSubmit, false);
    refreshWorkOrderPreflight();
  }
});

document
  .querySelector("#work-order-close")
  .addEventListener("click", () => elements.workOrderDialog.close());
elements.workOrderDialog.addEventListener("close", () => {
  elements.workOrderFormError.textContent = "";
});
elements.workOrderDevice.addEventListener("change", refreshWorkOrderActions);
elements.workOrderAction.addEventListener("change", refreshWorkOrderPreflight);

elements.incidentForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements.incidentForm.querySelector("button[type=submit]");
  elements.incidentFormError.textContent = "";
  setBusy(button, true);
  try {
    const body = createIncidentPayload({
      requestId: `ui_case_${crypto.randomUUID().replaceAll("-", "")}`,
      sourceValue: elements.incidentSource.value,
      severity: elements.incidentSeverity.value,
      assigneeLabel: elements.incidentAssignee.value,
    });
    const result = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/incident-cases`,
      { method: "POST", body: JSON.stringify(body) },
    );
    elements.incidentDialog.close();
    notify(result?.idempotent ? "Incident already exists" : "Incident opened");
    await loadFleet();
  } catch (error) {
    elements.incidentFormError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

elements.incidentUpdateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements.incidentUpdateForm.querySelector(
    "button[type=submit]",
  );
  elements.incidentUpdateError.textContent = "";
  setBusy(button, true);
  try {
    const body = updateIncidentPayload({
      status: elements.incidentUpdateStatus.value,
      severity: elements.incidentUpdateSeverity.value,
      assigneeLabel: elements.incidentUpdateAssignee.value,
    });
    await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/incident-cases/${encodeURIComponent(state.activeIncident.caseId)}/update`,
      { method: "POST", body: JSON.stringify(body) },
    );
    elements.incidentUpdateDialog.close();
    notify("Incident updated");
    await loadFleet();
  } catch (error) {
    elements.incidentUpdateError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

elements.incidentLinkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements.incidentLinkForm.querySelector("button[type=submit]");
  elements.incidentLinkError.textContent = "";
  setBusy(button, true);
  try {
    const body = linkIncidentPayload(elements.incidentLinkOrder.value);
    await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/incident-cases/${encodeURIComponent(state.activeIncident.caseId)}/work-orders`,
      { method: "POST", body: JSON.stringify(body) },
    );
    elements.incidentLinkDialog.close();
    notify("Work order linked");
    await loadFleet();
  } catch (error) {
    elements.incidentLinkError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

elements.incidentCloseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements.incidentCloseForm.querySelector(
    "button[type=submit]",
  );
  elements.incidentCloseError.textContent = "";
  setBusy(button, true);
  try {
    const body = closeIncidentPayload(
      state.activeIncident.caseId,
      elements.incidentOutcome.value,
    );
    const result = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/incident-cases/${encodeURIComponent(state.activeIncident.caseId)}/close`,
      { method: "POST", body: JSON.stringify(body) },
    );
    elements.incidentCloseDialog.close();
    notify(
      result?.idempotent
        ? "Signed closure already sealed"
        : "Incident closed with signed report",
    );
    await loadFleet();
  } catch (error) {
    elements.incidentCloseError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

for (const [selector, dialog] of [
  ["#incident-close", elements.incidentDialog],
  ["#incident-update-close", elements.incidentUpdateDialog],
  ["#incident-link-close", elements.incidentLinkDialog],
  ["#incident-close-close", elements.incidentCloseDialog],
]) {
  document
    .querySelector(selector)
    .addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => {
    state.activeIncident = null;
  });
}

function openPublish(kind) {
  const configuration = publishKinds[kind];
  if (!configuration) return;
  activePublishKind = kind;
  elements.publishTitle.textContent = configuration.title;
  elements.publishCopy.textContent = configuration.copy;
  elements.publishLimit.textContent =
    configuration.maximumBytes === 1024 * 1024
      ? "Maximum 1 MiB"
      : "Maximum 64 KiB";
  elements.publishDocument.maxLength = configuration.maximumBytes;
  elements.publishDocument.value = "";
  elements.publishError.textContent = "";
  elements.publish.showModal();
}

elements.publishForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const configuration = publishKinds[activePublishKind];
  if (!configuration) return;
  const button = elements.publishForm.querySelector("button[type=submit]");
  elements.publishError.textContent = "";
  setBusy(button, true);
  try {
    const canonical = boundedSignedDocument(
      elements.publishDocument.value,
      configuration,
      state.tenantId,
    );
    const payload = await request(
      `/v1/tenants/${encodeURIComponent(state.tenantId)}/${configuration.path}`,
      { method: "POST", body: canonical },
    );
    elements.publishDocument.value = "";
    elements.publish.close();
    notify(
      payload?.idempotent
        ? "Document already current"
        : "Signed document published",
    );
    await loadFleet();
  } catch (error) {
    elements.publishError.textContent = error.message;
  } finally {
    setBusy(button, false);
  }
});

elements.publish.addEventListener("close", () => {
  elements.publishDocument.value = "";
  elements.publishError.textContent = "";
  activePublishKind = null;
});
elements.publishClose.addEventListener("click", () => elements.publish.close());

document
  .querySelector("#refresh-button")
  .addEventListener("click", async (event) => {
    setBusy(event.currentTarget, true);
    try {
      const complete = await loadFleet();
      notify(
        complete
          ? "Fleet data refreshed"
          : "Fleet refreshed with a partial status warning",
        !complete,
      );
    } catch (error) {
      if (error.status === 401 || error.status === 403) clearSession();
      else notify(error.message, true);
    } finally {
      setBusy(event.currentTarget, false);
    }
  });
document
  .querySelector("#session-button")
  .addEventListener("click", clearSession);
document
  .querySelector("#open-enrollment")
  .addEventListener("click", () => elements.enrollment.showModal());
document
  .querySelector("#open-work-order")
  .addEventListener("click", openWorkOrder);
document
  .querySelector("#open-incident")
  .addEventListener("click", openIncident);
elements.deviceFilter.addEventListener("input", renderDevices);
elements.assetFilter.addEventListener("input", renderAssets);
elements.auditFilter.addEventListener("input", renderAudit);
elements.workOrderFilter.addEventListener("input", renderWorkOrders);
elements.incidentFilter.addEventListener("input", renderIncidents);
document
  .querySelectorAll(".publish-trigger")
  .forEach((button) =>
    button.addEventListener("click", () =>
      openPublish(button.dataset.publishKind),
    ),
  );
document.querySelectorAll(".nav-item").forEach((button) =>
  button.addEventListener("click", () => {
    state.view = button.dataset.view;
    applyView();
  }),
);

await health();
if (state.tenantId && state.token) {
  elements.tenantInput.value = state.tenantId;
  try {
    await loadFleet();
  } catch {
    clearSession();
  }
} else {
  render();
  elements.login.showModal();
}
