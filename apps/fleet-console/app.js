import { boundedSignedDocument } from "./publish-document.js";

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
  ] = await Promise.allSettled([
    request(`/v1/tenants/${encodedTenant}/devices`),
    request(`/v1/tenants/${encodedTenant}/assets`),
    request(`/v1/tenants/${encodedTenant}/audit-events`),
    request(`/v1/tenants/${encodedTenant}/policies`),
    request(`/v1/tenants/${encodedTenant}/entitlements`),
    request(`/v1/tenants/${encodedTenant}/update-manifests`),
  ]);
  if (devicesResult.status === "rejected") throw devicesResult.reason;
  if (assetsResult.status === "rejected") throw assetsResult.reason;
  for (const result of [
    auditResult,
    policiesResult,
    entitlementsResult,
    updatesResult,
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
  state.governanceError = governanceErrorMessage([
    policiesResult,
    entitlementsResult,
    updatesResult,
  ]);
  render();
  return state.auditError === "" && state.governanceError === "";
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
elements.deviceFilter.addEventListener("input", renderDevices);
elements.assetFilter.addEventListener("input", renderAssets);
elements.auditFilter.addEventListener("input", renderAudit);
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
