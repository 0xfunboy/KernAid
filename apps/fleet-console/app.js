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
  view: "overview",
};

const elements = {
  login: document.querySelector("#login-dialog"),
  loginForm: document.querySelector("#login-form"),
  loginError: document.querySelector("#login-error"),
  tenantInput: document.querySelector("#tenant-input"),
  tokenInput: document.querySelector("#token-input"),
  enrollment: document.querySelector("#enrollment-dialog"),
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
      const error = new Error(
        payload?.error?.message ??
          payload?.message ??
          `Request failed (${response.status})`,
      );
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally {
    clearTimeout(timer);
  }
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
  const [devicesResult, assetsResult, auditResult] = await Promise.allSettled([
    request(`/v1/tenants/${encodedTenant}/devices`),
    request(`/v1/tenants/${encodedTenant}/assets`),
    request(`/v1/tenants/${encodedTenant}/audit-events`),
  ]);
  if (devicesResult.status === "rejected") throw devicesResult.reason;
  if (assetsResult.status === "rejected") throw assetsResult.reason;
  if (
    auditResult.status === "rejected" &&
    [401, 403].includes(auditResult.reason?.status)
  ) {
    throw auditResult.reason;
  }

  state.devices = items(devicesResult.value);
  state.assets = items(assetsResult.value);
  state.auditEvents =
    auditResult.status === "fulfilled" ? auditItems(auditResult.value) : [];
  state.auditError =
    auditResult.status === "rejected"
      ? auditErrorMessage(auditResult.reason)
      : "";
  render();
  return state.auditError === "";
}

function auditErrorMessage(error) {
  if (error?.status === 404) {
    return "This control plane does not expose the tenant audit endpoint yet.";
  }
  return "Signed audit events could not be loaded. Refresh to retry.";
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

function applyView() {
  const titles = {
    overview: "Fleet overview",
    devices: "Enrolled devices",
    assets: "Observed assets",
    audit: "Tenant audit",
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

document
  .querySelector("#refresh-button")
  .addEventListener("click", async (event) => {
    setBusy(event.currentTarget, true);
    try {
      const complete = await loadFleet();
      notify(
        complete
          ? "Fleet data refreshed"
          : "Fleet refreshed; audit unavailable",
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
