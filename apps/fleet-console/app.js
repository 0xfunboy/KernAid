const apiBase =
  document
    .querySelector('meta[name="kernaid-api-base"]')
    ?.content.replace(/\/$/, "") ?? "";
const state = {
  tenantId: sessionStorage.getItem("kernaid.fleet.tenant") ?? "",
  token: sessionStorage.getItem("kernaid.fleet.admin-token") ?? "",
  devices: [],
  assets: [],
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
  deviceFilter: document.querySelector("#device-filter"),
  assetFilter: document.querySelector("#asset-filter"),
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

async function loadFleet() {
  if (!state.tenantId || !state.token) return;
  const encodedTenant = encodeURIComponent(state.tenantId);
  const [devices, assets] = await Promise.all([
    request(`/v1/tenants/${encodedTenant}/devices`),
    request(`/v1/tenants/${encodedTenant}/assets`),
  ]);
  state.devices = items(devices);
  state.assets = items(assets);
  render();
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

function applyView() {
  const titles = {
    overview: "Fleet overview",
    devices: "Enrolled devices",
    assets: "Observed assets",
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
      await loadFleet();
      notify("Fleet data refreshed");
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
