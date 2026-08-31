export const workOrderActions = Object.freeze({
  "linux.filesystem.health.v1": Object.freeze({
    label: "Filesystem health",
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: Object.freeze(["linux", "rescue"]),
    localApprovalRequired: false,
  }),
  "linux.storage.health.v1": Object.freeze({
    label: "Storage health",
    version: 1,
    kind: "diagnosis",
    risk: "R0",
    requiredFeature: "fleet",
    platforms: Object.freeze(["linux", "rescue"]),
    localApprovalRequired: false,
  }),
  "linux.fstab.disable-missing-uuid.v1": Object.freeze({
    label: "Repair missing fstab UUID",
    version: 1,
    kind: "repair",
    risk: "R2",
    requiredFeature: "enterprise_repair",
    platforms: Object.freeze(["rescue"]),
    localApprovalRequired: true,
  }),
});

const workOrderStatuses = new Set([
  "pending_approval",
  "queued",
  "leased",
  "succeeded",
  "failed",
  "rejected",
  "cancelled",
  "expired",
]);

export function createWorkOrderPayload(input) {
  const action = workOrderActions[input.actionId];
  if (!action) throw new Error("Select a supported typed action.");
  if (!/^KA-[0-9a-f]{24}$/.test(input.targetDeviceId ?? "")) {
    throw new Error("Select an enrolled KernAid device.");
  }
  if (!action.platforms.includes(input.platform)) {
    throw new Error("That action is not available on the selected runtime.");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.requestId ?? "")) {
    throw new Error("The generated request identifier is invalid.");
  }
  if (
    !Number.isSafeInteger(input.nowMs) ||
    !Number.isSafeInteger(input.lifetimeSeconds) ||
    input.lifetimeSeconds < 300 ||
    input.lifetimeSeconds > 7 * 24 * 60 * 60
  ) {
    throw new Error(
      "Select a work-order lifetime from five minutes to seven days.",
    );
  }
  return {
    requestId: input.requestId,
    targetDeviceId: input.targetDeviceId,
    actionId: input.actionId,
    actionVersion: action.version,
    expiresAt: new Date(
      input.nowMs + input.lifetimeSeconds * 1000,
    ).toISOString(),
  };
}

export function workOrderReadiness(input) {
  const action = workOrderActions[input.actionId];
  const platformReady = Boolean(
    action && action.platforms.includes(input.platform),
  );
  const policyReady = Number(input.policyCount) > 0;
  const entitlementReady = (input.entitlements ?? []).some((entitlement) => {
    const features = Array.isArray(entitlement?.features)
      ? entitlement.features
      : [];
    return (
      features.includes("fleet") &&
      action !== undefined &&
      features.includes(action.requiredFeature)
    );
  });
  return {
    platformReady,
    policyReady,
    entitlementReady,
    canSubmit: platformReady && policyReady && entitlementReady,
  };
}

export function workOrderActionsForPlatform(platform) {
  return Object.entries(workOrderActions)
    .filter(([, action]) => action.platforms.includes(platform))
    .map(([actionId, action]) => ({ actionId, ...action }));
}

export function workOrderControls(order) {
  return {
    canApprove: order?.status === "pending_approval",
    canCancel: ["pending_approval", "queued"].includes(order?.status),
  };
}

export function workOrderReceiptState(order) {
  if (!workOrderStatuses.has(order?.status)) return "Unavailable";
  if (["succeeded", "failed", "rejected"].includes(order.status)) {
    return "Result acknowledged";
  }
  if (order.status === "leased") return "Claim acknowledged";
  if (["cancelled", "expired"].includes(order.status)) return "Not issued";
  return "Awaiting device";
}

export function assertMinimizedWorkOrder(order) {
  if (order === null || typeof order !== "object" || Array.isArray(order)) {
    throw new Error("Work-order response crossed the minimized UI boundary.");
  }
  assertAllowedKeys(order, [
    "tenantId",
    "workOrderId",
    "requestId",
    "targetDeviceId",
    "actionId",
    "actionVersion",
    "kind",
    "risk",
    "localApprovalRequired",
    "status",
    "createdByCredentialId",
    "createdAt",
    "expiresAt",
    "approval",
    "lease",
    "result",
    "cancellation",
  ]);
  assertNullableRecord(order.approval, [
    "approvedByCredentialId",
    "approvedAt",
  ]);
  assertNullableRecord(order.lease, ["leaseId", "leasedAt", "leaseExpiresAt"]);
  assertNullableRecord(order.result, [
    "outcome",
    "resultSha256",
    "completedAt",
  ]);
  assertNullableRecord(order.cancellation, [
    "cancelledByCredentialId",
    "cancelledAt",
  ]);
  if (!workOrderStatuses.has(order?.status)) {
    throw new Error("Work-order response contains an unsupported status.");
  }
  return {
    tenantId: order.tenantId,
    workOrderId: order.workOrderId,
    requestId: order.requestId,
    targetDeviceId: order.targetDeviceId,
    actionId: order.actionId,
    actionVersion: order.actionVersion,
    kind: order.kind,
    risk: order.risk,
    localApprovalRequired: order.localApprovalRequired,
    status: order.status,
    createdByCredentialId: order.createdByCredentialId,
    createdAt: order.createdAt,
    expiresAt: order.expiresAt,
    approval: order.approval ?? null,
    lease: order.lease ?? null,
    result: order.result ?? null,
    cancellation: order.cancellation ?? null,
  };
}

function assertNullableRecord(value, allowedKeys) {
  if (value === undefined || value === null) return;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Work-order response crossed the minimized UI boundary.");
  }
  assertAllowedKeys(value, allowedKeys);
}

function assertAllowedKeys(value, allowedKeys) {
  const allowed = new Set(allowedKeys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error("Work-order response crossed the minimized UI boundary.");
  }
}
