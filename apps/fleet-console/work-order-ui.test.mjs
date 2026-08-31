import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assertMinimizedWorkOrder,
  createWorkOrderPayload,
  workOrderActions,
  workOrderActionsForPlatform,
  workOrderControls,
  workOrderReadiness,
  workOrderReceiptState,
} from "./work-order-ui.js";

const deviceId = "KA-0123456789abcdef01234567";

test("work-order creation emits only the closed server payload", () => {
  const payload = createWorkOrderPayload({
    requestId: "ui_0123456789abcdef",
    targetDeviceId: deviceId,
    platform: "rescue",
    actionId: "linux.fstab.disable-missing-uuid.v1",
    lifetimeSeconds: 3600,
    nowMs: Date.parse("2026-08-31T18:00:00Z"),
  });
  assert.deepEqual(payload, {
    requestId: "ui_0123456789abcdef",
    targetDeviceId: deviceId,
    actionId: "linux.fstab.disable-missing-uuid.v1",
    actionVersion: 1,
    expiresAt: "2026-08-31T19:00:00.000Z",
  });
  assert.deepEqual(Object.keys(payload).sort(), [
    "actionId",
    "actionVersion",
    "expiresAt",
    "requestId",
    "targetDeviceId",
  ]);
  assert.throws(() =>
    createWorkOrderPayload({
      ...payload,
      platform: "linux",
      lifetimeSeconds: 3600,
      nowMs: Date.parse("2026-08-31T18:00:00Z"),
    }),
  );
  assert.equal("shell.exec.v1" in workOrderActions, false);
});

test("readiness, actions, receipt labels, and minimized response are fail closed", () => {
  assert.deepEqual(
    workOrderActionsForPlatform("linux").map((action) => action.actionId),
    ["linux.filesystem.health.v1", "linux.storage.health.v1"],
  );
  assert.equal(
    workOrderReadiness({
      actionId: "linux.fstab.disable-missing-uuid.v1",
      platform: "rescue",
      policyCount: 1,
      entitlements: [{ features: ["enterprise_repair", "fleet"] }],
    }).canSubmit,
    true,
  );
  assert.equal(
    workOrderReadiness({
      actionId: "linux.fstab.disable-missing-uuid.v1",
      platform: "rescue",
      policyCount: 1,
      entitlements: [{ features: ["fleet"] }],
    }).canSubmit,
    false,
  );
  assert.deepEqual(workOrderControls({ status: "pending_approval" }), {
    canApprove: true,
    canCancel: true,
  });
  assert.equal(
    workOrderReceiptState({ status: "leased" }),
    "Claim acknowledged",
  );
  assert.equal(
    workOrderReceiptState({ status: "succeeded" }),
    "Result acknowledged",
  );
  assert.equal(
    assertMinimizedWorkOrder({
      status: "succeeded",
      result: { resultSha256: "a".repeat(64) },
    }).status,
    "succeeded",
  );
  assert.throws(() =>
    assertMinimizedWorkOrder({ status: "queued", command: "sh -c id" }),
  );
  assert.throws(() =>
    assertMinimizedWorkOrder({ status: "queued", serverNote: "unexpected" }),
  );
});
