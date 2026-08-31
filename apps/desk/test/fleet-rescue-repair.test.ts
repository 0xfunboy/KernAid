import assert from "node:assert/strict";
import test from "node:test";
import {
  FLEET_FSTAB_ACTION,
  FLEET_FSTAB_CONFIRMATION,
  FLEET_RESCUE_API_VERSION,
  FLEET_RESCUE_INTENT_SCHEMA,
  FleetRescueClient,
  parseFleetRescueIntent,
  type FleetRescueIntent,
} from "../src/fleet-rescue-repair.js";

const evidence = {
  preparedId: `Q-${"1".repeat(32)}`,
  sessionId: `S-${"2".repeat(32)}`,
  planId: `P-${"3".repeat(32)}`,
  planSha256: "4".repeat(64),
  targetSha256: "5".repeat(64),
  beforeSha256: `sha256:${"6".repeat(64)}`,
  afterSha256: `sha256:${"7".repeat(64)}`,
  diffSha256: `sha256:${"8".repeat(64)}`,
  backupLocator: `vault://repair/B-${"9".repeat(32)}`,
  approvalSequence: 1,
  evidenceSha256: "a".repeat(64),
};

function intent(): FleetRescueIntent {
  return parseFleetRescueIntent({
    schema: FLEET_RESCUE_INTENT_SCHEMA,
    deviceId: "KA-0123456789abcdef01234567",
    workOrderId: "wo-rescue-fstab-1",
    leaseId: "lease-rescue-fstab-1",
    executionId: "exec_0123456789abcdef0123456789abcdef",
    actionId: FLEET_FSTAB_ACTION,
    actionVersion: 1,
    risk: "R2",
    state: "awaiting-approval",
    leaseExpiresAt: "2026-08-31T12:35:00Z",
    evidence,
    confirmationRequired: FLEET_FSTAB_CONFIRMATION,
  });
}

test("Fleet Rescue intent schema rejects extra authority fields", () => {
  const valid = intent();
  assert.equal(valid.evidence?.evidenceSha256, "a".repeat(64));
  assert.throws(
    () => parseFleetRescueIntent({ ...valid, command: "rm -rf /" }),
    /Envelope Fleet Rescue/u,
  );
  assert.throws(
    () =>
      parseFleetRescueIntent({
        ...valid,
        evidence: { ...evidence, backupLocator: "/etc/fstab" },
      }),
    /Evidenza Fleet Rescue/u,
  );
});

test("local approval request echoes device action and exact evidence only", async () => {
  let requestBody = "";
  const approved = {
    ...intent(),
    state: "approved",
    confirmationRequired: null,
  };
  const client = new FleetRescueClient(async (_input, init) => {
    requestBody = String(init?.body);
    return new Response(JSON.stringify(approved), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
  const result = await client.approve(
    intent(),
    `A-${"b".repeat(32)}`,
    "2026-08-31T12:30:45Z",
    FLEET_FSTAB_CONFIRMATION,
  );
  assert.equal(result.state, "approved");
  const request = JSON.parse(requestBody) as Record<string, unknown>;
  assert.equal(request.apiVersion, FLEET_RESCUE_API_VERSION);
  assert.equal(request.actionId, FLEET_FSTAB_ACTION);
  assert.equal(request.evidenceSha256, evidence.evidenceSha256);
  assert.equal(request.targetSha256, evidence.targetSha256);
  assert.equal(request.typedConfirmation, FLEET_FSTAB_CONFIRMATION);
  assert.equal("command" in request, false);
  assert.equal("path" in request, false);
  assert.equal(requestBody.startsWith('{"actionId"'), true);
});
