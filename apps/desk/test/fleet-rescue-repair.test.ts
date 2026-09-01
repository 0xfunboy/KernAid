import assert from "node:assert/strict";
import test from "node:test";
import {
  FLEET_CRYPTTAB_ACTION,
  FLEET_CRYPTTAB_CONFIRMATION,
  FLEET_EXT4_ACTION,
  FLEET_EXT4_CONFIRMATION,
  FLEET_FSTAB_ACTION,
  FLEET_FSTAB_CONFIRMATION,
  FLEET_RESCUE_API_VERSION,
  FLEET_RESCUE_INTENT_SCHEMA,
  FLEET_RESOLVER_LINK_ACTION,
  FLEET_RESOLVER_LINK_CONFIRMATION,
  FleetRescueClient,
  fleetRescueActionCatalog,
  parseFleetRescueIntent,
  type FleetRescueActionId,
  type FleetRescueConfirmation,
  type FleetRescueIntent,
  type FleetRescueRisk,
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

const actions: readonly {
  actionId: FleetRescueActionId;
  risk: FleetRescueRisk;
  confirmation: FleetRescueConfirmation;
}[] = [
  {
    actionId: FLEET_FSTAB_ACTION,
    risk: "R2",
    confirmation: FLEET_FSTAB_CONFIRMATION,
  },
  {
    actionId: FLEET_CRYPTTAB_ACTION,
    risk: "R2",
    confirmation: FLEET_CRYPTTAB_CONFIRMATION,
  },
  {
    actionId: FLEET_EXT4_ACTION,
    risk: "R3",
    confirmation: FLEET_EXT4_CONFIRMATION,
  },
  {
    actionId: FLEET_RESOLVER_LINK_ACTION,
    risk: "R2",
    confirmation: FLEET_RESOLVER_LINK_CONFIRMATION,
  },
];

function intent(action = actions[0]): FleetRescueIntent {
  return parseFleetRescueIntent({
    schema: FLEET_RESCUE_INTENT_SCHEMA,
    deviceId: "KA-0123456789abcdef01234567",
    workOrderId: `wo-rescue-${action.actionId}`,
    leaseId: `lease-rescue-${action.actionId}`,
    executionId: "exec_0123456789abcdef0123456789abcdef",
    actionId: action.actionId,
    actionVersion: 1,
    risk: action.risk,
    state: "awaiting-approval",
    leaseExpiresAt: "2026-08-31T12:35:00Z",
    evidence,
    confirmationRequired: action.confirmation,
  });
}

test("Fleet Rescue catalog binds all four repairs to risk and typed confirmation", () => {
  assert.deepEqual(
    Object.keys(fleetRescueActionCatalog),
    actions.map(({ actionId }) => actionId),
  );
  for (const action of actions) {
    const valid = intent(action);
    assert.equal(valid.risk, action.risk);
    assert.equal(valid.confirmationRequired, action.confirmation);
  }
  assert.throws(
    () =>
      parseFleetRescueIntent({
        ...intent(actions[2]),
        risk: "R2",
      }),
    /Intento Fleet Rescue/u,
  );
  assert.throws(
    () =>
      parseFleetRescueIntent({
        ...intent(actions[1]),
        confirmationRequired: FLEET_FSTAB_CONFIRMATION,
      }),
    /Conferma Fleet Rescue/u,
  );
});

test("Fleet Rescue intent schema rejects extra authority fields", () => {
  const valid = intent(actions[0]);
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

test("local approval echoes each exact action and evidence without authority fields", async () => {
  for (const action of actions) {
    let requestBody = "";
    const approved = {
      ...intent(action),
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
      intent(action),
      `A-${"b".repeat(32)}`,
      "2026-08-31T12:30:45Z",
      action.confirmation,
    );
    assert.equal(result.state, "approved");
    const request = JSON.parse(requestBody) as Record<string, unknown>;
    assert.equal(request.apiVersion, FLEET_RESCUE_API_VERSION);
    assert.equal(request.actionId, action.actionId);
    assert.equal(request.evidenceSha256, evidence.evidenceSha256);
    assert.equal(request.targetSha256, evidence.targetSha256);
    assert.equal(request.typedConfirmation, action.confirmation);
    assert.equal("command" in request, false);
    assert.equal("path" in request, false);
    assert.equal(requestBody.startsWith('{"actionId"'), true);
  }
});

test("local approval rejects a confirmation from another repair", async () => {
  const client = new FleetRescueClient(async () => {
    throw new Error("fetch must not run");
  });
  await assert.rejects(
    client.approve(
      intent(actions[1]),
      `A-${"b".repeat(32)}`,
      "2026-08-31T12:30:45Z",
      FLEET_FSTAB_CONFIRMATION,
    ),
    /Approvazione locale/u,
  );
});
