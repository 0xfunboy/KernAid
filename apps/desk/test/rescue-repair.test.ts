import assert from "node:assert/strict";
import test from "node:test";
import {
  RESCUE_FSTAB_CONFIRMATION,
  RESCUE_FSTAB_RESOURCE_ID,
  RESCUE_FSTAB_ROLLBACK_CONFIRMATION,
  RESCUE_REPAIR_API_VERSION,
  RESCUE_ROLLBACK_API_VERSION,
  RescueRepairClient,
  RescueRepairServiceError,
  RescueRepairUnavailableError,
  parseRescueRepairResponse,
  preparedRepairDetail,
  preparedRollbackDetail,
  rescueRepairIsTerminal,
  rescueRepairNeedsPolling,
  rescueRepairStateMessage,
  type RescueRepairOperation,
  type RescueRepairSnapshot,
} from "../src/rescue-repair.js";
import {
  newestSnapshot,
  operationErrorMessage,
} from "../src/rescue-repair-panel.js";

const REQUEST = "R-11111111-1111-4111-8111-111111111111";
const NEXT_REQUEST = "R-22222222-2222-4222-8222-222222222222";
const THIRD_REQUEST = "R-33333333-3333-4333-8333-333333333333";
const FOURTH_REQUEST = "R-44444444-4444-4444-8444-444444444444";
const TARGET = `sha256:${"1".repeat(64)}`;

test("prepared response is exact, correlated, and contains no repair bytes", () => {
  const parsed = parseRescueRepairResponse(
    preparedEnvelope(REQUEST, "repair.fstab.prepare"),
    REQUEST,
    "repair.fstab.prepare",
  );
  const detail = preparedRepairDetail(parsed);
  assert.ok(detail);
  assert.equal(detail.actionId, "linux.fstab.disable-missing-uuid.v1");
  assert.equal(detail.backup.vaultDistinct, true);
  assert.equal(detail.resourceId, RESCUE_FSTAB_RESOURCE_ID);
  assert.equal(detail.backupLocator, `vault://repair/B-${"9".repeat(32)}`);
  assert.equal(detail.confirmationRequired, RESCUE_FSTAB_CONFIRMATION);
  assert.doesNotMatch(JSON.stringify(detail), /\/etc\/|\/dev\/|UUID=/u);

  for (const invalid of [
    { resourceId: "rescue:selected-linux-root:etc/shadow" },
    { backupLocator: "/run/kernaid-vault/backups/original" },
    { backupLocator: "vault://repair/B-../../host-path" },
  ]) {
    const envelope = preparedEnvelope(REQUEST, "repair.fstab.prepare");
    assert.throws(
      () =>
        parseRescueRepairResponse(
          {
            ...envelope,
            detail: {
              ...(envelope.detail as Record<string, unknown>),
              ...invalid,
            },
          },
          REQUEST,
          "repair.fstab.prepare",
        ),
      /non valido/u,
    );
  }

  assert.throws(
    () =>
      parseRescueRepairResponse(
        {
          ...preparedEnvelope(REQUEST, "repair.fstab.prepare"),
          path: "/etc/fstab",
        },
        REQUEST,
        "repair.fstab.prepare",
      ),
    /non valida/u,
  );
  assert.throws(
    () =>
      parseRescueRepairResponse(
        preparedEnvelope(REQUEST, "repair.fstab.prepare"),
        NEXT_REQUEST,
        "repair.fstab.prepare",
      ),
    /Correlazione/u,
  );
});

test("rollback v2 is exact, source-bound, and rejects cross-version aliases", async () => {
  const operation = "repair.fstab.rollback.prepare" as const;
  const parsed = parseRescueRepairResponse(
    rollbackPreparedEnvelope(REQUEST, operation),
    REQUEST,
    operation,
  );
  const detail = preparedRollbackDetail(parsed);
  assert.ok(detail);
  assert.equal(detail.actionId, "linux.fstab.restore");
  assert.equal(detail.confirmationRequired, RESCUE_FSTAB_ROLLBACK_CONFIRMATION);
  assert.equal(
    detail.backupLocator,
    `vault://repair/${detail.source.reservationId}`,
  );
  assert.doesNotMatch(JSON.stringify(detail), /\/run\/|\/dev\/|\/etc\//u);

  assert.throws(
    () =>
      parseRescueRepairResponse(
        {
          ...rollbackPreparedEnvelope(REQUEST, operation),
          apiVersion: RESCUE_REPAIR_API_VERSION,
        },
        REQUEST,
        operation,
      ),
    /Correlazione/u,
  );
  assert.throws(
    () =>
      parseRescueRepairResponse(
        {
          ...preparedEnvelope(REQUEST, "repair.fstab.prepare"),
          apiVersion: RESCUE_ROLLBACK_API_VERSION,
        },
        REQUEST,
        "repair.fstab.prepare",
      ),
    /Correlazione/u,
  );
  assert.throws(
    () =>
      parseRescueRepairResponse(
        {
          apiVersion: RESCUE_REPAIR_API_VERSION,
          requestId: REQUEST,
          operation: "repair.status",
          outcome: "ok",
          stateVersion: 5,
          state: "restored",
          detail: {
            kind: "terminal",
            terminalOutcome: "rolled-back-original",
            reservationId: `B-${"9".repeat(32)}`,
            transactionBindingSha256: `sha256:${"8".repeat(64)}`,
            rebootRequired: false,
            prepareFailureStage: null,
          },
        },
        REQUEST,
        "repair.status",
      ),
    /terminale/u,
  );

  const bodies: Array<Record<string, unknown>> = [];
  const requestIds = [REQUEST, NEXT_REQUEST];
  const client = new RescueRepairClient(
    async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      bodies.push(body);
      return frame(
        body.operation === "repair.fstab.rollback.prepare"
          ? rollbackPreparedEnvelope(String(body.requestId), operation)
          : {
              apiVersion: RESCUE_ROLLBACK_API_VERSION,
              requestId: body.requestId,
              operation: body.operation,
              outcome: "ok",
              stateVersion: 5,
              state: "restored",
              detail: {
                kind: "terminal",
                terminalOutcome: "rolled-back-original",
                reservationId: `B-${"9".repeat(32)}`,
                transactionBindingSha256: `sha256:${"8".repeat(64)}`,
                rebootRequired: false,
                prepareFailureStage: null,
              },
            },
      );
    },
    () => requestIds.shift()!,
    () => `A-${"e".repeat(32)}`,
  );
  const source = {
    reservationId: `B-${"9".repeat(32)}`,
    transactionBindingSha256: `sha256:${"8".repeat(64)}`,
  } as const;
  const staged = await client.prepareRollback(source);
  const stagedDetail = preparedRollbackDetail(staged);
  assert.ok(stagedDetail);
  await client.approveRollback(
    stagedDetail,
    RESCUE_FSTAB_ROLLBACK_CONFIRMATION,
  );
  assert.equal(bodies[0]?.apiVersion, RESCUE_ROLLBACK_API_VERSION);
  assert.deepEqual(bodies[0]?.source, source);
  assert.equal(bodies[1]?.approvalSequence, 2);
  assert.equal(
    bodies[1]?.typedConfirmation,
    RESCUE_FSTAB_ROLLBACK_CONFIRMATION,
  );
  assert.doesNotMatch(JSON.stringify(bodies), /path|device|bytes|authority/iu);
});

test("client sends only closed target claims and echoes only prepared bindings", async () => {
  const requestIds = [REQUEST, NEXT_REQUEST, THIRD_REQUEST, FOURTH_REQUEST];
  const bodies: Array<Record<string, unknown>> = [];
  const fetcher = async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    assert.equal(input, "/api/rescue/repair");
    assert.equal(init?.method, "POST");
    assert.equal(init?.cache, "no-store");
    assert.deepEqual(init?.headers, { "Content-Type": "application/json" });
    assert.equal(typeof init?.body, "string");
    const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
    bodies.push(request);
    const operation = request.operation as RescueRepairOperation;
    if (operation === "repair.status")
      return frame(idleEnvelope(String(request.requestId), operation));
    if (operation === "repair.fstab.prepare")
      return frame(preparedEnvelope(String(request.requestId), operation));
    if (operation === "repair.fstab.approve")
      return frame({
        apiVersion: RESCUE_REPAIR_API_VERSION,
        requestId: request.requestId,
        operation,
        outcome: "ok",
        stateVersion: 3,
        state: "executing",
        detail: null,
      });
    return frame(
      terminalEnvelope(String(request.requestId), operation, "cancelled"),
    );
  };
  const client = new RescueRepairClient(
    fetcher,
    () => requestIds.shift()!,
    () => `A-${"e".repeat(32)}`,
  );

  await client.status();
  const prepared = await client.prepare({
    scanFingerprint: `scan:${"a".repeat(64)}`,
    targetFingerprint: TARGET,
    targetId: `target:${"b".repeat(64)}`,
  });
  const detail = preparedRepairDetail(prepared);
  assert.ok(detail);
  await client.approve(detail, RESCUE_FSTAB_CONFIRMATION);
  await client.cancel(detail);

  assert.deepEqual(Object.keys(bodies[0]!), [
    "apiVersion",
    "requestId",
    "operation",
  ]);
  assert.deepEqual(Object.keys(bodies[1]!), [
    "apiVersion",
    "requestId",
    "operation",
    "target",
  ]);
  assert.deepEqual(Object.keys(bodies[1]!.target as object), [
    "scanFingerprint",
    "targetFingerprint",
    "targetId",
  ]);
  assert.doesNotMatch(
    JSON.stringify(bodies[1]),
    /path|device|bytes|actionId/iu,
  );
  assert.deepEqual(Object.keys(bodies[2]!), [
    "apiVersion",
    "requestId",
    "operation",
    "preparedId",
    "sessionId",
    "planId",
    "planHash",
    "approvalId",
    "approvalSequence",
    "typedConfirmation",
  ]);
  assert.equal(bodies[2]!.sessionId, detail.sessionId);
  assert.equal(bodies[2]!.planId, detail.planId);
  assert.equal(bodies[2]!.approvalId, `A-${"e".repeat(32)}`);
  assert.deepEqual(Object.keys(bodies[3]!), [
    "apiVersion",
    "requestId",
    "operation",
    "preparedId",
    "planHash",
  ]);
});

test("wrong confirmation is rejected before any request", async () => {
  let called = false;
  const client = new RescueRepairClient(
    async () => {
      called = true;
      throw new Error("must not fetch");
    },
    () => REQUEST,
    () => `A-${"e".repeat(32)}`,
  );
  const prepared = parseRescueRepairResponse(
    preparedEnvelope(REQUEST, "repair.fstab.prepare"),
    REQUEST,
    "repair.fstab.prepare",
  );
  const detail = preparedRepairDetail(prepared);
  assert.ok(detail);
  await assert.rejects(() => client.approve(detail, "disabilita voce fstab"));
  assert.equal(called, false);
});

test("404 and invalid local responses make the candidate unavailable", async () => {
  const missing = new RescueRepairClient(
    async () => new Response(null, { status: 404 }),
    () => REQUEST,
  );
  await assert.rejects(() => missing.status(), RescueRepairUnavailableError);
  const starting = new RescueRepairClient(
    async () => new Response(null, { status: 503 }),
    () => REQUEST,
  );
  await assert.rejects(() => starting.status(), RescueRepairUnavailableError);

  const invalid = new RescueRepairClient(
    async () =>
      new Response("not-json", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      }),
    () => REQUEST,
  );
  await assert.rejects(() => invalid.status(), RescueRepairUnavailableError);
});

test("closed service errors never become an implied success", async () => {
  const client = new RescueRepairClient(
    async (_input, init) => {
      const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return frame(
        {
          apiVersion: RESCUE_REPAIR_API_VERSION,
          requestId: request.requestId,
          operation: request.operation,
          outcome: "error",
          stateVersion: 9,
          state: "manual-reconciliation-required",
          detail: {
            kind: "terminal",
            terminalOutcome: "manual-reconciliation-required",
            reservationId: `B-${"b".repeat(32)}`,
            transactionBindingSha256: `sha256:${"c".repeat(64)}`,
            rebootRequired: true,
            prepareFailureStage: null,
          },
          error: "recovery-unavailable",
        },
        503,
      );
    },
    () => REQUEST,
  );
  await assert.rejects(
    () =>
      client.prepare({
        scanFingerprint: `scan:${"a".repeat(64)}`,
        targetFingerprint: TARGET,
        targetId: `target:${"b".repeat(64)}`,
      }),
    (error: unknown) => {
      assert.ok(error instanceof RescueRepairServiceError);
      assert.equal(error.state, "manual-reconciliation-required");
      assert.match(error.message, /Riavvia/u);
      return true;
    },
  );
});

test("polling and terminal presentation follow authenticated state versions", () => {
  const preparing = snapshot("preparing", 2, null);
  const executing = snapshot("executing", 3, null);
  const manual = parseRescueRepairResponse(
    terminalEnvelope(
      REQUEST,
      "repair.status",
      "manual-reconciliation-required",
    ),
    REQUEST,
    "repair.status",
  );
  assert.equal(rescueRepairNeedsPolling(preparing), true);
  assert.equal(rescueRepairNeedsPolling(executing), true);
  assert.equal(rescueRepairNeedsPolling(manual), false);
  assert.equal(rescueRepairIsTerminal(manual), true);
  assert.match(rescueRepairStateMessage(manual), /Non avviare|riavvia/u);
  assert.equal(newestSnapshot(executing, preparing), executing);
  assert.match(
    operationErrorMessage(new RescueRepairUnavailableError()),
    /stato è sconosciuto/u,
  );
});

test("prepare failure stage accepts only the closed public taxonomy", () => {
  const failed = {
    apiVersion: RESCUE_REPAIR_API_VERSION,
    requestId: REQUEST,
    operation: "repair.status",
    outcome: "ok",
    stateVersion: 4,
    state: "failed",
    detail: {
      kind: "terminal",
      terminalOutcome: "failed",
      reservationId: null,
      transactionBindingSha256: null,
      rebootRequired: false,
      prepareFailureStage: "vault-reserve",
    },
  };
  const parsed = parseRescueRepairResponse(failed, REQUEST, "repair.status");
  assert.equal(parsed.detail?.kind, "terminal");
  if (parsed.detail?.kind === "terminal")
    assert.equal(parsed.detail.prepareFailureStage, "vault-reserve");
  assert.throws(
    () =>
      parseRescueRepairResponse(
        {
          ...failed,
          detail: { ...failed.detail, prepareFailureStage: "/dev/sda" },
        },
        REQUEST,
        "repair.status",
      ),
    /non valido/u,
  );
});

function preparedEnvelope(
  requestId: string,
  operation: RescueRepairOperation,
): Record<string, unknown> {
  return {
    apiVersion: RESCUE_REPAIR_API_VERSION,
    requestId,
    operation,
    outcome: "ok",
    stateVersion: 2,
    state: "prepared",
    detail: {
      kind: "fstab-prepared",
      preparedId: `Q-${"a".repeat(32)}`,
      sessionId: `S-${"b".repeat(32)}`,
      planId: `P-${"c".repeat(32)}`,
      planHash: `sha256:${"2".repeat(64)}`,
      targetFingerprint: TARGET,
      beforeSha256: `sha256:${"3".repeat(64)}`,
      afterSha256: `sha256:${"4".repeat(64)}`,
      diffSha256: `sha256:${"5".repeat(64)}`,
      resourceId: RESCUE_FSTAB_RESOURCE_ID,
      backupLocator: `vault://repair/B-${"9".repeat(32)}`,
      actionId: "linux.fstab.disable-missing-uuid.v1",
      risk: "R2",
      backup: { state: "reserved", vaultDistinct: true },
      nextApprovalSequence: 1,
      confirmationRequired: RESCUE_FSTAB_CONFIRMATION,
    },
  };
}

function rollbackPreparedEnvelope(
  requestId: string,
  operation: RescueRepairOperation,
): Record<string, unknown> {
  return {
    apiVersion: RESCUE_ROLLBACK_API_VERSION,
    requestId,
    operation,
    outcome: "ok",
    stateVersion: 4,
    state: "prepared",
    detail: {
      kind: "fstab-rollback-prepared",
      preparedId: `Q-${"a".repeat(32)}`,
      rollbackId: `RB-${"b".repeat(32)}`,
      sessionId: `S-${"c".repeat(32)}`,
      planId: `P-${"d".repeat(32)}`,
      planHash: `sha256:${"6".repeat(64)}`,
      targetFingerprint: TARGET,
      source: {
        reservationId: `B-${"9".repeat(32)}`,
        transactionBindingSha256: `sha256:${"8".repeat(64)}`,
      },
      resourceId: RESCUE_FSTAB_RESOURCE_ID,
      backupLocator: `vault://repair/B-${"9".repeat(32)}`,
      actionId: "linux.fstab.restore",
      risk: "R2",
      nextApprovalSequence: 2,
      confirmationRequired: RESCUE_FSTAB_ROLLBACK_CONFIRMATION,
    },
  };
}

function idleEnvelope(
  requestId: string,
  operation: RescueRepairOperation,
): Record<string, unknown> {
  return {
    apiVersion: RESCUE_REPAIR_API_VERSION,
    requestId,
    operation,
    outcome: "ok",
    stateVersion: 1,
    state: "idle",
    detail: null,
  };
}

function terminalEnvelope(
  requestId: string,
  operation: RescueRepairOperation,
  state: "cancelled" | "manual-reconciliation-required",
): Record<string, unknown> {
  const manual = state === "manual-reconciliation-required";
  return {
    apiVersion: RESCUE_REPAIR_API_VERSION,
    requestId,
    operation,
    outcome: "ok",
    stateVersion: 8,
    state,
    detail: {
      kind: "terminal",
      terminalOutcome: manual ? "manual-reconciliation-required" : "cancelled",
      reservationId: manual ? `B-${"b".repeat(32)}` : null,
      transactionBindingSha256: manual ? `sha256:${"c".repeat(64)}` : null,
      rebootRequired: manual,
      prepareFailureStage: null,
    },
  };
}

function snapshot(
  state: "preparing" | "executing",
  stateVersion: number,
  detail: null,
): RescueRepairSnapshot {
  return {
    requestId: REQUEST,
    operation: "repair.status",
    stateVersion,
    state,
    detail,
  };
}

function frame(value: unknown, status = 200): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": String(new TextEncoder().encode(body).byteLength),
    },
  });
}
