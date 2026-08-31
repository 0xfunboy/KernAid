import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { test } from "node:test";
import {
  FLEET_WORK_ORDER_CLAIM_SCHEMA,
  FLEET_WORK_ORDER_RESULT_SCHEMA,
  parseWorkOrderClaimRequest,
  parseWorkOrderResult,
  workOrderActionCatalog,
  workOrderClaimSigningBytes,
  workOrderResultSigningBytes,
  type WorkOrderClaimRequest,
  type WorkOrderClaimRequestUnsigned,
  type WorkOrderResult,
  type WorkOrderResultUnsigned,
} from "../src/index.js";

const key = generateKeyPairSync("ed25519");
const tenantId = "tenant-work-order-test";
const deviceId = "KA-0123456789abcdef01234567";

test("work-order claim and result use closed direct-domain signatures", () => {
  const claimUnsigned: WorkOrderClaimRequestUnsigned = {
    schema: FLEET_WORK_ORDER_CLAIM_SCHEMA,
    tenantId,
    deviceId,
    issuedAt: "2026-08-31T18:00:00Z",
    nonce: randomBytes(32).toString("base64url"),
    leaseSeconds: 300,
  };
  const claim: WorkOrderClaimRequest = {
    ...claimUnsigned,
    signature: sign(
      null,
      workOrderClaimSigningBytes(claimUnsigned),
      key.privateKey,
    ).toString("base64url"),
  };
  assert.deepEqual(parseWorkOrderClaimRequest(claim), claim);
  assert.equal(
    verify(
      null,
      workOrderClaimSigningBytes(claim),
      key.publicKey,
      Buffer.from(claim.signature, "base64url"),
    ),
    true,
  );

  const resultUnsigned: WorkOrderResultUnsigned = {
    schema: FLEET_WORK_ORDER_RESULT_SCHEMA,
    tenantId,
    deviceId,
    workOrderId: "wo_0123456789abcdef0123456789abcdef",
    leaseId: "lease_0123456789abcdef0123456789abcdef",
    actionId: "linux.storage.health.v1",
    actionVersion: 1,
    outcome: "succeeded",
    completedAt: "2026-08-31T18:01:00Z",
    resultSha256: "a".repeat(64),
  };
  const result: WorkOrderResult = {
    ...resultUnsigned,
    signature: sign(
      null,
      workOrderResultSigningBytes(resultUnsigned),
      key.privateKey,
    ).toString("base64url"),
  };
  assert.deepEqual(parseWorkOrderResult(result), result);
  assert.equal(
    verify(
      null,
      workOrderResultSigningBytes(result),
      key.publicKey,
      Buffer.from(result.signature, "base64url"),
    ),
    true,
  );
});

test("work-order schemas reject shell-shaped fields and unknown actions", () => {
  assert.deepEqual(Object.keys(workOrderActionCatalog).sort(), [
    "linux.filesystem.health.v1",
    "linux.fstab.disable-missing-uuid.v1",
    "linux.storage.health.v1",
  ]);
  assert.throws(() =>
    parseWorkOrderClaimRequest({
      schema: FLEET_WORK_ORDER_CLAIM_SCHEMA,
      tenantId,
      deviceId,
      issuedAt: "2026-08-31T18:00:00Z",
      nonce: randomBytes(32).toString("base64url"),
      leaseSeconds: 300,
      signature: randomBytes(64).toString("base64url"),
      command: "sh -c id",
    }),
  );
  assert.throws(() =>
    parseWorkOrderResult({
      schema: FLEET_WORK_ORDER_RESULT_SCHEMA,
      tenantId,
      deviceId,
      workOrderId: "wo_0123456789abcdef0123456789abcdef",
      leaseId: "lease_0123456789abcdef0123456789abcdef",
      actionId: "shell.exec.v1",
      actionVersion: 1,
      outcome: "succeeded",
      completedAt: "2026-08-31T18:01:00Z",
      resultSha256: "a".repeat(64),
      signature: randomBytes(64).toString("base64url"),
    }),
  );
});
