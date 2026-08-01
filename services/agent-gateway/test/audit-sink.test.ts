import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  SECURE_AUDIT_STATUS,
  SIGNED_REPORT_MEDIA_TYPE,
  UNAVAILABLE_AUDIT_STATUS,
  parseArtifactRef,
  parseAuditRecord,
  type ArtifactRef,
  type AuditRecord,
  type AuditSealRequest,
  type AuditSink,
  type AuditSinkStatus,
} from "@kernaid/session-driver";
import type { DiagnosisProposal, ValidatedPlan } from "@kernaid/schemas";
import { InMemoryAuditSink } from "../src/audit-sink.js";
import { LocalSessionDriver } from "../src/fake-driver.js";

const fingerprint = `sha256:${"3".repeat(64)}`;

test("volatile audit records every transition in order and seals an explicit unsigned artifact", async () => {
  const sink = new InMemoryAuditSink();
  const driver = new LocalSessionDriver(undefined, undefined, sink);
  const promptSecret = `sk-${randomUUID().replaceAll("-", "")}`;
  const bearerSecret = `token-${randomUUID().replaceAll("-", "")}`;
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  assert.deepEqual(session.auditStatus, UNAVAILABLE_AUDIT_STATUS);

  await driver.requestEvidence(session.id, {
    collector: "linux.systemd.failed",
    target: "local-machine",
    summary: `OPENAI_API_KEY=${promptSecret}`,
    observedContent: `demo.service loaded failed failed Demo\nBearer ${bearerSecret}`,
  });
  const proposal = await diagnosis(
    driver,
    session.id,
    `Diagnose this host; accidental token ${promptSecret}`,
  );
  const plan = await driver.stagePlan(session.id, proposal);
  await driver.approvePlan(plan.planId, {
    schemaVersion: "1.0",
    approvalId: "A-audit-order",
    planId: plan.planId,
    targetFingerprint: fingerprint,
    approvedAt: "2026-08-01T00:00:00.000Z",
    approvedBy: promptSecret,
    typedConfirmation: `Bearer ${bearerSecret}`,
  });
  await drain(driver.executePlan(plan.planId));
  const artifact = await driver.exportReport(session.id, "json");

  assert.equal(artifact.mediaType, "application/json");
  assert.equal(artifact.payloadMediaType, "application/json");
  assert.equal(artifact.sha256, artifact.payloadSha256);
  assert.deepEqual(artifact.auditStatus, UNAVAILABLE_AUDIT_STATUS);
  const reportBody = decodeURIComponent(artifact.uri);
  assert.match(reportBody, /non è firmato e non è persistente/u);
  assert.doesNotMatch(reportBody, new RegExp(promptSecret, "u"));
  assert.doesNotMatch(reportBody, new RegExp(bearerSecret, "u"));

  const records = sink.records(session.id);
  assert.deepEqual(
    records.map((record) => record.type),
    [
      "session.started",
      "evidence",
      "diagnosis",
      "plan",
      "approval",
      "execution",
      "execution",
      "report",
    ],
  );
  assert.deepEqual(
    records.map((record) => record.sequence),
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  assert.ok(records.every((record) => record.sessionId === session.id));
  const encodedRecords = JSON.stringify(records);
  assert.doesNotMatch(encodedRecords, new RegExp(promptSecret, "u"));
  assert.doesNotMatch(encodedRecords, new RegExp(bearerSecret, "u"));
  assert.doesNotMatch(encodedRecords, /demo\.service/u);
});

test("in-memory audit keeps sequences and bindings isolated per session", async () => {
  const sink = new InMemoryAuditSink();
  const driver = new LocalSessionDriver(undefined, undefined, sink);
  const first = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  const second = await driver.startSession({
    targetFingerprint: `sha256:${"4".repeat(64)}`,
    mode: "rescue",
  });
  await driver.requestEvidence(first.id, {
    collector: "first.collector",
    target: "first-target",
  });
  await driver.requestEvidence(second.id, {
    collector: "second.collector",
    target: "second-target",
  });

  const firstRecords = sink.records(first.id);
  const secondRecords = sink.records(second.id);
  assert.deepEqual(
    firstRecords.map((record) => record.sequence),
    [1, 2],
  );
  assert.deepEqual(
    secondRecords.map((record) => record.sequence),
    [1, 2],
  );
  assert.ok(firstRecords.every((record) => record.sessionId === first.id));
  assert.ok(secondRecords.every((record) => record.sessionId === second.id));
  assert.doesNotMatch(JSON.stringify(firstRecords), new RegExp(second.id, "u"));
  assert.doesNotMatch(JSON.stringify(secondRecords), new RegExp(first.id, "u"));
});

test("an audit append failure closes the affected session at every phase", async (context) => {
  await context.test("session start", async () => {
    const sink = new FailingAuditSink(1);
    const driver = new LocalSessionDriver(undefined, undefined, sink);
    await assertAuditFailure(
      driver.startSession({ targetFingerprint: fingerprint, mode: "resident" }),
      sink.secretMarker,
    );
  });

  await context.test("evidence", async () => {
    const sink = new FailingAuditSink(2);
    const driver = new LocalSessionDriver(undefined, undefined, sink);
    const session = await driver.startSession({
      targetFingerprint: fingerprint,
      mode: "resident",
    });
    await assertAuditFailure(
      driver.requestEvidence(session.id, {
        collector: "test",
        target: "fixture",
      }),
      sink.secretMarker,
    );
    await assertAuditFailure(
      driver.exportReport(session.id, "json"),
      sink.secretMarker,
    );
  });

  await context.test("diagnosis", async () => {
    const sink = new FailingAuditSink(3);
    const { driver, sessionId } = await withEvidence(sink);
    await assertAuditFailure(
      drain(driver.sendUserPrompt(sessionId, "diagnose")),
      sink.secretMarker,
    );
    await assertAuditFailure(
      driver.exportReport(sessionId, "json"),
      sink.secretMarker,
    );
  });

  await context.test("plan", async () => {
    const sink = new FailingAuditSink(4);
    const prepared = await withDiagnosis(sink);
    await assertAuditFailure(
      prepared.driver.stagePlan(prepared.sessionId, prepared.proposal),
      sink.secretMarker,
    );
    await assertAuditFailure(
      prepared.driver.exportReport(prepared.sessionId, "json"),
      sink.secretMarker,
    );
  });

  await context.test("approval", async () => {
    const sink = new FailingAuditSink(5);
    const prepared = await withPlan(sink);
    await assertAuditFailure(
      prepared.driver.approvePlan(prepared.plan.planId, {
        schemaVersion: "1.0",
        approvalId: "A-failing-audit",
        planId: prepared.plan.planId,
        targetFingerprint: fingerprint,
        approvedAt: "2026-08-01T00:00:00.000Z",
        approvedBy: "local-technician",
      }),
      sink.secretMarker,
    );
    await assertAuditFailure(
      prepared.driver.exportReport(prepared.sessionId, "json"),
      sink.secretMarker,
    );
  });

  await context.test("execution start", async () => {
    const sink = new FailingAuditSink(5);
    const prepared = await withPlan(sink);
    await assertAuditFailure(
      drain(prepared.driver.executePlan(prepared.plan.planId)),
      sink.secretMarker,
    );
    await assertAuditFailure(
      prepared.driver.exportReport(prepared.sessionId, "json"),
      sink.secretMarker,
    );
  });

  await context.test("execution completion", async () => {
    const sink = new FailingAuditSink(6);
    const prepared = await withPlan(sink);
    const execution = prepared.driver.executePlan(prepared.plan.planId);
    const started = await execution.next();
    assert.equal(started.value?.status, "started");
    await assertAuditFailure(execution.next(), sink.secretMarker);
    await assertAuditFailure(
      prepared.driver.exportReport(prepared.sessionId, "json"),
      sink.secretMarker,
    );
  });

  await context.test("report append", async () => {
    const sink = new FailingAuditSink(5);
    const prepared = await withPlan(sink);
    await assertAuditFailure(
      prepared.driver.exportReport(prepared.sessionId, "json"),
      sink.secretMarker,
    );
  });
});

test("report sealing is fail-closed after its audit record was accepted", async () => {
  const sink = new FailingAuditSink(undefined, true);
  const prepared = await withPlan(sink);
  await assertAuditFailure(
    prepared.driver.exportReport(prepared.sessionId, "json"),
    sink.secretMarker,
  );
  assert.equal(sink.records(prepared.sessionId).at(-1)?.type, "report");
  await assertAuditFailure(
    drain(prepared.driver.executePlan(prepared.plan.planId)),
    sink.secretMarker,
  );
  await assertAuditFailure(
    prepared.driver.exportReport(prepared.sessionId, "json"),
    sink.secretMarker,
  );
});

test("audit contracts reject oversized records and ambiguous signed artifacts", () => {
  assert.throws(
    () =>
      parseAuditRecord({
        schemaVersion: "1.0",
        type: "diagnosis",
        sessionId: "S-contract",
        sequence: 2,
        capturedAt: "2026-08-01T00:00:00.000Z",
        payload: {
          diagnosisSha256: "a".repeat(64),
          confidence: 0.5,
          evidenceIds: Array.from({ length: 129 }, (_, index) => `E-${index}`),
          requestedEvidenceCount: 0,
        },
      }),
    /identifier collection/u,
  );
  assert.throws(
    () =>
      parseArtifactRef({
        mediaType: "application/json",
        payloadMediaType: "application/json",
        uri: "data:application/json,%7B%7D",
        sha256: "a".repeat(64),
        payloadSha256: "b".repeat(64),
        auditStatus: UNAVAILABLE_AUDIT_STATUS,
      }),
    /volatile artifact/u,
  );
  assert.doesNotThrow(() =>
    parseArtifactRef({
      mediaType: SIGNED_REPORT_MEDIA_TYPE,
      payloadMediaType: "application/json",
      uri: "data:application/vnd.kernaid.signed-report+json;base64,e30=",
      sha256: "a".repeat(64),
      payloadSha256: "b".repeat(64),
      auditStatus: SECURE_AUDIT_STATUS,
    }),
  );
  assert.throws(
    () =>
      parseArtifactRef({
        mediaType: SIGNED_REPORT_MEDIA_TYPE,
        payloadMediaType: "application/json",
        uri: "https://attacker.invalid/report.json",
        sha256: "a".repeat(64),
        payloadSha256: "b".repeat(64),
        auditStatus: SECURE_AUDIT_STATUS,
      }),
    /signed report container/u,
  );
});

class FailingAuditSink implements AuditSink {
  readonly status: AuditSinkStatus;
  readonly secretMarker = `sink-secret-${randomUUID()}`;

  readonly #delegate = new InMemoryAuditSink();
  readonly #failAppendAt?: number;
  readonly #failSeal: boolean;
  #appendCalls = 0;

  constructor(failAppendAt?: number, failSeal = false) {
    this.#failAppendAt = failAppendAt;
    this.#failSeal = failSeal;
    this.status = this.#delegate.status;
  }

  async append(record: AuditRecord): Promise<void> {
    this.#appendCalls += 1;
    if (this.#appendCalls === this.#failAppendAt)
      throw new Error(this.secretMarker);
    await this.#delegate.append(record);
  }

  async sealReport(request: AuditSealRequest): Promise<ArtifactRef> {
    if (this.#failSeal) throw new Error(this.secretMarker);
    return this.#delegate.sealReport(request);
  }

  records(sessionId: string): readonly AuditRecord[] {
    return this.#delegate.records(sessionId);
  }
}

async function withEvidence(sink: AuditSink): Promise<{
  driver: LocalSessionDriver;
  sessionId: string;
}> {
  const driver = new LocalSessionDriver(undefined, undefined, sink);
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  await driver.requestEvidence(session.id, {
    collector: "test",
    target: "fixture",
  });
  return { driver, sessionId: session.id };
}

async function withDiagnosis(sink: AuditSink): Promise<{
  driver: LocalSessionDriver;
  sessionId: string;
  proposal: DiagnosisProposal;
}> {
  const prepared = await withEvidence(sink);
  return {
    ...prepared,
    proposal: await diagnosis(prepared.driver, prepared.sessionId, "diagnose"),
  };
}

async function withPlan(sink: AuditSink): Promise<{
  driver: LocalSessionDriver;
  sessionId: string;
  plan: ValidatedPlan;
}> {
  const prepared = await withDiagnosis(sink);
  return {
    driver: prepared.driver,
    sessionId: prepared.sessionId,
    plan: await prepared.driver.stagePlan(
      prepared.sessionId,
      prepared.proposal,
    ),
  };
}

async function diagnosis(
  driver: LocalSessionDriver,
  sessionId: string,
  prompt: string,
): Promise<DiagnosisProposal> {
  let proposal: DiagnosisProposal | undefined;
  for await (const event of driver.sendUserPrompt(sessionId, prompt))
    if (event.proposal !== undefined) proposal = event.proposal;
  assert.ok(proposal);
  return proposal;
}

async function drain(iterable: AsyncIterable<unknown>): Promise<void> {
  for await (const event of iterable) void event;
}

async function assertAuditFailure(
  promise: Promise<unknown>,
  secretMarker: string,
): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.match(String(error), /Audit persistence failed/u);
    assert.doesNotMatch(String(error), new RegExp(secretMarker, "u"));
    return true;
  });
}
