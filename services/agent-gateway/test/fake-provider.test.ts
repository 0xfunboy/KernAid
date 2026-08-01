import assert from "node:assert/strict";
import test from "node:test";
import type { DiagnosisProposal } from "@kernaid/schemas";
import { LocalSessionDriver, type ActionExecutor } from "../src/fake-driver.js";
import type { ObservedEvidence, Provider } from "../src/fake-provider.js";
import { redactForProvider } from "../src/redaction.js";

const fingerprint = `sha256:${"1".repeat(64)}`;

async function stagedDriver(): Promise<{
  driver: LocalSessionDriver;
  sessionId: string;
  proposal: DiagnosisProposal;
  planId: string;
}> {
  const driver = new LocalSessionDriver();
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  await driver.requestEvidence(session.id, {
    collector: "linux.systemd.failed",
    target: "local-machine",
    observedContent: "demo.service loaded failed failed Demo",
  });
  let proposal: DiagnosisProposal | undefined;
  for await (const event of driver.sendUserPrompt(
    session.id,
    "Why does boot fail?",
  )) {
    if (event.proposal) proposal = event.proposal;
  }
  assert.ok(proposal);
  const plan = await driver.stagePlan(session.id, proposal);
  return { driver, sessionId: session.id, proposal, planId: plan.planId };
}

test("normalizes provider output, stages only R0, and exports a verified report", async () => {
  const { driver, sessionId, planId } = await stagedDriver();
  const events = [];
  for await (const event of driver.executePlan(planId)) events.push(event);
  assert.deepEqual(
    events.map((event) => [event.sequence, event.status]),
    [
      [1, "started"],
      [2, "succeeded"],
    ],
  );
  const report = await driver.exportReport(sessionId, "json");
  assert.equal(report.mediaType, "application/json");
  assert.match(report.sha256, /^[a-f0-9]{64}$/);
  assert.match(decodeURIComponent(report.uri), /"verification": "passed"/);
});

test("rejects replay and keeps a pre-execution report fail-closed", async () => {
  const { driver, sessionId, planId } = await stagedDriver();
  const before = await driver.exportReport(sessionId, "json");
  assert.match(decodeURIComponent(before.uri), /"verification": "not-run"/);
  await drain(driver.executePlan(planId));
  await assert.rejects(async () => {
    await drain(driver.executePlan(planId));
  }, /already executed/);
});

test("serializes concurrent execution and fails closed when the boundary rejects", async () => {
  let calls = 0;
  const rejectingExecutor: ActionExecutor = {
    async execute(): Promise<void> {
      calls += 1;
      throw new Error("stale target detail must not enter the report");
    },
  };
  const driver = new LocalSessionDriver(undefined, rejectingExecutor);
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  await driver.requestEvidence(session.id, {
    collector: "test",
    target: "fixture",
  });
  let proposal: DiagnosisProposal | undefined;
  for await (const event of driver.sendUserPrompt(session.id, "diagnose"))
    if (event.proposal) proposal = event.proposal;
  assert.ok(proposal);
  const plan = await driver.stagePlan(session.id, proposal);
  const first = driver.executePlan(plan.planId);
  const second = driver.executePlan(plan.planId);
  const [firstEvent, secondResult] = await Promise.all([
    first.next(),
    second.next().then(
      () => "unexpected success",
      (error: unknown) => String(error),
    ),
  ]);
  assert.equal(firstEvent.value?.status, "started");
  assert.match(secondResult, /already executed/);
  const failed = await first.next();
  assert.equal(failed.value?.status, "failed");
  assert.equal(calls, 1);
  const report = await driver.exportReport(session.id, "json");
  const decoded = decodeURIComponent(report.uri);
  assert.match(decoded, /"verification": "failed"/);
  assert.doesNotMatch(decoded, /stale target detail/);
});

test("rejects provider output with unknown fields or foreign evidence", async () => {
  class MaliciousProvider implements Provider {
    readonly capabilities = Object.freeze({
      streaming: false,
      structuredOutput: true,
      toolRequests: false,
      local: true,
    });

    constructor(private readonly foreignEvidence: boolean) {}
    async diagnose(
      _objective: string,
      evidence: readonly ObservedEvidence[],
    ): Promise<DiagnosisProposal> {
      return {
        schemaVersion: "1.0",
        diagnosis: "Injected proposal",
        confidence: 1,
        evidenceIds: [
          this.foreignEvidence
            ? "E-foreign"
            : (evidence[0]?.evidence.id ?? "E-missing"),
        ],
        requestedEvidence: [],
        ...(!this.foreignEvidence ? ({ command: "shell.exec" } as object) : {}),
      };
    }
  }

  for (const foreignEvidence of [false, true]) {
    const driver = new LocalSessionDriver(
      new MaliciousProvider(foreignEvidence),
    );
    const session = await driver.startSession({
      targetFingerprint: fingerprint,
      mode: "resident",
    });
    await driver.requestEvidence(session.id, {
      collector: "test",
      target: "fixture",
    });
    await assert.rejects(
      async () => {
        await drain(driver.sendUserPrompt(session.id, "diagnose"));
      },
      foreignEvidence ? /outside this session/ : /unknown field/,
    );
  }
});

test("redacts provider credentials from prompts and evidence", async () => {
  class InspectingProvider implements Provider {
    readonly capabilities = Object.freeze({
      streaming: false,
      structuredOutput: true,
      toolRequests: false,
      local: true,
    });

    async diagnose(
      objective: string,
      evidence: readonly ObservedEvidence[],
    ): Promise<DiagnosisProposal> {
      assert.doesNotMatch(objective, /sk-test-supersecret/);
      assert.doesNotMatch(
        evidence[0]?.content ?? "",
        /Bearer secret-token-value/,
      );
      assert.match(objective, /\[REDACTED\]/);
      assert.match(evidence[0]?.content ?? "", /\[REDACTED\]/);
      return {
        schemaVersion: "1.0",
        diagnosis: "No secret disclosed",
        confidence: 0.7,
        evidenceIds: evidence.map((item) => item.evidence.id),
        requestedEvidence: [],
      };
    }
  }
  const driver = new LocalSessionDriver(new InspectingProvider());
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  await driver.requestEvidence(session.id, {
    collector: "test",
    target: "fixture",
    observedContent: "Authorization: Bearer secret-token-value",
  });
  await drain(driver.sendUserPrompt(session.id, "key sk-test-supersecret"));
});

test("records only approvals bound to the staged plan and target", async () => {
  const { driver, planId } = await stagedDriver();
  await assert.rejects(
    driver.approvePlan(planId, {
      schemaVersion: "1.0",
      approvalId: "A-wrong",
      planId,
      targetFingerprint: `sha256:${"2".repeat(64)}`,
      approvedAt: new Date().toISOString(),
      approvedBy: "local-technician",
    }),
    /does not match/,
  );
  await driver.approvePlan(planId, {
    schemaVersion: "1.0",
    approvalId: "A-local",
    planId,
    targetFingerprint: fingerprint,
    approvedAt: new Date().toISOString(),
    approvedBy: "local-technician",
  });
});

test("standalone redaction covers common provider secret shapes", () => {
  const input =
    "OPENAI_API_KEY=abc123 sk-ant-abcdefghijk AIza012345678901234567890 Bearer abc.def.ghi";
  const output = redactForProvider(input);
  assert.doesNotMatch(output, /abc123|sk-ant-|AIza|abc\.def\.ghi/);
});

test("admits the qualified Windows evidence bound without widening other collectors", async () => {
  const driver = new LocalSessionDriver();
  const session = await driver.startSession({
    targetFingerprint: fingerprint,
    mode: "resident",
  });
  const largerThanLegacyBound = "x".repeat(64 * 1024 + 1);
  await driver.requestEvidence(session.id, {
    collector: "windows.event-log.window",
    target: "local-machine",
    observedContent: largerThanLegacyBound,
  });
  await assert.rejects(
    driver.requestEvidence(session.id, {
      collector: "linux.systemd.failed",
      target: "local-machine",
      observedContent: largerThanLegacyBound,
    }),
    /safe limit/u,
  );
  await assert.rejects(
    driver.requestEvidence(session.id, {
      collector: "windows.storage.identity",
      target: "local-machine",
      observedContent: largerThanLegacyBound,
    }),
    /safe limit/u,
  );
  await assert.rejects(
    driver.requestEvidence(session.id, {
      collector: "windows.event-log.window",
      target: "local-machine",
      observedContent: "x".repeat(1024 * 1024 + 1),
    }),
    /safe limit/u,
  );
});

async function drain(iterable: AsyncIterable<unknown>): Promise<void> {
  for await (const value of iterable) void value;
}
