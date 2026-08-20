import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import type { Provider } from "../src/fake-provider.js";
import { LocalSessionDriver } from "../src/fake-driver.js";
import {
  LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN,
  canonicalLinuxSnapshotJson,
} from "@kernaid/schemas";

const snapshot = JSON.parse(
  readFileSync(
    new URL(
      "../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as unknown;
const snapshotSha256 = readFileSync(
  new URL(
    "../../../tests/fixtures/linux-normalized-snapshot/expected/snapshot.v1.sha256",
    import.meta.url,
  ),
  "utf8",
).trim();
const linuxP0Collectors = [
  "linux.block.inventory",
  "linux.mounts.read-only",
  "linux.systemd.failed",
  "linux.systemd.state",
  "linux.fstab",
  "linux.df",
  "linux.network.links",
  "linux.network.routes",
  "linux.dpkg.audit",
];

function envelope(
  mode: "resident" | "rescue",
  snapshotValue: unknown = snapshot,
): string {
  const hash = createHash("sha256")
    .update(LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN)
    .update(canonicalLinuxSnapshotJson(snapshotValue))
    .digest("hex");
  return JSON.stringify({
    schemaVersion: "1.0",
    kind: "linux-normalized-snapshot",
    snapshotSha256: snapshotValue === snapshot ? snapshotSha256 : hash,
    capture:
      mode === "resident"
        ? {
            mode: "resident",
            targetScope: "running-root",
            accessPolicy: "fixed-descriptor-read-only",
            callerSuppliedPath: false,
            mutationRequested: false,
            crossDeviceTraversalAllowed: false,
          }
        : {
            mode: "rescue",
            targetScope: "selected-installed-target",
            accessPolicy: "temporary-read-only-no-replay",
            deviceOpenedReadOnly: true,
            journalReplayPrevented: true,
            privateMountNamespace: true,
            mountCleanupVerified: true,
            mutationPerformed: false,
            crossDeviceTraversalAllowed: false,
          },
    snapshot: snapshotValue,
  });
}

async function drain(stream: AsyncIterable<unknown>): Promise<void> {
  for await (const event of stream) {
    // Consume the driver operation to its terminal outcome.
    void event;
  }
}

test("complete Linux P0 evidence cannot cross admission without the common snapshot", async () => {
  const driver = new LocalSessionDriver(
    undefined,
    undefined,
    undefined,
    "linux-p0-v1",
  );
  const session = await driver.startSession({
    mode: "resident",
    targetFingerprint: `sha256:${"1".repeat(64)}`,
  });
  for (const collector of linuxP0Collectors)
    await driver.requestEvidence(session.id, {
      collector,
      target: "local-machine",
      observedContent: "{}",
    });
  await assert.rejects(
    drain(driver.sendUserPrompt(session.id, "Diagnose")),
    /exact Linux Resident P0 corpus is required/u,
  );
});

test("snapshot capture mode and target are bound to the session before storage", async () => {
  const driver = new LocalSessionDriver(
    undefined,
    undefined,
    undefined,
    "linux-p0-v1",
  );
  const session = await driver.startSession({
    mode: "resident",
    targetFingerprint: `sha256:${"2".repeat(64)}`,
  });
  await assert.rejects(
    driver.requestEvidence(session.id, {
      collector: "linux.normalized-snapshot.v1",
      target: "local-machine",
      contentType: "application/json",
      observedContent: envelope("rescue"),
    }),
    /admission binding is invalid/u,
  );

  const rescueSession = await driver.startSession({
    mode: "rescue",
    targetFingerprint: `sha256:${"4".repeat(64)}`,
  });
  await assert.rejects(
    driver.requestEvidence(rescueSession.id, {
      collector: "linux.normalized-snapshot.v1",
      target: "selected-installed-target",
      contentType: "application/json",
      observedContent: envelope("resident"),
    }),
    /admission binding is invalid/u,
  );

  const tampered = JSON.parse(envelope("resident")) as {
    snapshotSha256: string;
  };
  tampered.snapshotSha256 = "0".repeat(64);
  await assert.rejects(
    driver.requestEvidence(session.id, {
      collector: "linux.normalized-snapshot.v1",
      target: "local-machine",
      contentType: "application/json",
      observedContent: JSON.stringify(tampered),
    }),
    /admission binding is invalid/u,
  );
});

test("Linux Resident snapshot-only and partial corpora fail before provider invocation", async () => {
  for (const collectors of [[], [linuxP0Collectors[0]!]]) {
    let providerCalled = false;
    const provider: Provider = {
      capabilities: {
        streaming: false,
        structuredOutput: true,
        toolRequests: false,
        local: true,
      },
      async diagnose() {
        providerCalled = true;
        throw new Error("provider must not be called");
      },
    };
    const driver = new LocalSessionDriver(
      provider,
      undefined,
      undefined,
      "linux-p0-v1",
    );
    const session = await driver.startSession({
      mode: "resident",
      targetFingerprint: `sha256:${"5".repeat(64)}`,
    });
    await driver.requestEvidence(session.id, {
      collector: "linux.normalized-snapshot.v1",
      target: "local-machine",
      contentType: "application/json",
      observedContent: envelope("resident"),
    });
    for (const collector of collectors)
      await driver.requestEvidence(session.id, {
        collector,
        target: "local-machine",
        observedContent: "{}",
      });
    await assert.rejects(
      drain(driver.sendUserPrompt(session.id, "Diagnose")),
      /exact Linux Resident P0 corpus is required/u,
    );
    assert.equal(providerCalled, false);
  }
});

test("Linux profiles reject foreign targets before provider invocation", async () => {
  for (const mode of ["resident", "rescue"] as const) {
    let providerCalled = false;
    const provider: Provider = {
      capabilities: {
        streaming: false,
        structuredOutput: true,
        toolRequests: false,
        local: true,
      },
      async diagnose() {
        providerCalled = true;
        throw new Error("provider must not be called");
      },
    };
    const driver = new LocalSessionDriver(
      provider,
      undefined,
      undefined,
      "linux-p0-v1",
    );
    const session = await driver.startSession({
      mode,
      targetFingerprint: `sha256:${"9".repeat(64)}`,
    });
    const snapshotRequest = {
      collector: "linux.normalized-snapshot.v1",
      target: mode === "resident" ? "local-machine" : "foreign-machine",
      contentType: "application/json",
      observedContent: envelope(mode),
    };
    if (mode === "rescue") {
      await assert.rejects(
        driver.requestEvidence(session.id, snapshotRequest),
        /admission binding is invalid/u,
      );
      assert.equal(providerCalled, false);
      continue;
    }
    await driver.requestEvidence(session.id, snapshotRequest);
    if (mode === "resident") {
      await driver.requestEvidence(session.id, {
        collector: "system.hostname",
        target: "local-machine",
        observedContent: "production-hostname",
      });
      for (const collector of linuxP0Collectors)
        await driver.requestEvidence(session.id, {
          collector,
          target: "foreign-machine",
          observedContent: "foreign body canary",
        });
    }
    await assert.rejects(
      drain(driver.sendUserPrompt(session.id, "Diagnose")),
      /exact Linux Resident P0 corpus is required/u,
    );
    assert.equal(providerCalled, false);
  }
});

test("Linux profiles reject extra collectors before provider invocation", async () => {
  for (const mode of ["resident", "rescue"] as const) {
    let providerCalled = false;
    const provider: Provider = {
      capabilities: {
        streaming: false,
        structuredOutput: true,
        toolRequests: false,
        local: true,
      },
      async diagnose() {
        providerCalled = true;
        throw new Error("provider must not be called");
      },
    };
    const driver = new LocalSessionDriver(
      provider,
      undefined,
      undefined,
      "linux-p0-v1",
    );
    const session = await driver.startSession({
      mode,
      targetFingerprint: `sha256:${"a".repeat(64)}`,
    });
    const target =
      mode === "resident" ? "local-machine" : "selected-installed-target";
    await driver.requestEvidence(session.id, {
      collector: "linux.normalized-snapshot.v1",
      target,
      contentType: "application/json",
      observedContent: envelope(mode),
    });
    if (mode === "resident") {
      await driver.requestEvidence(session.id, {
        collector: "system.hostname",
        target,
        observedContent: "production-hostname",
      });
      for (const collector of linuxP0Collectors)
        await driver.requestEvidence(session.id, {
          collector,
          target,
          observedContent: "{}",
        });
    }
    await driver.requestEvidence(session.id, {
      collector: "linux.raw.uncontracted",
      target,
      observedContent: "extra body canary",
    });
    await assert.rejects(
      drain(driver.sendUserPrompt(session.id, "Diagnose")),
      mode === "resident"
        ? /exact Linux Resident P0 corpus is required/u
        : /exact Linux Rescue snapshot corpus is required/u,
    );
    assert.equal(providerCalled, false);
  }
});

test("Linux profiles reject duplicate corpus collectors before provider invocation", async () => {
  for (const mode of ["resident", "rescue"] as const) {
    let providerCalled = false;
    const driver = new LocalSessionDriver(
      {
        capabilities: {
          streaming: false,
          structuredOutput: true,
          toolRequests: false,
          local: true,
        },
        async diagnose() {
          providerCalled = true;
          throw new Error("provider must not be called");
        },
      },
      undefined,
      undefined,
      "linux-p0-v1",
    );
    const session = await driver.startSession({
      mode,
      targetFingerprint: `sha256:${"b".repeat(64)}`,
    });
    const target =
      mode === "resident" ? "local-machine" : "selected-installed-target";
    const snapshotRequest = {
      collector: "linux.normalized-snapshot.v1",
      target,
      contentType: "application/json",
      observedContent: envelope(mode),
    };
    await driver.requestEvidence(session.id, snapshotRequest);
    if (mode === "rescue") {
      await assert.rejects(
        driver.requestEvidence(session.id, snapshotRequest),
        /duplicated/u,
      );
      assert.equal(providerCalled, false);
      continue;
    }
    await driver.requestEvidence(session.id, {
      collector: "system.hostname",
      target,
      observedContent: "production-hostname",
    });
    for (const [index, collector] of linuxP0Collectors.entries())
      await driver.requestEvidence(session.id, {
        collector:
          index === linuxP0Collectors.length - 1
            ? linuxP0Collectors[0]!
            : collector,
        target,
        observedContent: "{}",
      });
    await assert.rejects(
      drain(driver.sendUserPrompt(session.id, "Diagnose")),
      /exact Linux Resident P0 corpus is required/u,
    );
    assert.equal(providerCalled, false);
  }
});

test("trusted Linux context cannot be downgraded and legacy context rejects Linux collectors", async () => {
  const linuxDriver = new LocalSessionDriver(
    undefined,
    undefined,
    undefined,
    "linux-p0-v1",
  );
  for (const attemptedProfile of [undefined, "legacy-non-linux"] as const) {
    await assert.rejects(
      linuxDriver.startSession({
        mode: "resident",
        targetFingerprint: `sha256:${"6".repeat(64)}`,
        evidenceProfile: attemptedProfile,
      } as Parameters<LocalSessionDriver["startSession"]>[0]),
      /trusted driver context/u,
    );
  }

  let providerCalled = false;
  const legacyDriver = new LocalSessionDriver({
    capabilities: {
      streaming: false,
      structuredOutput: true,
      toolRequests: false,
      local: true,
    },
    async diagnose(_objective, evidence) {
      providerCalled = true;
      return {
        schemaVersion: "1.0",
        diagnosis: "Legacy non-P0 observation.",
        confidence: 0.2,
        evidenceIds: [evidence[0]!.evidence.id],
        requestedEvidence: [],
      };
    },
  });
  const legacySession = await legacyDriver.startSession({
    mode: "resident",
    targetFingerprint: `sha256:${"7".repeat(64)}`,
  });
  await assert.rejects(
    legacyDriver.requestEvidence(legacySession.id, {
      collector: "linux.block.inventory",
      target: "local-machine",
      observedContent: "legacy single observation",
    }),
    /trusted Linux P0 context/u,
  );
  assert.equal(providerCalled, false);
});

test("unsupported multi-filesystem snapshots are rejected for Resident and Rescue admission", async () => {
  const unsupported = structuredClone(snapshot) as {
    topology: {
      separateEtcMountPresent: boolean;
      relevantSeparateMountPresent: boolean;
      supported: boolean;
    };
  };
  unsupported.topology.separateEtcMountPresent = true;
  unsupported.topology.relevantSeparateMountPresent = true;
  unsupported.topology.supported = false;
  for (const mode of ["resident", "rescue"] as const) {
    const driver = new LocalSessionDriver(
      undefined,
      undefined,
      undefined,
      "linux-p0-v1",
    );
    const session = await driver.startSession({
      mode,
      targetFingerprint: `sha256:${"8".repeat(64)}`,
    });
    await assert.rejects(
      driver.requestEvidence(session.id, {
        collector: "linux.normalized-snapshot.v1",
        target:
          mode === "resident" ? "local-machine" : "selected-installed-target",
        contentType: "application/json",
        observedContent: envelope(mode, unsupported),
      }),
      /topology is unsupported/u,
    );
  }
});

test("production-shaped Resident corpus reaches the provider only when all 11 records are exact", async () => {
  let providerCalled = false;
  const provider: Provider = {
    capabilities: {
      streaming: false,
      structuredOutput: true,
      toolRequests: false,
      local: true,
    },
    async diagnose(_objective, evidence) {
      providerCalled = true;
      return {
        schemaVersion: "1.0",
        diagnosis: "Bound Linux snapshot admitted.",
        confidence: 1,
        evidenceIds: [evidence[0]!.evidence.id],
        requestedEvidence: [],
      };
    },
  };
  const driver = new LocalSessionDriver(
    provider,
    undefined,
    undefined,
    "linux-p0-v1",
  );
  const session = await driver.startSession({
    mode: "resident",
    targetFingerprint: `sha256:${"3".repeat(64)}`,
  });
  await driver.requestEvidence(session.id, {
    collector: "linux.normalized-snapshot.v1",
    target: "local-machine",
    contentType: "application/json",
    observedContent: envelope("resident"),
  });
  await driver.requestEvidence(session.id, {
    collector: "system.hostname",
    target: "local-machine",
    observedContent: "production-hostname",
  });
  for (const collector of linuxP0Collectors)
    await driver.requestEvidence(session.id, {
      collector,
      target: "local-machine",
      observedContent: "{}",
    });
  await drain(driver.sendUserPrompt(session.id, "Diagnose"));
  assert.equal(providerCalled, true);
});
