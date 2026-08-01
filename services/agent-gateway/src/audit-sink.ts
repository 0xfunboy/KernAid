import {
  UNAVAILABLE_AUDIT_STATUS,
  parseArtifactRef,
  parseAuditRecord,
  parseAuditSealRequest,
  type ArtifactRef,
  type AuditRecord,
  type AuditSealRequest,
  type AuditSink,
  type AuditSinkStatus,
} from "@kernaid/session-driver";

const MAX_RECORDS_PER_SESSION = 2_048;

interface StoredSession {
  targetFingerprint: string;
  records: AuditRecord[];
  evidenceIds: Set<string>;
  planIds: Set<string>;
}

export class InMemoryAuditSink implements AuditSink {
  readonly status: AuditSinkStatus = UNAVAILABLE_AUDIT_STATUS;

  readonly #sessions = new Map<string, StoredSession>();

  async append(value: AuditRecord): Promise<void> {
    const item = parseAuditRecord(value);
    const existing = this.#sessions.get(item.sessionId);
    if (existing === undefined) {
      if (item.sequence !== 1 || item.type !== "session.started")
        throw auditAppendError();
      this.#sessions.set(item.sessionId, {
        targetFingerprint: item.payload.targetFingerprint,
        records: [item],
        evidenceIds: new Set(),
        planIds: new Set(),
      });
      return;
    }

    if (
      existing.records.length >= MAX_RECORDS_PER_SESSION ||
      item.sequence !== existing.records.length + 1 ||
      item.type === "session.started"
    )
      throw auditAppendError();
    this.#assertSessionBinding(existing, item);
    existing.records.push(item);
    if (item.type === "evidence")
      existing.evidenceIds.add(item.payload.evidenceId);
    if (item.type === "plan") existing.planIds.add(item.payload.planId);
  }

  async sealReport(value: AuditSealRequest): Promise<ArtifactRef> {
    const request = parseAuditSealRequest(value);
    const session = this.#sessions.get(request.sessionId);
    const latest = session?.records.at(-1);
    if (
      latest?.type !== "report" ||
      latest.payload.format !== request.format ||
      latest.payload.payloadMediaType !== request.payloadMediaType ||
      latest.payload.payloadSha256 !== request.payloadSha256
    )
      throw auditSealError();
    if ((await sha256(request.body)) !== request.payloadSha256)
      throw auditSealError();
    return parseArtifactRef({
      mediaType: request.payloadMediaType,
      payloadMediaType: request.payloadMediaType,
      uri: `data:${request.payloadMediaType};charset=utf-8,${encodeURIComponent(request.body)}`,
      sha256: request.payloadSha256,
      payloadSha256: request.payloadSha256,
      auditStatus: this.status,
    });
  }

  records(sessionId: string): readonly AuditRecord[] {
    return structuredClone(this.#sessions.get(sessionId)?.records ?? []);
  }

  #assertSessionBinding(session: StoredSession, item: AuditRecord): void {
    switch (item.type) {
      case "evidence":
        if (session.evidenceIds.has(item.payload.evidenceId))
          throw auditAppendError();
        return;
      case "diagnosis":
        if (
          item.payload.evidenceIds.some(
            (evidenceId) => !session.evidenceIds.has(evidenceId),
          )
        )
          throw auditAppendError();
        return;
      case "plan":
        if (
          item.payload.targetFingerprint !== session.targetFingerprint ||
          item.payload.evidenceIds.some(
            (evidenceId) => !session.evidenceIds.has(evidenceId),
          ) ||
          session.planIds.has(item.payload.planId)
        )
          throw auditAppendError();
        return;
      case "approval":
        if (
          item.payload.targetFingerprint !== session.targetFingerprint ||
          !session.planIds.has(item.payload.planId)
        )
          throw auditAppendError();
        return;
      case "execution":
        if (!session.planIds.has(item.payload.planId)) throw auditAppendError();
        return;
      case "report":
        return;
      case "session.started":
        throw auditAppendError();
    }
  }
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

function auditAppendError(): Error {
  return new Error("Audit append rejected");
}

function auditSealError(): Error {
  return new Error("Audit report sealing rejected");
}
