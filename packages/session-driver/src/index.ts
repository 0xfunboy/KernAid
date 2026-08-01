import type {
  Approval,
  DiagnosisProposal,
  Evidence,
  ExecutionEvent,
  ValidatedPlan,
} from "@kernaid/schemas";
import type { ArtifactRef, AuditSinkStatus } from "./audit.js";

export interface StartSession {
  targetFingerprint: string;
  mode: "rescue" | "resident";
}

export interface SessionInfo {
  id: string;
  state: "observe";
  auditStatus: AuditSinkStatus;
}

export interface EvidenceRequest {
  collector: string;
  target: string;
  summary?: string;
  observedContent?: string;
  contentType?: string;
}

export type ReportFormat = "json" | "markdown";

export type SessionEvent = {
  type: "status" | "proposal" | "error";
  message: string;
  proposal?: DiagnosisProposal;
};

export interface SessionDriver {
  startSession(input: StartSession): Promise<SessionInfo>;
  sendUserPrompt(
    sessionId: string,
    prompt: string,
  ): AsyncIterable<SessionEvent>;
  requestEvidence(
    sessionId: string,
    request: EvidenceRequest,
  ): Promise<Evidence[]>;
  stagePlan(
    sessionId: string,
    proposal: DiagnosisProposal,
  ): Promise<ValidatedPlan>;
  approvePlan(planId: string, approval: Approval): Promise<void>;
  executePlan(planId: string): AsyncIterable<ExecutionEvent>;
  rollback(planId: string): AsyncIterable<ExecutionEvent>;
  exportReport(sessionId: string, format: ReportFormat): Promise<ArtifactRef>;
}

export {
  AuditContractError,
  SECURE_AUDIT_STATUS,
  SIGNED_REPORT_MEDIA_TYPE,
  UNAVAILABLE_AUDIT_STATUS,
  auditStatusesEqual,
  parseArtifactRef,
  parseAuditRecord,
  parseAuditSealRequest,
  parseAuditSinkStatus,
} from "./audit.js";
export type {
  ArtifactRef,
  ApprovalAuditRecord,
  ArtifactMediaType,
  AuditRecord,
  AuditRecordType,
  AuditSealRequest,
  AuditSink,
  AuditSinkStatus,
  DiagnosisAuditRecord,
  EvidenceAuditRecord,
  ExecutionAuditRecord,
  PlanAuditRecord,
  ReportAuditRecord,
  ReportPayloadMediaType,
  SessionStartedAuditRecord,
} from "./audit.js";
