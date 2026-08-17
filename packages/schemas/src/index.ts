export type Risk = "R0" | "R1" | "R2" | "R3" | "R4";
export interface Evidence {
  schemaVersion: "1.0";
  id: string;
  collector: string;
  target: string;
  capturedAt: string;
  contentType: string;
  sha256: string;
  sensitivity: "public" | "system" | "sensitive";
  trust: "observed-untrusted";
  summary: string;
  blobRef: string;
}
export interface DiagnosisProposal {
  schemaVersion: "1.0";
  diagnosis: string;
  confidence: number;
  evidenceIds: string[];
  requestedEvidence: string[];
}
export interface PlanStep {
  action: string;
  args: Record<string, unknown>;
  preconditions: string[];
  backup: "not-required" | "required" | "inherited";
  validation: string;
  rollback: string | null;
}
export interface ValidatedPlan {
  schemaVersion: "1.0";
  planId: string;
  targetFingerprint: string;
  diagnosis: string;
  evidenceIds: string[];
  risk: Risk;
  steps: PlanStep[];
}
export interface Approval {
  schemaVersion: "1.0";
  approvalId: string;
  planId: string;
  targetFingerprint: string;
  approvedAt: string;
  approvedBy: string;
  typedConfirmation?: string;
}
export interface ExecutionEvent {
  schemaVersion: "1.0";
  planId: string;
  sequence: number;
  status: "started" | "succeeded" | "failed" | "rolled-back";
  action: string;
  message: string;
  capturedAt: string;
}
export interface SessionReport {
  schemaVersion: "1.0";
  sessionId: string;
  targetFingerprint: string;
  facts: Evidence[];
  inferences: DiagnosisProposal[];
  decisions: Approval[];
  events: ExecutionEvent[];
  verification: "not-run" | "passed" | "failed";
  unresolvedRisks: string[];
}
export {
  MAX_SESSION_REPORT_BYTES,
  SchemaValidationError,
  decodeSessionReportJson,
  parseApproval,
  parseDiagnosisProposal,
  parseEvidence,
  parseExecutionEvent,
  parseSessionReport,
  parseSessionReportJson,
  parseValidatedPlan,
  sessionReportSemanticBindingsAreValid,
} from "./validation.js";
