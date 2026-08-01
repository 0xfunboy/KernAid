import type { Approval, DiagnosisProposal, Evidence, ExecutionEvent, ValidatedPlan } from "@kernaid/schemas";
export interface StartSession { targetFingerprint:string; mode:"rescue"|"resident" }
export interface SessionInfo { id:string; state:"observe" }
export interface EvidenceRequest { collector:string; target:string }
export interface ArtifactRef { mediaType:string; uri:string; sha256:string }
export type ReportFormat = "json"|"markdown";
export type SessionEvent = { type:"status"|"proposal"|"error"; message:string; proposal?:DiagnosisProposal };
export interface SessionDriver {
 startSession(input:StartSession):Promise<SessionInfo>;
 sendUserPrompt(sessionId:string,prompt:string):AsyncIterable<SessionEvent>;
 requestEvidence(sessionId:string,request:EvidenceRequest):Promise<Evidence[]>;
 stagePlan(sessionId:string,proposal:DiagnosisProposal):Promise<ValidatedPlan>;
 approvePlan(planId:string,approval:Approval):Promise<void>;
 executePlan(planId:string):AsyncIterable<ExecutionEvent>;
 rollback(planId:string):AsyncIterable<ExecutionEvent>;
 exportReport(sessionId:string,format:ReportFormat):Promise<ArtifactRef>;
}
