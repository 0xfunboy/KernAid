import type { SessionDriver, StartSession, SessionInfo, EvidenceRequest, ArtifactRef, ReportFormat, SessionEvent } from "@kernaid/session-driver";
import type { Approval, DiagnosisProposal, Evidence, ExecutionEvent, ValidatedPlan } from "@kernaid/schemas";
import { FakeProvider } from "./fake-provider.js";
export class FakeSessionDriver implements SessionDriver {
 private readonly provider=new FakeProvider(); private evidence:Evidence[]=[]; private sessions=new Set<string>();
 async startSession(_input:StartSession):Promise<SessionInfo>{const id=`S-${crypto.randomUUID()}`;this.sessions.add(id);return{id,state:"observe"};}
 async *sendUserPrompt(sessionId:string,prompt:string):AsyncIterable<SessionEvent>{this.assert(sessionId);yield{type:"status",message:"Diagnosing fixture evidence"};const proposal=await this.provider.diagnose(prompt,this.evidence);yield{type:"proposal",message:proposal.diagnosis,proposal};}
 async requestEvidence(sessionId:string,request:EvidenceRequest):Promise<Evidence[]>{this.assert(sessionId);const hash="0".repeat(64);const item:Evidence={schemaVersion:"1.0",id:`E-${this.evidence.length+1}`,collector:request.collector,target:request.target,capturedAt:new Date().toISOString(),contentType:"application/vnd.kernaid.linux-inventory+json",sha256:hash,sensitivity:"system",trust:"observed-untrusted",summary:"Read-only fixture inventory",blobRef:`sha256:${hash}`};this.evidence.push(item);return[item];}
 async stagePlan(sessionId:string,proposal:DiagnosisProposal):Promise<ValidatedPlan>{this.assert(sessionId);return{schemaVersion:"1.0",planId:`P-${crypto.randomUUID()}`,targetFingerprint:`sha256:${"0".repeat(64)}`,diagnosis:proposal.diagnosis,evidenceIds:proposal.evidenceIds,risk:"R0",steps:[{action:"system.observe.noop",args:{},preconditions:["target.still_matches"],backup:"not-required",validation:"evidence.exists",rollback:null}]};}
 async approvePlan(_planId:string,_approval:Approval):Promise<void>{return;}
 async *executePlan(planId:string):AsyncIterable<ExecutionEvent>{yield{schemaVersion:"1.0",planId,sequence:1,status:"succeeded",action:"system.observe.noop",message:"Observe-only plan completed",capturedAt:new Date().toISOString()};}
 async *rollback(_planId:string):AsyncIterable<ExecutionEvent>{throw new Error("R0 plans do not mutate and require no rollback");}
 async exportReport(sessionId:string,format:ReportFormat):Promise<ArtifactRef>{this.assert(sessionId);return{mediaType:format==="json"?"application/json":"text/markdown",uri:`memory://reports/${sessionId}.${format}`,sha256:"0".repeat(64)};}
 private assert(id:string){if(!this.sessions.has(id))throw new Error("unknown session");}
}
