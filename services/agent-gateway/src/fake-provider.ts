import type { DiagnosisProposal, Evidence } from "@kernaid/schemas";
export interface Provider { diagnose(objective:string,evidence:readonly Evidence[]):Promise<DiagnosisProposal> }
export class FakeProvider implements Provider {
 async diagnose(objective:string,evidence:readonly Evidence[]):Promise<DiagnosisProposal>{
  if (!objective.trim()) throw new Error("objective is required");
  if (evidence.length===0) throw new Error("evidence is required");
  return {schemaVersion:"1.0",diagnosis:"Fixture indicates a Linux configuration inconsistency; no changes proposed.",confidence:0.72,evidenceIds:evidence.map(item=>item.id),requestedEvidence:[]};
 }
}
