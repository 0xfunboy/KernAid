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
export interface RescueFstabRepairApproval {
  schemaVersion: "1.0";
  approvalId: string;
  approvalSequence: number;
  sessionId: string;
  planId: string;
  planHash: string;
  targetFingerprint: string;
  targetSnapshot: string;
  resourceId: "rescue:selected-linux-root:etc/fstab";
  typedConfirmation: "DISABILITA VOCE FSTAB";
  approvedAt: string;
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

export interface LinuxResidentSnapshotCapture {
  mode: "resident";
  targetScope: "running-root";
  accessPolicy: "fixed-descriptor-read-only";
  callerSuppliedPath: false;
  mutationRequested: false;
  crossDeviceTraversalAllowed: false;
}

export interface LinuxRescueSnapshotCapture {
  mode: "rescue";
  targetScope: "selected-installed-target";
  accessPolicy: "temporary-read-only-no-replay";
  deviceOpenedReadOnly: true;
  journalReplayPrevented: true;
  privateMountNamespace: true;
  mountCleanupVerified: true;
  mutationPerformed: false;
  crossDeviceTraversalAllowed: false;
}

export type LinuxSnapshotCapture =
  LinuxResidentSnapshotCapture | LinuxRescueSnapshotCapture;

export interface LinuxReleaseSnapshot {
  id: string | null;
  name: string | null;
  prettyName: string | null;
  versionId: string | null;
  source: "etc-os-release" | "usr-lib-os-release" | "absent";
}

export interface LinuxBootSnapshot {
  directoryPresent: boolean;
  kernelArtifactCount: number;
  initramfsArtifactCount: number;
  bootloaderDirectoryCount: number;
  symlinkArtifactCount: number;
}

export interface LinuxFilesystemTopologySnapshot {
  collectionScope: "root-filesystem-only";
  separateEtcMountPresent: boolean;
  separateBootMountPresent: boolean;
  separateUsrMountPresent: boolean;
  separateVarMountPresent: boolean;
  relevantSeparateMountPresent: boolean;
  supported: boolean;
}

export interface LinuxFstabSnapshot {
  present: boolean;
  entryCount: number;
  rootEntryPresent: boolean;
  efiEntryPresent: boolean;
  swapEntryCount: number;
  networkEntryCount: number;
  malformedLineCount: number;
}

export interface LinuxNormalizedSnapshot {
  family: "linux";
  scope: "installed-root-static";
  installationConfirmed: boolean;
  topology: LinuxFilesystemTopologySnapshot;
  release: LinuxReleaseSnapshot;
  boot: LinuxBootSnapshot;
  configuration: {
    fstab: LinuxFstabSnapshot;
    machineIdPresent: boolean;
  };
  packageDatabases: {
    dpkgStatusPresent: boolean;
    rpmDatabasePresent: boolean;
    pacmanDatabasePresent: boolean;
  };
}

export interface LinuxNormalizedSnapshotEnvelope {
  schemaVersion: "1.0";
  kind: "linux-normalized-snapshot";
  snapshotSha256: string;
  capture: LinuxSnapshotCapture;
  snapshot: LinuxNormalizedSnapshot;
}
export {
  LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
  LINUX_NORMALIZED_SNAPSHOT_CONTENT_TYPE,
  LINUX_NORMALIZED_SNAPSHOT_HASH_DOMAIN,
  MAX_LINUX_NORMALIZED_SNAPSHOT_BYTES,
  MAX_SESSION_REPORT_BYTES,
  SchemaValidationError,
  canonicalLinuxSnapshotJson,
  decodeSessionReportJson,
  parseApproval,
  parseDiagnosisProposal,
  parseEvidence,
  parseExecutionEvent,
  parseLinuxNormalizedSnapshot,
  parseLinuxNormalizedSnapshotEnvelope,
  parseLinuxNormalizedSnapshotEnvelopeJson,
  parseSessionReport,
  parseSessionReportJson,
  parseValidatedPlan,
  sessionReportSemanticBindingsAreValid,
} from "./validation.js";
