import { useEffect, useRef, useState } from "react";
import {
  FIXTURE_REPAIR_APPROVAL_TEXT,
  FIXTURE_REPAIR_EVIDENCE_COLLECTOR,
  FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE,
  FIXTURE_REPAIR_RESOURCE_ID,
  FIXTURE_ROLLBACK_APPROVAL_TEXT,
  FixtureRepairSessionDriver,
  parseFixtureRepairSessionArtifact,
  type FixtureRepairReceiptDto,
  type FixtureRepairSessionArtifact,
  type FixtureRollbackReceiptDto,
  type StagedFixtureRepairDto,
  type StagedFixtureRollbackDto,
} from "@kernaid/agent-gateway";
import type {
  ArtifactRef,
  PlanApprovalRequirement,
} from "@kernaid/session-driver";
import type { DiagnosisProposal } from "@kernaid/schemas";
import type { ExecutionEvent } from "@kernaid/schemas";
import {
  NativeFixtureRepairBridge,
  fixtureLabCommandIsMissing,
  type FixtureLabInspection,
} from "./fixture-repair-lab";

interface FixtureLabRuntime {
  bridge: NativeFixtureRepairBridge;
  driver: FixtureRepairSessionDriver;
}

interface FixtureSessionBinding {
  id: string;
  targetFingerprint: string;
}

export function FixtureRepairLabPanel() {
  const runtime = useRef<FixtureLabRuntime | undefined>(undefined);
  if (runtime.current === undefined) {
    const bridge = new NativeFixtureRepairBridge();
    runtime.current = {
      bridge,
      driver: new FixtureRepairSessionDriver(bridge),
    };
  }
  const session = useRef<FixtureSessionBinding | undefined>(undefined);
  const [inspection, setInspection] = useState<FixtureLabInspection>();
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [approvalText, setApprovalText] = useState("");
  const [repairRequirement, setRepairRequirement] =
    useState<PlanApprovalRequirement>();
  const [rollbackRequirement, setRollbackRequirement] =
    useState<PlanApprovalRequirement>();
  const [repairPlan, setRepairPlan] = useState<StagedFixtureRepairDto>();
  const [repairReceipt, setRepairReceipt] = useState<FixtureRepairReceiptDto>();
  const [repairExecutionAttempted, setRepairExecutionAttempted] =
    useState(false);
  const [repairPostconditionVerified, setRepairPostconditionVerified] =
    useState(false);
  const [rollbackPlan, setRollbackPlan] = useState<StagedFixtureRollbackDto>();
  const [rollbackReceipt, setRollbackReceipt] =
    useState<FixtureRollbackReceiptDto>();
  const [rollbackExecutionAttempted, setRollbackExecutionAttempted] =
    useState(false);
  const [rollbackPostconditionVerified, setRollbackPostconditionVerified] =
    useState(false);

  useEffect(() => {
    let cancelled = false;
    runtime.current?.bridge
      .inspect()
      .then((next) => {
        if (cancelled || !next.status.enabled) return;
        setInspection(next);
        setVisible(true);
      })
      .catch((cause: unknown) => {
        if (cancelled || fixtureLabCommandIsMissing(cause)) return;
        setError("Il laboratorio isolato non ha superato l’avvio sicuro.");
        setVisible(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!visible) return null;
  const native = runtime.current;
  const sequence = rollbackPlan
    ? rollbackRequirement?.nextApprovalSequence
    : repairRequirement?.nextApprovalSequence;
  const phase = rollbackReceipt
    ? 4
    : rollbackPlan
      ? 3
      : repairReceipt
        ? 2
        : repairPlan
          ? 1
          : 0;

  async function stageRepair() {
    const finding = inspection?.finding;
    if (native === undefined || finding === undefined || finding === null)
      return;
    setBusy(true);
    setError(undefined);
    try {
      const started = await native.driver.startSession({
        targetFingerprint: finding.diagnosisSha256,
        mode: "resident",
      });
      session.current = {
        id: started.id,
        targetFingerprint: finding.diagnosisSha256,
      };
      await native.driver.requestEvidence(started.id, {
        collector: FIXTURE_REPAIR_EVIDENCE_COLLECTOR,
        target: FIXTURE_REPAIR_RESOURCE_ID,
        contentType: FIXTURE_REPAIR_EVIDENCE_CONTENT_TYPE,
      });
      let proposal: DiagnosisProposal | undefined;
      for await (const event of native.driver.sendUserPrompt(
        started.id,
        "Diagnostica il finding fixture Linux e prepara soltanto il piano tipizzato disponibile.",
      ))
        if (event.proposal !== undefined) proposal = event.proposal;
      if (proposal === undefined)
        throw new Error("fixture diagnosis proposal unavailable");
      const plan = await native.driver.stagePlan(started.id, proposal);
      const requirement = await native.driver.getApprovalRequirement(
        plan.planId,
      );
      const artifact = await strictArtifact(
        native.driver.exportRepairArtifact(started.id),
      );
      setRepairPlan(artifact.repair.staged);
      setRepairRequirement(requirement);
    } catch {
      setError("Il bridge ha rifiutato lo staging R2; riavvia il laboratorio.");
    } finally {
      setBusy(false);
    }
  }

  async function executeRepair() {
    if (
      native === undefined ||
      repairPlan === undefined ||
      repairRequirement === undefined ||
      approvalText !== FIXTURE_REPAIR_APPROVAL_TEXT
    )
      return;
    setBusy(true);
    setError(undefined);
    let attempted = false;
    let recoveryReceiptAvailable = false;
    try {
      const activeSession = requireSession(session.current);
      await native.driver.approvePlan(repairPlan.planId, {
        schemaVersion: "1.0",
        approvalId: opaqueId("A-repair"),
        planId: repairPlan.planId,
        targetFingerprint: activeSession.targetFingerprint,
        approvedAt: new Date().toISOString(),
        approvedBy: "local-fixture-technician",
        typedConfirmation: FIXTURE_REPAIR_APPROVAL_TEXT,
      });
      setRepairRequirement(undefined);
      setApprovalText("");
      attempted = true;
      setRepairExecutionAttempted(true);
      const events = await collectEvents(
        native.driver.executePlan(repairPlan.planId),
      );
      const artifact = await strictArtifact(
        native.driver.exportRepairArtifact(activeSession.id),
      );
      attempted = artifact.repair.executionAttempted;
      recoveryReceiptAvailable = artifact.repair.receipt !== null;
      setRepairExecutionAttempted(attempted);
      setRepairRequirement(undefined);
      setApprovalText("");
      if (artifact.repair.receipt === null)
        throw new Error("fixture repair receipt unavailable");
      setRepairReceipt(artifact.repair.receipt);
      setRepairPlan(artifact.repair.staged);
      setRepairPostconditionVerified(artifact.repair.postconditionVerified);
      if (
        events.at(-1)?.status !== "succeeded" ||
        !artifact.repair.postconditionVerified
      )
        throw new Error("fixture repair verification failed");
    } catch {
      setError(
        attempted
          ? recoveryReceiptAvailable
            ? "Riparazione non riconciliata: non ripetere l’approvazione; usa il rollback disponibile."
            : "Riparazione tentata senza ricevuta recuperabile: esecuzione bloccata, non ripetere l’approvazione e conserva il journal nativo."
          : "Il bridge ha rifiutato l’approvazione prima dell’esecuzione; il target non è stato modificato.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function stageRollback() {
    if (native === undefined || repairReceipt === undefined) return;
    setBusy(true);
    setError(undefined);
    try {
      const activeSession = requireSession(session.current);
      const plan = await native.driver.stageRollback(repairReceipt.planId);
      const requirement = await native.driver.getApprovalRequirement(
        plan.planId,
      );
      const artifact = await strictArtifact(
        native.driver.exportRepairArtifact(activeSession.id),
      );
      if (artifact.rollback === null)
        throw new Error("fixture rollback artifact unavailable");
      setRollbackPlan(artifact.rollback.staged);
      setRollbackRequirement(requirement);
    } catch {
      setError("Il bridge ha rifiutato il piano di rollback verificabile.");
    } finally {
      setBusy(false);
    }
  }

  async function executeRollback() {
    if (
      native === undefined ||
      rollbackPlan === undefined ||
      rollbackRequirement === undefined ||
      approvalText !== FIXTURE_ROLLBACK_APPROVAL_TEXT
    )
      return;
    setBusy(true);
    setError(undefined);
    let attempted = false;
    try {
      const activeSession = requireSession(session.current);
      await native.driver.approvePlan(rollbackPlan.planId, {
        schemaVersion: "1.0",
        approvalId: opaqueId("A-rollback"),
        planId: rollbackPlan.planId,
        targetFingerprint: activeSession.targetFingerprint,
        approvedAt: new Date().toISOString(),
        approvedBy: "local-fixture-technician",
        typedConfirmation: FIXTURE_ROLLBACK_APPROVAL_TEXT,
      });
      setRollbackRequirement(undefined);
      setApprovalText("");
      attempted = true;
      setRollbackExecutionAttempted(true);
      const events = await collectEvents(
        native.driver.rollback(rollbackPlan.planId),
      );
      const artifact = await strictArtifact(
        native.driver.exportRepairArtifact(activeSession.id),
      );
      if (artifact.rollback === null)
        throw new Error("fixture rollback artifact unavailable");
      attempted = artifact.rollback.executionAttempted;
      setRollbackExecutionAttempted(attempted);
      setRollbackRequirement(undefined);
      setApprovalText("");
      if (artifact.rollback.receipt === null)
        throw new Error("fixture rollback receipt unavailable");
      setRollbackReceipt(artifact.rollback.receipt);
      setRollbackPlan(artifact.rollback.staged);
      setRollbackPostconditionVerified(artifact.rollback.postconditionVerified);
      if (
        events.at(-1)?.status !== "rolled-back" ||
        !artifact.rollback.postconditionVerified
      )
        throw new Error("fixture rollback verification failed");
    } catch {
      setError(
        attempted
          ? "Rollback tentato senza esito riconciliato: non ripetere l’approvazione; chiudi il lab e conserva il journal nativo."
          : "Il bridge ha rifiutato l’approvazione di rollback prima dell’esecuzione.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="fixture-lab"
      aria-label="Laboratorio riparazione fixture R2"
    >
      <div className="fixture-lab-heading">
        <div>
          <small>DESK FIXTURE LAB · OPT-IN</small>
          <h2>Prima riparazione reversibile, su fixture usa-e-getta</h2>
          <p>
            Target temporaneo interno. Nessun disco, percorso o comando è
            selezionabile dalla UI.
          </p>
        </div>
        <span className="fixture-lab-badge">R2 ISOLATO</span>
      </div>

      <ol className="fixture-lab-progress" aria-label="Avanzamento laboratorio">
        {["Finding", "Ripara", "Verifica", "Rollback", "Chiuso"].map(
          (label, index) => (
            <li
              className={
                index < phase ? "done" : index === phase ? "active" : ""
              }
              key={label}
            >
              {label}
            </li>
          ),
        )}
      </ol>

      {inspection?.status.mutationBlocked && (
        <p className="fixture-lab-alert" role="alert">
          Journal nativo bloccato: mutazioni disabilitate.
        </p>
      )}
      {error && (
        <p className="fixture-lab-alert" role="alert">
          {error}
        </p>
      )}

      {!repairPlan && inspection?.finding && (
        <div className="fixture-lab-card">
          <div className="fixture-lab-card-title">
            <div>
              <small>FINDING DETERMINISTICO</small>
              <b>{inspection.finding.findingId} · fstab entry mancante</b>
            </div>
            <span>{inspection.finding.evidence.length} evidenze</span>
          </div>
          <HashRow
            label="Diagnosi"
            value={inspection.finding.diagnosisSha256}
          />
          <button
            className="fixture-lab-action"
            disabled={busy || inspection.status.mutationBlocked}
            onClick={stageRepair}
          >
            {busy ? "Staging…" : "Prepara piano R2"}
          </button>
        </div>
      )}

      {repairPlan && !repairReceipt && !repairExecutionAttempted && (
        <div className="fixture-lab-card">
          <PlanHeading label="PIANO RIPARAZIONE" risk={repairPlan.risk} />
          <HashRow label="Piano" value={repairPlan.planHash} />
          <HashRow label="Target snapshot" value={repairPlan.targetSnapshot} />
          <HashRow label="Prima" value={repairPlan.expectedBeforeSha256} />
          <HashRow label="Dopo" value={repairPlan.expectedAfterSha256} />
          <HashRow label="Diff" value={repairPlan.diffSha256} />
          <LocatorRow label="Backup" value={repairPlan.backupLocator} />
          <Approval
            expected={FIXTURE_REPAIR_APPROVAL_TEXT}
            sequence={sequence}
            value={approvalText}
            busy={busy}
            onChange={setApprovalText}
            onApprove={executeRepair}
          />
        </div>
      )}

      {repairPlan && !repairReceipt && repairExecutionAttempted && (
        <div className="fixture-lab-card" role="status">
          <PlanHeading label="RICONCILIAZIONE RICHIESTA" risk="BLOCKED" />
          <p>
            Il tentativo è registrato ma non esiste una ricevuta recuperabile.
            L’approvazione non può essere ripetuta e il rollback non è
            disponibile.
          </p>
          <HashRow label="Piano" value={repairPlan.planHash} />
          <HashRow label="Target snapshot" value={repairPlan.targetSnapshot} />
          <LocatorRow
            label="Backup previsto"
            value={repairPlan.backupLocator}
          />
        </div>
      )}

      {repairReceipt && !rollbackPlan && (
        <div
          className={`fixture-lab-card${repairPostconditionVerified ? " fixture-lab-card-success" : ""}`}
        >
          <PlanHeading
            label={
              repairPostconditionVerified
                ? "RIPARAZIONE VERIFICATA"
                : "RIPARAZIONE DA RICONCILIARE"
            }
            risk="R2"
          />
          <p>
            {repairPostconditionVerified
              ? "Finding assente, backup byte-verificato e ricevuta nativa validata."
              : "La ricevuta nativa è disponibile ma la post-verifica non è conclusa. Usa il rollback verificabile."}
          </p>
          <HashRow label="Installato" value={repairReceipt.afterSha256} />
          <HashRow label="Backup" value={repairReceipt.backupSha256} />
          <button
            className="fixture-lab-action fixture-lab-secondary"
            disabled={busy}
            onClick={stageRollback}
          >
            {busy ? "Staging rollback…" : "Prepara rollback"}
          </button>
        </div>
      )}

      {rollbackPlan && !rollbackReceipt && !rollbackExecutionAttempted && (
        <div className="fixture-lab-card">
          <PlanHeading label="PIANO ROLLBACK" risk={rollbackPlan.risk} />
          <HashRow label="Piano" value={rollbackPlan.planHash} />
          <HashRow
            label="Target snapshot"
            value={rollbackPlan.targetSnapshot}
          />
          <HashRow label="Installato" value={rollbackPlan.installedSha256} />
          <HashRow
            label="Da ripristinare"
            value={rollbackPlan.restoredSha256}
          />
          <LocatorRow label="Backup" value={rollbackPlan.backupLocator} />
          <Approval
            expected={FIXTURE_ROLLBACK_APPROVAL_TEXT}
            sequence={sequence}
            value={approvalText}
            busy={busy}
            onChange={setApprovalText}
            onApprove={executeRollback}
          />
        </div>
      )}

      {rollbackPlan && !rollbackReceipt && rollbackExecutionAttempted && (
        <div className="fixture-lab-card" role="status">
          <PlanHeading label="ROLLBACK DA RICONCILIARE" risk="BLOCKED" />
          <p>
            Il rollback è stato tentato senza una ricevuta recuperabile. La
            seconda approvazione non può essere ripetuta.
          </p>
          <HashRow label="Piano" value={rollbackPlan.planHash} />
          <HashRow
            label="Target snapshot"
            value={rollbackPlan.targetSnapshot}
          />
          <LocatorRow label="Backup" value={rollbackPlan.backupLocator} />
        </div>
      )}

      {rollbackReceipt && (
        <div
          className={`fixture-lab-card${rollbackPostconditionVerified ? " fixture-lab-card-success" : ""}`}
          role="status"
        >
          <PlanHeading
            label={
              rollbackPostconditionVerified
                ? "CICLO R2 COMPLETATO"
                : "ROLLBACK DA RICONCILIARE"
            }
            risk={rollbackPostconditionVerified ? "CLOSED" : "R2"}
          />
          <p>
            {rollbackPostconditionVerified
              ? "Byte originali ripristinati, finding riapparso e seconda ricevuta verificata dal bridge nativo."
              : "La ricevuta di rollback è disponibile, ma il finding originale non è stato riconfermato."}
          </p>
          <HashRow
            label="Ripristinato"
            value={rollbackReceipt.restoredSha256}
          />
          <HashRow label="Backup" value={rollbackReceipt.backupSha256} />
          <LocatorRow
            label="Approvazioni"
            value={`${rollbackReceipt.repairApprovalId} → ${rollbackReceipt.rollbackApprovalId}`}
          />
        </div>
      )}
    </div>
  );
}

interface ApprovalProps {
  expected: string;
  sequence: number | null | undefined;
  value: string;
  busy: boolean;
  onChange(value: string): void;
  onApprove(): void;
}

function Approval({
  expected,
  sequence,
  value,
  busy,
  onChange,
  onApprove,
}: ApprovalProps) {
  return (
    <div className="fixture-lab-approval">
      <label>
        Scrivi <code>{expected}</code>
        <input
          autoComplete="off"
          spellCheck={false}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
      </label>
      <button
        className="fixture-lab-action"
        disabled={
          busy ||
          value !== expected ||
          sequence === null ||
          sequence === undefined
        }
        onClick={onApprove}
      >
        {busy ? "Esecuzione…" : `Approva sequenza ${sequence ?? "—"}`}
      </button>
    </div>
  );
}

function PlanHeading({ label, risk }: { label: string; risk: string }) {
  return (
    <div className="fixture-lab-card-title">
      <small>{label}</small>
      <span>{risk}</span>
    </div>
  );
}

function HashRow({ label, value }: { label: string; value: string }) {
  return <LocatorRow label={label} value={value} hash />;
}

function LocatorRow({
  label,
  value,
  hash = false,
}: {
  label: string;
  value: string;
  hash?: boolean;
}) {
  const compact = hash ? `${value.slice(0, 18)}…${value.slice(-8)}` : value;
  return (
    <div className="fixture-lab-row">
      <span>{label}</span>
      <code title={value}>{compact}</code>
    </div>
  );
}

function opaqueId(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

async function strictArtifact(
  referencePromise: Promise<ArtifactRef>,
): Promise<FixtureRepairSessionArtifact> {
  const reference = await referencePromise;
  if (
    reference.auditStatus.state !== "unavailable" ||
    reference.mediaType !== "application/json" ||
    reference.payloadMediaType !== "application/json"
  )
    throw new Error("unexpected fixture repair artifact envelope");
  const prefix = "data:application/json;charset=utf-8,";
  if (!reference.uri.startsWith(prefix))
    throw new Error("unexpected fixture repair artifact URI");
  let decoded: unknown;
  try {
    decoded = JSON.parse(
      decodeURIComponent(reference.uri.slice(prefix.length)),
    ) as unknown;
  } catch {
    throw new Error("invalid fixture repair artifact JSON");
  }
  return parseFixtureRepairSessionArtifact(decoded);
}

function requireSession(
  value: FixtureSessionBinding | undefined,
): FixtureSessionBinding {
  if (value === undefined)
    throw new Error("fixture repair session is unavailable");
  return value;
}

async function collectEvents(
  iterable: AsyncIterable<ExecutionEvent>,
): Promise<ExecutionEvent[]> {
  const events: ExecutionEvent[] = [];
  for await (const event of iterable) events.push(event);
  return events;
}
