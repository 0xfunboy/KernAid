import { useEffect, useRef, useState } from "react";
import {
  FixtureRepairDriver,
  type FixtureRepairFindingDto,
  type FixtureRepairReceiptDto,
  type FixtureRollbackReceiptDto,
  type StagedFixtureRepairDto,
  type StagedFixtureRollbackDto,
} from "@kernaid/agent-gateway";
import {
  NativeFixtureRepairBridge,
  fixtureLabCommandIsMissing,
  type FixtureLabInspection,
} from "./fixture-repair-lab";

const REPAIR_APPROVAL = "APPROVO RIPARAZIONE R2";
const ROLLBACK_APPROVAL = "APPROVO ROLLBACK R2";

interface FixtureLabRuntime {
  bridge: NativeFixtureRepairBridge;
  driver: FixtureRepairDriver;
}

export function FixtureRepairLabPanel() {
  const runtime = useRef<FixtureLabRuntime | undefined>(undefined);
  if (runtime.current === undefined) {
    const bridge = new NativeFixtureRepairBridge();
    runtime.current = { bridge, driver: new FixtureRepairDriver(bridge) };
  }
  const sessionId = useRef(opaqueId("S"));
  const initialFinding = useRef<FixtureRepairFindingDto | undefined>(undefined);
  const [inspection, setInspection] = useState<FixtureLabInspection>();
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [approvalText, setApprovalText] = useState("");
  const [repairPlan, setRepairPlan] = useState<StagedFixtureRepairDto>();
  const [repairReceipt, setRepairReceipt] = useState<FixtureRepairReceiptDto>();
  const [rollbackPlan, setRollbackPlan] = useState<StagedFixtureRollbackDto>();
  const [rollbackReceipt, setRollbackReceipt] =
    useState<FixtureRollbackReceiptDto>();

  useEffect(() => {
    let cancelled = false;
    runtime.current?.bridge
      .inspect()
      .then((next) => {
        if (cancelled || !next.status.enabled) return;
        if (next.finding !== null) initialFinding.current = next.finding;
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
  const sequence = inspection?.status.nextApprovalSequence;
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
      const staged = await native.driver.stage({
        ...finding,
        sessionId: sessionId.current,
        planId: opaqueId("P-repair"),
      });
      setRepairPlan(staged);
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
      approvalText !== REPAIR_APPROVAL
    )
      return;
    setBusy(true);
    setError(undefined);
    try {
      const current = await native.bridge.inspect();
      const approvalSequence = current.status.nextApprovalSequence;
      if (approvalSequence === null)
        throw new Error("approval sequence unavailable");
      const receipt = await native.driver.execute({
        approvalId: opaqueId("A-repair"),
        approvalSequence,
        planId: repairPlan.planId,
        planHash: repairPlan.planHash,
        targetSnapshot: repairPlan.targetSnapshot,
      });
      setRepairReceipt(receipt);
      setApprovalText("");
      const verified = await native.bridge.inspect();
      setInspection(verified);
      if (verified.finding !== null)
        throw new Error("fixture finding still present");
    } catch {
      setError(
        "Esito della riparazione non riconciliato: non ripetere l’approvazione; usa il rollback disponibile o riavvia il lab.",
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
      const staged = await native.driver.stageRollback({
        sessionId: sessionId.current,
        planId: opaqueId("P-rollback"),
        repairApprovalId: repairReceipt.approvalId,
      });
      setRollbackPlan(staged);
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
      approvalText !== ROLLBACK_APPROVAL
    )
      return;
    setBusy(true);
    setError(undefined);
    try {
      const current = await native.bridge.inspect();
      const approvalSequence = current.status.nextApprovalSequence;
      if (approvalSequence === null)
        throw new Error("approval sequence unavailable");
      const receipt = await native.driver.executeRollback({
        approvalId: opaqueId("A-rollback"),
        approvalSequence,
        planId: rollbackPlan.planId,
        planHash: rollbackPlan.planHash,
        targetSnapshot: rollbackPlan.targetSnapshot,
      });
      setRollbackReceipt(receipt);
      setApprovalText("");
      const verified = await native.bridge.inspect();
      setInspection(verified);
      if (
        verified.finding === null ||
        verified.finding.diagnosisSha256 !==
          initialFinding.current?.diagnosisSha256 ||
        receipt.restoredSha256 !== receipt.backupSha256
      )
        throw new Error("fixture rollback verification failed");
    } catch {
      setError(
        "Esito del rollback non riconciliato: chiudi il lab e conserva le ricevute native.",
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

      {repairPlan && !repairReceipt && (
        <div className="fixture-lab-card">
          <PlanHeading label="PIANO RIPARAZIONE" risk={repairPlan.risk} />
          <HashRow label="Piano" value={repairPlan.planHash} />
          <HashRow label="Target snapshot" value={repairPlan.targetSnapshot} />
          <HashRow label="Prima" value={repairPlan.expectedBeforeSha256} />
          <HashRow label="Dopo" value={repairPlan.expectedAfterSha256} />
          <HashRow label="Diff" value={repairPlan.diffSha256} />
          <LocatorRow label="Backup" value={repairPlan.backupLocator} />
          <Approval
            expected={REPAIR_APPROVAL}
            sequence={sequence}
            value={approvalText}
            busy={busy}
            onChange={setApprovalText}
            onApprove={executeRepair}
          />
        </div>
      )}

      {repairReceipt && !rollbackPlan && (
        <div className="fixture-lab-card fixture-lab-card-success">
          <PlanHeading label="RIPARAZIONE VERIFICATA" risk="R2" />
          <p>
            Finding assente, backup byte-verificato e ricevuta nativa firmata
            validata.
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

      {rollbackPlan && !rollbackReceipt && (
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
            expected={ROLLBACK_APPROVAL}
            sequence={sequence}
            value={approvalText}
            busy={busy}
            onChange={setApprovalText}
            onApprove={executeRollback}
          />
        </div>
      )}

      {rollbackReceipt && (
        <div
          className="fixture-lab-card fixture-lab-card-success"
          role="status"
        >
          <PlanHeading label="CICLO R2 COMPLETATO" risk="CLOSED" />
          <p>
            Byte originali ripristinati, finding riapparso e seconda ricevuta
            firmata verificata dal bridge nativo.
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
