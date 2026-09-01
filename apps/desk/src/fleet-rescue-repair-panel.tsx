import { useEffect, useRef, useState } from "react";
import type { RescueOfflineInspection, RescueTargetSelection } from "./native";
import {
  FleetRescueClient,
  FleetRescueUnavailableError,
  fleetRescueAction,
  type FleetRescueIntent,
} from "./fleet-rescue-repair";
import {
  createRescueRepairApprovalId,
  rescueRepairTargetClaims,
} from "./rescue-repair";

export interface FleetRescueRepairPanelProps {
  readonly selection?: RescueTargetSelection;
  readonly targetFingerprint?: string;
  readonly inspection?: RescueOfflineInspection;
  readonly client?: FleetRescueClient;
}

export function FleetRescueRepairPanel({
  selection,
  targetFingerprint,
  inspection,
  client,
}: FleetRescueRepairPanelProps) {
  const repairClient = useRef(client ?? new FleetRescueClient()).current;
  const [intent, setIntent] = useState<FleetRescueIntent | null>();
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const qualifiedTarget =
    selection !== undefined &&
    targetFingerprint !== undefined &&
    inspection?.os.family === "linux" &&
    inspection.target.filesystem === "ext4" &&
    inspection.target.scanFingerprint === selection.scanFingerprint &&
    inspection.target.targetId === selection.target.targetId;

  useEffect(() => {
    const controller = new AbortController();
    const refresh = () =>
      void repairClient
        .status(controller.signal)
        .then(setIntent)
        .catch((error: unknown) => {
          if (!(error instanceof FleetRescueUnavailableError))
            setMessage(
              "Intento Fleet non leggibile: nessuna azione è consentita.",
            );
        });
    refresh();
    const timer = window.setInterval(refresh, 2500);
    return () => {
      window.clearInterval(timer);
      controller.abort();
    };
  }, [repairClient]);

  useEffect(() => {
    if (
      intent?.state !== "staging" ||
      selection === undefined ||
      targetFingerprint === undefined ||
      !qualifiedTarget ||
      busy
    )
      return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setBusy(true);
      void repairClient
        .stage(
          intent,
          rescueRepairTargetClaims(selection, targetFingerprint),
          controller.signal,
        )
        .then((next) => {
          setIntent(next);
          setMessage(undefined);
        })
        .catch(() =>
          setMessage(
            "Preparazione locale in attesa; nessuna scrittura eseguita.",
          ),
        )
        .finally(() => setBusy(false));
    }, 900);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [
    busy,
    intent,
    qualifiedTarget,
    repairClient,
    selection,
    targetFingerprint,
  ]);

  if (intent === undefined || intent === null) return null;
  const action = fleetRescueAction(intent.actionId);

  async function stage(): Promise<void> {
    if (
      intent === undefined ||
      intent === null ||
      selection === undefined ||
      targetFingerprint === undefined ||
      !qualifiedTarget ||
      busy
    )
      return;
    setBusy(true);
    setMessage(undefined);
    try {
      setIntent(
        await repairClient.stage(
          intent,
          rescueRepairTargetClaims(selection, targetFingerprint),
        ),
      );
    } catch {
      setMessage(
        "Preparazione locale non conclusa. Nessuna scrittura eseguita.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function approve(): Promise<void> {
    if (
      intent === undefined ||
      intent === null ||
      confirmation !== intent.confirmationRequired ||
      busy
    )
      return;
    setBusy(true);
    setMessage(undefined);
    try {
      setIntent(
        await repairClient.approve(
          intent,
          createRescueRepairApprovalId(),
          new Date().toISOString(),
          confirmation,
        ),
      );
      setConfirmation("");
    } catch {
      setMessage(
        "Approvazione scaduta o non corrispondente: riprova localmente.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function reject(): Promise<void> {
    if (intent === undefined || intent === null || busy) return;
    setBusy(true);
    setMessage(undefined);
    try {
      setIntent(await repairClient.reject(intent));
      setConfirmation("");
    } catch {
      setMessage("Rifiuto non confermato dal servizio locale.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rescue-repair fleet-rescue-intent" aria-live="polite">
      <div className="rescue-repair-heading">
        <div>
          <small>FLEET · INTENTO REMOTO, AUTORITÀ LOCALE</small>
          <h2>Riparazione proposta per questo dispositivo</h2>
        </div>
        <span>
          {intent.risk} · {action.label}
        </span>
      </div>
      <p className="rescue-repair-state">
        Fleet ha richiesto una sola azione nota. Non verrà eseguita finché
        questo Rescue non acquisisce evidenza fresca e tu non la approvi qui.
      </p>
      <div className="rescue-repair-card">
        <div className="rescue-repair-row">
          <span>Azione</span>
          <code>
            {intent.actionId}@{intent.actionVersion}
          </code>
        </div>
        <div className="rescue-repair-row">
          <span>Ordine / dispositivo</span>
          <code>
            {intent.workOrderId} · {intent.deviceId}
          </code>
        </div>
        {intent.evidence !== null && (
          <>
            <div className="rescue-repair-row">
              <span>Evidenza locale</span>
              <code title={intent.evidence.evidenceSha256}>
                {intent.evidence.evidenceSha256}
              </code>
            </div>
            <div className="rescue-repair-row">
              <span>Piano / target</span>
              <code>
                {intent.evidence.planSha256} · {intent.evidence.targetSha256}
              </code>
            </div>
            <div className="rescue-repair-backup">
              <b>Backup Vault riservato localmente</b>
              <small>{intent.evidence.backupLocator}</small>
            </div>
          </>
        )}
        {intent.state === "awaiting-target" && (
          <div className="rescue-repair-actions">
            <button
              className="rescue-repair-primary"
              disabled={!qualifiedTarget || busy}
              onClick={() => void stage()}
            >
              {busy ? "Verifica…" : "Verifica sul target selezionato"}
            </button>
          </div>
        )}
        {intent.state === "awaiting-approval" && (
          <>
            <label className="rescue-repair-confirmation">
              Nuova approvazione locale: scrivi esattamente
              <code>{intent.confirmationRequired}</code>
              <input
                autoComplete="off"
                spellCheck={false}
                disabled={busy}
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </label>
            <div className="rescue-repair-actions">
              <button disabled={busy} onClick={() => void reject()}>
                Rifiuta ordine
              </button>
              <button
                className="rescue-repair-primary"
                disabled={busy || confirmation !== intent.confirmationRequired}
                onClick={() => void approve()}
              >
                Approva questo piano
              </button>
            </div>
          </>
        )}
        {!["awaiting-target", "awaiting-approval", "staging"].includes(
          intent.state,
        ) && (
          <p className="rescue-repair-state">
            Stato locale: <b>{intent.state}</b>. Nessuna approvazione remota può
            modificare questa decisione.
          </p>
        )}
        {message !== undefined && (
          <p className="rescue-repair-alert">{message}</p>
        )}
      </div>
    </section>
  );
}
