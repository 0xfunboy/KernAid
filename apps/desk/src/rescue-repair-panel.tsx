import React, { useEffect, useRef, useState } from "react";
import type { RescueOfflineInspection, RescueTargetSelection } from "./native";
import {
  RESCUE_FSTAB_CONFIRMATION,
  RESCUE_FSTAB_FINDING_ID,
  RescueRepairClient,
  RescueRepairServiceError,
  RescueRepairUnavailableError,
  preparedRepairDetail,
  rescueRepairNeedsPolling,
  rescueRepairStateMessage,
  rescueRepairTargetClaims,
  type RescueRepairSnapshot,
} from "./rescue-repair";

export interface RescueRepairPanelProps {
  readonly selection?: RescueTargetSelection;
  readonly targetFingerprint?: string;
  readonly inspection?: RescueOfflineInspection;
  readonly client?: RescueRepairClient;
}

export function RescueRepairPanel({
  selection,
  targetFingerprint,
  inspection,
  client,
}: RescueRepairPanelProps) {
  const repairClient = useRef(client ?? new RescueRepairClient()).current;
  const [available, setAvailable] = useState<boolean>();
  const [snapshot, setSnapshot] = useState<RescueRepairSnapshot>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const [confirmation, setConfirmation] = useState("");
  const mounted = useRef(true);

  const qualifiedTarget =
    selection !== undefined &&
    targetFingerprint !== undefined &&
    inspection?.os.family === "linux" &&
    inspection.target.filesystem === "ext4" &&
    inspection.target.scanFingerprint === selection.scanFingerprint &&
    inspection.target.targetId === selection.target.targetId;
  const prepared = preparedRepairDetail(snapshot);
  const preparedTargetCurrent =
    prepared !== undefined &&
    qualifiedTarget &&
    prepared.targetFingerprint === targetFingerprint;

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    repairClient
      .status(controller.signal)
      .then((next) => {
        if (!mounted.current) return;
        setSnapshot(next);
        setAvailable(true);
      })
      .catch((error: unknown) => {
        if (!mounted.current) return;
        if (error instanceof RescueRepairServiceError) {
          setAvailable(true);
          setMessage(error.message);
        } else {
          setAvailable(false);
        }
      });
    return () => {
      mounted.current = false;
      controller.abort();
    };
  }, [repairClient]);

  useEffect(() => {
    if (!available || !rescueRepairNeedsPolling(snapshot)) return;
    const controller = new AbortController();
    let timer: number | undefined;
    let stopped = false;
    const schedule = () => {
      timer = window.setTimeout(() => void poll(), 1250);
    };
    const poll = async () => {
      try {
        const next = await repairClient.status(controller.signal);
        if (stopped || !mounted.current) return;
        setSnapshot((current) => newestSnapshot(current, next));
        setMessage(undefined);
        if (rescueRepairNeedsPolling(next)) schedule();
      } catch (error) {
        if (stopped || !mounted.current) return;
        setMessage(operationErrorMessage(error));
        schedule();
      }
    };
    schedule();
    return () => {
      stopped = true;
      if (timer !== undefined) window.clearTimeout(timer);
      controller.abort();
    };
  }, [available, repairClient, snapshot]);

  async function prepare(): Promise<void> {
    if (
      !qualifiedTarget ||
      busy ||
      selection === undefined ||
      targetFingerprint === undefined
    )
      return;
    setBusy(true);
    setMessage(undefined);
    setConfirmation("");
    try {
      const next = await repairClient.prepare(
        rescueRepairTargetClaims(selection, targetFingerprint),
      );
      if (!mounted.current) return;
      setSnapshot((current) => newestSnapshot(current, next));
    } catch (error) {
      if (!mounted.current) return;
      setMessage(operationErrorMessage(error));
      await refreshAfterError();
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  async function approve(): Promise<void> {
    if (
      prepared === undefined ||
      !preparedTargetCurrent ||
      confirmation !== RESCUE_FSTAB_CONFIRMATION ||
      busy
    )
      return;
    setBusy(true);
    setMessage(undefined);
    try {
      const next = await repairClient.approve(prepared, confirmation);
      if (!mounted.current) return;
      setSnapshot((current) => newestSnapshot(current, next));
      setConfirmation("");
    } catch (error) {
      if (!mounted.current) return;
      setMessage(operationErrorMessage(error));
      await refreshAfterError();
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  async function cancel(): Promise<void> {
    if (prepared === undefined || busy) return;
    setBusy(true);
    setMessage(undefined);
    try {
      const next = await repairClient.cancel(prepared);
      if (!mounted.current) return;
      setSnapshot((current) => newestSnapshot(current, next));
      setConfirmation("");
    } catch (error) {
      if (!mounted.current) return;
      setMessage(operationErrorMessage(error));
      await refreshAfterError();
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  async function refreshAfterError(): Promise<void> {
    try {
      const current = await repairClient.status();
      if (mounted.current)
        setSnapshot((previous) => newestSnapshot(previous, current));
    } catch {
      // Keep the last authenticated snapshot visible. Unknown is not success.
    }
  }

  if (available !== true || snapshot === undefined) return null;
  if (snapshot.state === "idle" && !qualifiedTarget) return null;

  return (
    <div
      className={`rescue-repair rescue-repair-${snapshot.state}`}
      aria-live="polite"
    >
      <div className="rescue-repair-heading">
        <div>
          <small>
            {prepared === undefined
              ? "VERIFICA RESCUE CANDIDATE"
              : "RIPARAZIONE RESCUE CANDIDATE"}
          </small>
          <h2>
            {prepared === undefined
              ? "Controllo sicuro della configurazione di avvio"
              : "Avvio Linux bloccato da una voce disco"}
          </h2>
        </div>
        <span>
          {prepared === undefined
            ? snapshot.state === "idle"
              ? "SOLA LETTURA"
              : rescueRepairStateBadge(snapshot.state)
            : `${RESCUE_FSTAB_FINDING_ID} · R2`}
        </span>
      </div>

      <p className="rescue-repair-state" role="status">
        {rescueRepairStateMessage(snapshot)}
      </p>

      {snapshot.state === "idle" && qualifiedTarget && (
        <div className="rescue-repair-card">
          <div className="rescue-repair-row">
            <span>Target</span>
            <b>Installazione Linux selezionata · EXT4</b>
          </div>
          <div className="rescue-repair-row">
            <span>Controllo</span>
            <b>Coerenza tra configurazione fstab e dischi osservati</b>
          </div>
          <p>
            KernAid verificherà in sola lettura se esiste esattamente il caso
            riparabile previsto. Nessun finding viene dichiarato prima del
            controllo. La preparazione non modifica il sistema installato e non
            accetta percorsi, nomi dispositivo o comandi.
          </p>
          <button
            className="rescue-repair-primary"
            disabled={busy}
            onClick={() => void prepare()}
          >
            {busy ? "Verifica…" : "Verifica caso riparabile"}
          </button>
        </div>
      )}

      {snapshot.state === "preparing" && (
        <div className="rescue-repair-card rescue-repair-wait">
          <span className="rescue-repair-spinner" aria-hidden="true" />
          <p>
            Il target viene riacquisito in sola lettura, il piano viene legato
            agli hash osservati e il backup viene riservato nel Vault separato.
          </p>
        </div>
      )}

      {prepared !== undefined && (
        <div className="rescue-repair-card">
          {!preparedTargetCurrent && (
            <p className="rescue-repair-alert">
              Il piano è legato a un altro target selezionato. Riseleziona il
              target originale oppure annulla il piano; l'approvazione resta
              bloccata.
            </p>
          )}
          <div className="rescue-repair-diff" aria-label="Anteprima modifica">
            <div>
              <span>− Prima</span>
              <code>voce UUID mancante · attiva</code>
            </div>
            <div>
              <span>+ Dopo</span>
              <code>stessa voce · disabilitata da KernAid</code>
            </div>
          </div>
          <div className="rescue-repair-row">
            <span>Hash diff sanitizzato</span>
            <code title={prepared.diffSha256}>{prepared.diffSha256}</code>
          </div>
          <div className="rescue-repair-row">
            <span>Binding piano</span>
            <code title={prepared.planHash}>{prepared.planHash}</code>
          </div>
          <div className="rescue-repair-backup">
            <b>Backup pronto su dispositivo distinto</b>
            <small>
              Riserva Vault verificata · i byte originali non sono mostrati al
              browser
            </small>
          </div>
          <label className="rescue-repair-confirmation">
            Per approvare, scrivi esattamente
            <code>{RESCUE_FSTAB_CONFIRMATION}</code>
            <input
              autoComplete="off"
              disabled={busy || !preparedTargetCurrent}
              spellCheck={false}
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </label>
          <div className="rescue-repair-actions">
            <button disabled={busy} onClick={() => void cancel()}>
              {busy ? "Attendi…" : "Annulla piano"}
            </button>
            <button
              className="rescue-repair-primary"
              disabled={
                busy ||
                !preparedTargetCurrent ||
                confirmation !== RESCUE_FSTAB_CONFIRMATION
              }
              onClick={() => void approve()}
            >
              Approva e ripara
            </button>
          </div>
        </div>
      )}

      {snapshot.state === "executing" && (
        <div className="rescue-repair-card rescue-repair-wait">
          <span className="rescue-repair-spinner" aria-hidden="true" />
          <p>
            KernAid sta applicando, verificando e chiudendo la transazione. Il
            risultato sarà mostrato solo dopo uno stato terminale autenticato.
          </p>
        </div>
      )}

      {snapshot.detail?.kind === "terminal" && (
        <div className="rescue-repair-card rescue-repair-terminal">
          {snapshot.state === "succeeded" && (
            <p>
              La voce non valida è stata disabilitata e il risultato è stato
              verificato. Puoi spegnere KernAid Rescue e provare ad avviare il
              sistema installato.
            </p>
          )}
          {snapshot.state === "restored" && (
            <p>
              La verifica non ha qualificato il risultato. KernAid ha
              ripristinato esattamente il backup originale; nessun successo
              viene dichiarato.
            </p>
          )}
          {snapshot.state === "cancelled" && (
            <p>Il piano è stato chiuso prima della modifica del target.</p>
          )}
          {snapshot.state === "failed" && (
            <p>
              L'operazione è terminata senza successo. Mantieni il computer in
              KernAid Rescue e richiedi assistenza prima di altri tentativi.
            </p>
          )}
          {snapshot.state === "manual-reconciliation-required" && (
            <p className="rescue-repair-alert">
              Riavvio Rescue obbligatorio. Non avviare il sistema installato e
              non modificare manualmente <code>fstab</code>. Riavvia dalla
              chiavetta KernAid: il recupero riprenderà dalla transazione
              persistita nel Vault.
            </p>
          )}
          {snapshot.detail.transactionBindingSha256 !== null && (
            <div className="rescue-repair-row">
              <span>Ricevuta transazione</span>
              <code title={snapshot.detail.transactionBindingSha256}>
                {snapshot.detail.transactionBindingSha256}
              </code>
            </div>
          )}
        </div>
      )}

      {message && (
        <p className="rescue-repair-alert" role="alert">
          {message}
        </p>
      )}
    </div>
  );
}

export function newestSnapshot(
  current: RescueRepairSnapshot | undefined,
  next: RescueRepairSnapshot,
): RescueRepairSnapshot {
  return current !== undefined && current.stateVersion >= next.stateVersion
    ? current
    : next;
}

export function operationErrorMessage(error: unknown): string {
  if (error instanceof RescueRepairServiceError) return error.message;
  if (error instanceof RescueRepairUnavailableError)
    return "Connessione al servizio di riparazione interrotta. Lo stato è sconosciuto: non assumere che l'operazione sia riuscita.";
  return "Risposta di riparazione non valida. L'operazione resta non confermata.";
}

function rescueRepairStateBadge(state: RescueRepairSnapshot["state"]): string {
  switch (state) {
    case "idle":
      return "SOLA LETTURA";
    case "preparing":
      return "VERIFICA";
    case "prepared":
      return "PIANO PRONTO";
    case "executing":
      return "IN ESECUZIONE";
    case "succeeded":
      return "COMPLETATA";
    case "restored":
      return "RIPRISTINATA";
    case "cancelled":
      return "ANNULLATA";
    case "manual-reconciliation-required":
      return "RIAVVIO RICHIESTO";
    case "failed":
      return "NON RIUSCITA";
  }
}
