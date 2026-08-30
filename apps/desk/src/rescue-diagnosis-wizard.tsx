import React, { useEffect, useRef, useState } from "react";
import type { ArtifactRef } from "@kernaid/session-driver";
import type { DiagnosisProposal, Evidence } from "@kernaid/schemas";
import {
  getRescueNativePromptStatus,
  openRescueNativeVaultPrompt,
  type RescueOfflineInspection,
  type RescueOfflineInspectionError,
  type RescueNativePromptStatus,
  type RescueTargetCandidate,
  type RescueTargetScan,
  type RescueTargetSelection,
} from "./native";
import type {
  RescueOpenAiContextPreview,
  RescueProviderMode,
} from "./rescue-openai";
import {
  jsonReportDownloadLabel,
  jsonReportDownloadName,
  UNSIGNED_MARKDOWN_DOWNLOAD_LABEL,
  type MarkdownReportExport,
} from "./report-export";
import {
  RESCUE_DIAGNOSIS_WIZARD_STEPS,
  rescueCandidatePresentation,
  rescueDiagnosisWizardProgress,
  rescueInspectionErrorPresentation,
  rescueInspectionPresentation,
  targetFamilyLabel,
} from "./rescue-ui";

const STEP_LABELS = {
  vault: "Vault",
  target: "Target",
  provider: "Provider",
  diagnosis: "Diagnosi",
  report: "Report",
} as const;

export interface RescueDiagnosisWizardProps {
  readonly vaultStatusReady: boolean;
  readonly vaultLabel: string;
  readonly vaultGuidance: string;
  readonly persistentAuditReady: boolean;
  readonly targetScan?: RescueTargetScan;
  readonly selectedTarget?: RescueTargetSelection;
  readonly targetReady: boolean;
  readonly targetBusy: boolean;
  readonly targetError?: string;
  readonly inspection?: RescueOfflineInspection;
  readonly inspectionError?: RescueOfflineInspectionError;
  readonly inspectionCurrent: boolean;
  readonly inspectionBusy: boolean;
  readonly inspectionBlocked: boolean;
  readonly providerMode: RescueProviderMode;
  readonly openAiReady: boolean;
  readonly providerSelectionDisabled: boolean;
  readonly inspectDisabled: boolean;
  readonly objective: string;
  readonly evidence: readonly Evidence[];
  readonly openAiContextPreview?: RescueOpenAiContextPreview;
  readonly openAiAcceptedContextSha256?: string;
  readonly openAiPreviewBusy: boolean;
  readonly openAiPreviewError?: string;
  readonly proposal?: DiagnosisProposal;
  readonly status: string;
  readonly busy: boolean;
  readonly diagnosisDisabled: boolean;
  readonly diagnosisButtonLabel: string;
  readonly report?: ArtifactRef;
  readonly sessionId?: string;
  readonly markdownReport?: MarkdownReportExport;
  readonly markdownReportError: boolean;
  readonly onRefreshTargets: () => void | Promise<void>;
  readonly onSelectTarget: (
    candidate: RescueTargetCandidate,
  ) => void | Promise<void>;
  readonly onChooseProvider: (mode: RescueProviderMode) => void;
  readonly onInspectTarget: () => void | Promise<void>;
  readonly onObjectiveChange: (value: string) => void;
  readonly onPreviewOpenAiContext: () => void | Promise<void>;
  readonly onAcceptOpenAiContext: (contextSha256: string) => void;
  readonly onDiagnose: () => void | Promise<void>;
}

export function RescueDiagnosisWizard({
  vaultStatusReady,
  vaultLabel,
  vaultGuidance,
  persistentAuditReady,
  targetScan,
  selectedTarget,
  targetReady,
  targetBusy,
  targetError,
  inspection,
  inspectionError,
  inspectionCurrent,
  inspectionBusy,
  inspectionBlocked,
  providerMode,
  openAiReady,
  providerSelectionDisabled,
  inspectDisabled,
  objective,
  evidence,
  openAiContextPreview,
  openAiAcceptedContextSha256,
  openAiPreviewBusy,
  openAiPreviewError,
  proposal,
  status,
  busy,
  diagnosisDisabled,
  diagnosisButtonLabel,
  report,
  sessionId,
  markdownReport,
  markdownReportError,
  onRefreshTargets,
  onSelectTarget,
  onChooseProvider,
  onInspectTarget,
  onObjectiveChange,
  onPreviewOpenAiContext,
  onAcceptOpenAiContext,
  onDiagnose,
}: RescueDiagnosisWizardProps) {
  const [nativePromptStatus, setNativePromptStatus] =
    useState<RescueNativePromptStatus>();
  const [nativePromptBusy, setNativePromptBusy] = useState(false);
  const [nativePromptMessage, setNativePromptMessage] = useState<string>();
  const nativePromptEpoch = useRef(0);
  const reportReady = report !== undefined && sessionId !== undefined;
  const progress = rescueDiagnosisWizardProgress({
    vaultStatusReady,
    targetSelected: selectedTarget !== undefined,
    inspectionReady: inspectionCurrent,
    reportReady,
  });
  const previewAccepted =
    providerMode !== "openai" ||
    (openAiContextPreview !== undefined &&
      openAiAcceptedContextSha256 === openAiContextPreview.contextSha256);
  const inspectionView =
    inspectionCurrent && inspection !== undefined
      ? rescueInspectionPresentation(inspection)
      : undefined;
  const inspectionErrorView =
    inspectionError === undefined
      ? undefined
      : rescueInspectionErrorPresentation(inspectionError);

  useEffect(() => {
    const epoch = nativePromptEpoch.current + 1;
    nativePromptEpoch.current = epoch;
    getRescueNativePromptStatus()
      .then((next) => {
        if (nativePromptEpoch.current === epoch) setNativePromptStatus(next);
      })
      .catch(() => {
        if (nativePromptEpoch.current === epoch)
          setNativePromptStatus(undefined);
    });
    return () => {
      nativePromptEpoch.current += 1;
    };
  }, []);

  async function openNativeVaultPrompt() {
    if (nativePromptBusy || nativePromptStatus?.availability !== "available")
      return;
    const epoch = nativePromptEpoch.current + 1;
    nativePromptEpoch.current = epoch;
    setNativePromptBusy(true);
    setNativePromptMessage(undefined);
    try {
      const result = await openRescueNativeVaultPrompt();
      if (nativePromptEpoch.current !== epoch) return;
      if (result.outcome !== "opened" && result.outcome !== "focused") {
        setNativePromptMessage(
          result.outcome === "busy"
            ? "Un altro prompt sicuro è già attivo."
            : "Prompt sicuro non disponibile.",
        );
        const next = await getRescueNativePromptStatus();
        if (nativePromptEpoch.current === epoch) setNativePromptStatus(next);
        return;
      }
      setNativePromptMessage(
        "Prompt sicuro aperto sul terminale dedicato. Desk tornerà aggiornato alla chiusura.",
      );
      const deadline = Date.now() + 620_000;
      while (nativePromptEpoch.current === epoch && Date.now() < deadline) {
        await new Promise((resolve) => globalThis.setTimeout(resolve, 500));
        const next = await getRescueNativePromptStatus();
        if (nativePromptEpoch.current !== epoch) return;
        setNativePromptStatus(next);
        if (next.availability !== "available" || next.promptState === "idle") {
          globalThis.location.reload();
          return;
        }
      }
      if (nativePromptEpoch.current === epoch)
        setNativePromptMessage(
          "Tempo del prompt terminato. Ricarica Desk per verificare il Vault.",
        );
    } catch {
      if (nativePromptEpoch.current === epoch) {
        setNativePromptStatus(undefined);
        setNativePromptMessage("Prompt sicuro non disponibile.");
      }
    } finally {
      if (nativePromptEpoch.current === epoch) setNativePromptBusy(false);
    }
  }

  return (
    <div className="rescue-wizard" aria-label="Diagnosi guidata Rescue">
      <div className="rescue-wizard-heading">
        <div>
          <small>KERNAID RESCUE · GUIDED MODE</small>
          <h1>Controlliamo il PC senza modificarlo.</h1>
          <p>
            Segui i cinque passaggi. La modalità iniziale è offline e ogni
            osservazione del disco resta in sola lettura.
          </p>
        </div>
        <span className="rescue-wizard-safety">DIAGNOSIS ONLY</span>
      </div>

      <ol className="rescue-wizard-progress" aria-label="Avanzamento">
        {RESCUE_DIAGNOSIS_WIZARD_STEPS.map((step, index) => (
          <li
            className={progress[step]}
            aria-current={progress[step] === "current" ? "step" : undefined}
            key={step}
          >
            <span>{index + 1}</span>
            <b>{STEP_LABELS[step]}</b>
          </li>
        ))}
      </ol>

      <div
        className={`rescue-wizard-card ${progress.vault}`}
        aria-current={progress.vault === "current" ? "step" : undefined}
      >
        <WizardCardTitle
          number="01"
          title="Vault e salvataggio"
          state={progress.vault}
        />
        {!vaultStatusReady ? (
          <p role="status">Verifica dello stato del Vault…</p>
        ) : (
          <div className="rescue-wizard-summary">
            <div>
              <b>{vaultLabel}</b>
              <small>
                {persistentAuditReady
                  ? "Report persistente disponibile."
                  : "Puoi continuare offline; il report resterà temporaneo."}
              </small>
            </div>
            {!persistentAuditReady && <p>{vaultGuidance}</p>}
            {!persistentAuditReady &&
              nativePromptStatus?.availability === "available" && (
                <button
                  className="rescue-wizard-secondary"
                  disabled={nativePromptBusy}
                  onClick={() => void openNativeVaultPrompt()}
                >
                  {nativePromptBusy
                    ? "Prompt sicuro attivo…"
                    : nativePromptStatus.promptState === "active"
                      ? "Torna al prompt sicuro"
                      : "Sblocca il Vault in modalità sicura"}
                </button>
              )}
            {nativePromptMessage && (
              <small role="status">{nativePromptMessage}</small>
            )}
            <small>
              Passphrase e credenziali si gestiscono fuori da Desk: questa
              pagina non le richiede, non le riceve e non le memorizza.
            </small>
          </div>
        )}
      </div>

      <div
        className={`rescue-wizard-card ${progress.target}`}
        aria-current={progress.target === "current" ? "step" : undefined}
      >
        <WizardCardTitle
          number="02"
          title="Scegli il sistema da controllare"
          state={progress.target}
        />
        {progress.target === "pending" && (
          <p>Attendi il controllo iniziale del Vault.</p>
        )}
        {progress.target === "current" && (
          <div className="rescue-wizard-targets">
            <p>
              KernAid mostra solo candidati identificati dai metadati. Il
              contenuto non viene aperto durante questa scelta.
            </p>
            <button
              className="rescue-wizard-secondary"
              disabled={targetBusy || inspectionBusy || busy}
              onClick={() => void onRefreshTargets()}
            >
              {targetBusy ? "Scansione…" : "Ripeti scansione"}
            </button>
            <div className="rescue-wizard-target-grid">
              {targetScan?.candidates.map((candidate, index) => {
                const item = rescueCandidatePresentation(
                  targetScan,
                  candidate,
                  index,
                );
                return (
                  <button
                    className={
                      selectedTarget?.target.targetId === candidate.targetId
                        ? "selected"
                        : ""
                    }
                    disabled={targetBusy || inspectionBusy || busy}
                    key={candidate.targetId}
                    onClick={() => void onSelectTarget(candidate)}
                  >
                    <b>{item.title}</b>
                    <small>{item.detail}</small>
                  </button>
                );
              })}
            </div>
            {targetReady && targetScan?.candidates.length === 0 && (
              <p className="rescue-wizard-alert">
                Nessun sistema selezionabile in modo sicuro.
              </p>
            )}
            {targetScan?.disks
              .filter((disk) => !disk.selectionEligible)
              .map((disk) => (
                <small key={disk.id}>
                  Escluso {disk.ref}: {disk.exclusionReasons.join(", ")}
                </small>
              ))}
            {targetError && (
              <p className="rescue-wizard-alert" role="alert">
                {targetError}
              </p>
            )}
          </div>
        )}
        {progress.target === "complete" && selectedTarget && (
          <div className="rescue-wizard-summary">
            <b>
              {targetFamilyLabel(selectedTarget.target.osFamilyHint)} ·{" "}
              {selectedTarget.target.sourceRef}
            </b>
            <small>Identità metadata-only rivalidata.</small>
          </div>
        )}
      </div>

      <div
        className={`rescue-wizard-card ${progress.provider}`}
        aria-current={progress.provider === "current" ? "step" : undefined}
      >
        <WizardCardTitle
          number="03"
          title="Scegli come analizzare"
          state={progress.provider}
          optional
        />
        {progress.provider === "pending" && (
          <p>Prima seleziona il sistema installato.</p>
        )}
        {progress.provider === "current" && (
          <div className="rescue-wizard-provider">
            <div className="rescue-wizard-choice-grid">
              <button
                aria-pressed={providerMode === "offline"}
                disabled={providerSelectionDisabled}
                onClick={() => onChooseProvider("offline")}
              >
                <b>Offline</b>
                <small>
                  Predefinito · nessun dato inviato · funziona senza Internet
                </small>
              </button>
              <button
                aria-pressed={providerMode === "openai"}
                disabled={providerSelectionDisabled || !openAiReady}
                onClick={() => onChooseProvider("openai")}
              >
                <b>OpenAI</b>
                <small>
                  Facoltativo · richiede Vault pronto e conferma anteprima
                </small>
              </button>
            </div>
            {!openAiReady && (
              <p className="rescue-wizard-note">{vaultGuidance}</p>
            )}
            {inspectionErrorView && (
              <div
                className={`rescue-wizard-alert ${inspectionErrorView.severity}`}
                role="alert"
              >
                <b>{inspectionErrorView.title}</b>
                <small>{inspectionErrorView.detail}</small>
                <small>{inspectionErrorView.action}</small>
              </div>
            )}
            <button
              className="rescue-wizard-primary"
              disabled={inspectDisabled}
              onClick={() => void onInspectTarget()}
            >
              {inspectionBlocked
                ? "Riavvio Rescue richiesto"
                : inspectionBusy
                  ? "Ispezione read-only…"
                  : `Continua con ${providerMode === "openai" ? "OpenAI" : "Offline"}`}
            </button>
            <small>
              Il target sarà aperto temporaneamente in sola lettura con cleanup
              verificato. Nessun path, comando o segreto proviene dal WebView.
            </small>
          </div>
        )}
        {progress.provider === "complete" && (
          <div className="rescue-wizard-summary">
            <b>{providerMode === "openai" ? "OpenAI" : "Offline rules"}</b>
            <small>
              Provider vincolato alla sessione e al target corrente.
            </small>
          </div>
        )}
      </div>

      <div
        className={`rescue-wizard-card ${progress.diagnosis}`}
        aria-current={progress.diagnosis === "current" ? "step" : undefined}
      >
        <WizardCardTitle
          number="04"
          title="Descrivi il problema"
          state={progress.diagnosis}
        />
        {progress.diagnosis === "pending" && (
          <p>Completa la preparazione read-only del target.</p>
        )}
        {(progress.diagnosis === "current" || reportReady) && (
          <div className="rescue-wizard-diagnosis">
            {inspectionView && (
              <div className="rescue-wizard-inspection" role="status">
                <b>{inspectionView.title}</b>
                <small>{inspectionView.detail}</small>
                {inspectionView.facts.map((fact) => (
                  <small key={fact}>{fact}</small>
                ))}
              </div>
            )}
            {!reportReady && (
              <>
                <label htmlFor="rescue-objective">
                  Cosa non funziona?
                  <small>
                    Non inserire password, token, email o altri dati personali.
                  </small>
                </label>
                <textarea
                  id="rescue-objective"
                  value={objective}
                  onChange={(event) => onObjectiveChange(event.target.value)}
                  placeholder="Esempio: Windows non si avvia dopo un aggiornamento…"
                />
              </>
            )}

            {providerMode === "openai" && !reportReady && (
              <div
                className="rescue-wizard-preview"
                role="region"
                aria-label="Anteprima OpenAI"
              >
                <div>
                  <small>ANTEPRIMA PRIMA DELL’INVIO</small>
                  <b>Contesto redatto prodotto da KernAid</b>
                </div>
                <button
                  className="rescue-wizard-secondary"
                  disabled={
                    openAiPreviewBusy ||
                    !objective.trim() ||
                    evidence.length !== 1
                  }
                  onClick={() => void onPreviewOpenAiContext()}
                >
                  {openAiPreviewBusy
                    ? "Preparazione anteprima…"
                    : openAiContextPreview
                      ? "Rigenera anteprima"
                      : "Prepara anteprima sicura"}
                </button>
                {openAiPreviewError && (
                  <p className="rescue-wizard-alert" role="alert">
                    {openAiPreviewError}
                  </p>
                )}
                {openAiContextPreview && (
                  <>
                    <dl>
                      <dt>Obiettivo redatto</dt>
                      <dd>{openAiContextPreview.context.objective}</dd>
                      <dt>Valutazione deterministica locale</dt>
                      <dd>
                        {
                          openAiContextPreview.context.deterministicProposal
                            .diagnosis
                        }
                      </dd>
                      <dt>Osservazioni inviate</dt>
                      <dd>
                        {openAiContextPreview.context.observations.map(
                          (item) => (
                            <code key={item.id}>
                              {item.id} · {item.collector} · {item.trust}
                            </code>
                          ),
                        )}
                      </dd>
                      <dt>Corpus grezzo</dt>
                      <dd>Non viene inviato a OpenAI</dd>
                      <dt>Binding</dt>
                      <dd>
                        <code>{openAiContextPreview.contextSha256}</code>
                      </dd>
                      <dt>Contesto completo</dt>
                      <dd>
                        <pre>
                          {JSON.stringify(
                            openAiContextPreview.context,
                            undefined,
                            2,
                          )}
                        </pre>
                      </dd>
                    </dl>
                    <button
                      className="rescue-wizard-secondary"
                      onClick={() =>
                        onAcceptOpenAiContext(
                          openAiContextPreview.contextSha256,
                        )
                      }
                    >
                      {previewAccepted
                        ? "Anteprima confermata"
                        : "Conferma questo contesto"}
                    </button>
                  </>
                )}
                <small>
                  La diagnosi reinvia questo digest e Rust ricalcola la stessa
                  proiezione prima di usare la credenziale o aprire la rete. Una
                  modifica annulla automaticamente la conferma.
                </small>
              </div>
            )}

            {!reportReady && (
              <button
                className="rescue-wizard-primary"
                disabled={diagnosisDisabled || !previewAccepted}
                onClick={() => void onDiagnose()}
              >
                {busy ? "Analisi…" : diagnosisButtonLabel}
              </button>
            )}
            <p className="rescue-wizard-live-status" role="status">
              {status}
            </p>
            {proposal && (
              <div className="rescue-wizard-result">
                <small>RISULTATO DIAGNOSTICO</small>
                <h2>{proposal.diagnosis}</h2>
                <p>
                  Confidenza {Math.round(proposal.confidence * 100)}% ·{" "}
                  {proposal.evidenceIds.length} evidenze collegate
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      <div
        className={`rescue-wizard-card ${progress.report}`}
        aria-current={progress.report === "current" ? "step" : undefined}
      >
        <WizardCardTitle
          number="05"
          title="Salva il report"
          state={progress.report}
        />
        {!reportReady ? (
          <p>Il report sarà disponibile al termine della diagnosi.</p>
        ) : (
          <div className="rescue-wizard-report">
            <p>
              {report.auditStatus.signed
                ? "Il JSON firmato è persistito anche nel Vault Rescue."
                : "Report temporaneo: JSON e Markdown non sono firmati."}
            </p>
            <div className="report-actions">
              <a
                href={report.uri}
                download={jsonReportDownloadName(report, sessionId)}
              >
                {jsonReportDownloadLabel(report)}
              </a>
              {markdownReport && (
                <a
                  href={markdownReport.uri}
                  download={markdownReport.downloadName}
                >
                  {UNSIGNED_MARKDOWN_DOWNLOAD_LABEL}
                </a>
              )}
            </div>
            <small>
              JSON SHA-256 <code>{report.sha256.slice(0, 12)}…</code>
              {markdownReport && (
                <>
                  {" "}
                  · Markdown SHA-256{" "}
                  <code>{markdownReport.sha256.slice(0, 12)}…</code>
                </>
              )}
            </small>
            {!markdownReport && !markdownReportError && (
              <small>Preparazione della copia Markdown non firmata…</small>
            )}
            {markdownReportError && (
              <small>
                Markdown non disponibile: il JSON non ha superato la validazione
                locale.
              </small>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function WizardCardTitle({
  number,
  title,
  state,
  optional = false,
}: {
  readonly number: string;
  readonly title: string;
  readonly state: "complete" | "current" | "pending";
  readonly optional?: boolean;
}) {
  return (
    <div className="rescue-wizard-card-title">
      <span>{number}</span>
      <div>
        <b>{title}</b>
        {optional && <small>FACOLTATIVO · OFFLINE È PREDEFINITO</small>}
      </div>
      <small>
        {state === "complete"
          ? "VERIFICATO"
          : state === "current"
            ? "ORA"
            : "DOPO"}
      </small>
    </div>
  );
}
