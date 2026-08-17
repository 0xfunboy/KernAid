import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { LocalSessionDriver } from "@kernaid/agent-gateway";
import type { ArtifactRef, AuditSink } from "@kernaid/session-driver";
import type {
  DiagnosisProposal,
  Evidence,
  ValidatedPlan,
} from "@kernaid/schemas";
import {
  authorizeObserve,
  collectLocalInventory,
  collectMacosP0Inventory,
  collectWindowsP0Inventory,
  getResidentOpenAiStatus,
  getSecureRuntimeStatus,
  hasLocalCollector,
  initializeDeviceIdentity,
  isNativeIdentityCollector,
  nativeObservationContentType,
  nativeObservationSummary,
  isNative,
  isRescueRuntime,
  NativeAuditSink,
  NativeOpenAiProvider,
  PlatformOfflineRulesProvider,
  fingerprintNativeTarget,
  scanRescueInstalledTargets,
  secureAuditReady,
  selectRescueInstalledTarget,
  logoutResidentOpenAi,
  type NativeObservation,
  type RescueTargetCandidate,
  type RescueTargetBinding,
  type RescueTargetScan,
  type RescueTargetSelection,
  type ResidentOpenAiStatus,
  type SecureRuntimeStatus,
} from "./native";
import {
  formatBytes,
  observationStatus,
  rescueCandidatePresentation,
  rescueTargetBinding,
  sameRescueSelection,
  targetFamilyLabel,
  type InventoryCategory,
} from "./rescue-ui";
import "./style.css";

type Workflow = "Observe" | "Diagnose" | "Plan" | "Verify";
type ProviderMode = "offline" | "openai";

function App() {
  const [driver, setDriver] = useState<LocalSessionDriver>();
  const [runtimeStatus, setRuntimeStatus] = useState<SecureRuntimeStatus>();
  const [runtimeReady, setRuntimeReady] = useState(false);
  const [providerMode, setProviderMode] = useState<ProviderMode>("offline");
  const [openAiStatus, setOpenAiStatus] = useState<ResidentOpenAiStatus>();
  const [providerLogoutBusy, setProviderLogoutBusy] = useState(false);
  const providerLogoutInFlight = useRef(false);
  const [objective, setObjective] = useState("");
  const [workflow, setWorkflow] = useState<Workflow>("Observe");
  const [status, setStatus] = useState("Pronto per una diagnosi sicura.");
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [proposal, setProposal] = useState<DiagnosisProposal>();
  const [plan, setPlan] = useState<ValidatedPlan>();
  const [report, setReport] = useState<ArtifactRef>();
  const [nativeEvidence, setNativeEvidence] = useState<NativeObservation[]>([]);
  const [inventoryReady, setInventoryReady] = useState(!hasLocalCollector());
  const [inventoryError, setInventoryError] = useState<string>();
  const [sessionId, setSessionId] = useState<string>();
  const [targetFingerprint, setTargetFingerprint] = useState<string>();
  const [sessionDriver, setSessionDriver] = useState<LocalSessionDriver>();
  const [sessionRescueTarget, setSessionRescueTarget] =
    useState<RescueTargetSelection>();
  const [rescueTargetScan, setRescueTargetScan] = useState<RescueTargetScan>();
  const [selectedRescueTarget, setSelectedRescueTarget] =
    useState<RescueTargetSelection>();
  const [rescueTargetReady, setRescueTargetReady] =
    useState(!isRescueRuntime());
  const [rescueTargetBusy, setRescueTargetBusy] = useState(false);
  const [rescueTargetError, setRescueTargetError] = useState<string>();

  useEffect(() => {
    let cancelled = false;
    async function startRuntime() {
      if (!isNative()) {
        if (!cancelled) {
          setDriver(createDriver());
          setRuntimeReady(true);
        }
        return;
      }
      try {
        const next = await getSecureRuntimeStatus();
        if (cancelled) return;
        setRuntimeStatus(next);
        if (secureAuditReady(next))
          setDriver(createDriver(new NativeAuditSink()));
        else if (
          next.audit === "unavailable" &&
          !next.persistentAuditStarted &&
          next.signing !== "blocked"
        )
          setDriver(createDriver());
        else setDriver(undefined);
      } catch {
        if (!cancelled) {
          setDriver(undefined);
          setStatus("Il runtime sicuro non è disponibile; riavviare KernAid.");
        }
      } finally {
        if (!cancelled) setRuntimeReady(true);
      }
    }
    void startRuntime();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isNative()) return;
    let cancelled = false;
    getResidentOpenAiStatus()
      .then((next) => {
        if (!cancelled) setOpenAiStatus(next);
      })
      .catch(() => {
        if (!cancelled) setOpenAiStatus(undefined);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isRescueRuntime()) return;
    let cancelled = false;
    scanRescueInstalledTargets()
      .then((scan) => {
        if (cancelled) return;
        setRescueTargetScan(scan);
        setSelectedRescueTarget(undefined);
        setRescueTargetError(undefined);
        if (scan.candidates.length === 0)
          setStatus(
            "Nessun candidato installato selezionabile: storage montato, cifrato o complesso richiede una procedura dedicata.",
          );
      })
      .catch((error) => {
        if (cancelled) return;
        const message = `Scansione target non disponibile: ${String(error)}`;
        setRescueTargetScan(undefined);
        setSelectedRescueTarget(undefined);
        setRescueTargetError(message);
        setStatus(message);
      })
      .finally(() => {
        if (!cancelled) setRescueTargetReady(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!hasLocalCollector()) return;
    collectLocalInventory()
      .then((items) => {
        setNativeEvidence(items);
        setInventoryError(undefined);
      })
      .catch((error) => {
        const message = `Inventario locale non disponibile: ${String(error)}`;
        setNativeEvidence([]);
        setInventoryError(message);
        setStatus(message);
      })
      .finally(() => setInventoryReady(true));
  }, []);

  function invalidateSession() {
    setEvidence([]);
    setProposal(undefined);
    setPlan(undefined);
    setReport(undefined);
    setSessionId(undefined);
    setTargetFingerprint(undefined);
    setSessionDriver(undefined);
    setSessionRescueTarget(undefined);
    setWorkflow("Observe");
  }

  async function diagnose() {
    if (
      !objective.trim() ||
      busy ||
      !driver ||
      (isRescueRuntime() &&
        (rescueTargetScan === undefined || selectedRescueTarget === undefined))
    )
      return;
    let activeDriver = driver;
    setBusy(true);
    invalidateSession();
    try {
      setWorkflow("Observe");
      setStatus("Raccolta evidenze in sola lettura…");
      let activeRescueSelection = selectedRescueTarget;
      if (isRescueRuntime()) {
        if (
          rescueTargetScan === undefined ||
          activeRescueSelection === undefined
        )
          throw new Error("Selezionare prima un candidato target Rescue.");
        activeRescueSelection = await selectRescueInstalledTarget(
          rescueTargetScan.scanFingerprint,
          activeRescueSelection.target,
        );
        setSelectedRescueTarget(activeRescueSelection);
      }
      let currentNativeEvidence: NativeObservation[] = [];
      if (hasLocalCollector()) {
        try {
          const currentIdentity = await collectLocalInventory();
          const windowsIdentity = currentIdentity.filter(
            (item) => item.collector === "windows.storage.identity",
          );
          const macosIdentity = currentIdentity.filter(
            (item) => item.collector === "macos.storage.identity",
          );
          if (isNative() && windowsIdentity.length > 0) {
            if (
              windowsIdentity.length !== 1 ||
              windowsIdentity.some((item) => !item.success || item.truncated)
            )
              throw new Error(
                "Identità Windows rapida non disponibile: diagnosi bloccata.",
              );
            setStatus(
              "Raccolta Windows P0 in parallelo (budget software 150 s; SFC non eseguito perché non ancora qualificato)…",
            );
            currentNativeEvidence = await collectWindowsP0Inventory();
            const diagnosticIdentity = currentNativeEvidence.filter(
              (item) => item.collector === "windows.storage.identity",
            );
            if (
              diagnosticIdentity.length !== 1 ||
              !diagnosticIdentity[0]?.success ||
              diagnosticIdentity[0].truncated ||
              diagnosticIdentity[0].output !== windowsIdentity[0]?.output
            )
              throw new Error(
                "Il target Windows è cambiato durante la raccolta: diagnosi annullata.",
              );
          } else if (isNative() && macosIdentity.length > 0) {
            if (
              macosIdentity.length !== 1 ||
              macosIdentity.some((item) => !item.success || item.truncated)
            )
              throw new Error(
                "Identità storage macOS rapida non disponibile: diagnosi bloccata.",
              );
            setStatus(
              "Raccolta macOS P0 in parallelo (otto proiezioni native, sola lettura, budget 90 s)…",
            );
            currentNativeEvidence = await collectMacosP0Inventory();
            const diagnosticIdentity = currentNativeEvidence.filter(
              (item) => item.collector === "macos.storage.identity",
            );
            if (
              diagnosticIdentity.length !== 1 ||
              !diagnosticIdentity[0]?.success ||
              diagnosticIdentity[0].truncated ||
              diagnosticIdentity[0].output !== macosIdentity[0]?.output
            )
              throw new Error(
                "Il target storage macOS è cambiato durante la raccolta: diagnosi annullata.",
              );
          } else currentNativeEvidence = currentIdentity;
        } catch (error) {
          const message = `Inventario locale non disponibile: ${String(error)}`;
          setNativeEvidence([]);
          setInventoryError(message);
          throw new Error(`${message} Diagnosi bloccata.`);
        }
      }
      if (hasLocalCollector() && currentNativeEvidence.length === 0)
        throw new Error(
          "L’inventario locale non ha restituito evidenze: diagnosi bloccata.",
        );
      if (hasLocalCollector()) {
        setNativeEvidence(currentNativeEvidence);
        setInventoryError(undefined);
      }
      const identityEvidence = currentNativeEvidence.filter((item) =>
        isNativeIdentityCollector(item.collector),
      );
      if (
        hasLocalCollector() &&
        (identityEvidence.length === 0 ||
          identityEvidence.some((item) => !item.success || item.truncated))
      )
        throw new Error(
          "Identità del target incompleta: la sessione è stata bloccata senza formulare diagnosi.",
        );
      let rescueBinding: RescueTargetBinding | undefined;
      if (activeRescueSelection !== undefined) {
        activeRescueSelection = await selectRescueInstalledTarget(
          activeRescueSelection.scanFingerprint,
          activeRescueSelection.target,
        );
        setSelectedRescueTarget(activeRescueSelection);
        rescueBinding = rescueTargetBinding(activeRescueSelection);
        activeDriver = createDriver(undefined, rescueBinding);
      }
      const targetFingerprint = currentNativeEvidence.length
        ? await fingerprintNativeTarget(currentNativeEvidence, rescueBinding)
        : `sha256:${"0".repeat(64)}`;
      setTargetFingerprint(targetFingerprint);
      const session = await activeDriver.startSession({
        mode: isNative() ? "resident" : "rescue",
        targetFingerprint,
      });
      setSessionDriver(activeDriver);
      setSessionRescueTarget(activeRescueSelection);
      setSessionId(session.id);
      const observed: Evidence[] = [];
      if (currentNativeEvidence.length) {
        for (const item of currentNativeEvidence)
          observed.push(
            ...(await activeDriver.requestEvidence(session.id, {
              collector: item.collector,
              target: isNative() ? "local-machine" : "rescue-runtime",
              summary: nativeObservationSummary(item),
              observedContent: item.output,
              contentType: nativeObservationContentType(item),
            })),
          );
        if (activeRescueSelection !== undefined)
          observed.push(
            ...(await activeDriver.requestEvidence(session.id, {
              collector: "rescue.installed-target.selection",
              target: "selected-installed-target-candidate",
              summary:
                "Candidato target rivalidato; soli metadati, nessun mount o contenuto ispezionato",
              observedContent: JSON.stringify(activeRescueSelection),
              contentType: "application/json",
            })),
          );
      } else if (!hasLocalCollector()) {
        observed.push(
          ...(await activeDriver.requestEvidence(session.id, {
            collector: "linux.fixture.inventory",
            target: "fixture:linux-root",
          })),
        );
      } else {
        throw new Error(
          "L’inventario locale è obbligatorio: diagnosi bloccata.",
        );
      }
      setEvidence(observed);
      setWorkflow("Diagnose");
      let diagnosis: DiagnosisProposal | undefined;
      for await (const event of activeDriver.sendUserPrompt(
        session.id,
        objective,
      )) {
        setStatus(event.message);
        if (event.proposal) diagnosis = event.proposal;
      }
      if (!diagnosis)
        throw new Error("Il provider non ha restituito una diagnosi valida.");
      setProposal(diagnosis);
      const staged = await activeDriver.stagePlan(session.id, diagnosis);
      setPlan(staged);
      setWorkflow("Plan");
      const artifact = await activeDriver.exportReport(session.id, "json");
      setReport(artifact);
      setStatus("Diagnosi completata. Nessuna modifica eseguita.");
    } catch (error) {
      if (isRescueRuntime()) setSelectedRescueTarget(undefined);
      invalidateSession();
      await refreshSecureRuntimeAfterFailure();
      setStatus(error instanceof Error ? error.message : "Errore inatteso");
    } finally {
      setBusy(false);
    }
  }

  async function refreshRescueTargets() {
    if (!isRescueRuntime() || rescueTargetBusy || busy) return;
    setRescueTargetBusy(true);
    setRescueTargetReady(false);
    setSelectedRescueTarget(undefined);
    invalidateSession();
    setStatus("Nuova scansione metadata-only dei target…");
    try {
      const scan = await scanRescueInstalledTargets();
      setRescueTargetScan(scan);
      setRescueTargetError(undefined);
      setStatus(
        scan.candidates.length
          ? "Seleziona il candidato del sistema da osservare."
          : "Nessun candidato installato selezionabile in modo sicuro.",
      );
    } catch (error) {
      const message = `Scansione target non disponibile: ${String(error)}`;
      setRescueTargetScan(undefined);
      setRescueTargetError(message);
      setStatus(message);
    } finally {
      setRescueTargetReady(true);
      setRescueTargetBusy(false);
    }
  }

  async function chooseRescueTarget(candidate: RescueTargetCandidate) {
    if (
      !isRescueRuntime() ||
      rescueTargetScan === undefined ||
      rescueTargetBusy ||
      busy
    )
      return;
    setRescueTargetBusy(true);
    setSelectedRescueTarget(undefined);
    invalidateSession();
    setStatus("Rivalidazione del candidato target…");
    try {
      const selected = await selectRescueInstalledTarget(
        rescueTargetScan.scanFingerprint,
        candidate,
      );
      setSelectedRescueTarget(selected);
      setRescueTargetError(undefined);
      setStatus(
        "Target selezionato in modalità metadata-only. Il contenuto del filesystem non è ancora stato ispezionato.",
      );
    } catch (error) {
      const message = `Target non più valido: ${String(error)}`;
      setRescueTargetError(message);
      setStatus(message);
    } finally {
      setRescueTargetBusy(false);
    }
  }

  async function verify() {
    if (
      !plan ||
      !sessionId ||
      !targetFingerprint ||
      busy ||
      !sessionDriver ||
      (isRescueRuntime() &&
        !sameRescueSelection(sessionRescueTarget, selectedRescueTarget))
    )
      return;
    const activeDriver = sessionDriver;
    setBusy(true);
    setWorkflow("Verify");
    setStatus("Verifica del piano e delle evidenze…");
    try {
      for await (const event of activeDriver.executePlan(plan.planId))
        setStatus(event.message);
      setReport(await activeDriver.exportReport(sessionId, "json"));
    } catch (error) {
      if (isRescueRuntime()) {
        setSelectedRescueTarget(undefined);
        invalidateSession();
      }
      await refreshSecureRuntimeAfterFailure();
      setStatus(
        error instanceof Error ? error.message : "Verifica non riuscita",
      );
    } finally {
      setBusy(false);
    }
  }

  async function activateSecureRuntime() {
    if (!isNative() || busy || sessionId) return;
    setBusy(true);
    setStatus("Attivazione dell’identità protetta dal sistema…");
    try {
      const next = await initializeDeviceIdentity();
      setRuntimeStatus(next);
      if (!secureAuditReady(next))
        throw new Error("Il portachiavi sicuro non è ancora disponibile.");
      setDriver(createDriver(new NativeAuditSink(), undefined, providerMode));
      setStatus("Audit cifrato e firma del dispositivo attivi.");
    } catch (error) {
      setDriver(undefined);
      await refreshSecureRuntimeAfterFailure();
      setStatus(
        error instanceof Error ? error.message : "Attivazione non riuscita",
      );
    } finally {
      setBusy(false);
    }
  }

  function chooseProvider(next: ProviderMode) {
    if (
      !isNative() ||
      busy ||
      sessionId !== undefined ||
      driver === undefined ||
      (next === "openai" && openAiStatus?.credential !== "configured")
    )
      return;
    invalidateSession();
    setProviderMode(next);
    setDriver(createDriver(activeAuditSink(runtimeStatus), undefined, next));
    setStatus(
      next === "openai"
        ? "OpenAI selezionato. Il corpus grezzo resta locale; vengono inviati obiettivo filtrato, proposta deterministica e soli ID/collector."
        : "Diagnostica offline selezionata. Nessun dato lascia il computer.",
    );
  }

  async function logoutOpenAi() {
    if (
      !isNative() ||
      providerLogoutInFlight.current ||
      (providerMode !== "openai" && (busy || sessionId !== undefined))
    )
      return;
    providerLogoutInFlight.current = true;
    setProviderLogoutBusy(true);
    setBusy(true);
    const hadDriver = driver !== undefined;
    try {
      const next = await logoutResidentOpenAi();
      setOpenAiStatus(next);
      setProviderMode("offline");
      invalidateSession();
      if (hadDriver)
        setDriver(
          createDriver(activeAuditSink(runtimeStatus), undefined, "offline"),
        );
      setStatus(
        "Logout OpenAI completato e verificato. Provider offline attivo.",
      );
    } catch (error) {
      setStatus(
        error instanceof Error
          ? error.message
          : "Logout OpenAI non completato.",
      );
    } finally {
      providerLogoutInFlight.current = false;
      setProviderLogoutBusy(false);
      setBusy(false);
    }
  }

  async function refreshSecureRuntimeAfterFailure() {
    if (!isNative()) return;
    try {
      const next = await getSecureRuntimeStatus();
      setRuntimeStatus(next);
      if (!secureAuditReady(next)) {
        setDriver(undefined);
        invalidateSession();
      }
    } catch {
      setDriver(undefined);
      invalidateSession();
      setRuntimeStatus(undefined);
    }
  }

  const securityBlocked =
    isNative() &&
    (runtimeStatus?.audit === "blocked" ||
      runtimeStatus?.signing === "blocked" ||
      (runtimeStatus?.persistentAuditStarted === true &&
        !secureAuditReady(runtimeStatus)));
  const securityNeedsActivation =
    isNative() &&
    runtimeStatus?.audit === "secure" &&
    runtimeStatus.signing !== "ready";
  const securityLabel = !isNative()
    ? "Vault bloccato"
    : !runtimeReady
      ? "Sicurezza in avvio"
      : runtimeStatus !== undefined && secureAuditReady(runtimeStatus)
        ? `Audit cifrato · ${runtimeStatus?.deviceId ?? "Firma attiva"}`
        : runtimeStatus?.audit === "unavailable"
          ? "Audit non disponibile · report non firmati"
          : securityBlocked
            ? "Sicurezza bloccata"
            : runtimeStatus === undefined
              ? "Sicurezza non disponibile"
              : "Attivazione sicurezza richiesta";
  const rescueSessionCurrent =
    !isRescueRuntime() ||
    sameRescueSelection(sessionRescueTarget, selectedRescueTarget);
  const categories: InventoryCategory[] = [
    "Hardware",
    "Storage",
    "Boot",
    "Network",
  ];

  return (
    <main>
      <header>
        <strong>KernAid</strong>
        <div className="runtime-summary">
          {isNative() && (
            <div className="provider-switch" aria-label="Provider diagnostico">
              <button
                aria-pressed={providerMode === "offline"}
                disabled={busy || sessionId !== undefined}
                onClick={() => chooseProvider("offline")}
              >
                Offline
              </button>
              <button
                aria-pressed={providerMode === "openai"}
                disabled={
                  busy ||
                  sessionId !== undefined ||
                  openAiStatus?.credential !== "configured"
                }
                onClick={() => chooseProvider("openai")}
              >
                OpenAI
              </button>
              {openAiStatus?.credential === "configured" && (
                <button
                  disabled={
                    providerLogoutBusy ||
                    (providerMode !== "openai" &&
                      (busy || sessionId !== undefined))
                  }
                  onClick={logoutOpenAi}
                >
                  {providerLogoutBusy ? "Logout…" : "Logout"}
                </button>
              )}
            </div>
          )}
          <span>
            {isNative() ? "Resident" : "Rescue"} ·{" "}
            {providerMode === "openai"
              ? "OpenAI · gpt-5.6-sol"
              : "Offline rules"}{" "}
            · {securityLabel}
          </span>
          {isNative() && openAiStatus?.credential !== "configured" && (
            <small>
              OpenAI non configurato · chiudi Desk e avvia con{" "}
              <code>configure</code> il companion nativo estratto
            </small>
          )}
        </div>
      </header>
      <aside>
        <p className="label">
          {isRescueRuntime() ? "TARGET INSTALLATO" : "TARGET MACHINE"}
        </p>
        <h2>
          {isNative()
            ? "Local machine"
            : hasLocalCollector()
              ? selectedRescueTarget
                ? `Candidato ${targetFamilyLabel(selectedRescueTarget.target.osFamilyHint)} · metadata-only`
                : "Target non selezionato"
              : "Linux fixture"}
        </h2>
        {isRescueRuntime() && (
          <div className="target-picker">
            <p>
              Solo metadati storage. Nessun filesystem viene montato e nessuna
              installazione è confermata.
            </p>
            <button
              disabled={rescueTargetBusy || busy}
              onClick={refreshRescueTargets}
            >
              {rescueTargetBusy ? "Scansione…" : "Ripeti scansione target"}
            </button>
            {rescueTargetScan?.candidates.map((candidate, index) => {
              const presentation = rescueCandidatePresentation(
                rescueTargetScan,
                candidate,
                index,
              );
              return (
                <button
                  className={
                    selectedRescueTarget?.target.targetId === candidate.targetId
                      ? "selected-target"
                      : ""
                  }
                  disabled={rescueTargetBusy || busy}
                  key={candidate.targetId}
                  onClick={() => chooseRescueTarget(candidate)}
                >
                  <b>{presentation.title}</b>
                  <small>{presentation.detail}</small>
                </button>
              );
            })}
            {rescueTargetScan?.disks
              .filter((disk) => !disk.selectionEligible)
              .map((disk) => (
                <small key={disk.id}>
                  Escluso {disk.ref} · {formatBytes(disk.sizeBytes)} ·{" "}
                  {disk.exclusionReasons.join(", ")}
                </small>
              ))}
            {rescueTargetReady && rescueTargetScan?.candidates.length === 0 && (
              <small>Nessun candidato selezionabile.</small>
            )}
            {rescueTargetError && <small>{rescueTargetError}</small>}
          </div>
        )}
        {isRescueRuntime() && (
          <div className="target-scope">
            <button>
              Storage metadata · {selectedRescueTarget ? "observed" : "pending"}
            </button>
            <button>OS content · not inspected</button>
            <button>Boot content · not inspected</button>
            <button>Target network · not inspected</button>
            <p className="label">AMBIENTE RESCUE</p>
            <h2>Runtime live · non è il target</h2>
          </div>
        )}
        {categories.map((item) => (
          <button key={item}>
            {isRescueRuntime() ? `Rescue ${item}` : item} ·{" "}
            {observationStatus(item, nativeEvidence)}
          </button>
        ))}
        {nativeEvidence.map((item) => (
          <details key={item.collector}>
            <summary>
              {isRescueRuntime() ? "Rescue · " : ""}
              {item.collector} · {item.success ? "observed" : "unavailable"}
            </summary>
            <pre>{item.output || "Nessun output"}</pre>
          </details>
        ))}
      </aside>
      <section>
        <div className="steps">
          {(["Observe", "Diagnose", "Plan", "Repair", "Verify"] as const).map(
            (step) => (
              <span className={step === workflow ? "active" : ""} key={step}>
                {step}
              </span>
            ),
          )}
        </div>
        <article>
          <small>
            {evidence.length
              ? `${evidence[0].id} · observed-untrusted`
              : "SESSION NOT STARTED"}
          </small>
          <h1>{proposal?.diagnosis ?? "Evidence before action."}</h1>
          <p>{status}</p>
          {proposal && (
            <p>
              Confidenza: {Math.round(proposal.confidence * 100)}% · Evidenze:{" "}
              {proposal.evidenceIds.join(", ")}
            </p>
          )}
        </article>
        {(securityNeedsActivation || securityBlocked) && (
          <div className={`security ${securityBlocked ? "blocked" : ""}`}>
            <b>
              {securityBlocked
                ? "Archivio sicuro bloccato"
                : "Proteggi audit e report"}
            </b>
            <p>
              {securityBlocked
                ? "KernAid ha rilevato uno stato sicuro incoerente. Nessuna sessione può partire: riavvia l’app e controlla il portachiavi di sistema."
                : "Premi una volta per creare l’identità del laboratorio nel portachiavi di sistema. I report saranno cifrati nel journal e firmati."}
            </p>
            {!securityBlocked && (
              <button
                disabled={busy || Boolean(sessionId)}
                onClick={activateSecureRuntime}
              >
                {busy
                  ? "Attivazione…"
                  : runtimeStatus?.signing === "uninitialized"
                    ? "Attiva sicurezza"
                    : "Riprova portachiavi"}
              </button>
            )}
          </div>
        )}
        {providerMode === "openai" && (
          <p className="provider-context-notice" role="note">
            A OpenAI invieremo l’obiettivo dopo filtri conservativi per token,
            email, IP e percorsi comuni, più la proposta diagnostica locale e
            soli ID/collector. Il corpus grezzo resta sul PC. Il testo libero
            può comunque contenere nomi o altri dati personali: non inserirli;
            questa versione non offre ancora un’anteprima del contesto.
          </p>
        )}
        <textarea
          aria-label="Problem description"
          value={objective}
          onChange={(event) => setObjective(event.target.value)}
          placeholder="Descrivi il problema del computer…"
        />
        <button
          className="primary"
          disabled={
            !objective.trim() ||
            busy ||
            !inventoryReady ||
            !rescueTargetReady ||
            (isRescueRuntime() && selectedRescueTarget === undefined) ||
            !runtimeReady ||
            !driver ||
            securityBlocked
          }
          onClick={diagnose}
        >
          {!inventoryReady || !runtimeReady || !rescueTargetReady
            ? "Avvio sicuro…"
            : busy
              ? "Analisi…"
              : isRescueRuntime() && selectedRescueTarget === undefined
                ? "Seleziona un target"
                : inventoryError
                  ? "Riprova inventario"
                  : "Diagnostica"}
        </button>
        {plan && workflow !== "Verify" && rescueSessionCurrent && (
          <button
            disabled={busy || !sessionDriver || securityBlocked}
            onClick={verify}
          >
            Verifica piano R0
          </button>
        )}
        {report && (
          <p className="report">
            <a
              href={report.uri}
              download={
                report.auditStatus.signed
                  ? "KernAid-signed-report.json"
                  : "KernAid-report.json"
              }
            >
              Scarica{" "}
              {report.auditStatus.signed ? "report firmato" : "report JSON"}
            </a>{" "}
            · SHA-256 <code>{report.sha256.slice(0, 12)}…</code>
          </p>
        )}
      </section>
      <aside className="right">
        <p className="label">STAGED PLAN</p>
        <h2>{plan ? plan.diagnosis : "Nessuna modifica prevista"}</h2>
        <p>
          Rischio {plan?.risk ?? "R0"} · {plan?.steps.length ?? 0} azioni
        </p>
        <hr />
        {plan?.steps.map((step) => (
          <div className="plan" key={step.action}>
            <b>{step.action}</b>
            <small>Validazione: {step.validation}</small>
          </div>
        ))}
        <p>
          Le riparazioni reali richiedono backup, risorse esplicite e
          approvazione locale.
        </p>
      </aside>
      <footer>
        {evidence.length + nativeEvidence.length} evidenze · Terminale
        disabilitato · Audit locale
      </footer>
    </main>
  );
}

function createDriver(
  auditSink?: AuditSink,
  rescueTarget?: RescueTargetBinding,
  providerMode: ProviderMode = "offline",
): LocalSessionDriver {
  return new LocalSessionDriver(
    providerMode === "openai" && isNative()
      ? new NativeOpenAiProvider()
      : new PlatformOfflineRulesProvider(),
    hasLocalCollector()
      ? {
          execute: (request) => authorizeObserve(request, rescueTarget),
        }
      : undefined,
    auditSink,
  );
}

function activeAuditSink(
  status: SecureRuntimeStatus | undefined,
): AuditSink | undefined {
  return status !== undefined && secureAuditReady(status)
    ? new NativeAuditSink()
    : undefined;
}

createRoot(document.getElementById("root")!).render(<App />);
