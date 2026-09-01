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
  collectLinuxFilesystemHealth,
  collectLinuxNormalizedSnapshot,
  collectLocalInventory,
  collectMacosP0Inventory,
  collectWindowsP0Inventory,
  getResidentOpenAiStatus,
  getResidentStructuredProviderStatus,
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
  NativeResidentStructuredProvider,
  PlatformOfflineRulesProvider,
  fingerprintNativeTarget,
  inspectRescueFilesystemHealth,
  inspectRescueInstalledTarget,
  linuxNormalizedSnapshotEvidenceSummary,
  linuxNormalizedSnapshotFromRescue,
  parseLinuxFilesystemHealth,
  parseLinuxBootCriticalPath,
  parseLinuxStorageHealth,
  projectLinuxStorageHealth,
  scanRescueInstalledTargets,
  secureAuditReady,
  selectRescueInstalledTarget,
  rescueOfflineCorpusJson,
  rescueOfflineEvidenceSummary,
  logoutResidentOpenAi,
  logoutResidentStructuredProvider,
  verifyRescueTauriIpcIsolation,
  LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
  LINUX_FILESYSTEM_HEALTH_COLLECTOR,
  LINUX_BOOT_CRITICAL_PATH_COLLECTOR,
  LINUX_STORAGE_HEALTH_COLLECTOR,
  RESCUE_OFFLINE_EVIDENCE_COLLECTOR,
  RESCUE_OFFLINE_EVIDENCE_TARGET,
  type NativeObservation,
  type LinuxFilesystemHealthSnapshot,
  type LinuxBootCriticalPathSnapshot,
  type LinuxStorageHealthSnapshot,
  type RescueOfflineInspection,
  RescueOfflineInspectionError,
  type RescueTargetCandidate,
  type RescueTargetBinding,
  type RescueTargetScan,
  type RescueTargetSelection,
  type ResidentOpenAiStatus,
  type ResidentStructuredProviderMode,
  type ResidentStructuredProviderStatus,
  type SecureRuntimeStatus,
} from "./native";
import { filesystemHealthEvidenceSummary } from "./filesystem-health";
import { storageHealthEvidenceSummary } from "./storage-health";
import {
  getRescueOpenAiStatus,
  parseRescueOpenAiContextPreview,
  rescueOpenAiReady,
  RescueOpenAiProvider,
  RescueProviderSessionBinding,
  transitionRescueProviderMode,
  type RescueOpenAiContextPreview,
  type RescueOpenAiStatus,
  type RescueProviderMode,
  type RescueProviderPreparation,
} from "./rescue-openai";
import { createRescueAuditSink, type RescueAuditSink } from "./rescue-audit";
import {
  createUnsignedMarkdownReport,
  jsonReportDownloadLabel,
  jsonReportDownloadName,
  UNSIGNED_MARKDOWN_DOWNLOAD_LABEL,
  type MarkdownReportExport,
} from "./report-export";
import {
  finishRescueInspection,
  observationStatus,
  rescueInspectionErrorPresentation,
  rescueInspectionFailureDisposition,
  rescueInspectionNeedsRescan,
  rescueInspectionPresentation,
  rescueInspectionResponseCurrent,
  rescueTargetBinding,
  sameRescueInspection,
  sameRescueSelection,
  targetFamilyLabel,
  tryStartRescueInspection,
  type InventoryCategory,
} from "./rescue-ui";
import { FixtureRepairLabPanel } from "./fixture-repair-lab-panel";
import { RescueDiagnosisWizard } from "./rescue-diagnosis-wizard";
import { RescueRepairPanel } from "./rescue-repair-entry";
import "./style.css";

type Workflow = "Observe" | "Diagnose" | "Plan" | "Verify";
type ProviderMode = RescueProviderMode | ResidentStructuredProviderMode;
const RESCUE_OPENAI_STATUS_ATTEMPTS = 20;
const RESCUE_OPENAI_STATUS_RETRY_MS = 250;

function App() {
  const [driver, setDriver] = useState<LocalSessionDriver>();
  const [rescueAuditSink, setRescueAuditSink] = useState<RescueAuditSink>();
  const [runtimeStatus, setRuntimeStatus] = useState<SecureRuntimeStatus>();
  const [runtimeReady, setRuntimeReady] = useState(false);
  const [providerMode, setProviderMode] = useState<ProviderMode>("offline");
  const [openAiStatus, setOpenAiStatus] = useState<
    ResidentOpenAiStatus | RescueOpenAiStatus
  >();
  const [openAiStatusReady, setOpenAiStatusReady] = useState(false);
  const [structuredProviderStatuses, setStructuredProviderStatuses] = useState<
    Partial<
      Record<ResidentStructuredProviderMode, ResidentStructuredProviderStatus>
    >
  >({});
  const [providerLogoutBusy, setProviderLogoutBusy] = useState(false);
  const providerLogoutInFlight = useRef(false);
  const [objective, setObjective] = useState("");
  const [rescueOpenAiContextPreview, setRescueOpenAiContextPreview] =
    useState<RescueOpenAiContextPreview>();
  const [
    rescueOpenAiAcceptedContextSha256,
    setRescueOpenAiAcceptedContextSha256,
  ] = useState<string>();
  const [rescueOpenAiPreviewBusy, setRescueOpenAiPreviewBusy] = useState(false);
  const [rescueOpenAiPreviewError, setRescueOpenAiPreviewError] =
    useState<string>();
  const rescueOpenAiPreviewEpoch = useRef(0);
  const [workflow, setWorkflow] = useState<Workflow>("Observe");
  const [status, setStatus] = useState("Pronto per una diagnosi sicura.");
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [proposal, setProposal] = useState<DiagnosisProposal>();
  const [plan, setPlan] = useState<ValidatedPlan>();
  const [report, setReport] = useState<ArtifactRef>();
  const [markdownReport, setMarkdownReport] = useState<MarkdownReportExport>();
  const [markdownReportError, setMarkdownReportError] = useState(false);
  const [nativeEvidence, setNativeEvidence] = useState<NativeObservation[]>([]);
  const [filesystemHealth, setFilesystemHealth] =
    useState<LinuxFilesystemHealthSnapshot>();
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
  const [rescueTargetBusy, setRescueTargetBusy] = useState(isRescueRuntime());
  const [rescueTargetError, setRescueTargetError] = useState<string>();
  const [rescueInspection, setRescueInspection] =
    useState<RescueOfflineInspection>();
  const [rescueInspectionError, setRescueInspectionError] =
    useState<RescueOfflineInspectionError>();
  const [rescueInspectionBusy, setRescueInspectionBusy] = useState(false);
  const [rescueInspectionBlocked, setRescueInspectionBlocked] = useState(false);
  const rescueInspectionInFlight = useRef(false);
  const rescueContextEpoch = useRef(0);
  const rescueProviderBinding = useRef(
    new RescueProviderSessionBinding("offline"),
  );
  const openAiReady =
    openAiStatus?.profile === "resident-default"
      ? openAiStatus.credential === "configured"
      : openAiStatus?.profile === "rescue-default"
        ? rescueOpenAiReady(openAiStatus)
        : false;
  const providerReady = (mode: ProviderMode): boolean => {
    if (mode === "offline") return true;
    if (mode === "openai") return openAiReady;
    return structuredProviderStatuses[mode]?.credential === "configured";
  };

  useEffect(() => {
    let cancelled = false;
    async function startRuntime() {
      if (!isNative()) {
        try {
          await verifyRescueTauriIpcIsolation();
        } catch {
          if (!cancelled) {
            setDriver(undefined);
            setStatus(
              "Confine IPC Rescue non sicuro; riavviare KernAid da un supporto verificato.",
            );
          }
          if (!cancelled) setRuntimeReady(true);
          return;
        }
        let auditSink: RescueAuditSink | undefined;
        if (isRescueRuntime()) {
          try {
            auditSink = await createRescueAuditSink();
          } catch {
            if (!cancelled)
              setStatus(
                "Audit persistente Rescue non disponibile: sbloccare il Vault e ricaricare Desk. La diagnosi corrente resta in sola lettura.",
              );
          }
        }
        if (!cancelled) {
          setRescueAuditSink(auditSink);
          setDriver(createDriver(auditSink));
          if (isRescueRuntime() && auditSink === undefined)
            setStatus((current) =>
              current.startsWith("Audit persistente")
                ? current
                : "Vault Rescue bloccato o assente: la diagnosi resta disponibile, ma il report non sarà persistente finché il Vault non viene sbloccato e Desk ricaricato.",
            );
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
    void Promise.all(
      (["anthropic_api", "gemini_api"] as const).map(async (providerMode) => {
        try {
          return [
            providerMode,
            await getResidentStructuredProviderStatus(providerMode),
          ] as const;
        } catch {
          return [providerMode, undefined] as const;
        }
      }),
    ).then((entries) => {
      if (cancelled) return;
      const next: Partial<
        Record<ResidentStructuredProviderMode, ResidentStructuredProviderStatus>
      > = {};
      for (const [providerMode, status] of entries) {
        if (status !== undefined) next[providerMode] = status;
      }
      setStructuredProviderStatuses(next);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const residentRuntime = isNative();
    const rescueRuntime = isRescueRuntime();
    if (!residentRuntime && !rescueRuntime) return;
    let cancelled = false;
    async function readStatus() {
      const attempts = rescueRuntime ? RESCUE_OPENAI_STATUS_ATTEMPTS : 1;
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        try {
          const next = residentRuntime
            ? await getResidentOpenAiStatus()
            : await getRescueOpenAiStatus();
          if (!cancelled) setOpenAiStatus(next);
          return;
        } catch {
          if (attempt + 1 < attempts)
            await new Promise((resolve) =>
              globalThis.setTimeout(resolve, RESCUE_OPENAI_STATUS_RETRY_MS),
            );
        }
      }
      if (!cancelled) setOpenAiStatus(undefined);
    }
    void readStatus().finally(() => {
      if (!cancelled) setOpenAiStatusReady(true);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isRescueRuntime()) return;
    let cancelled = false;
    const operationEpoch = ++rescueContextEpoch.current;
    setRescueTargetBusy(true);
    scanRescueInstalledTargets()
      .then((scan) => {
        if (cancelled || rescueContextEpoch.current !== operationEpoch) return;
        setRescueTargetScan(scan);
        setSelectedRescueTarget(undefined);
        setRescueInspection(undefined);
        setRescueInspectionError(undefined);
        setRescueTargetError(undefined);
        if (scan.candidates.length === 0)
          setStatus(
            "Nessun candidato installato selezionabile: storage montato, cifrato o complesso richiede una procedura dedicata.",
          );
      })
      .catch((error) => {
        if (cancelled || rescueContextEpoch.current !== operationEpoch) return;
        const message = `Scansione target non disponibile: ${String(error)}`;
        setRescueTargetScan(undefined);
        setSelectedRescueTarget(undefined);
        setRescueInspection(undefined);
        setRescueInspectionError(undefined);
        setRescueTargetError(message);
        setStatus(message);
      })
      .finally(() => {
        if (!cancelled && rescueContextEpoch.current === operationEpoch) {
          setRescueTargetReady(true);
          setRescueTargetBusy(false);
        }
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

  useEffect(() => {
    let cancelled = false;
    setMarkdownReport(undefined);
    setMarkdownReportError(false);
    if (report === undefined || sessionId === undefined) return;
    createUnsignedMarkdownReport(report, sessionId)
      .then((next) => {
        if (!cancelled) setMarkdownReport(next);
      })
      .catch(() => {
        if (!cancelled) setMarkdownReportError(true);
      });
    return () => {
      cancelled = true;
    };
  }, [report, sessionId]);

  function invalidateSession() {
    if (isRescueRuntime())
      rescueProviderBinding.current.clearSessionAndPreparation();
    setEvidence([]);
    setFilesystemHealth(undefined);
    clearRescueOpenAiPreview();
    setProposal(undefined);
    setPlan(undefined);
    setReport(undefined);
    setMarkdownReport(undefined);
    setMarkdownReportError(false);
    setSessionId(undefined);
    setTargetFingerprint(undefined);
    setSessionDriver(undefined);
    setSessionRescueTarget(undefined);
    setWorkflow("Observe");
  }

  function clearRescueOpenAiPreview() {
    rescueOpenAiPreviewEpoch.current += 1;
    setRescueOpenAiContextPreview(undefined);
    setRescueOpenAiAcceptedContextSha256(undefined);
    setRescueOpenAiPreviewError(undefined);
    setRescueOpenAiPreviewBusy(false);
  }

  function changeObjective(value: string) {
    setObjective(value);
    clearRescueOpenAiPreview();
  }

  function acceptRescueOpenAiContext(contextSha256: string) {
    if (rescueOpenAiContextPreview?.contextSha256 !== contextSha256) return;
    setRescueOpenAiAcceptedContextSha256(contextSha256);
  }

  async function previewRescueOpenAiContext() {
    if (
      providerMode !== "openai" ||
      !objective.trim() ||
      sessionId === undefined ||
      sessionDriver === undefined ||
      evidence.length < 1 ||
      evidence.length > 3 ||
      rescueOpenAiPreviewBusy ||
      busy ||
      !rescueProviderBinding.current.sessionMatches("openai")
    )
      return;
    const epoch = rescueOpenAiPreviewEpoch.current + 1;
    rescueOpenAiPreviewEpoch.current = epoch;
    const activeDriver = sessionDriver;
    const activeSessionId = sessionId;
    const activeObjective = objective;
    setRescueOpenAiPreviewBusy(true);
    setRescueOpenAiAcceptedContextSha256(undefined);
    setRescueOpenAiPreviewError(undefined);
    try {
      const preview = await activeDriver.previewProviderContext(
        activeSessionId,
        activeObjective,
      );
      if (rescueOpenAiPreviewEpoch.current !== epoch) return;
      setRescueOpenAiContextPreview(parseRescueOpenAiContextPreview(preview));
    } catch {
      if (rescueOpenAiPreviewEpoch.current !== epoch) return;
      setRescueOpenAiContextPreview(undefined);
      setRescueOpenAiAcceptedContextSha256(undefined);
      setRescueOpenAiPreviewError(
        "Anteprima non disponibile: riprova senza inserire dati personali.",
      );
    } finally {
      if (rescueOpenAiPreviewEpoch.current === epoch)
        setRescueOpenAiPreviewBusy(false);
    }
  }

  function invalidateRescuePreparedState() {
    setRescueInspection(undefined);
    setRescueInspectionError(undefined);
    invalidateSession();
  }

  async function diagnosePreparedRescue() {
    if (
      !objective.trim() ||
      busy ||
      rescueInspectionInFlight.current ||
      rescueTargetScan === undefined ||
      selectedRescueTarget === undefined ||
      !sameRescueInspection(selectedRescueTarget, rescueInspection) ||
      sessionId === undefined ||
      sessionDriver === undefined ||
      (providerMode === "openai" &&
        (rescueOpenAiContextPreview === undefined ||
          rescueOpenAiAcceptedContextSha256 !==
            rescueOpenAiContextPreview.contextSha256)) ||
      !rescueProviderBinding.current.sessionMatches(
        rescueProviderMode(providerMode),
      )
    )
      return;
    const operationEpoch = rescueContextEpoch.current;
    const activeDriver = sessionDriver;
    const activeSessionId = sessionId;
    setBusy(true);
    try {
      setWorkflow("Observe");
      setStatus("Rivalidazione metadata-only del target ispezionato…");
      const revalidated = await selectRescueInstalledTarget(
        rescueTargetScan.scanFingerprint,
        selectedRescueTarget.target,
      );
      if (
        rescueContextEpoch.current !== operationEpoch ||
        !sameRescueSelection(selectedRescueTarget, revalidated)
      )
        throw new Error(
          "Il target Rescue è cambiato: ripetere scansione e ispezione.",
        );
      if (
        !rescueProviderBinding.current.sessionMatches(
          rescueProviderMode(providerMode),
        )
      )
        throw new Error(
          "Il provider Rescue è cambiato: ripetere l’ispezione del target.",
        );
      setSelectedRescueTarget(revalidated);
      setWorkflow("Diagnose");
      let diagnosis: DiagnosisProposal | undefined;
      for await (const event of activeDriver.sendUserPrompt(
        activeSessionId,
        objective,
      )) {
        setStatus(event.message);
        if (event.proposal) diagnosis = event.proposal;
      }
      if (!diagnosis)
        throw new Error("Il provider non ha restituito una diagnosi valida.");
      setProposal(diagnosis);
      const staged = await activeDriver.stagePlan(activeSessionId, diagnosis);
      setPlan(staged);
      setWorkflow("Plan");
      setReport(await activeDriver.exportReport(activeSessionId, "json"));
      setStatus("Diagnosi completata. Nessuna modifica eseguita.");
    } catch (error) {
      rescueContextEpoch.current += 1;
      setRescueTargetScan(undefined);
      setSelectedRescueTarget(undefined);
      invalidateRescuePreparedState();
      const message =
        error instanceof Error
          ? error.message
          : "Diagnosi Rescue non riuscita.";
      setRescueTargetError(message);
      setStatus(message);
    } finally {
      setBusy(false);
    }
  }

  async function diagnose() {
    if (isRescueRuntime()) {
      await diagnosePreparedRescue();
      return;
    }
    if (!objective.trim() || busy || !driver) return;
    let activeDriver = driver;
    setBusy(true);
    invalidateSession();
    try {
      setWorkflow("Observe");
      setStatus("Raccolta evidenze in sola lettura…");
      let currentNativeEvidence: NativeObservation[] = [];
      let currentLinuxSnapshot:
        Awaited<ReturnType<typeof collectLinuxNormalizedSnapshot>> | undefined;
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
      if (
        isNative() &&
        currentNativeEvidence.some(
          (item) => item.collector === "linux.block.inventory",
        )
      ) {
        currentLinuxSnapshot = await collectLinuxNormalizedSnapshot();
        const filesystemObservation = await collectLinuxFilesystemHealth();
        currentNativeEvidence.push(filesystemObservation);
        setFilesystemHealth(
          parseLinuxFilesystemHealth(filesystemObservation.output),
        );
      }
      if (currentLinuxSnapshot !== undefined) {
        activeDriver = createDriver(
          runtimeStatus !== undefined && secureAuditReady(runtimeStatus)
            ? new NativeAuditSink()
            : undefined,
          undefined,
          providerMode,
          "linux-p0-v1",
        );
      }
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
      const targetFingerprint = currentNativeEvidence.length
        ? await fingerprintNativeTarget(currentNativeEvidence)
        : `sha256:${"0".repeat(64)}`;
      setTargetFingerprint(targetFingerprint);
      const session = await activeDriver.startSession({
        mode: isNative() ? "resident" : "rescue",
        targetFingerprint,
      });
      setSessionDriver(activeDriver);
      setSessionRescueTarget(undefined);
      setSessionId(session.id);
      const observed: Evidence[] = [];
      if (currentNativeEvidence.length) {
        for (const item of currentNativeEvidence)
          observed.push(
            ...(await activeDriver.requestEvidence(session.id, {
              collector: item.collector,
              target: "local-machine",
              summary: nativeObservationSummary(item),
              observedContent: item.output,
              contentType: nativeObservationContentType(item),
            })),
          );
        if (currentLinuxSnapshot !== undefined)
          observed.push(
            ...(await activeDriver.requestEvidence(session.id, {
              collector: LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
              target: "local-machine",
              summary:
                linuxNormalizedSnapshotEvidenceSummary(currentLinuxSnapshot),
              observedContent: JSON.stringify(currentLinuxSnapshot),
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
      invalidateSession();
      await refreshSecureRuntimeAfterFailure();
      setStatus(error instanceof Error ? error.message : "Errore inatteso");
    } finally {
      setBusy(false);
    }
  }

  async function refreshRescueTargets() {
    if (
      !isRescueRuntime() ||
      rescueTargetBusy ||
      rescueInspectionBusy ||
      rescueInspectionInFlight.current ||
      rescueInspectionBlocked ||
      busy
    )
      return;
    const operationEpoch = ++rescueContextEpoch.current;
    setRescueTargetBusy(true);
    setRescueTargetReady(false);
    setRescueTargetScan(undefined);
    setSelectedRescueTarget(undefined);
    invalidateRescuePreparedState();
    setStatus("Nuova scansione metadata-only dei target…");
    try {
      const scan = await scanRescueInstalledTargets();
      if (rescueContextEpoch.current !== operationEpoch) return;
      setRescueTargetScan(scan);
      setRescueTargetError(undefined);
      setStatus(
        scan.candidates.length
          ? "Seleziona il candidato del sistema da osservare."
          : "Nessun candidato installato selezionabile in modo sicuro.",
      );
    } catch (error) {
      if (rescueContextEpoch.current !== operationEpoch) return;
      const message = `Scansione target non disponibile: ${String(error)}`;
      setRescueTargetScan(undefined);
      setSelectedRescueTarget(undefined);
      invalidateRescuePreparedState();
      setRescueTargetError(message);
      setStatus(message);
    } finally {
      if (rescueContextEpoch.current === operationEpoch) {
        setRescueTargetReady(true);
        setRescueTargetBusy(false);
      }
    }
  }

  async function chooseRescueTarget(candidate: RescueTargetCandidate) {
    if (
      !isRescueRuntime() ||
      rescueTargetScan === undefined ||
      rescueTargetBusy ||
      rescueInspectionBusy ||
      rescueInspectionInFlight.current ||
      rescueInspectionBlocked ||
      busy
    )
      return;
    const operationEpoch = ++rescueContextEpoch.current;
    setRescueTargetBusy(true);
    setSelectedRescueTarget(undefined);
    invalidateRescuePreparedState();
    setStatus("Rivalidazione del candidato target…");
    try {
      const selected = await selectRescueInstalledTarget(
        rescueTargetScan.scanFingerprint,
        candidate,
      );
      if (rescueContextEpoch.current !== operationEpoch) return;
      setSelectedRescueTarget(selected);
      setRescueTargetError(undefined);
      setStatus(
        "Target selezionato in modalità metadata-only. Il contenuto del filesystem non è ancora stato ispezionato.",
      );
    } catch (error) {
      if (rescueContextEpoch.current !== operationEpoch) return;
      const message = `Target non più valido: ${String(error)}`;
      setRescueTargetScan(undefined);
      setSelectedRescueTarget(undefined);
      invalidateRescuePreparedState();
      setRescueTargetError(message);
      setStatus(message);
    } finally {
      if (rescueContextEpoch.current === operationEpoch)
        setRescueTargetBusy(false);
    }
  }

  async function inspectSelectedRescueTarget() {
    if (
      !isRescueRuntime() ||
      rescueTargetScan === undefined ||
      selectedRescueTarget === undefined ||
      rescueTargetBusy ||
      rescueInspectionBusy ||
      rescueInspectionBlocked ||
      busy ||
      !driver
    )
      return;
    if (!tryStartRescueInspection(rescueInspectionInFlight)) return;
    const operationEpoch = ++rescueContextEpoch.current;
    const expectedScan = rescueTargetScan;
    const expectedSelection = selectedRescueTarget;
    setRescueInspectionBusy(true);
    setRescueTargetError(undefined);
    invalidateRescuePreparedState();
    setStatus("Ispezione del target in sola lettura, senza replay…");
    let providerPreparation: RescueProviderPreparation | undefined;
    try {
      providerPreparation = rescueProviderBinding.current.beginPreparation();
      if (providerPreparation === undefined)
        throw new Error(
          "Binding del provider Rescue non disponibile: ripetere l’ispezione.",
        );
      const selected = await selectRescueInstalledTarget(
        expectedScan.scanFingerprint,
        expectedSelection.target,
      );
      if (
        rescueContextEpoch.current !== operationEpoch ||
        !rescueProviderBinding.current.preparationIsCurrent(
          providerPreparation,
        ) ||
        !sameRescueSelection(expectedSelection, selected)
      )
        throw new Error("Il target è cambiato durante la rivalidazione.");
      const currentRuntimeInventory = await collectLocalInventory();
      if (
        rescueContextEpoch.current !== operationEpoch ||
        !rescueProviderBinding.current.preparationIsCurrent(providerPreparation)
      )
        throw new Error("Il provider Rescue è cambiato durante l’ispezione.");
      const identity = currentRuntimeInventory.filter((item) =>
        isNativeIdentityCollector(item.collector),
      );
      if (
        identity.length === 0 ||
        identity.some((item) => !item.success || item.truncated)
      )
        throw new Error(
          "Identità del runtime Rescue incompleta: ispezione annullata.",
        );
      const inspection = await inspectRescueInstalledTarget(selected);
      if (
        !rescueInspectionResponseCurrent(
          operationEpoch,
          rescueContextEpoch.current,
          selected,
          inspection,
        )
      )
        throw new Error(
          "La risposta di ispezione appartiene a un altro target.",
        );
      const binding = rescueTargetBinding(selected);
      const fingerprint = await fingerprintNativeTarget(
        currentRuntimeInventory,
        binding,
      );
      if (
        rescueContextEpoch.current !== operationEpoch ||
        !rescueProviderBinding.current.preparationIsCurrent(providerPreparation)
      )
        throw new Error("Il provider Rescue è cambiato durante l’ispezione.");
      const preparedDriver = createDriver(
        rescueAuditSink,
        binding,
        providerPreparation.mode,
        inspection.os.family === "linux" ? "linux-p0-v1" : "legacy-non-linux",
      );
      const session = await preparedDriver.startSession({
        mode: "rescue",
        targetFingerprint: fingerprint,
      });
      if (
        rescueContextEpoch.current !== operationEpoch ||
        !rescueProviderBinding.current.preparationIsCurrent(providerPreparation)
      )
        throw new Error(
          "Il provider Rescue è cambiato durante la preparazione della sessione.",
        );
      const linuxSnapshot =
        inspection.os.family === "linux"
          ? await linuxNormalizedSnapshotFromRescue(inspection)
          : undefined;
      const selectedFilesystemHealth =
        await inspectRescueFilesystemHealth(selected);
      const storageObservation = currentRuntimeInventory.find(
        (item) =>
          item.collector === LINUX_STORAGE_HEALTH_COLLECTOR &&
          item.success &&
          !item.truncated,
      );
      const selectedDiskRef = expectedScan.disks.find(
        (disk) => disk.id === selected.target.diskId,
      )?.ref;
      let targetStorageHealth: LinuxStorageHealthSnapshot | undefined;
      if (storageObservation !== undefined && selectedDiskRef !== undefined) {
        targetStorageHealth = projectLinuxStorageHealth(
          parseLinuxStorageHealth(storageObservation.output),
          selectedDiskRef,
        );
      }
      const observed = await preparedDriver.requestEvidence(session.id, {
        collector:
          linuxSnapshot === undefined
            ? RESCUE_OFFLINE_EVIDENCE_COLLECTOR
            : LINUX_NORMALIZED_SNAPSHOT_COLLECTOR,
        target: RESCUE_OFFLINE_EVIDENCE_TARGET,
        summary:
          linuxSnapshot === undefined
            ? rescueOfflineEvidenceSummary(inspection)
            : linuxNormalizedSnapshotEvidenceSummary(linuxSnapshot),
        observedContent:
          linuxSnapshot === undefined
            ? rescueOfflineCorpusJson(inspection)
            : JSON.stringify(linuxSnapshot),
        contentType: "application/json",
      });
      if (targetStorageHealth !== undefined)
        observed.push(
          ...(await preparedDriver.requestEvidence(session.id, {
            collector: LINUX_STORAGE_HEALTH_COLLECTOR,
            target: RESCUE_OFFLINE_EVIDENCE_TARGET,
            summary: storageHealthEvidenceSummary(targetStorageHealth),
            observedContent: JSON.stringify(targetStorageHealth),
            contentType: "application/json",
          })),
        );
      observed.push(
        ...(await preparedDriver.requestEvidence(session.id, {
          collector: LINUX_FILESYSTEM_HEALTH_COLLECTOR,
          target: RESCUE_OFFLINE_EVIDENCE_TARGET,
          summary: filesystemHealthEvidenceSummary(selectedFilesystemHealth),
          observedContent: JSON.stringify(selectedFilesystemHealth),
          contentType: "application/json",
        })),
      );
      if (
        rescueContextEpoch.current !== operationEpoch ||
        rescueProviderBinding.current.commitPreparation(providerPreparation) !==
          providerPreparation.mode
      )
        throw new Error(
          "La sessione Rescue appartiene a un provider non più corrente.",
        );
      setNativeEvidence(currentRuntimeInventory);
      setFilesystemHealth(selectedFilesystemHealth);
      setInventoryError(undefined);
      setSelectedRescueTarget(selected);
      setRescueInspection(inspection);
      setRescueInspectionError(undefined);
      setEvidence(observed);
      setSessionId(session.id);
      setTargetFingerprint(fingerprint);
      setSessionDriver(preparedDriver);
      setSessionRescueTarget(selected);
      setWorkflow("Observe");
      setStatus(
        inspection.claims.installedOsConfirmed
          ? "Corpus del sistema installato acquisito read-only. Inserisci l'obiettivo e avvia la diagnosi."
          : "Contenuto ispezionato, ma installazione non confermata. La diagnosi resterà conservativa.",
      );
    } catch (error) {
      const disposition =
        error instanceof RescueOfflineInspectionError
          ? rescueInspectionFailureDisposition(
              operationEpoch,
              rescueContextEpoch.current,
              error,
            )
          : undefined;
      if (disposition?.requiresRestart) setRescueInspectionBlocked(true);
      if (
        disposition?.current === false ||
        (disposition === undefined &&
          rescueContextEpoch.current !== operationEpoch)
      )
        return;
      rescueContextEpoch.current += 1;
      invalidateSession();
      setRescueInspection(undefined);
      if (error instanceof RescueOfflineInspectionError) {
        setRescueInspectionError(error);
        const presentation = rescueInspectionErrorPresentation(error);
        setStatus(`${presentation.title}. ${presentation.action}`);
        if (rescueInspectionNeedsRescan(error)) {
          setRescueTargetScan(undefined);
          setSelectedRescueTarget(undefined);
        }
      } else {
        const message =
          error instanceof Error
            ? error.message
            : "Ispezione Rescue non riuscita.";
        setRescueTargetScan(undefined);
        setSelectedRescueTarget(undefined);
        setRescueTargetError(message);
        setStatus(message);
      }
    } finally {
      if (providerPreparation !== undefined)
        rescueProviderBinding.current.cancelPreparation(providerPreparation);
      finishRescueInspection(rescueInspectionInFlight);
      setRescueInspectionBusy(false);
    }
  }

  async function verify() {
    if (
      !plan ||
      !sessionId ||
      !targetFingerprint ||
      busy ||
      !sessionDriver ||
      (isRescueRuntime() && rescueInspectionInFlight.current) ||
      (isRescueRuntime() &&
        !rescueProviderBinding.current.sessionMatches(
          rescueProviderMode(providerMode),
        )) ||
      (isRescueRuntime() &&
        (!sameRescueSelection(sessionRescueTarget, selectedRescueTarget) ||
          !sameRescueInspection(selectedRescueTarget, rescueInspection)))
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
        rescueContextEpoch.current += 1;
        setRescueTargetScan(undefined);
        setSelectedRescueTarget(undefined);
        invalidateRescuePreparedState();
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
      (!isNative() && !isRescueRuntime()) ||
      (isRescueRuntime() && !isRescueProviderMode(next)) ||
      next === providerMode ||
      busy ||
      (isRescueRuntime() && rescueTargetBusy) ||
      rescueInspectionBusy ||
      (isRescueRuntime() && rescueInspectionInFlight.current) ||
      sessionId !== undefined ||
      driver === undefined ||
      !providerReady(next)
    )
      return;
    if (isRescueRuntime()) {
      if (!isRescueProviderMode(next)) return;
      const transition = transitionRescueProviderMode(
        rescueProviderBinding.current,
        next,
        rescueContextEpoch.current,
        {
          targetBusy: rescueTargetBusy,
          inspectionBusy: rescueInspectionBusy,
          inspectionInFlight: rescueInspectionInFlight.current,
        },
      );
      if (!transition.changed) return;
      rescueContextEpoch.current = transition.contextEpoch;
      invalidateRescuePreparedState();
    } else invalidateSession();
    setProviderMode(next);
    setDriver(
      createDriver(
        isNative() ? activeAuditSink(runtimeStatus) : rescueAuditSink,
        undefined,
        next,
      ),
    );
    setStatus(
      next === "offline"
        ? "Diagnostica offline selezionata. Nessun dato lascia il computer."
        : `${providerLabel(next)} selezionato. Il corpus grezzo resta locale; vengono inviati obiettivo filtrato, proposta deterministica e soli ID/collector.`,
    );
  }

  async function logoutProvider() {
    if (
      !isNative() ||
      providerLogoutInFlight.current ||
      providerMode === "offline"
    )
      return;
    const activeMode = providerMode;
    providerLogoutInFlight.current = true;
    setProviderLogoutBusy(true);
    setBusy(true);
    const hadDriver = driver !== undefined;
    try {
      if (activeMode === "openai") {
        const next = await logoutResidentOpenAi();
        setOpenAiStatus(next);
      } else {
        const next = await logoutResidentStructuredProvider(activeMode);
        setStructuredProviderStatuses((current) => ({
          ...current,
          [activeMode]: next,
        }));
      }
      setProviderMode("offline");
      invalidateSession();
      if (hadDriver)
        setDriver(
          createDriver(activeAuditSink(runtimeStatus), undefined, "offline"),
        );
      setStatus(
        `Logout ${providerLabel(activeMode)} completato e verificato. Provider offline attivo.`,
      );
    } catch (error) {
      setStatus(
        error instanceof Error
          ? error.message
          : "Logout provider non completato.",
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
  const securityLabel = isRescueRuntime()
    ? rescueVaultLabel(openAiStatus)
    : !isNative()
      ? "Runtime di sviluppo"
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
  const rescueInspectionCurrent =
    !isRescueRuntime() ||
    sameRescueInspection(selectedRescueTarget, rescueInspection);
  const rescueInspectionView =
    rescueInspection === undefined
      ? undefined
      : rescueInspectionPresentation(rescueInspection);
  const categories: InventoryCategory[] = [
    "Hardware",
    "Storage",
    "Boot",
    "Network",
  ];
  let storageHealth: LinuxStorageHealthSnapshot | undefined;
  const storageHealthObservation = nativeEvidence.find(
    (item) =>
      item.collector === LINUX_STORAGE_HEALTH_COLLECTOR &&
      item.success &&
      !item.truncated,
  );
  if (storageHealthObservation !== undefined) {
    try {
      storageHealth = parseLinuxStorageHealth(storageHealthObservation.output);
    } catch {
      storageHealth = undefined;
    }
  }
  let bootCriticalPath: LinuxBootCriticalPathSnapshot | undefined;
  const bootCriticalPathObservation = nativeEvidence.find(
    (item) =>
      item.collector === LINUX_BOOT_CRITICAL_PATH_COLLECTOR &&
      item.success &&
      !item.truncated,
  );
  if (bootCriticalPathObservation !== undefined) {
    try {
      bootCriticalPath = parseLinuxBootCriticalPath(
        bootCriticalPathObservation.output,
      );
    } catch {
      bootCriticalPath = undefined;
    }
  }

  return (
    <main>
      <header>
        <strong>KernAid</strong>
        <div className="runtime-summary">
          {isNative() && (
            <div className="provider-switch" aria-label="Provider diagnostico">
              <button
                aria-pressed={providerMode === "offline"}
                disabled={
                  busy ||
                  (isRescueRuntime() && rescueTargetBusy) ||
                  rescueInspectionBusy ||
                  (isRescueRuntime() && rescueInspectionInFlight.current) ||
                  sessionId !== undefined
                }
                onClick={() => chooseProvider("offline")}
              >
                Offline
              </button>
              <button
                aria-pressed={providerMode === "openai"}
                disabled={
                  busy ||
                  (isRescueRuntime() && rescueTargetBusy) ||
                  rescueInspectionBusy ||
                  (isRescueRuntime() && rescueInspectionInFlight.current) ||
                  sessionId !== undefined ||
                  !openAiReady
                }
                onClick={() => chooseProvider("openai")}
              >
                OpenAI
              </button>
              <button
                aria-pressed={providerMode === "anthropic_api"}
                disabled={
                  busy ||
                  sessionId !== undefined ||
                  !providerReady("anthropic_api")
                }
                onClick={() => chooseProvider("anthropic_api")}
              >
                Anthropic
              </button>
              <button
                aria-pressed={providerMode === "gemini_api"}
                disabled={
                  busy ||
                  sessionId !== undefined ||
                  !providerReady("gemini_api")
                }
                onClick={() => chooseProvider("gemini_api")}
              >
                Gemini
              </button>
              {isNative() &&
                providerMode !== "offline" &&
                providerReady(providerMode) && (
                  <button
                    disabled={providerLogoutBusy}
                    onClick={logoutProvider}
                  >
                    {providerLogoutBusy ? "Logout…" : "Logout"}
                  </button>
                )}
            </div>
          )}
          <span>
            {isNative() ? "Resident" : "Rescue"} ·{" "}
            {providerSummary(providerMode)} · {securityLabel}
          </span>
          {isNative() &&
            (openAiStatus?.credential !== "configured" ||
              structuredProviderStatuses.anthropic_api?.credential !==
                "configured" ||
              structuredProviderStatuses.gemini_api?.credential !==
                "configured") && (
              <small>
                I provider senza credenziale restano disabilitati · chiudi Desk
                e usa{" "}
                <code>kernaid-provider-key configure --provider NOME</code>
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
              ? rescueInspectionView
                ? `${rescueInspectionView.title} · read-only`
                : selectedRescueTarget
                  ? `Candidato ${targetFamilyLabel(selectedRescueTarget.target.osFamilyHint)} · metadata-only`
                  : "Target non selezionato"
              : "Linux fixture"}
        </h2>
        {isRescueRuntime() && (
          <div className="target-overview">
            <small>
              {rescueInspectionCurrent
                ? "Ispezione read-only completata"
                : selectedRescueTarget
                  ? "Metadati target selezionati"
                  : rescueTargetBusy
                    ? "Scansione target in corso"
                    : "Usa il percorso guidato al centro"}
            </small>
            <p>
              Il runtime live e il sistema installato restano due contesti
              separati.
            </p>
          </div>
        )}
        {isRescueRuntime() && (
          <div className="target-scope">
            <button disabled>
              Storage metadata · {selectedRescueTarget ? "observed" : "pending"}
            </button>
            <button disabled>
              OS content ·{" "}
              {rescueInspectionCurrent
                ? "observed"
                : rescueInspectionError
                  ? "unavailable"
                  : "pending"}
            </button>
            <button disabled>
              Boot content ·{" "}
              {rescueInspectionCurrent
                ? "observed"
                : rescueInspectionError
                  ? "unavailable"
                  : "pending"}
            </button>
            <button disabled>Target network · not inspected</button>
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
        {storageHealth !== undefined && (
          <div className="storage-health" aria-label="Storage health">
            <p className="label">SMART / NVME · READ-ONLY</p>
            {storageHealth.enumerationStatus === "unsupported" ? (
              <small>Telemetry unavailable · health not inferred</small>
            ) : (
              storageHealth.disks.map((disk) => {
                const finding = storageHealth?.findings.find(
                  (item) => item.diskRef === disk.diskRef,
                );
                return (
                  <div
                    className={`storage-health-disk ${disk.state}`}
                    key={disk.diskRef}
                  >
                    <strong>{disk.diskRef}</strong>
                    <span>{disk.state.replace("-", " ")}</span>
                    {disk.temperatureCelsius !== null && (
                      <small>{disk.temperatureCelsius} °C</small>
                    )}
                    {finding !== undefined && <p>{finding.nextAction}</p>}
                  </div>
                );
              })
            )}
          </div>
        )}
        {filesystemHealth !== undefined && (
          <div
            className={`storage-health filesystem-health ${filesystemHealth.state}`}
            aria-label="Filesystem health"
          >
            <p className="label">FILESYSTEM · FIXED READ-ONLY CHECK</p>
            <div className={`storage-health-disk ${filesystemHealth.state}`}>
              <strong>{filesystemHealth.targetRef}</strong>
              <span>
                {filesystemHealth.filesystem} · {filesystemHealth.state}
              </span>
              {filesystemHealth.finding !== null && (
                <p>{filesystemHealth.finding.nextAction}</p>
              )}
            </div>
          </div>
        )}
        {bootCriticalPath !== undefined && (
          <div
            className={`storage-health boot-health ${bootCriticalPath.state}`}
            aria-label="Boot critical path"
          >
            <p className="label">BOOT PATH · FIXED READ-ONLY CHECK</p>
            <div className={`storage-health-disk ${bootCriticalPath.state}`}>
              <strong>{bootCriticalPath.state.replace("-", " ")}</strong>
              <span>
                {bootCriticalPath.runtime.failedUnitCount} failed units ·{" "}
                {bootCriticalPath.runtime.slowestActivationMillis === null
                  ? "chain unavailable"
                  : `${bootCriticalPath.runtime.slowestActivationMillis} ms slowest`}
              </span>
              {bootCriticalPath.findings[0] !== undefined && (
                <p>{bootCriticalPath.findings[0].nextAction}</p>
              )}
            </div>
          </div>
        )}
        {nativeEvidence
          .filter(
            (item) =>
              item.collector !== LINUX_STORAGE_HEALTH_COLLECTOR &&
              item.collector !== LINUX_FILESYSTEM_HEALTH_COLLECTOR &&
              item.collector !== LINUX_BOOT_CRITICAL_PATH_COLLECTOR,
          )
          .map((item) => (
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
        {isRescueRuntime() ? (
          <RescueDiagnosisWizard
            vaultStatusReady={openAiStatusReady}
            vaultUnlockEligible={
              openAiStatus?.profile === "rescue-default" &&
              openAiStatus.vault === "locked"
            }
            vaultLabel={rescueVaultLabel(openAiStatus)}
            vaultGuidance={rescueOpenAiGuidance(openAiStatus)}
            persistentAuditReady={rescueAuditSink !== undefined}
            targetScan={rescueTargetScan}
            selectedTarget={selectedRescueTarget}
            targetReady={rescueTargetReady}
            targetBusy={rescueTargetBusy}
            targetError={rescueTargetError}
            inspection={rescueInspection}
            inspectionError={rescueInspectionError}
            inspectionCurrent={rescueInspectionCurrent}
            inspectionBusy={rescueInspectionBusy}
            inspectionBlocked={rescueInspectionBlocked}
            providerMode={rescueProviderMode(providerMode)}
            openAiReady={openAiReady}
            providerSelectionDisabled={
              busy ||
              rescueTargetBusy ||
              rescueInspectionBusy ||
              rescueInspectionInFlight.current ||
              sessionId !== undefined ||
              driver === undefined
            }
            inspectDisabled={
              selectedRescueTarget === undefined ||
              rescueTargetScan === undefined ||
              rescueTargetBusy ||
              rescueInspectionBusy ||
              rescueInspectionBlocked ||
              busy ||
              driver === undefined
            }
            objective={objective}
            evidence={evidence}
            openAiContextPreview={rescueOpenAiContextPreview}
            openAiAcceptedContextSha256={rescueOpenAiAcceptedContextSha256}
            openAiPreviewBusy={rescueOpenAiPreviewBusy}
            openAiPreviewError={rescueOpenAiPreviewError}
            proposal={proposal}
            status={status}
            busy={busy}
            diagnosisDisabled={
              !objective.trim() ||
              busy ||
              rescueInspectionBusy ||
              !inventoryReady ||
              !rescueTargetReady ||
              selectedRescueTarget === undefined ||
              !rescueInspectionCurrent ||
              sessionId === undefined ||
              sessionDriver === undefined ||
              !rescueProviderBinding.current.sessionMatches(
                rescueProviderMode(providerMode),
              ) ||
              rescueInspectionBlocked ||
              !runtimeReady ||
              !driver ||
              securityBlocked
            }
            diagnosisButtonLabel={
              !inventoryReady || !runtimeReady || !rescueTargetReady
                ? "Avvio sicuro…"
                : inventoryError
                  ? "Riprova inventario"
                  : "Avvia diagnosi"
            }
            report={report}
            sessionId={sessionId}
            markdownReport={markdownReport}
            markdownReportError={markdownReportError}
            onRefreshTargets={refreshRescueTargets}
            onSelectTarget={chooseRescueTarget}
            onChooseProvider={chooseProvider}
            onInspectTarget={inspectSelectedRescueTarget}
            onObjectiveChange={changeObjective}
            onPreviewOpenAiContext={previewRescueOpenAiContext}
            onAcceptOpenAiContext={acceptRescueOpenAiContext}
            onDiagnose={diagnose}
          />
        ) : (
          <>
            <div className="steps">
              {(
                ["Observe", "Diagnose", "Plan", "Repair", "Verify"] as const
              ).map((step) => (
                <span className={step === workflow ? "active" : ""} key={step}>
                  {step}
                </span>
              ))}
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
                  Confidenza: {Math.round(proposal.confidence * 100)}% ·
                  Evidenze: {proposal.evidenceIds.join(", ")}
                </p>
              )}
            </article>
          </>
        )}
        {isRescueRuntime() && (
          <RescueRepairPanel
            selection={selectedRescueTarget}
            targetFingerprint={targetFingerprint}
            inspection={rescueInspectionCurrent ? rescueInspection : undefined}
          />
        )}
        {isNative() && <FixtureRepairLabPanel />}
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
        {!isRescueRuntime() && providerMode !== "offline" && (
          <p className="provider-context-notice" role="note">
            A {providerLabel(providerMode)} invieremo l’obiettivo dopo filtri
            conservativi per token, email, IP e percorsi comuni, più la proposta
            diagnostica locale e soli ID/collector. Il corpus grezzo resta sul
            PC. Il testo libero può comunque contenere nomi o altri dati
            personali: non inserirli; questa versione non offre ancora
            un’anteprima del contesto.
          </p>
        )}
        {!isRescueRuntime() && (
          <>
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
                rescueInspectionBusy ||
                !inventoryReady ||
                !rescueTargetReady ||
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
                  : inventoryError
                    ? "Riprova inventario"
                    : "Diagnostica"}
            </button>
          </>
        )}
        {plan &&
          workflow !== "Verify" &&
          rescueSessionCurrent &&
          rescueInspectionCurrent && (
            <button
              disabled={busy || !sessionDriver || securityBlocked}
              onClick={verify}
            >
              Verifica piano R0
            </button>
          )}
        {!isRescueRuntime() && report && sessionId && (
          <div className="report">
            <p>
              {isRescueRuntime()
                ? report.auditStatus.signed
                  ? "Il JSON firmato è persistito anche nel Vault Rescue."
                  : "Report temporaneo: sblocca il Vault e ripeti la diagnosi. JSON e Markdown non sono firmati."
                : report.auditStatus.signed
                  ? "Il JSON è il bundle firmato autorevole."
                  : "Audit sicuro non disponibile: JSON e Markdown non sono firmati."}
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
  evidenceProfile: "legacy-non-linux" | "linux-p0-v1" = "legacy-non-linux",
): LocalSessionDriver {
  let provider;
  switch (providerMode) {
    case "offline":
      provider = new PlatformOfflineRulesProvider();
      break;
    case "openai":
      provider = isNative()
        ? new NativeOpenAiProvider()
        : isRescueRuntime()
          ? new RescueOpenAiProvider()
          : undefined;
      break;
    case "anthropic_api":
    case "gemini_api":
      provider = isNative()
        ? new NativeResidentStructuredProvider(providerMode)
        : undefined;
      break;
  }
  if (provider === undefined)
    throw new Error("Il provider selezionato non è disponibile nel runtime.");
  return new LocalSessionDriver(
    provider,
    hasLocalCollector()
      ? {
          execute: (request) => authorizeObserve(request, rescueTarget),
        }
      : undefined,
    auditSink,
    evidenceProfile,
  );
}

function isRescueProviderMode(mode: ProviderMode): mode is RescueProviderMode {
  return mode === "offline" || mode === "openai";
}

function rescueProviderMode(mode: ProviderMode): RescueProviderMode {
  return isRescueProviderMode(mode) ? mode : "offline";
}

function providerLabel(mode: Exclude<ProviderMode, "offline">): string {
  switch (mode) {
    case "openai":
      return "OpenAI";
    case "anthropic_api":
      return "Anthropic";
    case "gemini_api":
      return "Gemini";
  }
}

function providerSummary(mode: ProviderMode): string {
  switch (mode) {
    case "offline":
      return "Offline rules";
    case "openai":
      return "OpenAI · gpt-5.6-sol";
    case "anthropic_api":
      return "Anthropic · Claude Sonnet 5";
    case "gemini_api":
      return "Gemini · 3.1 Pro";
  }
}

function rescueVaultLabel(
  status: ResidentOpenAiStatus | RescueOpenAiStatus | undefined,
): string {
  if (status?.profile !== "rescue-default")
    return "Stato Vault non disponibile";
  switch (status.vault) {
    case "absent":
      return "Vault assente";
    case "unprovisioned":
      return "Vault non inizializzato";
    case "locked":
      return "Vault bloccato";
    case "unlocking":
      return "Vault in sblocco";
    case "unlocked":
      return status.credential === "configured"
        ? "Vault sbloccato · OpenAI configurato"
        : status.credential === "absent"
          ? "Vault sbloccato · OpenAI non configurato"
          : "Vault sbloccato · credenziale non disponibile";
    case "locking":
      return "Vault in blocco";
    case "faulted-reboot-required":
      return "Vault in fault · riavvio richiesto";
  }
}

function rescueOpenAiGuidance(
  status: ResidentOpenAiStatus | RescueOpenAiStatus | undefined,
): string {
  if (status?.profile !== "rescue-default")
    return "OpenAI Rescue non disponibile. Verifica dal TTY con “kernaid-rescue-vaultctl status”, poi ricarica Desk.";
  switch (status.vault) {
    case "absent":
      return "Vault persistente non rilevato. Desk e companion non creano il Vault: prepara un supporto compatibile e riavvia Rescue.";
    case "unprovisioned":
      return "Vault persistente non inizializzato. Desk e companion non lo inizializzano: prepara il supporto con la procedura qualificata e riavvia Rescue.";
    case "locked":
      return "Vault bloccato. Nel TTY esegui “kernaid-rescue-vaultctl unlock”; quindi “kernaid-rescue-vaultctl openai-configure” e ricarica Desk.";
    case "unlocking":
    case "locking":
      return "Transizione del Vault in corso. Attendi il completamento, verifica dal TTY con “kernaid-rescue-vaultctl status” e ricarica Desk.";
    case "faulted-reboot-required":
      return "Il Vault richiede un riavvio Rescue; OpenAI resta disabilitato.";
    case "unlocked":
      return status.credential === "configured"
        ? "Vault sbloccato: audit persistente e OpenAI sono disponibili."
        : status.credential === "absent"
          ? "Vault sbloccato. Configura OpenAI esclusivamente dal TTY con “kernaid-rescue-vaultctl openai-configure”, poi ricarica Desk."
          : "Credenziale non disponibile. Verifica dal TTY con “kernaid-rescue-vaultctl provider-status”, poi ricarica Desk.";
  }
}

function activeAuditSink(
  status: SecureRuntimeStatus | undefined,
): AuditSink | undefined {
  return status !== undefined && secureAuditReady(status)
    ? new NativeAuditSink()
    : undefined;
}

createRoot(document.getElementById("root")!).render(<App />);
