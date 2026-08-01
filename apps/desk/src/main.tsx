import React, { useEffect, useState } from "react";
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
  getSecureRuntimeStatus,
  hasLocalCollector,
  initializeDeviceIdentity,
  isNative,
  NativeAuditSink,
  PlatformOfflineRulesProvider,
  secureAuditReady,
  type NativeObservation,
  type SecureRuntimeStatus,
} from "./native";
import "./style.css";

type Workflow = "Observe" | "Diagnose" | "Plan" | "Verify";

function App() {
  const [driver, setDriver] = useState<LocalSessionDriver>();
  const [runtimeStatus, setRuntimeStatus] = useState<SecureRuntimeStatus>();
  const [runtimeReady, setRuntimeReady] = useState(false);
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

  async function fingerprint(items: NativeObservation[]): Promise<string> {
    const identity = items.filter((item) =>
      /hostname|block\.inventory|\.disks$|\.system$|\.storage\.identity$/.test(
        item.collector,
      ),
    );
    const canonical = identity
      .map((item) => `${item.collector}\0${item.output}`)
      .join("\0");
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical),
    );
    return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }

  async function diagnose() {
    if (!objective.trim() || busy || !driver) return;
    const activeDriver = driver;
    setBusy(true);
    setProposal(undefined);
    setPlan(undefined);
    setReport(undefined);
    try {
      setWorkflow("Observe");
      setStatus("Raccolta evidenze in sola lettura…");
      let currentNativeEvidence: NativeObservation[] = [];
      if (hasLocalCollector()) {
        try {
          currentNativeEvidence = await collectLocalInventory();
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
        /hostname|block\.inventory|\.disks$|\.system$|\.storage\.identity$/.test(
          item.collector,
        ),
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
        ? await fingerprint(currentNativeEvidence)
        : `sha256:${"0".repeat(64)}`;
      setTargetFingerprint(targetFingerprint);
      const session = await activeDriver.startSession({
        mode: isNative() ? "resident" : "rescue",
        targetFingerprint,
      });
      setSessionId(session.id);
      const observed: Evidence[] = [];
      if (currentNativeEvidence.length) {
        for (const item of currentNativeEvidence)
          observed.push(
            ...(await activeDriver.requestEvidence(session.id, {
              collector: item.collector,
              target: isNative() ? "local-machine" : "rescue-runtime",
              summary: item.success
                ? "Comando di inventario completato"
                : "Comando di inventario non disponibile",
              observedContent: item.output,
              contentType: "text/plain",
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
      await refreshSecureRuntimeAfterFailure();
      setStatus(error instanceof Error ? error.message : "Errore inatteso");
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    if (!plan || !sessionId || !targetFingerprint || busy || !driver) return;
    const activeDriver = driver;
    setBusy(true);
    setWorkflow("Verify");
    setStatus("Verifica del piano e delle evidenze…");
    try {
      for await (const event of activeDriver.executePlan(plan.planId))
        setStatus(event.message);
      setReport(await activeDriver.exportReport(sessionId, "json"));
    } catch (error) {
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
      setDriver(createDriver(new NativeAuditSink()));
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

  async function refreshSecureRuntimeAfterFailure() {
    if (!isNative()) return;
    try {
      const next = await getSecureRuntimeStatus();
      setRuntimeStatus(next);
      if (!secureAuditReady(next)) {
        setDriver(undefined);
        setReport(undefined);
      }
    } catch {
      setDriver(undefined);
      setReport(undefined);
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

  return (
    <main>
      <header>
        <strong>KernAid</strong>
        <span>
          {isNative() ? "Resident" : "Rescue"} · Offline rules · {securityLabel}
        </span>
      </header>
      <aside>
        <p className="label">TARGET MACHINE</p>
        <h2>
          {isNative()
            ? "Local machine"
            : hasLocalCollector()
              ? "Ambiente Rescue · target non selezionato"
              : "Linux fixture"}
        </h2>
        {["Hardware", "Storage", "Boot", "Network"].map((item, index) => (
          <button key={item}>
            {item} ·{" "}
            {index < nativeEvidence.length || index < evidence.length
              ? "observed"
              : "pending"}
          </button>
        ))}
        {nativeEvidence.map((item) => (
          <details key={item.collector}>
            <summary>{item.collector}</summary>
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
            !runtimeReady ||
            !driver ||
            securityBlocked
          }
          onClick={diagnose}
        >
          {!inventoryReady || !runtimeReady
            ? "Avvio sicuro…"
            : busy
              ? "Analisi…"
              : inventoryError
                ? "Riprova inventario"
                : "Diagnostica"}
        </button>
        {plan && workflow !== "Verify" && (
          <button
            disabled={busy || !driver || securityBlocked}
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

function createDriver(auditSink?: AuditSink): LocalSessionDriver {
  return new LocalSessionDriver(
    new PlatformOfflineRulesProvider(),
    hasLocalCollector() ? { execute: authorizeObserve } : undefined,
    auditSink,
  );
}

createRoot(document.getElementById("root")!).render(<App />);
