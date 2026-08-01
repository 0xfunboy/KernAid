import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { LocalSessionDriver } from "@kernaid/agent-gateway";
import type { ArtifactRef } from "@kernaid/session-driver";
import type { DiagnosisProposal, Evidence, ValidatedPlan } from "@kernaid/schemas";
import { collectLocalInventory, hasLocalCollector, isNative, type NativeObservation } from "./native";
import "./style.css";

type Workflow = "Observe" | "Diagnose" | "Plan" | "Verify";

function App() {
  const driver = useMemo(() => new LocalSessionDriver(), []);
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
  const [sessionId, setSessionId] = useState<string>();

  useEffect(() => {
    if (!hasLocalCollector()) return;
    collectLocalInventory()
      .then(items => setNativeEvidence(items))
      .catch(error => setStatus(`Inventario locale non disponibile: ${String(error)}`))
      .finally(() => setInventoryReady(true));
  }, []);

  async function fingerprint(items: NativeObservation[]): Promise<string> {
    const canonical = items.map(item => `${item.collector}\0${item.output}`).join("\0");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return `sha256:${Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("")}`;
  }

  async function diagnose() {
    if (!objective.trim() || busy) return;
    setBusy(true); setProposal(undefined); setPlan(undefined); setReport(undefined);
    try {
      setWorkflow("Observe"); setStatus("Raccolta evidenze in sola lettura…");
      const targetFingerprint = nativeEvidence.length ? await fingerprint(nativeEvidence) : `sha256:${"0".repeat(64)}`;
      const session = await driver.startSession({ mode: isNative() ? "resident" : "rescue", targetFingerprint });
      setSessionId(session.id);
      const observed: Evidence[] = [];
      if (nativeEvidence.length) {
        for (const item of nativeEvidence) observed.push(...await driver.requestEvidence(session.id, {
          collector: item.collector,
          target: "local-machine",
          summary: item.success ? "Comando di inventario completato" : "Comando di inventario non disponibile",
          observedContent: item.output,
          contentType: "text/plain"
        }));
      } else {
        observed.push(...await driver.requestEvidence(session.id, { collector: "linux.fixture.inventory", target: "fixture:linux-root" }));
      }
      setEvidence(observed); setWorkflow("Diagnose");
      let diagnosis: DiagnosisProposal | undefined;
      for await (const event of driver.sendUserPrompt(session.id, objective)) { setStatus(event.message); if (event.proposal) diagnosis = event.proposal; }
      if (!diagnosis) throw new Error("Il provider non ha restituito una diagnosi valida.");
      setProposal(diagnosis);
      const staged = await driver.stagePlan(session.id, diagnosis);
      setPlan(staged); setWorkflow("Plan");
      const artifact = await driver.exportReport(session.id, "json");
      setReport(artifact); setStatus("Diagnosi completata. Nessuna modifica eseguita.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Errore inatteso"); }
    finally { setBusy(false); }
  }

  async function verify() {
    if (!plan || !sessionId || busy) return;
    setBusy(true); setWorkflow("Verify"); setStatus("Verifica del piano e delle evidenze…");
    try {
      for await (const event of driver.executePlan(plan.planId)) setStatus(event.message);
      setReport(await driver.exportReport(sessionId, "json"));
    } catch (error) { setStatus(error instanceof Error ? error.message : "Verifica non riuscita"); }
    finally { setBusy(false); }
  }

  return <main>
    <header><strong>KernAid</strong><span>{isNative() ? "Resident" : "Rescue"} · Offline rules · Vault locked</span></header>
    <aside><p className="label">TARGET MACHINE</p><h2>{hasLocalCollector() ? "Local machine" : "Linux fixture"}</h2>{["Hardware", "Storage", "Boot", "Network"].map((item, index) => <button key={item}>{item} · {index < nativeEvidence.length || index < evidence.length ? "observed" : "pending"}</button>)}{nativeEvidence.map(item => <details key={item.collector}><summary>{item.collector}</summary><pre>{item.output || "Nessun output"}</pre></details>)}</aside>
    <section><div className="steps">{(["Observe", "Diagnose", "Plan", "Repair", "Verify"] as const).map(step => <span className={step === workflow ? "active" : ""} key={step}>{step}</span>)}</div>
      <article><small>{evidence.length ? `${evidence[0].id} · observed-untrusted` : "SESSION NOT STARTED"}</small><h1>{proposal?.diagnosis ?? "Evidence before action."}</h1><p>{status}</p>{proposal && <p>Confidenza: {Math.round(proposal.confidence * 100)}% · Evidenze: {proposal.evidenceIds.join(", ")}</p>}</article>
      <textarea aria-label="Problem description" value={objective} onChange={event => setObjective(event.target.value)} placeholder="Descrivi il problema del computer…" />
      <button className="primary" disabled={!objective.trim() || busy || !inventoryReady} onClick={diagnose}>{!inventoryReady ? "Inventario…" : busy ? "Analisi…" : "Diagnostica"}</button>{plan && workflow !== "Verify" && <button disabled={busy} onClick={verify}>Verifica piano R0</button>}{report && <p className="report"><a href={report.uri} download="KernAid-report.json">Scarica report JSON</a> · SHA-256 <code>{report.sha256.slice(0, 12)}…</code></p>}</section>
    <aside className="right"><p className="label">STAGED PLAN</p><h2>{plan ? plan.diagnosis : "Nessuna modifica prevista"}</h2><p>Rischio {plan?.risk ?? "R0"} · {plan?.steps.length ?? 0} azioni</p><hr />{plan?.steps.map(step => <div className="plan" key={step.action}><b>{step.action}</b><small>Validazione: {step.validation}</small></div>)}<p>Le riparazioni reali richiedono backup, risorse esplicite e approvazione locale.</p></aside>
    <footer>{evidence.length + nativeEvidence.length} evidenze · Terminale disabilitato · Audit locale</footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(<App />);
