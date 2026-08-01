import React, { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { FakeSessionDriver } from "@kernaid/agent-gateway";
import type { DiagnosisProposal, Evidence, ValidatedPlan } from "@kernaid/schemas";
import "./style.css";

type Workflow = "Observe" | "Diagnose" | "Plan" | "Verify";

function App() {
  const driver = useMemo(() => new FakeSessionDriver(), []);
  const [objective, setObjective] = useState("");
  const [workflow, setWorkflow] = useState<Workflow>("Observe");
  const [status, setStatus] = useState("Pronto per una diagnosi sicura.");
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [proposal, setProposal] = useState<DiagnosisProposal>();
  const [plan, setPlan] = useState<ValidatedPlan>();
  const [report, setReport] = useState<string>();

  async function diagnose() {
    if (!objective.trim() || busy) return;
    setBusy(true); setProposal(undefined); setPlan(undefined); setReport(undefined);
    try {
      setWorkflow("Observe"); setStatus("Raccolta evidenze in sola lettura…");
      const session = await driver.startSession({ mode: "rescue", targetFingerprint: `sha256:${"0".repeat(64)}` });
      const observed = await driver.requestEvidence(session.id, { collector: "linux.fixture.inventory", target: "fixture:linux-root" });
      setEvidence(observed); setWorkflow("Diagnose");
      let diagnosis: DiagnosisProposal | undefined;
      for await (const event of driver.sendUserPrompt(session.id, objective)) { setStatus(event.message); if (event.proposal) diagnosis = event.proposal; }
      if (!diagnosis) throw new Error("Il provider non ha restituito una diagnosi valida.");
      setProposal(diagnosis);
      const staged = await driver.stagePlan(session.id, diagnosis);
      setPlan(staged); setWorkflow("Plan");
      const artifact = await driver.exportReport(session.id, "json");
      setReport(artifact.uri); setStatus("Diagnosi completata. Nessuna modifica eseguita.");
    } catch (error) { setStatus(error instanceof Error ? error.message : "Errore inatteso"); }
    finally { setBusy(false); }
  }

  return <main>
    <header><strong>KernAid</strong><span>Rescue preview · Fake provider · Vault locked</span></header>
    <aside><p className="label">TARGET MACHINE</p><h2>Linux fixture</h2>{["Hardware", "Storage", "Boot", "Network"].map((item, index) => <button key={item}>{item} · {index < evidence.length ? "observed" : "pending"}</button>)}</aside>
    <section><div className="steps">{(["Observe", "Diagnose", "Plan", "Repair", "Verify"] as const).map(step => <span className={step === workflow ? "active" : ""} key={step}>{step}</span>)}</div>
      <article><small>{evidence.length ? `${evidence[0].id} · observed-untrusted` : "SESSION NOT STARTED"}</small><h1>{proposal?.diagnosis ?? "Evidence before action."}</h1><p>{status}</p>{proposal && <p>Confidenza: {Math.round(proposal.confidence * 100)}% · Evidenze: {proposal.evidenceIds.join(", ")}</p>}</article>
      <textarea aria-label="Problem description" value={objective} onChange={event => setObjective(event.target.value)} placeholder="Descrivi il problema del computer…" />
      <button className="primary" disabled={!objective.trim() || busy} onClick={diagnose}>{busy ? "Analisi…" : "Diagnostica"}</button>{report && <p className="report">Report pronto: <code>{report}</code></p>}</section>
    <aside className="right"><p className="label">STAGED PLAN</p><h2>{plan ? plan.diagnosis : "Nessuna modifica prevista"}</h2><p>Rischio {plan?.risk ?? "R0"} · {plan?.steps.length ?? 0} azioni</p><hr />{plan?.steps.map(step => <div className="plan" key={step.action}><b>{step.action}</b><small>Validazione: {step.validation}</small></div>)}<p>Le riparazioni reali richiedono backup, risorse esplicite e approvazione locale.</p></aside>
    <footer>{evidence.length} evidenze · Terminale disabilitato · Audit locale</footer>
  </main>;
}

createRoot(document.getElementById("root")!).render(<App />);
