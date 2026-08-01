import type { DiagnosisProposal } from "@kernaid/schemas";
import type { ObservedEvidence, Provider } from "@kernaid/provider-types";

export type { ObservedEvidence, Provider } from "@kernaid/provider-types";

export class OfflineRulesProvider implements Provider {
  readonly capabilities = Object.freeze({
    streaming: false,
    structuredOutput: true,
    toolRequests: false,
    local: true,
  });

  async diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
  ): Promise<DiagnosisProposal> {
    if (!objective.trim()) throw new Error("objective is required");
    if (evidence.length === 0) throw new Error("evidence is required");
    const joined = evidence
      .map((item) => `${item.evidence.collector}\n${item.content}`)
      .join("\n")
      .toLowerCase();
    let diagnosis =
      "Nessuna anomalia deterministica evidente nell'inventario raccolto. Servono controlli mirati prima di proporre modifiche.";
    let confidence = 0.55;
    if (
      /failed units|systemctl|systemd/.test(joined) &&
      /(^|\n)\s*[^\n]+\.service\s+loaded\s+failed/m.test(joined)
    ) {
      diagnosis =
        "Sono presenti servizi di sistema in stato failed. La causa va verificata nei log prima di qualsiasi riparazione.";
      confidence = 0.82;
    } else if (
      /no media|not ready|i\/o error|input\/output error|uncorrectable|critical warning[^\n]*[1-9]/.test(
        joined,
      )
    ) {
      diagnosis =
        "L'evidenza segnala un possibile problema del supporto di archiviazione. Evitare scritture e creare prima un'immagine o un backup verificato.";
      confidence = 0.88;
    } else if (/media disconnected|state down|no-carrier/.test(joined)) {
      diagnosis =
        "Una o più interfacce di rete risultano disconnesse. Verificare collegamento, adattatore e configurazione prima di modificare il sistema.";
      confidence = 0.76;
    }
    return {
      schemaVersion: "1.0",
      diagnosis,
      confidence,
      evidenceIds: evidence.map((item) => item.evidence.id),
      requestedEvidence: [],
    };
  }
}
