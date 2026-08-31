import type { RescueTargetSelection } from "./native";

export const RESCUE_REPAIR_API_VERSION =
  "kernaid.dev/rescue-repair-service/v1alpha1";
export const RESCUE_ROLLBACK_API_VERSION =
  "kernaid.dev/rescue-repair-service/v1alpha2";
export const RESCUE_REPAIR_ENDPOINT = "/api/rescue/repair";
export const RESCUE_FSTAB_FINDING_ID = "KA-LNX-P0-003";
export const RESCUE_FSTAB_ACTION_ID = "linux.fstab.disable-missing-uuid.v1";
export const RESCUE_FSTAB_RESOURCE_ID = "rescue:selected-linux-root:etc/fstab";
export const RESCUE_FSTAB_CONFIRMATION = "DISABILITA VOCE FSTAB";
export const RESCUE_CRYPTTAB_FINDING_ID = "KA-LNX-P0-012";
export const RESCUE_CRYPTTAB_ACTION_ID =
  "linux.crypttab.disable-missing-uuid.v1";
export const RESCUE_CRYPTTAB_RESOURCE_ID =
  "rescue:selected-linux-root:etc/crypttab";
export const RESCUE_CRYPTTAB_CONFIRMATION = "DISABILITA VOCE CRYPTTAB";
export const RESCUE_EXT4_FINDING_ID = "KA-LNX-FS-001";
export const RESCUE_EXT4_ACTION_ID = "linux.ext4.fsck-preen-with-undo.v1";
export const RESCUE_EXT4_RESOURCE_ID = "rescue:selected-linux-filesystem:ext4";
export const RESCUE_EXT4_CONFIRMATION = "REPAIR EXT4 OFFLINE";
export const RESCUE_RESOLVER_LINK_ACTION_ID =
  "linux.network.restore-resolver-link.v1";
export const RESCUE_RESOLVER_LINK_RESOURCE_ID =
  "rescue:selected-linux-root:etc/resolver-link";
export const RESCUE_RESOLVER_LINK_CONFIRMATION = "RESTORE RESOLVER LINK";
export const RESCUE_RESOLVER_LINK_FINDING_ID = "KA-LNX-NET-001";
export const RESCUE_FSTAB_ROLLBACK_ACTION_ID = "linux.fstab.restore";
export const RESCUE_FSTAB_ROLLBACK_CONFIRMATION = "RIPRISTINA FSTAB ORIGINALE";
export const RESCUE_CRYPTTAB_ROLLBACK_ACTION_ID =
  "linux.crypttab.disable-missing-source.v1";
export const RESCUE_CRYPTTAB_ROLLBACK_CONFIRMATION =
  "RIPRISTINA CRYPTTAB ORIGINALE";

const MAX_RESPONSE_BYTES = 4096;
const REQUEST_ID =
  /^R-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const PREPARED_ID = /^Q-[a-f0-9]{32}$/u;
const SESSION_ID = /^S-[a-f0-9]{32}$/u;
const PLAN_ID = /^P-[a-f0-9]{32}$/u;
const APPROVAL_ID = /^A-[a-f0-9]{32}$/u;
const ROLLBACK_ID = /^RB-[a-f0-9]{32}$/u;
const RESERVATION_ID = /^B-[A-Za-z0-9-]{1,126}$/u;
const SCAN_FINGERPRINT = /^scan:[a-f0-9]{64}$/u;
const TARGET_ID = /^target:[a-f0-9]{64}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const BACKUP_LOCATOR = /^vault:\/\/repair\/B-[a-f0-9]{32}$/u;

export type RescueRepairOperation =
  | "repair.status"
  | "repair.fstab.prepare"
  | "repair.fstab.approve"
  | "repair.fstab.cancel"
  | "repair.crypttab.prepare"
  | "repair.crypttab.approve"
  | "repair.crypttab.cancel"
  | "repair.ext4.prepare"
  | "repair.ext4.approve"
  | "repair.ext4.cancel"
  | "repair.resolver-link.prepare"
  | "repair.resolver-link.approve"
  | "repair.resolver-link.cancel"
  | "repair.fstab.rollback.status"
  | "repair.fstab.rollback.prepare"
  | "repair.fstab.rollback.approve"
  | "repair.fstab.rollback.cancel"
  | "repair.crypttab.rollback.status"
  | "repair.crypttab.rollback.prepare"
  | "repair.crypttab.rollback.approve"
  | "repair.crypttab.rollback.cancel";

export type RescueRepairState =
  | "idle"
  | "preparing"
  | "prepared"
  | "executing"
  | "succeeded"
  | "restored"
  | "cancelled"
  | "manual-reconciliation-required"
  | "failed";

export type RescueRepairTerminalOutcome =
  | "committed"
  | "closed-before-unchanged"
  | "closed-before-restored"
  | "rolled-back-original"
  | "cancelled"
  | "manual-reconciliation-required"
  | "failed";

export type RescueRepairPrepareFailureStage =
  | "target-capability-timed-out"
  | "target-capability-identity-changed"
  | "target-capability-unavailable"
  | "observation-preview"
  | "vault-reserve"
  | "admission-internal";

export type RescueRepairErrorToken =
  | "invalid-request"
  | "unauthorized"
  | "busy"
  | "state-conflict"
  | "binding-mismatch"
  | "approval-rejected"
  | "prepare-failed"
  | "cancel-failed"
  | "execution-failed"
  | "recovery-unavailable"
  | "rollback-unavailable"
  | "internal";

export interface RescueRepairTargetClaims {
  readonly scanFingerprint: string;
  readonly targetFingerprint: string;
  readonly targetId: string;
}

export interface RescueRepairPreparedDetail {
  readonly kind:
    | "fstab-prepared"
    | "crypttab-prepared"
    | "ext4-fsck-prepared"
    | "resolver-link-prepared";
  readonly preparedId: string;
  readonly sessionId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly targetFingerprint: string;
  readonly beforeSha256: string;
  readonly afterSha256: string;
  readonly diffSha256: string;
  readonly resourceId:
    | typeof RESCUE_FSTAB_RESOURCE_ID
    | typeof RESCUE_CRYPTTAB_RESOURCE_ID
    | typeof RESCUE_EXT4_RESOURCE_ID
    | typeof RESCUE_RESOLVER_LINK_RESOURCE_ID;
  readonly backupLocator: string;
  readonly actionId:
    | typeof RESCUE_FSTAB_ACTION_ID
    | typeof RESCUE_CRYPTTAB_ACTION_ID
    | typeof RESCUE_EXT4_ACTION_ID
    | typeof RESCUE_RESOLVER_LINK_ACTION_ID;
  readonly risk: "R2" | "R3";
  readonly backup: {
    readonly state: "reserved";
    readonly vaultDistinct: true;
  };
  readonly nextApprovalSequence: number;
  readonly confirmationRequired:
    | typeof RESCUE_FSTAB_CONFIRMATION
    | typeof RESCUE_CRYPTTAB_CONFIRMATION
    | typeof RESCUE_EXT4_CONFIRMATION
    | typeof RESCUE_RESOLVER_LINK_CONFIRMATION;
}

export interface RescueRollbackSourceReceipt {
  readonly reservationId: string;
  readonly transactionBindingSha256: string;
}

export interface RescueRollbackPreparedDetail {
  readonly kind: "fstab-rollback-prepared" | "crypttab-rollback-prepared";
  readonly preparedId: string;
  readonly rollbackId: string;
  readonly sessionId: string;
  readonly planId: string;
  readonly planHash: string;
  readonly targetFingerprint: string;
  readonly source: RescueRollbackSourceReceipt;
  readonly resourceId:
    typeof RESCUE_FSTAB_RESOURCE_ID | typeof RESCUE_CRYPTTAB_RESOURCE_ID;
  readonly backupLocator: string;
  readonly actionId:
    | typeof RESCUE_FSTAB_ROLLBACK_ACTION_ID
    | typeof RESCUE_CRYPTTAB_ROLLBACK_ACTION_ID;
  readonly risk: "R2";
  readonly nextApprovalSequence: number;
  readonly confirmationRequired:
    | typeof RESCUE_FSTAB_ROLLBACK_CONFIRMATION
    | typeof RESCUE_CRYPTTAB_ROLLBACK_CONFIRMATION;
}

export interface RescueRepairTerminalDetail {
  readonly kind: "terminal";
  readonly terminalOutcome: RescueRepairTerminalOutcome;
  readonly reservationId: string | null;
  readonly transactionBindingSha256: string | null;
  readonly rebootRequired: boolean;
  readonly prepareFailureStage: RescueRepairPrepareFailureStage | null;
}

export type RescueRepairDetail =
  | null
  | RescueRepairPreparedDetail
  | RescueRollbackPreparedDetail
  | RescueRepairTerminalDetail;

export interface RescueRepairSnapshot {
  readonly requestId: string;
  readonly operation: RescueRepairOperation;
  readonly stateVersion: number;
  readonly state: RescueRepairState;
  readonly detail: RescueRepairDetail;
}

type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type RequestIdFactory = () => string;
type ApprovalIdFactory = () => string;

export class RescueRepairUnavailableError extends Error {
  constructor() {
    super("Il servizio di riparazione Rescue non è disponibile.");
    this.name = "RescueRepairUnavailableError";
  }
}

export class RescueRepairServiceError extends Error {
  readonly token: RescueRepairErrorToken;
  readonly stateVersion: number;
  readonly state: RescueRepairState;
  readonly detail: RescueRepairDetail;

  constructor(
    token: RescueRepairErrorToken,
    stateVersion: number,
    state: RescueRepairState,
    detail: RescueRepairDetail,
  ) {
    super(rescueRepairErrorMessage(token));
    this.name = "RescueRepairServiceError";
    this.token = token;
    this.stateVersion = stateVersion;
    this.state = state;
    this.detail = detail;
  }
}

export class RescueRepairClient {
  readonly #fetch: FetchLike;
  readonly #requestId: RequestIdFactory;
  readonly #approvalId: ApprovalIdFactory;

  constructor(
    fetcher: FetchLike = fetch,
    requestIdFactory: RequestIdFactory = createRescueRepairRequestId,
    approvalIdFactory: ApprovalIdFactory = createRescueRepairApprovalId,
  ) {
    this.#fetch = fetcher;
    this.#requestId = requestIdFactory;
    this.#approvalId = approvalIdFactory;
  }

  async status(signal?: AbortSignal): Promise<RescueRepairSnapshot> {
    const requestId = this.#nextRequestId();
    return await this.#post(
      {
        apiVersion: RESCUE_REPAIR_API_VERSION,
        requestId,
        operation: "repair.status",
      },
      requestId,
      "repair.status",
      signal,
    );
  }

  async prepare(
    target: RescueRepairTargetClaims,
    candidate: "fstab" | "crypttab" | "ext4" | "resolver-link" = "fstab",
    signal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const claims = parseRescueRepairTargetClaims(target);
    const requestId = this.#nextRequestId();
    return await this.#post(
      {
        apiVersion: RESCUE_REPAIR_API_VERSION,
        requestId,
        operation: `repair.${candidate}.prepare`,
        target: claims,
      },
      requestId,
      `repair.${candidate}.prepare`,
      signal,
    );
  }

  async approve(
    prepared: RescueRepairPreparedDetail,
    typedConfirmation: string,
    signal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const exactPrepared = parsePreparedDetail(prepared);
    if (typedConfirmation !== exactPrepared.confirmationRequired)
      throw new Error("La frase di conferma non corrisponde.");
    const requestId = this.#nextRequestId();
    const approvalId = this.#approvalId();
    if (!APPROVAL_ID.test(approvalId))
      throw new Error("Identificatore di approvazione locale non valido.");
    return await this.#post(
      {
        apiVersion: RESCUE_REPAIR_API_VERSION,
        requestId,
        operation: repairOperation(exactPrepared.kind, "approve"),
        preparedId: exactPrepared.preparedId,
        sessionId: exactPrepared.sessionId,
        planId: exactPrepared.planId,
        planHash: exactPrepared.planHash,
        approvalId,
        approvalSequence: exactPrepared.nextApprovalSequence,
        typedConfirmation: exactPrepared.confirmationRequired,
      },
      requestId,
      repairOperation(exactPrepared.kind, "approve"),
      signal,
    );
  }

  async cancel(
    prepared: RescueRepairPreparedDetail,
    signal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const exactPrepared = parsePreparedDetail(prepared);
    const requestId = this.#nextRequestId();
    return await this.#post(
      {
        apiVersion: RESCUE_REPAIR_API_VERSION,
        requestId,
        operation: repairOperation(exactPrepared.kind, "cancel"),
        preparedId: exactPrepared.preparedId,
        planHash: exactPrepared.planHash,
      },
      requestId,
      repairOperation(exactPrepared.kind, "cancel"),
      signal,
    );
  }

  async rollbackStatus(
    signal?: AbortSignal,
    candidate: "fstab" | "crypttab" = "fstab",
  ): Promise<RescueRepairSnapshot> {
    const requestId = this.#nextRequestId();
    const operation =
      candidate === "crypttab"
        ? "repair.crypttab.rollback.status"
        : "repair.fstab.rollback.status";
    return await this.#post(
      {
        apiVersion: RESCUE_ROLLBACK_API_VERSION,
        requestId,
        operation,
      },
      requestId,
      operation,
      signal,
    );
  }

  async prepareRollback(
    source: RescueRollbackSourceReceipt,
    candidate: "fstab" | "crypttab" = "fstab",
    signal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const exactSource = parseRollbackSourceReceipt(source);
    const requestId = this.#nextRequestId();
    const operation =
      candidate === "crypttab"
        ? "repair.crypttab.rollback.prepare"
        : "repair.fstab.rollback.prepare";
    return await this.#post(
      {
        apiVersion: RESCUE_ROLLBACK_API_VERSION,
        requestId,
        operation,
        source: exactSource,
      },
      requestId,
      operation,
      signal,
    );
  }

  async approveRollback(
    prepared: RescueRollbackPreparedDetail,
    typedConfirmation: string,
    signal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const exactPrepared = parseRollbackPreparedDetail(prepared);
    if (typedConfirmation !== exactPrepared.confirmationRequired)
      throw new Error("La frase di conferma rollback non corrisponde.");
    const requestId = this.#nextRequestId();
    const approvalId = this.#approvalId();
    if (!APPROVAL_ID.test(approvalId))
      throw new Error("Identificatore di approvazione locale non valido.");
    const operation =
      exactPrepared.kind === "crypttab-rollback-prepared"
        ? "repair.crypttab.rollback.approve"
        : "repair.fstab.rollback.approve";
    return await this.#post(
      {
        apiVersion: RESCUE_ROLLBACK_API_VERSION,
        requestId,
        operation,
        preparedId: exactPrepared.preparedId,
        rollbackId: exactPrepared.rollbackId,
        sessionId: exactPrepared.sessionId,
        planId: exactPrepared.planId,
        planHash: exactPrepared.planHash,
        source: exactPrepared.source,
        approvalId,
        approvalSequence: exactPrepared.nextApprovalSequence,
        typedConfirmation: exactPrepared.confirmationRequired,
      },
      requestId,
      operation,
      signal,
    );
  }

  async cancelRollback(
    prepared: RescueRollbackPreparedDetail,
    signal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const exactPrepared = parseRollbackPreparedDetail(prepared);
    const requestId = this.#nextRequestId();
    const operation =
      exactPrepared.kind === "crypttab-rollback-prepared"
        ? "repair.crypttab.rollback.cancel"
        : "repair.fstab.rollback.cancel";
    return await this.#post(
      {
        apiVersion: RESCUE_ROLLBACK_API_VERSION,
        requestId,
        operation,
        preparedId: exactPrepared.preparedId,
        rollbackId: exactPrepared.rollbackId,
        planHash: exactPrepared.planHash,
        source: exactPrepared.source,
      },
      requestId,
      operation,
      signal,
    );
  }

  #nextRequestId(): string {
    const requestId = this.#requestId();
    if (!REQUEST_ID.test(requestId))
      throw new Error("Identificatore richiesta locale non valido.");
    return requestId;
  }

  async #post(
    body: Record<string, unknown>,
    requestId: string,
    operation: RescueRepairOperation,
    callerSignal?: AbortSignal,
  ): Promise<RescueRepairSnapshot> {
    const encoded = JSON.stringify(body);
    if (new TextEncoder().encode(encoded).byteLength > MAX_RESPONSE_BYTES)
      throw new Error("Richiesta di riparazione oltre il limite locale.");
    let response: Response;
    try {
      response = await this.#fetch(RESCUE_REPAIR_ENDPOINT, {
        method: "POST",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: encoded,
        signal: callerSignal ?? AbortSignal.timeout(20_000),
      });
    } catch {
      throw new RescueRepairUnavailableError();
    }
    if (
      (operation === "repair.status" ||
        operation.endsWith(".rollback.status")) &&
      (response.status === 404 || response.status === 503)
    )
      throw new RescueRepairUnavailableError();
    if (!isJsonResponse(response)) throw new RescueRepairUnavailableError();
    const payload = await readBoundedJson(response, MAX_RESPONSE_BYTES).catch(
      () => {
        throw new RescueRepairUnavailableError();
      },
    );
    const parsed = parseRescueRepairResponse(payload, requestId, operation);
    if (!response.ok) throw new RescueRepairUnavailableError();
    return parsed;
  }
}

export function rescueRepairTargetClaims(
  selection: RescueTargetSelection,
  targetFingerprint: string,
): RescueRepairTargetClaims {
  return parseRescueRepairTargetClaims({
    scanFingerprint: selection.scanFingerprint,
    targetFingerprint,
    targetId: selection.target.targetId,
  });
}

export function parseRescueRepairTargetClaims(
  value: unknown,
): RescueRepairTargetClaims {
  const item = exactRecord(value, [
    "scanFingerprint",
    "targetFingerprint",
    "targetId",
  ]);
  if (
    typeof item.scanFingerprint !== "string" ||
    !SCAN_FINGERPRINT.test(item.scanFingerprint) ||
    typeof item.targetFingerprint !== "string" ||
    !SHA256.test(item.targetFingerprint) ||
    typeof item.targetId !== "string" ||
    !TARGET_ID.test(item.targetId)
  )
    throw new Error("Binding del target Rescue non valido.");
  return structuredClone(item) as unknown as RescueRepairTargetClaims;
}

export function parseRescueRepairResponse(
  value: unknown,
  expectedRequestId: string,
  expectedOperation: RescueRepairOperation,
): RescueRepairSnapshot {
  if (!REQUEST_ID.test(expectedRequestId))
    throw new Error("Correlazione riparazione non valida.");
  const record = objectRecord(value);
  if (record.outcome === "error") {
    const error = exactRecord(value, [
      "apiVersion",
      "requestId",
      "operation",
      "outcome",
      "stateVersion",
      "state",
      "detail",
      "error",
    ]);
    assertEnvelope(error, expectedRequestId, expectedOperation);
    const state = parseState(error.state);
    const stateVersion = parseStateVersion(error.stateVersion);
    const token = parseErrorToken(error.error);
    const detail = parseDetail(error.detail, state, expectedOperation);
    throw new RescueRepairServiceError(token, stateVersion, state, detail);
  }
  const response = exactRecord(value, [
    "apiVersion",
    "requestId",
    "operation",
    "outcome",
    "stateVersion",
    "state",
    "detail",
  ]);
  assertEnvelope(response, expectedRequestId, expectedOperation);
  if (response.outcome !== "ok")
    throw new Error("Risposta del servizio di riparazione non valida.");
  const state = parseState(response.state);
  const detail = parseDetail(response.detail, state, expectedOperation);
  return Object.freeze({
    requestId: expectedRequestId,
    operation: expectedOperation,
    stateVersion: parseStateVersion(response.stateVersion),
    state,
    detail,
  });
}

export function preparedRepairDetail(
  snapshot: RescueRepairSnapshot | undefined,
): RescueRepairPreparedDetail | undefined {
  return snapshot?.state === "prepared" &&
    (snapshot.detail?.kind === "fstab-prepared" ||
      snapshot.detail?.kind === "crypttab-prepared" ||
      snapshot.detail?.kind === "ext4-fsck-prepared" ||
      snapshot.detail?.kind === "resolver-link-prepared")
    ? snapshot.detail
    : undefined;
}

export function preparedRollbackDetail(
  snapshot: RescueRepairSnapshot | undefined,
): RescueRollbackPreparedDetail | undefined {
  return snapshot?.state === "prepared" &&
    (snapshot.detail?.kind === "fstab-rollback-prepared" ||
      snapshot.detail?.kind === "crypttab-rollback-prepared")
    ? snapshot.detail
    : undefined;
}

export function rollbackSourceReceipt(
  snapshot: RescueRepairSnapshot | undefined,
  candidate: "fstab" | "crypttab" | "ext4" | "resolver-link" | undefined,
): RescueRollbackSourceReceipt | undefined {
  if (
    candidate === undefined ||
    candidate === "ext4" ||
    candidate === "resolver-link" ||
    snapshot?.state !== "succeeded" ||
    snapshot.detail?.kind !== "terminal" ||
    snapshot.detail.terminalOutcome !== "committed" ||
    snapshot.detail.reservationId === null ||
    snapshot.detail.transactionBindingSha256 === null
  )
    return undefined;
  return parseRollbackSourceReceipt({
    reservationId: snapshot.detail.reservationId,
    transactionBindingSha256: snapshot.detail.transactionBindingSha256,
  });
}

export function rescueRepairNeedsPolling(
  snapshot: RescueRepairSnapshot | undefined,
): boolean {
  return snapshot?.state === "preparing" || snapshot?.state === "executing";
}

export function rescueRepairIsTerminal(
  snapshot: RescueRepairSnapshot | undefined,
): boolean {
  return (
    snapshot !== undefined &&
    [
      "succeeded",
      "restored",
      "cancelled",
      "manual-reconciliation-required",
      "failed",
    ].includes(snapshot.state)
  );
}

export function rescueRepairStateMessage(
  snapshot: RescueRepairSnapshot,
): string {
  switch (snapshot.state) {
    case "idle":
      return "Pronto a preparare una verifica senza modifiche.";
    case "preparing":
      return "Verifica del finding e preparazione del backup in corso…";
    case "prepared":
      return "Piano preparato. Nessuna modifica è stata ancora eseguita.";
    case "executing":
      return "Riparazione in corso. Non spegnere il computer e non rimuovere i dispositivi.";
    case "succeeded":
      return "Riparazione completata e verificata.";
    case "restored":
      return "La modifica non è stata confermata: KernAid ha ripristinato i dati originali.";
    case "cancelled":
      return "Piano annullato. Nessuna modifica è stata eseguita.";
    case "manual-reconciliation-required":
      return "Stato non riconciliabile automaticamente. Non avviare il sistema installato: riavvia KernAid Rescue e richiedi assistenza.";
    case "failed":
      return "Riparazione non completata. Lo stato terminale non dichiara alcun successo.";
  }
}

export function rescueRepairErrorMessage(
  token: RescueRepairErrorToken,
): string {
  switch (token) {
    case "busy":
      return "Un'altra operazione Rescue è già in corso.";
    case "state-conflict":
    case "binding-mismatch":
      return "Lo stato o il target non corrisponde più. Aggiorna lo stato prima di continuare.";
    case "approval-rejected":
      return "Approvazione rifiutata: controlla il piano e la frase di conferma.";
    case "recovery-unavailable":
      return "Recupero automatico non disponibile. Riavvia KernAid Rescue e richiedi assistenza.";
    case "rollback-unavailable":
      return "Il rollback verificato non è disponibile in questa build Rescue.";
    case "unauthorized":
      return "Il pannello non è autorizzato a usare il servizio di riparazione.";
    case "prepare-failed":
      return "Il finding non è riparabile in sicurezza su questo target.";
    case "cancel-failed":
      return "Annullamento non confermato. Aggiorna lo stato prima di continuare.";
    case "execution-failed":
      return "Esecuzione non completata. Attendi lo stato terminale senza assumere il successo.";
    case "invalid-request":
    case "internal":
      return "Il servizio di riparazione ha rifiutato l'operazione.";
  }
}

export function createRescueRepairRequestId(): string {
  return `R-${crypto.randomUUID()}`;
}

export function createRescueRepairApprovalId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `A-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function parseDetail(
  value: unknown,
  state: RescueRepairState,
  operation: RescueRepairOperation,
): RescueRepairDetail {
  if (state === "prepared") {
    if (operation.includes(".rollback.")) {
      const rollback = parseRollbackPreparedDetail(value);
      if (
        (operation.startsWith("repair.crypttab.") &&
          rollback.kind !== "crypttab-rollback-prepared") ||
        (operation.startsWith("repair.fstab.") &&
          rollback.kind !== "fstab-rollback-prepared")
      )
        throw new Error("Risorsa rollback non coerente con l'operazione.");
      return rollback;
    }
    const prepared = parsePreparedDetail(value);
    if (
      (operation.startsWith("repair.crypttab.") &&
        prepared.kind !== "crypttab-prepared") ||
      (operation.startsWith("repair.fstab.") &&
        prepared.kind !== "fstab-prepared") ||
      (operation.startsWith("repair.ext4.") &&
        prepared.kind !== "ext4-fsck-prepared") ||
      (operation.startsWith("repair.resolver-link.") &&
        prepared.kind !== "resolver-link-prepared")
    )
      throw new Error("Risorsa preparata non coerente con l'operazione.");
    return prepared;
  }
  if (
    state === "succeeded" ||
    state === "restored" ||
    state === "cancelled" ||
    state === "manual-reconciliation-required" ||
    state === "failed"
  )
    return parseTerminalDetail(value, state, operation);
  if (value !== null)
    throw new Error("Dettaglio dello stato riparazione non valido.");
  return null;
}

function repairOperation(
  kind: RescueRepairPreparedDetail["kind"],
  phase: "approve" | "cancel",
): RescueRepairOperation {
  const candidate =
    kind === "crypttab-prepared"
      ? "crypttab"
      : kind === "ext4-fsck-prepared"
        ? "ext4"
        : kind === "resolver-link-prepared"
          ? "resolver-link"
          : "fstab";
  return `repair.${candidate}.${phase}` as RescueRepairOperation;
}

function parsePreparedDetail(value: unknown): RescueRepairPreparedDetail {
  const item = exactRecord(value, [
    "kind",
    "preparedId",
    "sessionId",
    "planId",
    "planHash",
    "targetFingerprint",
    "beforeSha256",
    "afterSha256",
    "diffSha256",
    "resourceId",
    "backupLocator",
    "actionId",
    "risk",
    "backup",
    "nextApprovalSequence",
    "confirmationRequired",
  ]);
  const backup = exactRecord(item.backup, ["state", "vaultDistinct"]);
  const crypttab = item.kind === "crypttab-prepared";
  const ext4 = item.kind === "ext4-fsck-prepared";
  const resolverLink = item.kind === "resolver-link-prepared";
  if (
    (item.kind !== "fstab-prepared" && !crypttab && !ext4 && !resolverLink) ||
    typeof item.preparedId !== "string" ||
    !PREPARED_ID.test(item.preparedId) ||
    typeof item.sessionId !== "string" ||
    !SESSION_ID.test(item.sessionId) ||
    typeof item.planId !== "string" ||
    !PLAN_ID.test(item.planId) ||
    typeof item.planHash !== "string" ||
    !SHA256.test(item.planHash) ||
    typeof item.targetFingerprint !== "string" ||
    !SHA256.test(item.targetFingerprint) ||
    typeof item.beforeSha256 !== "string" ||
    !SHA256.test(item.beforeSha256) ||
    typeof item.afterSha256 !== "string" ||
    !SHA256.test(item.afterSha256) ||
    typeof item.diffSha256 !== "string" ||
    !SHA256.test(item.diffSha256) ||
    item.beforeSha256 === item.afterSha256 ||
    item.resourceId !==
      (crypttab
        ? RESCUE_CRYPTTAB_RESOURCE_ID
        : ext4
          ? RESCUE_EXT4_RESOURCE_ID
          : resolverLink
            ? RESCUE_RESOLVER_LINK_RESOURCE_ID
            : RESCUE_FSTAB_RESOURCE_ID) ||
    typeof item.backupLocator !== "string" ||
    !BACKUP_LOCATOR.test(item.backupLocator) ||
    item.actionId !==
      (crypttab
        ? RESCUE_CRYPTTAB_ACTION_ID
        : ext4
          ? RESCUE_EXT4_ACTION_ID
          : resolverLink
            ? RESCUE_RESOLVER_LINK_ACTION_ID
            : RESCUE_FSTAB_ACTION_ID) ||
    item.risk !== (ext4 ? "R3" : "R2") ||
    backup.state !== "reserved" ||
    backup.vaultDistinct !== true ||
    !Number.isSafeInteger(item.nextApprovalSequence) ||
    Number(item.nextApprovalSequence) < 1 ||
    Number(item.nextApprovalSequence) > 1_000_000 ||
    item.confirmationRequired !==
      (crypttab
        ? RESCUE_CRYPTTAB_CONFIRMATION
        : ext4
          ? RESCUE_EXT4_CONFIRMATION
          : resolverLink
            ? RESCUE_RESOLVER_LINK_CONFIRMATION
            : RESCUE_FSTAB_CONFIRMATION) ||
    ((crypttab || ext4 || resolverLink) && item.nextApprovalSequence !== 1)
  )
    throw new Error("Piano Rescue preparato non valido.");
  return structuredClone({
    ...item,
    backup,
  }) as unknown as RescueRepairPreparedDetail;
}

function parseRollbackSourceReceipt(
  value: unknown,
): RescueRollbackSourceReceipt {
  const item = exactRecord(value, [
    "reservationId",
    "transactionBindingSha256",
  ]);
  if (
    typeof item.reservationId !== "string" ||
    !/^B-[a-f0-9]{32}$/u.test(item.reservationId) ||
    typeof item.transactionBindingSha256 !== "string" ||
    !SHA256.test(item.transactionBindingSha256)
  )
    throw new Error("Receipt sorgente rollback non valida.");
  return structuredClone(item) as unknown as RescueRollbackSourceReceipt;
}

function parseRollbackPreparedDetail(
  value: unknown,
): RescueRollbackPreparedDetail {
  const item = exactRecord(value, [
    "kind",
    "preparedId",
    "rollbackId",
    "sessionId",
    "planId",
    "planHash",
    "targetFingerprint",
    "source",
    "resourceId",
    "backupLocator",
    "actionId",
    "risk",
    "nextApprovalSequence",
    "confirmationRequired",
  ]);
  const source = parseRollbackSourceReceipt(item.source);
  const crypttab = item.kind === "crypttab-rollback-prepared";
  if (
    (item.kind !== "fstab-rollback-prepared" && !crypttab) ||
    typeof item.preparedId !== "string" ||
    !PREPARED_ID.test(item.preparedId) ||
    typeof item.rollbackId !== "string" ||
    !ROLLBACK_ID.test(item.rollbackId) ||
    typeof item.sessionId !== "string" ||
    !SESSION_ID.test(item.sessionId) ||
    typeof item.planId !== "string" ||
    !PLAN_ID.test(item.planId) ||
    typeof item.planHash !== "string" ||
    !SHA256.test(item.planHash) ||
    typeof item.targetFingerprint !== "string" ||
    !SHA256.test(item.targetFingerprint) ||
    item.resourceId !==
      (crypttab ? RESCUE_CRYPTTAB_RESOURCE_ID : RESCUE_FSTAB_RESOURCE_ID) ||
    typeof item.backupLocator !== "string" ||
    !BACKUP_LOCATOR.test(item.backupLocator) ||
    item.backupLocator !== `vault://repair/${source.reservationId}` ||
    item.actionId !==
      (crypttab
        ? RESCUE_CRYPTTAB_ROLLBACK_ACTION_ID
        : RESCUE_FSTAB_ROLLBACK_ACTION_ID) ||
    item.risk !== "R2" ||
    !Number.isSafeInteger(item.nextApprovalSequence) ||
    Number(item.nextApprovalSequence) < 2 ||
    Number(item.nextApprovalSequence) > 1_000_000 ||
    item.confirmationRequired !==
      (crypttab
        ? RESCUE_CRYPTTAB_ROLLBACK_CONFIRMATION
        : RESCUE_FSTAB_ROLLBACK_CONFIRMATION)
  )
    throw new Error("Piano rollback Rescue non valido.");
  return structuredClone({
    ...item,
    source,
  }) as unknown as RescueRollbackPreparedDetail;
}

function parseTerminalDetail(
  value: unknown,
  state: RescueRepairState,
  operation: RescueRepairOperation,
): RescueRepairTerminalDetail {
  const item = exactRecord(value, [
    "kind",
    "terminalOutcome",
    "reservationId",
    "transactionBindingSha256",
    "rebootRequired",
    "prepareFailureStage",
  ]);
  const outcomes: readonly RescueRepairTerminalOutcome[] = [
    "committed",
    "closed-before-unchanged",
    "closed-before-restored",
    "rolled-back-original",
    "cancelled",
    "manual-reconciliation-required",
    "failed",
  ];
  const prepareFailureStages: readonly RescueRepairPrepareFailureStage[] = [
    "target-capability-timed-out",
    "target-capability-identity-changed",
    "target-capability-unavailable",
    "observation-preview",
    "vault-reserve",
    "admission-internal",
  ];
  if (
    item.kind !== "terminal" ||
    !outcomes.includes(item.terminalOutcome as RescueRepairTerminalOutcome) ||
    (item.reservationId !== null &&
      (typeof item.reservationId !== "string" ||
        !RESERVATION_ID.test(item.reservationId))) ||
    (item.transactionBindingSha256 !== null &&
      (typeof item.transactionBindingSha256 !== "string" ||
        !SHA256.test(item.transactionBindingSha256))) ||
    typeof item.rebootRequired !== "boolean" ||
    item.rebootRequired !== (state === "manual-reconciliation-required") ||
    (item.prepareFailureStage !== null &&
      (state !== "failed" ||
        !prepareFailureStages.includes(
          item.prepareFailureStage as RescueRepairPrepareFailureStage,
        ))) ||
    !terminalOutcomeMatchesState(
      item.terminalOutcome as RescueRepairTerminalOutcome,
      state,
      operation,
    )
  )
    throw new Error("Esito terminale della riparazione non valido.");
  return structuredClone(item) as unknown as RescueRepairTerminalDetail;
}

function terminalOutcomeMatchesState(
  outcome: RescueRepairTerminalOutcome,
  state: RescueRepairState,
  operation: RescueRepairOperation,
): boolean {
  if (state === "succeeded") return outcome === "committed";
  if (state === "restored")
    return (
      outcome === "closed-before-unchanged" ||
      outcome === "closed-before-restored" ||
      (operation.includes(".rollback.") && outcome === "rolled-back-original")
    );
  if (state === "cancelled") return outcome === "cancelled";
  if (state === "manual-reconciliation-required")
    return outcome === "manual-reconciliation-required";
  return state === "failed" && outcome === "failed";
}

function assertEnvelope(
  item: Record<string, unknown>,
  expectedRequestId: string,
  expectedOperation: RescueRepairOperation,
): void {
  if (
    item.apiVersion !== apiVersionForOperation(expectedOperation) ||
    item.requestId !== expectedRequestId ||
    item.operation !== expectedOperation
  )
    throw new Error("Correlazione della risposta riparazione non valida.");
}

function apiVersionForOperation(
  operation: RescueRepairOperation,
): typeof RESCUE_REPAIR_API_VERSION | typeof RESCUE_ROLLBACK_API_VERSION {
  return operation.includes(".rollback.")
    ? RESCUE_ROLLBACK_API_VERSION
    : RESCUE_REPAIR_API_VERSION;
}

function parseState(value: unknown): RescueRepairState {
  const states: readonly RescueRepairState[] = [
    "idle",
    "preparing",
    "prepared",
    "executing",
    "succeeded",
    "restored",
    "cancelled",
    "manual-reconciliation-required",
    "failed",
  ];
  if (!states.includes(value as RescueRepairState))
    throw new Error("Stato riparazione non valido.");
  return value as RescueRepairState;
}

function parseStateVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 1)
    throw new Error("Versione stato riparazione non valida.");
  return Number(value);
}

function parseErrorToken(value: unknown): RescueRepairErrorToken {
  const tokens: readonly RescueRepairErrorToken[] = [
    "invalid-request",
    "unauthorized",
    "busy",
    "state-conflict",
    "binding-mismatch",
    "approval-rejected",
    "prepare-failed",
    "cancel-failed",
    "execution-failed",
    "recovery-unavailable",
    "rollback-unavailable",
    "internal",
  ];
  if (!tokens.includes(value as RescueRepairErrorToken))
    throw new Error("Errore riparazione non valido.");
  return value as RescueRepairErrorToken;
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
  optional: ReadonlySet<string> = new Set(),
): Record<string, unknown> {
  const item = objectRecord(value);
  const allowed = new Set(keys);
  if (
    keys.some((key) => !optional.has(key) && !Object.hasOwn(item, key)) ||
    Object.keys(item).some((key) => !allowed.has(key))
  )
    throw new Error("Risposta del servizio di riparazione non valida.");
  return item;
}

function objectRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("Risposta del servizio di riparazione non valida.");
  return value as Record<string, unknown>;
}

function isJsonResponse(response: Response): boolean {
  return /^application\/json(?:\s*;|$)/iu.test(
    response.headers.get("Content-Type") ?? "",
  );
}

async function readBoundedJson(
  response: Response,
  maximumBytes: number,
): Promise<unknown> {
  const declared = response.headers.get("Content-Length");
  if (
    declared !== null &&
    (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)
  )
    throw new Error("Risposta locale oltre il limite.");
  if (response.body === null) throw new Error("Risposta locale vuota.");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new Error("Risposta locale oltre il limite.");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(bytes),
  ) as unknown;
}
