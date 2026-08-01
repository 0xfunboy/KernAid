import type { DiagnosisProposal, Evidence } from "@kernaid/schemas";

export interface ProviderCapabilities {
  streaming: boolean;
  structuredOutput: boolean;
  toolRequests: boolean;
  local: boolean;
}

export interface ProviderEvent {
  type: "status" | "text" | "usage" | "error";
  payload: unknown;
}

export interface ObservedEvidence {
  evidence: Evidence;
  content: string;
}

export interface ProviderRequestOptions {
  signal?: AbortSignal;
}

export type ProviderSecretSupplier = () =>
  string | undefined | Promise<string | undefined>;

export interface Provider {
  readonly capabilities: Readonly<ProviderCapabilities>;
  diagnose(
    objective: string,
    evidence: readonly ObservedEvidence[],
    options?: ProviderRequestOptions,
  ): Promise<DiagnosisProposal>;
}

export type ProviderErrorCode =
  | "cancelled"
  | "credential_unavailable"
  | "invalid_configuration"
  | "invalid_request"
  | "invalid_response"
  | "request_too_large"
  | "response_too_large"
  | "timeout"
  | "transport"
  | "upstream";

export class ProviderError extends Error {
  readonly code: ProviderErrorCode;
  readonly status?: number;

  constructor(code: ProviderErrorCode, message: string, status?: number) {
    super(message);
    this.name = "ProviderError";
    this.code = code;
    if (status !== undefined) this.status = status;
  }
}
