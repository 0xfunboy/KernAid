import { invoke } from "@tauri-apps/api/core";

export interface NativeObservation {
  collector: string;
  trust: "observed-untrusted";
  output: string;
  success: boolean;
}

export interface ObserveAuthorization {
  sessionId: string;
  targetFingerprint: string;
  sequence: number;
  action: "system.observe.noop";
}

export function isNative(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export function hasLocalCollector(): boolean {
  return isNative() || (location.hostname === "127.0.0.1" && location.port === "4173");
}

export async function collectLocalInventory(): Promise<NativeObservation[]> {
  if (isNative()) return invoke<NativeObservation[]>("collect_local_inventory");
  if (hasLocalCollector()) {
    const response = await fetch("/api/inventory", { cache: "no-store" });
    if (!response.ok) throw new Error(`collector HTTP ${response.status}`);
    return response.json() as Promise<NativeObservation[]>;
  }
  return [];
}

export async function authorizeObserve(request: ObserveAuthorization): Promise<void> {
  if (isNative()) {
    await invoke("authorize_observe", { request });
    return;
  }
  if (!hasLocalCollector()) throw new Error("Il broker locale non è disponibile.");
  const response = await fetch("/api/authorize-observe", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const result = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(result?.error ?? `broker HTTP ${response.status}`);
  }
}
