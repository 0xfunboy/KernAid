import { invoke } from "@tauri-apps/api/core";

export interface NativeObservation {
  collector: string;
  trust: "observed-untrusted";
  output: string;
  success: boolean;
}

export function isNative(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export async function collectLocalInventory(): Promise<NativeObservation[]> {
  if (!isNative()) return [];
  return invoke<NativeObservation[]>("collect_local_inventory");
}
