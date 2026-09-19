export interface AssistantInspectionContext {
  kind: "kernaid.assistant-inspection.v1";
  osFamily: "linux" | "windows";
  filesystem: "ext4" | "ntfs";
  installationConfirmed: boolean;
  observations: Record<string, boolean | number | string | null>;
}
export function parseAssistantContext(
  value: unknown,
): AssistantInspectionContext;
export function assistantContextPreview(value: unknown): string;
