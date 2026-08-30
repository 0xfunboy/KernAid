import type { RescueOfflineInspection, RescueTargetSelection } from "./native";

export interface RescueRepairPanelProps {
  readonly selection?: RescueTargetSelection;
  readonly targetFingerprint?: string;
  readonly inspection?: RescueOfflineInspection;
}

// The shipping Desk has no repair component. Vite replaces this module only
// for the explicitly isolated repair-candidate build.
export function RescueRepairPanel(_props: RescueRepairPanelProps) {
  return null;
}
