import "./rescue-repair.css";

import type { RescueRepairPanelProps } from "./rescue-repair-panel";
import { FleetRescueRepairPanel } from "./fleet-rescue-repair-panel";
import { RescueRepairPanel as LocalRescueRepairPanel } from "./rescue-repair-panel";

export function RescueRepairPanel(props: RescueRepairPanelProps) {
  return (
    <>
      <FleetRescueRepairPanel
        selection={props.selection}
        targetFingerprint={props.targetFingerprint}
        inspection={props.inspection}
      />
      <LocalRescueRepairPanel {...props} />
    </>
  );
}
