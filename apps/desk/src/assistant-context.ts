import {
  parseAssistantContext,
  type AssistantInspectionContext,
} from "@kernaid/assistant-context";
import type { RescueOfflineInspection, RescueTargetSelection } from "./native";
import { sameRescueInspection } from "./rescue-ui";

/** Project only completed, still-selected read-only inspection facts. */
export function assistantInspectionContext(
  selection: RescueTargetSelection | undefined,
  inspection: RescueOfflineInspection | undefined,
): AssistantInspectionContext | undefined {
  if (
    !inspection ||
    !sameRescueInspection(selection, inspection) ||
    !inspection.claims.filesystemContentInspected ||
    !inspection.claims.mountCleanupVerified ||
    inspection.claims.mutationPerformed !== false ||
    inspection.claims.repairAttempted !== false ||
    !inspection.inspection.deviceOpenedReadOnly ||
    !inspection.inspection.journalReplayPrevented
  )
    return undefined;
  const os = inspection.os;
  const observations =
    os.family === "windows"
      ? {
          windowsDirectoryPresent:
            os.installationMarkers.windowsDirectoryPresent,
          system32DirectoryPresent:
            os.installationMarkers.system32DirectoryPresent,
          kernelPresent: os.installationMarkers.kernelPresent,
          systemHivePresent: os.installationMarkers.systemHivePresent,
          softwareHivePresent: os.installationMarkers.softwareHivePresent,
          usersDirectoryPresent: os.installationMarkers.usersDirectoryPresent,
          bootManagerPresent: os.boot.bootManagerPresent,
          bcdPresent: os.boot.bcdPresent,
          pendingXmlPresent: os.servicing.pendingXmlPresent,
          rebootPendingMarkerPresent: os.servicing.rebootPendingMarkerPresent,
          efiState: os.boot.efiSystemPartition.state,
          efiMicrosoftBootManagerPresent:
            os.boot.efiSystemPartition.microsoftBootManagerPresent,
          efiBcdPresent: os.boot.efiSystemPartition.bcdPresent,
          efiFallbackBootloaderPresent:
            os.boot.efiSystemPartition.fallbackBootloaderPresent,
        }
      : {
          bootDirectoryPresent: os.boot.directoryPresent,
          kernelArtifactCount: os.boot.kernelArtifactCount,
          initramfsArtifactCount: os.boot.initramfsArtifactCount,
          bootloaderDirectoryCount: os.boot.bootloaderDirectoryCount,
          fstabPresent: os.configuration.fstab.present,
          fstabEntryCount: os.configuration.fstab.entryCount,
          fstabRootEntryPresent: os.configuration.fstab.rootEntryPresent,
          fstabEfiEntryPresent: os.configuration.fstab.efiEntryPresent,
          fstabMalformedLineCount: os.configuration.fstab.malformedLineCount,
          separateBootMountPresent: os.topology.separateBootMountPresent,
          topologySupported: os.topology.supported,
          dpkgStatusPresent: os.packageDatabases.dpkgStatusPresent,
          rpmDatabasePresent: os.packageDatabases.rpmDatabasePresent,
          pacmanDatabasePresent: os.packageDatabases.pacmanDatabasePresent,
        };
  try {
    return parseAssistantContext({
      kind: "kernaid.assistant-inspection.v1",
      osFamily: inspection.target.osFamily,
      filesystem: inspection.target.filesystem,
      installationConfirmed: os.installationConfirmed,
      observations,
    });
  } catch {
    return undefined;
  }
}
