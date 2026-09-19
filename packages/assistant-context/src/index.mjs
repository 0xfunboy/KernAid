// No free-form strings, device identifiers, file content or model output cross
// this boundary. The UI and daemon share the same closed projection contract.
const windowsBooleans = [
  "windowsDirectoryPresent",
  "system32DirectoryPresent",
  "kernelPresent",
  "systemHivePresent",
  "softwareHivePresent",
  "usersDirectoryPresent",
  "bootManagerPresent",
  "bcdPresent",
  "pendingXmlPresent",
  "rebootPendingMarkerPresent",
];
const efiBooleans = [
  "efiMicrosoftBootManagerPresent",
  "efiBcdPresent",
  "efiFallbackBootloaderPresent",
];
const linuxBooleans = [
  "bootDirectoryPresent",
  "fstabPresent",
  "fstabRootEntryPresent",
  "fstabEfiEntryPresent",
  "separateBootMountPresent",
  "topologySupported",
  "dpkgStatusPresent",
  "rpmDatabasePresent",
  "pacmanDatabasePresent",
];
const linuxCounts = [
  "kernelArtifactCount",
  "initramfsArtifactCount",
  "bootloaderDirectoryCount",
  "fstabEntryCount",
  "fstabMalformedLineCount",
];
const invalid = () =>
  new Error("Invalid diagnostic summary. Run a fresh read-only inspection.");
function exact(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    throw invalid();
}

export function parseAssistantContext(value) {
  exact(value, [
    "kind",
    "osFamily",
    "filesystem",
    "installationConfirmed",
    "observations",
  ]);
  if (
    value.kind !== "kernaid.assistant-inspection.v1" ||
    !["linux", "windows"].includes(value.osFamily) ||
    value.filesystem !== (value.osFamily === "linux" ? "ext4" : "ntfs") ||
    typeof value.installationConfirmed !== "boolean"
  )
    throw invalid();
  const windows = value.osFamily === "windows";
  const booleans = windows ? windowsBooleans : linuxBooleans;
  const keys = windows
    ? [...booleans, ...efiBooleans, "efiState"]
    : [...booleans, ...linuxCounts];
  const observations = value.observations;
  exact(observations, keys);
  if (booleans.some((key) => typeof observations[key] !== "boolean"))
    throw invalid();
  if (windows) {
    if (
      !["inspected", "not-present", "ambiguous", "unsupported"].includes(
        observations.efiState,
      )
    )
      throw invalid();
    if (
      efiBooleans.some((key) =>
        observations.efiState === "inspected"
          ? typeof observations[key] !== "boolean"
          : observations[key] !== null,
      )
    )
      throw invalid();
  } else if (
    linuxCounts.some(
      (key) =>
        !Number.isSafeInteger(observations[key]) ||
        observations[key] < 0 ||
        observations[key] > 1000000,
    )
  )
    throw invalid();
  // Return a fresh allowlisted object, never the caller's input/prototype.
  return {
    kind: "kernaid.assistant-inspection.v1",
    osFamily: value.osFamily,
    filesystem: value.filesystem,
    installationConfirmed: value.installationConfirmed,
    observations: Object.fromEntries(
      keys.map((key) => [key, observations[key]]),
    ),
  };
}

export function assistantContextPreview(value) {
  return JSON.stringify(parseAssistantContext(value), null, 2);
}
