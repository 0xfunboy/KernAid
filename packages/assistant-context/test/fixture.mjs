export function linuxContext() {
  return {
    kind: "kernaid.assistant-inspection.v1",
    osFamily: "linux",
    filesystem: "ext4",
    installationConfirmed: true,
    observations: {
      bootDirectoryPresent: true,
      fstabPresent: true,
      fstabRootEntryPresent: true,
      fstabEfiEntryPresent: false,
      separateBootMountPresent: false,
      topologySupported: true,
      dpkgStatusPresent: true,
      rpmDatabasePresent: false,
      pacmanDatabasePresent: false,
      kernelArtifactCount: 1,
      initramfsArtifactCount: 0,
      bootloaderDirectoryCount: 1,
      fstabEntryCount: 2,
      fstabMalformedLineCount: 0,
    },
  };
}
