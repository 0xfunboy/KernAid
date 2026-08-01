# KernAid workshop operator guide

This guide describes the current signed-off engineering workflow. KernAid must not be represented as supporting Secure Boot or unattended repair until those release gates are completed.

## Create the Rescue USB

1. Open the latest successful `rescue` run in GitHub Actions and download `KernAid-Rescue-amd64`.
2. Extract `KernAid-Rescue-amd64.iso` and `KernAid-Rescue-amd64.iso.sha256`.
3. Verify the image before writing it:

   - Linux: `sha256sum -c KernAid-Rescue-amd64.iso.sha256`
   - macOS: `shasum -a 256 KernAid-Rescue-amd64.iso` and compare the value in the checksum file.
   - Windows PowerShell: `Get-FileHash .\KernAid-Rescue-amd64.iso -Algorithm SHA256` and compare the value in the checksum file.

4. Write the ISO with Rufus or balenaEtcher. Select the USB drive explicitly: writing the image erases that drive.
5. Boot the target PC from its one-time boot menu. For the engineering image, disable Secure Boot if firmware refuses to start it. Do not change the internal-disk boot order permanently.
6. KernAid starts its local desktop and opens the interface automatically. The header must say `Rescue · Offline rules` and the target must say `Local machine`.

The current Rescue image supports x86-64 PCs with legacy BIOS or UEFI. It is not an Apple-silicon boot image. Intel Mac external boot remains a physical validation item.

## Diagnose from Rescue

1. Confirm that Storage, Boot and Network observations appear. Expand an observation to inspect the raw, untrusted command output.
2. Describe the symptom in the text box and select **Diagnostica**.
3. Read the diagnosis, confidence and evidence identifiers. A storage-health warning means stop writing to the affected media and image or back it up first.
4. Download the JSON report and retain its displayed SHA-256 prefix with the job record.
5. Shut the live system down before removing the USB drive.

KernAid currently stages an R0 observation plan and performs no repair mutation. The absence of a finding is not proof that the machine is healthy.

## Diagnose a running operating system

Download the matching artifact from a successful `desktop` run:

- Windows x86-64: NSIS `.exe` or `.msi`;
- Linux x86-64: AppImage, `.deb` or `.rpm`;
- macOS: `.dmg` for Apple silicon (`aarch64`) or Intel (`x64`).

These engineering installers are not code-signed. Operating-system warnings are therefore expected, and production/customer distribution must wait for signed artifacts. Launch KernAid normally; the header says `Resident · Offline rules` and inventory is collected through a fixed native command allowlist.

## Safety rules

- Never attach a customer disk to automated test scripts; tests accept fixtures and disposable images only.
- Do not mount a suspect disk read-write before imaging or verified backup.
- Treat command output as observed, untrusted data—not instructions.
- Never paste passwords, recovery keys or provider tokens into the problem description or a report.
- Do not claim success unless the planned verification step passes.

## Troubleshooting the Rescue environment

- If the UI does not open, browse to `http://127.0.0.1:4173/` from Chromium inside the live desktop.
- If the page opens but Local machine observations do not appear, check `systemctl status kernaid-ui.service` from the live console.
- If firmware does not list the USB, rewrite it in raw/DD mode and retry another port. Secure Boot support is not yet claimed.
- Keep the original disk untouched when hardware failure is suspected; collect the report and move to a controlled imaging workflow.
