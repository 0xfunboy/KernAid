# KernAid workshop operator guide

This guide describes the current signed-off engineering workflow. KernAid must not be represented as supporting Secure Boot or unattended repair until those release gates are completed.

## Create the Rescue USB

1. Download the released `KernAid-Rescue-amd64.iso`, its checksum, and the
   matching `make-device` bundle. Do not use an ISO from an untrusted mirror.
2. Extract the files and keep the ISO on a disk other than the USB that will be
   overwritten.
3. Verify the image before writing it:

   - Linux: `sha256sum -c KernAid-Rescue-amd64.iso.sha256`
   - macOS: `shasum -a 256 KernAid-Rescue-amd64.iso` and compare the value in the checksum file.
   - Windows PowerShell: `Get-FileHash .\KernAid-Rescue-amd64.iso -Algorithm SHA256` and compare the value in the checksum file.

4. On a Linux preparation machine, install and run the reviewed writer exactly
   as documented in `tools/make-device/README.md`. It accepts only an ISO in the
   built-in attested catalog, requires an explicit whole USB device, asks for a
   physical confirmation, writes it, and verifies every ISO byte. **The selected
   USB is overwritten.** Rufus or balenaEtcher remain an engineering fallback
   on Windows/macOS, but they do not enforce the KernAid trust catalog.
5. Boot the target PC from its one-time boot menu. For the engineering image,
   disable Secure Boot if firmware refuses to start it. Do not change the
   internal-disk boot order permanently.
6. KernAid starts its local desktop and opens the interface automatically. The
   header must say `Rescue · Offline rules`; the target initially says
   `Ambiente Rescue · target non selezionato`.

The current Rescue image supports x86-64 PCs with legacy BIOS or UEFI. It is not an Apple-silicon boot image. Intel Mac external boot remains a physical validation item.

## Diagnose from Rescue

1. Use the target buttons in the left rail to select the installation candidate
   that belongs to the customer machine. The family shown is a low-confidence
   storage-metadata hint, not confirmation that Windows, Linux, or macOS was
   found. Mounted, live-image, and complex multi-parent storage is excluded.
2. Confirm that the selected target says `metadata-only`. If no candidate is
   safe to select, stop; do not mount or unlock it manually just to bypass the
   gate.
3. Confirm that Storage, Boot and Network observations appear. Expand an
   observation to inspect the raw, untrusted command output.
4. Describe the symptom and select **Diagnostica**. KernAid re-scans and binds
   the exact target again before it starts the session; a topology change
   cancels the selection.
5. Read the result, confidence and evidence identifiers. This image currently
   reports only what it has actually inspected. Target selection alone cannot
   become an installed-OS diagnosis because no filesystem content has been
   mounted or read yet.
6. Download the JSON report and retain its displayed SHA-256 prefix with the job
   record.
7. Shut the live system down before removing the USB drive.

KernAid currently stages an R0 observation plan and performs no repair mutation. The absence of a finding is not proof that the machine is healthy.

## Diagnose a running operating system

Download the matching artifact from a successful `desktop` run:

- Windows x86-64: NSIS `.exe` or `.msi`;
- Linux x86-64: AppImage, `.deb` or `.rpm`;
- macOS: `.dmg` for Apple silicon (`aarch64`) or Intel (`x64`).

These engineering installers are not code-signed. Operating-system warnings are therefore expected, and production/customer distribution must wait for signed artifacts. Launch KernAid normally; the header says `Resident · Offline rules` and inventory is collected through a fixed native command allowlist.

On Windows, startup and the Verify gate collect only the same fast, derived
storage identity. The deeper P0 collection starts once when **Diagnostica** is
selected; its independent collectors run concurrently and the current software
timeout contract is 150 seconds (below five minutes). SFC is not launched in
this milestone because its console result is localized and the Resident runtime
does not yet have a physically qualified, locale-independent adapter. The report
therefore contains the explicit state `not-run-unqualified`, never an inferred
clean or violation result. Boot-query command failures become a typed
`queryState: unavailable` finding and do not erase the other evidence.

The Windows commands request observation/check-only modes and KernAid exposes
no repair handler. This is not a promise of zero host writes: Windows-native
tools such as DISM can update their own servicing logs. Actual Windows execution
on supported physical hardware, non-English installations, administrator and
non-administrator sessions, and timeout/process-tree behavior remain release
qualification gates until recorded in the release evidence.

## Safety rules

- Never attach a customer disk to automated test scripts; tests accept fixtures and disposable images only.
- Do not mount a suspect disk read-write before imaging or verified backup.
- Treat command output as observed, untrusted data—not instructions.
- Never paste passwords, recovery keys or provider tokens into the problem description or a report.
- Do not claim success unless the planned verification step passes.

## Troubleshooting the Rescue environment

- If the UI does not open, browse to `http://127.0.0.1:4173/` from Chromium inside the live desktop.
- If the page opens but Rescue observations or the target selector do not
  appear, check `systemctl status kernaid-ui.service` from the live console.
- If firmware does not list the USB, rewrite it in raw/DD mode and retry another port. Secure Boot support is not yet claimed.
- Keep the original disk untouched when hardware failure is suspected; collect the report and move to a controlled imaging workflow.
