# Physical USB qualification

This runbook records one controlled physical boot of a virtually qualified
KernAid Rescue image. It does not turn one PC or USB drive into a general
hardware, firmware, Secure Boot, repair, or production support claim.

## Select the exact image

Use only the physical-test candidate currently named in
[`CURRENT_STATUS.md`](../CURRENT_STATUS.md). Open its
`KernAid-Rescue-amd64.qualified.json` and record these exact values before
writing the USB:

- `artifactVersion`;
- `source.commit`, `source.workflowRunId`, and `source.workflowRunAttempt`;
- `artifacts.retailImage.name`, `bytes`, and `sha256`;
- the qualification-manifest SHA-256 reported by the qualified workflow or
  Release Channel.

Stop if the candidate, digest, run, or attempt differs from
`CURRENT_STATUS.md`, if the Rescue workflow was not completely successful, or
if only an intermediate ISO artifact is available. On Windows, this procedure
uses the qualified retail `.img.xz`, not the ISO.

## Prepare the USB on Windows

1. Use a factory-new or disposable USB whose usable capacity exceeds the
   expanded size recorded by the qualified retail metadata. A nominal 64 GB
   drive is recommended for the current 32,000,000,000-byte layout. Disconnect
   irreplaceable, customer, and unrelated external drives where practical.
2. Verify the downloaded retail image in PowerShell, substituting the exact
   manifest filename:

   ```powershell
   Get-FileHash -LiteralPath '.\<qualified-retail-image>.img.xz' -Algorithm SHA256
   ```

   Require an exact match with both the adjacent checksum and
   `artifacts.retailImage.sha256`.
3. Select that `.img.xz` in a current Rufus, double-check the target USB, and
   choose raw/DD mode if Rufus asks. **balenaEtcher is not qualified for this
   procedure.**
4. Until `CURRENT_STATUS.md` explicitly records physical Secure Boot support,
   disable Secure Boot and use the firmware one-time boot menu rather than
   changing permanent boot order.

Rufus overwrites the bytes represented by the retail image; this is not a
whole-media sanitization procedure for a larger drive.

## Record without collecting secrets

Create one test record containing:

- date, tester, exact release/run/attempt/commit, retail filename, byte size,
  SHA-256, qualification-manifest SHA-256, Rufus version, and `DD` mode;
- USB make, marketed capacity, and port type only;
- PC vendor/model, CPU and GPU model, RAM, firmware vendor/version and boot
  mode, Secure Boot state, display connection/resolution, and wired/Wi-Fi
  result;
- boot entry, elapsed time to the UI, and the outcome fields in the rubric
  below.

Prefer the normalized **Hardware** evidence shown by KernAid for machine facts.
Do not record or photograph hardware serial numbers, service tags, USB serials,
MAC addresses, customer filenames, recovery keys, provider credentials, or the
Vault passphrase. Do not photograph the screen while a secret is being typed.

Use this compact record shape so separate machines remain comparable:

```text
candidate: release= run= attempt= commit= manifest_sha256=
retail: filename= bytes= sha256=
writer: rufus_version= mode=DD usb_make= capacity= port_type=
machine: vendor_model= cpu= gpu= ram= firmware= boot_mode= secure_boot=
display: connection= resolution= normal= compatibility= time_to_ui=
observed: hardware= storage= boot= network= target_selector= keyboard= mouse=
vault: boot1_state= boot1_device_id= boot2_state= boot2_device_id= stable=
diagnosis: result= evidence_ids= report_persistence=
overall: result= notes=
```

## Execute the shortest complete test

1. Start with the normal branded **KernAid Rescue** entry. Photograph the
   branded boot menu without including device serial labels.
2. On a new retail USB, enter a new Vault passphrase twice on `tty1`. Keep it
   private. Allow up to five minutes after provisioning for the graphical path
   to become ready.
3. Require the complete KernAid UI to paint, not merely a black desktop and
   movable pointer. Prove both mouse and keyboard input by changing focus or
   selection. Record whether Hardware, Storage, Boot, Network, and the target
   selector appear.
4. If a safe installed-system candidate is offered, select only that candidate
   and run one offline **Diagnostica** session. Record its terminal result and
   evidence identifiers. Do not claim a persistent signed report unless the
   Vault was unlocked before that Desk session initialized. Do not mount
   anything manually to bypass selection, configure a provider account, or
   attempt a repair. If no target is safely selectable, record
   `diagnosis=not-tested-no-safe-target`; do not convert that into a diagnosis
   pass or a display failure.
5. From a native live console, unlock the Vault locally, query it, and close it
   again. Type the passphrase only at its hidden prompt:

   ```text
   kernaid-rescue-vaultctl unlock
   kernaid-rescue-vaultctl status
   kernaid-rescue-vaultctl lock
   ```

   Record only the `vaultState: unlocked` result and the KernAid `deviceId`.
   Shut down cleanly.
6. Boot the same USB a second time with the same boot entry. Require the UI and
   input checks to pass again, repeat the unlock/status/lock sequence, and
   require the same `deviceId`. Shut down before removing the USB.

The Network result is an observation, not a prerequisite for the default
offline diagnosis path. A report from a physical test may support only the
specific machine, firmware mode, boot entry, display, USB, and functions that
were actually exercised.

## Black-screen evidence and compatibility entry

If the normal entry still shows a black frame, blank frame, frozen renderer, or
only a movable pointer after five minutes:

1. Record `normal-display=failed`, elapsed time, whether KernAid branding and
   the first-boot prompt appeared, whether the pointer moves, and a photo of the
   failed display containing no sensitive data.
2. Switch to a native live console if available and capture these bounded
   diagnostics:

   ```text
   cat /proc/cmdline
   systemctl --no-pager --full status display-manager.service kernaid-rescue-ui-session-ready.service kernaid-ui.service kernaid-rescue-desk-shell.service kernaid-ready.service
   ```

   Do not publish unexpected sensitive text; retain only the kernel command
   line and each unit's active/sub state when in doubt.
3. Reboot without rewriting the USB and select **KernAid Rescue - Compatibility
   graphics**. Confirm that `/proc/cmdline` contains `nomodeset`, then repeat
   the UI, input, Vault identity, and optional diagnosis checks. If it works,
   boot the compatibility entry once more and repeat its UI/input and Vault
   identity checks. Do not call a compatibility-only result a pass for the
   normal graphics path.

## Result rubric

| Recorded result | Required evidence |
| --- | --- |
| `normal-path=pass` | Exact image/checksum evidence; normal entry; branded boot; fully painted UI; mouse and keyboard response on both boots; successful Vault provisioning; identical `deviceId` on boot two. Record diagnosis separately as pass, fail, or not tested. |
| `compatibility-path=pass-only` | Normal graphics is recorded failed with bounded diagnostics; the `nomodeset` entry satisfies every boot, UI, input, and two-boot Vault requirement. Normal graphics remains failed on this machine. |
| `physical-test=failed` | Both entries are unusable, or provisioning, UI/input, clean second boot, or Vault identity persistence fails. Preserve the bounded failure evidence and do not promote a support claim. |
| `physical-test=incomplete` | Exact manifest/checksum evidence, the second boot, required observations, or failure diagnostics are missing. Repeat only the missing safe step. |

One passing record closes only this controlled retest. Expanding a support
claim requires the physical hardware matrix and release gates listed in
`CURRENT_STATUS.md`.
