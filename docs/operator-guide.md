# KernAid workshop operator guide

This guide describes the intended engineering-preview workflow. KernAid must
not be represented as supporting physical Rescue media, Secure Boot or
unattended repair until those release gates are completed.

## Create the Rescue USB

There is currently no physically qualified release. The private project area
exposes one exact internally qualified candidate from commit `015ee8f` to
collect the first physical-boot evidence. Its exact version, size, workflow
and SHA-256 are recorded in `CURRENT_STATUS.md`; do not substitute another
Actions artifact or an image from a mirror.

Trusted catalog v2 revision 3 authorizes only this exact ISO after its complete
virtual BIOS/UEFI workflow passed. The Linux v2 writer can therefore verify,
copy and provision its encrypted vault. The Windows procedure below remains a
raw physical boot test. The currently promoted `015ee8f` candidate predates the
in-guest first-boot provisioner; do not expect that older image to create a
Vault after Rufus writes it.

The Rescue build target is amd64 legacy BIOS and UEFI. Its boot evidence is
QEMU-only; physical PCs, firmware and USB media are unqualified. It
is not an Apple-silicon boot image, and Intel Mac external boot remains a
physical validation item.

### Rescue qualification manifest v1

On the protected `main` branch, the `rescue` workflow publishes
`KernAid-Rescue-amd64-qualified` only after the image build/smoke job and both
isolated BIOS and UEFI two-boot Vault lifecycle jobs succeed. The core bundle
contains the exact ISO, checksum, catalog-v2 entry, retail checksum/layout and
attestation metadata, pinned-Codex SBOM tranche and the evidence files. The
compressed 32,000,000,000-byte Windows retail raw image is published as the
separate `KernAid-Rescue-amd64-qualified-retail` artifact. Its canonical
`KernAid-Rescue-amd64.qualified.json` binds the source commit, workflow run and
attempt, artifact version, ISO and retail-image sizes and SHA-256 values, the
raw-image and zero-p3 binding, and the SHA-256 of every
catalog, SBOM and evidence input. This is virtual qualification only; it does
not satisfy the physical-machine or Secure Boot gates.

GitHub signs standard ISO build provenance and custom Sigstore attestations for
both the ISO and retail image whose predicate is that exact manifest. The core
artifact contains the returned bundles under deterministic names.
With a current GitHub CLI that supports `gh attestation`, verify the repository
and signing workflow before trusting the files. The custom qualification
predicate contains a URL fragment, so verify its downloaded bundle directly
instead of relying on an API predicate lookup:

```bash
gh attestation verify KernAid-Rescue-amd64.iso \
  -R 0xfunboy/KernAid \
  --signer-workflow 0xfunboy/KernAid/.github/workflows/rescue.yml \
  --source-ref refs/heads/main

gh attestation verify KernAid-Rescue-amd64.iso \
  -R 0xfunboy/KernAid \
  --bundle KernAid-Rescue-amd64.qualification.sigstore.json \
  --signer-workflow 0xfunboy/KernAid/.github/workflows/rescue.yml \
  --source-ref refs/heads/main \
  --predicate-type \
  'https://github.com/0xfunboy/KernAid/blob/main/docs/operator-guide.md#rescue-qualification-manifest-v1'

gh attestation verify KernAid-Rescue-amd64-retail.img.xz \
  -R 0xfunboy/KernAid \
  --bundle KernAid-Rescue-amd64-retail.qualification.sigstore.json \
  --signer-workflow 0xfunboy/KernAid/.github/workflows/rescue.yml \
  --source-ref refs/heads/main \
  --predicate-type \
  'https://github.com/0xfunboy/KernAid/blob/main/docs/operator-guide.md#rescue-qualification-manifest-v1'
```

Then compare `KernAid-Rescue-amd64.iso` with its `.sha256` file. A build-only
`KernAid-Rescue-amd64` artifact is an intermediate input, not the qualified
release bundle.

### Windows: physical boot qualification only

For workflow releases whose qualification manifest contains `retailImage`, use
`KernAid-Rescue-amd64-retail.img.xz` directly with a current Rufus in raw/DD
mode and verify its adjacent checksum first. The compressed image expands to
exactly 32,000,000,000 bytes and carries an all-zero p3 for first-boot Vault
provisioning; its manifest records the compressed, expanded and p3 digests.

Use only the exact private candidate identified in `docs/CURRENT_STATUS.md`.
This checks the candidate on real hardware; it does not promote the release.
Completing first boot creates a local encrypted Vault on that disposable USB,
but one successful device does not qualify every USB or firmware combination.

1. Use a factory-new or disposable USB drive of at least 32 GB. Rufus overwrites
   the first 32,000,000,000 bytes, but a larger device may retain data beyond
   that boundary; this procedure is not whole-media sanitization.
2. Verify the downloaded `.img.xz` in PowerShell with
   `Get-FileHash .\KernAid-Rescue-amd64-retail.img.xz -Algorithm SHA256` and
   compare the complete digest with its adjacent `.sha256` file and the exact
   value in the qualification manifest.
3. Write that exact `.img.xz` with Rufus. If Rufus offers a mode choice, choose
   raw/DD mode. Double-check the selected USB before starting.
4. For this engineering preview, disable Secure Boot. Disconnect customer,
   irreplaceable and unrelated data drives whenever practical, then use the
   firmware one-time boot menu rather than changing the permanent boot order.
5. On `tty1`, enter the new Vault passphrase twice, then confirm that the
   KernAid UI opens. Reboot the same USB once and verify that the same Vault
   identity persists. Record machine/firmware/network results and stop if the
   UI or expected read-only state is missing. Do not perform customer repairs
   from this qualification medium.

Rufus is preferred over balenaEtcher for this Windows qualification procedure
because it exposes the target and DD-mode choice clearly. The Linux v2 writer
is the catalog-bound vault-provisioning path for this exact promoted image.

The retail image guarantees that the boot medium's complete 8 GiB p3 starts in
the all-zero state. Boot pauses on tty1 before the graphical UI and asks for a
new Vault passphrase twice. Use at least 12 bytes and retain it: the passphrase
is not recoverable by KernAid. A matching entry provisions the canonical
encrypted Vault, closes it, verifies the locked state, and then lets normal
boot continue. An existing valid Vault or an optical boot does not prompt;
mixed/non-zero or failed media records a fail-closed error and still allows the
recovery UI to start. This path has no device selector and cannot be aimed at a
customer disk. It remains an engineering feature until the exact image passes
zero-p3 QEMU and physical USB qualification and is promoted in
`CURRENT_STATUS.md`.

## Diagnose from Rescue

Before Desk initializes, open a native TTY and unlock the writer-provisioned
Vault locally:

```text
kernaid-rescue-vaultctl status
kernaid-rescue-vaultctl unlock
```

The passphrase is read only from the controlling TTY. If Desk has already
initialized while the Vault was locked, unlock the Vault and reload Desk before
starting the session. A session begun with the fallback in-memory audit sink
cannot later be upgraded to persistent audit, and its report is not written to
the Vault.

1. Use the target buttons in the left rail to select the installation candidate
   that belongs to the customer machine. The family shown is a low-confidence
   storage-metadata hint, not confirmation that Windows, Linux, or macOS was
   found. Mounted, live-image, and complex multi-parent storage is excluded.
2. Confirm that the selected target says `metadata-only`. If no candidate is
   safe to select, stop; do not mount or unlock it manually just to bypass the
   gate.
3. Confirm that Hardware, Storage, Boot and Network observations appear. The
   Linux hardware document contains normalized public facts and an explicit
   status for CPU, memory, firmware/DMI, PCI and USB. It intentionally omits
   serial numbers, UUIDs, asset tags and bus addresses. Expand other
   observations only when the untrusted command output is needed for diagnosis.
4. Describe the symptom and select **Diagnostica**. KernAid re-scans and binds
   the exact target again before it starts the session; a topology change
   cancels the selection.
5. Read the result, confidence and evidence identifiers. This image currently
   reports only what it has actually inspected. Target selection alone remains
   metadata-only and cannot become an installed-OS diagnosis. **Diagnostica**
   may inspect a qualified direct leaf ext4 or NTFS target using a temporary
   read-only mount. Disks with any mounted descendant are not selectable. For
   an otherwise-selectable Windows target on GPT, KernAid inspects a separate
   EFI System Partition only when exactly one unmounted direct-sibling FAT
   partition has the standard ESP type; zero, multiple, or otherwise
   unqualified siblings produce `not-present`, `ambiguous`, or `unsupported`
   and make no boot-failure claim.
   Linux P0 snapshot parity v1 is root-filesystem-only in both Resident and
   Rescue. If `fstab` declares a separate mount at or below `/etc` (including
   `/etc/machine-id`), `/boot` (including `/boot/efi`), `/efi`, `/usr`, or
   `/var`, stop: KernAid reports the corpus as unsupported and blocks diagnosis.
   This release does not claim parity for multi-mount Linux installations.
6. On successful completion, Rescue persists the exact JSON report and its
   audit sequence in the encrypted Vault as a signed envelope. From a native
   TTY, list the available report IDs and export the selected envelope:

   ```text
   kernaid-rescue-vaultctl report-list
   kernaid-rescue-vaultctl report-export RP-...
   ```

   Export always uses the fixed path
   `/home/kernaid/KernAid-Reports/<id>.signed.json`. The directory is private,
   the file is mode `0600`, publication is atomic, and an existing filename is
   never overwritten. The companion accepts a canonical `RP-...` identifier,
   not a caller-selected path. Copy that exported file to the intended exchange
   medium only after checking the reported envelope SHA-256.
7. Shut the live system down before removing the USB drive.

The Windows EFI result contains only presence booleans for BCD, Windows Boot
Manager, and the x86-64 fallback loader. It contains no discovered filenames,
directory listings, bytes, device identifiers, or customer paths. KernAid
currently stages an R0 observation plan and performs no repair mutation. The
absence of a finding is not proof that the machine is healthy.

The graphical application reaches report persistence only through a bounded
same-origin loopback HTTP-to-AF_UNIX relay. That endpoint is internal to the
Rescue image; it is not a public or remotely supported API. The exact current
candidate passed signed-report persistence, retrieval and fixed-path export on
the same shipping image under virtual BIOS and UEFI. Physical USB behavior and
recovery remain separate gates.

### Codex account bootstrap in an engineering Rescue image

The image contains a bounded authentication bridge for the pinned official
Codex CLI. It is not a Codex diagnosis executor: it accepts no prompt, model,
path, command, API key, or broker operation. Use it only on a vault provisioned
by the matching v2 writer and only after the vault is unlocked locally:

```text
kernaid-rescue-vaultctl status
kernaid-rescue-vaultctl unlock
kernaid-codex-auth status
kernaid-codex-auth device-login
kernaid-codex-auth logout
```

`unlock` reads the vault passphrase from the controlling TTY. `device-login`
runs exactly `codex login --device-auth`; open only the displayed
`https://auth.openai.com/codex/device` URL and enter its one-time code. Status
returns only the authentication kind or signed-out state. Logout runs exactly
`codex logout` and removes state through the CLI itself. Do not run the private
`/usr/lib/kernaid/codex` binary directly.

The CLI owns `auth.json` inside its mode-0700 home on the encrypted vault.
KernAid validates only file metadata and never reads, copies, prints, or places
that file in reports. Operations are one-shot and bounded; locking/stopping the
vault revokes the complete service cgroup. A successful real-account device
login, provider terms/entitlement, outbound authentication connectivity, and
physical-media behavior remain external release gates. The automated BIOS and
UEFI lifecycle gates passed the real pinned CLI's offline signed-out status
path and do not create an account session.

## Diagnose a running operating system

Download the matching artifact from a successful `desktop` run:

- Windows x86-64: NSIS `.exe` or `.msi`;
- Linux x86-64: AppImage, `.deb` or `.rpm`;
- macOS: `.dmg` for Apple silicon (`aarch64`) or Intel (`x64`).

These engineering installers are not code-signed. Operating-system warnings are therefore expected, and production/customer distribution must wait for signed artifacts. Launch KernAid normally; the header says `Resident · Offline rules` and inventory is collected through a fixed native command allowlist.

On Linux, the Hardware observation is produced by the same no-argument Rust
collector shipped in Rescue. CPU and RAM come from bounded `/proc` reads;
firmware/DMI, PCI and USB come from fixed `/sys` locations. Only normalized
model/class/vendor/product facts cross the UI boundary. A partial, changing or
unavailable kernel source remains visible as a non-complete source status and
is not treated as a clean hardware diagnosis.

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

On macOS, startup and the Verify gate collect a normalized system-version and
storage identity. **Diagnostica** then runs the bounded read-only P0 collectors
in parallel and rejects the session if storage identity changes. The current
user's `launchd` table comes only from fixed `/bin/launchctl list`; system-domain
services are explicitly `not-run-unqualified`. KernAid does not invoke
`softwareupdate`, interpret its potentially stale preferences cache, or equate
process-name log lines with incidents. Update availability and system-event
counts therefore remain explicit limitation findings with no inferred zero.
Startup qualifies only numeric `kern.safeboot`; KernAid does not invoke the
human-readable `sfltool dumpbtm`, so login-item and background-item counts are
also explicit `not-run-unqualified` limitations with `null` values.
Physical Intel/Apple-silicon qualification and signing/notarization are still
release gates.

### Optional OpenAI diagnosis in Resident mode

The supported workshop procedure in this section is Resident-only. Rescue
contains feature-gated persistent-vault OpenAI plumbing and a loopback
UI-server relay. The current exact candidate passed the full virtual workflow,
including both privileged BIOS and UEFI lifecycle jobs, and trusted catalog v2
revision 3 authorizes that ISO. Physical media and live provider TLS with a
real account are still not qualified. Do not present Rescue OpenAI as supported
on customer media yet. The Resident credential companion
is not included in the desktop installer and is not added to `PATH`. From the
same successful Desktop workflow run, download and extract
the outer GitHub artifact matching the installed Desk build:

- `kernaid-provider-key-windows-x86_64` contains
  `kernaid-provider-key.exe`;
- `kernaid-provider-key-linux-x86_64` contains
  `kernaid-provider-key-linux-x86_64.tar.gz`;
- `kernaid-provider-key-macos-aarch64` contains
  `kernaid-provider-key-macos-aarch64.tar.gz`;
- `kernaid-provider-key-macos-x86_64` contains
  `kernaid-provider-key-macos-x86_64.tar.gz`.

On Linux or macOS, unpack the inner archive; it preserves the companion as an
owner-only executable:

```text
Linux x86_64: tar -xzf kernaid-provider-key-linux-x86_64.tar.gz
Apple silicon: tar -xzf kernaid-provider-key-macos-aarch64.tar.gz
Intel macOS: tar -xzf kernaid-provider-key-macos-x86_64.tar.gz
```

Close KernAid Desk, open a native terminal in the extracted directory, and
run the applicable command:

```text
Windows: .\kernaid-provider-key.exe configure
Linux/macOS: ./kernaid-provider-key configure
```

Enter the API key twice at the hidden TTY prompts. The companion rejects keys
from command-line arguments, redirected standard input, files and environment
variables. It stores the key under the public `resident-default` profile in
Windows Credential Manager, macOS Keychain or Linux Secret Service; no
plaintext fallback exists. `kernaid-provider-key status` reports only
`configured` or `absent`. Close Desk before running either companion command,
because Desk and the companion share an exclusive provider-store lock. The
companion accepts no data-directory override, and changing `HOME`, XDG or
`APPDATA` cannot create a second lock for the same OS-user provider profile.

Restart Desk and select **OpenAI** in the header. Selection is explicit:
KernAid starts with **Offline** rules even when a key exists and never silently
falls back or resubmits context to another provider. The backend sends one
bounded HTTPS request to `https://api.openai.com/v1/responses` using the fixed
`gpt-5.6-sol` profile, `store: false`, no tools, and a strict diagnosis-only
JSON schema. Reasoning effort is fixed to `medium`, the combined reasoning and
answer budget is 4,096 tokens, and the request fails closed after 60 seconds
(with a 10-second connection bound). Before any network request, the native
backend requires the exact complete OS-specific corpus, verifies each content
hash, and parses it with the strict local diagnostic pack. Raw collector
content, targets and summaries never enter provider context: OpenAI receives
only the provider-neutral deterministic proposal, minimized evidence
ID/collector metadata and the bounded objective after conservative
pattern-based filtering for common secrets, emails, network addresses and
paths. This filtering cannot guarantee removal of names or arbitrary personal
text. Desk shows that limitation before diagnosis; technicians must keep names,
document text and other customer identifiers out of the objective. This
milestone does not yet provide a context-preview screen. Observations remain
marked `observed-untrusted`; the response can only propose a diagnosis bound to
existing evidence identifiers and cannot invoke a repair or the broker.

Select **Logout** in the header to cancel any active provider request, remove
the selected key idempotently, verify its absence, and return to Offline rules.
If the keyring, network, timeout or provider response fails, the cloud request
fails closed while Offline diagnostics remain selectable. Provider use sends
diagnostic data to OpenAI under the technician's own account and terms; review
customer authorization and applicable data-processing requirements first.

## Safety rules

- Never attach a customer disk to automated test scripts; tests accept fixtures and disposable images only.
- Do not mount a suspect disk read-write before imaging or verified backup.
- Treat command output as observed, untrusted data—not instructions.
- Never paste passwords, recovery keys or provider tokens into the problem description or a report.
- Do not claim success unless the planned verification step passes.

## Troubleshooting the Rescue environment

- If the UI does not open, do not install or launch a browser fallback. From the
  live console check `systemctl status kernaid-ui.service`, then
  `systemctl status kernaid-rescue-desk-shell.service`. The latter is the
  unprivileged, restart-bounded owner of
  `/usr/bin/kernaid-rescue-desk-shell`; there is no desktop-file or browser
  fallback. Rescue readiness fails closed unless that shell, its WebKit
  renderer and its visible window are all present.
- If the page opens but Rescue observations or the target selector do not
  appear, check `systemctl status kernaid-ui.service` from the live console.
- During the controlled qualification of the exact private candidate, if
  firmware does not list the USB, rewrite the same verified image in raw/DD
  mode and retry another port. See [Current status](CURRENT_STATUS.md) for the
  exact candidate; this does not promote it. Secure Boot support is not yet
  claimed.
- Keep the original disk untouched when hardware failure is suspected; collect the report and move to a controlled imaging workflow.
