# KernAid workshop operator guide

This guide describes the intended engineering-preview workflow. KernAid must
not be represented as supporting physical Rescue media, Secure Boot or
unattended repair until those release gates are completed.

## Create the Rescue USB

This procedure is currently suspended: the checked-in v1 entry is historical
and its GitHub artifact is no longer downloadable, while the v2 catalog
authorizes no image. Do not substitute an unpromoted workflow artifact. Resume
these steps only after an exact Rescue image and matching writer bundle are
explicitly promoted.

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
   USB is overwritten.** Do not substitute Rufus, balenaEtcher, or another
   writer: they do not enforce the KernAid trust catalog.
5. Attempt to boot the target PC from its one-time boot menu. The current boot
   evidence is QEMU-only; physical USB and firmware compatibility are not yet
   qualified. For the engineering image, disable Secure Boot if firmware
   refuses to start it. Do not change the internal-disk boot order permanently.
6. On a successful boot, KernAid starts its local desktop and opens the
   interface automatically. The
   header must say `Rescue · Offline rules`; the target initially says
   `Ambiente Rescue · target non selezionato`.

The current Rescue image targets amd64 legacy BIOS and UEFI. Its current boot
evidence is QEMU-only; physical PCs, firmware and USB media are unqualified. It
is not an Apple-silicon boot image, and Intel Mac external boot remains a
physical validation item.

## Diagnose from Rescue

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
6. Download the JSON report and retain its displayed SHA-256 prefix with the job
   record.
7. Shut the live system down before removing the USB drive.

The Windows EFI result contains only presence booleans for BCD, Windows Boot
Manager, and the x86-64 fallback loader. It contains no discovered filenames,
directory listings, bytes, device identifiers, or customer paths. KernAid
currently stages an R0 observation plan and performs no repair mutation. The
absence of a finding is not proof that the machine is healthy.

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
physical-media behavior remain external release gates. The automated QEMU gate
uses the real pinned CLI only for offline signed-out status and does not create
an account session.

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
UI-server relay, but an exact revision is virtually qualified only after both
privileged BIOS and UEFI lifecycle jobs pass. The active physical writer v1
does not create that vault, and Chromium rendering, live provider TLS with a
real account, and physical media are not qualified; do not present Rescue
OpenAI as supported on customer media yet. The Resident credential companion
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

- If the UI does not open, browse to `http://127.0.0.1:4173/` from Chromium
  inside the live desktop. This is a troubleshooting step, not browser-renderer
  qualification.
- If the page opens but Rescue observations or the target selector do not
  appear, check `systemctl status kernaid-ui.service` from the live console.
- If firmware does not list the USB, rewrite it in raw/DD mode and retry another port. Secure Boot support is not yet claimed.
- Keep the original disk untouched when hardware failure is suspected; collect the report and move to a controlled imaging workflow.
