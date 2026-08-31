# KernAid Desk support matrix

Last reviewed: 31 August 2026

This page records what the current Desk evidence proves. It is intentionally
narrower than the product vision in the masterplan. KernAid Desk remains an
unsigned, diagnosis-only engineering preview; none of the rows below is a
production support claim.

## Evidence levels

- **Build-only**: the application and installer were produced by the named
  GitHub-hosted runner. This does not prove that the installed application
  starts or that native collectors work.
- **Runtime-probed**: a bounded production native command or collector path ran
  on the named GitHub-hosted runner. This does not qualify the complete
  installer, representative customer hardware or every OS version.
- **Physical**: the packaged application was installed and its documented flow
  was recorded on representative non-CI hardware. No Desk target currently has
  this evidence level.

## Current matrix

The latest successful Desk packaging evidence reviewed here is
[workflow run 33330140025, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33330140025)
from commit
[`5db47001fad2a3814d90837bcdcea545b2da0fa9`](https://github.com/0xfunboy/KernAid/commit/5db47001fad2a3814d90837bcdcea545b2da0fa9).
Those exact diagnosis-only packages are published in immutable internal release
[`0.1.0-internal.6`](https://github.com/0xfunboy/KernAid/releases/tag/kernaid-internal-v0.1.0-internal.6).
That run used Node.js 24.18.0, contains the matching exact local pin and
successfully produced both Windows installers with Tauri's embedded offline
WebView2 installer mode. Every platform job also passed the packaged-output
gate proving that the diagnosis-only Desk bundles exclude the repair UI and
the separately distributed credential companion. Where the table says
runtime-probed, the packaged native first-launch bootstrap also passed in an
isolated temporary profile; this is not a complete installed-GUI test.

| Platform target     | Produced packages  | Strongest current evidence                       | Exact evidence                                                                                                                                                                                                                                                                                                                                                                                                   | Physical status |
| ------------------- | ------------------ | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| Linux x86-64        | AppImage, DEB, RPM | Runtime-probed, partial                          | [Linux job 99307145731](https://github.com/0xfunboy/KernAid/actions/runs/33330140025/job/99307145731) built all packages, exercised the production normalized-snapshot command through Tauri IPC on Ubuntu 24.04, passed the packaged native bootstrap and verified that packages exclude repair UI and the credential companion. It did not install and launch every package format on representative hardware. | Not qualified   |
| Windows x86-64      | MSI, NSIS          | Runtime-probed, partial; offline runtime bundled | [Windows job 99307145747](https://github.com/0xfunboy/KernAid/actions/runs/33330140025/job/99307145747) built both installers with Tauri `offlineInstaller` WebView2 mode, passed the packaged native bootstrap and credential-boundary tests, and verified package exclusions. It did not run the complete native Windows P0 collector set or install and exercise the GUI on representative hardware.          | Not qualified   |
| macOS Apple silicon | APP, DMG           | Runtime-probed, partial                          | [Apple-silicon job 99307145722](https://github.com/0xfunboy/KernAid/actions/runs/33330140025/job/99307145722) built both packages, ran the native macOS P0 source probe, passed the packaged native bootstrap and verified package exclusions on the hosted runner. It did not install the DMG on representative hardware.                                                                                       | Not qualified   |
| macOS Intel x86-64  | APP, DMG           | Build-only                                       | [Intel job 99307145724](https://github.com/0xfunboy/KernAid/actions/runs/33330140025/job/99307145724) cross-built both packages and verified package exclusions. The native first-launch and collector probes were skipped for this cross-built target.                                                                                                                                                          | Not qualified   |

No Windows ARM, Linux ARM or 32-bit Desk artifact is currently produced. The
rolling `windows-latest` and `macos-latest` runner labels are build environments,
not a declaration that every corresponding OS release is supported. Minimum
Windows, Linux distribution and macOS version ranges remain unqualified until
they are pinned and backed by installation/runtime evidence.

## Linux storage-health boundary

Linux Resident and Rescue now share one read-only SMART/NVMe collector. It
reports only normalized `disk-N` references, overall health, critical warning,
media errors, temperature, spare and wear when the device exposes them. Its
closed states are `healthy`, `degraded`, `failing`, `unsupported` and
`permission-unavailable`; missing tools or permissions never become a healthy
result. Failing and degraded states recommend backup and physical replacement,
not a software repair.

The Rescue profile contains `smartmontools` and `nvme-cli`; Resident degrades
gracefully when either is absent. Fixture/unit evidence covers healthy,
failing, malformed and unavailable responses. Physical SATA, USB bridge and
NVMe compatibility is still **not qualified**, so this is an implemented
engineering-preview capability rather than a production support claim.

## Linux filesystem-health boundary

Linux Resident and Rescue share a fixed read-only filesystem checker for ext4
and NTFS. Resident can inspect only its mounted root and therefore reports a
clean check as `degraded` until it is repeated offline. Rescue revalidates the
selected normalized target and checks only an unmounted block device. No
filesystem is mounted or changed; ext4 uses `e2fsck -f -n` and NTFS uses
`ntfsfix -n` (no action). Results are limited to `healthy`, `degraded`,
`repair-required`, or `unsupported`, with fixed next actions and no file names,
device paths, tool output, or user content.

The Rescue image packages both fixed tools and has a readiness contract for
the normalized collector. Unit/static evidence covers normalized healthy,
repair-required, unavailable, malformed, and identity-bound paths. Physical
filesystem and power-loss matrices are still **not qualified**.

The private Repair candidate additionally contains one R3 ext4 preen action.
It is restricted to an unmounted, descriptor-bound selected target, requires a
distinct authenticated Vault evidence record and typed single-use approval,
and keeps `e2fsck` plus raw block authority inside the root helper. Its e2undo
stream is same-boot only and is not a full backup or power-loss-safe rollback;
ambiguous state stops for manual reconciliation. This candidate is **not
qualified, promoted, or present in stable images**. NTFS remains read-only.

## Current product boundary

- Offline deterministic diagnosis is the default path. Production Resident
  builds expose no host mutation handler.
- Windows, Linux and macOS installers are not code-signed; macOS packages are
  not notarized.
- The Windows bundle embeds the WebView2 offline installer. Workflow run
  `33330140025` proves successful MSI and NSIS packaging and an isolated native
  bootstrap with that configuration; it does not prove installation or first
  launch on representative hardware.
- All four platform jobs in workflow run `33330140025` attempt 1 passed the
  packaged-output gates that reject repair UI and the separately distributed
  credential companion from the diagnosis-only Desk artifacts.
- Optional Resident OpenAI setup still uses the separately distributed native
  credential companion documented in the operator guide.

Use [Current status](../CURRENT_STATUS.md) for the overall product boundary and
the [operator guide](../operator-guide.md#diagnose-a-running-operating-system)
for the engineering-preview installation procedure.
