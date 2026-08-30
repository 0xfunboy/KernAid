# KernAid Desk support matrix

Last reviewed: 30 August 2026

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
[workflow run 33298930980](https://github.com/0xfunboy/KernAid/actions/runs/33298930980)
from commit
[`ff0b99a408faee88499d02a27095cc97dc95310e`](https://github.com/0xfunboy/KernAid/commit/ff0b99a408faee88499d02a27095cc97dc95310e).
That run used Node.js 24.18.0, contains the matching exact local pin and
successfully produced both Windows installers with Tauri's embedded offline
WebView2 installer mode. Every platform job also passed the packaged-output
gate proving that the diagnosis-only Desk bundles exclude the repair UI.

| Platform target | Produced packages | Strongest current evidence | Exact evidence | Physical status |
| --- | --- | --- | --- | --- |
| Linux x86-64 | AppImage, DEB, RPM | Runtime-probed, partial | [Linux job 99223312448](https://github.com/0xfunboy/KernAid/actions/runs/33298930980/job/99223312448) built all packages, exercised the production normalized-snapshot command through Tauri IPC on Ubuntu 24.04 and verified the packaged Desk excludes repair UI. It did not install and launch every package format. | Not qualified |
| Windows x86-64 | MSI, NSIS | Build-only, offline runtime bundled | [Windows job 99223312527](https://github.com/0xfunboy/KernAid/actions/runs/33298930980/job/99223312527) built both installers with Tauri `offlineInstaller` WebView2 mode, exercised credential-boundary tests and verified the packaged Desk excludes repair UI. It did not run the native Windows P0 collector set or an installed-app smoke test. | Not qualified |
| macOS Apple silicon | APP, DMG | Runtime-probed, partial | [Apple-silicon job 99223312529](https://github.com/0xfunboy/KernAid/actions/runs/33298930980/job/99223312529) built both packages, ran the native macOS P0 source probe on the hosted runner and verified the packaged Desk excludes repair UI. It did not install the DMG on representative hardware. | Not qualified |
| macOS Intel x86-64 | APP, DMG | Build-only | [Intel job 99223312548](https://github.com/0xfunboy/KernAid/actions/runs/33298930980/job/99223312548) cross-built both packages and verified the packaged Desk excludes repair UI. Native runtime and collector probes were skipped for this target. | Not qualified |

No Windows ARM, Linux ARM or 32-bit Desk artifact is currently produced. The
rolling `windows-latest` and `macos-latest` runner labels are build environments,
not a declaration that every corresponding OS release is supported. Minimum
Windows, Linux distribution and macOS version ranges remain unqualified until
they are pinned and backed by installation/runtime evidence.

## Current product boundary

- Offline deterministic diagnosis is the default path. Production Resident
  builds expose no host mutation handler.
- Windows, Linux and macOS installers are not code-signed; macOS packages are
  not notarized.
- The Windows bundle embeds the WebView2 offline installer. Workflow run
  `33298930980` proves successful MSI and NSIS packaging with that configuration;
  it does not yet prove installation or first launch on representative hardware.
- All four jobs in workflow run `33298930980` passed the packaged-output gate
  that rejects repair UI from the diagnosis-only Desk artifacts.
- Optional Resident OpenAI setup still uses the separately distributed native
  credential companion documented in the operator guide.

Use [Current status](../CURRENT_STATUS.md) for the overall product boundary and
the [operator guide](../operator-guide.md#diagnose-a-running-operating-system)
for the engineering-preview installation procedure.
