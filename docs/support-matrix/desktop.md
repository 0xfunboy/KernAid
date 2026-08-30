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
[workflow run 33306689037, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306689037)
from commit
[`64db3bcf4050df01e96e1b55e08750b6957df801`](https://github.com/0xfunboy/KernAid/commit/64db3bcf4050df01e96e1b55e08750b6957df801).
That run used Node.js 24.18.0, contains the matching exact local pin and
successfully produced both Windows installers with Tauri's embedded offline
WebView2 installer mode. Every platform job also passed the packaged-output
gate proving that the diagnosis-only Desk bundles exclude the repair UI and
the separately distributed credential companion. Where the table says
runtime-probed, the packaged native first-launch bootstrap also passed in an
isolated temporary profile; this is not a complete installed-GUI test.

| Platform target | Produced packages | Strongest current evidence | Exact evidence | Physical status |
| --- | --- | --- | --- | --- |
| Linux x86-64 | AppImage, DEB, RPM | Runtime-probed, partial | [Linux job 99244403899](https://github.com/0xfunboy/KernAid/actions/runs/33306689037/job/99244403899) built all packages, exercised the production normalized-snapshot command through Tauri IPC on Ubuntu 24.04, passed the packaged native bootstrap and verified that packages exclude repair UI and the credential companion. It did not install and launch every package format on representative hardware. | Not qualified |
| Windows x86-64 | MSI, NSIS | Runtime-probed, partial; offline runtime bundled | [Windows job 99244403895](https://github.com/0xfunboy/KernAid/actions/runs/33306689037/job/99244403895) built both installers with Tauri `offlineInstaller` WebView2 mode, passed the packaged native bootstrap and credential-boundary tests, and verified package exclusions. It did not run the complete native Windows P0 collector set or install and exercise the GUI on representative hardware. | Not qualified |
| macOS Apple silicon | APP, DMG | Runtime-probed, partial | [Apple-silicon job 99244403896](https://github.com/0xfunboy/KernAid/actions/runs/33306689037/job/99244403896) built both packages, ran the native macOS P0 source probe, passed the packaged native bootstrap and verified package exclusions on the hosted runner. It did not install the DMG on representative hardware. | Not qualified |
| macOS Intel x86-64 | APP, DMG | Build-only | [Intel job 99244403904](https://github.com/0xfunboy/KernAid/actions/runs/33306689037/job/99244403904) cross-built both packages and verified package exclusions. The native first-launch and collector probes were skipped for this cross-built target. | Not qualified |

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
  `33306689037` proves successful MSI and NSIS packaging and an isolated native
  bootstrap with that configuration; it does not prove installation or first
  launch on representative hardware.
- All four platform jobs in workflow run `33306689037` attempt 1 passed the
  packaged-output gates that reject repair UI and the separately distributed
  credential companion from the diagnosis-only Desk artifacts.
- Optional Resident OpenAI setup still uses the separately distributed native
  credential companion documented in the operator guide.

Use [Current status](../CURRENT_STATUS.md) for the overall product boundary and
the [operator guide](../operator-guide.md#diagnose-a-running-operating-system)
for the engineering-preview installation procedure.
