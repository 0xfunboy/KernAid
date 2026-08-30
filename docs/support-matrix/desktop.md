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
[workflow run 33297179815](https://github.com/0xfunboy/KernAid/actions/runs/33297179815)
from commit
[`3f6c541bad66c399e9b6b4c8310057e810b7981c`](https://github.com/0xfunboy/KernAid/commit/3f6c541bad66c399e9b6b4c8310057e810b7981c).
The source changes that add the Windows offline WebView2 installer and exact
local Node.js pin postdate that run; they remain source-level changes until a
new Desktop run passes.

| Platform target | Produced packages | Strongest current evidence | Exact evidence | Physical status |
| --- | --- | --- | --- | --- |
| Linux x86-64 | AppImage, DEB, RPM | Runtime-probed, partial | [Linux job 99218757658](https://github.com/0xfunboy/KernAid/actions/runs/33297179815/job/99218757658) built all packages and exercised the production normalized-snapshot command through Tauri IPC on Ubuntu 24.04. It did not install and launch every package format. | Not qualified |
| Windows x86-64 | MSI, NSIS | Build-only | [Windows job 99218757643](https://github.com/0xfunboy/KernAid/actions/runs/33297179815/job/99218757643) built both installers and exercised credential-boundary tests. It did not run the native Windows P0 collector set or an installed-app smoke test. | Not qualified |
| macOS Apple silicon | APP, DMG | Runtime-probed, partial | [Apple-silicon job 99218757539](https://github.com/0xfunboy/KernAid/actions/runs/33297179815/job/99218757539) built both packages and ran the native macOS P0 source probe on the hosted runner. It did not install the DMG on representative hardware. | Not qualified |
| macOS Intel x86-64 | APP, DMG | Build-only | [Intel job 99218757665](https://github.com/0xfunboy/KernAid/actions/runs/33297179815/job/99218757665) cross-built both packages. Native runtime and collector probes were skipped for this target. | Not qualified |

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
- The Windows bundle is configured to embed the WebView2 offline installer, but
  that property must be confirmed in a newer successful Windows artifact before
  it becomes build evidence.
- Optional Resident OpenAI setup still uses the separately distributed native
  credential companion documented in the operator guide.

Use [Current status](../CURRENT_STATUS.md) for the overall product boundary and
the [operator guide](../operator-guide.md#diagnose-a-running-operating-system)
for the engineering-preview installation procedure.
