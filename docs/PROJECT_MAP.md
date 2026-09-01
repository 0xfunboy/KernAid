# KernAid project map

Last updated: 1 September 2026

This is the short operational map of the product, repository, build artifacts
and internal delivery channel. For exact qualification evidence, use
[Current status](CURRENT_STATUS.md); when that page and the long-term
[masterplan](MASTERPLAN.md) differ, Current status wins.

## Where the product is now

KernAid's stable customer-facing build remains a **diagnosis-only engineering
preview**. It collects bounded evidence, produces a diagnosis, validates a
typed R0 no-write plan and emits a hashed report. Rescue can additionally
preserve the exact report and audit sequence as a signed envelope in its
encrypted Vault. Separately built, off-default repair candidates now contain
closed fstab, crypttab, ext4 preen/undo and resolver-link recovery actions;
none is promoted into the stable image until its own qualification gate passes.

The intended complete product flow is:

```text
Observe -> Diagnose -> Plan -> Approve -> Repair -> Verify -> Roll back
```

The stable path currently stops after reporting. Candidate actions exercise
the same `SessionDriver -> Agent Gateway -> Core -> broker` boundary against
descriptor-bound disposable targets with Vault evidence and explicit
approval. They remain private and unsupported on customer data.

## Product surfaces

| Surface        | Purpose                                                                                         | Current boundary                                                                                                                                                                                          |
| -------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| KernAid Desk   | Diagnose a running Windows, Linux or macOS installation                                         | `6e9742e` four-platform packaging is green in run `33486399165`; Offline/OpenAI/Anthropic/Gemini remain native, tool-free provider boundaries                                                              |
| KernAid Rescue | Boot an amd64 PC that cannot start its installed OS                                             | Run `33486399275` passed integrated BIOS/UEFI and USB-style two-boot gates but failed UEFI Vault readiness; exact ISO is private physical-test input, not a promoted release                              |
| USB writers    | Verify an authorized image, write it and provision or verify the resulting medium               | Guarded Linux writer plus off-default Windows Media Creator; physical USB remains unqualified                                                                                                             |
| KernAid Fleet  | Enroll devices, retain minimized inventory, govern typed work orders and track incident closure | Live internal schema v13; disposable cryptographic E2E and backup restore drill are green, all four Rescue intents are mapped locally, and current native Resident enrollment/package workflows are green |
| Project site   | Explain the project publicly and distribute controlled artifacts privately                      | Public `/`; authenticated `/private/`; no public ISO route                                                                                                                                                |

## Canonical repository map

| Path                            | Contents                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `apps/desk/`                    | React/Tauri Desk application and native Resident adapters                                                                |
| `crates/`                       | Core, protocol, broker, identity, storage, Rescue vault/provider, Fleet client/policy/runtime and entitlement components |
| `services/fleet-control-plane/` | Multi-tenant signed enrollment and inventory registry                                                                    |
| `apps/fleet-console/`           | Internal same-origin Fleet operator console                                                                              |
| `packs/`                        | Strict deterministic diagnostic packs for Linux, Windows and macOS                                                       |
| `rescue/live-build/`            | Debian live-image contents and service configuration                                                                     |
| `tools/build-rescue/`           | Reproducible image build, QEMU gates, SBOM and attestation tooling                                                       |
| `tools/make-device/`            | Trusted catalogs and the guarded USB writer                                                                              |
| `tests/`                        | Integration, zero-write, Rescue and fixture coverage                                                                     |
| `site/`                         | Dependency-free public site and authenticated artifact server                                                            |
| `docs/`                         | Architecture, status and operator documentation                                                                          |

All Python files under these paths are tracked build, Rescue, writer or test
sources. They are not abandoned copies.

## Current build-host layout

On the internal build host used during this phase:

| Path/service                | Role                                                                                  |
| --------------------------- | ------------------------------------------------------------------------------------- |
| `/home/funboy/kernaid`      | Only canonical checkout of `0xfunboy/KernAid`, branch `main`                          |
| `/home/funboy/KernAid-dist` | Local staging for qualified/private artifacts; not another repository                 |
| `kaid-site.service`         | Node.js 24.18.0 site process on loopback                                              |
| `kaid-cloudflared.service`  | Tunnel for `https://kaid.funboy.eu.cc`                                                |
| `kernaid-fleet.service`     | Node.js 24.18.0 Fleet v13 origin on loopback, exposed at `https://fleet.funboy.eu.cc` |
| `~/.config/kaid-site/`      | Operator-owned password and tunnel credentials; never committed                       |

All three user services are enabled and user lingering keeps them active across
logout and reboot.

## How an artifact becomes downloadable

1. A source commit passes its relevant repository workflows.
2. The Rescue workflow builds one exact ISO and proves BIOS/UEFI boot,
   USB-style two-boot persistence, byte-identical disposable targets and the
   privileged Vault lifecycle on that same artifact.
3. One BIOS-only job reuses that ISO through a private, identity-checked and
   SHA-256-pinned raw copy. It provisions on boot one and drives the gated
   native Vault prompt on boot two, including `Type=notify` readiness, real UI
   activation, tty8 unlock, graphical-VT return and a root full-current-boot
   journal proof.
4. A final job binds the ISO, retail image, checksums, catalog entry, SBOM and
   lifecycle evidence into a canonical manifest, emits ISO build provenance
   and emits qualification attestations for both the ISO and retail image. The
   manifest requires the VT job and binds its sanitized 30-day evidence to the
   qualified ISO's exact SHA-256.
5. The ISO, retail image, checksums, qualification manifest, attestations and
   workflow identity are downloaded and verified locally.
6. Promotion is an explicit repository change: a new trusted-catalog revision
   authorizes one exact name, size, digest, layout and evidence set.
7. Only then are the private site metadata and pinned local artifact changed
   together and the service restarted.

The current integrated diagnosis source cut is
`6e9742e5b0c4397728dde80e9a0a91a09214f7cd`. CI run `33486399168` and the
complete Windows/Linux/Intel-macOS/Apple-silicon Desktop run `33486399165` are
green. Desktop includes native OpenAI, Anthropic and Gemini credential/status,
transport and selector boundaries; the provider-key companion remains outside
the installers. Live vendor-account behavior is still an external gate.

The two ISO workflows ended without a promotable image:

- diagnosis Rescue run `33486399275`: integrated build/boot/USB matrix green,
  UEFI Vault readiness failed, `internal.7` not dispatched; exact
  `8a971474…c46da` ISO exposed privately only as a physical-test candidate;
- repair Rescue run `33482972849` on `01cf8fe`: **FAILED** at
  `uefi:crypttab-lifecycle`; no qualified artifact or promotion exists.

The current Resident source is `fe3c940d525f5c1c2ecd8123bdb100cd3280b908`.
Linux (`33471097700`), Windows (`33471100838`) and macOS (`33471099291`) are
green for their staged native package workflows and explicit enrollment
contract. The source uses platform-bound identities, fixed signed enrollment,
post-acceptance token consumption and a required public binding before normal
startup. Publisher signing, physical key stores and a physical production
endpoint remain separate gates.

The focused Fleet software path is also green on disposable state: commercial
license, one-use token, signed enrollment, policy, entitlement, update, work
order, signed result/service receipt, audit and console. The four-action local
Rescue approval/broker/Vault adapter and signed backup verify/restore drill are
green. These tests do not promote either failed ISO candidate.

The existence of a GitHub Actions artifact alone never promotes it. Physical
USB, real-account provider TLS, signed installers and production repairs
remain separate release gates; virtual Secure Boot evidence is not a physical
firmware qualification claim.

## Safe workspace cleanup

- `target/`, Python `__pycache__/` directories and temporary compiler wrappers
  are generated and may be deleted.
- `node_modules/` is generated too, but keeping it avoids reinstalling packages
  during active development.
- Keep the exact artifact referenced by `site/content.json` and the trusted
  catalog. Old failed evidence and superseded unserved builds may be removed
  after their replacement is verified.
- Never treat `/home/funboy/KernAid-dist` as source code or commit secrets from
  `~/.config/kaid-site/`.

## Next product gates

The ordered, authoritative list is maintained in
[Current status](CURRENT_STATUS.md). Finish and promote only diagnosis Rescue
run `33486399275`; Repair run `33482972849` is recorded failed and intentionally
paused. Desktop and source CI are already green and should not be repeated
unchanged. The next external proof is physical USB boot on disposable
media and non-customer hardware; after that come physical Secure Boot, signed
delivery, real-account provider lifecycle and the first production repair
action with preconditions, backup, verification and rollback.
