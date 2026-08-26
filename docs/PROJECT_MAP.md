# KernAid project map

Last updated: 26 August 2026

This is the short operational map of the product, repository, build artifacts
and internal delivery channel. For exact qualification evidence, use
[Current status](CURRENT_STATUS.md); when that page and the long-term
[masterplan](MASTERPLAN.md) differ, Current status wins.

## Where the product is now

KernAid is a substantial **Phase 0 diagnosis-only engineering preview**. It
collects bounded evidence, produces a diagnosis, validates a typed R0 no-write
plan and emits a hashed report. Rescue can additionally preserve the exact
report and audit sequence as a signed envelope in its encrypted Vault. Normal
builds contain no production target-mutation handler.

The intended complete product flow is:

```text
Observe -> Diagnose -> Plan -> Approve -> Repair -> Verify -> Roll back
```

The production path currently stops after reporting. One Linux-only fixture
lab exercises repair and rollback against a disposable repository-owned test
tree; it cannot select a host path, disk or customer target.

## Product surfaces

| Surface | Purpose | Current boundary |
| --- | --- | --- |
| KernAid Desk | Diagnose a running Windows, Linux or macOS installation | Unsigned engineering builds; read-only production collectors |
| KernAid Rescue | Boot an amd64 PC that cannot start its installed OS | Hybrid BIOS/UEFI image; virtual qualification only until physical USB evidence exists |
| USB writer v2 | Verify an authorized ISO, write it and provision its encrypted Vault | Linux operator path; accepts only the exact trusted-catalog image |
| Project site | Explain the project publicly and distribute controlled artifacts privately | Public `/`; authenticated `/private/`; no public ISO route |

## Canonical repository map

| Path | Contents |
| --- | --- |
| `apps/desk/` | React/Tauri Desk application and native Resident adapters |
| `crates/` | Core, protocol, broker, identity, storage, Rescue vault/provider components |
| `packs/` | Strict deterministic diagnostic packs for Linux, Windows and macOS |
| `rescue/live-build/` | Debian live-image contents and service configuration |
| `tools/build-rescue/` | Reproducible image build, QEMU gates, SBOM and attestation tooling |
| `tools/make-device/` | Trusted catalogs and the guarded USB writer |
| `tests/` | Integration, zero-write, Rescue and fixture coverage |
| `site/` | Dependency-free public site and authenticated artifact server |
| `docs/` | Architecture, status and operator documentation |

All Python files under these paths are tracked build, Rescue, writer or test
sources. They are not abandoned copies.

## Current build-host layout

On the internal build host used during this phase:

| Path/service | Role |
| --- | --- |
| `/home/funboy/kernaid` | Only canonical checkout of `0xfunboy/KernAid`, branch `main` |
| `/home/funboy/KernAid-dist` | Local staging for qualified/private artifacts; not another repository |
| `kaid-site.service` | Node.js 24 site process on loopback |
| `kaid-cloudflared.service` | Tunnel for `https://kaid.funboy.eu.cc` |
| `~/.config/kaid-site/` | Operator-owned password and tunnel credentials; never committed |

Both user services are enabled and user lingering keeps them active across
logout and reboot.

## How an artifact becomes downloadable

1. A source commit passes its relevant repository workflows.
2. The Rescue workflow builds one exact ISO and proves BIOS/UEFI boot,
   USB-style two-boot persistence, byte-identical disposable targets and the
   privileged Vault lifecycle on that same artifact.
3. The ISO, checksum, catalog-entry evidence and workflow identity are
   downloaded and verified locally.
4. Promotion is an explicit repository change: a new trusted-catalog revision
   authorizes one exact name, size, digest, layout and evidence set.
5. Only then are the private site metadata and pinned local artifact changed
   together and the service restarted.

The existence of a GitHub Actions artifact alone never promotes it. Physical
USB, Secure Boot, real-account provider TLS, signed installers and production
repairs remain separate release gates.

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
[Current status](CURRENT_STATUS.md). In practical terms the next external
proof is physical USB boot on disposable media and non-customer hardware;
after that come Secure Boot, signed delivery, real-account provider lifecycle
and the first production repair action with preconditions, backup,
verification and rollback.

