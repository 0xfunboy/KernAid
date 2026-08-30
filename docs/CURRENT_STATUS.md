# KernAid current status

Last updated: 30 August 2026

This page separates the product vision from what the repository can safely do
today. The short version is: **the default KernAid Phase 0 product path is a
substantial diagnosis-only engineering preview, not yet a production repair
product.**

## Product in one minute

KernAid is an evidence-first platform for diagnosing and eventually repairing
computers through a controlled workflow:

```text
Observe → Diagnose → Plan → Approve → Repair → Verify → Roll back if needed
```

The model never receives a privileged raw shell. Collectors produce bounded,
typed evidence; Core validates plans and policy; only a narrow broker may ever
perform an approved mutation. Phase 0 deliberately stops before production
mutation.

The product family has two active engineering surfaces:

- **KernAid Desk** runs inside a working Windows, Linux or macOS installation.
- **KernAid Rescue** is an amd64 bootable environment for a machine whose
  installed operating system does not start.

KernAid One, signed releases, Secure Boot support, production repair packs,
WinPE Companion and Fleet management remain later milestones.

## What works now

| Area | Current engineering state |
| --- | --- |
| Desk UI | Tauri/React desktop shell with Windows, Linux, Intel macOS and Apple-silicon macOS build targets |
| Rescue UI | Branded Tauri/WebKitGTK shell in the Debian live image, with explicit runtime/readiness gates |
| Target handling | Candidate discovery and explicit target selection; target filesystems remain read-only |
| Evidence | Normalized Linux snapshots, bounded hardware inventory and provenance framing |
| Diagnosis | Deterministic offline rules plus a bounded optional Resident OpenAI reasoning adapter |
| Planning | Typed R0 no-write plan validated by Core |
| Reporting | Resident Desk exposes authoritative machine-readable JSON: a signed envelope when secure audit is active, otherwise an explicitly unsigned hashed JSON artifact. It also derives an always-unsigned human-readable Markdown copy that does not replace the JSON. Rescue can persist the exact signed JSON report plus audit sequence in the Vault and export it through the native TTY companion |
| Rescue credential boundary | Isolated credential vault and fail-closed Codex login/status/logout bridge; it does not run prompts or diagnoses |
| Rescue provider plumbing | Feature-gated OpenAI executor and loopback relay are implemented, but live TLS and a real-account lifecycle are not yet qualified |
| Virtual testing | Disposable QEMU fixtures, byte-level mutation checks, BIOS/UEFI boot and two-boot USB/vault coverage. The latest private repair run passed BIOS/UEFI boot and apply, but failed its UEFI post-commit rollback gate; the formal candidate publish step was skipped and only a short-lived Actions forensics artifact retained ISO/checksum for investigation |
| Repair experiment | Linux-only feature-gated Desk lab for one typed R2 repair and separately approved rollback on an internal temporary fixture. It now traverses the standard `SessionDriver`, Agent Gateway, explicit Core transaction states and typed broker; it remains absent from normal/Rescue builds and disconnected from production targets |
| Feature-gated Rescue repair candidate | The off-default candidate implements one ext4-only path for disabling a non-critical `fstab` entry whose UUID is freshly proven missing: closed repair daemon and UI, broker-owned observation/plan preparation, distinct-device Vault backup, exact Core approval, bounded atomic replacement, verification, automatic restore and crash/reboot reconciliation. Its v1alpha2 read-only root helper transfers an exact four-FD bundle: a read-only leaf, an `O_PATH` physical-parent identity, a sealed UUID-inventory memfd and a detached `ro,noload` ext4 mount. After the transaction is durable Pending, a separate write-helper socket consumes the Vault's boot-scoped, single-use write lease, resolves the stable recovery fingerprint three times against fresh current-boot claims and transfers only one detached read-write mount; raw block FDs stay inside the root helper. `repaird` has `PrivateDevices=yes`, no `DeviceAllow` and no `CAP_SYS_ADMIN`; its observer and parent guard do not open `/dev` or `/sys`. None of this is present in the default/stable Rescue image, which remains diagnosis-only. Exact-source run `33306646523` passed BIOS/UEFI boot and apply for this one action, then failed UEFI post-commit rollback at `repair-rollback-service-ready`; restart reconciliation was skipped. The candidate remains private, unavailable and unqualified. |
| Rescue first boot | The promoted image provisions an all-zero p3 into the canonical LUKS2/ext4 Vault, seeds its identity and Codex home, closes it and verifies the locked profile; the exact flow passed two-boot BIOS/UEFI QEMU qualification |
| Release channel | Canonical Release Channel v1, anti-rollback links, strict verification and immutable internal prerelease `0.1.0-internal.5` are active through sequence 5; this is not an automatic updater or signed production channel |

The canonical repository is
[`0xfunboy/KernAid`](https://github.com/0xfunboy/KernAid), branch `main`.
Temporary integration worktrees are not product branches and should not be
treated as a newer release.

## What does not work yet

- There is no mutation handler in the default/stable product and no supported
  customer-machine repair path. The only real handler is the explicitly
  feature-gated `fstab` candidate.
- The private repair build includes the dedicated repair account,
  socket-activated control plane, UI, executor, startup recovery barrier,
  separate read-only and write helpers, and tightened `repaird` sandbox. Its
  latest exact-image run passed BIOS/UEFI boot and apply but failed the UEFI
  post-commit rollback service-readiness gate. Restart reconciliation was
  skipped, no ISO was published, and all rollback/restart/failure paths remain
  unqualified.
- Repair Vault retention, crash-safe compaction and pending-transaction
  reconciliation are implemented; customer retention policy and destructive
  power-loss qualification remain promotion gates.
- Rescue zero-p3 first boot has exact-image BIOS/UEFI QEMU evidence, but no
  physical USB or firmware qualification evidence yet.
- The fixture lab's exported webview artifact is deliberately marked volatile
  and unsigned because the closed native bridge does not expose its signed
  broker envelope. It is development evidence, not a release receipt.
- Physical USB boot has not been qualified. The diagnosis-only stable image from
  commit `64db3bc` completed every normal virtual gate in Rescue run
  `33307231489` and is the active candidate for a controlled physical retest on
  a factory-new or disposable USB and non-customer hardware.
- The first reported physical boot of the previous diagnosis-only RC on an
  Intel Core i5-6200-class PC reached Xorg/Matchbox but showed only a black
  desktop and movable pointer. That is a failed physical qualification, not a
  pass. The image used WebKitGTK 2.52.6 together with the obsolete
  `WEBKIT_DISABLE_DMABUF_RENDERER=1` path. The current candidate replaces it
  with shared-memory transport and CPU rasterization, disables the ephemeral
  Mesa shader cache, adds a compatibility-graphics boot entry and replaces the
  Debian boot artwork with KernAid branding. Physical retest is still required
  before claiming physical hardware qualification.
- Secure Boot is not qualified.
- Desktop installers are unsigned engineering previews.
- In the current source, the Resident credential companion is a separate Cargo
  package and separate workflow artifact. The Desktop workflow now inspects
  DEB, RPM, AppImage, macOS APP/DMG and Windows MSI/NSIS output and fails if the
  companion appears inside an installer. All four platform jobs passed this
  gate in Desktop run `33306689037` attempt 1, and those exact artifacts were
  published in immutable internal release `0.1.0-internal.5`; physical install
  and complete GUI qualification remain open.
- The human-readable Markdown report is always unsigned. Its displayed hash
  protects local integrity only; authenticity, when available, belongs to the
  signed machine-readable JSON envelope. An unsigned JSON report likewise does
  not prove signer identity.
- Rescue provider login with a real account, live TLS and physical encrypted
  persistence are incomplete release gates.
- The signed Rescue report HTTP relay remains internal loopback plumbing, not a
  public API. Its virtual shipping-image gate has passed, but physical USB and
  recovery behavior are not yet qualified.
- The v2 USB writer can copy, verify and provision an exact catalog-authorized
  image. Catalog revision 7 authorizes only the exact internally qualified
  candidate documented below; this is not physical-hardware qualification.
- Hardware and firmware support claims still require physical test evidence.

## Build and ISO status

The private project area serves one controlled physical-qualification
candidate built from commit
[`64db3bcf4050df01e96e1b55e08750b6957df801`](https://github.com/0xfunboy/KernAid/commit/64db3bcf4050df01e96e1b55e08750b6957df801):

| Field | Exact value |
| --- | --- |
| Internal release | [`0.1.0-internal.5`](https://github.com/0xfunboy/KernAid/releases/tag/kernaid-internal-v0.1.0-internal.5), immutable sequence 5 |
| Artifact version | `ci-33307231489-1` |
| ISO size | `1,223,540,736` bytes |
| ISO SHA-256 | `7eb61dc111c00a7fc925371fa7af01eb44d64b840db80bb8476be75c4039c396` |
| Retail `.img.xz` size | `1,191,686,132` bytes; expands to `32,000,000,000` bytes |
| Retail `.img.xz` SHA-256 | `90a9832a59a20246649289a18f42bf47d5ab7612fb9371fced38439254d510ae` |
| Release Channel v1 manifest SHA-256 | `cf00d0bc8958c0188f96a4fe275c1686eacea700fe6ee02c4f7f1a888bad540a` |
| Rescue workflow | [Run 33307231489, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33307231489): [build/smoke 99245806989](https://github.com/0xfunboy/KernAid/actions/runs/33307231489/job/99245806989), [BIOS lifecycle 99250429349](https://github.com/0xfunboy/KernAid/actions/runs/33307231489/job/99250429349), [UEFI lifecycle 99250429415](https://github.com/0xfunboy/KernAid/actions/runs/33307231489/job/99250429415), [qualified release 99252350837](https://github.com/0xfunboy/KernAid/actions/runs/33307231489/job/99252350837); all jobs passed |
| Desk workflow | [Run 33306689037, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306689037), all four diagnosis-only platform jobs passed from the same source commit |
| Immutable publisher | [Release Channel run 33310633658, job 99254922330](https://github.com/0xfunboy/KernAid/actions/runs/33310633658/job/99254922330), success |

That run successfully built the hybrid ISO, validated shipping binaries and
SBOM, passed ordinary BIOS/UEFI QEMU smoke with the shipping WebKit process,
visible branded framebuffer and keyboard input, and passed the BIOS/UEFI
two-boot USB-style layout and persistent LUKS2/ext4 Vault checks with
byte-identical disposable targets. Both final privileged lifecycle jobs
provisioned the zero-state Vault, verified stable identity across boot, passed
the bounded Codex offline signed-out path using its persistent Vault home, and
passed the signed-report persist, list, get, cross-boot signer and fixed-path
export path on the same artifact. The exact locally verified catalog entry is
now the sole image authorized by trusted catalog v2 revision 7. The stable ISO
also passed the explicit packaging gate that rejects repair UI, handlers,
write-capable units and other repair surfaces. The final
qualification job also bound the ISO, checksum, retail image, catalog entry,
SBOM and lifecycle evidence into one canonical manifest and attested both the
ISO and retail image. Its GitHub/Sigstore ISO build-provenance and ISO/retail
custom qualification attestations were independently verified before
promotion. This is an **internally and virtually qualified candidate**, not a
production release or proof that the reported physical display failure is
fixed.

### Retired physical-test candidate

The earlier failed physical-test release
[`0.1.0-internal.2`](https://github.com/0xfunboy/KernAid/releases/tag/kernaid-internal-v0.1.0-internal.2),
built from commit
[`0d61eac1a5e4819dedb8b2243f53599de69eba32`](https://github.com/0xfunboy/KernAid/commit/0d61eac1a5e4819dedb8b2243f53599de69eba32)
by [Rescue run 33150274347](https://github.com/0xfunboy/KernAid/actions/runs/33150274347),
is retained only as immutable virtual-qualification evidence. Its ISO SHA-256
is `ca152712c7f7002024868efc707c71c32b7c1bd648cd42ed20bb245be8d90312`.
It is retired from the trusted catalog and private download area because its
first Intel physical boot produced the black WebKit frame described above. Do
not serve, redistribute or reuse it for the physical test.

New `main` candidates must pass the same final fail-closed qualification job,
then have their manifest, checksum and attestations independently verified.
No newer workflow artifact replaces the candidate listed above until another
explicit catalog and private-site promotion is completed.

### Private repair candidate

The latest separate repair candidate run used the same exact source commit as
the stable release:
[`64db3bcf4050df01e96e1b55e08750b6957df801`](https://github.com/0xfunboy/KernAid/commit/64db3bcf4050df01e96e1b55e08750b6957df801).
It does **not** replace the stable retail image or promoted diagnosis-only
internal release above.

| Field | Exact value |
| --- | --- |
| Workflow | [Repair candidate run 33306646523, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306646523), **failure** |
| Virtual boot smoke | BIOS pass; UEFI pass |
| Virtual apply | BIOS pass; UEFI pass for `linux.fstab.disable-missing-uuid.v1` |
| Failed gate | UEFI post-commit rollback, sanitized marker `repair-rollback-service-ready` |
| Not executed | UEFI restart reconciliation, skipped after the rollback failure |
| Channel | Not promoted and unavailable through the product site/Release Channel; the formal candidate ISO publish step was skipped, while a one-day Actions forensics artifact retained ISO and checksum only for CI investigation |

The successful apply gates used disposable direct-leaf ext4 targets and a
distinct LUKS2/ext4 Vault, retained typed single-use approval, verified exact
final `fstab` bytes, left the unrelated sentinel unchanged and proved the ISO
prefix immutable. The overall workflow still failed. It does not qualify
rollback, restart reconciliation, automatic restore, fault injection, process
termination, destructive power loss, physical USB, hardware, firmware, Secure
Boot, customer data or production use. No repair-candidate ISO from this run is
promoted or available through the product site or Release Channel. The
temporary one-day Actions forensics artifact is investigation evidence, not a
trusted distribution channel.

The current retail candidate above is exposed privately only to unblock the
first physical boot test. On Windows, verify the retail `.img.xz` checksum and
select that compressed image directly in Rufus; if prompted, use DD mode on a
factory-new or disposable USB of at least 32 GB. Keep Secure Boot disabled and
use non-customer hardware. Rufus only writes the qualified zero-state image;
the first live boot asks for a new passphrase and provisions the encrypted
Vault in place. This is still not a supported repair medium.

The latest complete unsigned Desk packaging matrix was built from the stable
source commit in [Desktop run 33306689037, attempt 1](https://github.com/0xfunboy/KernAid/actions/runs/33306689037).
Linux x86-64, Windows x86-64, Intel macOS and Apple-silicon macOS packaging all
passed, including the package gates that exclude repair UI and the separately
distributed credential companion. Those artifacts are part of immutable
release `0.1.0-internal.5`; signing, notarization, physical installation and
complete GUI qualification remain open.

## Immediate next gates

1. Boot the exact `64db3bc` image from physical USB on a small hardware matrix and
   record firmware, storage, network and UI evidence.
2. Finish the real-account Rescue provider/vault lifecycle without exposing or
   copying the CLI credential store.
3. Fix and qualify one exact repair candidate through post-commit rollback,
   automatic restore, injected faults, interrupted processes, restart/reboot
   reconciliation and destructive power-loss recovery on disposable targets.
4. Qualify the repair candidate on disposable two-device physical hardware,
   including unplug/reboot/power-loss recovery.
5. Qualify Secure Boot and signed release delivery.
6. Add and qualify the signed consumer/update path on top of the verified
   internal Release Channel v1 sequence.

Keep the repair candidate unpromoted until the virtual failure/recovery,
physical USB and Secure Boot matrices pass.

## Where to look

- [Repository overview](../README.md)
- [Phase 0 architecture](architecture/phase-0.md)
- [Operator guide](operator-guide.md)
- [Product and architecture masterplan](MASTERPLAN.md)
- [Security policy](../SECURITY.md)
- [Private/public project-site operations](../site/README.md)

When this page conflicts with a broad future-looking statement in the
masterplan, this page is authoritative for current shipping status.
