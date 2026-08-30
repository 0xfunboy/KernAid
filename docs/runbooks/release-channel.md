# Release channel v1

`tools/release/release_channel.py` creates a deterministic inventory for a
KernAid download channel. It binds every published file to its byte length and
SHA-256, one repository commit, and an exact GitHub Actions workflow run and
attempt. Sequence numbers and the previous manifest hash form a linear chain
which a client can use to reject rollback.

This manifest is **not** a signature, an updater, a support claim, or Rescue
qualification. Before adding a file, independently verify its GitHub/Sigstore
provenance and, for Rescue, its qualification manifest. The asserted workflow
run must have built the manifest-level `source.commit`. Publish the channel
over authenticated transport or sign the canonical manifest before using it as
a trust root.

## Create a manifest

Stage all files in one private directory. Filenames must be unique. Create a
descriptor outside the public directory; its `path` fields are local absolute
paths and are never copied to the output:

```json
{
  "schema": "dev.kernaid.release-channel-input.v1",
  "channel": "internal",
  "sequence": 1,
  "previous": null,
  "publishedAt": "2026-08-28T12:00:00Z",
  "source": {
    "repository": "0xfunboy/KernAid",
    "commit": "0123456789abcdef0123456789abcdef01234567"
  },
  "artifacts": [
    {
      "component": "rescue",
      "platform": "rescue",
      "architecture": "x86_64",
      "version": "ci-33000000002-1",
      "variant": "qualified-zip",
      "kind": "image",
      "path": "/srv/kernaid-stage/KernAid-Rescue-amd64-qualified.zip",
      "mediaType": "application/zip",
      "url": "https://downloads.example.invalid/internal/KernAid-Rescue-amd64-qualified.zip",
      "provenance": {
        "workflow": ".github/workflows/rescue.yml",
        "runId": 33000000002,
        "runAttempt": 1
      }
    },
    {
      "component": "rescue",
      "platform": "rescue",
      "architecture": "x86_64",
      "version": "ci-33000000002-1",
      "variant": "qualified-zip",
      "kind": "qualification",
      "path": "/srv/kernaid-stage/KernAid-Rescue-amd64.qualified.json",
      "mediaType": "application/json",
      "url": "https://downloads.example.invalid/internal/KernAid-Rescue-amd64.qualified.json",
      "provenance": {
        "workflow": ".github/workflows/rescue.yml",
        "runId": 33000000002,
        "runAttempt": 1
      }
    }
  ]
}
```

Every Desk component/platform/architecture/version/**variant** group requires
exactly one `package`; every Rescue group requires exactly one `image`.
Therefore Linux can publish AppImage, DEB and RPM together, Windows MSI and
NSIS together, and macOS app bundle and DMG together without colliding. The
accepted variants are `appimage`, `deb`, `rpm`, `msi`, `nsis`, `app`, `dmg`,
and Rescue `qualified-zip`, `qualified-iso` or `retail-img-xz`; each is valid
only on its matching platform. The publisher exposes the verified ISO and its
checksum as the `qualified-iso` group. The compressed Windows retail image and
its checksum form the separate `retail-img-xz` group; the image is never a
member of the qualified ZIP. The publisher rejects every individual GitHub
Release asset at or above 1,999,999,999 bytes.
Additional records may be `checksum`, `qualification`, `sbom`, or `signature`.
All files in one variant group must identify the same run. Desk uses
`desktop.yml`; Rescue uses `rescue.yml`.

Create a new output path (the command refuses overwrite):

```bash
python3 -I -B tools/release/release_channel.py create \
  --descriptor /srv/kernaid-stage/release-input.json \
  --output /srv/kernaid-stage/release-channel.v1.json
```

For sequence 2 and later, set `previous.sequence` to exactly `sequence - 1`
and `previous.sha256` to the digest printed by the preceding successful create
or verify operation.

## Verify before publication

The verification directory is flat and contains every filename listed by the
manifest. Verification rejects duplicate/non-canonical JSON, unexpected
fields, unsafe files, invalid chain metadata, mixed run provenance, and any
size or digest mismatch:

```bash
python3 -I -B tools/release/release_channel.py verify \
  --manifest /srv/kernaid-stage/release-channel.v1.json \
  --artifact-root /srv/kernaid-stage
```

Upload immutable artifact URLs first and the canonical channel manifest last.
Never replace bytes behind an existing URL or reuse a sequence number. A
consumer must persist the highest accepted sequence and manifest SHA-256; the
single-document verifier cannot by itself prove freshness.

## Publish the internal channel

`.github/workflows/release-channel.yml` is manual-only. It accepts one exact
successful Desk run and one exact virtually qualified Rescue run built from
the same full commit. Before publication it:

- verifies both first-attempt run identities, workflow paths and artifact names;
- re-runs the Rescue qualification-manifest verifier and GitHub/Sigstore checks
  on both the extracted ISO and separately downloaded retail image;
- publishes the qualified ZIP, direct ISO, Rufus-ready retail image and both
  versioned checksum sidecars, then builds and re-verifies their canonical
  manifest;
- attests the complete staged channel with GitHub OIDC; and
- requires repository release immutability and creates one immutable GitHub
  **prerelease** whose tag is
  `kernaid-internal-v<VERSION>`.

For sequence 2 and later the operator must name the current published channel
head and its manifest SHA-256. The workflow downloads and validates that
manifest, requires the immediately preceding sequence, and rejects a fork or
a second sequence 1 before publishing. It refuses every published release. An
unpublished draft can be resumed only when its identity and complete asset
size/digest inventory exactly match the newly verified staging set; partial or
different drafts fail closed. It accepts an existing tag only when it is a
lightweight ref resolving to the exact qualified source commit, and never
replaces assets or moves a ref.

GitHub's installation-scoped Actions token cannot create a tag at a historical
commit containing workflow-file changes. The first channel bootstrap may
therefore require an authorized publisher to pre-create that one exact
lightweight tag. This exception supplies only the immutable source ref: the
workflow still downloads, verifies, inventories, attests and publishes every
asset. Candidates released while their source commit is the workflow's current
head do not need the bootstrap.

The manual workflow holds `contents:write` solely so its final step can create
the internal prerelease; its preceding scripts do not publish repository
content. Repository release immutability was enabled on 28 August 2026 and the
publisher verifies that the exact published release reports `immutable: true`.
The Actions installation token cannot read the repository-level setting in
advance, so the operator must also retain the enabled setting as a release
precondition. Immutability applies only to releases published while enabled.
Consumers must still verify the included channel attestation and manifest
hash. This permission does not code-sign MSI, DMG, AppImage or the boot chain.
Those assets remain explicitly unsigned engineering candidates.

The checked-in JSON Schema is
`tools/release/release-channel.v1.schema.json`. Run the focused local contract
checks with:

```bash
just verify-release-channel
```

The channel attestation proves workflow provenance for the published archive
bytes. Native installer signing, Secure Boot and an A/B updater remain separate
release gates.
