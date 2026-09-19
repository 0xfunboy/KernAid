# Workspace layout and cleanup — 19 September 2026

Only `/home/funboy/kernaid` is the active source checkout. Do not use old
integration branches as a release or as a second source of product status.

| Location                                               | Purpose                                                                      |
| ------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `/home/funboy/kernaid`                                 | Canonical Git repository, documentation, site and build tooling              |
| `/home/funboy/KernAid-dist`                            | Published/private release artifacts; referenced by the running site; retain  |
| `/home/funboy/.local/share/kernaid-archive/2026-09-19` | Retained historical probes, logs and forensic image; not a release           |
| `/home/funboy/.local/share/kernaid-search`             | Active local SearXNG runtime; retain                                         |
| `/home/funboy/.config/kaid-site`                       | Private website credentials; never commit                                    |
| `/home/funboy/.config/kernaid-assistant`               | Private development provider credential; never commit or publish in an image |
| `/home/funboy/KERNAID_PRODUCT_AND_REPO_MASTERPLAN.md`  | Compatibility pointer to `docs/MASTERPLAN.md`, not another plan              |

## Integrated worktrees

The following worktrees were checked for tracked and untracked changes, unique
patches (`git cherry main HEAD`), ignored content and active process/service
references. All were clean; every branch patch was already represented in
`main`. The disposable copies and their reproducible `target`, `node_modules`,
`dist` and Python caches were removed (approximately 10.3 GiB). Branch refs
remain, so the source can be recovered with:

```sh
git -C /home/funboy/kernaid worktree add /chosen/new/path <branch>
```

| Removed directory under `/home/funboy` | Retained branch                        |
| -------------------------------------- | -------------------------------------- |
| `kernaid-docs-native-lifecycle`        | `docs/status-native-lifecycle`         |
| `kernaid-docs-state-sync`              | `docs/state-sync`                      |
| `kernaid-enterprise-license`           | `feat/fleet-enterprise-licensing-v1`   |
| `kernaid-fleet-macos-control-plane`    | `feat/fleet-macos-control-plane-v12`   |
| `kernaid-fleet-rescue-adapter`         | `feat/fleet-rescue-work-order-adapter` |
| `kernaid-fleet-rescue-four-actions`    | `feat/fleet-rescue-four-actions`       |
| `kernaid-fleet-resident-lifecycle`     | `feat/fleet-resident-native-lifecycle` |
| `kernaid-fleet-resident-macos`         | `feat/fleet-resident-macos-r0`         |
| `kernaid-fleet-resident-windows`       | `feat/fleet-resident-windows-r0`       |
| `kernaid-fleet-signed-backup`          | `feat/fleet-signed-backup-v1`          |
| `kernaid-macos-site-bundle`            | `feat/macos-resident-site-bundle`      |
| `kernaid-media-creator-wizard`         | `feat/media-creator-windows-wizard`    |
| `kernaid-provider-registry`            | `feat/provider-registry`               |
| `kernaid-repair-allpacks`              | `feat/rescue-repair-allpacks`          |
| `kernaid-repair-fix`                   | `repair-readiness-fix`                 |
| `kernaid-rescue-repair-promotion`      | `feat/rescue-repair-promotion`         |
| `kernaid-resident-ab`                  | `feat/fleet-resident-ab-activator`     |

## Preserved historical evidence

These exact directories were moved under the archive above, without deleting
their contents. Move an individual directory back if an old investigation must
be resumed; old absolute paths in historical notes are not active services.

- `KernAid-debug`: unique historical scripts, VM probes and logs.
- `kernaid-forensics.c8G6ix8L`: historical diagnostic ISO and checksum.
- `kernaid-native-prompt-evidence.P4Ohu6mV`: prompt evidence logs.
- `kernaid-prompt-replay.RRLNVigU`: replay evidence logs.
- `staging-probes/`: five obsolete deployment directories moved out of the
  source checkout, including historical assistant runtime copies, the pinned
  SearXNG probe clone and duplicate nested launcher caches. None is referenced
  by a running service; all remain recoverable.

The artifact store, live services, credentials, VSPiLink and unrelated projects
were not removed. New parallel work should use short-lived Git worktrees;
close them after integration, retaining any unique evidence in the archive.
