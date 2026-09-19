# Rescue network-first assistant

Implementation checkpoint: 19 September 2026. This source change is not yet
included in a newly qualified ISO; existing private downloads are unchanged.

The production-preparation batch binds credentials to their exact endpoint,
restores the active provider/model when reopening the wizard and permits the
dedicated daemon to create NetworkManager live-system profiles. Private NM
profiles require a login session and cannot be used by this headless account.
Wi-Fi passwords travel on stdin, not argv; profiles belong to the live OS,
not a target disk or the KernAid Vault. General live-overlay persistence is
not qualified by this change. Provider keys entered in the wizard remain
in-memory; the private development key is a separate service credential.

Pi staging now includes only runtime files and checks import on both the build
host and target Debian chroot; the chroot also checks the pinned SearXNG import.
Seven focused runtime tests and the Desk production build passed locally.
The existing QEMU smoke now additionally requires a running local HTTP-to-Unix
assistant relay, successful NetworkManager enumeration, SearXNG `/healthz`
and both systemd services active. It does not call a remote model or search
engine. Local probe/marker contract checks passed; the exact ISO run remains
the evidence for actual guest startup.

The owner reported a physical boot reaching the desktop and two installed-system
candidates, then apparently stopping after selection. No device logs establish
the cause. Disk selection now focuses and scrolls to the next step; its existing
bounded request still reports failures. This is not a verified fix of that PC.

## User journey

1. Enumerate Ethernet/Wi-Fi through NetworkManager, select an adapter, scan and
   connect. Connected Ethernet can be used immediately. Offline continuation is
   always available. Disk inventory/discovery waits for this step to finish.
2. Choose Gemrouter (default), OpenAI, DeepSeek, Gemini's OpenAI-compatible
   surface or a custom HTTPS base URL. Fetch `/models` or enter a model. Default:
   `gemini-3.8-flash` at `https://gemr.airewardrop.xyz`.
3. Verify an actual response and talk to Pi before selecting a disk. The
   assistant stays accessible during diagnosis. Only the conversation goes to
   the model; disk contents are not uploaded automatically.
4. Continue to existing evidence collection and diagnosis. Pi is advisory and
   cannot authorize or execute repairs. The existing broker/approval flow is
   still authoritative.

Wi-Fi passwords travel to `nmcli --ask` over stdin. NetworkManager owns its
profile in the live OS. Hidden SSID entry, enterprise 802.1X and captive-portal
login are not implemented in this first wizard. Physical adapter/firmware and
Wi-Fi behavior still require qualification.

## Harness and search

Pi SDK is pinned to `@earendil-works/pi-coding-agent` `0.80.10`. Sessions are
in-memory, with project context/extensions disabled and no built-in shell,
read, edit or write tools. Native-tool-capable providers receive only
`web_search`; model work is bounded to four turns and 60 seconds per request.

The live Gemrouter endpoint rejects native tools with HTTP 400:
`Tool calling is not supported on this router surface`. Its profile instead
uses a bounded text protocol: the model emits exactly
`{"web_search":"public technical query"}`; KernAid validates the shape,
queries SearXNG, and returns results to Pi as untrusted data. At most two
searches are allowed. Other text operations cannot execute anything.

SearXNG is pinned to `c0042add30116a315ebacfcb84781bb3e1e4e77e`, served by
Waitress `3.0.2` on `127.0.0.1:8888`, with JSON output and Google, Bing, Brave,
DuckDuckGo and Wikipedia. Results have at most five bounded titles, URLs and
snippets. Source and AGPL license travel with the image. Search queries leave
the machine; the agent is instructed to use public symptoms and omit private
identifiers/credentials. Anti-bot restrictions can make an engine unavailable.

References: [Pi SDK](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/sdk.md),
[SearXNG API](https://docs.searxng.org/dev/search_api.html).

## Credentials and installation

Endpoint/model defaults are committed; real keys are not. The supplied test key
is stored at `/home/funboy/.config/kernaid-assistant/gemrouter.key`, mode 0600,
and loaded into the development service through systemd `LoadCredential`.
Rotate it by editing this file and restarting
`systemctl --user restart kernaid-assistant.service`.
Keys entered through the wizard live only in memory. Endpoint changes discard
the prior credential and conversation; an existing key is never forwarded to
a new endpoint automatically.

Development services `kernaid-assistant.service` and `kernaid-search.service`
are installed and enabled for the current user. The assistant is available only
over `$XDG_RUNTIME_DIR/kernaid-assistant/assistant.sock`.

Both Rescue workflows stage the bundle with
`bash tools/build-rescue/stage-assistant.sh` on the Node 24.18.0/pnpm host before
the minimal Debian container. Use a fresh build worktree: staging refuses to
overwrite prior bundles. The chroot hook installs pinned SearXNG requirements
and enables services. The assistant runs as an unprivileged dedicated user with
private devices. Polkit grants only live NetworkManager control, Wi-Fi scan and
its own profile changes. The UI's group-restricted Unix-socket relay checks
Origin/Host and bounds request sizes and timeouts.

Public images ask for a key. For preconfigured **private test media**, supply
the private file explicitly during staging:

```sh
KERNAID_PRIVATE_GEMROUTER_KEY_FILE=/home/funboy/.config/kernaid-assistant/gemrouter.key \
  bash tools/build-rescue/stage-assistant.sh
```

That image contains a recoverable test key, loaded through a private systemd
drop-in; keep it internal. Both generated credential files are ignored by Git.
The image-generation endpoint is not used by this diagnostic assistant.

## Verification and remaining work

- Desk production bundle and the independent Pi package build/check succeed.
- Focused tests cover endpoint credential isolation, actual Pi tool allowlist,
  escaped Wi-Fi names, strict search protocol, timeout recovery and cross-origin
  rejection.
- Gemrouter accepted the supplied key, listed `gemini-3.8-flash`, and Pi returned
  `KernAid ready` using that model.
- SearXNG returned live NetworkManager documentation links. The initial
  DuckDuckGo CAPTCHA was handled by adding independent search engines.
- Later Gemrouter requests timed out. The complete live Pi→search→answer chain
  still needs confirmation once upstream is responsive; local tests prove the
  protocol, not remote reliability.
- New ISO/boot qualification, physical Wi-Fi and the reported disk-selection
  issue remain to be tested. Existing ISO/Vault/repair limitations still apply.
