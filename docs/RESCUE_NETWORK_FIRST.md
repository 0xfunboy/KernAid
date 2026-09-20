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
The focused runtime checks and Desk production build passed locally.
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
   `gemini-3.8-flash` at `https://gemr.airewardrop.xyz/v1`.
3. Verify an actual response and talk to Pi before selecting a disk. The
   assistant stays accessible during diagnosis. Only the conversation and an
   explicitly reviewed optional summary go to the model; files are not uploaded.
4. Continue to existing evidence collection and diagnosis. Pi is advisory and
   cannot authorize or execute repairs. The existing broker/approval flow is
   still authoritative.
5. After read-only inspection, reopen the assistant to explain its checks.
   Review the exact allowlisted summary, approve sharing for this question
   and ask Pi. This is advisory interpretation, not the signed diagnosis or
   an executable plan; the main diagnostic controls remain authoritative.

## Consented inspection summary

`@kernaid/assistant-context` is the shared browser/daemon contract. It accepts
only OS/filesystem enums, booleans and bounded counts: Windows boot/update
presence markers or Linux boot/fstab/package-database indicators. No free-form
collector output, release names, paths, target fingerprints, hostnames, disk
IDs, report blobs or keys can be attached through this schema. Unknown fields
and invalid facts are rejected, not forwarded.

The projection exists only for a completed read-only inspection of the still
selected target with verified mount cleanup. The UI shows the exact outgoing
data and the provider/model; approval binds the target, preview and endpoint
and resets after each send. The daemon independently rejects a changed
provider/model. Each attached summary uses a fresh one-question Pi session,
discarded after success or failure; follow-up questions need another explicit
attachment. Retargeting clears visible chat and drops late answers for the old
target. An opaque local conversation epoch also resets ordinary backend chat
history on retarget; it is never included in the model prompt. Normalized
provider configuration is reflected back into the UI before consent binding.
Text typed by the user still goes to the selected provider as before.

The summary is untrusted observations, not instructions or proof of hardware
health. Missing boot artifacts can reflect an uninspected separate filesystem;
the model is explicitly told not to infer corruption or an executed repair.
Unit checks cover projection/redaction, stale selection, closed schema,
endpoint binding and session disposal. Exact-image and real-provider behavior
remain qualification gates; the currently running `53afa5a` build predates
this additional source batch.

Wi-Fi passwords travel to `nmcli --ask` over stdin. NetworkManager owns its
profile in the live OS. Hidden SSID entry, enterprise 802.1X and captive-portal
login are not implemented in this first wizard. Physical adapter/firmware and
Wi-Fi behavior still require qualification.

## Harness and search

Pi SDK is pinned to `@earendil-works/pi-coding-agent` `0.80.10`. Sessions are
in-memory, with project context/extensions disabled and no built-in shell,
read, edit or write tools. Native-tool-capable providers receive only
`web_search`; model work is bounded to four turns and 120 seconds per question,
including any search turns.

The Gemrouter profile uses a dedicated Pi transport because the SDK's stock
OpenAI Completions adapter requests streaming. The verified gateway contract is:

| Setting        | KernAid value                                                                                       |
| -------------- | --------------------------------------------------------------------------------------------------- |
| API base       | `https://gemr.airewardrop.xyz/v1`                                                                   |
| Completion     | `POST /v1/chat/completions`, `stream: false`                                                        |
| Authentication | Endpoint-bound `Authorization: Bearer` service credential                                           |
| Backend        | `x-gemrouter-backend: gemini-api`                                                                   |
| Model          | `gemini-3.8-flash`, no automatic model/backend fallback                                             |
| Output limit   | `max_tokens: 2048` for normal answers; 64 only in the direct probe                                  |
| Deadlines      | 10 s DNS/TCP/TLS connection, 120 s complete HTTP request                                            |
| Budget         | At most 2 in-flight HTTP requests and 30 starts per rolling minute, process-wide                    |
| Retries        | None; exceeded budgets fail locally instead of queuing                                              |
| Discovery      | Once after a connected adapter exists at startup, cached; explicit Load models refresh is available |

The transport appends `/models` or `/chat/completions` to the selected base,
never another `/v1`. It sends no Origin, cookie, OAuth, Codex credentials,
thinking parameters or native tools, and follows no redirects. Request and
response JSON are bounded to 512 KiB. Pi still owns the conversation; the
adapter is not a replacement harness. Other provider profiles retain their
existing compatible transport.

Connected-startup discovery runs in the background and does not block local
status, network selection or offline diagnosis. With no usable adapter it is
deferred until a successful connection or provider configuration. Successful
results are reused when selecting another model on the same endpoint/key. A
changed provider, endpoint or credential invalidates them; a late response
cannot populate a new profile.
After an offline startup, connecting an adapter or explicitly configuring the
provider can start a fresh discovery. Chat itself never discovers models.
The local IPC, HTTP relay and browser deadlines are 125, 135 and 140 seconds
(relay peer timeout 130 s), so they do not cut off a valid 120 s model request.
The incoming browser Origin/Host check remains mandatory: it is distinct from
the outgoing server-to-server request, which has no Origin header.

Private testing media obtains its preconfigured provider credential through
systemd `LoadCredential`. The runtime accepts systemd's service-private `0440`
credential representation, while ordinary credential files remain restricted
to owner-only permissions.

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
After issuing a replacement in Gemrouter, rotate it by editing this file and restarting
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
private devices. Polkit grants the dedicated assistant account live
NetworkManager control, Wi-Fi scan and live-system profile changes (the daemon
has no login session for private profiles). The UI's group-restricted relay checks
Origin/Host and bounds request sizes and timeouts.

Public images ask for a key. The owner-authorized private-testing CI path
bundles the configured test credential and publishes only an encrypted
artifact for internal distribution. See the [private ISO runbook](runbooks/private-test-iso.md).
For a local preconfigured **private test build**, supply the private file
explicitly during staging:

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
- Earlier Gemrouter requests timed out. This was superseded by the live
  verification below after the owner reported an upstream production fix.
- On 19 September the synthetic, consented-summary Pi probe reached its 60 s
  deadline. Direct requests outside Pi also timed out: minimal non-streaming
  `/chat/completions` at 20 s and `/models` at 10 s, without a response status.
  This established that the earlier failure was not exclusively Pi streaming.
  Timeout still tells the user to retry or continue offline, without implying
  an invalid key.
- After the upstream fix reported as `1ef520d`, this VPS verified the supplied
  non-streaming Gemini contract: `/v1/models` HTTP 200 in 1.167 s, preferred
  model present (`req-88`); `/v1/chat/completions` HTTP 200 in 5.068 s,
  `KERNAID_TEST_OK`, backend `gemini-api`, 13 total tokens (`req-89`).
- The restarted **actual KernAid Unix-socket service**, using Pi and the new
  transport, answered `KERNAID_TEST_OK` in 4.800 s. Startup discovery was ready
  and the service reported `verified: true`. A subsequent live Pi → SearXNG →
  Pi question returned the official NetworkManager nmcli documentation URL
  in 20.299 s with exactly one search. No retry, fallback or key rotation was
  used. These are VPS checks, not physical USB or exact-ISO evidence.
- Focused transport/runtime checks cover non-streaming payloads, actual Pi
  provider dispatch, header isolation, deadlines, cancellation, JSON bounds,
  quota enforcement and discovery caching: 24 passed, plus 3 local relay
  boundary/readiness checks. The production Desk build and isolated production
  assistant bundle import passed with Node 24.18.0 and the frozen lockfile.
- New ISO/boot qualification, physical Wi-Fi and the reported disk-selection
  issue remain to be tested. Existing ISO/Vault/repair limitations still apply.
