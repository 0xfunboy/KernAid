# Rescue trusted prompt and provider-context boundary

Status: design gate. This document records the smallest safe backend contract;
it does not claim that a trusted graphical prompt is implemented.

## Current boundary

The shipping Rescue shell cannot safely launch the existing Vault, provider,
Codex, or report companions:

- `kernaid-rescue-desk-shell` runs as the isolated `kernaid-rescue-ui` account,
  has no supplementary groups, uses `PrivateDevices=yes`, receives fake D-Bus
  addresses, and has no privileged AF_UNIX sockets in its mount namespace;
- shell startup explicitly attests that the Vault, provider, Codex, inspector,
  and system-bus sockets are absent, and the Tauri builder registers no invoke
  handler;
- `kernaid-rescue-vaultctl` admits exactly UID 1000 and requires a foreground
  controlling `/dev/tty`; `kernaid-codex-auth` is likewise a live-user client;
- the kiosk intentionally contains no terminal, panel, launcher, or user
  switching path, and UID 1000 is denied the graphical Xauthority.

Consequently, adding a Tauri `Command::new`, granting the UI account the Vault
group, passing a secret through an HTTP/Tauri payload, or spawning the existing
companion from the shell would weaken an enforced security boundary and still
would not produce a valid controlling terminal. None is an acceptable bridge.

The non-secret status surfaces already exist and should remain authoritative:

- `GET /api/rescue/vault/status` returns only the closed Vault state and state
  version;
- `provider.status` through `/api/rescue/provider/openai` returns only the
  closed Vault/credential state;
- `GET /api/rescue/reports` returns bounded signed-report metadata.

Diagnosis-only operation remains available when the Vault or any future prompt
service is absent. The off-by-default repair candidate continues to require an
unlocked Vault and retains its independent compile-time and runtime gates.

## Minimum trusted-prompt contract

A graphical implementation needs a separate native prompt broker. The WebView
may communicate only with the shell, and the shell may send only this closed
control request to the broker:

```json
{
  "apiVersion": "kernaid.dev/rescue-native-prompt/v1alpha1",
  "requestId": "N-00000000-0000-0000-0000-000000000000",
  "operation": "prompt.open-or-focus",
  "kind": "vault-unlock"
}
```

`kind` is exactly one of:

- `vault-unlock`;
- `provider-openai-configure`;
- `provider-openai-logout`;
- `codex-device-login`;
- `codex-logout`;
- `report-export`.

The response contains only the correlated request ID and one of
`opened`, `focused`, `busy`, `unavailable`, or `failed`. Prompt text, entered
bytes, provider device codes, report contents, paths, daemon error strings,
file descriptors, and process identifiers never cross this control channel.
Only one prompt may exist at a time. A repeated request of the same kind
focuses it; a different kind returns `busy`. Client disconnect cancels any
not-yet-committed operation and closes every retained descriptor.

The broker, not the WebView or Tauri command, owns all input, confirmation,
selection, timeout, zeroization, and daemon exchange. Vault passphrases and API
keys move from the native input widget to the existing descriptor-based Vault
boundary through private CLOEXEC pipes and are zeroized on every exit. Report
export selects one canonical `RP-...` ID inside the trusted prompt and retains
the existing fixed destination and no-overwrite rules. No caller supplies a
path or a command string.

The existing companion implementation should be refactored, not duplicated:
its command/state validation, descriptor exchange, reconciliation, export, and
closed error mapping become an internal backend independent of terminal I/O;
`kernaid-rescue-vaultctl` remains the terminal adapter. A new prompt adapter
supplies hidden native input and receives only safe display states. The daemon
peer allowlist must authenticate the dedicated prompt service identity and
complete systemd cgroup, never the WebView identity.

### Graphical isolation gate

The current shared X11 kiosk is not a sufficient secret-input isolation
boundary: an authorized X client can observe global input state even when a
secret never appears in a WebView IPC message. Before calling the prompt
trusted, either:

1. move the kiosk and prompt to a Wayland compositor with per-client input
   isolation and qualify the exact WebKit/renderer/prompt stack; or
2. use an automatically focused, branded, dedicated virtual-terminal prompt
   as an interim engineering path and continue to describe it as a TTY flow.

The first option is required to remove TTY from the product journey. It also
requires new physical/QEMU evidence for focus, cancellation, renderer
containment, secret non-echo, lockout, reboot, and prompt-process crash. Until
that gate is complete, the existing terminal companions remain the safe path.

## Authoritative provider-context preview

The current WebView acknowledgement is derived from the objective plus visible
evidence ID/collector metadata. It does not prove the exact redacted context
that Rust sends to OpenAI. An authoritative preview must be produced by
`project_diagnosis`; the WebView must not reproduce redaction or deterministic
proposal logic.

The minimum protocol addition is a versioned
`provider.openai.context-preview` operation with the same raw
`objective`/single-evidence payload accepted for diagnosis. The Rust provider
parses it once with `project_diagnosis` and returns only:

```json
{
  "context": {
    "objective": "redacted objective",
    "deterministicProposal": {},
    "observations": [
      {
        "id": "E-example",
        "collector": "linux.normalized-snapshot.v1",
        "trust": "observed-untrusted"
      }
    ]
  },
  "contextSha256": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
```

The digest binds a domain separator and the exact compact JSON bytes emitted by
the Rust serializer. A subsequent diagnosis request supplies that digest with
the same raw input. Rust re-runs `project_diagnosis`, recomputes the digest, and
rejects a mismatch as `invalid_request` before borrowing a credential or
opening network egress. No preview state, raw evidence content, secret, model
parameter, URL, path, or tool field is returned.

This is a protocol change rather than a local UI helper. The coordinated edit
surface is:

- `crates/rescue-openai-provider/src/rescue_corpus.rs` for canonical projected
  bytes and the domain-bound digest;
- `crates/rescue-openai-provider/src/local_wire.rs` for the preview operation,
  response, and diagnosis binding;
- `crates/rescue-openai-executor/src/linux.rs` for a local preview response
  that borrows no credential and performs no egress;
- `packages/schemas/rescue-openai-{request,response}.schema.json` and golden
  frames for the public closed grammar;
- `apps/desk/src/rescue-openai.ts` only after the backend contract exists, to
  display the returned context and echo its opaque digest without duplicating
  projection logic.

Until that coordinated protocol change lands, the UI must label its current
metadata view as a summary, not as the exact provider-context preview required
by the master plan.
