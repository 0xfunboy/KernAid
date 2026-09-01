# KernAid native secrets

`kernaid-native-secrets` is the fail-closed Resident-mode adapter for the
operating system credential store:

- Windows Credential Manager with local persistence;
- macOS Keychain; and
- Linux Secret Service.

There is no plaintext, environment-variable, or file-backed fallback. Backend
errors are mapped to fixed categories that contain no credential name, stored
value, or platform error detail.

## Compatible secure-state records

Journal keys, journal anchors, and device-identity seeds retain their existing
credential names and `kernaid-secret-v1` purpose-bound envelopes. Provider
support does not migrate, rename, or reinterpret those records.

## Profiled provider API keys

`NativeProviderApiKeyStore` stores one API key for an explicit typed
`NativeProviderKind` (`OpenAi`, `Anthropic`, or `Gemini`) and public
`ProviderProfileId`. The closed provider enum prevents arbitrary strings from
creating ambiguous native records. Profile IDs are 1–48 bytes, use lowercase
ASCII letters and digits with optional single internal hyphens, and cannot
contain paths, whitespace, repeated separators, or backend syntax.

The credential name is separated by namespace, provider, profile, and key
version. Its `kernaid-provider-secret-v1` envelope is additionally bound to the
same namespace, typed provider API-key purpose, profile, and version. Copying
an envelope to another provider, profile, namespace, or secure-state purpose
therefore fails closed. Existing OpenAI names and envelope bytes are unchanged.
`NativeOpenAiApiKeyStore` remains as a source-compatible facade over the typed
OpenAI store, including its original constructors and
`with_openai_api_key` callback.

Keys must be 1–512 bytes of visible ASCII without spaces or control bytes. No
provider prefix is assumed. The 512-byte limit keeps the full base64url
envelope below 1 KiB, a conservative cross-platform size compatible with
Windows Credential Manager generic credentials.

The API intentionally exposes only:

- `status`, returning `Absent` or `Configured` after strict decoding;
- `configure`, consuming a `Zeroizing<Vec<u8>>` and verifying exact readback;
- `with_api_key` (or the compatible OpenAI-only `with_openai_api_key`), lending
  decoded bytes only for a Rust-backend callback and zeroizing them immediately
  afterwards; and
- `logout`, an idempotent delete followed by an absence readback.

There is no raw public getter, serialization support, Tauri command, log value,
or UI bridge in this crate. An application integration must keep setup and use
inside a trusted native backend; a webview must never load a stored key.

KernAid Desk uses the fixed public profile `resident-default`. Its
`kernaid-provider-key configure [--provider <openai|anthropic|gemini>]`
companion accepts the selected key only from two matching hidden native-TTY
prompts while Desk is closed. Each Resident HTTP adapter borrows the decoded
value through its backend-only callback, retains only a `Zeroizing`
request-lifetime copy in managed application memory, and exposes no configure
command to the webview. The webview receives a closed provider mode,
presence-only status, diagnosis results, sanitized error categories, and
idempotent logout.
The companion accepts no application-data override. Its provider lock has one
fixed identity per OS user, provider kind and public profile, independent of
`HOME`/XDG path aliases on Unix and resolved through the same platform data
directory contract as Tauri on Windows.

## Required application boundary

Open each store only after acquiring the application's inter-process
single-instance lock and hold that lock for complete configure/use/logout
operations. Immediate readback detects missing or altered writes and retained
deletes, but an OS keyring cannot prevent another process with the same user
authority from replacing a credential later.

Tests use in-memory synthetic byte sequences only. No live provider credential
belongs in source, fixtures, command output, logs, or CI variables.
