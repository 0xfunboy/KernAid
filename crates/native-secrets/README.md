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

## Profiled OpenAI API keys

`NativeOpenAiApiKeyStore` stores one API key for an explicit public
`ProviderProfileId`. Profile IDs are 1–48 bytes, use lowercase ASCII letters
and digits with optional single internal hyphens, and cannot contain paths,
whitespace, repeated separators, or backend syntax.

The credential name is separated by namespace, provider, profile, and key
version. Its `kernaid-provider-secret-v1` envelope is additionally bound to the
same namespace, OpenAI API-key purpose, profile, and version. Copying an
envelope to another profile or secure-state purpose therefore fails closed.

Keys must be 1–512 bytes of visible ASCII without spaces or control bytes. No
provider prefix is assumed. The 512-byte limit keeps the full base64url
envelope below 1 KiB, a conservative cross-platform size compatible with
Windows Credential Manager generic credentials.

The API intentionally exposes only:

- `status`, returning `Absent` or `Configured` after strict decoding;
- `configure`, consuming a `Zeroizing<Vec<u8>>` and verifying exact readback;
- `with_openai_api_key`, lending decoded bytes only for a Rust-backend
  callback and zeroizing them immediately afterwards; and
- `logout`, an idempotent delete followed by an absence readback.

There is no raw public getter, serialization support, Tauri command, log value,
or UI bridge in this crate. An application integration must keep setup and use
inside a trusted native backend; a webview must never load a stored key.

## Required application boundary

Open each store only after acquiring the application's inter-process
single-instance lock and hold that lock for complete configure/use/logout
operations. Immediate readback detects missing or altered writes and retained
deletes, but an OS keyring cannot prevent another process with the same user
authority from replacing a credential later.

Tests use in-memory synthetic byte sequences only. No live provider credential
belongs in source, fixtures, command output, logs, or CI variables.
