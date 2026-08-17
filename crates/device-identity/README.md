# KernAid signed-report verifier

`kernaid-verify-report` verifies the complete signed-report envelope while
keeping the authenticated payload out of terminal output.

```console
kernaid-verify-report \
  --device-id KA-0123456789abcdef01234567 \
  signed-report.json
```

A canonical unpadded base64url Ed25519 public key may be used instead, or
supplied together with `--device-id` for an additional consistency check:

```console
kernaid-verify-report --public-key TRUSTED_BASE64URL_KEY signed-report.json
```

The trust anchor must be copied from device enrollment or another authenticated
channel. Never copy the device ID or public key from the report being verified.
The verifier accepts only regular files up to 2 MiB and does not print the
report payload by default.

## Rust API memory contract

Authenticated report payloads are sensitive. `SignedReportEnvelope::verify`
and `SignedReportEnvelope::verify_zeroizing` both return
`VerifiedReportPayload`, an RAII value backed by `Zeroizing<Vec<u8>>`. Borrow
the bytes with `as_bytes()`, `as_slice()`, or `AsRef<[u8]>`; there is
intentionally no API that extracts a plain `Vec<u8>`. Its `Debug` output shows
only the byte length. The `verify_with_trust_anchors` and
`verify_for_device_id` variants return the same protected type.

```rust,ignore
let payload = envelope.verify_zeroizing(&trusted_public_key)?;
validate_session_report(payload.as_slice())?;
// `payload` zeroizes its full allocation here, including on early return.
```

Store and runtime consumers should keep this wrapper alive through validation;
they must not clone the borrowed bytes into an unprotected allocation or add an
outer `Zeroizing` wrapper.

This is a deliberate pre-1.0 breaking change from the former `Vec<u8>` return
type. `SignedReport` and `SignedReportEnvelope` also zeroize owned payload and
envelope fields on drop. As a consequence, move individual public fields only
by borrowing them; clone metadata such as a public key only when ownership is
required. Do not clone the base64url `payload` field.

Exit status is `0` for a verified report, `2` for arguments or trust-anchor
configuration, `3` for input errors, `4` for invalid envelope JSON, `5` for a
failed authenticity check, and `6` for output errors. Diagnostics intentionally
omit file paths, supplied values, payloads, and cryptographic internals.
