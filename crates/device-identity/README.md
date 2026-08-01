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

Exit status is `0` for a verified report, `2` for arguments or trust-anchor
configuration, `3` for input errors, `4` for invalid envelope JSON, `5` for a
failed authenticity check, and `6` for output errors. Diagnostics intentionally
omit file paths, supplied values, payloads, and cryptographic internals.
