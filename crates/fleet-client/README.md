# KernAid Fleet client E1

`kernaid-fleet-client` is the offline-first device side of Fleet enrollment
and inventory. It signs both protocols with the existing
`kernaid-device-identity::DeviceIdentity`; the Ed25519 seed is never copied
into Fleet state or serialized.

## Enrollment

```rust,ignore
let request = SignedEnrollmentRequest::sign(
    &identity,
    EnrollmentRequestInput::new(
        enrollment_token,
        tenant_id,
        EnrollmentPlatform::Linux,
        env!("CARGO_PKG_VERSION"),
        issued_at,
        nonce,
    ),
)?;
let transfer = request.export_offline()?;

// The enrollment service must supply the expected tenant and one-time token.
let verified = SignedEnrollmentRequest::import_offline(
    &transfer,
    expected_tenant,
    expected_one_time_token,
)?;
let device_public_key = verified.verify(expected_tenant, expected_one_time_token)?;
```

The public key is encoded as canonical unpadded base64url of an Ed25519
SubjectPublicKeyInfo DER value. The signature covers the recursive,
lexicographically-keyed canonical JSON of every field except `signature`,
prefixed by `kernaid:fleet:enrollment:v1\0`.

## Inventory

```rust,ignore
let envelope = SignedInventoryEnvelope::sign(
    &identity,
    InventoryEnvelopeInput::new(tenant_id, 1, observed_at, asset),
)?;
let transfer = envelope.export_offline()?;

// The receiver uses the public key retained during enrollment as its anchor.
let verified = SignedInventoryEnvelope::import_offline(
    &transfer,
    expected_tenant,
    expected_device_id,
    &enrolled_public_key,
)?;
```

Use `sign_inventory_batch` when a session observes several assets. It creates
one independently signed envelope per asset with consecutive sequence values;
it does not place multiple machines into an ambiguous shared signature.

## Wire and privacy rules

- Offline files are canonical JSON and imports reject whitespace, alternate
  escaping, reordered keys, duplicate/unknown fields, floats, and integers
  outside JavaScript's safe integer range. A successful import/export replay is
  byte-identical.
- IDs, versions, timestamps, hashes, counts, nonce, and total transfer size are
  bounded before signing or verification.
- `Debug` output omits enrollment tokens, nonces, signatures, public keys,
  target fingerprints, and snapshot hashes.
- Enrollment verification requires the expected tenant and one-time token.
  Inventory verification requires the tenant, device ID, and enrolled public
  key supplied by the caller; embedded fields are never treated as trust
  anchors.
- There is deliberately no HTTP dependency. The same bytes can be moved by
  removable media, an authenticated transport, or a later Fleet uploader.
