import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function generateSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function generateTenantId(): string {
  return `tenant_${randomBytes(16).toString("hex")}`;
}

export function hashSecret(
  kind: "admin" | "enrollment",
  secret: string,
): string {
  return createHash("sha256")
    .update(`kernaid:fleet:${kind}-token:v1\0`, "utf8")
    .update(secret, "utf8")
    .digest("hex");
}

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function secureSecretEqual(left: string, right: string): boolean {
  const leftHash = createHash("sha256").update(left, "utf8").digest();
  const rightHash = createHash("sha256").update(right, "utf8").digest();
  return timingSafeEqual(leftHash, rightHash);
}

export function importEd25519Spki(encoded: string): KeyObject {
  const der = decodeEd25519Spki(encoded);

  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("public key is not Ed25519");
  }
  const canonicalDer = key.export({ format: "der", type: "spki" });
  if (!Buffer.from(canonicalDer).equals(der)) {
    throw new Error("public key SPKI is not canonical DER");
  }
  return key;
}

export function importEd25519Raw(encoded: string): KeyObject {
  const raw = decodeBase64UrlExact(encoded);
  if (raw.length !== 32) {
    throw new Error("public key must be a raw Ed25519 key");
  }
  return importEd25519Spki(
    Buffer.concat([ED25519_SPKI_PREFIX, raw]).toString("base64url"),
  );
}

export function importEd25519PrivatePkcs8(der: Uint8Array): KeyObject {
  const encoded = Buffer.from(der);
  const key = createPrivateKey({ key: encoded, format: "der", type: "pkcs8" });
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new Error("private key is not Ed25519");
  }
  const canonical = Buffer.from(key.export({ format: "der", type: "pkcs8" }));
  if (!canonical.equals(encoded)) {
    throw new Error("private key PKCS#8 is not canonical DER");
  }
  return key;
}

export function ed25519RawPublicKey(key: KeyObject): string {
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  if (publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("key is not Ed25519");
  }
  const der = Buffer.from(publicKey.export({ format: "der", type: "spki" }));
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("public key is not canonical Ed25519 SPKI");
  }
  return der.subarray(ED25519_SPKI_PREFIX.length).toString("base64url");
}

export function signEd25519(key: KeyObject, message: Uint8Array): string {
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new Error("signing key is not a private Ed25519 key");
  }
  return sign(null, message, key).toString("base64url");
}

export function deviceIdForEd25519Spki(encoded: string): string {
  const rawPublicKey = decodeEd25519Spki(encoded).subarray(
    ED25519_SPKI_PREFIX.length,
  );
  return `KA-${createHash("sha256").update(rawPublicKey).digest("hex").slice(0, 24)}`;
}

export function verifyEd25519(
  key: KeyObject,
  message: Uint8Array,
  encodedSignature: string,
): boolean {
  try {
    const signature = decodeBase64UrlExact(encodedSignature);
    return signature.length === 64 && verify(null, message, key, signature);
  } catch {
    return false;
  }
}

export function decodeBase64UrlExact(encoded: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error("value is not unpadded base64url");
  }
  const decoded = Buffer.from(encoded, "base64url");
  if (decoded.toString("base64url") !== encoded) {
    throw new Error("value is not canonical base64url");
  }
  return decoded;
}

function decodeEd25519Spki(encoded: string): Buffer {
  const der = decodeBase64UrlExact(encoded);
  if (
    der.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("public key is not a canonical Ed25519 SPKI");
  }
  return der;
}
