import {
  createHash,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";

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

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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
