export function boundedSignedDocument(raw, configuration, tenantId) {
  const rawBytes = new TextEncoder().encode(raw).length;
  if (rawBytes === 0 || rawBytes > configuration.maximumBytes) {
    throw new Error(
      `The document must be between 1 byte and ${configuration.maximumBytes === 1024 * 1024 ? "1 MiB" : "64 KiB"}.`,
    );
  }
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("The document is not valid JSON.");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The signed document must be a JSON object.");
  }
  rejectSecretFields(value);
  if (!/^[A-Za-z0-9_-]{86}$/.test(value.signature ?? "")) {
    throw new Error(
      "The document must contain one canonical Ed25519 signature.",
    );
  }
  const schema = valueAt(value, configuration.schemaPath ?? ["schema"]);
  if (schema !== configuration.schema) {
    throw new Error(`Expected signed schema ${configuration.schema}.`);
  }
  if (
    configuration.tenantPath &&
    valueAt(value, configuration.tenantPath) !== tenantId
  ) {
    throw new Error("The signed document belongs to another tenant.");
  }
  const canonical = canonicalJson(value);
  if (new TextEncoder().encode(canonical).length > configuration.maximumBytes) {
    throw new Error("The canonical signed document exceeds its size limit.");
  }
  return canonical;
}

function valueAt(value, path) {
  let current = value;
  for (const segment of path) {
    if (current === null || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

function rejectSecretFields(value) {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach(rejectSecretFields);
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (
      /^(?:privateKey|privateKeySpki|signingKey|signingSeed|secretKey|apiKey|password|credential|accessToken|refreshToken)$/i.test(
        key,
      )
    ) {
      throw new Error(
        "Private keys, secrets and credentials cannot be published.",
      );
    }
    rejectSecretFields(child);
  }
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (
      /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF])/.test(
        value,
      )
    ) {
      throw new Error("The document contains invalid Unicode.");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Signed documents may contain only safe integers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value !== "object") {
    throw new Error("The document contains an unsupported JSON value.");
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}
