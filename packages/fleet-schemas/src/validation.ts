export class FleetSchemaError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FleetSchemaError";
  }
}

export function expectRecord(
  value: unknown,
  field = "request",
): Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new FleetSchemaError(`${field} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

export function expectExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  field = "request",
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new FleetSchemaError(`${field} contains missing or unknown fields`);
  }
}

export function expectString(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): string {
  if (typeof value !== "string") {
    throw new FleetSchemaError(`${field} is outside its permitted bounds`);
  }
  if (
    /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF])/.test(
      value,
    )
  ) {
    throw new FleetSchemaError(`${field} contains invalid Unicode`);
  }
  const encodedLength = new TextEncoder().encode(value).length;
  if (encodedLength < minimum || encodedLength > maximum) {
    throw new FleetSchemaError(`${field} is outside its permitted bounds`);
  }
  return value;
}

export function expectIdentifier(value: unknown, field: string): string {
  const identifier = expectString(value, field, 1, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(identifier)) {
    throw new FleetSchemaError(`${field} is not a valid opaque identifier`);
  }
  return identifier;
}

export function expectDeviceId(value: unknown): string {
  if (typeof value !== "string" || !/^KA-[0-9a-f]{24}$/.test(value)) {
    throw new FleetSchemaError(
      "deviceId must be a canonical KernAid key fingerprint",
    );
  }
  return value;
}

export function expectOpaqueAssetId(value: unknown): string {
  const assetId = expectString(value, "asset.assetId", 1, 256);
  if (
    [...assetId].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    })
  ) {
    throw new FleetSchemaError("asset.assetId contains a control character");
  }
  return assetId;
}

export function expectEnum<const T extends string>(
  value: unknown,
  field: string,
  options: readonly T[],
): T {
  if (typeof value !== "string" || !options.includes(value as T)) {
    throw new FleetSchemaError(`${field} is not an allowed value`);
  }
  return value as T;
}

export function expectBase64Url(
  value: unknown,
  field: string,
  minimumCharacters: number,
  maximumCharacters: number,
): string {
  const encoded = expectString(
    value,
    field,
    minimumCharacters,
    maximumCharacters,
  );
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new FleetSchemaError(`${field} must be unpadded base64url`);
  }
  if (!isCanonicalBase64Url(encoded)) {
    throw new FleetSchemaError(
      `${field} must use canonical base64url trailing bits`,
    );
  }
  return encoded;
}

function isCanonicalBase64Url(value: string): boolean {
  const remainder = value.length % 4;
  if (remainder === 1) return false;
  if (remainder === 0) return true;
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(value[value.length - 1] ?? "");
  return remainder === 2 ? (last & 0b1111) === 0 : (last & 0b11) === 0;
}

export function expectSha256(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new FleetSchemaError(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

export function expectSafeInteger(
  value: unknown,
  field: string,
  minimum: number,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new FleetSchemaError(`${field} must be a safe integer >= ${minimum}`);
  }
  return value as number;
}

export function expectRfc3339(value: unknown, field: string): string {
  const timestamp = expectString(value, field, 20, 35);
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/.exec(
      timestamp,
    );
  if (match === null) throw new FleetSchemaError(`${field} must be RFC3339`);

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zone = match[7];
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const zoneHour = zone === "Z" ? 0 : Number(zone?.slice(1, 3));
  const zoneMinute = zone === "Z" ? 0 : Number(zone?.slice(4, 6));

  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    zoneHour > 23 ||
    zoneMinute > 59 ||
    !Number.isFinite(Date.parse(timestamp))
  ) {
    throw new FleetSchemaError(`${field} must be a real RFC3339 timestamp`);
  }
  return timestamp;
}
