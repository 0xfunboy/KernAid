export type CanonicalJsonValue =
  | null
  | boolean
  | string
  | number
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

/**
 * Serialize the deliberately small Fleet signing data model.
 *
 * Objects are ordered recursively by key, arrays retain their order, and only
 * JSON strings, booleans, null and safe integers are accepted. Refusing other
 * JavaScript values prevents two implementations from signing different
 * representations of the same apparent payload.
 */
export function canonicalJson(value: unknown): string {
  return encodeCanonical(value, new WeakSet<object>());
}

function encodeCanonical(value: unknown, ancestors: WeakSet<object>): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") {
    if (
      /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF])/.test(
        value,
      )
    ) {
      throw new TypeError("canonical JSON strings must contain valid Unicode");
    }
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("canonical JSON numbers must be safe integers");
    }
    return JSON.stringify(value);
  }

  if (typeof value !== "object") {
    throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
  }
  if (ancestors.has(value))
    throw new TypeError("canonical JSON cannot be cyclic");

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => encodeCanonical(item, ancestors)).join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("canonical JSON objects must be plain objects");
    }
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new TypeError("canonical JSON objects cannot have symbol keys");
    }

    const objectValue = value as Record<string, unknown>;
    const entries = Object.keys(objectValue)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${encodeCanonical(objectValue[key], ancestors)}`,
      );
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}
