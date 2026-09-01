#!/usr/bin/env node
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { canonicalJson } from "@kernaid/fleet-schemas";
import {
  evaluateEnterpriseLicense,
  parseEnterpriseLicenseEnvelope,
  verifyEnterpriseLicense,
} from "./enterprise-license.js";

const [command, ...arguments_] = process.argv.slice(2);

try {
  if (command === "verify" && [3, 4].includes(arguments_.length)) {
    const [licensePath, anchorPath, keyId, tenantId] = arguments_;
    const envelope = parseEnterpriseLicenseEnvelope(
      JSON.parse(readBounded(licensePath!, 16 * 1024, false)) as unknown,
    );
    const anchor = readBounded(anchorPath!, 1024, false).trim();
    if (!verifyEnterpriseLicense(envelope, anchor, keyId!, tenantId)) {
      fail("enterprise license signature or binding is invalid");
    }
    const nowUnix = Math.floor(Date.now() / 1_000);
    const evaluation = evaluateEnterpriseLicense(envelope.claims, {
      nowUnix,
      retainedClockUnix: nowUnix,
      revoked: false,
    });
    output({
      operation: "verify",
      valid: true,
      tenantId: envelope.claims.tenantId,
      licenseId: envelope.claims.licenseId,
      sequence: envelope.claims.sequence,
      keyId: envelope.claims.keyId,
      state: evaluation.state,
    });
  } else if (command === "import" && arguments_.length === 3) {
    const [baseUrl, tokenPath, licensePath] = arguments_;
    const license = JSON.parse(
      readBounded(licensePath!, 16 * 1024, false),
    ) as unknown;
    parseEnterpriseLicenseEnvelope(license);
    output(
      await request(
        baseUrl!,
        tokenPath!,
        "POST",
        "/v1/admin/enterprise-licenses/import",
        canonicalJson(license),
      ),
    );
  } else if (command === "status" && arguments_.length === 3) {
    const [baseUrl, tokenPath, tenantId] = arguments_;
    output(
      await request(
        baseUrl!,
        tokenPath!,
        "GET",
        `/v1/admin/enterprise-licenses/${identifier(tenantId!)}`,
      ),
    );
  } else if (command === "revoke" && arguments_.length === 4) {
    const [baseUrl, tokenPath, tenantId, licenseId] = arguments_;
    output(
      await request(
        baseUrl!,
        tokenPath!,
        "POST",
        "/v1/admin/enterprise-licenses/revoke",
        canonicalJson({
          tenantId: identifier(tenantId!),
          licenseId: identifier(licenseId!),
        }),
      ),
    );
  } else {
    fail(
      "usage: kernaid-fleet-license-admin verify <license.json> <anchor.public> <key-id> [tenant-id] | import <https-base-url> <owner-only-root-token-file> <license.json> | status <https-base-url> <owner-only-root-token-file> <tenant-id> | revoke <https-base-url> <owner-only-root-token-file> <tenant-id> <license-id>",
    );
  }
} catch (error) {
  fail(
    error instanceof Error ? error.message : "license administration failed",
  );
}

async function request(
  baseUrl: string,
  tokenPath: string,
  method: "GET" | "POST",
  path: string,
  body?: string,
): Promise<unknown> {
  const url = new URL(baseUrl);
  if (
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.protocol !== "https:" &&
      !(
        url.protocol === "http:" &&
        ["127.0.0.1", "::1", "localhost"].includes(url.hostname)
      ))
  ) {
    throw new Error("control-plane URL must be HTTPS or loopback HTTP");
  }
  url.pathname = path;
  const token = readBounded(tokenPath, 1024, true).trim();
  if (token.length < 32 || !/^[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error("root token file is invalid");
  }
  const response = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body }),
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new Error(`control plane returned HTTP ${response.status}`);
  }
  if (!response.ok) {
    const code =
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      typeof (value as Record<string, unknown>).error === "string"
        ? (value as Record<string, unknown>).error
        : "request_failed";
    throw new Error(`control plane rejected request: ${code}`);
  }
  return value;
}

function readBounded(
  path: string,
  maximum: number,
  ownerOnly: boolean,
): string {
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const entry = fstatSync(descriptor);
    if (!entry.isFile() || entry.size < 1 || entry.size > maximum) {
      throw new Error("input must be a bounded regular file");
    }
    if (
      ownerOnly &&
      process.platform !== "win32" &&
      (entry.mode & 0o077) !== 0
    ) {
      throw new Error("root token file must be owner-only");
    }
    return readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
}

function identifier(value: string): string {
  if (
    value.length < 1 ||
    value.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)
  ) {
    throw new Error("identifier is invalid");
  }
  return value;
}

function output(value: unknown): void {
  process.stdout.write(`${canonicalJson(value)}\n`);
}

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
