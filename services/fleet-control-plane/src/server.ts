import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { extname, relative, resolve, sep } from "node:path";
import {
  FleetSchemaError,
  canonicalJson,
  enrollmentSigningBytes,
  expectExactKeys,
  expectIdentifier,
  expectRecord,
  expectSafeInteger,
  inventorySigningBytes,
  parseEnrollmentRequest,
  parseInventoryEnvelope,
} from "@kernaid/fleet-schemas";
import {
  generateSecret,
  generateTenantId,
  deviceIdForEd25519Spki,
  hashSecret,
  importEd25519Spki,
  secureSecretEqual,
  sha256Hex,
  verifyEd25519,
} from "./crypto.js";
import {
  FleetStore,
  StoreAuthorizationError,
  StoreConflictError,
  StoreReplayError,
  StoreRevokedError,
} from "./store.js";

const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_ENROLLMENT_TOKEN_SECONDS = 7 * 24 * 60 * 60;

export interface FleetControlPlaneOptions {
  databasePath: string;
  rootToken: string;
  enrollmentClockSkewMs?: number;
  now?: () => Date;
  consoleDirectory?: string;
}

export class FleetControlPlane {
  readonly #store: FleetStore;
  readonly #rootToken: string;
  readonly #clockSkewMs: number;
  readonly #now: () => Date;
  readonly #server: Server;
  readonly #consoleDirectory: string | undefined;
  #closed = false;

  constructor(options: FleetControlPlaneOptions) {
    if (
      options.rootToken.length < 32 ||
      options.rootToken.length > 512 ||
      !/^[A-Za-z0-9_-]+$/.test(options.rootToken)
    ) {
      throw new Error(
        "root token must be 32-512 canonical base64url characters",
      );
    }
    this.#store = new FleetStore(options.databasePath);
    this.#rootToken = options.rootToken;
    this.#clockSkewMs = options.enrollmentClockSkewMs ?? 300_000;
    this.#now = options.now ?? (() => new Date());
    this.#consoleDirectory = resolveConsoleDirectory(options.consoleDirectory);
    this.#server = createServer((request, response) => {
      void this.#handle(request, response);
    });
  }

  async listen(port = 0, host = "127.0.0.1"): Promise<string> {
    if (this.#closed) throw new Error("Fleet control plane is closed");
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => reject(error);
      this.#server.once("error", onError);
      this.#server.listen(port, host, () => {
        this.#server.off("error", onError);
        resolve();
      });
    });
    const address = this.#server.address() as AddressInfo;
    const renderedHost =
      address.family === "IPv6" ? `[${address.address}]` : address.address;
    return `http://${renderedHost}:${address.port}`;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#server.listening) {
      await new Promise<void>((resolve, reject) => {
        this.#server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
    }
    this.#store.close();
  }

  async #handle(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Referrer-Policy", "no-referrer");

    try {
      const url = new URL(request.url ?? "/", "http://fleet.invalid");
      if (url.search.length !== 0) throw new HttpError(400, "invalid_request");
      await this.#route(request, response, url.pathname);
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      if (error instanceof HttpError) {
        writeJson(response, error.status, { error: error.code });
      } else if (error instanceof FleetSchemaError) {
        writeJson(response, 400, { error: "invalid_request" });
      } else if (error instanceof StoreAuthorizationError) {
        writeJson(response, 401, { error: "not_authorized" });
      } else if (error instanceof StoreRevokedError) {
        writeJson(response, 403, { error: "device_revoked" });
      } else if (error instanceof StoreConflictError) {
        writeJson(response, 409, { error: "conflict" });
      } else if (error instanceof StoreReplayError) {
        writeJson(response, 409, { error: "sequence_replay" });
      } else {
        writeJson(response, 500, { error: "internal_error" });
      }
    }
  }

  async #route(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
  ): Promise<void> {
    const method = request.method ?? "GET";
    if (method === "GET" && path === "/console") {
      response.statusCode = 308;
      response.setHeader("Location", "/console/");
      response.end();
      return;
    }
    if (method === "GET" && path.startsWith("/console/")) {
      this.#serveConsoleAsset(path, response);
      return;
    }
    if (method === "GET" && path === "/healthz") {
      this.#store.healthCheck();
      writeJson(response, 200, { status: "ok" });
      return;
    }

    if (method === "POST" && path === "/v1/tenants") {
      this.#authorizeRoot(request);
      expectEmptyObject(await readJson(request));
      const tenantId = generateTenantId();
      const adminToken = generateSecret();
      const createdAt = this.#validNow().toISOString();
      this.#store.createTenant(
        tenantId,
        hashSecret("admin", adminToken),
        createdAt,
      );
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.tenant-created.v1",
        tenantId,
        adminToken,
        createdAt,
      });
      return;
    }

    const tokenMatch = /^\/v1\/tenants\/([^/]+)\/enrollment-tokens$/.exec(path);
    if (method === "POST" && tokenMatch !== null) {
      const tenantId = pathIdentifier(tokenMatch[1], "tenantId");
      this.#authorizeTenant(request, tenantId);
      const body = expectRecord(await readJson(request));
      expectExactKeys(body, ["expiresInSeconds"]);
      const expiresInSeconds = expectSafeInteger(
        body.expiresInSeconds,
        "expiresInSeconds",
        1,
      );
      if (expiresInSeconds > MAX_ENROLLMENT_TOKEN_SECONDS) {
        throw new HttpError(400, "invalid_request");
      }
      const token = generateSecret();
      const now = this.#validNow();
      const expiresAtMs = now.getTime() + expiresInSeconds * 1000;
      this.#store.createEnrollmentToken({
        tokenHash: hashSecret("enrollment", token),
        tenantId,
        createdAt: now.toISOString(),
        expiresAtMs,
      });
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.enrollment-token-created.v1",
        tenantId,
        enrollmentToken: token,
        expiresAt: new Date(expiresAtMs).toISOString(),
      });
      return;
    }

    if (method === "POST" && path === "/v1/enrollments") {
      const enrollment = parseEnrollmentRequest(await readJson(request));
      const now = this.#validNow();
      if (
        Math.abs(now.getTime() - Date.parse(enrollment.issuedAt)) >
        this.#clockSkewMs
      ) {
        throw new HttpError(401, "enrollment_timestamp_rejected");
      }
      const tokenHash = hashSecret("enrollment", enrollment.enrollmentToken);
      if (
        !this.#store.isEnrollmentTokenUsable(
          tokenHash,
          enrollment.tenantId,
          now.getTime(),
        )
      ) {
        throw new HttpError(401, "invalid_enrollment_token");
      }

      let publicKey;
      try {
        publicKey = importEd25519Spki(enrollment.publicKeySpki);
      } catch {
        throw new HttpError(400, "invalid_public_key");
      }
      if (
        deviceIdForEd25519Spki(enrollment.publicKeySpki) !== enrollment.deviceId
      ) {
        throw new HttpError(401, "device_key_mismatch");
      }
      if (
        !verifyEd25519(
          publicKey,
          enrollmentSigningBytes(enrollment),
          enrollment.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }

      this.#store.enrollDevice({
        tokenHash,
        tenantId: enrollment.tenantId,
        deviceId: enrollment.deviceId,
        publicKeySpki: enrollment.publicKeySpki,
        platform: enrollment.platform,
        agentVersion: enrollment.agentVersion,
        enrolledAt: now.toISOString(),
        nowMs: now.getTime(),
      });
      writeJson(response, 201, {
        schema: "dev.kernaid.fleet.enrollment-response.v1",
        tenantId: enrollment.tenantId,
        deviceId: enrollment.deviceId,
        enrolledAt: now.toISOString(),
        accepted: true,
      });
      return;
    }

    if (method === "POST" && path === "/v1/inventories") {
      const envelope = parseInventoryEnvelope(await readJson(request));
      const now = this.#validNow();
      if (Date.parse(envelope.observedAt) > now.getTime() + this.#clockSkewMs) {
        throw new HttpError(400, "inventory_timestamp_rejected");
      }
      const device = this.#store.getDevice(
        envelope.tenantId,
        envelope.deviceId,
      );
      if (device === undefined) throw new HttpError(401, "unknown_device");
      if (device.revokedAt !== null) throw new HttpError(403, "device_revoked");

      let publicKey;
      try {
        publicKey = importEd25519Spki(device.publicKeySpki);
      } catch {
        throw new HttpError(500, "invalid_stored_key");
      }
      if (
        !verifyEd25519(
          publicKey,
          inventorySigningBytes(envelope),
          envelope.signature,
        )
      ) {
        throw new HttpError(401, "invalid_signature");
      }

      const result = this.#store.recordInventory(
        envelope,
        sha256Hex(canonicalJson(envelope)),
        now.toISOString(),
      );
      writeJson(response, result.idempotent ? 200 : 201, {
        schema: "dev.kernaid.fleet.inventory-response.v1",
        tenantId: envelope.tenantId,
        deviceId: envelope.deviceId,
        sequence: envelope.sequence,
        accepted: true,
        idempotent: result.idempotent,
      });
      return;
    }

    const devicesMatch = /^\/v1\/tenants\/([^/]+)\/devices$/.exec(path);
    if (method === "GET" && devicesMatch !== null) {
      const tenantId = pathIdentifier(devicesMatch[1], "tenantId");
      this.#authorizeTenant(request, tenantId);
      const devices = this.#store.listDevices(tenantId).map((device) => ({
        tenantId: device.tenantId,
        deviceId: device.deviceId,
        platform: device.platform,
        agentVersion: device.agentVersion,
        enrolledAt: device.enrolledAt,
        revokedAt: device.revokedAt,
        status: device.revokedAt === null ? "active" : "revoked",
        lastSequence: device.lastSequence,
        lastSeenAt: device.lastSeenAt,
      }));
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.device-list.v1",
        tenantId,
        items: devices,
      });
      return;
    }

    const assetsMatch = /^\/v1\/tenants\/([^/]+)\/assets$/.exec(path);
    if (method === "GET" && assetsMatch !== null) {
      const tenantId = pathIdentifier(assetsMatch[1], "tenantId");
      this.#authorizeTenant(request, tenantId);
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.asset-list.v1",
        tenantId,
        items: this.#store.listAssets(tenantId),
      });
      return;
    }

    const revokeMatch =
      /^\/v1\/tenants\/([^/]+)\/devices\/([^/]+)\/revoke$/.exec(path);
    if (method === "POST" && revokeMatch !== null) {
      const tenantId = pathIdentifier(revokeMatch[1], "tenantId");
      const deviceId = pathIdentifier(revokeMatch[2], "deviceId");
      this.#authorizeTenant(request, tenantId);
      expectEmptyObject(await readJson(request));
      const revokedAt = this.#validNow().toISOString();
      if (!this.#store.revokeDevice(tenantId, deviceId, revokedAt)) {
        throw new HttpError(404, "not_found");
      }
      writeJson(response, 200, {
        schema: "dev.kernaid.fleet.device-revoked.v1",
        tenantId,
        deviceId,
        revokedAt,
      });
      return;
    }

    throw new HttpError(404, "not_found");
  }

  #authorizeRoot(request: IncomingMessage): void {
    const token = bearerToken(request);
    if (token === undefined || !secureSecretEqual(token, this.#rootToken)) {
      throw new HttpError(401, "not_authorized");
    }
  }

  #authorizeTenant(request: IncomingMessage, tenantId: string): void {
    const token = bearerToken(request);
    if (
      token === undefined ||
      !this.#store.authenticateTenant(tenantId, hashSecret("admin", token))
    ) {
      throw new HttpError(401, "not_authorized");
    }
  }

  #validNow(): Date {
    const now = this.#now();
    if (!Number.isFinite(now.getTime()))
      throw new Error("clock returned invalid time");
    return now;
  }

  #serveConsoleAsset(path: string, response: ServerResponse): void {
    if (this.#consoleDirectory === undefined) {
      throw new HttpError(404, "not_found");
    }
    let suffix: string;
    try {
      suffix = decodeURIComponent(path.slice("/console/".length));
    } catch {
      throw new HttpError(400, "invalid_request");
    }
    if (suffix === "") suffix = "index.html";
    if (
      suffix.includes("\\") ||
      suffix.includes("\0") ||
      suffix
        .split("/")
        .some((part) => part === "" || part === "." || part === "..")
    ) {
      throw new HttpError(404, "not_found");
    }

    const candidate = resolve(this.#consoleDirectory, suffix);
    const location = relative(this.#consoleDirectory, candidate);
    if (location.startsWith(`..${sep}`) || location === "..") {
      throw new HttpError(404, "not_found");
    }

    let realCandidate: string;
    try {
      realCandidate = realpathSync(candidate);
      const entry = lstatSync(realCandidate);
      const realLocation = relative(this.#consoleDirectory, realCandidate);
      if (
        !entry.isFile() ||
        realLocation.startsWith(`..${sep}`) ||
        realLocation === ".." ||
        entry.size > 10 * 1024 * 1024
      ) {
        throw new HttpError(404, "not_found");
      }
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(404, "not_found");
    }

    const body = readFileSync(realCandidate);
    response.statusCode = 200;
    response.setHeader("Content-Type", consoleMimeType(extname(realCandidate)));
    response.setHeader("Content-Length", body.length);
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    response.end(body);
  }
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

function bearerToken(request: IncomingMessage): string | undefined {
  const authorization = request.headers.authorization;
  if (authorization === undefined) return undefined;
  const match = /^Bearer ([A-Za-z0-9_-]{32,512})$/.exec(authorization);
  return match?.[1];
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const contentType = request.headers["content-type"];
  if (
    contentType === undefined ||
    !/^application\/json(?:\s*;|$)/i.test(contentType)
  ) {
    throw new HttpError(415, "json_content_type_required");
  }

  const declaredLength = request.headers["content-length"];
  if (declaredLength !== undefined) {
    const length = Number(declaredLength);
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > MAX_REQUEST_BYTES
    ) {
      throw new HttpError(413, "request_too_large");
    }
  }

  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_REQUEST_BYTES)
      throw new HttpError(413, "request_too_large");
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}

function expectEmptyObject(value: unknown): void {
  const object = expectRecord(value);
  expectExactKeys(object, []);
}

function pathIdentifier(value: string | undefined, field: string): string {
  if (value === undefined) throw new HttpError(404, "not_found");
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new HttpError(400, "invalid_request");
  }
  return expectIdentifier(decoded, field);
}

function writeJson(
  response: ServerResponse,
  status: number,
  body: unknown,
): void {
  const serialized = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(serialized));
  response.end(serialized);
}

function resolveConsoleDirectory(
  directory: string | undefined,
): string | undefined {
  if (directory === undefined) return undefined;
  const realDirectory = realpathSync(directory);
  if (!lstatSync(realDirectory).isDirectory()) {
    throw new Error("FLEET_CONSOLE_DIR must be a directory");
  }
  return realDirectory;
}

function consoleMimeType(extension: string): string {
  switch (extension.toLowerCase()) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
    case ".mjs":
      return "text/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".webp":
      return "image/webp";
    case ".ico":
      return "image/x-icon";
    default:
      return "application/octet-stream";
  }
}
