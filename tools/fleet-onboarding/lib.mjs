import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { link, lstat, mkdir, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join, parse, resolve, sep } from "node:path";

export const EXACT_NODE_VERSION = "24.18.0";
export const DEFAULT_EXPIRES_IN_SECONDS = 300;
export const MIN_EXPIRES_IN_SECONDS = 60;
export const MAX_EXPIRES_IN_SECONDS = 900;
export const ADMIN_CREDENTIAL_FILENAME = "tenant-admin.json";
export const DEVICE_BUNDLE_FILENAME = "device-enrollment.json";

const ADMIN_SCHEMA = "dev.kernaid.fleet.tenant-admin-credential.v1";
const BUNDLE_SCHEMA = "dev.kernaid.fleet.device-onboarding-bundle.v1";
const TENANT_CREATED_SCHEMA = "dev.kernaid.fleet.tenant-created.v1";
const TOKEN_CREATED_SCHEMA = "dev.kernaid.fleet.enrollment-token-created.v1";
const MAX_ENDPOINT_CHARACTERS = 2_048;
const MAX_PATH_CHARACTERS = 4_096;
const MAX_SECRET_FILE_BYTES = 16 * 1_024;
const MAX_RESPONSE_BYTES = 64 * 1_024;
const DEFAULT_TIMEOUT_MS = 10_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 30_000;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{32,512}$/;
const TENANT_PATTERN = /^tenant_[a-f0-9]{32}$/;

export class OnboardingError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = "OnboardingError";
    this.code = code;
  }
}

export function requireExactNodeVersion(version = process.versions.node) {
  if (version !== EXACT_NODE_VERSION) {
    throw new OnboardingError(
      "unsupported_node_version",
      `This wizard requires Node.js ${EXACT_NODE_VERSION} exactly.`,
    );
  }
}

export function normalizeEndpoint(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_ENDPOINT_CHARACTERS ||
    hasControlCharacter(value)
  ) {
    throw new OnboardingError("invalid_endpoint", "Invalid Fleet endpoint.");
  }

  let endpoint;
  try {
    endpoint = new URL(value);
  } catch {
    throw new OnboardingError("invalid_endpoint", "Invalid Fleet endpoint.");
  }
  if (
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.search !== "" ||
    endpoint.hash !== "" ||
    (endpoint.pathname !== "" && endpoint.pathname !== "/")
  ) {
    throw new OnboardingError(
      "invalid_endpoint",
      "Fleet endpoint must be an origin without credentials, path, query, or fragment.",
    );
  }

  const isLoopback =
    endpoint.hostname === "localhost" ||
    endpoint.hostname === "127.0.0.1" ||
    endpoint.hostname === "[::1]";
  if (
    endpoint.protocol !== "https:" &&
    !(endpoint.protocol === "http:" && isLoopback)
  ) {
    throw new OnboardingError(
      "invalid_endpoint",
      "Fleet endpoint must use HTTPS; HTTP is accepted only on exact loopback hosts.",
    );
  }
  return endpoint.origin;
}

export function validateExpiresInSeconds(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_EXPIRES_IN_SECONDS ||
    value > MAX_EXPIRES_IN_SECONDS
  ) {
    throw new OnboardingError(
      "invalid_expiry",
      `Enrollment expiry must be ${MIN_EXPIRES_IN_SECONDS}-${MAX_EXPIRES_IN_SECONDS} seconds.`,
    );
  }
  return value;
}

export async function checkFleetHealth({
  endpoint,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const normalizedEndpoint = normalizeEndpoint(endpoint);
  validateTimeout(timeoutMs);
  const body = await requestJson({
    fetchImpl,
    url: `${normalizedEndpoint}/healthz`,
    method: "GET",
    timeoutMs,
  });
  expectExactObject(body, ["status"], "health response");
  if (body.status !== "ok") {
    throw new OnboardingError(
      "unhealthy_endpoint",
      "Fleet health response was not healthy.",
    );
  }
  return Object.freeze({ endpoint: normalizedEndpoint, status: "ok" });
}

export async function preflightOnboarding({
  endpoint,
  rootTokenFile,
  outputDirectory,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const normalizedEndpoint = normalizeEndpoint(endpoint);
  const directory = await ensureOwnerOnlyDirectory(outputDirectory);
  const adminCredentialPath = join(directory, ADMIN_CREDENTIAL_FILENAME);
  const deviceBundlePath = join(directory, DEVICE_BUNDLE_FILENAME);
  await assertPathDoesNotExist(adminCredentialPath);
  await assertPathDoesNotExist(deviceBundlePath);
  await readOwnerOnlyToken(rootTokenFile, "Fleet root token");
  await checkFleetHealth({
    endpoint: normalizedEndpoint,
    fetchImpl,
    timeoutMs,
  });
  return Object.freeze({
    endpoint: normalizedEndpoint,
    outputDirectory: directory,
    adminCredentialPath,
    deviceBundlePath,
    health: "ok",
  });
}

export async function onboardTenant({
  endpoint,
  rootTokenFile,
  outputDirectory,
  expiresInSeconds = DEFAULT_EXPIRES_IN_SECONDS,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const expiry = validateExpiresInSeconds(expiresInSeconds);
  const preflight = await preflightOnboarding({
    endpoint,
    rootTokenFile,
    outputDirectory,
    fetchImpl,
    timeoutMs,
  });
  const rootToken = await readOwnerOnlyToken(rootTokenFile, "Fleet root token");
  const tenantResponse = parseTenantCreatedResponse(
    await requestJson({
      fetchImpl,
      url: `${preflight.endpoint}/v1/tenants`,
      method: "POST",
      bearerToken: rootToken,
      body: {},
      timeoutMs,
    }),
  );

  await writeOwnerOnlyJson(preflight.adminCredentialPath, {
    schema: ADMIN_SCHEMA,
    endpoint: preflight.endpoint,
    tenantId: tenantResponse.tenantId,
    adminToken: tenantResponse.adminToken,
    createdAt: tenantResponse.createdAt,
  });

  let tokenResponse;
  try {
    tokenResponse = parseEnrollmentTokenResponse(
      await requestJson({
        fetchImpl,
        url: `${preflight.endpoint}/v1/tenants/${encodeURIComponent(tenantResponse.tenantId)}/enrollment-tokens`,
        method: "POST",
        bearerToken: tenantResponse.adminToken,
        body: { expiresInSeconds: expiry },
        timeoutMs,
      }),
      tenantResponse.tenantId,
    );
    await writeDeviceBundle(
      preflight.deviceBundlePath,
      preflight.endpoint,
      tokenResponse,
    );
  } catch (error) {
    throw new OnboardingError(
      "device_bundle_not_created",
      `Tenant was created and its admin credential was saved at ${preflight.adminCredentialPath}. Retry with the token command.`,
      { cause: error },
    );
  }

  return Object.freeze({
    endpoint: preflight.endpoint,
    tenantId: tenantResponse.tenantId,
    adminCredentialPath: preflight.adminCredentialPath,
    deviceBundlePath: preflight.deviceBundlePath,
    expiresAt: tokenResponse.expiresAt,
  });
}

export async function createEnrollmentBundle({
  adminCredentialFile,
  bundleFile,
  expiresInSeconds = DEFAULT_EXPIRES_IN_SECONDS,
  fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
}) {
  const expiry = validateExpiresInSeconds(expiresInSeconds);
  validateTimeout(timeoutMs);
  const credential = await readAdminCredential(adminCredentialFile);
  await assertSecureOutputTarget(bundleFile);
  await checkFleetHealth({
    endpoint: credential.endpoint,
    fetchImpl,
    timeoutMs,
  });
  const tokenResponse = parseEnrollmentTokenResponse(
    await requestJson({
      fetchImpl,
      url: `${credential.endpoint}/v1/tenants/${encodeURIComponent(credential.tenantId)}/enrollment-tokens`,
      method: "POST",
      bearerToken: credential.adminToken,
      body: { expiresInSeconds: expiry },
      timeoutMs,
    }),
    credential.tenantId,
  );
  const outputPath = await writeDeviceBundle(
    bundleFile,
    credential.endpoint,
    tokenResponse,
  );
  return Object.freeze({
    endpoint: credential.endpoint,
    tenantId: credential.tenantId,
    deviceBundlePath: outputPath,
    expiresAt: tokenResponse.expiresAt,
  });
}

async function writeDeviceBundle(path, endpoint, tokenResponse) {
  return writeOwnerOnlyJson(path, {
    schema: BUNDLE_SCHEMA,
    endpoint,
    tenantId: tokenResponse.tenantId,
    enrollmentToken: tokenResponse.enrollmentToken,
    expiresAt: tokenResponse.expiresAt,
    singleUse: true,
  });
}

async function readAdminCredential(path) {
  const bytes = await readOwnerOnlyFile(path, "tenant admin credential");
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new OnboardingError(
      "invalid_admin_credential",
      "Tenant admin credential is not valid JSON.",
    );
  }
  expectExactObject(
    value,
    ["adminToken", "createdAt", "endpoint", "schema", "tenantId"],
    "tenant admin credential",
  );
  if (
    value.schema !== ADMIN_SCHEMA ||
    !SECRET_PATTERN.test(value.adminToken) ||
    !TENANT_PATTERN.test(value.tenantId) ||
    !isRfc3339(value.createdAt)
  ) {
    throw new OnboardingError(
      "invalid_admin_credential",
      "Tenant admin credential failed validation.",
    );
  }
  const endpoint = normalizeEndpoint(value.endpoint);
  if (endpoint !== value.endpoint) {
    throw new OnboardingError(
      "invalid_admin_credential",
      "Tenant admin credential endpoint is not canonical.",
    );
  }
  return { ...value, endpoint };
}

function parseTenantCreatedResponse(value) {
  expectExactObject(
    value,
    ["adminToken", "createdAt", "schema", "tenantId"],
    "tenant creation response",
  );
  if (
    value.schema !== TENANT_CREATED_SCHEMA ||
    !TENANT_PATTERN.test(value.tenantId) ||
    !SECRET_PATTERN.test(value.adminToken) ||
    !isRfc3339(value.createdAt)
  ) {
    throw new OnboardingError(
      "invalid_api_response",
      "Fleet returned an invalid tenant creation response.",
    );
  }
  return value;
}

function parseEnrollmentTokenResponse(value, tenantId) {
  expectExactObject(
    value,
    ["enrollmentToken", "expiresAt", "schema", "tenantId"],
    "enrollment token response",
  );
  if (
    value.schema !== TOKEN_CREATED_SCHEMA ||
    value.tenantId !== tenantId ||
    !SECRET_PATTERN.test(value.enrollmentToken) ||
    !isRfc3339(value.expiresAt)
  ) {
    throw new OnboardingError(
      "invalid_api_response",
      "Fleet returned an invalid enrollment token response.",
    );
  }
  return value;
}

async function requestJson({
  fetchImpl,
  url,
  method,
  bearerToken,
  body,
  timeoutMs,
}) {
  if (typeof fetchImpl !== "function") {
    throw new OnboardingError(
      "invalid_transport",
      "A Fetch-compatible transport is required.",
    );
  }
  validateTimeout(timeoutMs);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  timeout.unref?.();
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (bearerToken !== undefined)
    headers.Authorization = `Bearer ${bearerToken}`;

  try {
    const response = await fetchImpl(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: controller.signal,
    });
    return await parseJsonResponse(response);
  } catch (error) {
    if (error instanceof OnboardingError) throw error;
    throw new OnboardingError(
      "network_error",
      "Fleet endpoint could not be reached.",
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function parseJsonResponse(response) {
  if (
    response === null ||
    typeof response !== "object" ||
    !Number.isInteger(response.status) ||
    typeof response.headers?.get !== "function"
  ) {
    throw new OnboardingError(
      "invalid_api_response",
      "Fleet returned an invalid HTTP response.",
    );
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new OnboardingError(
      "invalid_api_response",
      "Fleet response must use application/json.",
    );
  }
  const text = await readBoundedResponseText(response);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new OnboardingError(
      "invalid_api_response",
      "Fleet returned invalid JSON.",
    );
  }
  if (response.status < 200 || response.status > 299) {
    const safeCode =
      isPlainObject(parsed) &&
      Object.keys(parsed).length === 1 &&
      typeof parsed.error === "string" &&
      /^[a-z0-9_]{1,64}$/.test(parsed.error)
        ? parsed.error
        : "request_rejected";
    throw new OnboardingError(
      safeCode,
      `Fleet rejected the request with HTTP ${response.status} (${safeCode}).`,
    );
  }
  return parsed;
}

async function readBoundedResponseText(response) {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (
      !Number.isSafeInteger(length) ||
      length < 0 ||
      length > MAX_RESPONSE_BYTES
    ) {
      throw new OnboardingError(
        "invalid_api_response",
        "Fleet response exceeded the allowed size.",
      );
    }
  }

  if (response.body === null || response.body === undefined) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new OnboardingError(
          "invalid_api_response",
          "Fleet response exceeded the allowed size.",
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new OnboardingError(
      "invalid_api_response",
      "Fleet response was not valid UTF-8.",
    );
  }
}

async function ensureOwnerOnlyDirectory(path) {
  const absolute = validatePath(path, "output directory");
  await assertNoSymlinkTraversal(absolute);
  try {
    await mkdir(absolute, { recursive: true, mode: 0o700 });
  } catch {
    throw new OnboardingError(
      "invalid_output_directory",
      "Output directory could not be created safely.",
    );
  }
  let canonical;
  try {
    canonical = await realpath(absolute);
  } catch {
    throw new OnboardingError(
      "invalid_output_directory",
      "Output directory could not be resolved.",
    );
  }
  if (canonical !== absolute) {
    throw new OnboardingError(
      "invalid_output_directory",
      "Output directory must not traverse symbolic links.",
    );
  }
  const entry = await lstat(canonical);
  if (!entry.isDirectory() || entry.isSymbolicLink()) {
    throw new OnboardingError(
      "invalid_output_directory",
      "Output location must be a directory.",
    );
  }
  assertOwnerOnly(entry, "Output directory");
  return canonical;
}

async function assertSecureOutputTarget(path) {
  const absolute = validatePath(path, "bundle file");
  const directory = await ensureOwnerOnlyDirectory(dirname(absolute));
  if (join(directory, basename(absolute)) !== absolute) {
    throw new OnboardingError(
      "invalid_output_path",
      "Output file must be inside its canonical owner-only directory.",
    );
  }
  await assertPathDoesNotExist(absolute);
  return absolute;
}

async function writeOwnerOnlyJson(path, value) {
  const target = await assertSecureOutputTarget(path);
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_SECRET_FILE_BYTES) {
    throw new OnboardingError(
      "output_too_large",
      "Credential output exceeded the allowed size.",
    );
  }
  const directory = dirname(target);
  const temporary = join(
    directory,
    `.${basename(target)}.${randomBytes(8).toString("hex")}.tmp`,
  );
  const flags =
    fsConstants.O_WRONLY |
    fsConstants.O_CREAT |
    fsConstants.O_EXCL |
    (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  let linked = false;
  try {
    handle = await open(temporary, flags, 0o600);
    await handle.writeFile(serialized, "utf8");
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, target);
    linked = true;
    await unlink(temporary);
    await syncDirectory(directory);
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => {});
    await unlink(temporary).catch(() => {});
    if (linked) await unlink(target).catch(() => {});
    if (error instanceof OnboardingError) throw error;
    throw new OnboardingError(
      "credential_write_failed",
      "Could not create the owner-only credential file.",
    );
  }
  try {
    const entry = await lstat(target);
    if (
      !entry.isFile() ||
      entry.isSymbolicLink() ||
      (entry.mode & 0o777) !== 0o600
    ) {
      throw new OnboardingError(
        "credential_write_failed",
        "Credential file permissions failed verification.",
      );
    }
    assertOwnedByCurrentUser(entry, "Credential file");
  } catch {
    await unlink(target).catch(() => {});
    throw new OnboardingError(
      "credential_write_failed",
      "Credential file permissions failed verification.",
    );
  }
  return target;
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, fsConstants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    if (error?.code !== "EINVAL" && error?.code !== "ENOTSUP") throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function readOwnerOnlyToken(path, label) {
  const bytes = await readOwnerOnlyFile(path, label);
  let token = bytes.toString("utf8");
  if (token.endsWith("\n")) token = token.slice(0, -1);
  if (!SECRET_PATTERN.test(token)) {
    throw new OnboardingError(
      "invalid_secret_file",
      `${label} file must contain one canonical base64url token.`,
    );
  }
  return token;
}

async function readOwnerOnlyFile(path, label) {
  const absolute = validatePath(path, `${label} file`);
  let canonical;
  try {
    canonical = await realpath(absolute);
  } catch {
    throw new OnboardingError(
      "secret_file_unavailable",
      `${label} file is unavailable.`,
    );
  }
  if (canonical !== absolute) {
    throw new OnboardingError(
      "invalid_secret_file",
      `${label} path must not traverse symbolic links.`,
    );
  }
  let pathEntry;
  try {
    pathEntry = await lstat(absolute);
  } catch {
    throw new OnboardingError(
      "secret_file_unavailable",
      `${label} file is unavailable.`,
    );
  }
  if (!pathEntry.isFile() || pathEntry.isSymbolicLink()) {
    throw new OnboardingError(
      "invalid_secret_file",
      `${label} must be a regular non-symlink file.`,
    );
  }
  assertOwnerOnly(pathEntry, `${label} file`);
  if (pathEntry.size < 1 || pathEntry.size > MAX_SECRET_FILE_BYTES) {
    throw new OnboardingError(
      "invalid_secret_file",
      `${label} file has an invalid size.`,
    );
  }

  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(absolute, flags);
    const openedEntry = await handle.stat();
    if (
      !openedEntry.isFile() ||
      openedEntry.dev !== pathEntry.dev ||
      openedEntry.ino !== pathEntry.ino ||
      openedEntry.size !== pathEntry.size
    ) {
      throw new OnboardingError(
        "secret_file_changed",
        `${label} file changed while it was being opened.`,
      );
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength > MAX_SECRET_FILE_BYTES) {
      throw new OnboardingError(
        "invalid_secret_file",
        `${label} file has an invalid size.`,
      );
    }
    return bytes;
  } catch (error) {
    if (error instanceof OnboardingError) throw error;
    throw new OnboardingError(
      "secret_file_unavailable",
      `${label} file could not be read.`,
    );
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function assertPathDoesNotExist(path) {
  try {
    await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw new OnboardingError(
      "output_check_failed",
      "Output path could not be checked safely.",
    );
  }
  throw new OnboardingError(
    "output_exists",
    `Refusing to overwrite existing output: ${path}`,
  );
}

function assertOwnerOnly(entry, label) {
  assertOwnedByCurrentUser(entry, label);
  if ((entry.mode & 0o077) !== 0) {
    throw new OnboardingError(
      "insecure_permissions",
      `${label} must not grant group or other permissions.`,
    );
  }
}

function assertOwnedByCurrentUser(entry, label) {
  const uid = process.getuid?.();
  if (uid !== undefined && entry.uid !== uid) {
    throw new OnboardingError(
      "wrong_owner",
      `${label} must be owned by the current user.`,
    );
  }
}

function validatePath(value, label) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_PATH_CHARACTERS ||
    hasControlCharacter(value)
  ) {
    throw new OnboardingError("invalid_path", `Invalid ${label} path.`);
  }
  return resolve(value);
}

async function assertNoSymlinkTraversal(absolute) {
  const root = parse(absolute).root;
  const parts = absolute.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = join(current, part);
    let entry;
    try {
      entry = await lstat(current);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw new OnboardingError(
        "invalid_output_directory",
        "Output directory path could not be inspected safely.",
      );
    }
    if (entry.isSymbolicLink()) {
      throw new OnboardingError(
        "invalid_output_directory",
        "Output directory must not traverse symbolic links.",
      );
    }
    if (!entry.isDirectory() && current !== absolute) {
      throw new OnboardingError(
        "invalid_output_directory",
        "Output directory parent must be a directory.",
      );
    }
  }
}

function validateTimeout(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_TIMEOUT_MS ||
    value > MAX_TIMEOUT_MS
  ) {
    throw new OnboardingError(
      "invalid_timeout",
      "HTTP timeout must be 1-30 seconds.",
    );
  }
}

function expectExactObject(value, keys, label) {
  if (!isPlainObject(value)) {
    throw new OnboardingError(
      "invalid_api_response",
      `${label} must be a JSON object.`,
    );
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new OnboardingError(
      "invalid_api_response",
      `${label} contained unexpected fields.`,
    );
  }
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function isRfc3339(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) {
    return false;
  }
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value
  );
}

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
