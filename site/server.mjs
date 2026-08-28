import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const publicRoot = path.join(root, "public");
const host = process.env.KAID_HOST || "127.0.0.1";
const port = parsePort(process.env.KAID_PORT || "3210");
const username = process.env.KAID_USERNAME || "funboy";
const authFile = process.env.KAID_AUTH_FILE || path.join(os.homedir(), ".config", "kaid-site", "password");
const isoPath = process.env.KAID_ISO_PATH || "";
const isoSha256Path = process.env.KAID_ISO_SHA256_PATH || (isoPath ? `${isoPath}.sha256` : "");
const retailPath = process.env.KAID_RETAIL_PATH || "";
const retailSha256Path = process.env.KAID_RETAIL_SHA256_PATH || (retailPath ? `${retailPath}.sha256` : "");
const repairCandidatePath = process.env.KAID_REPAIR_CANDIDATE_PATH || "";
const repairCandidateSha256Path = process.env.KAID_REPAIR_CANDIDATE_SHA256_PATH || (repairCandidatePath ? `${repairCandidatePath}.sha256` : "");
const sessionLifetimeMs = 12 * 60 * 60 * 1000;
const maxBodyBytes = 8 * 1024;
const maxSessions = 256;
const maxFailedLoginKeys = 2048;

const content = loadContent(path.join(root, "content.json"));
const password = readSecret(authFile);
const configuredArtifacts = Object.freeze({
  iso: loadArtifactSnapshot(isoPath, isoSha256Path, "ISO"),
  retail: loadArtifactSnapshot(retailPath, retailSha256Path, "retail image"),
  repairCandidate: loadArtifactSnapshot(
    repairCandidatePath,
    repairCandidateSha256Path,
    "repair candidate ISO",
  ),
});
const publicFiles = new Map([
  ["/", loadPublicFile("index.html", "text/html; charset=utf-8")],
  ["/index.html", loadPublicFile("index.html", "text/html; charset=utf-8")],
  ["/enterprise/", loadPublicFile("enterprise.html", "text/html; charset=utf-8")],
  ["/enterprise/index.html", loadPublicFile("enterprise.html", "text/html; charset=utf-8")],
  ["/retail.css", loadPublicFile("retail.css", "text/css; charset=utf-8")],
  ["/enterprise.css", loadPublicFile("enterprise.css", "text/css; charset=utf-8")],
  ["/styles.css", loadPublicFile("styles.css", "text/css; charset=utf-8")],
  ["/mark.svg", loadPublicFile("mark.svg", "image/svg+xml")],
]);
const loginTemplate = fs.readFileSync(path.join(root, "login.html"), "utf8");
const privateTemplate = fs.readFileSync(path.join(root, "private.html"), "utf8");
const sessions = new Map();
const failedLogins = new Map();

function parsePort(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error("KAID_PORT must be an integer between 1 and 65535");
  }
  return parsed;
}

function readSecret(filePath) {
  const stat = fs.lstatSync(filePath);
  assertOwnerOnlyFile(filePath, stat);
  const value = fs.readFileSync(filePath, "utf8").trim();
  if (!value) throw new Error(`Authentication file is empty: ${filePath}`);
  return value;
}

function assertOwnerOnlyFile(filePath, stat) {
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Expected a regular non-symlink file: ${filePath}`);
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`File is not owned by the service user: ${filePath}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`File must not be accessible by group or others: ${filePath}`);
  }
}

function assertOwnerOnlyDirectory(directoryPath) {
  const stat = fs.lstatSync(directoryPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Expected a non-symlink directory: ${directoryPath}`);
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`Directory is not owned by the service user: ${directoryPath}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`Directory must not be accessible by group or others: ${directoryPath}`);
  }
}

function loadContent(filePath) {
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  if (parsed?.schema !== "dev.kernaid.site-content.v1" || !parsed.release || !parsed.repairCandidate) {
    throw new Error("content.json does not match dev.kernaid.site-content.v1");
  }
  for (const key of ["name", "channel", "sourceCommit", "artifactVersion", "workflowUrl", "downloadName", "checksumName", "retailDownloadName", "retailChecksumName", "qualification", "warning"]) {
    if (typeof parsed.release[key] !== "string" || !parsed.release[key].trim()) {
      throw new Error(`content.json release.${key} must be a non-empty string`);
    }
  }
  for (const key of ["downloadName", "checksumName", "retailDownloadName", "retailChecksumName"]) {
    if (!/^[A-Za-z0-9._-]+$/.test(parsed.release[key])) {
      throw new Error(`content.json release.${key} is not a safe filename`);
    }
  }
  for (const key of ["name", "channel", "sourceCommit", "artifactVersion", "workflowUrl", "downloadName", "checksumName", "qualification", "warning"]) {
    if (typeof parsed.repairCandidate[key] !== "string" || !parsed.repairCandidate[key].trim()) {
      throw new Error(`content.json repairCandidate.${key} must be a non-empty string`);
    }
  }
  for (const key of ["downloadName", "checksumName"]) {
    if (!/^[A-Za-z0-9._-]+$/.test(parsed.repairCandidate[key])) {
      throw new Error(`content.json repairCandidate.${key} is not a safe filename`);
    }
  }
  for (const [label, section] of [["release", parsed.release], ["repairCandidate", parsed.repairCandidate]]) {
    let workflowUrl;
    try {
      workflowUrl = new URL(section.workflowUrl);
    } catch {
      throw new Error(`content.json ${label}.workflowUrl must be an absolute URL`);
    }
    if (workflowUrl.protocol !== "https:") {
      throw new Error(`content.json ${label}.workflowUrl must use HTTPS`);
    }
  }
  if (
    !Number.isSafeInteger(parsed.repairCandidate.workflowRunId) ||
    parsed.repairCandidate.workflowRunId < 1
  ) {
    throw new Error(
      "content.json repairCandidate.workflowRunId must be a positive safe integer",
    );
  }
  return Object.freeze(parsed);
}

function loadPublicFile(name, type) {
  const body = fs.readFileSync(path.join(publicRoot, name));
  return { body, type };
}

function safeEqual(left, right) {
  const a = Buffer.from(left || "", "utf8");
  const b = Buffer.from(right || "", "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function render(template, values) {
  return template.replace(/\{\{([a-zA-Z0-9]+)\}\}/g, (_, key) => values[key] ?? "");
}

function baseHeaders({ isPrivate = false, cache = "no-store" } = {}) {
  return {
    "Cache-Control": cache,
    "Content-Security-Policy": "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    ...(isPrivate ? { "X-Robots-Tag": "noindex, nofollow, noarchive" } : {}),
  };
}

function send(req, res, status, body, extra = {}, options = {}) {
  const buffer = Buffer.isBuffer(body) ? body : Buffer.from(body);
  res.writeHead(status, {
    ...baseHeaders(options),
    "Content-Length": String(buffer.length),
    ...extra,
  });
  res.end(req.method === "HEAD" ? undefined : buffer);
}

function redirect(res, location, extra = {}) {
  res.writeHead(303, {
    ...baseHeaders({ isPrivate: location.startsWith("/private") }),
    "Content-Length": "0",
    Location: location,
    ...extra,
  });
  res.end();
}

function getCookies(req) {
  const result = new Map();
  for (const item of String(req.headers.cookie || "").split(";")) {
    const separator = item.indexOf("=");
    if (separator < 1) continue;
    result.set(item.slice(0, separator).trim(), item.slice(separator + 1).trim());
  }
  return result;
}

function sessionFromRequest(req) {
  const token = getCookies(req).get("kaid_session") || "";
  if (!token) return null;
  const expiresAt = sessions.get(token);
  if (!expiresAt || expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return token;
}

function cleanSessions() {
  const now = Date.now();
  for (const [token, expiresAt] of sessions) {
    if (expiresAt <= now) sessions.delete(token);
  }
  while (sessions.size >= maxSessions) {
    sessions.delete(sessions.keys().next().value);
  }
}

function issueSession() {
  cleanSessions();
  const token = crypto.randomBytes(32).toString("base64url");
  sessions.set(token, Date.now() + sessionLifetimeMs);
  return token;
}

function sessionCookie(token, maxAge = Math.floor(sessionLifetimeMs / 1000)) {
  return `kaid_session=${token}; Path=/private; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}

function clientKey(req) {
  const cloudflareIp = req.headers["cf-connecting-ip"];
  return typeof cloudflareIp === "string" && cloudflareIp ? cloudflareIp : req.socket.remoteAddress || "unknown";
}

function loginAllowed(req) {
  const key = clientKey(req);
  const state = failedLogins.get(key);
  if (!state) return true;
  const now = Date.now();
  if (state.windowEnds <= now) {
    failedLogins.delete(key);
    return true;
  }
  return state.blockedUntil <= now;
}

function noteFailedLogin(req) {
  const key = clientKey(req);
  const now = Date.now();
  for (const [candidate, state] of failedLogins) {
    if (state.windowEnds <= now) failedLogins.delete(candidate);
  }
  while (failedLogins.size >= maxFailedLoginKeys) {
    failedLogins.delete(failedLogins.keys().next().value);
  }
  const previous = failedLogins.get(key);
  const count = previous && previous.windowEnds > now ? previous.count + 1 : 1;
  failedLogins.set(key, {
    count,
    windowEnds: now + 10 * 60 * 1000,
    blockedUntil: count >= 8 ? now + 5 * 60 * 1000 : 0,
  });
}

function clearFailedLogins(req) {
  failedLogins.delete(clientKey(req));
}

async function readForm(req) {
  const declaredLength = Number(req.headers["content-length"] || "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
    const error = new Error("Request body too large");
    error.status = 413;
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBodyBytes) {
      const error = new Error("Request body too large");
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function renderLogin(error = "") {
  return render(loginTemplate, {
    error: error ? `<p class="form-error" role="alert">${escapeHtml(error)}</p>` : "",
    username: escapeHtml(username),
  });
}

function loadArtifactSnapshot(filePath, checksumPath, label) {
  if (!filePath || !checksumPath) {
    return { artifact: null, error: new Error(`KernAid ${label} path is not configured`) };
  }
  let fd;
  try {
    assertOwnerOnlyDirectory(path.dirname(filePath));
    assertOwnerOnlyFile(checksumPath, fs.lstatSync(checksumPath));
    const checksumText = fs.readFileSync(checksumPath, "utf8");
    const match = /^([a-fA-F0-9]{64})(?:\s+[*]?.+)?$/m.exec(checksumText);
    if (!match) throw new Error(`Configured ${label} checksum file does not contain a SHA-256 value`);

    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    assertOwnerOnlyFile(filePath, stat);
    if (stat.size < 1) throw new Error(`Configured ${label} is empty`);

    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(4 * 1024 * 1024);
    let position = 0;
    while (position < stat.size) {
      const bytesRead = fs.readSync(fd, buffer, 0, Math.min(buffer.length, stat.size - position), position);
      if (bytesRead < 1) throw new Error(`Configured ${label} ended before its declared size`);
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const actualHash = hash.digest("hex");
    const expectedHash = match[1].toLowerCase();
    if (!safeEqual(actualHash, expectedHash)) {
      throw new Error(`Configured ${label} does not match its SHA-256 sidecar`);
    }
    return {
      artifact: Object.freeze({
        bytes: stat.size,
        fd,
        hash: actualHash,
        modified: stat.mtime.toISOString(),
        path: filePath,
      }),
      error: null,
    };
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    console.error(`KernAid ${label} unavailable: ${error.message}`);
    return { artifact: null, error };
  }
}

function readArtifact(snapshot) {
  if (!snapshot.artifact) throw snapshot.error;
  return snapshot.artifact;
}

function formatBytes(bytes) {
  return `${(bytes / (1024 ** 3)).toFixed(2)} GiB`;
}

function formatDate(isoDate) {
  return new Intl.DateTimeFormat("it-IT", {
    dateStyle: "long",
    timeZone: "UTC",
  }).format(new Date(isoDate));
}

function artifactView(snapshot) {
  try {
    const artifact = readArtifact(snapshot);
    return {
      hash: artifact.hash,
      modified: formatDate(artifact.modified),
      size: formatBytes(artifact.bytes),
      state: "File scaricabile",
      stateClass: "status-ready",
    };
  } catch {
    return {
      hash: "Non disponibile",
      modified: "Non disponibile",
      size: "Non disponibile",
      state: "Non disponibile",
      stateClass: "status-unavailable",
    };
  }
}

function renderPrivate() {
  const retail = artifactView(configuredArtifacts.retail);
  const iso = artifactView(configuredArtifacts.iso);
  const repairCandidate = artifactView(configuredArtifacts.repairCandidate);
  const release = content.release;
  const candidate = content.repairCandidate;
  return render(privateTemplate, {
    artifactName: escapeHtml(release.name),
    artifactState: retail.state,
    artifactVersion: escapeHtml(release.artifactVersion),
    channel: escapeHtml(release.channel),
    checksumName: escapeHtml(release.retailChecksumName),
    downloadName: escapeHtml(release.retailDownloadName),
    hash: escapeHtml(retail.hash),
    isoArtifactState: iso.state,
    isoChecksumName: escapeHtml(release.checksumName),
    isoDownloadName: escapeHtml(release.downloadName),
    isoHash: escapeHtml(iso.hash),
    isoModified: escapeHtml(iso.modified),
    isoSize: escapeHtml(iso.size),
    isoStateClass: iso.stateClass,
    modified: escapeHtml(retail.modified),
    qualification: escapeHtml(release.qualification),
    repairCandidateArtifactState: repairCandidate.state,
    repairCandidateArtifactVersion: escapeHtml(candidate.artifactVersion),
    repairCandidateChannel: escapeHtml(candidate.channel),
    repairCandidateChecksumName: escapeHtml(candidate.checksumName),
    repairCandidateDownloadName: escapeHtml(candidate.downloadName),
    repairCandidateHash: escapeHtml(repairCandidate.hash),
    repairCandidateModified: escapeHtml(repairCandidate.modified),
    repairCandidateName: escapeHtml(candidate.name),
    repairCandidateQualification: escapeHtml(candidate.qualification),
    repairCandidateSize: escapeHtml(repairCandidate.size),
    repairCandidateSourceCommit: escapeHtml(candidate.sourceCommit),
    repairCandidateStateClass: repairCandidate.stateClass,
    repairCandidateWarning: escapeHtml(candidate.warning),
    repairCandidateWorkflowRunId: escapeHtml(candidate.workflowRunId),
    repairCandidateWorkflowUrl: escapeHtml(candidate.workflowUrl),
    size: escapeHtml(retail.size),
    sourceCommit: escapeHtml(release.sourceCommit),
    stateClass: retail.stateClass,
    warning: escapeHtml(release.warning),
    workflowUrl: escapeHtml(release.workflowUrl),
  });
}

function parseRange(value, size) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(value || "");
  if (!match || (!match[1] && !match[2])) return null;
  let start;
  let end;
  if (!match[1]) {
    const suffix = Number(match[2]);
    if (!Number.isSafeInteger(suffix) || suffix <= 0) return null;
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] ? Number(match[2]) : size - 1;
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end < start || start >= size) {
    return null;
  }
  return { start, end: Math.min(end, size - 1) };
}

function serveArtifact(req, res, snapshot, downloadName) {
  let artifact;
  try {
    artifact = readArtifact(snapshot);
  } catch {
    send(req, res, 503, "Artefatto temporaneamente non disponibile.\n", { "Content-Type": "text/plain; charset=utf-8" }, { isPrivate: true });
    return;
  }
  const base = {
    "Accept-Ranges": "bytes",
    "Content-Disposition": `attachment; filename="${downloadName}"`,
    "Content-Type": "application/octet-stream",
    ETag: `"${artifact.hash}"`,
    "Last-Modified": new Date(artifact.modified).toUTCString(),
  };
  const requestedRange = req.headers.range;
  const range = requestedRange ? parseRange(requestedRange, artifact.bytes) : null;
  if (requestedRange && !range) {
    res.writeHead(416, {
      ...baseHeaders({ isPrivate: true }),
      ...base,
      "Content-Length": "0",
      "Content-Range": `bytes */${artifact.bytes}`,
    });
    res.end();
    return;
  }
  const start = range?.start ?? 0;
  const end = range?.end ?? artifact.bytes - 1;
  res.writeHead(range ? 206 : 200, {
    ...baseHeaders({ isPrivate: true }),
    ...base,
    "Content-Length": String(end - start + 1),
    ...(range ? { "Content-Range": `bytes ${start}-${end}/${artifact.bytes}` } : {}),
  });
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  const stream = fs.createReadStream(artifact.path, {
    autoClose: false,
    fd: artifact.fd,
    start,
    end,
  });
  stream.on("error", () => res.destroy());
  stream.pipe(res);
}

function serveChecksum(req, res, snapshot, downloadName, checksumName) {
  let artifact;
  try {
    artifact = readArtifact(snapshot);
  } catch {
    send(req, res, 503, "Checksum temporaneamente non disponibile.\n", { "Content-Type": "text/plain; charset=utf-8" }, { isPrivate: true });
    return;
  }
  send(req, res, 200, `${artifact.hash}  ${downloadName}\n`, {
    "Content-Disposition": `attachment; filename="${checksumName}"`,
    "Content-Type": "text/plain; charset=utf-8",
  }, { isPrivate: true });
}

async function handleRequest(req, res) {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/healthz") {
    if (!['GET', 'HEAD'].includes(req.method || "")) {
      send(req, res, 405, "Metodo non consentito.\n", { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
      return;
    }
    send(req, res, 200, "ok\n", { "Content-Type": "text/plain; charset=utf-8" });
    return;
  }

  if (url.pathname === "/robots.txt") {
    if (!['GET', 'HEAD'].includes(req.method || "")) {
      send(req, res, 405, "Metodo non consentito.\n", { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
      return;
    }
    send(req, res, 200, "User-agent: *\nDisallow: /private/\n", { "Content-Type": "text/plain; charset=utf-8" }, { cache: "public, max-age=3600" });
    return;
  }

  const publicFile = publicFiles.get(url.pathname);
  if (publicFile) {
    if (!['GET', 'HEAD'].includes(req.method || "")) {
      send(req, res, 405, "Metodo non consentito.\n", { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" });
      return;
    }
    send(req, res, 200, publicFile.body, { "Content-Type": publicFile.type }, { cache: "public, max-age=300" });
    return;
  }

  if (url.pathname === "/enterprise") {
    redirect(res, "/enterprise/");
    return;
  }

  if (url.pathname === "/private") {
    redirect(res, "/private/");
    return;
  }

  if (url.pathname === "/private/login") {
    if (req.method === "GET" || req.method === "HEAD") {
      if (sessionFromRequest(req)) {
        redirect(res, "/private/");
        return;
      }
      send(req, res, 200, renderLogin(), { "Content-Type": "text/html; charset=utf-8" }, { isPrivate: true });
      return;
    }
    if (req.method !== "POST") {
      send(req, res, 405, "Metodo non consentito.\n", { Allow: "GET, HEAD, POST", "Content-Type": "text/plain; charset=utf-8" }, { isPrivate: true });
      return;
    }
    if (!loginAllowed(req)) {
      send(req, res, 429, renderLogin("Troppi tentativi. Riprova tra qualche minuto."), { "Content-Type": "text/html; charset=utf-8", "Retry-After": "300" }, { isPrivate: true });
      return;
    }
    let form;
    try {
      form = await readForm(req);
    } catch (error) {
      const status = error.status === 413 ? 413 : 400;
      send(req, res, status, renderLogin(status === 413 ? "Richiesta troppo grande." : "Richiesta non valida."), { "Content-Type": "text/html; charset=utf-8" }, { isPrivate: true });
      return;
    }
    if (!safeEqual(form.get("username"), username) || !safeEqual(form.get("password"), password)) {
      noteFailedLogin(req);
      send(req, res, 401, renderLogin("Credenziali non valide."), { "Content-Type": "text/html; charset=utf-8" }, { isPrivate: true });
      return;
    }
    clearFailedLogins(req);
    const token = issueSession();
    redirect(res, "/private/", { "Set-Cookie": sessionCookie(token) });
    return;
  }

  if (!url.pathname.startsWith("/private/")) {
    send(req, res, 404, "Non trovato.\n", { "Content-Type": "text/plain; charset=utf-8" });
    return;
  }

  const session = sessionFromRequest(req);
  if (!session) {
    redirect(res, "/private/login");
    return;
  }

  if (url.pathname === "/private/logout") {
    if (req.method !== "POST") {
      send(req, res, 405, "Metodo non consentito.\n", { Allow: "POST", "Content-Type": "text/plain; charset=utf-8" }, { isPrivate: true });
      return;
    }
    sessions.delete(session);
    redirect(res, "/", { "Set-Cookie": sessionCookie("", 0) });
    return;
  }

  if (!['GET', 'HEAD'].includes(req.method || "")) {
    send(req, res, 405, "Metodo non consentito.\n", { Allow: "GET, HEAD", "Content-Type": "text/plain; charset=utf-8" }, { isPrivate: true });
    return;
  }

  if (url.pathname === "/private/") {
    send(req, res, 200, renderPrivate(), { "Content-Type": "text/html; charset=utf-8" }, { isPrivate: true });
    return;
  }
  if (url.pathname === "/private/downloads/iso") {
    serveArtifact(req, res, configuredArtifacts.iso, content.release.downloadName);
    return;
  }
  if (url.pathname === "/private/downloads/checksum") {
    serveChecksum(req, res, configuredArtifacts.iso, content.release.downloadName, content.release.checksumName);
    return;
  }
  if (url.pathname === "/private/downloads/retail") {
    serveArtifact(req, res, configuredArtifacts.retail, content.release.retailDownloadName);
    return;
  }
  if (url.pathname === "/private/downloads/retail-checksum") {
    serveChecksum(req, res, configuredArtifacts.retail, content.release.retailDownloadName, content.release.retailChecksumName);
    return;
  }
  if (url.pathname === "/private/downloads/repair-candidate") {
    serveArtifact(
      req,
      res,
      configuredArtifacts.repairCandidate,
      content.repairCandidate.downloadName,
    );
    return;
  }
  if (url.pathname === "/private/downloads/repair-candidate-checksum") {
    serveChecksum(
      req,
      res,
      configuredArtifacts.repairCandidate,
      content.repairCandidate.downloadName,
      content.repairCandidate.checksumName,
    );
    return;
  }
  send(req, res, 404, "Non trovato.\n", { "Content-Type": "text/plain; charset=utf-8" }, { isPrivate: true });
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch(() => {
    if (!res.headersSent) {
      send(req, res, 500, "Errore interno.\n", { "Content-Type": "text/plain; charset=utf-8" });
    } else {
      res.destroy();
    }
  });
});

server.listen(port, host, () => console.log(`KernAid project site listening on http://${host}:${port}`));
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => {
    for (const snapshot of Object.values(configuredArtifacts)) {
      if (snapshot.artifact) fs.closeSync(snapshot.artifact.fd);
    }
    process.exit(0);
  }));
}
