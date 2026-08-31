import { generateSecret, secureSecretEqual } from "./crypto.js";
import type { TenantRole } from "./access.js";

export const CONSOLE_SESSION_COOKIE = "__Host-kernaid_fleet_session";
export const CONSOLE_CSRF_HEADER = "x-kernaid-csrf";

const MAX_ACTIVE_SESSIONS = 2_048;
const MAX_RATE_LIMIT_KEYS = 4_096;
const DEFAULT_MUTATION_LIMIT = 180;
const DEFAULT_MUTATION_WINDOW_MS = 60_000;

export interface ConsoleSession {
  sessionId: string;
  csrfToken: string;
  tenantId: string;
  credentialId: string;
  role: TenantRole;
  createdAtMs: number;
  expiresAtMs: number;
  mutationWindowStartedAtMs: number;
  mutationCount: number;
}

export class ConsoleSessionCapacityError extends Error {}

export class ConsoleSessionRegistry {
  readonly #sessions = new Map<string, ConsoleSession>();
  readonly #ttlMs: number;

  constructor(ttlMs: number) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 60_000 || ttlMs > 3_600_000) {
      throw new Error(
        "console session TTL must be between 60 and 3600 seconds",
      );
    }
    this.#ttlMs = ttlMs;
  }

  create(input: {
    tenantId: string;
    credentialId: string;
    role: TenantRole;
    nowMs: number;
  }): ConsoleSession {
    this.#deleteExpired(input.nowMs);
    for (const [sessionId, session] of this.#sessions) {
      if (
        session.tenantId === input.tenantId &&
        session.credentialId === input.credentialId
      ) {
        this.#sessions.delete(sessionId);
      }
    }
    if (this.#sessions.size >= MAX_ACTIVE_SESSIONS) {
      throw new ConsoleSessionCapacityError("console session capacity reached");
    }
    const session: ConsoleSession = {
      sessionId: generateSecret(),
      csrfToken: generateSecret(),
      tenantId: input.tenantId,
      credentialId: input.credentialId,
      role: input.role,
      createdAtMs: input.nowMs,
      expiresAtMs: input.nowMs + this.#ttlMs,
      mutationWindowStartedAtMs: input.nowMs,
      mutationCount: 0,
    };
    this.#sessions.set(session.sessionId, session);
    return session;
  }

  get(sessionId: string, nowMs: number): ConsoleSession | undefined {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) return undefined;
    if (session.expiresAtMs <= nowMs) {
      this.#sessions.delete(sessionId);
      return undefined;
    }
    return session;
  }

  authorizeMutation(
    session: ConsoleSession,
    csrfToken: string | undefined,
    nowMs: number,
  ): "allowed" | "csrf" | "rate_limited" {
    if (
      csrfToken === undefined ||
      !/^[A-Za-z0-9_-]{43}$/.test(csrfToken) ||
      !secureSecretEqual(csrfToken, session.csrfToken)
    ) {
      return "csrf";
    }
    if (
      nowMs - session.mutationWindowStartedAtMs >=
      DEFAULT_MUTATION_WINDOW_MS
    ) {
      session.mutationWindowStartedAtMs = nowMs;
      session.mutationCount = 0;
    }
    if (session.mutationCount >= DEFAULT_MUTATION_LIMIT) {
      return "rate_limited";
    }
    session.mutationCount += 1;
    return "allowed";
  }

  revoke(sessionId: string): void {
    this.#sessions.delete(sessionId);
  }

  clear(): void {
    this.#sessions.clear();
  }

  #deleteExpired(nowMs: number): void {
    for (const [sessionId, session] of this.#sessions) {
      if (session.expiresAtMs <= nowMs) this.#sessions.delete(sessionId);
    }
  }
}

export class FixedWindowRateLimiter {
  readonly #entries = new Map<
    string,
    { windowStartedAtMs: number; attempts: number }
  >();

  constructor(
    readonly windowMs: number,
    readonly maximumAttempts: number,
  ) {
    if (
      !Number.isSafeInteger(windowMs) ||
      windowMs < 1_000 ||
      windowMs > 3_600_000 ||
      !Number.isSafeInteger(maximumAttempts) ||
      maximumAttempts < 1 ||
      maximumAttempts > 1_000
    ) {
      throw new Error("invalid console rate limit");
    }
  }

  consume(key: string, nowMs: number): boolean {
    let entry = this.#entries.get(key);
    if (
      entry !== undefined &&
      nowMs - entry.windowStartedAtMs >= this.windowMs
    ) {
      this.#entries.delete(key);
      entry = undefined;
    }
    if (entry === undefined) {
      this.#deleteExpired(nowMs);
      if (this.#entries.size >= MAX_RATE_LIMIT_KEYS) return false;
      this.#entries.set(key, { windowStartedAtMs: nowMs, attempts: 1 });
      return true;
    }
    if (entry.attempts >= this.maximumAttempts) return false;
    entry.attempts += 1;
    return true;
  }

  reset(key: string): void {
    this.#entries.delete(key);
  }

  clear(): void {
    this.#entries.clear();
  }

  #deleteExpired(nowMs: number): void {
    for (const [key, entry] of this.#entries) {
      if (nowMs - entry.windowStartedAtMs >= this.windowMs) {
        this.#entries.delete(key);
      }
    }
  }
}

export function consoleSessionCookie(sessionId: string, ttlMs: number): string {
  return `${CONSOLE_SESSION_COOKIE}=${sessionId}; Max-Age=${Math.floor(ttlMs / 1_000)}; Path=/; HttpOnly; Secure; SameSite=Strict; Priority=High`;
}

export function clearedConsoleSessionCookie(): string {
  return `${CONSOLE_SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict; Priority=High`;
}

export function consoleSessionId(
  cookieHeader: string | undefined,
): string | undefined {
  if (cookieHeader === undefined || cookieHeader.length > 4_096)
    return undefined;
  const matches = cookieHeader
    .split(";")
    .map((item) => item.trim())
    .filter((item) => item.startsWith(`${CONSOLE_SESSION_COOKIE}=`));
  if (matches.length !== 1) return undefined;
  const value = matches[0]?.slice(CONSOLE_SESSION_COOKIE.length + 1);
  return value !== undefined && /^[A-Za-z0-9_-]{43}$/.test(value)
    ? value
    : undefined;
}
