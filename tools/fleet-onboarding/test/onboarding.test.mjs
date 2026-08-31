import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createEnrollmentBundle,
  normalizeEndpoint,
  onboardTenant,
  OnboardingError,
  preflightOnboarding,
  requireExactNodeVersion,
} from "../lib.mjs";

const ROOT_TOKEN = "R".repeat(43);
const ADMIN_TOKEN = "A".repeat(43);
const ENROLLMENT_TOKEN = "E".repeat(43);
const SECOND_ENROLLMENT_TOKEN = "N".repeat(43);
const TENANT_ID = `tenant_${"a".repeat(32)}`;
const CREATED_AT = "2026-08-31T10:00:00.000Z";
const EXPIRES_AT = "2026-08-31T10:05:00.000Z";

test("preflight checks health and local owner-only boundaries without API mutation", async () => {
  const fixture = await makeFixture();
  const calls = [];
  const result = await preflightOnboarding({
    endpoint: "http://127.0.0.1:7341/",
    rootTokenFile: fixture.rootTokenFile,
    outputDirectory: fixture.outputDirectory,
    fetchImpl: mockFetch(calls, [jsonResponse(200, { status: "ok" })]),
  });

  assert.equal(result.endpoint, "http://127.0.0.1:7341");
  assert.equal(result.health, "ok");
  assert.deepEqual(
    calls.map(({ url, options }) => [url, options.method]),
    [["http://127.0.0.1:7341/healthz", "GET"]],
  );
  assert.equal(calls[0].options.headers.Authorization, undefined);
  assert.equal((await stat(fixture.outputDirectory)).mode & 0o777, 0o700);
});

test("onboard writes separated 0600 credentials and returns no secret", async () => {
  const fixture = await makeFixture();
  const calls = [];
  const fetchImpl = mockFetch(calls, [
    jsonResponse(200, { status: "ok" }),
    jsonResponse(201, {
      schema: "dev.kernaid.fleet.tenant-created.v1",
      tenantId: TENANT_ID,
      adminToken: ADMIN_TOKEN,
      createdAt: CREATED_AT,
    }),
    jsonResponse(201, {
      schema: "dev.kernaid.fleet.enrollment-token-created.v1",
      tenantId: TENANT_ID,
      enrollmentToken: ENROLLMENT_TOKEN,
      expiresAt: EXPIRES_AT,
    }),
  ]);

  const result = await onboardTenant({
    endpoint: "https://fleet.example.test",
    rootTokenFile: fixture.rootTokenFile,
    outputDirectory: fixture.outputDirectory,
    expiresInSeconds: 300,
    fetchImpl,
  });
  const admin = JSON.parse(await readFile(result.adminCredentialPath, "utf8"));
  const bundle = JSON.parse(await readFile(result.deviceBundlePath, "utf8"));

  assert.equal(calls[1].options.headers.Authorization, `Bearer ${ROOT_TOKEN}`);
  assert.equal(calls[2].options.headers.Authorization, `Bearer ${ADMIN_TOKEN}`);
  assert.deepEqual(JSON.parse(calls[1].options.body), {});
  assert.deepEqual(JSON.parse(calls[2].options.body), {
    expiresInSeconds: 300,
  });
  assert.equal(admin.adminToken, ADMIN_TOKEN);
  assert.equal("enrollmentToken" in admin, false);
  assert.equal("rootToken" in admin, false);
  assert.equal(bundle.enrollmentToken, ENROLLMENT_TOKEN);
  assert.equal(bundle.singleUse, true);
  assert.equal("adminToken" in bundle, false);
  assert.equal("rootToken" in bundle, false);
  assert.equal((await stat(result.adminCredentialPath)).mode & 0o777, 0o600);
  assert.equal((await stat(result.deviceBundlePath)).mode & 0o777, 0o600);
  const renderedResult = JSON.stringify(result);
  assert.equal(renderedResult.includes(ROOT_TOKEN), false);
  assert.equal(renderedResult.includes(ADMIN_TOKEN), false);
  assert.equal(renderedResult.includes(ENROLLMENT_TOKEN), false);
});

test("token command uses saved admin credential and never overwrites a bundle", async () => {
  const fixture = await makeFixture();
  const adminCredentialFile = join(fixture.outputDirectory, "admin.json");
  await writeFile(
    adminCredentialFile,
    `${JSON.stringify({
      schema: "dev.kernaid.fleet.tenant-admin-credential.v1",
      endpoint: "https://fleet.example.test",
      tenantId: TENANT_ID,
      adminToken: ADMIN_TOKEN,
      createdAt: CREATED_AT,
    })}\n`,
    { mode: 0o600 },
  );
  const bundleFile = join(fixture.outputDirectory, "device-02.json");
  const calls = [];
  const fetchImpl = mockFetch(calls, [
    jsonResponse(200, { status: "ok" }),
    jsonResponse(201, {
      schema: "dev.kernaid.fleet.enrollment-token-created.v1",
      tenantId: TENANT_ID,
      enrollmentToken: SECOND_ENROLLMENT_TOKEN,
      expiresAt: EXPIRES_AT,
    }),
  ]);

  const result = await createEnrollmentBundle({
    adminCredentialFile,
    bundleFile,
    expiresInSeconds: 120,
    fetchImpl,
  });
  assert.equal(calls[1].options.headers.Authorization, `Bearer ${ADMIN_TOKEN}`);
  assert.deepEqual(JSON.parse(calls[1].options.body), {
    expiresInSeconds: 120,
  });
  assert.equal(result.deviceBundlePath, bundleFile);
  await assert.rejects(
    createEnrollmentBundle({
      adminCredentialFile,
      bundleFile,
      expiresInSeconds: 120,
      fetchImpl,
    }),
    (error) =>
      error instanceof OnboardingError && error.code === "output_exists",
  );
});

test("unsafe inputs and insecure secret permissions fail before fetch", async () => {
  requireExactNodeVersion("24.18.0");
  assert.throws(
    () => requireExactNodeVersion("24.17.0"),
    (error) =>
      error instanceof OnboardingError &&
      error.code === "unsupported_node_version",
  );
  assert.throws(() => normalizeEndpoint("http://fleet.example.test"));
  assert.throws(() => normalizeEndpoint("https://user:secret@example.test"));

  const fixture = await makeFixture();
  await chmod(fixture.rootTokenFile, 0o644);
  let fetched = false;
  await assert.rejects(
    preflightOnboarding({
      endpoint: "https://fleet.example.test",
      rootTokenFile: fixture.rootTokenFile,
      outputDirectory: fixture.outputDirectory,
      fetchImpl: async () => {
        fetched = true;
        throw new Error("must not run");
      },
    }),
    (error) =>
      error instanceof OnboardingError && error.code === "insecure_permissions",
  );
  assert.equal(fetched, false);

  const symlinkTarget = join(fixture.directory, "symlink-target");
  const symlinkPath = join(fixture.directory, "output-link");
  await mkdir(symlinkTarget, { mode: 0o700 });
  await symlink(symlinkTarget, symlinkPath);
  await assert.rejects(
    preflightOnboarding({
      endpoint: "https://fleet.example.test",
      rootTokenFile: fixture.rootTokenFile,
      outputDirectory: join(symlinkPath, "must-not-be-created"),
      fetchImpl: async () => {
        fetched = true;
        throw new Error("must not run");
      },
    }),
    (error) =>
      error instanceof OnboardingError &&
      error.code === "invalid_output_directory",
  );
  await assert.rejects(stat(join(symlinkTarget, "must-not-be-created")), {
    code: "ENOENT",
  });
  assert.equal(fetched, false);
});

async function makeFixture() {
  const directory = await mkdtemp(join(tmpdir(), "kernaid-onboarding-"));
  await chmod(directory, 0o700);
  const rootTokenFile = join(directory, "root-token");
  await writeFile(rootTokenFile, `${ROOT_TOKEN}\n`, { mode: 0o600 });
  const outputDirectory = join(directory, "output");
  await mkdir(outputDirectory, { mode: 0o700 });
  return { directory, rootTokenFile, outputDirectory };
}

function mockFetch(calls, responses) {
  return async (url, options) => {
    calls.push({ url, options });
    const response = responses.shift();
    assert.ok(response, "unexpected fetch call");
    return response;
  };
}

function jsonResponse(status, value) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
