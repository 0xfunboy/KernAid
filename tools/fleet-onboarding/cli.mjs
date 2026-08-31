#!/usr/bin/env node

import { createInterface } from "node:readline/promises";
import {
  createEnrollmentBundle,
  DEFAULT_EXPIRES_IN_SECONDS,
  onboardTenant,
  OnboardingError,
  preflightOnboarding,
  requireExactNodeVersion,
} from "./lib.mjs";

const HELP = `KernAid Fleet Enterprise onboarding wizard

Usage:
  node tools/fleet-onboarding/cli.mjs preflight [options]
  node tools/fleet-onboarding/cli.mjs onboard [options]
  node tools/fleet-onboarding/cli.mjs token [options]

Commands:
  preflight  Check Fleet health and local secret/output boundaries. No API writes.
  onboard    Create one tenant and one short-lived single-use device bundle.
  token      Create another device bundle from a saved tenant admin credential.

Options for preflight/onboard:
  --endpoint URL             Fleet HTTPS origin (HTTP only for exact loopback)
  --root-token-file PATH     Owner-only Fleet root-token file
  --output-dir PATH          New or existing owner-only output directory

Options for onboard/token:
  --expires-in SECONDS       60-900; default 300
  --yes                      Skip the interactive confirmation

Options for token:
  --admin-credential-file PATH  Owner-only file created by onboard
  --bundle-file PATH            Non-existing output file in an owner-only directory

Secret values are accepted only from owner-only files. The wizard never prints
root, tenant-admin, enrollment, signing, or device-identity secret values.
`;

const COMMANDS = new Set(["preflight", "onboard", "token"]);
const VALUE_OPTIONS = new Set([
  "--endpoint",
  "--root-token-file",
  "--output-dir",
  "--expires-in",
  "--admin-credential-file",
  "--bundle-file",
]);
const FLAG_OPTIONS = new Set(["--yes", "--help"]);
const MAX_ARGUMENTS = 32;
const MAX_ARGUMENT_CHARACTERS = 4_096;

async function main(argv) {
  if (argv.includes("--help") || argv[0] === "help" || argv.length === 0) {
    process.stdout.write(HELP);
    return;
  }
  requireExactNodeVersion();
  const parsed = parseArguments(argv);
  const prompt = createPrompt();
  try {
    if (parsed.command === "preflight") {
      const options = await collectNewTenantOptions(parsed.values, prompt);
      const result = await preflightOnboarding(options);
      process.stdout.write(
        `Preflight passed for ${result.endpoint}.\nSecure output directory: ${result.outputDirectory}\n`,
      );
      return;
    }
    if (parsed.command === "onboard") {
      const options = await collectNewTenantOptions(parsed.values, prompt);
      options.expiresInSeconds = parseExpiry(parsed.values.get("--expires-in"));
      await confirmOrFail(
        parsed.flags.has("--yes"),
        prompt,
        "Create one tenant and one single-use enrollment bundle?",
      );
      const result = await onboardTenant(options);
      process.stdout.write(
        `Tenant created: ${result.tenantId}\nTenant admin credential: ${result.adminCredentialPath}\nSingle-use device bundle: ${result.deviceBundlePath}\nExpires at: ${result.expiresAt}\n`,
      );
      return;
    }

    const adminCredentialFile = await requiredValue(
      parsed.values.get("--admin-credential-file"),
      "Tenant admin credential file",
      prompt,
    );
    const bundleFile = await requiredValue(
      parsed.values.get("--bundle-file"),
      "New device bundle file",
      prompt,
    );
    await confirmOrFail(
      parsed.flags.has("--yes"),
      prompt,
      "Create one short-lived single-use enrollment bundle?",
    );
    const result = await createEnrollmentBundle({
      adminCredentialFile,
      bundleFile,
      expiresInSeconds: parseExpiry(parsed.values.get("--expires-in")),
    });
    process.stdout.write(
      `Single-use device bundle created for ${result.tenantId}: ${result.deviceBundlePath}\nExpires at: ${result.expiresAt}\n`,
    );
  } finally {
    prompt?.close();
  }
}

function parseArguments(argv) {
  if (argv.length > MAX_ARGUMENTS) fail("Too many command-line arguments.");
  for (const argument of argv) {
    if (
      typeof argument !== "string" ||
      argument.length === 0 ||
      argument.length > MAX_ARGUMENT_CHARACTERS ||
      argument.includes("\0")
    ) {
      fail("Invalid command-line argument.");
    }
  }
  const command = argv[0];
  if (!COMMANDS.has(command)) fail("Unknown command. Use --help.");
  const values = new Map();
  const flags = new Set();
  for (let index = 1; index < argv.length; index += 1) {
    const option = argv[index];
    if (FLAG_OPTIONS.has(option)) {
      if (flags.has(option)) fail(`Duplicate option: ${option}`);
      flags.add(option);
      continue;
    }
    if (!VALUE_OPTIONS.has(option)) fail(`Unknown option: ${option}`);
    if (values.has(option)) fail(`Duplicate option: ${option}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      fail(`Missing value for ${option}`);
    }
    values.set(option, value);
    index += 1;
  }

  const allowed =
    command === "token"
      ? new Set(["--admin-credential-file", "--bundle-file", "--expires-in"])
      : new Set(["--endpoint", "--root-token-file", "--output-dir"]);
  if (command === "onboard") allowed.add("--expires-in");
  for (const option of values.keys()) {
    if (!allowed.has(option)) fail(`${option} is not valid for ${command}.`);
  }
  if (command === "preflight" && flags.has("--yes")) {
    fail("--yes is not valid for preflight.");
  }
  return { command, values, flags };
}

async function collectNewTenantOptions(values, prompt) {
  return {
    endpoint: await requiredValue(
      values.get("--endpoint"),
      "Fleet endpoint",
      prompt,
    ),
    rootTokenFile: await requiredValue(
      values.get("--root-token-file"),
      "Fleet root-token file",
      prompt,
    ),
    outputDirectory: await requiredValue(
      values.get("--output-dir"),
      "Secure output directory",
      prompt,
    ),
  };
}

async function requiredValue(value, label, prompt) {
  if (value !== undefined) return value;
  if (prompt === undefined) {
    throw new OnboardingError(
      "missing_option",
      `${label} is required in non-interactive mode.`,
    );
  }
  const answer = (await prompt.question(`${label}: `)).trim();
  if (answer.length === 0 || answer.length > MAX_ARGUMENT_CHARACTERS) {
    throw new OnboardingError("invalid_input", `${label} is invalid.`);
  }
  return answer;
}

async function confirmOrFail(confirmed, prompt, question) {
  if (confirmed) return;
  if (prompt === undefined) {
    throw new OnboardingError(
      "confirmation_required",
      "Use --yes in non-interactive mode after reviewing the command.",
    );
  }
  const answer = (await prompt.question(`${question} [y/N] `))
    .trim()
    .toLowerCase();
  if (answer !== "y" && answer !== "yes") {
    throw new OnboardingError("cancelled", "Onboarding cancelled.");
  }
}

function parseExpiry(value) {
  if (value === undefined) return DEFAULT_EXPIRES_IN_SECONDS;
  if (!/^\d{1,4}$/.test(value)) {
    throw new OnboardingError(
      "invalid_expiry",
      "Enrollment expiry must be an integer number of seconds.",
    );
  }
  return Number(value);
}

function createPrompt() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) return undefined;
  return createInterface({ input: process.stdin, output: process.stdout });
}

function fail(message) {
  throw new OnboardingError("invalid_arguments", message);
}

main(process.argv.slice(2)).catch((error) => {
  const message =
    error instanceof OnboardingError
      ? error.message
      : "Unexpected Fleet onboarding failure.";
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 1;
});
