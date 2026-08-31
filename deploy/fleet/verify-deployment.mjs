import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const deploymentDirectory = dirname(fileURLToPath(import.meta.url));
const repository = resolve(deploymentDirectory, "../..");
const dockerfile = readFileSync(
  join(deploymentDirectory, "Dockerfile"),
  "utf8",
);
const compose = readFileSync(join(deploymentDirectory, "compose.yaml"), "utf8");
const dockerignore = readFileSync(join(repository, ".dockerignore"), "utf8");
const databaseLifecycle = readFileSync(
  join(deploymentDirectory, "database-lifecycle.mjs"),
  "utf8",
);

assert.equal(
  dockerfile.match(
    /^FROM node:24\.18\.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d/gm,
  )?.length,
  2,
  "both container stages must pin the Node.js 24.18.0 multi-platform digest",
);
assert.match(dockerfile, /^USER node:node$/m);
assert.match(dockerfile, /^HEALTHCHECK /m);
assert.match(dockerfile, /pnpm install --frozen-lockfile --ignore-scripts/);
assert.match(dockerfile, /FLEET_CONSOLE_DIR=\/opt\/kernaid\/console/);
assert.match(dockerfile, /VOLUME \["\/var\/lib\/kernaid-fleet"\]/);
assert.match(
  dockerfile,
  /ENTRYPOINT \["node", "\/opt\/kernaid\/services\/fleet-control-plane\/dist\/main\.js"\]/,
);
assert.doesNotMatch(dockerfile, /^ARG\s+NODE/m);
assert.doesNotMatch(dockerfile, /\bHOME=/);

assert.match(compose, /^\s+host_ip: 127\.0\.0\.1$/m);
assert.match(compose, /^\s+user: "1000:1000"$/m);
assert.match(compose, /^\s+read_only: true$/m);
assert.match(compose, /^\s+tmpfs:$/m);
assert.match(compose, /^\s+KERNAID_FLEET_ROOT_TOKEN_FILE: \/run\/secrets\//m);
assert.match(compose, /^\s+mode: 0400$/m);
assert.match(compose, /^\s+internal: true$/m);
assert.match(compose, /^\s+- ALL$/m);
assert.doesNotMatch(compose, /^\s+KERNAID_FLEET_ROOT_TOKEN:\s/m);

assert.match(dockerignore, /^\*\*$/m);
assert.match(dockerignore, /^!services\/fleet-control-plane\/\*\*$/m);
assert.match(dockerignore, /^!apps\/fleet-console\/\*\*$/m);

assert.match(databaseLifecycle, /from "node:sqlite"/);
assert.match(databaseLifecycle, /PRAGMA quick_check/);
assert.match(databaseLifecycle, /PRAGMA foreign_key_check/);
assert.match(databaseLifecycle, /destination already exists/);
assert.doesNotMatch(databaseLifecycle, /process\.env/);

process.stdout.write("Fleet deployment invariants verified\n");
