import { readFile } from "node:fs/promises";

const cli = await readFile(new URL("./cli.mjs", import.meta.url), "utf8");
const library = await readFile(new URL("./lib.mjs", import.meta.url), "utf8");
const packageJson = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);

assert(
  packageJson.engines?.node === "24.18.0",
  "package must pin Node.js 24.18.0 exactly",
);
assert(
  library.includes('export const EXACT_NODE_VERSION = "24.18.0"'),
  "runtime must pin Node.js 24.18.0 exactly",
);
for (const source of [cli, library]) {
  assert(!source.includes("node:child_process"), "child_process is forbidden");
  assert(
    !source.includes("localStorage"),
    "persistent browser storage is forbidden",
  );
}
for (const path of ["/commands", "/shell", "/execute", "/repairs"]) {
  assert(!library.includes(path), `remote command route is forbidden: ${path}`);
}
assert(
  !cli.includes("--root-token ") && !cli.includes("--admin-token "),
  "raw secret CLI flags are forbidden",
);
assert(
  library.includes("0o600") && library.includes("0o700"),
  "owner-only file and directory modes must be enforced",
);

process.stdout.write("Fleet onboarding wizard invariants verified\n");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
