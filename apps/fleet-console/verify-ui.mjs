import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(directory, "index.html"), "utf8");
const script = readFileSync(join(directory, "app.js"), "utf8");
const publishBoundary = readFileSync(
  join(directory, "publish-document.js"),
  "utf8",
);
const workOrderBoundary = readFileSync(
  join(directory, "work-order-ui.js"),
  "utf8",
);
const incidentBoundary = readFileSync(
  join(directory, "incident-case-ui.js"),
  "utf8",
);

assert.match(html, /data-view="governance"/);
assert.match(html, /id="publish-dialog"/);
assert.match(html, /id="publish-document"[^>]+maxlength="1048576"/s);
assert.match(html, /No signing happens in this console/);
assert.match(html, /Content-Security-Policy/);
assert.match(html, /data-view="workorders"/);
assert.match(html, /id="work-order-dialog"/);
assert.match(html, /id="work-order-events"/);
assert.match(html, /data-view="incidents"/);
assert.match(html, /id="incident-dialog"/);
assert.match(html, /id="incident-update-dialog"/);
assert.match(html, /id="incident-link-dialog"/);
assert.match(html, /id="incident-close-dialog"/);
assert.match(html, /id="incident-events"/);
assert.match(html, /No raw evidence, personal data, shell commands/);
assert.doesNotMatch(
  html,
  /<(?:input|textarea)[^>]+name="(?:command|arguments?|path|script|raw)/i,
);

for (const route of [
  "policies",
  "entitlements",
  "entitlement-revocations",
  "update-manifests",
  "work-orders",
  "work-order-events",
  "incident-cases",
  "incident-case-events",
]) {
  assert.match(script, new RegExp(route));
}
for (const schema of [
  "dev.kernaid.fleet.policy-bundle.v1",
  "dev.kernaid.entitlement.v1",
  "dev.kernaid.entitlement-revocations.v1",
  "dev.kernaid.update.manifest.v1",
]) {
  assert.match(script, new RegExp(schema.replaceAll(".", "\\.")));
}

assert.match(script, /\/v1\/console-sessions/);
assert.match(script, /\/v1\/console-session/);
assert.match(script, /X-KernAid-CSRF/);
assert.match(script, /const apiBase = ""/);
assert.doesNotMatch(html, /kernaid-api-base/);
assert.doesNotMatch(script, /sessionStorage|localStorage/);
assert.doesNotMatch(script, /Authorization|Bearer/);
assert.doesNotMatch(script, /state\.token/);
assert.match(html, /HttpOnly/);
assert.match(html, /SameSite Strict/);
assert.match(html, /autocomplete="off"/);
assert.doesNotMatch(script, /innerHTML|insertAdjacentHTML|document\.write/);
assert.doesNotMatch(
  workOrderBoundary,
  /innerHTML|insertAdjacentHTML|document\.write/,
);
assert.doesNotMatch(
  incidentBoundary,
  /innerHTML|insertAdjacentHTML|document\.write/,
);
assert.match(incidentBoundary, /canonicalIncidentReport/);
assert.match(incidentBoundary, /Use a bounded team or queue label/);
assert.match(script, /incident_case_close|serviceReceipt/);
assert.match(script, /\.incident-report\.json/);
assert.doesNotMatch(script, /\/v1\/(?:commands|shell|execute|repairs)/i);
assert.match(script, /decision: "approve"/);
assert.match(script, /body: JSON\.stringify\(\{\}\)/);
assert.match(workOrderBoundary, /linux\.fstab\.disable-missing-uuid\.v1/);
assert.doesNotMatch(workOrderBoundary, /shell\.exec|arbitrary/);
assert.match(script, /maximumBytes: 1024 \* 1024/);
assert.match(script, /maximumBytes: 64 \* 1024/);
assert.match(
  publishBoundary,
  /Private keys, secrets and credentials cannot be published/,
);

process.stdout.write("Fleet Console enterprise invariants verified\n");
