import { lstat, readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist/", import.meta.url));
const repairTokens = [
  "/api/rescue/repair",
  "repair.fstab.rollback.prepare",
  "repair.crypttab.rollback.prepare",
  "DISABILITA VOCE FSTAB",
  "RIPRISTINA FSTAB ORIGINALE",
  "RIPRISTINA CRYPTTAB ORIGINALE",
];
const diagnosisTokens = ["/api/rescue/inspect-installed-target", "Diagnostica"];
const payloads = [];
let totalBytes = 0;

async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isSymbolicLink()) {
      throw new Error(`stable Desk bundle contains a symlink: ${path}`);
    }
    if (entry.isDirectory()) {
      await collect(path);
    } else if (entry.isFile()) {
      const metadata = await lstat(path);
      if (metadata.size <= 0 || metadata.size > 16 * 1024 * 1024) {
        throw new Error(`stable Desk file is outside the size bound: ${path}`);
      }
      totalBytes += metadata.size;
      if (totalBytes > 64 * 1024 * 1024) {
        throw new Error("stable Desk bundle exceeds the size bound");
      }
      payloads.push(await readFile(path, "utf8"));
    }
  }
}

await collect(root);
for (const token of diagnosisTokens) {
  if (!payloads.some((payload) => payload.includes(token))) {
    throw new Error(`stable Desk diagnosis token is missing: ${token}`);
  }
}
for (const token of repairTokens) {
  if (payloads.some((payload) => payload.includes(token))) {
    throw new Error(`repair token leaked into stable Desk: ${token}`);
  }
}
