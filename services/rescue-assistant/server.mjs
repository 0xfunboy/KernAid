import net from "node:net";
import fs from "node:fs/promises";
import path from "node:path";
import {
  AssistantRuntime,
  networks,
  wifi,
  connectNetwork,
} from "./runtime.mjs";

process.umask(0o077);
const socketPath =
  process.env.KERNAID_ASSISTANT_SOCKET ||
  "/run/kernaid-assistant/assistant.sock";
const runtime = new AssistantRuntime({
  stateDir:
    process.env.KERNAID_ASSISTANT_STATE || "/run/kernaid-assistant/state",
  keyFile:
    process.env.KERNAID_ASSISTANT_KEY_FILE ||
    (process.env.CREDENTIALS_DIRECTORY
      ? path.join(process.env.CREDENTIALS_DIRECTORY, "gemrouter.key")
      : undefined),
  searchUrl: process.env.KERNAID_SEARCH_URL || "http://127.0.0.1:8888/search",
});
await runtime.initialize();
let operationBusy = false;
async function dispatch(request) {
  if (operationBusy)
    throw new Error(
      "Another connection operation is in progress. Retry shortly.",
    );
  operationBusy = true;
  try {
    switch (request.action) {
      case "status":
        return runtime.status();
      case "networks":
        return await networks();
      case "wifi":
        return await wifi(request.adapter);
      case "connect":
        return await connectNetwork(request);
      case "configure":
        return await runtime.configure(request);
      case "models":
        return await runtime.models();
      case "chat":
        return await runtime.chat(request.message);
      default:
        throw new Error("Unknown assistant operation.");
    }
  } finally {
    operationBusy = false;
  }
}
// Unix socket shared only with the local UI service; never a public listener.
await fs.mkdir(path.dirname(socketPath), { recursive: true, mode: 0o750 });
try {
  const stat = await fs.lstat(socketPath);
  if (!stat.isSocket()) throw new Error("Refusing to replace non-socket path");
  await fs.unlink(socketPath);
} catch (e) {
  if (e.code !== "ENOENT") throw e;
}
const server = net.createServer((socket) => {
  socket.setTimeout(75_000, () => socket.destroy());
  let data = Buffer.alloc(0);
  let received = false;
  socket.on("error", () => {});
  socket.on("data", (chunk) => {
    if (received) return;
    if (data.length + chunk.length > 16 * 1024) {
      socket.destroy();
      return;
    }
    data = Buffer.concat([data, chunk]);
    if (!data.includes(10)) return;
    received = true;
    void (async () => {
      try {
        const request = JSON.parse(data.toString("utf8"));
        if (!request || typeof request !== "object" || Array.isArray(request))
          throw new Error("Invalid request.");
        socket.end(
          JSON.stringify({ ok: true, ...(await dispatch(request)) }) + "\n",
        );
      } catch (e) {
        socket.end(
          JSON.stringify({
            ok: false,
            error: e instanceof Error ? e.message : "Operation unavailable.",
          }) + "\n",
        );
      }
    })();
  });
});
server.maxConnections = 8;
server.listen(socketPath, async () => {
  await fs.chmod(socketPath, 0o660);
  console.log("KernAid assistant ready (local Unix socket)");
});
