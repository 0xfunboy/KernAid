import { loadFleetServiceConfig } from "./config.js";
import { FleetControlPlane } from "./server.js";

const config = loadFleetServiceConfig();
const controlPlane = new FleetControlPlane({
  databasePath: config.databasePath,
  rootToken: config.rootToken,
  serviceReceiptSigningKey: config.serviceReceiptSigningKey,
  serviceReceiptTrustAnchor: config.serviceReceiptTrustAnchor,
  entitlementTrustAnchor: config.entitlementTrustAnchor,
  updateTrustAnchor: config.updateTrustAnchor,
  enrollmentClockSkewMs: config.enrollmentClockSkewMs,
  consoleDirectory: config.consoleDirectory,
});

const address = await controlPlane.listen(config.port, config.host);
process.stdout.write(`KernAid Fleet control plane listening on ${address}\n`);

let stopping = false;
async function stop(): Promise<void> {
  if (stopping) return;
  stopping = true;
  await controlPlane.close();
}

process.once("SIGINT", () => {
  void stop().then(() => process.exit(0));
});
process.once("SIGTERM", () => {
  void stop().then(() => process.exit(0));
});
