import assert from "node:assert/strict";
import { test } from "node:test";
import {
  FLEET_SERVICE_RECEIPT_DOMAIN,
  FLEET_SERVICE_RECEIPT_SCHEMA,
  canonicalJson,
  parseServiceReceipt,
  serviceReceiptSigningBytes,
  type ServiceReceipt,
  type ServiceReceiptUnsigned,
} from "../src/index.js";

test("service receipt signing bytes match the Rust domain and canonical contract", () => {
  const unsigned: ServiceReceiptUnsigned = {
    schema: FLEET_SERVICE_RECEIPT_SCHEMA,
    tenantId: "tenant-receipt-1",
    deviceId: "KA-3097e2dee2cb4a34b53840cd",
    operation: "inventory",
    sequence: 7,
    requestSha256: "11".repeat(32),
    responseSha256: "22".repeat(32),
    acceptedAt: "2026-08-31T12:30:45Z",
    outcome: "accepted",
  };
  assert.equal(
    new TextDecoder().decode(serviceReceiptSigningBytes(unsigned)),
    `${FLEET_SERVICE_RECEIPT_DOMAIN}${canonicalJson(unsigned)}`,
  );

  const receipt: ServiceReceipt = {
    ...unsigned,
    signature: Buffer.alloc(64, 0xa5).toString("base64url"),
  };
  assert.deepEqual(parseServiceReceipt(receipt), receipt);
  assert.throws(() => parseServiceReceipt({ ...receipt, rawData: "no" }));
  assert.throws(() =>
    parseServiceReceipt({ ...receipt, operation: "remote_command" }),
  );
});
