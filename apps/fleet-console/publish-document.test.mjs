import assert from "node:assert/strict";
import { test } from "node:test";
import { boundedSignedDocument } from "./publish-document.js";

const signature = "A".repeat(86);
const configuration = {
  maximumBytes: 1024 * 1024,
  schema: "dev.kernaid.fleet.policy-bundle.v1",
  tenantPath: ["tenantId"],
};

test("publish boundary canonicalizes a signed tenant document", () => {
  const canonical = boundedSignedDocument(
    JSON.stringify({
      tenantId: "tenant-one",
      signature,
      schema: configuration.schema,
      revision: 7,
      assignments: { all: true },
    }),
    configuration,
    "tenant-one",
  );
  assert.equal(
    canonical,
    `{"assignments":{"all":true},"revision":7,"schema":"${configuration.schema}","signature":"${signature}","tenantId":"tenant-one"}`,
  );
});

test("publish boundary rejects tenant mismatch and secret fields", () => {
  const document = {
    schema: configuration.schema,
    signature,
    tenantId: "tenant-two",
  };
  assert.throws(
    () =>
      boundedSignedDocument(
        JSON.stringify(document),
        configuration,
        "tenant-one",
      ),
    /another tenant/,
  );
  assert.throws(
    () =>
      boundedSignedDocument(
        JSON.stringify({
          ...document,
          tenantId: "tenant-one",
          privateKey: "x",
        }),
        configuration,
        "tenant-one",
      ),
    /Private keys/,
  );
});

test("publish boundary rejects unsafe JSON and byte overflow", () => {
  assert.throws(
    () =>
      boundedSignedDocument(
        JSON.stringify({
          schema: configuration.schema,
          signature,
          tenantId: "tenant-one",
          revision: 1.5,
        }),
        configuration,
        "tenant-one",
      ),
    /safe integers/,
  );
  assert.throws(
    () =>
      boundedSignedDocument(
        JSON.stringify({ schema: configuration.schema, signature }),
        { ...configuration, maximumBytes: 8 },
        "tenant-one",
      ),
    /between 1 byte/,
  );
});
