import test from "node:test";
import assert from "node:assert/strict";
import {
  parseAssistantContext,
  assistantContextPreview,
} from "../src/index.mjs";
import { linuxContext } from "./fixture.mjs";

test("context projection is a fresh closed object with a deterministic preview", () => {
  const input = linuxContext();
  const output = parseAssistantContext(input);
  assert.deepEqual(output, input);
  assert.notEqual(output.observations, input.observations);
  assert.equal(assistantContextPreview(input), JSON.stringify(output, null, 2));
});

test("unknown/free-form/identifying data and malformed facts are rejected", () => {
  const valid = linuxContext();
  for (const invalid of [
    null,
    [],
    { ...valid, hostname: "private-host" },
    { ...valid, filesystem: "ntfs" },
    {
      ...valid,
      observations: { ...valid.observations, path: "/home/private" },
    },
    {
      ...valid,
      observations: { ...valid.observations, fstabPresent: "secret-value" },
    },
    { ...valid, observations: { ...valid.observations, fstabEntryCount: -1 } },
    { ...valid, observations: { ...valid.observations, fstabEntryCount: 1.5 } },
    {
      ...valid,
      observations: { ...valid.observations, fstabEntryCount: 1000001 },
    },
  ])
    assert.throws(
      () => parseAssistantContext(invalid),
      /Invalid diagnostic summary/,
    );
});
