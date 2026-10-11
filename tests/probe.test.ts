import assert from "node:assert/strict";
import { test } from "node:test";
import { isNegotiatedHybrid } from "../src/probe.ts";

test("negotiated hybrid TLS 1.3 group", () => {
  assert.equal(isNegotiatedHybrid("X25519MLKEM768", "TLSv1.3"), true);
});
test("classical group is not hybrid", () => {
  assert.equal(isNegotiatedHybrid("X25519", "TLSv1.3"), false);
});
test("TLS 1.2 is not counted as hybrid", () => {
  assert.equal(isNegotiatedHybrid("X25519MLKEM768", "TLSv1.2"), false);
});
test("missing negotiated group is unknown, not hybrid", () => {
  assert.equal(isNegotiatedHybrid(null, "TLSv1.3"), false);
});
