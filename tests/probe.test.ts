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

import { isPublicAddress, measureHost } from "../src/probe.ts";
test("private/reserved/transition addresses are rejected by default", async () => {
  for (const address of ["127.0.0.1","10.0.0.1","169.254.169.254","192.168.1.1","100.64.1.2","0.0.0.0","224.0.0.1","::1","::ffff:8.8.8.8","64:ff9b::808:808","2002:0808:0808::1","2001:db8::1","fc00::1"]) assert.equal(isPublicAddress(address),false,address);
  for (const address of ["8.8.8.8","1.1.1.1","2606:4700::1111","2001:4860:4860::8888"]) assert.equal(isPublicAddress(address),true,address);
  const m=await measureHost("localhost",{address:"127.0.0.1"});
  assert.equal(m.certificateValidated,false);
  assert.match(m.error??"",/non-public/);
});
