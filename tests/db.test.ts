import assert from "node:assert/strict";
import { test } from "node:test";
import type pg from "pg";
import { upsertHosts, upsertProbe } from "../src/db.ts";
import { resolveDate } from "../src/run.ts";
import type { Measurement } from "../src/probe.ts";

test("panel upsert preserves an existing database opt-out", async () => {
  let sql = "", params: unknown[] = [];
  const client = { async query(query: string, values: unknown[]) { sql = query; params = values; return { rows: [] }; } } as unknown as pg.Client;
  await upsertHosts(client,[{domain:"example.org",category:"cloud",rank:1}],new Set());
  assert.match(sql,/opted_out_at = COALESCE\(observatory_host.opted_out_at, EXCLUDED.opted_out_at\)/);
  assert.equal(params[6],null);
});
test("new provenance uses existing raw JSON column without schema or historical rewrites", async () => {
  let values: unknown[] = [], sql = "";
  const client = { async query(query: string, params: unknown[]) { sql = query; values = params; return {rows:[]}; } } as unknown as pg.Client;
  const m = {cipher:"TLS_AES_256_GCM_SHA384",error:null,certificateValidated:true,peerSignatureType:"RSA-PSS",observation:{profile:"openssl-tls13-v1"},transcript:"diagnostics"} as unknown as Measurement;
  await upsertProbe(client,"host-id","2026-10-11",m,"signed.jwt.token");
  const raw = JSON.parse(values[9] as string);
  assert.equal(raw.signedObservation,"signed.jwt.token");
  assert.equal(raw.certificateValidated,true);
  assert.equal(raw.transcript,"diagnostics");
  assert.match(sql,/INSERT INTO observatory_probe/);
});
test("impossible run dates are rejected", () => {
  assert.throws(()=>resolveDate({date:"2026-02-31"}));
  assert.throws(()=>resolveDate({date:"2026-99-99"}));
  assert.equal(resolveDate({date:"2028-02-29"}),"2028-02-29");
});
