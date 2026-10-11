import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile, readdir, chmod, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createExporter, collectRecord } from "../src/export.ts";
import type { Measurement } from "../src/probe.ts";

const transcript = "CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nSignature type: rsa_pss_rsae_sha256\nVerification: OK\nNegotiated TLS1.3 group: X25519MLKEM768\nDONE\n";
function fixture(): Measurement {
  return { reachable: true, kexHybrid: true, kexGroup: "X25519MLKEM768", tlsVersion: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384",
    certSigAlg: "sha256WithRSAEncryption", certNotAfter: null, address: "8.8.8.8", ticketIssued: false, ticketLifetimeS: null,
    ticketWithoutRequest: false, resumed: null, error: null, certificateValidated: true, peerSignatureType: "rsa_pss_rsae_sha256", transcript,
    observation: { profile: "openssl-tls13-v1", observedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
      endpoint: { host: "example.org", port: 443, address: "8.8.8.8" },
      probe: { name: "openssl", version: "OpenSSL 3.5.9", groups: ["X25519MLKEM768"], certificateValidation: "pkix-hostname", exitCode: 0 },
      transcriptSha256: createHash("sha256").update(transcript).digest("hex") } };
}
test("export binds original evidence, policy and optional independently supplied manifest", async () => {
  const dir = await mkdtemp(join(tmpdir(), "obs-export-"));
  try {
    let request: Record<string, unknown> = {};
    const exporter = await createExporter({ outputDirectory: dir, authorityDirectory: "/operator-authority", onlineKeyRef: "kms-ref", keyId: "online",
      issuer: "https://issuer.example", audience: "monitor", ledgerPath: join(dir,"ledger.jsonl"), allowedSubjects: ["https://example.org"],
      snapshotBindings: { "https://example.org": "sha256:"+"a".repeat(64) } },
      { signer: {}, issue: async (options) => { request = options; return "test.stub.token"; } });
    const measurement = fixture();
    const bundle = await exporter.exportMeasurement(measurement);
    assert.equal(bundle.transcript, transcript);
    assert.equal(bundle.subject, "https://example.org");
    assert.equal(typeof request.now, "number");
    const claims = request.claims as Record<string, unknown>;
    assert.deepEqual(claims.observation, measurement.observation);
    assert.equal(claims.snapshotDigest, "sha256:"+"a".repeat(64));
    const files = await readdir(dir);
    assert.equal(files.length, 1);
    assert.deepEqual(JSON.parse(await readFile(join(dir,files[0]!),"utf8")), bundle);
    const tampered = fixture(); tampered.transcript += "spoof";
    await assert.rejects(exporter.exportMeasurement(tampered), /mismatch/);
    const unvalidated = fixture(); unvalidated.certificateValidated = false;
    await assert.rejects(exporter.exportMeasurement(unvalidated), /validated/);
    const stale = fixture(); stale.observation!.observedAt = "2020-01-01T00:00:00Z";
    await assert.rejects(exporter.exportMeasurement(stale), /one hour/);
    const unauthorized = fixture(); unauthorized.observation!.endpoint.host = "evil.example";
    await assert.rejects(exporter.exportMeasurement(unauthorized), /not authorized/);
  } finally { await rm(dir,{recursive:true,force:true}); }
});
test("collector preserves unsigned provenance and never upgrades historical rows", async () => {
  const dir = await mkdtemp(join(tmpdir(), "obs-collect-"));
  try {
    const m = fixture();
    const path = await collectRecord(dir,m);
    assert.deepEqual(JSON.parse(await readFile(path,"utf8")),m);
    await assert.rejects(collectRecord(dir, { kexHybrid: true } as Measurement), /unvalidated/);
    await chmod(dir,0o755);
    await assert.rejects(collectRecord(dir,m), /private/);
  } finally { await rm(dir,{recursive:true,force:true}); }
});
