import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, createConnection } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { measureHost, parseDiagnostic, runOpenSsl } from "../src/probe.ts";

const openssl = process.env.OPENSSL_BINARY || "openssl";
async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}
async function serverTest(groups: string, clientGroups: string, options: { trust?: boolean; hostname?: string; tls12?: boolean; expired?: boolean } = {}) {
  const dir = await mkdtemp(join(tmpdir(), "obs-test-"));
  const cert = join(dir, "cert.pem"), key = join(dir, "key.pem"), port = await freePort();
  const generated = spawnSync(openssl, ["req", "-config", "/dev/null", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], { encoding: "utf8" });
  assert.equal(generated.status, 0, generated.stderr);
  let activeCert = cert;
  if (options.expired) {
    activeCert = join(dir, "expired.pem");
    const expired = spawnSync(openssl, ["x509", "-in", cert, "-signkey", key, "-not_before", "20200101000000Z", "-not_after", "20200102000000Z", "-out", activeCert], { encoding: "utf8" });
    assert.equal(expired.status, 0, expired.stderr);
  }
  const server = spawn(openssl, ["s_server", "-accept", `127.0.0.1:${port}`, "-cert", activeCert, "-key", key,
    options.tls12 ? "-tls1_2" : "-tls1_3", "-groups", groups, "-quiet", "-www"], { stdio: "ignore" });
  try {
    for (let n = 0; n < 100; n++) {
      if (server.exitCode !== null) throw new Error("TLS server failed");
      const ready = await new Promise<boolean>((resolve) => {
        const c = createConnection({ host: "127.0.0.1", port });
        c.on("connect", () => { c.destroy(); resolve(true); });
        c.on("error", () => resolve(false));
      });
      if (ready) break;
      await delay(10);
    }
    const m = await measureHost(options.hostname ?? "localhost", { address: "127.0.0.1", allowPrivate: true, port,
      caFile: options.trust === false ? undefined : activeCert, groups: clientGroups, timeoutMs: 3000, holdMs: 100, sendRequest: false });
    return m;
  } finally {
    server.kill("SIGTERM");
    await new Promise<void>((resolve) => server.exitCode !== null ? resolve() : server.once("exit", () => resolve()));
    await rm(dir, { recursive: true, force: true });
  }
}

test("actual classical TLS validates certificate and records exact provenance", async () => {
  const m = await serverTest("X25519", "X25519");
  assert.equal(m.certificateValidated, true, JSON.stringify(m));
  assert.equal(m.kexHybrid, false);
  assert.equal(m.kexGroup, "X25519");
  assert.equal(m.observation?.profile, "openssl-tls13-v1");
  assert.ok(m.transcript?.includes("Verification: OK"));
  assert.equal(m.ticketIssued, true);
  assert.equal(m.ticketWithoutRequest, true);
  assert.equal(m.resumed, true);
  assert.ok(m.certSigAlg);
  assert.ok(m.certNotAfter);
});
test("actual hybrid and classical fallback with no silent hybrid-only retry", async (t) => {
  const support = spawnSync(openssl, ["list", "-tls1_3", "-tls-groups"], { encoding: "utf8" });
  if (!support.stdout.includes("X25519MLKEM768")) {
    assert.notEqual(process.env.REQUIRE_HYBRID_TLS, "1", "mandatory hybrid runtime unavailable");
    t.skip("OpenSSL 3.5+ required for hybrid"); return;
  }
  const hybrid = await serverTest("X25519MLKEM768:X25519", "X25519MLKEM768:X25519");
  assert.equal(hybrid.kexHybrid, true, JSON.stringify(hybrid));
  const classical = await serverTest("X25519", "X25519MLKEM768:X25519");
  assert.equal(classical.certificateValidated, true);
  assert.equal(classical.kexHybrid, false);
  const refused = await serverTest("X25519", "X25519MLKEM768");
  assert.equal(refused.certificateValidated, false);
  assert.equal(refused.observation, null);
});
test("untrusted and wrong-host certificates cannot create evidence", async () => {
  for (const options of [{ trust: false }, { hostname: "other.example" }, { tls12: true }, { expired: true }]) {
    const m = await serverTest("X25519", "X25519", options);
    assert.equal(m.reachable, false, JSON.stringify(m));
    assert.equal(m.observation, null);
  }
});
test("OpenSSL subprocess timeout, stream isolation and size bounds", async () => {
  const tooLarge = await runOpenSsl(["-e", 'process.stdout.write("x".repeat(100000))'], 2000, "", 0, process.execPath);
  assert.equal(tooLarge.error, "output limit");
  const slow = await runOpenSsl(["-e", 'setTimeout(()=>{},10000)'], 100, "", 0, process.execPath);
  assert.equal(slow.error, "timeout");
  const streams = await runOpenSsl(["-e", 'console.log("Verification: OK");console.error("real diagnostics")'], 2000, "", 0, process.execPath);
  assert.equal(streams.stderr, "real diagnostics\n");
  assert.equal(parseDiagnostic(streams.stderr).validated, false);
});
test("duplicate or uncompleted diagnostic summaries fail closed", () => {
  const summary = "Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nSignature type: rsa_pss_rsae_sha256\nVerification: OK\nPeer Temp Key: X25519, 253 bits\n";
  assert.equal(parseDiagnostic(summary).validated, true);
  assert.equal(parseDiagnostic(summary+"Negotiated TLS1.3 group: X25519MLKEM768\n").validated, false);
  assert.equal(parseDiagnostic(summary+"verify error: invalid certificate\n").validated, false);
  assert.equal(parseDiagnostic("ServerHello X25519MLKEM768").validated, false);
});
