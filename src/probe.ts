import { spawn } from "node:child_process";

/**
 * A single host measurement, produced by one read-only TLS handshake driven by
 * `openssl s_client`. We offer the hybrid group first alongside classical
 * fallbacks and record which the server actually selects, plus the certificate's
 * signature algorithm and expiry. No application data is ever sent.
 */
export type Measurement = {
  reachable: boolean;
  kexHybrid: boolean;
  kexGroup: string | null;
  tlsVersion: string | null;
  cipher: string | null;
  certSigAlg: string | null;
  certNotAfter: string | null;
  error: string | null;
};

/** Hybrid first, then classical fallbacks, so a hybrid-capable server selects it and others still connect. */
const GROUPS = "X25519MLKEM768:X25519:secp256r1:secp384r1:x448";

/** Run openssl with args (no shell), feed `stdin`, capture stdout+stderr, hard timeout. */
function runOpenssl(args: string[], timeoutMs: number, stdin: string): Promise<string> {
  return new Promise((resolve) => {
    const p = spawn("openssl", args, { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    const timer = setTimeout(() => {
      try {
        p.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }, timeoutMs);
    p.stdout.on("data", (d) => (out += d.toString()));
    p.stderr.on("data", (d) => (out += d.toString()));
    p.on("error", () => {
      clearTimeout(timer);
      resolve(out);
    });
    p.on("close", () => {
      clearTimeout(timer);
      resolve(out);
    });
    try {
      p.stdin.write(stdin);
      p.stdin.end();
    } catch {
      /* ignore */
    }
  });
}

function firstPem(s: string): string | null {
  const m = s.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  return m ? m[0] : null;
}

function parseNotAfter(x509text: string): string | null {
  const m = x509text.match(/notAfter=(.+)/);
  if (!m || !m[1]) return null;
  const d = new Date(m[1].trim());
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** One read-only handshake per host. Never throws; failures come back as `reachable: false`. */
export async function measureHost(domain: string, opts: { timeoutMs?: number } = {}): Promise<Measurement> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  const base: Measurement = {
    reachable: false,
    kexHybrid: false,
    kexGroup: null,
    tlsVersion: null,
    cipher: null,
    certSigAlg: null,
    certNotAfter: null,
    error: null,
  };

  const out = await runOpenssl(
    ["s_client", "-connect", `${domain}:443`, "-servername", domain, "-groups", GROUPS],
    timeoutMs,
    "",
  );

  const reachable = /Protocol\s*:\s*TLS|New,\s*TLS/i.test(out);
  if (!reachable) {
    const alert =
      out.match(/tlsv[\d]*\s*alert[^\n]*/i) ||
      out.match(/(connect:errno=\d+|Connection refused|Name or service not known|no peer certificate|timeout)/i);
    return { ...base, error: alert ? alert[0].trim().slice(0, 120) : "no TLS negotiated" };
  }

  const groupM = out.match(/Negotiated TLS1\.3 group:\s*(\S+)/i) || out.match(/Server Temp Key:\s*([^\n,]+)/i);
  const verM = out.match(/Protocol\s*:\s*(\S+)/i) || out.match(/New,\s*(TLSv[\d.]+)/i);
  const cipherM = out.match(/Cipher\s*:\s*(\S+)/i) || out.match(/Cipher is\s*(\S+)/i);

  let certSigAlg: string | null = null;
  let certNotAfter: string | null = null;
  const pem = firstPem(out);
  if (pem) {
    const x = await runOpenssl(["x509", "-noout", "-enddate", "-text"], timeoutMs, pem);
    certNotAfter = parseNotAfter(x);
    const sigM = x.match(/Signature Algorithm:\s*([^\n]+)/i);
    certSigAlg = sigM?.[1]?.trim() ?? null;
  }

  return {
    reachable: true,
    kexHybrid: /X25519MLKEM768/i.test(out),
    kexGroup: groupM?.[1]?.trim() ?? null,
    tlsVersion: verM?.[1] ?? null,
    cipher: cipherM?.[1] ?? null,
    certSigAlg,
    certNotAfter,
    error: null,
  };
}
