import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { createHash } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isIP, BlockList } from "node:net";

export const GROUPS = "X25519MLKEM768:X25519:secp256r1:secp384r1:x448";
const HYBRID_GROUPS = new Set(["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"]);
const MAX_OUTPUT = 65536;

export type Observation = {
  profile: "openssl-tls13-v1";
  observedAt: string;
  endpoint: { host: string; port: number; address: string };
  probe: { name: "openssl"; version: string; groups: string[]; certificateValidation: "pkix-hostname"; exitCode: number };
  transcriptSha256: string;
};
export type Measurement = {
  reachable: boolean;
  kexHybrid: boolean;
  kexGroup: string | null;
  tlsVersion: string | null;
  cipher: string | null;
  certSigAlg: string | null;
  certNotAfter: string | null;
  address: string | null;
  ticketIssued: boolean | null;
  ticketLifetimeS: number | null;
  ticketWithoutRequest: boolean | null;
  resumed: boolean | null;
  error: string | null;
  /** Added fields are never inferred for old database rows. */
  certificateValidated: boolean;
  peerSignatureType: string | null;
  observation: Observation | null;
  /** Exact bounded OpenSSL stderr bytes decoded as UTF-8, not application stdout. */
  transcript: string | null;
};

export function isNegotiatedHybrid(group: string | null, tlsVersion: string | null): boolean {
  return tlsVersion === "TLSv1.3" && group !== null && HYBRID_GROUPS.has(group);
}
export function connectTarget(address: string, port: number): string {
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

type ProcessResult = { stdout: string; stderr: string; exitCode: number | null; error: string | null };
/** Bounded independent streams. Application bytes cannot become TLS diagnostics. */
export function runOpenSsl(
  args: string[], timeoutMs: number, input = "", holdMs = 0, binary = process.env.OPENSSL_BINARY || "openssl",
): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const p = spawn(binary, args, { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, LC_ALL: "C" } });
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    let bytes = 0, error: string | null = null, settled = false;
    const timer = setTimeout(() => { error = "timeout"; p.kill("SIGKILL"); }, timeoutMs);
    let end: NodeJS.Timeout | undefined;
    const finish = (exitCode: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (end) clearTimeout(end);
      try {
        const decoder = new TextDecoder("utf-8", { fatal: true });
        resolve({ stdout: decoder.decode(Buffer.concat(stdout)), stderr: decoder.decode(Buffer.concat(stderr)), exitCode, error });
      } catch { resolve({ stdout: "", stderr: "", exitCode, error: "invalid UTF-8 diagnostics" }); }
    };
    const read = (target: Buffer[], data: Buffer): void => {
      if (error) return;
      bytes += data.length;
      if (bytes > MAX_OUTPUT) { error = "output limit"; p.kill("SIGKILL"); return; }
      target.push(data);
    };
    p.stdout.on("data", (d: Buffer) => read(stdout, d));
    p.stderr.on("data", (d: Buffer) => read(stderr, d));
    p.stdin.on("error", () => { /* EPIPE after a rejected handshake is reported by exitCode. */ });
    p.on("error", (e) => { error = e.message.slice(0, 120); finish(null); });
    p.on("close", finish);
    if (input) p.stdin.write(input);
    if (holdMs > 0) end = setTimeout(() => p.stdin.end(), holdMs);
    else p.stdin.end();
  });
}

function one(output: string, pattern: RegExp): string | null {
  const matches = [...output.matchAll(pattern)];
  return matches.length === 1 ? matches[0]?.[1]?.trim() ?? null : null;
}
export function parseDiagnostic(output: string): {
  tlsVersion: string | null; cipher: string | null; group: string | null; signature: string | null; validated: boolean;
} {
  const tlsVersion = one(output, /^Protocol version:\s*(\S+)\s*$/gm);
  const cipher = one(output, /^Ciphersuite:\s*(\S+)\s*$/gm);
  const group = one(output, /^(?:Negotiated TLS1\.3 group|Peer Temp Key|Server Temp Key):\s*([^\r\n,]+)/gm);
  const signature = one(output, /^Signature type:\s*([^\r\n]+)/gm);
  const validated = tlsVersion === "TLSv1.3" && cipher !== null && cipher !== "(NONE)" && cipher !== "0000"
    && [...output.matchAll(/^Verification: OK\s*$/gm)].length === 1
    && !/verify error|verification error|alert |handshake failure/i.test(output)
    && group !== null && signature !== null;
  return { tlsVersion, cipher, group, signature, validated };
}
async function hasSession(path: string): Promise<boolean> {
  try { const s = await stat(path); return s.isFile() && s.size > 0 && s.size <= MAX_OUTPUT; }
  catch { return false; }
}

export interface ProbeOptions {
  timeoutMs?: number;
  sendRequest?: boolean;
  /** Test/operator overrides, never derived from downloaded documents. */
  address?: string;
  allowPrivate?: boolean;
  port?: number;
  caFile?: string;
  groups?: string;
  holdMs?: number;
  opensslVersion?: string;
}

/** Reuse the first silent handshake for authenticated evidence and ticket discovery. */
export async function measureHost(domain: string, opts: ProbeOptions = {}): Promise<Measurement> {
  const timeoutMs = opts.timeoutMs ?? 8000, port = opts.port ?? 443, groups = opts.groups ?? GROUPS;
  if (!/^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(domain)
      || domain.length > 253 || !Number.isInteger(port) || port < 1 || port > 65535
      || !Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000
      || !groups.split(":").every((g) => GROUPS.split(":").includes(g))) throw new Error("invalid probe parameters");
  const holdMs = opts.holdMs ?? 3000;
  if (!Number.isInteger(holdMs) || holdMs < 0 || holdMs >= timeoutMs) throw new Error("invalid hold time");
  const base: Measurement = {
    reachable: false, kexHybrid: false, kexGroup: null, tlsVersion: null, cipher: null,
    certSigAlg: null, certNotAfter: null, address: null, ticketIssued: null,
    ticketLifetimeS: null, ticketWithoutRequest: null, resumed: null, error: null,
    certificateValidated: false, peerSignatureType: null, observation: null, transcript: null,
  };
  let address: string;
  try {
    if (opts.address) address = opts.address;
    else {
      let timer: NodeJS.Timeout | undefined;
      try {
        address = await Promise.race([lookup(domain, { all: true }).then((results) => {
            if (!results.length || (!opts.allowPrivate && results.some((r) => !isPublicAddress(r.address))))
              throw new Error("non-public DNS answer rejected");
            return results[0]!.address;
          }),
          new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("DNS timeout")), timeoutMs); })]);
      } finally { if (timer) clearTimeout(timer); }
    }
    if (!isIP(address) || (!opts.allowPrivate && !isPublicAddress(address))) throw new Error("non-public pinned address rejected");
  } catch (e) { return { ...base, error: `dns: ${(e as Error).message}`.slice(0, 120) }; }
  base.address = address;
  const version = opts.opensslVersion ?? (await runOpenSsl(["version"], timeoutMs)).stdout.trim();
  if (!version.startsWith("OpenSSL ") || version.length > 256) return { ...base, error: "cannot identify OpenSSL" };
  const work = await mkdtemp(join(tmpdir(), "obs-"));
  const sessionFile = join(work, "session.pem");
  try {
    const connect = ["s_client", "-connect", connectTarget(address, port), "-servername", domain,
      "-verify_hostname", domain, "-verify_return_error", "-tls1_3", "-groups", groups];
    if (opts.caFile) connect.push("-CAfile", opts.caFile);
    const first = await runOpenSsl([...connect, "-brief", "-sess_out", sessionFile], timeoutMs, "", holdMs);
    const parsed = parseDiagnostic(first.stderr);
    if (first.exitCode !== 0 || first.error || !parsed.validated || !groups.split(":").includes(parsed.group ?? "")) {
      return { ...base, error: first.error ?? `TLS validation failed (exit ${first.exitCode})` };
    }
    const observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const observation: Observation = { profile: "openssl-tls13-v1", observedAt,
      endpoint: { host: domain, port, address },
      probe: { name: "openssl", version, groups: groups.split(":"), certificateValidation: "pkix-hostname", exitCode: 0 },
      transcriptSha256: createHash("sha256").update(first.stderr, "utf8").digest("hex") };
    const volunteered = await hasSession(sessionFile);
    const request = opts.sendRequest === false ? "" : `HEAD / HTTP/1.1\r\nHost: ${domain}\r\nConnection: close\r\n\r\n`;
    let askedSucceeded = false;
    if (!volunteered && request) {
      const asked = await runOpenSsl([...connect, "-brief", "-sess_out", sessionFile], timeoutMs, request, holdMs);
      askedSucceeded = asked.exitCode === 0 && !asked.error && parseDiagnostic(asked.stderr).validated;
      if (!askedSucceeded) await rm(sessionFile, { force: true });
    }
    const issued = await hasSession(sessionFile);
    let certSigAlg: string | null = null, certNotAfter: string | null = null, lifetime: number | null = null;
    if (issued) {
      // A local session file is the only source; raw tickets are never exported.
      const session = await runOpenSsl(["sess_id", "-in", sessionFile, "-text", "-noout"], timeoutMs);
      if (session.exitCode === 0 && !session.error) {
        const life = one(session.stdout, /^\s*TLS session ticket lifetime hint:\s*(\d+)/gm);
        lifetime = life === null ? null : Number(life);
      }
      const cert = await runOpenSsl(["sess_id", "-in", sessionFile, "-cert"], timeoutMs);
      if (cert.exitCode === 0 && !cert.error && cert.stdout.includes("-----BEGIN CERTIFICATE-----")) {
        const details = await runOpenSsl(["x509", "-noout", "-text", "-enddate"], timeoutMs, cert.stdout);
        if (details.exitCode === 0 && !details.error) {
          certSigAlg = details.stdout.match(/Signature Algorithm:\s*([^\r\n]+)/)?.[1]?.trim() ?? null;
          const expiry = details.stdout.match(/^notAfter=(.+)$/m)?.[1];
          if (expiry && Number.isFinite(Date.parse(expiry))) certNotAfter = new Date(expiry).toISOString();
        }
      }
    }
    let resumed: boolean | null = null;
    if (issued) {
      const again = await runOpenSsl([...connect, "-sess_in", sessionFile], timeoutMs, request);
      // Exactly one genuine OpenSSL completion banner is required. Injecting an
      // additional banner in application output creates ambiguity, never success.
      const reuse = one(again.stdout, /^(New|Reused), TLSv1\.3, Cipher is \S+\s*$/gm);
      if (again.exitCode === 0 && !again.error && reuse) resumed = reuse === "Reused";
    }
    return { ...base, reachable: true, kexHybrid: isNegotiatedHybrid(parsed.group, parsed.tlsVersion),
      kexGroup: parsed.group, tlsVersion: parsed.tlsVersion, cipher: parsed.cipher, certSigAlg, certNotAfter,
      ticketIssued: issued ? true : askedSucceeded ? false : null, ticketLifetimeS: lifetime,
      ticketWithoutRequest: volunteered, resumed, certificateValidated: true,
      peerSignatureType: parsed.signature, observation, transcript: first.stderr };
  } finally { await rm(work, { recursive: true, force: true }); }
}

/** Fail closed for private, reserved, translation and transition destinations. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (!family) return false;
  const blocked = new BlockList();
  if (family === 4) {
    for (const [network, prefix] of [["0.0.0.0",8],["10.0.0.0",8],["100.64.0.0",10],["127.0.0.0",8],
      ["169.254.0.0",16],["172.16.0.0",12],["192.0.0.0",24],["192.0.2.0",24],["192.88.99.0",24],
      ["192.168.0.0",16],["198.18.0.0",15],["198.51.100.0",24],["203.0.113.0",24],["224.0.0.0",4],["240.0.0.0",4]] as const)
      blocked.addSubnet(network, prefix, "ipv4");
    return !blocked.check(address, "ipv4");
  }
  const global = new BlockList();
  global.addSubnet("2000::", 3, "ipv6");
  blocked.addSubnet("2001::", 23, "ipv6");
  blocked.addSubnet("2001:db8::", 32, "ipv6");
  blocked.addSubnet("2002::", 16, "ipv6");
  blocked.addSubnet("3fff::", 20, "ipv6");
  return global.check(address, "ipv6") && !blocked.check(address, "ipv6");
}
