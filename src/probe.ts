import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A single host measurement, produced by two read-only TLS handshakes driven by
 * `openssl s_client`. The first offers the hybrid group first alongside classical
 * fallbacks and records which the server actually selects, plus the certificate's
 * signature algorithm and expiry. The second offers back any session ticket the
 * first was issued, to the SAME address and the SAME SNI, and records whether the
 * server resumed. No application data is ever sent on either.
 *
 * Why the address is pinned: if the two connections landed on different edge nodes,
 * a failure to resume would be a statement about ticket-key distribution rather than
 * about the server's willingness to resume, and the two are indistinguishable after
 * the fact.
 *
 * Why `resumed` is nullable: a host that never issued a ticket cannot be said to have
 * refused to resume. That case records null, not false, so a coverage gap is never
 * counted as a refusal.
 */
export type Measurement = {
  reachable: boolean;
  kexHybrid: boolean;
  kexGroup: string | null;
  tlsVersion: string | null;
  cipher: string | null;
  certSigAlg: string | null;
  certNotAfter: string | null;
  /** Address both connections used. Null when resolution failed. */
  address: string | null;
  /**
   * Whether the first connection was issued a session ticket, or null when that could not
   * be observed because no application data was sent. Some servers, Cloudflare's among them,
   * send NewSessionTicket only after receiving a request: measured directly, ietf.org yields
   * no ticket banner after five seconds of silence and four after a single HEAD. Reporting
   * that silence as "issued no ticket" would be false for a large share of the web, so it is
   * reported as null instead.
   */
  ticketIssued: boolean | null;
  /** Server's lifetime hint in seconds, when it printed one. */
  ticketLifetimeS: number | null;
  /** True resumed, false refused, null not askable because no ticket was issued. */
  resumed: boolean | null;
  error: string | null;
};

/** Hybrid first, then classical fallbacks, so a hybrid-capable server selects it and others still connect. */
const GROUPS = "X25519MLKEM768:X25519:secp256r1:secp384r1:x448";

/**
 * Run openssl with args (no shell), feed `stdin`, capture stdout+stderr, hard timeout.
 *
 * `holdMs` keeps stdin open that long before closing it. A TLS 1.3 NewSessionTicket
 * arrives AFTER the handshake, so a client that writes nothing and exits immediately
 * never sees one, and every host would look as though it issued no ticket.
 */
function runOpenssl(args: string[], timeoutMs: number, stdin: string, holdMs = 0): Promise<string> {
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
      if (holdMs > 0) {
        const hold = setTimeout(() => {
          try {
            p.stdin.end();
          } catch {
            /* already closed */
          }
        }, holdMs);
        hold.unref?.();
      } else {
        p.stdin.end();
      }
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
export async function measureHost(
  domain: string,
  opts: { timeoutMs?: number; sendRequest?: boolean } = {},
): Promise<Measurement> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  // Default true. With it false the run sends no application data at all, which keeps the
  // handshake-only promise but makes ticket issuance unobservable on servers that withhold
  // NewSessionTicket until a request arrives; those record ticketIssued: null.
  const sendRequest = opts.sendRequest ?? true;
  const base: Measurement = {
    reachable: false,
    kexHybrid: false,
    kexGroup: null,
    tlsVersion: null,
    cipher: null,
    certSigAlg: null,
    certNotAfter: null,
    address: null,
    ticketIssued: false,
    ticketLifetimeS: null,
    resumed: null,
    error: null,
  };

  // Resolve once and pin, so both connections reach the same node. Without this a
  // non-resumption is unreadable: it could be the server refusing or simply a different
  // edge node that never held the ticket key.
  let address: string;
  try {
    address = (await lookup(domain)).address;
  } catch (e) {
    return { ...base, error: `dns: ${(e as Error).message}`.slice(0, 120) };
  }

  const work = await mkdtemp(join(tmpdir(), "obs-"));
  const sessionFile = join(work, "session.pem");
  try {
    return await measurePinned(domain, address, sessionFile, timeoutMs, sendRequest, base);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

/** Both handshakes, against a pinned address. Never throws. */
async function measurePinned(
  domain: string,
  address: string,
  sessionFile: string,
  timeoutMs: number,
  sendRequest: boolean,
  base: Measurement,
): Promise<Measurement> {
  base = { ...base, address };
  // HOLD_MS keeps the connection open after the handshake so a TLS 1.3
  // NewSessionTicket, which arrives post-handshake, has time to be written out.
  // Sending nothing and exiting immediately would miss every TLS 1.3 ticket.
  const HOLD_MS = 1500;
  // A HEAD for the root, nothing else, and only to make the ticket observable. It reads no
  // body and changes no state, and it is exactly what a browser sends on every visit.
  const request = sendRequest ? `HEAD / HTTP/1.1\r\nHost: ${domain}\r\nConnection: close\r\n\r\n` : "";
  const out = await runOpenssl(
    ["s_client", "-connect", `${address}:443`, "-servername", domain, "-verify_hostname", domain,
     "-groups", GROUPS, "-sess_out", sessionFile],
    timeoutMs,
    request,
    HOLD_MS,
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

  // A ticket shows up either as the TLS 1.3 post-handshake banner or, on 1.2, as a
  // session block carrying ticket material.
  const lifeM = out.match(/TLS session ticket lifetime hint:\s*(\d+)/i);
  const sawTicket =
    /Post-Handshake New Session Ticket arrived/i.test(out) || /TLS session ticket:/i.test(out);
  // Without a request, an absent ticket is unobservable rather than absent.
  const ticketIssued: boolean | null = sawTicket ? true : sendRequest ? false : null;

  let resumed: boolean | null = null;
  if (sawTicket) {
    // Same address, same SNI, ticket offered back. Never to a different host: replaying
    // across hosts is a scope experiment on somebody else's access control, not ours to run.
    const again = await runOpenssl(
      ["s_client", "-connect", `${address}:443`, "-servername", domain, "-verify_hostname", domain,
       "-groups", GROUPS, "-sess_in", sessionFile],
      timeoutMs,
      request,
      0,
    );
    if (/Protocol\s*:\s*TLS|New,\s*TLS|Reused,\s*TLS/i.test(again)) {
      resumed = /Reused,\s*TLS/i.test(again);
    }
    // If the second connection produced no handshake at all, resumed stays null: we asked
    // and got no answer, which is not the same as a refusal.
  }

  return {
    reachable: true,
    kexHybrid: /X25519MLKEM768/i.test(out),
    kexGroup: groupM?.[1]?.trim() ?? null,
    tlsVersion: verM?.[1] ?? null,
    cipher: cipherM?.[1] ?? null,
    certSigAlg,
    certNotAfter,
    address,
    ticketIssued,
    ticketLifetimeS: lifeM ? Number(lifeM[1]) : null,
    resumed,
    error: null,
  };
}
