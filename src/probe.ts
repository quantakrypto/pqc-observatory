import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * A single host measurement, produced by two or three read-only TLS handshakes driven
 * by `openssl s_client`. The first is silent: it offers the hybrid group first alongside
 * classical fallbacks, records which the server actually selects along with the
 * certificate's signature algorithm and expiry, and writes nothing at all, so a ticket
 * arriving on it is one the server volunteered. Servers that volunteer nothing get a
 * second connection carrying one HEAD request, because roughly half of the panel withholds
 * NewSessionTicket until a request arrives and would otherwise look ticketless. The last
 * connection offers back whatever ticket was issued, to the SAME address and the SAME SNI,
 * and records whether the server resumed.
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
   * Whether a session ticket was issued at all. Null only when no request was sent and none
   * arrived unprompted, in which case the server was never really asked.
   */
  ticketIssued: boolean | null;
  /** Server's lifetime hint in seconds, when it printed one. */
  ticketLifetimeS: number | null;
  /**
   * Whether the server volunteered a ticket on a connection that sent no application data.
   * False means none arrived while the silent connection was held open, which is a bounded
   * claim: the bound is SILENT_MS + HOLD_MS below, not infinity. Null when the silent
   * connection never completed a handshake.
   */
  ticketWithoutRequest: boolean | null;
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

/**
 * One s_client connection that answers two questions instead of one.
 *
 * It completes the handshake, waits `silentMs`, sends `request`, then holds the connection open
 * `holdMs` longer so a post-handshake NewSessionTicket has time to arrive.
 *
 * Passing an empty `request` makes this a silent connection: it handshakes, waits, and closes
 * without ever writing application data. That is how `ticketWithoutRequest` is measured.
 *
 * It has to be a separate connection, and this is worth recording because the obvious cheaper
 * design does not work. Snapshotting the transcript just before writing the request, to see
 * whether a ticket had already arrived, reads empty for every host including the ones that
 * demonstrably volunteer one: s_client surfaces the ticket banner only as the connection
 * closes, by which point the request has long gone. Measured, against aws.amazon.com: 3,780
 * bytes of transcript had arrived after 2.5s of silence with no banner, and the banner
 * appeared at close. Not output buffering, just when s_client prints it.
 */
function runSClient(
  args: string[],
  timeoutMs: number,
  request: string,
  silentMs: number,
  holdMs: number,
): Promise<string> {
  return new Promise((resolve) => {
    const p = spawn("openssl", args, { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(out);
    };
    const timer = setTimeout(() => {
      try {
        p.kill("SIGKILL");
      } catch {
        /* already gone */
      }
    }, timeoutMs);
    p.stdout.on("data", (d) => (out += d.toString()));
    p.stderr.on("data", (d) => (out += d.toString()));
    p.on("error", done);
    p.on("close", done);

    const send = setTimeout(() => {
      try {
        if (request) p.stdin.write(request);
      } catch {
        /* ignore */
      }
      const end = setTimeout(() => {
        try {
          p.stdin.end();
        } catch {
          /* already closed */
        }
      }, holdMs);
      end.unref?.();
    }, silentMs);
    send.unref?.();
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
    ticketIssued: null,
    ticketLifetimeS: null,
    ticketWithoutRequest: null,
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
  const SILENT_MS = 1500;
  const HOLD_MS = 1500;
  // A HEAD for the root, nothing else. It reads no body and changes no state, and it is what
  // a browser sends on every visit. It exists only to make ticket issuance observable on the
  // servers that withhold NewSessionTicket until a request arrives.
  const request = sendRequest ? `HEAD / HTTP/1.1\r\nHost: ${domain}\r\nConnection: close\r\n\r\n` : "";
  const connect = ["s_client", "-connect", `${address}:443`, "-servername", domain,
                   "-verify_hostname", domain, "-groups", GROUPS];

  // First connection, silent. Nothing is written on it, so a ticket arriving here is one the
  // server offered without being asked for anything.
  const out = await runSClient(
    [...connect, "-sess_out", sessionFile],
    timeoutMs,
    "",
    SILENT_MS,
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
  const TICKET = /Post-Handshake New Session Ticket arrived|TLS session ticket:/i;
  const LIFETIME = /TLS session ticket lifetime hint:\s*(\d+)/i;

  const volunteered = TICKET.test(out);
  let ticketTranscript = out;

  // Only the servers that volunteered nothing are asked. On this panel that is roughly half
  // of them, so the request costs a connection where it buys an answer and nowhere else.
  if (!volunteered && sendRequest) {
    const asked = await runSClient(
      [...connect, "-sess_out", sessionFile],
      timeoutMs,
      request,
      0,
      HOLD_MS,
    );
    if (TICKET.test(asked)) ticketTranscript = asked;
  }

  const sawTicket = TICKET.test(ticketTranscript);
  // With a request sent, absence is a real absence. Without one, it is merely unobserved.
  const ticketIssued: boolean | null = sawTicket ? true : sendRequest ? false : null;
  const lifeM = ticketTranscript.match(LIFETIME);

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
    ticketWithoutRequest: volunteered,
    resumed,
    error: null,
  };
}
