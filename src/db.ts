import { randomBytes } from "node:crypto";
import pg from "pg";
import type { SeedHost } from "./hosts.js";
import { resolveCategory } from "./categories.js";
import type { Measurement } from "./probe.js";

/**
 * Postgres access for the observatory. The website migration owns these tables;
 * we CREATE / ALTER them IF NOT EXISTS so the worker also runs standalone. Probes
 * bucket by `run_date` (YYYY-MM-DD) so the series has daily granularity.
 */

export async function openDb(databaseUrl: string): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  return client;
}

export async function ensureSchema(client: pg.Client): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS observatory_host (
      id text PRIMARY KEY, domain text UNIQUE NOT NULL, rank int, rank_source text,
      category text, reason text, relevance text,
      added_at timestamptz NOT NULL DEFAULT now(), opted_out_at timestamptz);
    ALTER TABLE observatory_host ADD COLUMN IF NOT EXISTS category text;
    ALTER TABLE observatory_host ADD COLUMN IF NOT EXISTS reason text;
    ALTER TABLE observatory_host ADD COLUMN IF NOT EXISTS relevance text;

    CREATE TABLE IF NOT EXISTS observatory_probe (
      id text PRIMARY KEY,
      host_id text NOT NULL REFERENCES observatory_host(id) ON DELETE CASCADE,
      run_date text NOT NULL, reachable boolean NOT NULL DEFAULT false,
      kex_hybrid boolean NOT NULL DEFAULT false, kex_group text, tls_version text,
      cert_sig_alg text, cert_expiry timestamptz, probed_at timestamptz NOT NULL DEFAULT now(),
      raw jsonb NOT NULL DEFAULT '{}'::jsonb, UNIQUE (host_id, run_date));
    -- Resumption. Both ticket_issued and resumed are deliberately NULLABLE with no default: a host that issued
    -- no ticket was never asked, and recording that as false would count a coverage gap as
    -- a refusal. Read it as: true resumed, false refused, null not askable.
    ALTER TABLE observatory_probe ADD COLUMN IF NOT EXISTS address text;
    ALTER TABLE observatory_probe ADD COLUMN IF NOT EXISTS ticket_issued boolean;
    ALTER TABLE observatory_probe ADD COLUMN IF NOT EXISTS ticket_lifetime_s int;
    ALTER TABLE observatory_probe ADD COLUMN IF NOT EXISTS resumed boolean;
    -- Whether the ticket arrived on a connection that sent no application data. Nullable for the
    -- same reason: false means none arrived while the silent connection was held open, and null
    -- means that connection never completed a handshake, so the question was not put.
    ALTER TABLE observatory_probe ADD COLUMN IF NOT EXISTS ticket_without_request boolean;
    CREATE INDEX IF NOT EXISTS observatory_probe_date_idx ON observatory_probe (run_date);

    CREATE TABLE IF NOT EXISTS observatory_rollup (
      run_date text PRIMARY KEY, hosts_probed int NOT NULL, pct_hybrid_kex numeric NOT NULL,
      by_category jsonb NOT NULL DEFAULT '{}'::jsonb, generated_at timestamptz NOT NULL DEFAULT now());
    -- Resumption rollup. COUNTS, not percentages, and each numerator gets its own denominator
    -- beside it, because the three questions are asked of three different populations: every
    -- reachable host is asked whether it volunteers a ticket, only hosts that were asked for one
    -- can be said to have issued or not issued it, and only hosts that issued one can be said to
    -- have resumed or refused. A single percentage over "reachable" would silently merge them.
    ALTER TABLE observatory_rollup ADD COLUMN IF NOT EXISTS ticket_asked int;
    ALTER TABLE observatory_rollup ADD COLUMN IF NOT EXISTS ticket_issued int;
    ALTER TABLE observatory_rollup ADD COLUMN IF NOT EXISTS ticket_volunteer_asked int;
    ALTER TABLE observatory_rollup ADD COLUMN IF NOT EXISTS ticket_volunteered int;
    ALTER TABLE observatory_rollup ADD COLUMN IF NOT EXISTS resumption_offered int;
    ALTER TABLE observatory_rollup ADD COLUMN IF NOT EXISTS resumed int;
  `);
}

/** Upsert the panel into observatory_host, filling category reason/relevance. Never clobbers opt-out. */
export async function upsertHosts(client: pg.Client, seeds: SeedHost[], optout: Set<string>): Promise<void> {
  for (const s of seeds) {
    const cat = resolveCategory(s.category);
    const id = `obh-${randomBytes(6).toString("hex")}`;
    await client.query(
      `INSERT INTO observatory_host (id, domain, rank, rank_source, category, reason, relevance, opted_out_at)
         VALUES ($1, $2, $3, 'panel', $4, $5, $6, $7)
       ON CONFLICT (domain) DO UPDATE SET
         rank = EXCLUDED.rank, category = EXCLUDED.category,
         reason = EXCLUDED.reason, relevance = EXCLUDED.relevance,
         opted_out_at = EXCLUDED.opted_out_at`,
      [id, s.domain, s.rank, cat.id, cat.reason, cat.relevance, optout.has(s.domain) ? new Date() : null],
    );
  }
}

export type HostRow = { id: string; optedOut: boolean; category: string | null };

export async function fetchHostRows(client: pg.Client, domains: string[]): Promise<Map<string, HostRow>> {
  const { rows } = await client.query(
    `SELECT id, domain, category, opted_out_at FROM observatory_host WHERE domain = ANY($1)`,
    [domains],
  );
  const map = new Map<string, HostRow>();
  for (const r of rows) map.set(r.domain, { id: r.id, optedOut: r.opted_out_at != null, category: r.category });
  return map;
}

export async function upsertProbe(client: pg.Client, hostId: string, runDate: string, m: Measurement): Promise<void> {
  const id = `obp-${randomBytes(8).toString("hex")}`;
  await client.query(
    `INSERT INTO observatory_probe
       (id, host_id, run_date, reachable, kex_hybrid, kex_group, tls_version, cert_sig_alg, cert_expiry, raw,
        address, ticket_issued, ticket_lifetime_s, resumed, ticket_without_request)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15)
     ON CONFLICT (host_id, run_date) DO UPDATE SET
       reachable = EXCLUDED.reachable, kex_hybrid = EXCLUDED.kex_hybrid, kex_group = EXCLUDED.kex_group,
       tls_version = EXCLUDED.tls_version, cert_sig_alg = EXCLUDED.cert_sig_alg,
       cert_expiry = EXCLUDED.cert_expiry, probed_at = now(), raw = EXCLUDED.raw,
       address = EXCLUDED.address, ticket_issued = EXCLUDED.ticket_issued,
       ticket_lifetime_s = EXCLUDED.ticket_lifetime_s, resumed = EXCLUDED.resumed,
       ticket_without_request = EXCLUDED.ticket_without_request`,
    [
      id,
      hostId,
      runDate,
      m.reachable,
      m.kexHybrid,
      m.kexGroup,
      m.tlsVersion,
      m.certSigAlg,
      m.certNotAfter,
      JSON.stringify({ cipher: m.cipher, error: m.error }),
      m.address,
      m.ticketIssued,
      m.ticketLifetimeS,
      m.resumed,
      m.ticketWithoutRequest,
    ],
  );
}

export type RollupResult = {
  runDate: string;
  hostsProbed: number;
  reachable: number;
  hybrid: number;
  pctHybridKex: number;
  byCategory: Record<string, { reachable: number; hybrid: number }>;
  /** Each count paired with the population it was drawn from. Never reduce these to one ratio. */
  resumption: {
    ticketAsked: number;
    ticketIssued: number;
    ticketVolunteerAsked: number;
    ticketVolunteered: number;
    resumptionOffered: number;
    resumed: number;
  };
};

// Categories tracked as their own separate panels, kept OUT of the headline
// pct_hybrid_kex. The top-line number is the "web" leading-indicator panel (CDNs,
// clouds, security vendors, etc.); the government panel is a different and slower
// population and must not move it. Each excluded category is still fully recorded
// in by_category so it can be reported on its own.
const HEADLINE_EXCLUDE = new Set<string>(["government"]);

export async function computeRollup(client: pg.Client, runDate: string): Promise<RollupResult> {
  const { rows } = await client.query(
    `SELECT h.category, p.reachable, p.kex_hybrid, p.ticket_issued, p.ticket_without_request, p.resumed
       FROM observatory_probe p JOIN observatory_host h ON h.id = p.host_id
      WHERE p.run_date = $1`,
    [runDate],
  );
  let reachable = 0;
  let hybrid = 0;
  const resumption = {
    ticketAsked: 0,
    ticketIssued: 0,
    ticketVolunteerAsked: 0,
    ticketVolunteered: 0,
    resumptionOffered: 0,
    resumed: 0,
  };
  const byCategory: Record<string, { reachable: number; hybrid: number }> = {};
  for (const r of rows) {
    const cat = r.category ?? "other";
    byCategory[cat] ??= { reachable: 0, hybrid: 0 };
    if (r.reachable) {
      byCategory[cat].reachable += 1;
      if (r.kex_hybrid) byCategory[cat].hybrid += 1;
      // The headline totals cover the web panel only; separate panels (government)
      // live in by_category and never move the top-line adoption figure.
      if (!HEADLINE_EXCLUDE.has(cat)) {
        reachable += 1;
        if (r.kex_hybrid) hybrid += 1;
        // Null is a host the question was never put to, so it joins neither numerator nor
        // denominator. Counting it in the denominator would read as a negative answer.
        if (r.ticket_issued !== null) {
          resumption.ticketAsked += 1;
          if (r.ticket_issued) resumption.ticketIssued += 1;
        }
        if (r.ticket_without_request !== null) {
          resumption.ticketVolunteerAsked += 1;
          if (r.ticket_without_request) resumption.ticketVolunteered += 1;
        }
        if (r.resumed !== null) {
          resumption.resumptionOffered += 1;
          if (r.resumed) resumption.resumed += 1;
        }
      }
    }
  }
  const pctHybridKex = reachable > 0 ? Math.round((hybrid / reachable) * 10000) / 100 : 0;
  await client.query(
    `INSERT INTO observatory_rollup (run_date, hosts_probed, pct_hybrid_kex, by_category, generated_at,
        ticket_asked, ticket_issued, ticket_volunteer_asked, ticket_volunteered, resumption_offered, resumed)
       VALUES ($1, $2, $3, $4::jsonb, now(), $5, $6, $7, $8, $9, $10)
     ON CONFLICT (run_date) DO UPDATE SET
       hosts_probed = EXCLUDED.hosts_probed, pct_hybrid_kex = EXCLUDED.pct_hybrid_kex,
       by_category = EXCLUDED.by_category, generated_at = now(),
       ticket_asked = EXCLUDED.ticket_asked, ticket_issued = EXCLUDED.ticket_issued,
       ticket_volunteer_asked = EXCLUDED.ticket_volunteer_asked,
       ticket_volunteered = EXCLUDED.ticket_volunteered,
       resumption_offered = EXCLUDED.resumption_offered, resumed = EXCLUDED.resumed`,
    [runDate, reachable, pctHybridKex, JSON.stringify(byCategory),
     resumption.ticketAsked, resumption.ticketIssued, resumption.ticketVolunteerAsked,
     resumption.ticketVolunteered, resumption.resumptionOffered, resumption.resumed],
  );
  return { runDate, hostsProbed: reachable, reachable, hybrid, pctHybridKex, byCategory, resumption };
}
