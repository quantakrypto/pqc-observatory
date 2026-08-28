import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPanel, loadOptOut, type SeedHost } from "./hosts.js";
import { measureHost } from "./probe.js";
import { openDb, ensureSchema, upsertHosts, fetchHostRows, upsertProbe, computeRollup } from "./db.js";

/**
 * One observatory run for a single date: load the panel and opt-out list, probe
 * each host under the restrained policy (sequential, spaced, one handshake, hard
 * timeout, no retries), and persist per-host probes plus the daily rollup. All
 * wall-clock reads happen inside `run`, never at module load.
 */
const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = resolve(HERE, "..");

export interface RunOptions {
  /** Explicit YYYY-MM-DD. Omitted: OBS_DATE env, else today (UTC). */
  date?: string;
  now?: Date;
  panelFile?: string;
  optoutFile?: string;
  timeoutMs?: number;
  minIntervalMs?: number;
  /** False makes every connection silent, so no application data is sent. Default true. */
  sendRequest?: boolean;
  dryRun?: boolean;
  databaseUrl?: string;
  log?: (line: string) => void;
}

export interface RunSummary {
  runDate: string;
  totalSeed: number;
  optedOut: number;
  probed: number;
  reachable: number;
  hybrid: number;
  pctHybridKex: number;
  dryRun: boolean;
}

const delay = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Print a tri-state as yes/no/n-a. Null is never printed as "no": across every resumption
 * field in this run, null means the question was not put to the server and false means it was
 * put and answered in the negative, and a log that blurs the two invites the wrong reading.
 */
const tri = (v: boolean | null): string => (v === null ? "n/a" : v ? "yes" : "no");

/** Validate/derive the run date as YYYY-MM-DD (UTC). */
export function resolveDate(opts: Pick<RunOptions, "date" | "now">): string {
  const explicit = opts.date ?? process.env.OBS_DATE;
  if (explicit) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(explicit)) throw new Error(`invalid --date "${explicit}": expected YYYY-MM-DD`);
    return explicit;
  }
  const d = opts.now ?? new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

export async function run(opts: RunOptions = {}): Promise<RunSummary> {
  const log = opts.log ?? ((line: string): void => void process.stderr.write(line + "\n"));
  const runDate = resolveDate(opts);
  const timeoutMs = opts.timeoutMs ?? 8000;
  const minIntervalMs = opts.minIntervalMs ?? 500;
  const sendRequest = opts.sendRequest ?? true;
  const dryRun = opts.dryRun ?? false;

  const panelFile = opts.panelFile ?? join(PKG_ROOT, "panel.json");
  const optoutFile = opts.optoutFile ?? join(PKG_ROOT, "optout.txt");
  const seeds: SeedHost[] = loadPanel(panelFile);
  const optout = new Set(loadOptOut(optoutFile));
  if (seeds.length === 0) throw new Error(`no hosts found in ${panelFile}`);

  log(`observatory: date=${runDate} panel=${seeds.length} opt-out=${optout.size} dryRun=${dryRun}`);

  const databaseUrl = opts.databaseUrl ?? process.env.DATABASE_URL;
  if (!dryRun && !databaseUrl) throw new Error("DATABASE_URL is not set (use --dry-run to probe without writing)");

  const client = !dryRun && databaseUrl ? await openDb(databaseUrl) : null;
  let probed = 0;
  let reachable = 0;
  let hybrid = 0;

  try {
    if (client) {
      await ensureSchema(client);
      await upsertHosts(client, seeds, optout);
    }
    const hostRows = client
      ? await fetchHostRows(client, seeds.map((s) => s.domain))
      : new Map<string, { id: string; optedOut: boolean; category: string | null }>();

    let first = true;
    for (const seed of seeds) {
      const row = hostRows.get(seed.domain);
      if (optout.has(seed.domain) || (row?.optedOut ?? false)) {
        log(`  skip ${seed.domain} (opted out)`);
        continue;
      }
      if (!first && minIntervalMs > 0) await delay(minIntervalMs);
      first = false;

      const m = await measureHost(seed.domain, { timeoutMs, sendRequest });
      probed += 1;
      if (m.reachable) {
        reachable += 1;
        if (m.kexHybrid) hybrid += 1;
      }
      log(
        `  ${seed.domain}: ${
          m.reachable
            ? `${m.tlsVersion ?? "?"} kex=${m.kexGroup ?? "?"} hybrid=${m.kexHybrid} sig=${m.certSigAlg ?? "?"} ` +
              `ticket=${tri(m.ticketIssued)} volunteered=${tri(m.ticketWithoutRequest)} resumed=${tri(m.resumed)}`
            : `unreachable (${m.error ?? "unknown"})`
        }`,
      );
      if (client) await upsertProbe(client, row?.id ?? seed.domain, runDate, m);
    }

    let pctHybridKex = reachable > 0 ? Math.round((hybrid / reachable) * 10000) / 100 : 0;
    if (client) {
      const rollup = await computeRollup(client, runDate);
      pctHybridKex = rollup.pctHybridKex;
      log(`observatory: rollup ${rollup.runDate} reachable=${rollup.reachable} hybrid=${rollup.hybrid} pct=${rollup.pctHybridKex}%`);
      const r = rollup.resumption;
      // Each count with its own denominator. These are three different populations and a
      // single ratio over "reachable" would merge them into a number that means nothing.
      log(
        `observatory: resumption ${rollup.runDate} ticket=${r.ticketIssued}/${r.ticketAsked} ` +
          `volunteered=${r.ticketVolunteered}/${r.ticketVolunteerAsked} resumed=${r.resumed}/${r.resumptionOffered}`,
      );
    }

    return {
      runDate,
      totalSeed: seeds.length,
      optedOut: seeds.filter((s) => optout.has(s.domain) || hostRows.get(s.domain)?.optedOut).length,
      probed,
      reachable,
      hybrid,
      pctHybridKex,
      dryRun,
    };
  } finally {
    if (client) await client.end();
  }
}
