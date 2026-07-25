/**
 * observatory - PQC readiness prober for the public panel.
 *
 *   observatory run [--date YYYY-MM-DD] [--panel PATH] [--optout PATH]
 *                   [--timeout MS] [--interval MS] [--dry-run]
 *
 * When --date is omitted it uses OBS_DATE, else today (UTC). --dry-run probes
 * without touching Postgres. DATABASE_URL is read from the environment.
 */
import { run } from "./run.js";

const HELP = `observatory - PQC readiness prober for the public panel

Usage:
  observatory run [options]

Options:
  --date YYYY-MM-DD  Run date (default: OBS_DATE env, else today UTC)
  --panel PATH       Panel file (default: panel.json)
  --optout PATH      Opt-out file (default: optout.txt)
  --timeout MS       Per-host handshake timeout (default: 8000)
  --interval MS      Minimum gap between hosts (default: 500)
  --dry-run          Probe without writing to Postgres
  -h, --help         Show this help

Environment:
  DATABASE_URL       Postgres connection string (required unless --dry-run)
  OBS_DATE           Fallback run date when --date is not given
`;

type Parsed = { date?: string; panel?: string; optout?: string; timeout?: number; interval?: number; dryRun?: boolean };

function parseArgs(argv: string[]): { cmd: string; opts: Parsed } {
  const [cmd = "", ...rest] = argv;
  const opts: Parsed = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    switch (a) {
      case "--date": opts.date = rest[++i]; break;
      case "--panel": opts.panel = rest[++i]; break;
      case "--optout": opts.optout = rest[++i]; break;
      case "--timeout": opts.timeout = Number(rest[++i]); break;
      case "--interval": opts.interval = Number(rest[++i]); break;
      case "--dry-run": opts.dryRun = true; break;
      default: break;
    }
  }
  return { cmd, opts };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") {
    process.stdout.write(HELP);
    return;
  }
  const { cmd, opts } = parseArgs(argv);
  if (cmd !== "run") {
    process.stderr.write(`unknown command "${cmd}"\n\n${HELP}`);
    process.exitCode = 2;
    return;
  }
  const summary = await run({
    date: opts.date,
    panelFile: opts.panel,
    optoutFile: opts.optout,
    timeoutMs: opts.timeout,
    minIntervalMs: opts.interval,
    dryRun: opts.dryRun,
  });
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}

main().catch((err) => {
  process.stderr.write(`observatory: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
