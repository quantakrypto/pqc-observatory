/**
 * observatory - PQC readiness prober for the public panel.
 *
 *   observatory run [--date YYYY-MM-DD] [--panel PATH] [--optout PATH]
 *                   [--timeout MS] [--interval MS] [--no-request] [--dry-run]
 *
 * When --date is omitted it uses OBS_DATE, else today (UTC). --dry-run probes
 * without touching Postgres. DATABASE_URL is read from the environment.
 */
import { run } from "./run.js";
import { exportFreshRecords } from "./export.js";

const HELP = `observatory - PQC readiness prober for the public panel

Usage:
  observatory run [options]
  observatory export --input-dir DIRECTORY

Options:
  --date YYYY-MM-DD  Run date (default: OBS_DATE env, else today UTC)
  --panel PATH       Panel file (default: panel.json)
  --optout PATH      Opt-out file (default: optout.txt)
  --timeout MS       Per-host handshake timeout (default: 8000)
  --interval MS      Minimum gap between hosts (default: 500)
  --no-request       Send no application data at all. Restores handshake-only behaviour;
                     hosts that withhold NewSessionTicket until a request arrives then
                     record ticket_issued as null rather than false
  --dry-run          Probe without writing to Postgres
  -h, --help         Show this help

Environment:
  DATABASE_URL       Postgres connection string (required unless --dry-run)
  OBS_DATE           Fallback run date when --date is not given
  OBS_COLLECT_OUTPUT  Private unsigned provenance directory for authenticated transfer
  OBS_SIGNED_OUTPUT   Private signed evidence directory; enables authority integration
  OBS_AUTHORITY_DIR   Deployed attestation-authority checkout (src/observation.mjs)
  QK_ONLINE_KEY_REF / QK_ONLINE_KEY_ID   Existing KMS key reference and public key id
  OBS_ISSUER / OBS_AUDIENCE / OBS_LEDGER_PATH   Explicit issuance policy
  OBS_SIGNING_SUBJECTS  Required JSON array of independently authorized HTTPS subjects
  OBS_SNAPSHOT_BINDINGS  Optional JSON map of subject to independently supplied manifest SHA-256
`;

type Parsed = { date?: string; panel?: string; optout?: string; timeout?: number; interval?: number; sendRequest?: boolean; dryRun?: boolean };

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
      case "--no-request": opts.sendRequest = false; break;
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
  if (argv[0] === "export") {
    if (argv.length !== 3 || argv[1] !== "--input-dir" || !argv[2]) throw new Error("usage: observatory export --input-dir DIRECTORY");
    const count = await exportFreshRecords(argv[2]);
    process.stdout.write(JSON.stringify({ signed: count })+"\n");
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
    sendRequest: opts.sendRequest,
    dryRun: opts.dryRun,
  });
  process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
}

main().catch((err) => {
  process.stderr.write(`observatory: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
