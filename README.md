# PQC Observatory

A daily, read-only measurement of post-quantum readiness across a public panel of
hosts: which of them negotiate hybrid TLS key exchange (X25519MLKEM768), and how
their certificates are signed, tracked over time. The results power the public
page at [quantakrypto.com/observatory](https://quantakrypto.com/observatory).

Maintained by [quantakrypto](https://quantakrypto.com). Apache-2.0.

## What it measures

For each host in [`panel.json`](panel.json), once a day, over a single read-only
TLS handshake to port 443:

- **Hybrid key exchange** - whether the server selects **X25519MLKEM768**, the
  hybrid that stays secure if either the classical or the post-quantum half holds.
  This is the clearest single signal that a host has begun its migration.
- **Certificate posture** - the negotiated TLS version and the leaf certificate's
  signature algorithm and expiry.
- **Reachability** - whether a handshake completed at all, so a coverage gap never
  reads as a drop in adoption.

The metric is "does the server select hybrid in a normal negotiation", not "does
it support hybrid if asked in isolation": we offer the hybrid group alongside the
usual classical groups and record what the server actually picks, which is what a
real client would get.

## Probing policy (restrained by design)

A measurement you cannot trust is worse than none, so the method is deliberately
dull and is enforced in code, not just documented (see
[docs/probing-policy.md](docs/probing-policy.md)):

- one TLS handshake per host per run, driven by `openssl s_client`;
- sequential, with a minimum gap between hosts (no parallel fan-out);
- a hard per-connection timeout and no aggressive retries (a refusal or timeout is
  recorded as unreachable);
- no application data is ever sent, and nothing beyond the handshake is attempted;
- a host in [`optout.txt`](optout.txt) (or marked opted-out in the database) is
  skipped before any connection.

This is the same class of unauthenticated measurement that public scanners such as
SSL Labs and Censys have run for years.

## The panel

[`panel.json`](panel.json) is the list of measured hosts, each tagged with a
category. The categories carry a short reason the host is on the panel and a note
on how strong a signal it is for web-wide readiness (see
[`src/categories.ts`](src/categories.ts)): CDNs are bellwethers because they carry
so much of the web, security and PKI vendors are expected to lead, privacy
messaging tends to move first, consumer sites are a baseline, governments are the
mandate-setters measured against their own public front doors, and so on.

The panel spans the technology categories above plus a **government** panel of
200+ official national government and public-sector portals (roughly one per UN
member state, plus a few notable territories), so the observatory tracks whether
the institutions that write the migration mandates have migrated their own front
doors.

### Contributing a host

Open a pull request adding an entry to `panel.json`:

```json
{ "domain": "example.com", "category": "cloud" }
```

Use a bare, publicly reachable domain and pick the closest category from
`src/categories.ts`. We keep the panel to notable endpoints where post-quantum
posture is a meaningful signal. To remove a host without deleting the entry, add
its domain to `optout.txt`; it is honored within one run.

## Running it

```bash
npm install
# Probe without writing anything (prints per-host results + a JSON summary):
npm run observatory -- run --dry-run
# A real run for today (writes to Postgres):
DATABASE_URL=postgres://... npm run observatory -- run
# A specific day:
npm run observatory -- run --date 2026-07-25
```

Options: `--date YYYY-MM-DD`, `--panel PATH`, `--optout PATH`, `--timeout MS`,
`--interval MS`, `--dry-run`. The run date defaults to `OBS_DATE`, else today (UTC).
`openssl` (3.5+, for the hybrid group) and Node 20+ are the only requirements.

## Data it writes

Idempotent per day into Postgres (the tables are owned by the quantakrypto site's
migration; this worker also creates them defensively):

- `observatory_host` - the panel: domain, rank, category, reason, relevance, opt-out.
- `observatory_probe` - one row per host per `run_date` (`ON CONFLICT (host_id, run_date)`),
  with reachability, hybrid selection, group, TLS version, cert signature and expiry.
- `observatory_rollup` - one row per `run_date` with the reachable count, the hybrid
  percentage, and a per-category breakdown.

## Deployment

The worker runs on the same VM as the site, on a daily `systemd` timer. It needs
`DATABASE_URL` and `openssl` 3.5+ in its environment. No separate infrastructure.
