# PQC Observatory

A daily, read-only measurement of post-quantum readiness across a public panel of
hosts: which of them negotiate hybrid TLS key exchange (X25519MLKEM768), and how
their certificates are signed, tracked over time. The results power the public
page at [quantakrypto.com/observatory](https://quantakrypto.com/observatory).

Maintained by [quantakrypto](https://quantakrypto.com). Apache-2.0.

## What it measures

For each host in [`panel.json`](panel.json), once a day, over two or three read-only TLS
handshakes to port 443:

- **Hybrid key exchange** - whether the server selects **X25519MLKEM768**, the
  hybrid that stays secure if either the classical or the post-quantum half holds.
  This is the clearest single signal that a host has begun its migration.
- **Certificate posture** - TLS 1.3 is mandatory; the chain and hostname must validate.
  The handshake signature is recorded separately from the leaf certificate's
  signature and expiry. Leaf details come from a locally saved session and remain
  unknown if the endpoint never issues a ticket.
- **Resumption** - whether the server issued a session ticket, the lifetime hint it
  carried, and whether a second connection offering that ticket back was resumed. Both
  connections use the same pinned address and the same SNI: without pinning, a failure to
  resume could be a different edge node rather than a refusal, and the two are not
  distinguishable afterwards. A ticket is never offered to a host that did not issue it.
  A host that issued no ticket records `resumed = null`, not false, because it was never
  asked, and a coverage gap must never be counted as a refusal.
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

- two or three TLS handshakes per host per run, driven by `openssl s_client`: a silent one
  that measures the handshake and sees whether a ticket is volunteered, a second carrying
  one `HEAD /` only if the first drew no ticket, and a last one offering that ticket back;
- sequential, with a minimum gap between hosts (no parallel fan-out);
- a hard per-connection timeout and no aggressive retries (a refusal or timeout is
  recorded as unreachable);
- at most one `HEAD /` per connection and nothing else. This changed when resumption was
  added: many servers send NewSessionTicket only after a request arrives, so measuring
  ticket issuance without one reports "no ticket" for a large share of the web. Measured
  on 28 August 2026, running a fourteen-host panel twice back to back, the second run
  starting as the first finished: silent connections drew a ticket from **8 of 14** hosts,
  one `HEAD /` drew one from **14 of 14**. The six that volunteer nothing are the Google- and Cloudflare-fronted names,
  `ietf.org` among them. The request reads no body and changes no state, and
  `--no-request` restores strict handshake-only behaviour, in which ticket issuance
  records as `null` rather than as false;
- the ticket is offered back only to the address and SNI that issued it, never across
  hosts;
- a host in [`optout.txt`](optout.txt) (or marked opted-out in the database) is
  skipped before any connection.

The probe authenticates the server certificate but sends no client credential.
Private, reserved and transition-network addresses are rejected before connecting;
all DNS answers must be public. Explicit private-address overrides exist only for
operator-controlled test calls. Diagnostics are bounded separately from application
output, and failures cannot become authenticated observations.

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
  with reachability, hybrid selection, group, TLS version, cert signature and expiry, plus
  the pinned address and four resumption columns: `ticket_issued`, `ticket_lifetime_s`,
  `ticket_without_request` and `resumed`. Three of those are nullable with no default, and
  the null means one specific thing: the question was not put to that server. A host that
  was never asked for a ticket has `ticket_issued = null`, not false; a host that issued no
  ticket has `resumed = null`, not false. Only `false` is a negative answer.
- `observatory_rollup` - one row per `run_date` with the reachable count, the hybrid
  percentage, a per-category breakdown, and the resumption counts as **counts beside their
  own denominators** (`ticket_issued`/`ticket_asked`, `ticket_volunteered`/
  `ticket_volunteer_asked`, `resumed`/`resumption_offered`) rather than as percentages.
  The three are drawn from three different populations, so a single ratio over the
  reachable count would merge them into a figure that means nothing.

## Deployment

The worker runs on the same VM as the site, on a daily `systemd` timer. It needs
`DATABASE_URL` and `openssl` 3.5+ in its environment. No separate infrastructure.

## Authenticated observation export

Fresh probes store certificate validation, exact bounded OpenSSL diagnostic
transcript and `openssl-tls13-v1` provenance in the existing `raw` JSON column.
Historical rows remain unchanged and cannot be upgraded to authenticated evidence.
`kex_hybrid` now counts only validated, completed TLS 1.3 negotiation, so changes
from old rollups can reflect stronger collection rules rather than server changes.
The denominator now excludes TLS 1.2 and certificate-invalid endpoints previously
counted as reachable; historical and new percentages are not directly comparable.
Before production rollout, the website chart must disclose the methodology change
and its effective collection date. This is a deployment gate, not evidence of
adoption. New `raw.observation.profile` distinguishes validated records; absent
profiles remain legacy telemetry. No extra reachability probe is introduced.

The same `observatory run` path optionally saves private unsigned collector records
with `OBS_COLLECT_OUTPUT`, or signs directly if `OBS_SIGNED_OUTPUT` and the issuer
configuration are provided. The existing GitHub KMS identity can instead sign
records transferred over an authenticated administrative channel:

```sh
npm run observatory -- export --input-dir /operator/verified-transfer
```

Signing uses the deployed attestation-authority `issueObservation` API, RFC 9964
ML-DSA-65 JWS, the existing KMS key and authority ledger. `OBS_SIGNING_SUBJECTS`
is an independently configured subject allowlist; optional `OBS_SNAPSHOT_BINDINGS`
contains explicit `sha256:<hex>` manifest digests. Records older than one hour,
invalid diagnostics and unauthorized subjects are rejected. No signing credentials
are copied to the collector. A signature authenticates the collector statement,
not independent proof that its measurement is true.

See [deployment.md](docs/deployment.md) for the artifact boundary and required
configuration. Dry runs never write the database, evidence files or KMS ledger.
The CI job requires real local hybrid TLS tests on a pinned OpenSSL build.
