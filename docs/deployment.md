# Authenticated evidence deployment

The existing Observatory runs beside quantakrypto.com on its existing daily systemd timer. Inspection on 2026-10-11 identified `observatory.service` and the enabled `observatory.timer` on `dl-latest`, running as root through `/root/pqc-observatory/run.sh`. The service pulls `main`, loads the existing website environment and invokes the collector. It has now been updated to merged commit `238860e`; the completed production run is recorded below. The initial inspection found Node 22.22.1 and OpenSSL 3.5.5. Recheck the installation and runtime before future changes; do not create another worker or scheduler. The website reads the Observatory's Postgres tables, which does not export authenticated measurements.

## 1. Inspect the existing installation

In an already authorized SSH session, these commands are read-only:

```sh
systemctl list-unit-files --no-pager | rg -i observatory
systemctl list-timers --all --no-pager | rg -i observatory
systemctl show "$OBS_SERVICE" \
  --property=User --property=Group --property=WorkingDirectory \
  --property=FragmentPath --property=EnvironmentFiles
```

Set `OBS_SERVICE` to the discovered service, not a guessed name. Inspect its working directory and runtime without printing environment values or credentials:

```sh
cd "$OBS_WORKER_DIR"
git rev-parse HEAD
node --version
"${OPENSSL_BINARY:-openssl}" version
"${OPENSSL_BINARY:-openssl}" list -tls1_3 -tls-groups
```

`OBS_WORKER_DIR` is the discovered directory. Node 24.6.0 or newer is required when the authority runs in the same process; OpenSSL 3.5+ must advertise X25519MLKEM768 for hybrid probes. Validate the exact committed worker and authority revisions before installing them: `npm ci`, `npm run typecheck` and `REQUIRE_HYBRID_TLS=1 npm test` in the worker, and `npm ci` plus `npm test` in the authority. Preserve the existing scheduler and database configuration.

A small operator-approved panel can exercise the collector without persistence:

```sh
npm run observatory -- run --dry-run --no-request \
  --panel "$CANARY_PANEL" --optout "$CANARY_OPTOUT"
```

This performs real TLS handshakes. It writes neither Postgres nor evidence files and never calls KMS. A successful dry run does not demonstrate signing or deployment.

## 2. Reuse the existing signing context

The website's Actions signing steps reference `QK_KMS_REGION`, `QK_ONLINE_KEY_ARN`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Their presence on the VM is not established. Keep credentials in their existing approved context; do not copy Actions secrets to the collector or provision another signing key.

The existing online public key is `qk-online-2026-08`, ML-DSA-65. Its SHA-256 over SPKI DER is:

```text
33698c1c345d1df7a5308c513ee5c3925bc7f31c12aeb883549430a6d8f7cc80
```

This corrected pin is SHA-256 of the 1974-byte SPKI DER, independently reproduced from the public `/.well-known/attestation-keys.json` committed in quantakrypto/website at `26be7d4b09873609f4b3e1ac8739932149ec003a`. The historical bundle and live bundle matched on 2026-10-11. The previous runbook fingerprint was incorrect; this correction does not rotate the key. The online certificate states 2026-08-07 through 2027-08-07. Before use, verify its root signature, validity and revocation using the independently trusted root; compare the KMS public key against the approved online pin. A repository copy or a fresh download alone must not silently establish a new trust anchor. Deliberate key rotation requires an independently reviewed pin update.

The deployed website workflows issue the legacy posture format through one serialized durable ledger transaction. Signing is now required for deployment. This is not an Observatory standard-JWS deployment path, and successful legacy issuance does not satisfy the authenticated evidence acceptance gate.

Run the authority canary inside that existing signing context, using Node 24.6.0 or newer:

```sh
QK_KMS_PROVIDER=aws node "$OBS_AUTHORITY_DIR/bin/check-key.mjs" \
  --online-key "$QK_ONLINE_KEY_ARN" \
  --key-id qk-online-2026-08 \
  --expected-spki-sha256 sha256:33698c1c345d1df7a5308c513ee5c3925bc7f31c12aeb883549430a6d8f7cc80
```

The canary reads the existing public key, requires the supplied pin before signing, then verifies a real KMS signature locally. It creates no key, attestation token or ledger entry and emits only public metadata. It still makes a real signing request; it is not an offline test. Preserve its successful result as deployment evidence. A missing identity, pin mismatch or signing failure blocks production acceptance.

## 3. Collect on the existing worker, sign in the authorized context

`OBS_COLLECT_OUTPUT` is now enabled on the existing scheduled `npm run observatory -- run` invocation, with an owner-only directory and files. The normal run continues writing Postgres and additionally retains validated measurement records; the completed run below produced unsigned records only. Preserve that existing scheduler. Leave `OBS_SIGNED_OUTPUT` unset on the VM unless its existing identity is explicitly authorized for signing.

Transfer only the fresh record files through the existing authenticated deployment transport. Authenticate the collector host and source directory; an unsigned file and its self-computed digest do not establish collector identity. Do not accept arbitrary uploaded artifacts as collector records. Complete transfer and issuance within one hour of measurement; stale records must be measured again.

In the authorized signing context, configure:

| Variable | Required value |
| --- | --- |
| `OBS_SIGNED_OUTPUT` | Private output directory for signed bundles |
| `OBS_AUTHORITY_DIR` | Exact tested authority checkout containing `src/observation.mjs` |
| `QK_ONLINE_KEY_REF` | Existing approved online KMS reference; map from existing `QK_ONLINE_KEY_ARN` |
| `QK_ONLINE_KEY_ID` | Approved public key ID, currently `qk-online-2026-08` |
| `QK_KMS_REGION` | Existing configured KMS region |
| `OBS_ISSUER` | Issuer identity explicitly trusted by the consumer |
| `OBS_AUDIENCE` | Intended consumer identity, matching its trust policy |
| `OBS_SIGNING_SUBJECTS` | Local JSON file containing the authorized HTTPS subject array |
| `OBS_LEDGER_PATH` | Existing durable authority ledger, protected against concurrent writers |
| `OBS_SNAPSHOT_BINDINGS` | Optional local JSON map from subject to `sha256:<hex>` of exact manifest bytes |

The current credentials stay in the signing environment. A workflow can map the non-secret key reference without exposing its credential values:

```sh
export QK_ONLINE_KEY_REF="$QK_ONLINE_KEY_ARN"
export QK_ONLINE_KEY_ID=qk-online-2026-08
cd "$OBS_WORKER_DIR"
npm run observatory -- export --input-dir "$COLLECTED_RECORDS_DIR"
```

This command signs and writes evidence: it is not a dry run. Supply a durable ledger with safe serialization and recovery; an ephemeral runner ledger must not reset or race the shared authority history. There is no automatic shared-ledger transport in this command. Reconcile successful issuance if a subsequent file transfer fails instead of blindly retrying and claiming that nothing was signed.

Each output contains the token and exact transcript. Configure consumer trust from the approved public key, issuer, subject, audience and purpose. The signature proves an authorized issuer statement; it does not independently prove collector honesty or endpoint behavior. Snapshot-bound monitoring requires a matching independently supplied manifest digest. Successful standalone ingestion does not substitute for that binding.

## Acceptance and remaining operational gate

Require a real KMS key-pin/signature canary, one fresh collector record signed by the existing identity, successful consumer verification with the real public key, and negative checks for modified transcript, wrong subject, replay and expiry. Confirm the existing timer remains the only scheduler and that failures retain the previous baseline and produce actionable monitoring output.

## Production receipts (2026-10-11)

The original changes merged as Observatory `238860e`, crypto-agility `7b79cd2`, Authority `55ff0fd` and website `c5cdbe0`. The existing Observatory service and timer were updated to `238860e`. A full production run from 18:41:47 to 19:00:31 UTC exited successfully and refreshed 271 of 271 database rows. It retained 203 certificate-validated records with directory mode 0700 and file mode 0600; filename and transcript hashes were checked. Zero records were signed. Local integrity checks and database freshness do not authenticate the collector's handoff to an issuer.

Certificate validation and mandatory TLS 1.3 changed the web denominator from 70 to 66 while the hybrid count remained 48 (`48/70` to `48/66`). This is a methodology effect, not adoption growth. The website's basic methodology disclosure is live. The explicit cutover-date disclosure is tracked in [website PR #276](https://github.com/quantakrypto/website/pull/276). Device compatibility remains unknown or declared unless representative measurements exist.

The existing-key canary passed in [website Actions run 38162473186](https://github.com/quantakrypto/website/actions/runs/38162473186), using website commit `36f64b7705d3f152f3780093f96a8fe4da7f0e37`. Its isolated job verified the corrected historical SPKI pin and a real KMS RAW signature; legacy issuance was skipped. It created no attestation, observation token or ledger entry. This demonstrates signing access and key continuity only. Read-only inspection found no AWS/KMS configuration names in the worker's loaded environment; the existing website Actions context retains the signing credentials.

### Shared ledger: legacy writers deployed, observation integration pending

[Website PR #286](https://github.com/quantakrypto/website/pull/286) merged as `b37e956`, with successful [CI](https://github.com/quantakrypto/website/actions/runs/38165662878), [deployment](https://github.com/quantakrypto/website/actions/runs/38165903487) and [production SEO/JSON-LD checks](https://github.com/quantakrypto/website/actions/runs/38166157610). The legacy website deployment and project-attestation writers now serialize through the same durable authority at `/var/lib/quantakrypto-attestation`. The public ledger is a replica. Owner-only canonical state retains a recovery journal and current per-subject artifacts; website release preparation restores them under the same lock before swapping public assets.

Authenticated migration preserved the existing 51-entry ledger with full-file SHA-256 `3c0262b8b37edb4c1e8e3f81d254f907c35c759287fe3fafb507a4afab99f765`. Real legacy issuance increased the ledger to 52 entries, with full-file SHA-256 `0ab2c5823eeb2d717f6e70c2c3695a04ded4810d28e8b17426ab9126c69c9bb0`. Canonical and served ledgers and all three artifact replicas matched, no pending journal remained, and the public ML-DSA signature verified against the approved SPKI pin above.

This transaction currently covers the legacy writers only. The Observatory exporter does not yet use it: do not point an ephemeral runner-local ledger at new observation issuance, bypass the serialized protocol, or treat a filesystem path as completed shared-ledger integration. Legacy v1 signatures bind the qScan logical content hash and readiness value. Stored byte checksums detect corruption but do not establish signed exact manifest/evidence bindings or prove the currently deployed runtime.

### Remaining acceptance gates

- Establish authoritative current key status. The documented revocation endpoint returned HTTP 404; a matching pin and successful KMS signing do not establish non-revocation.
- Complete the authenticated collector handoff, authorized subject policy, exact manifest binding and standard-JWS issuer integration with the same durable ledger. Recollect fresh records before issuance; the one-hour freshness requirement still applies.
- Verify real consumer trust and persistent monitor/replay state, then establish the intended alert destination and demonstrate actionable delivery and acknowledgment.
- Demonstrate independent complete consumer interoperability and obtain independent IETF-area feedback. The existing fixture and wire tests do not establish those outcomes.

No IETF submission has occurred. Production collection and legacy issuance are verified progress; authenticated observation issuance and complete consumer acceptance remain unfinished.
