# Authenticated evidence deployment

The existing Observatory runs beside quantakrypto.com on a daily systemd timer.
Read-only inspection on 2026-10-11 identified `observatory.service` and the enabled `observatory.timer` on the existing website host `dl-latest`. The service runs as root through `/root/pqc-observatory/run.sh`, which pulls `main`, loads the existing website environment and invokes the collector. Its installed commit was `d02ed4d996771333b9174fc329b8c20bd4bcc23c`, using Node 22.22.1 and OpenSSL 3.5.5. Recheck these coordinates before changing deployment; do not create a second worker or scheduler. The website reads the Observatory's
Postgres tables; that read path does not export authenticated measurements.

## 1. Inspect the existing installation

In an already authorized SSH session, these commands are read-only:

```sh
systemctl list-unit-files --no-pager | rg -i observatory
systemctl list-timers --all --no-pager | rg -i observatory
systemctl show "$OBS_SERVICE" \
  --property=User --property=Group --property=WorkingDirectory \
  --property=FragmentPath --property=EnvironmentFiles
```

Set `OBS_SERVICE` to the discovered service, not a guessed name. Inspect its working
directory and runtime without printing environment values or credentials:

```sh
cd "$OBS_WORKER_DIR"
git rev-parse HEAD
node --version
"${OPENSSL_BINARY:-openssl}" version
"${OPENSSL_BINARY:-openssl}" list -tls1_3 -tls-groups
```

`OBS_WORKER_DIR` is the discovered directory. Node 24.6.0 or newer is required when the authority
runs in the same process; OpenSSL 3.5+ must advertise X25519MLKEM768 for hybrid probes.
Validate the exact committed worker and authority revisions before installing them:
`npm ci`, `npm run typecheck` and `REQUIRE_HYBRID_TLS=1 npm test` in the worker, and `npm ci` plus `npm test`
in the authority. Preserve the existing scheduler and database configuration.

A small operator-approved panel can exercise the collector without persistence:

```sh
npm run observatory -- run --dry-run --no-request \
  --panel "$CANARY_PANEL" --optout "$CANARY_OPTOUT"
```

This performs real TLS handshakes. It writes neither Postgres nor evidence files and
never calls KMS. A successful dry run does not demonstrate signing or deployment.

## 2. Reuse the existing signing context

The website's Actions signing steps reference `QK_KMS_REGION`,
`QK_ONLINE_KEY_ARN`, `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. Their presence
on the VM is not established. Keep credentials in their existing approved context;
do not copy Actions secrets to the collector or provision another signing key.

The existing online public key is `qk-online-2026-08`, ML-DSA-65. Its SHA-256 over
SPKI DER is:

```text
33698c1c345d1df7a5308c513ee5c3925bc7f31c12aeb883549430a6d8f7cc80
```

This corrected pin is SHA-256 of the 1974-byte SPKI DER, independently reproduced from the public `/.well-known/attestation-keys.json` committed
in quantakrypto/website at `26be7d4b09873609f4b3e1ac8739932149ec003a`.
The historical bundle and live bundle matched on 2026-10-11. The previous runbook fingerprint was incorrect; this correction does not rotate the key. The online certificate states 2026-08-07 through 2027-08-07. Before use, verify its
root signature, validity and revocation using the independently trusted root;
compare the KMS public key against the approved online pin. A repository copy or a
fresh download alone must not silently establish a new trust anchor. Deliberate
key rotation requires an independently reviewed pin update.

Existing website workflows issue the legacy posture format. They are not an
Observatory JWS deployment path, and a best-effort signing step succeeding or
being skipped does not satisfy the evidence acceptance gate.

Run the authority canary inside that existing signing context, using Node 24.6.0 or newer:

```sh
QK_KMS_PROVIDER=aws node "$OBS_AUTHORITY_DIR/bin/check-key.mjs" \
  --online-key "$QK_ONLINE_KEY_ARN" \
  --key-id qk-online-2026-08 \
  --expected-spki-sha256 sha256:33698c1c345d1df7a5308c513ee5c3925bc7f31c12aeb883549430a6d8f7cc80
```

The canary reads the existing public key, requires the supplied pin before signing,
then verifies a real KMS signature locally. It creates no key, attestation token or
ledger entry and emits only public metadata. It still makes a real signing request;
it is not an offline test. Preserve its successful result as deployment evidence.
A missing identity, pin mismatch or signing failure blocks production acceptance.

## 3. Collect on the existing worker, sign in the authorized context

Configure `OBS_COLLECT_OUTPUT` as a private directory owned by the existing worker
and enable it for the existing scheduled `npm run observatory -- run` invocation.
That normal run continues writing Postgres and additionally retains fresh validated
measurement records. Do not launch a duplicate scheduler. Leave `OBS_SIGNED_OUTPUT`
unset on the VM unless its existing identity is explicitly authorized for signing.

Transfer only the fresh record files through the existing authenticated deployment
transport. Authenticate the collector host and source directory; an unsigned file
and its self-computed digest do not establish collector identity. Do not accept
arbitrary uploaded artifacts as collector records. Complete transfer and issuance
within one hour of measurement; stale records must be measured again.

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

The current credentials stay in the signing environment. A workflow can map the
non-secret key reference without exposing its credential values:

```sh
export QK_ONLINE_KEY_REF="$QK_ONLINE_KEY_ARN"
export QK_ONLINE_KEY_ID=qk-online-2026-08
cd "$OBS_WORKER_DIR"
npm run observatory -- export --input-dir "$COLLECTED_RECORDS_DIR"
```

This command signs and writes evidence: it is not a dry run. Supply a durable ledger
with safe serialization and recovery; an ephemeral runner ledger must not reset or
race the shared authority history. There is no automatic shared-ledger transport
in this command. Reconcile successful issuance if a subsequent file transfer fails
instead of blindly retrying and claiming that nothing was signed.

Each output contains the token and exact transcript. Configure consumer trust from
the approved public key, issuer, subject, audience and purpose. The signature proves
an authorized issuer statement; it does not independently prove collector honesty
or endpoint behavior. Snapshot-bound monitoring requires a matching independently
supplied manifest digest. Successful standalone ingestion does not substitute for
that binding.

## Acceptance and remaining operational gate

Require a real KMS key-pin/signature canary, one fresh collector record signed by the
existing identity, successful consumer verification with the real public key, and
negative checks for modified transcript, wrong subject, replay and expiry. Confirm
the existing timer remains the only scheduler and that failures retain the previous
baseline and produce actionable monitoring output.

Production deployment is not demonstrated by local tests. Read-only inspection found no AWS/KMS configuration names in the environment loaded by the worker; the existing website Actions configuration retains the signing credentials. The website legacy deployment and manual attestation workflows fetch and overwrite the published ledger, and do not yet establish one serialized durable writer shared with observation issuance. Do not deploy signed exports against independent runner-local ledgers. The collector service has not been switched to this revision, and authenticated signed production evidence, consumer monitoring and actionable delivery remain separate acceptance gates.

The existing-key canary subsequently passed in [website Actions run 38162473186](https://github.com/quantakrypto/website/actions/runs/38162473186), using website commit `36f64b7705d3f152f3780093f96a8fe4da7f0e37`. Its isolated job verified the corrected historical SPKI pin and a real KMS RAW signature; legacy issuance was skipped. It created no attestation, observation token or ledger entry. This demonstrates current signing access and key continuity only. The documented revocation endpoint still returned HTTP 404, so current key-status evidence remains an acceptance blocker.
