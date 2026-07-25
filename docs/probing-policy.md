# Probing policy

The observatory measures hosts we do not own. That is legitimate, and common
(SSL Labs, Censys, and other public scanners have done it for years), but it puts
the burden on us to be restrained and transparent. This document is the policy;
the worker enforces it in code.

## What we do

For each host on the panel, once per day:

- Exactly **one** TLS handshake to port 443, driven by `openssl s_client`.
- We offer the hybrid group X25519MLKEM768 alongside the usual classical groups and
  record which the server selects, plus the negotiated TLS version and the leaf
  certificate's signature algorithm and expiry.
- We read the handshake only. **No application data is ever sent.** We do not send
  HTTP, we do not authenticate, we do not attempt anything beyond the handshake.

## Restraint (enforced in `src/run.ts` and `src/probe.ts`)

- **Sequential.** Hosts are probed one at a time, never fanned out in parallel.
- **Spaced.** A minimum interval (default 500ms) separates successive hosts.
- **Bounded.** A hard per-connection timeout (default 8s). A refusal or timeout is
  recorded as `reachable = false`; we do not retry aggressively.
- **Opt-out first.** A host listed in `optout.txt`, or marked `opted_out_at` in the
  database, is skipped before any connection, and is honored within one run.

## Opt-out

To have a host removed from the panel, open a pull request adding it to
`optout.txt`, or contact quantakrypto. Either is honored within one measurement
cycle. We publish only aggregate trends and per-host readiness state, never traffic
or content (there is none to publish; we never send a request).

## Why a separate worker

qProbe, quantakrypto's endpoint prober, is gated behind an ownership attestation
because it is meant for endpoints you control. The observatory measures hosts we do
not own, so it deliberately does not use qProbe; it is a separate, self-contained
worker with this narrower, read-only policy and its own opt-out path.
