# Probing policy

The observatory measures hosts we do not own. That is legitimate, and common
(SSL Labs, Censys, and other public scanners have done it for years), but it puts
the burden on us to be restrained and transparent. This document is the policy;
the worker enforces it in code.

## What we do

For each host on the panel, once per day:

- **Two or three** TLS handshakes to port 443, driven by `openssl s_client`.
- The first is silent. We offer the hybrid group X25519MLKEM768 alongside the usual
  classical groups and record which the server selects, plus the negotiated TLS version
  and the leaf certificate's signature algorithm and expiry. We write nothing on it, so a
  session ticket arriving here is one the server volunteered.
- If the server volunteered no ticket, a second connection sends **one `HEAD /` and
  nothing else**, because many servers withhold NewSessionTicket until a request arrives.
  Measured on 28 August 2026, over a fourteen-host panel probed twice: silent connections
  drew a ticket from 8 hosts, a single HEAD drew one from all 14. Without the request,
  six hosts including `ietf.org`, `google.com` and `www.cloudflare.com` would be recorded
  as issuing no ticket, which is false.
- The last connection offers that ticket back, to the **same address and the same SNI**,
  and records whether the server resumed. A ticket is never offered to a host that did not
  issue it: that would be probing someone else's access control with credentials minted by
  another configuration, and we have no standing to do it.
- We authenticate nothing and we send no credential. `HEAD /` reads no body and changes no
  state. `--no-request` restores strict handshake-only behaviour, in which ticket issuance
  is recorded as `null` rather than as false, because a server that was never asked cannot
  be said to have declined.

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
or content. The only request we send is `HEAD /`, whose response body we do not read,
store or publish; what we keep from it is whether a session ticket was issued.

## Why a separate worker

qProbe, quantakrypto's endpoint prober, is gated behind an ownership attestation
because it is meant for endpoints you control. The observatory measures hosts we do
not own, so it deliberately does not use qProbe; it is a separate, self-contained
worker with this narrower, read-only policy and its own opt-out path.
