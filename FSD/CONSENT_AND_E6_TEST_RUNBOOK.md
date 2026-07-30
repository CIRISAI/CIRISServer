# Test runbook — explicit consent + E6 (for the agent team)

> What changed on the server (uncommitted, staged, green): consent is no longer
> auto-authored at boot. `prime_canonicals` now only ROOTS the canonical
> (reachability); the owner authors `consent:replication` explicitly via a new
> route, which the **agent wizard must call** when the user opts into sharing.
> Plus persist v21.1.0 / edge v14.0.0 adoption and the E6 rooting hardening.

## 0. Build the wheel

Same tooling as before (`BUILDING_A_LOCAL_WHEEL.md`):

```bash
maturin build --release --out dist --compatibility linux        # desktop/emulator host
tools/build-android-wheel.sh                                     # android_24 x86_64 (filmstrip)
```

`.post1`-repack the android wheel if a same-version wheel is already on PyPI (see the runbook), so `--find-links` picks the local build.

## 1. The behavior change you must wire (client)

The wizard already collects the decision — "Send traces to CIRIS L3C"
(`accordMetricsConsent`, gated on `announceOwnership`) + "Include location"
(`shareLocationInTraces`). **That decision no longer reaches the federation
layer by itself.** When the user opts in, the wizard must POST the consent, once,
**after the owner claim completes** (the route is owner-gated — pre-claim it 403s):

```
POST /v1/federation/consent            Authorization: Bearer <owner session>
{ "peer_key_id": "<canonical key_id>",
  "attestation_prefixes": ["trace:", "capacity:"] }
```

- `peer_key_id` = the canonical the node is rooted to (from
  `GET /v1/accord/canonical-servers` or `canonical_bootstrap_hints`).
- `attestation_prefixes` = the explicit scope the user consented to. Empty ⇒ 400.
- Idempotent; re-POST is a no-op. Response carries `grant_attestation_id`.

If the user does **not** opt in, the wizard calls nothing — the node reports
nothing to the canonical (correct: consent is explicit).

## 2. Server-side acceptance checks

### 2a. No auto-consent at boot (the core fix)
On a **fresh, unclaimed** node, after boot:
- `prime_canonicals` logs rooting only — grep the log for
  `"seeding from the baked canonical"` and `"rooted …"`; you must **NOT** see
  `"consent:replication grant authored at canonical peer"` (that line is gone).
- The consent peer set is **empty**: internally `list_consent_peers(node)` → `[]`.
  (No `capacity:` grant was minted for anyone.)

### 2b. Consent route contract (curl, with an owner session bearer)
```bash
# pre-claim (unowned node) → 403
curl -si -X POST $NODE/v1/federation/consent -H "Authorization: Bearer $OWNER" \
  -d '{"peer_key_id":"'"$CANON"'","attestation_prefixes":["trace:"]}' | head -1   # 403

# after claim, empty scope → 400
curl -sX POST $NODE/v1/federation/consent -H "Authorization: Bearer $OWNER" \
  -d '{"peer_key_id":"'"$CANON"'","attestation_prefixes":[]}'                      # 400

# after claim, unknown/unadmitted peer → 400
curl -sX POST $NODE/v1/federation/consent -H "Authorization: Bearer $OWNER" \
  -d '{"peer_key_id":"not-a-real-key","attestation_prefixes":["trace:"]}'         # 400

# after claim, admitted canonical + explicit scope → 200 { "consented": true, ... }
curl -sX POST $NODE/v1/federation/consent -H "Authorization: Bearer $OWNER" \
  -d '{"peer_key_id":"'"$CANON"'","attestation_prefixes":["trace:","capacity:"]}' # 200
```

### 2c. Consent → replication flows
After the 200: the reconcile loop reads the grant back (`list_consent_peers`
now includes the canonical) and converges the runtime — the canonical becomes an
active Initiator target with no restart. Confirm the reconciler nudged
(`"consent:replication recorded"` note in the response) and the peer appears in
the next reconcile tick.

## 3. The trace-pipeline filmstrip (the actual goal)

With v21.1.0 in the wheel, the corpus leg is fixed by the bump itself — persist
now materializes `trace_events` inside `put_attestation` (#501). End to end:

1. Fresh node → owner claim → wizard opt-in (§1) → consent authored.
2. Agent emits a `trace:complete:v1`; it replicates to the canonical.
3. On the canonical: `trace_events` gains the row (was 0), the scorer's corpus
   fills, `run_pass` logs `n_summaries > 0`, and `envelopes_sent > 0`.
4. → first `trace_events` row / **SHIP CONFIRMED**.

If step 3 still shows `n_summaries = 0`, the consent grant (§1) is missing or its
scope doesn't include `trace:` — check `list_consent_peers` and the grant's
`attestation_prefixes`.

## 4. E6 rooting hardening (log check)

`prime_trusted_peers` no longer roots on the stored `Rooted` flag alone — it
refuses any peer whose identity KeyRecord this node doesn't hold. In the boot log:
- `"trusted-peer boot prime complete … primed=<n> refused=<m>"` — `refused` counts
  Rooted rows for keys we don't hold (should be 0 in a healthy mesh).
- A refusal logs `"REFUSING to root an unheld/unverified key (E6)"`.
Legit peers (admitted key + Rooted) still prime exactly as before.

## 5. Regression surface (already green here)
195-file suite + `tests/federation_admin.rs` consent tests (happy / empty-scope
400 / unadmitted 400 / unowned 403) + `tests/replication_policy_gate.rs` (both
manifest hashes) all pass; clippy clean. Rebuild against the wheel and re-run the
filmstrip.
