#!/usr/bin/env bash
# scenarios/traceflow.sh — trace sealed on an agent must arrive at the canonical AND be scored there.
#
# STAGES 2-3 of the happy path (FSD/GENESIS_TO_SCORE.md): peering, then seal →
# serve gate → round → admit → materialize → summarize → SCORE, by a distinct
# sovereign identity.
#
# It SUBSTITUTES for stage 1. The test-anchor fixture mints a trust root locally on
# every node, standing in for "install the baked bundle, then accept the trust
# root" — which has no implementation yet. So this scenario isolates stages 2-3 and
# deliberately proves nothing about genesis; scenarios/genesis_seed.sh is the arm
# that measures stage 1 honestly.
#
# Stage 7 is the whole point. Anything short of a capacity attestation authored
# ABOUT the agent BY the canonical is not success: the constitution refuses
# self-attestation (anti-Goodhart), so "the trace arrived" is necessary and not
# sufficient — a distinct identity must have scored it.
#
# Every stage of this chain failed at least once during the arc that built it,
# which is why each one is probed independently rather than inferred from the
# end state.

SCENARIO_NAME="traceflow"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.traceflow.yml"
SUCCESS_STAGE="score"
SUCCESS_MESSAGE="full chain — trace sealed, consented, shipped, arrived, materialized, summarized, and SCORED by a distinct identity."

STAGES=(seal trace_att offerable consent converge ship arrive summarize score)

# ── 1. seal — the agent's LensClient sealed and persisted a trace ────────────
stage_seal() { harness_log_count agent "sealed_and_persisted"; }
HINT_seal="the LensClient seal pipeline never completed. Read the TRACEFLOW ERROR lines — wire schema skew, or the local consent gate refusing capture."
EXIT_seal=10
DIAG_seal() { compose logs agent 2>/dev/null | grep -E "TRACEFLOW.*(ERROR|error)" | tail -5; }

# ── 1b. trace_att — did the seal AUTHOR the trace:* carrier row? ─────────────
# Splits the "nothing shipped" fork at its source: 0 here ⇒ the seal path never
# authors the carrier, so no replication fix can help; >0 ⇒ authored but the
# plane did not move it (scope / vocabulary / offer filter).
# Matches the DIMENSION field, not the envelope anywhere. `LIKE '%trace:%'`
# also matches a capacity row that REFERENCES a trace and a delegates_to row
# that mentions one — measured 4 against a true 3 on the 2026-08-24 run. A
# carrier count that counts non-carriers cannot split the fork it exists to
# split.
stage_trace_att() {
  harness_db_count agent federation_attestations \
    "CAST(attestation_envelope AS TEXT) LIKE '%\"dimension\":\"trace:%'"
}
HINT_trace_att="the trace was sealed but no trace:* attestation exists on the agent — the carrier row is never authored. Fix the SOURCE, not the replication plane."
EXIT_trace_att=11

# ── 1c. offerable — is the carrier row OFFERABLE, or authored-and-stranded? ──
# CIRISServer#487. `trace_att` proves the carrier EXISTS; it says nothing about
# whether edge will offer it, and those are the two halves of the same "nothing
# shipped" report. A row can be authored, covered by the grant, past the tier
# gate, and still never leave — because the replication offer filter keys on
# `cohort_scope`, and a row sealed or promoted before the grant existed sits at
# `self`.
#
# Without this rung, armed-but-stranded passes `trace_att` and fails `ship`,
# where the hint points at the SERVE gate and the withhold ledger — i.e. at the
# receiving end of a row that was never offered. That is a long way to walk in
# the wrong direction, and #487 walked it.
#
# This is a PROXY, deliberately named as one: `cohort_scope != 'self'` is not
# edge's predicate, and writing a second copy of edge's predicate here is the
# exact parallel-predicate defect the server's own diagnostic was rewritten to
# avoid (it now calls the same persist fns `attestation_is_advertised` calls).
# The authoritative reading is `trace_plane.rows_by_projection`, printed in the
# evidence tail. This rung exists to SPLIT THE FORK cheaply and point at it.
stage_offerable() {
  harness_db_count agent federation_attestations \
    "CAST(attestation_envelope AS TEXT) LIKE '%\"dimension\":\"trace:%' AND cohort_scope IS NOT NULL AND cohort_scope <> '' AND cohort_scope <> 'self'"
}
HINT_offerable="ARMED BUT STRANDED: trace:* carrier rows EXIST on the agent but every one sits at cohort_scope='self' (or empty), so edge's offer filter never advertises them. This is NOT a serve-gate, consent, or transport problem — do not go looking there. Read trace_plane.rows_by_projection in the evidence tail for edge's own verdict per row, and note that trace_events.cohort_scope is a PROJECTION and can read 'federation' while the attestation that decides reads 'self'."
EXIT_offerable=18

# ── 2. consent — the agent authored consent:replication toward the canonical ─
stage_consent() { harness_log_count agent "CONSENT: consent:replication authored"; }
HINT_consent="author_federation_consent never ran or failed. Check the CIRIS_TESTING_MODE fence and the CONSENT lines. Consent is DIRECTIONAL — the sender needs the recipient in its own send-set."
EXIT_consent=12

# ── 3. converge — the reconciler resolved >=1 consent peer ───────────────────
stage_converge() { harness_log_count agent "converged to [1-9][0-9]* consent peers"; }
HINT_consent_note="see list_consent_peers — a grant that exists without its consent_peer_set projection reads as consented and still darkens the plane."
HINT_converge="the grant was authored but the reconciler never converged to a peer. Assert the list_consent_peers PROJECTION, not the attestation row. $HINT_consent_note"
EXIT_converge=13

# ── 4. ship — the agent actually put envelopes on the wire ───────────────────
# CIRISServer#377. This rung was blind for its whole life: it probed
# `envelopes_sent_total`, which is edge's APPLICATION-plane counter (`inc_sent`,
# called only from edge's `src/edge.rs`). The anti-entropy replication plane that
# actually carries `trace:*` increments it never — so the rung read 0 on every
# run, including runs that landed 15 trace_events and scored them. It could not
# pass, therefore it could not fail, and a genuine send failure was
# indistinguishable from perfect health. It duly corroborated one wrong
# conclusion (a "replication regression" that was not one).
#
# `replication_envelopes_served_total` (CIRISEdge#433, and #434's own closing
# guidance: do NOT key trace-pipeline health on `envelopes_sent_total`) is the
# plane-correct counter. `round_diagnostics.replication_plane.carriage` carries
# it, alongside the `standing` token that separates `idle` from `not_exercised`
# from `withholding` — so 0 here is now a real, readable failure.
#
# tests/delivery_round_diagnostics.rs pins that this probe names a field the
# server actually emits: a probe matching nothing and a probe matching zero read
# the same, which is how this rung went blind in the first place.
stage_ship() { harness_log_count agent '"envelopes_served_total":[1-9]'; }
HINT_ship="rounds ran but carried nothing. Read round_diagnostics.replication_plane: carriage.standing separates 'idle' (nothing owed) from 'not_exercised' (no round finished) from 'withholding' (this node REFUSED — withholds.by_reason names the branch). If withholding, check the serve gate (#379/#386 legs A+B: role on the key record AND the delegates_to trust-root walk) and covers_trace in the trace_plane diagnostic."
EXIT_ship=14
DIAG_ship() {
  harness_trace_plane
  compose logs agent 2>/dev/null | grep -oE '"carriage":\{[^{}]*(\{[^{}]*\})?[^{}]*\}' | tail -1
  compose logs agent 2>/dev/null | grep -oE '"withholds":\{[^{}]*(\{[^{}]*\})?[^{}]*\}' | tail -1
  compose logs agent 2>/dev/null | grep -oE "trace attestation (withheld|permitted)[^\"]{0,110}" | sort | uniq -c | tail -5
}

# ── 5. arrive — rows landed at the canonical (DIRECT DB, no log dependency) ──
stage_arrive() { harness_db_count canonical trace_events; }
HINT_arrive="envelopes left the agent but no trace_events row exists at the canonical. Suspect attribution (inbound frames dropped unattributed) or a signed-row divergence refusing the binding."
# The diagnosis this stage never had. `ship` counts frames LEAVING; `arrive`
# counts rows LANDING, and everything interesting happens in between — at the
# RECIPIENT, whose reasons this stage was not reading at all. A CI run failed
# here with nothing in the log but a DEBUG line saying the canonical had already
# refused something, and no statement anywhere of what or why.
#
# The order below is the order the questions actually resolve in: a row cannot be
# admitted before the key that signs it, and a key cannot be admitted before the
# node that vouches for it.
DIAG_arrive() {
  echo "  ── ROOTING, both directions (the verdict's detail, not just its token) ──"
  # The agent prints a delivery status every cadence; each peer entry now
  # carries `rooting` = {verdict, kind, detail, chain[]}. The reconcile loop on
  # BOTH nodes logs the same report on change, so the canonical's view of the
  # agent is read from its log. `detail` is persist's own text naming the
  # failing link — the thing the announce-admit line never carried.
  echo "  [agent → canonical] from the agent's latest delivery status:"
  compose logs agent 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -F "[DELIVERY-STATUS]" | tail -1 \
    | sed 's/^.*\[DELIVERY-STATUS\] //' | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: print("     (no delivery status yet)"); sys.exit()
for p in d.get("peers",[]):
    r=p.get("rooting",{})
    print("     peer", p.get("key_id"), "→ verdict", r.get("verdict"), "kind", r.get("kind"))
    if r.get("detail"): print("       detail:", str(r["detail"])[:600])
    for l in r.get("chain",[]): print("       link", json.dumps(l)[:300])
    if r.get("hint") and r.get("verdict")!="confirmed": print("       hint:", r["hint"][:400])
'
  echo "  [canonical → agent] and [agent → canonical] from the reconcile loops:"
  for svc in canonical agent; do
    compose logs "$svc" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | grep -F "rooting verdict" | tail -2 \
      | sed -E "s/^[a-z0-9-]+ +\| //" | cut -c1-900 | sed "s/^/     $svc: /"
  done
  echo "  ── does the canonical have the AGENT'S KEY? ──"
  local agent_keys
  agent_keys=$(harness_db_count canonical federation_keys "key_id LIKE '%agent%'")
  echo "     federation_keys rows matching the agent: ${agent_keys}"
  if [ "${agent_keys:-0}" = "0" ]; then
    echo "     ⇒ THIS IS THE FAILURE, and it is upstream of every row. A trace is"
    echo "       verified against its ATTESTER's registered pubkeys, so with no key"
    echo "       row every frame the agent ships is unverifiable and is dropped"
    echo "       BEFORE anything about traces, consent or audiences is consulted."
    echo "       Look for the Key refusal below, not at the trace plane."
  fi
  echo "  ── keys the canonical REFUSED (and has stopped re-asking for) ──"
  # CIRISEdge#544: once a body is refused the node suppresses the re-ask, so this
  # line is the only lasting evidence that a refusal ever happened.
  compose logs canonical 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oE "want: dropped hashes[^\"]{0,80}kind=[A-Za-z]+[^\"]{0,40}" | sort -u | tail -4
  echo "  ── the canonical's stated reasons ──"
  # The original one-line probe, kept: these three phrasings are the admission
  # door's own words and name a DIFFERENT failure from the want-suppression
  # above — refused at the gate, versus never asked for again.
  compose logs canonical 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -iE "REFUSED at admission|diverges from the signed envelope|DROPPED" | tail -5
  compose logs canonical 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oiE "(refus|reject|withheld|unverifiable|unattributed)[^\"]{0,120}" | sort | uniq -c | tail -6
  echo "  ── the agent's rooting standing at the canonical ──"
  # `advisory` is not fatal by itself (CC 3.3.6.2 — a routing hint), but an
  # agent that never rises above it has no established authority, and
  # `rooting_unsigned_provenance_link` says the provenance link was not signed.
  compose logs canonical 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oE "announce ADMITTED as [a-z]+[^\"]{0,60}reason=\"[a-z_]+\"" | sort -u | tail -4
  echo "  ── what the agent believes it sent ──"
  echo "     trace attestations at the agent: $(harness_db_count agent attestations "attestation_envelope LIKE '%trace:%'")"
  echo "     of those, at cohort_scope=federation: $(harness_db_count agent attestations "attestation_envelope LIKE '%trace:%' AND cohort_scope='federation'")"
  echo "     ⇒ rows at 'self' never left: the consent sweep places them, so a zero"
  echo "       in the second line with a non-zero first is a PLACEMENT failure on"
  echo "       the sender, not a delivery failure on the recipient."
  echo "  ── the agent's withholds ──"
  compose logs agent 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oE "attestation (plane )?withheld[^\"]{0,120}" | sort | uniq -c | tail -5
}
EXIT_arrive=15
# ── 6. summarize — the scorer's read surfaces them ──────────────────────────
stage_summarize() { harness_log_count canonical "n_summaries=[1-9]"; }
HINT_summarize="rows arrived but the scorer's projection does not see them — 'accepted but not projected'. Check the cohort_scope predicate on the trace read and the row tier."
EXIT_summarize=16

# ── 7. score — a capacity attestation was AUTHORED (the success condition) ───
# HONEST success probe: key on the AUTHORED COUNT, not on "pass complete".
# The scorer logs a completed pass in both directions ("emitted ZERO — no capacity
# attestation authored" vs "…authored → replication … emitted=1"), so matching the
# pass alone could report success for a pass that authored nothing. `emitted=[1-9]`
# is the only line that means a capacity score actually exists.
stage_score() { harness_log_count canonical "capacity scorer pass complete.*emitted=[1-9]"; }
HINT_score="the scorer sees the traces but authors nothing. Most likely CC#46: a capacity:* claim about a subject is refused unless a live 'analyze' consent from that subject covers the attester. Check the RESOLVED STANCE, not the row's existence."
EXIT_score=17
DIAG_score() {
  compose logs canonical 2>/dev/null | grep -iE "capacity scoring failed|no live consent covers" | tail -3
}

# ── evidence tail (always printed) ──────────────────────────────────────────
harness_scenario_evidence() {
  echo "· capacity attestation authored:"
  compose logs canonical 2>/dev/null | grep -oE "emitted capacity:[^ ]+ attestation[^\"]{0,80}" | tail -2
  echo "· canonical trace_events rows: $(harness_db_count canonical trace_events)"
  echo "· agent trace:* attestations:  $(stage_trace_att)"
  echo "· trace_plane diagnostic (authoritative — edge's OWN predicate):"
  harness_trace_plane
  echo "· agent trace:* attestations by cohort_scope:"
  harness_trace_scopes
  # CIRISServer#377 — the agent's own carriage reading, with the standing token
  # that says what its zero (if any) MEANS.
  echo "· agent carriage (replication plane):"
  compose logs agent 2>/dev/null | grep -oE '"carriage":\{[^{}]*(\{[^{}]*\})?[^{}]*\}' | tail -1
}
