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

STAGES=(seal trace_att consent converge ship arrive summarize score)

# ── 1. seal — the agent's LensClient sealed and persisted a trace ────────────
stage_seal() { harness_log_count agent "sealed_and_persisted"; }
HINT_seal="the LensClient seal pipeline never completed. Read the TRACEFLOW ERROR lines — wire schema skew, or the local consent gate refusing capture."
EXIT_seal=10
DIAG_seal() { compose logs agent 2>/dev/null | grep -E "TRACEFLOW.*(ERROR|error)" | tail -5; }

# ── 1b. trace_att — did the seal AUTHOR the trace:* carrier row? ─────────────
# Splits the "nothing shipped" fork at its source: 0 here ⇒ the seal path never
# authors the carrier, so no replication fix can help; >0 ⇒ authored but the
# plane did not move it (scope / vocabulary / offer filter).
stage_trace_att() {
  harness_db_count agent federation_attestations \
    "CAST(attestation_envelope AS TEXT) LIKE '%trace:%'"
}
HINT_trace_att="the trace was sealed but no trace:* attestation exists on the agent — the carrier row is never authored. Fix the SOURCE, not the replication plane."
EXIT_trace_att=11

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
  compose logs agent 2>/dev/null | grep -oE '"trace_plane":\{[^}]*\}' | tail -1
  compose logs agent 2>/dev/null | grep -oE '"carriage":\{[^{}]*(\{[^{}]*\})?[^{}]*\}' | tail -1
  compose logs agent 2>/dev/null | grep -oE '"withholds":\{[^{}]*(\{[^{}]*\})?[^{}]*\}' | tail -1
  compose logs agent 2>/dev/null | grep -oE "trace attestation (withheld|permitted)[^\"]{0,110}" | sort | uniq -c | tail -5
}

# ── 5. arrive — rows landed at the canonical (DIRECT DB, no log dependency) ──
stage_arrive() { harness_db_count canonical trace_events; }
HINT_arrive="envelopes left the agent but no trace_events row exists at the canonical. Suspect attribution (inbound frames dropped unattributed) or a signed-row divergence refusing the binding."
EXIT_arrive=15
DIAG_arrive() {
  compose logs canonical 2>/dev/null | grep -iE "REFUSED at admission|diverges from the signed envelope|DROPPED" | tail -5
}

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
  echo "· trace_plane diagnostic:"
  compose logs agent 2>/dev/null | grep -oE '"trace_plane":\{[^}]*\}' | tail -1
  # CIRISServer#377 — the agent's own carriage reading, with the standing token
  # that says what its zero (if any) MEANS.
  echo "· agent carriage (replication plane):"
  compose logs agent 2>/dev/null | grep -oE '"carriage":\{[^{}]*(\{[^{}]*\})?[^{}]*\}' | tail -1
}
