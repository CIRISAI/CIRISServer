#!/usr/bin/env bash
# scenarios/genesis_seed.sh — can a node with ONLY the baked seed serve traces?
#
# ARM B of the genesis A/B. Arm A (`traceflow`) proves the CARRIER: seal → ship →
# score. It proves nothing about GENESIS, because the test-anchor fixture
# (`test_bless::perform_trust_root_ceremony`) mints the charter, the lifecycle
# witness AND the node's own trust edge LOCALLY, at `cohort_scope: self`, fresh on
# every boot, on every node. That is exactly the set of things a real deployment
# cannot do — so arm A silently simulates a world where every delta below is
# already solved.
#
# This arm removes the fixture. The agent sets `CIRIS_TEST_NO_CEREMONY=true`
# (docker-compose.genesis.yml), so `test_anchor_root_or_skip` returns None and NO
# ceremony runs. The agent then has only what production gives it: the baked
# canonical key record.
#
# It does NOT drop `CIRIS_TEST_TRUST_ROOT_SEED` to achieve that, though the
# unblessed overlay exists and looks like the obvious lever. We tried it and
# verified `SEED=SET` on the agent afterwards: compose silently re-materializes
# the `!reset null`, the agent self-blesses, and arm B runs arm A while reporting
# green. docker-compose.field.yml already documented that exact trap — "the agent
# silently self-blessed and the run tested the wrong topology" — and we hit it
# anyway. A flag the code itself honours cannot be undone by merge semantics.
#
# The question this scenario asks is the only one that matters for the portable
# trust root:
#
#     Given a node holding nothing but the baked seed, does
#     capability_roots_to_trusted_root(node, canonical, "infra:serve") resolve?
#
# VERDICT_MODE=audit deliberately. These are INDEPENDENT preconditions, not a
# pipeline — reporting only the first zero is what let four distinct defects look
# like one problem for an entire arc. Every ✗ is a separate fix.
#
# Expected today: 2 passes (the seed's own co-scrub), 4 fails. When all stages go
# green the portable trust root is operable and this scenario becomes a
# regression gate. Until then, a RED here is the honest state of genesis.
#
# Deltas under test (see CIRISPersist#548):
#   Δ4  edge_exists      nothing writes delegates_to(node → root) off the minting node
#   Δ3  root_self_declares / charter_recovery   the bundle has no distribution path;
#                                               canonical_seed.json is the key record ALONE
#   Δ2  lifecycle_active accord:lifecycle is freshness-windowed (90d) — a baked row ages out
#   Δ1  quorum_survives  Attestation carries ONE scrub_key_id (no additional_scrubs), so a
#                        3-key ceremony degrades to 1-of-n once the rows land. Tested
#                        in-process, not here — see tests/genesis_quorum_pin.rs.

SCENARIO_NAME="genesis_seed"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.traceflow.yml -f docker-compose.genesis.yml"
VERDICT_MODE="audit"
SUCCESS_STAGE="leg_b"
SUCCESS_MESSAGE="a node holding only the baked seed resolves leg B and serves traces — the portable trust root is operable."

STAGES=(seed_admitted leg_a_role edge_exists root_self_declares charter_recovery lifecycle_active leg_b)

# Probes run on the AGENT: it is the asker. `capability_roots_to_trusted_root` is
# evaluated in the SENDER's directory, so what the canonical holds is irrelevant
# here — a fact this project relearned the hard way.
# ROOT-AGNOSTIC probes. An earlier version keyed these on the canonical's key_id,
# which produced false negatives: in the delegation plane the ROOT is a separate
# key (a seated accord holder), not the subject. Ask the structural question
# instead — "does a charter exist at all", "has this node authored a trust edge to
# anything" — so the scenario stays correct whichever plane the seed uses.
CANON_LIKE="key_id LIKE 'ciris-canonical%'"
SELF_LIKE="attesting_key_id LIKE 'ciris-agent%'"

# ── 1. the seed is admitted at all ──────────────────────────────────────────
stage_seed_admitted() { harness_db_count agent federation_keys "$CANON_LIKE"; }
HINT_seed_admitted="the baked canonical key record is not in the agent's directory — genesis did not seed. Nothing below can hold."
EXIT_seed_admitted=20

# ── 2. leg A: the accord's conferral, in the co-scrub encoding ──────────────
# EXPECTED TO PASS. The seed carries roles:[infra:serve] inside the signed
# registration_envelope, co-scrubbed 2-of-3 (A1 + additional_scrubs B1).
stage_leg_a_role() {
  harness_db_count agent federation_keys \
    "$CANON_LIKE AND CAST(registration_envelope AS TEXT) LIKE '%infra:serve%'"
}
HINT_leg_a_role="the seed does not carry roles:[infra:serve] in its signed registration_envelope — leg A cannot pass, and the co-scrub conferral plane (persist v22.1.0) has nothing to read."
EXIT_leg_a_role=21

# ── 3. Δ4 — the node's OWN trust edge, and the operator's un-trust lever ────
stage_edge_exists() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'delegates_to' AND $SELF_LIKE AND attested_key_id <> attesting_key_id"
}
HINT_edge_exists="Δ4 — the agent has NOT authored delegates_to(self → root). Only write_node_trust_edge (accord_provision) writes this, and only on the MINTING node; attach_genesis deliberately refuses. So every node that did not mint has no trust edge and edge_exists is false. This row is also the operator's un-trust lever, so it must exist AND stay deletable — it cannot be replaced by a universal rule."
EXIT_edge_exists=22

# ── 4/5. Δ3 — the charter and its recovery commitment ───────────────────────
stage_root_self_declares() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'delegates_to' AND attesting_key_id = attested_key_id"
}
HINT_root_self_declares="Δ3 — no self-referential charter for the root reached this node. The ceremony mints one, but canonical_seed.json is the KEY RECORD ALONE and a GenesisBundle has no distribution path, so the charter never travels."
EXIT_root_self_declares=23

stage_charter_recovery() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'delegates_to' AND attesting_key_id = attested_key_id \
     AND CAST(attestation_envelope AS TEXT) LIKE '%pre_rotation%'"
}
HINT_charter_recovery="Δ3 — the charter (if any) carries no pre-rotation commitment, so charter_has_recovery is false. persist refuses a charter without one, which means a charter that arrives WITHOUT it is unrecoverable by construction."
EXIT_charter_recovery=24

# ── 6. Δ2 — the liveness witness, and whether it has aged out ───────────────
stage_lifecycle_active() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'scores' AND CAST(attestation_envelope AS TEXT) LIKE '%accord:lifecycle%'"
}
HINT_lifecycle_active="Δ2/Δ3 — no accord:lifecycle witness about the root reached this node. NOTE this stage counts the row's PRESENCE; persist additionally requires it within ACCORD_LIFECYCLE_FRESHNESS_DAYS (90). A baked witness therefore ages out and every node fails together, three months after the mint, with no error at the point of use — which is why presence alone is not sufficient and a seed carrying one has a shelf life."
EXIT_lifecycle_active=25

# ── 7. the actual question ──────────────────────────────────────────────────
stage_leg_b() { harness_log_count agent "trace attestation permitted"; }
HINT_leg_b="leg B does not resolve: capability_roots_to_trusted_root returns None, so the agent withholds every trace. This is the observable consequence of the ✗ stages above — fix those and this follows."
EXIT_leg_b=26
DIAG_leg_b() {
  compose logs agent 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' \
    | grep -oE "trace attestation withheld[^\"]{0,120}" | sort | uniq -c | tail -3
}

harness_scenario_evidence() {
  echo "· agent federation_keys:"
  compose exec -T agent python -c 'import glob,sqlite3
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        for r in sqlite3.connect(d).execute("SELECT key_id, identity_type FROM federation_keys"):
            print("   ", r)
    except Exception: pass' 2>/dev/null || true
  echo "· agent attestations (type | attester -> attested):"
  compose exec -T agent python -c 'import glob,sqlite3
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        for r in sqlite3.connect(d).execute("SELECT attestation_type, attesting_key_id, attested_key_id FROM federation_attestations"):
            print("   ", r)
    except Exception: pass' 2>/dev/null || true
}
