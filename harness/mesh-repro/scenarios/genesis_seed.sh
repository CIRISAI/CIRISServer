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
# The remaining red is ONE missing input, not four missing implementations. As of
# 0.5.140 stage 1 exists (install_trust_root_records + accept_trust_root, on both
# boot paths) — but the baked bundle ships EMPTY (holders 0, attestations 0,
# authorizations 0), so stage 1 runs and installs nothing. Every stage below is
# downstream of that one fact. Bake a minted bundle and they resolve together;
# that is the thesis this arm exists to test, and it must be measured, not assumed.
#
# Deltas under test (see CIRISPersist#548):
#   Δ4  edge_exists      RESOLVED in 0.5.140 — accept_trust_root writes the node's own
#                        trust:accepts at boot. Retained: it is the un-trust lever and
#                        must keep existing AND stay deletable. Red only while the
#                        bundle it accepts is empty.
#   Δ3  root_self_declares / charter_recovery   the bundle now HAS a distribution path
#                                               (persist v23 bakes a GenesisBundle); it
#                                               is simply not yet filled
#   (Δ2 RESOLVED in persist v23: liveness left `trust_root_valid` entirely and became a
#    banded `drill_freshness` reported beside the verdict, so a seed no longer expires.
#    The heartbeat stage below is retained as an OBSERVABILITY check, not a gate.)
#   Δ1  RESOLVED in persist v24.0.0 (CIRISPersist#556, our issue): Attestation gained
#                        `additional_scrubs`, and our cosign step now populates it, so the
#                        2-of-3 that authorized the bundle SURVIVES into the graph instead
#                        of collapsing to whichever holder signed first.
#   Δ0  RESOLVED in persist v24.0.0 (CIRISPersist#557, our issue): the root is a THRESHOLD,
#                        not a seat. The charter attests the keyless FAMILY
#                        (`A1 -> humanity-accord`) and counts only once its verified scrub
#                        set reaches the family threshold; the grant stays `A1 -> canonical`
#                        and the family is DERIVED from the verified signer set, never named
#                        (attribution-by-signature — a keyless attester field would be
#                        attribution-by-claim). A1 alone roots to A1; A1+B1 roots to the family.
#
# WATCH THE SILENT-SUCCESS ARM. persist keeps solo 1-of-1 roots valid on purpose, so a
# mis-shaped family charter — or an unseeded family row — does NOT error: it yields a
# WORKING single-key root pointing at A1. `family_row` and `family_quorum` below exist
# because a green trace plane is NOT evidence the family arm engaged.

SCENARIO_NAME="genesis_seed"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.traceflow.yml -f docker-compose.genesis.yml"
VERDICT_MODE="audit"
SUCCESS_STAGE="leg_b"
SUCCESS_MESSAGE="a node holding only the baked seed resolves leg B and serves traces — the portable trust root is operable."

STAGES=(seed_admitted family_row leg_a_role edge_exists root_self_declares charter_recovery family_quorum accord_heartbeat leg_b)

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
HINT_edge_exists="Δ4 — the agent has NOT authored delegates_to(self → root). As of 0.5.140 accept_trust_root writes this at boot on every node, so the remaining cause is upstream: it accepts the BAKED bundle's charter root, and an empty bundle names none. install_trust_root_records still deliberately refuses to write it — accepting a root is the node's own signed act, never something a bundle may assign. This row is also the operator's un-trust lever, so it must exist AND stay deletable; it cannot be replaced by a universal rule."
EXIT_edge_exists=22

# ── 4/5. Δ3 — the charter and its recovery commitment ───────────────────────
# NOT a self-loop match. A family charter is `A1 -> humanity-accord`, so keying
# on `attesting_key_id = attested_key_id` silently stops finding the charter the
# moment the root becomes a threshold — and "no charter" reads as an unminted
# mesh rather than a mis-shaped one. Match the charter's stable ID instead.
stage_root_self_declares() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'delegates_to' AND attestation_id = 'genesis-charter'"
}
HINT_root_self_declares="Δ3 — no self-referential charter for the root reached this node. The ceremony mints one, but the baked seed is bundle-SHAPED as of persist v23 but ships EMPTY (holders 0, attestations 0, authorizations 0) — the container exists, the ceremony has not yet filled it."
EXIT_root_self_declares=23

stage_charter_recovery() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'delegates_to' AND attestation_id = 'genesis-charter' \
     AND CAST(attestation_envelope AS TEXT) LIKE '%pre_rotation%'"
}
HINT_charter_recovery="Δ3 — the charter (if any) carries no pre-rotation commitment, so charter_has_recovery is false. persist refuses a charter without one, which means a charter that arrives WITHOUT it is unrecoverable by construction."
EXIT_charter_recovery=24

# ── 6. Δ2 — the liveness witness, and whether it has aged out ───────────────
stage_accord_heartbeat() {
  harness_db_count agent federation_attestations \
    "attestation_type = 'scores' AND CAST(attestation_envelope AS TEXT) LIKE '%accord:lifecycle%'"
}
HINT_accord_heartbeat="Δ3 — no accord heartbeat about the trust root reached this node. NOT a validity failure: persist v23 reports liveness as a banded drill_freshness beside the verdict rather than gating on it. Consumers will show this root's drill band as unknown until a heartbeat arrives (CIRISServer#332)."
EXIT_accord_heartbeat=25

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

# ── the family row (persist #386 seed_accord_family) ────────────────────────
# Nothing in CIRISServer called seed_accord_family until 0.5.141. Without this
# row lookup_family returns None, resolve_family_root yields None, and
# trust_root_valid reports RootKind::Key — the family arm never engages and the
# mesh silently roots to one seat.
stage_family_row() {
  compose exec -T agent python -c 'import glob,sqlite3
n=0
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        for r in sqlite3.connect(d).execute("SELECT COUNT(*) FROM federation_families WHERE family_key_id LIKE %s" % "'"'"'humanity-accord'"'"'"):
            n += r[0]
    except Exception: pass
print(n)' 2>/dev/null | tail -1
}
HINT_family_row="the HUMANITY_ACCORD family row is absent — seed_accord_family never ran, so lookup_family('humanity-accord') returns None and trust_root_valid can only ever report RootKind::Key. A family-chartered bundle would degrade SILENTLY to a single-seat root here (persist keeps 1-of-1 valid on purpose)."
EXIT_family_row=27

# ── the charter's quorum: does 2-of-3 survive into the graph? ───────────────
# Δ1/#556. The charter counts as a family charter only when its verified scrub
# set reaches the threshold. One scrub = a valid root pointing at A1, which is
# indistinguishable from success unless you count.
stage_family_quorum() {
  compose exec -T agent python -c 'import glob,sqlite3,json
n=0
for d in glob.glob("/var/lib/ciris/**/*.db*", recursive=True):
    if d.endswith(("-wal","-shm")): continue
    try:
        for r in sqlite3.connect(d).execute("SELECT additional_scrubs FROM federation_attestations WHERE attestation_type=%s" % "'"'"'delegates_to'"'"'"):
            try:
                if r[0] and len(json.loads(r[0])) >= 1: n += 1
            except Exception: pass
    except Exception: pass
print(n)' 2>/dev/null | tail -1
}
HINT_family_quorum="no delegates_to row carries additional_scrubs — the 2-of-3 that authorized the bundle did NOT survive into the graph, so the charter is 1-of-1 in the directory and the grant roots to a single seat. Pre-v24 this was structurally impossible (CIRISPersist#556); if it is still 0 on v24 the COSIGN step did not co-scrub."
EXIT_family_quorum=28
