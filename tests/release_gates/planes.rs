//! **The plane rungs** — the things a 0.5 node does, and the properties it must
//! not lose doing them.
//!
//! Most of these are anchored rungs: the invariant is already proven somewhere in
//! this repo, and re-proving it here would fork the proof. Where a direct check
//! is cheap AND answers a different question than the anchored proof does, it
//! sits alongside — never instead.

use ciris_persist::federation::consent::consent_dimension;
use ciris_verify_core::fedcode::derive_key_id;

use crate::ladder::{
    assert_proven, repo, BOTH_CONSENTS, ERASURE_NOISE_FLOOR, IDENTITY_DERIVED, KEX,
    REPLICATION_BY_CONSENT, SIGNED_ROW_INTEGRITY, TRACE_FLOW_INGEST, TRACE_FLOW_REPLICATION,
    TRACE_PLANE_LIVENESS,
};

/// Traces arrive over HTTP ingest, and a batch that should not arrive does not.
///
/// **Scope note, deliberately narrow.** This rung covers the HTTP ingest path
/// only. Trace delivery over an anti-entropy replication round is a SEPARATE
/// rung — [`gate_trace_flow_over_replication`], directly below. The two were
/// split while replication was red and they stay split now that it is green:
/// folding them would let either half vouch for the other, which is how "traces
/// flow" became a claim nobody could locate.
#[test]
fn gate_trace_flow_over_http_ingest() {
    assert_proven(&TRACE_FLOW_INGEST);
}

/// **A sealed trace crosses a real anti-entropy round** — the rung this cut is
/// for, live since persist v30.1.0 / edge v15.18.3.
///
/// The direct half reads `tests/trace_round_e2e.rs` and answers one question the
/// anchored half cannot: does the round test still ASSERT that the trace
/// arrived? That file spent the whole trace arc ending in a named soft frontier
/// (`if traces.is_empty() { eprintln!("FRONTIER: …") }`) — present, armed,
/// passing, and asserting nothing about the one outcome it exists to prove. An
/// anchored rung cannot see that difference: the test is there and it is armed
/// either way. So the arrival assertion is checked as a source fact here, and
/// the proof's execution is CI's job (`--features test-anchor`, without which
/// the file compiles to zero tests).
#[test]
fn gate_trace_flow_over_replication() {
    assert!(
        replication_round_asserts_arrival(),
        "\n\
         🚫 RELEASE GATE [trace-flow-replication] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: `tests/trace_round_e2e.rs` no longer asserts that the agent's\n\
         `trace:*` reached the canonical. Peer-to-peer trace delivery is the claim this\n\
         node's whole reason for existing rests on, and this is the only instrument that\n\
         drives a real two-node round end to end. Without the assertion the test still\n\
         runs, still passes, and covers everything EXCEPT arrival.\n\
         \n\
         If you are here because the round went red and softening it looked like the way\n\
         through: it is not. Diagnose it, and start at the SENDER.\n\
         \n\
         \x20 1. The sender's ledger first — edge's `withholds_by_reason` (surfaced on\n\
         \x20    our operator surface under `carriage`). A serve-gate WITHHOLD and a\n\
         \x20    Deliver-pack DROP are indistinguishable from the receiver: in both cases\n\
         \x20    the row is advertised and then simply never arrives, with no refusal\n\
         \x20    anywhere. Reading the receiver first is what made the original hunt cost\n\
         \x20    two days.\n\
         \x20 2. Then the pack accounting on the sending side (`wanted=N packed=N-1\n\
         \x20    dropped=1`): a ref advertised from a hash the wire index cannot serve\n\
         \x20    packs short and says so THERE, and nowhere else.\n\
         \x20 3. Only then the receiver's apply path, which has been loud since\n\
         \x20    CIRISEdge#423 — if it never names the row, the row never got there.\n\
         \n\
         Prior art, both CLOSED — named so a recurrence is recognised, not re-derived:\n\
         \x20 * CIRISEdge#455 — the serve gate withheld at per-peer advertise when\n\
         \x20   `infra:serve` was claimed but not accord-conferred.\n\
         \x20 * CIRISPersist#610 (closed in v30.1.0) — `set_attestation_cohort_scope`\n\
         \x20   updated the row without upserting `signed_wire_index`, so a promoted\n\
         \x20   trace advertised a hash the index could not serve: `wanted=6 packed=5\n\
         \x20   dropped=1`, and the one dropped ref was the trace.\n"
    );
    assert_proven(&TRACE_FLOW_REPLICATION);
}

/// Does the two-node replication round ASSERT that a trace arrived?
///
/// Both halves matter. The frontier form must be GONE, and the arrival assertion
/// must be PRESENT — checking only the first would pass a file that had deleted
/// the check outright, which is the same hole one step further along.
fn replication_round_asserts_arrival() -> bool {
    let Ok(src) = std::fs::read_to_string(repo().join("tests/trace_round_e2e.rs")) else {
        return false;
    };
    !src.contains("if traces.is_empty() {") && src.contains("!traces.is_empty(),")
}

/// If the trace plane stops, something says so — and the readings that must stay
/// apart (dark / unknown / stuck_producer / no-signers) stay apart.
#[test]
fn gate_trace_plane_liveness_alarms() {
    assert_proven(&TRACE_PLANE_LIVENESS);
}

/// Federation session KEX is hybrid and fails closed; occurrence KEX seals.
#[test]
fn gate_kex_hybrid_and_occurrence() {
    assert_proven(&KEX);
}

/// **Two consents, two dimensions.** Replication consent lets a peer HOLD our
/// traces; CC#46 `analyze` consent lets it SCORE them. They are different
/// dimensions on different edges and authoring one does not imply the other.
///
/// The direct half below is one line and answers a question the anchored proofs
/// do not: are the two dimension namespaces still DISJOINT? If a substrate rename
/// ever made `consent:state:granted` a prefix of the replication dimension (or
/// the reverse), a prefix-matched read of one would start matching rows of the
/// other — and every scoring authority decision would silently widen to the 240
/// peers who consented only to send.
#[test]
fn gate_both_consents_are_distinct_dimensions() {
    const REPLICATION: &str = "consent:replication";
    let analyze = consent_dimension::STATE_GRANTED_PREFIX;
    assert!(
        !analyze.starts_with(REPLICATION) && !REPLICATION.starts_with(analyze),
        "\n\
         🚫 RELEASE GATE [both-consents] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the analyze-consent dimension ({analyze:?}) and the replication\n\
         dimension ({REPLICATION:?}) are no longer disjoint namespaces. Consent reads are\n\
         prefix-matched, so one now matches rows of the other — and a peer that consented\n\
         only to HOLD our traces reads as having consented to SCORE them. Measured on the\n\
         production canonical 2026-08-01, that is 240 peers who never agreed to it.\n"
    );
    assert_proven(&BOTH_CONSENTS);
}

/// No unsigned rewrite of envelope-covered columns; the revocation bound is
/// enforced at every standing read; equivocation is recorded, including our own.
#[test]
fn gate_signed_row_integrity() {
    assert_proven(&SIGNED_ROW_INTEGRITY);
}

/// **Replication is by consent state, never by copy.**
///
/// The direct half is a source ratchet. An outbox — a durable send queue holding
/// a second copy of a row — is the anti-pattern this replication model exists to
/// delete: once a row sits in a queue, revoking consent no longer stops it
/// leaving, because the decision was made at enqueue time and the queue does not
/// re-ask. The ratchet is narrow on purpose: it forbids the SHAPE (a
/// `send_durable`/outbox emit path of our own), not the word — persist's
/// `ceg_outbox` is the local CEG object store the node drains for its OWN
/// records, which is a different thing and is allowed by name.
#[test]
fn gate_replication_is_by_consent_not_an_outbox() {
    /// Names that would mean we grew our own durable send queue.
    const FORBIDDEN: &[&str] = &["send_durable", "replication_outbox", "outbox_enqueue"];
    /// `ceg_outbox` is verify's local self-record store, not a replication queue.
    const ALLOWED_SUBSTRING: &str = "ceg_outbox";

    let mut hits: Vec<String> = Vec::new();
    let mut stack = vec![repo().join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src must be readable") {
            let p = entry.expect("dir entry").path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().and_then(|x| x.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&p).expect("source file");
            for (n, line) in src.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if code.contains(ALLOWED_SUBSTRING) {
                    continue;
                }
                for f in FORBIDDEN {
                    if code.contains(f) {
                        hits.push(format!(
                            "  {}:{} — `{f}`",
                            p.strip_prefix(repo()).unwrap_or(&p).display(),
                            n + 1
                        ));
                    }
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "\n\
         🚫 RELEASE GATE [replication-by-consent] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: an outbox has grown back. A durable send queue is a SECOND COPY\n\
         of the truth with its own lifetime — the consent decision is made once at enqueue\n\
         and never re-asked, so revoking consent no longer stops the row leaving. Rows\n\
         must replicate because a consent state SAYS they may, evaluated at serve time.\n\
         \n\
         {}\n",
        hits.join("\n"),
    );
    assert_proven(&REPLICATION_BY_CONSENT);
}

/// **Identity is derived, never claimed** (CIRISServer#372).
///
/// The direct half checks the derivation itself has the three properties every
/// caller assumes: it is a FUNCTION of the key (same key, same id), it BINDS the
/// key (different key, different id even under the same label), and the id is not
/// the label — so no caller can name itself by choosing a string.
#[test]
fn gate_identity_is_derived_never_claimed() {
    let label = "ciris-canonical";
    let a1 = derive_key_id(label, &[1u8; 32]);
    let a2 = derive_key_id(label, &[1u8; 32]);
    let b = derive_key_id(label, &[2u8; 32]);

    assert_eq!(
        a1, a2,
        "\n\
         🚫 RELEASE GATE [identity-derived] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: `derive_key_id` is not deterministic, so the same key derives two\n\
         different federation identities. Every row this node ever signed becomes\n\
         unattributable to the key that signed it.\n"
    );
    assert_ne!(
        a1, b,
        "\n\
         🚫 RELEASE GATE [identity-derived] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: two DIFFERENT keys derive the SAME federation identity under one\n\
         label. The identity no longer binds the key material, so holding the label is\n\
         enough to speak as the identity — which is the claimed-identity failure this\n\
         invariant exists to prevent.\n"
    );
    assert_ne!(
        a1, label,
        "\n\
         🚫 RELEASE GATE [identity-derived] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the derived identity IS the caller-supplied label, so a caller\n\
         names itself. Every authority decision downstream is then about a string the\n\
         caller chose.\n"
    );
    assert_proven(&IDENTITY_DERIVED);
}

/// Provable individual-unrecoverability — the erasure claim, measured.
#[test]
fn gate_erasure_noise_floor() {
    assert_proven(&ERASURE_NOISE_FLOOR);
}
