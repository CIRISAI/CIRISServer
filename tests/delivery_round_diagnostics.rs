//! **CIRISServer#377 — the `ship` rung must be able to FAIL.**
//!
//! `harness/mesh-repro/scenarios/traceflow.sh` stage 5 probed
//! `"envelopes_sent_total":[1-9]` in `delivery_status().round_diagnostics`. That
//! field is edge's APPLICATION-plane counter (`inc_sent`, called only from
//! `src/edge.rs`); the anti-entropy replication plane that actually carries
//! `trace:*` rows to a canonical increments it never. So the rung read 0 on
//! every run — including runs that landed 15 `trace_events`, summarized and
//! scored them. A check that could not pass is a check that could not fail, and
//! it lived inside the instrument built to catch exactly that class. It has
//! already corroborated one wrong conclusion (a "replication regression" that
//! was not one — `ship=0` was present in the green arm too).
//!
//! Upstream root-caused and CLOSED this as CIRISEdge#434; the plane-correct
//! counter is `replication_envelopes_served_total` (CIRISEdge#433), live in the
//! adopted edge v15.20.0. This file pins that our surface reads it, that the
//! harness probes what our surface emits, and that no zero on this surface is
//! reported bare.
//!
//! Every test drives edge's REAL incrementers through `EdgeMetrics` and
//! snapshots — never a hand-built bundle — so a change to which counter edge
//! bumps is visible here rather than mocked away.

use ciris_edge::observability::{EdgeMetrics, RoundOutcome, WithholdReason};
use ciris_edge::replication::EnvelopeKind;
use ciris_server::federation_delivery::round_diagnostics_json;
use serde_json::json;

/// The exact live shape from the #377 report: 27 completed / 4 error / 1
/// timed_out rounds that carried 15 trace attestations to the canonical, while
/// the application plane genuinely sent nothing. **Both are true at once** —
/// that is the whole point, and the reason a single `envelopes_sent_total` field
/// could not describe this node.
#[test]
fn a_run_that_moved_rows_reports_positive_carriage_though_the_application_plane_is_zero() {
    let m = EdgeMetrics::new();
    for _ in 0..27 {
        m.inc_round_outcome(RoundOutcome::Completed);
    }
    for _ in 0..4 {
        m.inc_round_outcome(RoundOutcome::Error);
    }
    m.inc_round_outcome(RoundOutcome::TimedOut);
    for _ in 0..15 {
        m.inc_replication_served(EnvelopeKind::Attestation);
    }

    let snap = m.snapshot();
    let v = round_diagnostics_json(&snap, true, true, false);

    let carriage = &v["replication_plane"]["carriage"];
    assert_eq!(
        carriage["envelopes_served_total"],
        json!(15),
        "the plane that carried the rows must report having carried them; this is \
         the assertion that read 0 on a green run before #377"
    );
    assert_eq!(carriage["by_kind"]["attestation"], json!(15));
    assert_eq!(
        carriage["standing"],
        json!("moving"),
        "rows served + nothing withheld = moving, not idle and not not_exercised"
    );
    assert_eq!(
        carriage["rounds_total"],
        json!(32),
        "the denominator rides with the count — 0 served against 0 rounds is not a \
         carriage statement at all"
    );

    // The application plane is honestly zero, and says so where it cannot be
    // mistaken for carriage.
    assert_eq!(v["application_plane"]["envelopes_sent_total"], json!(0));
    assert_eq!(v["application_plane"]["envelopes_received_total"], json!(0));

    // …and the field that told the lie is GONE from the top level. A consumer
    // grepping the old path now finds nothing, which is loud, instead of finding
    // 0, which is silent and wrong.
    assert!(
        v["envelopes_sent_total"].is_null(),
        "`round_diagnostics.envelopes_sent_total` must not exist: it read as a \
         total for carriage it never observed (CIRISEdge#434). Got {}",
        v["envelopes_sent_total"]
    );
    assert!(
        v["envelopes_received_total"].is_null(),
        "same for the receive half — got {}",
        v["envelopes_received_total"]
    );
}

/// **The rung and the surface must name the same field.** This is the structural
/// half of the fix: without it the harness can silently drift back onto a field
/// the server does not emit, and a probe that matches nothing is indistinguishable
/// from a probe that matches zero — which is precisely how stage 5 went blind.
#[test]
fn the_traceflow_ship_rung_probes_a_field_this_surface_actually_emits() {
    // BOTH copies of the ladder. `run_traceflow2.sh` carried the identical blind
    // rung; a fix applied to one file and not the other leaves the defect live
    // behind a green test.
    let ladders: [(&str, &str); 2] = [
        (
            "scenarios/traceflow.sh",
            include_str!("../harness/mesh-repro/scenarios/traceflow.sh"),
        ),
        (
            "run_traceflow2.sh",
            include_str!("../harness/mesh-repro/run_traceflow2.sh"),
        ),
    ];
    for (name, src) in ladders {
        // Comments explaining the history are allowed to name the old field;
        // executable lines are not. Match the FULL field name, never a prefix —
        // `FSD/RCA_TRACE_PLANE_2026-07-31.md` item 3 records a ship detector that
        // matched `envelopes_sent_total` as a substring and reported the wrong
        // thing, which is not a mistake to re-commit inside its own regression pin.
        let code: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect();
        assert!(
            code.iter().any(|l| l.contains("envelopes_served_total")),
            "{name} must probe the REPLICATION-plane counter — the only one that \
             observes trace carriage (CIRISEdge#433/#434). A ladder that probes no \
             ship counter at all is the failure mode one step past probing the \
             wrong one."
        );
        if let Some(bad) = code.iter().find(|l| l.contains("envelopes_sent_total")) {
            panic!(
                "{name}: no executable line may probe the application-plane counter \
                 `envelopes_sent_total` — it is 0 on every healthy trace run, so the \
                 rung could never pass and therefore could never fail \
                 (CIRISServer#377). Got: {bad}"
            );
        }
    }

    // And the field it probes is one this surface really emits, with a value the
    // probe's `[1-9]` class can actually match.
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    m.inc_replication_served(EnvelopeKind::Attestation);
    let snap = m.snapshot();
    let v = round_diagnostics_json(&snap, true, true, false);
    assert_eq!(
        v["replication_plane"]["carriage"]["envelopes_served_total"],
        json!(1),
        "the emitted key the rung greps must exist and be positive when a row moved"
    );
}

/// The zero-denominator rule. A node whose rounds have never terminated has an
/// UNTESTED zero, not a clean one, and must not read the same as a node that ran
/// rounds and had nothing its peers needed.
#[test]
fn a_zero_with_no_rounds_reads_not_exercised_not_idle() {
    let fresh = EdgeMetrics::new().snapshot();
    let v = round_diagnostics_json(&fresh, true, true, false);
    assert_eq!(
        v["replication_plane"]["carriage"]["standing"],
        json!("not_exercised"),
        "no terminal round ⇒ the serving path has never run ⇒ the zero is untested"
    );
    assert_eq!(v["replication_plane"]["carriage"]["rounds_total"], json!(0));
    assert_eq!(
        v["replication_plane"]["receive"]["standing"],
        json!("not_exercised")
    );

    // Rounds ran, nothing was owed: a real and DIFFERENT healthy state.
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    let v = round_diagnostics_json(&m.snapshot(), true, true, false);
    assert_eq!(
        v["replication_plane"]["carriage"]["standing"],
        json!("idle"),
        "rounds finished and nothing was served ⇒ idle, which is not the same fact \
         as never having run one"
    );
    assert_eq!(
        v["replication_plane"]["receive"]["standing"],
        json!("clean")
    );
}

/// #377's second complaint, answered on the right plane. `round_outcomes.error`
/// counting while `send_failures_by_class` stayed `{}` was NOT "failures tallied
/// but never classified" — those are two different planes. The replication
/// plane's own refusal axis is `apply_refusals_by_kind`, and it is now surfaced
/// beside the rounds that carried the refused rows.
#[test]
fn replication_refusals_are_classified_beside_the_rounds_that_carried_them() {
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    m.inc_round_outcome(RoundOutcome::Error);
    // The WARN #377 quoted — `delivered envelope REFUSED — not applied`
    // (CIRISEdge#425 choke point) — books here.
    m.inc_apply_refusal_kind(EnvelopeKind::Attestation);
    m.inc_apply_refusal_kind(EnvelopeKind::Attestation);

    let v = round_diagnostics_json(&m.snapshot(), true, true, false);
    let receive = &v["replication_plane"]["receive"];
    assert_eq!(receive["standing"], json!("refusing"));
    assert_eq!(receive["apply_refusals_total"], json!(2));
    assert_eq!(
        receive["by_kind"]["attestation"],
        json!(2),
        "the refusal is named by the kind that was refused, not left as a bare count"
    );
    assert_eq!(v["replication_plane"]["round_outcomes"]["error"], json!(1));

    // The application-plane failure map stays where it belongs and stays empty —
    // and that is now a consistent report rather than a contradiction.
    assert_eq!(v["application_plane"]["send_failures_by_class"], json!({}));
}

/// "Served nothing" and "REFUSED to serve" reported identically before the
/// withhold ledger existed. The hint must lead with the withhold, because no
/// transport fix applies to it.
#[test]
fn a_withholding_node_outranks_every_transport_branch_in_the_hint() {
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    m.inc_withhold(
        WithholdReason::ServeCapabilityMissing,
        "peer-b",
        "no infra:serve",
    );

    let v = round_diagnostics_json(&m.snapshot(), true, true, true);
    assert_eq!(
        v["replication_plane"]["carriage"]["standing"],
        json!("withholding")
    );
    assert_eq!(v["replication_plane"]["withholds"]["total"], json!(1));
    assert_eq!(
        v["replication_plane"]["withholds"]["by_reason"]["serve_capability_missing"],
        json!(1)
    );
    let hint = v["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains("WITHHELD"),
        "a node refusing to serve must be told so before it is sent to chase \
         transport; got: {hint}"
    );
}

/// The planes must not leak into each other. An application-plane send is not
/// carriage, no matter how many of them there are.
#[test]
fn application_plane_traffic_never_moves_the_carriage_reading() {
    use ciris_edge::messages::MessageType;
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    for _ in 0..100 {
        m.inc_sent(&MessageType::FederationAnnouncement);
    }

    let v = round_diagnostics_json(&m.snapshot(), true, true, false);
    assert_eq!(v["application_plane"]["envelopes_sent_total"], json!(100));
    assert_eq!(
        v["replication_plane"]["carriage"]["envelopes_served_total"],
        json!(0),
        "100 announces are not 1 row of carriage"
    );
    assert_eq!(
        v["replication_plane"]["carriage"]["standing"],
        json!("idle"),
        "and the node is idle on the plane that matters, not `moving`"
    );
}
