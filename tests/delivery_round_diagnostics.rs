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
//! **CIRISEdge#457 (edge v15.20.1) closed the receive half of the same arc.**
//! `apply_refusals_by_kind` booked refusals and nothing booked an accepted apply,
//! so `receive.standing: "clean"` was three facts under one token — nothing
//! offered, everything offered applied, everything offered already held. The
//! `applied`/`converged`/`idle` arms below are that split, and the field-presence
//! test pins the #377 mechanism itself: a probe matching NOTHING and a probe
//! matching ZERO must not read the same.
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
        json!("idle"),
        "rounds finished and nothing was offered to the apply path ⇒ idle. This read \
         `clean` until CIRISEdge#457, which is the same collapse one direction over: \
         `clean` also meant 'we applied every row we were handed'"
    );
}

/// **CIRISEdge#457 — the receive half's three-way split.** Three nodes, all with
/// zero apply refusals, in three genuinely different conditions. Until edge
/// v15.20.1 booked `Admitted` and `Duplicate` they produced one token and one
/// payload, so an operator watching a stalled trace could not tell "nothing is
/// reaching us" from "everything reaching us already landed".
#[test]
fn nothing_offered_all_applied_and_all_duplicates_are_three_readings_not_one() {
    /// A node that ran a round and then saw `n` of `outcome`.
    fn node(f: impl Fn(&EdgeMetrics)) -> serde_json::Value {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        f(&m);
        round_diagnostics_json(&m.snapshot(), true, true, false)
    }

    let nothing = node(|_| {});
    let applied = node(|m| {
        for _ in 0..15 {
            m.inc_applied(EnvelopeKind::Attestation);
        }
    });
    let held = node(|m| {
        for _ in 0..15 {
            m.inc_duplicate(EnvelopeKind::Attestation);
        }
    });

    let recv = |v: &serde_json::Value| v["replication_plane"]["receive"].clone();
    for v in [&nothing, &applied, &held] {
        assert_eq!(
            recv(v)["apply_refusals_total"],
            json!(0),
            "all three are honestly zero-refusal — that is what made them collapse"
        );
    }

    let tokens: std::collections::HashSet<String> = [&nothing, &applied, &held]
        .iter()
        .map(|v| recv(v)["standing"].as_str().expect("standing").to_owned())
        .collect();
    assert_eq!(
        tokens.len(),
        3,
        "identical zero refusals, three different causes — the tokens must differ: {tokens:?}"
    );
    assert_eq!(recv(&nothing)["standing"], json!("idle"));
    assert_eq!(recv(&applied)["standing"], json!("applying"));
    assert_eq!(recv(&held)["standing"], json!("converged"));

    // The counts, each beside its denominator.
    assert_eq!(recv(&applied)["applied_total"], json!(15));
    assert_eq!(recv(&applied)["applied_by_kind"]["attestation"], json!(15));
    assert_eq!(recv(&applied)["duplicate_total"], json!(0));
    assert_eq!(recv(&held)["duplicate_total"], json!(15));
    assert_eq!(recv(&held)["duplicate_by_kind"]["attestation"], json!(15));
    assert_eq!(
        recv(&held)["applied_total"],
        json!(0),
        "a duplicate is not an apply — it is its own fact and books its own axis"
    );
    assert_eq!(recv(&nothing)["decided_total"], json!(0));
    assert_eq!(recv(&applied)["decided_total"], json!(15));
    assert_eq!(recv(&held)["decided_total"], json!(15));
    for v in [&nothing, &applied, &held] {
        assert_eq!(
            recv(v)["rounds_total"],
            json!(1),
            "a decided_total of 0 against 0 rounds is not a receive statement at all, \
             so the round count rides with it"
        );
    }

    // And the caveat that asserted this was impossible is GONE from the wire.
    assert!(
        recv(&applied)["accepted_total_unavailable"].is_null(),
        "`accepted_total_unavailable` said edge counts refusals and not accepted \
         applies (CIRISEdge#457). It does count them now, so the string must not \
         survive: a stale caveat tells a reader not to trust a number that is \
         trustworthy. Got {}",
        recv(&applied)["accepted_total_unavailable"]
    );
}

/// **A probe matching nothing and a probe matching zero must not read the same.**
///
/// This is the exact mechanism that blinded the #377 `ship` rung: stage 5 grepped
/// `"envelopes_sent_total":[1-9]`, the field was emitted and always 0, and a
/// no-match was indistinguishable from a zero. Every field the receive half now
/// adds is a candidate for the same failure, so each one is asserted PRESENT and
/// numeric on a node that has done nothing — because an absent key and a key
/// reading 0 must be different states for a consumer, and only one of them can be
/// "we have no counter for this".
#[test]
fn every_receive_field_is_present_and_numeric_even_when_it_reads_zero() {
    let m = EdgeMetrics::new();
    m.inc_round_outcome(RoundOutcome::Completed);
    let idle = round_diagnostics_json(&m.snapshot(), true, true, false);
    let recv = &idle["replication_plane"]["receive"];

    for field in [
        "applied_total",
        "duplicate_total",
        "apply_refusals_total",
        "decided_total",
        "rounds_total",
    ] {
        assert!(
            recv[field].is_u64(),
            "`{field}` must be emitted as a number even when it is 0. A consumer that \
             greps for it and finds NOTHING has learned that this build has no such \
             counter; one that finds 0 has learned the counter is live and reads zero. \
             Collapsing those two is CIRISServer#377's blind rung exactly. Got: {}",
            recv[field]
        );
    }
    for field in ["applied_by_kind", "duplicate_by_kind", "by_kind"] {
        assert!(
            recv[field].is_object(),
            "`{field}` must be an (empty) object, not absent: {}",
            recv[field]
        );
    }

    // The other half of the same rule: a field this surface does NOT emit must
    // read as absent rather than as a plausible zero.
    assert!(
        recv["accepted_total"].is_null(),
        "nothing emits `receive.accepted_total`; the counted field is `applied_total` \
         and a consumer looking for the wrong name must find nothing, not 0"
    );

    // And the value moves off zero when the thing it counts happens — the check
    // that proves the field is wired to the counter rather than hard-zero.
    m.inc_applied(EnvelopeKind::Key);
    let moved = round_diagnostics_json(&m.snapshot(), true, true, false);
    assert_eq!(
        moved["replication_plane"]["receive"]["applied_total"],
        json!(1)
    );
    assert_ne!(
        moved["replication_plane"]["receive"]["standing"], recv["standing"],
        "one applied row must change the standing; a field that only ever reads its \
         idle value is a probe that can never fail"
    );
}

/// The hint ladder's carriage branch could not tell a ONE-WAY path from a
/// two-way one, because "nothing was offered back to us" was not a statement
/// this node could make. CIRISEdge#457 made it one, and the two conditions have
/// different remedies: a reverse-path/NAT gap, versus a round that is reaching us
/// and failing to complete.
#[test]
fn a_one_way_carriage_and_a_two_way_one_get_different_hints() {
    let one_way = {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_replication_served(EnvelopeKind::Attestation);
        round_diagnostics_json(&m.snapshot(), true, true, true)
    };
    let two_way = {
        let m = EdgeMetrics::new();
        m.inc_round_outcome(RoundOutcome::Completed);
        m.inc_replication_served(EnvelopeKind::Attestation);
        m.inc_applied(EnvelopeKind::IdentityOccurrence);
        round_diagnostics_json(&m.snapshot(), true, true, true)
    };

    let h1 = one_way["hint"].as_str().unwrap_or_default();
    let h2 = two_way["hint"].as_str().unwrap_or_default();
    assert_ne!(
        h1, h2,
        "served rows with nothing coming back, and served rows with rows coming back, \
         are different diagnoses and must not share a hint"
    );
    assert!(
        h1.contains("one-way"),
        "rows out and nothing in is a one-way path and the hint must say so; got: {h1}"
    );
    assert!(
        h2.contains("BOTH directions"),
        "rows moving both ways rules the reverse path out; got: {h2}"
    );
    assert_eq!(
        one_way["replication_plane"]["receive"]["decided_total"],
        json!(0)
    );
    assert_eq!(
        two_way["replication_plane"]["receive"]["decided_total"],
        json!(1)
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
