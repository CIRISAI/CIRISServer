//! **The 0.5.156 release gate: traces flow, and if they stop, something says so.**
//!
//! `FSD/RCA_INGEST_REJECTION_2026-08-05.md` is the whole brief. Traces stopped
//! on 2026-08-03T23:30. The server refused 8,631 correct 401s a day from two
//! unregistered keys for 71 hours, and **no instrument turned "the trace plane
//! is dead" into a signal.** Every individual link was right; the composite was
//! dead; nobody owned the join.
//!
//! So this file tests the JOIN, and only the join. Where a link is already
//! covered in isolation it is not re-covered here — `src/operator_surface.rs`
//! bands, `src/ingest_http.rs` counts, `tests/ingest_http.rs` drives one
//! admission through the real gate. What none of them prove is:
//!
//! 1. **[`a_second_arrival_moves_the_band_and_a_dark_plane_goes_green_again`]** —
//!    that `last_admitted_at` *moves*, and that a plane which has gone RED goes
//!    GREEN again when a trace lands. Every existing test admits ONE trace, so
//!    the reading is only ever proven non-null; a reader wired to the corpus's
//!    OLDEST instant, or to a value latched at first read, passes all of them
//!    and would have stayed red through the recovery it exists to announce.
//! 2. **[`the_outage_shape_reads_stuck_producer_at_every_hour_of_its_71`]** —
//!    that the refusal reading holds for the whole outage rather than at one
//!    convenient instant, and that it CLEARS afterwards rather than latching.
//!    A one-shot assertion cannot tell a detector from a fixture.
//! 3. **[`the_33_hour_overlap_window_reads_live_and_stuck_at_once`]** — the
//!    RCA's own missed-detection window: 33 hours in which one producer was
//!    already being refused while another still succeeded, "and nothing compared
//!    the two". That is the one reading that would have fired BEFORE the plane
//!    went dark, and nothing asserted it.
//! 4. **[`the_federation_identity_zero_names_how_it_was_arrived_at`]** — the
//!    `peer_counts_standing` arm of `GET /v1/federation/identity`
//!    (CIRISServer#372), which was compile-checked only because no test in this
//!    repo had ever constructed an `Arc<Edge>`. Its silent fallback answers
//!    `200 {"peer_count_total": 0}` — a confident, wrong, healthy-looking zero,
//!    the RCA's shape exactly.
//!
//! The composition gate — *the route that admits and the route that reads share
//! ONE ledger* — lives in `tests/operator_surface.rs`, where the owner-session
//! fixtures already are.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

use ciris_persist::federation::types::{algorithm, identity_type};
use ciris_persist::federation::{FederationDirectory as _, KeyRecord, SignedKeyRecord};
use ciris_persist::ingest::IngestError;
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::Error as VerifyError;

use ciris_server::ingest_http::{self, IngestRefusals, LEGACY_INGEST_PATH};
use ciris_server::mesh_config_effect::MeshConfigEffect;
use ciris_server::operator_surface::{self, IngestStanding, OperatorStateOptions};

#[path = "support/accord_batch.rs"]
mod accord_batch;

// ═══════════════════════════════════════════════════════════════════════════
//  Fixtures
// ═══════════════════════════════════════════════════════════════════════════

/// One node: an in-memory Engine keyed by a deterministic Ed25519 signer.
async fn node(seed: u8, alias: &str) -> Arc<Engine> {
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[seed; 32]),
        alias.to_string(),
        None,
        None,
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

/// Cross-register a producer's Ed25519 verifying key so `VerifyMode::Full`
/// resolves a trace signed under `key_id`. The founder-quorum door does this in
/// production; here it is what separates the good producer from the stuck one.
async fn cross_register(engine: &Engine, key_id: &str, sk: &SigningKey, id_type: &str) {
    let pubkey_b64 = BASE64.encode(sk.verifying_key().to_bytes());
    let now = Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: pubkey_b64.clone(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.into(),
        identity_type: id_type.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": key_id }),
        original_content_hash: "deadbeef".into(),
        scrub_signature_classical: pubkey_b64,
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("cross-register key in federation directory");
}

/// POST a batch through the REAL ingest router, counting into `refusals`.
async fn post(
    engine: Arc<Engine>,
    refusals: &IngestRefusals,
    body: Vec<u8>,
) -> (StatusCode, serde_json::Value) {
    let app = ingest_http::router(engine, refusals.clone(), MeshConfigEffect::unwired());
    let req = Request::builder()
        .method("POST")
        .uri(LEGACY_INGEST_PATH)
        .header("content-type", "application/json")
        .header("user-agent", "CIRIS-AccordMetrics/1.0")
        .body(Body::from(body))
        .expect("build request");
    let resp = app.oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn at(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("rfc3339 fixture")
        .with_timezone(&Utc)
}

fn opts(now: DateTime<Utc>) -> OperatorStateOptions {
    OperatorStateOptions {
        self_key_id: None,
        root_key_id: None,
        now: Some(now),
        sla_seconds: None,
    }
}

/// The corpus instant persist itself reports — read through the SAME aggregate
/// the surface reads, so a test can never anchor on a value the surface does not
/// see.
async fn newest_admitted(engine: &Engine) -> Option<DateTime<Utc>> {
    engine
        .storage_summary()
        .await
        .expect("storage summary")
        .trace_events
        .newest_ts
}

// ═══════════════════════════════════════════════════════════════════════════
//  PART 1 — the whole chain, and the one link nothing tested: it MOVES
// ═══════════════════════════════════════════════════════════════════════════

/// **producer signs → HTTP ingest → verify-before-persist → row lands →
/// `last_admitted_at` MOVES → the band follows it, in both directions.**
///
/// The existing end-to-end admits one trace and asserts the plane reads green.
/// That proves the reading is *derived from* an arrival; it does not prove the
/// reading *tracks* arrivals, and those are different claims. A reader wired to
/// `oldest_ts` instead of `newest_ts`, or one that cached the first value it
/// saw, satisfies the first and fails the second — and would leave a recovered
/// node showing RED, which is the same instrument failure as a dead node showing
/// GREEN, wearing the opposite colour.
///
/// So this walks the RCA's own arc: the last real admission at
/// `2026-08-03T23:30`, the discovery 38 hours later with the plane RED, and then
/// the fix — a producer signing correctly again — and asserts the band goes back
/// to GREEN *because the stored instant moved*, not because the clock did.
///
/// MUTATION EVIDENCE: point `corpus_of` at `oldest_ts`; the recovery leg reads
/// `dark`/red and this goes RED. The pre-existing suite stays green.
#[tokio::test]
async fn a_second_arrival_moves_the_band_and_a_dark_plane_goes_green_again() {
    const PRODUCER: &str = "ciris-agent-bootstrap-25uzoxtlro";
    // The RCA's own instants.
    let first = at("2026-08-03T23:30:00Z");
    let found_at = at("2026-08-05T13:55:00Z");
    let recovery = at("2026-08-05T14:10:00Z");

    let engine = node(0xE0, "node-release-gate").await;
    let refusals = IngestRefusals::new();
    let sk = SigningKey::from_bytes(&[0x21; 32]);
    cross_register(&engine, PRODUCER, &sk, identity_type::AGENT).await;

    // ── The chain, link by link, through the real route ─────────────────────
    let (status, body) = post(
        Arc::clone(&engine),
        &refusals,
        accord_batch::build_batch_bytes_at(&sk, PRODUCER, "trace-gate-0001", first),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the signed batch must admit: {body}"
    );
    assert_eq!(
        body["trace_events_inserted"],
        serde_json::json!(1),
        "a 200 that inserted nothing is not an admission: {body}"
    );
    assert_eq!(
        body["signatures_verified"],
        serde_json::json!(1),
        "verify-before-persist must have RUN, not been skipped: {body}"
    );
    assert_eq!(
        newest_admitted(&engine).await,
        Some(first),
        "the row's own instant must be what the corpus reports"
    );

    let live = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(first + Duration::minutes(5)),
    )
    .await;
    assert_eq!(live["trace_plane"]["standing"], serde_json::json!("live"));
    assert_eq!(live["trace_plane"]["band"], serde_json::json!("green"));
    assert_eq!(
        live["trace_plane"]["last_admitted_at"],
        serde_json::json!(first)
    );

    // ── 38 hours later, nothing new: RED ────────────────────────────────────
    let dark = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(found_at),
    )
    .await;
    assert_eq!(dark["trace_plane"]["standing"], serde_json::json!("dark"));
    assert_eq!(dark["trace_plane"]["band"], serde_json::json!("red"));

    // ── THE LINK NOTHING TESTED: a newer trace lands ────────────────────────
    let (status, body) = post(
        Arc::clone(&engine),
        &refusals,
        accord_batch::build_batch_bytes_at(&sk, PRODUCER, "trace-gate-0002", recovery),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the recovery batch must admit: {body}"
    );
    assert_eq!(
        body["trace_events_inserted"],
        serde_json::json!(1),
        "a deduplicated re-POST would leave the corpus unchanged and prove nothing: {body}"
    );
    assert_eq!(
        newest_admitted(&engine).await,
        Some(recovery),
        "MAX(trace_events.ts) must follow the newest arrival — a reading anchored to the corpus's \
         OLDEST row survives every single-admission test and never recovers"
    );

    let green_again = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(recovery + Duration::minutes(5)),
    )
    .await;
    assert_eq!(
        green_again["trace_plane"]["last_admitted_at"],
        serde_json::json!(recovery),
        "the band must be reading the NEW arrival: {}",
        green_again["trace_plane"]
    );
    assert_eq!(
        green_again["trace_plane"]["standing"],
        serde_json::json!("live"),
        "a plane being fed again must stop reading dark — an alarm that cannot clear is an alarm \
         nobody will trust the second time: {}",
        green_again["trace_plane"]
    );
    assert_eq!(
        green_again["trace_plane"]["band"],
        serde_json::json!("green")
    );
    assert_eq!(
        green_again["trace_plane"]["rows"],
        serde_json::json!(2),
        "both admissions are in the corpus; the band reads the newest, not the count"
    );
    // And the recovery is a real state change, not the same reading twice.
    assert_ne!(
        green_again["trace_plane"]["last_admitted_at"],
        dark["trace_plane"]["last_admitted_at"]
    );
    assert_ne!(
        green_again["trace_plane"]["band"],
        dark["trace_plane"]["band"]
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  PART 2 — the outage's own shape, unbroken, and its clearing
// ═══════════════════════════════════════════════════════════════════════════

/// The two identities from the RCA, verbatim.
const STUCK: [&str; 2] = ["agent-55fe8d181727", "agent-1ee871dcf31b"];

fn unknown_key(id: &str) -> IngestError {
    IngestError::Verify(VerifyError::UnknownKey(id.to_owned()))
}

/// **6 refusals a minute, alternating between two stable ids, for 71 hours
/// unbroken — and the reading must be `stuck_producer` at EVERY hour of it.**
///
/// The RCA's numbers: 8,631 refusals/day ≈ 6/min, two identities, "no growth, no
/// variation", 71 hours. Every existing assertion on this condition is taken at
/// one instant against a ledger loaded in one burst. That cannot distinguish a
/// detector from a fixture: a reading that happens to be right once is what the
/// node already had.
///
/// Two properties, and the second matters as much as the first:
///
/// - the reading holds at every hourly sample across the whole outage — it does
///   not flicker as the sliding window slides, and the bounded event cap
///   ([`ingest_http::REFUSAL_EVENT_CAP`]) never bites at this rate, so no count
///   is silently a floor;
/// - it CLEARS once the producer stops. An alarm that latches is an alarm that
///   gets muted, and the muted alarm is the one that is not read during the next
///   outage.
///
/// MUTATION EVIDENCE: drop the `distinct_signers <= MAX` conjunct from
/// `ingest_standing` and the wide-set control below goes RED; latch the standing
/// (never leave `StuckProducer`) and the clearing leg goes RED.
#[test]
fn the_outage_shape_reads_stuck_producer_at_every_hour_of_its_71() {
    // First rejection, per the RCA timeline.
    let t0 = at("2026-08-02T14:23:00Z");
    const HOURS: i64 = 71;
    const PER_MINUTE: i64 = 6;

    let ledger = IngestRefusals::started_at(t0);

    // The clock runs FORWARD, and the reading is taken as it goes. The ledger is
    // a live sliding window that prunes on every write, so a test that loads 71
    // hours and then snapshots backwards is not sampling history — it is
    // sampling one window and calling it seventy-one. The loop below emits an
    // hour and reads it, an hour and reads it, exactly as the node experienced.
    let mut minute = 0i64;
    for hour in 1..=HOURS {
        while minute < hour * 60 {
            for k in 0..PER_MINUTE {
                let at_ = t0 + Duration::minutes(minute) + Duration::seconds(k * 10);
                ledger.observe_refusal_at(at_, &unknown_key(STUCK[(k % 2) as usize]));
            }
            minute += 1;
        }
        let now = t0 + Duration::hours(hour);
        let bundle = ledger.snapshot_at(now);
        assert!(
            !bundle.window_truncated,
            "at 6/min the event cap must never bite — a truncated window would make every count \
             below a FLOOR, and this test would be asserting on an under-report (hour {hour})"
        );
        assert_eq!(
            bundle.distinct_signers_in_window, 2,
            "the identity set is stable and small — that is the whole discrimination (hour {hour})"
        );
        assert_eq!(
            bundle.refusals_in_window,
            (PER_MINUTE * 60) as u64,
            "the trailing hour holds exactly one hour of a constant rate (hour {hour})"
        );
        assert_eq!(
            operator_surface::ingest_standing(Some(&bundle)),
            IngestStanding::StuckProducer,
            "hour {hour} of 71: a sustained rate of CORRECT refusals from a stable identity set is \
             a fault report about someone else, at every hour and not merely at a convenient one"
        );
    }

    // ── The control: the SAME rate, spread wide, is NOT a stuck producer ─────
    //
    // Without this the test above passes on a predicate that ignores identity
    // entirely, which is the version of this reading that cannot tell a
    // misconfigured client from a Sybil probe.
    let wide = IngestRefusals::started_at(t0);
    for minute in 0..60 {
        for k in 0..PER_MINUTE {
            let at_ = t0 + Duration::minutes(minute) + Duration::seconds(k * 10);
            wide.observe_refusal_at(at_, &unknown_key(&format!("probe-{minute:04}-{k}")));
        }
    }
    let wide_bundle = wide.snapshot_at(t0 + Duration::hours(1));
    let stuck_bundle = ledger.snapshot_at(t0 + Duration::hours(HOURS));
    assert_eq!(
        wide_bundle.refusals_in_window, stuck_bundle.refusals_in_window,
        "the two fixtures MUST carry identical counts, or the identity dimension is not what is \
         being tested"
    );
    assert_eq!(
        operator_surface::ingest_standing(Some(&wide_bundle)),
        IngestStanding::Background,
        "one counter, two opposite conditions: 360/h from 360 identities is a probe, not a \
         producer to go telephone"
    );

    // ── The clearing: the producer is fixed, and the reading lets go ─────────
    let after = t0 + Duration::hours(HOURS);
    // Still red at the moment the flood stops.
    assert_eq!(
        operator_surface::ingest_standing(Some(&ledger.snapshot_at(after))),
        IngestStanding::StuckProducer
    );
    // ...and, a full window later with nothing new refused, it is not.
    let recovered =
        ledger.snapshot_at(after + Duration::seconds(ingest_http::REFUSAL_WINDOW_SECS + 1));
    assert_eq!(recovered.refusals_in_window, 0);
    assert_eq!(
        operator_surface::ingest_standing(Some(&recovered)),
        IngestStanding::Clean,
        "an alarm that cannot clear gets muted, and a muted alarm is the one nobody reads during \
         the NEXT outage"
    );
    assert_eq!(
        recovered.refused_total,
        (HOURS * 60 * PER_MINUTE) as u64,
        "the window emptied; the process total must not, or a node that weathered an outage reads \
         as one that never had it"
    );
}

/// **The 33-hour overlap window — the RCA's own missed-detection window.**
///
/// > "Both conditions ran concurrently for 33 hours before the plane went fully
/// > silent. That overlap is the missed detection window: a producer was being
/// > refused while another was still succeeding, and nothing compared the two."
///
/// This is the reading that would have fired on **2026-08-02**, a day and a half
/// before the plane went dark and three days before a human looked. It is also
/// the one combination nothing asserted: the existing composed-view coverage
/// pairs a DARK plane with `stuck_producer` and a DARK plane with `clean`, both
/// of which are already-too-late readings. `live` + `stuck_producer` is the
/// early one, and it must not be silent just because the headline band is not
/// red on the trace plane's account.
///
/// MUTATION EVIDENCE: make `IngestStanding::StuckProducer.band()` anything but
/// red, or let a green trace plane suppress the ingest reading, and this goes
/// RED.
#[test]
fn the_33_hour_overlap_window_reads_live_and_stuck_at_once() {
    // The overlap: first rejection 2026-08-02T14:23, last admission
    // 2026-08-03T23:30 — 33h07m apart. Take the reading in the middle of it,
    // while traces were STILL LANDING.
    let first_rejection = at("2026-08-02T14:23:00Z");
    let during = at("2026-08-03T12:00:00Z");
    // A trace admitted an hour ago: the plane is genuinely being fed.
    let corpus = operator_surface::TraceCorpus {
        last_admitted_at: Some(during - Duration::hours(1)),
        rows: 120_000,
    };

    let ledger = IngestRefusals::started_at(first_rejection);
    let mut t = first_rejection;
    while t <= during {
        for k in 0..6 {
            ledger.observe_refusal_at(
                t + Duration::seconds(k * 10),
                &unknown_key(STUCK[(k % 2) as usize]),
            );
        }
        t += Duration::minutes(1);
    }
    let bundle = ledger.snapshot_at(during);

    let view = operator_surface::compose(
        operator_surface::Sources {
            node: Err("not read in this fixture".to_owned()),
            edge: Err("no edge in this fixture".to_owned()),
            trace: Ok(&corpus),
            ingest: Some(&bundle),
        },
        during,
    );

    assert_eq!(
        view["trace_plane"]["standing"],
        serde_json::json!("live"),
        "traces were still landing — this is 33 hours BEFORE the plane went silent: {}",
        view["trace_plane"]
    );
    assert_eq!(view["trace_plane"]["band"], serde_json::json!("green"));
    assert_eq!(
        view["ingest"]["standing"],
        serde_json::json!("stuck_producer"),
        "...and a producer was ALREADY being refused, unbroken, from two stable ids. Nothing \
         compared the two, and that is the entire missed-detection window: {}",
        view["ingest"]
    );
    assert_eq!(view["ingest"]["band"], serde_json::json!("red"));
    assert_eq!(
        view["band"],
        serde_json::json!("red"),
        "a healthy trace plane must NOT out-vote a red ingest reading — the whole point of this \
         window is that the node still looked fine: {view}"
    );

    // The two named producers are on the wire, so the alarm is actionable at
    // the moment it first could have fired.
    let named: std::collections::HashSet<&str> = view["ingest"]["top_signers"]
        .as_array()
        .expect("top_signers")
        .iter()
        .map(|t| t["signer_id"].as_str().expect("signer_id"))
        .collect();
    for who in STUCK {
        assert!(named.contains(who), "{}", view["ingest"]);
    }

    // The control: the SAME live plane with a clean gate is green all through.
    // Without it, "red" above could be coming from anywhere in the payload.
    let quiet = IngestRefusals::started_at(first_rejection);
    quiet.observe_accept_at(during);
    let quiet_bundle = quiet.snapshot_at(during);
    let calm = operator_surface::compose(
        operator_surface::Sources {
            node: Err("not read in this fixture".to_owned()),
            edge: Err("no edge in this fixture".to_owned()),
            trace: Ok(&corpus),
            ingest: Some(&quiet_bundle),
        },
        during,
    );
    assert_eq!(calm["ingest"]["standing"], serde_json::json!("clean"));
    assert_ne!(
        calm["ingest"]["band"], view["ingest"]["band"],
        "a fed node with a working gate and a fed node with a stuck producer must not read alike"
    );
}

/// **The three trace-plane zeroes, driven through the real corpus reader.**
///
/// `unreadable` (could not ask) / `never_admitted` (asked, holds nothing) /
/// `dark` (holds traces, none recent) are three different facts, and a bare
/// timestamp renders all three identically. The unit coverage in
/// `src/operator_surface.rs` pins the narrowing over hand-built `TraceCorpus`
/// values; this pins that a REAL engine on a REAL fresh node produces the
/// `never_admitted` arm — the one an in-memory fixture is most likely to get
/// wrong, because an empty table and a failed read are one line apart in
/// `corpus_of`.
///
/// The `unreadable` arm is composed directly and not driven: no backend in the
/// substrate can be made to fail on demand from a test. That limitation is
/// CIRISPersist#604, referenced rather than re-litigated here.
///
/// MUTATION EVIDENCE: fold the corpus read's `Err` into an empty corpus and the
/// `unreadable` leg reads `never_admitted`; this goes RED on the `assert_ne!`.
#[tokio::test]
async fn the_three_trace_plane_zeroes_stay_three_on_a_real_engine() {
    let engine = node(0xE1, "node-fresh").await;
    let now = at("2026-08-05T13:55:00Z");

    // (a) A REAL fresh node: the corpus was read, and it holds nothing.
    let fresh = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        None,
        &opts(now),
    )
    .await;
    assert_eq!(
        fresh["trace_plane"]["standing"],
        serde_json::json!("never_admitted"),
        "a node that has never been fed must say THAT, not 'dark' and not 'unreadable': {}",
        fresh["trace_plane"]
    );
    assert_eq!(
        fresh["trace_plane"]["band"],
        serde_json::json!("unknown"),
        "an untested zero is not a healthy one"
    );
    assert_eq!(
        fresh["trace_plane"]["rows"],
        serde_json::json!(0),
        "the row count is what makes `never_admitted` checkable rather than inferred"
    );
    assert!(
        fresh["unknown"]
            .as_array()
            .expect("unknown")
            .contains(&serde_json::json!("trace_plane")),
        "an unfed plane must be NAMED as an unknown so it cannot render as health: {fresh}"
    );

    // (b) A node whose corpus could not be read at all.
    let blind = operator_surface::compose(
        operator_surface::Sources {
            node: Err("not read in this fixture".to_owned()),
            edge: Err("no edge in this fixture".to_owned()),
            trace: Err("sqlite: database is locked".to_owned()),
            ingest: None,
        },
        now,
    );

    // (c) A node holding traces, none of them recent.
    let stale = operator_surface::TraceCorpus {
        last_admitted_at: Some(at("2026-08-03T23:30:00Z")),
        rows: 120_000,
    };
    let dark = operator_surface::compose(
        operator_surface::Sources {
            node: Err("not read in this fixture".to_owned()),
            edge: Err("no edge in this fixture".to_owned()),
            trace: Ok(&stale),
            ingest: None,
        },
        now,
    );

    // THREE readings, THREE tokens. Any pair collapsing is the defect.
    let tokens = [
        blind["trace_plane"]["standing"].clone(),
        fresh["trace_plane"]["standing"].clone(),
        dark["trace_plane"]["standing"].clone(),
    ];
    assert_eq!(tokens[0], serde_json::json!("unreadable"));
    assert_eq!(tokens[1], serde_json::json!("never_admitted"));
    assert_eq!(tokens[2], serde_json::json!("dark"));
    let distinct: std::collections::HashSet<String> = tokens
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    assert_eq!(
        distinct.len(),
        3,
        "'could not ask' / 'asked, nothing there' / 'asked, nothing recent' are three facts and a \
         bare timestamp renders all three the same: {tokens:?}"
    );
    // ...and the two that share the `unknown` band still do not share a token.
    assert_eq!(blind["trace_plane"]["band"], fresh["trace_plane"]["band"]);
    assert_ne!(
        blind["trace_plane"]["standing"], fresh["trace_plane"]["standing"],
        "a band never replaces a token"
    );
    assert_ne!(dark["trace_plane"]["band"], fresh["trace_plane"]["band"]);
    // Only the unreadable arm carries a cause; the other two carry a corpus.
    assert!(blind["trace_plane"]["detail"].is_string(), "{blind}");
    assert!(fresh["trace_plane"]["detail"].is_null(), "{fresh}");
}

/// **The 401 body names the namespace, through the real route, for the real
/// producer, on the ledger the surface reads.**
///
/// The producer is the only party who can fix a wrong-namespace signature, and
/// during the outage it received one opaque token equally true of a typo, a
/// revoked key, a pending registration and this. `tests/ingest_http.rs` pins the
/// body; what it does not pin is that the SAME refusal both informs the producer
/// AND registers on the operator's reading — the two halves of #370/#371 are one
/// event, and a build where the body is right and the ledger is empty (or the
/// reverse) is a build where one of the two audiences is still in the dark.
///
/// MUTATION EVIDENCE: drop `key_id_namespace` from `ingest_error_body` and the
/// namespace leg goes RED; drop the `observe_refusal` call from the handler and
/// the ledger leg goes RED. Neither mutation is visible to the other half.
#[tokio::test]
async fn one_refusal_both_names_the_namespace_and_reaches_the_operator_reading() {
    let engine = node(0xE2, "node-namespace").await;
    let refusals = IngestRefusals::new();
    // A REAL Ed25519 key, correctly signed — the producer's only mistake is
    // naming itself with its agent-credits identity.
    let sk = SigningKey::from_bytes(&[0x11; 32]);

    let (status, body) = post(
        Arc::clone(&engine),
        &refusals,
        accord_batch::build_batch_bytes_at(
            &sk,
            STUCK[0],
            "trace-namespace-0001",
            at("2026-08-05T13:00:00Z"),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the admission gate was always right and must not soften: {body}"
    );
    assert_eq!(body["error"], serde_json::json!("verify_unknown_key"));
    assert_eq!(
        body["key_id_namespace"],
        serde_json::json!("agent_credits"),
        "the producer's ONLY actionable field: {body}"
    );
    assert!(
        !body.to_string().contains(STUCK[0]),
        "AV-15 — the refused value stays in the log: {body}"
    );

    // The SAME refusal, on the operator's side of the wall.
    let view = operator_surface::operator_state(
        &engine,
        Err("no edge in this fixture".to_owned()),
        Some(&refusals),
        &opts(at("2026-08-05T13:05:00Z")),
    )
    .await;
    assert_eq!(
        view["ingest"]["refused_total"],
        serde_json::json!(1),
        "a refusal the operator surface cannot see is a refusal with one audience: {}",
        view["ingest"]
    );
    assert_eq!(
        view["ingest"]["by_kind"]["verify_unknown_key"],
        serde_json::json!(1),
        "persist's own stable token, carried: {}",
        view["ingest"]
    );
    assert_eq!(
        view["ingest"]["top_signers"][0]["signer_id"],
        serde_json::json!(STUCK[0]),
        "the operator's copy DOES name the id — that is the asymmetry: the producer is told what \
         KIND of identity it used, the operator is told WHICH one to go chase: {}",
        view["ingest"]
    );
    // One refusal is not yet a stuck producer, and must not claim to be.
    assert_eq!(
        view["ingest"]["standing"],
        serde_json::json!("background"),
        "an instrument that fires on a single refusal trains people to ignore it: {}",
        view["ingest"]
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  PART 3 — the known-untested arm: GET /v1/federation/identity
// ═══════════════════════════════════════════════════════════════════════════

/// A transport that carries nothing. `EdgeBuilder::build` refuses a transportless
/// Edge ("no transport configured"), and this repo needs an `Arc<Edge>` for a
/// route that reads exactly one thing off it (`signer_key_id`). Mirrors the
/// `NullTransport` CIRISEdge's own `tests/canonical_peer.rs` uses, so the shape
/// is the substrate's own test convention rather than an invention here.
struct NullTransport;

#[async_trait::async_trait]
impl ciris_edge::transport::Transport for NullTransport {
    fn id(&self) -> ciris_edge::transport::TransportId {
        ciris_edge::transport::TransportId::HTTP
    }
    async fn send(
        &self,
        _: &str,
        _: &[u8],
    ) -> Result<ciris_edge::transport::TransportSendOutcome, ciris_edge::transport::TransportError>
    {
        Ok(ciris_edge::transport::TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _: tokio::sync::mpsc::Sender<ciris_edge::transport::InboundFrame>,
    ) -> Result<(), ciris_edge::transport::TransportError> {
        Ok(())
    }
}

/// A live `Arc<Edge>` over `engine`'s own SQLite backend — one pool, no second
/// store, no transport that can reach anything.
async fn edge_over(engine: &Engine, key_id: &str, seed: u8) -> Arc<ciris_edge::Edge> {
    let dir = std::env::temp_dir().join(format!(
        "ciris-release-gate-edge-{}-{}-{seed}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&dir).expect("seed dir");
    std::fs::write(dir.join("ed25519.seed"), [seed; 32]).expect("write seed");
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: key_id.to_owned(),
        key_path: dir.join("ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .expect("load_local_seed");
    let signer = Arc::new(ciris_edge::identity::LocalSigner::new(
        key_id, classical, None,
    ));
    let backend = engine
        .sqlite_backend()
        .expect("sqlite-backed engine")
        .clone();
    Arc::new(
        ciris_edge::Edge::builder()
            .directory(backend.clone())
            .federation_directory(backend.clone())
            .queue(backend)
            .signer(signer)
            .transport(Arc::new(NullTransport))
            .build()
            .expect("build edge"),
    )
}

/// GET the identity route off a real composed federation surface.
async fn federation_identity(
    engine: Arc<Engine>,
    edge: Arc<ciris_edge::Edge>,
) -> serde_json::Value {
    let app = ciris_server::federation_surface::router(engine, edge);
    let req = Request::builder()
        .method("GET")
        .uri("/v1/federation/identity")
        .body(Body::empty())
        .expect("build request");
    let resp = app.oneshot(req).await.expect("router oneshot");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the identity route degrades rather than fails — that is precisely why the DEGRADATION has \
         to be named"
    );
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json body");
    body["data"].clone()
}

/// An engine whose signer is **ECDSA P-256**, not Ed25519 — the real
/// misconfiguration persist hardened against. `local_derived_key_id` refuses to
/// derive a federation id over a 65-byte key, so this node genuinely cannot
/// resolve who it is. Mirrors `tests/self_identity_fold.rs::blind_engine`.
async fn blind_engine() -> Arc<Engine> {
    // NOTE: this engine DOES carry the baked genesis family — it has real peers.
    // That is what makes it the sharp fixture: its zero is not merely
    // unexplained, it is factually WRONG.
    let dir = std::env::temp_dir().join(format!(
        "ciris-release-gate-blind-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let signer =
        ciris_keyring::SoftwareSigner::new("ciris-blind-node", &dir).expect("P-256 signer");
    let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(signer);
    Arc::new(
        Engine::with_hardware_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_hardware_signer (sqlite::memory:)"),
    )
}

/// **A zero that cannot say why it is zero is not evidence** — the RCA's shape,
/// on the one route in this repo that had no test at all because nothing here
/// had ever built an `Arc<Edge>`.
///
/// `GET /v1/federation/identity` degrades rather than fails on a peer-count
/// problem, deliberately: an Edge identity is still worth serving. The hazard is
/// that the degraded answer is `200 {"peer_count_total": 0}` — indistinguishable
/// from a healthy node that simply has no peers yet. `peer_counts_standing`
/// (CIRISServer#372) is what separates them, and until now the field was
/// compile-checked and never once observed.
///
/// Three fixtures, two of which produce the SAME number:
///
/// | fixture | `peer_count_total` | standing |
/// |---|---|---|
/// | a node with peers | non-zero | `measured` |
/// | a node with genuinely none | **0** | `measured` |
/// | a node that cannot resolve itself | **0** | `self_identity_unresolved` |
///
/// The last two rows are the whole test. Identical payload numbers, opposite
/// meanings, and only the token tells them apart — and the third node's zero is
/// not merely unexplained, it is FALSE: that engine carries the baked genesis
/// family and really does have peers. It reports none because it cannot work out
/// which key is itself, which is a node-configuration fault reported as an empty
/// federation.
///
/// **NOT covered, and why:** the `store_unavailable` arm. It needs a directory
/// read that fails on demand and no backend in the substrate can be made to do
/// that from a test — the same limitation CIRISPersist#604 already tracks for
/// the operator surface's `unreadable` arms. Referenced rather than faked: an
/// arm asserted through a stub that cannot occur in production is worse than an
/// arm known to be uncovered.
///
/// MUTATION EVIDENCE: collapse the `Err` arm of `self_identity::resolve` in
/// `get_identity` into `COUNTS_MEASURED` and the third fixture reads `measured`
/// with zero peers — a confident, wrong, healthy zero — and this goes RED.
#[tokio::test]
async fn the_federation_identity_zero_names_how_it_was_arrived_at() {
    // ── (1) A node with peers: a measured non-zero ──────────────────────────
    //
    // The baseline is read first because a production engine is seeded with the
    // baked genesis family — a fresh node already HAS peers, and a fixture that
    // assumed otherwise would be asserting on the seed rather than on the two
    // rows it registered.
    let engine = node(0xE3, "node-fedsurface").await;
    let baseline = federation_identity(
        Arc::clone(&engine),
        edge_over(&engine, "edge-baseline", 0x40).await,
    )
    .await;
    let baked = baseline["peer_count_total"].as_u64().expect("baseline");
    assert_eq!(
        baseline["peer_counts_standing"],
        serde_json::json!("measured"),
        "the baseline read itself has to be a measurement, or the delta below means nothing"
    );

    cross_register(
        &engine,
        "peer-agent-alpha",
        &SigningKey::from_bytes(&[0x31; 32]),
        identity_type::AGENT,
    )
    .await;
    // A second peer under a DIFFERENT identity_type, because `peer_counts`
    // unions seven of them and de-dupes — a fixture using one type would not
    // notice a projection that dropped six.
    //
    // Neither peer is `canonical`: persist refuses a self-asserted canonical
    // role at the put-gate (`CanonicalRoleNotAccordConferred` — it is
    // accord-CONFERRED, minted only by an m-of-n co-scrub), so a test cannot
    // mint one without standing up a whole accord family. `peer_count_canonical`
    // is therefore asserted as a real measured zero here rather than faked.
    cross_register(
        &engine,
        "peer-node-1",
        &SigningKey::from_bytes(&[0x32; 32]),
        identity_type::NODE,
    )
    .await;
    let edge = edge_over(&engine, "edge-release-gate", 0x41).await;
    let data = federation_identity(Arc::clone(&engine), edge).await;

    assert_eq!(
        data["peer_counts_standing"],
        serde_json::json!("measured"),
        "a count taken off a directory that answered is MEASURED: {data}"
    );
    assert_eq!(
        data["peer_count_total"],
        serde_json::json!(baked + 2),
        "the two registered peers must MOVE the count — a projection that dropped an \
         identity_type would render a plausible number computed over the wrong set: {data}"
    );
    assert_eq!(data["peer_count_canonical"], serde_json::json!(0), "{data}");
    assert_eq!(
        data["signer_key_id"],
        serde_json::json!("edge-release-gate"),
        "the Edge half must still be served, and from the live Edge: {data}"
    );

    // ── (2) A node with NO peers at all: a TRUE measured ZERO ───────────────
    //
    // `with_signer_no_genesis_seed` is persist's test-only seam (#387): an
    // engine with the baked family deliberately skipped, so this zero is a real
    // measurement of an empty directory rather than an artefact.
    let empty = Arc::new(
        Engine::with_signer_no_genesis_seed(
            Arc::new(LocalSigner::from_parts(
                SigningKey::from_bytes(&[0xE4; 32]),
                "node-no-peers".to_string(),
                None,
                None,
            )),
            "sqlite::memory:",
        )
        .await
        .expect("Engine::with_signer_no_genesis_seed"),
    );
    let edge = edge_over(&empty, "edge-no-peers", 0x42).await;
    let empty_data = federation_identity(Arc::clone(&empty), edge).await;
    assert_eq!(
        empty_data["peer_counts_standing"],
        serde_json::json!("measured"),
        "an empty directory that ANSWERED is a measurement: {empty_data}"
    );
    assert_eq!(empty_data["peer_count_total"], serde_json::json!(0));

    // ── (3) A node that cannot resolve its own identity: the SAME zero ──────
    let blind = blind_engine().await;
    let edge = edge_over(&blind, "edge-blind", 0x43).await;
    let blind_data = federation_identity(Arc::clone(&blind), edge).await;
    assert_eq!(
        blind_data["peer_counts_standing"],
        serde_json::json!("self_identity_unresolved"),
        "there is no `self` to count peers relative to, and that is not the same fact as having \
         none: {blind_data}"
    );
    assert_eq!(blind_data["peer_count_total"], serde_json::json!(0));
    assert!(
        baked > 0,
        "the blind engine carries the same baked genesis family as the baseline, so its zero is \
         not merely unexplained — it is WRONG about {baked} real peers"
    );

    // ── THE DISCRIMINATION ──────────────────────────────────────────────────
    assert_eq!(
        blind_data["peer_count_total"], empty_data["peer_count_total"],
        "the fixtures MUST render identical counts, or this proves nothing about the counter being \
         insufficient"
    );
    assert_ne!(
        blind_data["peer_counts_standing"], empty_data["peer_counts_standing"],
        "same zero, opposite meanings — without the standing this route answers `200 {{\"peers\": \
         [], \"total\": 0}}` for a node that does not know who it is, which is the 2026-08-05 \
         false clean with a different subject"
    );
    assert_ne!(
        blind_data["peer_counts_standing"],
        serde_json::json!("store_unavailable"),
        "and it is not the store's fault either — three conditions, three tokens"
    );
    // The token is the one `self_identity` publishes, not a restatement.
    assert_eq!(
        blind_data["peer_counts_standing"],
        serde_json::json!(ciris_server::self_identity::REFUSAL_TOKEN),
        "one source for the token, or two surfaces will drift apart naming one condition"
    );
}
