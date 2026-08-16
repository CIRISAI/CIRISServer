//! **The scrubber the agent actually gets** (CIRISServer#418).
//!
//! `EgressScrubber` was wired into this crate's two Rust ingest paths in
//! 0.5.173. The agent uses neither: it constructs persist's `Engine` from
//! Python, and that constructor takes `scrubber: Option<callable>` defaulting to
//! `NullScrubber`. So the node scrubbed nothing on the path it actually receives
//! traces over, and persist v32.1.0 turned the standing warning into a refusal:
//!
//! ```text
//! RuntimeError: engine.receive_and_persist: ValueError:
//!   ('scrub_treatment_mismatch', 'label=full_traces treated_as=full_traces')
//! ```
//!
//! Ten occurrences in one staged QA run, zero traces persisted.
//!
//! Two `Engine` construction sites; 0.5.173 fixed one. The break carries NO
//! signature change anywhere — which is why comparing the API surface across the
//! bump came back clean, and why only running it caught this.
//!
//! These pin the contract [`ciris_server::scrub::scrub_envelope_json`] must meet
//! for persist's `PyCallableScrubber` to accept its output at all.
//!
//! # The constraint that was lifted (persist v32.3.0, CIRISPersist#701)
//!
//! Under v32.1.0 a Python scrubber could not perform #690's own sanctioned
//! remedy — treat `full_traces` content at `detailed` and relabel — because the
//! preservation gate rejected any `trace_level` edit and `applied_trace_level`
//! was then read back off the unchanged envelope. We reported that; v32.3.0
//! lets the callable STATE its treated level as a fifth tuple element,
//! downgrade-only, and persist performs the relabel.
//!
//! So the split these now pin is: the ENVELOPE keeps the incoming batch label
//! (the gate is as strict as ever), the EVENTS keep the downgraded level
//! (persist relabels only the batch, and the two must agree afterwards), and
//! the FIFTH ELEMENT carries the truth.

use ciris_server::scrub::scrub_envelope_json;

/// A minimal batch envelope at the given level, carrying one trace with a field
/// the scrub catalog redacts.
fn envelope(level: &str) -> String {
    serde_json::json!({
        "events": [{
            "event_type": "complete_trace",
            "trace_level": level,
            "trace": {
                "trace_id": "t-418-python-door",
                "thought_id": "th-1",
                "agent_id_hash": "agent-abc",
                "started_at": "2026-08-14T12:00:00Z",
                "completed_at": "2026-08-14T12:00:01Z",
                "trace_level": level,
                "trace_schema_version": "1.0.0",
                "cohort_scope": "federation",
                "signature": "",
                "signature_key_id": "test",
                "components": [{
                    "component_type": "observation",
                    "event_type": "thought_start",
                    "timestamp": "2026-08-14T12:00:00Z",
                    "data": {
                        "thought_content": "reach me at alice@example.com or 555-12-9999",
                    }
                }]
            }
        }],
        "batch_timestamp": "2026-08-14T12:00:00Z",
        "consent_timestamp": "2026-08-14T12:00:00Z",
        "trace_level": level,
        "trace_schema_version": "1.0.0",
    })
    .to_string()
}

/// **The level must come back exactly as it went in.**
///
/// persist re-reads the envelope after the callable returns and refuses any
/// scrubber that moved `trace_level`:
///
/// ```text
/// scrubber altered trace_level — rejected
/// ```
///
/// It then derives `applied_trace_level` from that unchanged envelope. So the
/// downgrade the Rust path performs — `FullTraces` without a model becomes
/// `Detailed`, label rewritten to match — is structurally unavailable here.
/// Performing it anyway would trade persist's documented refusal for a vaguer
/// one, on every batch.
#[test]
fn the_level_is_never_relabelled_on_the_python_path() {
    for level in ["generic", "detailed", "full_traces"] {
        let (out, _, _, _, _) = scrub_envelope_json(&envelope(level)).expect("scrub");
        let v: serde_json::Value = serde_json::from_str(&out).expect("json");

        assert_eq!(
            v["trace_level"], level,
            "batch trace_level was rewritten {level} -> {}. persist's PyCallableScrubber \
             rejects a callable that alters trace_level, so this turns every batch into \
             `scrubber altered trace_level — rejected`.",
            v["trace_level"]
        );
    }
}

/// **The declared level is the treated level, and it may only go down.**
///
/// persist relabels the batch to whatever the fifth element says, refusing any
/// value that RAISES the level — "a scrubber may REDUCE the level it treated
/// content at, never raise it", because raising would let a callable launder a
/// `detailed` pass into a `full_traces` label.
#[test]
fn the_declared_level_never_exceeds_the_label() {
    let rank = |l: &str| match l {
        "generic" => 0,
        "detailed" => 1,
        "full_traces" => 2,
        other => panic!("unknown level {other}"),
    };
    for level in ["generic", "detailed", "full_traces"] {
        let (_, _, ner_ran, _, applied) = scrub_envelope_json(&envelope(level)).expect("scrub");
        assert!(
            rank(&applied) <= rank(level),
            "declared applied_trace_level `{applied}` is HIGHER than the label `{level}`. \
             persist refuses that outright, and it is the direction that matters: it would \
             claim the content got more treatment than it did."
        );
        if level == "full_traces" && !ner_ran {
            assert_eq!(
                applied, "detailed",
                "no NER pass ran on a `full_traces` batch, so the treated level must be \
                 declared as `detailed` — that declaration IS the remedy #690 asks for, and \
                 CIRISPersist#701 is what made it reachable from Python. Declaring \
                 `full_traces` here is the refusal all over again."
            );
        }
    }
}

/// **`ner_ran` must be the truth, and must not be inferred from a count.**
///
/// It is the single fact persist's refusal turns on:
///
/// ```rust,ignore
/// if scrub_outcome.applied_trace_level == TraceLevel::FullTraces.as_str()
///     && !scrub_outcome.ner_ran
/// ```
///
/// persist's 2-tuple fallback reports `ner_ran: false` precisely because a
/// nonzero modified-count says fields changed, never that a named-entity pass
/// ran — treating one as the other would manufacture the evidence #690 exists to
/// demand. So this door must return the 4-tuple, and its third element must
/// track `ner::is_configured()` rather than the redaction count.
#[test]
fn ner_ran_tracks_the_model_not_the_edit_count() {
    let (_, modified, ner_ran, digest, _) =
        scrub_envelope_json(&envelope("full_traces")).expect("scrub");

    let configured = ciris_persist::pipeline::scrub::ner::is_configured();
    assert_eq!(
        ner_ran, configured,
        "ner_ran ({ner_ran}) disagrees with whether a model is loaded ({configured}). \
         This is the value persist's ScrubTreatmentMismatch turns on: claiming true \
         without a model asserts a treatment the content never received, and claiming \
         false with one refuses a batch that was properly scrubbed."
    );
    if !configured {
        assert!(
            !ner_ran,
            "no model is loaded, yet ner_ran is true — {modified} fields were modified, \
             and a modification count is not evidence of a named-entity pass."
        );
    }
    assert!(
        digest.is_none(),
        "a model digest was reported. persist exposes `ner::is_configured()` but nothing \
         identifying WHICH model answered, so there is no honest value here — and \
         inventing one defeats the field's purpose, which is telling a receiver what \
         instrument ran."
    );
}

/// **Content is actually redacted — the point of wiring anything at all.**
///
/// `NullScrubber` returns `fields_modified: 0` having touched nothing, and at
/// `detailed` (what production runs) persist accepts that batch. So the silent
/// failure was never the refusal — it was every `detailed` batch federating
/// unredacted while a warning scrolled past.
#[test]
fn detailed_actually_redacts_where_nullscrubber_passed_content_through() {
    let (out, modified, _, _, _) = scrub_envelope_json(&envelope("detailed")).expect("scrub");

    assert!(
        modified > 0,
        "nothing was redacted at `detailed`. That is NullScrubber's behaviour, and it is \
         accepted by persist — no refusal, no signal, content federated as written."
    );
    assert!(
        !out.contains("alice@example.com"),
        "the address survived the scrub. This is the leak the refusal drew attention to, \
         and the one that was live on every detailed batch:\n{out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The role boundary, and the assumption that makes the Engine-level scrubber safe
// ─────────────────────────────────────────────────────────────────────────────

/// **The relay must pass its scrubber EXPLICITLY, never inherit one.**
///
/// Capture and relay want opposite things, and `COHABITATION.md` is explicit
/// about why:
///
/// > Scrubbing is the originating client node's egress-filter responsibility
/// > […] inter-node federation traffic is post-egress-filter by contract.
///
/// So `LensCoreHandler` passes `NullScrubber` **deliberately**. Re-scrubbing at
/// relays causes NER-version content drift across the federation — the same
/// trace stored differently at relays running different NER versions — and
/// demands models relays are not provisioned with. Capture is the privacy
/// boundary; relay is not. Anyone "fixing" that `NullScrubber` to match the
/// capture path breaks the contract.
///
/// # Why this is a test and not a comment
///
/// `Engine(scrubber=egress_scrub)` sets an ENGINE-LEVEL default, because
/// persist's Python `receive_and_persist(body, pre_verified)` takes no scrubber
/// argument — the Engine field is the only lever Python has. That is safe today
/// for exactly one reason: **no relay path goes through Python.** The relay is
/// Rust and names its scrubber at the call site, so the Engine default cannot
/// reach it.
///
/// That is an assumption, not a guarantee, and it is invisible at the place it
/// would be violated. Route relay traffic through the Python API — or drop the
/// explicit argument here — and every relayed batch silently starts being
/// re-scrubbed, producing precisely the drift the contract forbids. Nothing
/// would fail; the corpus would just diverge across the federation.
///
/// So this pins the load-bearing half: **no relay path reaches persist through
/// Python.** The Rust signature already forces an explicit scrubber argument at
/// the relay — asserting that would only restate a compiler guarantee. What the
/// compiler cannot see is a relay routed through `engine.receive_and_persist`
/// on the Python side, which takes no scrubber and would inherit ours.
#[test]
fn no_relay_path_reaches_persist_through_python() {
    let role =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/ciris-lens-core/src/role");
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    walk(&role, &mut files);
    assert!(
        !files.is_empty(),
        "no sources under {} — the relay moved, so this gate is measuring nothing. \
         A zero denominator is the error, not a pass.",
        role.display()
    );

    // The Python-call shapes that would inherit the Engine-level scrubber.
    // SPLIT so this predicate cannot match itself.
    let verb = format!("{}_and_persist", "receive");
    let mut offenders = Vec::new();
    for f in &files {
        let Ok(src) = std::fs::read_to_string(f) else {
            continue;
        };
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") {
                continue;
            }
            let py_call = line.contains("call_method") && line.contains(verb.as_str());
            if py_call {
                offenders.push(format!("  {}:{}  {}", f.display(), i + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "\nA RELAY REACHES PERSIST THROUGH PYTHON.\n\n{}\n\n\
         persist's Python `receive_and_persist(body, pre_verified)` takes NO scrubber \
         argument — it uses the ENGINE-level one. A composed node sets that to \
         `egress_scrub` so the CAPTURE path redacts (CIRISServer#418), so a relay routed \
         this way would silently start re-scrubbing relayed traffic.\n\n\
         That is the drift COHABITATION.md forbids: the same trace stored differently at \
         relays running different NER versions, and models relays are not provisioned \
         with. Nothing would fail — the corpus would just diverge across the \
         federation.\n\n\
         Relay through the RUST API and name the scrubber (`&NullScrubber`), as \
         `handler.rs` does.\n",
        offenders.join("\n")
    );
}
