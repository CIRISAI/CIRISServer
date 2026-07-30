//! Cross-repo substrate contract drift gate (CIRISServer#327 §0).
//!
//! Companion to `tests/replication_policy_gate.rs`. That file already pins the
//! two REPLICATION-plane manifests — persist's `REPLICATION_POLICY_HASH` (APPLY
//! authority) and edge's `SERVE_ADVERTISE_POLICY_HASH` (responder half) — so
//! they are deliberately NOT re-pinned here (single source of truth; see the
//! `already_pinned_elsewhere` note at the bottom).
//!
//! This file pins the REMAINING substrate contract hashes the server consumes,
//! each exported by the substrate crate as a by-construction, self-witnessed
//! manifest hash (the same "computed == pinned" loud-drift discipline as
//! [`ciris_edge::WIRE_VOCABULARY_HASH`]). The server is a downstream consumer of
//! all of them, so it pins the current literal here: any change to a substrate
//! contract flips its hash → this build fails → the change cannot ride a
//! substrate bump into the server silently. Re-pinning is a deliberate, reviewed
//! act that travels WITH the persist/edge version bump — never a quiet edit.
//!
//! Pinned against persist v21.10.0 (`cf345df`) + edge v15.0.0 (`5c03230`).

// ─────────────────────────── persist: namespace-superset manifest ──────────

/// persist v21 (`ciris_persist::federation::namespace::supersets`) — the
/// vendored namespace-superset manifest version (`_meta.manifest_version`).
/// Bumps when persist re-vendors a new CEG walk (CIRISPersist#519 adoption).
/// A change here means the whole 95-family superset manifest was re-cut —
/// every downstream card/projection derives from it, so it is a deliberate cut,
/// never accidental skew.
const RATIFIED_VENDORED_MANIFEST_VERSION: &str = "0.3.0";

// ─────────────────────────── persist: consent grammar ──────────────────────

/// persist v21 (`ciris_persist::federation::consent_grammar`) — the consent
/// wire-grammar manifest hash. Flips when the set/shape of consent grant
/// dimensions changes (which cohorts route which kinds). A silent change would
/// re-scope who may replicate what → this must be a reviewed re-pin.
const RATIFIED_CONSENT_GRAMMAR_HASH: &str =
    "2064b567c60062fe9583ea983224d977db7440c8d240d6902a2db50e3e157d05";

// ─────────────────────────── persist: transform algebra ────────────────────

/// persist v21 (`ciris_persist::federation::transform`) — the projection
/// transform-algebra manifest hash (opcode set + arities + live/declared
/// status). Flips when a projection opcode is added/changed (CIRISPersist#519).
/// A silent change would alter how records are reduced when fanned out to a
/// peer → deliberate re-pin only.
const RATIFIED_TRANSFORM_ALGEBRA_HASH: &str =
    "b7bd779468f4ad1ab551a5fd2dc0392df01e6f2e0ed393f924a806ed49686b4b";

// ─────────────────────────── persist: envelope vocabulary ──────────────────

/// persist v21 (`ciris_persist::federation::envelope`) — the wire
/// envelope-vocabulary hash (the 14 EnvelopeKind names + their claim shape).
/// Flips when a wire kind is added/renamed/reshaped. A silent change would
/// desync producers and readers across the triple → reviewed re-pin only.
const RATIFIED_ENVELOPE_VOCABULARY_SHA256: &str =
    "f1a0bc77d24915fc1e099c4715621c936ca4fb38678b71268b88a9d614c04929";

// ─────────────────────────── persist: trace-summary extraction ─────────────

/// persist v21 (`ciris_persist::trace_summary_contract`) — the pinned
/// trace-summary feature-vector extraction contract hash
/// (CIRISPersist#494/v19.2.0). Flips when the extracted trace-summary field set
/// changes. The server serves this on `/v1/health` (wired by a separate agent);
/// pinning it HERE and serving it there are distinct concerns — this pin
/// guarantees the value the health endpoint reports is the one the build was
/// compiled against. A silent change would skew the scorer's raw input → a
/// reviewed re-pin only.
const RATIFIED_TRACE_SUMMARY_EXTRACTION_SHA256: &str =
    "f4dfea6e8e8e3f11d2abd22cb4dd5adbe15cf662246b7f90fbcfd0bb9cf5b76d";

#[test]
fn persist_vendored_manifest_version_pinned() {
    assert_eq!(
        ciris_persist::federation::namespace::supersets::VENDORED_MANIFEST_VERSION,
        RATIFIED_VENDORED_MANIFEST_VERSION,
        "persist re-vendored the namespace-superset manifest (a new CEG walk) — \
         the whole 95-family superset set was re-cut. Reconcile the in-repo \
         FSD/namespace_supersets.json (see manifest_version_coherent_with_repo) \
         and re-pin deliberately with the substrate bump (CIRISServer#327 §0, \
         CIRISPersist#519).",
    );
}

#[test]
fn persist_consent_grammar_hash_pinned() {
    assert_eq!(
        ciris_persist::federation::consent_grammar::CONSENT_GRAMMAR_HASH,
        RATIFIED_CONSENT_GRAMMAR_HASH,
        "persist's consent grammar drifted — a change to the consent grant \
         dimensions (which cohorts may route which kinds). Re-scoping who may \
         replicate what is never accidental: reconcile and re-pin deliberately \
         (CIRISServer#327 §0).",
    );
}

#[test]
fn persist_transform_algebra_hash_pinned() {
    assert_eq!(
        ciris_persist::federation::transform::TRANSFORM_ALGEBRA_HASH,
        RATIFIED_TRANSFORM_ALGEBRA_HASH,
        "persist's projection transform algebra drifted — an opcode was \
         added/changed (arity or live/declared status), altering how records \
         are reduced when fanned out to a peer. Re-pin deliberately with the \
         substrate bump (CIRISServer#327 §0, CIRISPersist#519).",
    );
}

#[test]
fn persist_envelope_vocabulary_hash_pinned() {
    assert_eq!(
        ciris_persist::federation::envelope::ENVELOPE_VOCABULARY_SHA256,
        RATIFIED_ENVELOPE_VOCABULARY_SHA256,
        "persist's wire envelope vocabulary drifted — an EnvelopeKind was \
         added/renamed/reshaped. A silent change desyncs producers and readers \
         across the server/edge/agent triple. Re-pin deliberately with the \
         substrate bump (CIRISServer#327 §0).",
    );
}

#[test]
fn persist_trace_summary_extraction_hash_pinned() {
    assert_eq!(
        ciris_persist::trace_summary_contract::TRACE_SUMMARY_EXTRACTION_SHA256,
        RATIFIED_TRACE_SUMMARY_EXTRACTION_SHA256,
        "persist's trace-summary extraction contract drifted — the extracted \
         feature-vector field set changed. This is the value the server reports \
         on /v1/health and the scorer's raw input; a silent change skews N_eff. \
         Re-pin deliberately with the substrate bump (CIRISServer#327 §0, \
         CIRISPersist#494).",
    );
}

/// Coherence: the manifest persist vendors (`VENDORED_MANIFEST_VERSION`) MUST
/// match the copy checked into this repo at `FSD/namespace_supersets.json`
/// (`_meta.manifest_version`). Persist DOES vendor the manifest (it
/// `include_str!`s `namespace_supersets.json` and exports the version const), so
/// this asserts the server's in-repo copy has not fallen behind the substrate's
/// — a mismatch means the FSD copy is stale relative to persist v21.10.0 and
/// must be re-vendored before the bump can land (CIRISServer#327 §0).
#[test]
fn manifest_version_coherent_with_repo() {
    let repo_manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/FSD/namespace_supersets.json");
    let raw = std::fs::read_to_string(repo_manifest_path)
        .expect("in-repo FSD/namespace_supersets.json must exist");
    let doc: serde_json::Value =
        serde_json::from_str(&raw).expect("FSD/namespace_supersets.json must be valid JSON");
    let repo_version = doc
        .get("_meta")
        .and_then(|m| m.get("manifest_version"))
        .and_then(|v| v.as_str())
        .expect("FSD/namespace_supersets.json must carry _meta.manifest_version");

    assert_eq!(
        repo_version,
        ciris_persist::federation::namespace::supersets::VENDORED_MANIFEST_VERSION,
        "the in-repo FSD/namespace_supersets.json (_meta.manifest_version = {repo_version}) \
         has drifted from persist's vendored VENDORED_MANIFEST_VERSION. Re-vendor the FSD \
         copy from persist v21.10.0 before landing the substrate bump (CIRISServer#327 §0).",
    );
}

// ─────────────────────────── already pinned elsewhere ──────────────────────
//
// Two substrate contracts named by CIRISServer#327 §0 are intentionally NOT
// re-pinned here because `tests/replication_policy_gate.rs` already owns them
// (single source of truth):
//   - persist  `REPLICATION_POLICY_HASH`      → replication_policy_gate::persist_replication_policy_hash_pinned
//   - edge     `SERVE_ADVERTISE_POLICY_HASH`  → replication_policy_gate::edge_serve_advertise_policy_hash_pinned  (CIRISServer#320)
// A compile-time reference keeps this note honest: if either const is renamed
// or removed upstream, THIS file also fails to compile, forcing reconciliation.
#[test]
fn already_pinned_elsewhere_still_exist() {
    // Not re-asserting the literals (that is replication_policy_gate.rs's job);
    // only witnessing the symbols still resolve at the paths #327 §0 names, so a
    // silent upstream rename can't leave the split-out pins orphaned.
    let _ = ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH;
    let _ = ciris_edge::replication::serve_policy::SERVE_ADVERTISE_POLICY_HASH;
}
