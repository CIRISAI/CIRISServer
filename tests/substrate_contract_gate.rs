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
//!
//! # v31.1.0 re-pin — the 15th wire kind (reviewed 2026-08-14)
//!
//! Both hashes moved for ONE coherent addition, verified by diffing persist
//! v31.0.0 → v31.1.0 rather than by trusting the bump:
//!
//! `EnvelopeKind::AccordQuorumEvidence` joins the wire vocabulary (14 → 15),
//! admitted by `QuorumFromOwnDirectory` + `StewardRosterFromDirectory`, and
//! projecting to a new `RoleWithdrawals` plane. `consent_grammar` places it on
//! the `StructuralPlane`.
//!
//! That is CIRISPersist#662's fix, and it is the replicate-evidence rule made
//! concrete: `federation_role_withdrawals` rows carry NO signature columns, so
//! shipping them would be a derived verdict asking the receiver to trust the
//! sender. Instead the SIGNED accord quorum evidence travels and each receiver
//! re-derives the withdrawal from its own directory.
//!
//! Impact on this server: none that changes behaviour. We never name an
//! `EnvelopeKind` variant in `src/` (only edge's re-export, in a test), so the
//! new kind cannot break an exhaustive match, and we neither produce nor consume
//! `AccordQuorumEvidence`. What it does mean is that a node will now SEE this
//! kind on the wire, which is the point — it is how a de-canonicalisation
//! reaches us at all.

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
    "b66870da9639c8560538a26c566168fea9759139eaa67ad4116ff8a5f290d69f";

// ─────────────────────────── persist: transform algebra ────────────────────

/// persist v21 (`ciris_persist::federation::transform`) — the projection
/// transform-algebra manifest hash (opcode set + arities + live/declared
/// status). Flips when a projection opcode is added/changed (CIRISPersist#519).
/// A silent change would alter how records are reduced when fanned out to a
/// peer → deliberate re-pin only.
const RATIFIED_TRANSFORM_ALGEBRA_HASH: &str =
    "b7bd779468f4ad1ab551a5fd2dc0392df01e6f2e0ed393f924a806ed49686b4b";

// ─────────────────────────── persist: envelope vocabulary ──────────────────

/// persist v36.1.0 (`ciris_persist::federation::envelope`) — the wire
/// envelope-vocabulary hash (the EnvelopeKind names + their claim shape).
/// Flips when a wire kind is added/renamed/reshaped. A silent change would
/// desync producers and readers across the triple → reviewed re-pin only.
///
/// Re-pinned at the v36 adopt: v36.0.0 (#642) added `consent_supersedes` to the
/// signed envelope, making consent ordering CAUSAL instead of resting on a
/// producer-chosen wall clock. Reviewed and accepted — the key lives only inside
/// the signed envelope, so it has no unsigned column twin to diverge from, which
/// is why persist shipped it with no migration.
const RATIFIED_ENVELOPE_VOCABULARY_SHA256: &str =
    "e7135559a3d843ecff3ad34ee3b1a10acf92b33f199a327758139969e19f5699";

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

/// The README states the substrate pins, and the README **is** the public site
/// (`https://cirisai.github.io/CIRISServer/` renders `main:/README.md`). So a
/// stale line there is a wrong answer served to everyone who asks what this node
/// runs on.
///
/// It had drifted to `persist v21.4.0 / edge v14.4.0` while the tree was on
/// v24.1.0 / v15.7.1 — three majors on persist. Nothing noticed, because a
/// human-written sentence and a machine-read manifest are two lists of the same
/// fact maintained separately, which is the defect class this project keeps
/// paying for.
///
/// Asserted against `Cargo.toml` rather than a literal, so the gate tracks the
/// pin instead of freezing a third copy of it.
#[test]
fn readme_substrate_pins_match_cargo_toml() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo = std::fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let readme = std::fs::read_to_string(root.join("README.md")).expect("read README.md");

    // The pin as the build actually resolves it.
    let pin_of = |repo: &str| -> String {
        let needle = format!("{repo}\", tag = \"");
        let i = cargo.find(&needle).unwrap_or_else(|| {
            panic!("no `{repo}` git tag pin found in Cargo.toml — did the dependency move?")
        }) + needle.len();
        cargo[i..]
            .split('"')
            .next()
            .expect("tag literal")
            .to_string()
    };

    for (repo, label) in [
        ("CIRISPersist", "persist"),
        ("CIRISEdge", "edge"),
        ("CIRISVerify", "verify"),
    ] {
        let pin = pin_of(repo);
        let claim = format!("{label} {pin}");
        assert!(
            readme.contains(&claim),
            "README.md does not state the real {label} pin.\n  Cargo.toml resolves: {pin}\n  \
             expected the README to contain: {claim:?}\n\n\
             README.md is served as the public site, so a stale pin there is a wrong answer \
             given to every reader. Update the Status section's substrate line."
        );
    }
}

// ───────────── redundancy.* : persist's CEILINGS vs edge's FLOORS ──────────

/// **The reconciliation neither substrate can perform, and both asked for.**
///
/// persist v30.0.0 (CIRISPersist#602) split `redundancy.*` into four typed keys
/// after two defects that a hand-transcription produced and nothing could see:
/// `redundancy.k_repair_target` carried `n_source`'s **20** under `k_repair`'s
/// name, and `redundancy.min_viable_floor`'s ceiling of **3** sat *below* the
/// consumer's floor of **5** — under ceiling semantics (roots may only tighten)
/// that made the knob **unsatisfiable**: no root could configure the planner to
/// a value the planner itself considers viable.
///
/// Both substrates then said, in their own words, that the fix is incomplete
/// from where they stand:
///
/// - persist's own `CONSUMER_FLOORS` table hand-records edge's constants — *"the
///   same transcription that produced the bug"* — and is **blind to edge raising
///   a floor past our ceiling**. It is a ratchet, not a reconciliation.
/// - edge v15.18.0 (CIRISEdge#453) closed the half only edge can close: it EMITS
///   the five planner constants from the same `pub const`s the planner runs on
///   ([`fountain_floor_manifest`](ciris_edge::holonomic::fountain_defaults::fountain_floor_manifest)),
///   byte-locked to `evidence/CIRISEdge.fountain_floors.json` by its own drift
///   test. It cannot see persist's registry.
///
/// **This build links both**, so it is the only place the two halves meet. The
/// gate reads persist's `MeshConfigKey::spec()` and calls edge's emitter — no
/// number is written down here — and fails in **either** direction:
///
/// 1. a persist ceiling BELOW edge's operating value ⇒ the unsatisfiable-knob
///    defect #602 fixed, recurring;
/// 2. edge raising a floor past a persist ceiling ⇒ the direction persist states
///    it cannot detect;
/// 3. a redundancy key whose axis has no counterpart in the manifest ⇒ the
///    axis-fusion defect returning under a new name.
///
/// It reads persist's numbers as CEILINGS and edge's as the operating values,
/// which is persist's own instruction: *"do not treat persist's redundancy
/// defaults as authoritative about what edge's planner will do."*
///
/// **Mutation-verified** in both directions: adding 1000 to every floor read
/// turns arm 1 red naming `redundancy.k_repair_symbols`; deleting an `AXIS` row
/// turns arm 3 red naming the unreconciled key.
#[test]
fn persist_redundancy_ceilings_clear_edges_emitted_floors() {
    use ciris_persist::federation::{MeshConfigKey, MeshConfigUnit};

    let manifest = ciris_edge::holonomic::fountain_defaults::fountain_floor_manifest();
    assert_eq!(
        manifest["schema_version"], 1,
        "edge's floor-manifest SHAPE changed (CIRISEdge#453 versions the shape, not the values) \
         — re-read the emitter before trusting the paths below"
    );
    // persist's registry names the consumer; edge's manifest names itself. If
    // they ever disagree, this gate is reconciling two different processors.
    assert_eq!(
        manifest["consumer"], "repair_planner",
        "edge's manifest names a different consumer than persist's registry does"
    );

    /// Where each registered key's operating value lives in edge's manifest.
    /// The `knob` name is persist's own (`MeshConfigKeySpec::knob`), so this
    /// table maps NAME→PATH and carries no numbers — the two things that can
    /// drift are both read, never restated.
    const AXIS: &[(&str, &str, &str)] = &[
        ("redundancy.k_repair_symbols", "symbols", "k_repair"),
        ("redundancy.min_viable_symbols", "symbols", "min_viable"),
        ("redundancy.target_holders", "holders", "target"),
        ("redundancy.min_viable_holders", "holders", "min_viable"),
    ];

    let mut checked = 0usize;
    for &key in MeshConfigKey::ALL {
        let spec = key.spec();
        if !spec.wire_name.starts_with("redundancy.") {
            continue;
        }
        // The axis must be TYPED — `Count` is the fusion #602 removed, and a
        // redundancy key wearing it again means the split was undone.
        assert!(
            matches!(spec.unit, MeshConfigUnit::Symbols | MeshConfigUnit::Holders),
            "`{}` is a redundancy knob typed `{}`; every one counts either fountain symbols or \
             distinct holders",
            spec.wire_name,
            spec.unit.as_str()
        );
        let Some(&(_, group, leaf)) = AXIS.iter().find(|(w, _, _)| *w == spec.wire_name) else {
            panic!(
                "persist registers `{}` and this gate has no path into edge's manifest for it. A \
                 redundancy knob with no reconciled consumer value is exactly how \
                 `k_repair_target` came to carry `n_source`'s 20.",
                spec.wire_name
            );
        };
        // The group and the unit are two statements of one fact.
        assert_eq!(
            group == "symbols",
            spec.unit == MeshConfigUnit::Symbols,
            "`{}` is typed `{}` but this gate reconciles it against the manifest's `{group}` \
             group — the axis and the source must agree",
            spec.wire_name,
            spec.unit.as_str()
        );
        let floor = manifest[group][leaf].as_i64().unwrap_or_else(|| {
            panic!(
                "edge's manifest has no integer at {group}.{leaf} — the emitter moved and this \
                 gate is reading nothing"
            )
        });

        assert!(
            spec.owner_default >= floor,
            "`{}` consent CEILING is {} but edge's planner runs {floor} ({group}.{leaf}). \
             owner_default is a ceiling and roots may only tighten beneath it, so NO root can \
             configure the planner to a value it considers viable — an unsatisfiable knob, which \
             is worse than a wrong default because no operator action reaches the intended state. \
             This is CIRISPersist#602's second defect, and the direction persist's own \
             CONSUMER_FLOORS table cannot see (it is blind to edge raising a floor).",
            spec.wire_name,
            spec.owner_default
        );
        assert!(
            spec.max >= floor && spec.min <= floor,
            "`{}` domain is [{}, {}] but edge's planner runs {floor} — the operating value is not \
             even expressible on the wire.",
            spec.wire_name,
            spec.min,
            spec.max
        );
        checked += 1;
    }

    // Non-vacuity. A gate that reconciles nothing passes forever; this repo has
    // shipped five of those this week.
    assert_eq!(
        checked,
        AXIS.len(),
        "expected to reconcile {} redundancy keys against edge's manifest, reconciled {checked}",
        AXIS.len()
    );
}
