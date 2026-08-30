//! **The row and its envelope have ONE author** (CIRISServer#402).
//!
//! # The class
//!
//! An attestation is two things that must agree: the typed COLUMNS the store
//! orders and joins on, and the signed ENVELOPE the mesh verifies. When those are
//! built by two pieces of code, their agreement is a property nobody wrote down —
//! and this repo built them separately at seven sites for most of its life.
//!
//! persist v31 started checking that agreement at every door, and found FOUR
//! violations in the owner-binding path alone, each surfacing as a 500 on a live
//! first-run claim, each looking like its own small bug:
//!
//! | gate | what diverged |
//! |------|---------------|
//! | CIRISPersist#659 | the registration envelope did not name its subject |
//! | CIRISPersist#598 | the `asserted_at` column was a second clock read |
//! | CIRISPersist#598 | that instant carried sub-microsecond precision postgres cannot store |
//! | CIRISPersist#643 | the envelope carried no mirror of the seven typed columns |
//!
//! # What this file does about it
//!
//! Two kinds of test, because either alone is worth much less than the pair:
//!
//! - **Structural** — no code outside `src/attest.rs` builds an `Attestation`.
//!   This is a grep, and a grep is a poor substitute for a type; what it buys is
//!   that the NEXT hand-rolled row fails here rather than in front of an operator
//!   mid-ceremony. `src/attest.rs` is a private-by-convention door, not a
//!   compiler-enforced one, so the convention needs a gate.
//!
//! - **Mutational** — take a row minted through that door, break each bound field
//!   in turn, and require the substrate to REFUSE it. This is what makes the
//!   structural test mean something: it proves the properties are actually load
//!   bearing on this substrate version, so a future persist that quietly stopped
//!   checking one would be caught here instead of being discovered by a peer.
//!
//! # Why the control case is not decoration
//!
//! [`the_unmutated_row_is_accepted`] stores an untouched row and requires success.
//! Without it every mutation assertion could pass for a reason having nothing to
//! do with mutation — an unregistered key, a closed store, a fixture that never
//! satisfied the gate to begin with — and the file would report the class dead
//! while testing nothing. Each mutation also mints a FRESH row, so a refusal can
//! never be a duplicate-id conflict wearing a binding error's clothes.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{
    algorithm, attestation_type, cohort_scope, identity_type, Attestation, KeyRecord,
    SignedAttestation, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_server::attest::{Emit, Spec};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

// ─── Structural: one door ───────────────────────────────────────────────────

/// Files that may build an `Attestation` literal, and why.
///
/// The exemption is BY NAME with a reason, not a pattern, so adding one is a
/// decision on the record rather than a hole someone widened.
const EXEMPT: &[(&str, &str)] = &[
    (
        "src/attest.rs",
        "the door itself — the only place that assembles a row",
    ),
    (
        "src/admin_ops.rs",
        "read_admission_standing's PROBE: never signed, never stored, never leaves the \
         function. It exists to ask a persist predicate a question, and it deliberately carries \
         NO dimension (a probe bearing PEER_DEADMISSION_DIMENSION would take the exemption arm \
         and every key would read as admitted).",
    ),
];

fn repo_rust_files() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>, root: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out, root);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                // Normalized: a CRLF checkout otherwise breaks every `\n`-bearing
                // assertion, which has cost this repo three Windows-only CI failures.
                if let Ok(s) = std::fs::read_to_string(&p) {
                    out.push((rel, s.replace("\r\n", "\n")));
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    walk(&root.join("src"), &mut out, root);
    out
}

/// Strip `//` comments and doc comments — a comment naming the shape is not the
/// shape, and this file's own prose would otherwise trip its own gate.
fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Split a file at its first `#[cfg(test)]`. Everything after it is unit-test
/// scaffolding, which is exempt — but conditionally, see below.
fn split_at_cfg_test(code: &str) -> (&str, &str) {
    match code.find("#[cfg(test)]") {
        Some(i) => (&code[..i], &code[i..]),
        None => (code, ""),
    }
}

#[test]
fn nothing_outside_the_door_builds_a_row() {
    let mut offenders = Vec::new();
    for (path, body) in repo_rust_files() {
        if EXEMPT.iter().any(|(f, _)| *f == path) {
            continue;
        }
        let code = code_only(&body);
        let (shipping, _fixtures) = split_at_cfg_test(&code);
        for (n, line) in shipping.lines().enumerate() {
            // `-> Attestation {` is a return type, not a construction.
            //
            // `Plane::Attestation { dimension }` is persist v36's PLANE enum
            // variant (#713's per-dimension decomposition), not a row. It names
            // which plane `projection_for` should answer for; it allocates no
            // row, signs nothing and stores nothing, so #402's two-authors
            // hazard cannot arise from it. The token `Attestation {` now spells
            // two different things — the row struct and this variant — which is
            // this repo's own one-name-two-things class arriving inside a gate
            // written to catch it.
            //
            // Excluded by the PATH SEGMENT before it, not by a looser pattern:
            // only `Plane::Attestation` is skipped, so `federation::Attestation
            // {` and a bare `Attestation {` still offend. Exempting the FILE
            // instead — which this gate's failure message offers — would have
            // been the wrong lever: EXEMPT is file-scoped, so it would blind the
            // gate to every real row construction in `federation_delivery.rs`
            // forever, to silence one line that was never a row.
            let constructs = line.contains("Attestation {")
                && !line.contains("SignedAttestation {")
                && !line.contains("Plane::Attestation {")
                && !line.contains("->");
            if constructs {
                offenders.push(format!("{path}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these SHIPPING sites build an `Attestation` outside `crate::attest`:\n  {}\n\nEvery \
         such site is an instance of CIRISServer#402 — the row and its envelope built by two \
         authors and required to agree. persist v31 refuses four distinct ways they can disagree \
         and has more bindings coming; a hand-rolled row satisfies today's four by luck and \
         tomorrow's by nothing. Route it through `crate::attest::Emit` (stamp → sign → assemble), \
         or add it to EXEMPT here WITH THE REASON if it is genuinely never signed and never \
         stored.",
        offenders.join("\n  ")
    );
}

/// `#[cfg(test)]` fixtures may build rows — they feed READ predicates in memory,
/// and routing them through the door would make them prove the door works rather
/// than what they are actually testing.
///
/// That exemption is only safe while it stays read-only, so it is CHECKED rather
/// than trusted: a unit-test module that both hand-rolls a row and stores one is
/// asserting the substrate accepts a row this server does not produce, which is
/// exactly how four binding defects reached a live claim with every gate green.
#[test]
fn unit_test_fixtures_build_rows_but_never_store_them() {
    let mut offenders = Vec::new();
    for (path, body) in repo_rust_files() {
        if EXEMPT.iter().any(|(f, _)| *f == path) {
            continue;
        }
        let code = code_only(&body);
        let (_shipping, fixtures) = split_at_cfg_test(&code);
        let builds = fixtures.lines().any(|l| {
            l.contains("Attestation {") && !l.contains("SignedAttestation {") && !l.contains("->")
        });
        if builds && fixtures.contains("put_attestation") {
            offenders.push(path);
        }
    }
    assert!(
        offenders.is_empty(),
        "these `#[cfg(test)]` modules hand-roll an `Attestation` AND store one: {offenders:?}.\n\n\
         A fixture that only feeds an in-memory read predicate is fine — it is testing the \
         predicate. One that also puts is testing the substrate against a row this server never \
         produces, which is a green test for a shape nothing ships. Build it through \
         `crate::attest::Emit` (see `tests/one_author_per_row.rs` for the pattern), or drop the \
         store."
    );
}

/// The exemptions must stay honest: a file listed here must still contain the
/// literal it was exempted for. A stale exemption is a hole nobody can see.
#[test]
fn every_exemption_is_still_load_bearing() {
    let files = repo_rust_files();
    for (path, why) in EXEMPT {
        let Some((_, body)) = files.iter().find(|(p, _)| p == path) else {
            panic!("EXEMPT names {path}, which no longer exists — drop the exemption ({why})");
        };
        assert!(
            code_only(body).contains("Attestation {"),
            "EXEMPT names {path}, but it no longer builds an `Attestation` literal. Drop the \
             exemption: a stale one silently licenses the next hand-rolled row in that file.\n\
             (was exempted because: {why})"
        );
    }
}

/// The instant may not be sampled twice — on EITHER plane.
///
/// On the attestation plane `Emit` takes ONE `now`, hands it to persist's stamp,
/// and persist's `assemble` reads it back out of the signed envelope, so a clock
/// read between the stamp and the assemble would recreate CIRISPersist#598
/// exactly. On the key plane `register_key` stamps `valid_from` and
/// `scrub_timestamp` from one read for the same reason in miniature: two reads
/// would let a record's validity window and its scrub disagree about when it was
/// made, and nothing would ever say so.
#[test]
fn the_door_reads_one_clock_per_plane() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/attest.rs"),
    )
    .expect("read src/attest.rs")
    .replace("\r\n", "\n");
    let code = code_only(&src);
    // Split on the key-plane entry point itself, not on a banner comment —
    // `code_only` strips comments, so a comment landmark would silently become
    // "not found" and this gate would count one region twice.
    let split = code
        .find("pub async fn register_key")
        .expect("register_key moved — this gate would otherwise count the wrong region");
    for (plane, region) in [("attestation", &code[..split]), ("key", &code[split..])] {
        assert_eq!(
            region.matches("chrono::Utc::now()").count(),
            1,
            "the {plane} plane in `src/attest.rs` reads the clock {} times, not once. Every \
             extra read is a second author for one instant — the CIRISPersist#598 shape. \
             `Emit::stamp_at` exists so a caller that needs a specific instant supplies it \
             rather than adding a read here.",
            region.matches("chrono::Utc::now()").count(),
        );
    }
    assert!(
        !code.contains("crate::ids::new_id"),
        "`src/attest.rs` mints its own row id. The id comes out of the SIGNED mirror \
         (CIRISPersist#643) — an id minted here would be a second name for the row, sampled after \
         the bytes existed, which is #598's defect wearing #643's clothes."
    );
}

/// **No producer writes the signed instant, except the one that must.**
///
/// `stamp_and_canonicalize` honours a producer-set `asserted_at` instead of
/// overwriting it — deliberately, for the staged/co-signed case. The cost of that
/// courtesy is that a producer which sets it also owns TRUNCATING it, and a plain
/// `Utc::now().to_rfc3339()` carries nanoseconds postgres cannot store. Three
/// production paths did exactly that (config writes, replication consent, and the
/// ceremony), so on v31 every write on those paths was refused.
///
/// One producer legitimately sets it: [`scorer`] floors the instant to a
/// coalescing bucket so a re-measurement that has not moved produces
/// byte-identical envelope bytes. Being on a bucket boundary it is a whole number
/// of seconds, so it cannot carry sub-microsecond precision — which is why that
/// exemption is safe and why it is named here rather than pattern-matched.
#[test]
fn no_producer_writes_the_signed_instant_unbucketed() {
    /// (file, why) — producers allowed to set `asserted_at` in an envelope.
    const MAY_SET: &[(&str, &str)] = &[
        (
            "src/scorer.rs",
            "floors the instant to a coalescing bucket so an unchanged re-measurement \
             produces byte-identical bytes (SCORE_COALESCE_BASE). A bucket boundary is a whole \
             number of seconds, so it cannot carry sub-microsecond precision.",
        ),
        (
            "src/compose.rs",
            "a signed identity OCCURRENCE, not an attestation: it is produced by verify's \
             produce_signed_identity_occurrence and never reaches put_attestation, so the \
             instant-binding gate does not govern it. It is truncated to milliseconds anyway.",
        ),
    ];

    let mut offenders = Vec::new();
    for (path, body) in repo_rust_files() {
        if path == "src/attest.rs" || MAY_SET.iter().any(|(f, _)| *f == path) {
            continue;
        }
        let code = code_only(&body);
        let (shipping, _fixtures) = split_at_cfg_test(&code);
        for (n, line) in shipping.lines().enumerate() {
            // A WRITE looks like `"asserted_at": <expr>` inside a json! literal.
            // A READ looks like `.get("asserted_at")` or `row.asserted_at`, and a
            // RENDER puts a stored value into a response body — both fine.
            let writes = line.contains("\"asserted_at\":") && !line.contains(".asserted_at");
            if writes {
                offenders.push(format!("{path}:{}: {}", n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these producers write `asserted_at` into an envelope:\n  {}\n\nThe emit stamp writes \
         it — once, truncated to the substrate's resolution — and `assemble` reads the row \
         column back out of it. A producer-set value is HONOURED and NOT truncated, so a plain \
         `Utc::now()` here lands with nanoseconds postgres cannot store and every put on the \
         path is refused (CIRISPersist#598). Delete the field and let the stamp write it. If \
         this producer genuinely needs a chosen instant — a coalescing bucket, a staged row — \
         add it to MAY_SET with the reason AND make sure the value is truncated.",
        offenders.join("\n  ")
    );

    for (path, why) in MAY_SET {
        let (_, body) = repo_rust_files()
            .into_iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("MAY_SET names {path}, which no longer exists ({why})"));
        assert!(
            code_only(&body).contains("\"asserted_at\":"),
            "MAY_SET names {path}, but it no longer writes `asserted_at`. Drop the exemption — a \
             stale one licenses the next unbucketed producer in that file.\n(exempted because: \
             {why})"
        );
    }
}

// ─── Mutational: the properties are load bearing ────────────────────────────

const NODE: &str = "author-node";
const USER: &str = "author-user";

fn seed(tag: &str, salt: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    let d = Sha256::digest(format!("{tag}/{salt}").as_bytes());
    s.copy_from_slice(&d[..32]);
    s
}

fn signer_for(key_id: &str) -> LocalSigner {
    let ed = SigningKey::from_bytes(&seed(key_id, 1));
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&seed(key_id, 2), format!("{key_id}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        ed,
        key_id.to_string(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    )
}

/// Register `key_id` through the CANONICAL admission gate, with a registration
/// envelope that BINDS ITS SUBJECT (CIRISPersist#659) — built by persist's own
/// binder, not by a local re-spelling of what the binder does.
async fn register(engine: &Engine, signer: &LocalSigner, key_id: &str, ident: &str) {
    let mut envelope = serde_json::json!({ "key_id": key_id });
    // Sign an empty probe first purely to read the signer's public halves off the
    // produced signature — the same move the owner-binding path uses, so the keys
    // registered are exactly the keys that will sign.
    let probe = signer.sign_hybrid(b"probe").await.expect("probe sign");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        ident,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .expect("bind the subject into the registration envelope (#659)");

    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("canonicalize registration envelope");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: ed_pub,
        pubkey_ml_dsa_65_base64: Some(pqc_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: ident.to_string(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .register_federation_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("register {key_id} through the admission gate: {e}"));
}

/// A live substrate with both parties registered, plus the user's signer.
async fn fixture() -> (Arc<Engine>, LocalSigner) {
    let node_signer = signer_for(NODE);
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE)), "sqlite::memory:")
            .await
            .expect("Engine::with_signer(sqlite::memory:)"),
    );
    register(&engine, &node_signer, NODE, "node").await;
    let user_signer = signer_for(USER);
    register(&engine, &user_signer, USER, identity_type::USER).await;
    (engine, user_signer)
}

/// Mint a fresh, valid row through the ONE door. Fresh every call, so each
/// mutation below gets its own row id and no refusal can be a duplicate-key
/// conflict in disguise.
async fn fresh_row(user: &LocalSigner) -> Attestation {
    Emit::stamp(
        user.key_id(),
        Spec::new(
            attestation_type::DELEGATES_TO,
            cohort_scope::SELF,
            serde_json::json!({
                "kind": "delegates_to",
                "attesting_key_id": USER,
                "node_key_id": NODE,
                "scope": ["infra:serve"],
            }),
        )
        .about(NODE),
    )
    .expect("stamp")
    .sign_and_assemble(ciris_server::attest::KeySigner::Local(user))
    .await
    .expect("sign + assemble")
}

async fn put(engine: &Engine, row: Attestation) -> Result<(), String> {
    // See the note in `abuse_surface.rs`: this suite asserts on authorship
    // refusals, so the success variant is deliberately dropped.
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation: row })
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// **The control.** Without this, every refusal below could be a refusal for
/// reasons unrelated to mutation, and this file would certify a class dead while
/// proving nothing at all.
#[tokio::test]
async fn the_unmutated_row_is_accepted() {
    let (engine, user) = fixture().await;
    let row = fresh_row(&user).await;
    put(&engine, row).await.expect(
        "a row minted through `crate::attest` must be storable — if this fails the whole \
                 mutation suite below is green for the wrong reason",
    );
}

/// Every column bound into the signed mirror must be load bearing: change it on
/// the row and the substrate must refuse the row.
///
/// This is the test that would have caught all four v31 gates BEFORE the wheel
/// shipped, and it is the one that keeps catching a future persist that stops
/// enforcing one of them.
#[tokio::test]
async fn every_mirrored_column_is_load_bearing() {
    let (engine, user) = fixture().await;

    // (name, mutation) — one per member of the seven-column mirror.
    type Mutate = fn(&mut Attestation);
    let cases: &[(&str, Mutate)] = &[
        ("attestation_id", |r| {
            r.attestation_id = uuid::Uuid::new_v4().to_string();
        }),
        ("attesting_key_id", |r| {
            r.attesting_key_id = NODE.to_string();
        }),
        ("attestation_type", |r| {
            r.attestation_type = attestation_type::SCORES.to_string();
        }),
        ("attested_key_id", |r| {
            r.attested_key_id = USER.to_string();
        }),
        ("subject_key_ids", |r| {
            // The #658 authority-injection shape: APPEND a key in transit and it
            // gains revocation authority over someone else's row.
            r.subject_key_ids.push(USER.to_string());
        }),
        ("cohort_scope", |r| {
            // The audience widened in transit — `self` published to the federation.
            r.cohort_scope = cohort_scope::FEDERATION.to_string();
        }),
        ("weight", |r| {
            r.weight = Some(0.5);
        }),
        ("asserted_at", |r| {
            // CIRISPersist#598: the column that decides which claim wins a fold.
            r.asserted_at += chrono::Duration::seconds(1);
        }),
    ];

    for (name, mutate) in cases {
        let mut row = fresh_row(&user).await;
        mutate(&mut row);
        let outcome = put(&engine, row).await;
        assert!(
            outcome.is_err(),
            "mutating `{name}` on a signed row was ACCEPTED. That column is not bound to the \
             signed envelope on this substrate, which means a relay can rewrite it while the \
             producer's signature still verifies — the signature-preserving attack \
             CIRISPersist#643 exists to stop. Either persist stopped enforcing the binding, or \
             this fixture stopped exercising it."
        );
    }
}

/// The mirror itself must be REQUIRED, not merely checked when present. A row
/// whose envelope carries no mirror is the pre-#643 shape, and admitting it would
/// make every assertion above bypassable by deletion rather than by forgery.
#[tokio::test]
async fn a_row_with_no_mirror_is_refused() {
    let (engine, user) = fixture().await;
    let mut row = fresh_row(&user).await;
    row.attestation_envelope
        .as_object_mut()
        .expect("envelope is an object")
        .remove(ciris_persist::federation::envelope::paths::ROW);
    assert!(
        put(&engine, row).await.is_err(),
        "a row whose envelope carries NO typed-column mirror was accepted. The binding gates are \
         then optional in the one direction that matters: an attacker does not have to defeat \
         them, only delete them."
    );
}

/// The stamped instant must be storable on BOTH backends. sqlite keeps whatever
/// precision it is given; postgres TIMESTAMPTZ keeps microseconds — so a
/// nanosecond-precision instant makes a strict ordering on one a TIE on the
/// other, and the fold that reads it silently disagrees across a fleet.
#[tokio::test]
async fn the_stamped_instant_is_storable_on_postgres() {
    let (_engine, user) = fixture().await;
    let row = fresh_row(&user).await;
    assert_eq!(
        row.asserted_at.timestamp_subsec_nanos() % 1_000,
        0,
        "the stamped `asserted_at` carries sub-microsecond precision ({}). postgres TIMESTAMPTZ \
         cannot store it, so two rows that are strictly ordered on sqlite become a TIE on \
         postgres — the same fold, two answers, no error anywhere (CIRISPersist#598).",
        row.asserted_at.to_rfc3339()
    );
    // …and the column must equal the SIGNED instant, not merely be well-formed.
    let signed = row
        .attestation_envelope
        .get(ciris_persist::federation::envelope::paths::ASSERTED_AT)
        .and_then(|v| v.as_str())
        .expect("the envelope carries the signed instant");
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(signed)
            .expect("RFC-3339")
            .timestamp_micros(),
        row.asserted_at.timestamp_micros(),
        "the `asserted_at` COLUMN diverges from the instant inside the signed envelope. That is \
         CIRISPersist#598 exactly: the column decides which claim wins a fold, so a column no \
         signature covers is a replay knob for whoever writes the row."
    );
}

/// The subject binding on the KEY registration (CIRISPersist#659) is the fourth
/// gate, and it lives on a different table — so it needs its own case. An
/// envelope that does not name its subject stands for ANY record it is pasted
/// onto, because every signature over that row is verified over those bytes only.
#[tokio::test]
async fn an_unbound_registration_envelope_is_refused() {
    let engine = Arc::new(
        Engine::with_signer(Arc::new(signer_for(NODE)), "sqlite::memory:")
            .await
            .expect("Engine::with_signer(sqlite::memory:)"),
    );
    let signer = signer_for(USER);
    let probe = signer.sign_hybrid(b"probe").await.expect("probe sign");
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);

    // The PRE-#659 envelope: a bare key_id, naming neither the identity type nor
    // either pubkey leg.
    let envelope = serde_json::json!({ "key_id": USER });
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .expect("canonicalize");
    let sig = signer.sign_hybrid(&canonical).await.expect("sign");
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: USER.to_string(),
        pubkey_ed25519_base64: ed_pub,
        pubkey_ml_dsa_65_base64: Some(pqc_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.to_string(),
        identity_ref: USER.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: USER.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    assert!(
        engine
            .register_federation_key(SignedKeyRecord { record })
            .await
            .is_err(),
        "a registration envelope carrying only `key_id` was ADMITTED. It names neither the \
         identity type nor either pubkey leg, so the signature over it vouches for nothing in \
         particular and the bytes stand for any record they are pasted onto (CIRISPersist#659). \
         This is the gate that broke first-run claim on v31, and this test is what stops it \
         being un-broken by a fixture that never exercised it."
    );
}
