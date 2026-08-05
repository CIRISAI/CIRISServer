//! CIRISServer#371 — the gate for [`FederationKeyId`].
//!
//! The newtype and its unit tests live in the in-tree `ciris-lens-core` crate,
//! whose `--lib` tests are NOT what `cargo test` runs at this workspace root
//! (the root package is the default member, so a green CI says nothing about a
//! member crate's unit tests). The load-bearing proofs therefore live HERE, in
//! the gate that actually runs — which is itself an instance of the discipline
//! this whole issue is about: an instrument that cannot run is not an
//! instrument.
//!
//! Four propositions, in the order they matter:
//!
//! 1. **The incident is refused, by name.** `agent-55fe8d181727` cannot become
//!    a `FederationKeyId`, and the refusal says *which* namespace it is.
//! 2. **The derivation is verify's.** Anything `fedcode::derive_key_id` emits
//!    parses; if verify moves, this goes red rather than the parser going
//!    quietly wrong.
//! 3. **The wire is unchanged.** One plain JSON string, byte-identical.
//! 4. **The seal stamps the DERIVED id, not the keystore alias.** The live
//!    defect the newtype surfaced — six Rust sites in this repo stamped the
//!    `derive_key_id` *input* into a field the verifier resolves as its
//!    *output* (CIRISServer#118 / CIRISPersist#247).
//!
//! The fifth proposition — that the incident is a **compile error** — cannot be
//! written as a runtime test. It is the `compile_fail` doc-test on the
//! `ciris_server::FederationKeyId` re-export in `src/lib.rs`, which `cargo test`
//! runs as a doc-test of this crate.

use ciris_lens_core::capture::partial::{CompleteTrace, TraceComponent};
use ciris_lens_core::capture::seal;
use ciris_server::{classify_key_id, FederationKeyId, KeyIdNamespace, KeyIdNamespaceError};

/// The two producer ids from `FSD/RCA_INGEST_REJECTION_2026-08-05.md`, refused
/// by namespace rather than by shrug.
#[test]
fn the_incident_id_cannot_become_a_federation_key_id() {
    for id in ["agent-55fe8d181727", "agent-1ee871dcf31b"] {
        assert_eq!(classify_key_id(id), KeyIdNamespace::AgentCredits);
        assert_eq!(
            FederationKeyId::parse(id),
            Err(KeyIdNamespaceError::AgentCredits),
            "{id} is the agent-credits namespace; a federation plane that cannot say \
             so answers 8,631 identical 401s a day and calls it working"
        );
    }

    // The id the federation plane DOES know, from the same log line.
    let good = FederationKeyId::parse("ciris-agent-bootstrap-25uzoxtlro").expect("derived id");
    assert_eq!(good.as_str(), "ciris-agent-bootstrap-25uzoxtlro");
}

/// The anti-drift pin: the newtype recognizes exactly what verify mints.
///
/// `parse` inspects shape because a parser holds no pubkey to derive from — so
/// the shape rule must be tied to the real derivation by construction, not by
/// a comment. Feed `derive_key_id` a corpus that exercises every branch of its
/// label sanitizer and require every output back through `parse`.
#[test]
fn every_derive_key_id_output_parses() {
    for (i, label) in [
        "ciris-agent-bootstrap",
        "ciris-client",
        "A1",                  // uppercase → sanitized
        "Eric Moore's Node!!", // punctuation + spaces
        "",                    // empty label → the `id-<fp>` form
        "----",                // all separators → also `id-<fp>`
        "node9",
        "ünïcödé",
        "a",
    ]
    .iter()
    .enumerate()
    {
        let pubkey = [i as u8; 32];
        let derived = ciris_verify_core::fedcode::derive_key_id(label, &pubkey);
        assert_eq!(
            FederationKeyId::parse(&derived).map(FederationKeyId::into_string),
            Ok(derived.clone()),
            "derive_key_id({label:?}) = {derived:?} must parse — a red here means \
             verify's derivation moved and this node is now refusing honest producers"
        );
        assert_eq!(
            FederationKeyId::derive(label, &pubkey).as_str(),
            derived,
            "the newtype's constructor must BE verify's derivation, not a copy of it"
        );
    }
}

/// A type-system change, not a wire change.
#[test]
fn the_wire_is_the_same_plain_string() {
    let id = FederationKeyId::derive("ciris-agent-bootstrap", &[9u8; 32]);
    assert_eq!(
        serde_json::to_string(&id).expect("serialize"),
        serde_json::to_string(id.as_str()).expect("serialize str"),
        "a FederationKeyId field must be indistinguishable on the wire from the \
         String field it replaced"
    );
}

/// **Why this type stops at the seal and does not reach the row readers.**
///
/// The production trust root — `canonical_seed.json`, baked into persist v24.1.0
/// and sha256-pinned — registers `federation_keys` rows under `A1`, `B1`, `C1`
/// and a family under `humanity-accord`. Those keys sign real attestations
/// (`attesting_key_id: "A1"`, `scrub_key_id: "A1"` / `"B1"`). None of them is
/// `derive_key_id` output; they are a *third* namespace minted by the seed
/// ceremony, and the RCA's own diagnostic sample shows them sitting in
/// `accord_public_keys` beside a derived id.
///
/// So a `FederationKeyId` on `Attestation::attesting_key_id` — i.e. on
/// `key_standing` / `peer` / `scorer`, the paths that *compare* key ids — would
/// refuse this node's own trust root. That is the boundary of the type, proved
/// against the real seed values rather than asserted in a comment.
#[test]
fn the_trust_roots_own_key_ids_are_not_in_this_namespace() {
    // Straight out of CIRISPersist/src/federation/genesis/canonical_seed.json.
    for seat in ["A1", "B1", "C1"] {
        assert_eq!(
            classify_key_id(seat),
            KeyIdNamespace::Unrecognized,
            "{seat} is an accord SEAT id — typing attesting_key_id as a \
             FederationKeyId would make this node refuse its own trust root"
        );
    }
    assert_eq!(
        classify_key_id("humanity-accord"),
        KeyIdNamespace::Unrecognized,
        "the family id is a fourth namespace again"
    );
    // The serve node in the same bundle IS derive_key_id-shaped — which is
    // exactly why one `String` looked uniform: the seed carries three
    // namespaces in one column.
    assert_eq!(
        classify_key_id("ciris-canonical-1-d7bdeu223k"),
        KeyIdNamespace::Federation
    );
}

fn sealed_trace() -> CompleteTrace {
    CompleteTrace {
        trace_id: "t-371".into(),
        thought_id: "th-371".into(),
        task_id: None,
        agent_id_hash: "agenthash".into(),
        started_at: "2026-08-05T00:00:00Z".into(),
        completed_at: Some("2026-08-05T00:00:01Z".into()),
        components: Vec::<TraceComponent>::new(),
        signature: None,
        signature_key_id: None,
        signature_ml_dsa_65: None,
        pubkey_ml_dsa_65: None,
        pqc_key_id: None,
        trace_level: Some("generic".into()),
        trace_schema_version: "3.0.0".into(),
        deployment_profile: None,
    }
}

/// **The live defect the newtype found.**
///
/// `seal::sign_trace` stamped `LocalSigner::key_id()` — the raw keystore
/// **alias** — into `signature_key_id`. persist registers the `federation_keys`
/// row under `derive_key_id(alias, pubkey)` and says so on its own accessor:
/// *"any value that must FK to `federation_keys` … MUST use this, not
/// `key_id`"* (CIRISPersist#247). An alias-stamped trace is answered with
/// `verify_unknown_key` — the exact refusal the 2026-08-05 flood consisted of,
/// from a different wrong namespace.
///
/// Five sibling sites carried the same value; typing the parameter turned all
/// six into compile errors. This test is the one that would have been red
/// before the fix, and it is written against the *observable* stamp so it
/// cannot be satisfied by renaming anything.
#[test]
fn the_seal_stamps_the_derived_id_and_not_the_keystore_alias() {
    use ciris_persist::prelude::LocalSigner;
    use ed25519_dalek::SigningKey;

    const ALIAS: &str = "ciris-client";

    let sk = SigningKey::from_bytes(&[58u8; 32]);
    let vk = sk.verifying_key();
    let signer = LocalSigner::from_parts(sk, ALIAS.into(), None, None);

    let mut trace = sealed_trace();
    seal::sign_trace(&signer, &mut trace).expect("sign");

    let stamped = trace
        .signature_key_id
        .as_deref()
        .expect("sign_trace must stamp signature_key_id");

    assert_ne!(
        stamped, ALIAS,
        "the alias is the derive_key_id INPUT — stamping it is CIRISServer#118, \
         and the verifier answers it with verify_unknown_key"
    );
    assert_eq!(
        stamped,
        FederationKeyId::derive(ALIAS, vk.as_bytes()).as_str(),
        "the stamp must be derive_key_id(alias, pubkey) — the id the \
         federation_keys row is registered under"
    );
    assert_eq!(
        classify_key_id(stamped),
        KeyIdNamespace::Federation,
        "a stamp this node mints must itself be in the federation namespace"
    );
    assert!(
        seal::verify_trace_signature(&trace, &vk.to_bytes()),
        "changing WHICH id is stamped must not change the signed canonical bytes \
         (signature_key_id is not part of the canonical envelope)"
    );
}
