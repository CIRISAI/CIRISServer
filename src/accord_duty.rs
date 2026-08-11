//! **Conferring a moderation DUTY from the humanity accord** (CIRISServer#392).
//!
//! # The gap this closes
//!
//! Every tier-2/3/4 act on the enforcement ladder — `quarantine`, `descend`,
//! `de_admission`, `refuse_writes` — requires the `slash` duty. persist checks
//! it by walking `delegates_to` edges on the DELEGATION plane
//! (`dimension: trust:confers:v1`, `scope ⊇ {duty}`).
//!
//! Nothing in this server could write that row. The trust-root card confers
//! `canonical` / `infra:serve` / `infra:attest` — roles co-scrubbed INTO a key
//! record, which is the CEREMONY plane, a different plane entirely. So an
//! operator holding the accord could bless a node all day and still not be able
//! to hand anyone the authority to moderate. CIRISServer#383's 61 leaked QA keys
//! sat behind exactly this: not blocked on code to *perform* the de-admission,
//! blocked on there being no way to *grant* the authority to perform it.
//!
//! # Why the family, not the seat
//!
//! The grant is signed by accord HOLDERS and adopted at the family's own
//! `quorum:M/N` (2-of-3 for `humanity-accord`). persist then reads it through
//! [`ConferralPlane::FamilyQuorum`]: a grant carrying enough distinct seated
//! holders' scrubs is a grant BY THE FAMILY, and the candidate root is the
//! family id — never the seat that happened to sign first.
//!
//! That is deliberate and it is the whole point. A single holder able to confer
//! `slash` unilaterally would be exactly the authority CIRISPersist#557 took
//! away from any one seat. Two of three is not a formality here; it is the
//! difference between the accord acting and a person acting in its name.
//!
//! # Two steps, because two humans
//!
//! `propose` (holder A signs) → hand the partial to holder B → `cosign`
//! (holder B appends a scrub) → at quorum the row is PUT. This mirrors the
//! canonical co-scrub ceremony (`accord_provision`) exactly, including that the
//! partial is inert until quorum: persist REFUSES a sub-quorum grant, so a
//! one-seat partial confers nothing even if it is replicated.
//!
//! The row is federation-tier, so once adopted it replicates to peers by
//! ordinary anti-entropy — the authority arrives everywhere the accord is known
//! without anyone re-issuing it.
//!
//! # Sub-delegation is bounded HERE, at the grant
//!
//! persist's contract (`delegation_sub_delegation_depth`):
//!
//! | envelope | meaning |
//! |---|---|
//! | `sub_delegation` absent/`false` | leaf — may exercise, may not pass on |
//! | `sub_delegation: true`, no depth | may pass on, bounded only by the global rail |
//! | `sub_delegation: true, sub_delegation_depth: N` | may pass on; `N` further hops |
//!
//! The depth can only ever TIGHTEN — the global rail
//! ([`MAX_MODERATION_DELEGATION_DEPTH`], 5) still caps every chain. It is chosen
//! at conferral time because that is the only moment the granting authority is
//! in the room; a recipient cannot widen what it was given.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::admission::{
    DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW, DELEGATION_SCOPE_SLASH,
    MAX_MODERATION_DELEGATION_DEPTH,
};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::trust_root::TRUST_CONFERS_DIMENSION;
use ciris_persist::federation::types::{
    attestation_tier, attestation_type, cohort_scope, Attestation, ScrubSig,
};
use ciris_persist::federation::SignedAttestation;
use ciris_persist::prelude::Engine;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The duties this surface may confer. A closed set on purpose: these are the
/// three the §11.10 walk recognizes, and an unrecognized scope would be a grant
/// that reads as authority in the UI and admits nothing at the gate.
pub const CONFERRABLE_DUTIES: &[&str] = &[
    DELEGATION_SCOPE_SLASH,
    DELEGATION_SCOPE_MODERATE,
    DELEGATION_SCOPE_REVIEW,
];

#[derive(Clone)]
pub struct DutyState {
    pub engine: Arc<Engine>,
}

/// The holder's custody handle — the same shape `accord_provision` takes, so an
/// operator uses one mental model for every accord act.
#[derive(Debug, Clone, Deserialize)]
pub struct HolderRef {
    pub key_id: String,
    #[serde(default)]
    pub mldsa_usb_path: String,
    #[serde(default)]
    pub pkcs11: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    pub holder: HolderRef,
    pub subject_key_id: String,
    pub duty: String,
    #[serde(default)]
    pub sub_delegation: bool,
    #[serde(default)]
    pub sub_delegation_depth: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CosignRequest {
    pub holder: HolderRef,
    pub partial: Attestation,
}

#[derive(Debug, Serialize)]
pub struct DutyResponse {
    pub partial: Attestation,
    pub scrub_count: usize,
    pub quorum_needed: usize,
    pub adopted: bool,
    /// Present when `adopted` — what the grant now says, in one line, so the
    /// operator can read back what they signed rather than infer it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conferred: Option<String>,
}

fn err(code: StatusCode, reason_id: &str, msg: impl Into<String>) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": msg.into(), "reason_id": reason_id })),
    )
        .into_response()
}

/// The envelope both steps sign. Built from the REQUEST once, then carried on
/// the partial — every scrub must cover byte-identical canonical bytes, so the
/// second holder signs what the first one did, not a re-derivation of it.
fn conferral_envelope(
    id: &str,
    subject: &str,
    duty: &str,
    sub_delegation: bool,
    depth: Option<u32>,
) -> serde_json::Value {
    // Envelope KEYS come from persist's constants, never hand-mirrored literals
    // (CIRISServer#322): a rename upstream must break the build here rather than
    // silently skew the wire.
    let mut env = serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): id,
        // The plane. A row labelled charter or trust-edge points the other way
        // and confers nothing (CIRISPersist#551 item 2).
        (paths::DIMENSION): TRUST_CONFERS_DIMENSION,
        "scope": [duty],
        "subject_key_id": subject,
    });
    // Written only when TRUE. Absent and `false` mean the same thing to persist
    // (leaf), and emitting `false` would put a field on the wire that reads like
    // a decision when it is the default.
    if sub_delegation {
        env["sub_delegation"] = serde_json::json!(true);
        if let Some(n) = depth {
            env["sub_delegation_depth"] = serde_json::json!(n);
        }
    }
    env
}

/// How many distinct holders have scrubbed this partial.
fn distinct_scrubs(a: &Attestation) -> usize {
    let mut ids: Vec<&str> = vec![a.scrub_key_id.as_str()];
    for s in &a.additional_scrubs {
        ids.push(s.scrub_key_id.as_str());
    }
    ids.sort_unstable();
    ids.dedup();
    ids.len()
}

/// The accord's own `quorum:M/N`, read from the family — never a constant here.
/// A holder removed from the roster must stop counting immediately, which only
/// works if the threshold is re-derived at use.
async fn quorum_needed(engine: &Engine) -> usize {
    crate::accord_provision::family_quorum_m_for_duty(engine)
        .await
        .max(1)
}

#[cfg(not(feature = "pkcs11"))]
async fn sign_as_holder(
    _holder: &HolderRef,
    _canonical: &[u8],
) -> Result<(String, String, String), Response> {
    Err(err(
        StatusCode::NOT_IMPLEMENTED,
        "accord.duty.pkcs11_required",
        "Conferring a duty needs the `pkcs11` feature — the holder signs with their YubiKey \
         plus the USB-wrapped ML-DSA half, exactly as the canonical co-scrub ceremony does.",
    ))
}

/// Open the holder's hardware custody and scrub `canonical`.
/// Returns `(scrub_key_id, ed25519_b64, mldsa_b64)`.
#[cfg(feature = "pkcs11")]
async fn sign_as_holder(
    holder: &HolderRef,
    canonical: &[u8],
) -> Result<(String, String, String), Response> {
    use ciris_verify_core::self_at_login::SelfSigner as _;
    let pk: crate::accord_provision::ProvisionPkcs11 =
        serde_json::from_value(holder.pkcs11.clone()).unwrap_or_default();
    let identity = crate::accord_provision::open_holder_identity(
        holder.key_id.trim(),
        holder.mldsa_usb_path.trim(),
        &pk,
    )
    .await
    .map_err(|(code, msg)| err(code, "accord.duty.holder_custody", msg))?;
    let (ed, pqc) = identity.sign_bound(canonical).await.map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "accord.duty.sign_failed",
            format!("holder scrub failed: {e}"),
        )
    })?;
    Ok((identity.key_id().to_string(), ed, pqc))
}

async fn propose(State(st): State<DutyState>, body: axum::body::Bytes) -> Response {
    let req: ProposeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "accord.duty.bad_request",
                format!("bad request: {e}"),
            )
        }
    };
    let duty = req.duty.trim();
    if !CONFERRABLE_DUTIES.contains(&duty) {
        return err(
            StatusCode::BAD_REQUEST,
            "accord.duty.unknown_duty",
            format!(
                "`{duty}` is not a conferrable duty. The §11.10 walk recognizes {:?} — anything \
                 else would render as authority in the UI and admit nothing at the gate.",
                CONFERRABLE_DUTIES
            ),
        );
    }
    let subject = req.subject_key_id.trim();
    if subject.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "accord.duty.no_subject",
            "a conferral needs a subject key_id — the identity the duty is granted TO",
        );
    }
    if let Some(n) = req.sub_delegation_depth {
        if n as usize > MAX_MODERATION_DELEGATION_DEPTH {
            return err(
                StatusCode::BAD_REQUEST,
                "accord.duty.depth_over_rail",
                format!(
                    "sub_delegation_depth {n} exceeds the global rail of \
                     {MAX_MODERATION_DELEGATION_DEPTH}. Depth can only ever TIGHTEN the rail, \
                     never widen it, so a larger number would promise reach the walk will not \
                     honour."
                ),
            );
        }
        if !req.sub_delegation {
            return err(
                StatusCode::BAD_REQUEST,
                "accord.duty.depth_without_delegation",
                "sub_delegation_depth was given but sub_delegation is false. `false` is a LEAF \
                 grant — it may act and may not pass the duty on — so a depth on it would be a \
                 bound on a gate that is shut.",
            );
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let envelope = conferral_envelope(
        &id,
        subject,
        duty,
        req.sub_delegation,
        req.sub_delegation_depth,
    );
    let canonical = match ceg_produce_canonicalize(&envelope) {
        Ok(c) => c,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "accord.duty.canonicalize",
                format!("canonicalize conferral: {e}"),
            )
        }
    };
    let (scrub_key_id, ed, pqc) = match sign_as_holder(&req.holder, &canonical).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let now = chrono::Utc::now();
    let partial = Attestation {
        attestation_id: id,
        attesting_key_id: scrub_key_id.clone(),
        attested_key_id: subject.to_string(),
        attestation_type: attestation_type::DELEGATES_TO.to_string(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: ed,
        scrub_signature_pqc: Some(pqc),
        scrub_key_id,
        additional_scrubs: Vec::new(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![subject.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    let needed = quorum_needed(&st.engine).await;
    let count = distinct_scrubs(&partial);
    tracing::info!(
        subject = %subject, duty = %duty, holder = %partial.scrub_key_id,
        scrubs = count, needed,
        "duty conferral PROPOSED — inert until quorum; hand the partial to another holder"
    );
    // Deliberately NOT put here even if a 1-of-1 family existed: adoption goes
    // through the same code path for every quorum, so there is one place where a
    // grant becomes real.
    (
        StatusCode::OK,
        Json(DutyResponse {
            partial,
            scrub_count: count,
            quorum_needed: needed,
            adopted: false,
            conferred: None,
        }),
    )
        .into_response()
}

async fn cosign(State(st): State<DutyState>, body: axum::body::Bytes) -> Response {
    let req: CosignRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "accord.duty.bad_request",
                format!("bad request: {e}"),
            )
        }
    };
    let mut partial = req.partial;

    // Re-canonicalize the PARTIAL's own envelope. Every scrub must cover
    // byte-identical bytes, so the second holder signs what the first signed —
    // never a re-derivation from request fields, which is how two signatures end
    // up over two different meanings.
    let canonical = match ceg_produce_canonicalize(&partial.attestation_envelope) {
        Ok(c) => c,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "accord.duty.canonicalize",
                format!("the partial's envelope does not canonicalize: {e}"),
            )
        }
    };
    if hex::encode(Sha256::digest(&canonical)) != partial.original_content_hash {
        return err(
            StatusCode::BAD_REQUEST,
            "accord.duty.partial_tampered",
            "the partial's content hash does not match its envelope — it was altered after the \
             first holder signed it. Signing it now would put two signatures over two different \
             meanings.",
        );
    }

    let (scrub_key_id, ed, pqc) = match sign_as_holder(&req.holder, &canonical).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if scrub_key_id == partial.scrub_key_id
        || partial
            .additional_scrubs
            .iter()
            .any(|s| s.scrub_key_id == scrub_key_id)
    {
        return err(
            StatusCode::CONFLICT,
            "accord.duty.already_signed",
            format!(
                "{scrub_key_id} has already scrubbed this conferral. Quorum counts DISTINCT \
                 holders — one seat signing twice is one seat."
            ),
        );
    }
    partial.additional_scrubs.push(ScrubSig {
        scrub_key_id: scrub_key_id.clone(),
        scrub_signature_classical: ed,
        scrub_signature_pqc: Some(pqc),
    });

    let needed = quorum_needed(&st.engine).await;
    let count = distinct_scrubs(&partial);
    if count < needed {
        tracing::info!(
            scrubs = count, needed, holder = %scrub_key_id,
            "duty conferral CO-SIGNED but still short of quorum — still inert"
        );
        return (
            StatusCode::OK,
            Json(DutyResponse {
                partial,
                scrub_count: count,
                quorum_needed: needed,
                adopted: false,
                conferred: None,
            }),
        )
            .into_response();
    }

    // Quorum. persist is the authority on admission: it re-verifies EVERY scrub
    // over the same canonical bytes (v24.0.0) and derives the FAMILY from the
    // verified signer set. A sub-quorum or forged set is refused here, not by us.
    let env = partial.attestation_envelope.clone();
    let subject = partial.attested_key_id.clone();
    let duty = env
        .get("scope")
        .and_then(|s| s.get(0))
        .and_then(|s| s.as_str())
        .unwrap_or("?")
        .to_string();
    if let Err(e) = st
        .engine
        .federation_directory()
        .put_attestation(SignedAttestation {
            attestation: partial.clone(),
        })
        .await
    {
        tracing::warn!(error = %e, "duty conferral REFUSED by the substrate at quorum");
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "accord.duty.refused",
            format!("the substrate refused the conferral: {e}"),
        );
    }
    let depth = env
        .get("sub_delegation")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        .then(|| {
            env.get("sub_delegation_depth")
                .and_then(serde_json::Value::as_u64)
                .map(|n| format!("{n} further hop(s)"))
                .unwrap_or_else(|| {
                    format!("bounded only by the rail ({MAX_MODERATION_DELEGATION_DEPTH})")
                })
        })
        .unwrap_or_else(|| "leaf — may act, may not pass it on".to_string());
    let conferred = format!("{duty} conferred on {subject}; sub-delegation: {depth}");
    tracing::warn!(
        subject = %subject, duty = %duty, scrubs = count, needed,
        "DUTY CONFERRAL ADOPTED — federation-tier, replicates by anti-entropy"
    );
    (
        StatusCode::OK,
        Json(DutyResponse {
            partial,
            scrub_count: count,
            quorum_needed: needed,
            adopted: true,
            conferred: Some(conferred),
        }),
    )
        .into_response()
}

/// **Test seam** (`tests/accord_duty_grant.rs`): build a conferral partial
/// scrubbed by the given holders, without the PKCS#11 custody path.
///
/// The production route opens the holder's YubiKey; a test holds the synthetic
/// genesis holders' software halves directly. Both produce the SAME row over the
/// SAME canonical bytes — this seam exists so the 2-of-3 property can be
/// exercised with real signatures against the roster persist itself resolves,
/// not so the ceremony can be bypassed.
#[cfg(feature = "test-anchor")]
#[doc(hidden)]
pub async fn test_support_build_partial(
    subject: &str,
    duty: &str,
    sub_delegation: bool,
    depth: Option<u32>,
    holders: &[&ciris_persist::federation::operational::test_support::Identity],
) -> Attestation {
    assert!(!holders.is_empty(), "a conferral needs at least one scrub");

    // A deterministic id keyed on the subject+duty, so a re-run re-derives the
    // same row rather than racing a previous one.
    // The id includes the SCRUB SET, so a 1-of-3 partial and the 2-of-3 grant are
    // different rows. They have to be: the test stores the sub-quorum one to prove
    // it confers nothing, and a shared id would collide on insert instead.
    let holder_ids: Vec<&str> = holders.iter().map(|h| h.key_id.as_str()).collect();
    let id = hex::encode(Sha256::digest(
        format!("{subject}/{duty}/{}", holder_ids.join("+")).as_bytes(),
    ));
    let envelope = conferral_envelope(&id[..32], subject, duty, sub_delegation, depth);
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");

    let mut scrubs: Vec<(String, String, String)> = Vec::new();
    for h in holders {
        // `sign_bytes` IS the bound-hybrid construction the route's `sign_bound`
        // performs — Ed25519 over the canonical bytes, ML-DSA-65 over
        // `canonical ‖ ed_sig`. Same signature, different custody.
        let (ed, pqc) = h.sign_bytes(&canonical);
        scrubs.push((h.key_id.clone(), ed, pqc));
    }
    let (first_id, first_ed, first_pqc) = scrubs.remove(0);
    let now = chrono::Utc::now();
    Attestation {
        attestation_id: id[..32].to_string(),
        attesting_key_id: first_id.clone(),
        attested_key_id: subject.to_string(),
        attestation_type: attestation_type::DELEGATES_TO.to_string(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: first_ed,
        scrub_signature_pqc: Some(first_pqc),
        scrub_key_id: first_id,
        additional_scrubs: scrubs
            .into_iter()
            .map(|(k, ed, pqc)| ScrubSig {
                scrub_key_id: k,
                scrub_signature_classical: ed,
                scrub_signature_pqc: Some(pqc),
            })
            .collect(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: vec![subject.to_string()],
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    }
}

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/v1/accord/duty/propose", axum::routing::post(propose))
        .route("/v1/accord/duty/cosign", axum::routing::post(cosign))
        .with_state(DutyState { engine })
}
