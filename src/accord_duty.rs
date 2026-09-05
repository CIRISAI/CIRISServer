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
use ciris_persist::federation::admission::MAX_MODERATION_DELEGATION_DEPTH;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::trust_root::TRUST_CONFERS_DIMENSION;
use ciris_persist::federation::types::{attestation_type, cohort_scope, Attestation, ScrubSig};
use ciris_persist::federation::SignedAttestation;
use ciris_persist::prelude::Engine;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// **Every delegated-duty scope the substrate defines** — now the substrate's own
/// array, not a list assembled here.
///
/// # It was hand-picked, and it drifted
///
/// This shipped with three of the five scopes: `takedown` and
/// `consent_revocation` were absent, so the card could not confer them and the
/// menu looked complete. Nobody scans a dropdown wondering what is *not* on it.
///
/// The cause was structural — persist declared five `DELEGATION_SCOPE_*` consts
/// and no array over them, so every consumer hand-picked a subset and every
/// hand-picked mirror drifts the moment the vocabulary grows. Filed as
/// CIRISPersist#637; persist v30.11.0 exports
/// [`DELEGATED_DUTY_SCOPES`](ciris_persist::federation::admission::DELEGATED_DUTY_SCOPES)
/// and this is now a re-export of it.
///
/// That closes the membership hole a local list could not: a sixth scope added
/// upstream appears here on the next bump with no edit, because there is nothing
/// here to edit. `tests/duty_scopes_match_the_substrate.rs` keeps its assertions
/// (they now compare the substrate against itself, which is cheap and still
/// catches a future re-hand-rolling), and drops the source-grep that stood in for
/// this import.
pub const CONFERRABLE_DUTIES: &[&str] = ciris_persist::federation::admission::DELEGATED_DUTY_SCOPES;

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
    /// The duties to confer — a SET. persist admits `scope` as "a bare string OR
    /// a JSON array of strings (set-containment)", so conferring `moderate` AND
    /// `takedown` in one grant is native to the wire; this field carrying a
    /// single `String` was a narrowing invented here, not a substrate limit. One
    /// grant, one co-scrub ceremony, several duties.
    #[serde(default)]
    pub duties: Vec<String>,
    /// The pre-set spelling. Accepted so an older client keeps working; folded
    /// into [`Self::duties`] on read.
    #[serde(default)]
    pub duty: Option<String>,
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
    subject: &str,
    duties: &[String],
    sub_delegation: bool,
    depth: Option<u32>,
) -> serde_json::Value {
    // Envelope KEYS come from persist's constants, never hand-mirrored literals
    // (CIRISServer#322): a rename upstream must break the build here rather than
    // silently skew the wire.
    //
    // This used to carry `references_attestation_id` set to the row's OWN id —
    // a second, independently-minted name for the row, sitting next to the
    // column. persist ignores the field on non-composer rows (it is the TARGET
    // of a withdraw/supersede, and a conferral retracts nothing), so it bought
    // nothing and could disagree with the column, which is the CIRISServer#402
    // class in miniature. The row's identity now lives in the signed mirror
    // `crate::attest` stamps, where exactly one thing writes it.
    let mut env = serde_json::json!({
        // The plane. A row labelled charter or trust-edge points the other way
        // and confers nothing (CIRISPersist#551 item 2).
        (paths::DIMENSION): TRUST_CONFERS_DIMENSION,
        "scope": duties,
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
    // Fold the legacy singular spelling into the set, then dedupe + sort so the
    // canonical bytes do not depend on the order the operator ticked the boxes.
    let mut duties: Vec<String> = req
        .duties
        .iter()
        .chain(req.duty.iter())
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    duties.sort();
    duties.dedup();
    if duties.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "accord.duty.no_duty",
            format!(
                "a conferral needs at least one duty. The §11.10 walk recognizes {CONFERRABLE_DUTIES:?}."
            ),
        );
    }
    if let Some(bad) = duties
        .iter()
        .find(|d| !CONFERRABLE_DUTIES.contains(&d.as_str()))
    {
        return err(
            StatusCode::BAD_REQUEST,
            "accord.duty.unknown_duty",
            format!(
                "`{bad}` is not a conferrable duty. The §11.10 walk recognizes \
                 {CONFERRABLE_DUTIES:?} — anything else would render as authority in the UI and \
                 admit nothing at the gate."
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

    // ── Through the ONE door (CIRISServer#402) ────────────────────────────────
    //
    // A co-signed conferral is exactly the case persist's `assemble`-without-put
    // exists for: the canonical bytes must exist for the OTHER holders to sign,
    // and they cannot exist without a row. This route used to hand-roll that row
    // — which is how it acquired every binding defect the claim path had, silently,
    // because nobody had run a conferral on v31 yet. See [`crate::attest`].
    let stamped = match crate::attest::Emit::stamp(
        // The proposing holder is the attester; the co-signers append scrubs to
        // the row it mints, over the same canonical bytes.
        req.holder.key_id.trim(),
        crate::attest::Spec::new(
            attestation_type::DELEGATES_TO,
            cohort_scope::FEDERATION,
            conferral_envelope(
                subject,
                &duties,
                req.sub_delegation,
                req.sub_delegation_depth,
            ),
        )
        .about(subject)
        .weighing(Some(1.0)),
    ) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "accord.duty.canonicalize",
                format!("build conferral: {e}"),
            )
        }
    };
    let (scrub_key_id, ed, pqc) = match sign_as_holder(&req.holder, stamped.canonical()).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    // The holder's custody must open as the key the mirror was stamped for. If
    // hardware answers as a different identity, the row's `attesting_key_id` and
    // its scrub would name two different holders — refuse rather than mint it.
    if scrub_key_id != req.holder.key_id.trim() {
        return err(
            StatusCode::CONFLICT,
            "accord.duty.holder_identity_mismatch",
            format!(
                "the conferral was stamped for holder {} but the custody opened as \
                 {scrub_key_id}. The attester is inside the signed bytes (CIRISPersist#643), so \
                 these cannot be reconciled after the fact.",
                req.holder.key_id.trim(),
            ),
        );
    }
    let partial = match stamped.assemble_from_b64(&ed, &pqc) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "accord.duty.assemble",
                format!("assemble conferral: {e}"),
            )
        }
    };
    let needed = quorum_needed(&st.engine).await;
    let count = distinct_scrubs(&partial);
    tracing::info!(
        subject = %subject, duties = %duties.join("+"), holder = %partial.scrub_key_id,
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
        // v39.0.0 adds CC 2.6.7 `cosigned_at`, stamped by
        // `crossing::plan_enter_mesh` on a NODE co-scrub at the tier crossing.
        // This is an accord-quorum scrub on a key record, not a crossing, so
        // there is no such instant to state — and inventing one here would ship
        // a semantic change disguised as a repin.
        cosigned_at: None,
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
    // EVERY scope, not `scope[0]`. This string is the operator's read-back of what
    // they just signed; showing the first of several would under-report a grant
    // that cannot be un-signed. `scope` admits a bare string or an array, so read
    // both shapes rather than assuming the one we happen to write.
    let duty = match env.get("scope") {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(" + "),
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => "?".to_string(),
    };
    // AUTHORED door (persist v41): this node assembled and signed the partial;
    // it is not a peer's row and must not be metered as one.
    if let Err(e) = st
        .engine
        .federation_directory()
        .put_attestation_authored(SignedAttestation {
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
    // The three states of the sub_delegation contract, rendered for the operator
    // log: absent/false is a LEAF, `true` with no depth is bounded by the global
    // rail, `true` + a depth is that many further hops. Depth only ever TIGHTENS.
    let sub_delegation = env
        .get("sub_delegation")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let depth = if sub_delegation {
        match env
            .get("sub_delegation_depth")
            .and_then(serde_json::Value::as_u64)
        {
            Some(n) => format!("{n} further hop(s)"),
            None => format!("bounded only by the rail ({MAX_MODERATION_DELEGATION_DEPTH})"),
        }
    } else {
        "leaf — may act, may not pass it on".to_string()
    };
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
    duties: &[String],
    sub_delegation: bool,
    depth: Option<u32>,
    holders: &[&ciris_persist::federation::operational::test_support::Identity],
) -> Attestation {
    assert!(!holders.is_empty(), "a conferral needs at least one scrub");

    // Through the SAME door as the route (CIRISServer#402). A test seam that
    // hand-rolls the row proves the substrate accepts a row this server does not
    // actually produce — which is the failure mode that let four separate binding
    // defects reach a live claim with every gate green.
    //
    // The row id used to be derived here from `subject/duties/holder-set`, so a
    // 1-of-3 partial and the 2-of-3 grant would land as different rows rather than
    // colliding on insert. The stamp mints a fresh id per call, which gives the
    // same property without a second minting rule.
    let stamped = crate::attest::Emit::stamp(
        &holders[0].key_id,
        crate::attest::Spec::new(
            attestation_type::DELEGATES_TO,
            cohort_scope::FEDERATION,
            conferral_envelope(subject, duties, sub_delegation, depth),
        )
        .about(subject)
        .weighing(Some(1.0)),
    )
    .expect("stamp conferral");

    let mut scrubs: Vec<(String, String, String)> = Vec::new();
    for h in holders {
        // `sign_bytes` IS the bound-hybrid construction the route's `sign_bound`
        // performs — Ed25519 over the canonical bytes, ML-DSA-65 over
        // `canonical ‖ ed_sig`. Same signature, different custody.
        let (ed, pqc) = h.sign_bytes(stamped.canonical());
        scrubs.push((h.key_id.clone(), ed, pqc));
    }
    let (_first_id, first_ed, first_pqc) = scrubs.remove(0);
    let mut row = stamped
        .assemble_from_b64(&first_ed, &first_pqc)
        .expect("assemble conferral");
    row.additional_scrubs = scrubs
        .into_iter()
        .map(|(k, ed, pqc)| ScrubSig {
            scrub_key_id: k,
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
            // Accord-quorum scrub, not a tier crossing — see the sibling site.
            cosigned_at: None,
        })
        .collect();
    row
}

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/v1/accord/duty/propose", axum::routing::post(propose))
        .route("/v1/accord/duty/cosign", axum::routing::post(cosign))
        .with_state(DutyState { engine })
}
