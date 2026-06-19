//! Moderation as a **delegable DUTY** (FSD MODERATION_CHILD_SAFETY §0/§3/§6;
//! Constitution §4.5.x — `moderate`/`takedown`/`review` duties with ENFORCED
//! admission via `delegates_to`).
//!
//! The load-bearing reframe (FSD §0): there is **no fabric-assigned moderator
//! role.** The fabric ships the duty SCOPES (`moderate`/`takedown`/`review`) and
//! the resolution that makes every action attributable + revocable. WHO exercises
//! a duty is a delegation choice. This is "takedown isn't a coup," structural:
//! every action is signed by the delegate, traceable to the duty-holder via the
//! `delegates_to` chain, and instantly revocable by `withdraws`.
//!
//! ## COMPOSED from persist v9.0.0 (the admission gate is NOT re-implemented)
//!
//! persist v9.0.0 (CIRISPersist#233 / CEG §11.10) ships the full admit-iff gate.
//! [`admit_moderation_action`] is a thin COMPOSITION of:
//!
//! - `admission::DELEGATION_SCOPE_{MODERATE,TAKEDOWN,REVIEW}` — the duty tokens.
//! - `admission::duty_holders_for_community` — the duty-holder set (the
//!   community's owner-bound named-moderator authority roots).
//! - `admission::check_moderation_admission` — the §11.10 admit-iff: admit IFF
//!   the signer is a duty-holder (as-self) OR sits on a live, unrevoked, scoped
//!   `delegates_to` chain from one. **Absence never admits — fail-secure.**
//!
//! What is BUILT server-side: the `ModerationEvent`-shaped `moderation:*`
//! `scores` EMIT ([`emit_moderation_event`]) and the
//! `moderation_track_record:{community}` READ ([`read_track_record`]) composition
//! (the auto-promotion ranking signal — see [`super::named`]).
//!
//! ## Honesty discipline
//!
//! - Detection / `ratchet:flag:*` is advisory ONLY — it can NEVER be the sole
//!   evidence for `slashing:*`; a named-moderator / quorum adjudication is the
//!   load-bearing gate (FSD §6). This module emits the `ModerationEvent` only
//!   when the signer is ADMITTED to exercise the duty.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::admission;
use ciris_persist::federation::types::{attestation_type, LocalAttestationInput};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};

use crate::auth::verify::{self, VerifyError};

/// The `moderation:{allegation_type}` dimension prefix (CEG §5.6.4 /
/// persist `MODERATION_DIMENSION_PREFIX`). A `moderation:*` `scores` row IS the
/// ModerationEvent in the §11.10 admission model (the gate keys off this prefix).
pub const MODERATION_DIMENSION_PREFIX: &str = admission::MODERATION_DIMENSION_PREFIX;

/// The `moderation_track_record:{community}` dimension prefix — the named
/// composition (FSD §A.1) the auto-promotion ranking reads. Computed fabric-side
/// over the reputation basis (no new primitive; upstream-ask §9 #10 to
/// canonicalize the dimension name + the deterministic ranking).
pub const TRACK_RECORD_DIMENSION_PREFIX: &str = "moderation_track_record:";

/// The duty a moderation action exercises. Maps to the persist enforced scope
/// tokens (`moderate`/`takedown`/`review`) — the §4.5.x agency-class duties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Duty {
    /// Emit a ModerationEvent / detection flag on behalf of the duty-holder.
    Moderate,
    /// File a takedown_notice on behalf of the duty-holder.
    Takedown,
    /// Adjudicate reports / route deferrals on behalf of the duty-holder.
    Review,
}

impl Duty {
    /// The persist enforced-scope token for this duty.
    pub fn scope_token(self) -> &'static str {
        match self {
            Duty::Moderate => admission::DELEGATION_SCOPE_MODERATE,
            Duty::Takedown => admission::DELEGATION_SCOPE_TAKEDOWN,
            Duty::Review => admission::DELEGATION_SCOPE_REVIEW,
        }
    }

    /// Parse a duty from its `moderate`/`takedown`/`review` token.
    pub fn from_token(s: &str) -> Option<Duty> {
        match s {
            "moderate" => Some(Duty::Moderate),
            "takedown" => Some(Duty::Takedown),
            "review" => Some(Duty::Review),
            _ => None,
        }
    }
}

/// **COMPOSE the §11.10 admit-iff gate.** Admit `signer` to exercise `duty` over
/// community `community_key_id` IFF the signer is an owner-bound named-moderator
/// duty-holder (as-self) OR sits on a live, unrevoked, `duty`-scoped
/// `delegates_to` chain from one. Absence never admits (fail-secure).
///
/// This is a thin composition: persist's `duty_holders_for_community` resolves
/// the holder set, `check_moderation_admission` walks the chain. We do not
/// re-derive the rule — the substrate IS the authority.
pub async fn admit_moderation_action(
    engine: &Engine,
    signer: &str,
    community_key_id: &str,
    duty: Duty,
) -> Result<bool, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let scope = duty.scope_token();
    let duty_holders =
        admission::duty_holders_for_community(directory.as_ref(), community_key_id, scope)
            .await
            .map_err(|e| format!("duty_holders_for_community: {e}"))?;
    match admission::check_moderation_admission(
        directory.as_ref(),
        signer,
        &duty_holders,
        scope,
        community_key_id,
    )
    .await
    {
        Ok(()) => Ok(true),
        // The stable §11.10 rejection (`federation_delegated_scope_unauthorized`).
        Err(ciris_persist::federation::Error::DelegatedScopeUnauthorized { .. }) => Ok(false),
        Err(e) => Err(format!("check_moderation_admission: {e}")),
    }
}

/// **Emit a ModerationEvent** — a `moderation:{allegation_type}` `scores` row.
/// The CALLER MUST have already admitted the signer via
/// [`admit_moderation_action`] (the HTTP route does). Persist's
/// `check_delegated_duty_scores_admission` ALSO re-runs the §11.10 gate at
/// `put_attestation` for a `moderation:*` row, so admission is enforced at the
/// substrate even if a caller forgets — defense in depth.
///
/// Returns the persisted attestation id.
pub async fn emit_moderation_event(
    engine: &Engine,
    signer_key_id: &str,
    community_key_id: &str,
    allegation_type: &str,
    target_key_ids: &[String],
    payload: serde_json::Value,
) -> Result<String, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    // Every `scores` dimension MUST carry a `:vN` version segment (persist
    // `require_version_segment`, CEG §13.1).
    let dimension = format!("{MODERATION_DIMENSION_PREFIX}{allegation_type}:v1");
    let envelope = serde_json::json!({
        "dimension": dimension,
        "community_id": community_key_id,
        "allegation_type": allegation_type,
        "payload": payload,
    });
    let input = LocalAttestationInput {
        attesting_key_id: signer_key_id.to_owned(),
        attested_key_id: target_key_ids.first().cloned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: envelope,
        subject_key_ids: target_key_ids.to_vec(),
        cohort_scope: "self".to_owned(),
    };
    let attestation_id = directory
        .attestation_upsert_local(input)
        .await
        .map_err(|e| format!("upsert moderation event: {e}"))?;
    // Promote to federation tier so the ModerationEvent is federation-visible
    // (the audit chain + the track-record signal read it across the federation).
    engine
        .attestation_promote(&attestation_id)
        .await
        .map_err(|e| format!("promote moderation event: {e}"))?;
    Ok(attestation_id)
}

/// **Read** a member's `moderation_track_record:{community}` — the count of
/// upheld moderation actions they have authored in this community (the
/// auto-promotion ranking signal, FSD §A.1/§A.3).
///
/// Near-term composition (no new primitive): the count of the member's `scores`
/// rows in this community that record a moderation action — EITHER a live
/// `moderation:*` ModerationEvent (the action itself; admission-gated, so only an
/// admitted duty-holder can mint these) OR a `moderation_track_record:{community}`
/// reputation row (the upheld-action ledger a prior moderator accrues, which
/// survives the lapse of their `moderate` standing — exactly the signal merit
/// auto-promotion needs after a moderator steps down). Upstream-ask §9 #10
/// canonicalizes the richer reputation basis + the deterministic tiebreak.
pub async fn read_track_record(
    engine: &Engine,
    member_key_id: &str,
    community_key_id: &str,
) -> u64 {
    let Some(directory) = engine.sqlite_backend() else {
        return 0;
    };
    let Ok(rows) = directory.list_attestations_by(member_key_id).await else {
        return 0;
    };
    rows.into_iter()
        .filter(|r| {
            if r.attestation_type != attestation_type::SCORES {
                return false;
            }
            let Some(dimension) = r
                .attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
            else {
                return false;
            };
            let is_mod_signal = dimension.starts_with(MODERATION_DIMENSION_PREFIX)
                || dimension.starts_with(TRACK_RECORD_DIMENSION_PREFIX);
            is_mod_signal
                && r.attestation_envelope
                    .get("community_id")
                    .and_then(|v| v.as_str())
                    == Some(community_key_id)
        })
        .count() as u64
}

// ─── HTTP surface ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct ModState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct ModerationRequest {
    /// The acting key (the delegate or the duty-holder itself).
    signer_key_id: String,
    /// The community the action is scoped to.
    community_key_id: String,
    /// The duty being exercised (`moderate`/`takedown`/`review`).
    duty: Duty,
    /// The `moderation:{allegation_type}` allegation token.
    allegation_type: String,
    /// The targets the action names.
    #[serde(default)]
    target_key_ids: Vec<String>,
    /// Free-form action payload (reason, evidence refs, …).
    #[serde(default)]
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ModerationResponse {
    attestation_id: String,
    duty: Duty,
}

/// `POST /v1/safety/moderation` — file a `moderate`/`takedown`/`review` action.
/// Admitted IFF the signer holds the duty or sits on a live delegated chain
/// (the §11.10 gate, composed). Non-holders are REJECTED (403) — the duty is
/// held or delegated, never assumed.
async fn moderation(State(st): State<ModState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(StatusCode::UNAUTHORIZED, format!("signature: {e}"))
        }
    };
    let req: ModerationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    // The HTTP signer must act for the declared acting key (self or an admitted
    // occurrence) — then the §11.10 duty gate decides authority.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.signer_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the acting key nor an admitted occurrence of it",
        );
    }
    // COMPOSE the §11.10 admit-iff gate.
    match admit_moderation_action(
        &st.engine,
        &req.signer_key_id,
        &req.community_key_id,
        req.duty,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return err(
                StatusCode::FORBIDDEN,
                "not authorized for this duty: the duty is held or delegated, never assumed \
                 (CEG §11.10 — no named-moderator authority and no live delegated chain)",
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
    match emit_moderation_event(
        &st.engine,
        &req.signer_key_id,
        &req.community_key_id,
        &req.allegation_type,
        &req.target_key_ids,
        req.payload,
    )
    .await
    {
        Ok(attestation_id) => (
            StatusCode::OK,
            Json(ModerationResponse {
                attestation_id,
                duty: req.duty,
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The moderation router. Default [`HybridPolicy::Strict`].
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/safety/moderation", axum::routing::post(moderation))
        .with_state(ModState { engine, policy })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duty_maps_to_persist_scope_tokens() {
        assert_eq!(Duty::Moderate.scope_token(), "moderate");
        assert_eq!(Duty::Takedown.scope_token(), "takedown");
        assert_eq!(Duty::Review.scope_token(), "review");
        // And they are exactly persist's enforced tokens.
        assert_eq!(
            Duty::Moderate.scope_token(),
            admission::DELEGATION_SCOPE_MODERATE
        );
    }

    #[test]
    fn duty_token_roundtrip() {
        for d in [Duty::Moderate, Duty::Takedown, Duty::Review] {
            assert_eq!(Duty::from_token(d.scope_token()), Some(d));
        }
        assert_eq!(Duty::from_token("bogus"), None);
    }
}
