//! Infohazard consent-gate — the protective **reveal gate** (CC 4.5.13; the
//! CC 4.5.5 `content_class` gate × the CC 3.3.1 consent primitive).
//!
//! ## The gap this closes (CIRISServer#161)
//!
//! persist already ADMITS the two halves and REFUSES to let a viewer forge
//! either one:
//!
//! - `content_class:infohazard` / `content_class:reported` is a
//!   **substrate-reserved** prefix (persist `default_reserved_prefix_rules` —
//!   `content_class:` requires `identity_type = substrate_persist`; CEG 0.3
//!   §5.6.8.3 / §11.5.3). A viewer/agent that tries to self-clear the flag is
//!   refused (`federation_reserved_prefix_emitter_mismatch`).
//! - `consent:state:granted` + `consent:scope:view` emit cleanly from the
//!   viewer's own key — a real, admittable wire shape.
//!
//! The ONLY missing piece was the *decision*: "may viewer V reveal flagged
//! subject S?" persist is correct to have no engine byte-gate — the enforcement
//! is a **composition** (the consumer / policy tier, CC 4.4), which is exactly
//! what CIRISServer (the absorbed LensCore) is for. This module is that
//! composition; NO persist change, NO new wire shape.
//!
//! ## What ships
//!
//! 1. **the pure gate** — [`infohazard_reveal_decision`] decides visibility from
//!    `(flag, has_consent)`. The default is PROTECTIVE: a flagged subject with
//!    absent/unknown consent ⇒ [`RevealDecision::Interstitial`], never a passive
//!    `Allow`. Mirrors [`super::age::gate_content_for`].
//! 2. **flag resolution** — [`subject_flag`] reads the `content_class:*` flag on
//!    the subject (any live row ⇒ flagged).
//! 3. **consent resolution** — persist's `resolve_scoped_consent` (v16.1.1,
//!    CIRISPersist#389) folds the viewer's `consent:state:*` rows latest-wins over
//!    those naming `scope:view` + the flagged `content_class`. We used to hand-roll
//!    this; that duplicate is DELETED (CIRISServer#243, the DRY-audit H2 finding).
//!    A scope-less BLANKET revoke still re-closes the gate — the substrate fold is
//!    asymmetric on stance, so it is a strict superset of the fold we removed.
//! 4. **the decision endpoint** — `POST /v1/safety/reveal` (decision-only; it
//!    NEVER emits the consent — the app emits it via the existing attestation
//!    surface, then re-calls).
//!
//! ## The loop (no new emit path)
//!
//! app calls `/reveal` → `403 interstitial` → user clicks "I consent" → app emits
//! `consent:state:granted {scope:"view", content_class:"infohazard"}` via the
//! **existing** attestation surface (the viewer's own signed act) → app re-calls
//! `/reveal` → `200 allow` → renders. Passive exposure is structurally
//! impossible: the fabric never returns `allow` for a flagged item until the
//! viewer's signed consent is on the graph.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ciris_persist::federation::consent::consent_dimension;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::hard_case::ConsentState;
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::{EmitAttestationInput, FederationDirectory};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use serde::{Deserialize, Serialize};

use super::moderation::{admit_moderation_action, Duty};
use crate::auth::verify::{self, VerifyError};

/// The substrate-reserved `content_class:infohazard` flag prefix (a producer /
/// `substrate_persist` emits it; a viewer cannot). CEG 0.3 §5.6.8.3.
pub const CONTENT_CLASS_INFOHAZARD_PREFIX: &str = "content_class:infohazard";
/// The substrate-reserved `content_class:reported` flag prefix.
pub const CONTENT_CLASS_REPORTED_PREFIX: &str = "content_class:reported";
/// The `consent:scope:view` scope the interstitial requires.
pub const CONSENT_SCOPE_VIEW: &str = "consent:scope:view";
/// The bare scope token persist's `resolve_scoped_consent` matches on — the
/// envelope's `"scope"` member carries `"view"`, NOT the `consent:scope:view`
/// dimension limb (that is the dimension spelling, a different string).
const VIEW_SCOPE: &str = "view";

/// The producer-declared content flag (CC 3.3.12), substrate-reserved. Ordered
/// by protective precedence: [`ContentFlag::Infohazard`] outranks
/// [`ContentFlag::Reported`] when both are present and the caller did not
/// disambiguate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentFlag {
    /// Flagged as a potential infohazard (the more severe class).
    Infohazard,
    /// Flagged as reported.
    Reported,
}

impl ContentFlag {
    /// The `content_class` token tail (`"infohazard"` / `"reported"`).
    pub fn as_str(self) -> &'static str {
        match self {
            ContentFlag::Infohazard => "infohazard",
            ContentFlag::Reported => "reported",
        }
    }

    /// Parse from a `content_class` token (`"infohazard"` / `"reported"`).
    pub fn from_token(s: &str) -> Option<ContentFlag> {
        match s {
            "infohazard" => Some(ContentFlag::Infohazard),
            "reported" => Some(ContentFlag::Reported),
            _ => None,
        }
    }

    /// The substrate-reserved `content_class:*` dimension prefix for this flag.
    pub fn dimension_prefix(self) -> &'static str {
        match self {
            ContentFlag::Infohazard => CONTENT_CLASS_INFOHAZARD_PREFIX,
            ContentFlag::Reported => CONTENT_CLASS_REPORTED_PREFIX,
        }
    }

    /// The interstitial prompt the viewer affirms to unlock a reveal.
    pub fn prompt(self) -> &'static str {
        match self {
            ContentFlag::Infohazard => {
                "I consent to view this material reported as a potential infohazard."
            }
            ContentFlag::Reported => "I consent to view this material that has been reported.",
        }
    }
}

/// The consent an interstitial requires the viewer to emit — the wire shape the
/// app publishes via the *existing* attestation surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequiredConsent {
    /// `consent:state:granted`.
    pub state: &'static str,
    /// `consent:scope:view`.
    pub scope: &'static str,
    /// The flagged class the consent must name (`"infohazard"` / `"reported"`).
    pub content_class: String,
}

/// The reveal decision — the whole gate output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealDecision {
    /// Not flagged, or flagged-AND-consented — the app may render the content.
    Allow,
    /// Flagged, no matching live consent — the app MUST show the interstitial and
    /// WITHHOLD the content until a consent-to-view is emitted.
    Interstitial {
        /// Which class the subject is flagged as.
        flag: ContentFlag,
        /// The consent the viewer must emit to unlock the reveal.
        required: RequiredConsent,
    },
}

/// **The pure reveal gate** — CC 4.5.5 `content_class` × CC 3.3.1 consent. No
/// I/O; unit-testable. Mirrors the protective default of
/// [`super::age::gate_content_for`]:
///
/// - `flag == None` → `Allow` (unflagged content is universally visible).
/// - `flag == Some(_) && has_consent` → `Allow` (the viewer consented).
/// - `flag == Some(f) && !has_consent` → `Interstitial { .. }` — the PROTECTIVE
///   default: absent/unknown consent NEVER passively allows.
pub fn infohazard_reveal_decision(flag: Option<ContentFlag>, has_consent: bool) -> RevealDecision {
    match flag {
        None => RevealDecision::Allow,
        Some(_) if has_consent => RevealDecision::Allow,
        Some(flag) => RevealDecision::Interstitial {
            flag,
            required: RequiredConsent {
                state: consent_dimension::STATE_GRANTED_PREFIX,
                scope: CONSENT_SCOPE_VIEW,
                content_class: flag.as_str().to_owned(),
            },
        },
    }
}

// ─── Resolution helpers (I/O-free cores, wired to the substrate above) ───────

/// True if `dimension`/`expires_at` describe a LIVE `content_class:*` flag at
/// `now` (not expired). Pure — the liveness rule, factored for testing.
fn flag_row_is_live(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    expires_at.is_none_or(|exp| exp > now)
}

/// **Resolve the flag on the subject.** Reads the subject's inbound
/// `content_class:*` attestations; a live `content_class:infohazard` /
/// `content_class:reported` row ⇒ flagged. When `requested` is `Some`, only that
/// class counts (the caller disambiguating). Otherwise the more severe
/// [`ContentFlag::Infohazard`] wins over [`ContentFlag::Reported`].
///
/// **The clear fold (latest-wins per class).** A moderator can CLEAR a flag
/// (retain→unflag, CC 4.5.13) — [`emit_content_flag`] with `withdrawn = true`
/// emits a superseding `content_class:{class}:v1` row (still substrate-signed,
/// so the reserved-prefix rule stays satisfied) carrying `"withdrawn": true`.
/// Per class, the row with the newest `asserted_at` decides: a live flag row
/// ⇒ flagged; a newer withdrawal ⇒ cleared; a still-newer re-flag ⇒ flagged
/// again. This mirrors the latest-wins revocation fold persist applies to consent
/// already uses for consent, so a producer→gate flag and its later clear compose
/// without a separate `withdraws`-discovery read.
///
/// Returns `Ok(None)` when the subject carries no live, un-withdrawn flag.
pub async fn subject_flag(
    engine: &Engine,
    subject_key_id: &str,
    requested: Option<ContentFlag>,
) -> Result<Option<ContentFlag>, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let rows = directory
        .list_attestations_for(subject_key_id)
        .await
        .map_err(|e| format!("list flags for subject: {e}"))?;
    let now = Utc::now();
    // Per class: the newest live `content_class:*` row's `(asserted_at, withdrawn)`.
    let mut infohazard: Option<(DateTime<Utc>, bool)> = None;
    let mut reported: Option<(DateTime<Utc>, bool)> = None;
    for row in rows {
        if !flag_row_is_live(row.expires_at, now) {
            continue;
        }
        let Some(dimension) = row
            .attestation_envelope
            .get(paths::DIMENSION)
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        let slot = if dimension.starts_with(CONTENT_CLASS_INFOHAZARD_PREFIX) {
            &mut infohazard
        } else if dimension.starts_with(CONTENT_CLASS_REPORTED_PREFIX) {
            &mut reported
        } else {
            continue;
        };
        let withdrawn = row
            .attestation_envelope
            .get("withdrawn")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        // Latest-wins: keep only the newest row for this class.
        if slot.is_none_or(|(ts, _)| row.asserted_at >= ts) {
            *slot = Some((row.asserted_at, withdrawn));
        }
    }
    // Present iff the newest row for the class is a (non-withdrawn) flag.
    let present = |f: ContentFlag| {
        matches!(
            match f {
                ContentFlag::Infohazard => infohazard,
                ContentFlag::Reported => reported,
            },
            Some((_, false))
        )
    };
    Ok(match requested {
        // Caller disambiguated: only that class counts.
        Some(f) => present(f).then_some(f),
        // Undisambiguated: the more severe class wins.
        None if present(ContentFlag::Infohazard) => Some(ContentFlag::Infohazard),
        None if present(ContentFlag::Reported) => Some(ContentFlag::Reported),
        None => None,
    })
}

/// **Resolve the whole gate against the substrate.** Reads the subject's flag +
/// the viewer's live consent, then applies [`infohazard_reveal_decision`].
pub async fn reveal_decision(
    engine: &Engine,
    viewer_key_id: &str,
    subject_key_id: &str,
    requested: Option<ContentFlag>,
) -> Result<RevealDecision, String> {
    let flag = subject_flag(engine, subject_key_id, requested).await?;
    let has_consent = match flag {
        None => false, // unflagged: consent is moot (Allow regardless).
        Some(f) => {
            // CIRISServer#243 / CIRISPersist#389 — the ONE canonical scoped fold.
            //
            // We used to hand-roll this (`resolve_view_consent` + a `ConsentRow`
            // projection). That duplicate is now DELETED: persist v16.1.1's
            // `resolve_scoped_consent` folds `consent:state:*` rows latest-wins over
            // exactly the rows that name `scope:view` + this `content_class`.
            //
            // The adoption was HELD until v16.1.1 because v16.1.0's fold dropped
            // scope-less rows before the latest-wins step — which would have silently
            // deleted a tested safety property of THIS gate: a viewer who issues a
            // BLANKET `consent:state:revoked` (no scope named) would have kept the
            // infohazard gate OPEN, because an older scoped grant still won. On a CC
            // 4.5.13 child-safety gate that is not an acceptable regression.
            //
            // v16.1.1's `matches_scoped_query` fixes it with the right asymmetry, and
            // is now a strict superset of the fold we deleted:
            //   * a row NAMING this scope       → matches (on content_class);
            //   * a row naming ANOTHER scope    → unrelated, never re-closes us;
            //   * a scope-LESS non-grant        → BLANKET withdrawal, re-closes us;
            //   * a scope-LESS grant            → matches NOTHING (`granted` is the
            //     only fail-OPEN stance, so it must name its scope exactly — you can
            //     never back into a view-consent with a bare `consent:state:granted`).
            //
            // Only `Granted` opens the gate: `Revoked` / `Expired` / `Unspecified` all
            // fail closed, which is the protective default this gate has always had.
            let state = engine
                .federation_directory()
                .resolve_scoped_consent(
                    subject_key_id, // target: whose content is flagged
                    viewer_key_id,  // subject: who asserted the consent
                    VIEW_SCOPE,
                    Some(f.as_str()), // the content_class qualifier
                    chrono::Utc::now(),
                )
                .await
                .map_err(|e| format!("resolve_scoped_consent: {e}"))?;
            matches!(state, ConsentState::Granted)
        }
    };
    Ok(infohazard_reveal_decision(flag, has_consent))
}

// ─── The producer (CIRISServer#181) — substrate-signed flag emit ─────────────

/// **Emit the substrate-reserved `content_class:{class}:v1` flag on `subject`**
/// (CC 4.5.13 producer hook). This is the row [`subject_flag`] reads and the
/// `/v1/safety/reveal` gate keys off — WITHOUT it the gate is inert (every read
/// `allow`s).
///
/// ## Why a `substrate_persist` signer, not the node / duty-holder
///
/// `content_class:` is a **substrate-reserved** prefix: persist's
/// `default_reserved_prefix_rules` admit a `content_class:*` `scores` row ONLY
/// from an emitter whose `federation_keys` row is `identity_type =
/// substrate_persist` (CEG 0.3 §5.6.8.3). The node's OWN key is `identity_type =
/// node` (an infrastructure identity, CC 1.13.5) — emitting the flag with it (or
/// with the duty-holder's key) is refused `federation_reserved_prefix_emitter_mismatch`.
/// So the duty-HOLDER authorizes (the §11.10 gate at the HTTP layer) but the
/// SUBSTRATE signs: `substrate_signer` is the node-scoped `substrate_persist`
/// identity minted + registered at boot (`compose::substrate_persist_signer` /
/// `compose::register_substrate_key`). [`Engine::emit_attestation`] derives the
/// attester/scrub key_id from that signer, so the row's `attesting_key_id` is
/// the substrate identity — never the node or the moderator.
///
/// `withdrawn = false` FLAGS; `withdrawn = true` CLEARS (retain→unflag) — a
/// superseding row [`subject_flag`]'s latest-wins fold reads as "no live flag".
/// Returns the emitted attestation id.
pub async fn emit_content_flag(
    engine: &Engine,
    substrate_signer: &LocalSigner,
    subject_key_id: &str,
    flag: ContentFlag,
    withdrawn: bool,
) -> Result<String, String> {
    let class = flag.as_str();
    // The exact shape `subject_flag` reads + the test harness emits: a `scores`
    // row on `content_class:{class}:v1`, envelope `{dimension, content_class}`
    // (plus `withdrawn: true` on a clear). SCORES is required — the reserved-
    // prefix gate only fires for `scores` rows.
    let dimension = format!("content_class:{class}:v1");
    let mut envelope = serde_json::json!({ (paths::DIMENSION): dimension, "content_class": class });
    if withdrawn {
        envelope["withdrawn"] = serde_json::Value::Bool(true);
    }
    let input = EmitAttestationInput {
        attestation_type: attestation_type::SCORES.to_owned(),
        attested_key_id: Some(subject_key_id.to_owned()),
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .map_err(|e| e.to_string())?,
        subject_key_ids: vec![subject_key_id.to_owned()],
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        expires_at: None,
        weight: None,
    };
    engine
        .emit_attestation(substrate_signer, input)
        .await
        .map_err(|e| format!("emit content_class:{class} flag (substrate-signed): {e}"))
}

// ─── HTTP surface ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct RevealState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct RevealRequest {
    /// The CEG subject a detection / moderation flow may have flagged.
    subject_key_id: String,
    /// Optional disambiguation when both classes are present.
    #[serde(default)]
    content_class: Option<ContentFlag>,
}

/// `POST /v1/safety/reveal` — decide whether the (signed) viewer may reveal a
/// flagged subject. Decision-only: it NEVER emits the consent (the app does, via
/// the existing attestation surface, then re-calls). Every view is attributable —
/// the viewer's signature is required (missing/invalid ⇒ 401).
///
/// - `200 { "decision": "allow" }` — unflagged, or flagged-and-consented.
/// - `403 { "decision": "interstitial", "flag": .., "prompt": .., "required": .. }`
///   — flagged, no live consent (the enforcement).
async fn reveal(State(st): State<RevealState>, headers: HeaderMap, body: Bytes) -> Response {
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
    let req: RevealRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    match reveal_decision(
        &st.engine,
        &caller.key_id,
        &req.subject_key_id,
        req.content_class,
    )
    .await
    {
        Ok(RevealDecision::Allow) => (
            StatusCode::OK,
            Json(serde_json::json!({ "decision": "allow" })),
        )
            .into_response(),
        Ok(RevealDecision::Interstitial { flag, required }) => (
            // 403: the enforcement. The content is WITHHELD until the viewer's
            // consent lands and the app re-calls.
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "decision": "interstitial",
                "flag": flag.as_str(),
                "prompt": flag.prompt(),
                "required": required,
            })),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

// ─── The producer endpoint (CIRISServer#181) — POST /v1/safety/flag ──────────

#[derive(Clone)]
struct FlagState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
    /// The node-scoped `substrate_persist` signer that authors the reserved
    /// `content_class:*` flag. `None` on a node with no substrate identity
    /// wired (the flag endpoint then 503s — the gate stays honestly inert
    /// rather than emitting with the wrong identity).
    substrate_signer: Option<Arc<LocalSigner>>,
}

/// Flag vs. clear (retain→unflag). Defaults to [`FlagAction::Flag`].
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FlagAction {
    /// Emit the `content_class:{class}` flag on the subject.
    #[default]
    Flag,
    /// Clear a prior flag (emit a superseding withdrawal — the latest-wins fold).
    Clear,
}

#[derive(Debug, Deserialize)]
struct FlagRequest {
    /// The acting key (the moderator delegate or the duty-holder itself).
    signer_key_id: String,
    /// The community the moderation action is scoped to (the §11.10 duty gate).
    community_key_id: String,
    /// The CEG subject to flag / clear.
    subject_key_id: String,
    /// Which class (`infohazard` / `reported`).
    content_class: ContentFlag,
    /// `flag` (default) or `clear`.
    #[serde(default)]
    action: FlagAction,
}

#[derive(Debug, Serialize)]
struct FlagResponse {
    /// The emitted `content_class` attestation id.
    attestation_id: String,
    /// The class flagged / cleared.
    content_class: &'static str,
    /// `flag` or `clear`.
    action: &'static str,
    /// The `substrate_persist` identity that SIGNED the reserved flag (never the
    /// duty-holder). The reserved-prefix rule is satisfied by this key, not the
    /// authorizing moderator.
    emitter_key_id: String,
}

/// `POST /v1/safety/flag` — a **duty-gated producer** (CC 4.5.13): a moderator
/// flags a subject and the NODE's `substrate_persist` identity emits the
/// substrate-reserved `content_class:{class}` flag, which makes
/// `/v1/safety/reveal` withhold the subject from non-consented viewers.
///
/// Auth mirrors [`super::moderation`] exactly: `verify_request` → caller;
/// `signer_acts_for`; then the §11.10 `Duty::Moderate` admit-iff gate is the
/// authority (a held/delegated `moderate` duty stands in for "a live-majority
/// favors moderation" in today's model — the FSD-004 live-quorum vote is a
/// future upgrade). A non-duty caller is REFUSED (403).
///
/// The duty-HOLDER authorizes; the SUBSTRATE signs (see [`emit_content_flag`]).
async fn flag(State(st): State<FlagState>, headers: HeaderMap, body: Bytes) -> Response {
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
    let req: FlagRequest = match serde_json::from_slice(&body) {
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
    // COMPOSE the §11.10 admit-iff gate — a `moderate` duty is required.
    match admit_moderation_action(
        &st.engine,
        &req.signer_key_id,
        &req.community_key_id,
        Duty::Moderate,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return err(
                StatusCode::FORBIDDEN,
                "not authorized to flag: the moderate duty is held or delegated, never assumed \
                 (CEG §11.10 — no named-moderator authority and no live delegated chain)",
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
    // The duty-holder authorized; the SUBSTRATE identity signs the reserved flag.
    let Some(substrate_signer) = st.substrate_signer.as_ref() else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no substrate_persist signer wired on this node — cannot author the reserved \
             content_class flag (compose::substrate_persist_signer)",
        );
    };
    let withdrawn = req.action == FlagAction::Clear;
    match emit_content_flag(
        &st.engine,
        substrate_signer,
        &req.subject_key_id,
        req.content_class,
        withdrawn,
    )
    .await
    {
        Ok(attestation_id) => (
            StatusCode::OK,
            Json(FlagResponse {
                attestation_id,
                content_class: req.content_class.as_str(),
                action: if withdrawn { "clear" } else { "flag" },
                emitter_key_id: substrate_signer.derived_key_id(),
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The infohazard reveal-gate + producer router. Default [`HybridPolicy::Strict`].
///
/// `substrate_signer` is the node-scoped `substrate_persist` identity that
/// authors the reserved `content_class:*` flag; pass `None` where no producer
/// endpoint is needed (the reveal gate + `/v1/safety/flag` then 503s the flag).
pub fn router(
    engine: Arc<Engine>,
    policy: HybridPolicy,
    substrate_signer: Option<Arc<LocalSigner>>,
) -> Router {
    Router::new()
        .route("/v1/safety/reveal", axum::routing::post(reveal))
        .with_state(RevealState {
            engine: Arc::clone(&engine),
            policy,
        })
        .merge(
            Router::new()
                .route("/v1/safety/flag", axum::routing::post(flag))
                .with_state(FlagState {
                    engine,
                    policy,
                    substrate_signer,
                }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── flag liveness ───────────────────────────────────────────────────────

    #[test]
    fn flag_liveness_folds_expiry() {
        let now = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        assert!(flag_row_is_live(None, now), "no expiry ⇒ live");
        assert!(
            flag_row_is_live(DateTime::<Utc>::from_timestamp(2_000, 0), now),
            "future expiry ⇒ live"
        );
        assert!(
            !flag_row_is_live(DateTime::<Utc>::from_timestamp(500, 0), now),
            "past expiry ⇒ not live"
        );
    }

    #[test]
    fn content_flag_token_roundtrip() {
        for f in [ContentFlag::Infohazard, ContentFlag::Reported] {
            assert_eq!(ContentFlag::from_token(f.as_str()), Some(f));
        }
        assert_eq!(ContentFlag::from_token("bogus"), None);
    }

    // ─── HTTP: 401 without a signed request (returns before engine use) ───────

    #[tokio::test]
    async fn reveal_requires_a_signature() {
        use axum::body::Body;
        use axum::http::Request;
        use ciris_persist::prelude::LocalSigner;
        use ed25519_dalek::SigningKey;
        use tower::ServiceExt;

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x11; 32]),
            "reveal-test-node".to_string(),
            None,
            None,
        ));
        let engine = Arc::new(
            Engine::with_signer(signer, "sqlite::memory:")
                .await
                .expect("engine"),
        );
        let app = router(engine, HybridPolicy::Strict, None);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/safety/reveal")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "subject_key_id": "some-subject" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
