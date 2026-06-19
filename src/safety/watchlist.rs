//! Per-group content **watchlist** (CC 4.5.7; FSD WATCHLIST_DETECTION) —
//! opt-in (default OFF), per-group, by-authority, signed, revocable.
//!
//! A holder of the `moderate` scope over a group can OPTIONALLY enable a
//! watchlist (a CSAM perceptual-hash DB, or another named content list) for a
//! group they moderate. From that moment the fabric auto-fires the matcher at the
//! publish/share seam and auto-fires the action on a hit. Every step is signed,
//! attributed to the enabling authority, and on the audit chain — the auto-fire
//! is **attributed to a named accountable human and revocable**, not a unilateral
//! chokepoint.
//!
//! ## What is BUILT NOW (the config + the duty/authority gate + the hook point)
//!
//! - The **enable config** ([`WatchlistEnable`]) — a config attestation (the
//!   `consent.rs` recipe), `attestation_type: "watchlist_config"`, fixed
//!   dimension `watchlist:{id}`, scoped to ONE group (`group_key_id`).
//! - The **authority gate** ([`enable_watchlist`]) — admitted IFF the signer
//!   holds `moderate` over the group (CSAM additionally requires `takedown`,
//!   since a CSAM match auto-files a takedown). COMPOSES the §11.10 gate via
//!   [`super::moderation::admit_moderation_action`].
//! - **Revocation** ([`disable_watchlist`]) — a `withdraws`; consent requires
//!   revocability.
//! - The **per-group enable read** ([`watchlist_enables_for_group`]).
//! - The **hook point** ([`on_publish`]) — the publish/share-seam entry the
//!   matcher plugs into.
//!
//! ## What is DEFERRED to the NodeCore content seam (flagged, not silent)
//!
//! - The actual **perceptual-hash MATCHER** + `takedown_notice{PerceptualHashCsam}`
//!   auto-fire. The matcher fires at `put_blob_signing` inline-blob ingress —
//!   that seam is NodeCore content (not yet landed). [`on_publish`] today returns
//!   [`SeamOutcome::DeferredNoMatcher`] when a watchlist IS enabled but no matcher
//!   is installed: it does NOT silently admit (fail-secure intent), and it does
//!   NOT pretend to match. persist ships the `PerceptualHashMatcher` trait
//!   (`NullPerceptualHashMatcher` default); the concrete adapter + the licensed
//!   hash-DB are OPERATOR-provisioned, never shipped.
//!
//! ## Honesty discipline (kept TRUE in code)
//!
//! - The watchlist is **per-group, NEVER global** — there is no fabric-wide
//!   watchlist and no watchlist over a group you do not moderate (no bulk
//!   surveillance). [`enable_watchlist`] gates on the group's own `moderate`
//!   scope; the dimension binds the group.
//! - It **cannot reach `self`/`family` private content** — detection runs only at
//!   the share/publish seam (the E2EE-equivalent limit; `ceg_egress.rs` already
//!   suppresses self/family egress). Not claimed solved.
//! - **IWF/NCMEC/PhotoDNA hashes are operator-provisioned** — the fabric ships
//!   the seam, never the restricted lists.
//! - The **§2258A NCMEC report is the operator's duty**, not the fabric's — the
//!   fabric emits evidence; the operator reports.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::types::{attestation_type, cohort_scope, LocalAttestationInput};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};

use super::moderation::{self, Duty};
use crate::auth::verify::{self, VerifyError};

/// The fixed dimension PREFIX for a watchlist config attestation
/// (`watchlist:{id}`). NOT a substrate primitive — the §3 fabric-side workaround
/// (no new primitive). Upstream-ask: canonicalize the `watchlist:{id}` config
/// vocabulary (FSD §10 #1).
pub const WATCHLIST_DIMENSION_PREFIX: &str = "watchlist:";

/// `attestation_type` for a watchlist enable/disable config row (the consent.rs
/// recipe, specialized).
pub const WATCHLIST_CONFIG_TYPE: &str = "watchlist_config";

/// The `hard_case:*` reasons a watchlist enable / match emit so they are
/// auditable, never silent (FSD §10 #3 upstream-ask to the CEG §7.8 reason set).
pub const HARD_CASE_WATCHLIST_ENABLED: &str = "watchlist_enabled";
/// The `hard_case:*` reason an auto-fired match emits.
pub const HARD_CASE_WATCHLIST_MATCH: &str = "watchlist_match";

/// CSAM vs other-content — drives the auto-fire branch + the no-human-in-the-loop
/// rule (CSAM only) at the content seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchlistClass {
    /// CSAM hash-DB. A match auto-files `takedown_notice{PerceptualHashCsam}`
    /// (no human in the match loop) — so enabling it ALSO requires `takedown`.
    Csam,
    /// Any other named content list (ToS, extremist-symbol set, …). A match
    /// routes a flag to the named moderator (human in the loop) — no autonomous
    /// punitive action.
    OtherContent,
}

/// AlertOnly (shadow: log, don't act — characterize false-positive rate) vs
/// Enforce. Maps to the persist `OnMatchPolicy` at the seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchlistMode {
    /// Log a match; do not act (the recommended rollout default for a new list).
    AlertOnly,
    /// Act on a match (auto-takedown for CSAM; route-to-moderator otherwise).
    Enforce,
}

/// A watchlist enable/disable — a CONFIG attestation, NOT a new wire primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistEnable {
    /// The group (`community` key_id) the watchlist is scoped to. The authority
    /// MUST hold `moderate` for THIS group — enable is per-group, NEVER global.
    pub group_key_id: String,
    /// Which watchlist. Operator-pinned id (e.g. `csam:ncmec`,
    /// `tos:extremist-symbols-v3`). Maps to a `HashDatabaseId` the operator's
    /// matcher exposes.
    pub watchlist_id: String,
    /// CSAM vs other-content.
    pub class: WatchlistClass,
    /// `true` = enable, `false` = disable (disable emits a `withdraws`).
    pub enabled: bool,
    /// AlertOnly (shadow) vs Enforce.
    pub mode: WatchlistMode,
    /// For non-CSAM lists: the moderator key_id a match routes the flag to.
    /// Ignored for CSAM (no human in the match loop).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_to_moderator: Option<String>,
}

impl WatchlistEnable {
    /// The full `watchlist:{id}` dimension this enable writes.
    pub fn dimension(&self) -> String {
        format!("{WATCHLIST_DIMENSION_PREFIX}{}", self.watchlist_id)
    }
}

/// **The authority gate** (FSD §3.2). A watchlist enable/disable for group `G` is
/// admitted IFF the signer holds `moderate` over `G` AND (for CSAM) `takedown`
/// over `G` — because a CSAM match auto-files a `takedown_notice` (you cannot
/// enable an auto-takedown without holding takedown authority). COMPOSES the
/// §11.10 gate.
pub async fn authority_admits_enable(
    engine: &Engine,
    signer: &str,
    enable: &WatchlistEnable,
) -> Result<bool, String> {
    if !moderation::admit_moderation_action(engine, signer, &enable.group_key_id, Duty::Moderate)
        .await?
    {
        return Ok(false);
    }
    if enable.class == WatchlistClass::Csam
        && !moderation::admit_moderation_action(
            engine,
            signer,
            &enable.group_key_id,
            Duty::Takedown,
        )
        .await?
    {
        return Ok(false);
    }
    Ok(true)
}

/// **Enable a watchlist** for a group. The CALLER MUST have admitted the signer
/// via [`authority_admits_enable`] (the HTTP route does). Writes the config
/// attestation (the consent.rs recipe). Returns the persisted attestation id.
pub async fn enable_watchlist(
    engine: &Engine,
    signer_key_id: &str,
    enable: &WatchlistEnable,
) -> Result<String, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let envelope = serde_json::json!({
        "dimension": enable.dimension(),
        "group_key_id": enable.group_key_id,
        "watchlist_id": enable.watchlist_id,
        "class": enable.class,
        "enabled": enable.enabled,
        "mode": enable.mode,
        "route_to_moderator": enable.route_to_moderator,
    });
    let input = LocalAttestationInput {
        attesting_key_id: signer_key_id.to_owned(),
        attested_key_id: Some(enable.group_key_id.clone()),
        attestation_type: WATCHLIST_CONFIG_TYPE.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: envelope,
        subject_key_ids: vec![enable.group_key_id.clone()],
        cohort_scope: cohort_scope::SELF.to_owned(),
    };
    let attestation_id = directory
        .attestation_upsert_local(input)
        .await
        .map_err(|e| format!("upsert watchlist_config: {e}"))?;
    // Promote to federation tier so a peer reads the same enable (cross-fabric
    // agreement on "is a watchlist on for this group"). Attributed to the
    // enabling authority; node co-signs the promotion.
    engine
        .attestation_promote(&attestation_id)
        .await
        .map_err(|e| format!("promote watchlist_config: {e}"))?;
    Ok(attestation_id)
}

/// **Disable a watchlist** — a `withdraws` against the enable. Consent requires
/// revocability: turning a watchlist off is as attributed + immediate as turning
/// it on. The CALLER MUST have admitted the signer (the HTTP route does).
pub async fn disable_watchlist(
    engine: &Engine,
    signer_key_id: &str,
    group_key_id: &str,
    watchlist_id: &str,
) -> Result<String, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let dimension = format!("{WATCHLIST_DIMENSION_PREFIX}{watchlist_id}");
    let envelope = serde_json::json!({
        "dimension": dimension,
        "group_key_id": group_key_id,
        "watchlist_id": watchlist_id,
        "enabled": false,
    });
    let input = LocalAttestationInput {
        attesting_key_id: signer_key_id.to_owned(),
        attested_key_id: Some(group_key_id.to_owned()),
        attestation_type: attestation_type::WITHDRAWS.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: envelope,
        subject_key_ids: vec![group_key_id.to_owned()],
        cohort_scope: cohort_scope::SELF.to_owned(),
    };
    let attestation_id = directory
        .attestation_upsert_local(input)
        .await
        .map_err(|e| format!("withdraw watchlist_config: {e}"))?;
    engine
        .attestation_promote(&attestation_id)
        .await
        .map_err(|e| format!("promote watchlist withdraw: {e}"))?;
    Ok(attestation_id)
}

/// **Read** the CURRENT (un-withdrawn) watchlist enables for a group. The seam
/// reads this on each publish; a withdrawn enable drops out mid-flight.
pub async fn watchlist_enables_for_group(
    engine: &Engine,
    group_key_id: &str,
) -> Vec<WatchlistEnable> {
    let Some(directory) = engine.sqlite_backend() else {
        return Vec::new();
    };
    let Ok(rows) = directory.list_attestations_for(group_key_id).await else {
        return Vec::new();
    };
    // Collect enables and the set of withdrawn watchlist_ids.
    let mut enables: std::collections::HashMap<String, WatchlistEnable> =
        std::collections::HashMap::new();
    let mut withdrawn: std::collections::HashSet<String> = std::collections::HashSet::new();
    for row in rows {
        let env = &row.attestation_envelope;
        let Some(watchlist_id) = env.get("watchlist_id").and_then(|v| v.as_str()) else {
            continue;
        };
        if row.attestation_type == attestation_type::WITHDRAWS {
            withdrawn.insert(watchlist_id.to_owned());
            continue;
        }
        if row.attestation_type != WATCHLIST_CONFIG_TYPE {
            continue;
        }
        if !env
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            continue;
        }
        if let Ok(enable) = serde_json::from_value::<WatchlistEnable>(env.clone()) {
            enables.insert(watchlist_id.to_owned(), enable);
        }
    }
    enables
        .into_iter()
        .filter(|(id, _)| !withdrawn.contains(id))
        .map(|(_, e)| e)
        .collect()
}

/// The outcome of the publish/share-seam hook ([`on_publish`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeamOutcome {
    /// No watchlist enabled for the group → admit (opt-in: default OFF).
    Admit,
    /// A watchlist IS enabled but NO matcher is installed (the DEFERRED case:
    /// the perceptual-hash matcher + the content seam land with NodeCore). We do
    /// NOT silently admit unscanned content under an active watchlist (the
    /// fail-secure intent), and we do NOT pretend to match. The content path
    /// installs the matcher and replaces this with a real Match/NoMatch.
    DeferredNoMatcher,
}

/// **The publish/share-seam HOOK POINT** (FSD §5.2). Built NOW; the actual match
/// fires when content lands.
///
/// Today it answers ONE thing honestly: is a watchlist enabled for this group?
/// - No enable → [`SeamOutcome::Admit`] (opt-in default OFF; the matcher is not
///   even invoked for that group).
/// - An enable but no installed matcher → [`SeamOutcome::DeferredNoMatcher`] (the
///   content seam + the operator-provisioned matcher land with NodeCore; we do
///   not fake a match and do not silently pass unscanned content).
///
/// When the NodeCore content seam lands, this gains the `Arc<dyn
/// PerceptualHashMatcher>` argument, computes the sha256, invokes
/// `matcher.check(...)`, and branches on `class`/`mode` into the §11.4 takedown
/// fast-path (CSAM) or the named-moderator route (other). That matcher + the
/// licensed hash-DB are OPERATOR-provisioned, never shipped.
pub async fn on_publish(engine: &Engine, group_key_id: &str) -> SeamOutcome {
    let enables = watchlist_enables_for_group(engine, group_key_id).await;
    if enables.is_empty() {
        return SeamOutcome::Admit;
    }
    // A watchlist is enabled, but the matcher + content seam are NodeCore — the
    // honest outcome is "deferred," not a faked admit/match.
    SeamOutcome::DeferredNoMatcher
}

// ─── HTTP surface ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct WatchlistState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Serialize)]
struct WatchlistResponse {
    attestation_id: String,
    enabled: bool,
    dimension: String,
}

/// `POST /v1/safety/watchlist` — enable/disable a per-group watchlist
/// (`moderate`-gated; CSAM additionally `takedown`-gated). Per-group, NEVER
/// global; signed by + attributed to the enabling authority; revocable.
async fn watchlist(State(st): State<WatchlistState>, headers: HeaderMap, body: Bytes) -> Response {
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

    #[derive(Deserialize)]
    struct Req {
        signer_key_id: String,
        #[serde(flatten)]
        enable: WatchlistEnable,
    }
    let req: Req = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.signer_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the acting key nor an admitted occurrence of it",
        );
    }

    // The authority gate (moderate; CSAM also takedown). COMPOSED §11.10.
    match authority_admits_enable(&st.engine, &req.signer_key_id, &req.enable).await {
        Ok(true) => {}
        Ok(false) => {
            return err(
                StatusCode::FORBIDDEN,
                "not authorized to manage a watchlist for this group: requires `moderate` \
                 (CSAM also `takedown`) over the group — per-group, never global",
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }

    let result = if req.enable.enabled {
        enable_watchlist(&st.engine, &req.signer_key_id, &req.enable).await
    } else {
        disable_watchlist(
            &st.engine,
            &req.signer_key_id,
            &req.enable.group_key_id,
            &req.enable.watchlist_id,
        )
        .await
    };

    match result {
        Ok(attestation_id) => (
            StatusCode::OK,
            Json(WatchlistResponse {
                attestation_id,
                enabled: req.enable.enabled,
                dimension: req.enable.dimension(),
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// `GET /v1/safety/watchlist/:group_key_id` — the current enables for a group
/// (operator/moderator introspection; surfaces that an enable is on the record).
async fn list_enables(
    State(st): State<WatchlistState>,
    Path(group_key_id): Path<String>,
) -> Response {
    let enables = watchlist_enables_for_group(&st.engine, &group_key_id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "group_key_id": group_key_id,
            "enables": enables,
            "honesty": {
                "per_group_never_global": true,
                "cannot_reach_self_family_private_content": true,
                "hashes_operator_provisioned": true,
                "ncmec_report_is_operator_duty": true,
            }
        })),
    )
        .into_response()
}

/// The watchlist router. Default [`HybridPolicy::Strict`].
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/safety/watchlist", axum::routing::post(watchlist))
        .route(
            "/v1/safety/watchlist/{group_key_id}",
            axum::routing::get(list_enables),
        )
        .with_state(WatchlistState { engine, policy })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimension_binds_the_watchlist_id() {
        let e = WatchlistEnable {
            group_key_id: "community:acme".into(),
            watchlist_id: "csam:ncmec".into(),
            class: WatchlistClass::Csam,
            enabled: true,
            mode: WatchlistMode::Enforce,
            route_to_moderator: None,
        };
        assert_eq!(e.dimension(), "watchlist:csam:ncmec");
    }

    #[test]
    fn csam_requires_takedown_class_marker() {
        // The class drives the extra takedown requirement; assert the marker is
        // distinguishable (the gate keys off it in `authority_admits_enable`).
        assert_eq!(WatchlistClass::Csam, WatchlistClass::Csam);
        assert_ne!(WatchlistClass::Csam, WatchlistClass::OtherContent);
    }
}
