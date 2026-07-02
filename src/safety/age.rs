//! Age-assurance — the protective age-gate (FSD MODERATION_CHILD_SAFETY §4.2;
//! Constitution part_3 `age_assurance:{self|provider:{k}:adult|government:{c}:adult}`).
//!
//! ## What persist v9.0.0 ALREADY ships (narrower gap than the FSD stated)
//!
//! persist v9.0.0 ALREADY RESERVES the `age_assurance:` dimension prefix as a
//! **witness-emitted** family (`default_reserved_prefix_rules` — a registered
//! age-assurance PROVIDER, `identity_type = witness`, CEG 0.3 §5.6.8.3). So the
//! `provider:`/`government:` ladder rungs map onto the shipped reserved prefix:
//! a verifier service registered as a `witness` emits `age_assurance:{level}`.
//!
//! The GAP is therefore narrower than "no dimension": it is the **self-declared**
//! rung. A subject's self-declaration is NOT a provider attestation, so it MUST
//! NOT borrow the witness-reserved `age_assurance:` prefix (the substrate rejects
//! a `user` emitter there — correctly). We emit self-declaration on a DISTINCT,
//! non-reserved dimension [`AGE_SELF_DECLARED_DIMENSION_PREFIX`]
//! (`age_self_declared:{band}`), subject-signed. The read accessor unions both:
//! a `witness`-emitted `age_assurance:*` (provider/government) OUTRANKS a
//! subject `age_self_declared:*`. Upstream-ask: canonicalize the self-declared
//! dimension name + the `self < provider < government` ordering for cross-fabric
//! agreement (the provider/government prefix is already canonical upstream).
//!
//! ## What ships now
//!
//! 1. **emit/store** — [`emit_age_assurance`] writes a subject-signed `scores`
//!    row on the `age_assurance:{level}` dimension. We start with `self`
//!    (self-declared age range — the onboarding "state your age range" step) and
//!    structure the ladder so `provider:` / `government:` levels slot in later.
//! 2. **read** — [`read_age_level`] resolves an identity's current (highest) age
//!    level from its `scores` rows.
//! 3. **the protective gate** — [`gate_content_for`] decides visibility: a minor
//!    viewer is BLOCKED from `adult`-class content; the protective default.
//!
//! ## Honesty discipline
//!
//! - **Misdeclaration NEVER fires slashing.** A wrong self-declaration routes to
//!   the [`MISDECLARATION_ALLEGATION`] adjudication path (a `moderation:*`
//!   ModerationEvent + quorum — [`super::moderation`]), never `slashing:*`. The
//!   data subject controls their own assurance level.
//! - **`self`-level is unfalsifiable from inside the fabric** (SAFETY_LANDSCAPE
//!   §5.2 / FSD §B.5) — a sensitive space must REQUIRE a verified level
//!   (`provider:`/`government:`), which `self` does not satisfy. The gate's
//!   default is *protective* (deny adult content to anything below `adult`),
//!   never permissive.

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

use crate::auth::verify::{self, VerifyError};

/// The witness-RESERVED dimension prefix for a PROVIDER/GOVERNMENT-attested
/// age-assurance `scores` row (persist `default_reserved_prefix_rules` —
/// `identity_type = witness`; CEG 0.3 §5.6.8.3). A subject CANNOT emit on this
/// prefix; a registered verifier (`witness`) does. Read here, emitted by the
/// out-of-fabric verifier path (not yet wired).
pub const AGE_ASSURANCE_DIMENSION_PREFIX: &str = "age_assurance:";

/// The NON-reserved dimension prefix for a SUBJECT's SELF-DECLARED age band
/// (`age_self_declared:{band}`). Subject-signed; distinct from the witness-
/// reserved provider prefix above (a self-declaration is not a provider
/// attestation). This is the onboarding "state your age range" rung.
pub const AGE_SELF_DECLARED_DIMENSION_PREFIX: &str = "age_self_declared:";

/// The `moderation:*` allegation type a misdeclaration routes to — the
/// adjudication path. **A misdeclaration is NEVER `slashing:*` alone** (FSD
/// §4.2 / part_3 namespace); it is a `ModerationEvent` adjudicated by quorum.
pub const MISDECLARATION_ALLEGATION: &str = "age_assurance_misdeclaration";

/// The age band the subject self-declares at ID setup (the onboarding "state
/// your age range" step). The ordering is by protection: a `Minor` viewer is
/// gated out of adult content; `Adult` is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeBand {
    /// Under the age of majority — gated OUT of adult content (the protective
    /// default also covers "declined to state" and "unknown").
    Minor,
    /// At/over the age of majority.
    Adult,
}

impl AgeBand {
    /// The canonical token used in the `age_assurance:{level}` dimension tail.
    pub fn as_str(self) -> &'static str {
        match self {
            AgeBand::Minor => "minor",
            AgeBand::Adult => "adult",
        }
    }

    pub fn from_token(s: &str) -> Option<AgeBand> {
        match s {
            "minor" => Some(AgeBand::Minor),
            "adult" => Some(AgeBand::Adult),
            _ => None,
        }
    }
}

/// The assurance LEVEL — how the band was established. The ladder is
/// `Self < Provider < Government` (FSD §4.2): a sensitive space may require a
/// verified level, which bare `Self` does not satisfy. Only `Self` is wired now;
/// the others are structured for later (the verifier path is out-of-fabric).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// Self-declared (the onboarding default; unfalsifiable from inside).
    SelfDeclared,
    /// Attested by a third-party provider (`provider:{verifier_key}:adult`).
    /// Structured for later — the verifier is an out-of-fabric service.
    Provider,
    /// Attested by a government credential (`government:{credential_class}:adult`).
    /// Structured for later.
    Government,
}

impl AssuranceLevel {
    /// The canonical token used in the `age_assurance:{level}` dimension.
    pub fn as_str(self) -> &'static str {
        match self {
            AssuranceLevel::SelfDeclared => "self",
            AssuranceLevel::Provider => "provider",
            AssuranceLevel::Government => "government",
        }
    }

    fn from_token(s: &str) -> Option<AssuranceLevel> {
        match s {
            "self" => Some(AssuranceLevel::SelfDeclared),
            "provider" => Some(AssuranceLevel::Provider),
            "government" => Some(AssuranceLevel::Government),
            _ => None,
        }
    }
}

/// A resolved age assurance — the band PLUS how it was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgeAssurance {
    /// The declared/verified age band.
    pub band: AgeBand,
    /// The level the band was established at (`self`/`provider`/`government`).
    pub level: AssuranceLevel,
}

/// A content class for the protective gate (FSD §4.3 `content_class:{class}`).
/// We model the gate-relevant distinction now: `Adult`-class content is gated
/// away from minors; `General` is universally visible. The full
/// `content_rating:{scheme}:{rating}` vocabulary slots in at the content seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    /// Visible to everyone.
    General,
    /// Adult-only — minors are gated OUT (the protective default).
    Adult,
}

/// **The protective age-gate.** Decide whether a viewer at `viewer` assurance
/// may see content of `content_class`.
///
/// The default is PROTECTIVE, not permissive:
/// - `General` content is visible to everyone.
/// - `Adult` content is visible ONLY to a viewer whose band is [`AgeBand::Adult`].
///   A `Minor` band — and, by the caller's choice via [`read_age_level`], the
///   *absence* of any assurance (which resolves to the protective `Minor`
///   default) — is BLOCKED.
///
/// This function NEVER fires slashing on a mismatch; it only decides visibility.
/// A space that needs a *verified* adult (not bare self-declaration) checks the
/// returned [`AgeAssurance::level`] separately — `self` is unfalsifiable.
pub fn gate_content_for(viewer: AgeAssurance, content_class: ContentClass) -> bool {
    match content_class {
        ContentClass::General => true,
        ContentClass::Adult => viewer.band == AgeBand::Adult,
    }
}

/// Build the dimension for a (level, band) pair. The SELF level uses the
/// non-reserved `age_self_declared:{band}` prefix (subject-signed); PROVIDER /
/// GOVERNMENT use the witness-reserved `age_assurance:{level}:{band}` prefix.
pub fn age_dimension(level: AssuranceLevel, band: AgeBand) -> String {
    // Every `scores` dimension MUST carry a `:vN` version segment (persist
    // `require_version_segment`, CEG §13.1).
    match level {
        AssuranceLevel::SelfDeclared => {
            format!("{AGE_SELF_DECLARED_DIMENSION_PREFIX}{}:v1", band.as_str())
        }
        AssuranceLevel::Provider | AssuranceLevel::Government => format!(
            "{AGE_ASSURANCE_DIMENSION_PREFIX}{}:{}:v1",
            level.as_str(),
            band.as_str()
        ),
    }
}

/// Parse a self-declared or provider/government age dimension back into its
/// parts (the inverse of [`age_dimension`]). Tolerant of the trailing `:vN`.
fn parse_age_dimension(dimension: &str) -> Option<AgeAssurance> {
    // Strip a trailing `:vN` version segment if present.
    let core = dimension
        .rsplit_once(":v")
        .filter(|(_, v)| v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty())
        .map(|(head, _)| head)
        .unwrap_or(dimension);
    if let Some(band_tok) = core.strip_prefix(AGE_SELF_DECLARED_DIMENSION_PREFIX) {
        return Some(AgeAssurance {
            level: AssuranceLevel::SelfDeclared,
            band: AgeBand::from_token(band_tok)?,
        });
    }
    let rest = core.strip_prefix(AGE_ASSURANCE_DIMENSION_PREFIX)?;
    let (level_tok, band_tok) = rest.split_once(':')?;
    Some(AgeAssurance {
        level: AssuranceLevel::from_token(level_tok)?,
        band: AgeBand::from_token(band_tok)?,
    })
}

/// **Emit/store** a subject-signed `age_assurance:{level}` `scores` row. The
/// onboarding "state your age range" step calls this at `self` level. Writes a
/// local-tier (`cohort_scope: self`) row keyed by the subject's own occurrence —
/// the subject controls their own assurance.
///
/// Returns the persisted attestation id. The caller may `attestation_promote` it
/// to federation visibility (the same recipe `consent.rs` uses) when a space
/// needs to read it across the federation.
pub async fn emit_age_assurance(
    engine: &Engine,
    subject_key_id: &str,
    level: AssuranceLevel,
    band: AgeBand,
) -> Result<String, String> {
    emit_age_assurance_inner(engine, subject_key_id, level, band, true).await
}

/// Local-tier-only variant: persist the self-declared age WITHOUT promoting it to
/// the federation tier. The LOCAL gate ([`read_age_level`] → `list_attestations_by`)
/// reads local rows, so this is sufficient for a node enforcing its OWN owner's
/// age (the wizard self-age). Federation promotion (cross-node visibility) is
/// skipped — it requires the subject's federation-key shape the local self-age
/// path doesn't need, and on a fresh node the promote FK-fails.
pub async fn emit_age_assurance_local(
    engine: &Engine,
    subject_key_id: &str,
    level: AssuranceLevel,
    band: AgeBand,
) -> Result<String, String> {
    emit_age_assurance_inner(engine, subject_key_id, level, band, false).await
}

/// **CEG-native signed self-declared age.** The subject signs the
/// `scores` / `age_self_declared:{band}` attestation with their OWN fed-ID
/// (`signer`) and it lands at federation tier via
/// [`crate::auth::ownership::emit_signed_attestation`] — a properly-signed CEG
/// object, readable by `read_age_level` (`list_attestations_by`). This replaces
/// the unsigned local-upsert + `attestation_promote` path, which is broken on real
/// nodes (CIRISPersist#247: promote's `scrub_key_id` FK). `signer.key_id()` is the
/// subject. Use when the node holds the subject's signer (the wizard self-age).
pub async fn emit_age_assurance_signed(
    engine: &Engine,
    signer: &ciris_persist::prelude::LocalSigner,
    level: AssuranceLevel,
    band: AgeBand,
) -> Result<String, String> {
    let subject = signer.key_id().to_string();
    let dimension = age_dimension(level, band);
    let envelope = serde_json::json!({
        "dimension": dimension,
        "band": band.as_str(),
        "level": level.as_str(),
    });
    crate::auth::ownership::emit_signed_attestation(
        engine,
        signer,
        attestation_type::SCORES,
        &subject,
        envelope,
        vec![subject.clone()],
        None, // an age-assurance score is not time-bounded.
    )
    .await
    .map_err(|e| format!("emit signed age assurance: {e}"))
}

async fn emit_age_assurance_inner(
    engine: &Engine,
    subject_key_id: &str,
    level: AssuranceLevel,
    band: AgeBand,
    promote: bool,
) -> Result<String, String> {
    let directory = engine
        .sqlite_backend()
        .ok_or_else(|| "no SQLite federation directory".to_string())?;
    let dimension = age_dimension(level, band);
    let envelope = serde_json::json!({
        "dimension": dimension,
        "band": band.as_str(),
        "level": level.as_str(),
    });
    let input = LocalAttestationInput {
        attesting_key_id: subject_key_id.to_owned(),
        attested_key_id: Some(subject_key_id.to_owned()),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: envelope,
        subject_key_ids: vec![subject_key_id.to_owned()],
        cohort_scope: cohort_scope::SELF.to_owned(),
    };
    let attestation_id = directory
        .attestation_upsert_local(input)
        .await
        .map_err(|e| format!("upsert age_assurance: {e}"))?;
    // Promote to federation tier so the age level is readable across the
    // federation (a gate running on any node consumes it). The node co-signs the
    // promotion (the same recipe consent.rs uses). The DECLARED VALUE remains the
    // subject's — promotion is visibility, not authorship.
    if promote {
        engine
            .attestation_promote(&attestation_id)
            .await
            .map_err(|e| format!("promote age_assurance: {e}"))?;
    }
    Ok(attestation_id)
}

/// **Read** an identity's current age assurance — the HIGHEST level it has
/// declared/verified. Resolves over the subject's `scores` rows on
/// `age_assurance:*` dimensions.
///
/// Returns `None` when the identity has NO age assurance on record. Callers MUST
/// treat `None` PROTECTIVELY — the gate's default for an unknown viewer is
/// [`AgeBand::Minor`] (deny adult content), never permissive. [`viewer_or_minor`]
/// is the helper that encodes that default.
pub async fn read_age_level(engine: &Engine, subject_key_id: &str) -> Option<AgeAssurance> {
    let directory = engine.sqlite_backend()?;
    // Both the subject's own (`by`) and subject-targeted (`for`) rows; an
    // age-assurance row is self-attested so `by` is the primary source.
    let rows = directory.list_attestations_by(subject_key_id).await.ok()?;
    let mut best: Option<AgeAssurance> = None;
    for row in rows {
        if row.attestation_type != attestation_type::SCORES {
            continue;
        }
        let Some(dimension) = row
            .attestation_envelope
            .get("dimension")
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        let Some(a) = parse_age_dimension(dimension) else {
            continue;
        };
        // Keep the strongest (highest) level on record. The band of the
        // strongest level wins.
        best = match best {
            Some(prev) if prev.level >= a.level => Some(prev),
            _ => Some(a),
        };
    }
    best
}

/// Resolve a viewer's assurance, defaulting to the PROTECTIVE band when none is
/// on record: an unknown viewer is treated as a [`AgeBand::Minor`] at the
/// `self` level (deny adult content). This is the safe default the gate uses.
pub async fn viewer_or_minor(engine: &Engine, viewer_key_id: &str) -> AgeAssurance {
    read_age_level(engine, viewer_key_id)
        .await
        .unwrap_or(AgeAssurance {
            band: AgeBand::Minor,
            level: AssuranceLevel::SelfDeclared,
        })
}

// ─── HTTP surface (the safety cards drive these) ────────────────────────────

#[derive(Clone)]
struct AgeState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct SetAgeRequest {
    /// The subject's own `federation_keys.key_id`.
    subject_key_id: String,
    /// The declared band (`minor` / `adult`).
    band: AgeBand,
    /// The level — only `self` is wired now; omit to default to `self`.
    #[serde(default)]
    level: Option<AssuranceLevel>,
}

#[derive(Debug, Serialize)]
struct SetAgeResponse {
    attestation_id: String,
    dimension: String,
}

/// `POST /v1/safety/age-assurance` — set the caller's self-declared age level.
/// Signed by the subject (or an admitted occurrence) — the subject controls
/// their own assurance. NEVER slashes on the value.
async fn set_age(State(st): State<AgeState>, headers: HeaderMap, body: Bytes) -> Response {
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
    let req: SetAgeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    // The subject controls their OWN assurance: the signer must be the subject
    // or an admitted occurrence of it.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.subject_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "age assurance must be signed by the subject or an admitted occurrence of it",
        );
    }
    let level = req.level.unwrap_or(AssuranceLevel::SelfDeclared);
    // Only `self` is wired now (provider/government need an out-of-fabric
    // verifier path); a higher level via this self-signed route is refused —
    // a subject cannot self-mint a `provider`/`government` adulthood.
    if level != AssuranceLevel::SelfDeclared {
        return err(
            StatusCode::BAD_REQUEST,
            "only self-declared level is supported via this route; provider/government \
             levels require a verifier attestation (not yet wired)",
        );
    }
    match emit_age_assurance(&st.engine, &req.subject_key_id, level, req.band).await {
        Ok(attestation_id) => (
            StatusCode::OK,
            Json(SetAgeResponse {
                attestation_id,
                dimension: age_dimension(level, req.band),
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[derive(Debug, Serialize)]
struct AgeStatusResponse {
    key_id: String,
    /// `None` when no assurance is on record (callers MUST treat as protective).
    assurance: Option<AgeAssurance>,
}

/// `GET /v1/safety/age-assurance/:key_id` — read an identity's age level.
async fn get_age(State(st): State<AgeState>, Path(key_id): Path<String>) -> Response {
    let assurance = read_age_level(&st.engine, &key_id).await;
    (
        StatusCode::OK,
        Json(AgeStatusResponse { key_id, assurance }),
    )
        .into_response()
}

/// `GET /v1/safety/status` — the aggregate safety status for the caller's
/// identity (age assurance today; moderation duties fold in as the cards grow).
async fn safety_status(State(st): State<AgeState>, Path(key_id): Path<String>) -> Response {
    let assurance = read_age_level(&st.engine, &key_id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "key_id": key_id,
            "age_assurance": assurance,
            // Honest framing surfaced to the client (kept TRUE in the wire):
            "honesty": {
                "self_level_unfalsifiable": true,
                "misdeclaration_routes_to_adjudication": MISDECLARATION_ALLEGATION,
            }
        })),
    )
        .into_response()
}

/// The age-assurance + safety-status router. Default [`HybridPolicy::Strict`].
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/safety/age-assurance", axum::routing::post(set_age))
        .route(
            "/v1/safety/age-assurance/{key_id}",
            axum::routing::get(get_age),
        )
        .route(
            "/v1/safety/status/{key_id}",
            axum::routing::get(safety_status),
        )
        .with_state(AgeState { engine, policy })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_blocks_minor_from_adult_allows_adult() {
        let minor = AgeAssurance {
            band: AgeBand::Minor,
            level: AssuranceLevel::SelfDeclared,
        };
        let adult = AgeAssurance {
            band: AgeBand::Adult,
            level: AssuranceLevel::SelfDeclared,
        };
        // Minor blocked from adult content; adult allowed.
        assert!(!gate_content_for(minor, ContentClass::Adult));
        assert!(gate_content_for(adult, ContentClass::Adult));
        // General content visible to everyone (protective != prudish).
        assert!(gate_content_for(minor, ContentClass::General));
        assert!(gate_content_for(adult, ContentClass::General));
    }

    #[test]
    fn dimension_roundtrips() {
        // Self-declared uses the non-reserved prefix (subject-signed), versioned.
        let d = age_dimension(AssuranceLevel::SelfDeclared, AgeBand::Adult);
        assert_eq!(d, "age_self_declared:adult:v1");
        let a = parse_age_dimension(&d).expect("parse self");
        assert_eq!(a.band, AgeBand::Adult);
        assert_eq!(a.level, AssuranceLevel::SelfDeclared);
        // Provider uses the witness-reserved `age_assurance:` prefix, versioned.
        let p = age_dimension(AssuranceLevel::Provider, AgeBand::Adult);
        assert_eq!(p, "age_assurance:provider:adult:v1");
        let pa = parse_age_dimension(&p).expect("parse provider");
        assert_eq!(pa.level, AssuranceLevel::Provider);
    }

    #[test]
    fn level_ordering_self_lowest() {
        assert!(AssuranceLevel::SelfDeclared < AssuranceLevel::Provider);
        assert!(AssuranceLevel::Provider < AssuranceLevel::Government);
    }
}
