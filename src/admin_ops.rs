//! **The graded admin-op ladder, tiers 0–4** (CIRISServer#346, adoption debt
//! #361) — the owner-gated routes that make the substrate's removal primitives
//! reachable from this node.
//!
//! Every primitive these routes call shipped in persist and had **zero callers
//! here** (#361: seven for seven). The mesh was manageable; this node could not
//! manage it. This module is the caller.
//!
//! ```text
//! POST /v1/admin/preview      read-only  -> exact row set + counts + SELECTION HASH
//! POST /v1/admin/annotate     tier 0     scope: review
//! POST /v1/admin/throttle     tier 1     scope: moderate     (+ un_throttle)
//! POST /v1/admin/quarantine   tier 2     scope: moderate*    (+ un_quarantine)
//! POST /v1/admin/descend      tier 3     scope: slash + QUORUM
//! POST /v1/admin/deadmit      tier 4     scope: slash        (+ re_admit)
//! ```
//!
//! `*` — see [`REQUIRED_SCOPE_QUARANTINE`]. The FSD ladder says tier 2 is
//! `moderate`; persist's own admission door says `slash`. The substrate wins.
//!
//! # The five properties, each gated by a test in `tests/admin_ops.rs`
//!
//! 1. **Preview-hash commit.** Every mutating call presents the hash its
//!    preview returned; a mismatch REFUSES ([`SELECTION_HASH_VERSION`],
//!    [`selection_hash`]). What was previewed is what executes — TOCTOU-closed,
//!    and the left-pad rule: a retraction needs a blast-radius check, as a gate
//!    rather than a convenience. The preview is an [`AttestationFilter`]
//!    push-down (the UI's filter IS the query filter) — the #343 read pattern
//!    `graph_config::live_config_rows` established, never the whole-corpus
//!    self-authored scan that cost a 152-second boot phase.
//! 2. **Authority in the artifact.** `{delegation_id, reason}` are REQUIRED in
//!    every tombstone and the call is refused without them. Persist enforces
//!    this independently at `record_hard_case`
//!    (`check_admin_action_attribution`) and at the quarantine door
//!    (`QuarantineRefusalReason::Unattributed`); this module refuses first so
//!    the operator gets a localizable reason instead of a substrate error.
//!    *An action that does not carry its own authority cannot be told from an
//!    unauthorized one once the actor is gone.*
//! 3. **Reversal ops exist.** `un_throttle`, `un_quarantine`, `re_admit` are
//!    routes, not adjectives. What each one actually reverses is reported
//!    honestly per op — see [`ReversalReach`].
//! 4. **Tier 3 takes quorum, not one delegation chain.** It is the only
//!    irreversible op, and gating by irreversibility rather than blast radius
//!    is the correction the 344-failure audit forced.
//!    [`DESCEND_QUORUM_MIN`] distinct authority roots, each independently
//!    re-derived from this node's own verified state.
//! 5. **Tier 3 accepts an optional `after:`** — the time-bounded judgement a
//!    key compromise needs. It is a real [`AttestationFilter::window`]
//!    push-down, so it changes the selection AND the hash.
//!
//! # Authority is re-derived, never asserted (#377)
//!
//! A caller names a `delegation_id`. This module does NOT trust it: it resolves
//! the row, requires it to be a live `delegates_to` **to the acting key**, and
//! then re-walks `reachable_under_scope(issuer → actor, scope)` — persist's own
//! §11.10 walk (⊆-attenuation, `sub_delegation` deputization, per-edge
//! `withdraws` skipping, depth ≤
//! [`MAX_MODERATION_DELEGATION_DEPTH`](ciris_persist::federation::admission::MAX_MODERATION_DELEGATION_DEPTH)).
//! The recorded `delegation_id` is therefore an id that WAS checked, not one
//! that was merely written down.
//!
//! # Why `CapabilityVerb::Wipe`
//!
//! Every route here is gated on the never-delegatable
//! [`Wipe`](crate::auth::gate::CapabilityVerb::Wipe) verb rather than a new
//! per-tier verb. Consequence, stated rather than discovered later: **no
//! delegated bearer token may run a graded admin op — only the owner
//! directly.** The graded part of the authority is the persist-side delegation
//! scope (`review` / `moderate` / `slash`), which is where the ladder actually
//! lives; the verb layer is about what a *delegated session* may do, and the
//! fail-secure answer there is "none of this".
//!
//! # Operator-facing strings
//!
//! Every human-readable string is a `{id, text}` pair, like
//! [`crate::peer::consent_disclosure_json`]. `id` is a stable message key;
//! `text` is the English source. **Never hand a UI a pre-formatted sentence.**
//! The ids are wire-stable: renaming one silently un-translates that string in
//! every locale. If the MEANING changes, mint a new id (`…:v2`).
//!
//! # Deliberately NOT here
//!
//! Tiers S (self-directed) and R (subject-side reader policy), and everything
//! on the mesh-config plane. The latter is blocked on CIRISConstitution#57:
//! CC 4.2.1 scopes accord signatures to `EmergencyShutdown` alone, so nobody
//! may sign a mesh-config row yet.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ciris_persist::ceg::list::federation::AttestationFilter;
use ciris_persist::federation::admission::{
    DELEGATION_SCOPE_MODERATE, DELEGATION_SCOPE_REVIEW, DELEGATION_SCOPE_SLASH,
    MAX_MODERATION_DELEGATION_DEPTH,
};
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::hard_case::{admin_action_event, admin_op, HardCaseEvent};
use ciris_persist::federation::quarantine;
use ciris_persist::federation::types::{
    attestation_tier, attestation_type, cohort_scope, Attestation, Revocation, SignedRevocation,
};
use ciris_persist::prelude::{CallerScope, Engine};

use crate::auth::gate::CapabilityVerb;
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

// ═══════════════════════════════════════════════════════════════════════════
//  Vocabulary
// ═══════════════════════════════════════════════════════════════════════════

/// The delegation scope tier 0 (`annotate`) requires — a signed judgement with
/// no effect until honoured needs the review duty, nothing more.
pub const REQUIRED_SCOPE_ANNOTATE: &str = DELEGATION_SCOPE_REVIEW;

/// The delegation scope tier 1 (`throttle` / `un_throttle`) requires.
pub const REQUIRED_SCOPE_THROTTLE: &str = DELEGATION_SCOPE_MODERATE;

/// The delegation scope tier 2 (`quarantine` / `un_quarantine`) requires.
///
/// **This is `slash`, and the FSD ladder says `moderate`.** The divergence is
/// persist's, and persist is right to own it: a quarantine marker takes
/// something away, so
/// `check_delegated_duty_scores_admission`'s `QUARANTINE_DIMENSION_PREFIX` arm
/// gates it on `slash` — *"there is no laxer path for the harsher op"*. A route
/// that advertised `moderate` here would be advertising an authority the
/// substrate refuses at the door, which is the worst of both: the operator is
/// told they may act and the write fails anyway.
pub const REQUIRED_SCOPE_QUARANTINE: &str = DELEGATION_SCOPE_SLASH;

/// The delegation scope tier 3 (`descend`) requires — of EVERY quorum member.
pub const REQUIRED_SCOPE_DESCEND: &str = DELEGATION_SCOPE_SLASH;

/// The delegation scope tier 4 (`deadmit` / `re_admit`) requires.
pub const REQUIRED_SCOPE_DEADMIT: &str = DELEGATION_SCOPE_SLASH;

/// **Tier 3 quorum floor** — distinct authority ROOTS (not distinct
/// `delegation_id`s: two chains from one root are one authority wearing two
/// hats) that must each independently reach the acting key under `slash`.
///
/// Two, not three: the audit's correction was that tier 3 needed *more than one
/// delegation chain*, and a floor that cannot be met is a floor that gets
/// bypassed. Raising it is a one-line change with a test that reads the
/// constant.
pub const DESCEND_QUORUM_MIN: usize = 2;

/// `admin_action:{op}` suffix for tier 0. Persist's `admin_op` vocabulary is
/// OPEN (`ADMIN_ACTION_PREFIX` + any suffix); it names `quarantine`,
/// `quarantine_release` and `de_admission` itself, and the rest are minted
/// here.
pub const OP_ANNOTATE: &str = "annotate";
/// `admin_action:{op}` suffix for tier 1.
pub const OP_THROTTLE: &str = "throttle";
/// `admin_action:{op}` suffix for the tier 1 reversal.
pub const OP_THROTTLE_RELEASE: &str = "throttle_release";
/// `admin_action:{op}` suffix for tier 3.
pub const OP_DESCEND: &str = "descend";
/// `admin_action:{op}` suffix for the tier 4 reversal.
pub const OP_RE_ADMISSION: &str = "re_admission";

/// Default page size for a preview. A bound, not a working set.
pub const DEFAULT_PREVIEW_LIMIT: i64 = 500;

/// Hard ceiling on a preview page. A selection an operator cannot read is a
/// selection they cannot ratify, and the hash would be a rubber stamp.
pub const MAX_PREVIEW_LIMIT: i64 = 2_000;

/// Version tag inside the selection-hash preimage. Bumping it invalidates every
/// outstanding preview by construction — which is the point: a hash whose
/// meaning changed silently is worse than no hash.
pub const SELECTION_HASH_VERSION: &str = "ciris-admin-selection:v1";

/// The locale the `text` half of every `{id, text}` pair is written in.
const SOURCE_LOCALE: &str = "en";

// ═══════════════════════════════════════════════════════════════════════════
//  Localizable strings
// ═══════════════════════════════════════════════════════════════════════════

/// One localizable string: a stable key plus its English source.
fn m(id: &str, text: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "text": text })
}

/// A refusal: a **stable program token** the caller can branch on, plus the
/// `{id, text}` pair a UI renders. Never a pre-formatted sentence.
fn refusal(code: StatusCode, token: &str, id: &str, text: &str) -> Response {
    (
        code,
        Json(serde_json::json!({
            "refused": true,
            "refusal": token,
            "source_locale": SOURCE_LOCALE,
            "message": m(id, text),
        })),
    )
        .into_response()
}

/// A non-refusal error (substrate unavailable, bad JSON) in the same shape, so
/// a caller has ONE response contract.
fn err(code: StatusCode, token: &str, id: &str, text: String) -> Response {
    (
        code,
        Json(serde_json::json!({
            "refused": true,
            "refusal": token,
            "source_locale": SOURCE_LOCALE,
            "message": m(id, &text),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
//  State + the owner gate
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct AdminOpsState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — the ACTING key of every op here, and
    /// the key whose delegated authority is re-walked.
    node_key_id: String,
}

/// Owner-authority gate. Identical spine to
/// [`crate::federation_admin`]'s: `resolve_bearer → SessionCaller →
/// SYSTEM_ADMIN + FullAccess`. Both, so neither a role-permission drift nor a
/// permission-only check can silently widen who may remove other people's rows.
async fn require_owner(st: &AdminOpsState, headers: &HeaderMap) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_absent",
            "admin.refusal.session_absent",
            "No session token was presented. Graded admin operations are owner-only.",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(caller)
        }
        Ok(Some(_)) => Err(refusal(
            StatusCode::FORBIDDEN,
            "not_owner",
            "admin.refusal.not_owner",
            "Graded admin operations require the owner (SYSTEM_ADMIN) role.",
        )),
        Ok(None) => Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "admin.refusal.session_invalid",
            "That session is invalid or expired.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "admin.refusal.store_unavailable",
            format!("The substrate could not be read: {e}"),
        )),
    }
}

/// The gate stack every route in this module runs, in this order: serve-only
/// floor (an unowned node performs no judgement on anyone's behalf) → owner
/// session → the never-delegatable `Wipe` verb.
async fn gate(st: &AdminOpsState, headers: &HeaderMap) -> Result<(), Response> {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "node_unowned",
            "admin.refusal.node_unowned",
            "This node has no responsible party (owner-binding), so it performs no graded \
             admin operation on anyone's behalf. Claim ownership first.",
        ));
    }
    let caller = require_owner(st, headers).await?;
    if let Some(resp) = crate::auth::gate::require_verb(&caller, CapabilityVerb::Wipe) {
        return Err(resp);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//  Selection — the UI's filter IS the query filter (#343)
// ═══════════════════════════════════════════════════════════════════════════

/// The operator's selection. Every field is an [`AttestationFilter`] predicate
/// pushed into the QUERY — there is no application-side `continue` anywhere in
/// this module, which is the whole #343 lesson.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct Selection {
    /// Rows authored BY this key (the key being judged, in almost every op).
    #[serde(default)]
    pub attesting_key_id: Option<String>,
    /// Rows authored ABOUT this key.
    #[serde(default)]
    pub attested_key_id: Option<String>,
    /// `scores` / `delegates_to` / `withdraws` / …
    #[serde(default)]
    pub attestation_type: Option<String>,
    /// Hierarchical dimension prefixes, OR-combined.
    #[serde(default)]
    pub dimension_prefixes: Vec<String>,
    /// Exact dimension match, AND-composed with the prefix set.
    #[serde(default)]
    pub dimension_exact: Option<String>,
    /// Rows naming this subject.
    #[serde(default)]
    pub subject_key_id: Option<String>,
    /// **The time bound.** Half-open `[after, before)` on `asserted_at`,
    /// pushed down as [`AttestationFilter::window`]. Tier 3's optional
    /// `after:` is this field — the time-bounded judgement a key compromise
    /// needs, and it changes the selection hash because it changes the
    /// selection.
    #[serde(default)]
    pub after: Option<DateTime<Utc>>,
    /// Upper bound of the window. Omitted ⇒ "now" at preview time is NOT used
    /// (that would make the hash time-varying); omitted means unbounded above.
    #[serde(default)]
    pub before: Option<DateTime<Utc>>,
    /// Page bound, clamped to [`MAX_PREVIEW_LIMIT`].
    #[serde(default)]
    pub limit: Option<i64>,
}

impl Selection {
    /// Trim / drop-empty / sort / dedupe, so two spellings of one selection
    /// hash identically.
    fn normalized(&self) -> Self {
        fn s(v: &Option<String>) -> Option<String> {
            v.as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
        }
        let mut prefixes: Vec<String> = self
            .dimension_prefixes
            .iter()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .collect();
        prefixes.sort();
        prefixes.dedup();
        Self {
            attesting_key_id: s(&self.attesting_key_id),
            attested_key_id: s(&self.attested_key_id),
            attestation_type: s(&self.attestation_type),
            dimension_prefixes: prefixes,
            dimension_exact: s(&self.dimension_exact),
            subject_key_id: s(&self.subject_key_id),
            after: self.after,
            before: self.before,
            limit: Some(self.effective_limit()),
        }
    }

    fn effective_limit(&self) -> i64 {
        self.limit
            .unwrap_or(DEFAULT_PREVIEW_LIMIT)
            .clamp(1, MAX_PREVIEW_LIMIT)
    }

    /// Is this selection empty of every predicate? An unpredicated selection is
    /// "the whole corpus", which is not a blast radius anyone reviewed.
    fn is_unpredicated(&self) -> bool {
        let n = self.normalized();
        n.attesting_key_id.is_none()
            && n.attested_key_id.is_none()
            && n.attestation_type.is_none()
            && n.dimension_prefixes.is_empty()
            && n.dimension_exact.is_none()
            && n.subject_key_id.is_none()
            && n.after.is_none()
            && n.before.is_none()
    }

    /// The push-down. `AttestationFilter` is `#[non_exhaustive]` — persist owns
    /// its shape and may add predicates — so this is build-then-set: a new
    /// field arrives as a default we did not have to notice, rather than as a
    /// compile break.
    fn to_filter(&self) -> AttestationFilter {
        let n = self.normalized();
        let mut f = AttestationFilter::default();
        f.attesting_key_id = n.attesting_key_id;
        f.attested_key_id = n.attested_key_id;
        f.attestation_type = n.attestation_type;
        f.dimension_prefixes = n.dimension_prefixes;
        f.dimension_exact = n.dimension_exact;
        f.subject_key_id = n.subject_key_id;
        f.window = match (n.after, n.before) {
            (None, None) => None,
            (a, b) => Some((
                a.unwrap_or(DateTime::<Utc>::MIN_UTC),
                b.unwrap_or(DateTime::<Utc>::MAX_UTC),
            )),
        };
        f
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Preview + the selection hash
// ═══════════════════════════════════════════════════════════════════════════

/// One previewed row, projected to what an operator ratifies.
#[derive(Debug, Clone, Serialize)]
pub struct PreviewRow {
    pub attestation_id: String,
    pub attesting_key_id: String,
    pub attested_key_id: String,
    pub attestation_type: String,
    pub dimension: Option<String>,
    pub asserted_at: DateTime<Utc>,
    pub cohort_scope: String,
}

/// What a preview produced — the exact row set, the blast-radius counts, and
/// the hash a commit must present.
#[derive(Debug, Clone)]
pub struct Preview {
    pub rows: Vec<PreviewRow>,
    /// Distinct `attesting_key_id`s — the KEYS an op acts on.
    pub targets: Vec<String>,
    /// Rows per attester. The blast-radius check, in the shape an operator
    /// reads: "this touches 3 keys and 9,811 of them are one key's liveness".
    pub per_attester: BTreeMap<String, usize>,
    /// `true` when the page filled to the limit — the selection may be larger
    /// than what was hashed, and a commit therefore acts on a PAGE.
    pub truncated: bool,
    /// Where the `[after, before)` window was actually enforced. See
    /// [`WindowEnforcement`].
    pub window_enforced: WindowEnforcement,
    pub selection_hash: String,
}

/// **Where the time window is enforced — stated, because it is not where it
/// should be.**
///
/// `AttestationFilter::window` is a v17.4.0 axis and `list_attestations` on
/// sqlite does not read it: its predicate builder emits `attesting_key_id`,
/// `attested_key_id`, `attestation_type`, `pqc_completed`,
/// `dimension_prefixes`, `dimension_exact`, `valid_at`, `confidence_floor`,
/// `subject_key_id` and the scope gate — and nothing for `window`, `tier` or
/// `attester_filter`. Only the `list_scores` / `resolve_scores` handles run the
/// shared builder that does, and those join the subject table, so they cannot
/// serve a general selection.
///
/// This is the same silent-narrowing class `dimension_exact` was in until
/// v17.5.2 (#461): the caller sets a predicate, the substrate returns rows that
/// do not satisfy it, and nothing says so. A preview that silently ignored
/// `after:` would hand an operator a hash over a blast radius twice the size
/// they asked to ratify — so the window IS enforced, in this process, and the
/// response says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowEnforcement {
    /// No window was asked for.
    None,
    /// Enforced in this process over the substrate's page, because
    /// `list_attestations` does not honour the axis. The page bound is applied
    /// BEFORE this filter, so a windowed selection can come back short while
    /// [`Preview::truncated`] is set.
    Application,
}

impl WindowEnforcement {
    fn token(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Application => "application",
        }
    }
}

/// The selection hash: SHA-256 over a canonical, versioned preimage covering
/// **both** the normalized filter and the exact set of row ids it returned.
///
/// Covering the row ids (not just the filter) is what closes TOCTOU: a row that
/// arrives between preview and commit changes the hash, so the commit refuses
/// and the operator re-previews. Covering the filter too means a hash cannot be
/// replayed against a different question that happened to return the same rows.
///
/// Ids are SORTED, so the hash is a function of the row SET and never of the
/// order the substrate happened to page them in.
#[must_use]
pub fn selection_hash(selection: &Selection, row_ids: &[String]) -> String {
    let n = selection.normalized();
    let mut pre = String::with_capacity(256 + row_ids.len() * 40);
    pre.push_str(SELECTION_HASH_VERSION);
    pre.push('\n');
    let f = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".to_owned());
    let t = |o: &Option<DateTime<Utc>>| o.map(|d| d.to_rfc3339()).unwrap_or_else(|| "-".to_owned());
    pre.push_str(&format!("attesting={}\n", f(&n.attesting_key_id)));
    pre.push_str(&format!("attested={}\n", f(&n.attested_key_id)));
    pre.push_str(&format!("type={}\n", f(&n.attestation_type)));
    pre.push_str(&format!("dimension_exact={}\n", f(&n.dimension_exact)));
    pre.push_str(&format!("subject={}\n", f(&n.subject_key_id)));
    pre.push_str(&format!("after={}\n", t(&n.after)));
    pre.push_str(&format!("before={}\n", t(&n.before)));
    pre.push_str(&format!("limit={}\n", n.effective_limit()));
    for p in &n.dimension_prefixes {
        pre.push_str(&format!("prefix={p}\n"));
    }
    let mut ids: Vec<&String> = row_ids.iter().collect();
    ids.sort();
    pre.push_str(&format!("rows={}\n", ids.len()));
    for id in ids {
        pre.push_str(&format!("row={id}\n"));
    }
    hex::encode(Sha256::digest(pre.as_bytes()))
}

/// Run the preview. **The filter is in the QUERY.**
///
/// The caller admission is the node authenticated AS ITSELF — the same honest
/// scope `graph_config::live_config_rows` resolves. `build_caller_admission` is
/// the only public path to an admission (no public constructor, AV-44 forge
/// resistance), so this cannot fabricate authority it does not hold.
async fn run_preview(
    engine: &Arc<Engine>,
    node_key_id: &str,
    selection: &Selection,
) -> Result<Preview, String> {
    let admission = ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned())
        .await
        .map_err(|e| format!("resolve caller admission: {e}"))?;
    let limit = selection.effective_limit();
    let page = engine
        .list_attestations(
            selection.to_filter(),
            None,
            limit,
            CallerScope::Authenticated { admission },
        )
        .await
        .map_err(|e| format!("list attestations: {e}"))?;

    // The page bound is the substrate's; `truncated` is measured BEFORE the
    // window filter, so a short windowed page is never mistaken for a complete
    // one.
    let truncated = i64::try_from(page.items.len()).unwrap_or(i64::MAX) >= limit;
    let n = selection.normalized();
    let window_enforced = if n.after.is_some() || n.before.is_some() {
        WindowEnforcement::Application
    } else {
        WindowEnforcement::None
    };
    let in_window = |a: &ciris_persist::federation::types::Attestation| {
        n.after.is_none_or(|start| a.asserted_at >= start)
            && n.before.is_none_or(|end| a.asserted_at < end)
    };

    let mut per_attester: BTreeMap<String, usize> = BTreeMap::new();
    let rows: Vec<PreviewRow> = page
        .items
        .iter()
        .filter(|a| in_window(a))
        .map(|a| {
            *per_attester.entry(a.attesting_key_id.clone()).or_insert(0) += 1;
            PreviewRow {
                attestation_id: a.attestation_id.clone(),
                attesting_key_id: a.attesting_key_id.clone(),
                attested_key_id: a.attested_key_id.clone(),
                attestation_type: a.attestation_type.clone(),
                // The envelope KEY comes from persist, never a hand-mirrored
                // literal (SRV-1/#322) — a rename upstream must break the
                // build, not silently skew the projection.
                dimension: a
                    .attestation_envelope
                    .get(paths::DIMENSION)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                asserted_at: a.asserted_at,
                cohort_scope: a.cohort_scope.clone(),
            }
        })
        .collect();
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    let targets: Vec<String> = per_attester.keys().cloned().collect();
    Ok(Preview {
        selection_hash: selection_hash(selection, &ids),
        rows,
        targets,
        per_attester,
        truncated,
        window_enforced,
    })
}

fn preview_json(p: &Preview) -> serde_json::Value {
    let mut out = serde_json::json!({
        "selection_hash": p.selection_hash,
        "counts": {
            "rows": p.rows.len(),
            "targets": p.targets.len(),
            "per_attester": p.per_attester,
            "truncated": p.truncated,
        },
        "window_enforced": p.window_enforced.token(),
        "targets": p.targets,
        "rows": p.rows,
    });
    if p.window_enforced == WindowEnforcement::Application {
        out["window_note"] = m(
            "admin.preview.window_in_application",
            "The time window is applied by this node, not by the substrate query: the \
             general attestation read does not honour the window axis. The page bound is \
             applied first, so a windowed selection can come back short.",
        );
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
//  The commit envelope — attribution, authority, hash
// ═══════════════════════════════════════════════════════════════════════════

/// The fields EVERY mutating call carries.
#[derive(Debug, Clone, Deserialize)]
pub struct Commit {
    /// The selection this op runs over — byte-for-byte what was previewed.
    pub selection: Selection,
    /// The hash the preview returned. A mismatch refuses.
    pub selection_hash: String,
    /// **MANDATORY.** The `delegates_to` attestation id the actor acts UNDER.
    pub delegation_id: String,
    /// **MANDATORY.** Free text: WHY. Recorded, never interpreted.
    pub reason: String,
}

/// A delegation this module RESOLVED and RE-WALKED — never one it merely read
/// off the request.
#[derive(Debug, Clone)]
struct AuthorityProof {
    delegation_id: String,
    /// The root the scoped chain was walked FROM.
    issuer_key_id: String,
}

/// The scope set a `delegates_to` envelope declares — bare string OR array, the
/// two wire shapes the substrate walk accepts.
///
/// Hand-parsed here because persist's own `delegation_scope_set` is
/// `pub(crate)`: there is **no public predicate for "does THIS delegation row
/// carry scope S"**, only the issuer-to-target walk, which answers a different
/// question (see [`resolve_authority`]). This mirrors persist's parse exactly;
/// if it is ever exported, delete this and compose it.
fn delegation_scopes(envelope: &serde_json::Value) -> BTreeSet<String> {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => std::iter::once(s.clone()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => BTreeSet::new(),
    }
}

/// Resolve + re-derive one delegation under `scope`. Refusals are named.
async fn resolve_authority(
    engine: &Arc<Engine>,
    actor_key_id: &str,
    delegation_id: &str,
    scope: &str,
) -> Result<AuthorityProof, Response> {
    let id = delegation_id.trim();
    if id.is_empty() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "attribution_absent",
            "admin.refusal.attribution_absent",
            "delegation_id is required. An action that does not carry its own authority \
             cannot be told from an unauthorized one once the actor is gone.",
        ));
    }
    let row = match engine.federation_directory().get_attestation(id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(refusal(
                StatusCode::FORBIDDEN,
                "authority_unresolved",
                "admin.refusal.authority_unresolved",
                "The named delegation is not a row this node holds, so its scope cannot be \
                 checked. This node does not act on an authority it cannot verify.",
            ))
        }
        Err(e) => {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The substrate could not be read: {e}"),
            ))
        }
    };
    if row.attestation_type != attestation_type::DELEGATES_TO {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_not_a_delegation",
            "admin.refusal.authority_not_a_delegation",
            "The named delegation id is not a delegates_to row.",
        ));
    }
    if row.attested_key_id != actor_key_id {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_not_to_actor",
            "admin.refusal.authority_not_to_actor",
            "The named delegation was not granted to this node, so this node is not the \
             party it authorizes.",
        ));
    }
    // **The row must itself carry the scope**, not merely descend from an issuer
    // who granted it somewhere else. `reachable_under_scope` answers *"does this
    // ISSUER reach this ACTOR under S"* — which is true the moment the issuer
    // granted S by ANY edge, so on its own it would let a `review` delegation be
    // recorded as the authority for a `slash` act. The tombstone names THIS row,
    // so THIS row is what has to bear the scope.
    if !delegation_scopes(&row.attestation_envelope).contains(scope) {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_scope_absent",
            "admin.refusal.authority_scope_absent",
            "The named delegation does not carry the scope this operation requires. \
             Another delegation from the same issuer might, but the act would then \
             record an authority it was not taken under.",
        ));
    }
    match engine
        .reachable_under_scope(
            &row.attesting_key_id,
            actor_key_id,
            scope,
            MAX_MODERATION_DELEGATION_DEPTH,
        )
        .await
    {
        Ok(true) => Ok(AuthorityProof {
            delegation_id: id.to_owned(),
            issuer_key_id: row.attesting_key_id,
        }),
        Ok(false) => Err(refusal(
            StatusCode::FORBIDDEN,
            "authority_scope_unreachable",
            "admin.refusal.authority_scope_unreachable",
            "No live delegation chain carrying the scope this operation requires reaches \
             this node from that issuer. Authority is re-derived from this node's own \
             verified state, never taken from the request.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "admin.refusal.store_unavailable",
            format!("The delegation walk could not complete: {e}"),
        )),
    }
}

/// What a commit established: the preview it re-ran, and the authority it
/// re-derived.
struct Committed {
    preview: Preview,
    authority: AuthorityProof,
    /// Every distinct authority root, for the quorum ops.
    quorum_roots: BTreeSet<String>,
    quorum_delegation_ids: Vec<String>,
}

/// The shared commit gate: attribution → authority → **re-preview and compare
/// the hash**. In that order, so an unattributed call is refused before any
/// substrate work happens.
async fn commit_gate(
    st: &AdminOpsState,
    c: &Commit,
    scope: &str,
    extra_delegation_ids: &[String],
    quorum_min: usize,
) -> Result<Committed, Response> {
    if c.reason.trim().is_empty() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "attribution_absent",
            "admin.refusal.reason_absent",
            "reason is required. An action with no recorded reason is indistinguishable \
             from an unauthorized one once the actor is gone.",
        ));
    }
    if c.selection.is_unpredicated() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "selection_unpredicated",
            "admin.refusal.selection_unpredicated",
            "The selection carries no predicate at all, which means the whole corpus. \
             Name what you are acting on.",
        ));
    }

    let authority = resolve_authority(&st.engine, &st.node_key_id, &c.delegation_id, scope).await?;
    let mut quorum_roots: BTreeSet<String> = BTreeSet::new();
    quorum_roots.insert(authority.issuer_key_id.clone());
    let mut quorum_delegation_ids = vec![authority.delegation_id.clone()];
    for extra in extra_delegation_ids {
        let proof = resolve_authority(&st.engine, &st.node_key_id, extra, scope).await?;
        quorum_roots.insert(proof.issuer_key_id);
        quorum_delegation_ids.push(proof.delegation_id);
    }
    if quorum_roots.len() < quorum_min {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "refused": true,
                "refusal": "quorum_insufficient",
                "source_locale": SOURCE_LOCALE,
                "message": m(
                    "admin.refusal.quorum_insufficient",
                    "This operation is irreversible and takes a quorum of distinct \
                     authorities, not one delegation chain. Two chains from the same root \
                     are one authority wearing two hats.",
                ),
                "quorum_required": quorum_min,
                "quorum_distinct_roots": quorum_roots.len(),
            })),
        )
            .into_response());
    }

    let preview = run_preview(&st.engine, &st.node_key_id, &c.selection)
        .await
        .map_err(|e| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "admin.refusal.store_unavailable",
                format!("The preview could not be re-run: {e}"),
            )
        })?;
    if preview.selection_hash != c.selection_hash.trim() {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "refused": true,
                "refusal": "preview_hash_mismatch",
                "source_locale": SOURCE_LOCALE,
                "message": m(
                    "admin.refusal.preview_hash_mismatch",
                    "What you previewed is not what would execute — the selection has \
                     changed since the preview. Re-run the preview and ratify the new hash.",
                ),
                "presented_selection_hash": c.selection_hash.trim(),
                "current_selection_hash": preview.selection_hash,
                "current": preview_json(&preview),
            })),
        )
            .into_response());
    }
    Ok(Committed {
        preview,
        authority,
        quorum_roots,
        quorum_delegation_ids,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
//  The attributed tombstone
// ═══════════════════════════════════════════════════════════════════════════

/// Build the attributed `hard_case:admin_action:{op}` row, using persist's OWN
/// builder for the required attribution keys and adding the context this ladder
/// carries. The builder cannot stop a caller passing empties; the gate at
/// `record_hard_case` is the one that has to hold — and it does, on all three
/// backends.
fn tombstone(
    op: &str,
    target_key_id: &str,
    delegation_id: &str,
    reason: &str,
    at: DateTime<Utc>,
    extra: serde_json::Value,
) -> HardCaseEvent {
    let mut ev = admin_action_event(
        op,
        target_key_id,
        Some(target_key_id),
        delegation_id,
        reason,
        at,
    );
    if let (Some(detail), Some(more)) = (ev.detail.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            detail.insert(k.clone(), v.clone());
        }
    }
    ev
}

/// The context every tombstone in this module carries beyond the mandatory
/// `{delegation_id, reason}`: WHAT was selected, and under WHICH authorities.
fn tombstone_context(c: &Committed, selection: &Selection) -> serde_json::Value {
    serde_json::json!({
        "selection_hash": c.preview.selection_hash,
        "selection_rows": c.preview.rows.len(),
        "selection_truncated": c.preview.truncated,
        "selection_after": selection.after.map(|d| d.to_rfc3339()),
        "quorum_roots": c.quorum_roots.iter().cloned().collect::<Vec<_>>(),
        "quorum_delegation_ids": c.quorum_delegation_ids,
    })
}

/// Record one tombstone. A failure here is FATAL to the op's report for that
/// target: the whole point of the ladder is that the act and its authority land
/// together.
async fn record(engine: &Arc<Engine>, ev: HardCaseEvent) -> Result<String, String> {
    let id = ev.event_id.clone();
    engine
        .federation_directory()
        .record_hard_case(ev)
        .await
        .map(|()| id)
        .map_err(|e| e.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════
//  Reversal reach — what a reversal actually reverses
// ═══════════════════════════════════════════════════════════════════════════

/// How far a reversal op actually reaches in persist v28.2.0. The prior FSD
/// claimed tiers 1/2/4 were reversible and shipped no route that reversed
/// anything; these routes exist, and each one says what it undoes rather than
/// leaving a reader to assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReversalReach {
    /// The substrate state flips. `un_quarantine`: a `quarantine:released:v1`
    /// marker supersedes the withhold and `resolve_quarantine` folds to
    /// `released` — the serve paths stop withholding.
    Substrate,
    /// Nothing in the substrate changes because nothing in the substrate
    /// enforced the original op either. `un_throttle`: symmetric with
    /// `throttle`.
    Symmetric,
    /// The original act's row SURVIVES and this reversal is evidence only.
    /// `re_admit`: revocations are append-only, `fold_key_statement_standing`
    /// composes restrictions and never leniencies, and persist exposes no
    /// un-revoke at any layer.
    EvidenceOnly,
}

impl ReversalReach {
    fn token(self) -> &'static str {
        match self {
            Self::Substrate => "substrate",
            Self::Symmetric => "symmetric",
            Self::EvidenceOnly => "evidence_only",
        }
    }

    fn note(self) -> serde_json::Value {
        match self {
            Self::Substrate => m(
                "admin.reversal.substrate",
                "The substrate state is reversed: this node stops withholding the key's rows.",
            ),
            Self::Symmetric => m(
                "admin.reversal.symmetric",
                "Nothing in the substrate is reversed because nothing in the substrate \
                 enforced the original judgement. Both acts are recorded evidence.",
            ),
            Self::EvidenceOnly => m(
                "admin.reversal.evidence_only",
                "The original row survives and is still folded by every reader. This \
                 reversal is recorded evidence, not an undo — the substrate exposes no \
                 un-revoke.",
            ),
        }
    }
}

fn reversal_json(r: ReversalReach) -> serde_json::Value {
    serde_json::json!({ "reach": r.token(), "note": r.note() })
}

// ═══════════════════════════════════════════════════════════════════════════
//  POST /v1/admin/preview
// ═══════════════════════════════════════════════════════════════════════════

async fn preview(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
    let selection: Selection = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    match run_preview(&st.engine, &st.node_key_id, &selection).await {
        Ok(p) => {
            let mut out = preview_json(&p);
            out["source_locale"] = serde_json::json!(SOURCE_LOCALE);
            out["note"] = m(
                "admin.preview.note",
                "This is exactly what a commit will act on. Present the selection hash \
                 with the commit; if the selection has changed, the commit refuses.",
            );
            (StatusCode::OK, Json(out)).into_response()
        }
        Err(e) => err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "admin.refusal.store_unavailable",
            format!("The preview could not be run: {e}"),
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 0 / tier 1 — judgement-only ops
// ═══════════════════════════════════════════════════════════════════════════

/// What a judgement-only op IS: its `admin_action:{op}` suffix, the delegation
/// scope it takes, its rung, and the honest statement of what it enforces.
struct JudgementOp<'a> {
    op: &'a str,
    scope: &'a str,
    tier: u8,
    enforcement: serde_json::Value,
    reversal: Option<ReversalReach>,
}

/// Shared body for the ops whose entire effect is an attributed tombstone.
async fn judgement_only(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    spec: JudgementOp<'_>,
) -> Response {
    let JudgementOp {
        op,
        scope,
        tier,
        enforcement,
        reversal,
    } = spec;
    if let Err(resp) = gate(st, headers).await {
        return resp;
    }
    let c: Commit = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let committed = match commit_gate(st, &c, scope, &[], 1).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut recorded = Vec::new();
    let mut failed = Vec::new();
    for target in &committed.preview.targets {
        let ev = tombstone(
            op,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            now,
            context.clone(),
        );
        match record(&st.engine, ev).await {
            Ok(id) => recorded.push(serde_json::json!({ "target_key_id": target, "event_id": id })),
            Err(e) => failed.push(serde_json::json!({ "target_key_id": target, "error": e })),
        }
    }
    tracing::warn!(
        op,
        tier,
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed"
    );
    let mut out = serde_json::json!({
        "op": op,
        "tier": tier,
        "source_locale": SOURCE_LOCALE,
        "required_scope": scope,
        "selection_hash": committed.preview.selection_hash,
        "counts": {
            "rows": committed.preview.rows.len(),
            "targets": committed.preview.targets.len(),
            "truncated": committed.preview.truncated,
        },
        "recorded": recorded,
        "failed": failed,
        "enforcement": enforcement,
    });
    if let Some(r) = reversal {
        out["reversal"] = reversal_json(r);
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn annotate(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_ANNOTATE,
            scope: REQUIRED_SCOPE_ANNOTATE,
            tier: 0,
            enforcement: m(
                "admin.enforcement.annotate",
                "A signed judgement with no effect until a reader honours it. Nothing is \
                 withheld, throttled or removed.",
            ),
            reversal: None,
        },
    )
    .await
}

/// Tier 1 enforcement note. **This is the honest one.**
fn throttle_enforcement() -> serde_json::Value {
    m(
        "admin.enforcement.throttle",
        "Recorded as an attributed judgement only. This substrate has no \
         recipient-authored per-key admission budget: the peer write quota is a fixed \
         runaway-loop backstop, not a policy surface a throttle can key on. Nothing \
         changes what this node accepts from the named keys.",
    )
}

async fn throttle(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_THROTTLE,
            scope: REQUIRED_SCOPE_THROTTLE,
            tier: 1,
            enforcement: throttle_enforcement(),
            reversal: None,
        },
    )
    .await
}

async fn un_throttle(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_THROTTLE_RELEASE,
            scope: REQUIRED_SCOPE_THROTTLE,
            tier: 1,
            enforcement: throttle_enforcement(),
            reversal: Some(ReversalReach::Symmetric),
        },
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 2 — quarantine / un-quarantine (the REAL substrate marker)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
struct QuarantineRequest {
    #[serde(flatten)]
    commit: Commit,
    /// The community whose authority the marker is filed under. Persist's
    /// `slash` gate resolves the duty-holders from THIS community's named
    /// moderators — a marker with no community names no authority.
    community_id: String,
}

/// Build a signed quarantine marker WITHOUT storing it, because
/// `record_quarantine_marker` takes an already-assembled, already-signed row
/// and does the storing itself.
///
/// Every sanctioned emit helper persist exposes (`emit_attestation_self`,
/// `emit_with_local_signer`, `assemble_and_put`) canonicalizes, signs, assembles
/// **and puts** in one step. There is no assemble-only variant, so the one door
/// built for this op cannot be reached through the chokepoint built to stop
/// hand-rolled rows. This is that hand-rolled row, kept to one function.
async fn build_marker(
    engine: &Arc<Engine>,
    subject_key_id: &str,
    envelope: serde_json::Value,
) -> Result<Attestation, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive acting key_id: {e}"))?;
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize marker: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| format!("hybrid-sign marker: {e}"))?;
    let now = Utc::now();
    Ok(Attestation {
        attestation_id: crate::ids::new_id(),
        attesting_key_id: key_id.clone(),
        attested_key_id: subject_key_id.to_owned(),
        attestation_type: attestation_type::SCORES.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id,
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

/// Shared body for quarantine + un-quarantine: same gates, different marker.
async fn quarantine_op(
    st: &AdminOpsState,
    headers: &HeaderMap,
    body: &axum::body::Bytes,
    release: bool,
) -> Response {
    if let Err(resp) = gate(st, headers).await {
        return resp;
    }
    let req: QuarantineRequest = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    if req.community_id.trim().is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "community_absent",
            "admin.refusal.community_absent",
            "community_id is required: a quarantine is filed under a community's authority, \
             and a marker that names no community names no authority.",
        );
    }
    let c = req.commit;
    let committed = match commit_gate(st, &c, REQUIRED_SCOPE_QUARANTINE, &[], 1).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let op = if release {
        admin_op::QUARANTINE_RELEASE
    } else {
        admin_op::QUARANTINE
    };
    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        // A release must name the withhold it lifts — resolve it from THIS
        // node's own fold rather than asking the caller to carry a row id.
        let releases = if release {
            match st.engine.resolve_quarantine(target, now).await {
                Ok(fold) if fold.withholds() => fold.marker_id,
                Ok(fold) => {
                    results.push(serde_json::json!({
                        "target_key_id": target,
                        "outcome": "skipped",
                        "reason": "not_withheld",
                        "state": fold.state.as_str(),
                        "message": m(
                            "admin.quarantine.not_withheld",
                            "This key is not currently withheld here, so there is nothing to \
                             release.",
                        ),
                    }));
                    continue;
                }
                Err(e) => {
                    results.push(serde_json::json!({
                        "target_key_id": target, "outcome": "error", "error": e.to_string(),
                    }));
                    continue;
                }
            }
        } else {
            None
        };
        let envelope = if release {
            let Some(marker_id) = releases else {
                results.push(serde_json::json!({
                    "target_key_id": target, "outcome": "skipped", "reason": "not_withheld",
                }));
                continue;
            };
            quarantine::release_envelope(
                target,
                req.community_id.trim(),
                &marker_id,
                &committed.authority.delegation_id,
                &c.reason,
            )
        } else {
            quarantine::withhold_envelope(
                target,
                req.community_id.trim(),
                &committed.authority.delegation_id,
                &c.reason,
            )
        };
        let marker = match build_marker(&st.engine, target, envelope).await {
            Ok(m) => m,
            Err(e) => {
                results.push(serde_json::json!({
                    "target_key_id": target, "outcome": "error", "error": e,
                }));
                continue;
            }
        };
        match st.engine.record_quarantine_marker(&marker).await {
            Ok(outcome) => match outcome.refusal() {
                None => {
                    let ev = tombstone(
                        op,
                        target,
                        &committed.authority.delegation_id,
                        &c.reason,
                        now,
                        context.clone(),
                    );
                    let event_id = record(&st.engine, ev).await;
                    results.push(serde_json::json!({
                        "target_key_id": target,
                        "outcome": "admitted",
                        "marker_id": marker.attestation_id,
                        "event_id": event_id.ok(),
                    }));
                }
                Some(reason) => results.push(serde_json::json!({
                    "target_key_id": target,
                    "outcome": "refused",
                    // The substrate's OWN stable token — never re-spelled here.
                    "reason": reason.as_str(),
                })),
            },
            Err(e) => results.push(serde_json::json!({
                "target_key_id": target, "outcome": "error", "error": e.to_string(),
            })),
        }
    }
    tracing::warn!(
        op,
        tier = 2,
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed"
    );
    let mut out = serde_json::json!({
        "op": op,
        "tier": 2,
        "source_locale": SOURCE_LOCALE,
        "required_scope": REQUIRED_SCOPE_QUARANTINE,
        "selection_hash": committed.preview.selection_hash,
        "community_id": req.community_id.trim(),
        "results": results,
        "enforcement": m(
            "admin.enforcement.quarantine",
            "A signed marker, not a command: nothing is deleted and nothing is rewritten. \
             This node's serve paths stop handing the named keys' rows and blobs to peers; \
             a peer that folds differently simply does not receive them from us.",
        ),
    });
    if release {
        out["reversal"] = reversal_json(ReversalReach::Substrate);
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn quarantine_route(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    quarantine_op(&st, &headers, &body, false).await
}

async fn un_quarantine_route(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    quarantine_op(&st, &headers, &body, true).await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 3 — force descent (quorum; the only irreversible op)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
struct DescendRequest {
    #[serde(flatten)]
    commit: Commit,
    /// The OTHER authorities' delegation ids. Each is resolved and re-walked
    /// exactly as the primary one is; the quorum counts distinct ROOTS.
    #[serde(default)]
    quorum_delegation_ids: Vec<String>,
}

async fn descend(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
    let req: DescendRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let c = req.commit;
    let committed = match commit_gate(
        &st,
        &c,
        REQUIRED_SCOPE_DESCEND,
        &req.quorum_delegation_ids,
        DESCEND_QUORUM_MIN,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    // **Property 5, and the wall it runs into.**
    //
    // `after:` bounds the JUDGEMENT: only statements made after that instant
    // are in doubt. The only payload-descent primitive this substrate exposes
    // over an actor is unbounded — it takes the whole corpus or none of it.
    // Driving an unbounded eviction from a bounded judgement is exactly the
    // DigiNotar error: the long tail of a total revocation is measured in the
    // things that were fine and died anyway. So a bounded descent records its
    // judgement and REFUSES the payload leg, naming the op that IS bounded.
    let bounded = c.selection.after.is_some();
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        let payload = if bounded {
            serde_json::json!({
                "performed": false,
                "refusal": "bounded_descent_unsupported",
                "message": m(
                    "admin.descend.bounded_unsupported",
                    "A time-bounded judgement cannot drive an unbounded eviction. The \
                     substrate's only actor-keyed descent takes the whole corpus, which \
                     would destroy the history this bound deliberately leaves standing. \
                     The time-bounded removal that IS implemented is de-admission with a \
                     history bound.",
                ),
            })
        } else {
            match st.engine.evict_actor(target, now).await {
                Ok(report) => serde_json::json!({
                    "performed": true,
                    "report": serde_json::to_value(&report).unwrap_or(serde_json::Value::Null),
                }),
                Err(e) => serde_json::json!({
                    "performed": false, "refusal": "evict_failed", "error": e.to_string(),
                }),
            }
        };
        let ev = tombstone(
            OP_DESCEND,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            now,
            {
                let mut ctx = context.clone();
                if let Some(o) = ctx.as_object_mut() {
                    o.insert("bounded".into(), serde_json::json!(bounded));
                    o.insert("payload_descent".into(), payload.clone());
                }
                ctx
            },
        );
        let event_id = record(&st.engine, ev).await;
        results.push(serde_json::json!({
            "target_key_id": target,
            "event_id": event_id.as_ref().ok(),
            "event_error": event_id.err(),
            "payload_descent": payload,
        }));
    }
    tracing::warn!(
        op = OP_DESCEND,
        tier = 3,
        bounded,
        delegation_id = %committed.authority.delegation_id,
        quorum_roots = committed.quorum_roots.len(),
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "IRREVERSIBLE graded admin op committed"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "op": OP_DESCEND,
            "tier": 3,
            "source_locale": SOURCE_LOCALE,
            "required_scope": REQUIRED_SCOPE_DESCEND,
            "selection_hash": committed.preview.selection_hash,
            "quorum": {
                "required": DESCEND_QUORUM_MIN,
                "distinct_roots": committed.quorum_roots.len(),
                "roots": committed.quorum_roots.iter().cloned().collect::<Vec<_>>(),
                "delegation_ids": committed.quorum_delegation_ids,
            },
            "bounded": bounded,
            "after": c.selection.after.map(|d| d.to_rfc3339()),
            "results": results,
            "irreversible": m(
                "admin.enforcement.descend",
                "Irreversible by design. Descent never terminates at zero — the blur and \
                 the tombstone survive — but what was shed is not coming back.",
            ),
            "not_reached": m(
                "admin.descend.not_reached",
                "The selected attestation rows themselves are not descended. Every payload \
                 carrier on this substrate is sealed inside its own signature, so its bytes \
                 cannot be dropped without making the row read as forged; erasability is \
                 decided at mint and nothing minted today is erasable.",
            ),
        })),
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 4 — de-admit / re-admit
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
struct DeadmitRequest {
    #[serde(flatten)]
    commit: Commit,
    /// **The history bound.** The last instant this key's statements are still
    /// stood behind. Omitted ⇒ all-or-nothing, which is what an unbounded
    /// revocation has always meant.
    ///
    /// It rides here as well as on the selection because this is where persist
    /// actually implements it (`Revocation::revoked_after`) — the FSD put the
    /// time bound on tier 3 and the substrate put it on tier 4.
    #[serde(default)]
    after: Option<DateTime<Utc>>,
}

async fn deadmit(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = gate(&st, &headers).await {
        return resp;
    }
    let req: DeadmitRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "admin.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let c = req.commit;
    let committed = match commit_gate(&st, &c, REQUIRED_SCOPE_DEADMIT, &[], 1).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // The bound the selection carries is the operator's stated compromise
    // instant; an explicit `after` on the body wins, so a de-admission can be
    // bounded without re-scoping the preview.
    let bound = req.after.or(c.selection.after);
    let now = Utc::now();
    let context = tombstone_context(&committed, &c.selection);
    let mut results = Vec::new();
    for target in &committed.preview.targets {
        match put_revocation_for(
            &st.engine,
            target,
            &committed.authority.delegation_id,
            &c.reason,
            bound,
            now,
        )
        .await
        {
            Ok(revocation_id) => {
                let ev = tombstone(
                    admin_op::DE_ADMISSION,
                    target,
                    &committed.authority.delegation_id,
                    &c.reason,
                    now,
                    {
                        let mut ctx = context.clone();
                        if let Some(o) = ctx.as_object_mut() {
                            o.insert("revocation_id".into(), serde_json::json!(revocation_id));
                            o.insert(
                                "revoked_after".into(),
                                serde_json::json!(bound.map(|d| d.to_rfc3339())),
                            );
                        }
                        ctx
                    },
                );
                let event_id = record(&st.engine, ev).await;
                results.push(serde_json::json!({
                    "target_key_id": target,
                    "outcome": "revoked",
                    "revocation_id": revocation_id,
                    "event_id": event_id.ok(),
                }));
            }
            Err(e) => results.push(serde_json::json!({
                "target_key_id": target, "outcome": "error", "error": e,
            })),
        }
    }
    tracing::warn!(
        op = admin_op::DE_ADMISSION,
        tier = 4,
        bounded = bound.is_some(),
        delegation_id = %committed.authority.delegation_id,
        reason = %c.reason,
        selection_hash = %committed.preview.selection_hash,
        targets = committed.preview.targets.len(),
        "graded admin op committed"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "op": admin_op::DE_ADMISSION,
            "tier": 4,
            "source_locale": SOURCE_LOCALE,
            "required_scope": REQUIRED_SCOPE_DEADMIT,
            "selection_hash": committed.preview.selection_hash,
            "revoked_after": bound.map(|d| d.to_rfc3339()),
            "results": results,
            "enforcement": m(
                "admin.enforcement.deadmit",
                "A signed revocation on the ordinary append-only plane. It is evidence a \
                 reader folds, not a door that slams: signature verification, the \
                 replication cursors and row ingest all deliberately keep working, because \
                 refusing a compromised key's older rows would destroy the evidence needed \
                 to adjudicate the compromise.",
            ),
        })),
    )
        .into_response()
}

/// Mint + store one signed [`Revocation`]. The history bound is
/// **envelope-bound**: the typed `revoked_after` must be mirrored, to the
/// second, by a `revoked_after` in the SIGNED envelope, or persist refuses the
/// row. An unsigned leniency field is an attacker's field.
async fn put_revocation_for(
    engine: &Arc<Engine>,
    revoked_key_id: &str,
    delegation_id: &str,
    reason: &str,
    revoked_after: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let revoking_key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive acting key_id: {e}"))?;
    let mut envelope = serde_json::json!({
        "revoked_key_id": revoked_key_id,
        "revoking_key_id": revoking_key_id,
        "reason": reason,
        "delegation_id": delegation_id,
        "effective_at": now.to_rfc3339(),
    });
    if let Some(bound) = revoked_after {
        envelope[ciris_persist::federation::register::REVOKED_AFTER_ENVELOPE_FIELD] =
            serde_json::json!(bound.to_rfc3339());
    }
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize revocation: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| format!("hybrid-sign revocation: {e}"))?;
    let revocation = Revocation {
        revocation_id: crate::ids::new_id(),
        revoked_key_id: revoked_key_id.to_owned(),
        revoking_key_id: revoking_key_id.clone(),
        reason: Some(reason.to_owned()),
        revoked_at: now,
        effective_at: now,
        revocation_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: revoking_key_id,
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        observed_region: ciris_persist::federation::verify_coord::region::US.to_owned(),
        revoked_after,
        persist_row_hash: String::new(),
    };
    let id = revocation.revocation_id.clone();
    engine
        .federation_directory()
        .put_revocation(SignedRevocation { revocation })
        .await
        .map_err(|e| e.to_string())?;
    Ok(id)
}

async fn re_admit(
    State(st): State<AdminOpsState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    judgement_only(
        &st,
        &headers,
        &body,
        JudgementOp {
            op: OP_RE_ADMISSION,
            scope: REQUIRED_SCOPE_DEADMIT,
            tier: 4,
            enforcement: m(
                "admin.enforcement.re_admit",
                "Recorded as an attributed reversal. The revocation row survives and every \
                 reader still folds it: restrictions compose and leniencies do not, and no \
                 layer of this substrate exposes an un-revoke.",
            ),
            reversal: Some(ReversalReach::EvidenceOnly),
        },
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════════════════

/// The graded admin-op router. `node_key_id` is THIS node's #247 DERIVED
/// federation key id — the ACTING key whose delegated authority every op
/// re-walks, and the identity `emit_attestation_self` / `sign_hybrid` sign as.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    let state = AdminOpsState {
        engine,
        node_key_id,
    };
    Router::new()
        .route("/v1/admin/preview", axum::routing::post(preview))
        .route("/v1/admin/annotate", axum::routing::post(annotate))
        .route("/v1/admin/throttle", axum::routing::post(throttle))
        .route("/v1/admin/un-throttle", axum::routing::post(un_throttle))
        .route(
            "/v1/admin/quarantine",
            axum::routing::post(quarantine_route),
        )
        .route(
            "/v1/admin/un-quarantine",
            axum::routing::post(un_quarantine_route),
        )
        .route("/v1/admin/descend", axum::routing::post(descend))
        .route("/v1/admin/deadmit", axum::routing::post(deadmit))
        .route("/v1/admin/re-admit", axum::routing::post(re_admit))
        .with_state(state)
}
