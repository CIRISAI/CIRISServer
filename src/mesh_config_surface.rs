//! **The Mesh Configuration surface** (CIRISServer#346, the fourth tab) — the
//! owner-gated read and the two write paths onto persist's
//! [`mesh_config`](ciris_persist::federation::mesh_config) plane.
//!
//! ```text
//! GET  /v1/mesh-config           read-only  effective values + provenance + TTLs + the registry
//! GET  /v1/mesh-config/history   read-only  every mesh-config row this node holds
//! POST /v1/mesh-config/durable   owner      the durable path
//! POST /v1/mesh-config/relief    owner      the emergency relief path (TTL mandatory)
//! ```
//!
//! # Why these paths are not `/v1/accord/config`
//!
//! CIRISServer#346 named the write routes `POST /v1/accord/config` and
//! `POST /v1/accord/config-relief`. **The substrate refuses that authority in
//! terms.** `mesh_config`'s module doc quotes CC 4.2.1: the author is *"the
//! trust root, acting on the CC 3.2 delegation plane (`trust:confers:v1`),
//! **never the accord's ceremony plane**"*, and
//! [`MeshConfigRefusalReason`](ciris_persist::federation::MeshConfigRefusalReason)
//! has no accord-holder variant to refuse on. A route whose PATH names the
//! accord would advertise an authority no row can ever be admitted under —
//! the same "the operator is told they may act and the write fails anyway"
//! failure `admin_ops::REQUIRED_SCOPE_QUARANTINE` documents from the other
//! direction. So the paths name the plane, and the divergence is recorded here
//! rather than encoded in a URL.
//!
//! # The five walls this module is held to
//!
//! 1. **The key registry is READ from persist, never restated.**
//!    [`MeshConfigKey::ALL`] is the closed set and
//!    [`MeshConfigKey::spec`] is the one place a key's facts live; the
//!    registry this surface serves is a projection of them. A hand-copied key
//!    list here would be the hand-mirrored-vocabulary defect
//!    `tests/envelope_vocabulary_single_source.rs` exists for. Request bodies
//!    deserialize the key THROUGH [`MeshConfigKey`], so an unregistered key is
//!    refused by persist's own `Deserialize` with persist's own sentence.
//! 2. **The durability rule is NOT encoded here.** persist v29.0.0 reversed
//!    v28.3.0 — a cold durable row now admits under the root's own quorum and
//!    is refused at threshold-1 — and CIRISConstitution#86 is open asking CC to
//!    rule, with persist saying it will revert if CC rules the other way. This
//!    module therefore contains no quorum count, no scrub arithmetic and no
//!    "quorum earns durability" predicate: it assembles the row, hands it to
//!    [`Engine::record_mesh_config_row`], and renders whatever
//!    [`MeshConfigOutcome`] comes back. When the rule flips, this file does not
//!    change.
//! 3. **[`EMERGENCY_MAX_TTL_HOURS`] is read, never written down.** It is
//!    surfaced so a UI can bound its own input, and the actual bound is
//!    persist's `ttl_too_long` refusal. This module does not clamp.
//! 4. **Distinct zeroes.** "No mesh-config set" and "could not read the plane"
//!    do not render alike, and neither do "no history" and "history
//!    unavailable" — see [`PlaneStanding`] and [`HistoryStanding`], which are
//!    the `operator_surface.rs` house pattern applied to this plane.
//! 5. **Strings are `{id, text}` pairs**, like
//!    [`crate::peer::consent_disclosure_json`]. A counting-down TTL is
//!    `remaining_seconds` plus a message id, never "expires in 3 hours".
//!
//! # The snapshot, and why the rows are gathered here
//!
//! Both reads run over ONE row snapshot and then call persist's own **pure,
//! public** [`fold_mesh_config`] — never a second fold. The gathering is done
//! here rather than through [`Engine::resolve_mesh_config`] for two reasons,
//! both about zeroes:
//!
//! - `resolve_mesh_config` skips a root whose `list_attestations_for` answers
//!   `Error::Unsupported`, so a backend that cannot answer for one root is
//!   indistinguishable from a root that said nothing. This surface names the
//!   roots it could not read ([`PlaneStanding::Unreadable`],
//!   [`HistoryStanding::Partial`]);
//! - the read surface and the history must describe the SAME instant, or the
//!   `row_id` a UI joins them on can name a row the other half never saw.
//!
//! # The baseline is the node's own, and a failed baseline read is fatal
//!
//! [`MeshConfigBaseline`] is *"what its owner consented to"* — the ceiling
//! `relieve-never-expand` is measured against — and persist takes it from the
//! host, never from the row being judged. This node's host value is its **SELF
//! config plane** (#324): `mesh_config.baseline.{wire_name}` in
//! [`crate::graph_config`], a namespace deliberately spelled in the config
//! plane's dotted style rather than persist's `mesh_config:` dimension prefix,
//! because the two planes never merge (FSD wall 5).
//!
//! A failed baseline read is **fatal to the whole surface**, not a fallback to
//! [`MeshConfigBaseline::owner_defaults`]: falling back would silently RAISE
//! the ceiling every incoming row is clamped against, which is an expansion
//! caused by a read error.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::mesh_config::{
    field, fold_mesh_config, is_mesh_config_dimension, mesh_config_envelope, DIMENSION_PREFIX,
    EMERGENCY_MAX_TTL_HOURS, NAMESPACE_FAMILY,
};
use ciris_persist::federation::types::{
    attestation_tier, attestation_type, cohort_scope, Attestation, ScrubSig,
};
use ciris_persist::federation::{
    trust_root, MeshConfigBaseline, MeshConfigFold, MeshConfigForm, MeshConfigKey,
    MeshConfigOutcome, MeshConfigSetting,
};
use ciris_persist::prelude::Engine;

use crate::auth::gate::CapabilityVerb;
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::{resolve_bearer, SessionCaller};

// ═══════════════════════════════════════════════════════════════════════════
//  Routes + vocabulary
// ═══════════════════════════════════════════════════════════════════════════

/// `GET` — the effective values, their provenance, and their TTLs.
pub const ROUTE_READ: &str = "/v1/mesh-config";
/// `GET` — every mesh-config row this node holds, newest first.
pub const ROUTE_HISTORY: &str = "/v1/mesh-config/history";
/// `POST` — the durable path.
pub const ROUTE_DURABLE: &str = "/v1/mesh-config/durable";
/// `POST` — the emergency relief path.
pub const ROUTE_RELIEF: &str = "/v1/mesh-config/relief";

/// The locale the `text` half of every `{id, text}` pair is written in.
pub const SOURCE_LOCALE: &str = "en";

/// The SELF-plane ([`crate::graph_config`]) config-key namespace this node's
/// own mesh-config **baseline** lives in: `mesh_config.baseline.{wire_name}`,
/// where `wire_name` is [`MeshConfigKey::wire_name`] and never a literal.
///
/// Dotted, like every other config key (`auth.admin_key_ids`,
/// `net.bootstrap_peers`) — and deliberately NOT persist's
/// [`DIMENSION_PREFIX`]. Node config is SELF and the mesh-config plane is
/// federation-scoped; a shared spelling is how two planes start looking like
/// one.
pub const BASELINE_CONFIG_PREFIX: &str = "mesh_config.baseline.";

/// Hard ceiling on one history page. A history an operator cannot read is not
/// evidence; the response says when it was cut.
pub const MAX_HISTORY_LIMIT: usize = 2_000;

/// Default history page size.
pub const DEFAULT_HISTORY_LIMIT: usize = 200;

/// A localizable string: a stable id plus its English source.
fn m(id: &str, text: &str) -> Value {
    json!({ "id": id, "text": text })
}

fn err(code: StatusCode, token: &str, id: &str, text: String) -> Response {
    (
        code,
        Json(json!({
            "refused": true,
            "refusal": token,
            "source_locale": SOURCE_LOCALE,
            "message": m(id, &text),
        })),
    )
        .into_response()
}

fn refusal(code: StatusCode, token: &str, id: &str, text: &str) -> Response {
    err(code, token, id, text.to_owned())
}

// ═══════════════════════════════════════════════════════════════════════════
//  State + gates
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct MeshConfigState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — the SUBSCRIBER whose `trust:accepts`
    /// edges enumerate the roots, and the node whose baseline is the ceiling.
    /// The row's *author* is the signer's derived key id, resolved per call.
    node_key_id: String,
}

/// Owner-authority gate — the [`crate::federation_admin`] spine verbatim:
/// `resolve_bearer → SessionCaller → SYSTEM_ADMIN + FullAccess`, both, so
/// neither a role-permission drift nor a permission-only check can widen who
/// may turn a mesh-wide knob.
async fn require_owner(
    st: &MeshConfigState,
    headers: &HeaderMap,
) -> Result<SessionCaller, Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_absent",
            "mesh_config.refusal.session_absent",
            "No session token was presented. The mesh-configuration surface is owner-only.",
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
            "mesh_config.refusal.not_owner",
            "The mesh-configuration surface requires the owner (SYSTEM_ADMIN) role.",
        )),
        Ok(None) => Err(refusal(
            StatusCode::UNAUTHORIZED,
            "session_invalid",
            "mesh_config.refusal.session_invalid",
            "That session is invalid or expired.",
        )),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "mesh_config.refusal.store_unavailable",
            format!("The substrate could not be read: {e}"),
        )),
    }
}

/// The gate stack: serve-only floor → owner session → the capability verb.
///
/// Reads take [`CapabilityVerb::ReadNodeState`] — delegatable, the same posture
/// `GET /v1/node/state` holds, so an owner may hand a monitoring agent "watch
/// this node's effective config" without also handing it the knobs. Writes take
/// the never-delegatable [`CapabilityVerb::Wipe`], exactly as
/// [`crate::admin_ops`] does: **no delegated bearer token may turn a mesh-wide
/// knob, only the owner directly.** `ConfigWrite` would have been the wrong
/// verb in a way that matters — it is the SELF config plane's verb, and the two
/// planes never merge.
async fn gate(
    st: &MeshConfigState,
    headers: &HeaderMap,
    verb: CapabilityVerb,
) -> Result<(), Response> {
    if crate::auth::gate::require_owner_bound(&st.engine, &st.node_key_id)
        .await
        .is_err()
    {
        return Err(refusal(
            StatusCode::FORBIDDEN,
            "node_unowned",
            "mesh_config.refusal.node_unowned",
            "This node has no responsible party (owner-binding), so it neither reports nor \
             changes mesh configuration on anyone's behalf. Claim ownership first.",
        ));
    }
    let caller = require_owner(st, headers).await?;
    if let Some(resp) = crate::auth::gate::require_verb(&caller, verb) {
        return Err(resp);
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
//  The registry — a PROJECTION of persist's closed set, never a copy
// ═══════════════════════════════════════════════════════════════════════════

/// Every registered key with its full [`MeshConfigKeySpec`], read from persist.
///
/// [`MeshConfigKey::ALL`] is the closed set and `spec()` is the one place a
/// key's facts live, so adding a key upstream adds it here with no edit. The
/// wire spelling, the polarity, the unit, the domain, the owner default and the
/// consumer/knob pair all come off the spec — this function writes down none of
/// them.
///
/// [`MeshConfigKeySpec`]: ciris_persist::federation::MeshConfigKeySpec
#[must_use]
pub fn registry_json() -> Vec<Value> {
    MeshConfigKey::ALL
        .iter()
        .map(|k| {
            let s = k.spec();
            json!({
                "key": s.wire_name,
                // The envelope KEY comes from persist (SRV-1/#322) — the
                // response spells the field the same way the wire does.
                (paths::DIMENSION): k.dimension(),
                "polarity": s.polarity.as_str(),
                "unit": s.unit.as_str(),
                "min": s.min,
                "max": s.max,
                "owner_default": s.owner_default,
                "consumer": s.consumer,
                "knob": s.knob,
            })
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
//  TTL — data plus a message id, never a sentence
// ═══════════════════════════════════════════════════════════════════════════

/// A TTL, counting down. **`remaining_seconds` is the countdown**; the sentence
/// is a message id a UI resolves in the reader's language.
///
/// Three arms, because "no TTL", "expired" and "running" are three facts and a
/// `null` would collapse the first two.
fn ttl_json(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Value {
    match expires_at {
        None => json!({
            "bounded": false,
            "message": m(
                "mesh_config.ttl.unbounded",
                "This row carries no expiry. It applies until it is superseded.",
            ),
        }),
        Some(at) => {
            let remaining = (at - now).num_seconds();
            let expired = remaining <= 0;
            json!({
                "bounded": true,
                "expires_at": at.to_rfc3339(),
                "remaining_seconds": remaining.max(0),
                "expired": expired,
                "message": if expired {
                    m(
                        "mesh_config.ttl.expired",
                        "This row's window has closed. The fold drops an expired row at read \
                         time, so it needs no revocation and no reachable author.",
                    )
                } else {
                    m(
                        "mesh_config.ttl.running",
                        "This row's window is open and closes at the named instant.",
                    )
                },
            })
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Distinct zeroes — the plane
// ═══════════════════════════════════════════════════════════════════════════

/// **What a zero on this surface MEANS.** Five different facts that all produce
/// "nine keys at their baseline", separated by token rather than by band.
///
/// This repo has collapsed a zero four times (`ScoreOutcome`, `RetentionOutcome`,
/// edge's withhold ledger, `operator_surface`), so the rule is stated rather
/// than assumed: *`0` because nobody spoke and `0` because nothing could be
/// read must not render the same.*
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneStanding {
    /// The plane could not be read — the subscription enumeration failed, a
    /// subscribed root's rows could not be listed, or the node's own baseline
    /// could not be resolved. **Not** "nothing is set".
    Unreadable,
    /// The plane read cleanly and this node subscribes to NO trust root, so no
    /// root can speak to it at all. Every key sits at the owner's baseline
    /// because there is nobody to move it.
    NoSubscription,
    /// Roots are subscribed and this node holds ZERO mesh-config rows from any
    /// of them.
    NoRowsHeld,
    /// Rows are held and none of them binds: every one is expired, clamped to
    /// the baseline, or asks for exactly the baseline value.
    NoneBinding,
    /// At least one key is moved off the owner's baseline by a root.
    Configured,
}

impl PlaneStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::NoSubscription => "no_subscription",
            Self::NoRowsHeld => "no_rows_held",
            Self::NoneBinding => "none_binding",
            Self::Configured => "configured",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::NoSubscription,
        Self::NoRowsHeld,
        Self::NoneBinding,
        Self::Configured,
    ];

    /// The operator-facing explanation.
    #[must_use]
    fn message(self) -> Value {
        match self {
            Self::Unreadable => m(
                "mesh_config.plane.unreadable",
                "The mesh-config plane could not be read here. This is NOT a statement that \
                 nothing is set — the values below are unknown, not defaults.",
            ),
            Self::NoSubscription => m(
                "mesh_config.plane.no_subscription",
                "This node holds no live trust-root edge, so no root may configure it. The \
                 subscription IS the trust edge.",
            ),
            Self::NoRowsHeld => m(
                "mesh_config.plane.no_rows_held",
                "This node subscribes to at least one trust root and holds no mesh-config row \
                 from any of them. Every key runs at the owner's own baseline.",
            ),
            Self::NoneBinding => m(
                "mesh_config.plane.none_binding",
                "Mesh-config rows are held and none of them binds: each is expired, clamped to \
                 the owner's consent, or asks for the baseline value already in force.",
            ),
            Self::Configured => m(
                "mesh_config.plane.configured",
                "At least one key is moved off the owner's baseline by a subscribed root.",
            ),
        }
    }

    /// Read the standing off a snapshot. `None` is the unreadable arm and is
    /// the only way to reach it — an error must never arrive here as an empty
    /// fold.
    #[must_use]
    fn of(snapshot: Option<&Snapshot>) -> Self {
        let Some(s) = snapshot else {
            return Self::Unreadable;
        };
        if !s.unreadable_roots.is_empty() {
            return Self::Unreadable;
        }
        if s.fold.roots.is_empty() {
            return Self::NoSubscription;
        }
        if s.fold.settings.iter().all(|x| x.per_root.is_empty()) {
            return Self::NoRowsHeld;
        }
        if s.fold.settings.iter().any(|x| x.relieved) {
            Self::Configured
        } else {
            Self::NoneBinding
        }
    }
}

/// **Where one key's current value came from.** Three arms, because a key at
/// its baseline because nobody spoke and a key at its baseline because a root
/// asked for exactly that value are different provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueProvenance {
    /// No root has a live row for this key. The value is the owner's own.
    BaselineUnspoken,
    /// Roots have live rows and none moved the value off the baseline.
    BaselineNotMoved,
    /// A root's row bound. `decided_by_root` / `row_id` / `decided_by` name it.
    Root,
}

impl ValueProvenance {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaselineUnspoken => "baseline_unspoken",
            Self::BaselineNotMoved => "baseline_not_moved",
            Self::Root => "root",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[Self::BaselineUnspoken, Self::BaselineNotMoved, Self::Root];

    /// Read it off persist's own resolved setting.
    #[must_use]
    fn of(s: &MeshConfigSetting) -> Self {
        if s.decided_by_root.is_some() {
            Self::Root
        } else if s.per_root.is_empty() {
            Self::BaselineUnspoken
        } else {
            Self::BaselineNotMoved
        }
    }

    fn message(self) -> Value {
        match self {
            Self::BaselineUnspoken => m(
                "mesh_config.provenance.baseline_unspoken",
                "No subscribed root holds a live row for this key, so the node runs the value \
                 its owner consented to.",
            ),
            Self::BaselineNotMoved => m(
                "mesh_config.provenance.baseline_not_moved",
                "Subscribed roots hold live rows for this key and none of them moved it: each \
                 was clamped to the owner's consent or asked for the value already in force.",
            ),
            Self::Root => m(
                "mesh_config.provenance.root",
                "A subscribed root's signed row set this value. The row, its author and the \
                 delegation it was taken under are named beside it.",
            ),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Distinct zeroes — the history
// ═══════════════════════════════════════════════════════════════════════════

/// **What an empty history MEANS.** "No history" and "history unavailable" are
/// different answers, and a history that is missing SOME roots is a third.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryStanding {
    /// Nothing could be read: the subscription enumeration failed, the baseline
    /// failed, or every subscribed root's rows failed to list.
    Unreadable,
    /// Some roots were read and some were not. The rows below are real and the
    /// set is INCOMPLETE; `unreadable_roots` names which.
    Partial,
    /// No trust root is subscribed, so there is no plane to have a history on.
    NoSubscription,
    /// Every subscribed root read cleanly and none has ever filed a row.
    Empty,
    /// Rows were read.
    Present,
}

impl HistoryStanding {
    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::Partial => "partial",
            Self::NoSubscription => "no_subscription",
            Self::Empty => "empty",
            Self::Present => "present",
        }
    }

    /// Every variant — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Unreadable,
        Self::Partial,
        Self::NoSubscription,
        Self::Empty,
        Self::Present,
    ];

    fn message(self) -> Value {
        match self {
            Self::Unreadable => m(
                "mesh_config.history.unreadable",
                "The mesh-config history could not be read here. This is NOT a statement that \
                 no row was ever filed.",
            ),
            Self::Partial => m(
                "mesh_config.history.partial",
                "Some subscribed roots could not be read, so this history is incomplete. The \
                 roots that failed are named.",
            ),
            Self::NoSubscription => m(
                "mesh_config.history.no_subscription",
                "This node holds no live trust-root edge, so no root has ever been able to file \
                 a mesh-config row here.",
            ),
            Self::Empty => m(
                "mesh_config.history.empty",
                "Every subscribed root was read and none has ever filed a mesh-config row.",
            ),
            Self::Present => m(
                "mesh_config.history.present",
                "Every mesh-config row this node holds, newest first.",
            ),
        }
    }

    /// Read the standing off a snapshot. `None` is the unreadable arm.
    #[must_use]
    fn of(snapshot: Option<&Snapshot>) -> Self {
        let Some(s) = snapshot else {
            return Self::Unreadable;
        };
        if s.fold.roots.is_empty() {
            // A failed enumeration never lands here — it lands as `None`.
            return Self::NoSubscription;
        }
        if s.unreadable_roots.len() == s.fold.roots.len() {
            return Self::Unreadable;
        }
        if !s.unreadable_roots.is_empty() {
            return Self::Partial;
        }
        if s.rows.is_empty() {
            Self::Empty
        } else {
            Self::Present
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  The snapshot — ONE read, persist's own pure fold
// ═══════════════════════════════════════════════════════════════════════════

/// One consistent read of the plane: the rows, the roots that could not be
/// read, the node's baseline, and persist's own fold over exactly those rows.
struct Snapshot {
    rows: Vec<Attestation>,
    /// Subscribed roots whose rows could not be listed, with the reason.
    unreadable_roots: BTreeMap<String, String>,
    baseline: MeshConfigBaseline,
    fold: MeshConfigFold,
    now: DateTime<Utc>,
}

/// Resolve this node's own baseline from its SELF config plane.
///
/// Sparse: a key the owner has not pinned falls through to
/// [`MeshConfigKey::owner_default`], which is persist's own answer to *"what
/// its owner consented to by default"*. An out-of-domain pin is clamped by
/// [`MeshConfigBaseline::with`] — persist's rule, not one invented here.
///
/// A FAILED read is an `Err`, never a fallback: silently returning
/// `owner_defaults()` would raise the ceiling every row is clamped against.
async fn resolve_baseline(engine: &Arc<Engine>) -> Result<MeshConfigBaseline, String> {
    let pinned = crate::graph_config::list_configs(engine, Some(BASELINE_CONFIG_PREFIX))
        .await
        .map_err(|e| format!("read mesh-config baseline from the SELF config plane: {e}"))?;
    let mut baseline = MeshConfigBaseline::owner_defaults();
    for &key in MeshConfigKey::ALL {
        let config_key = format!("{BASELINE_CONFIG_PREFIX}{}", key.wire_name());
        if let Some(v) = pinned.get(&config_key).and_then(|e| e.value.as_i64()) {
            baseline = baseline.with(key, v);
        }
    }
    Ok(baseline)
}

/// Gather every mesh-config row this node holds, per subscribed root, then run
/// persist's own pure [`fold_mesh_config`] over exactly them.
///
/// Row gathering mirrors persist's `resolve_mesh_config` in ONE respect only —
/// rows are filed against the root, so `list_attestations_for(root)` is the
/// read — and differs in one: a root that cannot be read is RECORDED rather
/// than skipped.
async fn snapshot(
    engine: &Arc<Engine>,
    node_key_id: &str,
    now: DateTime<Utc>,
) -> Result<Snapshot, String> {
    let baseline = resolve_baseline(engine).await?;
    let directory = engine.federation_directory();
    let roots = trust_root::trusted_roots_of(directory.as_ref(), node_key_id, now)
        .await
        .map_err(|e| format!("enumerate this node's trust roots: {e}"))?;

    let mut rows: Vec<Attestation> = Vec::new();
    let mut unreadable_roots: BTreeMap<String, String> = BTreeMap::new();
    for root in &roots {
        match directory.list_attestations_for(root).await {
            Ok(found) => rows.extend(found.into_iter().filter(|r| {
                r.attestation_envelope
                    .get(paths::DIMENSION)
                    .and_then(|v| v.as_str())
                    .is_some_and(is_mesh_config_dimension)
            })),
            Err(e) => {
                unreadable_roots.insert(root.clone(), e.to_string());
            }
        }
    }
    let fold = fold_mesh_config(node_key_id, &baseline, &roots, &rows, now);
    Ok(Snapshot {
        rows,
        unreadable_roots,
        baseline,
        fold,
        now,
    })
}

/// The roots that could not be read, as the wire carries them.
fn unreadable_roots_json(s: &Snapshot) -> Vec<Value> {
    s.unreadable_roots
        .iter()
        .map(|(root, reason)| json!({ "root_ref": root, "error": reason }))
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════
//  GET /v1/mesh-config — effective values, provenance, TTLs
// ═══════════════════════════════════════════════════════════════════════════

/// One key's resolved setting, rendered. Every number is persist's; this adds
/// the provenance token and the counting-down TTL.
fn setting_json(s: &MeshConfigSetting, now: DateTime<Utc>) -> Value {
    let provenance = ValueProvenance::of(s);
    let spec = s.key.spec();
    json!({
        "key": spec.wire_name,
        "unit": s.unit.as_str(),
        "polarity": s.polarity.as_str(),
        "consumer": spec.consumer,
        "knob": spec.knob,
        "baseline": s.baseline,
        "effective": s.effective,
        "relieved": s.relieved,
        "provenance": {
            "source": provenance.as_str(),
            "message": provenance.message(),
            "decided_by_root": s.decided_by_root,
            "row_id": s.row_id,
            "decided_by": s.decided_by,
            "delegation_id": s.delegation_id,
            "form": s.form.map(MeshConfigForm::as_str),
            "grounds": s.grounds,
        },
        "ttl": ttl_json(s.expires_at, now),
        "per_root": s.per_root.iter().map(|rv| json!({
            "root_ref": rv.root_ref,
            "asked": rv.asked,
            "effective": rv.effective,
            "clamped": rv.clamped,
            "row_id": rv.row_id,
            "form": rv.form.as_str(),
            "ttl": ttl_json(rv.expires_at, now),
        })).collect::<Vec<_>>(),
        "clamped_roots": s.clamped_roots,
    })
}

/// The whole read surface, as a value — so it is unit-testable without a
/// socket. `snapshot` is `None` exactly when the plane could not be read.
fn read_surface_json(snapshot: Option<&Snapshot>, now: DateTime<Utc>) -> Value {
    let standing = PlaneStanding::of(snapshot);
    let mut out = json!({
        "source_locale": SOURCE_LOCALE,
        "namespace_family": NAMESPACE_FAMILY,
        "dimension_prefix": DIMENSION_PREFIX,
        "generated_at": now.to_rfc3339(),
        "standing": standing.as_str(),
        "standing_message": standing.message(),
        "registry": registry_json(),
        "emergency": {
            // READ from persist. A UI bounds its own input with this; the
            // BOUND itself is persist's `ttl_too_long` refusal, never a check
            // here.
            "max_ttl_hours": EMERGENCY_MAX_TTL_HOURS,
            "message": m(
                "mesh_config.emergency.bound",
                "Emergency relief expires by construction. The maximum window is the \
                 substrate's, carried here so a form can bound its input; the substrate \
                 refuses anything longer at its own door.",
            ),
        },
        "durability": m(
            "mesh_config.durability.substrate_decides",
            "Which acts earn a durable setting is the substrate's ruling, re-read on every \
             call and reported by its own refusal token. This node encodes no durability \
             rule of its own.",
        ),
    });
    match snapshot {
        None => {
            out["roots"] = json!(Value::Null);
            out["settings"] = json!(Value::Null);
        }
        Some(s) => {
            out["roots"] = json!(s.fold.roots);
            out["unreadable_roots"] = json!(unreadable_roots_json(s));
            out["node_key_id"] = json!(s.fold.node_key_id);
            out["rows_held"] = json!(s.rows.len());
            out["settings"] = json!(s
                .fold
                .settings
                .iter()
                .map(|x| setting_json(x, s.now))
                .collect::<Vec<_>>());
            out["baseline"] = json!(MeshConfigKey::ALL
                .iter()
                .map(|k| json!({ "key": k.spec().wire_name, "value": s.baseline.get(*k) }))
                .collect::<Vec<_>>());
        }
    }
    out
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NowQuery {
    /// RFC 3339. Pin the instant every TTL counts down from — so a test, or a
    /// UI replaying an incident, reads the same numbers twice.
    now: Option<String>,
}

/// Pin the read instant. `Err` carries the parse complaint, not a whole
/// response — the response is built at the call site so the error type stays
/// small.
fn parse_now(raw: Option<&str>) -> Result<DateTime<Utc>, String> {
    match raw {
        None => Ok(Utc::now()),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| format!("`now` must be RFC 3339: {e}")),
    }
}

fn bad_now(e: String) -> Response {
    err(
        StatusCode::BAD_REQUEST,
        "bad_request",
        "mesh_config.refusal.bad_now",
        e,
    )
}

async fn get_mesh_config(
    State(st): State<MeshConfigState>,
    headers: HeaderMap,
    Query(q): Query<NowQuery>,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::ReadNodeState).await {
        return resp;
    }
    let now = match parse_now(q.now.as_deref()) {
        Ok(n) => n,
        Err(e) => return bad_now(e),
    };
    match snapshot(&st.engine, &st.node_key_id, now).await {
        Ok(s) => (StatusCode::OK, Json(read_surface_json(Some(&s), now))).into_response(),
        Err(e) => {
            let mut body = read_surface_json(None, now);
            body["error"] = json!(e);
            (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  GET /v1/mesh-config/history — every row this node holds
// ═══════════════════════════════════════════════════════════════════════════

/// One held row, projected. The envelope field NAMES come from persist's
/// [`field`] module — never a hand-mirrored literal (SRV-1/#322).
fn history_row_json(
    row: &Attestation,
    counted: &BTreeSet<String>,
    binding: &BTreeSet<String>,
    now: DateTime<Utc>,
) -> Value {
    let env = &row.attestation_envelope;
    let s = |k: &str| env.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    let dimension = env.get(paths::DIMENSION).and_then(|v| v.as_str());
    let key = dimension.and_then(MeshConfigKey::from_dimension);
    let valid_until = env
        .get(field::VALID_UNTIL)
        .and_then(|v| v.as_str())
        .and_then(|t| t.parse::<DateTime<Utc>>().ok());
    json!({
        "attestation_id": row.attestation_id,
        (paths::DIMENSION): dimension,
        // `None` here is a row on this plane whose key is not in the closed
        // registry — held, never folded. Rendered as null rather than dropped.
        "key": key.map(|k| k.spec().wire_name),
        "value": env.get(field::VALUE).and_then(serde_json::Value::as_i64),
        "root_ref": s(field::ROOT_REF),
        "form": s(field::FORM),
        "author": row.attesting_key_id,
        "delegation_id": s(field::DELEGATION_ID),
        "ratifies_row_id": s(field::RATIFIES),
        "grounds": s(field::GROUNDS),
        "asserted_at": row.asserted_at.to_rfc3339(),
        "scrubs": row.scrubs().len(),
        "ttl": ttl_json(valid_until, now),
        // Both flags are READ OFF persist's fold — never re-derived here, and
        // they are two different facts. `counted`: the fold used this row as
        // its answer for that (root, key) at this instant, so a superseded or
        // TTL-expired row is false. `binding`: that answer is also the one that
        // won across roots, which is what the read surface reports as
        // `provenance.row_id`. A row can be counted and not binding — its root
        // spoke and a tighter root won.
        "counted": counted.contains(&row.attestation_id),
        "binding": binding.contains(&row.attestation_id),
    })
}

/// The history surface, as a value. `snapshot` is `None` exactly when nothing
/// could be read.
fn history_json(snapshot: Option<&Snapshot>, limit: usize, now: DateTime<Utc>) -> Value {
    let standing = HistoryStanding::of(snapshot);
    let mut out = json!({
        "source_locale": SOURCE_LOCALE,
        "generated_at": now.to_rfc3339(),
        "standing": standing.as_str(),
        "standing_message": standing.message(),
    });
    match snapshot {
        None => {
            out["rows"] = json!(Value::Null);
        }
        Some(s) => {
            let counted: BTreeSet<String> = s
                .fold
                .settings
                .iter()
                .flat_map(|x| x.per_root.iter().map(|rv| rv.row_id.clone()))
                .collect();
            let binding: BTreeSet<String> = s
                .fold
                .settings
                .iter()
                .filter_map(|x| x.row_id.clone())
                .collect();
            let mut ordered: Vec<&Attestation> = s.rows.iter().collect();
            ordered.sort_by(|a, b| {
                b.asserted_at
                    .cmp(&a.asserted_at)
                    .then_with(|| a.attestation_id.cmp(&b.attestation_id))
            });
            let total = ordered.len();
            let truncated = total > limit;
            out["roots"] = json!(s.fold.roots);
            out["unreadable_roots"] = json!(unreadable_roots_json(s));
            out["total"] = json!(total);
            out["truncated"] = json!(truncated);
            out["rows"] = json!(ordered
                .into_iter()
                .take(limit)
                .map(|r| history_row_json(r, &counted, &binding, s.now))
                .collect::<Vec<_>>());
            if truncated {
                out["truncation_message"] = m(
                    "mesh_config.history.truncated",
                    "This page was cut at the limit. The total below counts every row read.",
                );
            }
        }
    }
    out
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    now: Option<String>,
    limit: Option<usize>,
}

async fn get_history(
    State(st): State<MeshConfigState>,
    headers: HeaderMap,
    Query(q): Query<HistoryQuery>,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::ReadNodeState).await {
        return resp;
    }
    let now = match parse_now(q.now.as_deref()) {
        Ok(n) => n,
        Err(e) => return bad_now(e),
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_HISTORY_LIMIT)
        .clamp(1, MAX_HISTORY_LIMIT);
    match snapshot(&st.engine, &st.node_key_id, now).await {
        Ok(s) => (StatusCode::OK, Json(history_json(Some(&s), limit, now))).into_response(),
        Err(e) => {
            let mut body = history_json(None, limit, now);
            body["error"] = json!(e);
            (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  The two write paths
// ═══════════════════════════════════════════════════════════════════════════

/// The fields both write paths carry.
///
/// `key` deserializes THROUGH [`MeshConfigKey`], so an unregistered key is
/// refused by persist's own `Deserialize` with persist's own sentence — CC
/// 4.2.1's closed registry, enforced without a list here.
#[derive(Debug, Clone, Deserialize)]
struct ConfigWriteBase {
    /// The registered key.
    key: MeshConfigKey,
    /// The value, in the key's own unit.
    value: i64,
    /// The trust root this row is issued UNDER. Also the row's
    /// `attested_key_id`, so persist's fold finds it.
    root_ref: String,
    /// **MANDATORY.** The `delegates_to` id the author acted UNDER.
    delegation_id: String,
    /// **MANDATORY.** Free text: WHY. Recorded, never interpreted.
    grounds: String,
}

/// The emergency relief body. `ttl_hours` is **not optional** — relief that
/// does not expire is not relief. The BOUND on it is persist's
/// ([`EMERGENCY_MAX_TTL_HOURS`], refused as `ttl_too_long`), not a check here.
#[derive(Debug, Clone, Deserialize)]
struct ReliefRequest {
    #[serde(flatten)]
    base: ConfigWriteBase,
    ttl_hours: i64,
}

/// The durable body.
#[derive(Debug, Clone, Deserialize)]
struct DurableRequest {
    #[serde(flatten)]
    base: ConfigWriteBase,
    /// The emergency row this makes permanent, when there is one. Passed
    /// through untouched — which of the substrate's doors it opens is the
    /// substrate's ruling.
    #[serde(default)]
    ratifies_row_id: Option<String>,
    /// Co-signatures over the SAME canonical envelope, carried onto the row's
    /// scrub set. What they are worth is counted by the substrate; this module
    /// counts nothing.
    #[serde(default)]
    additional_scrubs: Vec<ScrubSig>,
    /// Return the canonical envelope and its `payload_sha256` WITHOUT signing
    /// or submitting, so co-signers can produce `additional_scrubs` over
    /// exactly the bytes the submission will carry.
    #[serde(default)]
    dry_run: bool,
}

/// Refuse a blank required string.
fn require_nonblank(
    v: &str,
    token: &'static str,
    id: &'static str,
    text: &'static str,
) -> Option<Response> {
    if v.trim().is_empty() {
        Some(refusal(StatusCode::BAD_REQUEST, token, id, text))
    } else {
        None
    }
}

/// Check the base fields every write shares. **No authority decision is made
/// here** — that is `root_authorizes_author`'s, inside the substrate. What this
/// does is refuse an id that names nothing at all, the `authority_unresolved`
/// gate [`crate::admin_ops::router`] uses, so the recorded attribution is at
/// least a row this node holds rather than a string someone typed.
async fn check_base(engine: &Arc<Engine>, base: &ConfigWriteBase) -> Option<Response> {
    if let Some(r) = require_nonblank(
        &base.root_ref,
        "root_absent",
        "mesh_config.refusal.root_absent",
        "root_ref is required: a mesh-config row is issued under a trust root, and a row that \
         names none is filed where no fold will ever count it.",
    ) {
        return Some(r);
    }
    if let Some(r) = require_nonblank(
        &base.delegation_id,
        "attribution_absent",
        "mesh_config.refusal.attribution_absent",
        "delegation_id is required. An act that does not carry its own authority cannot be told \
         from an unauthorized one once the actor is gone.",
    ) {
        return Some(r);
    }
    if let Some(r) = require_nonblank(
        &base.grounds,
        "attribution_absent",
        "mesh_config.refusal.grounds_absent",
        "grounds is required. A knob turned for no recorded reason is indistinguishable from one \
         turned for a bad one.",
    ) {
        return Some(r);
    }
    match engine
        .federation_directory()
        .get_attestation(base.delegation_id.trim())
        .await
    {
        Ok(Some(row)) if row.attestation_type == attestation_type::DELEGATES_TO => None,
        Ok(Some(_)) => Some(refusal(
            StatusCode::FORBIDDEN,
            "authority_not_a_delegation",
            "mesh_config.refusal.authority_not_a_delegation",
            "The named delegation id is not a delegates_to row.",
        )),
        Ok(None) => Some(refusal(
            StatusCode::FORBIDDEN,
            "authority_unresolved",
            "mesh_config.refusal.authority_unresolved",
            "The named delegation is not a row this node holds, so the authority it records \
             would name nothing. Whether it actually authorizes this act is the substrate's \
             ruling, made at its own door.",
        )),
        Err(e) => Some(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "mesh_config.refusal.store_unavailable",
            format!("The substrate could not be read: {e}"),
        )),
    }
}

/// Assemble + hybrid-sign one mesh-config row.
///
/// The envelope comes from persist's own [`mesh_config_envelope`], so producer
/// and fold cannot disagree about where a value lives. `attested_key_id` is the
/// root, which is what makes the row findable by the fold's
/// `list_attestations_for(root)` read.
async fn build_row(
    engine: &Arc<Engine>,
    envelope: Value,
    root_ref: &str,
    additional_scrubs: Vec<ScrubSig>,
    now: DateTime<Utc>,
) -> Result<Attestation, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive acting key_id: {e}"))?;
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize mesh-config row: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| format!("hybrid-sign mesh-config row: {e}"))?;
    Ok(Attestation {
        attestation_id: crate::ids::new_id(),
        attesting_key_id: key_id.clone(),
        attested_key_id: root_ref.to_owned(),
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
        additional_scrubs,
    })
}

/// `sha256(JCS(envelope))` — the `payload_sha256` CC 4.2.1 names, so a
/// co-signer can be told exactly which bytes to sign.
fn payload_sha256(envelope: &Value) -> Result<String, String> {
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| format!("canonicalize mesh-config row: {e}"))?;
    Ok(hex::encode(Sha256::digest(&canonical)))
}

/// **Render the substrate's outcome. Nothing is decided here.**
///
/// The refusal token is [`MeshConfigRefusalReason::as_str`] verbatim — persist
/// owns that vocabulary and it is append-only — and the message id is DERIVED
/// from it, so the localizable id set cannot drift from the token set and no
/// variant list is written down.
///
/// [`MeshConfigRefusalReason::as_str`]: ciris_persist::federation::MeshConfigRefusalReason::as_str
fn outcome_response(
    outcome: MeshConfigOutcome,
    mut body: serde_json::Map<String, Value>,
) -> Response {
    match outcome.refusal() {
        None => {
            body.insert("admitted".into(), json!(true));
            body.insert(
                "message".into(),
                m(
                    "mesh_config.outcome.admitted",
                    "The substrate admitted this row. It is a MARKER, not a command: nothing was \
                     changed by its arrival, and its effect is entirely the read-time fold a \
                     consumer may honour.",
                ),
            );
            (StatusCode::OK, Json(Value::Object(body))).into_response()
        }
        Some(reason) => {
            let token = reason.as_str();
            body.insert("refused".into(), json!(true));
            body.insert("refusal".into(), json!(token));
            body.insert(
                "message".into(),
                m(
                    &format!("mesh_config.refusal.{token}"),
                    &format!(
                        "The substrate refused this mesh-config row at the {token} gate. The \
                         refusal token names which rule; the substrate owns that vocabulary."
                    ),
                ),
            );
            (StatusCode::CONFLICT, Json(Value::Object(body))).into_response()
        }
    }
}

/// The shared tail of both write paths: check the base fields, resolve the
/// baseline, assemble, sign, submit, render.
async fn submit(
    st: &MeshConfigState,
    base: &ConfigWriteBase,
    form: MeshConfigForm,
    valid_until: Option<DateTime<Utc>>,
    ratifies: Option<&str>,
    additional_scrubs: Vec<ScrubSig>,
    now: DateTime<Utc>,
) -> Response {
    if let Some(resp) = check_base(&st.engine, base).await {
        return resp;
    }
    let baseline = match resolve_baseline(&st.engine).await {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "baseline_unreadable",
                "mesh_config.refusal.baseline_unreadable",
                format!(
                    "This node's own consent baseline could not be read, so there is no ceiling \
                     to judge this row against and it is refused rather than judged against a \
                     default: {e}"
                ),
            )
        }
    };
    let envelope = mesh_config_envelope(
        base.key,
        base.value,
        base.root_ref.trim(),
        form,
        valid_until,
        base.delegation_id.trim(),
        ratifies,
        base.grounds.trim(),
    );
    let sha = match payload_sha256(&envelope) {
        Ok(s) => s,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "canonicalize_failed",
                "mesh_config.refusal.canonicalize_failed",
                e,
            )
        }
    };
    let row = match build_row(
        &st.engine,
        envelope.clone(),
        base.root_ref.trim(),
        additional_scrubs,
        now,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "sign_failed",
                "mesh_config.refusal.sign_failed",
                e,
            )
        }
    };
    let outcome = match st
        .engine
        .record_mesh_config_row(&st.node_key_id, &baseline, &row, now)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "store_unavailable",
                "mesh_config.refusal.store_unavailable",
                format!("The substrate could not judge this row: {e}"),
            )
        }
    };
    tracing::warn!(
        form = form.as_str(),
        key = base.key.wire_name(),
        value = base.value,
        root_ref = %base.root_ref.trim(),
        delegation_id = %base.delegation_id.trim(),
        payload_sha256 = %sha,
        refusal = outcome.refusal().map(|r| r.as_str()).unwrap_or("-"),
        "mesh-config row submitted"
    );
    let mut body = serde_json::Map::new();
    body.insert("source_locale".into(), json!(SOURCE_LOCALE));
    body.insert("form".into(), json!(form.as_str()));
    body.insert("key".into(), json!(base.key.spec().wire_name));
    body.insert("value".into(), json!(base.value));
    body.insert("root_ref".into(), json!(base.root_ref.trim()));
    body.insert("attestation_id".into(), json!(row.attestation_id));
    body.insert("payload_sha256".into(), json!(sha));
    body.insert("envelope".into(), envelope);
    body.insert("ttl".into(), ttl_json(valid_until, now));
    outcome_response(outcome, body)
}

async fn post_relief(
    State(st): State<MeshConfigState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::Wipe).await {
        return resp;
    }
    let req: ReliefRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "mesh_config.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let now = Utc::now();
    // Arithmetic guard ONLY — the admissible window is the substrate's.
    let Some(window) = Duration::try_hours(req.ttl_hours) else {
        return err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "mesh_config.refusal.bad_ttl",
            format!("ttl_hours {} does not express a duration.", req.ttl_hours),
        );
    };
    let Some(valid_until) = now.checked_add_signed(window) else {
        return err(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "mesh_config.refusal.bad_ttl",
            format!(
                "ttl_hours {} does not land on a representable instant.",
                req.ttl_hours
            ),
        );
    };
    // No `additional_scrubs` and no `ratifies` on this path, deliberately:
    // emergency relief IS the threshold-1 door, so a co-signature buys nothing
    // here, and a row that ratifies something is not an emergency.
    submit(
        &st,
        &req.base,
        MeshConfigForm::Emergency,
        Some(valid_until),
        None,
        Vec::new(),
        now,
    )
    .await
}

async fn post_durable(
    State(st): State<MeshConfigState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = gate(&st, &headers, CapabilityVerb::Wipe).await {
        return resp;
    }
    let req: DurableRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "mesh_config.refusal.bad_request",
                format!("The request body could not be parsed: {e}"),
            )
        }
    };
    let now = Utc::now();
    let ratifies = req
        .ratifies_row_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if req.dry_run {
        let envelope = mesh_config_envelope(
            req.base.key,
            req.base.value,
            req.base.root_ref.trim(),
            MeshConfigForm::Durable,
            None,
            req.base.delegation_id.trim(),
            ratifies,
            req.base.grounds.trim(),
        );
        return match payload_sha256(&envelope) {
            Ok(sha) => (
                StatusCode::OK,
                Json(json!({
                    "source_locale": SOURCE_LOCALE,
                    "dry_run": true,
                    "form": MeshConfigForm::Durable.as_str(),
                    "payload_sha256": sha,
                    "envelope": envelope,
                    "message": m(
                        "mesh_config.dry_run",
                        "Nothing was signed and nothing was submitted. These are the exact \
                         canonical bytes a co-signer must sign for their scrub to count on the \
                         real submission.",
                    ),
                })),
            )
                .into_response(),
            Err(e) => err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "canonicalize_failed",
                "mesh_config.refusal.canonicalize_failed",
                e,
            ),
        };
    }
    submit(
        &st,
        &req.base,
        MeshConfigForm::Durable,
        None,
        ratifies,
        req.additional_scrubs,
        now,
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════════════════

/// Mount the Mesh Configuration surface. `node_key_id` is THIS node's
/// federation key id — the SUBSCRIBER whose trust edges enumerate the roots and
/// whose baseline is the ceiling every row is clamped against.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    Router::new()
        .route(ROUTE_READ, axum::routing::get(get_mesh_config))
        .route(ROUTE_HISTORY, axum::routing::get(get_history))
        .route(ROUTE_DURABLE, axum::routing::post(post_durable))
        .route(ROUTE_RELIEF, axum::routing::post(post_relief))
        .with_state(MeshConfigState {
            engine,
            node_key_id,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339")
    }

    const NOW: &str = "2026-08-03T12:00:00Z";

    fn empty_snapshot(roots: Vec<String>, rows: Vec<Attestation>) -> Snapshot {
        let baseline = MeshConfigBaseline::owner_defaults();
        let now = ts(NOW);
        let fold = fold_mesh_config("n", &baseline, &roots, &rows, now);
        Snapshot {
            rows,
            unreadable_roots: BTreeMap::new(),
            baseline,
            fold,
            now,
        }
    }

    #[test]
    fn plane_and_history_zeroes_name_their_own_cause() {
        // "could not read the plane" and "no mesh-config set" are DIFFERENT.
        assert_eq!(PlaneStanding::of(None), PlaneStanding::Unreadable);
        assert_eq!(
            PlaneStanding::of(Some(&empty_snapshot(Vec::new(), Vec::new()))),
            PlaneStanding::NoSubscription
        );
        assert_eq!(
            PlaneStanding::of(Some(&empty_snapshot(vec!["r".into()], Vec::new()))),
            PlaneStanding::NoRowsHeld
        );
        assert_ne!(
            PlaneStanding::Unreadable.as_str(),
            PlaneStanding::NoRowsHeld.as_str()
        );
        assert_ne!(
            PlaneStanding::NoSubscription.as_str(),
            PlaneStanding::NoRowsHeld.as_str()
        );

        // "history unavailable" and "no history" are DIFFERENT.
        assert_eq!(HistoryStanding::of(None), HistoryStanding::Unreadable);
        assert_eq!(
            HistoryStanding::of(Some(&empty_snapshot(vec!["r".into()], Vec::new()))),
            HistoryStanding::Empty
        );
        assert_ne!(
            HistoryStanding::Unreadable.as_str(),
            HistoryStanding::Empty.as_str()
        );

        // Every token in both closed sets is distinct.
        for (n, tokens) in [
            (
                PlaneStanding::ALL.len(),
                PlaneStanding::ALL
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<BTreeSet<_>>(),
            ),
            (
                HistoryStanding::ALL.len(),
                HistoryStanding::ALL
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<BTreeSet<_>>(),
            ),
            (
                ValueProvenance::ALL.len(),
                ValueProvenance::ALL
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<BTreeSet<_>>(),
            ),
        ] {
            assert_eq!(tokens.len(), n, "duplicate standing token");
        }
    }

    #[test]
    fn a_partial_history_is_not_a_complete_one() {
        let mut s = empty_snapshot(vec!["r1".into(), "r2".into()], Vec::new());
        s.unreadable_roots.insert("r2".into(), "boom".into());
        assert_eq!(HistoryStanding::of(Some(&s)), HistoryStanding::Partial);
        // And a plane with ANY unreadable root is unreadable, never "nothing set".
        assert_eq!(PlaneStanding::of(Some(&s)), PlaneStanding::Unreadable);

        let mut all_bad = empty_snapshot(vec!["r1".into()], Vec::new());
        all_bad.unreadable_roots.insert("r1".into(), "boom".into());
        assert_eq!(
            HistoryStanding::of(Some(&all_bad)),
            HistoryStanding::Unreadable
        );
    }

    #[test]
    fn the_registry_is_persists_own_closed_set() {
        let served = registry_json();
        assert_eq!(served.len(), MeshConfigKey::ALL.len());
        for (v, k) in served.iter().zip(MeshConfigKey::ALL.iter()) {
            let s = k.spec();
            assert_eq!(v["key"], json!(s.wire_name));
            assert_eq!(v["owner_default"], json!(s.owner_default));
            assert_eq!(v["consumer"], json!(s.consumer));
        }
    }

    #[test]
    fn a_ttl_is_data_plus_a_message_id() {
        let now = ts(NOW);
        let running = ttl_json(Some(now + Duration::hours(3)), now);
        assert_eq!(running["remaining_seconds"], json!(3 * 3600));
        assert_eq!(running["expired"], json!(false));
        // The sentence is an id, never a rendered countdown.
        let text = running["message"]["text"].as_str().expect("text");
        assert!(
            !text.chars().any(|c| c.is_ascii_digit()),
            "a TTL message must not render the countdown: {text}"
        );
        let unbounded = ttl_json(None, now);
        assert_eq!(unbounded["bounded"], json!(false));
        assert!(unbounded.get("remaining_seconds").is_none());
        let expired = ttl_json(Some(now - Duration::hours(1)), now);
        assert_eq!(expired["expired"], json!(true));
        assert_eq!(expired["remaining_seconds"], json!(0));
        // "no TTL" and "expired TTL" do not render alike.
        assert_ne!(unbounded["message"]["id"], expired["message"]["id"]);
    }

    #[test]
    fn the_emergency_bound_is_read_from_the_substrate() {
        let v = read_surface_json(None, ts(NOW));
        assert_eq!(
            v["emergency"]["max_ttl_hours"],
            json!(EMERGENCY_MAX_TTL_HOURS)
        );
        // The unreadable arm carries NO settings — never nine clean defaults.
        assert_eq!(v["settings"], Value::Null);
        assert_eq!(v["standing"], json!("unreadable"));
    }
}
