//! **Households: the family routes** (CIRISServer#627, `FSD/ROSTER_AND_DRIVE_CRUD.md` §3).
//!
//! Until 0.5.216 nothing in production could charter a household or admit a
//! member: `family::create_family` had one caller (the keyless accord, through
//! the trusted-local door) and `family::add_member` had none. This module is the
//! household instantiation of the accord's governance model
//! (`FSD/ROSTERED_GROUP_KEY_OPS.md`), generalised from one entrenched 2/3 family
//! to any family that declares its own `consensus_protocol`.
//!
//! # The rules every route here keeps (FSD §1)
//!
//! 1. **The owner's session.** Every write needs the node owner's own session
//!    (bearer, not delegated, SystemAdmin + FullAccess, owner-bound node). A
//!    delegate is refused `family.delegate_may_not_author`: a roster row is
//!    signed with the owner's fed-ID, and that signature outlives any
//!    delegation.
//! 2. **The human signs.** Every row is signed by the caller's fed-ID pen
//!    (`owner_signer_capsule::acquire`), never the node key: the record
//!    (`SignedFamily`, persist's REPLICATED `put_family` door — never the
//!    accord-only `put_family_local`), each roster growth (`AdmitSpec`), each
//!    removal (`SignedFamilyMembershipRevocation`), each supersede.
//! 3. **Membership is the FOLD.** Who is in a family is persist's
//!    `active_members(Cohort::Family, …)` — the record's roster MINUS effective
//!    revocations. Nothing here reads `family.members` for a membership
//!    decision; the record's raw roster is read only to build the NEXT record
//!    (a supersede must restate what it replaces).
//! 4. **Governance is the family's own rule.** `founder_only` (the default) is
//!    satisfied by one founder's signature, so the common case is one call.
//!    `quorum:M/N` goes through envelope → cosign → assemble, and the quorum is
//!    verified by persist's `verify_membership_quorum` /
//!    `supersede_family_with_quorum` (verify's `verify_membership_change`
//!    underneath), never by counting here.
//! 5. **Leaving is always your own act**, never subject to quorum.
//! 6. **A non-member cannot find out a family exists**: every route answers a
//!    non-member exactly as it answers an unknown id, `family.not_found` (404).
//!
//! # What persist admits at these pins (v48.0.0), and what it does not
//!
//! Measured while building this, and written down in the FSD §3.5 as well:
//!
//! - **`family_key_id` is a keyless group identifier.** The FK to
//!   `federation_keys` was dropped in persist v13.3.0 (V097, CIRISPersist#386);
//!   the invariant `put_family` enforces is that every MEMBER is a registered
//!   key. So a household id is minted here (`family:v1:<uuid>`), never
//!   registered, and nothing signs "as the family".
//! - **Only `quorum:M/N` is verifiable.** Verify's membership-change gate reads
//!   the prior AND new envelopes' `consensus_protocol` as `quorum:M/N` with
//!   `N == member count` and `2M > N`. `majority` / `unanimous` are therefore
//!   accepted at create as ALIASES and stored in their `quorum:M/N` form, and a
//!   quorum family's protocol is re-derived on every roster change
//!   ([`rescale`]) so `N` keeps matching.
//! - **An empty roster is not a verifiable membership change** (verify's
//!   `WeakQuorum { m: 0 }`), so a quorum DISSOLVE is authorized by the quorum
//!   cosigning a dissolve-marked envelope over the CURRENT roster (verified by
//!   `verify_membership_quorum`), and the terminal write is the authority-signed
//!   supersede to an empty roster, carrying that proof as its authorization.
//! - **A removed member cannot be re-added.** A family membership revocation is
//!   keyed `(family, member)` and has no re-establishment rule (unlike an
//!   identity occurrence's #421), so the fold excludes that key forever. A
//!   re-add is refused by name (`family.readd_unsupported`) rather than
//!   reported as a success the fold would ignore.
//! - **Only the first record and the removals replicate.** A peer applies a
//!   `Family` row with `put_family`, which is a plain INSERT: a grown or
//!   superseded record under an id the peer already holds is refused there. The
//!   revocation plane replicates independently, so removals, leaves and
//!   dissolves cross; growth and role changes after first contact do not until
//!   persist gives the family plane the community plane's widening (#860).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Deserialize;

use ciris_persist::federation::cohort::{AdmitSpec, Cohort, RosterMember};
use ciris_persist::federation::types::{
    Family, FamilyMember, FamilyMembershipRevocation, SignedFamily,
    SignedFamilyMembershipRevocation,
};
use ciris_persist::prelude::Engine;
use ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
use ciris_verify_core::threshold::ThresholdSignature;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;
use crate::owner_signer_capsule::{self, OwnerSignerCapsule};

/// The prefix of a household id minted here. Keyless (see the module docs):
/// nothing is registered under it and nothing signs as it.
pub const FAMILY_ID_PREFIX: &str = "family:v1:";

/// The role a family's creator holds.
pub const ROLE_FOUNDER: &str = "founder";
/// The role everyone else holds unless named otherwise.
pub const ROLE_MEMBER: &str = "member";
/// The default protocol of a new household (FSD §1 rule 4).
pub const FOUNDER_ONLY: &str = "founder_only";

const MAX_NAME_CHARS: usize = 200;
const MAX_ROLE_CHARS: usize = 64;
const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;

#[derive(Clone)]
struct FamilyState {
    engine: Arc<Engine>,
    user_seed_dir: std::path::PathBuf,
}

// ─── Refusals ───────────────────────────────────────────────────────────────
//
// Every refusal is `{error, reason_id, detail}` with a STABLE id (FSD §1 rule 6).
// An id that is emitted from more than one place goes through ONE function here,
// so it can only ever carry one English sentence (the localization guard's
// single-valued check), and no id is ever built with `format!`.

fn refuse(code: StatusCode, id: &'static str, text: &'static str) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": text, "reason_id": id, "detail": text })),
    )
        .into_response()
}

fn refuse_with(code: StatusCode, id: &'static str, text: &'static str, detail: String) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": text, "reason_id": id, "detail": detail })),
    )
        .into_response()
}

fn not_found() -> Response {
    refuse(
        StatusCode::NOT_FOUND,
        "family.not_found",
        "no family with that id is visible to you — it does not exist, or you are not one of \
         its members",
    )
}

fn not_authorized(detail: String) -> Response {
    refuse_with(
        StatusCode::FORBIDDEN,
        "family.not_authorized",
        "this family's consensus protocol is not satisfied for that change",
        detail,
    )
}

fn quorum_pending(detail: String) -> Response {
    refuse_with(
        StatusCode::CONFLICT,
        "family.quorum_pending",
        "this family's protocol needs more members' signatures before the change can be applied \
         — collect them through the change envelope, cosign and assemble routes",
        detail,
    )
}

fn bad_protocol(detail: String) -> Response {
    refuse_with(
        StatusCode::BAD_REQUEST,
        "family.bad_consensus_protocol",
        "that consensus protocol is not one a household can use: founder_only, majority, \
         unanimous or quorum:M/N with a strict majority over the whole roster",
        detail,
    )
}

fn unknown_member_key(key_id: &str) -> Response {
    refuse_with(
        StatusCode::BAD_REQUEST,
        "family.unknown_member_key",
        "that key is not a registered identity on this node, so it cannot be a family member",
        key_id.to_owned(),
    )
}

fn already_member(key_id: &str) -> Response {
    refuse_with(
        StatusCode::CONFLICT,
        "family.already_member",
        "that identity is already a member of this family",
        key_id.to_owned(),
    )
}

fn not_a_member(key_id: &str) -> Response {
    refuse_with(
        StatusCode::NOT_FOUND,
        "family.not_a_member",
        "that identity is not a current member of this family",
        key_id.to_owned(),
    )
}

fn last_founder() -> Response {
    refuse(
        StatusCode::CONFLICT,
        "family.last_founder",
        "you are the family's last founder and other members remain — make another member a \
         founder first, or dissolve the family",
    )
}

fn readd_unsupported(key_id: &str) -> Response {
    refuse_with(
        StatusCode::CONFLICT,
        "family.readd_unsupported",
        "that identity was removed from this family, and a removal cannot be undone at this \
         substrate version — found a new family to include them again",
        key_id.to_owned(),
    )
}

fn bad_role() -> Response {
    refuse(
        StatusCode::BAD_REQUEST,
        "family.bad_role",
        "a role must be a short non-empty name such as founder or member",
    )
}

fn bad_change(detail: String) -> Response {
    refuse_with(
        StatusCode::CONFLICT,
        "family.bad_change",
        "that change envelope does not describe a change to this family as it stands now — \
         build a fresh envelope",
        detail,
    )
}

fn bad_request(detail: String) -> Response {
    refuse_with(
        StatusCode::BAD_REQUEST,
        "family.bad_request",
        "the request body is not a valid family request",
        detail,
    )
}

fn store_unavailable(detail: String) -> Response {
    refuse_with(
        StatusCode::SERVICE_UNAVAILABLE,
        "family.store_unavailable",
        "the family store could not be read or written",
        detail,
    )
}

fn signer_unavailable(detail: String) -> Response {
    refuse_with(
        StatusCode::FORBIDDEN,
        "family.author_signer_unavailable",
        "your federation identity could not be opened to sign this family change",
        detail,
    )
}

fn session_required(code: StatusCode) -> Response {
    refuse(
        code,
        "family.owner_session_required",
        "families are the node owner's own surface — sign in as the owner of this claimed node",
    )
}

fn delegate_may_not_author() -> Response {
    refuse(
        StatusCode::FORBIDDEN,
        "family.delegate_may_not_author",
        "a delegated session may read families but may not change one — a roster row is signed \
         with the owner's own key, and that signature would outlive the delegation",
    )
}

// ─── The owner gate ─────────────────────────────────────────────────────────

/// Why the owner gate refused. Each surface renders these under its OWN ids, so
/// the gate decides only WHAT is true and never how a refusal is worded.
#[derive(Debug)]
pub(crate) enum GateRefusal {
    /// No bearer, or a bearer that does not resolve.
    NoSession,
    /// A live session that is not the owner's (role / permissions).
    NotOwner,
    /// A delegated session (`dgrant:`), which carries the owner's role by design.
    Delegated,
    /// This node has no owner binding: there is no human to act as.
    Unowned,
    /// The session or directory store failed.
    Store(String),
}

/// The caller, proved to be this node's owner.
pub(crate) struct OwnerCaller {
    /// The owner's federation identity key — the family member key.
    pub owner_key_id: String,
    /// This node's key (the wire identity on a split install).
    pub node_key_id: String,
    /// The bearer, re-presented to `owner_signer_capsule::acquire`.
    pub bearer: String,
}

/// **Is the caller this node's owner?** One question for every family and
/// self-device route, asked the way `drive_auth::owner` asks it (bearer →
/// not delegated → SystemAdmin+FullAccess → the WIRE node's owner binding).
///
/// `admit_delegate` is `true` for reads only: a delegation is bounded by its
/// own lifetime, so reading under it is fine; writing is not, because the row
/// would be signed with the owner's key and outlive it.
pub(crate) async fn owner_caller(
    engine: &Engine,
    headers: &HeaderMap,
    admit_delegate: bool,
) -> Result<OwnerCaller, GateRefusal> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(GateRefusal::NoSession)?;
    let caller = match resolve_bearer(engine, token).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(GateRefusal::NoSession),
        Err(e) => return Err(GateRefusal::Store(format!("{e:#}"))),
    };
    // Delegation FIRST: a `dgrant:` token carries the owner's role and
    // FullAccess, so checking the role first would pass it (same order as
    // `owner_signer_capsule::acquire`).
    if caller.actor.is_some() && !admit_delegate {
        return Err(GateRefusal::Delegated);
    }
    if caller.role != UserRole::SystemAdmin || !caller.permissions.contains(&Permission::FullAccess)
    {
        return Err(GateRefusal::NotOwner);
    }
    let node_key_id = this_node_key(engine).await.map_err(GateRefusal::Store)?;
    let owner_key_id = crate::auth::gate::require_owner_bound(engine, &node_key_id)
        .await
        .map_err(|()| GateRefusal::Unowned)?;
    Ok(OwnerCaller {
        owner_key_id,
        node_key_id,
        bearer: token.to_owned(),
    })
}

/// THIS node's key: the wire identity when boot split one off (the owner
/// binding lives there, CC 3.4.7.3), else the engine's derived id.
pub(crate) async fn this_node_key(engine: &Engine) -> Result<String, String> {
    match crate::node_key::wire_identity() {
        Some(w) => Ok(w.to_owned()),
        None => engine
            .local_derived_key_id()
            .await
            .map_err(|e| format!("derive this node's key id: {e}")),
    }
}

#[allow(clippy::result_large_err)] // the Err IS the axum Response
fn gate(r: Result<OwnerCaller, GateRefusal>) -> Result<OwnerCaller, Response> {
    r.map_err(|e| match e {
        GateRefusal::NoSession => session_required(StatusCode::UNAUTHORIZED),
        GateRefusal::NotOwner | GateRefusal::Unowned => session_required(StatusCode::FORBIDDEN),
        GateRefusal::Delegated => delegate_may_not_author(),
        GateRefusal::Store(d) => store_unavailable(d),
    })
}

async fn pen(st: &FamilyState, caller: &OwnerCaller) -> Result<OwnerSignerCapsule, Response> {
    owner_signer_capsule::acquire(
        &st.engine,
        Some(&caller.bearer),
        &caller.owner_key_id,
        st.user_seed_dir.clone(),
    )
    .await
    .map_err(|e| match e {
        owner_signer_capsule::CapsuleRefusal::Delegated => delegate_may_not_author(),
        other => signer_unavailable(other.to_string()),
    })
}

// ─── Protocols ──────────────────────────────────────────────────────────────

/// A consensus protocol this surface can GOVERN with. Anything else a family
/// may carry (a replicated row from elsewhere) is refused at the first write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    FounderOnly,
    Quorum { m: usize, n: usize },
}

fn parse_quorum(s: &str) -> Option<(usize, usize)> {
    let (m, n) = s.strip_prefix("quorum:")?.split_once('/')?;
    Some((m.parse().ok()?, n.parse().ok()?))
}

fn strict_majority(n: usize) -> usize {
    n / 2 + 1
}

fn quorum_string(m: usize, n: usize) -> String {
    format!("quorum:{m}/{n}")
}

impl Protocol {
    fn of(stored: &str) -> Option<Self> {
        if stored == FOUNDER_ONLY {
            return Some(Self::FounderOnly);
        }
        let (m, n) = parse_quorum(stored)?;
        (m >= 1 && m <= n && 2 * m > n).then_some(Self::Quorum { m, n })
    }
}

/// Normalise a DECLARED protocol for a roster of `n` into the stored form.
/// `founder_only` stays; `majority` → strict-majority `quorum:M/n`;
/// `unanimous` → `quorum:n/n`; `quorum:M/N` must already name `N == n` and be a
/// strict majority (the only shape verify's membership-change gate counts).
fn normalize_protocol(declared: Option<&str>, n: usize) -> Result<String, String> {
    let declared = declared.map(str::trim).unwrap_or(FOUNDER_ONLY);
    match declared {
        FOUNDER_ONLY => Ok(FOUNDER_ONLY.to_owned()),
        "majority" => Ok(quorum_string(strict_majority(n), n)),
        "unanimous" => Ok(quorum_string(n, n)),
        other => {
            let (m, big_n) = parse_quorum(other).ok_or_else(|| {
                format!("{other:?} is not founder_only, majority, unanimous or quorum:M/N")
            })?;
            if big_n != n {
                return Err(format!(
                    "{other:?} names N={big_n} but the roster has {n} member(s) — persist's \
                     quorum verifier requires N to equal the roster size"
                ));
            }
            if m == 0 || m > n || 2 * m <= n {
                return Err(format!(
                    "{other:?} is not a strict majority (need 2·M > N and M ≤ N)"
                ));
            }
            Ok(quorum_string(m, n))
        }
    }
}

/// Re-derive a quorum family's protocol when its roster moves from `n` to
/// `new_n`, keeping the declared RATIO (so `quorum:3/3` stays unanimous as
/// `4/4`) and never dropping below a strict majority.
fn rescale(m: usize, n: usize, new_n: usize) -> String {
    if new_n == 0 {
        return quorum_string(0, 0);
    }
    let scaled = (m * new_n).div_ceil(n.max(1));
    let m2 = scaled.max(strict_majority(new_n)).min(new_n);
    quorum_string(m2, new_n)
}

// ─── Small helpers ──────────────────────────────────────────────────────────

fn now() -> chrono::DateTime<chrono::Utc> {
    ciris_persist::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now())
}

fn role_ok(role: &str) -> bool {
    let r = role.trim();
    !r.is_empty() && r.chars().count() <= MAX_ROLE_CHARS && r == role
}

fn role_of(m: &RosterMember) -> &str {
    m.role.as_deref().unwrap_or(ROLE_MEMBER)
}

fn founders(active: &[RosterMember]) -> usize {
    active.iter().filter(|m| role_of(m) == ROLE_FOUNDER).count()
}

#[allow(clippy::result_large_err)]
fn parse<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, Response> {
    let raw: &[u8] = if body.is_empty() { b"{}" } else { body };
    serde_json::from_slice(raw).map_err(|e| bad_request(e.to_string()))
}

/// A family as this caller may see it: the record, and the FOLD.
struct Loaded {
    family: Family,
    active: Vec<RosterMember>,
}

impl Loaded {
    fn member(&self, key_id: &str) -> Option<&RosterMember> {
        self.active.iter().find(|m| m.key_id == key_id)
    }
}

/// Load a family for `caller`, or 404. A non-member and an unknown id get the
/// SAME answer (FSD §3: "cannot even find out it is there"). The accord's
/// constitutional family is not a household and is never served here.
async fn load(engine: &Engine, family_id: &str, caller: &str) -> Result<Loaded, Response> {
    if family_id == HUMANITY_ACCORD_FAMILY_KEY_ID {
        return Err(not_found());
    }
    let dir = engine.federation_directory();
    let family = match dir.lookup_family(family_id).await {
        Ok(Some(f)) => f,
        Ok(None) => return Err(not_found()),
        Err(e) => return Err(store_unavailable(format!("lookup_family: {e:#}"))),
    };
    let active = dir
        .active_members(Cohort::Family, family_id)
        .await
        .map_err(|e| store_unavailable(format!("active_members: {e:#}")))?;
    if !active.iter().any(|m| m.key_id == caller) {
        return Err(not_found());
    }
    Ok(Loaded { family, active })
}

/// The authority that signed the family's current record, from the SIGNED
/// read surface (a trusted-local row has none).
async fn authority_of(engine: &Engine, family_id: &str) -> Option<String> {
    engine
        .federation_directory()
        .list_signed_families_since(None, u32::MAX)
        .await
        .ok()?
        .into_iter()
        .find(|s| s.family.family.family_key_id == family_id)
        .map(|s| s.family.authority_key_id)
}

async fn view(engine: &Engine, loaded: &Loaded, caller: &str) -> serde_json::Value {
    let f = &loaded.family;
    let members: Vec<serde_json::Value> = loaded
        .active
        .iter()
        .map(|m| {
            serde_json::json!({
                "key_id": m.key_id,
                "role": role_of(m),
                "joined_at": m.joined_at.to_rfc3339(),
            })
        })
        .collect();
    serde_json::json!({
        "family_id": f.family_key_id,
        "name": f.family_name,
        "consensus_protocol": f.consensus_protocol,
        "founded_at": f.founded_at.to_rfc3339(),
        "members": members,
        "my_role": loaded.member(caller).map(role_of),
        // The row's envelope (FSD §1 rule 8, CSD-006): what it is about, who
        // signed it, and at which audience it travels.
        "envelope": {
            "subject": f.family_key_id,
            "attester": authority_of(engine, &f.family_key_id).await,
            "cohort_scope": ciris_persist::federation::types::cohort_scope::FAMILY,
            "dimension": "family",
            "persist_row_hash": f.persist_row_hash,
        },
    })
}

async fn sign_family(capsule: &OwnerSignerCapsule, family: Family) -> Result<SignedFamily, String> {
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&family.signing_envelope())
            .map_err(|e| format!("canonicalize the family record: {e}"))?;
    let sig = capsule.sign_hybrid(&canonical).await?;
    Ok(SignedFamily {
        family,
        authority_key_id: sig.key_id,
        scrub_signature_classical: B64.encode(&sig.classical_signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc_signature)),
    })
}

/// Write a signed removal of `removed` from `family_id`, authored by the
/// capsule's owner. This is the plane that REPLICATES a removal.
async fn write_revocation(
    engine: &Engine,
    capsule: &OwnerSignerCapsule,
    family_id: &str,
    removed: &str,
    reason: &str,
) -> Result<(), String> {
    let at = now();
    let row = FamilyMembershipRevocation {
        family_key_id: family_id.to_owned(),
        removed_identity_key_id: removed.to_owned(),
        removed_at: at,
        effective_at: at,
        reason: Some(reason.to_owned()),
        witness_set: vec![capsule.key_id().to_owned()],
        persist_row_hash: String::new(),
    };
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&row.signing_envelope())
            .map_err(|e| format!("canonicalize the removal: {e}"))?;
    let sig = capsule.sign_hybrid(&canonical).await?;
    engine
        .federation_directory()
        .put_family_membership_revocation(SignedFamilyMembershipRevocation {
            family_membership_revocation: row,
            authority_key_id: sig.key_id,
            scrub_signature_classical: B64.encode(&sig.classical_signature),
            scrub_signature_pqc: Some(B64.encode(&sig.pqc_signature)),
        })
        .await
        .map_err(|e| format!("put_family_membership_revocation({removed}): {e:#}"))
}

/// Re-wrap the family's existing at-rest DEKs to a newcomer
/// (`at_rest_cascade::rekey_family_member_add`). The add has already
/// committed, so a failure here is REPORTED, not raised: the member is in, and
/// what they cannot yet read is named.
async fn rewrap(engine: &Engine, family_id: &str, key_id: &str) -> serde_json::Value {
    match engine.rekey_family_member_add(family_id, key_id).await {
        Ok(r) => serde_json::json!({
            "blobs_scanned": r.blobs_scanned,
            "granted": r.granted.iter().map(|(k, n)| serde_json::json!({"occurrence_key_id": k, "grants": n})).collect::<Vec<_>>(),
            "excluded": r.excluded,
        }),
        Err(e) => {
            tracing::warn!(
                family = %family_id, member = %key_id, error = %e,
                "family: the new member is in, but the DEK re-wrap failed — they cannot read \
                 content written before they joined until it is re-run"
            );
            serde_json::json!({ "error": e.to_string() })
        }
    }
}

fn kick(reason: &'static str) {
    let _ = crate::compose::kick_replication(reason);
}

// ─── POST /v1/families ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateRequest {
    name: String,
    #[serde(default)]
    consensus_protocol: Option<String>,
    /// Further founding members (identity keys). The caller is always the
    /// founder and need not be listed. Needed for a quorum family: verify
    /// counts `quorum:M/N` over a roster of exactly N.
    #[serde(default)]
    members: Vec<String>,
}

async fn create_family(State(st): State<FamilyState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let req: CreateRequest = match parse(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return refuse(
            StatusCode::BAD_REQUEST,
            "family.name_empty",
            "a family needs a name of at most 200 characters",
        );
    }
    let dir = st.engine.federation_directory();
    let mut others: Vec<String> = Vec::new();
    for k in &req.members {
        if k == &caller.owner_key_id || others.contains(k) {
            return already_member(k);
        }
        match dir.lookup_public_key(k).await {
            Ok(Some(_)) => others.push(k.clone()),
            Ok(None) => return unknown_member_key(k),
            Err(e) => return store_unavailable(format!("lookup_public_key: {e:#}")),
        }
    }
    let protocol = match normalize_protocol(req.consensus_protocol.as_deref(), 1 + others.len()) {
        Ok(p) => p,
        Err(d) => return bad_protocol(d),
    };
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let at = now();
    let mut members = vec![FamilyMember {
        key_id: caller.owner_key_id.clone(),
        joined_at: at,
        role: Some(ROLE_FOUNDER.to_owned()),
    }];
    members.extend(others.iter().map(|k| FamilyMember {
        key_id: k.clone(),
        joined_at: at,
        role: Some(ROLE_MEMBER.to_owned()),
    }));
    let family_id = format!("{FAMILY_ID_PREFIX}{}", uuid::Uuid::new_v4().simple());
    let family = Family {
        family_key_id: family_id.clone(),
        family_name: name.to_owned(),
        members,
        founded_at: at,
        consensus_protocol: protocol,
        consensus_protocol_entrenched: false,
        persist_row_hash: String::new(),
    };
    let signed = match sign_family(&capsule, family).await {
        Ok(s) => s,
        Err(e) => return signer_unavailable(e),
    };
    if let Err(e) = dir.put_family(signed).await {
        return store_unavailable(format!("put_family: {e:#}"));
    }
    tracing::info!(family = %family_id, founder = %caller.owner_key_id, "family: created");
    kick("family:create");
    match load(&st.engine, &family_id, &caller.owner_key_id).await {
        Ok(l) => (
            StatusCode::CREATED,
            Json(view(&st.engine, &l, &caller.owner_key_id).await),
        )
            .into_response(),
        Err(r) => r,
    }
}

// ─── GET /v1/families ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    after: Option<String>,
}

async fn list_families(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, true).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // The FOLD: families where the caller is an ACTIVE member.
    let mut fams = match st
        .engine
        .federation_directory()
        .list_families_for_member_active(&caller.owner_key_id)
        .await
    {
        Ok(f) => f,
        Err(e) => return store_unavailable(format!("list_families_for_member_active: {e:#}")),
    };
    fams.retain(|f| f.family_key_id != HUMANITY_ACCORD_FAMILY_KEY_ID);
    fams.sort_by(|a, b| a.family_key_id.cmp(&b.family_key_id));
    if let Some(after) = &q.after {
        fams.retain(|f| &f.family_key_id > after);
    }
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let more = fams.len() > limit;
    fams.truncate(limit);
    let mut out = Vec::with_capacity(fams.len());
    for f in &fams {
        match load(&st.engine, &f.family_key_id, &caller.owner_key_id).await {
            Ok(l) => out.push(view(&st.engine, &l, &caller.owner_key_id).await),
            // Raced with a removal: the caller is no longer in it.
            Err(_) => continue,
        }
    }
    let resume = if more {
        fams.last().map(|f| f.family_key_id.clone())
    } else {
        None
    };
    Json(serde_json::json!({ "families": out, "resume": resume })).into_response()
}

// ─── GET /v1/families/{id} ──────────────────────────────────────────────────

async fn read_family(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, true).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    match load(&st.engine, &id, &caller.owner_key_id).await {
        Ok(l) => Json(view(&st.engine, &l, &caller.owner_key_id).await).into_response(),
        Err(r) => r,
    }
}

// ─── The shared write preamble ──────────────────────────────────────────────

/// Gate + load + parse the protocol. Every write starts here, in this order:
/// session (401/403) → membership (404, hidden) → protocol.
async fn write_preamble(
    st: &FamilyState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(OwnerCaller, Loaded, Protocol), Response> {
    let caller = gate(owner_caller(&st.engine, headers, false).await)?;
    let loaded = load(&st.engine, id, &caller.owner_key_id).await?;
    let protocol = Protocol::of(&loaded.family.consensus_protocol).ok_or_else(|| {
        bad_protocol(format!(
            "this family carries {:?}, which this node cannot govern",
            loaded.family.consensus_protocol
        ))
    })?;
    Ok((caller, loaded, protocol))
}

/// `founder_only`: the caller must be an active FOUNDER.
#[allow(clippy::result_large_err)]
fn require_founder(loaded: &Loaded, caller: &str) -> Result<(), Response> {
    match loaded.member(caller).map(role_of) {
        Some(ROLE_FOUNDER) => Ok(()),
        _ => Err(not_authorized(
            "founder_only: only a founder of this family may change its roster".to_owned(),
        )),
    }
}

fn needs_quorum(m: usize, n: usize) -> Response {
    quorum_pending(format!(
        "this family is quorum:{m}/{n} — POST /v1/families/{{id}}/changes/envelope, have {m} \
         member(s) cosign, then assemble"
    ))
}

// ─── POST /v1/families/{id}/members ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddRequest {
    key_id: String,
    #[serde(default)]
    role: Option<String>,
}

async fn add_member(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let req: AddRequest = match parse(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let role = req.role.clone().unwrap_or_else(|| ROLE_MEMBER.to_owned());
    if !role_ok(&role) {
        return bad_role();
    }
    if let Protocol::Quorum { m, n } = protocol {
        return needs_quorum(m, n);
    }
    if let Err(r) = require_founder(&loaded, &caller.owner_key_id) {
        return r;
    }
    if let Err(r) = check_addable(&st.engine, &loaded, &req.key_id).await {
        return r;
    }
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let member = FamilyMember {
        key_id: req.key_id.clone(),
        joined_at: now(),
        role: Some(role.clone()),
    };
    // The authority signs the GROWN record (persist v31 #654): the roster as it
    // will be after the addition, so a signature over one roster cannot be
    // lifted onto another.
    let mut grown = loaded.family.clone();
    grown.members.push(member.clone());
    let spec = match sign_family(&capsule, grown).await {
        Ok(s) => AdmitSpec {
            authority_key_id: s.authority_key_id,
            scrub_signature_classical: s.scrub_signature_classical,
            scrub_signature_pqc: s.scrub_signature_pqc,
        },
        Err(e) => return signer_unavailable(e),
    };
    match st
        .engine
        .federation_directory()
        .add_member(Cohort::Family, &id, RosterMember::from(member), &spec)
        .await
    {
        Ok(true) => {}
        Ok(false) => return already_member(&req.key_id),
        Err(e) => return store_unavailable(format!("add_member: {e:#}")),
    }
    let dek = rewrap(&st.engine, &id, &req.key_id).await;
    tracing::info!(family = %id, member = %req.key_id, %role, "family: member added");
    kick("family:add_member");
    respond_with_family(&st, &id, &caller, serde_json::json!({ "dek_rewrap": dek })).await
}

/// A target may join iff it is a registered identity, not already an ACTIVE
/// member, and was never removed (a removal is permanent at this pin).
async fn check_addable(engine: &Engine, loaded: &Loaded, key_id: &str) -> Result<(), Response> {
    if loaded.member(key_id).is_some() {
        return Err(already_member(key_id));
    }
    // On the RECORD but not in the FOLD ⇒ removed by a revocation. This is the
    // one read of the record's roster, and it is to refuse, never to admit.
    if loaded.family.members.iter().any(|m| m.key_id == key_id) {
        return Err(readd_unsupported(key_id));
    }
    match engine
        .federation_directory()
        .lookup_public_key(key_id)
        .await
    {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(unknown_member_key(key_id)),
        Err(e) => Err(store_unavailable(format!("lookup_public_key: {e:#}"))),
    }
}

async fn respond_with_family(
    st: &FamilyState,
    id: &str,
    caller: &OwnerCaller,
    extra: serde_json::Value,
) -> Response {
    match load(&st.engine, id, &caller.owner_key_id).await {
        Ok(l) => {
            let mut v = view(&st.engine, &l, &caller.owner_key_id).await;
            if let (Some(obj), Some(ex)) = (v.as_object_mut(), extra.as_object()) {
                for (k, val) in ex {
                    obj.insert(k.clone(), val.clone());
                }
            }
            Json(v).into_response()
        }
        // The caller is no longer a member (left / dissolved): the change is
        // done, and there is nothing of the family left for them to see.
        Err(_) => Json(extra).into_response(),
    }
}

// ─── DELETE /v1/families/{id}/members/{key_id} ──────────────────────────────

async fn remove_member(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path((id, key_id)): Path<(String, String)>,
) -> Response {
    let (caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    // Removing yourself is LEAVING (FSD §1 rule 5) — never subject to quorum.
    if key_id == caller.owner_key_id {
        return leave_inner(&st, caller, loaded, protocol).await;
    }
    let Some(target) = loaded.member(&key_id) else {
        return not_a_member(&key_id);
    };
    if let Protocol::Quorum { m, n } = protocol {
        return needs_quorum(m, n);
    }
    if let Err(r) = require_founder(&loaded, &caller.owner_key_id) {
        return r;
    }
    if role_of(target) == ROLE_FOUNDER && founders(&loaded.active) <= 1 {
        return last_founder();
    }
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = write_revocation(&st.engine, &capsule, &id, &key_id, "removed").await {
        return store_unavailable(e);
    }
    tracing::info!(family = %id, member = %key_id, "family: member removed");
    kick("family:remove_member");
    respond_with_family(&st, &id, &caller, serde_json::json!({ "removed": key_id })).await
}

// ─── POST /v1/families/{id}/leave ───────────────────────────────────────────

async fn leave(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let caller = match gate(owner_caller(&st.engine, &headers, false).await) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let loaded = match load(&st.engine, &id, &caller.owner_key_id).await {
        Ok(l) => l,
        Err(r) => return r,
    };
    // Leaving does not need a protocol this node can govern — it is the
    // caller's own act whatever the family declares. Only a quorum family's
    // record is rewritten (so its N keeps matching the roster).
    let protocol = Protocol::of(&loaded.family.consensus_protocol).unwrap_or(Protocol::FounderOnly);
    leave_inner(&st, caller, loaded, protocol).await
}

async fn leave_inner(
    st: &FamilyState,
    caller: OwnerCaller,
    loaded: Loaded,
    protocol: Protocol,
) -> Response {
    let me = caller.owner_key_id.clone();
    let id = loaded.family.family_key_id.clone();
    let i_am_founder = loaded.member(&me).map(role_of) == Some(ROLE_FOUNDER);
    if i_am_founder && founders(&loaded.active) <= 1 && loaded.active.len() > 1 {
        return last_founder();
    }
    let capsule = match pen(st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // A quorum family's record must keep N == roster, or every later quorum
    // check reads a seat that has left. Rewritten FIRST (by the leaver, whose
    // own act this is); the revocation below is what replicates the departure.
    if let Protocol::Quorum { m, n } = protocol {
        let remaining: Vec<FamilyMember> = loaded
            .family
            .members
            .iter()
            .filter(|fm| fm.key_id != me)
            .cloned()
            .collect();
        if !remaining.is_empty() {
            let mut next = loaded.family.clone();
            next.consensus_protocol = rescale(m, n, remaining.len());
            next.members = remaining;
            let signed = match sign_family(&capsule, next).await {
                Ok(s) => s,
                Err(e) => return signer_unavailable(e),
            };
            if let Err(e) = st
                .engine
                .federation_directory()
                .supersede_family(
                    signed,
                    Some(serde_json::json!({ "action": "leave", "member": me })),
                )
                .await
            {
                return store_unavailable(format!("supersede_family(leave): {e:#}"));
            }
        }
    }
    if let Err(e) = write_revocation(&st.engine, &capsule, &id, &me, "left").await {
        return store_unavailable(e);
    }
    tracing::info!(family = %id, member = %me, "family: member left");
    kick("family:leave");
    Json(serde_json::json!({ "family_id": id, "left": true })).into_response()
}

// ─── POST /v1/families/{id}/members/{key_id}/role ───────────────────────────

#[derive(Debug, Deserialize)]
struct RoleRequest {
    role: String,
}

async fn change_role(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path((id, key_id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let (caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let req: RoleRequest = match parse(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !role_ok(&req.role) {
        return bad_role();
    }
    let Some(target) = loaded.member(&key_id) else {
        return not_a_member(&key_id);
    };
    if let Protocol::Quorum { m, n } = protocol {
        return needs_quorum(m, n);
    }
    if let Err(r) = require_founder(&loaded, &caller.owner_key_id) {
        return r;
    }
    if role_of(target) == ROLE_FOUNDER && req.role != ROLE_FOUNDER && founders(&loaded.active) <= 1
    {
        return last_founder();
    }
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let mut next = loaded.family.clone();
    for fm in &mut next.members {
        if fm.key_id == key_id {
            fm.role = Some(req.role.clone());
        }
    }
    let signed = match sign_family(&capsule, next).await {
        Ok(s) => s,
        Err(e) => return signer_unavailable(e),
    };
    if let Err(e) = st
        .engine
        .federation_directory()
        .supersede_family(
            signed,
            Some(serde_json::json!({ "action": "role", "member": key_id, "role": req.role })),
        )
        .await
    {
        return store_unavailable(format!("supersede_family(role): {e:#}"));
    }
    tracing::info!(family = %id, member = %key_id, role = %req.role, "family: role changed");
    kick("family:role");
    respond_with_family(&st, &id, &caller, serde_json::json!({})).await
}

// ─── DELETE /v1/families/{id} ───────────────────────────────────────────────

async fn dissolve(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let (caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if let Protocol::Quorum { m, n } = protocol {
        return needs_quorum(m, n);
    }
    if let Err(r) = require_founder(&loaded, &caller.owner_key_id) {
        return r;
    }
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    terminal_dissolve(
        &st,
        &caller,
        &capsule,
        &loaded,
        serde_json::json!({ "action": "dissolve", "protocol": FOUNDER_ONLY }),
    )
    .await
}

/// The terminal write of a dissolve, however it was authorized: one signed
/// removal per active member (the plane that REPLICATES — a peer holding the
/// family learns it is empty), then the authority-signed supersede to an empty
/// roster (the version history records who dissolved it and on what authority).
async fn terminal_dissolve(
    st: &FamilyState,
    caller: &OwnerCaller,
    capsule: &OwnerSignerCapsule,
    loaded: &Loaded,
    authorization: serde_json::Value,
) -> Response {
    let id = loaded.family.family_key_id.clone();
    for m in &loaded.active {
        if let Err(e) = write_revocation(&st.engine, capsule, &id, &m.key_id, "dissolved").await {
            return store_unavailable(e);
        }
    }
    let mut next = loaded.family.clone();
    next.members = Vec::new();
    let signed = match sign_family(capsule, next).await {
        Ok(s) => s,
        Err(e) => return signer_unavailable(e),
    };
    if let Err(e) = st
        .engine
        .federation_directory()
        .supersede_family(signed, Some(authorization))
        .await
    {
        return store_unavailable(format!("supersede_family(dissolve): {e:#}"));
    }
    tracing::info!(family = %id, by = %caller.owner_key_id, "family: dissolved");
    kick("family:dissolve");
    Json(serde_json::json!({ "family_id": id, "dissolved": true })).into_response()
}

// ─── The quorum flow: envelope → cosign → assemble ──────────────────────────
//
// The accord's three steps (`/v1/accord/family/change/envelope` + supersede),
// generalised to any `quorum:M/N` household. Stateless: the envelope travels
// with the caller, each member cosigns on THEIR OWN node with THEIR OWN pen,
// and any member assembles. The envelope carries, beside verify's canonical
// membership-change fields, the action, the roles, and the persist row hash of
// the record it changes — so a signature cannot be replayed against a later
// state of the family (verify's `supersedes.prior_member_key_ids` binds the
// roster, not the roles).

const ACTIONS: &[&str] = &["add", "remove", "role", "dissolve"];

#[derive(Debug, Deserialize)]
struct EnvelopeRequest {
    action: String,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    role: Option<String>,
    /// Override the re-derived protocol for the NEW roster (must be a strict
    /// majority `quorum:M/N` with N the new roster size).
    #[serde(default)]
    consensus_protocol: Option<String>,
}

async fn change_envelope(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (_caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let Protocol::Quorum { m, n } = protocol else {
        return bad_protocol(
            "this family is founder_only — a founder makes each change in one call; the \
             envelope flow is for quorum families"
                .to_owned(),
        );
    };
    let req: EnvelopeRequest = match parse(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if !ACTIONS.contains(&req.action.as_str()) {
        return bad_request(format!(
            "action {:?} is not one of add, remove, role, dissolve",
            req.action
        ));
    }
    // The record's roster, in order: verify binds `supersedes.prior_member_key_ids`
    // to it, and a quorum family's record IS its fold (every removal rewrites it).
    let mut keys: Vec<String> = loaded
        .family
        .members
        .iter()
        .map(|fm| fm.key_id.clone())
        .collect();
    let mut roles: serde_json::Map<String, serde_json::Value> = loaded
        .family
        .members
        .iter()
        .map(|fm| {
            (
                fm.key_id.clone(),
                serde_json::json!(fm.role.clone().unwrap_or_else(|| ROLE_MEMBER.to_owned())),
            )
        })
        .collect();
    let target = req.key_id.clone();
    match req.action.as_str() {
        "add" => {
            let Some(k) = target.as_deref() else {
                return bad_request("action add needs key_id".to_owned());
            };
            if let Err(r) = check_addable(&st.engine, &loaded, k).await {
                return r;
            }
            let role = req.role.clone().unwrap_or_else(|| ROLE_MEMBER.to_owned());
            if !role_ok(&role) {
                return bad_role();
            }
            keys.push(k.to_owned());
            roles.insert(k.to_owned(), serde_json::json!(role));
        }
        "remove" => {
            let Some(k) = target.as_deref() else {
                return bad_request("action remove needs key_id".to_owned());
            };
            let Some(t) = loaded.member(k) else {
                return not_a_member(k);
            };
            if role_of(t) == ROLE_FOUNDER && founders(&loaded.active) <= 1 {
                return last_founder();
            }
            keys.retain(|x| x != k);
            roles.remove(k);
            if keys.is_empty() {
                return bad_request(
                    "removing the last member is dissolving — use action dissolve".to_owned(),
                );
            }
        }
        "role" => {
            let Some(k) = target.as_deref() else {
                return bad_request("action role needs key_id".to_owned());
            };
            let Some(role) = req.role.clone() else {
                return bad_role();
            };
            if !role_ok(&role) {
                return bad_role();
            }
            let Some(t) = loaded.member(k) else {
                return not_a_member(k);
            };
            if role_of(t) == ROLE_FOUNDER && role != ROLE_FOUNDER && founders(&loaded.active) <= 1 {
                return last_founder();
            }
            roles.insert(k.to_owned(), serde_json::json!(role));
        }
        _ => {} // dissolve: the roster is unchanged; the action says what is authorized.
    }
    let new_protocol = match req.consensus_protocol.as_deref() {
        Some(p) => match normalize_protocol(Some(p), keys.len()) {
            Ok(p) if p.starts_with("quorum:") => p,
            Ok(p) => {
                return bad_protocol(format!(
                    "{p:?} cannot be adopted through a quorum change — verify's membership-change \
                     gate counts only quorum:M/N"
                ))
            }
            Err(d) => return bad_protocol(d),
        },
        None if keys.len() == n => loaded.family.consensus_protocol.clone(),
        None => rescale(m, n, keys.len()),
    };
    let dir = st.engine.federation_directory();
    let mut env = match dir
        .build_membership_change_envelope(Cohort::Family, &id, &keys, false, Some(&new_protocol))
        .await
    {
        Ok(v) => v,
        Err(e) => return store_unavailable(format!("build_membership_change_envelope: {e:#}")),
    };
    if let Some(obj) = env.as_object_mut() {
        obj.insert("action".into(), serde_json::json!(req.action));
        obj.insert("target_key_id".into(), serde_json::json!(target));
        obj.insert("roles".into(), serde_json::Value::Object(roles));
        obj.insert(
            "prior_persist_row_hash".into(),
            serde_json::json!(loaded.family.persist_row_hash),
        );
    }
    let bytes = match ciris_verify_core::jcs::canonicalize(&env) {
        Ok(b) => b,
        Err(e) => return store_unavailable(format!("canonicalize the change: {e}")),
    };
    Json(serde_json::json!({
        "change_envelope": env,
        "signing_bytes_base64": B64.encode(&bytes),
        "required_signatures": m,
        "signers": loaded.active.iter().map(|x| x.key_id.clone()).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct CosignRequest {
    change_envelope: serde_json::Value,
    #[serde(default)]
    signatures: Vec<ThresholdSignature>,
}

/// The envelope must describe THIS family AS IT STANDS: same id, same record
/// hash, a known action. Anything else is a stale or foreign envelope.
#[allow(clippy::result_large_err)]
fn check_envelope(loaded: &Loaded, env: &serde_json::Value) -> Result<String, Response> {
    let id = env.get("family_key_id").and_then(|v| v.as_str());
    if id != Some(loaded.family.family_key_id.as_str()) {
        return Err(bad_change(
            "the envelope names a different family".to_owned(),
        ));
    }
    let prior = env.get("prior_persist_row_hash").and_then(|v| v.as_str());
    if prior != Some(loaded.family.persist_row_hash.as_str()) {
        return Err(bad_change(
            "the family has changed since this envelope was built (its record hash moved)"
                .to_owned(),
        ));
    }
    let action = env
        .get("action")
        .and_then(|v| v.as_str())
        .filter(|a| ACTIONS.contains(a))
        .ok_or_else(|| bad_change("the envelope carries no known action".to_owned()))?;
    Ok(action.to_owned())
}

async fn cosign(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let Protocol::Quorum { m, .. } = protocol else {
        return bad_protocol("this family is founder_only — nothing to cosign".to_owned());
    };
    let req: CosignRequest = match parse(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    if let Err(r) = check_envelope(&loaded, &req.change_envelope) {
        return r;
    }
    let bytes = match ciris_verify_core::jcs::canonicalize(&req.change_envelope) {
        Ok(b) => b,
        Err(e) => return bad_change(format!("canonicalize: {e}")),
    };
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let sig = match capsule.sign_hybrid(&bytes).await {
        Ok(s) => s,
        Err(e) => return signer_unavailable(e),
    };
    let mine = ThresholdSignature {
        member_id: sig.key_id.clone(),
        ed25519_signature_base64: B64.encode(&sig.classical_signature),
        mldsa65_signature_base64: Some(B64.encode(&sig.pqc_signature)),
    };
    let mut signatures = req.signatures;
    signatures.retain(|s| s.member_id != mine.member_id);
    signatures.push(mine.clone());
    let quorum_met = st
        .engine
        .federation_directory()
        .verify_membership_quorum(Cohort::Family, &id, &req.change_envelope, &signatures)
        .await
        .is_ok();
    Json(serde_json::json!({
        "signature": mine,
        "signatures": signatures,
        "required_signatures": m,
        "quorum_met": quorum_met,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct AssembleRequest {
    change_envelope: serde_json::Value,
    signatures: Vec<ThresholdSignature>,
}

/// Map persist's quorum refusal onto the two ids: too few signatures is
/// PENDING (collect more), anything else is NOT AUTHORIZED.
fn quorum_refusal(e: &ciris_persist::federation::Error, protocol: &str) -> Response {
    let text = format!("{e:#}");
    if text.contains("quorum not met") || text.contains("QuorumNotMet") {
        quorum_pending(text)
    } else {
        not_authorized(format!("{protocol}: {text}"))
    }
}

async fn assemble(
    State(st): State<FamilyState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let (caller, loaded, protocol) = match write_preamble(&st, &headers, &id).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    if !matches!(protocol, Protocol::Quorum { .. }) {
        return bad_protocol("this family is founder_only — nothing to assemble".to_owned());
    }
    let req: AssembleRequest = match parse(&body) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let action = match check_envelope(&loaded, &req.change_envelope) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let capsule = match pen(&st, &caller).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let dir = st.engine.federation_directory();
    let env = &req.change_envelope;
    let proto_now = loaded.family.consensus_protocol.clone();

    if action == "dissolve" {
        // An empty roster is not a verifiable membership change (verify's
        // WeakQuorum at m = 0), so the quorum authorizes the dissolve-marked
        // envelope over the CURRENT roster, and that proof rides the terminal
        // supersede as its authorization.
        if let Err(e) = dir
            .verify_membership_quorum(Cohort::Family, &id, env, &req.signatures)
            .await
        {
            return quorum_refusal(&e, &proto_now);
        }
        return terminal_dissolve(
            &st,
            &caller,
            &capsule,
            &loaded,
            serde_json::json!({
                "action": "dissolve",
                "change_envelope": env,
                "quorum_signatures": req.signatures,
            }),
        )
        .await;
    }

    // add / remove / role: the new record IS the envelope — its roster, its
    // protocol, its roles — with each continuing member's join time kept.
    let Some(members_env) = env.get("members").and_then(|v| v.as_array()) else {
        return bad_change("the envelope has no members".to_owned());
    };
    let roles = env.get("roles").and_then(|v| v.as_object());
    let at = now();
    let mut members = Vec::with_capacity(members_env.len());
    for m in members_env {
        let Some(k) = m.get("key_id").and_then(|v| v.as_str()) else {
            return bad_change("an envelope member has no key_id".to_owned());
        };
        let joined_at = loaded
            .family
            .members
            .iter()
            .find(|fm| fm.key_id == k)
            .map_or(at, |fm| fm.joined_at);
        let role = roles
            .and_then(|r| r.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or(ROLE_MEMBER)
            .to_owned();
        members.push(FamilyMember {
            key_id: k.to_owned(),
            joined_at,
            role: Some(role),
        });
    }
    let Some(new_protocol) = env.get("consensus_protocol").and_then(|v| v.as_str()) else {
        return bad_change("the envelope has no consensus_protocol".to_owned());
    };
    let mut next = loaded.family.clone();
    next.members = members;
    next.consensus_protocol = new_protocol.to_owned();
    let signed = match sign_family(&capsule, next).await {
        Ok(s) => s,
        Err(e) => return signer_unavailable(e),
    };
    let version = match dir
        .supersede_family_with_quorum(signed, env.clone(), req.signatures.clone())
        .await
    {
        Ok(v) => v,
        Err(e) => return quorum_refusal(&e, &proto_now),
    };
    let target = env
        .get("target_key_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let mut extra = serde_json::json!({ "action": action, "version": version });
    match (action.as_str(), target.as_deref()) {
        ("add", Some(k)) => {
            extra["dek_rewrap"] = rewrap(&st.engine, &id, k).await;
        }
        ("remove", Some(k)) => {
            // The supersede shrank the record; the revocation is what
            // REPLICATES the removal (a peer never applies a supersede).
            if let Err(e) = write_revocation(&st.engine, &capsule, &id, k, "removed").await {
                return store_unavailable(e);
            }
            extra["removed"] = serde_json::json!(k);
        }
        _ => {}
    }
    tracing::info!(family = %id, %action, version, "family: quorum change applied");
    kick("family:quorum_change");
    respond_with_family(&st, &id, &caller, extra).await
}

// ─── Router ─────────────────────────────────────────────────────────────────

/// The household routes (FSD §3). `user_seed_dir` is where the owner's fed-ID
/// is re-opened for signing — the same directory the drive and chat routers
/// take.
pub fn router(engine: Arc<Engine>, user_seed_dir: std::path::PathBuf) -> Router {
    use axum::routing::{delete, get, post};
    Router::new()
        .route("/v1/families", get(list_families).post(create_family))
        .route("/v1/families/{id}", get(read_family).delete(dissolve))
        .route("/v1/families/{id}/members", post(add_member))
        .route("/v1/families/{id}/members/{key_id}", delete(remove_member))
        .route("/v1/families/{id}/members/{key_id}/role", post(change_role))
        .route("/v1/families/{id}/leave", post(leave))
        .route("/v1/families/{id}/changes/envelope", post(change_envelope))
        .route("/v1/families/{id}/changes/cosign", post(cosign))
        .route("/v1/families/{id}/changes/assemble", post(assemble))
        .with_state(FamilyState {
            engine,
            user_seed_dir,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_protocols_normalize_to_what_verify_counts() {
        assert_eq!(normalize_protocol(None, 1).unwrap(), "founder_only");
        assert_eq!(
            normalize_protocol(Some("majority"), 3).unwrap(),
            "quorum:2/3"
        );
        assert_eq!(
            normalize_protocol(Some("unanimous"), 3).unwrap(),
            "quorum:3/3"
        );
        assert_eq!(
            normalize_protocol(Some("quorum:2/3"), 3).unwrap(),
            "quorum:2/3"
        );
        assert!(
            normalize_protocol(Some("quorum:2/3"), 1).is_err(),
            "N ≠ roster"
        );
        assert!(
            normalize_protocol(Some("quorum:1/2"), 2).is_err(),
            "split brain"
        );
        assert!(normalize_protocol(Some("weighted:rubric"), 2).is_err());
    }

    #[test]
    fn rescale_keeps_the_ratio_and_a_strict_majority() {
        assert_eq!(rescale(2, 3, 4), "quorum:3/4");
        assert_eq!(rescale(3, 3, 4), "quorum:4/4");
        assert_eq!(rescale(2, 3, 2), "quorum:2/2");
        assert_eq!(rescale(3, 5, 3), "quorum:2/3");
        assert_eq!(rescale(1, 1, 2), "quorum:2/2");
    }
}
