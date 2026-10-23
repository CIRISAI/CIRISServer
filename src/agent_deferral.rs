//! **An agent's deferral and the identity amendment it authorises, as signed
//! rows** (CIRISAgent#1316; CC rc10 3.1.9.4 and 3.1.5, catalogue v5 T7).
//!
//! - `deferral:request:v1`: the agent defers one question to a Wise Authority.
//!   Signed by the agent's OCCURRENCE key (this engine's key), about the agent's
//!   IDENTITY key, addressed to the cell (`self`), never a federation broadcast.
//! - `deferral:response:{approved|rejected}:v1`: the WA's answer, signed by the
//!   WA's OWN key through the resolver's session (`owner_signer_capsule`).
//!
//! All three live in the ROOM of the agent's conversation with the person (Eric,
//! 2026-10-22: deferrals are not chat messages, but they use the same room): the
//! request names it, the response and the amendment inherit it.
//! - `identity_amendment:v1`: the agent applied the change an approved response
//!   authorised. Occurrence key, about the identity key, carrying
//!   `amendment_digest` and `authorized_by`, `evidence_refs` → the response.
//!
//! # The admission rule, enforced at THIS door
//!
//! CC 3.1.5: an amendment is admitted only when the cited response is admitted,
//! approved, about this agent, and signed by a key that held a WA seat at its
//! `asserted_at`; otherwise `identity_amendment_unauthorized`. The general
//! admission gate (one that also refuses a REPLICATED amendment from another
//! producer) belongs in persist (CIRISPersist#1120); when it lands this copy goes. Until it lands this door
//! refuses to author an unauthorised one, which is the only way this node makes
//! one.
//!
//! **Who is a seated WA** (Eric, 2026-10-22): the node's OWNER is the seated WA
//! for their own agent; that is the only pen a node can reach. A non-owner WA
//! signing with their own key is CIRISServer#814.

use ciris_persist::federation::admission::owner_of;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::prelude::Engine;

use crate::attest::{self, KeySigner, Spec};

/// `deferral:request:v1`.
pub const DEFERRAL_REQUEST: &str = "deferral:request:v1";
/// `deferral:response:approved:v1`.
pub const DEFERRAL_APPROVED: &str = "deferral:response:approved:v1";
/// `deferral:response:rejected:v1`.
pub const DEFERRAL_REJECTED: &str = "deferral:response:rejected:v1";
/// `identity_amendment:v1`.
pub const IDENTITY_AMENDMENT: &str = "identity_amendment:v1";

/// What the agent supplies when it defers.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DeferralRequest {
    /// The agent's own deferral id.
    pub deferral_id: String,
    /// The task the deferral belongs to.
    pub task_id: String,
    /// The thought that deferred.
    pub thought_id: String,
    /// Lowercase hex SHA-256 of the deferral reason (the text stays local).
    pub reason_digest: String,
    /// Which WA domain the question is for, when the agent knows.
    #[serde(default)]
    pub domain_hint: Option<String>,
    /// The room this deferral belongs to: the agent's conversation with the
    /// person (Eric, 2026-10-22: deferrals are not chat messages, but they live
    /// in the same room). A `chat:pair:v1:` or `chat:room:v1:` id, carried as the
    /// envelope's `community_key_id` (the member persist reads as the row's
    /// cohort target, as chat rows carry it). The response and the amendment
    /// inherit it from the row they cite.
    #[serde(default)]
    pub room_id: Option<String>,
}

/// The envelope member that names a row's room — edge's
/// `chat::FIELD_COMMUNITY_ID`, one of persist's `COHORT_TARGET_ENVELOPE_FIELDS`.
pub const ROOM_FIELD: &str = ciris_edge::chat::FIELD_COMMUNITY_ID;

fn room_ok(room: &str) -> Result<(), AgentRowError> {
    if room.starts_with(ciris_edge::chat::PAIR_COMMUNITY_PREFIX)
        || room.starts_with(ciris_edge::chat::ROOM_COMMUNITY_PREFIX)
    {
        Ok(())
    } else {
        Err(AgentRowError::BadInput(format!(
            "room_id {room:?} is not a chat room id ({}… or {}…)",
            ciris_edge::chat::PAIR_COMMUNITY_PREFIX,
            ciris_edge::chat::ROOM_COMMUNITY_PREFIX
        )))
    }
}

/// Carry the cited row's room onto a new body.
fn inherit_room(body: &mut serde_json::Value, cited: &serde_json::Value) {
    if let Some(room) = cited.get(ROOM_FIELD) {
        body[ROOM_FIELD] = room.clone();
    }
}

/// Why a row was not authored. [`Self::reason_id`] is the stable code the agent
/// branches on.
#[derive(Debug)]
pub enum AgentRowError {
    /// An input is malformed (a digest that is not lowercase hex64, an empty id).
    BadInput(String),
    /// The deferral the response names is not an admitted `deferral:request:v1`.
    UnknownDeferral(String),
    /// No session presented for the response.
    NotSignedIn,
    /// A delegated session: answering a deferral is the WA's own act.
    Delegated,
    /// The resolver is signed in but holds no key this node can sign with: only
    /// the node's owner is a seated WA here (a non-owner WA is CIRISServer#814).
    ResolverHasNoKey,
    /// The owner exists but has not minted a federation ID yet.
    NoIdentity,
    /// CC 3.1.5's admission rule: the cited response does not authorise this
    /// amendment. The text says which condition failed.
    Unauthorized(String),
    /// The directory read or the write failed.
    Store(String),
}

impl AgentRowError {
    /// The stable code (the agent branches on it; it leads every message).
    #[must_use]
    pub fn reason_id(&self) -> &'static str {
        match self {
            Self::BadInput(_) => "deferral.bad_input",
            Self::UnknownDeferral(_) => "deferral.unknown_request",
            Self::NotSignedIn => "deferral.not_signed_in",
            Self::Delegated => "deferral.delegated",
            Self::ResolverHasNoKey => "deferral.resolver_has_no_key",
            Self::NoIdentity => "deferral.no_identity",
            Self::Unauthorized(_) => "identity_amendment_unauthorized",
            Self::Store(_) => "deferral.store",
        }
    }
}

impl std::fmt::Display for AgentRowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: ", self.reason_id())?;
        match self {
            Self::BadInput(m) => write!(f, "bad input: {m}"),
            Self::UnknownDeferral(m) => write!(f, "{m}"),
            Self::NotSignedIn => f.write_str("answering a deferral needs the WA's own session"),
            Self::Delegated => f.write_str(
                "a delegated session cannot answer a deferral — it is the Wise Authority's own act",
            ),
            Self::ResolverHasNoKey => f.write_str(
                "signed in, but this node holds no key for you: only its owner is a seated Wise \
                 Authority here (a non-owner WA signing with their own key: CIRISServer#814)",
            ),
            Self::NoIdentity => {
                f.write_str("the owner has no federation ID yet — mint one before answering")
            }
            Self::Unauthorized(m) => write!(f, "{m}"),
            Self::Store(m) => write!(f, "store: {m}"),
        }
    }
}

impl std::error::Error for AgentRowError {}

fn hex64(field: &str, v: &str) -> Result<(), AgentRowError> {
    if v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(AgentRowError::BadInput(format!(
            "{field} must be lowercase hex SHA-256 (64 chars), got {v:?}"
        )))
    }
}

fn nonempty(field: &str, v: &str) -> Result<(), AgentRowError> {
    if v.trim().is_empty() {
        Err(AgentRowError::BadInput(format!("{field} is empty")))
    } else {
        Ok(())
    }
}

/// This engine's occurrence key and the identity it belongs to.
async fn occurrence_and_identity(engine: &Engine) -> Result<(String, String), AgentRowError> {
    let occurrence = engine
        .local_derived_key_id()
        .await
        .map_err(|e| AgentRowError::Store(format!("this engine's key: {e:#}")))?;
    let identity = engine
        .federation_directory()
        .active_identity_for_occurrence(&occurrence)
        .await
        .map_err(|e| AgentRowError::Store(format!("identity of {occurrence}: {e:#}")))?;
    Ok((occurrence, identity))
}

async fn self_at(
    engine: &Engine,
    key: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<String, AgentRowError> {
    ciris_persist::federation::self_roster::self_of_at(
        engine.federation_directory().as_ref(),
        key,
        at,
    )
    .await
    .map_err(|e| AgentRowError::Store(format!("self_of_at({key}): {e:#}")))
}

/// **Sign and store `deferral:request:v1`** with this engine's (occurrence) key.
/// Returns the row's `attestation_id`, which the WA's response references.
pub async fn emit_deferral_request(
    engine: &Engine,
    req: &DeferralRequest,
) -> Result<String, AgentRowError> {
    nonempty("deferral_id", &req.deferral_id)?;
    nonempty("task_id", &req.task_id)?;
    nonempty("thought_id", &req.thought_id)?;
    hex64("reason_digest", &req.reason_digest)?;
    let (occurrence, identity) = occurrence_and_identity(engine).await?;
    let mut body = serde_json::json!({
        "deferral_id": req.deferral_id,
        "task_id": req.task_id,
        "thought_id": req.thought_id,
        "reason_digest": req.reason_digest,
        // persist's cirisnode wire shape for a deferral (CC 3.1.9.4).
        "contribution_type": "deferral_request",
    });
    if let Some(d) = req.domain_hint.as_deref().filter(|d| !d.trim().is_empty()) {
        body["domain_hint"] = serde_json::Value::String(d.to_owned());
    }
    if let Some(room) = req
        .room_id
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        room_ok(room)?;
        body[ROOM_FIELD] = serde_json::Value::String(room.to_owned());
    }
    let id = attest::emit(
        engine,
        KeySigner::Engine(engine),
        Spec::new(DEFERRAL_REQUEST, cohort_scope::SELF, body).about(&identity),
    )
    .await
    .map_err(|e| AgentRowError::Store(format!("emit {DEFERRAL_REQUEST}: {e}")))?;
    tracing::info!(
        attestation_id = %id,
        occurrence = %occurrence,
        identity = %identity,
        deferral_id = %req.deferral_id,
        "deferral:request:v1 signed — the agent is inactive on this question until a WA answers"
    );
    Ok(id)
}

/// **Sign and store the WA's answer**, `deferral:response:{approved|rejected}:v1`,
/// with the RESOLVER's own pen: `bearer` is the resolver's session, and only the
/// node's owner (a non-delegated session) gets a pen here. `user_key_id` /
/// `seed_dir` locate the owner's seed, as for every owner-pen door.
pub async fn emit_deferral_response(
    engine: &std::sync::Arc<Engine>,
    bearer: Option<&str>,
    user_key_id: &str,
    seed_dir: std::path::PathBuf,
    request_id: &str,
    approved: bool,
) -> Result<String, AgentRowError> {
    use crate::owner_signer_capsule::{acquire, CapsuleRefusal};
    nonempty("request_id", request_id)?;
    // The request first: an unknown deferral is refused before any pen is opened.
    admitted_request(engine, request_id).await?;
    let capsule = acquire(engine, bearer, user_key_id, seed_dir)
        .await
        .map_err(|r| match r {
            CapsuleRefusal::NotSignedIn => AgentRowError::NotSignedIn,
            CapsuleRefusal::Delegated => AgentRowError::Delegated,
            CapsuleRefusal::NotTheOwner | CapsuleRefusal::Unowned => {
                AgentRowError::ResolverHasNoKey
            }
            CapsuleRefusal::NoFedIdentity => AgentRowError::NoIdentity,
            CapsuleRefusal::Unavailable(e) => AgentRowError::Store(e),
        })?;
    sign_deferral_response(engine, capsule.local_signer(), request_id, approved).await
}

async fn admitted_request(
    engine: &Engine,
    request_id: &str,
) -> Result<ciris_persist::federation::types::Attestation, AgentRowError> {
    engine
        .federation_directory()
        .get_attestation(request_id)
        .await
        .map_err(|e| AgentRowError::Store(format!("get_attestation({request_id}): {e:#}")))?
        .filter(|r| r.attestation_type == DEFERRAL_REQUEST)
        .ok_or_else(|| {
            AgentRowError::UnknownDeferral(format!(
                "{request_id} is not an admitted {DEFERRAL_REQUEST}"
            ))
        })
}

/// The answer, signed with `wa_pen` — the half of [`emit_deferral_response`]
/// after the session check. Public so a test can sign as the owner without a
/// session; production reaches it only through the capsule, so holding the pen
/// is already the authorization.
pub async fn sign_deferral_response(
    engine: &Engine,
    wa_pen: &ciris_persist::prelude::LocalSigner,
    request_id: &str,
    approved: bool,
) -> Result<String, AgentRowError> {
    let request = admitted_request(engine, request_id).await?;
    let dimension = if approved {
        DEFERRAL_APPROVED
    } else {
        DEFERRAL_REJECTED
    };
    let mut body = serde_json::json!({
        ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID: request_id,
    });
    if let Some(d) = request.attestation_envelope.get("deferral_id") {
        body["deferral_id"] = d.clone();
    }
    inherit_room(&mut body, &request.attestation_envelope);
    let id = attest::emit(
        engine,
        KeySigner::Local(wa_pen),
        Spec::new(dimension, cohort_scope::SELF, body).about(&request.attested_key_id),
    )
    .await
    .map_err(|e| AgentRowError::Store(format!("emit {dimension}: {e}")))?;
    tracing::info!(
        attestation_id = %id,
        request = %request_id,
        wa = %wa_pen.key_id(),
        agent = %request.attested_key_id,
        dimension,
        "the Wise Authority answered a deferral, signed with their own key"
    );
    Ok(id)
}

/// **Check CC 3.1.5's rule for the response `authorized_by` names, then sign
/// and store `identity_amendment:v1`.** `node_key_id` is the node whose owner is
/// the seated WA (the node key on a split home, this engine's key otherwise).
pub async fn emit_identity_amendment(
    engine: &Engine,
    node_key_id: &str,
    amendment_digest: &str,
    authorized_by: &str,
) -> Result<String, AgentRowError> {
    hex64("amendment_digest", amendment_digest)?;
    nonempty("authorized_by", authorized_by)?;
    let (occurrence, identity) = occurrence_and_identity(engine).await?;
    let dir = engine.federation_directory();
    let unauthorized = |m: String| AgentRowError::Unauthorized(m);

    // Admitted: the row is in this node's store, past persist's gates.
    let response = dir
        .get_attestation(authorized_by)
        .await
        .map_err(|e| AgentRowError::Store(format!("get_attestation({authorized_by}): {e:#}")))?
        .ok_or_else(|| unauthorized(format!("no admitted row {authorized_by}")))?;
    // Approved.
    if response.attestation_type != DEFERRAL_APPROVED {
        return Err(unauthorized(format!(
            "{authorized_by} is {:?}, not {DEFERRAL_APPROVED}",
            response.attestation_type
        )));
    }
    // About this agent.
    if response.attested_key_id != identity {
        return Err(unauthorized(format!(
            "the response is about {:?}, not this agent ({identity})",
            response.attested_key_id
        )));
    }
    // Signed by a seated WA at its asserted_at: the node's owner (or a roster key
    // of the owner's self), compared self to self at that instant.
    let owner = owner_of(dir.as_ref(), node_key_id)
        .await
        .map_err(|e| AgentRowError::Store(format!("owner_of({node_key_id}): {e:#}")))?
        .ok_or_else(|| unauthorized(format!("node {node_key_id} has no owner, so no seated WA")))?;
    let signer_self = self_at(engine, &response.attesting_key_id, response.asserted_at).await?;
    let owner_self = self_at(engine, &owner, response.asserted_at).await?;
    if signer_self != owner_self {
        return Err(unauthorized(format!(
            "the response is signed by {:?} (self {signer_self:?}), not a seated WA — this \
             node's WA is its owner (self {owner_self:?})",
            response.attesting_key_id
        )));
    }

    let mut body = serde_json::json!({
        "amendment_digest": amendment_digest,
        "authorized_by": authorized_by,
        "evidence_refs": [authorized_by],
    });
    inherit_room(&mut body, &response.attestation_envelope);
    let id = attest::emit(
        engine,
        KeySigner::Engine(engine),
        Spec::new(IDENTITY_AMENDMENT, cohort_scope::SELF, body).about(&identity),
    )
    .await
    .map_err(|e| AgentRowError::Store(format!("emit {IDENTITY_AMENDMENT}: {e}")))?;
    tracing::info!(
        attestation_id = %id,
        occurrence = %occurrence,
        identity = %identity,
        authorized_by = %authorized_by,
        wa = %response.attesting_key_id,
        "identity_amendment:v1 signed, citing the WA's approval"
    );
    Ok(id)
}
