//! **The owner re-binds a split node from their own device** (CIRISServer#811).
//!
//! A node claimed on ≤0.5.188 ran on its agent key, and the owner-binding names
//! that key. 0.5.189 mints a separate node key and splits (CC 3.4.7.3 Clause A);
//! compose then moves the binding onto the node key with the owner's own pen
//! (`node_key::move_owner_binding_to_node_key`). On a device the owner installed
//! that pen is on disk — installing is claiming. On a node claimed REMOTELY
//! (a Docker agent, a headless server claimed from a phone) it never was: the
//! seed lives on the owner's device. The move only warns, `owner_of(node key)`
//! stays empty, and nothing re-opens: the claim minted a ROOT WaCert, so
//! `is_first_run` is false and setup/root refuses a second claim.
//!
//! This is the door for that state. The owner's device signs
//! `delegates_to(owner → node key, infra:*)` and posts it to
//! `POST /v1/setup/owner-rebind` on the split node. The authority is two signed
//! facts, so no PIN is asked:
//!
//! - the binding the owner signed on ≤0.5.188, still live on the ACTOR key;
//! - a fresh binding signed by the same self: the same key, or a roster key of
//!   that fedID proven by its occurrence rows (CIRISServer#806).
//!
//! Admitted only while the node key is unowned, so it can never re-point an
//! owned node. `owner_of` keeps reading one key: the node's own binding, never
//! the predecessor's (that would let an actor key confer node ownership, the
//! composition Clause A exists to end).

use axum::http::StatusCode;
use ciris_persist::federation::admission::owner_of;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use serde::{Deserialize, Serialize};

use crate::auth::ownership::{self, AppliedOwnerBinding, OwnershipError, SignedOwnerBinding};
use crate::claim_remote::RosterProof;

/// Whether this node's owner-binding is where its operating key is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OwnerBindingState {
    /// `owner_of(node key)` resolves.
    Owned,
    /// Nobody owns the node key, and no predecessor binding exists to follow.
    Unowned,
    /// The split happened and the owner did not follow: the actor key is owned,
    /// the node key is not. The owner re-binds from their device.
    SplitUnfollowed {
        /// The actor key the binding still names.
        actor_key_id: String,
        /// That binding's granter.
        actor_owner_key_id: String,
    },
}

/// Read [`OwnerBindingState`]. `actor_key_id` is the split's actor
/// (`node_key::actor_identity`); `None` on a node that carries no brain.
pub async fn owner_binding_state(
    engine: &Engine,
    node_key_id: &str,
    actor_key_id: Option<&str>,
) -> Result<OwnerBindingState, ciris_persist::federation::Error> {
    let dir = engine.federation_directory();
    if owner_of(dir.as_ref(), node_key_id).await?.is_some() {
        return Ok(OwnerBindingState::Owned);
    }
    let Some(actor) = actor_key_id.filter(|a| *a != node_key_id) else {
        return Ok(OwnerBindingState::Unowned);
    };
    Ok(match owner_of(dir.as_ref(), actor).await? {
        Some(owner) => OwnerBindingState::SplitUnfollowed {
            actor_key_id: actor.to_owned(),
            actor_owner_key_id: owner,
        },
        None => OwnerBindingState::Unowned,
    })
}

/// Why a re-bind was refused. Each maps to a fixed reason id.
#[derive(Debug)]
pub enum RebindRefusal {
    /// This node carries no actor key, so there is no predecessor binding.
    NoSplit,
    /// The node key already has an owner.
    AlreadyOwned,
    /// The actor key is not owned either; this is an ordinary claim.
    ActorUnowned,
    /// The binding's signer is not the actor key's owner (nor a roster key of
    /// that owner's self).
    NotTheOwner {
        /// The self the signer resolves to.
        signer_self: String,
        /// The self the predecessor binding resolves to.
        owner_self: String,
    },
    /// The binding failed verification or persist refused it.
    Binding(OwnershipError),
    /// The directory read or the roster proof's admission failed.
    Directory(String),
}

impl RebindRefusal {
    /// The door's answer. Each id is a literal at its `refuse` call so the
    /// localization guard sees every one (an id returned through a variable is
    /// invisible to it).
    #[must_use]
    pub fn into_response(self) -> axum::response::Response {
        use crate::auth::refusal::refuse;
        let (code, msg) = (self.status(), self.to_string());
        match self {
            Self::NoSplit => refuse(code, "owner_rebind.no_split", msg),
            Self::AlreadyOwned => refuse(code, "owner_rebind.already_owned", msg),
            Self::ActorUnowned => refuse(code, "owner_rebind.actor_unowned", msg),
            Self::NotTheOwner { .. } => refuse(code, "owner_rebind.not_the_owner", msg),
            Self::Binding(_) => refuse(code, "owner_rebind.binding_rejected", msg),
            Self::Directory(_) => refuse(code, "owner_rebind.directory", msg),
        }
    }

    /// The HTTP status the door answers with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NoSplit | Self::AlreadyOwned | Self::ActorUnowned => StatusCode::CONFLICT,
            Self::NotTheOwner { .. } => StatusCode::FORBIDDEN,
            Self::Binding(
                OwnershipError::AgencyScopeRefused
                | OwnershipError::Validation(_)
                | OwnershipError::Canonicalize(_),
            ) => StatusCode::BAD_REQUEST,
            Self::Binding(OwnershipError::Verify(_)) => StatusCode::UNAUTHORIZED,
            Self::Binding(_) | Self::Directory(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for RebindRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSplit => f.write_str(
                "this node carries no actor key, so there is no earlier owner-binding to follow",
            ),
            Self::AlreadyOwned => f.write_str("the node key already has an owner"),
            Self::ActorUnowned => f.write_str(
                "the actor key has no owner either — claim the node instead (setup/root)",
            ),
            Self::NotTheOwner {
                signer_self,
                owner_self,
            } => write!(
                f,
                "the binding is signed for {signer_self:?}, but the actor key's owner is \
                 {owner_self:?} — only the same owner re-binds"
            ),
            Self::Binding(e) => write!(f, "owner-binding rejected: {e}"),
            Self::Directory(e) => write!(f, "directory: {e}"),
        }
    }
}

async fn self_of(engine: &Engine, key: &str) -> Result<String, RebindRefusal> {
    ciris_persist::federation::self_roster::self_of_at(
        engine.federation_directory().as_ref(),
        key,
        chrono::Utc::now(),
    )
    .await
    .map_err(|e| RebindRefusal::Directory(format!("self_of_at({key}): {e:#}")))
}

/// **Admit the owner's re-bind onto the node key.** See the module doc for the
/// authority. The roster proof, when present, is admitted through persist's own
/// verifying gates BEFORE the owner check, and only the rows about this
/// binding's signer are taken.
pub async fn admit_owner_rebind(
    engine: &Engine,
    node_key_id: &str,
    actor_key_id: Option<&str>,
    cohort_scope: &str,
    policy: HybridPolicy,
    binding: &SignedOwnerBinding,
    roster_proof: Option<&RosterProof>,
) -> Result<AppliedOwnerBinding, RebindRefusal> {
    let Some(actor) = actor_key_id.filter(|a| *a != node_key_id) else {
        return Err(RebindRefusal::NoSplit);
    };
    let owner = match owner_binding_state(engine, node_key_id, Some(actor))
        .await
        .map_err(|e| RebindRefusal::Directory(format!("{e:#}")))?
    {
        OwnerBindingState::Owned => return Err(RebindRefusal::AlreadyOwned),
        OwnerBindingState::Unowned => return Err(RebindRefusal::ActorUnowned),
        OwnerBindingState::SplitUnfollowed {
            actor_owner_key_id, ..
        } => actor_owner_key_id,
    };

    // The signature first: nothing is written for a binding that does not verify
    // or does not attest THIS node key.
    ownership::verify_signed_owner_binding(node_key_id, policy, binding)
        .map_err(RebindRefusal::Binding)?;

    let signer = binding.attesting_key_id.as_str();
    if let Some(p) = roster_proof.and_then(|p| crate::claim_remote::roster_proof_about(p, signer)) {
        // Already held on any node the owner claimed; a Conflict is benign.
        let _ = engine
            .register_federation_key(p.identity_key_record.clone())
            .await;
        ownership::register_user_key(engine, binding)
            .await
            .map_err(RebindRefusal::Binding)?;
        for occ in &p.occurrences {
            engine
                .federation_directory()
                .put_identity_occurrence(occ.clone())
                .await
                .map_err(|e| {
                    RebindRefusal::Directory(format!(
                        "roster occurrence for {signer} refused: {e:#}"
                    ))
                })?;
        }
    }

    let signer_self = self_of(engine, signer).await?;
    let owner_self = self_of(engine, &owner).await?;
    if signer_self != owner_self {
        return Err(RebindRefusal::NotTheOwner {
            signer_self,
            owner_self,
        });
    }

    let applied =
        ownership::apply_signed_owner_binding(engine, node_key_id, cohort_scope, policy, binding)
            .await
            .map_err(RebindRefusal::Binding)?;
    tracing::info!(
        node_key_id = %node_key_id,
        actor_key_id = %actor,
        owner = %owner_self,
        signer = %signer,
        "owner re-bound the split node from their own device — owner_of(node key) resolves \
         (CIRISServer#811)"
    );
    Ok(applied)
}

/// `POST /v1/setup/owner-rebind` body.
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnerRebindRequest {
    /// The cohort the owner binds the node under (`self` / `family` / `community`).
    pub cohort_scope: String,
    /// `delegates_to(owner → this node key, infra:*)`, signed by the owner's device.
    pub owner_binding: SignedOwnerBinding,
    /// The fedID behind a roster-key signer (CIRISServer#806).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_roster_proof: Option<RosterProof>,
}

/// Why driving a re-bind of another node failed.
#[derive(Debug)]
pub enum RebindRemoteError {
    /// The target could not be reached, or answered unreadably.
    Transport(String),
    /// The target carries no actor key: nothing to re-bind.
    NotSplit,
    /// Building the binding failed.
    Build(OwnershipError),
    /// The target refused (its status and body).
    TargetRejected {
        /// HTTP status.
        status: u16,
        /// Response body.
        body: String,
    },
}

impl std::fmt::Display for RebindRemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "target unreachable: {e}"),
            Self::NotSplit => f.write_str(
                "the target reports no actor key — it was never split, so there is nothing to re-bind",
            ),
            Self::Build(e) => write!(f, "build the owner-binding: {e}"),
            Self::TargetRejected { status, body } => write!(f, "target refused ({status}): {body}"),
        }
    }
}

/// **The owner's side.** Read the target's `GET /v1/identity` for its node key,
/// sign the owner-binding onto it with `user_signer`, and post it to the
/// target's `POST /v1/setup/owner-rebind`. Returns the target's JSON answer.
pub async fn rebind_remote(
    http: &reqwest::Client,
    user_signer: &LocalSigner,
    target_url: &str,
    cohort_scope: &str,
    owner_roster_proof: Option<&RosterProof>,
) -> Result<serde_json::Value, RebindRemoteError> {
    let base = target_url.trim().trim_end_matches('/');
    let identity: serde_json::Value = http
        .get(format!("{base}/v1/identity"))
        .send()
        .await
        .map_err(|e| RebindRemoteError::Transport(e.to_string()))?
        .json()
        .await
        .map_err(|e| RebindRemoteError::Transport(format!("GET /v1/identity: {e}")))?;
    let node_key_id = identity
        .get("node_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RebindRemoteError::Transport("/v1/identity carries no node_key_id".into())
        })?;
    if identity
        .get("actor_key_id")
        .and_then(|v| v.as_str())
        .is_none_or(|a| a == node_key_id)
    {
        return Err(RebindRemoteError::NotSplit);
    }

    let infra_scopes: Vec<String> = ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let owner_binding = ownership::build_signed_owner_binding(
        user_signer,
        node_key_id,
        &infra_scopes,
        cohort_scope,
    )
    .await
    .map_err(RebindRemoteError::Build)?;
    let req = OwnerRebindRequest {
        cohort_scope: cohort_scope.to_owned(),
        owner_binding,
        owner_roster_proof: owner_roster_proof.cloned(),
    };
    let resp = http
        .post(format!("{base}/v1/setup/owner-rebind"))
        .json(&req)
        .send()
        .await
        .map_err(|e| RebindRemoteError::Transport(e.to_string()))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(RebindRemoteError::TargetRejected {
            status: status.as_u16(),
            body,
        });
    }
    Ok(serde_json::from_str(&body).unwrap_or(serde_json::Value::Null))
}
