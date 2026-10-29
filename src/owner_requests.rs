//! **What a node needs its owner to sign** — and the round trip that gets it
//! signed when the owner's pen is not on the node.
//!
//! A node claimed remotely (a managed agent; `upgrade-owner` with a staged
//! binding) is owned by a person whose key never touches it. Every owner act
//! the node would perform with the pen in hand is then impossible here, and
//! each used to end in a log line: the owner's root acceptance ("waits for the
//! claim"), the capture grant ("community-trust grant DEFERRED"), the
//! announcement. Nothing reached the owner, so nothing was ever signed, and the
//! node never shipped a trace.
//!
//! The steward's rule: anything a node needs the owner to sign goes to the
//! owner as a request to sign or decide; it is never skipped. This module is
//! that round trip:
//!
//! 1. **[`pending`]** — on the node: what is missing, computed from the node's
//!    own rows every time it is asked. There is no queue to drift from the
//!    truth: a request disappears when the row it asks for is held.
//! 2. **[`sign`]** — on the owner's device: each request is built and signed
//!    with the owner's pen. Only the kinds below, each built by the same
//!    builder the node would have used. It is not a signing oracle: the
//!    owner names the node they are signing for, and a request about any other
//!    node, or for an owner other than this device's self, is refused.
//! 3. **[`apply`]** — back on the node: every row must be signed by the node's
//!    owner (the fedID or a live roster key of it, proven by the bundle's
//!    roster proof) and be about this node; persist's own doors then admit it.
//!
//! The carriage between 2 and 3 is the owner's tool today (the manager client,
//! over each node's HTTP API). Delivering requests to the owner's devices over
//! the mesh is the next step (CIRISPersist#1140); the request and bundle shapes
//! stay the same.

use std::sync::Arc;

use ciris_persist::federation::admission::owner_of;
use ciris_persist::federation::types::{attestation_type, cohort_scope, Attestation};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use serde::{Deserialize, Serialize};

use crate::claim_remote::{roster_proof_about, roster_proof_for, RosterProof, StagedOwnerBinding};

/// The owner re-signs this node's owner-binding at `federation`, alongside the
/// `self` row (CC 3.2, CC 5.4.6). Without it no peer, the canonical included,
/// can resolve who owns the node, and the capture grant names an owner nobody
/// else can check.
pub const KIND_ANNOUNCE: &str = "announce";
/// The owner's own `delegates_to(owner → root, infra:*)` for a root this node
/// accepts (CIRISServer#632; CIRISEdge#659's Rooted walk reads the owner).
pub const KIND_ROOT_ACCEPTANCE: &str = "root_acceptance";
/// The owner's `consent:community_trust` grant: this node's sealed traces may
/// be captured (CC 3.3.1; CIRISPersist#1096).
pub const KIND_COMMUNITY_TRUST: &str = "community_trust";

/// One thing the node needs its owner to sign. Its `id` is stable for as long
/// as the need stands, so a client can de-duplicate across reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerRequest {
    pub id: String,
    pub kind: String,
    pub node_key_id: String,
    /// `owner_of(node)`: the self that must sign (or a roster key of it).
    pub owner_key_id: String,
    /// The key that acts on the node (the agent on a split home), named in a
    /// capture grant's subjects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_key_id: Option<String>,
    /// The root a `root_acceptance` is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_key_id: Option<String>,
    /// One sentence a person reads before signing.
    pub why: String,
}

/// What the owner's device hands back: one row per request it signed, the
/// staged announcement, and what proves the signer is the owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOwnerRequests {
    pub node_key_id: String,
    pub signer_key_id: String,
    /// The signer's own key record, so the node can verify the rows before it
    /// has seen the signer anywhere else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key_record: Option<ciris_persist::federation::types::SignedKeyRecord>,
    /// The fedID behind a roster-key signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_proof: Option<RosterProof>,
    /// The `announce` request, signed: a federation-scope owner-binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<StagedOwnerBinding>,
    /// Every other request, signed.
    #[serde(default)]
    pub rows: Vec<SignedRequestRow>,
    /// Requests this device would not sign, and why.
    #[serde(default)]
    pub refused: Vec<RequestOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequestRow {
    pub request_id: String,
    pub kind: String,
    pub attestation: Attestation,
}

/// What happened to one request, on either side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestOutcome {
    pub request_id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl RequestOutcome {
    fn new(request_id: &str, outcome: &str, detail: impl Into<String>) -> Self {
        Self {
            request_id: request_id.to_owned(),
            outcome: outcome.to_owned(),
            detail: detail.into(),
        }
    }
}

/// Why a whole bundle was refused before any row was looked at.
#[derive(Debug)]
pub enum ApplyRefusal {
    /// The bundle is for another node.
    WrongNode(String),
    /// This node has no owner; claim it first.
    Unowned,
    /// The signer is not this node's owner, nor a roster key of it.
    NotTheOwner(String),
    /// The roster proof or the signer's key record was refused.
    ProofRefused(String),
    Directory(String),
}

impl ApplyRefusal {
    #[must_use]
    pub fn into_response(self) -> axum::response::Response {
        use crate::auth::refusal::refuse;
        use axum::http::StatusCode;
        match self {
            Self::WrongNode(m) => refuse(StatusCode::BAD_REQUEST, "owner_requests.wrong_node", m),
            Self::Unowned => refuse(
                StatusCode::CONFLICT,
                "owner_requests.unowned",
                "this node has no owner yet; claim it before applying what its owner signed",
            ),
            Self::NotTheOwner(m) => {
                refuse(StatusCode::FORBIDDEN, "owner_requests.not_the_owner", m)
            }
            Self::ProofRefused(m) => {
                refuse(StatusCode::BAD_REQUEST, "owner_requests.proof_refused", m)
            }
            Self::Directory(m) => refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "owner_requests.directory",
                m,
            ),
        }
    }
}

/// The roots this node accepts, read the way the owner's acceptance is written
/// ([`crate::mesh_genesis::accept_trust_roots_as_owner`]).
async fn roots_of_this_node(engine: &Engine) -> anyhow::Result<Vec<String>> {
    crate::mesh_genesis::roots_this_node_accepts(engine)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// **What this node needs its owner to sign, now.** Empty on an unowned node
/// (there is nobody to ask; the claim comes first).
///
/// # Errors
/// A directory read failed.
pub async fn pending(engine: &Engine) -> anyhow::Result<Vec<OwnerRequest>> {
    let node = crate::node_key::this_node_id(engine).await?;
    let dir = engine.federation_directory();
    let Some(owner) = owner_of(dir.as_ref(), &node)
        .await
        .map_err(|e| anyhow::anyhow!("owner_of({node}): {e:#}"))?
    else {
        return Ok(Vec::new());
    };
    let agent = engine
        .local_derived_key_id()
        .await
        .map_err(|e| anyhow::anyhow!("derive the agent's key id: {e}"))?;
    let request = |kind: &str, suffix: Option<&str>, why: &str| OwnerRequest {
        id: match suffix {
            Some(s) => format!("{kind}:{node}:{s}"),
            None => format!("{kind}:{node}"),
        },
        kind: kind.to_owned(),
        node_key_id: node.clone(),
        owner_key_id: owner.clone(),
        agent_key_id: None,
        root_key_id: None,
        why: why.to_owned(),
    };
    let mut out = Vec::new();

    if !crate::auth::ownership::owner_binding_is_announced(engine, &node, &owner)
        .await
        .map_err(|e| anyhow::anyhow!("read the owner-binding: {e}"))?
    {
        out.push(request(
            KIND_ANNOUNCE,
            None,
            "Announce this node as yours, so peers and the canonical can see who it acts for. \
             It joins your public roster.",
        ));
    }
    for root in roots_of_this_node(engine).await? {
        if root == owner {
            continue;
        }
        if crate::mesh_genesis::holds_labelled_acceptance(engine, &owner, &root)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            continue;
        }
        let mut r = request(
            KIND_ROOT_ACCEPTANCE,
            Some(&root),
            "Accept the trust root this node accepts, so peers sharing it read this node as \
             Rooted.",
        );
        r.root_key_id = Some(root);
        out.push(r);
    }
    if ciris_persist::federation::community_trust_consent::community_trust_consent_for(
        dir.as_ref(),
        &node,
    )
    .await
    .map_err(|e| anyhow::anyhow!("community_trust_consent_for({node}): {e}"))?
    .is_none()
    {
        let mut r = request(
            KIND_COMMUNITY_TRUST,
            None,
            "Let this node's sealed reasoning traces be captured for the community-trust plane.",
        );
        r.agent_key_id = Some(agent);
        out.push(r);
    }
    Ok(out)
}

/// The self `signer` speaks for on this device: its fedID when it is a roster
/// key, else itself.
async fn self_of(engine: &Engine, signer_key_id: &str) -> String {
    ciris_persist::federation::self_roster::self_of_at(
        engine.federation_directory().as_ref(),
        signer_key_id,
        chrono::Utc::now(),
    )
    .await
    .unwrap_or_else(|_| signer_key_id.to_owned())
}

/// **Sign what a node asked for, on the owner's device.** `node_key_id` is the
/// node the OWNER says they are signing for; a request about any other node,
/// for another owner, or of an unknown kind, is refused and nothing is signed
/// for it.
///
/// # Errors
/// Never for a single request (each outcome is reported); only when the
/// device cannot read its own directory.
pub async fn sign(
    engine: &Engine,
    signer: &LocalSigner,
    node_key_id: &str,
    requests: &[OwnerRequest],
) -> anyhow::Result<SignedOwnerRequests> {
    let signer_key_id = signer.key_id().to_owned();
    let me = self_of(engine, &signer_key_id).await;
    let mut out = SignedOwnerRequests {
        node_key_id: node_key_id.to_owned(),
        signer_key_id: signer_key_id.clone(),
        signer_key_record: engine
            .federation_directory()
            .lookup_public_key(&signer_key_id)
            .await
            .ok()
            .flatten()
            .map(|record| ciris_persist::federation::types::SignedKeyRecord { record }),
        roster_proof: roster_proof_for(engine, &signer_key_id).await,
        announce: None,
        rows: Vec::new(),
        refused: Vec::new(),
    };
    for r in requests {
        if r.node_key_id != node_key_id {
            out.refused.push(RequestOutcome::new(
                &r.id,
                "wrong_node",
                format!("asks about {}, not {node_key_id}", r.node_key_id),
            ));
            continue;
        }
        if r.owner_key_id != me && r.owner_key_id != signer_key_id {
            out.refused.push(RequestOutcome::new(
                &r.id,
                "not_this_owner",
                format!(
                    "the node is owned by {}, and this device signs for {me}",
                    r.owner_key_id
                ),
            ));
            continue;
        }
        match r.kind.as_str() {
            KIND_ANNOUNCE => match crate::claim_remote::stage_owner_binding(
                engine,
                signer,
                node_key_id,
                cohort_scope::FEDERATION,
            )
            .await
            {
                Ok(staged) => out.announce = Some(staged),
                Err(e) => {
                    out.refused
                        .push(RequestOutcome::new(&r.id, "sign_failed", e.to_string()))
                }
            },
            KIND_ROOT_ACCEPTANCE => {
                let Some(root) = r.root_key_id.as_deref() else {
                    out.refused
                        .push(RequestOutcome::new(&r.id, "malformed", "no root_key_id"));
                    continue;
                };
                match acceptance_row(engine, signer, root).await {
                    Ok(row) => out.rows.push(SignedRequestRow {
                        request_id: r.id.clone(),
                        kind: r.kind.clone(),
                        attestation: row,
                    }),
                    Err(e) => out.refused.push(RequestOutcome::new(
                        &r.id,
                        "sign_failed",
                        format!("{e:#}"),
                    )),
                }
            }
            KIND_COMMUNITY_TRUST => {
                match community_trust_row(
                    signer,
                    node_key_id,
                    &r.owner_key_id,
                    r.agent_key_id.as_deref(),
                )
                .await
                {
                    Ok(row) => out.rows.push(SignedRequestRow {
                        request_id: r.id.clone(),
                        kind: r.kind.clone(),
                        attestation: row,
                    }),
                    Err(e) => out.refused.push(RequestOutcome::new(
                        &r.id,
                        "sign_failed",
                        format!("{e:#}"),
                    )),
                }
            }
            other => out.refused.push(RequestOutcome::new(
                &r.id,
                "unknown_kind",
                format!("this device does not sign {other:?} requests"),
            )),
        }
    }
    Ok(out)
}

/// The owner's acceptance of `root`, built the way
/// [`crate::mesh_genesis::accept_trust_roots_as_owner`] builds it on a node
/// that holds the pen, and signed here. Refused unless this device itself
/// accepts the root: the owner does not accept, from a node's request, a root
/// their own device does not.
async fn acceptance_row(
    engine: &Engine,
    signer: &LocalSigner,
    root: &str,
) -> anyhow::Result<Attestation> {
    let own = crate::node_key::this_node_id(engine).await?;
    let accepted = ciris_persist::federation::trust_root::trusted_roots_of(
        engine.federation_directory().as_ref(),
        &own,
        chrono::Utc::now(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("trusted_roots_of({own}): {e}"))?;
    let baked = crate::mesh_genesis::roots_this_node_accepts(engine)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    anyhow::ensure!(
        accepted.iter().any(|r| r == root) || baked.iter().any(|r| r == root),
        "this device does not accept the root {root:?}; accept it here first"
    );
    let envelope = crate::mesh_genesis::acceptance_envelope(engine, signer.key_id(), root)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    crate::attest::Emit::stamp(
        signer.key_id(),
        crate::attest::Spec::new(
            attestation_type::DELEGATES_TO,
            cohort_scope::FEDERATION,
            envelope,
        )
        .attested_to(root),
    )
    .map_err(|e| anyhow::anyhow!("stamp the acceptance: {e}"))?
    .sign_and_assemble(crate::attest::KeySigner::Local(signer))
    .await
    .map_err(|e| anyhow::anyhow!("sign the acceptance: {e}"))
}

/// The capture grant, in [`crate::federation_delivery::author_community_trust`]'s
/// shape: about the node, its subjects the node, its owner and the agent that
/// acts on it, at federation.
async fn community_trust_row(
    signer: &LocalSigner,
    node: &str,
    owner: &str,
    agent: Option<&str>,
) -> anyhow::Result<Attestation> {
    crate::federation_delivery::community_trust_grant(signer, signer.key_id(), node, owner, agent)
        .await
}

/// What [`apply`] did with each row.
#[derive(Debug, Clone, Serialize)]
pub struct Applied {
    pub node_key_id: String,
    pub owner_key_id: String,
    pub outcomes: Vec<RequestOutcome>,
}

/// **Apply what the owner signed, on the node.** The bundle must be for this
/// node and signed by its owner (directly, or by a roster key the bundle's
/// proof ties to the owner); each row must be the kind it claims and about
/// this node. Persist's own doors admit each row.
///
/// # Errors
/// The whole bundle is refused ([`ApplyRefusal`]); a single row that fails is
/// reported in its outcome instead.
pub async fn apply(
    engine: &Arc<Engine>,
    policy: HybridPolicy,
    bundle: &SignedOwnerRequests,
) -> Result<Applied, ApplyRefusal> {
    let node = crate::node_key::this_node_id(engine)
        .await
        .map_err(|e| ApplyRefusal::Directory(format!("{e:#}")))?;
    if bundle.node_key_id != node {
        return Err(ApplyRefusal::WrongNode(format!(
            "signed for {}, and this node is {node}",
            bundle.node_key_id
        )));
    }
    let dir = engine.federation_directory();
    let owner = owner_of(dir.as_ref(), &node)
        .await
        .map_err(|e| ApplyRefusal::Directory(format!("owner_of({node}): {e:#}")))?
        .ok_or(ApplyRefusal::Unowned)?;
    let signer = bundle.signer_key_id.as_str();

    // Who signed, before what they signed: the signer's key record, then the
    // roster proof through persist's own gates, so the signer resolves to the
    // fedID that owns this node.
    if let Some(rec) = &bundle.signer_key_record {
        if rec.record.key_id != signer {
            return Err(ApplyRefusal::ProofRefused(format!(
                "the key record is for {}, not the signer {signer}",
                rec.record.key_id
            )));
        }
        // Already held on any node the owner reached; a conflict is benign.
        let _ = engine.register_federation_key(rec.clone()).await;
    }
    if let Some(p) = bundle
        .roster_proof
        .as_ref()
        .and_then(|p| roster_proof_about(p, signer))
    {
        let _ = engine
            .register_federation_key(p.identity_key_record.clone())
            .await;
        for occ in &p.occurrences {
            dir.put_identity_occurrence(occ.clone())
                .await
                .map_err(|e| {
                    ApplyRefusal::ProofRefused(format!("the roster proof was refused: {e:#}"))
                })?;
        }
    }
    if signer != owner && !crate::auth::verify::signer_acts_for(engine, signer, &owner).await {
        return Err(ApplyRefusal::NotTheOwner(format!(
            "signed by {signer}, which is neither this node's owner {owner} nor a live roster \
             key of it"
        )));
    }

    let mut outcomes = Vec::new();
    if let Some(staged) = &bundle.announce {
        let id = format!("{KIND_ANNOUNCE}:{node}");
        let binding = &staged.owner_binding;
        let outcome = if binding.attesting_key_id != signer {
            RequestOutcome::new(&id, "refused", "the binding is signed by another key")
        } else if staged.cohort_scope != cohort_scope::FEDERATION {
            RequestOutcome::new(
                &id,
                "refused",
                "an announcement is a federation-scope binding",
            )
        } else {
            match crate::auth::ownership::apply_signed_owner_binding(
                engine,
                &node,
                cohort_scope::FEDERATION,
                policy,
                binding,
            )
            .await
            {
                Ok(a) => RequestOutcome::new(&id, "applied", a.attestation_id),
                Err(e) => RequestOutcome::new(&id, "refused", e.to_string()),
            }
        };
        outcomes.push(outcome);
    }
    for row in &bundle.rows {
        let a = &row.attestation;
        let shaped = a.attesting_key_id == signer
            && match row.kind.as_str() {
                KIND_COMMUNITY_TRUST => {
                    a.attested_key_id == node
                        && a.attestation_type == attestation_type::SCORES
                        && a.attestation_envelope
                            .get(ciris_persist::federation::envelope::paths::DIMENSION)
                            .and_then(serde_json::Value::as_str)
                            == Some(
                                ciris_persist::federation::community_trust_consent::COMMUNITY_TRUST_DIMENSION,
                            )
                }
                KIND_ROOT_ACCEPTANCE => {
                    a.attestation_type == attestation_type::DELEGATES_TO
                        && a.attestation_envelope
                            .get(ciris_persist::federation::envelope::paths::DIMENSION)
                            .and_then(serde_json::Value::as_str)
                            == Some(ciris_persist::federation::trust_root::TRUST_ACCEPTS_DIMENSION)
                }
                _ => false,
            };
        if !shaped {
            outcomes.push(RequestOutcome::new(
                &row.request_id,
                "refused",
                format!("not a {} row about this node signed by {signer}", row.kind),
            ));
            continue;
        }
        outcomes.push(match crate::attest::put(engine, a.clone()).await {
            Ok(id) => RequestOutcome::new(&row.request_id, "applied", id),
            Err(e) => RequestOutcome::new(&row.request_id, "refused", format!("{e:#}")),
        });
    }
    if outcomes.iter().any(|o| o.outcome == "applied") {
        crate::compose::kick_replication("owner-signed requests applied");
    }
    tracing::info!(
        node_key_id = %node,
        owner = %owner,
        signer,
        applied = outcomes.iter().filter(|o| o.outcome == "applied").count(),
        refused = outcomes.iter().filter(|o| o.outcome != "applied").count(),
        "owner requests: what the owner signed on their own device was applied here"
    );
    Ok(Applied {
        node_key_id: node,
        owner_key_id: owner,
        outcomes,
    })
}
