//! **Sign UNDER a verified owner session, without ever releasing the key**
//! (CIRISServer#342).
//!
//! # The asymmetry this closes
//!
//! The `Engine` could already *resolve* the owner (`owner_of_json`,
//! `substrate_owner`) and *sign as the node* (`local_sign_hybrid`). It could not
//! sign **as the owner**. So an agent recording a human authorization — a Wise
//! Authority approving a `requires_approval` tool call — could not put the
//! authorizing human's own signature on it.
//!
//! The faithful approximation shipped instead: the delegate signs, the record
//! names the root, and the owner is re-resolved from the federation directory at
//! verification. That is a real delegation chain. What it cannot do is show an
//! external reviewer the owner's **own** signature on a human approval, and for
//! a control whose entire purpose is "a human authorized this consequential
//! action", that is the difference an auditor asks about.
//!
//! # What is deliberately NOT done
//!
//! The owner's fed-ID is the most powerful key on the node — it signs
//! owner-bindings, delegations and age, and it re-roots ownership. This does not
//! export it, and no method here returns key material. The capsule holds an
//! `Arc<LocalSigner>` privately and offers exactly one verb: sign these bytes.
//!
//! Releasing the key to Python on demand would be strictly worse than the gap it
//! closes, which is why the requesting issue asked for a capsule rather than an
//! accessor.
//!
//! # The gate, and the part that is easy to get wrong
//!
//! Acquisition runs the SAME checks as the HTTP owner gate, including the one
//! that is not obvious:
//!
//! **A DELEGATE MAY NOT OBTAIN THIS.** `resolve_bearer` hands a `dgrant:` token
//! the owner's role AND FullAccess by design — that is what makes a delegation
//! useful — so role alone does not distinguish the owner from someone acting for
//! them. A capsule that signs *as the owner* must refuse delegated sessions, or
//! a temporary grant becomes a permanent power to author the owner's signature.
//! `caller.actor.is_some()` is the discriminator, exactly as
//! `oauth_link::require_owner` and `/v1/accord/*` use it.
//!
//! Below that gate it goes through `compose::resolve_user_signer` — the enforced
//! choke point — rather than reaching for the seed directly, so there remains
//! ONE place where the fed-ID is released and one place to audit.

use std::sync::Arc;

use ciris_persist::prelude::{Engine, LocalSigner};

/// Why a capsule request was refused. Typed so a caller can tell "you are not
/// the owner" from "you are acting FOR the owner" — different remedies, and
/// collapsing them would tell a delegate to go get a session they already have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleRefusal {
    /// No bearer presented.
    NotSignedIn,
    /// A live session, but not the owner's.
    NotTheOwner,
    /// A DELEGATED session. The role check passes and this still refuses.
    Delegated,
    /// The owner exists but has no minted fed-ID yet.
    NoFedIdentity,
    /// The store could not be read.
    Unavailable(String),
}

impl std::fmt::Display for CapsuleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSignedIn => write!(
                f,
                "not signed in — an owner session is required to sign as the owner"
            ),
            Self::NotTheOwner => write!(
                f,
                "signed in, but not as this node's owner — signing as the owner is the \
                 owner's own act"
            ),
            Self::Delegated => write!(
                f,
                "this is a DELEGATED session. A delegate may act for the owner but may not \
                 author the owner's signature: the signature outlives the delegation, so a \
                 temporary grant would become permanent authority"
            ),
            Self::NoFedIdentity => write!(
                f,
                "no responsible-user identity minted yet — create the federation ID first"
            ),
            Self::Unavailable(e) => write!(f, "identity store unavailable: {e}"),
        }
    }
}

/// A signing capability scoped to the owner's fed-ID.
///
/// Holds the signer privately. There is no `Deref`, no serialization, and no
/// public accessor — the only way out through the crate boundary is a signature.
///
/// # The one in-crate exception, and its boundary
///
/// [`Self::edge_signer`] is `pub(crate)` and hands out an
/// `Arc<ciris_edge::identity::LocalSigner>` for the chat plane (CIRISServer#524).
/// Edge's chat surface takes a signer VALUE — `chat_message_attestation(&author,
/// …)` and `Signers { node, actor }` — because from v19.0.0 the row is signed by
/// its author at write and the node merely co-scrubs; there is no "hand me bytes
/// and I will sign them" seam to pass this capsule through.
///
/// What that does and does not widen:
///
/// * It confers the same AUTHORITY [`Self::sign_hybrid`] already confers — the
///   ability to produce the owner's signature over bytes this process chooses.
///   A caller that can reach `edge_signer` could reach `sign_hybrid`.
/// * It does NOT export key material. `LocalSigner` holds `Arc<dyn
///   HardwareSigner>`, whose whole contract is that the private half never
///   leaves the backend, so the module's promise — "no method here returns key
///   material" — still holds literally.
/// * It stays `pub(crate)`. The threat this capsule was built against is release
///   to Python/FFI/HTTP callers, and `pub(crate)` cannot be reached from any of
///   them. Making it `pub` would be a different decision and is not this one.
///
/// The gate is unchanged either way: a capsule only exists after
/// [`acquire`] has run the owner check, so holding one is already the
/// authorization.
pub struct OwnerSignerCapsule {
    signer: Arc<LocalSigner>,
    /// The SAME identity as `signer`, in edge's type — see the type docs.
    edge_signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// One hybrid signature over caller-supplied canonical bytes.
#[derive(Debug, Clone)]
pub struct HybridSignature {
    pub key_id: String,
    pub classical_signature: Vec<u8>,
    pub pqc_signature: Vec<u8>,
}

impl OwnerSignerCapsule {
    /// The owner's key id — public, and the one an auditor resolves against the
    /// federation directory.
    #[must_use]
    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }

    /// The owner's signer in EDGE's type, for signing a row edge composes.
    ///
    /// `pub(crate)` on purpose — see the type docs for what this widens (the
    /// same authority `sign_hybrid` already confers) and what it does not (key
    /// material, which `HardwareSigner` never releases).
    ///
    /// Use it where edge needs the AUTHOR: `chat::chat_message_attestation`, and
    /// the `actor` half of `attestation_bind::Signers`. Everywhere else, prefer
    /// [`Self::sign_hybrid`], which keeps the bytes under the caller's control.
    pub(crate) fn edge_signer(&self) -> &Arc<ciris_edge::identity::LocalSigner> {
        &self.edge_signer
    }

    /// Sign caller-supplied bytes with the owner's hybrid identity.
    ///
    /// The caller canonicalizes. This deliberately does not canonicalize for
    /// them: a signer that reshapes its input decides what was signed, and the
    /// whole value here is that the bytes an auditor verifies are the bytes the
    /// caller meant.
    ///
    /// # Errors
    /// Propagates the signer's own failure (sealed seed unavailable, PQC half
    /// missing).
    pub async fn sign_hybrid(&self, canonical: &[u8]) -> Result<HybridSignature, String> {
        let sig = self
            .signer
            .sign_hybrid(canonical)
            .await
            .map_err(|e| format!("owner fed-ID hybrid sign: {e}"))?;
        Ok(HybridSignature {
            key_id: self.signer.key_id().to_owned(),
            classical_signature: sig.classical.signature.clone(),
            pqc_signature: sig.pqc.signature.clone(),
        })
    }
}

/// Acquire the capsule for a bearer token, or say precisely why not.
///
/// `user_key_id` / `seed_dir` are the node's configured owner-seed location —
/// the same pair `mesh_relay` and `claim-remote` pass, resolved through
/// `active_user_alias` so a renamed owner still resolves.
///
/// # Errors
/// [`CapsuleRefusal`] — never a partial success, and never a capsule for a
/// session that failed any check.
pub async fn acquire(
    engine: &Arc<Engine>,
    bearer: Option<&str>,
    user_key_id: &str,
    seed_dir: std::path::PathBuf,
) -> Result<OwnerSignerCapsule, CapsuleRefusal> {
    use crate::auth::roles::{Permission, UserRole};
    use crate::auth::session::resolve_bearer;

    let Some(token) = bearer.map(str::trim).filter(|t| !t.is_empty()) else {
        return Err(CapsuleRefusal::NotSignedIn);
    };

    let caller = match resolve_bearer(engine, token).await {
        Ok(Some(c)) => c,
        Ok(None) => return Err(CapsuleRefusal::NotSignedIn),
        Err(e) => return Err(CapsuleRefusal::Unavailable(e.to_string())),
    };

    // ORDER IS LOAD-BEARING: the delegation check comes FIRST. A `dgrant:` token
    // carries the owner's role and FullAccess, so checking the role first and
    // the actor second would pass a delegate through any reordering that later
    // dropped the second check. Refusing the actor before consulting the role
    // means the strongest condition cannot be lost by accident.
    if caller.actor.is_some() {
        return Err(CapsuleRefusal::Delegated);
    }
    if caller.role != UserRole::SystemAdmin || !caller.permissions.contains(&Permission::FullAccess)
    {
        return Err(CapsuleRefusal::NotTheOwner);
    }

    // THE ENFORCED CHOKE POINT — not a second path to the seed. `resolve_user_signer`
    // re-checks its own authorization, so this gate and that one must BOTH hold.
    let alias = crate::active_user_alias(&seed_dir, user_key_id);
    match crate::compose::resolve_user_signers(
        engine,
        crate::compose::FedIdUse::OwnerSession,
        &alias,
        seed_dir,
    )
    .await
    {
        Ok(Some((signer, edge_signer))) => Ok(OwnerSignerCapsule {
            signer,
            edge_signer,
        }),
        Ok(None) => Err(CapsuleRefusal::NoFedIdentity),
        Err(e) => Err(CapsuleRefusal::Unavailable(e.to_string())),
    }
}
