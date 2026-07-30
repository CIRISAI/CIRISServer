//! Portable mesh genesis (`FSD/MESH_GENESIS.md`) — produce + attach a
//! self-verifying bundle carrying **the trust root and ≥1 `infra:serve` node**.
//!
//! # Why this exists
//!
//! A trust root alone is inert: it can vouch, but nothing can serve or receive.
//! The genesis object therefore guarantees a **minimum viable mesh** — a root you
//! can trust *and* a node that can actually serve you. That invariant is enforced
//! at PRODUCE time: [`produce_genesis`] refuses to emit a bundle whose serve set is
//! empty, so the CIRISPersist#480 failure (a baked seed shipping `roles: []`, which
//! darks the whole trace plane) cannot be reproduced as a portable artifact. Today
//! [`produce_genesis_from_baked`] REFUSES for exactly that reason — the refusal is
//! the invariant working, not a bug.
//!
//! # Self-verifying
//!
//! [`verify_bundle`] checks the bundle against ITSELF, offline: every serve node's
//! scrub roots to a holder carried in the same bundle, and every serve node carries
//! an `infra:serve` role. A tampered or hand-assembled genesis fails these checks —
//! the object is trustworthy because it proves its own rooting, not because of where
//! it came from. Safe to move over any channel (file, QR, USB).
//!
//! The cryptographic anchor is the **holder records** (signed) plus each serve
//! node's scrub to them; `family_key_id` is a grouping identifier, not authority.
//!
//! # What it is NOT
//!
//! Public records + attestations only — **never a seed or secret byte**. Attaching
//! seeds the RECORDS; it deliberately does not write the user's
//! `delegates_to(user → root)` trust edge, which is the user's own signed,
//! deletable, nuclear-revocable act (`FSD/TRUST_ROOT_CAPABILITY_GATE.md` §1). The
//! operator *chooses* a trust root; a bundle never assigns one.

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::trust_root::{
    pre_rotation_commitment, ACCORD_LIFECYCLE_DIMENSION, ACCORD_LIFECYCLE_FRESHNESS_DAYS,
    CHARTER_PRE_ROTATION_FIELD, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
};
use ciris_persist::federation::types::delegation_scope::INFRA_SERVE;
use ciris_persist::federation::types::{attestation_type, Attestation, SignedAttestation};
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Wire version of the genesis bundle. Bump on any breaking shape change.
///
/// **v2** (the seed ceremony) adds the *delegation plane*: a v1 bundle carried
/// only key records, so attaching it produced keys with **no authority** — no
/// charter meant `trust_root_valid` stayed false and the capability gate stayed
/// shut. v2 carries the charter + grants that make the root an actual root, and
/// the m-of-n holder authorizations that prove a quorum minted it.
pub const GENESIS_VERSION: u32 = 2;

/// A portable, self-verifying mesh genesis: the trust root + ≥1 serve node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBundle {
    pub version: u32,
    /// The trust root's family identifier (grouping; authority lives in `holders`).
    pub family_key_id: String,
    /// The accord holders: the pinned anchor pubkeys every chain terminates in.
    pub holders: Vec<SignedKeyRecord>,
    /// **≥1** `infra:serve`-blessed node, so the mesh can actually serve on attach.
    pub serve_nodes: Vec<SignedKeyRecord>,
    /// The family's **entrenched** `quorum:M/N` as it stood at production. Carried,
    /// never assumed — a verifier must not guess how many holders authorized this.
    /// Anti-downgrade: [`verify_bundle`] additionally requires M to be at least a
    /// strict majority of the holders the bundle carries, so a tampered policy
    /// string cannot talk the threshold down to 1.
    #[serde(default)]
    pub consensus_protocol: String,
    /// The **delegation plane**: the self-referential charter (`delegates_to(root →
    /// root)`, carrying its pre-rotation commitment) plus one `infra:serve` grant
    /// per serve node. Without these the bundle is inert — keys and no authority.
    #[serde(default)]
    pub attestations: Vec<SignedAttestation>,
    /// The m-of-n proof: holder signatures over [`authorization_digest`], which
    /// binds the whole artifact (charter, grants, holders, serve nodes). This is
    /// what makes minting a trust root a quorum act rather than one holder's
    /// unilateral decision.
    #[serde(default)]
    pub authorizations: Vec<GenesisAuthorization>,
    pub produced_at: String,
}

/// One holder's authorization of a genesis bundle — a bound-hybrid signature over
/// [`authorization_digest`]. Distinct from the charter's own signature: the charter
/// says "this root declares itself"; an authorization says "I, a seated holder,
/// concur that this artifact should exist".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAuthorization {
    pub holder_key_id: String,
    pub signature_classical: String,
    pub signature_pqc: String,
}

#[derive(Debug)]
pub enum GenesisError {
    /// The invariant: a genesis without a serve node is a dark mesh.
    NoServeNode,
    /// A serve node does not carry `infra:serve` (it cannot receive traces).
    ServeNodeUnblessed(String),
    /// A serve node's scrub does not root to any holder carried in this bundle.
    ServeNodeUnrooted(String),
    NoHolders,
    Directory(String),
    /// No self-referential charter — the bundle is keys without authority.
    NoCharter,
    /// The charter is malformed (wrong shape, scope below the root minimum, or a
    /// missing/ill-formed pre-rotation commitment).
    CharterInvalid(String),
    /// A serve node has no `infra:serve` grant from the charter root.
    ServeNodeUngranted(String),
    /// No `accord:lifecycle:v1` liveness row about the charter root. Without it
    /// `trust_root_valid` returns false on its FIFTH conjunct and the capability
    /// gate stays shut — the bundle looks complete and is inert.
    NoLifecycle,
    /// The liveness row exists but is outside the freshness window, so it no
    /// longer counts. Refused loudly rather than attached to produce a root that
    /// silently fails the walk.
    LifecycleStale {
        asserted_at: String,
        max_age_days: i64,
    },
    /// Fewer holder authorizations than the family's entrenched M.
    QuorumNotMet {
        have: usize,
        needed: usize,
    },
    /// An authorization is not from a holder the bundle carries, is a duplicate,
    /// or its signature does not verify over the bundle digest.
    AuthorizationInvalid(String),
}

impl std::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCharter => write!(
                f,
                "genesis carries no trust-root charter: attaching it would seed keys \
                 with no authority (trust_root_valid stays false and the capability \
                 gate stays shut)"
            ),
            Self::CharterInvalid(d) => write!(f, "trust-root charter invalid: {d}"),
            Self::NoLifecycle => write!(
                f,
                "genesis carries no accord:lifecycle:v1 liveness row about the charter root — \
                 trust_root_valid needs edge_exists && root_self_declares && \
                 charter_has_recovery && lifecycle_active && !halt_latched, and this bundle \
                 satisfies only the first three. Attaching it would seed a root that every \
                 capability walk silently rejects (CIRISPersist#483)"
            ),
            Self::LifecycleStale {
                asserted_at,
                max_age_days,
            } => write!(
                f,
                "the accord:lifecycle:v1 liveness row is stale (asserted_at={asserted_at}, \
                 window={max_age_days}d) — re-run the ceremony to mint a fresh one. A stale \
                 row does not count toward lifecycle_active, so attaching this bundle would \
                 produce an inert trust root"
            ),
            Self::ServeNodeUngranted(k) => write!(
                f,
                "serve node {k} carries no infra:serve grant from the charter root — \
                 the capability would not root to the trust root"
            ),
            Self::QuorumNotMet { have, needed } => write!(
                f,
                "genesis authorized by {have} holder(s), the family's entrenched \
                 quorum needs {needed}"
            ),
            Self::AuthorizationInvalid(d) => write!(f, "holder authorization invalid: {d}"),
            Self::NoServeNode => write!(
                f,
                "genesis has no infra:serve-blessed serve node — attaching it would \
                 produce a DARK mesh (nothing could receive traces). Bless a canonical \
                 with infra:serve first (CIRISPersist#480)"
            ),
            Self::ServeNodeUnblessed(k) => {
                write!(f, "serve node {k} does not carry the infra:serve role")
            }
            Self::ServeNodeUnrooted(k) => write!(
                f,
                "serve node {k} scrub does not root to any accord holder in this bundle \
                 (not self-verifying)"
            ),
            Self::NoHolders => write!(f, "genesis carries no accord holders (no anchor)"),
            Self::Directory(e) => write!(f, "directory: {e}"),
        }
    }
}

impl std::error::Error for GenesisError {}

/// Does this record carry `infra:serve`? Checks the **attested** surface first.
///
/// Verify materializes `ScrubTarget.roles` into the scrub-signed
/// `registration_envelope` (v10.5.0 — "attested by this scrub"), so THAT is where an
/// accord-conferred capability actually lives. persist does not yet lift those into
/// the top-level `KeyRecord.roles` that `claims_role` reads (**CIRISPersist#486**),
/// which is why a bundle holder must read the envelope directly rather than trusting
/// `roles` — the top-level field is empty by design from the producer.
///
/// The `identity_type` set and top-level `roles` are also honored, so this stays
/// correct once #486 lands and for records that express the claim either way.
pub fn carries_infra_serve(rec: &SignedKeyRecord) -> bool {
    use ciris_persist::federation::types::identity_type;
    let attested_in_envelope = rec
        .record
        .registration_envelope
        .get("roles")
        .and_then(|v| v.as_array())
        .is_some_and(|a| a.iter().any(|r| r.as_str() == Some(INFRA_SERVE)));

    attested_in_envelope
        || identity_type::set_contains(&rec.record.identity_type, INFRA_SERVE)
        || rec.record.roles.iter().any(|r| r == INFRA_SERVE)
}

// ─────────────────────────────────────────────────────────────────────────────
// The delegation plane: charter, grants, and the m-of-n authorization digest.
// ─────────────────────────────────────────────────────────────────────────────

/// Attestation id of the charter within a bundle (stable, content-independent —
/// the bundle carries exactly one).
pub const CHARTER_ATTESTATION_ID: &str = "genesis-charter";
/// Prefix for the per-serve-node `infra:serve` grant ids.
pub const GRANT_ATTESTATION_ID_PREFIX: &str = "genesis-grant-serve";

/// The liveness row's attestation id — the FIFTH conjunct of `trust_root_valid`.
pub const LIFECYCLE_ATTESTATION_ID: &str = "genesis-lifecycle";

/// The scopes a genesis charter confers on the root. The accord's charter is its
/// domain ceiling: because delegation is attenuation-bound, nothing downstream can
/// ever hold more than this. `serve` + `attest` are the RC3 validity minimum
/// (CIRISPersist#488 — a root that cannot both serve and vouch is inert); `store`
/// and `transport` are what a mesh needs to carry data at all.
///
/// Deliberately ABSENT: `infra:network_presence` and the `hold_*_membership`
/// scopes. Those are owner-granted, never root-granted — a root that could confer
/// presence would make un-trust unsurvivable (revoking the root would unplug the
/// device from the network it needs to reach a replacement).
pub const CHARTER_SCOPES: &[&str] = &[
    INFRA_ATTEST_SCOPE,
    INFRA_SERVE_SCOPE,
    "infra:store",
    "infra:transport",
];

/// The bytes every holder authorization signs: a canonical digest binding the
/// bundle's identity, its holder set, its serve set, and its whole delegation
/// plane. Signing this means "I concur with THIS artifact" — a co-signer cannot
/// be replayed onto a bundle with a swapped serve node or a widened charter.
///
/// Deliberately excludes `authorizations` (they are what is being accumulated)
/// and `produced_at` is included so two ceremonies are distinguishable.
pub fn authorization_digest(bundle: &GenesisBundle) -> Result<Vec<u8>, GenesisError> {
    let preimage = serde_json::json!({
        "version": bundle.version,
        "family_key_id": bundle.family_key_id,
        "consensus_protocol": bundle.consensus_protocol,
        "produced_at": bundle.produced_at,
        "holders": bundle.holders.iter().map(|h| &h.record.key_id).collect::<Vec<_>>(),
        "serve_nodes": bundle.serve_nodes.iter().map(|n| &n.record.key_id).collect::<Vec<_>>(),
        "attestations": bundle
            .attestations
            .iter()
            .map(|a| {
                serde_json::json!({
                    "attestation_id": a.attestation.attestation_id,
                    "attesting_key_id": a.attestation.attesting_key_id,
                    "attested_key_id": a.attestation.attested_key_id,
                    "attestation_type": a.attestation.attestation_type,
                    "attestation_envelope": a.attestation.attestation_envelope,
                })
            })
            .collect::<Vec<_>>(),
    });
    ciris_persist::verify::canonical::ceg_produce_canonicalize(&preimage)
        .map_err(|e| GenesisError::CharterInvalid(format!("digest canonicalize: {e}")))
}

/// The bundle's short content fingerprint — the value an operator compares
/// **out of band** before attaching. Self-verification proves untampered; only a
/// second channel proves *intended* (`FSD/MESH_GENESIS.md` §2, the KERI/OOBI
/// concession). Rendered on the card for exactly that comparison.
pub fn fingerprint(bundle: &GenesisBundle) -> Result<String, GenesisError> {
    let d = authorization_digest(bundle)?;
    Ok(hex::encode(sha2::Sha256::digest(&d))[..16].to_string())
}

/// Build the charter envelope for `root_key_id`, pre-committing to `successors`.
///
/// The successor set is the m-of-n recovery path: if the charter key is
/// compromised, only a key named here can rotate the charter, and persist binds
/// the successor set's hash to this commitment. Callers pass the OTHER seated
/// holders — never a hard-coded pair.
pub fn charter_envelope(successors: &[String]) -> Result<serde_json::Value, GenesisError> {
    let commitment = pre_rotation_commitment(successors)
        .map_err(|e| GenesisError::CharterInvalid(format!("pre-rotation commitment: {e}")))?;
    Ok(serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): CHARTER_ATTESTATION_ID,
        "scope": CHARTER_SCOPES,
        CHARTER_PRE_ROTATION_FIELD: commitment,
        "successor_key_ids": successors,
    }))
}

/// Build the `infra:serve` grant envelope for one serve node (leg B of the edge
/// trace gate: the capability that must root to a trusted root).
pub fn grant_envelope(serve_key_id: &str) -> serde_json::Value {
    serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): format!("{GRANT_ATTESTATION_ID_PREFIX}:{serve_key_id}"),
        "scope": [INFRA_SERVE_SCOPE],
    })
}

/// Build the `accord:lifecycle:v1` liveness envelope for the charter root — the
/// FIFTH conjunct of `trust_root_valid`, and the one a v2 bundle was missing.
///
/// `trust_root_valid` is an AND over five things: `edge_exists`,
/// `root_self_declares`, `charter_has_recovery`, **`lifecycle_active`**, and
/// `!halt_latched`. A bundle can carry a perfect charter and perfect grants and
/// still produce a root that every capability walk rejects, because a root with no
/// live liveness row is indistinguishable from one nobody is attesting to.
///
/// The row is a `scores` attestation ABOUT the root (`attested_key_id = root`)
/// carrying this dimension, and persist requires an `accord_holder` attester for
/// the `accord:*` namespace — so at genesis the root, itself a seated holder,
/// scores itself.
///
/// **It expires.** `ACCORD_LIFECYCLE_FRESHNESS_DAYS` is 90, so this is not a
/// mint-once artifact: a bundle attached more than 90 days after it was produced
/// carries a row that no longer counts, and the root goes inert with no error at
/// the point of use. [`verify_bundle_structure`] refuses a stale bundle for that
/// reason, and a long-lived mesh needs the row re-minted on a cadence.
pub fn lifecycle_envelope() -> serde_json::Value {
    serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): LIFECYCLE_ATTESTATION_ID,
        (paths::DIMENSION): ACCORD_LIFECYCLE_DIMENSION,
    })
}

/// The liveness row carried by a bundle, if any: a `scores` row about the root
/// on the `accord:lifecycle:v1` dimension.
fn lifecycle_of<'a>(bundle: &'a GenesisBundle, root: &str) -> Option<&'a Attestation> {
    bundle
        .attestations
        .iter()
        .map(|a| &a.attestation)
        .find(|a| {
            a.attestation_type == attestation_type::SCORES
                && a.attested_key_id == root
                && a.attestation_envelope
                    .get(paths::DIMENSION)
                    .and_then(|v| v.as_str())
                    == Some(ACCORD_LIFECYCLE_DIMENSION)
        })
}

/// The key that chartered itself — the bundle's actual trust root, as opposed to
/// `family_key_id` (a grouping identifier that carries no authority).
pub fn charter_root_key_id(bundle: &GenesisBundle) -> Option<String> {
    charter_of(bundle).map(|c| c.attesting_key_id.clone())
}

/// Parse `quorum:M/N` into M. Returns `None` when absent/unparseable — callers
/// must treat that as "unknown", never as a default threshold.
fn policy_m(consensus_protocol: &str) -> Option<usize> {
    consensus_protocol
        .strip_prefix("quorum:")
        .and_then(ciris_verify_core::threshold::QuorumPolicy::parse)
        .map(|p| p.m)
}

/// The charter carried by a bundle, if any: the self-loop `delegates_to`.
fn charter_of(bundle: &GenesisBundle) -> Option<&Attestation> {
    bundle
        .attestations
        .iter()
        .map(|a| &a.attestation)
        .find(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attesting_key_id == a.attested_key_id
        })
}

fn scope_has(env: &serde_json::Value, want: &str) -> bool {
    match env.get("scope") {
        Some(serde_json::Value::String(s)) => s == want,
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(want)),
        _ => false,
    }
}

/// **Verify a bundle against itself, offline** — everything except the quorum
/// COUNT. Used mid-ceremony, where a partial legitimately carries fewer than M
/// authorizations but every other property must already hold: the charter is
/// well-formed, each serve node is blessed, rooted and granted, and every
/// authorization present is a genuine signature from a seated holder.
pub fn verify_bundle_structure(bundle: &GenesisBundle) -> Result<(), GenesisError> {
    if bundle.holders.is_empty() {
        return Err(GenesisError::NoHolders);
    }
    if bundle.serve_nodes.is_empty() {
        return Err(GenesisError::NoServeNode);
    }
    let holder_ids: Vec<&str> = bundle
        .holders
        .iter()
        .map(|h| h.record.key_id.as_str())
        .collect();
    for n in &bundle.serve_nodes {
        if !carries_infra_serve(n) {
            return Err(GenesisError::ServeNodeUnblessed(n.record.key_id.clone()));
        }
        // Self-verifying: the serve node's scrub must terminate in an anchor the
        // bundle itself carries.
        if !holder_ids.contains(&n.record.scrub_key_id.as_str()) {
            return Err(GenesisError::ServeNodeUnrooted(n.record.key_id.clone()));
        }
    }

    // ── The delegation plane. A v1 bundle (records only) is inert: attaching it
    // seeds keys with no authority. Reject it rather than hand anyone an artifact
    // that silently fails to unlock anything.
    let charter = charter_of(bundle).ok_or(GenesisError::NoCharter)?;
    let root = charter.attesting_key_id.as_str();
    if !holder_ids.contains(&root) {
        return Err(GenesisError::CharterInvalid(format!(
            "charter root {root} is not a holder carried in this bundle"
        )));
    }
    // The RC3 validity minimum: a root serves AND vouches, or it is inert.
    for want in [INFRA_SERVE_SCOPE, INFRA_ATTEST_SCOPE] {
        if !scope_has(&charter.attestation_envelope, want) {
            return Err(GenesisError::CharterInvalid(format!(
                "charter scope is missing {want} (the root minimum is \
                 {INFRA_SERVE_SCOPE} AND {INFRA_ATTEST_SCOPE})"
            )));
        }
    }
    // The KERI lesson, enforced here as well as at persist admission: without a
    // pre-rotation commitment, charter-key compromise is unrecoverable and the
    // attacker owns the tombstoning pen.
    let commitment = charter
        .attestation_envelope
        .get(CHARTER_PRE_ROTATION_FIELD)
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if commitment.len() != 64 || !commitment.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(GenesisError::CharterInvalid(format!(
            "charter carries no well-formed {CHARTER_PRE_ROTATION_FIELD} (64 hex)"
        )));
    }

    // Every serve node needs an infra:serve grant FROM the charter root, or its
    // capability does not root to the trust root (edge trace-gate leg B).
    for n in &bundle.serve_nodes {
        let granted = bundle.attestations.iter().map(|a| &a.attestation).any(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attesting_key_id == root
                && a.attested_key_id == n.record.key_id
                && scope_has(&a.attestation_envelope, INFRA_SERVE_SCOPE)
        });
        if !granted {
            return Err(GenesisError::ServeNodeUngranted(n.record.key_id.clone()));
        }
    }

    // ── The fifth conjunct. A charter and grants make the root DECLARED; the
    // liveness row makes it COUNT. Checked here rather than left to the walk,
    // because the walk's failure mode is a silent `false` at the point of use —
    // by which time the operator is debugging a dark trace plane, not a bad
    // bundle. Refuse the artifact instead.
    let lifecycle = lifecycle_of(bundle, root).ok_or(GenesisError::NoLifecycle)?;
    let age = chrono::Utc::now().signed_duration_since(lifecycle.asserted_at);
    if age > chrono::Duration::days(ACCORD_LIFECYCLE_FRESHNESS_DAYS) {
        return Err(GenesisError::LifecycleStale {
            asserted_at: lifecycle.asserted_at.to_rfc3339(),
            max_age_days: ACCORD_LIFECYCLE_FRESHNESS_DAYS,
        });
    }

    // ── The m-of-n proof. M comes from the family policy the bundle carries, but
    // is floored at a strict majority of the holders present so a tampered policy
    // string cannot talk the threshold down.
    let carried_m = policy_m(&bundle.consensus_protocol).ok_or_else(|| {
        GenesisError::AuthorizationInvalid(format!(
            "bundle carries no parseable consensus_protocol (got {:?}) — a verifier \
             must not guess how many holders authorized this",
            bundle.consensus_protocol
        ))
    })?;
    let _ = carried_m; // the COUNT gate lives in `verify_bundle`; parse here only
                       // so a bundle with an unreadable policy fails early.

    let digest = authorization_digest(bundle)?;
    let mut seen: Vec<&str> = Vec::new();
    for auth in &bundle.authorizations {
        let holder = bundle
            .holders
            .iter()
            .find(|h| h.record.key_id == auth.holder_key_id)
            .ok_or_else(|| {
                GenesisError::AuthorizationInvalid(format!(
                    "{} is not a holder carried in this bundle",
                    auth.holder_key_id
                ))
            })?;
        if seen.contains(&auth.holder_key_id.as_str()) {
            return Err(GenesisError::AuthorizationInvalid(format!(
                "duplicate authorization from {} — m-of-n counts DISTINCT holders",
                auth.holder_key_id
            )));
        }
        ciris_persist::verify::verify_hybrid(
            &digest,
            &auth.signature_classical,
            Some(&auth.signature_pqc),
            &holder.record.pubkey_ed25519_base64,
            holder.record.pubkey_ml_dsa_65_base64.as_deref(),
            ciris_persist::verify::HybridPolicy::Strict,
            None,
        )
        .map_err(|e| {
            GenesisError::AuthorizationInvalid(format!(
                "{}: hybrid-verify failed: {e}",
                auth.holder_key_id
            ))
        })?;
        seen.push(auth.holder_key_id.as_str());
    }
    Ok(())
}

/// How many distinct holder authorizations this bundle still needs: the family's
/// entrenched M, floored at a strict majority of the holders carried (so a
/// tampered policy string cannot talk the threshold down).
pub fn authorizations_needed(bundle: &GenesisBundle) -> Result<usize, GenesisError> {
    let carried_m = policy_m(&bundle.consensus_protocol).ok_or_else(|| {
        GenesisError::AuthorizationInvalid(format!(
            "bundle carries no parseable consensus_protocol (got {:?})",
            bundle.consensus_protocol
        ))
    })?;
    Ok(
        carried_m.max(ciris_verify_core::accord_genesis::strict_majority(
            bundle.holders.len(),
        )),
    )
}

/// **The complete gate.** Structure + the m-of-n quorum: this is what an attach
/// runs, and what "the seed is ready" means. A bundle that passes here proves —
/// offline, against itself — that a quorum of seated holders minted a trust root
/// that can actually serve.
pub fn verify_bundle(bundle: &GenesisBundle) -> Result<(), GenesisError> {
    verify_bundle_structure(bundle)?;
    let needed = authorizations_needed(bundle)?;
    let have = bundle.authorizations.len();
    if have < needed {
        return Err(GenesisError::QuorumNotMet { have, needed });
    }
    Ok(())
}

/// **Produce** a genesis from caller-supplied serve records.
///
/// `serve_candidates` may be the baked genesis records, or the freshly re-blessed
/// output of the accord co-scrub ceremony — the source does not matter, the
/// invariant does: records not carrying `infra:serve` are dropped, and if that
/// leaves none, this REFUSES. A genesis that cannot serve is the persist#480
/// darkness in portable form, and emitting one would just relocate the outage.
#[allow(clippy::too_many_arguments)]
pub fn produce_genesis(
    family_key_id: &str,
    consensus_protocol: &str,
    serve_candidates: Vec<SignedKeyRecord>,
    attestations: Vec<SignedAttestation>,
    authorizations: Vec<GenesisAuthorization>,
    now_rfc3339: &str,
) -> Result<GenesisBundle, GenesisError> {
    let holders: Vec<SignedKeyRecord> =
        ciris_persist::federation::genesis::effective_accord_holder_records().into_owned();
    if holders.is_empty() {
        return Err(GenesisError::NoHolders);
    }
    // The narrowing IS the invariant — not a warning, a refusal.
    let serve_nodes: Vec<SignedKeyRecord> = serve_candidates
        .into_iter()
        .filter(carries_infra_serve)
        .collect();
    if serve_nodes.is_empty() {
        return Err(GenesisError::NoServeNode);
    }

    let bundle = GenesisBundle {
        version: GENESIS_VERSION,
        family_key_id: family_key_id.to_string(),
        consensus_protocol: consensus_protocol.to_string(),
        holders,
        serve_nodes,
        attestations,
        authorizations,
        produced_at: now_rfc3339.to_string(),
    };
    // Structure only: a freshly proposed bundle legitimately carries one
    // authorization and is completed by the co-signers.
    verify_bundle_structure(&bundle)?;
    Ok(bundle)
}

/// Convenience: produce from the BAKED canonical genesis records.
///
/// Today this REFUSES with [`GenesisError::NoServeNode`] — the baked
/// `canonical_seed.json` still ships `roles: []` (CIRISPersist#480), so no baked
/// canonical is blessed to serve. That refusal is the invariant doing its job: it
/// is exactly the condition that darks the live trace plane, caught before it can
/// be handed to anyone as an artifact. It starts succeeding the moment the seed
/// bakes an `infra:serve`-blessed canonical.
pub fn produce_genesis_from_baked(now_rfc3339: &str) -> Result<GenesisBundle, GenesisError> {
    let family = ciris_persist::federation::genesis::accord_family_genesis_record();
    let baked: Vec<SignedKeyRecord> =
        ciris_persist::federation::genesis::canonical_genesis_records().to_vec();
    // No charter, no grants, no authorizations: the baked seed carries records
    // only. It therefore cannot produce a VALID genesis even once #480 blesses a
    // canonical — a trust root has to be minted by a quorum of holders through the
    // seed ceremony (`/v1/accord/genesis/{propose,cosign}`), which is the point.
    produce_genesis(
        &family.family_key_id,
        "",
        baked,
        Vec::new(),
        Vec::new(),
        now_rfc3339,
    )
}

/// What an attach actually did.
#[derive(Debug, Serialize)]
pub struct AttachReport {
    pub family_key_id: String,
    pub holders_seeded: usize,
    pub serve_nodes_seeded: usize,
    /// The charter + grants written — the delegation plane. Zero here would mean
    /// the attach seeded keys with no authority (the v1 defect).
    pub attestations_seeded: usize,
    /// The root the caller should now sign `delegates_to(user → root)` against —
    /// the key that CHARTERED itself, never the family grouping id.
    /// Attaching seeds the RECORDS; the trust edge is the user's own signed act.
    pub trust_root_key_id: String,
}

/// **Attach** a genesis: verify it, then seed its records into the directory.
///
/// Deliberately does NOT write the `delegates_to(user → root)` trust edge — that is
/// the user's own signed act (the 2-phase user-signed path that mirrors the
/// owner-binding claim). Attaching makes the root and its serve node KNOWN; trusting
/// them stays an explicit, revocable choice.
pub async fn attach_genesis<D>(
    dir: &D,
    bundle: &GenesisBundle,
) -> Result<AttachReport, GenesisError>
where
    D: FederationDirectory + ?Sized,
{
    verify_bundle(bundle)?;

    for h in &bundle.holders {
        dir.put_public_key(h.clone())
            .await
            .map_err(|e| GenesisError::Directory(e.to_string()))?;
    }
    for n in &bundle.serve_nodes {
        dir.put_public_key(n.clone())
            .await
            .map_err(|e| GenesisError::Directory(e.to_string()))?;
    }

    // The delegation plane — the whole point of a v2 bundle. Seeding the KEYS
    // alone is what made a v1 genesis inert: the charter is what makes the root a
    // root (`trust_root_valid`), and the grants are what let a serve node's
    // capability root to it (edge trace-gate leg B). Writing these goes through
    // persist's real ingest gate, so a tampered charter is rejected HERE too,
    // independently of `verify_bundle` — defense in depth on the attach path.
    for a in &bundle.attestations {
        dir.put_attestation(a.clone())
            .await
            .map_err(|e| GenesisError::Directory(e.to_string()))?;
    }

    // The trust root is the key that CHARTERED itself — not the family grouping
    // id, which carries no authority and cannot be delegated to.
    let trust_root_key_id = charter_of(bundle)
        .map(|c| c.attesting_key_id.clone())
        .ok_or(GenesisError::NoCharter)?;

    Ok(AttachReport {
        attestations_seeded: bundle.attestations.len(),
        trust_root_key_id,
        family_key_id: bundle.family_key_id.clone(),
        holders_seeded: bundle.holders.len(),
        serve_nodes_seeded: bundle.serve_nodes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The #480 landing, asserted.** Two invariants meet here, and their
    /// interaction is the whole point:
    ///
    /// 1. CIRISPersist#480 baked `infra:serve` into `canonical_seed.json`, so the
    ///    baked canonical is no longer a dark serve node — the baked path clears
    ///    the `NoServeNode` refusal it used to hit (that darkened the trace plane).
    /// 2. But a serve-capable seed is STILL not a trust root: `produce_genesis`
    ///    refuses it with `NoCharter`, because a root must be minted by a QUORUM
    ///    of holders through the seed ceremony (`/v1/accord/genesis/{propose,cosign}`)
    ///    — never baked into a build. The baked path carries no delegation plane by
    ///    design, so it cannot fabricate authority no one signed.
    ///
    /// If #480 ever regresses, this fails with `NoServeNode` (back to a dark seed).
    /// If someone lets the baked path emit a chartered bundle, it stops being
    /// `NoCharter` — and a build would be minting trust roots with no ceremony.
    #[test]
    fn baked_seed_is_serve_capable_but_not_a_trust_root() {
        match produce_genesis_from_baked("2026-07-21T00:00:00Z") {
            Err(GenesisError::NoCharter) => {
                // Correct: #480 gave the baked canonical infra:serve (past the
                // NoServeNode gate), but only the ceremony mints a charter.
            }
            Err(GenesisError::NoServeNode) => panic!(
                "CIRISPersist#480 regressed: the baked canonical is dark again \
                 (roles: []), which darkens the trace plane"
            ),
            Err(e) => panic!("unexpected genesis error: {e}"),
            Ok(_) => panic!(
                "the baked path produced a CHARTERED genesis — a build must never \
                 mint a trust root; that is the quorum ceremony's job alone"
            ),
        }
    }

    /// **CIRISPersist#480 landed: the baked canonical is serve-capable.** The seed
    /// that ships in the build now carries `infra:serve` — the fresh-canonical
    /// darkness is closed at the source.
    #[test]
    fn baked_canonical_now_carries_infra_serve() {
        let baked = ciris_persist::federation::genesis::canonical_genesis_records();
        let Some(rec) = baked.first().cloned() else {
            return; // no baked canonical in this build
        };
        assert!(
            carries_infra_serve(&rec),
            "CIRISPersist#480 landed — the baked canonical must read as serve-capable"
        );
    }

    /// **CIRISPersist#486 guard (envelope-read).** The accord's conferral is
    /// attested INSIDE the scrub-signed `registration_envelope`; the producer
    /// leaves the top-level `KeyRecord.roles` empty. So a serve-capability check
    /// MUST read the envelope. If someone "simplifies" `carries_infra_serve` back
    /// to `record.roles` only, this fails — and the trace plane silently goes dark
    /// again, which is exactly how we got here. Built from a synthetic UNBLESSED
    /// record so it stays true regardless of what the baked seed carries.
    #[test]
    fn envelope_attested_role_is_seen_though_top_level_roles_is_empty() {
        let baked = ciris_persist::federation::genesis::canonical_genesis_records();
        let Some(mut rec) = baked.first().cloned() else {
            return; // no baked canonical in this build
        };
        // Strip every serve surface to get a genuinely UNBLESSED baseline.
        rec.record.roles.clear();
        rec.record.identity_type = "canonical,node".to_string();
        if let Some(o) = rec.record.registration_envelope.as_object_mut() {
            o.remove("roles");
        }
        assert!(
            !carries_infra_serve(&rec),
            "a record with no serve role on any surface must not read serve-capable"
        );
        // A conferral lands in the SIGNED envelope; top-level roles stays empty.
        rec.record
            .registration_envelope
            .as_object_mut()
            .expect("registration_envelope is a JSON object")
            .insert("roles".into(), serde_json::json!([INFRA_SERVE]));
        assert!(
            rec.record.roles.is_empty(),
            "top-level roles stays empty — the ENVELOPE is what carries the claim"
        );
        assert!(
            carries_infra_serve(&rec),
            "envelope-attested infra:serve must be seen even with top-level roles empty"
        );
    }

    #[test]
    fn verify_rejects_an_unrooted_serve_node() {
        // A bundle whose serve node scrubs to someone not in the bundle is not
        // self-verifying and must be refused.
        let holders =
            ciris_persist::federation::genesis::effective_accord_holder_records().into_owned();
        if holders.is_empty() {
            return; // no anchors compiled in this build; nothing to assert
        }
        let bundle = GenesisBundle {
            version: GENESIS_VERSION,
            family_key_id: "fam".into(),
            consensus_protocol: "quorum:2/3".into(),
            holders,
            serve_nodes: Vec::new(),
            attestations: Vec::new(),
            authorizations: Vec::new(),
            produced_at: "2026-07-21T00:00:00Z".into(),
        };
        assert!(matches!(
            verify_bundle(&bundle),
            Err(GenesisError::NoServeNode)
        ));
    }
}

// ── the v2 delegation-plane invariants ───────────────────────────────────────
//
// These run against hand-built bundles (no hardware): the point is the REFUSALS.
// The signing half is exercised end-to-end by `trust_root_qa`, which mints a
// portable root in software and drives both trace-gate legs.

#[cfg(test)]
mod v2_tests {
    use super::*;
    use ciris_persist::federation::types::attestation_type;

    /// Build records/attestations through serde rather than enumerating every
    /// substrate field — these fixtures exist to exercise the REFUSALS, and the
    /// signing half is covered end-to-end by `trust_root_qa`.
    fn record(key_id: &str, identity_type: &str, extra: serde_json::Value) -> SignedKeyRecord {
        let mut v = serde_json::json!({
            "key_id": key_id,
            "algorithm": "ed25519",
            "identity_type": identity_type,
            "identity_ref": key_id,
            "valid_from": "2026-07-01T00:00:00Z",
            "valid_until": null,
            "registration_envelope": {},
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_signature_pqc": null,
            "scrub_key_id": "",
            "scrub_timestamp": "2026-07-01T00:00:00Z",
            "pqc_completed_at": null,
            "persist_row_hash": "",
            "roles": [],
            "attestation_evidence": null,
            "pubkey_ed25519_base64": "AAAA",
            "pubkey_ml_dsa_65_base64": null,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, val) in e {
                o.insert(k.clone(), val.clone());
            }
        }
        SignedKeyRecord {
            record: serde_json::from_value(v).expect("KeyRecord fixture"),
        }
    }

    fn holder(key_id: &str) -> SignedKeyRecord {
        record(key_id, "accord_holder", serde_json::json!({}))
    }

    fn serve_node(key_id: &str, scrub: &str) -> SignedKeyRecord {
        record(
            key_id,
            "canonical,node",
            serde_json::json!({ "scrub_key_id": scrub, "roles": [INFRA_SERVE] }),
        )
    }

    fn att(id: &str, from: &str, to: &str, env: serde_json::Value) -> SignedAttestation {
        SignedAttestation {
            attestation: serde_json::from_value(serde_json::json!({
                "attestation_id": id,
                "attesting_key_id": from,
                "attested_key_id": to,
                "attestation_type": attestation_type::DELEGATES_TO,
                "attestation_envelope": env,
                "asserted_at": "2026-07-22T00:00:00Z",
                "original_content_hash": "",
                "scrub_signature_classical": "",
                "scrub_key_id": from,
                "scrub_timestamp": "2026-07-22T00:00:00Z",
                "persist_row_hash": "",
                "subject_key_ids": [],
                "cohort_scope": "federation",
                "tier": "federation",
            }))
            .expect("Attestation fixture"),
        }
    }

    /// A `scores` fixture. Separate from [`att`] because the liveness row is NOT a
    /// `delegates_to`, and because its `asserted_at` must be LIVE: `lifecycle_active`
    /// is freshness-windowed (90d), so a hard-coded date would turn every genesis
    /// test into a time bomb that starts failing ~90 days after it was written.
    fn scores_att(id: &str, from: &str, to: &str, env: serde_json::Value) -> SignedAttestation {
        let now = chrono::Utc::now().to_rfc3339();
        SignedAttestation {
            attestation: serde_json::from_value(serde_json::json!({
                "attestation_id": id,
                "attesting_key_id": from,
                "attested_key_id": to,
                "attestation_type": attestation_type::SCORES,
                "attestation_envelope": env,
                "asserted_at": now,
                "original_content_hash": "",
                "scrub_signature_classical": "",
                "scrub_key_id": from,
                "scrub_timestamp": now,
                "persist_row_hash": "",
                "subject_key_ids": [],
                "cohort_scope": "federation",
                "tier": "federation",
            }))
            .expect("scores Attestation fixture"),
        }
    }

    /// The fifth conjunct: a live `accord:lifecycle:v1` row about the root.
    fn good_lifecycle() -> SignedAttestation {
        scores_att(LIFECYCLE_ATTESTATION_ID, "A1", "A1", lifecycle_envelope())
    }

    fn bundle_with(attestations: Vec<SignedAttestation>) -> GenesisBundle {
        GenesisBundle {
            version: GENESIS_VERSION,
            family_key_id: "fam".to_string(),
            consensus_protocol: "quorum:2/3".to_string(),
            holders: vec![holder("A1"), holder("B1"), holder("C1")],
            serve_nodes: vec![serve_node("canon-1", "A1")],
            attestations,
            authorizations: Vec::new(),
            produced_at: "2026-07-22T00:00:00Z".to_string(),
        }
    }

    fn good_charter() -> SignedAttestation {
        att(
            CHARTER_ATTESTATION_ID,
            "A1",
            "A1",
            charter_envelope(&["B1".to_string(), "C1".to_string()]).unwrap(),
        )
    }

    fn good_grant() -> SignedAttestation {
        att(
            &format!("{GRANT_ATTESTATION_ID_PREFIX}:canon-1"),
            "A1",
            "canon-1",
            grant_envelope("canon-1"),
        )
    }

    /// The headline v1 defect: a records-only bundle attaches as keys with NO
    /// authority — `trust_root_valid` stays false and the capability gate stays
    /// shut. Refuse to emit one rather than hand someone an inert artifact.
    #[test]
    fn a_records_only_bundle_is_refused_as_inert() {
        let b = bundle_with(Vec::new());
        assert!(matches!(
            verify_bundle_structure(&b),
            Err(GenesisError::NoCharter)
        ));
    }

    /// The KERI lesson (CIRISPersist#488): a charter with no pre-rotation
    /// commitment makes charter-key compromise unrecoverable by construction.
    #[test]
    fn a_charter_without_pre_rotation_is_refused() {
        let naked = att(
            CHARTER_ATTESTATION_ID,
            "A1",
            "A1",
            serde_json::json!({ "scope": CHARTER_SCOPES }),
        );
        match verify_bundle_structure(&bundle_with(vec![naked, good_grant()])) {
            Err(GenesisError::CharterInvalid(d)) => {
                assert!(d.contains(CHARTER_PRE_ROTATION_FIELD), "got: {d}")
            }
            other => panic!("expected a pre-rotation refusal, got {other:?}"),
        }
    }

    /// The RC3 root minimum: a root that can vouch but never serve is inert.
    #[test]
    fn a_vouch_only_charter_is_refused() {
        let mut env = charter_envelope(&["B1".to_string()]).unwrap();
        env["scope"] = serde_json::json!([INFRA_ATTEST_SCOPE]);
        let vouch = att(CHARTER_ATTESTATION_ID, "A1", "A1", env);
        match verify_bundle_structure(&bundle_with(vec![vouch, good_grant()])) {
            Err(GenesisError::CharterInvalid(d)) => {
                assert!(d.contains(INFRA_SERVE_SCOPE), "got: {d}")
            }
            other => panic!("expected a root-minimum refusal, got {other:?}"),
        }
    }

    /// Leg B: without a grant the serve node's capability does not root to the
    /// trust root, so the trace gate would still fail-close after attach.
    #[test]
    fn a_serve_node_without_a_grant_is_refused() {
        match verify_bundle_structure(&bundle_with(vec![good_charter()])) {
            Err(GenesisError::ServeNodeUngranted(k)) => assert_eq!(k, "canon-1"),
            other => panic!("expected an ungranted-serve refusal, got {other:?}"),
        }
    }

    /// A charter minted by a key the bundle does not carry roots to nothing.
    #[test]
    fn a_charter_from_an_uncarried_key_is_refused() {
        let outsider = att(
            CHARTER_ATTESTATION_ID,
            "Z9",
            "Z9",
            charter_envelope(&["B1".to_string()]).unwrap(),
        );
        match verify_bundle_structure(&bundle_with(vec![outsider, good_grant()])) {
            Err(GenesisError::CharterInvalid(d)) => assert!(d.contains("Z9"), "got: {d}"),
            other => panic!("expected an uncarried-root refusal, got {other:?}"),
        }
    }

    /// Structurally sound but under-authorized: the ceremony is mid-flight, not
    /// finished. `verify_bundle` is what "the seed is ready" means.
    #[test]
    fn a_structurally_sound_bundle_still_needs_the_quorum() {
        let b = bundle_with(vec![good_charter(), good_grant(), good_lifecycle()]);
        assert!(verify_bundle_structure(&b).is_ok(), "structure holds");
        match verify_bundle(&b) {
            Err(GenesisError::QuorumNotMet { have, needed }) => {
                assert_eq!(have, 0);
                assert_eq!(needed, 2, "quorum:2/3 over 3 holders");
            }
            other => panic!("expected QuorumNotMet, got {other:?}"),
        }
    }

    /// Anti-downgrade: a tampered policy string cannot talk the threshold below a
    /// strict majority of the holders the bundle actually carries.
    #[test]
    fn a_downgraded_policy_cannot_lower_the_threshold() {
        let mut b = bundle_with(vec![good_charter(), good_grant()]);
        b.consensus_protocol = "quorum:1/3".to_string();
        assert_eq!(
            authorizations_needed(&b).unwrap(),
            2,
            "1-of-3 is floored at a strict majority of the 3 carried holders"
        );
    }

    /// THE FIFTH CONJUNCT. A bundle with a perfect charter and perfect grants is
    /// still inert without a live `accord:lifecycle:v1` row: `trust_root_valid`
    /// ANDs `lifecycle_active` in, so the walk returns false at the point of USE —
    /// a dark trace plane, not a bad-bundle error. Refuse the artifact instead.
    #[test]
    fn a_bundle_without_a_liveness_row_is_refused() {
        match verify_bundle_structure(&bundle_with(vec![good_charter(), good_grant()])) {
            Err(GenesisError::NoLifecycle) => {}
            other => panic!("expected a missing-liveness refusal, got {other:?}"),
        }
    }

    /// The row EXPIRES. A bundle minted long ago carries a row that no longer
    /// counts, so attaching it would produce a root that silently fails the walk.
    #[test]
    fn a_stale_liveness_row_is_refused() {
        let mut stale = good_lifecycle();
        stale.attestation.asserted_at =
            chrono::Utc::now() - chrono::Duration::days(ACCORD_LIFECYCLE_FRESHNESS_DAYS + 1);
        match verify_bundle_structure(&bundle_with(vec![good_charter(), good_grant(), stale])) {
            Err(GenesisError::LifecycleStale { max_age_days, .. }) => {
                assert_eq!(max_age_days, ACCORD_LIFECYCLE_FRESHNESS_DAYS)
            }
            other => panic!("expected a stale-liveness refusal, got {other:?}"),
        }
    }

    /// A verifier must never GUESS the threshold.
    #[test]
    fn an_unparseable_policy_is_refused_not_defaulted() {
        let mut b = bundle_with(vec![good_charter(), good_grant(), good_lifecycle()]);
        b.consensus_protocol = String::new();
        assert!(matches!(
            verify_bundle_structure(&b),
            Err(GenesisError::AuthorizationInvalid(_))
        ));
    }
}
