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
    pre_rotation_commitment, ACCORD_HEARTBEAT_DIMENSION, CHARTER_PRE_ROTATION_FIELD,
    INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
};
use ciris_persist::federation::types::delegation_scope::INFRA_SERVE;
use ciris_persist::federation::types::{attestation_type, Attestation, SignedAttestation};
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use serde::Serialize;
use sha2::Digest as _;

/// Wire version of the genesis bundle. Bump on any breaking shape change.
///
/// **v2** (the seed ceremony) adds the *delegation plane*: a v1 bundle carried
/// only key records, so attaching it produced keys with **no authority** — no
/// charter meant `trust_root_valid` stayed false and the capability gate stayed
/// shut. v2 carries the charter + grants that make the root an actual root, and
/// the m-of-n holder authorizations that prove a quorum minted it.
pub const GENESIS_VERSION: u32 = 2;

// ── ONE bundle type, ONE digest. ────────────────────────────────────────────
//
// persist v23.0.0 owns `GenesisBundle`, `GenesisAuthorization` and
// `authorization_digest` — its doc credits "producer's construction (CIRISServer
// mesh_genesis)", i.e. it adopted the shape we produced. We re-export rather than
// redeclare.
//
// This is not tidiness. A duplicated bundle type is two field lists that must
// agree, and a duplicated `authorization_digest` is worse: the m-of-n holder
// signatures are taken OVER that digest, so two implementations drifting by a
// byte silently invalidates a ceremony's quorum. That is the same
// two-things-that-must-agree class as CIRISPersist#541 (preserve set vs verified
// set) and #547 (advertised hash vs indexed hash), and the cure is the same —
// have one.
pub use ciris_persist::federation::genesis::bundle::authorization_digest;
pub use ciris_persist::federation::genesis::{GenesisAuthorization, GenesisBundle};

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
/// Verify materializes `ScrubTarget.roles` (materialized into `capability_roles`) into the scrub-signed
/// `registration_envelope` (v10.5.0 — "attested by this scrub"), so THAT is where an
/// accord-conferred capability actually lives. persist does not yet lift those into
/// the top-level `KeyRecord.capability_roles` that `claims_role` reads (**CIRISPersist#486**),
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
        || rec.record.capability_roles.iter().any(|r| r == INFRA_SERVE)
}

/// Does this record carry ONE named scope on the co-scrub plane?
///
/// Generalization of [`carries_infra_serve`], reading the same three surfaces.
pub fn carries_scope(rec: &SignedKeyRecord, scope: &str) -> bool {
    use ciris_persist::federation::types::identity_type;
    rec.record
        .registration_envelope
        .get("roles")
        .and_then(|v| v.as_array())
        .is_some_and(|a| a.iter().any(|r| r.as_str() == Some(scope)))
        || identity_type::set_contains(&rec.record.identity_type, scope)
        || rec.record.capability_roles.iter().any(|r| r == scope)
}

/// Does this record already confer EVERY scope a canonical needs?
///
/// The re-bless predicate. It must ask about the whole set, not one member:
/// through 0.5.141 the ceremony asked `carries_infra_serve`, so a record already
/// carrying `infra:serve` was treated as fully blessed and reused VERBATIM — and
/// because `roles` lives inside the scrub-SIGNED `registration_envelope`, the
/// three new scopes could never enter it. The delegation plane got all four
/// (it is minted fresh each ceremony) while the co-scrub plane silently kept
/// one. Exactly the axis split [`SERVE_NODE_SCOPES`] exists to prevent, caught
/// on the genesis_3 candidate by the both-planes gate.
pub fn carries_all_serve_scopes(rec: &SignedKeyRecord) -> bool {
    SERVE_NODE_SCOPES.iter().all(|s| carries_scope(rec, s))
}

// ─────────────────────────────────────────────────────────────────────────────
// The delegation plane: charter, grants, and the m-of-n authorization digest.
// ─────────────────────────────────────────────────────────────────────────────

/// Attestation id of the charter within a bundle (stable, content-independent —
/// the bundle carries exactly one).
pub const CHARTER_ATTESTATION_ID: &str = "genesis-charter";
/// Prefix for the per-serve-node capability grant ids.
///
/// Named `genesis-grant` and **not** `genesis-grant-serve`: the grant confers
/// [`SERVE_NODE_SCOPES`], which is more than `serve`. An id that names one of
/// the scopes it carries is the "one name, two things" trap — a reader greps
/// `-serve` and concludes serve is all it grants.
pub const GRANT_ATTESTATION_ID_PREFIX: &str = "genesis-grant";

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
    INFRA_STORE_SCOPE,
    INFRA_TRANSPORT_SCOPE,
];

/// `infra:store` — persist / store data as infrastructure.
pub const INFRA_STORE_SCOPE: &str = ciris_persist::federation::types::delegation_scope::INFRA_STORE;
/// `infra:transport` — relay / transport traffic as infrastructure.
pub const INFRA_TRANSPORT_SCOPE: &str =
    ciris_persist::federation::types::delegation_scope::INFRA_TRANSPORT;

/// The scopes a genesis grant confers on a **canonical serve node** — the
/// accord's own infrastructure, so it gets the full infra charter set.
///
/// Each is a DIFFERENT authority, and a canonical exercises all four at 1.0
/// (registry + node folded in):
///
/// | scope | what it authorizes |
/// |---|---|
/// | `infra:serve` | answer requests — trace ingest, the API, handing out manifests and cards. Edge's trace gate (`SERVE_CAPABILITY`) keys on exactly this. |
/// | `infra:attest` | **vouch.** The registry does not merely hand you a manifest, it attests the manifest is authentic. Serving bytes and standing behind them are separate authorities. |
/// | `infra:store` | hold bulk content on behalf of the mesh (Wikipedia and friends) — custody of data that is not the node's own attestations. |
/// | `infra:transport` | relay OTHER nodes' traffic. Load-bearing for a canonical specifically: it carries the `transport_hints` every new node dials, so it relays for peers that cannot reach each other directly. |
///
/// Equal to [`CHARTER_SCOPES`] today, and deliberately written as its own
/// constant rather than aliased: the charter is the accord's *ceiling* and this
/// is what one node is *granted*. They coincide for a canonical (accord-operated
/// infrastructure) and must not for a personal node, which gets `infra:serve`
/// alone. Fusing them would make "what may a root grant" and "what does this
/// node get" one name answering two questions.
///
/// Deliberately ABSENT, same reason as the charter: `infra:network_presence` and
/// the `hold_*_membership` scopes are owner-granted, never root-granted.
///
/// **Both conferral planes must carry this set.** The delegation plane reads the
/// grant's `scope` ([`grant_envelope`]); the co-scrub plane reads the key
/// record's `registration_envelope.roles` (`ScrubTarget.roles`, set in
/// `accord_provision`). Through 0.5.141 both carried `[infra:serve]` alone, so
/// `capability_roots_to_trusted_root(.., "infra:attest")` returned `None` and
/// `has_accord_conferred_role(.., "infra:attest")` returned `false` on the real
/// baked root — invisible because every test asked only for `infra:serve`.
pub const SERVE_NODE_SCOPES: &[&str] = &[
    INFRA_SERVE_SCOPE,
    INFRA_ATTEST_SCOPE,
    INFRA_STORE_SCOPE,
    INFRA_TRANSPORT_SCOPE,
];

/// concession). Rendered on the card for exactly that comparison.
pub fn fingerprint(bundle: &GenesisBundle) -> Result<String, GenesisError> {
    let d = authorization_digest(bundle)
        .map_err(|e| GenesisError::CharterInvalid(format!("digest: {e}")))?;
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

/// Build the capability grant envelope for one serve node — the DELEGATION
/// plane (edge trace-gate leg B: the capability that must root to a trusted
/// root).
///
/// Confers [`SERVE_NODE_SCOPES`], not `infra:serve` alone. The co-scrub plane
/// must confer the SAME set via `ScrubTarget.roles`; a node that resolves a
/// scope on one plane and not the other is the axis split this project keeps
/// paying for.
pub fn grant_envelope(serve_key_id: &str) -> serde_json::Value {
    serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): format!("{GRANT_ATTESTATION_ID_PREFIX}:{serve_key_id}"),
        "scope": SERVE_NODE_SCOPES,
    })
}

/// Build the accord **heartbeat** envelope for the trust root.
///
/// The heartbeat is a LIVENESS SIGNAL, never a validity gate. `trust_root_valid`
/// is an AND over four things — `edge_exists`, `root_self_declares`,
/// `charter_has_recovery`, `!halt_latched` — and liveness is not among them.
/// persist reports it separately as a banded `drill_freshness`, so an old or
/// absent heartbeat degrades a displayed signal rather than invalidating a root.
/// That is what lets a seed be durable: valid until revoked, withdrawn or
/// superseded.
///
/// The row is a `scores` attestation ABOUT the root (`attested_key_id = root`)
/// carrying this dimension, and persist requires an `accord_holder` attester for
/// the `accord:*` namespace — so at genesis the root, itself a seated holder,
/// scores itself.
///
/// Mint it at ceremony time and re-mint it when a mesh wants a fresh drill
/// signal. Nothing breaks if you do not: consumers show the band as stale.
pub fn lifecycle_envelope() -> serde_json::Value {
    serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): LIFECYCLE_ATTESTATION_ID,
        (paths::DIMENSION): ACCORD_HEARTBEAT_DIMENSION,
    })
}

/// The heartbeat carried by a bundle, if any: a `scores` row about the trust
/// root on the accord-heartbeat dimension.
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
                    == Some(ACCORD_HEARTBEAT_DIMENSION)
        })
}

/// The bundle's trust root — what a node writes its `trust:accepts` edge to.
///
/// v24.0.0 (CIRISPersist#557): this is the charter's **attested** subject, not
/// its attester. A family charter is `delegates_to(holder -> family)` carried in
/// the ABOUT set, so the root is the family id (`humanity-accord`) and the
/// signing holder is merely one seat of the roster that chartered it.
///
/// A solo 1-of-1 root remains legitimate and self-loops (`A1 -> A1`), so reading
/// `attested_key_id` is correct for BOTH arms — it is the attester only in the
/// degenerate case where they coincide.
pub fn charter_root_key_id(bundle: &GenesisBundle) -> Option<String> {
    charter_of(bundle).map(|c| c.attested_key_id.clone())
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
    // Identified by its ATTESTATION ID, not by a self-loop. Through 0.5.141 this
    // matched `attesting_key_id == attested_key_id`, which silently stops finding
    // the charter the moment it is family-shaped (`A1 -> humanity-accord`) — and
    // "no charter" is a LOUD SKIP at boot, so the failure would have looked like
    // an unminted mesh rather than a mis-shaped one.
    bundle
        .attestations
        .iter()
        .map(|a| &a.attestation)
        .find(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attestation_id == CHARTER_ATTESTATION_ID
        })
}

/// Is this directory error "the row is already there", as opposed to a real
/// failure? Matched on the message because persist returns a stringly-typed
/// conflict here; a false negative degrades to the old fail-loud behaviour, which
/// is the safe direction.
fn is_already_exists(e: &impl std::fmt::Display) -> bool {
    let m = e.to_string();
    m.contains("already exists")
        || m.contains("conflicts with existing row")
        // sqlite / postgres surface a duplicate attestation_id this way
        || m.contains("UNIQUE constraint failed")
        || m.contains("duplicate key value")
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
    // TWO different questions, and under family rooting they have two different
    // answers — so two names. `root` answered both and was the ATTESTER, which
    // made the heartbeat check look for a drill about A1 while the drill is about
    // the family: a false "carries no accord heartbeat" warning on a bundle whose
    // heartbeat is exactly right. Third instance of attester-vs-attested in this
    // file; the first two were charter_of and charter_root_key_id.
    let charter_signer = charter.attesting_key_id.as_str(); // WHO signed the charter
    let trust_root = charter.attested_key_id.as_str(); // WHAT the charter charters
    if !holder_ids.contains(&charter_signer) {
        return Err(GenesisError::CharterInvalid(format!(
            "charter signer {charter_signer} is not a holder carried in this bundle"
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

    // Every serve node needs an infra:serve grant, or its capability does not root
    // to the trust root (edge trace-gate leg B).
    //
    // Matched on the charter's SIGNER, not on the trust root: persist v24 keeps the
    // grant as `holder -> subject` and DERIVES the family from the verified signer
    // set, because a keyless family cannot sign and a granter field naming it would
    // be attribution-by-claim. So the grant is signed by a seated holder; reaching
    // the threshold is what makes it the family's act.
    for n in &bundle.serve_nodes {
        let granted = bundle.attestations.iter().map(|a| &a.attestation).any(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attesting_key_id == charter_signer
                && a.attested_key_id == n.record.key_id
                && scope_has(&a.attestation_envelope, INFRA_SERVE_SCOPE)
        });
        if !granted {
            return Err(GenesisError::ServeNodeUngranted(n.record.key_id.clone()));
        }
    }

    // ── The accord heartbeat: MINTED, but never a gate. ──────────────────────
    //
    // persist v23.0.0 (CIRISPersist#551 item 4) removed liveness from validity:
    //
    //     let valid = edge_exists && root_self_declares
    //                 && charter_has_recovery && halt_latched != Some(true);
    //
    // `lifecycle_active: bool` became a banded `drill_freshness`, "reported
    // beside the verdict, not enforced inside it". That is the right call and it
    // is what makes a seed DURABLE: an artifact valid until revoked / withdrawn /
    // superseded, rather than one that silently expires 90 days after the mint
    // and takes every node with it.
    //
    // So we mint the heartbeat (it is a real trust signal — CIRISServer#332 asks
    // the trust card to surface the band) and we DO NOT refuse a bundle for its
    // absence or its age. A pre-v23 build of this file did refuse, which would
    // now reject bundles persist considers perfectly valid.
    if lifecycle_of(bundle, trust_root).is_none() {
        tracing::warn!(
            trust_root,
            "genesis bundle carries no accord heartbeat about the trust root. NOT fatal — \
             v23 reports liveness as a band beside the verdict rather than gating on it — but \
             consumers will show this root's drill-freshness as unknown/red until one exists."
        );
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

    let digest = authorization_digest(bundle)
        .map_err(|e| GenesisError::CharterInvalid(format!("digest: {e}")))?;
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
        ciris_persist::federation::genesis::canonical_genesis_bundle()
            .serve_nodes
            .clone();
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

/// **Stage 1b** — write this node's `trust:accepts` edge to a bundle's trust root.
///
/// This is the node's OWN signed act, and the whole reason stage 1 is two steps.
/// It cannot ride in the bundle: the row's `attesting_key_id` is this node, whose
/// key does not exist when a seed is baked. Recognition can be shipped;
/// acceptance can only be signed.
///
/// It is **default trust, not consent** — the constitution already says a fresh
/// node trusts `ciris-canonical` — so boot performs it without asking. What makes
/// that safe is that it stays one deletable row:
///
/// > delete it → `trust_root_valid` false → the walk returns `None` → the serve
/// > gate withholds → agent capabilities gate off → manifests stop.
///
/// Every one of those is emergent. None is special-cased, and nothing may replace
/// this row with a universal rule, or un-trust stops being expressible.
///
/// Idempotent, and a no-op when this node IS the root (a self-loop charter already
/// says so, and `trust_root_valid` requires `root != user`).
///
/// Returns the accepted root's `key_id`, or `None` when there was nothing to
/// accept.
pub async fn accept_trust_root(
    engine: &ciris_persist::prelude::Engine,
    bundle: &GenesisBundle,
) -> Result<Option<String>, GenesisError> {
    use ciris_persist::federation::types::cohort_scope;
    use ciris_persist::federation::EmitAttestationInput;

    let Some(root) = charter_root_key_id(bundle) else {
        return Ok(None);
    };
    let node_key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| GenesisError::Directory(format!("resolve node identity: {e}")))?;
    if node_key_id == root {
        return Ok(None);
    }
    if node_trusts_root(engine, &node_key_id, &root).await? {
        tracing::debug!(root, "trust root already accepted — no-op");
        return Ok(Some(root));
    }

    let id = format!("trust-edge:{node_key_id}:{root}");
    let envelope = serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): id,
        // Trust the root for exactly what a root is for. Attenuation does the
        // rest: the node can never exercise more than the charter holds.
        "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
    });
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::DELEGATES_TO,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
            .map_err(|e| GenesisError::CharterInvalid(e.to_string()))?,
        // Federation-visible: the mesh must be able to verify this node's anchoring.
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(root.clone());
    engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| GenesisError::Directory(format!("write trust:accepts: {e}")))?;
    tracing::info!(
        node_key_id = %node_key_id,
        trust_root = %root,
        "trust root ACCEPTED — this node now accepts the root's authority. Delete this \
         attestation to un-trust (the capability cascade then fails closed on its own)."
    );
    Ok(Some(root))
}

/// Has this node already accepted `root`? Idempotency for [`accept_trust_root`].
async fn node_trusts_root(
    engine: &ciris_persist::prelude::Engine,
    node_key_id: &str,
    root: &str,
) -> Result<bool, GenesisError> {
    let rows = engine
        .federation_directory()
        .list_attestations_by(node_key_id)
        .await
        .map_err(|e| GenesisError::Directory(e.to_string()))?;
    Ok(rows
        .iter()
        .any(|a| a.attestation_type == attestation_type::DELEGATES_TO && a.attested_key_id == root))
}

/// **Stage 1** — install the BAKED trust root and accept it. Called at boot.
///
/// The full happy-path stage 1 (`FSD/GENESIS_TO_SCORE.md`): a node ships with the
/// baked bundle, installs its records, and accepts its root. After this
/// `trust_root_valid` holds and the serve gate can resolve.
///
/// A bundle with no charter is a clean, LOUD skip rather than an error: persist
/// ships a bundle-shaped seed that is empty until a ceremony fills it, and a node
/// booting against an unminted mesh is a legitimate state — it simply cannot serve
/// traces yet, and should say so once at boot rather than fail 200 frames later.
pub async fn install_baked_trust_root(
    engine: &std::sync::Arc<ciris_persist::prelude::Engine>,
) -> Result<(), GenesisError> {
    let bundle = ciris_persist::federation::genesis::canonical_genesis_bundle();
    if charter_root_key_id(bundle).is_none() {
        tracing::warn!(
            serve_nodes = bundle.serve_nodes.len(),
            holders = bundle.holders.len(),
            attestations = bundle.attestations.len(),
            "baked trust-root bundle carries NO charter — nothing to install. This node has \
             no trust root, so `capability_roots_to_trusted_root` cannot resolve and it will \
             withhold every trace:* row. Expected on an unminted mesh; run the genesis \
             ceremony (FSD/GENESIS_TO_SCORE.md stage 0)."
        );
        return Ok(());
    }
    // ORDERING CONTRACT (persist v24.0.0 / CIRISPersist#557, #386): holders ->
    // family -> everything else. The keyless HUMANITY_ACCORD family row must
    // exist before the charter that attests it, or `lookup_family` returns None,
    // `resolve_family_root` yields None, and `trust_root_valid` reports
    // RootKind::Key — a correctly family-chartered bundle would degrade SILENTLY
    // to a single-seat root rather than erroring.
    //
    // PERSIST ALREADY GUARANTEES IT. `seed_family_and_canonical` calls
    // `seed_accord_family` + `verify_family_seeded` (genesis/mod.rs:588), and
    // Engine construction calls that (engine.rs:6250 pg / 6303 sqlite). Stage 1
    // takes an `&Arc<Engine>`, so the Engine — and therefore the family row —
    // provably exists before we get here. No call is needed.
    //
    // 0.5.144 added one anyway, with a comment claiming "nothing called it before
    // now". That was false, and the grep that produced it excluded the file
    // holding the answer: `grep seed_accord_family --include=*.rs src/ | grep -v
    // genesis/mod.rs`. The call site is IN genesis/mod.rs. Same shape as the
    // `*.log` glob that skipped a rotated file and returned a zero read as
    // evidence of absence — see FSD/RCA_TRACE_PLANE_2026-07-31.md heuristic 1.
    // Removed rather than left redundant-but-harmless: a call carrying a false
    // justification is worse than no call, because the next reader trusts it.
    let dir = engine.federation_directory();

    let report = install_trust_root_records(dir.as_ref(), bundle).await?;
    let accepted = accept_trust_root(engine, bundle).await?;

    // VERIFY THE CLAIM. The caller's failure path says "this node has no trust
    // root and will withhold every trace:* row" — a consequence, asserted without
    // ever being checked. On the production canonical that fired while the
    // charter, grant, trust edge and heartbeat were all present and correct.
    //
    // `trust_root_valid` is the same predicate the serve gate consults, so this is
    // the honest answer to "can this node serve?" rather than one inferred from
    // whether an idempotent install returned Ok.
    let verdict = match (&accepted, engine.local_derived_key_id().await) {
        (Some(root), Ok(node)) => ciris_persist::federation::trust_root::trust_root_valid(
            engine.federation_directory().as_ref(),
            &node,
            root,
        )
        .await
        .ok(),
        _ => None,
    };
    match &verdict {
        Some(v) if v.valid => tracing::info!(
            holders_seeded = report.holders_seeded,
            serve_nodes_seeded = report.serve_nodes_seeded,
            attestations_seeded = report.attestations_seeded,
            accepted_root = ?accepted,
            root_kind = ?v.root_kind,
            drill = ?v.drill_freshness,
            "stage 1 complete — trust root installed, accepted, and VERIFIED valid"
        ),
        Some(v) => tracing::error!(
            accepted_root = ?accepted,
            verdict = ?v,
            "stage 1 ran but the trust root is NOT valid — this node WILL withhold every \
             trace:* row. The verdict names which conjunct failed."
        ),
        None => tracing::warn!(
            accepted_root = ?accepted,
            "stage 1 ran but the trust root could not be evaluated — serve-gate state unknown"
        ),
    }
    Ok(())
}

/// **Stage 1a** — verify a bundle and install its records into the directory.
///
/// Installs holders, serve nodes, and the delegation plane (`trust:charter` +
/// `trust:confers`). After this the trust root and its serve nodes are KNOWN.
///
/// Deliberately does NOT write this node's `trust:accepts` edge — see
/// [`accept_trust_root`]. A bundle may seed records; it may never assign a
/// stranger a trust root. Knowing a root and accepting it are separate acts, and
/// keeping them separate is what leaves the operator a lever to delete.
pub async fn install_trust_root_records<D>(
    dir: &D,
    bundle: &GenesisBundle,
) -> Result<AttachReport, GenesisError>
where
    D: FederationDirectory + ?Sized,
{
    verify_bundle(bundle)?;

    // A key record that ALREADY EXISTS is not a reason to abandon the install.
    //
    // Engine construction seeds the baked genesis, so on any node that has booted
    // before, the holder and canonical rows are already present. When a re-minted
    // bundle re-blesses the canonical, its record differs from the seeded one (new
    // roles inside the scrub-signed envelope) and persist rightly refuses to
    // replace an anchored row — `put_public_key` returns a conflict.
    //
    // That conflict used to be `?`-propagated, so ONE pre-existing record aborted
    // the WHOLE of stage 1: the charter and the grants — the entire delegation
    // plane, the part that is genuinely new — never got installed, and the node
    // came up with no trust root at all. Seen in the field as
    // "stage 1 (baked trust root) FAILED ... key_id <canonical> already exists with
    // different content", on a node whose only problem was that it had booted
    // before.
    //
    // The identity plane is idempotent-or-already-correct; the delegation plane is
    // what stage 1 exists to install. So a conflict is reported and stepped over,
    // and any OTHER directory error still fails loudly.
    let mut identity_conflicts: Vec<String> = Vec::new();
    for rec in bundle.holders.iter().chain(bundle.serve_nodes.iter()) {
        match dir.put_public_key(rec.clone()).await {
            Ok(()) => {}
            Err(e) if is_already_exists(&e) => {
                identity_conflicts.push(rec.record.key_id.clone());
            }
            Err(e) => return Err(GenesisError::Directory(e.to_string())),
        }
    }
    if !identity_conflicts.is_empty() {
        tracing::warn!(
            records = ?identity_conflicts,
            "genesis install: these key records already exist with different content and were \
             NOT replaced (persist refuses to replace an anchored row). The delegation plane \
             below still installs. If this bundle re-blessed a canonical, that node keeps its \
             OLDER capability roles on the CO-SCRUB plane until the new record is the baked one \
             — the delegation plane carries the new scopes either way."
        );
    }

    // The delegation plane — the whole point of a v2 bundle. Seeding the KEYS
    // alone is what made a v1 genesis inert: the charter is what makes the root a
    // root (`trust_root_valid`), and the grants are what let a serve node's
    // capability root to it (edge trace-gate leg B). Writing these goes through
    // persist's real ingest gate, so a tampered charter is rejected HERE too,
    // independently of `verify_bundle` — defense in depth on the attach path.
    // Same tolerance as the identity plane above, and for a stronger reason:
    // genesis attestation ids are STABLE (`genesis-charter`,
    // `genesis-grant:<node>`, `genesis-lifecycle`), so the SECOND boot of any node
    // re-inserts rows it already has and hits
    // `UNIQUE constraint failed: federation_attestations.attestation_id`.
    //
    // That aborted stage 1 on EVERY reboot after the first successful install, and
    // the caller then logged "this node has no trust root and will withhold every
    // trace:* row" — a consequence it never checked. Observed on the production
    // canonical, whose charter, grant, trust edge and heartbeat were all present
    // and correct. It sent people hunting a delivery bug that did not exist.
    let mut attestation_conflicts: Vec<String> = Vec::new();
    for a in &bundle.attestations {
        match dir.put_attestation(a.clone()).await {
            Ok(()) => {}
            Err(e) if is_already_exists(&e) => {
                attestation_conflicts.push(a.attestation.attestation_id.clone());
            }
            Err(e) => return Err(GenesisError::Directory(e.to_string())),
        }
    }
    if !attestation_conflicts.is_empty() {
        tracing::debug!(
            attestations = ?attestation_conflicts,
            "genesis install: already present (normal on any boot after the first — genesis \
             attestation ids are stable). Not replaced; persist refuses to overwrite. If this \
             bundle SUPERSEDES an older bake, the node keeps the older rows until superseded."
        );
    }

    // The root is the charter's ATTESTED subject, matching `charter_root_key_id`
    // and the `trust:accepts` edge. Under family rooting that is the family id;
    // for a solo root the charter self-loops, so the two coincide.
    //
    // Was `attesting_key_id` through 0.5.141, which reported the SIGNING HOLDER
    // as the trust root — so the install log said `root=A1` on a bundle whose
    // root is `humanity-accord`, and this report is what an operator reads to
    // confirm what they just installed.
    let trust_root_key_id = charter_of(bundle)
        .map(|c| c.attested_key_id.clone())
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
        let baked = ciris_persist::federation::genesis::canonical_genesis_bundle()
            .serve_nodes
            .as_slice();
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
    /// leaves the top-level `KeyRecord.capability_roles` empty. So a serve-capability check
    /// MUST read the envelope. If someone "simplifies" `carries_infra_serve` back
    /// to `record.roles` only, this fails — and the trace plane silently goes dark
    /// again, which is exactly how we got here. Built from a synthetic UNBLESSED
    /// record so it stays true regardless of what the baked seed carries.
    #[test]
    fn envelope_attested_role_is_seen_though_top_level_roles_is_empty() {
        let baked = ciris_persist::federation::genesis::canonical_genesis_bundle()
            .serve_nodes
            .as_slice();
        let Some(mut rec) = baked.first().cloned() else {
            return; // no baked canonical in this build
        };
        // Strip every serve surface to get a genuinely UNBLESSED baseline.
        rec.record.capability_roles.clear();
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
            rec.record.capability_roles.is_empty(),
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
// The signing half is exercised end-to-end by `tests/trust_root_qa.rs`, which mints a
// portable root in software and drives both trace-gate legs.

#[cfg(test)]
mod v2_tests {
    use super::*;
    use ciris_persist::federation::types::attestation_type;

    /// Build records/attestations through serde rather than enumerating every
    /// substrate field — these fixtures exist to exercise the REFUSALS, and the
    /// signing half is covered end-to-end by `tests/trust_root_qa.rs`.
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

    /// A heartbeat about the trust root (a signal, not a gate).
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

    /// THE HEARTBEAT IS NOT A GATE — and this pin exists to keep it that way.
    ///
    /// A previous cut of this file refused a bundle with no `accord:lifecycle:v1`
    /// row, and refused a stale one, because pre-v23 `trust_root_valid` ANDed
    /// `lifecycle_active` into validity. persist v23.0.0 (CIRISPersist#551 item 4)
    /// removed it:
    ///
    ///     let valid = edge_exists && root_self_declares
    ///                 && charter_has_recovery && halt_latched != Some(true);
    ///
    /// `drill_freshness` is now a band "reported beside the verdict, not enforced
    /// inside it". That is what makes a seed DURABLE — valid until revoked,
    /// withdrawn or superseded, rather than silently expiring 90 days after the
    /// mint and taking every node with it.
    ///
    /// So a heartbeat-less bundle must ATTACH. Re-introducing the refusal would
    /// reject artifacts persist considers perfectly valid, and would put a shelf
    /// life back on the production trust root.
    #[test]
    fn a_bundle_without_a_heartbeat_still_verifies() {
        assert!(
            verify_bundle_structure(&bundle_with(vec![good_charter(), good_grant()])).is_ok(),
            "the accord heartbeat is a SIGNAL, not a validity gate (v23) — a bundle without \
             one must still verify, or a baked seed acquires a shelf life"
        );
    }

    /// Same property, from the other side: age is not a defect.
    #[test]
    fn an_old_heartbeat_does_not_invalidate_a_bundle() {
        let mut old = good_lifecycle();
        old.attestation.asserted_at = chrono::Utc::now() - chrono::Duration::days(400);
        assert!(
            verify_bundle_structure(&bundle_with(vec![good_charter(), good_grant(), old])).is_ok(),
            "a 400-day-old heartbeat reports as stale drill_freshness; it must not make the \
             bundle invalid"
        );
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
