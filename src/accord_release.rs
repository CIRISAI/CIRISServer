//! **Offline-verifiable HUMANITY_ACCORD halt release** (CIRISServer#347, CC 4.2.1
//! / FSD `MESH_GOVERNANCE_AND_ADMIN_OPS.md` §3) — the tier-5 recovery path that
//! does not require the halted node to be running.
//!
//! # The defect this closes
//!
//! A tier-5 halt latches to disk and `exit(42)`s ([`crate::accord_halt`]). The
//! constitutional way back, [`crate::accord_reactivate`], needs the node's persist
//! `Engine` to read the LIVE family roster — which means the DB, the keystore, and
//! a host healthy enough to open both. Replication cannot deliver the un-halt at
//! all: replication is pull-based and a halted node pulls nothing. So recovery was
//! O(nodes) physical acts, and the FSD's §3 table now says so.
//!
//! That cost falls on the failure that is *most likely to actually happen* — **a
//! mistake, not an attack.** A kill switch whose false trip costs the same as a
//! real compromise is a kill switch operators hesitate to use, which is the worst
//! property a safety mechanism can have.
//!
//! # The shape
//!
//! A **release token** is an `accord:lifecycle:active` [`Invocation`] carrying
//! M-of-N accord cosignatures, whose `payload_sha256` is the digest of a
//! [`ReleaseBinding`] naming *exactly which latch on exactly which node* it ends.
//! The halt latch records that binding ([`HaltRecord::release_binding`]), so a
//! dark node's own latch file states what would lift it. Any transport works —
//! file drop, USB, QR, operator paste — because nothing is delivered *to* a
//! process; the bytes are read off disk by the boot gate.
//!
//! ## Offline-verifiable, and what that costs
//!
//! Verification touches **no network, no peer, no quorum, and no database**:
//!
//! | input | source |
//! |---|---|
//! | the accord family + its `quorum:M/N` | `humanity_accord_genesis()` — baked into the verify binary |
//! | the holders' hybrid public keys | `accord_holder_genesis_records()` — baked into the persist binary |
//! | what this token must release | the halt latch, in this node's `home` |
//! | the token | a file in this node's `home` |
//!
//! The price is that the authority is the **baked genesis family**, not the live
//! (possibly rotated / grown) one, because the live roster lives in the DB. This
//! is deliberate and it is not a weakening:
//!
//! - It is the *same class* of authority that can fire a halt — an accord quorum
//!   — never a single party, and never the operator.
//! - It is the authority [`crate::accord_reactivate`] *already* treats as the
//!   floor: that path's B2 review fix requires ≥1 signature resolved from the
//!   **pinned baked genesis**, precisely because the locally-readable roster "an
//!   operator with DB write could forge". Offline verification keeps the pinned
//!   half and drops the forgeable half. It does not invent a second rule.
//! - A family that has rotated past its founders still has
//!   [`crate::accord_reactivate`]: live M-of-N + ≥1 original. The two paths are
//!   the same ladder rung reached with different material, not two ladders.
//!
//! ## What the binding stops
//!
//! `payload_sha256` covers `{purpose, node_id, halt_invocation_id,
//! halt_payload_sha256, latch_id}`, and the signatures cover the whole invocation
//! including that digest. Therefore:
//!
//! - **another node** — a different `node_id` ⇒ a different digest ⇒ the
//!   signatures do not verify against the preimage this node reconstructs. A
//!   token is not a mesh-wide skeleton key.
//! - **another halt** — a different `invocation_id` / `payload_sha256` ⇒ refused.
//! - **a future halt on this node** — every latch mints a fresh CSPRNG `latch_id`,
//!   so a token cannot be stockpiled against a halt that has not happened. (This
//!   is stronger than `resumes_halt_id` alone, which pins the halt *id* but would
//!   still honour a re-latch of the same invocation.)
//! - **an earlier halt on this node** — same mechanism, other direction.
//! - **a tampered token** — any edit changes `canonical_bytes()`; the hybrid
//!   signatures fail. Any edit to the *binding block* is ignored outright: the
//!   expected digest is recomputed from the LATCH, never read from the token.
//!
//! ## What it deliberately does not stop
//!
//! An operator with filesystem write can still delete the latch. That was already
//! true (`check_halt_gate` is a file-presence gate) and the halt never claimed
//! durability against a hostile local root — CC 4.2 puts the authority outside
//! the federation, not outside the disk. The property this module adds is
//! narrower and checkable: **nobody without an accord quorum can produce a
//! release the node will honour and log as authorized.**
//!
//! ## Composition, not re-implementation
//!
//! The signature preimage is [`Invocation::canonical_bytes`] (verify's encoder,
//! `LIFECYCLE_DOMAIN_PREFIX`-scoped so a halt signature can never be replayed
//! into it); the quorum check is [`verify_threshold_signatures`]; the roster and
//! `M` come from verify's own `accord_roster_from_family` /
//! `accord_quorum_from_family` over the baked genesis. This module composes **no**
//! signature preimage of its own — the last site that did was retired in #283
//! finding 3, and a second correct copy is still a copy that can only drift. The
//! only bytes assembled here are the release *payload*, canonicalized with
//! verify's [`jcs`] and hashed into the slot `payload_sha256` exists for.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ciris_persist::federation::genesis::accord_holder_genesis_records;
use ciris_verify_core::accord_genesis::{
    accord_quorum_from_family, accord_roster_from_family, humanity_accord_genesis,
};
use ciris_verify_core::humanity_accord::{Invocation, InvocationKind};
use ciris_verify_core::jcs;
use ciris_verify_core::threshold::{
    verify_threshold_signatures, ThresholdMember, ThresholdSignature,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::accord_halt::{halt_latch_path, HaltRecord};

/// Domain tag inside the release payload. Distinct from every other payload this
/// node hashes, so a digest computed for another purpose can never coincide with
/// a release binding.
pub const RELEASE_BINDING_PURPOSE: &str = "ciris.accord.halt_release.v1";

/// The file an operator drops into the node `home` to present a release token.
/// The boot gate consumes it ([`crate::accord_halt::check_halt_gate`]); the
/// `ciris-server accord release --token <path>` CLI takes it from anywhere.
pub const RELEASE_TOKEN_FILE: &str = "HUMANITY_ACCORD_RELEASE.json";

/// Append-only JSONL journal of every release *attempt* — honoured and refused
/// alike. A release is a governance act and must be at least as auditable as the
/// halt that it ends.
pub const RELEASE_JOURNAL_FILE: &str = "HUMANITY_ACCORD_RELEASES.jsonl";

/// Cap on journal lines surfaced by [`read_release_journal`] (the file itself is
/// never truncated — a governance log that rotates itself is not a log).
const MAX_JOURNAL_LINES_READ: usize = 256;

/// Where the boot gate looks for a presented token.
#[must_use]
pub fn release_token_path(home: &Path) -> PathBuf {
    home.join(RELEASE_TOKEN_FILE)
}

/// Where honoured/refused releases are journaled.
#[must_use]
pub fn release_journal_path(home: &Path) -> PathBuf {
    home.join(RELEASE_JOURNAL_FILE)
}

/// **What a release token must be bound to** — derived from the halt latch, never
/// from the token. Its JCS digest is the `payload_sha256` the accord signs over.
///
/// Every field narrows the token: `node_id` to one node, `halt_invocation_id` +
/// `halt_payload_sha256` to one halt, `latch_id` to one *instance* of that halt
/// being latched here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBinding {
    /// The federation `key_id` of the node whose latch this releases.
    pub node_id: String,
    /// `invocation_id` of the `CONSTITUTIONAL` halt being ended.
    pub halt_invocation_id: String,
    /// `payload_sha256` of that halt invocation.
    pub halt_payload_sha256: String,
    /// CSPRNG id minted when THIS latch was written — the anti-replay-across-halts
    /// discriminator.
    pub latch_id: String,
}

impl ReleaseBinding {
    /// Read the binding a latched [`HaltRecord`] demands.
    ///
    /// # Errors
    ///
    /// Fails closed when the latch predates #347 (any of the three binding fields
    /// absent) — such a latch names nothing a token could be bound to, so no token
    /// may release it and the operator is sent to `accord reactivate`.
    pub fn from_halt_record(record: &HaltRecord) -> Result<Self> {
        let missing = |what: &str| -> anyhow::Error {
            anyhow::anyhow!(
                "this halt latch carries no {what}: it was written before the offline release \
                 token existed (CIRISServer#347), so there is nothing a token could bind to. \
                 Use `ciris-server accord reactivate --proof <lifecycle-active.json>` (which \
                 reads the live family from persist) to clear it."
            )
        };
        let node_id = record.node_id.clone().filter(|s| !s.is_empty());
        let halt_payload_sha256 = record.halt_payload_sha256.clone().filter(|s| !s.is_empty());
        let latch_id = record.latch_id.clone().filter(|s| !s.is_empty());
        Ok(Self {
            node_id: node_id.ok_or_else(|| missing("node_id"))?,
            halt_invocation_id: record.invocation_id.clone(),
            halt_payload_sha256: halt_payload_sha256
                .ok_or_else(|| missing("halt_payload_sha256"))?,
            latch_id: latch_id.ok_or_else(|| missing("latch_id"))?,
        })
    }

    /// The release payload, as the accord reads it. Carries [`RELEASE_BINDING_PURPOSE`]
    /// so the digest cannot collide with any other payload this node hashes.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "purpose": RELEASE_BINDING_PURPOSE,
            "node_id": self.node_id,
            "halt_invocation_id": self.halt_invocation_id,
            "halt_payload_sha256": self.halt_payload_sha256,
            "latch_id": self.latch_id,
        })
    }

    /// `sha256(JCS(payload))`, lowercase hex — the value a conformant release
    /// token carries in `invocation.payload_sha256`.
    ///
    /// JCS is verify's canonicalizer ([`jcs::canonicalize`]); this is a *payload*
    /// digest, not a signature preimage (the preimage is
    /// [`Invocation::canonical_bytes`]).
    ///
    /// # Errors
    ///
    /// [`anyhow::Error`] if JCS canonicalization faults.
    pub fn payload_sha256(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let bytes = jcs::canonicalize(&self.to_json())
            .map_err(|e| anyhow::anyhow!("canonicalize the release binding: {e}"))?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// The artifact an operator presents to a halted node.
///
/// Wire-compatible in spirit with [`crate::accord_reactivate::ReactivationProof`]
/// (an invocation + cosignatures); the difference is *where the authority comes
/// from* (baked genesis vs. live persist roster) and *what the invocation is bound
/// to* (a specific latch instance vs. only the halt id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseToken {
    /// The `accord:lifecycle:active` invocation. Its `resumes_halt_id` MUST name
    /// the latched halt and its `payload_sha256` MUST equal the latch's binding
    /// digest.
    pub invocation: Invocation,
    /// ≥M accord-holder cosignatures over [`Invocation::canonical_bytes`].
    pub signatures: Vec<ThresholdSignature>,
    /// The binding in the clear, so a human can read what the token releases.
    /// **Advisory only** — verification recomputes the expected digest from the
    /// LATCH and compares against `invocation.payload_sha256`. Editing this block
    /// changes nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Value>,
}

/// Who may authorize a release, and at what threshold.
#[derive(Debug, Clone)]
pub struct ReleaseAuthority {
    /// The seats whose cosignatures count.
    pub roster: Vec<ThresholdMember>,
    /// M — distinct valid hybrid cosignatures required.
    pub threshold: usize,
    /// Provenance of the two above, journaled with every release.
    pub source: String,
}

/// Provenance string for the production authority.
pub const AUTHORITY_SOURCE_BAKED: &str = "baked-humanity-accord-genesis";

/// **The offline authority**: the baked HUMANITY_ACCORD family genesis resolved
/// against the baked holder key records — verify's pinned family + persist's
/// pinned pubkeys, both compiled into this binary. No network, no DB, no peer.
///
/// The roster and `M` are read by verify's own resolvers, so the one-seat /
/// duplicate-pubkey / strict-majority gates apply here exactly as they do at
/// every other accord gate.
///
/// # Errors
///
/// Fails closed when the genesis is not baked, the pinned holder directory does
/// not resolve the family's members, or the declared quorum is not a strict
/// majority. No anchor ⇒ no release, never a partial one.
pub fn baked_release_authority() -> Result<ReleaseAuthority> {
    let genesis = humanity_accord_genesis().context(
        "the HUMANITY_ACCORD genesis is NOT baked into this build — there is no offline authority \
         to verify a release token against (fail-closed). Use `accord reactivate`.",
    )?;
    let directory: Vec<ThresholdMember> = accord_holder_genesis_records()
        .iter()
        .map(|r| ThresholdMember {
            member_id: r.record.key_id.clone(),
            ed25519_public_key_base64: r.record.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: r.record.pubkey_ml_dsa_65_base64.clone(),
            role: None,
        })
        .collect();
    let roster = accord_roster_from_family(genesis, &directory)
        .map_err(|e| anyhow::anyhow!("resolve the baked accord roster: {e}"))?;
    let threshold = accord_quorum_from_family(genesis)
        .map_err(|e| anyhow::anyhow!("read the baked accord quorum M: {e}"))?;
    Ok(ReleaseAuthority {
        roster,
        threshold,
        source: AUTHORITY_SOURCE_BAKED.to_string(),
    })
}

/// What a verified release proved. Journaled verbatim.
#[derive(Debug, Clone, Serialize)]
pub struct ReleaseVerdict {
    /// `invocation_id` of the `lifecycle:active` that authorized this release.
    pub release_invocation_id: String,
    /// Count of distinct seats whose hybrid cosignature verified.
    pub valid_signers: usize,
    /// M required.
    pub threshold: usize,
    /// N — the resolved roster size.
    pub roster_size: usize,
    /// Where the roster + M came from ([`AUTHORITY_SOURCE_BAKED`] in prod).
    pub authority_source: String,
    /// The binding digest that was satisfied (recomputed from the latch).
    pub bound_payload_sha256: String,
    /// The latch instance released.
    pub latch_id: String,
    /// The node the binding named.
    pub node_id: String,
}

/// Verify a release token against a latched halt — the whole gate, offline.
///
/// Checks, in order (binding before signatures so a mis-addressed token reports
/// *that* rather than an opaque quorum failure):
///
/// 1. the latch carries a release binding at all (else: pre-#347 latch);
/// 2. the token is `accord:lifecycle:active` — the wire- and scope-isolated
///    resumption domain, so no `CONSTITUTIONAL` halt signature can be replayed
///    into it;
/// 3. `resumes_halt_id` names THIS latch's halt (CC 4.2.1.3). Together with (2)
///    this satisfies verify's structural resumption rule *a fortiori* — it is the
///    same rule pinned to one value, not a second copy of it;
/// 4. `payload_sha256` equals the digest recomputed **from the latch**;
/// 5. the token has not expired (see [`release_reference_time`] for the clock rule);
/// 6. ≥M distinct valid hybrid cosignatures from `authority` over
///    [`Invocation::canonical_bytes`].
///
/// # Errors
///
/// [`anyhow::Error`] naming the first failed check. Every failure is fail-closed:
/// the caller must leave the latch in place.
pub fn verify_release_token(
    record: &HaltRecord,
    token: &ReleaseToken,
    authority: &ReleaseAuthority,
    now_rfc3339: &str,
) -> Result<ReleaseVerdict> {
    // (1) What this latch demands. Derived from the LATCH — the token's own
    // `binding` block is never consulted.
    let binding = ReleaseBinding::from_halt_record(record)?;
    let expected = binding.payload_sha256()?;

    // (2) Scope. `lifecycle:active` signs LIFECYCLE_DOMAIN_PREFIX; a halt signs
    // INVOCATION_DOMAIN_PREFIX. Wire-isolated by construction — this check makes
    // the refusal legible instead of surfacing as a preimage mismatch.
    if token.invocation.invocation_kind != InvocationKind::LifecycleActive {
        bail!(
            "a release token must be an accord:lifecycle:active invocation, got {:?} — a halt \
             (CONSTITUTIONAL) signature signs a different canonical domain and can never release",
            token.invocation.invocation_kind
        );
    }

    // (3) Which halt. CC 4.2.1.3 makes `resumes_halt_id` mandatory here; we
    // additionally pin it to the latched id, so a `lifecycle:active` stockpiled
    // against some OTHER halt is refused before any crypto runs.
    match token.invocation.resumes_halt_id.as_deref() {
        Some(id) if id == binding.halt_invocation_id => {}
        Some(id) => bail!(
            "the release token resumes halt {id:?} but this node is latched on halt {:?} — \
             a token is valid against exactly the halt it names",
            binding.halt_invocation_id
        ),
        None => bail!(
            "the release token carries no resumes_halt_id — CC 4.2.1.3 makes it mandatory for \
             accord:lifecycle:active, and it is what binds a resumption to the one halt it ends"
        ),
    }

    // (4) Which node, which latch instance. This is the anti-skeleton-key check:
    // the digest covers node_id + latch_id + the halt's own payload hash, so the
    // signed bytes differ for every (node, halt, latch) triple in the mesh.
    if token.invocation.payload_sha256 != expected {
        bail!(
            "the release token is not bound to THIS halt latch.\n  latch demands \
             payload_sha256 = {expected}\n  token carries     payload_sha256 = {}\n  latch \
             binding = {}\nA token minted for another node, another halt, or an earlier latch \
             of this halt cannot release this one.",
            token.invocation.payload_sha256,
            serde_json::to_string(&binding.to_json()).unwrap_or_default(),
        );
    }

    // (5) Freshness. A token binds to a latch_id that did not exist before the
    // halt, so it cannot be pre-minted; `valid_until` is defence in depth against
    // a *collected-but-unused* token sitting in a drawer.
    let reference = release_reference_time(record, now_rfc3339);
    let valid_until = parse_rfc3339(&token.invocation.valid_until).with_context(|| {
        format!(
            "release token valid_until {:?} is not a canonical RFC-3339 instant",
            token.invocation.valid_until
        )
    })?;
    if valid_until < reference {
        bail!(
            "the release token expired at {} (judged against {}, the later of this node's clock \
             {} and the latch's own latched_at {}) — mint a fresh one. A window that closed \
             before this latch even existed cannot be a release for it, whatever the clock says.",
            token.invocation.valid_until,
            reference.to_rfc3339(),
            now_rfc3339,
            record.latched_at,
        );
    }

    // (6) The quorum. verify's own threshold verifier over verify's own preimage.
    let canonical = token.invocation.canonical_bytes();
    let valid = verify_threshold_signatures(
        &canonical,
        &authority.roster,
        &token.signatures,
        authority.threshold,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "release quorum NOT met ({} of {} seats required, authority = {}): {e}",
            authority.threshold,
            authority.roster.len(),
            authority.source,
        )
    })?;

    Ok(ReleaseVerdict {
        release_invocation_id: token.invocation.invocation_id.clone(),
        valid_signers: valid,
        threshold: authority.threshold,
        roster_size: authority.roster.len(),
        authority_source: authority.source.clone(),
        bound_payload_sha256: expected,
        latch_id: binding.latch_id,
        node_id: binding.node_id,
    })
}

/// The instant expiry is judged against: `max(now, latched_at)` — the wall clock,
/// **floored** at the halt already on disk.
///
/// A halted node has been dark, possibly for months, possibly with a dead RTC, so
/// its clock is the least trustworthy input in the room. The floor is what makes
/// the expiry check mean something anyway:
///
/// - **backwards / stopped clock** (`now` < `latched_at`): without a floor, a
///   node reading 1970 would accept *any* token, including one whose window
///   closed before this latch existed — which cannot be a legitimate release for
///   it. The floor refuses that. It is never more lenient than the raw clock.
/// - **fast clock** (`now` > `latched_at`): the floor does nothing and the raw
///   clock governs, so a mis-set-into-the-future node fails closed and the
///   operator mints a fresh token. That is the safe direction, and it is cheap:
///   minting needs the quorum they already have.
///
/// The floor is defence in depth, not the anti-replay mechanism — `latch_id` is
/// (a token cannot be minted before the halt that produced its binding).
#[must_use]
pub fn release_reference_time(
    record: &HaltRecord,
    now_rfc3339: &str,
) -> chrono::DateTime<chrono::Utc> {
    let now = parse_rfc3339(now_rfc3339).unwrap_or_else(|_| chrono::Utc::now());
    match parse_rfc3339(&record.latched_at) {
        Ok(latched) if latched > now => latched,
        _ => now,
    }
}

fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    Ok(chrono::DateTime::parse_from_rfc3339(s)
        .with_context(|| format!("parse RFC-3339 instant {s:?}"))?
        .with_timezone(&chrono::Utc))
}

/// **Producer side** — the unsigned `lifecycle:active` invocation the accord seats
/// cosign to release a specific latch. Holds no keys: each holder signs
/// [`Invocation::canonical_bytes`] on their own device, exactly as for a halt.
///
/// Producer and verifier live in one module on purpose — the round-trip
/// ([`tests::round_trip_release_clears_the_latch`]) is the contract.
///
/// # Errors
///
/// [`anyhow::Error`] if the binding cannot be canonicalized.
pub fn build_release_invocation(
    binding: &ReleaseBinding,
    invocation_id: &str,
    nonce: &str,
    asserted_at: &str,
    valid_until: &str,
) -> Result<Invocation> {
    Ok(Invocation {
        invocation_kind: InvocationKind::LifecycleActive,
        invocation_id: invocation_id.to_string(),
        resumes_halt_id: Some(binding.halt_invocation_id.clone()),
        nonce: nonce.to_string(),
        asserted_at: asserted_at.to_string(),
        valid_until: valid_until.to_string(),
        payload_sha256: binding.payload_sha256()?,
    })
}

/// The **release request** a dark node emits for the accord to sign: what the
/// latch demands, the exact invocation to cosign, and the byte string to sign.
///
/// This is what makes the token mintable at all — the halt latch alone states the
/// binding, and this turns it into a ceremony input. Pure function of the latch;
/// no keys, no DB, no network.
///
/// # Errors
///
/// [`anyhow::Error`] if the latch carries no binding or the baked authority does
/// not resolve.
pub fn build_release_request(record: &HaltRecord, ttl_hours: i64) -> Result<Value> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let binding = ReleaseBinding::from_halt_record(record)?;
    let authority = baked_release_authority()?;

    // Fail-secure CSPRNG (CIRISServer#283 finding 2) — never a predictable nonce.
    let mut nonce_bytes = [0u8; 32];
    ciris_crypto::random::fill(&mut nonce_bytes)
        .map_err(|e| anyhow::anyhow!("CSPRNG for the release-invocation nonce: {e}"))?;
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);

    let now = chrono::Utc::now();
    let invocation = build_release_invocation(
        &binding,
        &format!("release-{}", uuid::Uuid::new_v4()),
        &nonce,
        &canonical_rfc3339(now),
        &canonical_rfc3339(now + chrono::Duration::hours(ttl_hours)),
    )?;
    let canonical = invocation.canonical_bytes();

    Ok(json!({
        "binding": binding.to_json(),
        "invocation": invocation,
        // What each holder signs: Ed25519 over these bytes, ML-DSA-65 over
        // (these bytes ‖ ed25519_sig) — the federation's standing bound-hybrid rule.
        "canonical_bytes_base64": base64::engine::general_purpose::STANDARD.encode(&canonical),
        "canonical_bytes_sha256": hex::encode(Sha256::digest(&canonical)),
        "authority": {
            "source": authority.source,
            "threshold": authority.threshold,
            "roster": authority.roster.iter().map(|m| m.member_id.clone()).collect::<Vec<_>>(),
        },
        "how_to_use": format!(
            "Each of >={} accord seats signs canonical_bytes on their own device, then place \
             {{\"invocation\":<invocation>,\"signatures\":[...]}} at <home>/{RELEASE_TOKEN_FILE} \
             (or pass it to `ciris-server accord release --token <file>`). Verification is \
             offline: no network, no peer, no database.",
            authority.threshold,
        ),
    }))
}

/// CEG §0.5 canonical RFC-3339 (`YYYY-MM-DDTHH:MM:SS.sssZ`).
fn canonical_rfc3339(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Verify a token and, on success, clear the latch — **the whole release act**.
///
/// Ordering is chosen for the audit trail: the journal entry is written *before*
/// the latch is removed, so a release that verified is recorded even if the
/// removal then fails (and that failure gets its own line). Refusals are
/// journaled too — a rejected release attempt on a halted node is exactly the
/// event an incident review needs.
///
/// # Errors
///
/// [`anyhow::Error`] if verification fails (the latch is left in place) or if the
/// latch could not be removed after a verified release.
pub fn honor_release_token(
    home: &Path,
    record: &HaltRecord,
    token: &ReleaseToken,
    authority: &ReleaseAuthority,
    now_rfc3339: &str,
) -> Result<ReleaseVerdict> {
    let verdict = match verify_release_token(record, token, authority, now_rfc3339) {
        Ok(v) => v,
        Err(e) => {
            journal_rejection(home, record, token, now_rfc3339, &e.to_string());
            return Err(e);
        }
    };

    let entry = json!({
        "event": "accord_halt_release",
        "outcome": "honored",
        "released_at": now_rfc3339,
        "verdict": verdict,
        "halt_record": record,
        "release_token": token,
    });
    append_journal_line(home, &entry).context(
        "write the release audit journal (a release is a governance act and must leave a trace)",
    )?;

    let latch = halt_latch_path(home);
    if let Err(e) = std::fs::remove_file(&latch) {
        let _ = append_journal_line(
            home,
            &json!({
                "event": "accord_halt_release",
                "outcome": "latch_removal_failed",
                "released_at": now_rfc3339,
                "latch": latch.display().to_string(),
                "error": e.to_string(),
            }),
        );
        bail!(
            "the release token VERIFIED but the halt latch {} could not be removed: {e} — the \
             node stays down (fail-secure). The verified release is journaled.",
            latch.display()
        );
    }

    // Consume the presented token so a stale file does not re-trip the gate on
    // every boot. It is preserved verbatim in the journal.
    let _ = std::fs::remove_file(release_token_path(home));
    Ok(verdict)
}

/// Boot-gate entry point: a token file is present next to the latch — verify it
/// and clear the latch, or refuse with the reason.
///
/// Reads the latch body the caller already has (the gate reads it for its error
/// message), so the file is not read twice.
///
/// # Errors
///
/// [`anyhow::Error`] if the latch is unparseable, the token is unparseable, the
/// baked authority does not resolve, or verification fails.
pub fn consume_presented_release_token(home: &Path, latch_body: &str) -> Result<ReleaseVerdict> {
    let record: HaltRecord = serde_json::from_str(latch_body).context(
        "the halt latch is not a parseable HaltRecord, so no release token can be bound to it \
         (fail-secure: the node stays down)",
    )?;
    let token_path = release_token_path(home);
    let bytes = std::fs::read(&token_path)
        .with_context(|| format!("read the presented release token {}", token_path.display()))?;
    let token: ReleaseToken = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parse the presented release token {} as {{invocation, signatures}}",
            token_path.display()
        )
    })?;
    let authority = baked_release_authority()?;
    let now = canonical_rfc3339(chrono::Utc::now());
    honor_release_token(home, &record, &token, &authority, &now)
}

/// Append one JSON line to the release journal.
///
/// # Errors
///
/// [`std::io::Error`] wrapped, if the journal cannot be opened or written.
pub fn append_journal_line(home: &Path, entry: &Value) -> Result<()> {
    use std::io::Write as _;
    let path = release_journal_path(home);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open the release journal {}", path.display()))?;
    writeln!(f, "{entry}").with_context(|| format!("append to {}", path.display()))?;
    Ok(())
}

/// Journal a refusal — but not the same refusal twice in a row, so a supervisor
/// restart-looping a halted node cannot grow the journal without bound.
fn journal_rejection(
    home: &Path,
    record: &HaltRecord,
    token: &ReleaseToken,
    now_rfc3339: &str,
    reason: &str,
) {
    use sha2::{Digest, Sha256};
    let token_sha256 = serde_json::to_vec(token)
        .map(|b| hex::encode(Sha256::digest(&b)))
        .unwrap_or_default();
    let entry = json!({
        "event": "accord_halt_release",
        "outcome": "refused",
        "attempted_at": now_rfc3339,
        "reason": reason,
        "token_sha256": token_sha256,
        "halt_invocation_id": record.invocation_id,
        "latch_id": record.latch_id,
        "release_invocation_id": token.invocation.invocation_id,
    });
    // Restart-loop guard: identical (token, reason) as the previous line ⇒ skip.
    if let Some(last) = read_release_journal(home).last() {
        if last.get("outcome").and_then(Value::as_str) == Some("refused")
            && last.get("token_sha256").and_then(Value::as_str) == Some(token_sha256.as_str())
            && last.get("reason").and_then(Value::as_str) == Some(reason)
        {
            return;
        }
    }
    let _ = append_journal_line(home, &entry);
}

/// Read back the release journal (oldest-first, last [`MAX_JOURNAL_LINES_READ`]).
/// Never fails: an absent or partly-corrupt journal reads as the lines that parse.
#[must_use]
pub fn read_release_journal(home: &Path) -> Vec<Value> {
    let Ok(body) = std::fs::read_to_string(release_journal_path(home)) else {
        return Vec::new();
    };
    let all: Vec<Value> = body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let skip = all.len().saturating_sub(MAX_JOURNAL_LINES_READ);
    all.into_iter().skip(skip).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};

    const B64: base64::engine::general_purpose::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    /// A software accord seat — stands in for a holder's YubiKey in-process. The
    /// PRODUCTION authority is the baked genesis; `baked_authority_resolves_offline`
    /// pins that separately.
    struct Seat {
        id: String,
        ed: Ed25519Signer,
        pqc: MlDsa65Signer,
    }

    impl Seat {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                ed: Ed25519Signer::random().unwrap(),
                pqc: MlDsa65Signer::new().unwrap(),
            }
        }
        fn member(&self) -> ThresholdMember {
            ThresholdMember {
                member_id: self.id.clone(),
                ed25519_public_key_base64: B64.encode(self.ed.verifying_key().to_bytes()),
                mldsa65_public_key_base64: Some(B64.encode(self.pqc.public_key().unwrap())),
                role: None,
            }
        }
        /// The federation's bound-hybrid rule: ML-DSA over `bytes ‖ ed25519_sig`.
        fn sign(&self, bytes: &[u8]) -> ThresholdSignature {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = self.pqc.sign(&bound).unwrap();
            ThresholdSignature {
                member_id: self.id.clone(),
                ed25519_signature_base64: B64.encode(&ed_sig),
                mldsa65_signature_base64: Some(B64.encode(&pqc_sig)),
            }
        }
    }

    fn authority(seats: &[Seat]) -> ReleaseAuthority {
        ReleaseAuthority {
            roster: seats.iter().map(Seat::member).collect(),
            threshold: 2,
            source: "test-seats".to_string(),
        }
    }

    fn record(node: &str, halt_id: &str, latch_id: &str) -> HaltRecord {
        HaltRecord {
            invocation_kind: "CONSTITUTIONAL".into(),
            invocation_id: halt_id.into(),
            valid_signers: vec!["A1".into(), "B1".into()],
            quorum_threshold: 2,
            latched_at: "2026-08-01T00:00:00.000Z".into(),
            node_id: Some(node.into()),
            halt_payload_sha256: Some("ab".repeat(32)),
            latch_id: Some(latch_id.into()),
            release_payload_sha256: None,
            release_binding: None,
        }
    }

    fn token_for(rec: &HaltRecord, seats: &[&Seat]) -> ReleaseToken {
        let binding = ReleaseBinding::from_halt_record(rec).unwrap();
        let inv = build_release_invocation(
            &binding,
            "release-001",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "2026-08-02T00:00:00.000Z",
            "2030-01-01T00:00:00.000Z",
        )
        .unwrap();
        let canonical = inv.canonical_bytes();
        ReleaseToken {
            invocation: inv,
            signatures: seats.iter().map(|s| s.sign(&canonical)).collect(),
            binding: Some(binding.to_json()),
        }
    }

    const NOW: &str = "2026-08-03T00:00:00.000Z";

    #[test]
    fn a_valid_two_of_three_token_releases_its_own_latch() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_for(&rec, &[&seats[0], &seats[1]]);
        let v = verify_release_token(&rec, &tok, &auth, NOW).expect("valid token must verify");
        assert_eq!(v.valid_signers, 2);
        assert_eq!(v.node_id, "node-alpha");
        assert_eq!(v.latch_id, "latch-aaa");
    }

    #[test]
    fn a_token_for_a_different_node_is_refused() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let mine = record("node-alpha", "halt-001", "latch-aaa");
        let theirs = record("node-beta", "halt-001", "latch-aaa");
        // A perfectly valid token — for the OTHER node.
        let tok = token_for(&theirs, &[&seats[0], &seats[1]]);
        let e = verify_release_token(&mine, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not bound to THIS halt latch"), "{e}");
    }

    #[test]
    fn a_token_for_a_different_halt_is_refused() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let mine = record("node-alpha", "halt-002", "latch-aaa");
        let other = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_for(&other, &[&seats[0], &seats[1]]);
        let e = verify_release_token(&mine, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("resumes halt"), "{e}");
    }

    #[test]
    fn a_token_for_an_earlier_latch_of_the_same_halt_is_refused() {
        // The replay that `resumes_halt_id` alone does NOT stop: same node, same
        // halt id — but the node was released and re-halted, so the latch instance
        // is new. The stockpiled token must be worthless.
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let old = record("node-alpha", "halt-001", "latch-aaa");
        let new = record("node-alpha", "halt-001", "latch-bbb");
        let tok = token_for(&old, &[&seats[0], &seats[1]]);
        let e = verify_release_token(&new, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not bound to THIS halt latch"), "{e}");
    }

    #[test]
    fn a_token_signed_by_the_wrong_keys_is_refused() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        // Two impostors using the SAME member_ids as real seats.
        let fakes = [Seat::new("A1"), Seat::new("B1")];
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_for(&rec, &[&fakes[0], &fakes[1]]);
        let e = verify_release_token(&rec, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("quorum NOT met"), "{e}");
    }

    #[test]
    fn one_signature_does_not_meet_the_two_of_three() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_for(&rec, &[&seats[0]]);
        let e = verify_release_token(&rec, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("quorum NOT met"), "{e}");
    }

    #[test]
    fn a_tampered_token_is_refused_in_every_field_that_is_signed() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let good = token_for(&rec, &[&seats[0], &seats[1]]);

        // nonce / asserted_at / valid_until all ride the canonical bytes.
        for mutate in [
            (|t: &mut ReleaseToken| t.invocation.nonce.push('X')) as fn(&mut ReleaseToken),
            |t: &mut ReleaseToken| t.invocation.asserted_at = "2026-08-02T00:00:01.000Z".into(),
            |t: &mut ReleaseToken| t.invocation.valid_until = "2031-01-01T00:00:00.000Z".into(),
            |t: &mut ReleaseToken| t.invocation.invocation_id = "release-002".into(),
            |t: &mut ReleaseToken| {
                t.signatures[0].ed25519_signature_base64 = B64.encode([0u8; 64]);
            },
        ] {
            let mut bad = good.clone();
            mutate(&mut bad);
            let e = verify_release_token(&rec, &bad, &auth, NOW)
                .expect_err("a tampered token must never verify")
                .to_string();
            assert!(e.contains("quorum NOT met"), "{e}");
        }

        // The advisory `binding` block is NOT trusted: rewriting it changes nothing.
        let mut relabelled = good.clone();
        relabelled.binding = Some(json!({ "node_id": "node-beta", "latch_id": "latch-zzz" }));
        verify_release_token(&rec, &relabelled, &auth, NOW)
            .expect("the token's own binding block is advisory — verification uses the LATCH");
    }

    #[test]
    fn a_halt_signature_cannot_be_replayed_as_a_release() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let mut tok = token_for(&rec, &[&seats[0], &seats[1]]);
        tok.invocation.invocation_kind = InvocationKind::Constitutional;
        let e = verify_release_token(&rec, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("accord:lifecycle:active"), "{e}");
    }

    /// Mint a signed token with an explicit validity window.
    fn token_with_window(
        rec: &HaltRecord,
        seats: &[&Seat],
        asserted_at: &str,
        valid_until: &str,
    ) -> ReleaseToken {
        let binding = ReleaseBinding::from_halt_record(rec).unwrap();
        let inv =
            build_release_invocation(&binding, "release-001", "nonce", asserted_at, valid_until)
                .unwrap();
        let canonical = inv.canonical_bytes();
        ReleaseToken {
            signatures: seats.iter().map(|s| s.sign(&canonical)).collect(),
            binding: None,
            invocation: inv,
        }
    }

    #[test]
    fn an_expired_token_is_refused() {
        // latched_at = 2026-08-01, now = 2026-08-03, window closed 2026-08-02.
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_with_window(
            &rec,
            &[&seats[0], &seats[1]],
            "2026-08-02T00:00:00.000Z",
            "2026-08-02T12:00:00.000Z",
        );
        let e = verify_release_token(&rec, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("expired"), "{e}");
    }

    #[test]
    fn expiry_is_floored_at_the_latch_so_a_backwards_clock_cannot_revive_a_stale_token() {
        // A halted node's clock is the least trustworthy input in the room. With
        // the reference floored at `latched_at`:
        //   (a) a window that closed BEFORE this latch existed is refused even
        //       when the wall clock reads 1970 — it cannot be a release for a halt
        //       that had not happened yet;
        //   (b) a live window is still honoured under the same broken clock, so
        //       the floor never blocks a legitimate recovery.
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let rec = record("node-alpha", "halt-001", "latch-aaa"); // latched 2026-08-01
        const DEAD_RTC: &str = "1970-01-01T00:00:00.000Z";

        let stale = token_with_window(
            &rec,
            &[&seats[0], &seats[1]],
            "2026-06-01T00:00:00.000Z",
            "2026-07-01T00:00:00.000Z", // closed a month before the halt
        );
        let e = verify_release_token(&rec, &stale, &auth, DEAD_RTC)
            .expect_err("a window that closed before the latch must never release it")
            .to_string();
        assert!(e.contains("expired"), "{e}");

        let live = token_with_window(
            &rec,
            &[&seats[0], &seats[1]],
            "2026-08-02T00:00:00.000Z",
            "2030-01-01T00:00:00.000Z",
        );
        verify_release_token(&rec, &live, &auth, DEAD_RTC)
            .expect("a broken clock must not block a live token");
    }

    #[test]
    fn a_pre_347_latch_names_nothing_a_token_could_bind_to() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let mut old = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_for(&old, &[&seats[0], &seats[1]]);
        old.latch_id = None;
        let e = verify_release_token(&old, &tok, &auth, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("accord reactivate"), "{e}");
    }

    #[test]
    fn the_latchs_stored_release_digest_is_documentation_not_authority() {
        // A tampered `release_payload_sha256` in the latch must NOT change what is
        // accepted — verification recomputes from the binding fields.
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let mut rec = record("node-alpha", "halt-001", "latch-aaa");
        let tok = token_for(&rec, &[&seats[0], &seats[1]]);
        rec.release_payload_sha256 = Some("00".repeat(32));
        rec.release_binding = Some(json!({ "node_id": "node-beta" }));
        verify_release_token(&rec, &tok, &auth, NOW)
            .expect("the stored digest is advisory; the recomputed one is authority");
    }

    #[test]
    fn round_trip_release_clears_the_latch_and_leaves_a_trace() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let home = std::env::temp_dir().join(format!(
            "accord-release-rt-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        crate::accord_halt::latch_halt(&home, &rec).unwrap();
        assert!(
            crate::accord_halt::check_halt_gate(&home).is_err(),
            "latched ⇒ boot refused"
        );

        let tok = token_for(&rec, &[&seats[0], &seats[1]]);
        let v = honor_release_token(&home, &rec, &tok, &auth, NOW).unwrap();
        assert_eq!(v.valid_signers, 2);
        assert!(
            !halt_latch_path(&home).exists(),
            "the latch must be cleared"
        );
        assert!(
            crate::accord_halt::check_halt_gate(&home).is_ok(),
            "released ⇒ boot allowed"
        );

        let journal = read_release_journal(&home);
        assert_eq!(journal.len(), 1, "the release must leave exactly one trace");
        assert_eq!(journal[0]["outcome"], "honored");
        assert_eq!(journal[0]["verdict"]["node_id"], "node-alpha");
        assert_eq!(journal[0]["halt_record"]["invocation_id"], "halt-001");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_refused_release_is_journaled_once_not_once_per_restart() {
        let seats = vec![Seat::new("A1"), Seat::new("B1"), Seat::new("C1")];
        let auth = authority(&seats);
        let home = std::env::temp_dir().join(format!(
            "accord-release-refuse-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&home).unwrap();
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        crate::accord_halt::latch_halt(&home, &rec).unwrap();
        let tok = token_for(&rec, &[&seats[0]]); // one signature: short of 2-of-3

        for _ in 0..5 {
            assert!(honor_release_token(&home, &rec, &tok, &auth, NOW).is_err());
        }
        assert!(
            halt_latch_path(&home).exists(),
            "a refused release must not clear the latch"
        );
        let journal = read_release_journal(&home);
        assert_eq!(
            journal.len(),
            1,
            "restart-looping must not grow the journal: {journal:?}"
        );
        assert_eq!(journal[0]["outcome"], "refused");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn baked_authority_resolves_offline_and_is_a_strict_majority() {
        // THE load-bearing property: the production authority resolves from
        // compiled-in material alone — no network, no peer, no DB, no engine.
        let auth = baked_release_authority().expect("the baked accord genesis must resolve");
        assert_eq!(auth.source, AUTHORITY_SOURCE_BAKED);
        assert!(auth.roster.len() >= 3, "roster: {:?}", auth.roster.len());
        assert!(
            2 * auth.threshold > auth.roster.len(),
            "the release threshold must be a strict majority ({} of {})",
            auth.threshold,
            auth.roster.len()
        );
        // Every seat carries BOTH halves — a classical-only seat could not meet the
        // RequireHybrid federation-tier bar and would silently shrink the roster.
        for m in &auth.roster {
            assert!(
                m.mldsa65_public_key_base64.is_some(),
                "seat {} has no ML-DSA-65 half",
                m.member_id
            );
        }
        // Cross-check against verify's own pinned rooting anchor: the release
        // roster and the bootstrap anchor are the SAME seats, resolved by the same
        // resolver, so they cannot drift.
        let anchor = ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor();
        assert_eq!(anchor.len(), auth.roster.len());
        for m in &auth.roster {
            let ed: [u8; 32] = B64
                .decode(&m.ed25519_public_key_base64)
                .unwrap()
                .try_into()
                .unwrap();
            assert!(
                anchor.contains(&ed),
                "seat {} is not in the pinned anchor",
                m.member_id
            );
        }
    }

    #[test]
    fn the_release_request_is_a_pure_function_of_the_latch() {
        let rec = record("node-alpha", "halt-001", "latch-aaa");
        let req = build_release_request(&rec, 72).expect("a release request needs only the latch");
        assert_eq!(req["binding"]["node_id"], "node-alpha");
        assert_eq!(req["binding"]["purpose"], RELEASE_BINDING_PURPOSE);
        assert_eq!(req["invocation"]["invocation_kind"], "lifecycle:active");
        assert_eq!(req["invocation"]["resumes_halt_id"], "halt-001");
        assert_eq!(
            req["invocation"]["payload_sha256"],
            ReleaseBinding::from_halt_record(&rec)
                .unwrap()
                .payload_sha256()
                .unwrap()
        );
        // The bytes a holder signs are the invocation's own canonical bytes.
        let inv: Invocation = serde_json::from_value(req["invocation"].clone()).unwrap();
        assert_eq!(
            req["canonical_bytes_base64"],
            B64.encode(inv.canonical_bytes())
        );
        // Two requests over the same latch differ ONLY in nonce/timestamps — the
        // binding digest is stable, so holders can sign either.
        let req2 = build_release_request(&rec, 72).unwrap();
        assert_eq!(
            req["invocation"]["payload_sha256"],
            req2["invocation"]["payload_sha256"]
        );
        assert_ne!(req["invocation"]["nonce"], req2["invocation"]["nonce"]);
    }
}
