//! Canonical-peer enrollment — lens-core's membership in the
//! `ciris-canonical` governed global community (CIRISLensCore#33 /
//! CIRISRegistry#56).
//!
//! ## Decision (LOCKED 2026-06-05 — CIRISRegistry#56)
//!
//! The CIRIS canonical/bootstrap services (Registry + Lens + Node) are
//! modeled as a single **governed global `community`** with
//! `community_key_id: ciris-canonical`. Lens-core installs join as
//! **members** once the founding-core quorum (the three regional stewards
//! US/EU/APAC) publishes the community Contribution. This module is the
//! lens-core side of that enrollment — it expresses the intent, resolves
//! current enrollment state against the persist directory, and provides
//! the enroll-when-published readiness check.
//!
//! ## What is gated
//!
//! **CIRISRegistry side (gap — not yet shipped):** the `ciris-canonical`
//! community Contribution has not been emitted by Registry as of the
//! edge 2.2 / persist 5.5.3 floor (CIRISRegistry#56 checklist item
//! "emit `community` Contribution via `ingest_community`/`resolve_community`
//! path" is still open). Until the Registry publishes that envelope and it
//! propagates to the local persist directory, `lookup_community` returns
//! `None`. Once it lands, `is_enrolled` auto-resolves to `true` via the
//! standard persist `FederationDirectory` API — no code change needed.
//!
//! Upstream gap tracked as CIRISRegistry#59 (filed 2026-06-12).
//!
//! ## Admission model
//!
//! - `community_key_id: ciris-canonical`
//! - `consensus_protocol: quorum:2/3` (entrenched; founding-core = 3 stewards)
//! - `cohort_subkind: infrastructure` (plaintext commons carve-out per
//!   persist v4.12.0 `cohort_scope::crypto_tier`)
//! - New-operator admission via `supersedes` gated by founding-core quorum
//!   (CEG §8.1.13.2)
//!
//! ## CEG envelope federation
//!
//! See [`ceg_egress`] for the detection-attestation → CEG-envelope building
//! surface. RET-medium federation of those envelopes waits on the
//! PQC-KEX session surface from CIRISEdge#54 / CIRISVerify#47.

pub mod ceg_egress;

use std::sync::Arc;

use ciris_persist::prelude::Engine;
// `FederationDirectory` trait methods are callable on the `Arc<dyn
// FederationDirectory>` returned by `Engine::federation_directory()`
// without an explicit `use` — Rust resolves dyn-trait vtable calls
// without requiring the trait in scope at the call site.
#[allow(unused_imports)]
use ciris_persist::federation::FederationDirectory as _FederationDirectoryForDocs;

/// The stable `community_key_id` for the CIRIS canonical/bootstrap
/// services community. Consumers pin this constant; they do NOT
/// hard-pin per-install fingerprints (per CIRISRegistry#56
/// `TRUST_CONTRACT.md` discipline). Once the Registry publishes the
/// community Contribution, `lookup_community(CIRIS_CANONICAL_COMMUNITY_KEY_ID)`
/// resolves the full roster.
pub const CIRIS_CANONICAL_COMMUNITY_KEY_ID: &str = "ciris-canonical";

/// Errors from canonical-peer enrollment operations.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// Persist directory lookup failed (I/O / DB error).
    #[error("directory lookup failed: {0}")]
    Directory(String),
    /// The lens-core install's own `key_id` is not in the resolved
    /// community's member roster. This is a normal transient state during
    /// the Registry-side admission ceremony; callers should log and retry.
    #[error("not yet a member: local key_id '{key_id}' absent from ciris-canonical roster")]
    NotYetMember { key_id: String },
}

/// Canonical-peer enrollment state for this lens-core install.
///
/// Constructed once at startup via [`CanonicalPeerEnrollment::new`] and
/// polled (or logged) by the node role. The struct is lightweight —
/// the persist `Engine` is Arc-shared with the rest of the process.
pub struct CanonicalPeerEnrollment {
    engine: Arc<Engine>,
    /// The federation `key_id` under which THIS install is known.
    local_key_id: String,
}

impl CanonicalPeerEnrollment {
    /// Construct the enrollment tracker. `local_key_id` is the
    /// relay's `federation_keys.key_id` — the same string passed to
    /// `LensCore::relay` or `LensCore::ret_relay`.
    pub fn new(engine: Arc<Engine>, local_key_id: impl Into<String>) -> Self {
        Self {
            engine,
            local_key_id: local_key_id.into(),
        }
    }

    /// Check whether this install is currently enrolled in
    /// `ciris-canonical`.
    ///
    /// Returns:
    /// - `Ok(true)` — the community exists in the local directory and
    ///   `local_key_id` is in the member roster.
    /// - `Ok(false)` — the community Contribution has not yet propagated
    ///   to the local directory. This is the expected state until
    ///   Registry publishes it (CIRISRegistry#56 / #59). No action
    ///   needed: once it lands, the next `is_enrolled` call resolves
    ///   to `true`.
    /// - `Err(EnrollmentError::NotYetMember)` — the community record
    ///   exists but this install's `key_id` is not in the roster. This
    ///   indicates the admission ceremony has not yet been completed for
    ///   this particular node.
    /// - `Err(EnrollmentError::Directory)` — a persist I/O error.
    ///
    /// # Stubbed admission path
    ///
    /// Active enrollment (signing and submitting the member-admission
    /// Contribution) requires the Registry to publish the founding
    /// Contribution first (CIRISRegistry#56 / #59). This method
    /// provides the read-side check; the write-side admission-ceremony
    /// surface is **gated on CIRISRegistry#59** and is not implemented
    /// here yet. When the founding Contribution lands and the Registry
    /// publishes this node's admission Contribution, the member row will
    /// appear in the roster and this method transitions from
    /// `Ok(false)` to `Ok(true)` automatically.
    pub async fn is_enrolled(&self) -> Result<bool, EnrollmentError> {
        // Use `Engine::federation_directory()` to get the typed trait
        // object — this works for both SQLite and Postgres engines.
        //
        // GATING NOTE (CIRISRegistry#59): `lookup_community` returns
        // `Ok(None)` when the community Contribution has not yet been
        // ingested by the local directory — that is NOT an error.
        // Return `Ok(false)` so callers can log-and-retry without
        // alarming the operator on a fresh deployment.
        let directory = self.engine.federation_directory();
        let community = directory
            .lookup_community(CIRIS_CANONICAL_COMMUNITY_KEY_ID)
            .await
            .map_err(|e| EnrollmentError::Directory(e.to_string()))?;

        let Some(community) = community else {
            // Community Contribution not yet in local directory. Normal
            // transient state during the founding ceremony.
            tracing::debug!(
                community_key_id = CIRIS_CANONICAL_COMMUNITY_KEY_ID,
                "ciris-canonical community not yet in local directory; \
                 enrollment pending CIRISRegistry#59",
            );
            return Ok(false);
        };

        let enrolled = community
            .members
            .iter()
            .any(|m| m.key_id == self.local_key_id);

        if enrolled {
            tracing::debug!(
                local_key_id = %self.local_key_id,
                community_key_id = CIRIS_CANONICAL_COMMUNITY_KEY_ID,
                "enrolled in ciris-canonical",
            );
            Ok(true)
        } else {
            Err(EnrollmentError::NotYetMember {
                key_id: self.local_key_id.clone(),
            })
        }
    }

    /// The `key_id` this enrollment tracker was constructed for.
    pub fn local_key_id(&self) -> &str {
        &self.local_key_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn community_key_id_constant_matches_registry_decision() {
        // CIRISRegistry#56 LOCKED decision: the anchor key is
        // "ciris-canonical". This constant must never drift.
        assert_eq!(CIRIS_CANONICAL_COMMUNITY_KEY_ID, "ciris-canonical");
    }

    #[test]
    fn enrollment_error_not_yet_member_message_is_actionable() {
        let err = EnrollmentError::NotYetMember {
            key_id: "lens-us-east-1".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("lens-us-east-1"), "key_id in message: {msg}");
        assert!(
            msg.contains("ciris-canonical"),
            "community in message: {msg}"
        );
    }

    #[test]
    fn enrollment_error_directory_message_carries_cause() {
        let err = EnrollmentError::Directory("connection refused".into());
        assert!(err.to_string().contains("connection refused"));
    }
}
