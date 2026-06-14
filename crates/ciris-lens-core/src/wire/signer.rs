//! `Ed25519TraceSigner` — typed wrapper around persist's
//! `LocalSigner` for trace + audit-event signing.
//!
//! Per `FSD/LENS_CORE_V0_5.md` §5.1. The trace-signing identity is
//! the host's local identity (CIRISAgent's local for client-mode
//! deployments; deployed-lens's local for relay/node modes). This
//! wrapper provides:
//!
//! 1. A typed API for *trace* signing specifically — distinguishing
//!    it from generic envelope signing at the lens-core call site.
//! 2. Sync sign_ed25519 + async sign_hybrid surfaces matching
//!    `LocalSigner`'s contract; canonicalization wraps the wire-
//!    contract `canonical_bytes` helper.
//! 3. Pre-binds the hybrid signature construction (canonical_bytes
//!    ++ ed25519_sig signed by PQC) so callers don't reimplement it.
//!    Same construction `verify_hybrid_via_directory` reverses on
//!    the receive side (CIRISPersist#14 + this crate's
//!    `signing::event::sign_detection`).
//!
//! Lens-core never owns key material; this is a thin wrapper over a
//! `LocalSigner` constructed by the host (persist's `Engine`).

use std::sync::Arc;

use ciris_persist::prelude::{LocalSigner, LocalSignerError};

use super::{canonical_bytes, BatchEnvelope, CanonicalError};

/// Typed trace-signing identity. Wraps a shared `LocalSigner` so
/// multiple call sites can sign without re-loading filesystem seeds.
#[derive(Clone)]
pub struct Ed25519TraceSigner {
    signer: Arc<LocalSigner>,
}

impl Ed25519TraceSigner {
    /// Wrap a pre-constructed `LocalSigner`. The signer must have
    /// been loaded with the host's local identity (filesystem
    /// seeds for Ed25519 + optional ML-DSA-65). Lens-core never
    /// constructs the underlying signer; the host (CIRISAgent or
    /// deployed-lens) constructs via `persist::signing::LocalSigner`
    /// and hands the `Arc` here.
    pub fn new(signer: Arc<LocalSigner>) -> Self {
        Self { signer }
    }

    /// The wrapped local identity's `key_id`. Stamped onto signed
    /// trace envelopes for federation-side verification via
    /// `verify_hybrid_via_directory`.
    pub fn key_id(&self) -> &str {
        self.signer.key_id()
    }

    /// Sign a [`BatchEnvelope`] with Ed25519 only. Used in transit
    /// contexts where PQC isn't required (sovereign-mode loopback,
    /// integration tests).
    pub fn sign_ed25519(&self, envelope: &BatchEnvelope) -> Result<SignedEnvelope, SignError> {
        let canonical = canonical_bytes(envelope)?;
        let ed25519_sig = self.signer.sign_ed25519(&canonical)?;
        if ed25519_sig.len() != 64 {
            return Err(SignError::SignatureShape {
                field: "ed25519_sig",
                actual: ed25519_sig.len(),
                expected: 64,
            });
        }
        Ok(SignedEnvelope {
            canonical_bytes: canonical,
            ed25519_sig: ed25519_sig.to_vec(),
            ml_dsa_65_sig: None,
            signing_key_id: self.signer.key_id().to_string(),
        })
    }

    /// Hybrid-sign a [`BatchEnvelope`] — Ed25519 + ML-DSA-65 PQC
    /// bound construction (PQC signs canonical_bytes ++ ed25519_sig).
    /// Required for federation evidence; matches
    /// `LocalSigner::sign_hybrid` and `verify_hybrid_via_directory`.
    pub async fn sign_hybrid(&self, envelope: &BatchEnvelope) -> Result<SignedEnvelope, SignError> {
        let canonical = canonical_bytes(envelope)?;
        let ed25519_sig = self.signer.sign_ed25519(&canonical)?;
        if ed25519_sig.len() != 64 {
            return Err(SignError::SignatureShape {
                field: "ed25519_sig",
                actual: ed25519_sig.len(),
                expected: 64,
            });
        }
        let mut bound = Vec::with_capacity(canonical.len() + 64);
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed25519_sig);
        let ml_dsa_65_sig = self.signer.sign_ml_dsa_65(&bound).await?;
        if ml_dsa_65_sig.len() != 3309 {
            return Err(SignError::SignatureShape {
                field: "ml_dsa_65_sig",
                actual: ml_dsa_65_sig.len(),
                expected: 3309,
            });
        }
        Ok(SignedEnvelope {
            canonical_bytes: canonical,
            ed25519_sig: ed25519_sig.to_vec(),
            ml_dsa_65_sig: Some(ml_dsa_65_sig),
            signing_key_id: self.signer.key_id().to_string(),
        })
    }
}

/// Output of [`Ed25519TraceSigner::sign_ed25519`] /
/// [`Ed25519TraceSigner::sign_hybrid`]. Carries canonical bytes,
/// signatures, and the signing key_id stamped onto downstream
/// federation evidence rows.
#[derive(Debug, Clone)]
pub struct SignedEnvelope {
    /// Canonical-JSON bytes the signatures were computed over.
    pub canonical_bytes: Vec<u8>,
    /// 64-byte Ed25519 signature.
    pub ed25519_sig: Vec<u8>,
    /// 3309-byte ML-DSA-65 signature (FIPS 204 final). `None` for
    /// `sign_ed25519`-only paths; required for federation evidence.
    pub ml_dsa_65_sig: Option<Vec<u8>>,
    /// Wrapped signer's `key_id` at sign time.
    pub signing_key_id: String,
}

/// Errors from [`Ed25519TraceSigner`] sign operations.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Canonicalization failed (typically a non-serializable
    /// `CorrelationMetadata` variant).
    #[error("canonicalize: {0}")]
    Canonicalize(#[from] CanonicalError),
    /// Underlying `LocalSigner` failed — seed read, PQC backend
    /// error, or PQC not configured for the hybrid path.
    #[error("signer: {0}")]
    Signer(#[from] LocalSignerError),
    /// Signature byte length didn't match the federation-stable
    /// expectation (Ed25519: 64 bytes; ML-DSA-65: 3309 bytes per
    /// FIPS 204 final). Fail-fast for a clearer diagnostic.
    #[error("signature shape: {field} length is {actual}, expected {expected}")]
    SignatureShape {
        /// Which signature failed the length check.
        field: &'static str,
        /// Observed byte length.
        actual: usize,
        /// Federation-stable expected length.
        expected: usize,
    },
}
