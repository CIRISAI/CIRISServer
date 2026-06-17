//! The one fabric request verifier — the `x-ciris-*` hybrid auth contract.
//!
//! Every fabric control endpoint (self-login today; federation / groups /
//! consent / erasure next) verifies through here, so the contract is unified.
//! It wraps persist's `verify_hybrid_via_directory` + [`HybridPolicy`] — the
//! same primitive + policy the lens read API uses, so the *authority* is one
//! (the federation directory + the hybrid contract), even though each crate has
//! a thin wrapper.
//!
//! It also resolves the §9 "as the user" vs "on behalf of" question: a request
//! is validly signed by the **identity itself** OR by **any admitted occurrence**
//! of it — the consenting *user* (direct, `witness_relation: self`) AND the
//! generating *agent* (delegate, `act_on_behalf`) are both valid signers
//! (§5.6.8.8 occurrence binding).

use axum::http::HeaderMap;
use ciris_persist::prelude::{verify_hybrid_via_directory, Engine, HybridPolicy};
use ciris_persist::FederationDirectory;

/// `x-ciris-signing-key-id` — the signer's `federation_keys.key_id`.
pub const HEADER_KEY_ID: &str = "x-ciris-signing-key-id";
/// `x-ciris-signature-ed25519` — base64 Ed25519 over the request body.
pub const HEADER_ED25519: &str = "x-ciris-signature-ed25519";
/// `x-ciris-signature-ml-dsa-65` — base64 ML-DSA-65 (required under Strict).
pub const HEADER_ML_DSA_65: &str = "x-ciris-signature-ml-dsa-65";

/// A signature-verified caller.
#[derive(Debug, Clone)]
pub struct VerifiedCaller {
    /// The signing key, signature-verified against the federation directory.
    pub key_id: String,
}

/// Why a request failed to authenticate.
#[derive(Debug)]
pub enum VerifyError {
    /// A mandatory `x-ciris-*` header was absent.
    MissingHeader(&'static str),
    /// No federation directory reachable (e.g. a non-SQLite Engine).
    NoDirectory,
    /// The hybrid signature did not verify under the active policy.
    SignatureInvalid(String),
}

/// Verify the `x-ciris-*` hybrid signature over `body` against the federation
/// directory. `policy` is the hard-cut gate (default callers pass
/// [`HybridPolicy::Strict`] — no classical-only path).
pub async fn verify_request(
    engine: &Engine,
    headers: &HeaderMap,
    body: &[u8],
    policy: HybridPolicy,
) -> Result<VerifiedCaller, VerifyError> {
    let key_id = header(headers, HEADER_KEY_ID)?;
    let ed25519 = header(headers, HEADER_ED25519)?;
    let ml_dsa_65 = headers
        .get(HEADER_ML_DSA_65)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    let directory = engine
        .sqlite_backend()
        .ok_or(VerifyError::NoDirectory)?
        .clone();
    verify_hybrid_via_directory(
        &*directory,
        body,
        &key_id,
        &ed25519,
        ml_dsa_65.as_deref(),
        policy,
        None,
    )
    .await
    .map_err(|e| VerifyError::SignatureInvalid(format!("{e}")))?;

    Ok(VerifiedCaller { key_id })
}

/// True if `signer` may act for `identity_key_id`: it **is** the identity, or an
/// **admitted, active occurrence** of it (§5.6.8.8). This is the corrected
/// admission rule — a user device OR the user's agent both qualify (the §9
/// as/on-behalf model), not just the root identity key.
pub async fn signer_acts_for(engine: &Engine, signer: &str, identity_key_id: &str) -> bool {
    if signer == identity_key_id {
        return true;
    }
    let Some(directory) = engine.sqlite_backend() else {
        return false;
    };
    match directory
        .list_identity_occurrences_active(identity_key_id)
        .await
    {
        Ok(occs) => occs.iter().any(|o| o.occurrence_key_id == signer),
        Err(_) => false,
    }
}

fn header(headers: &HeaderMap, name: &'static str) -> Result<String, VerifyError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or(VerifyError::MissingHeader(name))
}
