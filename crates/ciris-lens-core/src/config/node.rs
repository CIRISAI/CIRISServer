//! Node-mode configuration types (FSD §3 + #15).
//!
//! Three structs exclusive to node mode:
//!
//! - [`PeerAcl`] — which federation steward keys may query the read
//!   API (auth middleware + allow-list).
//! - [`ScoringConfig`] — sample-size gate and RATCHET calibration
//!   bundle version stamped onto every score.
//! - [`UxConfig`] — API + web-shell root paths. Web shell is out of
//!   scope for v0.4 (`web_root = None`); `api_root` sets the axum
//!   router prefix.
//!
//! All three are `#[non_exhaustive]` — future minor versions may add
//! fields. Constructing them by name (not `..`) is required.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use ciris_persist::prelude::Engine;

/// Which federation steward keys are allowed to query the node's
/// read API.
///
/// The three postures map to the deployment use-cases:
///
/// - `AllowAll` — open/local-dev; no signature check beyond the
///   verify step.
/// - `AllowList(Vec<key_id>)` — explicit static allow-list operator
///   knows all peers in advance.
/// - `FromDirectory(engine)` — derive the allow-list from the host
///   Engine's `federation_keys` table at request time. This is the
///   production posture: federation-registered peers are trusted,
///   unregistered keys are rejected.
///
/// The auth middleware calls
/// `engine.verify_hybrid_via_directory(signing_key_id, canonical,
/// ed25519_sig, ml_dsa_sig)` for every request and then checks the
/// `signing_key_id` against this ACL.
#[derive(Clone)]
#[non_exhaustive]
pub enum PeerAcl {
    /// No key-ID allow-list check after verify — any valid federation
    /// signature is accepted. Suitable for local-dev / single-operator
    /// node with the full federation trusted.
    AllowAll,

    /// Static allow-list. Only `signing_key_id` values present in this
    /// list pass after verify. Good for small known-peer deployments
    /// where the operator controls both sides.
    AllowList(Vec<String>),

    /// Derive the allow-list from the host Engine's `federation_keys`
    /// table at request time. Production posture: every registered
    /// federation key is trusted; unregistered keys are rejected with
    /// `401 unauthorized_key`.
    ///
    /// The `Arc<Engine>` is the same process-singleton the node was
    /// constructed with — one Engine, multiple shared handles.
    FromDirectory(Arc<Engine>),
}

impl PeerAcl {
    /// Derive the allow-list from the host Engine's federation
    /// directory. Production constructor matching the PyO3 surface's
    /// `cl.PeerAcl.from_directory(engine)`.
    pub fn from_directory(engine: Arc<Engine>) -> Self {
        Self::FromDirectory(engine)
    }

    /// Check whether `key_id` is permitted under this ACL.
    ///
    /// `AllowAll` always returns `true`. `AllowList` checks the
    /// static list. `FromDirectory` defers to the engine's directory
    /// lookup — for the HTTP middleware this is done post-verify, so
    /// the key is already structurally valid; the ACL is an identity
    /// allow-list, not a crypto check.
    ///
    /// This sync helper covers the `AllowAll` + `AllowList` paths.
    /// The `FromDirectory` path is handled by the auth middleware via
    /// the Engine handle (directory lookup is async but the engine
    /// exposes a sync federation-key check for this purpose via the
    /// `verify_hybrid_via_directory` roundtrip — if verify succeeds
    /// the key IS in the directory, so `FromDirectory` is effectively
    /// `AllowAll` post-verify for registered keys; unregistered keys
    /// fail verify before this check fires).
    pub fn permits(&self, key_id: &str) -> bool {
        match self {
            Self::AllowAll => true,
            Self::AllowList(list) => list.iter().any(|k| k == key_id),
            // Post-verify the signing key is in the directory by
            // construction (verify_hybrid_via_directory checks this).
            // FromDirectory = AllowAll post-verify.
            Self::FromDirectory(_) => true,
        }
    }
}

/// Scoring configuration for node mode.
///
/// These values are stamped onto every score emitted by the node and
/// used by the read API to filter / annotate responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ScoringConfig {
    /// Minimum cohort sample count required to emit a `Numeric` score
    /// (LC-AV-18). Below this gate the score is
    /// `ManifoldConformity::Indeterminate { SampleSizeBelowGate }`.
    /// FSD default: 500.
    pub sample_size_gate: u32,

    /// RATCHET calibration bundle version applied to scores emitted by
    /// this node. Stamped onto detection events and exposed in the
    /// `/calibration_bundles` read endpoint. `0` = no bundle loaded
    /// (cold-start / Phase-1 sentinel).
    pub ratchet_calibration_version: i32,
}

impl ScoringConfig {
    /// Construct a `ScoringConfig`.
    pub fn new(sample_size_gate: u32, ratchet_calibration_version: i32) -> Self {
        Self {
            sample_size_gate,
            ratchet_calibration_version,
        }
    }
}

impl Default for ScoringConfig {
    /// FSD §3 defaults: 500-sample gate, version 0 (no bundle).
    fn default() -> Self {
        Self {
            sample_size_gate: 500,
            ratchet_calibration_version: 0,
        }
    }
}

/// UX configuration for node mode.
///
/// Controls the HTTP server's path prefix for the read API. The web
/// shell (HTML/JS frontend) is out of scope for v0.4; `web_root` is
/// always `None` until it ships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UxConfig {
    /// The path prefix for the read API. Frozen at `/lens/api/v1` per
    /// the issue #15 contract. Must not be empty; must start with `/`.
    pub api_root: String,

    /// The path prefix for the web shell (HTML/JS). `None` = API-only
    /// (the v0.4 posture). Ships `Some(...)` when the web shell
    /// subsystem lands.
    pub web_root: Option<String>,
}

impl UxConfig {
    /// API-only configuration (the v0.4 default). `web_root = None`.
    pub fn api_only(api_root: impl Into<String>) -> Self {
        Self {
            api_root: api_root.into(),
            web_root: None,
        }
    }
}

impl Default for UxConfig {
    /// Frozen API root (`/lens/api/v1`), no web shell.
    fn default() -> Self {
        Self::api_only("/lens/api/v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoring_config_default_matches_fsd() {
        let c = ScoringConfig::default();
        assert_eq!(c.sample_size_gate, 500);
        assert_eq!(c.ratchet_calibration_version, 0);
    }

    #[test]
    fn scoring_config_serde_roundtrip() {
        let c = ScoringConfig::new(1000, 2);
        let json = serde_json::to_string(&c).unwrap();
        let back: ScoringConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn ux_config_default_api_root() {
        let u = UxConfig::default();
        assert_eq!(u.api_root, "/lens/api/v1");
        assert!(u.web_root.is_none());
    }

    #[test]
    fn ux_config_serde_roundtrip() {
        let u = UxConfig::api_only("/lens/api/v1");
        let json = serde_json::to_string(&u).unwrap();
        let back: UxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn peer_acl_allow_all_permits_any() {
        assert!(PeerAcl::AllowAll.permits("any-key-id"));
        assert!(PeerAcl::AllowAll.permits(""));
    }

    #[test]
    fn peer_acl_allow_list_permits_only_listed() {
        let acl = PeerAcl::AllowList(vec!["key-a".into(), "key-b".into()]);
        assert!(acl.permits("key-a"));
        assert!(acl.permits("key-b"));
        assert!(!acl.permits("key-c"));
        assert!(!acl.permits(""));
    }

    #[test]
    fn peer_acl_allow_list_empty_permits_none() {
        let acl = PeerAcl::AllowList(vec![]);
        assert!(!acl.permits("any"));
    }
}
