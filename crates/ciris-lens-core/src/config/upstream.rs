//! `UpstreamLens` — one destination in the multi-recipient fan-out
//! (FSD §3).
//!
//! A client-mode lens-core forwards each sealed trace to **N**
//! upstreams, each with its own [`EgressFilter`]. The destination is
//! identified by the lens's federation `key_id`, NOT a hostname — the
//! transport (HTTP, Reticulum, LoRa, I²P) resolves the key via
//! persist's `federation_keys` directory + edge's `peer_urls` map.
//! Key rotation is a directory update; no DNS in the trust path
//! (FSD §1).

use serde::{Deserialize, Serialize};

use crate::config::EgressFilter;

/// A single destination lens for outbound forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UpstreamLens {
    /// The upstream lens's `federation_keys.key_id`. Edge resolves
    /// this to a transport endpoint via its `peer_urls` map; the
    /// resolution boundary is keyring + directory, not DNS.
    pub lens_steward_key_id: String,

    /// What gets forwarded to this upstream.
    pub egress_filter: EgressFilter,
}

impl UpstreamLens {
    /// Construct an upstream destination.
    pub fn new(lens_steward_key_id: impl Into<String>, egress_filter: EgressFilter) -> Self {
        Self {
            lens_steward_key_id: lens_steward_key_id.into(),
            egress_filter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::TraceLevel;

    #[test]
    fn ctor_accepts_string_like_key_id() {
        let u = UpstreamLens::new("lens-prod-eu-west", EgressFilter::default());
        assert_eq!(u.lens_steward_key_id, "lens-prod-eu-west");
    }

    #[test]
    fn serde_roundtrip_preserves_destination_and_filter() {
        let u = UpstreamLens::new(
            "my-sovereign-anchor",
            EgressFilter::new(TraceLevel::Detailed),
        );
        let json = serde_json::to_string(&u).unwrap();
        let back: UpstreamLens = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
        assert_eq!(back.egress_filter.trace_level, TraceLevel::Detailed);
    }
}
