//! **Broadcasting the portable trust root** (`GET /v1/trust-root/bundle`).
//!
//! The federation-facing read of the `GenesisBundle` persist bakes: the
//! `humanity-accord` charter, its A1/B1/C1 holder roster, the `infra:*` scopes
//! that charter confers, and the serve-node grants issued under it.
//!
//! # Why this exists, and what it replaces
//!
//! CIRISRegistry published its own key as its own trust root at
//! `GET /v1/steward-key`. That endpoint is being retired rather than repaired
//! (CIRISRegistry#133), and the reasoning is worth carrying here because it is
//! the whole design constraint on this module:
//!
//! - the response carried **no signature at all**, while declaring
//!   `signature_mode: "HYBRID_REQUIRED"` — trust-root material arriving
//!   unauthenticated on the wire;
//! - it asserted `hardware_class: HSM_PROD` under `self_attested: true`, which
//!   is a producer claim, not evidence (CC 4.2.2.1);
//! - and three mutually incompatible schemas for it exist across the fleet, no
//!   two of which agree, so nothing was successfully consuming it anyway.
//!
//! The replacement is not "the same thing, signed". It is a different *shape* of
//! claim. A node no longer publishes a root it asserts; it serves the root it was
//! **conferred by**, and that artifact carries its own proof.
//!
//! # The authority is inside `bundle`, and nowhere else
//!
//! This is the property that must survive every future edit to this file.
//!
//! The bundle is **self-authenticating**: its `authorizations` are hybrid
//! Ed25519 + ML-DSA-65 signatures from accord holders over the charter, and
//! `verify_bundle_quorum` re-derives authority from the reader's OWN records
//! rather than from anything the bundle says about itself. A forged bundle
//! carrying attacker "holders" proves nothing (the CIRISPersist#377 lesson).
//!
//! Everything OUTSIDE `bundle` in this response — `bundle_fingerprint`,
//! `charter_root_key_id`, `served_by` — is **unsigned convenience metadata**. It
//! is this node's unverified claim about itself and about bytes it is relaying.
//! A consumer MUST verify the bundle and MUST NOT promote any outer field to a
//! trust decision. Signing the envelope would not help: it would only prove that
//! the relaying node said it, which is precisely the thing `/v1/steward-key`
//! proved and precisely the thing that was worthless.
//!
//! So: no `response_signature` here, deliberately, and the field names say
//! `served_by` rather than anything that reads like an attestation.
//!
//! # Public by design
//!
//! Unlike [`crate::trust_root_api`] — whose import/list/delete verbs are
//! loopback-gated, because choosing a node's trust root is the operator's own
//! act — this is a **federation read**. The bundle is entirely public material:
//! public keys, signatures, an already-announced transport hint, and YubiKey PIV
//! attestation certificates. There is nothing here to withhold, and withholding
//! it would defeat the point: a peer bootstrapping into the mesh needs to be able
//! to fetch the root and check it against its own roster.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::Serialize;

#[derive(Clone)]
pub struct BroadcastState {
    pub engine: Arc<Engine>,
    /// THIS node's federation key — the `user_key_id` side of the trust edge,
    /// and therefore the identity whose acceptance is being reported.
    pub node_key_id: String,
}

/// What this node says about itself while relaying the bundle. **Unsigned.**
///
/// Present so a consumer can tell a node that merely *knows* the root from one
/// that has actually accepted it — useful for diagnostics, never for trust.
#[derive(Debug, Serialize)]
struct ServedBy {
    node_key_id: String,
    /// Does this node's own `trust:accepts` edge reach the charter root?
    ///
    /// `false` is a legitimate state, not an error: a node can hold and relay
    /// the bundle without having accepted it. It is also the operator's un-trust
    /// lever — deleting that one row flips this and fails the node's own gates
    /// closed, without touching the bundle it serves.
    accepts_this_root: bool,
}

#[derive(Debug, Serialize)]
struct BundleBroadcast {
    /// The artifact. **The only part of this response that carries authority.**
    bundle: serde_json::Value,
    /// Content fingerprint of `bundle`, so a caller can cheaply notice a change
    /// without diffing. Convenience only — recompute it yourself if it matters.
    bundle_fingerprint: Option<String>,
    /// The charter root the bundle declares (`humanity-accord`). Read off the
    /// bundle for discoverability; verify it, do not trust it.
    charter_root_key_id: Option<String>,
    served_by: ServedBy,
}

fn err(code: StatusCode, reason: &str, msg: impl Into<String>) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": msg.into(), "reason_id": reason })),
    )
        .into_response()
}

/// `GET /v1/trust-root/bundle` — serve the portable trust root.
async fn get_bundle(State(st): State<BroadcastState>) -> Response {
    let bundle = ciris_persist::federation::genesis::canonical_genesis_bundle();

    let bundle_json = match serde_json::to_value(bundle) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "bundle_not_serializable",
                format!("the baked genesis bundle could not be serialized: {e}"),
            )
        }
    };

    // Both of these are best-effort. A bundle we cannot fingerprint or whose
    // charter we cannot name is still worth serving — the consumer verifies the
    // bundle itself, and withholding the artifact because a convenience field is
    // unavailable would trade a real capability for a cosmetic one.
    let bundle_fingerprint = crate::mesh_genesis::fingerprint(bundle).ok();
    let charter_root_key_id = crate::mesh_genesis::charter_root_key_id(bundle);

    let accepts_this_root = match &charter_root_key_id {
        Some(root) => ciris_persist::federation::trust_root::trust_root_valid(
            st.engine.federation_directory().as_ref(),
            &st.node_key_id,
            root,
        )
        .await
        .ok()
        .and_then(|v| serde_json::to_value(&v).ok())
        .and_then(|j| j.get("user_accepts").and_then(serde_json::Value::as_bool))
        .unwrap_or(false),
        None => false,
    };

    Json(BundleBroadcast {
        bundle: bundle_json,
        bundle_fingerprint,
        charter_root_key_id,
        served_by: ServedBy {
            node_key_id: st.node_key_id.clone(),
            accepts_this_root,
        },
    })
    .into_response()
}

/// The broadcast router. **Merge WITHOUT a loopback layer** — see the module
/// docs: this is a federation read, and a peer bootstrapping into the mesh has
/// to be able to reach it.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    Router::new()
        .route("/v1/trust-root/bundle", axum::routing::get(get_bundle))
        .with_state(BroadcastState {
            engine,
            node_key_id,
        })
}

#[cfg(test)]
mod tests {
    //! The invariant under test is not "the handler returns 200". It is that the
    //! response carries the artifact and claims no authority of its own — the
    //! failure mode `/v1/steward-key` shipped for years.

    use super::*;

    fn baked() -> &'static crate::mesh_genesis::GenesisBundle {
        ciris_persist::federation::genesis::canonical_genesis_bundle()
    }

    /// The bundle we broadcast is the one persist bakes, reached through the
    /// same accessor everything else uses — not a second path to the same bytes
    /// that could drift from it.
    #[test]
    fn the_broadcast_serves_the_baked_bundle_verbatim() {
        let b = baked();
        let json = serde_json::to_value(b).expect("bundle serializes");
        assert!(
            json.get("authorizations").is_some(),
            "the authorizations are what make this artifact self-authenticating — \
             a bundle serialized without them would be exactly the unsigned \
             trust-root material /v1/steward-key shipped"
        );
        assert!(
            json.get("holders").is_some() && json.get("serve_nodes").is_some(),
            "a consumer needs the holder roster to verify the quorum and the serve \
             nodes to know who was blessed under it"
        );
    }

    /// The charter names the capability ceiling of the whole trust domain. If
    /// this ever stops carrying the four infra verbs, the registry slice's role
    /// gate silently stops being satisfiable — so pin it here, where the bundle
    /// is served, and not only where it is consumed.
    #[test]
    fn the_charter_confers_the_infra_verbs_the_registry_slice_needs() {
        let json = serde_json::to_value(baked()).expect("bundle serializes");
        let charter = json["attestations"]
            .as_array()
            .expect("attestations is an array")
            .iter()
            .find(|a| a["attestation"]["attestation_id"] == "genesis-charter")
            .expect("the bundle carries a genesis-charter");
        let scope = charter["attestation"]["attestation_envelope"]["scope"]
            .as_array()
            .expect("the charter declares a scope array");
        let scopes: Vec<&str> = scope.iter().filter_map(|s| s.as_str()).collect();
        for needed in [
            ciris_persist::federation::trust_root::INFRA_ATTEST_SCOPE,
            ciris_persist::federation::trust_root::INFRA_SERVE_SCOPE,
        ] {
            assert!(
                scopes.contains(&needed),
                "the charter must confer {needed} — the registry slice's role gate \
                 walks for it (FSD/REGISTRY_SLICE_ROLE_GATE.md). Charter carries: {scopes:?}"
            );
        }
    }

    /// The outer envelope must stay authority-free. A `response_signature` here
    /// would only prove the relaying node said it — the exact worthless claim
    /// /v1/steward-key made — and would invite consumers to check the wrapper
    /// instead of the bundle.
    #[test]
    fn the_outer_envelope_claims_no_authority() {
        let body = BundleBroadcast {
            bundle: serde_json::json!({"stub": true}),
            bundle_fingerprint: Some("f".into()),
            charter_root_key_id: Some("humanity-accord".into()),
            served_by: ServedBy {
                node_key_id: "some-node".into(),
                accepts_this_root: true,
            },
        };
        let json = serde_json::to_value(&body).expect("serializes");
        let outer: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for forbidden in ["response_signature", "signature_mode", "hardware_class"] {
            assert!(
                !outer.contains(&forbidden),
                "`{forbidden}` must not appear on the outer envelope: the authority \
                 lives inside `bundle` and signing the wrapper would prove only that \
                 the relay said so (CIRISRegistry#133)"
            );
        }
        assert!(
            outer.contains(&"bundle"),
            "the artifact itself must be present — it is the only part that matters"
        );
    }
}
