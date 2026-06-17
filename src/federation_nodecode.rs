//! The node's own NodeCode — the QR-able federation-key bootstrap handle
//! (CEG §0.10) the operator reads off THIS node and hands to a founder's app.
//!
//! `GET /v1/federation/node-code` (UNAUTHENTICATED — the code is a PUBLIC
//! bootstrap handle, carrying only this node's `key_id`, its Ed25519 pubkey, and
//! optional transport/alias hints; there is nothing secret to gate, and a peer
//! must be able to read it out-of-band to bootstrap). It returns:
//!
//! ```json
//! { "code": "CIRIS-V1-...", "qr_payload": "CIRIS-V1-...", "key_id": "...", "alias_hint": "..." }
//! ```
//!
//! matching the agent's `GET /v1/system/peers/my-node-code` response shape.
//!
//! The code is built ONCE at boot from THIS node's steward `key_id` + the raw
//! Ed25519 pubkey of its federation signing key (the same pubkey carried on the
//! self-signed `SignedKeyRecord`), plus a `transport_hint` (`CIRIS_TRANSPORT_HINT`,
//! falling back to the node's public base URL env) and an optional `alias_hint`
//! (`CIRIS_NODE_ALIAS`). It is stable for the node's lifetime and served verbatim.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::nodecode::{self, NodeCode};

/// Env: an explicit transport hint embedded in this node's NodeCode (e.g. a
/// `tcp://host:port` or `https://host` a peer's UI shows on first contact). Not
/// authoritative — Edge resolves real transports via its own discovery.
pub const ENV_TRANSPORT_HINT: &str = "CIRIS_TRANSPORT_HINT";
/// Env: a public base URL used as the transport hint when [`ENV_TRANSPORT_HINT`]
/// is unset (the node's reachable HTTP address).
pub const ENV_PUBLIC_BASE_URL: &str = "CIRIS_PUBLIC_BASE_URL";
/// Env: a human-readable alias the node suggests for itself in the NodeCode.
pub const ENV_NODE_ALIAS: &str = "CIRIS_NODE_ALIAS";

#[derive(Clone)]
struct NodeCodeState {
    /// The pre-rendered response JSON — built once at boot, served verbatim.
    response_json: Arc<String>,
}

/// Resolve the transport hint from the env surface: explicit `CIRIS_TRANSPORT_HINT`,
/// else the node's public base URL, else none.
fn transport_hint_from_env() -> Option<String> {
    for key in [ENV_TRANSPORT_HINT, ENV_PUBLIC_BASE_URL] {
        if let Ok(v) = std::env::var(key) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// The alias hint from `CIRIS_NODE_ALIAS`, if set + non-empty.
fn alias_hint_from_env() -> Option<String> {
    std::env::var(ENV_NODE_ALIAS)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Build THIS node's [`NodeCode`] from its steward `key_id` + raw Ed25519 pubkey
/// (base64) + env-derived hints. The pubkey is the same `pubkey_ed25519_base64`
/// carried on the self-signed `SignedKeyRecord` (the federation signing key).
pub fn build_node_code(key_id: &str, pubkey_ed25519_base64: &str) -> NodeCode {
    NodeCode {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: pubkey_ed25519_base64.to_string(),
        transport_hint: transport_hint_from_env(),
        alias_hint: alias_hint_from_env(),
    }
}

/// Render the `GET /v1/federation/node-code` response JSON for a given NodeCode.
/// Returns an `Err` only if the identity is structurally un-encodable (a wrong-
/// size / non-base64 pubkey), which is a boot-time misconfiguration.
pub fn render_response_json(nc: &NodeCode) -> Result<String, nodecode::NodeCodeError> {
    let code = nodecode::encode(nc)?;
    let qr_payload = nodecode::encode_qr(nc)?;
    Ok(serde_json::json!({
        "code": code,
        "qr_payload": qr_payload,
        "key_id": nc.key_id,
        "alias_hint": nc.alias_hint,
    })
    .to_string())
}

async fn node_code(State(st): State<NodeCodeState>) -> Response {
    (
        [(CONTENT_TYPE, "application/json")],
        (*st.response_json).clone(),
    )
        .into_response()
}

/// The node-code router — merge onto the read-API listener beside the other
/// federation routers. `response_json` is THIS node's pre-rendered NodeCode
/// response, built once at boot (stable for the node's lifetime).
pub fn router(response_json: String) -> Router {
    Router::new()
        .route("/v1/federation/node-code", axum::routing::get(node_code))
        .with_state(NodeCodeState {
            response_json: Arc::new(response_json),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    #[test]
    fn response_json_decodes_back_to_identity() {
        let pk = B64.encode([9u8; 32]);
        let nc = NodeCode {
            key_id: "ciris-server".into(),
            pubkey_ed25519_base64: pk.clone(),
            transport_hint: Some("https://node.example".into()),
            alias_hint: Some("Test Node".into()),
        };
        let json = render_response_json(&nc).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["key_id"], "ciris-server");
        assert_eq!(v["alias_hint"], "Test Node");
        let decoded = nodecode::decode(v["code"].as_str().unwrap()).unwrap();
        assert_eq!(decoded.key_id, "ciris-server");
        assert_eq!(decoded.pubkey_ed25519_base64, pk);
        // The qr_payload decodes to the same identity.
        let decoded_qr = nodecode::decode(v["qr_payload"].as_str().unwrap()).unwrap();
        assert_eq!(decoded_qr, decoded);
    }
}
