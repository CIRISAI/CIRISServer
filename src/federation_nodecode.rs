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
//! self-signed `SignedKeyRecord`), plus an optional `transport_hint` and an
//! optional `alias_hint` (Server 0.5: the `node.alias` config:* object, resolved
//! at boot — no `CIRIS_NODE_ALIAS` env). It is stable for the node's lifetime and
//! served verbatim.

use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::Router;

use crate::nodecode::{self, NodeCode};

#[derive(Clone)]
struct NodeCodeState {
    /// The pre-rendered response JSON — built once at boot, served verbatim.
    response_json: Arc<String>,
}

/// Normalize an optional hint string: trimmed, `None` when empty.
fn nonempty(hint: Option<String>) -> Option<String> {
    hint.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Build THIS node's [`NodeCode`] from its steward `key_id` + raw Ed25519 pubkey
/// (base64) + boot-resolved hints. The pubkey is the same `pubkey_ed25519_base64`
/// carried on the self-signed `SignedKeyRecord` (the federation signing key).
///
/// `alias_hint` is the boot-resolved `node.alias` config:* value (Server 0.5 — no
/// `CIRIS_NODE_ALIAS` env); `transport_hint` is an optional reachability hint a
/// peer's UI may show on first contact (not authoritative — Edge resolves real
/// transports via its own discovery).
pub fn build_node_code(
    key_id: &str,
    pubkey_ed25519_base64: &str,
    alias_hint: Option<String>,
    transport_hint: Option<String>,
) -> NodeCode {
    NodeCode {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: pubkey_ed25519_base64.to_string(),
        transport_hint: nonempty(transport_hint),
        alias_hint: nonempty(alias_hint),
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
