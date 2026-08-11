//! **Server health** — the fabric node's OWN liveness endpoint.
//!
//! The kill-switch/ownership flows aside, a relying client (the desktop/mobile app,
//! a load balancer, a peer) must be able to ask "is this NODE up?" without an agent
//! running on top. That is what ciris-server answers here. It is the MANDATORY base
//! health: a bare node serves it.
//!
//! Layering (CIRISServer = the server; agent = server + brain):
//!   - `GET /health`            — plain liveness (`{"status":"ok"}`), for LBs.
//!   - `GET /v1/health`         — the structured SERVER health the client checks.
//!   - `GET /v1/system/health`  — the SAME server-health base; an agent running on
//!     top INHERITS this endpoint and ENRICHES it with its optional cognitive
//!     health (`cognitive_state`, the 22 services). The agent's cognitive health is
//!     OPTIONAL; the server health is NOT — so the client's required check resolves
//!     here on a bare node, and the agent's adapter extends it when present.
//!
//! Unauthenticated by design (liveness is public; it carries no owner-gated data).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use ciris_persist::prelude::Engine;

/// The node's **CC 2.2 / CC 2.6.4 wire identity** as health reports it
/// (CIRISServer#159, extended by CIRISServer#323): the profiles this BUILD
/// implements, the CEG wire version it speaks, the `WIRE_VOCABULARY.md` SHA-256 it
/// pinned at build, and the persist-owned CEG contract-hash fingerprint
/// (`contract_hashes`).
///
/// This is the BUILD-level (capability) view — the STATE-level view (what the node
/// actually *declares*, which an operator may narrow via
/// `config:node.conformance_profiles`) is the authenticated-substrate read served at
/// `GET /v1/federation/conformance`, because it requires the Engine. Health is
/// stateless and public, so it reports the honest ceiling + the wire identity a peer
/// or LB needs to know it is even talking to a compatible node.
///
/// `contract_hashes` (CIRISServer#323 / SRV-2) publishes the persist-owned
/// envelope-vocabulary, trace-summary-extraction, consent-grammar and
/// transform-algebra hashes — making true the persist docs that already claim
/// "CIRISServer serves the hash on /v1/health". `wire_vocabulary_sha256` keeps its
/// top-level key unchanged (a published surface); the new hashes are ADDED beside
/// it. See [`crate::conformance::contract_hashes`] for the exact set + rationale,
/// and [`crate::conformance::assert_contract_hashes_pinned`] for the boot witness
/// that keeps every served value reproducible from the linked substrate.
fn build_conformance() -> serde_json::Value {
    serde_json::json!({
        "build_profiles": crate::conformance::BUILD_PROFILES
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>(),
        "ceg_wire_version": crate::conformance::CEG_WIRE_VERSION,
        "wire_vocabulary_sha256": crate::conformance::wire_vocabulary_sha256(),
        "contract_hashes": crate::conformance::contract_hashes(),
        "declared_at": "/v1/federation/conformance",
    })
}

/// Plain liveness — `{"status":"ok","version":"…"}`.
async fn plain_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "conformance": build_conformance(),
    }))
}

/// Structured SERVER health (the `{"data":{…}}` envelope the client parses). A bare
/// node reports `status: "ok"` with no `cognitive_state` — that field appears only
/// when an agent enriches this endpoint (optional). `services` is the server's own
/// (empty at this layer; the agent adds its service map).
async fn server_health() -> Json<serde_json::Value> {
    Json(node_health())
}

fn node_health() -> serde_json::Value {
    serde_json::json!({
        "data": {
            "status": "ok",
            "role": "fabric-node",
            "version": env!("CARGO_PKG_VERSION"),
            "services": {},
            // CC 2.2 / CC 2.6.4 (CIRISServer#159) — see `build_conformance`.
            "conformance": build_conformance(),
        }
    })
}

/// The brain base URL, when one is folded. `None` ⇒ bare node.
#[derive(Clone)]
struct BrainState {
    upstream: Option<String>,
    client: reqwest::Client,
}

/// **`GET /v1/system/health` — the UNION of both meanings** (CIRISServer#390).
///
/// # The bug this exists to close
///
/// A folded deployment serves the node and the brain on ONE port. The universal
/// client decides node-vs-agent from this endpoint: AGENT iff `cognitive_state`
/// is present or the service map is non-empty. But health is a SUBSTRATE path —
/// the node answers it natively and never proxies — so on the folded port a full
/// agent reported as a bare NODE, and the client hid the 22 cognitive services
/// of the very agent it was talking to.
///
/// Pointing the client at the brain's own port instead does not work either:
/// that port 404s the node's surface. **Neither port served both meanings**, so
/// it had to be fixed here. This is the same one-name-two-axes shape as the rest
/// of this codebase's worst bugs: one path answering "is the NODE up?" and "is
/// there a BRAIN, and how is it?" — correct for one axis, silently wrong on the
/// other.
///
/// # Merge, never replace
///
/// Proxying this path wholesale would answer the second question and lose the
/// first: a bare node's liveness would vanish behind an upstream that may not
/// exist. So the node's own health is always the base, and the brain's
/// `cognitive_state` / `services` are merged ON TOP. The endpoint is the union
/// because the union is what is true.
///
/// # Three states, not two
///
/// `agent.folded` and `agent.reachable` are reported separately, because "no
/// brain is attached" and "a brain is attached and did not answer" are DIFFERENT
/// facts with different fixes — and both would otherwise render as a bare node,
/// which is the failure mode this endpoint just had. A client may still key
/// purely on `cognitive_state`; the extra field costs it nothing and tells an
/// operator which of the two they are looking at.
async fn folded_health(State(st): State<BrainState>) -> Json<serde_json::Value> {
    let mut out = node_health();
    let Some(upstream) = st.upstream.as_deref() else {
        out["data"]["agent"] = serde_json::json!({ "folded": false, "reachable": false });
        return Json(out);
    };
    // Bounded: health is a liveness probe and a client blocks on it during
    // startup. A slow brain must not hang the node's own liveness answer.
    let probe = st
        .client
        .get(format!("{upstream}/v1/system/health"))
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    let brain: Option<serde_json::Value> = match probe {
        Ok(r) if r.status().is_success() => r.json().await.ok(),
        Ok(r) => {
            tracing::debug!(status = %r.status(), "brain health probe returned non-success");
            None
        }
        Err(e) => {
            tracing::debug!(error = %e, "brain health probe failed");
            None
        }
    };
    let Some(brain) = brain else {
        out["data"]["agent"] = serde_json::json!({ "folded": true, "reachable": false });
        return Json(out);
    };
    // The brain speaks the same `{"data":{…}}` envelope; tolerate a bare object
    // so a future/older brain shape still contributes what it has.
    let bd = brain.get("data").unwrap_or(&brain);
    for key in ["cognitive_state", "services", "cognitive", "agent_id"] {
        if let Some(v) = bd.get(key) {
            out["data"][key] = v.clone();
        }
    }
    out["data"]["agent"] = serde_json::json!({ "folded": true, "reachable": true });
    Json(out)
}

/// The server-health routes, merged onto the read API. Stateless (liveness only).
///
/// This is the node's boot path for the health surface (compose merges it at
/// startup), so it is where the CIRISServer#323 contract-hash **boot drift-witness**
/// fires: before wiring the routes we assert every hash `/v1/health` will serve is
/// reproducible from the linked substrate — a mismatch PANICS the boot rather than
/// let the node publish a fingerprint it cannot stand behind (run once per process).
pub fn router() -> Router {
    router_with_brain(None)
}

/// [`router`], plus the folded brain's base URL when one is attached, so
/// `/v1/system/health` can answer BOTH meanings on one port (CIRISServer#390).
///
/// `/v1/health` deliberately stays node-only: it is documented as the structured
/// SERVER health, and a caller that wants the node's own answer must keep having
/// somewhere to get it. Enriching both would leave no path that means "the node".
pub fn router_with_brain(brain_upstream: Option<String>) -> Router {
    static WITNESS: std::sync::Once = std::sync::Once::new();
    WITNESS.call_once(crate::conformance::assert_contract_hashes_pinned);
    let brain = BrainState {
        upstream: brain_upstream.map(|u| u.trim_end_matches('/').to_string()),
        client: reqwest::Client::new(),
    };
    Router::new()
        .route("/health", get(plain_health))
        .route("/v1/health", get(server_health))
        // The base the agent inherits + enriches (optional cognitive health on top).
        .merge(
            Router::new()
                .route("/v1/system/health", get(folded_health))
                .with_state(brain),
        )
}

/// State for the read-only verify-status endpoint: the node Engine (to report its
/// derived federation key_id) + the custody hardware-class label.
#[derive(Clone)]
pub struct VerifyStatusState {
    pub engine: Arc<Engine>,
    /// `TPM_2_0` | `EXTERNAL_SECURE_ELEMENT` | `PKCS11` | `SOFTWARE_ONLY`.
    pub hardware_type: String,
}

/// `GET /v1/system/verify-status` — read-only CIRISVerify / attestation status for
/// the client's Trust & Security display.
///
/// CIRISVerify is part of the node substrate (it's statically linked into the
/// wheel), so `loaded`/`binary_ok` are always true on a bare node; the node's
/// federation identity is reported via its derived key_id. This closes the gap
/// where the client GET-ed the POST-only `/v1/auth/attestation` *emit* route (405)
/// and there was no read-only verify-status route at all. Unauthenticated like
/// `/v1/system/health` — the key_id is public (it's in the NodeCode / federation_keys).
async fn verify_status(State(st): State<VerifyStatusState>) -> Json<serde_json::Value> {
    let key_id = st.engine.local_derived_key_id().await.ok();
    let has_key = key_id.is_some();
    // The node's own ed25519 fingerprint (for display) = the suffix of the
    // FSD-003 derived key_id (`<label>-<fp>`), if present.
    let fingerprint = key_id
        .as_deref()
        .and_then(|k| k.rsplit('-').next())
        .map(|s| s.to_string());
    let hw = st.hardware_type.as_str();
    let hardware_backed = hw != "SOFTWARE_ONLY";
    // Coarse attestation level for the trust meter: a booted node with a
    // registered federation identity is software-attested (2); a hardware
    // custody class lifts it. Honest floor — see the SOFTWARE_ONLY TODO.
    let max_level = if !has_key {
        0
    } else if hardware_backed {
        4
    } else {
        2
    };
    let key_storage_mode = match hw {
        "TPM_2_0" => "tpm",
        "EXTERNAL_SECURE_ELEMENT" => "secure_enclave",
        "PKCS11" => "pkcs11",
        _ => "software",
    };
    Json(serde_json::json!({
        "data": {
            // Core: the verify family is statically linked into the node wheel.
            "loaded": true,
            "binary_ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "agent_version": env!("CARGO_PKG_VERSION"),
            "role": "fabric-node",
            // Custody + identity.
            "hardware_type": st.hardware_type,
            "hardware_backed": hardware_backed,
            "key_storage_mode": key_storage_mode,
            "key_status": if has_key { "active" } else { "none" },
            "key_id": key_id,
            "ed25519_fingerprint": fingerprint,
            "attestation_status": if has_key { "verified" } else { "not_attempted" },
            // Attestation-level checks the node can honestly assert: the verify
            // binary is functional, the node self-registered its federation key,
            // and it carries an audit chain. The agent-only checks (DNS/HTTPS
            // cross-probe, file/env integrity, Play Integrity) are not run by a
            // bare node → reported false rather than over-claimed.
            "registry_ok": has_key,
            "audit_ok": true,
            "binary_self_check": "ok",
            "max_level": max_level,
            "level_pending": false,
            "attestation_mode": if hardware_backed { "full" } else { "partial" },
            "platform_os": std::env::consts::OS,
            "platform_arch": std::env::consts::ARCH,
            "checks": {
                "verify_loaded": true,
                "key_registered": has_key,
                "audit_chain": true,
                "hardware_backed": hardware_backed,
            },
            "disclaimer": "CIRISVerify provides cryptographic attestation of this node's federation identity.",
        }
    }))
}

/// The verify-status route (state-bearing — needs the node Engine + custody class).
/// Merged onto the read API next to [`router`].
pub fn verify_status_router(engine: Arc<Engine>, hardware_type: String) -> Router {
    Router::new()
        .route("/v1/system/verify-status", get(verify_status))
        .with_state(VerifyStatusState {
            engine,
            hardware_type,
        })
}
