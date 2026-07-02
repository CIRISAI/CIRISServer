//! **Mesh control-plane relay** (CIRISServer#128 Phase D) — administer an owned
//! remote node by federation `key_id` over the mesh, with **no route to its IP
//! and no password on the remote** (`FSD/RNS_CONTROL_RELAY.md`, rebuilt on the
//! edge v8.0.0 generic opaque RPC per `FSD/EDGE_8_0_OPAQUE_MIGRATION.md` §6).
//!
//! Both halves live in this one module so the signed envelope stays coherent:
//!
//! - **C1 — the local relay endpoint** (`POST /v1/mesh/relay`): the operator's
//!   LOCAL node is the RNS gateway. It authorizes the caller (owner session or
//!   an `owner:act-on-behalf` dgrant whose constraints permit `mesh_relay`,
//!   `gate::CapabilityVerb::MeshRelay`), resolves the owner fed-ID signer
//!   through the [`crate::compose::resolve_user_signer`] choke point, hybrid-
//!   signs the inner [`ControlEnvelope`], and ships it as an `OpaqueRequest`
//!   of kind [`MESH_CONTROL_KIND`] (CIRISServer's own CC 0.7 Tier-2 range —
//!   see `WIRE_VOCABULARY_KINDS.md`).
//!
//! - **C3 — the remote responder** ([`MeshControlResponder`]): registered on
//!   the shared Edge via [`register_mesh_control_handler`]. It verifies the
//!   inner **owner fed-ID** hybrid signature against its own federation
//!   directory (the exact [`crate::auth::verify::verify_request`] contract
//!   `self_login` uses), authorizes the signer against THIS node's
//!   owner-binding ([`crate::auth::ownership::is_steward_bound`] +
//!   [`crate::auth::verify::signer_acts_for`]), replay-guards, enforces the
//!   closed route **allow-list**, and dispatches into the node's OWN v1 axum
//!   router via `tower::ServiceExt::oneshot` — so the RNS path and the HTTP
//!   path execute the identical handler code (`RNS_CONTROL_RELAY.md` §5.4).
//!
//! ## Two identities, per `RNS_CONTROL_RELAY.md` §9
//!
//! The OUTER edge envelope is signed by the local node's federation signer
//! (transport/routing identity — edge builds it in `send_opaque_request`). The
//! INNER [`ControlEnvelope`] is hybrid-signed by the **owner's fed-ID** — the
//! authorization principal. The remote's owner authority is a signed CEG fact
//! (the `delegates_to(owner → node)` owner-binding the claim persisted), so a
//! request signed by that owner IS proof of authority; the HTTP password path
//! is bypassed entirely.
//!
//! ## Byte-exact inner contract (CC 0.7 §3.3 — "the app owns meaning")
//!
//! The signed bytes are the EXACT serialized JSON of the [`ControlEnvelope`];
//! they travel base64 inside [`ControlPayload`] together with the same three
//! `x-ciris-*` signature headers the HTTP fabric contract uses, so the remote
//! runs `verify_request(&engine, &headers, &envelope_bytes, policy)` verbatim
//! — no canonicalization scheme, no re-serialization, nothing to drift.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::wa_cert::WaRole;
use serde::{Deserialize, Serialize};
use tower::ServiceExt as _;

use crate::auth::gate::{self, CapabilityVerb};
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;
use crate::auth::verify::{self, VerifyError, HEADER_ED25519, HEADER_KEY_ID, HEADER_ML_DSA_65};

// ─── The CC 0.7 kind allocation (WIRE_VOCABULARY.md v1.0.1 §3.1) ─────────────

/// CIRISServer's Tier-2 opaque kind for the mesh control-plane relay
/// (request/response over `OpaqueRequest`/`OpaqueResponse`). CIRISServer
/// stewards `0x0000_0000..=0x0000_FFFF`; this allocation is published in
/// `WIRE_VOCABULARY_KINDS.md` at the repo root. `0x0000_0002+` is reserved for
/// future control ops (e.g. a health probe).
pub const MESH_CONTROL_KIND: u32 = 0x0000_0001;

/// Freshness window (seconds) for the inner envelope's `ts` — a request older
/// (or claiming to be newer) than this is rejected on the remote. Generous
/// enough for slow LoRa paths + modest clock skew, tight enough that a captured
/// envelope goes stale fast (`RNS_CONTROL_RELAY.md` §10 replay posture).
pub const RELAY_FRESHNESS_SECS: i64 = 300;

/// Request-body cap — a control envelope must stay a single edge segment
/// (`RNS_CONTROL_RELAY.md` §4.4); owner-op bodies are < 1 KiB in practice.
pub const RELAY_BODY_CAP: usize = 256 * 1024;

/// Bounded size of the remote's seen-nonce set (covers far more traffic within
/// the freshness window than owner-op cadence ever produces).
const REPLAY_GUARD_CAP: usize = 4096;

/// Default C1 relay round-trip timeout (ms) — mirrors the FSD's 30 s.
pub const RELAY_TIMEOUT_MS: u64 = 30_000;

// ─── The closed route allow-list (RNS_CONTROL_RELAY.md §5.3, MVP set) ────────

/// The ONLY `(method, path)` pairs a relayed control op may dispatch — the
/// mesh-seed surface plus the reads the node switcher needs. Everything else
/// is refused with 403 BEFORE any dispatch. **Never-relayable by omission**
/// (asserted in tests): wipe (`/v1/system/data/*`), claim (`/v1/setup/root`),
/// fed-ID mint (`/v1/self/identity`), login, delegation issuance, and any
/// large read. Adding a route here is a reviewed code change, not config.
pub const RELAYABLE: &[(&str, &str)] = &[
    ("POST", "/v1/federation/announce"),
    ("POST", "/v1/federation/peering"),
    ("GET", "/v1/federation/self-key-record"),
    ("GET", "/v1/setup/owned-nodes"),
];

/// True iff `(method, path)` is on the closed relayable allow-list.
pub fn is_relayable(method: &str, path: &str) -> bool {
    RELAYABLE.iter().any(|(m, p)| *m == method && *p == path)
}

/// The delegation-constraint verb a relayed op ADDITIONALLY exercises, when it
/// maps to one. Defense-in-depth on the LOCAL gateway: a dgrant scoped to
/// `mesh_relay` but not `announce` must not smuggle an announce through the
/// relay — the same verb the target's own handler would gate on.
fn relayed_verb(method: &str, path: &str) -> Option<CapabilityVerb> {
    match (method, path) {
        ("POST", "/v1/federation/announce") => Some(CapabilityVerb::Announce),
        ("POST", "/v1/federation/peering") => Some(CapabilityVerb::Peer),
        _ => None,
    }
}

// ─── The signed inner envelope (byte-exact contract) ─────────────────────────

/// The inner control envelope the OWNER fed-ID signs — `{target, method, path,
/// body, nonce, ts}` (`RNS_CONTROL_RELAY.md` §4.3, JSON instead of separate
/// hash fields: the signature covers the exact serialized bytes, so the body
/// is tamper-bound without a separate digest). The remote asserts
/// `target_key_id == its own key_id` (defence-in-depth vs a misrouted /
/// cross-replayed envelope).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlEnvelope {
    /// Envelope schema version (1).
    pub v: u8,
    /// The intended remote node's federation `key_id`.
    pub target_key_id: String,
    /// `GET` / `POST` (the allow-list is the real gate).
    pub method: String,
    /// Absolute v1 path, e.g. `/v1/federation/announce`.
    pub path: String,
    /// JSON request body (`null` for body-less ops).
    pub body: serde_json::Value,
    /// 16 random bytes, base64 — the replay key.
    pub nonce: String,
    /// Unix seconds at signing — the freshness anchor.
    pub ts: i64,
}

impl ControlEnvelope {
    /// Build a fresh envelope (random nonce, `ts = now`).
    pub fn new(
        target_key_id: &str,
        method: &str,
        path: &str,
        body: serde_json::Value,
    ) -> ControlEnvelope {
        let mut nonce = [0u8; 16];
        let _ = getrandom::fill(&mut nonce);
        ControlEnvelope {
            v: 1,
            target_key_id: target_key_id.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            body,
            nonce: B64.encode(nonce),
            ts: chrono::Utc::now().timestamp(),
        }
    }
}

/// The opaque `payload` carried on the wire: the three `x-ciris-*` signature
/// headers + the base64 of the EXACT envelope bytes they sign. Shaped so the
/// remote can feed [`verify::verify_request`] verbatim (the one fabric
/// verifier — `src/auth/verify.rs`), keeping the RNS and HTTP auth contracts
/// literally the same code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPayload {
    /// `x-ciris-signing-key-id` / `x-ciris-signature-ed25519` /
    /// `x-ciris-signature-ml-dsa-65` — the fabric signature-header trio.
    pub headers: BTreeMap<String, String>,
    /// Base64 of the exact [`ControlEnvelope`] JSON bytes the headers sign.
    pub envelope_b64: String,
}

/// Hybrid-sign `envelope` with the owner fed-ID signer and wrap it as the
/// wire [`ControlPayload`] bytes. `LocalSigner::sign_hybrid` produces exactly
/// the bound form `verify_hybrid_via_directory` checks (Ed25519 over the
/// bytes; ML-DSA-65 over bytes‖ed_sig) — the same recipe every fabric-signed
/// request uses.
pub async fn sign_control_payload(
    signer: &LocalSigner,
    envelope: &ControlEnvelope,
) -> Result<Vec<u8>, String> {
    let envelope_bytes =
        serde_json::to_vec(envelope).map_err(|e| format!("serialize control envelope: {e}"))?;
    let sig = signer
        .sign_hybrid(&envelope_bytes)
        .await
        .map_err(|e| format!("owner fed-ID hybrid sign: {e}"))?;
    let mut headers = BTreeMap::new();
    headers.insert(HEADER_KEY_ID.to_owned(), signer.key_id().to_owned());
    headers.insert(
        HEADER_ED25519.to_owned(),
        B64.encode(&sig.classical.signature),
    );
    headers.insert(HEADER_ML_DSA_65.to_owned(), B64.encode(&sig.pqc.signature));
    serde_json::to_vec(&ControlPayload {
        headers,
        envelope_b64: B64.encode(&envelope_bytes),
    })
    .map_err(|e| format!("serialize control payload: {e}"))
}

// ─── The transport seam (Edge in production; loopback in the e2e harness) ────

/// The wire-level reply to one relayed control op: the responder's HTTP-ish
/// status + the dispatched handler's body bytes (maps 1:1 onto
/// `OpaqueResponse{status, payload}`).
#[derive(Debug, Clone)]
pub struct WireResponse {
    /// HTTP status the target's own v1 handler produced (or a responder-level
    /// 4xx/5xx from the verify/authz/allow-list gates).
    pub status: u16,
    /// Response body bytes (JSON in practice) — returned to the client verbatim.
    pub payload: Vec<u8>,
}

/// Why a mesh send failed before any response arrived.
#[derive(Debug)]
pub enum MeshSendError {
    /// No rooted path / timeout — surfaced as `502 mesh_target_unreachable`.
    Unreachable(String),
    /// Anything else (config, serialization) — surfaced as `502 mesh_send_failed`.
    Other(String),
}

/// Boxed future a [`MeshRequester`] returns.
pub type MeshSendFuture = Pin<Box<dyn Future<Output = Result<WireResponse, MeshSendError>> + Send>>;

/// The one seam between the relay endpoint and the mesh hop:
/// `(target_key_id, kind, payload, timeout_ms) → WireResponse`. Production
/// wraps `Edge::send_opaque_request` ([`edge_mesh_requester`]); the e2e
/// harness wires an in-process loopback straight into the REAL
/// [`MeshControlResponder`]s (the documented `tests/mesh_seed_e2e.rs`
/// in-process-transport honesty — everything except the RNS hop is real).
pub type MeshRequester = Arc<dyn Fn(String, u32, Vec<u8>, u64) -> MeshSendFuture + Send + Sync>;

/// Production requester over a live `Arc<ciris_edge::Edge>` whose inbound
/// dispatch is running (`spawn_background_listeners` — the pattern the edge
/// opaque conformance suite proves). Maps `OpaqueResponse{status,payload}`
/// straight onto [`WireResponse`]; edge's synthesized `501` for an
/// unregistered kind flows through as `status: 501` (C1 maps it to
/// `502 mesh_relay_unsupported` — never a silent drop).
///
/// NOTE (edge v8.0.0 lifecycle): `Edge::run(self, …)` CONSUMES the Edge, so a
/// composition root that runs the full lifecycle via `run()` cannot retain the
/// `Arc<Edge>` this requester needs — see the `compose.rs` wiring note. This
/// constructor is the ready send leg for any host that drives the edge via
/// `Arc<Edge> + spawn_background_listeners` (the Phase E two-node harness).
pub fn edge_mesh_requester(edge: Arc<ciris_edge::Edge>) -> MeshRequester {
    Arc::new(move |target, kind, payload, timeout_ms| {
        let edge = Arc::clone(&edge);
        Box::pin(async move {
            match edge
                .send_opaque_request(&target, kind, payload, timeout_ms)
                .await
            {
                Ok(resp) => Ok(WireResponse {
                    status: resp.status,
                    payload: resp.payload,
                }),
                Err(ciris_edge::EdgeError::Unreachable(e)) => Err(MeshSendError::Unreachable(e)),
                Err(e) => Err(MeshSendError::Other(e.to_string())),
            }
        })
    })
}

/// The v8.0.0 composition-root requester: `target == self` short-circuits to
/// the in-process responder (no RNS hop — `RNS_CONTROL_RELAY.md` §6 step 2);
/// any OTHER target honestly fails `mesh_send_unwired`, because
/// `Edge::run(self)` consumed the only handle `send_opaque_request` could ride
/// (see the compose wiring note + the follow-up filed against CIRISEdge for a
/// `run(self: Arc<Self>)` receiver). The RESPONDER side is fully wired either
/// way — every owned node is administrable over RNS; initiating from a
/// `run()`-lifecycle node awaits the edge receiver change.
pub fn local_only_requester(
    self_key_id: String,
    responder: Arc<MeshControlResponder>,
) -> MeshRequester {
    Arc::new(move |target, _kind, payload, _timeout_ms| {
        let responder = Arc::clone(&responder);
        let self_key_id = self_key_id.clone();
        Box::pin(async move {
            if target == self_key_id {
                return Ok(responder.handle(&payload).await);
            }
            Err(MeshSendError::Other(format!(
                "mesh_send_unwired: the RNS send leg needs a retained Arc<Edge> \
                 (edge v8.0.0 Edge::run(self) consumes it); target {target} is only \
                 reachable once the edge exposes an Arc-receiver run"
            )))
        })
    })
}

// ─── C3 — the remote responder ────────────────────────────────────────────────

/// Bounded seen-nonce set + freshness window — the `RNS_CONTROL_RELAY.md` §10
/// replay guard. Insert-order eviction is sufficient: an evicted nonce is by
/// construction older than the freshness window (the set holds far more
/// entries than owner-op cadence produces within it).
struct ReplayGuard {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl ReplayGuard {
    fn new() -> ReplayGuard {
        ReplayGuard {
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// `true` iff `nonce` is fresh (records it); `false` on a replay.
    fn admit(&mut self, nonce: &str) -> bool {
        if self.seen.contains(nonce) {
            return false;
        }
        self.seen.insert(nonce.to_owned());
        self.order.push_back(nonce.to_owned());
        while self.order.len() > REPLAY_GUARD_CAP {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

/// A [`WireResponse`] carrying the standard `{"error": …}` JSON body every
/// fabric endpoint rejects with — the relay client sees the same error shape
/// it would from a direct HTTP call.
fn wire_err(status: u16, msg: impl Into<String>) -> WireResponse {
    WireResponse {
        status,
        payload: serde_json::json!({ "error": msg.into() })
            .to_string()
            .into_bytes(),
    }
}

/// **C3 — the RNS control responder** (`RNS_CONTROL_RELAY.md` §5, mirrored on
/// `self_login`'s verify → authorize → dispatch shape). One per node; holds
/// the node's Engine, its own federation `key_id` (the `target_key_id` bind),
/// the replay guard, and the v1 dispatch router.
///
/// The router rides an `Arc<OnceLock<Router>>` because compose registers the
/// responder on the Edge BEFORE the read-API router exists (the Edge must have
/// its handlers attached before `run()` consumes it, `compose.rs:332`); the
/// slot is filled as soon as the merged v1 router is built. A relay arriving
/// in the boot gap gets an honest `503 mesh_dispatch_not_ready`.
pub struct MeshControlResponder {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — the inner envelope's `target_key_id`
    /// must equal it, and the owner-binding lookup keys on it.
    node_key_id: String,
    /// The node's own merged v1 router (the SAME handlers HTTP serves — §5.4
    /// "reuse, do not fork"). Filled once by compose / the test harness.
    router: Arc<OnceLock<Router>>,
    replay: Mutex<ReplayGuard>,
}

impl MeshControlResponder {
    /// Production constructor — the router slot is filled later by compose.
    pub fn new(
        engine: Arc<Engine>,
        node_key_id: String,
        router: Arc<OnceLock<Router>>,
    ) -> MeshControlResponder {
        MeshControlResponder {
            engine,
            node_key_id,
            router,
            replay: Mutex::new(ReplayGuard::new()),
        }
    }

    /// Test/harness constructor — the dispatch router is known up front.
    pub fn with_router(
        engine: Arc<Engine>,
        node_key_id: String,
        router: Router,
    ) -> MeshControlResponder {
        let slot = Arc::new(OnceLock::new());
        let _ = slot.set(router);
        MeshControlResponder::new(engine, node_key_id, slot)
    }

    /// Handle one inbound mesh control payload: verify the OWNER signature,
    /// authorize against THIS node's owner-binding, replay-guard, allow-list,
    /// then dispatch into the node's own v1 router. Every reject is an
    /// explicit status — never a silent drop (MISSION anti-pattern 6).
    pub async fn handle(&self, payload: &[u8]) -> WireResponse {
        // (1) Decode the wire payload + the exact signed envelope bytes.
        let payload: ControlPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => return wire_err(400, format!("bad mesh control payload: {e}")),
        };
        let envelope_bytes = match B64.decode(&payload.envelope_b64) {
            Ok(b) => b,
            Err(e) => return wire_err(400, format!("bad envelope_b64: {e}")),
        };
        let mut headers = HeaderMap::new();
        for (k, v) in &payload.headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::header::HeaderName::try_from(k.as_str()),
                axum::http::header::HeaderValue::try_from(v.as_str()),
            ) {
                headers.insert(name, value);
            }
        }

        // (2) Verify the OWNER's hybrid signature over the EXACT envelope bytes
        // against THIS node's federation directory — verbatim the one fabric
        // verifier (`verify_request`, HybridPolicy::Strict; no classical-only
        // path on a control op).
        let caller = match verify::verify_request(
            &self.engine,
            &headers,
            &envelope_bytes,
            HybridPolicy::Strict,
        )
        .await
        {
            Ok(c) => c,
            Err(VerifyError::MissingHeader(h)) => {
                return wire_err(401, format!("missing signature header {h}"))
            }
            Err(VerifyError::NoDirectory) => return wire_err(503, "no federation directory"),
            Err(VerifyError::SignatureInvalid(e)) => {
                return wire_err(401, format!("owner signature verification failed: {e}"))
            }
        };

        // (3) Parse the now-authenticated envelope.
        let env: ControlEnvelope = match serde_json::from_slice(&envelope_bytes) {
            Ok(e) => e,
            Err(e) => return wire_err(400, format!("bad control envelope: {e}")),
        };

        // (4) Target bind — a verified envelope for a DIFFERENT node must not
        // execute here (misrouted / cross-replayed).
        if env.target_key_id != self.node_key_id {
            return wire_err(
                421, // Misdirected Request
                format!(
                    "control envelope targets {} but this node is {}",
                    env.target_key_id, self.node_key_id
                ),
            );
        }

        // (5) Freshness + (6) replay. Freshness first: a stale envelope is
        // refused without spending a nonce slot.
        let now = chrono::Utc::now().timestamp();
        if (now - env.ts).abs() > RELAY_FRESHNESS_SECS {
            return wire_err(401, "control envelope outside the freshness window");
        }
        {
            let mut guard = self
                .replay
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Key the guard on (signer, nonce) so two signers can't collide.
            if !guard.admit(&format!("{}:{}", caller.key_id, env.nonce)) {
                return wire_err(409, "control envelope replayed (nonce already seen)");
            }
        }

        // (7) AUTHORIZE — the verified signer must BE (or act for, §5.6.8.8)
        // THIS node's bound owner. An unowned node refuses every relayed op
        // (the CC 3.2 serve-only floor); a signer that isn't the owner (nor an
        // admitted occurrence of it) has no authority here, whatever it signed.
        let Some(owner) = gate::is_steward_bound(&self.engine, &self.node_key_id).await else {
            return wire_err(
                403,
                "this node has no responsible party (owner-binding) — mesh control refused",
            );
        };
        if !verify::signer_acts_for(&self.engine, &caller.key_id, &owner).await {
            return wire_err(
                403,
                "signer does not act for this node's owner — mesh control refused",
            );
        }

        // (8) Allow-list — the closed relayable set. Wipe / claim / mint /
        // login are never here (asserted in tests); no dispatch on a miss.
        if !is_relayable(&env.method, &env.path) {
            return wire_err(
                403,
                format!("{} {} is not a relayable control op", env.method, env.path),
            );
        }

        // (9) Dispatch into the node's OWN v1 router (the same handlers HTTP
        // serves). The bearer-gated handlers (`require_owner` →
        // `resolve_bearer`) need an authorized caller: fabric session tokens
        // are `sess:<wa_id>:<rand>` resolved purely by the ACTIVE `wa_cert`
        // row, so we mint a loopback session bearer for the node's founding
        // ROOT cert — the cert the owner's claim created. This is the
        // "short-lived internal session" seam (option (i) of the FSD §5.4
        // auth-injection choice): the signature verified above IS the owner's
        // authority; the synthetic bearer only carries it across the existing
        // bearer plumbing unchanged.
        let Some(router) = self.router.get().cloned() else {
            return wire_err(503, "mesh_dispatch_not_ready (v1 router not built yet)");
        };
        let bearer = match crate::auth::store::list_by_role(&self.engine, WaRole::Root, 1000).await
        {
            Ok(certs) => certs
                .into_iter()
                .filter(|c| c.active)
                .min_by_key(|c| c.created)
                .map(|c| format!("sess:{}:mesh-relay", c.wa_id)),
            Err(e) => return wire_err(503, format!("wa_cert store: {e}")),
        };

        let method = match axum::http::Method::try_from(env.method.as_str()) {
            Ok(m) => m,
            Err(_) => return wire_err(400, format!("bad method {}", env.method)),
        };
        let mut builder = axum::http::Request::builder().method(method).uri(&env.path);
        if let Some(bearer) = &bearer {
            builder = builder.header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {bearer}"),
            );
        }
        let body_bytes = if env.body.is_null() {
            Vec::new()
        } else {
            builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
            env.body.to_string().into_bytes()
        };
        let mut request = match builder.body(Body::from(body_bytes)) {
            Ok(r) => r,
            Err(e) => return wire_err(400, format!("assemble dispatch request: {e}")),
        };
        // The relayed op executes ON the node's own host, authorized by the
        // owner's signature — morally a local-operator call, so satisfy the
        // loopback guard the setup routes carry (`require_loopback` reads
        // ConnectInfo from extensions and fails CLOSED without it).
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));

        let response = match router.oneshot(request).await {
            Ok(r) => r,
            Err(never) => match never {}, // Router's error is Infallible.
        };
        let status = response.status().as_u16();
        let body = match axum::body::to_bytes(response.into_body(), RELAY_BODY_CAP * 8).await {
            Ok(b) => b.to_vec(),
            Err(e) => return wire_err(500, format!("collect dispatched response: {e}")),
        };
        WireResponse {
            status,
            payload: body,
        }
    }
}

/// Register the mesh-control responder on the shared Edge for
/// [`MESH_CONTROL_KIND`] — call in compose BEFORE `edge.run()` consumes the
/// Edge (registration is `&self`; the run loop invokes the closure inline in
/// its async inbound dispatcher).
///
/// ⚠ Sync-closure bridge (`EDGE_8_0_OPAQUE_MIGRATION.md` §3): edge's
/// `register_opaque_handler` takes a **synchronous** closure invoked on a
/// tokio worker, but the responder is async (hybrid verify + router oneshot).
/// `block_in_place` + `Handle::current().block_on` is the documented pattern —
/// it requires the multi-thread runtime flavor (which the node runs) and
/// blocks that inbound-dispatch task only for the request's duration
/// (acceptable at owner-op cadence).
pub fn register_mesh_control_handler(
    edge: &ciris_edge::Edge,
    responder: Arc<MeshControlResponder>,
) {
    edge.register_opaque_handler(MESH_CONTROL_KIND, move |sender_key_id, payload| {
        let responder = Arc::clone(&responder);
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                tracing::info!(
                    transport_signer = %sender_key_id,
                    "inbound mesh control op (authorization = the INNER owner signature, \
                     not the transport signer)"
                );
                let wire = responder.handle(&payload).await;
                ciris_edge::messages::OpaqueResponse {
                    kind: MESH_CONTROL_KIND,
                    status: wire.status,
                    payload: wire.payload,
                }
            })
        })
    });
}

// ─── C1 — the local relay endpoint (POST /v1/mesh/relay) ─────────────────────

#[derive(Clone)]
struct MeshRelayState {
    engine: Arc<Engine>,
    /// Default owner fed-ID ALIAS (the `<keystore>-user` convention) —
    /// resolved to the ACTIVE alias at request time ([`crate::active_user_alias`],
    /// the post-claim pointer fix), then to the signer through the
    /// [`crate::compose::resolve_user_signer`] choke point.
    user_key_id: String,
    user_seed_dir: PathBuf,
    /// The mesh hop ([`MeshRequester`]) — `None` degrades to an honest
    /// `502 mesh_send_unwired` on every send (a relay endpoint with no
    /// transport is a misconfiguration, not a silent success).
    requester: Option<MeshRequester>,
    timeout_ms: u64,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// `POST /v1/mesh/relay` request — the client addresses an owned node purely
/// by `key_id`; it never holds a route to the target's IP.
#[derive(Debug, Deserialize)]
struct RelayRequest {
    target_key_id: String,
    method: String,
    path: String,
    #[serde(default)]
    body: serde_json::Value,
}

/// Send one signed control op over the mesh seam and surface transport-level
/// failures as the FSD's stable tokens (`502 mesh_target_unreachable` /
/// `502 mesh_send_failed` / `504 mesh_relay_timeout`).
async fn send_signed(
    st: &MeshRelayState,
    signer: &LocalSigner,
    target_key_id: &str,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<WireResponse, Response> {
    let Some(requester) = st.requester.as_ref() else {
        return Err(err(
            StatusCode::BAD_GATEWAY,
            "mesh_send_unwired: this node has no mesh send transport configured",
        ));
    };
    let envelope = ControlEnvelope::new(target_key_id, method, path, body);
    let payload = sign_control_payload(signer, &envelope)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let fut = requester(
        target_key_id.to_owned(),
        MESH_CONTROL_KIND,
        payload,
        st.timeout_ms,
    );
    match tokio::time::timeout(std::time::Duration::from_millis(st.timeout_ms), fut).await {
        Ok(Ok(wire)) => Ok(wire),
        Ok(Err(MeshSendError::Unreachable(e))) => Err(err(
            StatusCode::BAD_GATEWAY,
            format!("mesh_target_unreachable: {e}"),
        )),
        Ok(Err(MeshSendError::Other(e))) => Err(err(
            StatusCode::BAD_GATEWAY,
            format!("mesh_send_failed: {e}"),
        )),
        Err(_elapsed) => Err(err(StatusCode::GATEWAY_TIMEOUT, "mesh_relay_timeout")),
    }
}

/// The C1 handler — auth gate → allow-list → (peering enrichment) → owner
/// fed-ID sign → mesh send → verbatim status/body passthrough.
async fn relay_handler(
    State(st): State<MeshRelayState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // ── Auth gate: owner session or delegated dgrant, apex role, MeshRelay verb.
    // Mirrors `claim_remote::require_owner` (SYSTEM_ADMIN + FullAccess — the
    // apex, since a relayed op wields the owner's authority on a remote), then
    // the delegation-constraints gate on the `mesh_relay` verb — the wiring
    // the constraints branch added the verb FOR (`gate.rs:50`).
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return err(StatusCode::UNAUTHORIZED, "missing bearer session token");
    };
    let caller = match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            caller
        }
        Ok(Some(_)) => {
            return err(
                StatusCode::FORBIDDEN,
                "mesh relay requires the owner (SYSTEM_ADMIN) role",
            )
        }
        Ok(None) => return err(StatusCode::UNAUTHORIZED, "invalid or expired session"),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, format!("store: {e}")),
    };
    if let Some(resp) = gate::require_verb(&caller, CapabilityVerb::MeshRelay) {
        return resp;
    }

    let req: RelayRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };

    // ── Allow-list on the GATEWAY too (fail fast; also: never sign a
    // non-relayable op). The remote re-enforces this independently — two
    // gates, neither trusting the other (§10 "not an open proxy").
    if !is_relayable(&req.method, &req.path) {
        return err(
            StatusCode::FORBIDDEN,
            format!("{} {} is not a relayable control op", req.method, req.path),
        );
    }
    // Defense-in-depth: a delegated caller must ALSO hold the verb the relayed
    // op itself exercises (a `mesh_relay`-only grant can't smuggle an announce).
    if let Some(verb) = relayed_verb(&req.method, &req.path) {
        if let Some(resp) = gate::require_verb(&caller, verb) {
            return resp;
        }
    }
    if serde_json::to_vec(&req.body).map(|b| b.len()).unwrap_or(0) > RELAY_BODY_CAP {
        return err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "relay body exceeds the single-segment cap (256 KiB)",
        );
    }

    // ── Resolve the OWNER fed-ID signer at request time (the choke point:
    // released only under a verified owner session — which the gate above IS).
    let alias = crate::active_user_alias(&st.user_seed_dir, &st.user_key_id);
    let signer = match crate::compose::resolve_user_signer(
        &st.engine,
        crate::compose::FedIdUse::OwnerSession,
        &alias,
        st.user_seed_dir.clone(),
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "no responsible-user identity minted yet — create your federation ID first",
            )
        }
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("owner signer: {e}"),
            )
        }
    };

    // ── Gateway enrichment (the runbook §7 step the client no longer does):
    // a relayed peering that names only `peer_key_id` gets the peer's
    // self-signed key record fetched OVER THE MESH and injected, so the
    // client-side contract stays "address everything by key_id". The record is
    // public proof-of-possession (the same JSON `GET /v1/federation/
    // self-key-record` serves) and the TARGET's admission gate re-verifies it
    // fail-secure — the gateway adds reach, not trust.
    let mut relay_body = req.body.clone();
    if req.method == "POST" && req.path == "/v1/federation/peering" {
        let peer_key_id = relay_body
            .get("peer_key_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        if relay_body.get("peer_key_record").is_none() {
            let Some(peer_key_id) = peer_key_id else {
                return err(
                    StatusCode::BAD_REQUEST,
                    "peering relay requires peer_key_id",
                );
            };
            let fetched = match send_signed(
                &st,
                &signer,
                &peer_key_id,
                "GET",
                "/v1/federation/self-key-record",
                serde_json::Value::Null,
            )
            .await
            {
                Ok(w) if w.status == 200 => w,
                Ok(w) => {
                    return err(
                        StatusCode::BAD_GATEWAY,
                        format!(
                            "mesh_peer_key_record_unavailable: {} returned {} for its \
                             self-key-record",
                            peer_key_id, w.status
                        ),
                    )
                }
                Err(resp) => return resp,
            };
            let record: serde_json::Value = match serde_json::from_slice(&fetched.payload) {
                Ok(r) => r,
                Err(e) => {
                    return err(
                        StatusCode::BAD_GATEWAY,
                        format!("mesh_peer_key_record_unavailable: bad record JSON: {e}"),
                    )
                }
            };
            if let Some(obj) = relay_body.as_object_mut() {
                obj.insert("peer_key_record".to_owned(), record);
            }
        }
    }

    // ── Sign + send + verbatim passthrough.
    let wire = match send_signed(
        &st,
        &signer,
        &req.target_key_id,
        &req.method,
        &req.path,
        relay_body,
    )
    .await
    {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    // Edge answers an unregistered kind with a synthesized 501 (a peer that
    // is not relay-capable) — map it to the FSD's stable token.
    if wire.status == 501 {
        return err(
            StatusCode::BAD_GATEWAY,
            "mesh_relay_unsupported: target node has no mesh control responder",
        );
    }
    let status = StatusCode::from_u16(wire.status).unwrap_or(StatusCode::BAD_GATEWAY);
    (
        status,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        wire.payload,
    )
        .into_response()
}

/// The mesh-relay router — merge onto the read-API listener beside the other
/// owner routers. `user_key_id`/`user_seed_dir` are the SAME request-time
/// owner-signer inputs `claim_remote::router` takes; `requester` is the mesh
/// hop seam (see [`MeshRequester`]).
pub fn router(
    engine: Arc<Engine>,
    user_key_id: String,
    user_seed_dir: PathBuf,
    requester: Option<MeshRequester>,
    timeout_ms: u64,
) -> Router {
    let state = MeshRelayState {
        engine,
        user_key_id,
        user_seed_dir,
        requester,
        timeout_ms,
    };
    Router::new()
        .route("/v1/mesh/relay", axum::routing::post(relay_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inner envelope + payload wrapper round-trip byte-exactly — the
    /// "sign exact bytes, transmit exact bytes" contract.
    #[test]
    fn control_envelope_round_trips() {
        let env = ControlEnvelope::new(
            "ciris-status-1-abcdef",
            "POST",
            "/v1/federation/announce",
            serde_json::json!({}),
        );
        let bytes = serde_json::to_vec(&env).expect("serialize");
        let back: ControlEnvelope = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(env, back, "envelope must round-trip losslessly");

        let payload = ControlPayload {
            headers: BTreeMap::from([(HEADER_KEY_ID.to_owned(), "owner-1".to_owned())]),
            envelope_b64: B64.encode(&bytes),
        };
        let wire = serde_json::to_vec(&payload).expect("serialize payload");
        let back: ControlPayload = serde_json::from_slice(&wire).expect("parse payload");
        assert_eq!(
            B64.decode(&back.envelope_b64).expect("decode"),
            bytes,
            "the signed envelope bytes survive the payload wrapper verbatim"
        );
    }

    /// Two envelopes for the same op differ (fresh nonce) — the replay key.
    #[test]
    fn envelopes_carry_fresh_nonces() {
        let a = ControlEnvelope::new("n", "GET", "/v1/setup/owned-nodes", serde_json::Value::Null);
        let b = ControlEnvelope::new("n", "GET", "/v1/setup/owned-nodes", serde_json::Value::Null);
        assert_ne!(a.nonce, b.nonce, "every envelope mints a fresh nonce");
    }

    /// The replay guard admits a nonce once and once only, and stays bounded.
    #[test]
    fn replay_guard_rejects_repeats_and_stays_bounded() {
        let mut g = ReplayGuard::new();
        assert!(g.admit("owner:n1"), "first use admitted");
        assert!(!g.admit("owner:n1"), "replay rejected");
        // Bounded: pushing past the cap evicts oldest without unbounded growth.
        for i in 0..(REPLAY_GUARD_CAP + 10) {
            let _ = g.admit(&format!("owner:bulk-{i}"));
        }
        assert!(g.seen.len() <= REPLAY_GUARD_CAP, "seen set stays bounded");
        assert_eq!(g.seen.len(), g.order.len(), "set and eviction order agree");
    }

    /// The allow-list admits exactly the MVP mesh-seed surface…
    #[test]
    fn allow_list_admits_the_mesh_seed_surface() {
        assert!(is_relayable("POST", "/v1/federation/announce"));
        assert!(is_relayable("POST", "/v1/federation/peering"));
        assert!(is_relayable("GET", "/v1/federation/self-key-record"));
        assert!(is_relayable("GET", "/v1/setup/owned-nodes"));
        // …and method matters: announcing is POST-only.
        assert!(!is_relayable("GET", "/v1/federation/announce"));
    }

    /// …and the NEVER-relayable classes are structurally absent from the const
    /// (wipe / claim / fed-ID mint / login / delegation issuance / large reads)
    /// — `RNS_CONTROL_RELAY.md` §5.3/§10.
    #[test]
    fn never_relayable_classes_are_absent() {
        for (method, path) in [
            ("POST", "/v1/system/data/reset-account"),
            ("POST", "/v1/system/data/wipe-signing-key"),
            ("POST", "/v1/setup/root"),
            ("POST", "/v1/self/identity"),
            ("POST", "/v1/auth/login"),
            ("POST", "/v1/auth/device/delegate"),
            ("GET", "/v1/memory/timeline"),
            ("GET", "/v1/telemetry/logs"),
        ] {
            assert!(
                !is_relayable(method, path),
                "{method} {path} must NEVER be relayable"
            );
        }
        // Defense against a future edit sneaking a prefix in: no allow-list
        // entry may live under the never-relayable path classes.
        for (_, p) in RELAYABLE {
            assert!(
                !p.starts_with("/v1/system/data")
                    && *p != "/v1/setup/root"
                    && *p != "/v1/self/identity"
                    && !p.starts_with("/v1/auth/"),
                "allow-list entry {p} violates the never-relayable floor"
            );
        }
    }

    /// A relayed announce/peering ALSO exercises its own capability verb on
    /// the gateway (a `mesh_relay`-only delegation can't smuggle either).
    #[test]
    fn relayed_ops_map_to_their_verbs() {
        assert!(matches!(
            relayed_verb("POST", "/v1/federation/announce"),
            Some(CapabilityVerb::Announce)
        ));
        assert!(matches!(
            relayed_verb("POST", "/v1/federation/peering"),
            Some(CapabilityVerb::Peer)
        ));
        assert!(relayed_verb("GET", "/v1/federation/self-key-record").is_none());
    }

    /// A garbage payload is answered 400 — never a panic, never a silent drop.
    #[tokio::test(flavor = "multi_thread")]
    async fn responder_rejects_garbage_payload() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            "mesh-unit-node".to_string(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine");
        let responder = MeshControlResponder::with_router(
            Arc::new(engine),
            "mesh-unit-node".into(),
            Router::new(),
        );
        let resp = responder.handle(b"not json").await;
        assert_eq!(resp.status, 400, "garbage payload → 400");
    }
}
