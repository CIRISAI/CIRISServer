# RNS Control Relay — administering an owned remote node by `key_id` over the mesh

**Status:** DESIGN — implementation-ready (no production code in this doc).
**Author:** research + spec pass.
**Substrate floor at time of writing:** ciris-server 0.5.71, **edge v7.4.4**
(git checkout `aebb9e1`), persist v11.5.0, verify family v8.3.0.
**Tracks:** CIRISServer #8 (mesh-addressing) and #125 P2 (reach owned remotes
by `key_id`; today "listed-but-not-switchable").
**Supersedes:** `FSD/MESH_SEED_RUNBOOK_POST_DELEGATION.md` **§2 "Option A"**
(the HTTP `announce-remote` / `peer-remote` proxies that reach the target over
its `transport_hint` HTTP URL). This FSD reaches the target by **fed `key_id`
over Reticulum**, so an IP-less node is administrable.
**Companion:** `FSD/RNS_CLIENT_TRANSPORT.md` (the "local-node-as-RNS-gateway"
decision). That doc assumed edge's `link_request` was a ready two-way primitive
(its G2); §4 below corrects that for v7.4.4 and pins the actual ready primitive
(`Edge::send::<M>`).

---

## 1. Summary, goals, non-goals

### 1.1 Summary

Let the owner drive the full owner-op surface (announce, peering, config,
owned-nodes, self-key-record, …) of an **owned remote node** — Node A / Node B —
from a client that has no route to that node's IP, by relaying each control
request through the client's **own local node**, over Reticulum, addressed by the
target's federation `key_id`. The remote authorizes the request by **signature**
(the owner's fed-ID), so the HTTP password/login path
(`src/auth/session.rs:381`) is bypassed entirely.

Three hops:

```
 ┌────────────┐   HTTP loopback        ┌──────────────────┐   RNS (edge.send      ┌────────────────┐
 │  KMP client│   127.0.0.1:4243       │  LOCAL node      │   by key_id, typed    │  REMOTE owned  │
 │ (desktop / │──────────────────────▶ │  = RNS GATEWAY   │   req/resp envelope)  │  node A/B      │
 │  android / │  POST /v1/mesh/relay   │                  │──────────────────────▶│  RNS control   │
 │  ios)      │  {target_key_id,       │  owner fed-ID    │◀──────────────────────│  listener      │
 │            │◀──────────────────────│  signs the       │   MeshControlResponse  │  verify+dispatch│
 └────────────┘  streamed response    │  control request │                       │  → v1 handlers  │
    dgrant /                          └──────────────────┘                       └────────────────┘
  owner session                       transport = node signer                     authz = owner fed-ID
                                       authz  = owner fed-ID sig                    (no password)
```

The client change is minimal and target-agnostic: a URL-less owned node routes
its API calls to `LOCAL_NODE_URL + /v1/mesh/relay` with a `target_key_id`, on the
existing Ktor+HTTP stack. **No RNS in Kotlin.**

### 1.2 Goals

1. Administer an owned remote node by `key_id` over the mesh — no public IP / DNS
   / bearer dance on the remote.
2. Authorize on the remote by the **owner's fed-ID signature**, reusing the exact
   verify model the HTTP fabric endpoints use (`verify::verify_request` +
   `verify::signer_acts_for`, `src/auth/verify.rs:48,84`).
3. Reuse the shipped substrate: the node is already a Reticulum node with the
   typed request/response primitive (`Edge::send::<M>`, §4). Do **not** invent a
   parallel mesh stack; do **not** put RNS in the client.
4. Additive: HTTP `baseUrl` nodes keep working unchanged.

### 1.3 Non-goals

- **No RNS stack in the KMP client.** The local node is the sole mesh
  participant (the gateway decision, `FSD/RNS_CLIENT_TRANSPORT.md` §4).
- **No open HTTP proxy.** The relay forwards a *closed allow-list* of
  owner-op routes to *owned* targets only, never an arbitrary `{method,path}`
  to an arbitrary host (§10).
- **No new mesh identity class.** Transport identity = the local node's existing
  federation signer; authz identity = the owner fed-ID. (`RNS_CLIENT_TRANSPORT.md`
  §5.)
- **wasmJs is out of scope** for mesh-only targets: a browser tab has no local
  node to gateway through (`RNS_CLIENT_TRANSPORT.md` G4). Web reaches only
  `transport_hint`/HTTP nodes, as today.
- Not a store-and-forward / offline queue for control ops — a control relay is
  synchronous request/response; if the target is unreachable the relay fails
  fast (§7).

---

## 2. Current state (cited)

- **The control API is HTTP/axum only.** All owner ops are mounted on the read-API
  listener as axum routers (`src/compose.rs:600-655`): federation admin
  (`src/federation_admin.rs`), claim-remote + announce-self
  (`src/claim_remote.rs:655,724-762`), config, owned-nodes
  (`src/auth/bootstrap.rs:1096`), etc. Owner gating is a **bearer session**
  (`require_owner`, `src/claim_remote.rs` — SYSTEM_ADMIN + `Permission::FullAccess`).
- **Only trace-ingest rides Reticulum.** The single thing received over the mesh
  today is the `AccordEventsBatch` ingest, via the edge typed-handler path
  (`LensCoreHandler`, `crates/ciris-lens-core/src/role/handler.rs:58`;
  registered with `edge.register_handler::<AccordEventsBatch,_>` at
  `crates/ciris-lens-core/src/role/relay.rs:112`). `src/ingest_http.rs` is the
  HTTP mirror of that same `Engine::receive_and_persist` path — the closest
  existing "receive → verify → dispatch" pattern, but it is **push** ingest, not
  request/response, and it is unauthenticated (the CEG per-trace signature is the
  auth, `src/ingest_http.rs:35-46`).
- **The client addresses nodes by `baseUrl`.** `CIRISApiClient` holds one
  `baseUrl` (default `http://127.0.0.1:4243`, `CIRISApiClient.kt:210,365`);
  switching is a `updateBaseUrl` + `recreateApis` (`CIRISApiClient.kt:252-341`).
- **Remote owned nodes are unreachable.** The switcher builds an owned *remote*
  profile with **`baseUrl = ""`** (`NodeSwitcherViewModel.kt:129-137`), and
  `switchTo` **refuses** a blank-baseUrl profile with "reachable over the mesh —
  coming soon" (`NodeSwitcherViewModel.kt:244-253`). The source of the owned
  `key_id`s is `GET /v1/setup/owned-nodes` → `{owner, nodes:[{key_id,is_self}]}`
  (`src/auth/bootstrap.rs:983-1030`), projected from the `delegates_to(owner→node)`
  owner-bindings (`ownership::nodes_stewarded_by`, `bootstrap.rs:1004`). It carries
  **no endpoint** — only `key_id`.
- **The only remote-reach precedent is HTTP-to-`transport_hint`.**
  `claim_remote()` (`src/claim_remote.rs:181`) decodes the target NodeCode
  (`nodecode::decode`, `src/nodecode.rs:68`) and POSTs a fed-ID-signed
  `owner_binding` to `{transport_hint}/v1/setup/root`. `announce_self_handler`
  (`src/claim_remote.rs:655`) only promotes **this** node (`st.node_key_id`).
  There is **no** `announce-remote` / `peer-remote`, and none over RNS. The mesh
  runbook flagged exactly this gap (`MESH_SEED_RUNBOOK_POST_DELEGATION.md`
  §"The one real gap").

---

## 3. Architecture

### 3.1 Components

| # | Component | Where | Responsibility |
|---|-----------|-------|----------------|
| C1 | **Local relay endpoint** | new `src/mesh_relay.rs`, mounted in `compose.rs` | Loopback `POST /v1/mesh/relay`. Owner/dgrant-gated. Resolves the owner fed-ID signer, builds a fed-signed `NodeControlRequest`, calls `edge.send::<NodeControlRequest>(target_key_id, …)`, streams the `NodeControlResponse` back to the client. |
| C2 | **`NodeControlRequest` / `NodeControlResponse` wire types + `Message` impl** | new module in `crates/ciris-lens-core` (or a small `ciris-node-core`-style crate) | The typed body carried over the edge envelope; `impl Message { const TYPE = MessageType::NodeControlRequest; type Response = NodeControlResponse; }`. |
| C3 | **RNS control listener (responder)** | new `MeshControlHandler`, `impl Handler<NodeControlRequest>`, registered via `edge.register_handler` in `compose.rs` next to `LensCore::attach_handler` (`compose.rs:266`) | Receives the envelope on the shared Edge, verifies the inner owner fed-ID signature, authorizes (signer acts for **this node's** owner), dispatches the allow-listed `{method,path,body}` into the v1 handler surface, returns `NodeControlResponse{status,headers,body}`. |
| E1 | **edge `MessageType::NodeControlRequest` variant** | upstream **CIRISEdge** (`src/messages/mod.rs:52`) | The wire discriminator. `MessageType` is a closed enum; a new typed message needs a new variant (§4.2 — the one edge dependency). |

### 3.2 Flow (owner drives `POST /v1/federation/announce` on remote Node A)

1. Client is switched to Node A (an owned remote, `baseUrl=""`, `pinnedKeyId=A`).
   It has an owner session / dgrant on its **local** node.
2. Client issues `POST /v1/mesh/relay` (loopback) with
   `{target_key_id:"A", method:"POST", path:"/v1/federation/announce", body:{}}`
   and the local owner bearer.
3. C1 authorizes the caller (owner session or `owner:act-on-behalf` dgrant),
   confirms `A` is in the local node's owned-nodes projection, resolves the owner
   fed-ID signer (`compose::resolve_user_signer`, `src/compose.rs:852`), signs the
   canonical `{method,path,body,nonce,ts}` (hybrid Ed25519 + ML-DSA-65), and calls
   `edge.send::<NodeControlRequest>("A", req)`.
4. The edge envelope (signed by the **local node's** federation signer) routes to
   A's rooted destination and lands on A's `MeshControlHandler::handle`.
5. C3 on A: `verify_request`-equivalent over the inner signed payload →
   `signer_acts_for(owner_of_A, signer)` → allow-list check on
   `POST /v1/federation/announce` → dispatch → `announce_self_handler` logic runs
   **locally on A** (promote owner-binding to federation, set
   `net.announce_ownership=true`). Returns `NodeControlResponse{200, …}`.
6. The response round-trips back as the edge ACK; `edge.send` returns it to C1;
   C1 streams `{status,body}` back to the client verbatim.

The client sees an ordinary HTTP 200 from its local node; the owner op executed
on A, authorized by signature, with no password and no route to A's IP.

---

## 4. Wire protocol

### 4.1 The ready primitive: `Edge::send::<M>` (typed request/response by `key_id`)

Edge already exposes a **typed request/response round-trip addressed by
`key_id`**, which is exactly the control-plane primitive we need:

```rust
// ciris_edge (v7.4.4)
pub async fn send<M: Message>(&self, destination_key_id: &str, msg: M)
    -> Result<M::Response, EdgeError>;              // src/edge.rs:1766
```

- `M: Message` declares `const TYPE: MessageType`, `const DELIVERY: Delivery`,
  and `type Response` (`src/handler.rs:162-169`).
- The initiator's envelope is signed by the node's federation signer
  (`self.signer.key_id`, `src/edge.rs:1763`) and sent by `key_id`
  (`transport.send(destination_key_id, &envelope_bytes)`, `src/edge.rs:1838`);
  the reticulum transport resolves `key_id → destination` from its rooted-peer map.
- On the responder, `register_handler::<M,H>` (`src/edge.rs:1730`) stores an
  erased fn that parses the body, calls `Handler::handle` (`src/handler.rs:240`),
  and **serializes the handler's `M::Response` as the ACK bytes**
  (`src/edge.rs:1742-1744`). `send` returns that `M::Response` to the caller.
- `HandlerContext` (`src/handler.rs:193-212`) hands the responder the
  verify-resolved `signing_key_id` (the *transport* signer = the local node),
  `verify_outcome`, and `transport` id — the same context `LensCoreHandler` uses.

This is the SAME machinery trace-ingest rides (`LensCoreHandler`,
`role/handler.rs:58`), but two-way: `AccordEventsBatch::Response =
AccordEventsResponse`. We define a new message whose `Response` carries the
proxied HTTP result.

### 4.2 The one edge dependency — a new `MessageType` variant

`MessageType` is a **closed enum** owned by edge (`src/messages/mod.rs:52`); there
is no `Custom`/`Opaque` passthrough variant. Consumer crates own the *body
structs* but each points back to a variant here
(`src/messages/mod.rs:44-51` doc). So the MVP requires **one upstream edge
change**: add

```rust
// CIRISEdge src/messages/mod.rs
NodeControlRequest,   // owner control-plane relay → owned node. Ephemeral.
```

(Response types do **not** need a variant — only the request `Message` carries
`TYPE`; the `Response` is serialized inline as the ACK, §4.1.) File a CIRISEdge
issue; pin the co-bump in `Cargo.toml` (×2) + `crates/ciris-lens-core/Cargo.toml`
(the three-pin rule, MEMORY 0.5.60). Until it lands, prototype behind a fork
branch — do not repurpose an unrelated variant (`StewardDirective`, etc.):
semantics + body-struct collision.

> **Why not `link_open`/`link_request`?** `RNS_CLIENT_TRANSPORT.md` G2 assumed
> `link_request` (`transport/reticulum.rs:1883`) was a ready two-way primitive.
> It is **initiator-only** in v7.4.4: the responder side of a leviculum
> `send_request` is **not wired** in edge's event loop — inbound requests fall
> through to `other => trace!("unhandled")` (`transport/reticulum.rs:2957`;
> the loop handles `LinkEstablished`/`ResourceCompleted`/`ResponseReceived` but
> not an inbound `RequestReceived`). Serving `link_request` would need a *larger*
> edge change (an inbound request-responder registration). `Edge::send::<M>` is
> the smaller, already-proven path (needs only the enum variant). Choose it.

### 4.3 Envelope format

`NodeControlRequest` (C2 body struct, msgpack/JSON over the edge envelope):

| field | type | purpose |
|-------|------|---------|
| `target_key_id` | `String` | The intended remote `key_id`. Responder asserts `== self.node_key_id` (defence-in-depth vs a misrouted/replayed envelope). |
| `method` | `String` | `GET`/`POST`/`PUT`/`DELETE`. |
| `path` | `String` | Absolute v1 path, e.g. `/v1/federation/announce`. Allow-listed (§5.3). |
| `body` | `Option<Vec<u8>>` | Request body bytes (opaque; JSON in practice). |
| `nonce` | `[u8;16]` | Random per request — replay key. |
| `issued_at` | `i64` | Unix seconds — freshness window. |
| `signer_key_id` | `String` | The **owner fed-ID** `key_id` that signed. |
| `sig_ed25519` | `String` (b64) | Ed25519 over the canonical signing payload. |
| `sig_ml_dsa_65` | `String` (b64) | ML-DSA-65 over the same (hybrid; required under Strict, mirrors `verify.rs:24-25`). |

**Canonical signing payload** = a deterministic serialization of
`{target_key_id, method, path, sha256(body), nonce, issued_at}` (NOT the outer
envelope — the outer envelope carries the node-signer signature independently).
Sign it with the owner fed-ID signer exactly as `claim_remote` signs the owner
binding (`resolve_user_signer` → `LocalSigner`, `src/claim_remote.rs:367,454`).

`NodeControlResponse`:

| field | type | purpose |
|-------|------|---------|
| `status` | `u16` | HTTP status the local handler produced on the remote. |
| `body` | `Vec<u8>` | Response body bytes (streamed back to the client verbatim). |
| `content_type` | `String` | Echoed so the client renders correctly. |

### 4.4 Correlation, timeout, MTU/chunking

- **Correlation** is handled by edge: `send::<M>` blocks and returns the matching
  `M::Response` (request/response is 1:1 per call; edge's internal request-id
  slotting, `transport/reticulum.rs:1899-1926`, is below this layer).
- **Timeout:** the relay wraps `edge.send` in a `tokio::time::timeout`
  (default 30 s, config `mesh.relay_timeout_secs`); on elapse → HTTP 504 to the
  client with a stable token (`mesh_relay_timeout`).
- **MTU/chunking:** edge envelopes are single-segment up to an **8 MiB** resource
  cap (`transport/reticulum.rs:2890-2891`). Owner-op bodies (announce, peering,
  config, owned-nodes) are < 1 KiB, so no chunking is needed for the MVP route
  set. The relay **rejects** a `body` over a conservative cap (e.g. 256 KiB) with
  413 rather than risk a multi-segment path that the responder loop doesn't
  reassemble for requests. Larger read surfaces (memory/timeline) are excluded
  from the allow-list for exactly this reason (§5.3).

---

## 5. Server — RNS control listener (C3)

### 5.1 Registration

Registered on the shared Edge alongside the ingest handler, before `edge.run()`
consumes the Edge:

```rust
// src/compose.rs, near LensCore::attach_handler (compose.rs:266)
edge.register_handler::<NodeControlRequest, _>(
    MeshControlHandler::new(Arc::clone(&engine), cfg.key_id.clone(),
                            cfg.user_key_id.clone(), cfg.user_seed_dir.clone()),
).await?;
```

Gated: register only when the node is owner-bound (there is an owner to authorize
against) and `caps.lens_store` isn't required (a relay-only node can still be
administered). It reuses the ONE shared Reticulum transport — no second listener.

### 5.2 `handle()` — mirror the `self_login` shape exactly

The handler mirrors `self_login` (`src/auth/self_login.rs:109-140`), the canonical
"verify → parse → admit → dispatch" fabric pattern:

1. **Verify** the inner hybrid signature over the canonical signing payload
   (§4.3), against the federation directory, under `HybridPolicy::Strict`. Reuse
   `verify_hybrid_via_directory` (the primitive behind `verify::verify_request`,
   `src/auth/verify.rs:65`) — but feed it the reconstructed payload + the
   envelope's `sig_*` fields rather than HTTP headers (the RNS carrier has no
   `HeaderMap`; the signature fields live in the struct). Factor the header-free
   core out of `verify_request` so both callers share it.
2. **Authorize:** resolve **this node's** owner
   (`ownership::is_steward_bound(engine, self_node_key_id)`,
   `src/auth/bootstrap.rs:1002`) and assert
   `verify::signer_acts_for(engine, signer_key_id, owner_key_id)`
   (`src/auth/verify.rs:84`) — the signer IS the owner or an admitted occurrence
   of it. No owner, or signer not-for-owner → reject (`HandlerError::ApplicationRejected`).
3. **Replay/freshness:** reject if `issued_at` is outside ±120 s, or if
   `(signer_key_id, nonce)` is in the recent-nonce cache (§10).
4. **Target check:** assert `target_key_id == self_node_key_id`.
5. **Allow-list:** `(method, path)` must be in the relayable set (§5.3), else
   reject (never dispatch an arbitrary route).
6. **Dispatch** into the v1 handler surface (§5.4), collect
   `{status, content_type, body}`, return `NodeControlResponse`.

Handler errors map to edge wire rejects (`HandlerError`, `src/handler.rs:217-235`)
which surface to the initiator as an `EdgeError` — the relay maps those to HTTP
statuses for the client (401/403/404/413/502).

### 5.3 Allow-list (MVP)

Relayable owner ops — the mesh-seed surface the runbook needs, plus the reads the
switcher wants:

| method | path | maps to |
|--------|------|---------|
| GET | `/v1/setup/owned-nodes` | `bootstrap::owned_nodes` (`bootstrap.rs:1001`) |
| GET | `/v1/federation/self-key-record` | `claim_remote` self-key-record (public) |
| GET | `/v1/federation/peers` | `federation_peers::router` (`compose.rs:629`) |
| POST | `/v1/federation/announce` | `announce_self_handler` (`claim_remote.rs:655`) |
| POST | `/v1/federation/peering` | `federation_admin` peering (`federation_admin.rs`) |
| GET | `/v1/config` / GET `/v1/config/{key}` | `graph_config` reads |
| GET | `/v1/identity`, `/v1/setup/status` | identity/status reads |

**Never relayable** (§10): the two-mode wipe (`/v1/system/data/*`,
`src/system_data.rs`), `/v1/setup/root` (claim — has its own remote path,
`claim_remote.rs`), `/v1/self/identity` mint, `/login`, and any large read
(`/v1/memory/*`, `/v1/telemetry/logs`) that would blow the single-segment cap.
The allow-list is a `const &[(Method, &str)]` — explicit, reviewable, closed.

### 5.4 Reuse vs fork the router

**Reuse — do not fork axum.** Build the v1 router **once** in a factory that
`compose.rs` calls for both the HTTP listener and the relay. In `handle()`,
construct an `http::Request` from `{method, path, body}` and drive it through the
in-process router via `tower::ServiceExt::oneshot` (axum `Router` is a `tower`
`Service`). This guarantees the RNS path and the HTTP path execute **the same
handler code** — no drift, no second implementation of announce/peering. The one
difference is the auth layer: HTTP handlers gate on a bearer (`require_owner`);
over RNS the caller is already owner-verified by signature, so the relay injects a
synthetic owner `SessionCaller` (an internal request extension the shared handlers
read) rather than requiring an `Authorization` header. Factor `require_owner`
(`claim_remote.rs`) to accept "caller already established" so both paths converge.

---

## 6. Server — local relay endpoint (C1)

`POST /v1/mesh/relay` on the **loopback control listener only** (not the public
read API — same posture as the owner-gated setup routes). Request:

```json
{ "target_key_id": "ciris-status-1-ab12…",
  "method": "POST", "path": "/v1/federation/announce", "body": null }
```

Handler (`src/mesh_relay.rs`):

1. **Auth gate** — `require_owner`-style: a SYSTEM_ADMIN + `FullAccess` bearer,
   which includes a minted **dgrant** (`owner:act-on-behalf`,
   `src/auth/device_grant.rs:68`; the dgrant resolves to a SYSTEM_ADMIN
   `SessionCaller`, `device_grant.rs:693`). So the client's existing delegation
   grant authorizes the relay call.
2. **Ownership scoping** — confirm `target_key_id` is in this node's owned-nodes
   projection (`ownership::nodes_stewarded_by(engine, owner)`, `bootstrap.rs:1004`).
   Refuse a target the local owner does not own (the relay is **not** an open
   proxy — §10). `target == self_node_key_id` short-circuits to the local HTTP
   router (no RNS hop needed).
3. **Sign** — resolve the owner fed-ID signer
   (`compose::resolve_user_signer(engine, FedIdUse::OwnerSession, user_key_id,
   seed_dir)`, `src/compose.rs:852`; the choke-point releases the fed-ID only under
   a live owner session — exactly our gate). Build + hybrid-sign the canonical
   payload (§4.3).
4. **Send** — `tokio::time::timeout(relay_timeout,
   edge.send::<NodeControlRequest>(target_key_id, req))`.
5. **Return** — map `NodeControlResponse{status,body,content_type}` onto the HTTP
   response verbatim; map `EdgeError`/timeout onto 502/504 + a stable token.

`compose.rs` passes C1 the `Edge` handle (it already holds `edge` before
`edge.run()`, `compose.rs:332`), the engine, `cfg.key_id`, and the user-signer
inputs (same triple `claim_remote::router` gets, `claim_remote.rs:727-733`).

### 6.1 `key_id → destination` resolution

**The relay does not derive destinations manually.** `edge.send(target_key_id, …)`
resolves `key_id → Reticulum destination` internally from edge's **rooted-peer
map**, populated from received authenticated announces
(`transport/reticulum.rs:1794-1807` shows `link_open` requiring a rooted peer;
`send` uses the same map). The relay supplies only `target_key_id` — which
owned-nodes already provides. `reticulum_destination_for_pubkey(pubkey) =
sha256(pubkey)[..16]` (`transport/addressing.rs:46`) is edge-internal; the relay
never touches it.

---

## 7. `key_id → destination` resolution & reachability

**How the gateway learns a target's destination:** by **rooting the target's
announce**. Every ciris-server node announces its NODE-key attestation on the
shared Reticulum transport, because edge v7.0+ **always** wires
`ReticulumAuth.signer` (`src/compose.rs:1398-1401,1419-1425`). Crucially,
`net.announce_ownership` gates only whether the **owner-binding** is promoted to
*federation cohort scope* (`compose.rs:1407-1418`); it does **not** suppress the
NODE-key transport announce. So an owned node with the default self-scoped owner
binding is **still rooted-and-reachable by `key_id`** over RNS — the owner's
privacy (owner-binding cohort = self) is preserved while transport routing works.
This is the key enabler: we do **not** require the target to have run
`POST /v1/federation/announce` to administer it over the relay.

**Preconditions for a successful relay:** (a) both nodes share a Reticulum path
(same LAN interface, or a transport-node/testnet route — the NAT-traversal infra
is already configured, `compose.rs:1448`), and (b) the gateway has **received and
rooted** the target's announce (announce cadence = `ANNOUNCE_INTERVAL` 300 s,
`compose.rs:38-39`). Cold-start: the first relay to a just-seen node may race the
announce; `edge.send` returns `EdgeError::Unreachable`-class → the relay retries
once after a short backoff, then surfaces **502 `mesh_target_unreachable`** with
"target not currently announced/reachable" so the client can show
"node offline / not on the mesh right now."

**Optional resolver assist (post-MVP):** owned-nodes could additionally return the
target's Ed25519 pubkey (it is in the owner-binding), letting the gateway seed a
`PeerResolver` entry (`transport/reticulum.rs` resolver hook) for the target's
derived destination even before an announce is heard, tightening cold-start. Not
required for the MVP.

---

## 8. Client changes

Minimal, additive, on the existing Ktor stack. **No RNS in Kotlin.**

1. **`NodeProfile`** — already carries `pinnedKeyId` and `baseUrl`. Add a
   derived notion "relay node" = `isOwned && baseUrl.isBlank() && pinnedKeyId != null`.
   (Optionally a `transport: http|mesh` discriminant for clarity, but the blank
   baseUrl + key_id already encodes it.)
2. **`CIRISApiClient`** — add a nullable `relayTargetKeyId: String?` and a
   `updateRelay(keyId: String)` that sets `baseUrl = LOCAL_NODE_URL`
   (`CIRISApiClient.kt:365`) and records the target. In the request path, when
   `relayTargetKeyId != null`, wrap the outgoing call as
   `POST {LOCAL_NODE_URL}/v1/mesh/relay { target_key_id, method, path, body }`
   instead of issuing `{baseUrl}{path}` directly. The cleanest seam: a small Ktor
   client plugin / a wrapper around the generated API calls that rewrites
   `(method, path, body)` into a relay envelope when relay mode is active. All 15+
   generated API instances (`CIRISApiClient.kt:436-341`) keep pointing at
   `LOCAL_NODE_URL`; only the request-shaping changes.
3. **`NodeSwitcherViewModel.switchTo`** (`NodeSwitcherViewModel.kt:244`) — replace
   the blank-baseUrl refusal (`:250-253`) with: if the profile is a relay node,
   call `apiClient.updateRelay(profile.pinnedKeyId!!)` and set it active; else the
   existing `updateBaseUrl` path (`:259`). Clearing relay mode (switching back to a
   `baseUrl` node) sets `relayTargetKeyId = null`.
4. **wasmJs** — keep the "reachable from a device with a local node" message for
   relay nodes (no local backend to gateway through, `RNS_CLIENT_TRANSPORT.md` G4).
   Gate the relay path off on the web target.

Everything else — token handling, screens, the owned-nodes reload — is unchanged;
a relayed call looks like an ordinary local HTTP call to the rest of the client.

---

## 9. Auth model — who signs what, and why no password on the remote

Two independent identities, per the substrate model
(`RNS_CLIENT_TRANSPORT.md` §5):

- **Transport identity (routing):** the edge envelope carrying the
  `NodeControlRequest` is signed by the **local node's** federation signer
  (`edge.send` → `self.signer`, `src/edge.rs:1763`). This roots the packet on the
  mesh and populates `HandlerContext.signing_key_id` on the remote. It is **not**
  the authorization principal.
- **Authorization identity (owner):** inside the envelope, the
  `{method,path,body,nonce,ts}` payload is hybrid-signed by the **owner's fed-ID**
  (`resolve_user_signer`, `src/compose.rs:852`). The remote verifies this against
  its federation directory and checks `signer_acts_for(owner_of_this_node, signer)`
  (`src/auth/verify.rs:84`) — the identical admission rule `self_login` uses
  (`self_login.rs:135`) and `portable_occurrence` relies on (`portable_occurrence.rs:41`).

**Why no password/bearer on the remote:** the remote's owner authority is a
signed CEG fact — the `delegates_to(owner→node)` owner-binding already in the
remote's directory (the same binding `owned-nodes` projects, `bootstrap.rs:1004`).
A request signed by that owner (or an admitted occurrence) **is** proof of
authority; there is nothing a password would add. This is why the HTTP
password/login path (`src/auth/session.rs:381`, which *refuses a ROOT cert with no
password* — the exact wall the mesh runbook hit,
`MESH_SEED_RUNBOOK_POST_DELEGATION.md` §"The one real gap") is **bypassed
entirely**: the remote nodes were claimed *without* a password, and over the relay
they never need one.

**End-to-end chain:** client → (dgrant `owner:act-on-behalf`, or owner session,
on the **local** node) → C1 resolves the owner fed-ID signer under that gate
(`resolve_user_signer` choke-point only releases the fed-ID to a verified owner
session, `compose.rs:858-869`) → owner-signed `NodeControlRequest` → node-signed
edge envelope → remote verifies **owner** signature → remote authorizes because
the owner owns it → dispatch. The dgrant thus transitively authorizes remote
administration, attributed to the owner.

---

## 10. Security

- **Not an open proxy.** C1 forwards only to `target_key_id`s the local owner
  **owns** (owned-nodes scoping, §6.2). C3 dispatches only **allow-listed**
  `(method,path)` pairs (§5.3) and only when the inner signer acts for **this
  node's** owner. Two independent gates; neither trusts the client's raw
  `{method,path}` as authority.
- **Replay protection.** `nonce` (16 random bytes) + `issued_at` (±120 s window);
  C3 keeps a bounded LRU of recently-seen `(signer_key_id, nonce)` (size/TTL
  covering the freshness window) and rejects repeats. The node-signer envelope
  layer plus the fresh owner signature mean a captured envelope cannot be
  replayed after the window or to a different node (`target_key_id` binding).
- **Request scoping / never-relayable.** Wipe (`/v1/system/data/*`), claim
  (`/v1/setup/root`), fed-ID mint (`/v1/self/identity`), `/login`, and any large
  read are excluded (§5.3). Adding a route to the allow-list is a reviewed code
  change, not config.
- **SSRF / loopback.** C1 is mounted on the **loopback control listener** only
  (`compose.rs` control-listener layer, mirroring the setup routes) — never the
  public read API. It performs **no arbitrary outbound HTTP**: the only egress is
  `edge.send` by `key_id` to an **owned** target, so there is no URL for an
  attacker to point it at. `target == self` short-circuits to the in-process
  router (no network at all).
- **Rate limits.** Per-`signer_key_id` and per-`target_key_id` token buckets on
  C3 (config `mesh.relay_rate_per_min`, default e.g. 60/min) to bound a
  compromised-gateway blast radius; C1 similarly caps outstanding relays.
- **Body cap.** 256 KiB request-body cap (413) so a control envelope stays
  single-segment (§4.4); prevents a multi-segment path the responder loop does not
  reassemble for requests.
- **Fail-honest reachability.** An unrooted/offline target yields
  `502 mesh_target_unreachable`, never a silent success (`MISSION.md` anti-pattern
  6 posture, mirrored from `ingest_http` error discipline, `ingest_http.rs:146-160`).

---

## 11. Migration / back-compat

- **Purely additive.** HTTP `baseUrl` nodes (added by URL / NodeCode this session)
  keep working — `switchTo` still takes the `updateBaseUrl` path for them
  (`NodeSwitcherViewModel.kt:259`). The relay is a new route + a new edge message
  type; nothing existing changes behavior.
- **No substrate migration.** Owner-bindings, directory, and the owned-nodes
  projection are unchanged. The remote needs no new state — it authorizes off the
  `delegates_to` binding it already holds.
- **Edge co-bump.** The only floor change is the new `MessageType` variant
  (§4.2) → a CIRISEdge point release, pinned in the three places (MEMORY 0.5.60
  three-pin rule). Nodes on the old edge simply reject the unknown message type
  (fail-honest); a relay only works node↔node once both are on the co-bumped edge.
- **`transport_hint` still honored.** A node that *does* have a public
  `transport_hint` can still be reached by HTTP (`claim_remote` path); the relay is
  the answer for IP-less nodes, chosen client-side by "owned + blank baseUrl".

---

## 12. Test plan

**Unit (server):**
- `NodeControlRequest`/`Response` round-trip serde; canonical signing-payload
  determinism (byte-stable across re-serialization).
- Signature verify: a valid owner-signed payload passes; tampered
  `method`/`path`/`body`/`nonce` fails; wrong signer (not owner, not occurrence)
  → `signer_acts_for` false → reject. Reuse `self_login` verify tests as the
  template (`self_login.rs` test module).
- Allow-list: a non-listed `(method,path)` is rejected pre-dispatch; wipe/claim
  paths are absent from the const list (assert).
- Replay: same `(signer,nonce)` twice → second rejected; stale `issued_at` →
  rejected.
- C1 ownership scoping: relay to a non-owned `key_id` → 403; `target==self` →
  local-router short-circuit (no `edge.send`).

**Integration (loopback + same-host second node):**
- Boot **two** ciris-server instances on one host over a shared Reticulum
  interface (the `transport_reticulum_loopback` bench setup in edge is the
  reference, `.cargo/.../benches/transport_reticulum_loopback.rs`), owner-bind both
  to the same fed-ID. Wait for mutual rooting.
- Drive `POST /v1/mesh/relay {target=B, POST /v1/federation/announce}` against A's
  loopback with a dgrant; assert B promotes its owner-binding + sets
  `net.announce_ownership=true` (assert on B's CEG/config), and A's client gets 200.
- Drive `POST /v1/federation/peering` A→B and B→A **through the relay** (the mesh
  runbook flow, over RNS instead of HTTP) and assert the bilateral
  `consent:replication` objects land — the end-to-end proof this FSD's Option
  supersedes the runbook's HTTP Option A.
- `GET /v1/setup/owned-nodes` and `/v1/federation/peers` relayed → responses match
  the target's local HTTP responses byte-for-byte (same-router guarantee, §5.4).
- Reachability failure: tear down B, relay to B → 502 `mesh_target_unreachable`
  within the timeout.

**Client:**
- `NodeSwitcherViewModel.switchTo` on a relay node sets relay mode (no
  `updateBaseUrl` to a blank URL); switching back to a `baseUrl` node clears it.
- A relayed API call issues `POST {LOCAL_NODE_URL}/v1/mesh/relay` with the right
  `{target_key_id,method,path,body}` (mock the local endpoint).

---

## 13. Phasing

### MVP — hardcoded owner-op route set, server-first

Prove the path end-to-end before any client work (the `RNS_CLIENT_TRANSPORT.md`
§6 "validate Node A↔B over RNS with curl first" discipline).

**File-by-file touch list (MVP):**

1. **CIRISEdge (upstream):** add `MessageType::NodeControlRequest`
   (`src/messages/mod.rs:52`); cut a point release. — *the one external dep.*
2. **`crates/ciris-lens-core/src/…` (new module, e.g. `mesh_control.rs`):**
   `NodeControlRequest` / `NodeControlResponse` structs + `impl Message for
   NodeControlRequest { TYPE = NodeControlRequest; DELIVERY = Ephemeral; Response
   = NodeControlResponse; }`. Export.
3. **`src/mesh_control.rs` (new):** `MeshControlHandler` (`impl
   Handler<NodeControlRequest>`) — verify (header-free core factored from
   `verify.rs`), `signer_acts_for` authz, replay/freshness, allow-list, dispatch
   via the shared v1 router (`tower::ServiceExt::oneshot`).
4. **`src/mesh_relay.rs` (new):** `POST /v1/mesh/relay` router + handler — owner/
   dgrant gate, owned-nodes scoping, `resolve_user_signer`, sign, `edge.send`,
   timeout, response mapping.
5. **`src/auth/verify.rs`:** factor a header-free `verify_signed_payload(engine,
   payload, signer_key_id, ed25519, ml_dsa_65, policy)` core out of
   `verify_request` (`verify.rs:48`) so C3 reuses it.
6. **`src/compose.rs`:** (a) build the v1 router via a shared factory usable by
   both the HTTP listener and C3; (b) `edge.register_handler::<NodeControlRequest,
   _>(…)` near `LensCore::attach_handler` (`compose.rs:266`); (c) mount
   `mesh_relay::router(edge, engine, cfg, user-signer inputs)` on the control
   listener; pass the `Edge` handle before `edge.run()` (`compose.rs:332`).
7. **`Cargo.toml` ×2 + `crates/ciris-lens-core/Cargo.toml`:** bump the pinned edge
   rev (three-pin rule).

Allow-list for MVP: `owned-nodes`, `self-key-record`, `federation/announce`,
`federation/peering`, `federation/peers` (the mesh-seed surface). No client change
yet — validate with `curl` against A's loopback `/v1/mesh/relay`.

### Full — generic signed relay + client relay-mode UX

- Extend the allow-list to the whole owner-op read/manage surface (config
  read/write, identity, status), with per-route body caps.
- Client: `CIRISApiClient` relay-mode wrapper (§8) + `NodeSwitcherViewModel`
  relay switch + relay-node UX (a "on the mesh" badge; offline → clear error).
- Optional resolver-assist cold-start seeding (§7) if announce-race latency is
  felt in the field.
- Optional: the native-FFI leaf transport (`RNS_CLIENT_TRANSPORT.md` A2/Slice 3)
  slots behind the same relay-mode seam later, unchanged by this design.

---

## 14. Open questions / risks

1. **Edge enum dependency (highest).** The MVP is blocked on an upstream
   CIRISEdge `MessageType::NodeControlRequest` variant (§4.2). Mitigation:
   prototype on a fork branch; the change is tiny and mechanical. Confirm the edge
   maintainers accept a "control-plane" message class (vs. asking us to reuse
   `link_request` — which would need the bigger responder-side wiring, §4.2).
2. **Single-segment cap for request bodies.** The responder loop reassembles
   *resources* for the push/ingest path but not for `link_request`s; `edge.send`
   uses the resource/envelope path, which IS reassembled — verify empirically that
   a >8 MiB `NodeControlResponse` (a large read) chunks correctly, or keep large
   reads off the allow-list (current plan). Risk is low given owner-op bodies are
   tiny.
3. **Cold-start announce race.** First relay to a freshly-seen node may 502 until
   the announce is rooted (§7). Retry-once mitigates; resolver-assist removes it.
   Acceptable for MVP.
4. **Occurrence-signer breadth.** `signer_acts_for` admits *any* admitted
   occurrence of the owner (`verify.rs:84-98`) — an agent occurrence could then
   drive remote owner ops. That is the intended §9 "on-behalf-of" model, but
   confirm the allow-list is the right scope for a *delegated* occurrence vs the
   root owner identity (may want a tighter allow-list for occurrence signers than
   for the root fed-ID). Defer; note for review.
5. **Two signatures per request** (node envelope + owner payload) — modest CPU
   (two hybrid verifies on the remote). Negligible at owner-op cadence.
6. **Reachability over the wider Internet** depends on a shared Reticulum
   transport path between the owner's nodes (transport nodes / testnet). Same
   dependency as all federation traffic today; not new to this feature.
</content>
</invoke>
