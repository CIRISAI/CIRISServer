# RNS Client Transport — reaching a remote node over the mesh

Status: DESIGN (no production code). Author: research pass 2026-06-25.
Substrate floor at time of writing: ciris-server 0.5.52, edge v7.0.12,
leviculum v0.7.0, verify family v7.5.0, persist v10.2.2.

Scope: how the KMP/Compose client (Kotlin; Android, iOS, desktop JVM,
wasmJs) reaches a *remote* node over RNS (Reticulum) so the owner can do
full remote interaction/management, authenticated by their federation
identity (fed-ID).

---

## 1. Problem & goals

The client today talks **HTTP only** to a single `baseUrl` per session
(default `http://127.0.0.1:4243`), with a first-class node-switcher
(`NodeProfile { baseUrl, sessionToken, pinnedKeyId, isLocal, isOwned }`,
`NodeSwitcherViewModel`, `NodeProfileStore`). Remote nodes are reached
today only by a routable IP/DNS `baseUrl` + a bearer token. There is **no
RNS code in the client** (grep of `client/` for reticulum/RNS/mesh/
destination = empty).

Goals:

1. **Remote interaction/management over the mesh** — the owner activates a
   remote node by its NodeCode and gets a working read/manage session,
   *without* that node having a public IP/DNS name. "Addressing IS
   identity": the node's fed Ed25519 pubkey *is* its routable RNS
   destination (`sha256(pubkey)[..16]`, see §grounding).
2. **fed-ID authentication** — the session is authorized by the OWNER's
   federation identity (owner-binding `delegates_to(owner→node, infra:*)`,
   already established for Node A/B), distinct from whatever identity
   *routes* the packets.
3. **All four KMP targets** — Android, iOS, desktop JVM, wasmJs. (The web
   target is the constraint that breaks the obvious answer; see §2.)
4. **Minimum elegant + adequate** — reuse the substrate the node already
   ships, do not invent a parallel mesh stack, do not over-build a new
   node class unless warranted.

Non-goals: a public DHT/name service (we have NodeCodes); the client
acting as an RNS *relay* or corpus holder; offline message queuing
(store-and-forward is a node concern, not a client concern).

---

## 2. Grounding facts (verified in-repo)

These are load-bearing; the architecture choice falls out of them.

**G1 — addressing IS identity, no DNS.**
`ciris_edge::transport::addressing::reticulum_destination_for_pubkey(pubkey: &[u8;32]) -> [u8;16]`
= `sha256(pubkey)[..16]` (edge `src/transport/addressing.rs:46`,
`RETICULUM_DEST_LEN = 16`). The 32-byte fed pubkey is carried in the
NodeCode (`CIRIS-V1-...`; `src/nodecode.rs` — pubkey + an *optional*
`transport_hint` HTTP URL). So the RNS destination of any node is
derivable client-side from its NodeCode with zero infrastructure.

**G2 — the read-API-over-RNS request primitive already exists in edge,
and is already exposed via UniFFI.** edge `ReticulumTransport` has:
- `link_open(&destination_hash, timeout) -> EdgeLinkHandle{ link_id }`
- `link_request(&link_id, &path, &data, timeout) -> Vec<u8>`  (blocking
  request/response over the established link; `data` opaque bytes,
  leviculum wraps msgpack on the wire)
- `link_teardown(&link_id)`, `knows_peer(key_id)`, `link_list/count`

These are surfaced in `src/ffi/uniffi_impl_links.rs` as free functions
(`link_open`, `link_request`, `link_teardown`, …) over the process-global
`current_reticulum()` transport, with UniFFI types
`EdgeLinkHandle{ link_id: Vec<u8> }` / `EdgeLinkInfo`. edge builds
`crate-type = ["cdylib","rlib"]` with **UniFFI 0.31.1** (`ffi-uniffi`
feature) generating Kotlin + Swift bindings, plus PyO3. So a request →
response call to a remote node over RNS is a *solved problem at the Rust
layer*; the only open question is which process runs that Rust on each
KMP target.

**G3 — the transport stack is Rust (Leviculum), needs real sockets, and
has no wasm.** edge's Reticulum transport is Leviculum
(`reticulum-core` + `reticulum-std`, **AGPL-3.0-or-later**). `reticulum-std`
depends on `tokio` (rt-multi-thread), `socket2`, `tokio-serial`;
`reticulum-ffi` ships `crate-type = ["cdylib","staticlib"]`. There is
**no `wasm32` / `wasm-bindgen` / `target_arch="wasm"` anywhere** in edge
or leviculum (grep = empty). Tokio multi-thread + socket2 + serial are
fundamentally incompatible with `wasm32-unknown-unknown` (no threads, no
sockets). Porting is not a flag flip; it is a rewrite of the transport's
IO layer onto an async-single-thread + WebSocket/WebTransport model.

**G4 — the embedded local node differs per target.**
- Desktop JVM: subprocess `ciris-server` binary (`PythonRuntime.desktop.kt`,
  `--key-id ciris-client`). This is a *full Reticulum node* (edge runtime).
- Android: Chaquopy-embedded **Python agent** (`PythonRuntimeService.kt`),
  serving `127.0.0.1:8080`. The agent process *is* a ciris-server one-wheel
  host (edge inside), so it too carries a Reticulum transport — but the
  surface the client talks to is the agent's, not a bare ciris-server.
- iOS: PythonKit-embedded runtime (same family as Android).
- wasmJs: **no embedded backend at all.** A browser tab cannot fork a
  process or open raw sockets. This target has only `fetch`/WebSocket.

**G5 — node↔node reach today is HTTP, not RNS, for management.**
`claim_remote.rs` already reaches a *remote* node, but over **HTTP** to
`{transport_hint}/v1/setup/root`. Federation replication runs over RNS
(`compose.rs` ReplicationRuntime), and ingest has an RNS relay
(`LensCoreHandler`) mirrored by `ingest_http.rs`. But **no code today
opens an RNS link to call a remote peer's authenticated read/manage
API.** That path has to be built on either side of the seam — the edge
primitives (G2) exist, the wiring does not.

**G6 — the client identity `ciris-client-*` is a node label, not a
separate identity class.** `--key-id ciris-client` is the keystore alias;
the wire identity is the derived `ciris-client-<fp(sha256(pubkey))>`
(FSD-003). The desktop "client" is literally a ciris-server node that
happens to host the UI's local backend. There is no distinct mesh CLASS
for it today.

---

## 3. The two architectures

### A. Native RNS in the client

The Kotlin client itself holds an RNS identity/destination and speaks
Reticulum directly (`link_open`/`link_request` to the remote node's
destination). Three sub-options:

**A1 — pure-Kotlin/KMP Reticulum.** Reimplement Reticulum (announce,
path-finding, link establishment, resource transfer, the encryption
suite — X25519 + Ed25519 + AES-GCM + the CIRIS hybrid ML-KEM/ML-DSA
envelope) in common Kotlin. *Verdict: rejected.* This is a multi-
person-quarter reimplementation of a security-critical wire protocol that
must stay byte-compatible with Leviculum across versions, with its own
crypto-correctness and audit burden, duplicating a stack we already own
in Rust. No existing mature KMP/Kotlin Reticulum implementation exists to
reuse. This is the single largest maintenance/security surface of any
option and buys nothing the FFI option doesn't.

**A2 — Rust Leviculum via FFI (UniFFI/JNI on JVM+Android, cinterop on
iOS).** Bundle edge's Reticulum transport as a native lib and call its
already-generated UniFFI Kotlin/Swift bindings (G2). This is *viable* on
the three native targets:
- **Desktop JVM**: load the edge cdylib via JNA/JNI; UniFFI Kotlin
  bindings already exist. Feasible.
- **Android**: same UniFFI Kotlin bindings, edge cross-compiled to the
  Android ABIs (arm64/x86_64). Feasible; this is exactly what UniFFI is
  for.
- **iOS**: edge/leviculum `staticlib` + the UniFFI Swift bindings via
  cinterop. Feasible.
- **wasmJs**: **NOT feasible** (G3). No sockets, no threads, no wasm
  build of leviculum.

  Cost/risk: ship and sign a ~tens-of-MB native lib per ABI in the app
  bundle; an **AGPL-3.0** transport library inside a distributed client
  app (G3) — a genuine licensing decision for the shipped product, not
  just the server. The client would also become a *second* Reticulum node
  on the mesh (its own identity, path table, link lifecycle) running
  inside the UI process.

**A3 — WASM build of the Rust stack for wasmJs.** *Verdict: not viable
today, large.* Requires (a) a wasm32 port of leviculum's IO layer off
tokio-multithread/socket2/serial onto a browser-compatible async model,
(b) a browser-reachable Reticulum *interface* (raw UDP/TCP is impossible
in a tab — would need a WebSocket or WebTransport interface kind that a
relay terminates), and (c) re-exporting the UniFFI/wasm-bindgen surface.
This is effectively "invent the browser transport for Reticulum and
upstream it to Leviculum." It is the right *long-term* answer for a
serverless web client but is out of scope for a minimum-adequate slice.

### B. Local-node-as-RNS-gateway

The client keeps speaking **HTTP to its embedded local node**. To reach a
remote node, the *local node* (which already has the edge Reticulum
transport + a fed identity, G4) opens an RNS link to the remote node's
destination (derived from the NodeCode pubkey, G1) and reverse-proxies
the client's read/manage API calls over `link_request` (G2). We already
have an HTTP reverse-proxy seam (`src/proxy.rs`, `reverse_proxy_router`)
and an HTTP→remote-node precedent (`claim_remote.rs`, G5) — the new piece
is an HTTP→RNS proxy variant inside the node.

- **Desktop JVM**: local ciris-server is a full edge node → can open the
  RNS link directly. Clean.
- **Android / iOS**: the embedded *agent* hosts edge too (one-wheel), so
  the same RNS link can be opened from the agent process; the client adds
  one HTTP route to its existing local backend. Works, but couples the
  remote-mesh feature to the agent backend surface.
- **wasmJs**: there is **no embedded backend** (G4). The browser client
  has nothing local to proxy through. It can only reach a node that
  exposes an HTTP(S)/WebSocket endpoint (a `transport_hint`), i.e. it
  *cannot* reach an IP-less mesh-only node at all under either A or B.
  This is a hard floor of the web target, independent of architecture.

### Feasibility / effort / security matrix

| Target  | A2 native FFI (Leviculum)         | A3 wasm native            | B gateway (local node proxies RNS) |
|---------|-----------------------------------|---------------------------|-------------------------------------|
| JVM     | Viable. Med effort (JNI + ABI ship + AGPL). 2nd node in UI proc. | n/a | Viable. **Low** effort (one proxy route; node already a full edge node). |
| Android | Viable. Med effort (UniFFI + ABIs + AGPL). | n/a | Viable. Low–med (proxy route in agent backend). |
| iOS     | Viable. Med–high (staticlib + cinterop + signing + AGPL). | n/a | Viable. Low–med (proxy route in agent backend). |
| wasmJs  | **Not viable** (no sockets/threads/wasm). | Large, not viable today (rewrite leviculum IO + browser interface). | Reach mesh-only node: **not possible** (no local backend). Reach `transport_hint` node: already works over plain HTTP. |
| Security surface | New attack surface = a full RNS node + AGPL transport inside the *UI* process, per platform. | Same, plus an immature wasm IO layer. | **Smallest**: RNS stays in the node we already trust/ship; client keeps its existing HTTP+token model; one new server-side proxy route to review. |
| Maintenance | N native libs to cross-compile, sign, version-lockstep with edge, per release. | Worst (own browser-transport fork). | Reuses the node's existing edge upgrade cadence; no client-side native lib. |

---

## 4. Recommendation — gateway now, native-FFI as an opt-in later

**Adopt B (local-node-as-RNS-gateway) as the minimum elegant + adequate
design.** Rationale:

1. **It is the only design that is uniform across the three targets that
   can reach a mesh-only node, and it does not pretend to solve wasm**
   (which no architecture solves for an IP-less node — that is a target
   limitation, §3.B/G4, to be stated honestly in the UI, not engineered
   around now).
2. **The hard part is already built.** edge exposes `link_open` +
   `link_request` + destination-from-pubkey (G1/G2). The node is already a
   Reticulum node with the owner-binding authz (Node A/B). The remaining
   work is one HTTP→RNS reverse-proxy route, sibling to `proxy.rs` and
   reusing the `claim_remote.rs` NodeCode→target resolution — *server-side
   Rust we control*, not a new native client stack.
3. **Smallest security + maintenance surface.** RNS — and its AGPL
   transport — stays inside the node, which already ships it. The client
   keeps its proven Ktor+token model unchanged across all four targets.
   No per-ABI native lib to cross-compile/sign/lockstep with edge.
4. **It does not foreclose native.** If/when a serverless desktop or a
   mesh-native mobile app is wanted, A2 (UniFFI FFI) is viable and the
   bindings already exist — it can be added as an opt-in transport behind
   the same `activate` seam without rework.

This is *not* defaulting to the gateway out of caution: native A2 is
genuinely viable on JVM/Android/iOS, but it is strictly more cost
(AGPL-in-client, N native libs, a second node in the UI process) for the
same user-visible result on those targets, and it does **nothing** for the
one target that is actually hard (wasm). The gateway is the smaller true
floor.

**Honest caveat:** the gateway concentrates the mesh in the local node, so
a node-less context (wasmJs) is mesh-blind by construction. We accept that
for v1 and surface it: in the web client, only nodes with a
`transport_hint` (HTTP) are activatable; mesh-only nodes show as
"reachable from a device with a local node."

---

## 5. Identity model — transport identity vs owner fed-ID authz

Two identities, kept distinct (this is the existing substrate model, not a
new one):

- **Transport identity (who routes the packets).** The RNS link is opened
  by the **local node's** existing federation identity (the embedded
  ciris-server/agent node, `ciris-client-<fp>` on desktop). Its pubkey →
  its destination (G1); leviculum announces it; the remote node sees a
  rooted peer. *No new identity is minted for transport.* The client UI
  process itself never gets an RNS identity under the gateway design.
- **Authorization (who is allowed to act).** The **owner's fed-ID** is the
  authz principal. The request carried over `link_request` is a
  hybrid-signed envelope whose signer is the owner (the same
  owner-binding `delegates_to(owner→remote node, infra:*)` that gates
  management today). The remote node verifies the owner-binding against
  *its own* directory exactly as `/v1/setup/root` / `require_owner` do for
  HTTP. Transport identity routes; fed-ID authorizes.

**On the proposed "client" / leaf node type.** Evaluated and **not
warranted as a new mesh CLASS for the gateway design.** Under B, the only
RNS participant is the local node, which already exists. A distinct leaf
*class* (opportunistic outbound links, no announce, no relay, no corpus)
becomes meaningful **only if** we later adopt A2 and let the *UI process*
itself be an RNS endpoint on a backend-less platform — at which point a
leaf profile is the right shape (don't announce a UI tab as a routable
relay; open links opportunistically; carry no corpus). Recommendation:

- For v1 (gateway): no new identity, no new class. Reuse the embedded
  node's identity for transport, the owner fed-ID for authz.
- Reserve the term **`leaf` node profile** for the future A2 path — and
  make it a *profile/role flag on the existing node identity*
  (announce=off, relay=off, corpus=off, outbound-link=on), **not** a new
  key class. "Client" is a deployment role of a node, consistent with G6
  ("client" is already just a node label), not a new identity type in the
  mesh.

**How `activate <remote node>` resolves to a session (gateway path):**

1. User selects a `NodeProfile` (or pastes a NodeCode). Client decodes the
   NodeCode → `{ key_id, pubkey, transport_hint? }`.
2. Client decides transport: if a usable `transport_hint` and reachability
   → plain HTTP (today's path). Else → **mesh path**: client calls its
   local node, e.g. `POST /v1/mesh/activate { node_code }`.
3. Local node derives `destination = reticulum_destination_for_pubkey(
   pubkey)` (G1), `link_open(destination)` (waiting on the announce/path
   if needed), establishes the link, and returns an opaque
   `mesh_session_id` to the client.
4. Subsequent client read/manage calls go to a local proxy route
   (`/v1/mesh/{mesh_session_id}/...`) that the node forwards over
   `link_request(link_id, path, owner_signed_body)` to the remote node's
   read/manage handler, returning the response bytes verbatim (the
   `proxy.rs` shape, but HTTP→RNS instead of HTTP→HTTP).
5. The remote node verifies the owner-binding on each signed request
   (fed-ID authz) and serves its read/manage API. `mesh_session_id` maps
   1:1 to the edge link; teardown on idle (`link_teardown`).

This keeps the client's `NodeProfile`/switcher model intact: add an
optional `nodeCode` / `meshDestination` field and a `transport: http|mesh`
discriminant; `sessionToken` stays the bearer for HTTP nodes, while mesh
nodes authorize via the owner-signed envelope the node injects.

---

## 6. Concrete next steps — smallest buildable first slice

Order by value-to-risk. The first slice is **server-side only** and
target-agnostic.

1. **Slice 1 (server, no client change): HTTP→RNS reverse proxy + activate.**
   - Add a `mesh_proxy` module modeled on `proxy.rs` that, given a target
     NodeCode, resolves the destination (`reticulum_destination_for_pubkey`),
     opens an edge link (`link_open`), and forwards read calls via
     `link_request`. Reuse `nodecode::decode` + the `claim_remote.rs`
     resolution.
   - Add `POST /v1/mesh/activate { node_code } -> { mesh_session_id }` and
     `ANY /v1/mesh/{session}/{*path}`.
   - Owner-signed request envelope reuses the `claim_remote` /
     `build_signed_owner_binding` signer surface; remote side verifies via
     the same `require_owner` path used for HTTP.
   - **Validate end-to-end Node A ↔ Node B over RNS** (both already have
     edge transport + the owner-binding) with `curl` against the local
     `/v1/mesh/...` proxy — *before any client work*. This proves the read-
     API-over-RNS path that G5 says does not yet exist.
   - Define the remote-side request handler: which read/manage routes are
     served over the link (start with read-only: `/v1/self/identity`,
     `/v1/federation/peers`, status), then management behind owner authz.

2. **Slice 2 (client): wire `activate` to the mesh path.**
   - Extend `NodeProfile` with `nodeCode` + `transport: http|mesh`.
   - `NodeSwitcherViewModel.switch()` calls `POST /v1/mesh/activate` for
     mesh profiles and points `updateBaseUrl` at the local
     `/v1/mesh/{session}/` prefix. No new Ktor engine, no native lib —
     pure additive on the existing HTTP client. Lands on JVM + Android +
     iOS uniformly.
   - wasmJs: gate the mesh option off (no local backend); show mesh-only
     nodes as "reachable from a device with a local node." HTTP
     (`transport_hint`) nodes keep working on web.

3. **Slice 3 (later, optional): native A2 leaf transport.**
   - Only if a backend-less desktop or mesh-native mobile app is wanted.
     Consume edge's existing UniFFI Kotlin/Swift `link_open`/`link_request`
     bindings; add a `leaf` node *profile* (announce/relay/corpus off);
     resolve the AGPL-in-client licensing decision first. Slots behind the
     same `activate` seam, so no rework of slices 1–2.

4. **Out of scope / track separately:** wasm-native Reticulum (A3) — a
   leviculum browser-transport (WebSocket/WebTransport interface kind +
   wasm IO layer) is the only path to a truly serverless web mesh client;
   file upstream against leviculum if/when the serverless web client is a
   product goal.

---

## Appendix — file anchors

- edge destination derivation: `…/cirisedge/src/transport/addressing.rs:46`
  (`reticulum_destination_for_pubkey`, `RETICULUM_DEST_LEN=16`).
- edge RNS request/response: `…/cirisedge/src/transport/reticulum.rs`
  (`link_open` ~:1392, `link_request` ~:1490, `link_teardown` ~:1447,
  `knows_peer` ~:1286).
- edge UniFFI link surface: `…/cirisedge/src/ffi/uniffi_impl_links.rs`
  (`link_open`/`link_request`/`link_teardown`), types in
  `…/src/ffi/uniffi_types.rs` (`EdgeLinkHandle`, `EdgeLinkInfo`).
- leviculum (transport, AGPL-3.0): `…/leviculum/{reticulum-core,
  reticulum-std,reticulum-ffi}` — `reticulum-ffi` crate-type
  `["cdylib","staticlib"]`; no wasm32 anywhere.
- server reverse proxy seam: `/home/emoore/CIRISServer/src/proxy.rs`
  (`reverse_proxy_router`).
- server remote-node-over-HTTP precedent: `…/src/claim_remote.rs`
  (`build_claim_for_target`, `claim_remote`, NodeCode resolution).
- NodeCode codec: `…/src/nodecode.rs` (`decode`, `NodeCode{ pubkey,
  transport_hint }`).
- client networking: `…/client/shared/src/commonMain/.../api/CIRISApiClient.kt`
  (Ktor, per-target engines, `updateBaseUrl`, default `:4243`);
  switcher `…/viewmodels/NodeSwitcherViewModel.kt`; model
  `…/models/NodeProfile.kt`; desktop backend `…/desktopMain/.../PythonRuntime.desktop.kt`
  (`--key-id ciris-client`); Android backend
  `…/androidApp/.../PythonRuntimeService.kt` (Chaquopy Python agent).
