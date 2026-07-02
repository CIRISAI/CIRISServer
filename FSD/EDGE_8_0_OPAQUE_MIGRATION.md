# Edge v8.0.0 opaque-wire migration + mesh control-plane RNS relay (CIRISServer#128)

**Status:** DESIGN — implementation-ready (no production code in this doc).
**Author:** research + spec pass (2026-07-01).
**Substrate floor (target):** ciris-server 0.5.73, **edge v7.4.4 → v8.0.0**
(git tag `a1991db`), **persist v11.5.0 → v11.6.0**, verify family v8.3.0
(unchanged), Leviculum v0.8.1+ciris.1 (unchanged).
**Tracks / closes:** CIRISServer#128 (this is the whole issue: edge/persist
co-bump + removed-type migration + mesh control-plane 0x0000_*).
**Coordinated cut:** CIRISEdge#241 (v8.0.0), CIRISRegistry#130 /
`manifests/WIRE_VOCABULARY.md` v1.0.1, CIRISAgent#904 (agent-side co-migration
of the inline-text + accord-events emitter), CIRISConformance#53 (cohab gauntlet).
**Supersedes:** `FSD/RNS_CONTROL_RELAY.md` §4.2 (the "one edge dependency" —
`MessageType::NodeControlRequest` — evaporates; the relay now rides the generic
`OpaqueRequest` surface edge already ships) and
`FSD/MESH_SEED_RUNBOOK_POST_DELEGATION.md` §2 "Option A" (HTTP announce/peer
proxies → replaced by relay calls, §7 below).
**Ships as ONE release with the delegation-constraints work** already merged-pending
on `feat/delegation-constraints-0.5.72` — the relay endpoint is gated on the
`mesh_relay` `CapabilityVerb` those constraints introduced (`src/auth/gate.rs:51`),
and both halves are required to seed the A↔B mesh over RNS.

---

## 1. Summary, goals, non-goals

### 1.1 Summary

CIRISEdge v8.0.0 is a coordinated substrate MAJOR that **removes** three
`MessageType` variants CIRISServer's world touched (`AccordEventsBatch`,
`FederationKeyDirectoryQuery`, `InlineText*`) and replaces them with **three
generic opaque envelopes** carrying a `kind: u32` from a per-repo reserved range
(`WIRE_VOCABULARY.md` v1.0.1 §3.1). Edge now carries `payload` as opaque bytes —
"reach, not meaning" — and the *app* owns inner canonicalization. `SchemaVersion::V2_0_0`
becomes the sole-allowlisted strict default, and `WIRE_VOCABULARY_HASH =
c6bd6aa4…` is pinned as a cohabitation build-gate.

`#128` bundles four things, in strict order:

- **A.** Co-bump edge 7.4.4→8.0.0 (×3 pins) + persist 11.5.0→11.6.0 (×3 pins),
  absorb the `SchemaVersion` strict flip, pin the vocabulary hash.
- **B.** Migrate our **only real removed-type usage** — the lens-core
  `Handler<AccordEventsBatch>` trace-ingest-over-Reticulum path (3 files) — to
  `register_opaque_subscriber` on the CIRISPersist `0x0005_*` kind, decoding the
  `BatchEnvelope` from `payload` bytes; the HTTP sibling (`src/ingest_http.rs`)
  is unaffected (it already works on raw bytes).
- **C.** `FederationKeyDirectoryQuery` (`0x0003_*`) — **N/A on our side**
  (grep-confirmed: zero references, code or docs).
- **D.** Build the **mesh control-plane relay** (`0x0000_*`, CIRISServer's range),
  which is `FSD/RNS_CONTROL_RELAY.md` rebuilt on `OpaqueRequest`/`OpaqueResponse` —
  no upstream edge change required.

### 1.2 Goals

1. Cohabit cleanly on the v8.0.0 substrate: compile-green, cohab-hash-green,
   all suites green, no behavioral regression on the HTTP ingest path.
2. Preserve **verify-before-persist** for trace ingest across the wire change.
3. Ship the mesh control-plane relay (`POST /v1/mesh/relay`) so an owner can
   administer an IP-less owned node by `key_id` over RNS, authorized by the owner
   fed-ID signature, gated on the `mesh_relay` delegated capability.
4. Seed Node A ↔ Node B entirely over the relay (announce, key-record fetch, peer),
   superseding the runbook's HTTP Option A.

### 1.3 Non-goals

- No new **Tier-1** wire vocabulary. Everything we add is Tier-2 opaque `kind`s in
  CIRISServer's own `0x0000_*` range — zero-ceremony Private Use (§3.1 spec).
- No re-implementation of canonicalization in edge or in our transport tier — the
  `BatchEnvelope` schema + its canonicalization already live in
  `ciris_persist::schema::BatchEnvelope` (steward = CIRISPersist), exactly the
  "app owns meaning" posture (`WIRE_VOCABULARY.md` §3.3 normative note).
- No RNS in the KMP client; no open proxy; no new mesh identity class — all
  carried forward unchanged from `RNS_CONTROL_RELAY.md` §1.3.
- No adoption of persist v11.6.0's `directory_ops_capsule` (edge deferred that to
  v8.1.0 / CIRISEdge#245 — §9.3).

---

## 2. Breaking-change impact table

Every removed edge type, where we touch it, and its opaque replacement. Verified
against a full-tree grep of `crates/` + `src/`.

| Removed edge type | Our usage (file:line) | Kind of usage | Replacement | Owner range |
|---|---|---|---|---|
| `AccordEventsBatch` / `AccordEventsResponse` | `crates/ciris-lens-core/src/role/handler.rs:35,58-97` | `impl Handler<AccordEventsBatch> for LensCoreHandler` (receive→verify→persist, returns counts as ACK) | `OpaqueEvent` via `register_opaque_subscriber(0x0005_*)` + a drain loop calling `receive_and_persist` | CIRISPersist `0x0005_*` |
| `AccordEventsBatch` | `crates/ciris-lens-core/src/role/relay.rs:22,112,139` | `edge.register_handler::<AccordEventsBatch,_>` (HTTP relay + `attach_handler`) | `edge.register_opaque_subscriber(kind)` + spawn drain task | `0x0005_*` |
| `AccordEventsBatch` | `crates/ciris-lens-core/src/role/ret_relay.rs:52,192` | `edge.register_handler::<AccordEventsBatch,_>` (RET relay) | same as above | `0x0005_*` |
| `AccordEventsBatch` | `src/ingest_http.rs` (doc comments only, code uses raw `Bytes`→`receive_and_persist`) | **none — HTTP path is type-free** | no code change; refresh comments | — |
| `AccordEventsBatch` | `src/lib.rs:148`, `src/compose.rs:651`, `crates/…/role/node.rs:12,962`, `role/mod.rs:10,22`, `ffi/pyo3.rs:445,447,472` | **doc comments only** | update prose to "opaque trace-batch event" | — |
| `FederationKeyDirectoryQuery` | *(none — grep-confirmed absent in code AND docs)* | — | N/A | CIRISRegistry `0x0003_*` |
| `InlineText*` / `speak_pipeline` | *(none — agent-tier; CIRISAgent#904)* | — | N/A (CIRISAgent `0x0004_0001`) | — |
| `MessageType::NodeControlRequest` (never shipped; `RNS_CONTROL_RELAY.md` §4.2 planned it upstream) | — | planned edge dep | **eliminated** — relay rides `OpaqueRequest` kind `0x0000_0001` (§6) | CIRISServer `0x0000_*` |

**Net:** exactly **three source files** carry real removed-type code
(`handler.rs`, `relay.rs`, `ret_relay.rs`); everything else is comments or the
new relay. No outbound `edge.send::<AccordEventsBatch>` exists (the lens-core
`send_durable` references in `capture/client.rs` / `ceg_egress.rs` are documented
future surface + the unrelated `LensStatePublication` gossip type — grep found
zero live `.send_durable`/`.send::<>` call sites).

---

## 3. Edge v8.0.0 opaque API (the surface we build against)

From the v8.0.0 checkout (`git -C /home/emoore/CIRISEdge checkout v8.0.0`):

**Body structs** — `src/messages/mod.rs:444/456/471`, `MessageType` fieldless at
`:42-63`:

```rust
OpaqueRequest  { kind: u32, payload: Vec<u8> }              // Delivery::Ephemeral, Response = OpaqueResponse
OpaqueResponse { kind: u32, status: u16, payload: Vec<u8> } // Delivery::Ephemeral, no Response
OpaqueEvent    { kind: u32, payload: Vec<u8> }              // Delivery::Durable{requires_ack:false}, no Response
```

**Methods on `Edge`** (`src/edge.rs`):

| Method | Sig | Line | Notes |
|---|---|---|---|
| `send_opaque_request` | `(&self, dest_key_id:&str, kind:u32, payload:Vec<u8>, timeout_ms:u64) -> Result<OpaqueResponse, EdgeError>` | 2076 | Blocks awaiting the correlated response; keyed on request `body_sha256` → response `in_reply_to`. |
| `send_opaque_event` | `(&self, dest_key_id:&str, kind:u32, payload:Vec<u8>) -> Result<DurableHandle, EdgeError>` | 2142 | Durable fire-and-forget; enqueues (needs `Edge::run`'s outbound dispatcher to transmit). |
| `register_opaque_handler` | `(&self, kind:u32, f: Fn(String, Vec<u8>) -> OpaqueResponse + Send + Sync + 'static)` | 2603 | **Synchronous** closure; `f(sender_key_id, payload)`. Re-register replaces. |
| `register_opaque_subscriber` | `(&self, kind:u32) -> (u64, mpsc::UnboundedReceiver<(String,u32,Vec<u8>)>)` | 2561 | Fan-out feed for `OpaqueEvent`; drain in your own async task. |
| `spawn_background_listeners` | — | 3084 | Drives inbound dispatch (listen + fan-out) — the ingest/relay-responder leg. |

**Load-bearing behaviors** (proven by `tests/opaque_conformance.rs`, 9/9):

- **Unknown `kind` → sender-visible `OpaqueResponse{status:501}`**, synthesized in
  `dispatch_inbound` (`edge.rs:4840-4844`), never a silent drop. Our relay
  responder inherits this for free: any un-allow-listed relay reaches a registered
  handler which returns its own status; an unregistered `kind` 501s.
- **ACK-matching fix:** the opaque request handler closure is invoked **inline in
  the async `dispatch_inbound`** at `edge.rs:4833` (`h(signing_key_id, payload)`),
  and `OpaqueResponse` is now excluded from the pre-opaque ACK-matching block (it
  carries `in_reply_to` as its own correlation token) — this is the fix that
  un-deadlocks `send_opaque_request`'s round-trip (the #240 response leg).
- **`SchemaVersion::default() == V2_0_0`** (strict) — the sole allowlisted version;
  a v7.x peer (V1 default) and a v8.0.0 peer **cannot interop** (§9 risk).

> **⚠ Sync-closure constraint (design-critical).** `register_opaque_handler`
> takes a **synchronous** `Fn(String,Vec<u8>) -> OpaqueResponse`, but it is
> called on a tokio worker inside `dispatch_inbound` (async). Our relay responder
> (§6) must do async work (hybrid verify + `tower::oneshot` into the axum router).
> Bridge with `tokio::task::block_in_place(|| Handle::current().block_on(async {…}))`
> — which **requires the multi-thread runtime flavor** (the edge listeners use
> `new_multi_thread`, confirmed in the conformance harness `edge_runtime()`), and
> blocks that inbound-dispatch task for the request's duration (acceptable at
> owner-op cadence; alternative: hand off over a channel to a dedicated worker and
> block on a `std`/`oneshot` recv). The `OpaqueEvent` **subscriber** path (§5) has
> no such constraint — you own the async drain loop.

---

## 4. Phase A — substrate co-bump

### 4.1 Exact pin edits

**edge v7.4.4 → v8.0.0** (3 pins; the three-pin rule, MEMORY 0.5.60 — two
`ciris_edge` versions resolving is the `expected &Edge found &Edge` trap):

| File | Line | Current | Change |
|---|---|---|---|
| `Cargo.toml` | 127 | `ciris-edge … tag = "v7.4.4", features = ["transport-reticulum","transport-http","transport-packet-radio"]` | `tag = "v8.0.0"` |
| `Cargo.toml` | 256 | `ciris-edge … tag = "v7.4.4", features = ["codec-fountain"]` | `tag = "v8.0.0"` |
| `crates/ciris-lens-core/Cargo.toml` | 29 | `ciris-edge … tag = "v7.4.4", version = "7", features = ["transport-http","transport-reticulum"]` | `tag = "v8.0.0", version = "8"` |

**persist v11.5.0 → v11.6.0** (3 pins; `version = "11"` unchanged — same major):

| File | Line | Current | Change |
|---|---|---|---|
| `Cargo.toml` | 126 | `ciris-persist … tag = "v11.5.0"` (sqlite features) | `tag = "v11.6.0"` |
| `Cargo.toml` | 203 | `ciris-persist … tag = "v11.5.0"` (postgres features) | `tag = "v11.6.0"` |
| `crates/ciris-lens-core/Cargo.toml` | 28 | `ciris-persist … tag = "v11.5.0", version = "11"` | `tag = "v11.6.0"` (version stays `"11"`) |

verify family stays v8.3.0 (`Cargo.toml:136`, `:44` lens-core) — no touch.

### 4.2 What breaks at compile time and why

1. **`use ciris_edge::{AccordEventsBatch, AccordEventsResponse, …}`** in
   `handler.rs:35`, `relay.rs:22`, `ret_relay.rs:52` → **unresolved import** (types
   removed). This forces Phase B. Comment-only references (§2) don't break the
   build but must be refreshed to avoid stale rustdoc intra-doc-link failures
   where `[`AccordEventsBatch`]: ciris_edge::AccordEventsBatch` is a doc link
   (`role/mod.rs:22`) — those `[…]` links to a removed path are a `broken_intra_doc_links`
   error under our doc-lint. Convert to plain text or link the new opaque surface.
2. **`SchemaVersion` strict flip:** CIRISServer constructs **no** `EdgeEnvelope`
   directly (grep: zero `SchemaVersion` references) — edge stamps V2 internally in
   `send_opaque_*`/`send`. So the flip is transparent *at compile time*; its bite
   is **wire-compat** (§9): every peer in a mesh must be on v8.0.0 simultaneously.
3. **persist 11.6.0** is a drop-in floor bump — no API our code calls changed
   (§9.3). The rebuild simply re-resolves the substrate lockstep.

### 4.3 The WIRE_VOCABULARY_HASH cohabitation gate

Edge holds `pub const WIRE_VOCABULARY_HASH` (`CIRISEdge/src/lib.rs:109`), and the
authoritative value is `c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c`
(`WIRE_VOCABULARY.md` v1.0.1; asserted in `CIRISEdge/tests/opaque_conformance.rs:45`).
CIRISServer today pins **no** hash of its own. Per spec §4/§5, every ratifying repo
pins it. Add a **one-line assertion test** (e.g. in `tests/` or a `#[cfg(test)]`
module in `src/lib.rs`):

```rust
// #128: cohabitation build-gate — our transitive edge MUST carry the
// registry-ratified vocabulary hash (WIRE_VOCABULARY.md v1.0.1).
const WIRE_VOCABULARY_HASH_HEX: &str =
    "c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c";
assert_eq!(hex::encode(ciris_edge::WIRE_VOCABULARY_HASH), WIRE_VOCABULARY_HASH_HEX);
```

This is our assertion side of the CIRISConformance#53 gauntlet — a drift (e.g. a
stray edge minor that re-hashes the vocab) fails our build, not just conformance's.

---

## 5. Phase B — `AccordEventsBatch` → opaque `OpaqueEvent` `0x0005_*`

### 5.1 The migration shape

Per `WIRE_VOCABULARY.md` §3.3, `AccordEventsBatch` migrates to **`OpaqueEvent`**
(durable fire-and-forget) in the **CIRISPersist `0x0005_*`** range. The steward
(CIRISPersist) owns the schema+canonicalization — which it already does:
`ciris_persist::schema::BatchEnvelope`, decoded by `Engine::receive_and_persist`.
So the payload bytes ARE the JSON `BatchEnvelope` (exactly what
`src/ingest_http.rs` already posts). **We change only the receive plumbing.**

**Kind allocation (coordination point).** `0x0005_*` is CIRISPersist's range;
CIRISServer *consumes* the kind CIRISPersist publishes. Proposed:
`0x0005_0001 = accord-events trace batch (BatchEnvelope over OpaqueEvent)`.
Confirm/adopt the exact value from CIRISPersist's `WIRE_VOCABULARY_KINDS.md`
before cutting; define it once as a shared const (e.g.
`crates/ciris-lens-core/src/role/mod.rs::ACCORD_EVENTS_KIND: u32 = 0x0005_0001`).
It MUST match the CIRISAgent#904 emitter byte-for-byte.

### 5.2 Receiver rewrite (`handler.rs` + `relay.rs` + `ret_relay.rs`)

Replace `impl Handler<AccordEventsBatch>` + `register_handler::<AccordEventsBatch,_>`
with a subscriber drain loop. `LensCoreHandler` becomes a plain struct holding
`Arc<Engine>` with an `async fn spawn_ingest(edge:&Edge, engine, kind) -> JoinHandle`:

```rust
// crates/ciris-lens-core/src/role/handler.rs (sketch — not production code)
pub fn spawn_accord_ingest(edge: &Edge, engine: Arc<Engine>, kind: u32) -> JoinHandle<()> {
    let (_sub_id, mut rx) = edge.register_opaque_subscriber(kind); // (u64, mpsc::UnboundedReceiver<(String,u32,Vec<u8>)>)
    tokio::spawn(async move {
        while let Some((sender_key_id, _kind, payload)) = rx.recv().await {
            // payload IS the BatchEnvelope JSON — same call ingest_http + the old
            // Handler both made; VerifyMode::Full inside receive_and_persist runs
            // the CEG hybrid-signature gate BEFORE any row lands (verify-before-persist).
            match engine.receive_and_persist(&payload, &NullScrubber).await {
                Ok(s)  => tracing::debug!(peer=%sender_key_id, events=s.trace_events_inserted, "opaque ingest persisted"),
                Err(e) => tracing::warn!(peer=%sender_key_id, error=%e, "opaque ingest rejected"),
            }
        }
    })
}
```

- `role/relay.rs:112,139` (`LensCore::relay` + `attach_handler`) and
  `role/ret_relay.rs:192` swap `edge.register_handler::<AccordEventsBatch,_>(…)` for
  `spawn_accord_ingest(&edge, engine, ACCORD_EVENTS_KIND)`. `attach_handler` returns
  the `JoinHandle` (or stores it on the handle) so shutdown can abort the drain.
- The `serde_json::to_vec(&msg.0)` re-serialize in the old handler
  (`handler.rs:69`) is **gone** — the subscriber already hands us the wire bytes,
  a strict improvement (no round-trip).
- `RelayError`/`RetRelayHandle`/`RelayHandle` are unchanged.

### 5.3 Semantic change: the ACK is lost — call it out

The old `Handler<AccordEventsBatch>` returned `AccordEventsResponse{counts}` as the
**requires_ack** response (`handler.rs:91`). `OpaqueEvent` is
`Delivery::Durable{requires_ack:false}` — **there is no response leg**. So a
**mesh** emitter no longer receives insert-counts back. This is the
delivery-expressiveness downgrade the spec explicitly accepts for telemetry
(`WIRE_VOCABULARY.md` §3 limit + §3.3: "Trace/telemetry; … edge is agnostic").
Consequences:
- **HTTP path is unaffected** — `src/ingest_http.rs` still returns `IngestOk{counts}`
  to its HTTP caller synchronously (it never used the mesh ACK).
- The mesh emitter (CIRISAgent#904) must not block on a receipt; the `DurableHandle`
  from `send_opaque_event` observes only edge-queue outcome, not persist counts.
- If a completion receipt is ever needed, model it as a separate `OpaqueEvent`
  counts-receipt (§3 limit) — out of scope here.

### 5.4 The "stable-frozen" contract note + peer wire-compat

`PUBLIC_SCHEMA_CONTRACT.md` marks the trace-ingest-over-Reticulum path
**stable-frozen**. This migration **is** a break of that frozen wire (new
discriminator `OpaqueEvent`+`kind`, no ACK). It is sanctioned because it is part
of the **coordinated v8.0.0 substrate cut** governed by the vocabulary covenant
(§5 of `WIRE_VOCABULARY.md` — unanimous hash-commit). Requirements:
- **Lockstep with CIRISAgent#904:** the emitter and our receiver must flip to the
  same `kind` in the same cut. A v7 emitter (typed `AccordEventsBatch`) → a v8
  receiver is simply not on the wire vocabulary → dropped/501-class; a v8 emitter →
  v7 receiver likewise. No mixed-version trace ingest.
- Update `PUBLIC_SCHEMA_CONTRACT.md`: move the accord-events row from
  "stable-frozen typed" to "Tier-2 opaque `0x0005_0001`, schema owned by
  CIRISPersist `BatchEnvelope`," noting the v8.0.0 coordinated break + ACK loss.

---

## 6. Phase D — mesh control-plane relay (`0x0000_*`)

`FSD/RNS_CONTROL_RELAY.md` rebuilt on the generic opaque surface. **The entire
"one edge dependency" (that FSD §4.2 + §14.1) is eliminated** — edge 8.0 ships
`OpaqueRequest`/`send_opaque_request`/`register_opaque_handler`, and edge holds no
Tier-2 range by design (`WIRE_VOCABULARY.md` §3.1: "CIRISServer's range, above").
Everything else in `RNS_CONTROL_RELAY.md` (§2 current state, §5.3 allow-list, §6
local endpoint, §7 reachability, §9 auth model, §10 security) **stands unchanged**;
this section rewrites only §3/§4/§5.1 (the wire binding).

### 6.1 Kind allocation

CIRISServer owns `0x0000_0000..=0x0000_FFFF`. Allocate:
`0x0000_0001 = mesh control-plane relay` (request/response over
`OpaqueRequest`/`OpaqueResponse`). Publish it in a new
`WIRE_VOCABULARY_KINDS.md` at the CIRISServer repo root (spec §3.1 requires each
steward publish its `kind → semantics`). Reserve `0x0000_0002+` for future control
ops (e.g. a health probe).

### 6.2 The relay bodies stay in CIRISServer (app owns meaning)

`NodeControlRequest` / `NodeControlResponse` (the `RNS_CONTROL_RELAY.md` §4.3
structs — `{target_key_id, method, path, body, nonce, issued_at, signer_key_id,
sig_ed25519, sig_ml_dsa_65}` / `{status, body, content_type}`) are **CIRISServer
types**, serialized to JSON and carried as the opaque `payload`. Edge never sees
them — no `Message` impl, no `MessageType` variant, no edge `canonical_bytes`. The
canonical **inner** signing payload (`{target_key_id, method, path, sha256(body),
nonce, issued_at}`, hybrid-signed by the owner fed-ID) is the app's own
canonicalization, honoring the §3.3 normative rule.

### 6.3 C1 — local relay endpoint (`POST /v1/mesh/relay`)

> **Status (0.5.72):** the C1 **initiator send leg is now WIRED**. edge#249
> (edge v8.2.0) changed `Edge::run` to `run(self: Arc<Self>)`, so `compose.rs`
> retains a live `Arc<Edge>` across `run()` and wires
> `mesh_relay::edge_mesh_requester_with_loopback` — `target==self` short-circuits
> to the in-process responder, every other owned target sends for real over RNS
> via `Edge::send_opaque_request`. The interim `local_only_requester` stub
> (which 502'd cross-node sends while `run(self)` consumed the Edge) is retired.

`src/mesh_relay.rs`, mounted on the **loopback control listener** in `compose.rs`.
Unchanged from `RNS_CONTROL_RELAY.md` §6 except the send call:

1. **Auth gate** — `require_owner`-style bearer (SYSTEM_ADMIN + `FullAccess`, incl.
   the `owner:act-on-behalf` dgrant), **then** `authorize_delegated(caller,
   CapabilityVerb::MeshRelay)` (`src/auth/gate.rs:110,51`). `MeshRelay` is
   **delegatable** (not on the never-list `delegate|wipe|accord_halt`,
   `gate.rs:80-85`), so a delegation grant scoped to `mesh_relay` authorizes it,
   and a grant that omits/denies `mesh_relay` is refused with the standard
   `DenyReason` 403. This is the wiring the delegation-constraints branch added the
   verb for.
2. **Ownership scoping** — assert `target_key_id ∈ ownership::nodes_stewarded_by(engine,
   owner)` (`bootstrap.rs:1004`). `target == self` short-circuits to the in-process
   router (no RNS).
3. **Sign** — `resolve_user_signer(engine, FedIdUse::OwnerSession, user_key_id,
   seed_dir)` (`src/compose.rs:852`); hybrid-sign the canonical inner payload.
4. **Send** — the one changed line:
   ```rust
   let resp: OpaqueResponse = tokio::time::timeout(
       relay_timeout,
       edge.send_opaque_request(&target_key_id, 0x0000_0001,
                                serde_json::to_vec(&node_control_req)?, relay_timeout_ms),
   ).await??;
   ```
5. **Return** — decode `NodeControlResponse` from `resp.payload`; map
   `resp.status`/body/content-type onto the HTTP response verbatim. Map
   `EdgeError::Unreachable` → `502 mesh_target_unreachable`, timeout → `504`,
   `resp.status == 501` (no responder handler / node not relay-capable) →
   `502 mesh_relay_unsupported`.

### 6.4 C3 — RNS control responder (`register_opaque_handler` on `0x0000_0001`)

`src/mesh_control.rs`. Registered on the shared Edge in `compose.rs` **before
`edge.run()`**, alongside the (now opaque) ingest subscriber. Gated: register only
when the node is owner-bound (there is an owner to authorize against).

```rust
// src/compose.rs — near where the ingest subscriber is spawned
let engine2 = engine.clone(); let self_key = cfg.key_id.clone();
let user_inputs = (cfg.user_key_id.clone(), cfg.user_seed_dir.clone());
edge.register_opaque_handler(0x0000_0001, move |sender_key_id, payload| {
    // ⚠ sync closure on an async worker (§3): bridge to async.
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(
            mesh_control::handle(&engine2, &self_key, &user_inputs, sender_key_id, payload)
        )
    })
});
```

`mesh_control::handle(...) -> OpaqueResponse` mirrors `self_login`'s
verify→authorize→dispatch shape (`RNS_CONTROL_RELAY.md` §5.2), returning an
`OpaqueResponse{kind:0x0000_0001, status, payload:NodeControlResponse}`:

1. Decode `NodeControlRequest` from `payload` (a decode failure → `OpaqueResponse
   {status:400}`).
2. **Verify** the inner hybrid signature over the reconstructed canonical payload
   via the header-free core factored from `verify_request` (`src/auth/verify.rs:48` →
   new `verify_signed_payload(...)`, `RNS_CONTROL_RELAY.md` §13 item 5), under
   `HybridPolicy::Strict`. `sender_key_id` (the verified **transport** signer — the
   remote's own node key) is available from the closure arg for logging; the
   **authorization** principal is the inner owner signature, not the transport one.
3. **Authorize:** resolve this node's owner (`ownership::is_steward_bound`,
   `bootstrap.rs:1002`) and assert `verify::signer_acts_for(engine, signer_key_id,
   owner_key_id)` (`src/auth/verify.rs:84`). Fail → `status:403`.
4. **Replay/freshness:** `issued_at` within ±120 s; `(signer_key_id, nonce)` not in
   the bounded LRU. Fail → `status:401`/`409`.
5. **Target check:** `target_key_id == self_key`. Fail → `status:421`.
6. **Allow-list:** `(method, path) ∈` the closed `const &[(Method,&str)]`
   (`RNS_CONTROL_RELAY.md` §5.3 — owned-nodes, self-key-record, federation
   announce/peering/peers, config reads, identity/status). Not listed →
   `status:403` (no dispatch). **Never-relayable** stays enforced: wipe
   (`/v1/system/data/*`), claim (`/v1/setup/root`), fed-ID mint
   (`/v1/self/identity`), `/login`, large reads.
7. **Dispatch:** build an `http::Request` from `{method,path,body}` + a synthetic
   owner `SessionCaller` extension, and drive the **shared v1 router** via
   `tower::ServiceExt::oneshot` (§6.5). Collect `{status, content_type, body}` →
   `NodeControlResponse` → `OpaqueResponse`.

Unknown-kind (a peer hitting `0x0000_0001` on a node with no responder registered)
→ edge synthesizes `501` (`edge.rs:4840`) → C1 maps to `502 mesh_relay_unsupported`.
No silent drop.

### 6.5 Shared router factory (unchanged from §5.4)

Build the v1 router **once** in a factory `compose.rs` calls for both the HTTP
listener and C3, so RNS and HTTP execute the identical handler code. The only
difference is auth injection: HTTP gates on a bearer; over RNS the caller is
owner-verified by signature, so C3 injects a synthetic owner `SessionCaller`
request-extension. Factor `require_owner` to accept "caller already established."

---

## 7. Phase E — seed A ↔ B over the relay (supersedes runbook Option A)

Concrete sequence, each step a `POST /v1/mesh/relay` on the operator's **local**
node, authorized by a delegation grant **constrained to `{announce, peer,
mesh_relay}`** (the delegation-constraints allow-list, `gate.rs:142`) — proving
constraints + relay ship together:

1. `relay {target:A, GET /v1/federation/self-key-record}` → cache A's key record.
2. `relay {target:B, GET /v1/federation/self-key-record}` → cache B's key record.
3. `relay {target:A, POST /v1/federation/announce}` → A promotes its owner-binding
   to FEDERATION + sets `net.announce_ownership=true` (verb `announce`).
4. `relay {target:B, POST /v1/federation/announce}` → same on B.
5. `relay {target:A, POST /v1/federation/peering {peer:B, key_record:<B's>}}` and
   `relay {target:B, POST /v1/federation/peering {peer:A, key_record:<A's>}}` →
   bilateral `consent:replication` (verb `peer`).
6. `relay {target:A|B, GET /v1/federation/peers}` → assert the bilateral edge
   landed on both.

Each relayed op runs locally on the target, authorized by the owner fed-ID
signature — **no password, no route to the target's IP** (the exact wall
`MESH_SEED_RUNBOOK_POST_DELEGATION.md` §"The one real gap" hit). The runbook's §2
"Option A" HTTP `announce-remote`/`peer-remote` proxies are struck; the runbook
gets a pointer to this §7.

---

## 8. Test / conformance plan

**Phase A (gate):**
- `wire_vocabulary_hash_pinned` — `hex::encode(ciris_edge::WIRE_VOCABULARY_HASH) ==
  c6bd6aa4…` (§4.3). Our side of CIRISConformance#53.
- Build-green on the full workspace (both persist feature sets: sqlite + postgres).

**Phase B (accord-events opaque):**
- Unit: `spawn_accord_ingest` drains a synthetic `(sender, kind, BatchEnvelope-json)`
  and persists; a tampered/unsigned batch is **rejected** by `receive_and_persist`
  (verify-before-persist preserved) and nothing lands.
- Regression: `src/ingest_http.rs` tests unchanged and green (HTTP path untouched).
- **Two-node proof:** boot two same-host edges (the `opaque_conformance.rs` loopback
  harness is the reference), emitter `send_opaque_event(recv, ACCORD_EVENTS_KIND,
  batch)`, assert the subscriber persists it. Mirrors CIRISAgent#904's emitter side —
  the byte-for-byte `kind` + `BatchEnvelope` interop check.

**Phase D (relay):**
- Unit: `NodeControlRequest/Response` serde round-trip; canonical inner-payload
  determinism; owner-sig verify pass / tamper-fail / wrong-signer-fail; allow-list
  reject pre-dispatch; wipe/claim absent from the const; replay (same nonce → 2nd
  rejected); C1 ownership scoping (non-owned target → 403); `target==self`
  short-circuit (no `send_opaque_request`).
- **Two-instance same-host integration:** two ciris-server processes, one owner,
  mutual RNS rooting. Drive `relay {target:B, POST /v1/federation/announce}` →
  assert B's config/CEG changed + client sees 200. Drive the full §7 A↔B peering →
  assert bilateral `consent:replication`. `GET /v1/setup/owned-nodes` relayed ==
  target's local HTTP response byte-for-byte (shared-router guarantee).
- **501-on-unknown-kind:** `send_opaque_request(target, 0x9999_9999, …)` (or
  `0x0000_0001` to a node with no responder) → `resp.status == 501` → C1 maps to
  `502 mesh_relay_unsupported`, never a hang (proves the sender-visible 501 path
  end-to-end on our types).
- **Reachability failure:** tear down B → relay to B → `502 mesh_target_unreachable`
  within the timeout.

---

## 9. Sequencing & risk

### 9.1 Strict phase order

**A → (B, C) → D → E.** A must compile-green + cohab-hash-green before B/C (the
removed-type imports won't resolve until the pins move). B/C (receive-side) before
D (the relay reuses the same `compose.rs` edge-registration seam). D before E
(E is the integration exercise of D). Do **not** interleave the relay build with
the pin bump — a half-migrated tree won't compile.

### 9.2 Frozen-contract / peer-coordination risk (highest)

The accord-events wire is `PUBLIC_SCHEMA_CONTRACT.md`-frozen and the `SchemaVersion`
strict flip means **no mixed-version mesh**. Mitigation: this is a *coordinated
cut* — ship in lockstep with CIRISAgent#904 (emitter) and the covenant's unanimous
hash-commit (`WIRE_VOCABULARY.md` §4). Field ordering: co-bump every node the owner
runs in one release wave; a straggler v7 node silently stops ingesting/relaying
(fail-honest, not corrupt). Document in the release notes + `PUBLIC_SCHEMA_CONTRACT.md`.

### 9.3 persist v11.6.0 `directory_ops_capsule` — confirmed non-blocking

v11.6.0 makes `directory_ops_capsule` (CIRISPersist#322) *available*, but edge
**deferred full adoption to v8.1.0** (CIRISEdge#245 — the security-critical
`verify_hybrid` path needs a persist `VerifyHybrid` op first). CIRISServer touches
none of it (grep: zero references); for us v11.6.0 is a drop-in floor bump. No
action, no block. Re-confirm at the v8.1.0 co-bump.

### 9.4 Sync-closure / runtime-flavor risk

The relay responder's `block_in_place` (§3, §6.4) panics on a current-thread
runtime. The edge listeners are multi-thread (conformance-confirmed), but assert it
in the integration test (a single-threaded misconfig would surface as a panic under
load, not at compile). Fallback: channel hand-off to a dedicated worker + block on
recv.

### 9.5 Rollback

Purely a pin revert (edge v8.0.0→v7.4.4, persist v11.6.0→v11.5.0) + `git revert` of
the B/D source. No persisted-state migration (owner-bindings, directory, trace rows
are schema-stable across the bump). A rolled-back node simply rejoins the v7 wire —
but note it then **cannot** talk to any node already cut to v8 (strict flip), so
rollback is all-or-nothing across the owner's cohort, same as §9.2.

---

## 10. File-by-file touch list

**Phase A (pins + gate):**
- `Cargo.toml` L126, L127, L203, L256 — persist ×2 → v11.6.0, edge ×2 → v8.0.0.
- `crates/ciris-lens-core/Cargo.toml` L28 (persist→v11.6.0), L29 (edge→v8.0.0 +
  `version="8"`).
- `src/lib.rs` (or `tests/wire_vocab_hash.rs`) — add the `WIRE_VOCABULARY_HASH`
  assertion (§4.3).

**Phase B (accord-events → opaque `0x0005_0001`):**
- `crates/ciris-lens-core/src/role/handler.rs` — drop `impl Handler<AccordEventsBatch>`;
  add `spawn_accord_ingest(edge, engine, kind)` subscriber drain (§5.2).
- `crates/ciris-lens-core/src/role/relay.rs` L22,112,139 — remove the edge type
  import; `register_handler` → `spawn_accord_ingest`; carry the `JoinHandle`.
- `crates/ciris-lens-core/src/role/ret_relay.rs` L52,192 — same swap.
- `crates/ciris-lens-core/src/role/mod.rs` — add `ACCORD_EVENTS_KIND` const; fix the
  `[`AccordEventsBatch`]` intra-doc link (L22) + prose (L10).
- `src/ingest_http.rs`, `src/lib.rs:148`, `src/compose.rs:651`,
  `crates/…/role/node.rs`, `crates/…/ffi/pyo3.rs` — comment refresh only.
- `PUBLIC_SCHEMA_CONTRACT.md` — reclassify the accord-events row (§5.4).

**Phase C:** none (N/A).

**Phase D (relay):**
- `WIRE_VOCABULARY_KINDS.md` (new, repo root) — document `0x0000_0001`.
- `crates/ciris-lens-core/src/…/mesh_control.rs` **or** `src/mesh_control.rs` (new) —
  `NodeControlRequest/Response` structs + `mesh_control::handle(...) -> OpaqueResponse`
  (verify/authz/replay/allow-list/oneshot-dispatch).
- `src/mesh_relay.rs` (new) — `POST /v1/mesh/relay`: owner+`MeshRelay` gate,
  owned-nodes scoping, `resolve_user_signer`, `send_opaque_request(…,0x0000_0001,…)`,
  timeout, response mapping.
- `src/auth/verify.rs` — factor header-free `verify_signed_payload(...)` core out of
  `verify_request` (`:48`).
- `src/compose.rs` — (a) shared v1-router factory; (b)
  `edge.register_opaque_handler(0x0000_0001, …)` near the ingest subscriber, before
  `edge.run()`; (c) mount `mesh_relay::router(...)` on the loopback control listener.
- `src/auth/gate.rs` — no change (`MeshRelay`/`Announce`/`Peer` already present,
  L43-51); the relay simply **calls** `authorize_delegated`.

**Docs:**
- `FSD/RNS_CONTROL_RELAY.md` — annotate §4.2/§14.1 superseded (no edge variant;
  rides `OpaqueRequest 0x0000_0001`).
- `FSD/MESH_SEED_RUNBOOK_POST_DELEGATION.md` — strike §2 Option A, point to §7 here.
```
