# Mesh-seed runbook — seeding the canonical mesh over the RNS relay

**Goal:** promote Node A (`ciris-canonical-1`) and Node B (`ciris-status-1`) from
self-scoped to federation-scoped, and wire the bilateral `consent:replication:v1`
peering A↔B — **entirely through the LOCAL node's API using a constrained
delegation grant**, reaching the remotes **by fed key_id over RNS**, never by
curling them directly.

**Status (2026-07-02):** the *code* is shipped. **CIRISServer 0.5.72 is live on
PyPI** (delegation constraints + edge v8.3.0 opaque wire + the two-leg RNS mesh
control-plane relay + ratified `TRACE_BATCH_KIND`). **CIRISStatus v0.3.12** (Node
B's image, repinned to 0.5.72) is tagged. The **relay is the path** — the old
HTTP "Option A / Option B" proxy dance in prior revisions of this doc is
**superseded** and removed. The remaining work is a **fleet deploy + the seed
run**, below.

---

## 0. Preconditions — ALL must hold before the seed can run

| # | Precondition | State |
|---|---|---|
| 0.1 | CIRISServer **0.5.72 live on PyPI** | ✅ done |
| 0.2 | **A, B, and lapbuntu2 are all rolled to 0.5.72** (see §1 — the relay is bilateral) | ⛔ deploy |
| 0.3 | A and B are already **owner-bound** to your fed-ID (`eric-moore-v2-portable-…`) at `cohort_scope: self` (the claim step, done earlier) | ✅ done |
| 0.4 | You issue me a **constrained delegation grant** on lapbuntu2 (§2) | ⛔ pending |

If 0.2 is not met, the relay **cannot** reach A/B — see §1.

---

## 1. THE hard precondition: the fleet must run 0.5.72 (the relay is bilateral)

The relay is a two-sided protocol. lapbuntu2 hosts `POST /v1/mesh/relay` and
*sends*; A and B must *receive* on opaque kind `0x0000_0001`, which requires **both**:

1. **Edge v8.0+ on A/B.** 0.5.70 nodes run edge v7.4.4 — which has **no**
   `OpaqueRequest`/`OpaqueResponse` message types at all; an opaque envelope is an
   unknown `MessageType` → dropped. No interop.
2. **The `MeshControlHandler`** (new in 0.5.72) registered on their edge — else an
   8.x node answers `501 unknown kind`.

So **A, B, and lapbuntu2 must all run 0.5.72** before a single announce/peer can
cross the wire. Deploy targets:

- **lapbuntu2** (the local seeding node): `pip install -U ciris-server==0.5.72`
  (or the standalone Rust binary), restart on `127.0.0.1:4243`.
- **Node A** (`ciris-canonical-1`, `108.61.242.236:4243`): 0.5.72 (ciris-server).
- **Node B** (`ciris-status-1`, `108.61.242.236:4253`): the **CIRISStatus v0.3.12**
  image (repinned to ciris-server 0.5.72 / edge 8.3 / persist 11.9.1).
- **mac**: 0.5.72 when convenient (not on the A↔B seed path, but part of the fleet).

**"Deploy" ≠ "configure directly."** Rolling the binary/image is a prerequisite,
distinct from configuring federation state — which still flows only through the
local grant over the relay (§3). Deploying software to a node is never the thing
the "don't touch the remotes directly" rule forbids.

Also note: edge v8.0's `SchemaVersion::V2` strict-flip means an 8.x and a 7.x node
can't cleanly cohabit the mesh anyway — 0.5.72 is the coordinated substrate floor
for every participant, not just a relay nicety.

---

## 2. The constrained delegation grant (the safety envelope)

On lapbuntu2, issue me a delegation grant **bounded to exactly the seed ops** — so
the AI driving the seed is cryptographically limited and can't wipe, re-delegate,
or act outside the seed:

```json
POST /v1/auth/device/delegate      // owner session
{
  "mode": "existing",              // or "create"
  "existing_key_id": "<my agent fed key_id>",
  "constraints": {
    "actions_allow": ["announce", "peer", "mesh_relay"],
    "goal": "seed the canonical mesh"
  }
}
```

I claim the offer (`POST /v1/auth/device/claim {pin}`) → `dgrant:…`. Every use
carries the `x-ciris-delegation` header, and the guard refuses anything outside
`{announce, peer, mesh_relay}` (and the server never-list: no delegate/wipe/accord).
`mesh_relay` is what gates `/v1/mesh/relay`; `announce`/`peer` gate what the relay
is allowed to invoke on A/B.

**Preflight I verify (no side effects):** `GET /v1/auth/me` → `SYSTEM_ADMIN` +
the constraint shows in the delegation; `GET /v1/setup/owned-nodes` lists A and B
under your owner fed-ID.

---

## 3. The seed — driven from `127.0.0.1:4243` over the relay

Every step is a `POST http://127.0.0.1:4243/v1/mesh/relay` with the dgrant bearer.
lapbuntu2 signs the inner request with **your fed-ID** and sends it as an
`OpaqueRequest{kind:0x0000_0001}` over **RNS to the target by key_id**; the remote
`MeshControlResponder` verifies the signature, sees the signer **is its owner**,
and dispatches into the node's own v1 router. **No password/bearer on A/B** — the
fed-ID signature *is* the auth. The relay only permits the closed set
`{announce, peering, self-key-record, owned-nodes}`.

Relay envelope: `{ "target_key_id": "<A|B key_id>", "method": "...", "path": "...", "body": {...} }`.

1. **Announce A** — `{target: A, POST /v1/federation/announce}` → A promotes its
   owner-binding `self → federation` + sets `net.announce_ownership=true`
   (Reticulum identity announce takes effect on A's **next boot**).
2. **Announce B** — same, `{target: B}`.
3. **Fetch key records** — `{target: A, GET /v1/federation/self-key-record}` and
   `{target: B, …}` (public; also fetchable directly). Needed for peering.
4. **Peer A→B** — `{target: A, POST /v1/federation/peering, body: {peer_key_id: B,
   attestation_prefixes: ["capacity:", "<trace prefix>"]}}`. The relay's gateway
   enrichment injects B's fetched key record; A emits its directed
   `consent:replication:v1` grant scoped to B, **covering the trace prefix** so the
   `ReplicationRuntime` replicates traces (not just `capacity:` scores).
5. **Peer B→A** — the reverse, `{target: B, peer_key_id: A}`.

---

## 4. Post-conditions I verify (the runbook is done when these hold)

- A's owner-binding `delegates_to(owner→A)` is now `cohort_scope: federation`; same
  for B. (I flag that A and B need a **restart** for the Reticulum identity announce
  to actually carry the attestation on the wire.)
- `consent:replication:v1` grants exist **both directions**; `GET
  /v1/federation/peers` on each (over the relay) shows the other, and each grant's
  `attestation_prefixes` covers traces.
- **Trace RNS-sync A→B:** a trace ingested on A reaches B's corpus via the
  `ReplicationRuntime` anti-entropy (the consent topology drives it). This is the
  payoff the TDD gate (`tests/mesh_seed_e2e.rs`) asserts at the CEG level.

---

## 5. What I will NOT do

- Curl `108.61.242.236` directly with improvised requests — everything goes through
  `127.0.0.1:4243` and the relay.
- Touch your key material / seed files to "inspect."
- Announce/peer anything you didn't ask for (announce is opt-in; the grant is
  bounded to announce/peer/mesh_relay).
- Act outside the constrained grant — the guard enforces it, and I honor it.

---

## 6. Readiness at a glance

| Gate | State |
|---|---|
| 0.5.72 on PyPI · relay both legs · constrained delegation · TDD gate | ✅ done |
| CIRISStatus v0.3.12 (Node B image) tagged | ✅ done (image building) |
| **Fleet rolled to 0.5.72** (lapbuntu2, A, B, mac) | ⛔ deploy |
| **Constrained delegation grant issued** | ⛔ your move |
| Seed run (§3) + verify (§4) | ⛔ blocked on the two above |

**We are ready to seed the moment the fleet is on 0.5.72 and you hand me a grant.**
