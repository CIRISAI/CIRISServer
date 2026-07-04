# Mesh-seed runbook — seeding the canonical mesh from the Trust Root card (0.5.80)

> ## ⚡ MODEL CHANGE (2026-07-04) — the seed is now a Trust Root card action
>
> **This runbook was the 0.5.75 delegation-grant + RNS-relay procedure** (promote
> A/B `self → federation` and wire bilateral `consent:replication:v1` over
> `POST /v1/mesh/relay` with a constrained delegation grant). **That model is
> superseded.** As of **0.5.80 (the mesh-seed release)** the canonical mesh is
> seeded by a **single accord-holder action on the Trust Root card** — the
> **add-canonical** op — not by a delegation grant, not over the relay, and not by
> promoting a node to "federation cohort scope." The delegation/relay machinery
> still exists (it is how an owner drives a *remote* node's own API), but it is no
> longer how the mesh is seeded.
>
> **Why the change:** a node is canonical because **the trust root signed off**, not
> because it announced itself into a federation cohort. The seed is therefore an
> **accord-conferred** act: an accord holder (A1, 1 of 3) scrub-signs the node to the
> baked `HUMANITY_ACCORD` anchor with a `canonical` role. persist v13's admission
> gate **refuses** the `canonical` role on any record that is not anchor-scrubbed
> (`CanonicalRoleNotAccordConferred`), so nobody can bootstrap themselves into the
> founding set. See CIRISServer#164 (the op), #163/CIRISPersist#342 (Option-A
> addressing), CIRISPersist#372 (the `canonical` role + its gate).
>
> The **legacy delegation/relay procedure is preserved verbatim in Appendix A** for
> the historical record and for the *separate* concern of driving a remote node's own
> API over RNS. The cross-references to "§2 Option A" / "the one real gap" in
> `RNS_CONTROL_RELAY.md` / `EDGE_8_0_OPAQUE_MIGRATION.md` point at Appendix A.

**Goal:** bring **`canonical-server-1`** (Node A) into the canonical trust root so it
**roots to the `HUMANITY_ACCORD` anchor**, is **marked `canonical`**, and is
**reachable by a pubkey-authenticated address** — entirely from the **Trust Root
card** with the operator's **A1 accord keyset** (portable FIPS YubiKey + USB-wrapped
ML-DSA cosign), no CLI, no relay.

**Substrate floor (the 0.5.80 mesh-seed release):**
edge **v9.0.0** · persist **v13.0.0** · verify family **v8.7.0** (CC 1.0-rc). The
`canonical` identity_type role and its accord-conferred admission gate ship in persist
v13.0.0.

---

## 0. Who is who (and who is NOT in the trust root)

| Actor | Role in the seed |
|---|---|
| **`canonical-server-1`** (Node A) | **the node being seeded.** A normal, operator-owned (self-claimed) node until the accord signs it in. The lens / mesh-entry node. |
| **A1 accord holder** (you) | **1 of 3** `HUMANITY_ACCORD` holders. Signs the add-canonical invocation from the Trust Root card with the portable keyset. `add`/`update-address` are **1-of-N** today (see the ladder in §4). |
| **lapbuntu2** | **where the A1 crypto ops run** (the app/card + the portable signer). **NOT canonical, NOT in the trust root** — it is the operator's workstation, nothing more. |
| **Node B** (`ciris-status-1`) | **NOT a canonical server** and **not involved in the seed.** B is an out-of-group status node; its bilateral replication with A is a separate, optional concern (Appendix A). |

The trust root is the **baked `HUMANITY_ACCORD` accord holders** (A1/B1/C1), seeded at
persist first-boot. Canonical servers are the nodes those holders scrub-sign in. One
scrub-signed record both **roots** the node and **marks it canonical** — there is no
separate roster to maintain.

---

## 1. Preconditions

| # | Precondition | State |
|---|---|---|
| 1.1 | **CIRISServer 0.5.80 on PyPI / the node image** — carries edge v9.0.0 · persist v13.0.0 · verify v8.7.0 and the **add-canonical** op + Trust Root "Canonical servers" card section. | ⛔ cut |
| 1.2 | **`canonical-server-1` deployed + operator-self-claimed** (owner-binding present) — the ordinary deploy+claim, unchanged from `FSD/BRIDGE_SEED_MESH.md` §0–§4a. The node need NOT be "announced to federation"; the accord scrub is what roots it. | ⛔ deploy |
| 1.3 | **The A1 keyset is available on the signing workstation** (lapbuntu2): the portable FIPS YubiKey (Ed25519 slot) + the USB-wrapped ML-DSA-65 half — the same cosign path admit-node uses. | ✅ (you hold these) |
| 1.4 | **The baked `HUMANITY_ACCORD` anchor is present** in the node's persist (first-boot seed, persist v13). `GET /v1/accord/family` projects it. | ✅ (v13 baked) |
| 1.5 | **`net.bootstrap_peers` reachability** for any peer that will dial `canonical-server-1` — an `IP:port` config value (replaceable; NOT the trust anchor). Option-A addressing, §5. | ⛔ config |

---

## 2. The Trust Root card

The card (renamed from "Accord" in PR #165) is visible to **everyone** but only the
**three accord holders** can act. It has two regions:

- **Trust root** — the `HUMANITY_ACCORD` family + its live roster (read-only projection
  of `GET /v1/accord/family`), and the kill-switch invocation surface (2-of-3).
- **Canonical servers** (the 0.5.80 addition) — the list of nodes carrying the
  `canonical` role, each with its bound address, plus the holder-only actions:
  **Add canonical server · Update address · Supersede · Withdraw**.

The app holds **no keys**. Every action assembles an invocation, hands the JCS-canonical
bytes to the **portable signer** (YubiKey Ed25519 + USB ML-DSA cosign), and posts the
holder signature(s) to the node. The node verifies the accord quorum against its live
`federation_keys` roster — the signature *is* the authority.

---

## 3. The seed — "Add canonical server" (the one action)

On the Trust Root card → **Canonical servers** → **Add canonical server**:

1. **Select the target** — `canonical-server-1` (its derived `key_id`,
   `canonical-server-1-<fp>`), pulled from the operator's owned-nodes.
2. **Touch the YubiKey** (+ the USB ML-DSA half) — the card signs the add-canonical
   invocation with the A1 keyset.
3. Done. The node is rooted, marked canonical, and its address is published.

Behind that one tap, **add-canonical composes three effects**, each **accord-authorized
1-of-N** via `canonical_op_quorum_m(CanonicalOpClass::Operational)` (so it auto-scales
to m-of-n as the founder set grows — §4):

1. **Scrub-sign → root + mark canonical.** Reusing admit-node's scrub path
   (`produce_scrubbed_key_record`, `src/accord_provision.rs`), the holder scrub-signs
   the node's registration record and sets **`canonical`** in its `identity_type` set.
   persist v13 admits it **only because** the scrub key is a `HUMANITY_ACCORD` anchor
   holder — a self-signed or non-anchor record carrying `canonical` is **rejected**
   (`CanonicalRoleNotAccordConferred`, fail-closed). This is the whole security
   invariant: **canonical is conferred by the trust root, never self-claimed.**
2. **Adopt onto the node's own row.** The scrubbed (anchored) record replaces the
   node's self-signed own row via the DO-UPDATE upgrade path
   (`Engine::adopt_scrub_upgrade`, local — shipped 0.5.78; or the remote
   `POST /v1/federation/adopt-scrubbed`, shipped 0.5.79). The Key-plane then publishes
   an **anchored, rootable** own-record. *(When CIRISEdge#277 ← CIRISPersist#375 land —
   the upgrade-aware `apply_key` — replication itself can adopt a scrub-upgrade instead
   of `DO NOTHING`-ing it; until then the adopt step above is the delivery path.)*
3. **Publish the address.** Bind the node's `transport_destination` via the
   **update-address** op (`POST /v1/accord/canonical/address`, shipped PR #165) — a
   pubkey-authenticated, replaceable identity↔address record (Option-A, §5).

**Rooting is receiver-side.** Any peer that pins the `HUMANITY_ACCORD` anchor roots
`canonical-server-1`'s own record via `root_binding_anchored` (a directory lookup
against the *receiver's* anchor) the moment it sees the published record. No push, no
promotion, no relay.

---

## 4. The authority ladder (1-of-N now, m-of-n later)

Every canonical op resolves its quorum in **one place** — `canonical_op_quorum_m`
(`src/accord.rs`) — so scaling is a one-line change, never a scatter of hard-coded
`2`s.

| Op | Class | Quorum today | Scales via |
|---|---|---|---|
| **Add canonical** (the seed) | `Operational` | **1-of-N** | change the `Operational` arm to read the family's entrenched `quorum:M/N` |
| **Update address** | `Operational` | **1-of-N** | ″ |
| **Supersede** (replace a canonical key) | `Structural` | **m-of-n** | `kill_switch_quorum_m` — the family's entrenched `quorum:M/N` (already m-of-n) |
| **Withdraw** (remove from the trust root) | `Structural` | **m-of-n** | ″ |

Additive/operational acts (bring a server in, move its address) are 1-of-N because a
single holder can safely grow reach. Destructive acts (remove or replace a founding
server) are m-of-n — they need the family. As the founder set scales past 3, flip the
`Operational` arm to the entrenched `quorum:M/N` and **all** ops become m-of-n with no
other change.

---

## 5. Addressing — Option A (trust ≠ reachability; CIRISServer#163 / CIRISPersist#342)

The seed **never bakes an IP as the anchor.** Three distinct layers:

- **Trust** = the **pinned accord pubkeys** (the baked `HUMANITY_ACCORD` anchor). This
  is what roots a node. Immutable, cryptographic.
- **Reachability** = the node's **pubkey-derived RNS destination hash** + the signed
  **`transport_destination`** published by the update-address op (CC 3.3.6.2). Rebindable
  by a 1-of-N accord signature when the server moves.
- **Bootstrap hint** = `net.bootstrap_peers`, an ordinary `IP:port` **config** value
  (owner-authored, replaceable). `CANONICAL_BOOTSTRAP_PEERS` stays **`[]`** for 0.5 by
  design; **0.6 bakes the founder pubkeys + a replaceable address hint** (never IPs as
  the anchor) — CIRISServer#163.

So moving `canonical-server-1` to a new host is a **1-of-N Update-address** on the card
plus a `net.bootstrap_peers` edit — the node's identity and rooted status are untouched.

---

## 6. Post-conditions — the seed is done when these hold

- **`canonical-server-1`'s own row carries `canonical`** in its `identity_type` set and
  its `scrub_key_id` is a `HUMANITY_ACCORD` holder (anchor-scrubbed, not self-signed).
- The node **roots to the anchor** — `root_binding_anchored` = Confirmed against the
  baked `HUMANITY_ACCORD` terminus.
- Its **`transport_destination` is bound** (visible in the card's Canonical-servers list).
- A **second node that pins the same anchor roots `canonical-server-1`** from its
  published record — the field proof the mesh has a genesis trust root.

---

## 7. What this seed does NOT require (vs. the old model)

- **No delegation grant, no `POST /v1/mesh/relay`.** The card posts an accord-signed
  invocation to the node directly; the accord signature is the auth.
- **No "promote to federation cohort scope."** Rooting is by accord scrub, not by an
  owner-binding cohort flip.
- **No A↔B bilateral peering to seed the root.** B is not canonical. (Optional A↔B
  `consent:replication:v1` is a separate concern — Appendix A.)
- **No wipe / reseed to fix pending rows.** The upgrade path (`adopt_scrub_upgrade`,
  DO-UPDATE) heals a self-signed own row in place; no new key_id needed.

---

## Appendix A — Legacy delegation-grant + RNS-relay seed (0.5.75, SUPERSEDED)

> Kept for the historical record and as the reference for the *separate* concern of
> driving a **remote** node's own API over the RNS control-plane relay with a
> constrained delegation grant (the "§2 Option A" / "one real gap" cross-refs in
> `RNS_CONTROL_RELAY.md` and `EDGE_8_0_OPAQUE_MIGRATION.md` resolve here). This is NOT
> how the canonical mesh is seeded as of 0.5.80 — see §3.

The 0.5.75 procedure promoted Node A (`ciris-canonical-1`) and Node B (`ciris-status-1`)
from self-scoped to federation-scoped and wired the bilateral `consent:replication:v1`
peering A↔B **through the LOCAL node's API using a constrained delegation grant**,
reaching the remotes **by fed key_id over RNS** (never curling them directly):

1. **Fleet on 0.5.75**; A + B reseeded with new key_ids + re-claimed (hybrid-COMPLETE
   rows); `net.announce_ownership=true` on A and B (the transport-announce prereq);
   A↔B bootstrap wired.
2. **A constrained delegation grant** (`POST /v1/auth/device/delegate`, constraints
   `actions_allow: [announce, peer, mesh_relay]`, goal "seed the canonical mesh"),
   claimed to a `dgrant:…` bearer.
3. **The seed over the relay** — each step a `POST /v1/mesh/relay` with the dgrant
   bearer: promote A→federation, promote B→federation, fetch key records, peer A→B,
   peer B→A. lapbuntu2 signed each inner request with the owner fed-ID and sent it as an
   `OpaqueRequest{kind:0x0000_0001}` over RNS to the target by key_id; the remote
   `MeshControlResponder` verified the signature (signer *is* its owner) and dispatched
   into the node's own v1 router. No password/bearer on A/B.
4. **Verify:** A/B owner-bindings at `cohort_scope: federation`; `consent:replication:v1`
   both directions; a trace ingested on A reaches B's corpus via the `ReplicationRuntime`
   anti-entropy (`tests/mesh_seed_e2e.rs`).

The bilateral A↔B replication topology from this appendix is still valid and useful as an
**optional** post-seed step if you want A and B to exchange corpora — it is simply no
longer part of establishing the canonical trust root.
