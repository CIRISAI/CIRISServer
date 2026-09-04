# Mesh-seed runbook — seeding the canonical mesh by a **2-of-3 co-scrub** across two machines (0.5.84)

> ## ⚡ MODEL (current — 0.5.84) — the seed is a cross-device m-of-n co-scrub
>
> A canonical server is admitted to the trust root by a **quorum of accord holders**,
> not one. Since **0.5.84** the `HUMANITY_ACCORD` family is BAKED (persist v13.3.1 /
> CIRISPersist#386 seeds the entrenched `quorum:2/3` row at boot on every node), and
> the add-canonical admission gate is **dynamic m-of-n** (persist v13.2.0 /
> CIRISPersist#383 — `canonical` is conferred iff the record's `distinct_scrub_count()`
> ≥ the family's entrenched `M`, i.e. **2 of 3**). So the seed is a **co-scrub**: A1
> scrub-signs the target (scrub #1), a second holder (B1) appends a scrub (scrub #2)
> over the byte-identical envelope, and at 2-of-3 the record is conferred `canonical`.
>
> **This runbook covers the cross-machine case** the operator actually runs: **A1 on
> `lapbuntu2`, B1 on `mac-mini`** — two separate machines, each holding one portable
> keyset. The two boxes are **NOT accord-peered**, so the co-scrub partial travels by
> **manual transfer** (save/copy the JSON, or paste it into the Cosign sheet), not by
> accord-gossip. (If they were peered, the partial + the completed record would gossip
> automatically — noted at each step.)
>
> **Why m-of-n, why baked:** a node is canonical because **the trust root signed off**
> — and the trust root is a *quorum*, so no single holder (or a single compromised
> holder) can mint a founding server. The 1-of-N single-tap add of 0.5.80 is retired.
>
> **Superseded models** (kept in Appendix A): the 0.5.75 delegation-grant + RNS-relay
> seed, and the 0.5.80 1-of-N Trust Root "Add canonical server" tap. The delegation/
> relay machinery still exists for driving a *remote* node's own API, but is not how
> the mesh is seeded. Cross-refs in `RNS_CONTROL_RELAY.md` / `EDGE_8_0_OPAQUE_MIGRATION.md`
> point at Appendix A.

**Goal:** bring **`canonical-server-1`** (Node A) into the canonical trust root so it
**roots to the `HUMANITY_ACCORD` anchor**, is **marked `canonical`** (by a 2-of-3
co-scrub), and is **reachable by a pubkey-authenticated address** — driven from the
**Trust Root card** with the two portable accord keysets (FIPS YubiKey + USB-wrapped
ML-DSA cosign), no CLI.

**Substrate floor (0.5.84):**
edge **v9.1.4** · persist **v13.3.1** · verify family **v8.9.0**. The baked `quorum:2/3`
family + the dynamic m-of-n `canonical` admission gate + the co-scrub endpoints
(`propose`/`cosign`, the open `/gossip-partial`, `/pending`) all ship at this floor.

---

## 0. Who is who (and who is NOT in the trust root)

| Actor | Role in the seed |
|---|---|
| **`canonical-server-1`** (Node A) | **the node being seeded.** A normal, operator-owned (self-claimed) node until the accord co-scrub confers `canonical`. The lens / mesh-entry node. The **completed 2-of-3 record must reach THIS node** to root (§3 step 5). |
| **A1 holder** on **`lapbuntu2`** | **1 of 3** `HUMANITY_ACCORD` holders — the **proposer**. Runs the Trust Root card on lapbuntu2 with the A1 portable keyset (FIPS YubiKey Ed25519 + USB-wrapped ML-DSA). Produces **scrub #1** (`propose`). |
| **B1 holder** on **`mac-mini`** | **1 of 3** holders — the **cosigner**. Runs the Trust Root card on the mac-mini with the B1 portable keyset. Appends **scrub #2** (`cosign`) over the byte-identical partial → the record reaches the 2-of-3 quorum. |
| **lapbuntu2 / mac-mini** | **where the A1 / B1 crypto ops run** — the operator's two workstations. **NEITHER is canonical, NEITHER is in the trust root** — they are just where each holder's keyset is plugged in. |
| **Node B** (`ciris-status-1`) | **NOT a canonical server** and **not involved in the seed.** An out-of-group status node; its bilateral replication with A is a separate, optional concern (Appendix A). *(Do not confuse the mac-**mini** — a holder's signing box — with Node **B** the status node.)* |

The trust root is the **baked `HUMANITY_ACCORD` accord holders** (A1/B1/C1), seeded at
persist first-boot (v13.3.1) as the entrenched `quorum:2/3` family. Canonical servers
are the nodes those holders **co-scrub** in. The completed 2-of-3 scrubbed record both
**roots** the node and **marks it canonical** — there is no separate roster to maintain.

> **Custody note.** The scrub crypto runs **where each YubiKey is** — A1's on lapbuntu2,
> B1's on the mac-mini — NOT on the canonical node. So neither signing box ends up
> `canonical`; the *record they jointly produce* does, once it is delivered to and
> adopted by Node A (§3 step 5).

---

## 1. Preconditions

| # | Precondition | State |
|---|---|---|
| 1.1 | **CIRISServer 0.5.84** on PyPI (the wheel each holder's app/node runs) — edge v9.1.4 · persist v13.3.1 · verify v8.9.0; carries the co-scrub endpoints (`propose`/`cosign`/`pending`) + the Trust Root card's **Propose** action, **Pending co-signs** section, and the **paste-a-partial** Cosign fallback. | ✅ live on PyPI |
| 1.2 | **`canonical-server-1` (Node A) deployed + operator-self-claimed** (owner-binding present) — the ordinary deploy+claim, unchanged from `FSD/BRIDGE_SEED_MESH.md` §0–§4a. The node need NOT be "announced to federation"; the accord co-scrub is what roots it. | ⛔ deploy |
| 1.3 | **A1 keyset on lapbuntu2** — the A1 FIPS YubiKey (Ed25519 slot) + its USB-wrapped ML-DSA-65 half, plugged into lapbuntu2. | ✅ (you hold these) |
| 1.4 | **B1 keyset on the mac-mini** — the B1 FIPS YubiKey + its USB-wrapped ML-DSA-65 half, plugged into the mac-mini. **Two distinct holders/keysets are required** — A1 alone (1 scrub) does NOT confer canonical under the 2/3 gate. | ✅ (you hold these) |
| 1.5 | **The baked `quorum:2/3` `HUMANITY_ACCORD` family is present** on Node A's persist (first-boot seed, v13.3.1). `GET /v1/accord/family` returns it with `entrenched:true` + the 3 seats. | ✅ (v13.3.1 baked) |
| 1.6 | **A transfer channel lapbuntu2 → mac-mini → Node A** — the two signing boxes are **NOT accord-peered**, so you move the partial (and the finished record) by hand: AirDrop / scp / USB / copy-paste. No mesh path is required for the co-scrub itself. | ✅ (any file copy) |
| 1.7 | **`net.bootstrap_peers` reachability** for any peer that will dial `canonical-server-1` — an `IP:port` config value (replaceable; NOT the trust anchor). Option-A addressing, §5. | ⛔ config |

---

## 2. The Trust Root card

The card (renamed from "Accord" in PR #165) is visible to **everyone** but only the
**three accord holders** can act. It has two regions:

- **Trust root** — the `HUMANITY_ACCORD` family + its live roster (read-only projection
  of `GET /v1/accord/family`), and the kill-switch surface (raise a 2-of-3 halt).
- **Canonical servers** — the list of nodes carrying the `canonical` role, each with its
  bound address, plus **[+ New] → Propose a canonical server** (scrub #1) and the
  holder ops **Update address · Supersede · Withdraw**.
- **Pending co-signs (canonical)** — co-scrub partials awaiting more scrubs (below the
  family quorum). Each has a **Cosign** action; **[+ New] → Cosign a pasted partial**
  handles the not-peered case (paste the partial JSON A1 produced).

The app holds **no keys**. Every action hands the JCS-canonical bytes to the **portable
signer** (YubiKey Ed25519 + USB ML-DSA cosign) and posts the holder scrub to the node.
Admission is persist's dynamic **m-of-n** gate against the entrenched family — the
distinct scrub set *is* the authority; the record is conferred `canonical` only at 2-of-3.

---

## 3. The seed — the cross-machine 2-of-3 co-scrub

Five steps across the two boxes. Steps 1–2 on **lapbuntu2** (A1), step 3 on the
**mac-mini** (B1), steps 4–5 deliver the finished record to **Node A**. The partial and
the finished record move by **hand** (you are not peered).

### Step 1 — A1 proposes (scrub #1), on lapbuntu2

Trust Root card → **Canonical servers → [+ New] → Propose a canonical server**:

1. **Select the target** — `canonical-server-1` (its derived `key_id`,
   `canonical-server-1-<fp>`), from the owned-nodes picker. Set its address/transport
   hint if prompted (Option-A, §5).
2. **A1 keyset** — touch the YubiKey (+ USB ML-DSA). The card calls
   `POST /v1/accord/canonical/propose`: `produce_scrubbed_key_record` scrub-signs the
   target with the `canonical` role → a **1-scrub partial** (a verify `SignedKeyRecord`).
3. This is **sub-quorum** (1 of 2) — NOT yet canonical. The response gives you the
   `partial` JSON and `saved_to`:
   `$CIRIS_HOME/ceg/outbox/canonical_coscrub/<canonical-server-1-<fp>>.json` on lapbuntu2.

### Step 2 — hand the partial to the mac-mini

Copy that partial `.json` (or the `partial` field from the propose response) to the
mac-mini — **AirDrop / scp / USB / paste-buffer**, whatever's handy. It is a
self-contained object; the mac-mini needs nothing else about Node A to sign it.
*(If the two boxes were accord-peered, the partial would have gossiped to the mac-mini's
"Pending co-signs" automatically and you'd skip this copy.)*

### Step 3 — B1 cosigns (scrub #2), on the mac-mini

Trust Root card → **Pending co-signs (canonical)**:

- If it's listed (gossip) → **⋮ → Cosign**.
- Not peered → **[+ New] → Cosign a pasted partial**, and **paste** the JSON from step 2.

Then **B1 keyset** — touch the mac-mini's YubiKey (+ USB ML-DSA). The card calls
`POST /v1/accord/canonical/cosign`: `append_scrub` appends B1's scrub over the
**byte-identical** envelope → a **2-scrub** record. That meets the family `M` = 2.

> **Expect `conferred: false` here.** The mac-mini tries `adopt_scrub_upgrade` and it
> fails — the record is **Node A's** row, not the mac-mini's. That is by design: the
> mac-mini produced the finished *artifact*, it does not host the target. The finished
> record is saved to
> `$CIRIS_HOME/ceg/outbox/canonical_coscrub/<canonical-server-1-<fp>>.json` **on the
> mac-mini** (and returned as `advanced` in the response). See §6.5.

### Step 4 — get the finished record off the mac-mini

The 2-of-3 record is that `advanced` JSON. Take it from the outbox file above (or the
`advanced`/`saved_to` fields the Cosign result surfaces) and move it to a box that can
reach Node A — same AirDrop/scp/USB as step 2.

### Step 5 — deliver it to Node A → root + canonical

Apply the finished record onto Node A's own row:

```
POST http://<node-A>:4243/v1/federation/adopt-scrubbed
     Content-Type: application/json
     <the finished 2-of-3 SignedKeyRecord>
```

`adopt_scrub_upgrade` runs **in place** on Node A (this IS its own row) → the self-signed
row is replaced by the **anchor-scrubbed, 2-of-3** record → Node A is marked `canonical`
and **roots to the `HUMANITY_ACCORD` anchor**. persist admits it **only because** the two
scrub keys are `HUMANITY_ACCORD` holders and the distinct-scrub count meets the entrenched
`M` — a self-signed or sub-quorum record carrying `canonical` is **rejected**
(fail-closed). That is the whole invariant: **canonical is conferred by a trust-root
quorum, never self-claimed, never by one holder.**

**Rooting is receiver-side.** Any peer that pins the `HUMANITY_ACCORD` anchor then roots
`canonical-server-1`'s published record via `root_binding_anchored` (a lookup against the
*receiver's* baked anchor) — no push, no promotion, no relay.

---

## 4. The authority — dynamic m-of-n against the entrenched family

Admission reads the family's entrenched `quorum:M/N` (today **2/3**) via verify's
`verify_quorum_policy` — a **dynamic** gate, never a hard-coded `2`. So the whole table
is m-of-n and scales with the family with no code change:

| Op | Quorum | How |
|---|---|---|
| **Add canonical** (the seed) | **m-of-n (2/3)** | the co-scrub — `distinct_scrub_count()` ≥ `M` confers `canonical` (§3) |
| **Update address** | **m-of-n (2/3)** | same admission gate on the address record |
| **Supersede** (replace a canonical key) | **m-of-n (2/3)** | 2-of-3 via `proposal_digest` (CIRISServer#377) |
| **Withdraw** (remove from the trust root) | **m-of-n (2/3)** | ″ |

The 0.5.80 "additive ops are 1-of-N" ladder is **retired** — a single holder minting a
founding server was the weakness the co-scrub closes. Grow the family to 3/5 and every op
becomes 3-of-5 automatically (the gate reads the entrenched policy).

---

## 5. Addressing — Option A (trust ≠ reachability; CIRISServer#163 / CIRISPersist#342)

The seed **never bakes an IP as the anchor.** Three distinct layers:

- **Trust** = the **pinned accord pubkeys** (the baked `HUMANITY_ACCORD` anchor). This
  is what roots a node. Immutable, cryptographic.
- **Reachability** = the node's **pubkey-derived RNS destination hash** + the signed
  **`transport_destination`** carried in the scrub envelope / rebound by the update-address
  op (CC 3.3.6.2). Rebindable by an **m-of-n** accord signature when the server moves.
- **Bootstrap hint** = the mesh entry set is sourced from the **baked canonical servers'
  signed envelope transport hints** (`Engine::canonical_bootstrap_hints`, 0.5.81 —
  `CANONICAL_BOOTSTRAP_PEERS` the const is retired), unioned with the optional
  `net.bootstrap_peers` `IP:port` override (owner-authored, replaceable). Never an IP as
  the anchor — CIRISServer#163.

So moving `canonical-server-1` to a new host is an **m-of-n Update-address** on the card
plus a `net.bootstrap_peers` edit — the node's identity and rooted status are untouched.

---

## 6. Post-conditions — the seed is done when these hold

- **On Node A**, `GET /v1/accord/canonical/servers` lists `canonical-server-1` with the
  `canonical` role, and its record carries **≥ 2 distinct accord-holder scrubs** (A1 + B1)
  — `distinct_scrub_count()` ≥ the family `M`. `is_canonical` reads **`true`** on Node A.
- Its own row is **anchor-scrubbed, not self-signed** (both `scrub_key_id`s are
  `HUMANITY_ACCORD` holders), and the node **roots to the anchor** —
  `root_binding_anchored` = Confirmed against the baked `HUMANITY_ACCORD` terminus.
- Its **`transport_destination` is bound** (visible in the card's Canonical-servers list).
- A **second node that pins the same anchor roots `canonical-server-1`** from its
  published record — the field proof the mesh has a 2-of-3-founded genesis trust root.
- On lapbuntu2 / the mac-mini the record reads **not** canonical / `conferred:false` —
  EXPECTED (they are signing boxes, not the target). Only Node A confers.

---

## 6.5 Collecting the seed object (what to hand to the persist bake)

The co-scrub emits, at each step, a **verify `SignedKeyRecord`** for the target — the
1-scrub partial (after propose) then the 2-of-3 finished record (after cosign). The JSON
on disk is authoritative; it is what you carry between machines (§3 steps 2 & 4).

1. **The card** — Propose surfaces the `partial` + `saved_to`; Cosign surfaces `advanced`
   + `saved_to` + `distinct_scrub_count` + `conferred`.
2. **On disk (authoritative)**, on whichever signing box just ran —
   `$CIRIS_HOME/ceg/outbox/canonical_coscrub/<canonical-server-1-<fp>>.json`
   (`$CIRIS_HOME` = the node's `--home`; env `CIRIS_HOME`, else `~/ciris` on lapbuntu2 /
   the mac node home on the mac-mini). After propose it holds the **1-scrub partial**;
   after cosign it holds the **2-of-3 finished record** (`record.additional_scrubs` = the
   appended scrubs). **This JSON is the artifact you move.**
3. **DB + logs** — once adopted on Node A it is a `federation_keys` row (read via
   `GET /v1/accord/canonical/servers`); `ciris-server.log` logs
   *"Trust Root: co-scrub proposed / cosigned"* with `distinct_scrubs` + `conferred`.

> **Custody: which host writes which file.** The scrub runs where the YubiKey is — the
> **partial** lands on **lapbuntu2** (A1), the **finished record** on the **mac-mini**
> (B1). On both signing boxes `is_canonical` reads **`false`** / `conferred:false` —
> EXPECTED (neither is the target). The record roots + confers only when the finished
> JSON is applied on **Node A** via `POST /v1/federation/adopt-scrubbed` (§3 step 5).

**Two uses of the finished 2-of-3 record:**
- **Adopt on Node A** (`/v1/federation/adopt-scrubbed`) — the live seed, this runbook's
  path. Node A roots + becomes canonical immediately.
- **Bake into persist genesis** (optional, CIRISServer#139 / a persist first-boot seed of
  the canonical node record) — so *every* fresh node recognizes `canonical-server-1` as
  canonical with zero adoption, the same way the `HUMANITY_ACCORD` holders + family are
  baked. Hand off the finished JSON + `target_key_id` for that.

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
