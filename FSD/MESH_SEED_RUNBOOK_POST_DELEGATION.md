# Mesh-seed runbook — seeding the canonical mesh over the RNS relay

**Goal:** promote Node A (`ciris-canonical-1`) and Node B (`ciris-status-1`) from
self-scoped to federation-scoped, and wire the bilateral `consent:replication:v1`
peering A↔B — **entirely through the LOCAL node's API using a constrained
delegation grant**, reaching the remotes **by fed key_id over RNS**, never by
curling them directly.

**Status (2026-07-02):** **0.5.74** is the mesh-seed release the field run actually
needs. The story so far: 0.5.72 shipped the relay; 0.5.73 made claiming record the
node locally (+ appended its RNS address to `net.bootstrap_peers`) and added a
`config set/get` CLI. But the live seed then stalled on a subtle gap: the
`config set/get` CLI only existed in the **standalone binary** (`src/main.rs`),
while the published **wheel/image** boots through `py_main`, which dispatched only
`import-traces` + serve. So Node A — running the wheel — had **no `config`
command**, and therefore no way to flip the one knob the relay depends on:
**`net.announce_ownership`**. **0.5.74 adds the `config` arm to the wheel/image
entry**, so a headless wheel node can self-configure from the console.

**The relay dependency the field run surfaced (important):** the relay addresses a
remote **by fed key_id over RNS**. A node is only reachable by key_id once it has
emitted its **Reticulum identity announce**, which is gated on
`net.announce_ownership = true`. A self-scoped node ships with
`announce_ownership: false` → it never announces → **the relay cannot root its
key_id and every probe times out.** So enabling the announce on A and B is a
**bootstrap PREREQUISITE**, done on each node's own console with `config set`
(deployment, not remote federation-state config) — NOT a post-seed step reached
*through* the relay (that was the chicken-and-egg the first field run hit).

---

## 0. Preconditions — ALL must hold before the seed can run

| # | Precondition | State |
|---|---|---|
| 0.1 | CIRISServer **0.5.74 on PyPI** + **CIRISStatus** image repinned to 0.5.74 | ⛔ cut |
| 0.2 | Fleet on 0.5.74: mac + lapbuntu2 **upgraded in place**; **A + B wiped, fresh-installed, re-claimed** (§1) | ⛔ deploy |
| 0.3 | RNS reachability wired: lapbuntu2→A/B (auto, via re-claim) **and A↔B** (set B→A bootstrap, §1) | ⛔ config |
| 0.4 | **`net.announce_ownership=true` set on A AND B** via `config set` (the announce prereq) + restart | ⛔ config |
| 0.5 | You issue me a delegation grant on lapbuntu2 (goal "seed mesh"; §2) | ⛔ your move |

---

## 1. Fleet roll — keep your fedID, upgrade mac/lapbuntu2, wipe+re-claim A/B

The relay is bilateral: lapbuntu2 hosts `POST /v1/mesh/relay` and *sends*; A and B
must *receive* on opaque kind `0x0000_0001` — which needs edge v8.x + the
`MeshControlHandler` (both in 0.5.7x). So every node must be on 0.5.73. The clean,
identity-preserving path (**your fedID is never wiped**):

1. **mac + lapbuntu2 — upgrade in place** (identity-preserving; persist auto-migrates):
   `pip install -U ciris-server==0.5.73` (or the standalone binary) + restart. Your
   owner fedID (`eric-moore-v2-portable-…`) lives here and is untouched.

2. **A + B — wipe, fresh-install 0.5.73, re-claim.** A/B already have a ROOT, so a
   re-claim would `409`; a fresh install clears that. Cost: A/B mint **new** derived
   key_ids (fine for canonical/status service nodes) and lose their (re-seedable)
   corpus. Then **re-claim each from lapbuntu2** (`ciris-server claim …` or the app).
   Because 0.5.73's claim now **records the node locally**, this one step auto-fixes
   the whole "lapbuntu2 forgot A/B" problem:
   - A/B appear in lapbuntu2's `GET /v1/setup/owned-nodes`,
   - their key records land in lapbuntu2's `federation_keys`,
   - **their RNS address is appended to lapbuntu2's `net.bootstrap_peers`** → lapbuntu2
     can now dial them (the "≥1 node with an IP" the mesh needs). Restart lapbuntu2
     once after the re-claims so the new bootstrap takes effect.
   - Node B = the **CIRISStatus v0.3.13** image (repinned to 0.5.73).

3. **Wire the A↔B link** (the claim only links lapbuntu2→A and lapbuntu2→B; A and B
   still need each other for the actual trace replication + peering). A and B are
   **co-located on the same host**, so on B's console, with the wheel's `config` CLI:
   ```
   ciris-server config set net.bootstrap_peers '["127.0.0.1:4242"]' --home <B-home>
   # then restart B   (A is the RNS origin on 0.0.0.0:4242 — no bootstrap of its own)
   ```
   Confirm A actually listens on `0.0.0.0:4242` and is a transport node
   (`transport.node=true` — the default on server/proxy nodes) so it forwards for
   the mesh.

4. **Enable the identity announce on A AND B** — the relay reaches a node **by fed
   key_id over RNS**, which only works once the node has emitted its Reticulum
   identity announce. Self-scoped nodes ship `announce_ownership: false`, so on
   **each** node's own console (this is deployment on a node you operate, not remote
   config):
   ```
   ciris-server config set net.announce_ownership true --home <node-home>
   # then restart the node   → it now announces its key_id → the relay can root it
   ```
   Verify with `ciris-server config get net.announce_ownership --home <node-home>`
   (→ `true`). Without this, §3's relay probes to A/B **time out** (the first field
   run's failure). **This is the 0.5.74 fix** — earlier wheels had no `config` arm.

**"Deploy" ≠ "configure directly."** Rolling the binary/image + the console
`config set` on a node you operate is deployment, not the federation-state
configuration the "don't touch remotes directly" rule governs — that still flows
only through the grant over the relay (§3).

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

> **Prereq (NOT a relay step):** A and B must already have
> `net.announce_ownership=true` + a restart (§1.4) so they're reachable by key_id.
> The relay probes below will time out otherwise. The `POST /v1/federation/announce`
> owner-binding **promotion** (self→federation cohort scope) below is a *separate*
> concern from the *transport* announce — the transport announce is the boot-time
> prereq; this relay step promotes the CEG owner-binding.

1. **Promote A → federation** — `{target: A, POST /v1/federation/announce}` → A
   promotes its owner-binding `self → federation` cohort scope. (A is already
   reachable because §1.4 turned on the transport announce.)
2. **Promote B → federation** — same, `{target: B}`.
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
| relay both legs · delegation constraints · TDD gate (0.5.72) | ✅ done |
| claim-records-locally + `config set` CLI + copy-all card (0.5.73) | ✅ done |
| **0.5.74** (`config` arm in the WHEEL/image entry) on PyPI + **CIRISStatus** image repinned | ⛔ cut |
| mac + lapbuntu2 upgraded in place; **A + B wiped, fresh-installed, re-claimed** (§1) | ⛔ deploy |
| A↔B bootstrap wired (B→A, §1.3); lapbuntu2→A/B auto (re-claim) | ⛔ config |
| **`net.announce_ownership=true` on A + B** (§1.4) + restart — the relay-reachability prereq | ⛔ config |
| Delegation grant issued (§2) | ⛔ your move |
| Seed run (§3) + verify (§4) | ⛔ blocked on the above |

**Ready to seed the moment the fleet is on 0.5.74, A/B re-claimed + announcing, A↔B wired, and you hand me a grant.**
