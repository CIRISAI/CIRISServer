# Mesh-seed runbook — seeding the canonical mesh over the RNS relay

**Goal:** promote Node A (`ciris-canonical-1`) and Node B (`ciris-status-1`) from
self-scoped to federation-scoped, and wire the bilateral `consent:replication:v1`
peering A↔B — **entirely through the LOCAL node's API using a constrained
delegation grant**, reaching the remotes **by fed key_id over RNS**, never by
curling them directly.

**Status (2026-07-02):** **0.5.73** is the mesh-seed *operability* release. 0.5.72
shipped the relay but the seed hit two real gaps in the field: (a) `claim_remote`
was fire-and-forget — the claiming node never recorded what it claimed, so
lapbuntu2 had no local record of A/B and **no IP to dial them over RNS**; (b) a
headless node (console-only, no app/session) had **no way to set
`net.bootstrap_peers`**. 0.5.73 fixes both: **claiming a node now records it in your
own fed directory + appends its RNS address to `net.bootstrap_peers`**, and a new
**`ciris-server config set/get` CLI** lets headless nodes be configured from the
console. The **relay is the path**; the old HTTP "Option A/B" is gone.

---

## 0. Preconditions — ALL must hold before the seed can run

| # | Precondition | State |
|---|---|---|
| 0.1 | CIRISServer **0.5.73 on PyPI** + **CIRISStatus v0.3.13** image | ⛔ cut |
| 0.2 | Fleet on 0.5.73: mac + lapbuntu2 **upgraded in place**; **A + B wiped, fresh-installed, re-claimed** (§1) | ⛔ deploy |
| 0.3 | RNS reachability wired: lapbuntu2→A/B (auto, via re-claim) **and A↔B** (set B→A bootstrap, §1) | ⛔ config |
| 0.4 | You issue me a delegation grant on lapbuntu2 (goal "seed mesh"; §2) | ⛔ your move |

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
   **co-located on the same host**, so on B's console, with the new 0.5.73 CLI:
   ```
   ciris-server config set net.bootstrap_peers '["127.0.0.1:4242"]' --home <B-home>
   # then restart B   (A is the RNS origin on 0.0.0.0:4242 — no bootstrap of its own)
   ```
   Confirm A actually listens on `0.0.0.0:4242` and is a transport node
   (`transport.node=true`) so it forwards for the mesh.

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
| relay both legs · delegation constraints · TDD gate (0.5.72) | ✅ done |
| **0.5.73** (claim-records-locally + `config set` CLI + copy-all card) on PyPI + **CIRISStatus v0.3.13** image | ⛔ cut |
| mac + lapbuntu2 upgraded in place; **A + B wiped, fresh-installed, re-claimed** (§1) | ⛔ deploy |
| A↔B bootstrap wired (B→A, §1.3); lapbuntu2→A/B auto (re-claim) | ⛔ config |
| Delegation grant issued (§2) | ⛔ your move |
| Seed run (§3) + verify (§4) | ⛔ blocked on the above |

**Ready to seed the moment the fleet is on 0.5.73, A/B re-claimed, A↔B wired, and you hand me a grant.**
