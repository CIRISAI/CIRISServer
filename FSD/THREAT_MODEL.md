# FSD — Threat Model: the safe-mesh-seed trust architecture (server tier)

> **This is a COMPOSITION threat model, not a standalone one.** CIRISServer
> authors no crypto, no storage, no transport — it *composes* the substrate. So
> this document owns exactly the surfaces the substrate docs do NOT: the
> **server-tier** trust machinery (accord trust root, kill-switch, holder custody
> orchestration, canonical mesh seed, the `substrate_persist` emitter, the
> infohazard consent gate, ownership) and the **cross-tier composition** threats —
> the gaps *between* tiers that no single substrate doc can see.
>
> Grounded in the **0.5.84** source (branch `feat/181-producer-hook`; substrate
> edge v9.1.3 / persist v13.3.0 / verify v8.9.0). Where a control here reads
> stronger than the code, the code wins — file it against this doc.

---

## 0. Tiered threat model — who owns what

Every threat class below is owned by a tier's own threat model. This document
**defers** to them and does not restate their content. Read them for the
primitive-level analysis; read *this* for how the server composes them and where
the seams are.

| Tier | Doc | Owns (do NOT re-derive here) |
|------|-----|------------------------------|
| **verify** | [`CIRISVerify/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md) + [`FEDERATION_THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/FEDERATION_THREAT_MODEL.md) | Crypto & identity: hybrid Ed25519+ML-DSA-65, threshold-signature verification, the YubiKey-PIV custody-attestation chain verify, `HybridPolicy::RequireHybrid`, the `infra:*`/`agency:*` delegation split, the `infrastructure_community` M-of-N trust-root primitive, software-PQC-seed honest boundary (AV-44), surviving-key revocation (AV-45), the federation-emergent + moderation-principal (`on_behalf_of`) model. |
| **persist** | [`CIRISPersist/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/THREAT_MODEL.md) | Storage & admission: the reserved-prefix admission rule (`content_class:`/`system:`/`audit_chain:` ⟹ `substrate_persist`), the m-of-n canonical admission gate (`adopt_scrub_upgrade`/`verify_quorum_policy`), the node/agency write-time gate (CC 4.4.3.4.3), single-owner `owner_of` / `NodeAlreadyOwned`, family-row seed + migrations (V097), cohort_scope gates, membership-revocation forward secrecy. |
| **edge** | [`CIRISEdge/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISEdge/blob/main/docs/THREAT_MODEL.md) | Transport & delivery: Reticulum/HTTP/LoRa envelope carriage, authenticated `PeerResolver` cold-start (AV-42), cryptographic addressing, Key-plane / consent-plane replication convergence. |
| **lens-core** | [`crates/ciris-lens-core/docs/THREAT_MODEL.md`](../crates/ciris-lens-core/docs/THREAT_MODEL.md) | The **entire lens/scoring tier** — score-gaming, manifold-conformity evasion, cohort-routing attacks, N_eff / capacity-scoring manipulation, coherence-ratchet detector/statistical attacks, federation-scoring. **This doc does NOT cover any scoring threat.** |
| **server (this doc)** | `FSD/THREAT_MODEL.md` + [`FSD/SAFE_MESH.md`](SAFE_MESH.md) (invariant claim) + [`docs/SCOPE_PRIVACY.md`](../docs/SCOPE_PRIVACY.md) (privacy residual) | The **composition**: accord trust root & kill-switch, portable-holder custody *orchestration*, canonical mesh SEED, the node `substrate_persist` emitter, the infohazard consent gate + producer, ownership binding, and the cross-tier seams. |

**Composition stance.** *Ingest is open and cheap; admission is the gate.* Server
endpoints accept structurally-valid objects into bounded, ephemeral display /
coordination stores; the load-bearing cryptographic checks live one tier down
(persist admission, verify threshold) at cosign→adopt / verify-invocation — never
at the server's network edge. The threats worth writing down here are the ones
that live in *that gap*.

---

## 1. Server-tier assets

Only the assets the server tier introduces or is responsible for composing
(primitive assets — key secrecy, wire integrity — are the substrate docs'):

| # | Asset | Why the SERVER owns it |
|---|-------|------------------------|
| A1 | **The entrenched HUMANITY_ACCORD trust root** (quorum:2/3 A1/B1/C1 family row) as the server *presents and gates on* it | persist seeds/stores the row; the server owns the genesis-assemble ceremony + every gate that reads it. |
| A2 | **The kill-switch RAISE→LATCH→boot-gate path** | verify decides the 2/3; the *server* replicates-then-latches-then-exits and refuses boot. |
| A3 | **Holder custody orchestration** — provisioning, cosign, admit flows | verify verifies the attestation; the server drives the loopback ceremony that produces + presents it. |
| A4 | **Canonical mesh integrity** — the co-scrub SEED end-to-end (propose→gossip→cosign→adopt) | persist gates the m-of-n; the server owns the propose/gossip/pending plumbing around it. |
| A5 | **Infohazard content confidentiality behind the reveal gate** | the *decision* + producer are pure server composition on top of persist's reserved-prefix rule. |
| A6 | **Single-owner node ownership** as the `self`/governance boundary | persist resolves `owner_of`; the server gates every governance act on it. |

---

## 2. Actors & the server's trust of each

Primitive trust (key holders, peers as transport) is the substrate docs'. The
server-specific trust decisions:

| Actor | Server trusts for | Server does NOT trust for |
|-------|-------------------|---------------------------|
| **Accord holders (2/3)** | Raising a halt, running genesis, admitting canonical nodes — each gated on a verify-verified threshold. | Any *single* holder halting or (under m-of-n) conferring canonical alone. |
| **Node owner (SYSTEM_ADMIN, non-delegated)** | Governance on their own node (`require_owner`: `SystemAdmin` + `FullAccess` + `actor.is_none()`). | Overwriting the constitutional trust root (§4.1); acting as a self-amplifying *delegated* actor (explicitly refused). |
| **The node `substrate_persist` emitter** | Authoring reserved-prefix rows *within the operator's own store*. | Any cross-node authority — it is a node-local key (§3.4). |
| **App / client** | Driving **loopback-only** setup/provision endpoints on the user's own box; rendering the interstitial. | Being the enforcement point — it is trusted to *call* `/reveal`, which is exactly the not-yet-closed seam (§4.4). |
| **Remote peers** | Relaying gossip (kill-switch messages, co-scrub partials). | Being a cryptographic authority — every plane re-verifies at admission, not at the server's ingest. |

---

## 3. Server-tier threats → mitigations → residual

### 3.1 Trust root & kill-switch

**Files:** `src/accord.rs`, `src/accord_halt.rs`, `src/family.rs`,
`src/accord_reactivate.rs`. Substrate: persist seeds the keyless quorum:2/3 row
at boot (CIRISPersist#386, V097 drops the `family_key_id → federation_keys` FK);
verify owns the 2/3 threshold verification — **not restated here**.

| Threat | Server mitigation (mechanism) | Residual risk |
|--------|-------------------------------|---------------|
| **One human holds two seats** → self-satisfies 2/3. | Roster = family SEATS (`family::active_threshold_roster`), NOT "every `accord_holder` row" — a vaulted cold-spare is registered but unseated. `assert_distinct_roster` re-asserts one-key-one-seat at the verification point (defence-in-depth over verify's own distinct-key gate). | Distinctness is by **key**, not by **human**. Two seats provisioned to the same person on two YubiKeys pass. One-seat-per-human is a **ceremony/social** property, not cryptographic. |
| **False/forced halt** (griefing DoS). | Fail-secure RAISE path: replicate-to-peers-**first**, then latch (`HUMANITY_ACCORD_HALT`), then `exit(42)`; `check_halt_gate` blocks every future boot. Recovery needs a verified 2/3 `accord:lifecycle:active` incl. ≥1 original genesis holder (`accord_reactivate`) — never an operator restart. | Intentionally near-irreversible: if ≥1 original genesis holder key is permanently lost, reactivation is impossible by design (CC 4.2.3). Availability is sacrificed to make the kill-switch real. |
| **Kill-switch message flood** exhausts the coordination tables. | `MAX_PENDING_INVOCATIONS` (4096) / `MAX_SEEN_INVOCATIONS` (16384) / `MAX_ACCORD_EVENTS` (1024); pending pruned of expired on every insert; per-peer replication time-bounded so a stalling peer can't block the latch. Sub-quorum vs quorum gossip tracked independently (`(kind,id,is_global_halt)`, B3). | Caps are backstops, not an authenticated rate limit. `InvocationDedup` is in-memory — a restart re-opens the anti-replay window (the durable 2/3 signatures remain the load-bearing check). |
| **Single-holder-compromise forges a halt.** | A synthesized/opener invocation carries ONE signature — sub-quorum, **cannot latch**; only the family M (`kill_switch_quorum_m`, from the entrenched `quorum:M/N`, never a hard-coded 2) latches. | **Compromise of 2 of 3 holders = trust-root capture** (halt + canonical). The explicit threshold; no defence above it beyond custody (§3.2) + the distinct-human ceremony. |

### 3.2 Holder custody (server orchestration)

**Files:** `src/accord_custody.rs`, `src/accord_provision.rs`
(`provision_holder`, `cosign_family`, `admit_node`, `open_holder_identity`),
`accord_pki/`. Verify owns the attestation-chain crypto (pinned Yubico root,
FIPS + touch-always + attested-key==holder bind) — **deferred to verify**.

| Threat | Server mitigation | Residual risk |
|--------|-------------------|---------------|
| **Software-only / non-FIPS key holds the kill-switch.** | `POST /v1/accord/holder` **mandates** a `custody_attestation` (B1 — no longer optional) and passes it to verify's `verify_accord_custody_attestation`; genesis-assemble additionally requires every seat to be a registered `accord_holder`, so "seat ⟹ accord_holder ⟹ FIPS custody" holds regardless of how any other key reached `federation_keys`. | The gate proves *hardware class*, not that the *right human* holds the token. Attestation-PKI trust is verify's + out-of-scope (§6). |
| **Provisioning endpoint abused remotely.** | `provision-holder` / `cosign-family` / `admit-node` are **loopback-only** (`require_loopback`) + `pkcs11`-gated (501 without a token); the OWNER gate is downstream at `POST /v1/accord/holder`. The touch-required tap is the real authority. | Loopback trust assumes a non-shared, non-hostile host (§6). Two-factor custody + at-rest seed handling: §3.4. |

### 3.3 Canonical mesh SEED (co-scrub end-to-end)

**Files:** `src/accord_provision.rs` (`propose_canonical`, `cosign_canonical`,
`ingest_partial`, `receive_gossip_partial`, `withdraw`/`supersede`),
`src/compose.rs`. persist owns the m-of-n admission gate
(`adopt_scrub_upgrade` → `check_canonical_role_admission`, `verify_quorum_policy`)
— **deferred to persist**.

| Threat | Server mitigation | Residual risk |
|--------|-------------------|---------------|
| **Forged canonical admission** (mint a `canonical` node without holder consent). | Scrubs are produced only via the hardware custody path (`open_holder_identity`); confer is persist's dynamic m-of-n (`distinct_scrub_count() ≥` entrenched `quorum:M/N`), not a server threshold. 1-of-N auto-bake retired. | **m compromised holders** confer canonical — same threshold class as §3.1. |
| **`/gossip-partial` is an OPEN (non-loopback) endpoint** — anyone can POST a "partial". | Deliberate, explicit trust posture: `ingest_partial` **structurally validates only** (a well-formed `SignedKeyRecord` with ≥1 scrub + a target) into a **bounded** (`MAX_PENDING_COSCRUBS`=256), **ephemeral display store** behind `GET /pending`. `roster_verified` is a best-effort *hint*, not a decision. The crypto gate is at **cosign→adopt** (persist), never at ingest. Cosign resubmits the byte-identical stored envelope (`append_scrub` rejects a re-encode/duplicate anchor). | The open store can be **polluted** with structurally-valid junk (UX annoyance + a place a socially-engineered holder might be nudged to cosign the *wrong target*). Bounded + loop-stopped `(target, scrub-count)`. **A holder who cosigns a pending entry without verifying the target is the real risk — the display is not authenticated.** This is a genuine cross-tier seam (§4.2). |

### 3.4 Infohazard consent gate + producer (server composition)

**Files:** `src/safety/infohazard.rs`, `src/safety/moderation.rs`,
`src/compose.rs` (`substrate_persist_signer`, `register_substrate_key`). persist
owns the reserved-prefix admission rule — **deferred to persist**.

| Threat | Server mitigation | Residual risk |
|--------|-------------------|---------------|
| **Unauthorized moderator flags content.** | `POST /v1/safety/flag` is **duty-gated**: `verify_request` → `signer_acts_for` → `admit_moderation_action(Moderate)` — a `moderate` duty must be held/delegated, never assumed (CEG §11.10). The duty-HOLDER authorizes; the SUBSTRATE identity signs. | A held/delegated `moderate` duty stands in for "a live majority favors moderation" today — the **FSD-004 live-quorum vote is a future upgrade**. |
| **Passive exposure** of flagged content. | Pure gate `infohazard_reveal_decision` is **protective by default**: flagged + absent/unknown consent ⇒ `Interstitial` (403), never a passive `Allow`. Consent is latest-wins with a **revocation fold** (a later `revoked`, even blanket, re-closes). Every `/reveal` requires the viewer's signature (attributable). | **The gate is a DECISION surface, not an enforced read path** — see the cross-tier seam §4.4. |
| **Viewer self-clears a flag.** | Refused by persist's reserved-prefix rule (`content_class:` ⟹ `substrate_persist` emitter) — **deferred to persist**. The server's role is to author flags *through* the `substrate_persist` identity, never the node/duty-holder key. | The over-broad emitter: §3.5. |

### 3.5 The node `substrate_persist` emitter (server-introduced)

**Files:** `src/compose.rs` (`substrate_persist_signer`, `register_substrate_key`).

| Threat | Server mitigation | Residual risk |
|--------|-------------------|---------------|
| **The node needs to author a reserved `content_class:*` flag but its own key is `identity_type = node`** (refused by persist). | The server mints a SEPARATE hybrid identity `identity_type = substrate_persist` at boot (sealed Ed25519 `<alias>-substrate` + software ML-DSA seed) and registers it through the canonical self-signed `register_federation_key` gate. The duty-holder authorizes at HTTP; THIS key signs. | **The emitter is over-broad: it can author ANY reserved prefix (`system:`/`audit_chain:`/`content_class:`), not just `content_class:`.** Bounded today only by "the operator already controls their own store," so it grants no cross-node authority — but the correct refinement is a **narrower persist `identity_type`** (or per-prefix scoping) so the infohazard producer cannot also forge `system:`/`audit_chain:` rows. This is a **server↔persist seam** (§4.3). |
| **At-rest custody of the emitter's software halves.** | Ed25519 half hardware-sealed (open-or-mint, stable across restarts so a later CLEAR resolves); ML-DSA seed `0o600` at `substrate_ml_dsa_65.seed`. | Software seeds rest on host integrity + filesystem perms (§6). Same posture verify documents for the user identity's software PQC half (AV-44). |

### 3.6 Ownership (server gating over persist's projection)

**Files:** `src/auth/ownership.rs`. persist owns `owner_of` / `NodeAlreadyOwned`
and the write-time node-agency gate — **deferred to persist**.

| Threat | Server mitigation | Residual risk |
|--------|-------------------|---------------|
| **Ambiguous multi-owner `self` boundary.** | Reads use `admission::owner_of`; `AmbiguousNodeOwner` → treated as **unowned, fail-closed** (`is_steward_bound`). The single-owner admission gate makes ambiguity unreachable going forward. | Fail-closed read is a backstop for legacy multi-owner rows. |
| **Delegation-based agency escalation** (a `delegates_to(user → node)` confers governance). | Governance endpoints (`require_owner`) refuse a delegated actor; the load-bearing write-time `infra:*`-only gate is persist's (**deferred**). | Correctness of the write gate is persist's + out-of-scope (§6). |

---

## 4. Cross-tier composition threats (the seams no single tier owns)

These are the reason this doc exists — a gap *between* tiers, invisible to each
tier's own model.

### 4.1 Trust-root takeover via genesis-assemble — **CLOSED by idempotency**
An `insert-or-replace` in the server's `genesis_assemble` would have let an
**owner + two admitted holders** overwrite the constitutional A1/B1/C1 family and
capture the trust root — a *server-tier* write over a *persist-tier* asset that
neither tier alone flags. Closed: persist v13.3.0 seeds the keyless quorum:2/3
row at boot and drops the FK (V097), so `genesis_assemble` is now **idempotent** —
on a seeded node it records the founder-signed proof and *confirms* the row, and
only inserts when NONE exists (`already_entrenched` guard, `src/accord.rs`).
**Residual:** a genuinely pre-v13.3.0 store with no seeded row still takes the
defensive create path; mitigated in practice because every current node boots the
seed. *This is the canonical example of a composition threat — worth keeping
documented even though it's closed.* (Historically flagged as the SAFE_MESH.md §7
"root operator can rewrite `federation_families`" open question — now resolved.)

### 4.2 Structural-at-ingest vs crypto-at-adopt (the co-scrub seam)
A co-scrub partial is **structurally** validated at the OPEN `/gossip-partial`
(edge/server transport surface) but only **cryptographically** gated at
cosign→adopt (persist). The seam: nothing between those two points authenticates
the *display* a holder sees. Neither edge (which correctly just delivers) nor
persist (which correctly just gates admission) owns "did the holder cosign the
*right* target?" The server's `roster_verified` hint mitigates, but the residual
(§3.3) is a real social-engineering surface the server must own — e.g. by making
the client render the target + scrubbers unmissably before a cosign.

### 4.3 Reserved-prefix breadth (the `substrate_persist` seam)
persist enforces "reserved prefix ⟹ `substrate_persist` emitter" correctly; the
server introduces a *single* `substrate_persist` identity to satisfy it. The seam:
persist's rule is coarse-grained (any reserved prefix), so the server's one
emitter is over-authorized relative to its one use (infohazard flags). Closing it
needs a **persist-tier** refinement (a narrower identity_type or per-prefix scope)
that the server then adopts — filed as a follow-up (§7).

### 4.4 Decision-surface vs enforced-read (the infohazard seam)
The server owns the reveal *decision*; no tier owns *forcing every read through
it*. `/v1/safety/reveal` returns the correct protective verdict, but content the
fabric serves via other read APIs is not automatically routed through the gate —
the **read-path fan-out (#185) is not built**, and the consent lifecycle +
interstitial UX (#182/#183) aren't either. So the gate is **load-bearing in design
but not switched on end-to-end**. This is a pure composition gap: every tier is
correct; the wiring between them is incomplete.

---

## 5. Supersession of the v0.5.30 mesh threat model

The prior server-tier mesh/trust-root threat model lives in
[`FSD/SAFE_MESH.md`](SAFE_MESH.md) §4 (in-scope threats) + §8 (the 2026-06-21
four-agent red-team). It is framed at **v0.5.30** and is now **stale** — **this
section is the current (0.5.84) version**; SAFE_MESH.md remains authoritative
only for the **safe-mesh-floor definition and its I1–I8 invariants** (not
restated here — read §1–§3 there).

**What changed since v0.5.30** (why the old model no longer describes the code):

- The **trust root is now BAKED** (persist v13.3.0 seeds the keyless quorum:2/3
  A1/B1/C1 family at boot); it was ceremony-assembled + operator-writable then.
- The **kill-switch is RAISEABLE** in-band (`POST /v1/accord/halt`, the binding
  twin of `/drill`); it was verify-only then.
- **Canonical admission is m-of-n co-scrub** end-to-end (§3.3); the 1-of-N
  auto-bake is retired.
- **Single-owner is enforced** (`NodeAlreadyOwned`, §3.6); ownership was
  multi-binding then.

**The §8 red-team findings, at 0.5.84** (all carried forward + resolved; the
mechanisms are cited in §3–§4 above):

| Finding (v0.5.30) | Status at 0.5.84 | Where |
|-------------------|------------------|-------|
| **B1** — FIPS custody floor bypassable (`custody_attestation` optional). | **CLOSED** — mandatory for `accord_holder`; verified verdict coupled to the persisted `attestation_evidence`. | §3.2 |
| **B2** — reactivation/halt-clear rooted in operator-writable local state, not a pin. | **Superseded by the BAKED family** (persist v13.3.0) + the idempotent trust root — the continuity anchor is now the seeded row, not a forgeable local `federation_families` write. The `rm <latch>` break-glass is explicitly a **non-conformant** operator override (§3.1); tamper-evident/quorum-bound latch remains a hardening item. | §3.1, §4.1 |
| **B3** — quorum-completing halt not propagated (seen-set keyed sub-quorum). | **CLOSED** — seen-set keyed `(kind, id, is_global_halt)`; a newly-quorum halt always re-replicates. | §3.1 |
| **B4** — a halt resurrects if the latch write fails. | **CLOSED** — a failed latch write no longer exits "as halted" (fail-louder); `check_halt_gate` is fail-secure on presence. | §3.1 |
| **N1** — live halt threshold hard-coded to `2`. | **CLOSED** — `kill_switch_quorum_m` derives M from the entrenched `quorum:M/N` on the halt paths too. | §3.1 |
| **N2** — `verify-invocation` no distinct-pubkey re-check. | **CLOSED** — `assert_distinct_roster` re-asserts one-key-one-seat at the verification point. | §3.1 |

**New at 0.5.84** (surfaces the v0.5.30 model did not have): the m-of-n co-scrub
seam (§4.2), the `substrate_persist` emitter breadth (§4.3), and the infohazard
decision-vs-enforced-read seam (§4.4).

**The out-of-scope-for-the-floor items** (coercion of ≥2 humans, physical
compromise of ≥2 tokens+USB+PIN, running-mesh availability, substrate supply
chain) carry forward **unchanged** from SAFE_MESH.md §4 — see §6 here.

---

## 6. Out-of-scope / assumptions

Deferred to the substrate docs or explicitly assumed:

- **All primitive crypto, identity, attestation, and threshold verification** →
  verify's threat models. This doc trusts them.
- **Storage, admission rules, migrations, the reserved-prefix + node-agency +
  single-owner gates** → persist's threat model.
- **Transport confidentiality/authenticity, gossip delivery, peer resolution** →
  edge's threat model. **Privacy vs a global passive adversary** →
  [`docs/SCOPE_PRIVACY.md`](../docs/SCOPE_PRIVACY.md) (base CEG/RET is insufficient;
  layer the Anonymous Tier).
- **Physical YubiKey / FIPS token security** and the **Yubico attestation PKI**
  (incl. the pinned root) — trusted.
- **The operator's host** — non-hostile: loopback endpoints, `0o600` software
  seeds, the node + `substrate_persist` keys all rest on host integrity; a rooted
  host compromises the node identity and can request (touch-gated) holder signs.
- **The distinct-human ceremony** — that A1/B1/C1 are three different people under
  independent custody is social/procedural; the code enforces distinct *keys*.

---

## 7. Known gaps & follow-ups

| Gap | Where | Tracking |
|-----|-------|----------|
| Infohazard gate not switched on end-to-end (read-path fan-out; consent lifecycle + interstitial UX). | §4.4, `src/safety/infohazard.rs` | **#180** umbrella → #181 producer (done), **#182/#183** lifecycle + UX, **#185** read-path fan-out |
| `substrate_persist` emitter is over-broad (any reserved prefix). Refinement = a narrower persist `identity_type` / per-prefix scope. | §3.5 / §4.3, `src/compose.rs` | substrate_persist narrowing (persist follow-up) |
| Live-majority moderation vote (the `moderate` duty gate stands in today). | §3.4, `src/safety/moderation.rs` | FSD-004 live-quorum vote (future) |
| Legacy `ensure_accord_family_anchor` throwaway key lingers in the pre-v13.3.0 assemble path. | §3.1, `src/accord.rs` | retire ensure_accord_family_anchor (low-risk) |
| Co-scrub display is unauthenticated at ingest — client must render target/scrubbers unmissably before cosign. | §3.3 / §4.2 | client cosign UX hardening |
| Two-holder compromise = trust-root capture (inherent to m-of-n; documented, not fixable above the threshold). | §3.1 / §3.3 | — |

---

*Companion server docs: [`FSD/SAFE_MESH.md`](SAFE_MESH.md) (the invariant claim +
its ceremony), [`docs/SCOPE_PRIVACY.md`](../docs/SCOPE_PRIVACY.md) (the privacy
residual). Substrate tiers linked in §0 — read those for primitive-level threats.*
