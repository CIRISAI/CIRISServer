# FSD — Mesh replication: consolidating the topology in edge (keys, consent, corpus, storage)

> **Status:** design (2026-07-03). Motivated by the admit-node / rooting field blocker:
> a scrub-signed key record produced on one node has **no path to reach the verifiers
> that must root it**. Root-causing that led to a full audit of *how records replicate*
> across the mesh. This FSD is the answer + the work plan.
>
> **One-line finding:** the replication **engine** already lives in edge and is correct;
> the replication **policy** is scattered in the server and is wired for exactly one
> record type (`Attestation`). Keys/rooting records — and four other kinds — do not
> replicate at all. The fix is to move the *policy* into a per-`EnvelopeKind` plane
> (still edge-owned), adopt a KERI-shaped discipline for key records, and add the one
> axis nobody has specified: **storage contention on owned nodes**.

---

## 1. Where replication logic lives today (audited, not assumed)

| Layer | Role | Verdict |
| --- | --- | --- |
| **edge** (`src/replication/`) | The anti-entropy **engine**: CRPL `Summary/Diff/Fetch/Deliver`, 13 `EnvelopeKind`s, `ReplicationRuntime`, `install_replication_routing`, the `ReplicationDirectory`/`bridge` apply-arms. | **Correct + centralized.** This *is* "all replication logic in edge" — for the mechanism. |
| **persist** | The **merge/admission authority** — `put_*`, R1/Q1 `monotonic_quorum`, content-addressed idempotent dedup, anti-rollback. | Correct. |
| **verify** | Signatures + **rooting** (`root_binding`, read-only — *requires* the row to pre-exist; never writes a key). | Correct, but read-only — **not a replication path**. |
| **server** (`compose.rs`, `replication_reconcile.rs`, `peer.rs`) | **Policy: which peers, which kinds.** Peer set derived from `consent:replication` CEG; kind **hard-coded to `Attestation`**. | **This is the scattered + wrong-shaped seam.** |

**What actually moves over the mesh today: only `EnvelopeKind::Attestation`.**
`compose.rs:1355-1361` builds every `ReplicationPeer` with `kind: EnvelopeKind::Attestation`
and nothing else. Edge supports 13 kinds; the server lights up one. Consequence
(confirmed by reading the code, four independent ways):

- **Key records do NOT replicate.** No `Key`-kind coordinator is ever spawned.
- Even if one were, **`bridge.rs:394` `list_keys` is cohort-scoped** — it advertises each
  *cohort member's own* key record (`lookup_public_key` over the peer set). It will
  **never** advertise (a) the node's **own** record (self ∉ its own consent cohort) or
  (b) a **third-party anchored** record (a row whose `scrub_key_id` = an accord holder).
  So the enumeration is the *wrong shape* for "publish my rootable record to my verifiers."
- Registration is only ever **point-to-point pull of the counterparty's own self-record**
  (`claim_remote`, `/v1/federation/peering`, `mesh_relay`) — never third-party fan-out.
- Rooting/announce is **read-only** — it needs the key to already be present. This is
  exactly the field blocker (`av=AV-42 rooting_not_rooted_at_steward`, later the anchor
  seed): a node cannot root a peer whose record it never received.

Also dark today: `Revocation`, `IdentityOccurrence`, `Family`, `Community`, and the v2
operational kinds (`Org`/`OrgMembership`/`PartnerRecord`). And the consent grant's
`attestation_prefixes: ["capacity:"]` is **recorded as intent but not enforced** — the
bridge replicates *all* cohort-touching attestations.

---

## 2. What the Constitution already mandates (the spec is ahead of the code)

Replication is a **first-class normative subsystem** ("CEG-native replication"); the
substrate is *forbidden* to invent merge policy (CC 5.3.2.3). The user's four axes map
almost 1:1 onto documented rules:

1. **By wire type — normative, the core axis.** Merge policy is a property *of the
   `subject_kind`*: `partner_record` → `monotonic_quorum` + `revision` anti-rollback;
   revocations → monotonic_quorum; ordinary attestations (incl. `consent:replication`,
   `capacity:*`, `health:*`) → plain `Attestation`. This is edge's `EnvelopeKind` table.
2. **By membership — `cohort_scope` is the master switch.** `self`/`family` **never
   federate** (structural, wire-enforced). In-group community members auto-replicate
   with **no per-peer object**. Out-of-group needs an explicit consent object (the
   CIRISServer→CIRISStatus `capacity:*` case is named in the text). **Key registration
   (`federation_keys`) IS the admission gate** — "the substrate gate that lets P's corpus
   admit G's replicated rows is G's key existing in P's `federation_keys`" (CC 3.3.7).
3. **By consent — `consent:replication:v1`**, a **unilateral directed** grant (G→P),
   pairs into a bilateral peering; it is the **auditable/revocable record of intent, NOT
   the admission check**. Governs *attestation prefixes*, not keys.
4. **By resource / storage contention — LARGELY ABSENT (the real gap).** Only *reactive*
   disk-pressure eviction exists (`EvictionSweeper`, holder 24h TTL, downweighting).
   **No pre-admission quota, no owner byte-budget, no who-pays.** An owner bounding what
   replicates onto their node *before it arrives* is specified nowhere.

**The load-bearing consequence:** the Constitution models **key propagation as an
admission/membership concern** (get G's key into P's `federation_keys`), **separate from
consent-gated *attestation* replication.** So a scrub-signed key record must ride the
**membership/registration** track — it must NOT be gated behind a `consent:replication`
attestation-prefix grant. The current code has taken neither track for keys.

---

## 3. How comparable meshes solve it (the patterns we adopt)

Every mature system replicates **different object types under different disciplines**
(KERI events vs receipts vs `rpy`; SSB feeds vs blobs; Matrix PDUs vs EDUs; IPFS blocks
vs IPNS pointers). CIRIS should too. The chosen models:

### 3.1 Key / rooting records → **KERI** (not CT-gossip, not SSB follow-graph)
A scrub-signed key record *is* a KERI establishment event + anchor receipt:
- **Accord anchor = witness quorum / TOAD.** A1/B1/C1 at 2-of-3 is exactly KERI's
  "accountable once M-of-N have receipted." The scrub-signature is the **receipt**;
  a record is rootable iff it carries a quorum-valid anchor scrub-signature.
- **The node publishes its OWN record** (controller publishing its KEL). Verifiers
  **pull-and-verify in-band**; push is only a notification.
- **`net.announce_ownership` is the OOBI** — an *untrusted* `key_id → Reticulum endpoint`
  introduction. This reframes the field blocker precisely: the announce is a **discovery
  prerequisite set on each node's own console**, never authority; authority is the
  in-band scrub-signature against the baked anchor. (Rooting already works this way.)
- **First-seen + duplicity refusal (watcher discipline):** a verifier records the
  first valid record for a `key_id` and refuses/flags any later conflicting one. This
  formalizes "a pending row can't be silently superseded" (the legacy-row pain that
  forced reseeds) — cheap and non-repudiable because everything is signed.

### 3.2 Membership + consent → **Matrix** (authorized push over a bounded set)
- **Owned/consented cohort = room membership**; **`consent:replication` = the join/auth
  event.** Accept a replicated object iff (i) source ∈ cohort AND (ii) it passes an auth
  check against a live consent record. Stronger than SSB (which has no authorization).
- Consent is a **monotonic BADA-ordered record that governs the rest** (like `server_acl`
  / NIP-65 relay lists): replicate consent first, then let it gate everything else.
  **Revocation = a newer consent object, not a delete** (avoids tombstone races).
- **Owner-bounded = flat authorized set (hops = 1).** Do **not** build SSB transitive
  friend-of-friend replication — the owner cohort is explicitly enumerated.

### 3.3 Storage contention → **IPFS pinning** (the absent 4th axis)
- **Identity / consent / config = always pinned** (small, identity-critical, durable).
- **Corpus = pin-on-consent, cache-otherwise.** A `consent:replication` object *is* the
  pin authorization; unpinned corpus received via relay is transient + GC-eligible under
  pressure. This gives the owner the "bound what lands on me" control that's missing.
- **Content-address the corpus** (CID-style) so dedup is free and a pin is a stable ref;
  copy SSB's **size cap** + **want/have** so a large object is *wanted-then-pulled*,
  never unsolicited-pushed (both a consent and a bandwidth control).

### 3.4 Transport over intermittent RNS → **δ-CRDT / Cassandra pairwise anti-entropy**
Edge's CRPL already *is* this (Summary → Diff/want → Deliver). Keep it. All CIRIS objects
are signed + monotonic/content-addressed ⇒ idempotent, commutative, associative merge ⇒
**duplicate/late delivery is harmless** (right property for a lossy radio). Refinements:
- On contact, exchange a **compact digest** per object-class (`{key_id → latest-seq/hash}`
  vector, or a Merkle root). **Equal → transfer nothing** — the single biggest radio win.
- Ship only deltas; a node back from downtime pulls one coalesced set, not a replay.
- **Reduce push to a tiny "I have newer X" notify**; the peer pulls + verifies on its own
  schedule.
- **Skip** the DHT / Kademlia, the consistent-hashing ownership ring, the CT STH-gossip
  apparatus, and transitive hops — all over-engineering for a small trusted enumerated
  cohort with a relay it already has.

---

## 4. Target design — one plane per `EnvelopeKind`, all policy in edge

The engine stays in edge; we move the **policy** (which kinds converge, and *what each
kind advertises*) out of the server's hard-coded `Attestation` and into edge as a
per-kind plane definition. The server's only remaining job is to hand edge the
**consent-derived cohort**; edge decides per-kind what to enumerate/merge.

| `EnvelopeKind` | Track (§2) | Enumeration (what a node advertises) | Merge |
| --- | --- | --- | --- |
| `Key` | **membership/registration** | **the node's OWN record + rooting-relevant held records** (KERI publish-own-KEL) — *not* cohort-members'-own | content-addressed + **first-seen/duplicity** |
| `Revocation` | membership | held revocations touching the cohort | `monotonic_quorum` (R1/Q1) |
| `Attestation` | **consent** | cohort-touching attestations **filtered to the granted prefixes** (enforce the intent) | plain, idempotent |
| `IdentityOccurrence` / `Family` / `Community` | membership | cohort rosters | per CEG 0.7 |
| corpus (content) | **pin-on-consent** | content-addressed, **want/have + size cap** | content-addressed dedup |

**The single change that unblocks rooting:** `Key` gets its own plane whose enumeration
publishes the node's *own* scrub-signed record (and any anchor/rooting records it holds),
converged across the consent cohort. That is the KERI shape and it is an **edge** change
(the bridge's `list_keys` is the wrong shape today), plus a **server** change to actually
run the `Key` plane instead of `Attestation`-only.

---

## 5. Work breakdown (by repo — keep the engine in edge)

1. **CIRISEdge** — the substantive change, so "all replication logic is in edge":
   - Add a `Key`-plane enumeration mode: advertise **self + held rooting records**, not
     cohort-members'-own (fix `bridge.rs:394` shape). Likely a new `ReplicationDirectory`
     enumeration variant or a per-kind cohort/selection callback.
   - Apply-side **first-seen/duplicity** for `Key` (refuse a conflicting record for an
     existing `key_id`; surface as evidence). Confirm persist's `put_public_key` merge
     already gives content-addressed idempotency; add the duplicity gate if not.
   - (Later) a `Corpus` plane with want/have + size cap + pinning hooks.
2. **CIRISPersist** — ensure `Key` merge is content-addressed-idempotent with first-seen
   semantics (mostly present via R1/Q1); expose a "pinned vs cache" flag for corpus rows
   (new — for the storage axis).
3. **CIRISServer** — stop hard-coding `Attestation`-only in `setup_peer_replication` /
   `replication_reconcile`: converge `Key` (+ `Revocation`, `IdentityOccurrence`,
   `Family`) over the consent cohort; enforce the consent `attestation_prefixes` filter
   (close the unenforced-intent gap). This is the smallest change and is what unblocks A/B.
4. **CIRISRegistry / Constitution (CEG)** — specify the **absent 4th axis**: the
   pin-on-consent + size-cap + owner-budget storage-contention primitive (the IPFS-pinning
   model), since replication resource rules must live in the canonical CEG, not be invented
   per-node by the substrate (CC 5.3.2.3). File as a CEG proposal.

---

## 6. Immediate field unblock (A/B rooting) vs the full plane

The full `Key` plane (§4/§5) is the right long-term fix and the one the user asked for
("all replication logic in edge"). For the **A/B/lapbuntu2 bridge right now**, the minimal
correct interim that does not add a new hack layer:

- **admit-node registers the scrubbed record as the node's OWN record locally** (run the
  card against each node with the portable holder YubiKey+USB), and the node's
  `/v1/federation/self-key-record` then serves the **scrubbed** record (`scrub_key_id`=A1)
  instead of the self-signed one. The existing point-to-point pulls (claim / peering /
  relay) then distribute a **rootable** record — because they already fetch "the peer's
  own self-record," which is now the scrubbed one.
- This is a stepping stone *toward* the KERI publish-own model (the node publishes its own
  scrub-signed record; verifiers pull-and-verify), so it is not throwaway. When the `Key`
  plane lands, the same record simply converges via anti-entropy instead of point-to-point.

**Recommendation:** ship the interim to unblock the seed, and build the `Key` plane in
edge as the durable design. Both write the *same* scrub-signed record; only the carrier
differs (point-to-point pull now → anti-entropy later).
