# De-risking the registry fold (Server 0.5)

> Pre-building, in CIRISServer at 0.1, the capabilities the `ciris-registry-core`
> fold needs at 0.5 — so the fold is mechanical. Most are **shared with the lens
> slice**, so building them now (for lens) de-risks registry. Scouted 2026-06-14
> on the triple persist v6.8.1 / edge v3.5.0 / verify v5.4.0.
>
> Companion: [`MISSION.md`](../MISSION.md) §1.5/§3, [`FSD/SERVER_1.0_PLAN.md`](SERVER_1.0_PLAN.md),
> [`FSD/LENS_TO_SERVER_MIGRATION.md`](LENS_TO_SERVER_MIGRATION.md), CIRISServer#1.

## 1. Steward key → the accord quorum (the trust-root swap)

> **Re-cut 2026-11-09 (CIRISServer#537) under the steward's ruling of
> 2026-09-22: infrastructure does not vote.** Only the accord family is a
> quorum; a canonical node's OWNER sets its configuration. The founder-quorum
> reading below (kept, struck, as the record of what was built and why it was
> retired) gave each `ciris-canonical` node key a vote. Nodes have no vote.
>
> **What holds now:**
>
> - The trust-root swap is steward-key → **accord** quorum. The authority is
>   `humanity-accord`'s entrenched `quorum:M/N` over the holder roster
>   (`accord.rs::canonical_op_quorum_m` → `family_quorum_m`); the
>   `ciris-canonical` community is the conferred ROSTER the accord admits
>   serve nodes into, and its founders are the accord holders (CC 8.1.1,
>   rc10; `final_genesis.rs`). It is an audience, not a voter.
> - `src/quorum.rs` (the node-founder quorum) was deleted in 0.5.233 (#803)
>   on the "founders are the holders" ruling; it had no production callers.
> - A node serves the registry slice because the accord conferred
>   `infra:attest` on it — `src/registry_slice.rs` walks
>   `capability_roots_to_trusted_root(dir, me, me, infra:attest)` — never
>   because an operator set a flag. The owner's signed `config:slices.registry`
>   can only DECLINE a conferred slice.
> - `/v1/steward-key` serves the portable trust root (the baked
>   `GenesisBundle`, self-authenticating), not a node's own key and not a
>   founder roster (CIRISRegistry#133).
> - The Operational vs Structural quorum for `add-canonical` (#441) is a
>   question over the **accord holders**, open with the steward.
>
> **Retired reading (2026-06-14, not in force):**
>
> The shared vaulted steward key (registry-us + registry-eu held one secret — the
> AV-14 single point of compromise) is **retired**, replaced by an **entrenched
> 2-of-3 founder-quorum** over the three `ciris-canonical` per-node keys. A node
> gains a vote, never a verdict (MISSION §1.5; CEG §8.1.13.1.1 founder-subset eval).
>
> **Built now: `src/quorum.rs`** (shared; the registry slice uses it at 0.5):
> - `canonical_community(founders)` → the `InfrastructureCommunity` trust root
>   (`community_key_id: "ciris-canonical"`, `cohort_subkind: infrastructure`,
>   `admission_quorum_basis: founders`, `consensus_protocol: "quorum:2/3"`,
>   `consensus_protocol_entrenched: true`) — `is_trust_root_conformant()` by
>   construction.
> - `verify_canonical_quorum(community, bytes, sigs)` → `QuorumPolicy::parse` +
>   `verify_quorum_policy` (verify v5.4.0 `threshold` / `infrastructure_community`):
>   strict-majority `2M>N`, declared N == founder roster, non-founder sigs don't
>   count (anti-Sybil), hybrid Ed25519 + ML-DSA-65.
> - `community_signing_bytes()` — domain-separated, member-order-independent.
>
> Consumers re-root their pin from the steward fingerprint to `community_key_id:
> "ciris-canonical"` (lens already pins the constant). `/v1/steward-key` becomes the
> community/founder-roster publish. **Break-glass stays the 3 human accord keys
> (CEG §9), hardware-rooted, NEVER on the fabric nodes — verifier-only.**

## 2. Accommodating registry's existing keys (adopt vs retire)

Same byte-identical adoption CIRISServer already does for lens (compose
`federation_signer` + the transport keystore). When CIRISServer replaces
registry-us/registry-eu:

| Key | Disposition |
|---|---|
| Steward **Ed25519 seed** (`ED25519_KEY_PATH`) | **ADOPT** byte-identical → `SealedEd25519Signer::adopt` (key_id preserved), TPM-sealed. Its role as *shared constitutional authority* is **RETIRED** → the accord quorum (§1, re-cut 2026-11-09; was "the 2-of-3 quorum" of node keys). If literally shared us↔eu, split into per-node sealed identities. |
| Steward **ML-DSA-65 seed** (`MLDSA_KEY_PATH`) | **ADOPT** byte-identical (travels with the Ed25519 seed; the hybrid half). *(Follow-up: extend `federation_signer` to also adopt the PQC seed — today it adopts the Ed25519 seed; the PQC adoption mirrors it.)* |
| **Reticulum transport identity** (`CIRIS_REGISTRY_EDGE_IDENTITY_PATH`, 64B) | **ADOPT** byte-identical via `CIRIS_SERVER_RET_IDENTITY_PATH` → `BlobTransportKeystore` (dest hash preserved). Already wired. |
| JWT / mTLS / DB password | per-node operational; re-provision, not federation identity. |
| **HUMANITY_ACCORD accord-holder keys** (CEG §9) | **NEVER on the node.** Hardware-rooted on holders' devices; the node is verifier-only (2-of-3 check). Preserve verifier-only handling. |

DB-resident keys (`signing_keys` / `trusted_primitive_keys` / `partner_keys`) are
**public-only** — nothing private to migrate; the boot self-seed follows the
adopted seed.

## 3. CEG-RC5 peer-to-peer replication (the Spock replacement)

CEG is at **1.0-RC5** (wire frozen since RC1; RC5 is additive). Replication model:
*no cross-region byte moves outside a signed CEG envelope* — federation speaks
**CEG over Reticulum, not TCP/IP**; Postgres multi-master ("Spock") → **anti-entropy
of signed envelopes**. Merge intents are **declared per subject_kind** (§10.1.6):
`lww_skew_bounded`+`withdrawal_forward_only` (organization/org_membership),
`monotonic_quorum` (partner_record/revocations), content-addressed-idempotent
(keys/attestations/occurrences/families/communities). Two quorums:
steward-signature **admission** (verify) ≠ region **merge** (`quorum_weight`).
Partition-tolerant: stable-id grouping, not chain-walk.

**Two transport planes (verified in persist 6.8.1 / edge 3.5.0):**

- **App/message plane (lens traces).** `Edge::send(peer_key_id,
  AccordEventsBatch(..))` → RET → peer's `LensCore::attach_handler` (registered
  on `Edge::run`'s inbound dispatch) → `Engine::receive_and_persist`. Inbound is
  already wired in CIRISServer. **Note:** `AccordEventsBatch` is
  `Delivery::Ephemeral`, so `send_durable` returns `DeliveryClassMismatch` at
  runtime — the app plane is fire-with-response ingest, **not** store-and-forward.
  Durable, partition-tolerant corpus replication between nodes is the
  anti-entropy plane's job (below), not a durable app-plane send. The remaining
  app-plane work is the **outbound fan-out** (enqueue locally-captured batches to
  peer key_ids). Content-addressed dedup in `receive_and_persist` prevents gossip
  loops — **verified** by `tests/replication.rs` (re-delivery → 0 inserts, dedup
  conflict).
- **Replication/anti-entropy plane (registry-grade: keys/attestations/revocations/
  op-data — the actual Spock replacement).** `ReplicationRuntime::start(directory,
  transport, peers, cfg)` drives CRPL Summary/Diff/Deliver per `(peer, EnvelopeKind)`
  over the `FederationDirectoryReplicationBridge`. **GAP: `Edge::run` does NOT route
  inbound replication frames** — there is no `Edge::install_replication_routing` in
  v3.5.0. `Edge::run` *owns* the `Transport::listen` loop, so a headless
  composition root (where the operator doesn't own that loop) has no seam to feed
  into `ReplicationRegistry::route_inbound_bytes`; the runtime's own docs
  (`runtime.rs` §"Why no auto-routing") defer the helper to a follow-up. **Filed:
  [CIRISEdge#119](https://github.com/CIRISAI/CIRISEdge/issues/119)** — the blocker
  for the full registry-grade plane's Responder side.

**Two-node test — DONE: [`tests/replication.rs`](../tests/replication.rs)**
(`cargo test --test replication`, green on the triple). Proves the app-plane /
corpus spine across two **independent** `Engine`s: a `build_batch_bytes` CEG
envelope signed under node A's agent key → `receive_and_persist` at origin A
(insert + verify) → the SAME wire bytes at a *trusting* peer B (replicate +
verify against the cross-registered key — exactly what the `attach_handler`
inbound dispatch feeds `receive_and_persist`) → re-delivery to B is an idempotent
no-op (0 inserts + dedup conflict = **anti gossip-loop**) → an *untrusting* peer
C **rejects** the envelope (`Err UnknownKey` — the verify gate is key-bound, not a
rubber stamp; v6.8.1 rejects unknown-key traces outright rather than persisting
them unverified). The Reticulum transport hop is covered by edge's own round-trip
tests; the anti-entropy Responder awaits CIRISEdge#119.

## 4. Fold-capability superset (★ = shared with lens, build now)

1. ★ `/v1/identity` — six-key `LocalIdentityAggregate` (same shared-Engine path).
2. ★ `/v1/steward-key` → `community_key_id` re-root (§1; `quorum.rs`).
3. ★ Founder-quorum admission door (read-side already in lens `CanonicalPeerEnrollment`).
4. ★ CEG-native replication (§3) — the #58 Spock replacement; both slices ride it.
5. ★ Fabric-sibling CEG/RET wiring (#62): `compose_registry(&edge, &engine, &cfg)`
   mirrors `LensCore::attach_handler` on the **same shared Edge + Engine**.
6. ★ `FederationDirectory` reads over the shared Engine.
7. Registry-specific: gRPC trust surface (lookup/revocation/license/attestation),
   build-manifest/transparency, the write-side admission ceremony.

**The one non-mechanical seam:** registry-core wants a Postgres `Database` +
`HybridCrypto`; CIRISServer runs a SQLite `Engine` + a sealed-Ed25519
`HardwareSigner`. Resolving that impedance + the #76 co-bump (registry-core →
6.8.1/3.5.0/5.4.0; it's on the old 5.5.5/2.2.2/5.1.3 floor) is the only seam that
isn't a copy of an already-working lens pattern.

## 5. Fold status (2026-11-09, `fold/registry`, CIRISServer#537)

Read §4 items 2 and 3 through §1's re-cut: there is no founder-quorum door and
no founder-roster publish; `/v1/steward-key` serves the bundle.

The "one non-mechanical seam" above is resolved by **porting, not pinning**.
Registry-core's no-`standalone` fold surface (`fold.rs`, `fold_builds.rs`,
`fold_evidence.rs`, at CIRISRegistry `f04b149` / v4.1.0) needs no Postgres
`Database` and no `HybridCrypto`. It runs on the shared `Engine`. It is ported
into `src/registry/` at this repo's substrate triple, so there is no co-bump
and no second persist/edge graph. The sqlx/tonic half of registry-core is not
ported. Each of its live surfaces is rewritten onto the persist directory when
it is taken up (revocation, key lookup, partner, licensure), or waits on a
persist table (`/v1/verify/*-manifest` bytes, transparency witnesses, device
integrity).

| Increment | What | Where |
|---|---|---|
| Phase 1 | The role gate: conferred by the accord, declinable by the owner | `src/registry_slice.rs` |
| Phase 2a | `GET /v1/trust-root/bundle` (+ `/v1/steward-key`) in the CC 5.3.4 / registry wrapper | `src/trust_root_api.rs` (#830) |
| Phase 2b | CEG-native `/v1/builds`, mounted on conferred nodes only | `src/registry/builds.rs` |
| Deferred | `/v1/evidence/{suite}` (CC 3.1.5.5), the same door generalized: it cites Goal-side rows (CSD-130, #833/#834) and its reads walk every author kind, so it waits for a dimension-indexed read | — |
| — | `src/registry/` existing makes the release ladder's 0.6 boundary (`gate_registry_surface_present`) live. Whether the cut carrying it is 0.6 is the steward's call | `tests/release_gates/boundary.rs` |
| Later | Commons-blob holding of manifests between canonicals; the P-tier directory reads; licensure | — |
