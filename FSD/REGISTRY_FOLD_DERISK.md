# De-risking the registry fold (Server 0.5)

> Pre-building, in CIRISServer at 0.1, the capabilities the `ciris-registry-core`
> fold needs at 0.5 — so the fold is mechanical. Most are **shared with the lens
> slice**, so building them now (for lens) de-risks registry. Scouted 2026-06-14
> on the triple persist v6.8.1 / edge v3.5.0 / verify v5.4.0.
>
> Companion: [`MISSION.md`](../MISSION.md) §1.5/§3, [`FSD/SERVER_1.0_PLAN.md`](SERVER_1.0_PLAN.md),
> [`FSD/LENS_TO_SERVER_MIGRATION.md`](LENS_TO_SERVER_MIGRATION.md), CIRISServer#1.

## 1. Steward key → m-of-N founder-quorum (the trust-root swap)

The shared vaulted steward key (registry-us + registry-eu held one secret — the
AV-14 single point of compromise) is **retired**, replaced by an **entrenched
2-of-3 founder-quorum** over the three `ciris-canonical` per-node keys. A node
gains a vote, never a verdict (MISSION §1.5; CEG §8.1.13.1.1 founder-subset eval).

**Built now: `src/quorum.rs`** (shared; the registry slice uses it at 0.5):
- `canonical_community(founders)` → the `InfrastructureCommunity` trust root
  (`community_key_id: "ciris-canonical"`, `cohort_subkind: infrastructure`,
  `admission_quorum_basis: founders`, `consensus_protocol: "quorum:2/3"`,
  `consensus_protocol_entrenched: true`) — `is_trust_root_conformant()` by
  construction.
- `verify_canonical_quorum(community, bytes, sigs)` → `QuorumPolicy::parse` +
  `verify_quorum_policy` (verify v5.4.0 `threshold` / `infrastructure_community`):
  strict-majority `2M>N`, declared N == founder roster, non-founder sigs don't
  count (anti-Sybil), hybrid Ed25519 + ML-DSA-65.
- `community_signing_bytes()` — domain-separated, member-order-independent.

Consumers re-root their pin from the steward fingerprint to `community_key_id:
"ciris-canonical"` (lens already pins the constant). `/v1/steward-key` becomes the
community/founder-roster publish. **Break-glass stays the 3 human accord keys
(CEG §9), hardware-rooted, NEVER on the fabric nodes — verifier-only.**

## 2. Accommodating registry's existing keys (adopt vs retire)

Same byte-identical adoption CIRISServer already does for lens (compose
`federation_signer` + the transport keystore). When CIRISServer replaces
registry-us/registry-eu:

| Key | Disposition |
|---|---|
| Steward **Ed25519 seed** (`ED25519_KEY_PATH`) | **ADOPT** byte-identical → `SealedEd25519Signer::adopt` (key_id preserved), TPM-sealed. Its role as *shared constitutional authority* is **RETIRED** → the 2-of-3 quorum. If literally shared us↔eu, split into per-node sealed identities. |
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
