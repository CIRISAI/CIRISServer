# FSD — CEG → Replication: the mechanistic admission model

> **Status:** ratified design (2026-07-24), from the full CEG-replication audit of
> edge v13.15.1 / persist v20.1.0 / verify-core v10.6.1 / server main.
> Companion to `FSD/MESH_REPLICATION.md` (2026-07-03, the *engine/policy split*)
> and `CIRISEdge FSD/REPLICATION_WIRE_FORMAT_V1.md` (the *wire format*). This doc
> is the missing third leg: **which signed CEG claim gates which kind, at which
> of the three gates, and how that is enforced by construction.**

---

## 0. The invariant

**CEG is everything.** State on a node changes **only** via a verified signed
claim (hybrid Ed25519 + ML-DSA-65, `HybridPolicy::Strict`) by a **known actor**
— a signer resolved against the node's *own registered directory*, never against
material the sender supplied — evolved by the CEG's own structural modifiers
(`withdraws` / `supersedes` / `delegates_to` / consent). Any state flow not
gated that way is a **classical edge**: a place where trust rides on transport
identity, TOFU, stored flags, caller-passed rosters, or bare FK existence
instead of post-quantum-assured authorship.

**Enforcement must be mechanistic, never disciplinary.** The model for this is
the serde edge closed in persist v20 (`EnvelopeCore` + the
`envelope_core_paths_bind_serde_names` binding witness): the contract lives in
**one typed place**, every consumer derives from it, and drift is a
**compile/test failure** — not something a reviewer has to remember. This FSD
specifies the same move for admission: a single declarative registry keyed on
the finite `EnvelopeKind` enum, exhaustively matched, exported as a hashed
manifest, witnessed by build-failing gates in every repo (the
`WIRE_VOCABULARY_KINDS.md` / `wire_vocabulary_gate.rs` pattern this repo
already ships).

---

## 1. The three gates (the undocumented architecture)

Replication is gated in **three independent places** — conflating them is how
every audit miss happened:

| Gate | Direction | Question | Where | CEG driver |
| --- | --- | --- | --- | --- |
| **ADVERTISE** | Initiator (pull) | *Which peers do I sync with, for which kinds?* | server `peer.rs::replication_peers_from_consent` → edge coordinators | signed `consent:replication:v1` SCORES attestations (per-peer, per-kind) |
| **SERVE** | Responder | *Do I answer this peer's Summary/Fetch?* | edge `replication/registry.rs`, `bridge.rs` | **none by design** for public signed envelopes (registry.rs:46-48) — **except** `trace:*` attestations, recipient-gated by `peer_has_serve_capability` (bridge.rs:883-942: accord `has_effective_role` ∧ `capability_roots_to_trusted_root`) |
| **APPLY** | Inbound | *Do I admit this record into my store?* | edge `apply_*` → persist `put_*` (edge does **no** verification; persist is the admission authority) | per-record hybrid verify vs the **registered** key — where implemented (see §2) |

Consequences that must be understood together:

- `consent:replication` gates **only** the pull direction and `trace:*` serving.
  Every other kind is served to **any peer that can establish a link and get
  attributed a `source_key_id`**. That is deliberate (public signed envelopes) —
  but it means the SERVE gate's entire trust reduces to (a) the integrity of
  transport attribution and (b) the APPLY gate verifying every record. Findings
  E3, E1/E2/E4 below break exactly those two premises.
- Advertise **selection** is CEG-clean everywhere: persist
  `namespace::projection_for` resolves each record's own signed fields
  (bridge.rs:775-802); `self_provider`/`local_key_id` use only owned material;
  the peer set comes from signed consent claims (peer.rs:326-349).
- APPLY is where the classical edges cluster: several `put_*` paths admit on
  FK-existence alone.

---

## 2. The crystal table — every kind, its CEG gate, its verdict

All 14 `EnvelopeKind`s (edge `replication/protocol.rs:81`). "Apply verify" =
what persist actually checks on the replicated-inbound path (file:line at the
audited pins). ✅ = fully CEG + PQ. ⚠/❌ = classical edge (§3).

| # | Kind | Advertise driver | Serve gate | Apply-side verification | Verdict |
|---|---|---|---|---|---|
| 1 | `IdentityOccurrence` | SelfOwn (publish-own) | public | hybrid Strict + `signer_acts_for` vs registered pinned key, fail-closed (persist admission.rs:1487/1594/1607) | ✅ |
| 2 | `IdentityOccurrenceRevocation` | Global (tombstone) | public | hybrid 1-of-1 + `signer_acts_for`, fail-closed (admission.rs:1676/1759/1769) | ✅ |
| 3 | `TransportDestination` | SelfOwn | public | hybrid + `signer_acts_for`; provenance read only from the **verified** envelope (admission.rs:1808/1898/1930/1941 — closes edge#337) | ✅ |
| 4 | `Attestation` (federation-tier) | per-record projection from dimension / cohort_scope / type (bridge.rs:775-802) | **`trace:*` recipient-gated**; others public | hybrid Strict vs registered key, fail-closed (tier_ingest.rs:218/232) | ✅ integrity; ⚠ serve gate keys on classical attribution (E3) and the capability walk trusts stored rows (E5) |
| 5 | `Key` | SelfOwn | public | **split**: self→anchor *upgrade* = hybrid Strict + `owner_of` (register.rs:259/556); **fresh insert = NONE — TOFU** via `put_public_key` (engine.rs:2499) | ❌ E2 |
| 6 | `Revocation` | Global | public | **NONE** — FK-existence only; scrub sig stored, never verified; no R1/Q1 quorum on this path (memory.rs:2309, sqlite.rs:3631) | ❌ E1 |
| 7 | `Family` | Cohort | public | **NONE** — FK-only (memory.rs:2706) | ❌ E4 |
| 8 | `Community` | Cohort | public | **NONE** — FK-only (memory.rs:2964) | ❌ E4 |
| 9 | `FamilyMembershipRevocation` | Global | public | **NONE** (memory.rs:3387) | ❌ E4 |
| 10 | `CommunityMembershipRevocation` | Global | public | **NONE**; insert rotates the DEK epoch (memory.rs:3424) | ❌ E4 |
| 11 | `LocationProof` | Cohort | public | **NONE** — FK-only (memory.rs:3739) | ❌ E4 |
| 12 | `Organization` / 13 `OrgMembership` | bulk list-since | public | hybrid role-authority — but vs a **caller-passed** roster (operational.rs:417) | ⚠ E9 |
| 14 | `PartnerRecord` | bulk list-since | public | hybrid M-of-N — **caller-passed** steward roster (operational.rs:464) | ⚠ E9 |

PQC is **not deferred** on any path that does verify — every verifying path pins
`HybridPolicy::Strict` / `RequireHybrid`. The failures are paths that don't
verify at all, or that verify against the wrong root of trust.

### 2.1 Why 14 wire kinds carry the entire 95-family namespace (validated)

The CC 3.1 namespace — **95 prefix families at leaf granularity, 83 normative**
— is vendored into persist as `federation/namespace/namespace_registry.json`
at **CC 1.0-RC2**, pinned by `source_sha256` + the
`vendored_manifest_matches_the_pinned_cc_cut` gate test (the manifest-witness
pattern of §4.2 already in production for the constitution cut itself).

Every one of the 95 families is a **claim-dimension prefix** (`accord:*`,
`attestation:*`, `trace:*`, `consent:*`, `provenance:*`, …) — i.e. a namespaced
signed claim living in `federation_attestations`. **All 95 ride
`EnvelopeKind::Attestation`.** This is the evolving-claims model doing its job:
a new object type is a new *dimension*, never a new wire kind — adding a family
requires zero wire-protocol changes, and the APPLY gate (hybrid Strict,
tier_ingest) covers all 95 uniformly. Which is also why **E5 is a hole under
all 95 families at once** — the local-tier exemption bypasses the one gate the
whole claim namespace shares.

Per-family differentiation happens where it belongs, not on the wire:

- **Emit authority** — `namespace::authority_for(dimension)` resolves the CC 3.4
  reserved-prefix rule from the vendored registry (longest-prefix wins; 24
  reserved families, e.g. `accord:*` = accord_holder-only,
  `provenance:build_manifest:*` = AccordCoScrub like a canonical). Unknown
  dimensions default to `ProducerSteward` — deliberately open claim space; the
  write-path reserved-prefix admission gate is the enforcement point.
- **Advertise projection** — per-record from the claim's own signed
  `dimension` / `cohort_scope` / `type` (bridge.rs:775-802).

The other **13 kinds are not namespace entries** — they are the typed
non-claim planes whose *merge semantics* differ (key PoP + quorum revocation,
occurrence forward-secrecy, roster LWW, partner monotonic-fail-secure,
transport mutable/disposable). Kinds exist per merge discipline; families exist
per claim meaning. 14 kinds ↔ 95 families is not a compression trick — it is
the CEG working as designed.

---

## 3. The nine classical edges (ranked, with mechanistic closures)

| ID | Edge | One-line attack | Mechanistic closure |
|---|---|---|---|
| **E1** | `put_revocation`: revocation admitted with **no signature check** (wire-reachable) | any linked peer forges `{revoked_key_id: victim, revoking_key_id: any}` → targeted de-peer / trust DoS | registry row: hybrid-verify scrub sig vs `revoking_key_id`'s **registered** key + the R1/Q1 quorum the protocol doc already advertises (protocol.rs:89) |
| **E2** | Fresh-key **TOFU**: replicated `Key` insert bypasses `verify_key_registration` (PoP lives only on the local-register path) | gossip a self-consistent fake key for a victim `identity_ref` → later attestations by it *verify* | registry row: run the hybrid PoP gate on the replicated insert path too |
| **E3** | Transport attribution is **Ed25519-only and advisory-spoofable**: `source_key_id` derived from link identity vs `RootedPeer` with no `provenance`/`owns_key` check (reticulum.rs:4254-4262); advisory admits (CC 3.3.6.2) verify the announce only against its **own claimed** pubkey | announce a serve-capable victim's `federation_key_id` while the victim isn't currently Rooted → be **served their `trace:*` corpus**; plus the honest path is quantum-fragile | newtype gate: `source_key_id` constructible **only** from `provenance == Rooted ∧ owns_key`; make the announce attestation **hybrid** (add the ML-DSA half over the binding) |
| **E4** | `put_family` / `put_community` / both membership-revocations / `put_location_proof`: **no signature verification**, FK-only | forge a roster, forge a membership *removal* (community removal rotates the DEK = forward-secrecy eviction DoS), forge a location proof | registry rows: hybrid vs the declared signer's registered key — exactly what the occurrence plane already does |
| **E5** | **Local-tier exemption poisons the trust-root walk**: `put_attestation` skips all verification for `tier=local` (tier_ingest.rs:124) and `trust_root_valid` / `capability_roots_to_trusted_root` / `owner_of` walk rows with **no tier filter, no re-verify** (admission.rs:3346, trust_root.rs:208/349) | a local-tier `delegates_to` / root self-charter silently counts in the capability gate the `trace:*` serve gate depends on | chokepoint forces wire admits to federation-tier; tier-filter the walks (or re-verify at walk time) |
| **E6** | Server auto-consents to + transport-roots the **baked canonical** with no owner gate, no re-verify (`prime_canonicals`, federation_delivery.rs:469/528; `prime_trusted_peers` trusts a stored `binding_provenance` flag, compose.rs:1506) | poisoned seed/DB row → node auto-consents its corpus to an attacker key and dials traces to their dest | route `prime_canonicals` through the same `require_owner_bound` gate as the API path; re-verify the canonical's accord-scrub; derive rooting from a **verified announce**, never a stored flag |
| **E7** | Consent **read** path never re-verifies grant sigs and **ignores revocation** (`TODO(consent revocation)`, peer.rs:320-345) | an injected store row replicates the corpus to an attacker; a **revoked peer keeps receiving forever** — breaks nuclear-un-trust | consent peer-set becomes a **projection maintained by the DRY projector** with `withdraws`/`supersedes` folded in (§4.3) — the read becomes a trivial SELECT of already-verified, already-revocation-filtered state |
| **E8** | MLS Welcome **inline-pk TOFU** on directory miss (welcome_wrap.rs:178-181; `verify_inline_match` defaults true; ML-DSA-only single-alg) — CIRISEdge#331 | forge a group-Welcome inviter identity on any cold-start directory miss | flip the fallback to `InviterUnknown`; require directory resolution (typed: inviter key must be a directory-resolved value, not sender bytes) |
| **E9** | Operational kinds verify against a **caller-passed roster** (operational.rs:417/464) — genuine hybrid crypto, wrong root | ops misconfiguration or a caller deriving the roster from untrusted input collapses the gate | persist resolves rosters from its **own** `federation_keys` directory; the passed-slice parameters go away |

---

## 4. The cure: one Registry-of-Record (the single DRY object)

This is the same object as the CIRISPersist#501 projection cure — **admission
policy, projection fan-out, advertise policy, and serve gate are four columns
of the same row**, keyed on the finite kind. One registry, one chokepoint, in
persist (the admission authority):

```rust
/// ONE row per EnvelopeKind. Exhaustive match — adding a kind without
/// declaring its policy is a COMPILE failure (the serde-edge move).
struct KindPolicy {
    /// APPLY: what must verify before the row exists. Never `None` for a
    /// wire-reachable kind. Roots of trust are *variants*, so "verify
    /// against sender-supplied material" is unrepresentable:
    admission: Admission,      // HybridStrict { signer: RegisteredKey | RevokingKey
                               //   | QuorumFromDirectory { m, of } , pop_on_insert: bool }
    binding:   SignerBinding,  // SelfOwn | OwnerOf | SignerActsFor | StewardRoster
    tier:      WireTier,       // FederationOnly (wire admits can never claim local tier)
    /// The #501 fan-out: every projection this kind maintains, run
    /// IN THE SAME TRANSACTION as the source write (improving on the
    /// trust plane's post-commit hooks):
    projections: &'static [Projection],
    /// ADVERTISE: how the record projects into peers' pull sets:
    advertise: ProjectionPolicy, // SelfOwn | Global | Cohort | PerRecord
    /// SERVE: responder gate:
    serve: ServeGate,            // Public | RecipientGated
}

/// The ONLY wire-reachable admission entrypoint. The per-kind `put_*`
/// become internals unreachable from replication:
fn admit_replicated(kind: EnvelopeKind, envelope: &[u8]) -> Result<Admitted>
```

### 4.1 Why the registry is CODE, not a table

A policy **table** would itself be mutable state — a new classical edge (who
writes the policy rows? verified how?). Policy is code on the closed enum,
changed only by reviewed commit, and pinned cross-repo by manifest hash
(§4.2). *Namespace properties already work this way* (`namespace::
projection_for`) — the registry generalizes that module; **no new
namespace-property tables are needed.**

### 4.2 The manifest + cross-repo witnesses (the wire-vocabulary pattern)

- **persist** exports the registry as a canonical manifest:
  `REPLICATION_POLICY_MANIFEST` (JCS bytes) + `REPLICATION_POLICY_HASH`
  (sha256 const), exactly like `ciris_edge::WIRE_VOCABULARY_HASH`.
- **edge** pins persist's hash in a gate test AND exports its own
  serve/advertise manifest (the responder half it owns) the same way.
- **server** pins **both** hashes in `tests/release_gates/` (beside the
  existing `wire_vocabulary_gate.rs`).

Any repo drifting its half of the contract → the other repos' builds fail.
Two-surface drift becomes structurally impossible across the whole triple.

### 4.3 The non-registry closures (typed gates, same philosophy)

- **edge (E3):** `SourceKeyId` newtype constructible only from a peer entry
  with `provenance == Rooted ∧ owns_key` — attribution can't be fabricated
  from an advisory admit because the type can't be built from one. Announce
  attestation goes hybrid (ML-DSA half added to the binding).
- **edge (E8):** inviter key type = directory-resolved only; inline fallback
  becomes `InviterUnknown` (CIRISEdge#331).
- **server (E6):** `prime_canonicals` routes through the owner-bound gate the
  API path already has; rooting derives from a verified announce, never a
  stored provenance flag.
- **server (E7):** dies as a side-effect of §4 — the consent peer-set becomes a
  persist **projection** maintained by the DRY projector (claims + `withdraws`
  + `supersedes` folded mechanistically, per the CEG's own structural
  modifiers). This is the *one new persist table* this design needs, and it is
  a projection (derived, rebuildable), not a new source of truth.

### 4.4 What this buys, by construction

- A kind **cannot** be admitted unverified: `admit_replicated` is the only wire
  entrypoint and its match is exhaustive — no policy row, no compile.
- A verification **cannot** target sender-supplied material: the trust-root
  variants don't include one.
- A projection **cannot** be forgotten at a write path: one chokepoint fans out
  to all of them, in-transaction (#501).
- A repo **cannot** drift its half of the contract: manifest-hash witnesses
  fail the build (§4.2).
- A revoked consent **cannot** keep replicating: revocation is folded into the
  projection the reconciler reads, not a TODO at a call site.

---

## 5. Work plan (issue map)

| Repo | Issue | Ask | Closes |
|---|---|---|---|
| **persist** | **CIRISPersist#502** (admission) + **#501** (projection) | The Registry-of-Record: `KindPolicy` + `admit_replicated` chokepoint (the single DRY object, both halves); admission rows for Revocation / fresh-Key-PoP / Family / Community / membership-revocations / LocationProof; tier-filter the trust-root walks; roster-from-directory for operational kinds; consent-peer-set projection; manifest + hash export | E1 E2 E4 E5 E9, E7 (substrate half), #501 |
| **edge** | **CIRISEdge#393** (E3) + **#331** (E8) | `SourceKeyId` Rooted∧owns_key gate + hybrid announce; Welcome directory-required; pin persist's policy hash + export serve/advertise manifest | E3, E8, drift |
| **server** | **CIRISServer#318** | `prime_canonicals` owner-gate + verified-announce rooting; `peer.rs` reads the consent projection; pin both manifest hashes in release gates | E6, E7 (read half), drift |

> The trace-pipeline unblock is the first slice of the persist object (#501 `trace_events`
> projection + #502 skeleton + E5), landing under the current freeze. Everything else
> sequences on the same object afterward.

### 5.1 Adoption status (2026-07-25)

Substrate shipped **all** asks: **persist v21.1.0** (#502 admission Registry-of-Record;
#501 `trace_events` projection is now automatic inside `put_attestation`; #504 signed
since-cursor reads for the 5 keyless planes) + **edge v14.0.0** (#393 E3 +
`serve_policy` manifest). Verify stays v10.6.1.

Server adopted and green (188 lib tests, clippy clean, both drift gates pass):

- **E4** — `SignedFamily` grew `authority_key_id` + hybrid scrub (compile-caught). `family.rs::create_family` → `put_family_local` (its sole caller entrenches the keyless HUMANITY_ACCORD constitutional family — persist's designated trusted-local path); `accord.rs::signed_family_from_envelope` leaves the authority scrub empty because its consumer `supersede_family_with_quorum` is quorum-gated (the ≥M cosignatures are the authority, the single scrub is not verified there).
- **E7 (read half)** — `peer.rs::replication_peers_from_consent` now delegates to persist's `list_consent_peers` (revocation folded via `withdraws`/`supersedes`); the former hand-rolled `presence == active` reader — and its `TODO(consent revocation)` — are deleted. Restores nuclear-un-trust for every caller (reconciler / holonomic / compose).
- **Drift gate** — `tests/replication_policy_gate.rs` pins both `REPLICATION_POLICY_HASH` (`351912ea…`) and `SERVE_ADVERTISE_POLICY_HASH` (`79f5c63a…`).

Still pending (server-owned, needs direction): **E6** — `prime_canonicals` owner-gate + verified-announce rooting (#318). This is boot-trust hardening, not substrate adoption, so it is held for an explicit decision rather than bundled into the pin bump.

Sequencing: the persist registry lands first (it is the admission authority and
the #501 fix rides the same object); edge/server witnesses adopt on the next
pin. Until then, the ✅ planes (occurrence / occurrence-revocation / transport /
federation-tier attestation integrity) are the only ones whose replicated state
carries post-quantum assurety — treat every ⚠/❌ row above as untrusted input.
