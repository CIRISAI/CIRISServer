# FSD — The Safe Mesh (what it means, and why v0.5.30 is the floor)

> **Status:** REMEDIATED (2026-06-21). A red-team review (§8) refuted the original
> v0.5.30 claim; the blockers were then fixed and re-verified (§9). **B1, B3, B4, N1,
> N2 are CLOSED; B2 is mitigated and its full closure is gated on G2 (the verify
> genesis bake) + latch hardening.** Net: the code floor is essentially complete; the
> remaining path to the ceremony is G1→G2→G3 (§6) with the B2 latch/continuity
> hardening landed alongside G2. §3/§5 are the original claim; **read §8 (findings)
> then §9 (remediation).**
>
> This FSD defines "safe mesh", states the invariants that make a mesh safe, maps each
> to the code that was *intended* to satisfy it, and is explicit about what is NOT yet
> done (the operational ceremony + the verify genesis bake) before 0.6 mints the
> canonical mesh.
>
> Audience: the maintainers deciding whether to run the genesis ceremony and cut 0.6.
> This document is written to be **challenged** — every invariant cites the module
> that implements it so a reviewer can verify or refute the claim against real code.

## 0. The one-sentence definition

> **A *safe mesh* is a federation that cannot be brought into persistent, self-
> bootstrapping existence (a canonical mesh) before humanity holds an enforceable,
> distributed, hardware-custodied kill-switch over it.**

Concretely: we refuse to bake `CANONICAL_BOOTSTRAP_PEERS` and cut 0.6 (+registry,
which makes the mesh self-seeding) until a verified **2-of-3 human** authority can
**halt every node** in a way **no operator, steward, or Wise Authority can override**,
and until the keys that wield that authority are under **genuine two-factor,
distributed-human custody** (no single person, and no software-only key, can halt or
*prevent* a halt).

This is a **floor, not a ceiling**: it is the *minimum* that must be true before the
mesh becomes hard to switch off. It is deliberately conservative — the cost of
getting it wrong is an un-haltable federation.

## 1. The two trios (do NOT conflate them)

The safe-mesh genesis mints **two orthogonal trios**, on two orthogonal trust roots:

| | **The canonical-trio (NODES)** | **The HUMANITY_ACCORD holders (HUMANS)** |
|---|---|---|
| What | 3 fabric **nodes** that seed the mesh | 3 **humans** who hold the kill-switch |
| Trust root | infra / `CANONICAL_BOOTSTRAP_PEERS` (baked at 0.6) | constitutional / `humanity_accord_genesis()` (baked in verify) |
| Identity | node federation keys (derived `<label>-<fp>`) | `accord_holder` keys under FIPS+USB custody |
| Cardinality | 3 nodes (seed + 2 registry anchors at 0.6) | 3 primary SEATS + 3 vaulted spares = 6 keys / 6 USB / 3 people |
| Authority | *runs* the mesh | can *halt* the mesh; cannot run it |
| Governs | availability / discovery | existence / kill-switch (CC 4.2.1) |

A node being canonical (infra trust) grants it **no** kill-switch power. A human
holding an accord seat grants them **no** node/infra authority. **Conflating the two
is the central design error this FSD exists to prevent** — the kill-switch must not be
exercisable by whoever happens to run infrastructure, and the mesh must not depend on
the kill-switch holders to operate.

"**Mint the 2 trios**" (the operator's phrase) = run the genesis ceremony that
establishes *both*: the 3 accord-holder humans (now) and the 3 canonical nodes (at 0.6).

## 2. The safe-mesh invariants

A mesh is safe iff ALL of these hold. Each is a falsifiable claim.

- **I1 — Enforceable halt.** A verified 2-of-3 `CONSTITUTIONAL` accord invocation makes
  a node *stop operating* — not pause, not degrade-with-override. It is fail-secure.
- **I2 — Irreversible-by-operator.** Once halted, no operator/steward/WA restart brings
  the node back. The only way back is a verified 2-of-3 `lifecycle:active` **plus** ≥1
  original-genesis seat.
- **I3 — Mesh-wide propagation.** A halt reaches all reachable peers *before* the
  honoring node goes dark, so the kill spreads even as nodes terminate.
- **I4 — One-seat-per-human.** The 2-of-3 cannot be satisfied by one human's two keys.
  A vaulted spare is not a live seat; quorum counts distinct humans, distinct keys.
- **I5 — Hardware-custodied authority.** An accord holder key is only admitted with a
  verified FIPS hardware-custody attestation (YubiKey PIV chain → pinned Yubico root) +
  the portable two-factor key mode (FIPS YubiKey + USB-wrapped ML-DSA, touch+PIN). A
  software-only key cannot hold the kill-switch.
- **I6 — No trust-on-first-use recognition.** A node that was NOT at the ceremony
  recognizes the authoritative roster + quorum from a *pinned* root, never by fetching
  it from a peer.
- **I7 — Post-quantum + distinct-key threshold.** Every authority signature is hybrid
  (Ed25519 + ML-DSA-65); the threshold verifier counts distinct keys and rejects a key
  occupying two seats.
- **I8 — Growable / recoverable governance.** Seats can be superseded / recovered /
  the family grown (3→5, quorum 2/3→3/5) under a quorum-authorized, anti-replay,
  one-seat-preserving membership change — without re-keying or a redeploy.

## 3. How v0.5.30 satisfies each invariant (the claim, with code)

| Inv | Mechanism | Where |
|---|---|---|
| I1 | `POST /v1/accord/message` → verify 2/3 CONSTITUTIONAL → `latch_halt` (disk latch) → process exit 42; startup `check_halt_gate` refuses to boot while latched | `src/accord.rs`, `src/accord_halt.rs` |
| I2 | `accord reactivate` clears the latch ONLY on a verify-native `lifecycle:active` proof meeting the current M-of-N quorum **AND** ≥1 ORIGINAL (genesis version-1) seat; `rm` demoted to non-conformant break-glass | `src/accord_reactivate.rs`, `src/accord_halt.rs` (`check_halt_gate` msg) |
| I3 | replicate-to-all-peers-FIRST, then latch + terminate (seen-set loop-stop) | `src/accord.rs` (the message/invocation halt path) |
| I4 | kill-switch roster = the LIVE family SEATS (`family::active_threshold_roster`), NOT every `accord_holder` row; a registered spare is not a seat | `src/accord.rs` (`accord_roster`), `src/family.rs` |
| I5 | `register_holder` routes through `Engine::register_federation_key` (persist refuses `SoftwareOnly`) + verifies `custody_attestation` against the **pinned** Yubico Attestation Root 1; provisioning uses `UsbWrappedMlDsa65Signer` + FIPS YubiKey (CIRISVerify#91/#62) | `src/accord.rs`, `src/accord_provision.rs`, `src/accord_custody.rs`, `src/accord_pki/` |
| I6 | cold-start recognition resolves the roster/quorum from the BAKED `humanity_accord_genesis()` against pinned holder keys, never a peer | `src/accord.rs` (`resolve_kill_switch_roster`), verify `accord_genesis` |
| I7 | `verify_invocation` / `verify_threshold_signatures` over hybrid sigs; verify rejects duplicate member key / duplicate pubkey | verify `humanity_accord`, `threshold`, `accord_genesis` |
| I8 | `POST /v1/accord/family/{change/envelope,supersede,history}` → persist `supersede_family_with_quorum` (re-verifies ≥M prior-roster cosigs + anti-replay + one-seat IN THE SUBSTRATE) | `src/accord.rs`, `src/family.rs`, persist v9.10.0 cohort governance |

The substrate floor under all of this: **edge v6.3.0 / persist v9.10.0 / verify family
v6.11.0**, single-version across both the lens node (ciris-server) and the status node
(ciris-status v0.3.5).

## 4. Threat model — what the safe mesh defends against

In scope (the floor must hold against these):
- **A captured operator / host.** Root on a node, or the whole deploy, must NOT be able
  to keep a halted node running, nor halt the mesh alone (no software key, no single seat).
- **A captured infra trust root.** Whoever holds `CANONICAL_BOOTSTRAP_PEERS` / runs the
  registry nodes must NOT thereby be able to halt or un-halt (I1/I2/I4 are on the
  *human* trust root, not the node one).
- **A rotated/captured current roster.** A fully rotated roster must NOT be able to
  resurrect a node the *founding* humanity halted (I2's original-genesis-seat floor).
- **A single malicious holder.** One holder, even with their spare, cannot reach 2/3 (I4).
- **A harvest-now-decrypt-later adversary.** PQC hybrid on every authority sig (I7).
- **TOFU roster substitution.** A peer cannot feed a fresh node a fake roster (I6).

Explicitly OUT of scope for the *floor* (acknowledged, not solved here):
- Coercion of ≥2 of the 3 humans simultaneously (a 2/3 social-trust assumption — the
  cardinality/threshold choice is the mitigation, not a cryptographic one).
- Physical compromise of ≥2 FIPS tokens **and** their paired USB halves **and** PINs.
- Availability attacks on the *running* mesh (that is 0.6+ registry/discovery hardening,
  not the kill-switch floor).
- Supply-chain compromise of the substrate crates themselves (mitigated separately by
  pinned tags + the build-manifest path, not by this FSD).

## 5. Why we believe v0.5.30 **is** the floor

1. Every invariant I1–I8 has a concrete, merged implementation (§3) with tests
   (`tests/accord.rs`, `examples/qa_runner` 36/36 incl. `run_ceremony`, the guard tests
   in `accord_halt`/`accord_reactivate`).
2. The kill-switch is **enforceable, not merely verifiable** — the disk latch + startup
   gate make "halt" a property of the node process, not a report (I1/I2).
3. The keys are under **real** custody, validated on **real** FIPS hardware
   (CIRISVerify#91/#62 closed + validated on a YubiKey 5 FIPS), not a software promise (I5).
4. The recognition root is **no-TOFU** and the recovery path is **continuity-bound** to
   the original humanity (I6/I2).
5. The whole surface is **substrate-native** (the one-seat + M-of-N + anti-replay
   invariants are enforced in persist/verify, not hand-rolled in this repo) — so the
   guarantees do not depend on app-layer discipline (I4/I7/I8).

## 6. What is NOT done yet (the gates between here and 0.6)

The **code** floor is claimed complete. The **operational** floor is not:

- **G1 — Run the genesis ceremony.** 3 humans × {primary, spare} provision on real
  hardware (6 FIPS YubiKeys + 6 USB keys), register holders, assemble the 2/3-founder
  family genesis. The desktop wizard + `qa_runner run_ceremony` are the reference; this
  has been exercised software-only end-to-end but **not yet run for real**.
- **G2 — Bake the genesis into verify.** `humanity_accord_genesis()` returns `None`
  today (`HUMANITY_ACCORD_GENESIS_JSON = ""`). The assembled ceremony object must be
  pasted into verify (CIRISVerify#107) and a verify release cut, so cold-start nodes get
  the no-TOFU recognition root (I6). **Until then I6 is satisfied only for nodes that
  hold the entrenched persist family, not for fresh cold-start nodes.**
- **G3 — Mint the canonical-node trio + bake `CANONICAL_BOOTSTRAP_PEERS`.** The 3 seed/
  registry nodes (0.6 work) and the baked const — the act that makes the mesh
  self-bootstrapping. **This is the step the entire floor gates.**

**Sequencing is load-bearing:** G1 → G2 → (only then) G3. Cutting 0.6 (G3) before G1+G2
would bootstrap a canonical mesh with no live, recognized kill-switch — exactly the
state "safe mesh" forbids.

## 7. Honest open questions for review (challenge these)

- Is `accord reactivate` the right **and only** recovery surface, or does the disk-latch
  break-glass (`rm`) leave an operator-override path that violates I2 in practice?
- Does the halt **replicate-before-terminate** (I3) actually reach peers under realistic
  partition/timing, or can a node die before propagation completes?
- Is "the LIVE family SEATS" (I4) truly the only quorum source on every path
  (verify-invocation, message, concur), with no residual `accord_holder`-row counting?
- Does cold-start recognition (I6) fail **closed** in every branch when the baked genesis
  is present but holder keys aren't yet pinned, and is the persist-family path equally
  no-TOFU?
- Is anything in the kill-switch path still hand-rolled in this repo rather than enforced
  by persist/verify (a place where app-layer drift could weaken an invariant)?
- Are there capabilities a node gains at boot (holonomic swarm, replication, config) that
  should be **gated behind** a live accord but currently are not?

If the answers hold, v0.5.30 is the safe-mesh floor and G1–G3 may proceed in order. If
any fail, that gap is a blocker before the ceremony.

## 8. Red-team review outcome (2026-06-21) — this REVISES §5

A four-agent adversarial review (one per invariant cluster, each tasked to *refute*)
read the merged v0.5.30 code + the pinned substrate (verify v6.11.0, persist v9.10.0).
Result: **the code floor is NOT complete.** I6 (no-TOFU recognition), I7 (PQC-hybrid +
distinct-key), and I8 (governance/membership change) hold as implemented. The
following gaps were found and verified against source.

### Ceremony BLOCKERS (must fix before minting the trios)

- **B1 — CRITICAL (I5): the FIPS custody floor is bypassable.** `register_holder`'s
  `custody_attestation` is `#[serde(default)] Option` (`src/accord.rs:~363`); when
  absent the code admits the holder anyway (`else => Null`, `src/accord.rs:~425`). The
  always-on substrate gate (`register_federation_key` → persist `HardwareAttestationPolicy`)
  only refuses `SoftwareOnly` and accepts *any* other hardware type (Android StrongBox,
  TPM, …) from a caller-asserted, chain-unverified `attestation_evidence` field that is
  *disjoint* from the YubiKey `custody_attestation`. So an owner session can seat a
  kill-switch holder with a fabricated non-FIPS claim and **no YubiKey/FIPS/touch** —
  which is exactly what `tests/accord.rs` + `examples/qa_runner` do. The rigorous
  Yubico-root chain verification *exists* and is sound, but is **not on the mandatory
  path.** Fix: make `custody_attestation` REQUIRED for `identity_type==accord_holder`,
  couple the verified `CustodyVerdict` to the persisted `attestation_evidence`, and/or
  install a strict YubiKey-FIPS `HardwareAttestationPolicy`.

- **B2 — CRITICAL (I2): reactivation/halt-clear continuity is rooted in operator-
  writable local state, not a pin.** `reactivate_accord` reads BOTH the current roster
  and the "ORIGINAL genesis (version-1)" set from `engine.federation_directory()` — the
  local persist DB (`src/accord_reactivate.rs:74, 112-142`) — and never consults the
  pinned `humanity_accord_genesis()`. A root operator can rewrite `federation_families`
  / forge a version-1 group row with their own keys and self-author a "valid" 2/3
  `lifecycle:active`. Compounded by the `rm <latch>` break-glass that `check_halt_gate`
  itself advertises (`src/accord_halt.rs:73-74`): the latch is a plain file clearable by
  any process as the node user, with no quorum. So I2 ("no operator action brings it
  back without a 2/3 proof") is false against a captured host — the exact threat in §4.
  Fix: anchor the original-genesis continuity check to the *pinned* baked genesis (needs
  G2), make the latch tamper-evident / quorum-bound, and close/neuter the bare-`rm` path.

- **B3 — HIGH (I3): the quorum-completing halt is not propagated mesh-wide.** The gossip
  loop-stop `seen` set is keyed on `(invocation_kind, invocation_id)` only and is
  inserted on the FIRST (sub-quorum) sighting (`src/accord.rs:~1133-1152`). A
  CONSTITUTIONAL invocation normally arrives sub-quorum first; when the signature that
  COMPLETES the 2/3 arrives later, `first_sight==false` so `replicate_to_peers` is
  skipped — the node latches + exits **without** propagating the now-quorum halt, and
  the earlier gossiped object carried <2 sigs so no peer can halt from it. Fix: make the
  loop-stop quorum-aware (track quorum-met sightings separately; always replicate a
  global halt that newly reaches quorum).

- **B4 — HIGH (I1): a halt can resurrect if the latch write fails.** In
  `replicate_and_maybe_halt`, if all latch-write attempts fail the node logs + still
  `exit(42)` (`src/accord.rs:~1177-1198`); next boot finds no latch and starts normally.
  A full/read-only disk silently un-halts a killed node. Fix: a failed latch write must
  not exit "as halted" — stay down / retry / fail louder.

### Not an initial-ceremony blocker, but MUST fix before the family grows

- **N1 — HIGH (I4, latent): the live halt threshold is hard-coded to `2`.**
  `verify_invocation` (literal `2`) and `accord_invocation_status`
  (`ACCORD_QUORUM_THRESHOLD=2`) never read the family's `consensus_protocol`, unlike
  `reactivate` which derives M correctly. Correct for the genesis `quorum:2/3` trio, but
  after an I8 growth to 3/5 a **2-of-5 minority** could trigger the irreversible global
  kill (and reactivation would need 3 — an asymmetry). Fix: derive M from
  `consensus_protocol` on the halt paths too.

- **N2 — MEDIUM (I7 boundary): `verify-invocation` applies no distinct-pubkey re-check**
  (only `member_id`-string dedup); the same key under two `member_id`s would be counted
  twice there. Contained today because the roster is built by genesis/supersede which
  enforce distinct pubkeys in the substrate, and no raw add-member route is exposed —
  but the property should be re-asserted at the verifier, not relied on upstream.

### Verified SOUND (no flaw found)
I6 no-TOFU recognition (fails safe; cold-start with no baked genesis recognizes NO
roster rather than a fetched one); I7 PQC-hybrid required on every authority path +
zero/over-threshold rejected; I8 supersede (substrate-enforced strict-majority +
one-seat + anti-replay + entrenchment-preserving); startup-gate fail-secure on latch
presence; wrong-kind reactivate proof rejected before engine open; spare-vs-seat
self-quorum closed (roster = live family seats only).

### Revised bottom line
v0.5.30 is the right architecture and most of it is sound, but **running the ceremony
now would mint a kill-switch that (B1) admits non-hardware holders, (B2) a root
operator can both `rm`-clear and forge a reactivation for, and (B3) may fail to spread
when triggered.** B1+B2+B3+B4 must be fixed (and G2 — the verify genesis bake — is a
hard dependency of B2's real fix) before the genesis ceremony and the 0.6 canonical cut.

## 9. Remediation (2026-06-21) — the §8 blockers, fixed + re-verified

The blockers were fixed and re-checked by a second adversarial pass. Status:

- **B1 (custody bypass) — CLOSED.** `custody_attestation` is now MANDATORY at
  `POST /v1/accord/holder` (a missing attestation is refused), so no software-only key
  is admitted there. The re-review then found a *side-door* (the generic
  `/v1/federation/peering` route admitted a caller-typed `accord_holder` with no custody
  check), now closed at two points: `peer::register_peer_key` REFUSES
  `identity_type==accord_holder`, and `genesis_assemble` requires **every entrenched
  seat to be a registered `accord_holder`** (⟹ custody-verified). So "seat ⟹
  accord_holder ⟹ FIPS custody" holds regardless of how any other key reached
  `federation_keys`. Tests: `holder_without_custody_attestation_is_rejected`,
  `genesis_refuses_a_member_that_is_not_a_custody_verified_accord_holder`.
- **B3 (halt not propagated) — CLOSED.** The gossip loop-stop key now carries
  `is_global_halt`, so a sub-quorum first sighting no longer suppresses the
  quorum-completing halt's replication; replicate is still awaited before latch+exit.
- **B4 (halt resurrects) — CLOSED.** The clean `exit(42)` is now gated on a durable
  latch; on latch-write failure the node `abort()`s (after replicating to peers) rather
  than exiting "as halted", so it cannot restart un-gated.
- **N1 (hard-coded threshold) — CLOSED.** The halt paths derive M from the family's
  ENTRENCHED `consensus_protocol` (the same M reactivate honors), falling back to
  strict-majority only at cold-start — a grown 3/5 needs 3 to halt.
- **N2 (distinct-key at verifier) — CLOSED.** `assert_distinct_roster` re-asserts
  one-key-one-seat at the verification point.
- **B2 (operator-forgeable reactivation) — MITIGATED; full closure gated on G2.** The
  ORIGINAL-genesis continuity check is now anchored to the PINNED
  `humanity_accord_genesis()` (compiled into verify, not operator-writable) **when it is
  baked**, and `check_halt_gate` no longer advertises the `rm` break-glass. **Residual
  (tracked):** (a) until **G2** bakes the genesis, the original-set falls back to the
  local-DB version-1 snapshot (now warned, honest); (b) the *current-roster* quorum
  (reactivate step 1) and the disk latch remain local/operator-writable — full closure
  needs the genesis bake **plus** a pinned/quorum-bound current-roster source and a
  tamper-evident latch. These ride with **G2** (already the sequenced gate before 0.6),
  so B2 is not an *additional* blocker beyond G2 — but G2 must now also land the latch +
  current-roster hardening, not just the JSON paste.

### Revised bottom line
With B1/B3/B4/N1/N2 closed, the enforceable, hardware-custodied, mesh-propagating,
correctly-thresholded kill-switch is in place for the genesis `quorum:2/3` trio. The
one remaining floor item is **B2's continuity/latch hardening, which is folded into G2**
(the verify genesis bake). Sequencing to the ceremony is unchanged — G1 → G2 (now also
carrying B2's latch + current-roster pin) → G3 — and minting the two trios is gated on
G2, not on any further G1-time code.
