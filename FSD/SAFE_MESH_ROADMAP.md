# Safe-Mesh Roadmap — from v0.5.31 to the canonical trio (0.6)

> The agreed order of operations from here to a self-bootstrapping canonical mesh.
> Companion to [`SAFE_MESH.md`](SAFE_MESH.md) (definition + invariants + G1/G2/G3) and
> [`BRIDGE_UPGRADE_v0.5.30.md`](BRIDGE_UPGRADE_v0.5.30.md) (the node upgrade runbook).
> Two trios are minted across this sequence — the **HUMAN accord trio** (kill-switch)
> and the **canonical NODE trio** (mesh seed) — on orthogonal trust roots; see
> SAFE_MESH §1. Project stays **0.5.X** until G3.

## The sequence

| # | Step | Who | Produces | Gate it clears |
|---|------|-----|----------|----------------|
| 1 | **Green on main/PyPI** — ship the safe-mesh blocker fixes | done | **ciris-server 0.5.31** (main + PyPI) | B1/B3/B4/N1/N2 closed |
| 2 | **Upgrade server + status** to 0.5.31 | ops | Node A (lens) + Node B (status `v0.3.6`) on 0.5.31 | nodes carry the fixed kill-switch |
| 3 | **Set up the human accord keys (G1 ceremony)** | 3 humans | 3 primary SEATS + 3 vaulted spares (6 FIPS YubiKeys + 6 USB) → an assembled 2/3 `accord_family_genesis` object | the human trio exists, custody-verified |
| 4 | **Take control of A & B; bake the genesis (G2)** | you | node A entrenched as the **1st canonical node** + the human accord trio baked as **verify 7.0** (paste the genesis into `HUMANITY_ACCORD_GENESIS_JSON`) + **persist v10** (major) + **edge minor** — one coordinated substrate cut | I6 (no-TOFU cold-start root) + B2 residual close |
| 5 | **Cut the next 0.5.X patch (0.5.32)** adopting verify 7.0 / persist 10 / edge minor; **upgrade server + status** again | us | ciris-server 0.5.32 the agent can adopt | substrate carries the baked root |
| 6 | **Prove lens trace flow via RNS → lens** from the dev **agent 2.9.7** + ciris-server | us | working end-to-end trace ingest over Reticulum | the agent path validated |
| 7 | **Cut agent 2.9.7** | agent team | released agent on ciris-server | — |
| 8 | **ciris-server 0.6** = +registry — replaces the 2 registry servers | us | the **2nd + 3rd canonical nodes** → full canonical TRIO; bake `CANONICAL_BOOTSTRAP_PEERS=[A, reg1, reg2]` | G3 — the mesh self-bootstraps |

**Sequencing is load-bearing:** the human accord trio (3) is minted + baked (steps 3–4)
**before** the canonical node trio is completed (step 8). The mesh becomes hard to
switch off (0.6) only after humanity already holds the verified kill-switch.

## G2 scope — the verify 7.0 / persist 10 / edge minor cut (step 4)

What the coordinated substrate cut must carry, beyond the version bumps:

### verify 7.0 (CIRISVerify)
1. **Bake the genesis (the core of G2).** Paste the ceremony's assembled
   `accord_family_genesis` `SignedCegObject` JSON into `HUMANITY_ACCORD_GENESIS_JSON`
   (`src/ciris-verify-core/src/accord_genesis.rs:673`, currently `""`). The accessor
   `humanity_accord_genesis()` + `accord_roster_from_family` already exist (v6.11.0) and
   are consumed by ciris-server (`resolve_kill_switch_roster`, `accord_reactivate`); the
   bake is a one-const change that flips both from `None` to the pinned root. This is the
   no-TOFU recognition root (SAFE_MESH I6) and the pin that closes B2's continuity check
   (`reactivate` already prefers the baked genesis when `Some`).
2. **Confirm the baked object is self-consistent** — kind `accord_family_genesis`, the 3
   primary SEATS as members, `consensus_protocol: quorum:2/3`, the 2/3 founder
   signatures. `humanity_accord_genesis()` already fail-closes a malformed bake to
   `None`; add a verify unit test asserting the baked object parses + its roster resolves
   against the founders' pinned keys (so a bad paste fails CI, not production).
3. **Why a MAJOR (7.0):** baking the recognition root changes cold-start recognition
   semantics meshwide (a node that was not at the ceremony now recognizes a roster it
   previously did not) — a deliberate, breaking trust-surface change.

### persist v10 (CIRISPersist) — major
- Coordinated cut alongside verify 7.0 (the verify-family lockstep: persist transitively
  pins ciris-verify-core, so a verify 7.0 forces persist to re-pin → a fresh persist cut).
- ciris-server adoption is mechanical (a pin bump in root + `crates/ciris-lens-core`)
  **iff** the persist 10 API surface stays source-compatible; if persist 10 carries its
  own breaking DX changes, scope those as a separate adoption PR.

### edge minor (CIRISEdge)
- Lockstep re-pin to the verify-7.0 family; expected additive (a minor), no ciris-server
  source change.

### ciris-server side (the 0.5.32 adoption — step 5)
- Bump the three pins in `Cargo.toml` (root) + `crates/ciris-lens-core/Cargo.toml`;
  confirm single-version resolve (no dual `ciris_verify_core`).
- **Land B2's remaining hardening alongside G2** (SAFE_MESH §9 residual), now that the
  genesis is pinned: (a) the `reactivate` original-genesis check is already pinned-anchored
  — verify it now resolves against the baked root (no local-DB fallback warning); (b) make
  the halt **latch tamper-evident** (e.g. record the halting invocation + sign/anchor it,
  so a bare `rm` is detectable on next boot) — server-side, not gated on verify; (c)
  consider anchoring the reactivate **current-roster** (step 1) read to the signed family
  attestation chain rather than the raw mutable row.
- Repin **CIRISStatus** to 0.5.32 (Node B) the same way.
- Run the gate set + `qa_runner` (incl. `run_ceremony`); CI green; tag the 0.5.32 patch.

## What is NOT in scope yet
- The 2 registry nodes / `CANONICAL_BOOTSTRAP_PEERS` bake — that is **0.6 (G3, step 8)**,
  after the agent 2.9.7 cut. The const stays `&[]` through all of 0.5.X (by design).
