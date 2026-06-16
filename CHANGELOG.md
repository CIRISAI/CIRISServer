# Changelog

All notable changes to CIRISServer. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses [Semantic Versioning](https://semver.org/). The minor line tracks
the fabric-node scope (0.1 lens · 0.5 +registry · 1.0 +node), paced by the CIRISAgent train.

## [0.2.5] — 2026-06-16

First cut of the **holonomic federation scoreboard** (CIRISServer#12/#13) — the
operator-facing measured-vs-modeled surface, replacing per-cut SOTA-comparison toy
numbers with grounded metrics.

### Added
- **`server::benchmarks` module + `ciris-server scoreboard`** — emits a JSON
  scoreboard of the federation's capacity/survival posture.
  - **Storage tier — fully grounded** from a `FountainPolicy` (N=20, K=6, H=30
    reference). Replication overhead (1.5×), per-peer load (5%), active-eject
    threshold (H×1.15=34.5), holographic degradation tiers, and the **survival
    floor** `P(Binomial(H, q) ≥ N)` computed in log-space. The calculator
    **reproduces the scale_model v0.7 survival curve from first principles**
    (99.99999 / 99.991 / 99.706 / 97.438 / 73.04 % at q = 0.95/0.90/0.85/0.80/0.70)
    — asserted in tests — which is what makes "measured vs modeled" trustworthy.
  - **Live overlay** (`with_measurement`): recomputes overhead + survival from
    observed holders + real per-peer `q`, and **alarms** when live survival dips
    under the 99% floor (the early-warning signal before content becomes
    unreconstructable), or on >2.0× over-replication.
  - **Substrate + holonomic tiers are honest `gated` stubs** (not fabricated):
    substrate gated on edge v4.1.1's `NETWORK_CAPACITY_MODEL.md` + benches
    (CIRISEdge PR#147); holonomic gated on fountain/holonomic wiring (#11) +
    CIRISRegistry#88's composite model that grounds the targets.

## [0.2.4] — 2026-06-16

Catch-up to the **v8 / v4 / v5.8 substrate family** and **CEG 1.0-RC11**. Two
substrate MAJOR bumps (persist 7→8, edge 3→4) adopted with **zero composition-root
changes** — the breakage surface was a single benchmark.

### Changed
- **Substrate floor → persist v8.1.0 / edge v4.1.0 / verify-family v5.8.0**
  (root + in-tree `ciris-lens-core`, MAJOR caret pins co-bumped). The major bumps
  are additive: persist v8 = the `fountain` content primitive (new module);
  edge v4 = the `holonomic` substrate (CEG §19) + realtime-A/V scale work — none of
  it touches the symbols the composition root calls. `compose.rs`, `import.rs`,
  `lib.rs`, and the replication bench/test needed no edits; `CompleteTrace` and the
  hybrid ingest gate are unchanged (replication test still green under v8.1.0).
- **CEG → 1.0-RC11** (doc/vendor-only for the node, as RC6/RC7 were). The frozen
  §4 "1+4" attestation envelope, signature format, dest-hash, trace schema, and
  identity aggregate are untouched across RC7→RC11. The one envelope-touching
  behavior change — RC8's store-path PQC clarification (the durable corpus MUST
  carry+verify the ML-DSA-65 half) — is already satisfied by 0.2.3's hybrid hard
  cut. RC9/RC10/RC11 wire additions (`codec_id`/`ChunkLayer`, the full
  `SealedAvChunk` layout + double-seal nonces, the §19 holonomic shapes) are
  **edge-owned transport/substrate framing**, additive, reached only through the
  edge dependency.

### Fixed
- **`pqc_av_streaming` bench** updated to edge v3.8.0's seal API (CIRISEdge#128):
  `seal_av_chunk`/`seal_av_inner` take `codec_id` + `ChunkLayer` (pass
  `CODEC_OPAQUE` + `ChunkLayer::BASE` to keep byte-identical v3.7.0 wire output),
  and `MeshParticipant::new` defaults the new `layer_policy`. CI now checks
  `--all-targets` so the (harness=false) bench can't silently break on a co-bump.

### Adoption
- Closes the persist 7.0/7.1/7.2 adoption issues (#3/#8/#10) — all satisfied by the
  0.2.3 hybrid hard cut + this floor. persist v8.0's fountain store API (#11) is now
  available at the floor; wiring the fountain/swarm storage role is tracked as
  follow-on feature work, not required for the floor.

## [0.2.3] — 2026-06-16

Hybrid **hard cut, complete end-to-end** (no classical-only path at any tier),
substrate floor → the v3.7.1 / v7.2.0 / v5.7.0 family, CEG **1.0-RC7**, and a
CEWP-honest benchmark page.

### Changed
- **Hard cut to hybrid signing — now end-to-end (CIRISVerify#75 — "no classical-
  only, HNDL demands it").** Three tiers, all hybrid (sealed Ed25519 + ML-DSA-65):
  1. **Federation wire** sigs — edge `LocalSigner` (already hybrid).
  2. **Storage-tier scrub** sig — the Engine is built with
     `Engine::with_hardware_signer_hybrid` (CIRISPersist#224); the Ed25519 half
     stays hardware-sealed (never unsealed), the ML-DSA-65 half is the software PQC
     signer. Applies to the node Engine **and** the legacy-import Engine.
  3. **Per-trace envelope** sig — closed by **persist v7.2.0** (CIRISPersist#225,
     migration `V083`): `trace_events` carries the ML-DSA-65 half and
     `VerifyMode::Full` **rejects classical-only per-trace sigs**. CIRISServer's
     replication path inherits the rejection; the legacy-import path stays exempt
     (`TrustPreVerified`, provenance-only Ed25519).
  Rationale is forge-later, not decrypt-later: the trace corpus is durable,
  content-addressed, kept-for-posterity evidence, so its signatures must outlive
  the classical primitive.
- **`GET /v1/identity` now serves all six keys.** With the hybrid hardware Engine,
  the aggregate is sourced directly from persist's `local_identity_aggregate`
  (CIRISPersist#223) — the ML-DSA-65 signing half **and** the persist-minted
  content-KEM pair (`content_x25519` / `content_ml_kem_768`) are populated; they
  are no longer `null`. Removes the hand-assembled aggregate.
- **Substrate floor → persist v7.2.0 / edge v3.7.1 / verify-family v5.7.0**
  (edge v3.7.1's hard-cut co-bump: verify v5.7.0 = hybrid-required at federation
  tier, closes CIRISVerify#75/#76/#77; persist v7.2.0 = trace-tier hybrid, #225);
  **CEG 1.0-RC7**. lens-core co-bumped in lockstep.

### Added
- **Benchmark upgrade — the CEWP crux ("stream and store at massive scale").**
  - `av_mesh_fanout/shared_inner` now drives v3.7.0's real `seal_av_inner` /
    `seal_av_outer` (CIRISEdge#122), not a hand-rolled mirror — measured fan-out
    win 1.36×/1.85×/**2.07×** at N=2/8/50.
  - **`av_rekey`** (new): the membership-change rekey cost, **projected** from the
    real hybrid-KEM wrap — `flat_rewrap` O(N) vs `tree_rewrap` O(log N). A 50-room
    delta is ~3.4 ms flat → ~0.41 ms with the tree (8.3×). Labelled projected: the
    substrate doesn't rekey on join/leave yet (**CIRISEdge#129**), so "effectively
    free" holds at steady state, not yet under churn.
  - **Honest accounting:** `av_frame_halves` now measures seal (send) vs open
    (recv) **per size**; the report charges receivers open-only and states its GOP
    model inline instead of cherry-picking a frame. A 50-person 30 fps room is
    ~0.5% of a core to receive (stated 720p/GOP-30 model), range ~0.17–0.45%.
  - **Replication is now hybrid (the hard cut at the store path).** The bench
    signs full-hybrid traces (the only kind v7.2.0 accepts); measured ingest is
    **~230 µs/trace (~4,300 traces/s/core)** — the ML-DSA-65 verify adds ~150 µs
    over the old Ed25519-only ~76 µs. That is the **measured HNDL price** at the
    store path. Re-delivery still pays full verify (replay is verify-bound by
    design — verify-before-mutation; dedup-first would be an AV-9 oracle), so the
    levers are the pre-verified relay path + **batch verification** (now materially
    more valuable; tracked in CIRISPersist#225's scale note), not reordering.

## [0.2.2] — 2026-06-15

### Added
- **`import-traces` on the wheel** (pip-only bridge): the abi3 wheel now exposes
  `ciris_server.import_traces(dump_dir)`, and the `ciris-server` console script
  accepts `ciris-server import-traces <dump-dir>` (same CLI as the binary). The
  legacy CIRISLens dump → persist-corpus-as-CEG import no longer needs the
  source-built binary. Verified from the installed wheel against the prod dump:
  all 12,165 traces, errored=0.

## [0.2.1] — 2026-06-15

Android wheels (incl. arm32) now publish; legacy-trace importer.

### Added
- **`ciris-server import-traces <dump-dir>`** — imports the legacy CIRISLens
  TimescaleDB dump into the persist corpus as CEG objects. Reconstructs flat
  1.9.x lens rows → `CompleteTrace`/`BatchEnvelope` (reasoning columns →
  components; original schema + signature in a provenance component); stamped
  `2.7.legacy`; imported pre-verified; idempotent. A salvage pass repairs the
  dump's systematic `\\"`→`\"` export mis-escaping and flags those rows
  `_salvaged: true`. Validated on the prod dump: **all 12,165 traces →
  20,959 trace-events, errored=0** (3,635 salvaged).
- **Android wheels** (armeabi-v7a + arm64-v8a) now build & publish (NDK r26b
  cross-compile: explicit `CC`/`AR`/linker for the toolchain, legacy-NDK
  tool-name shims for openssl-src, `ANDROID_API_LEVEL`). Promoted from
  continue-on-error to a required publish lane.

## [0.2.0] — 2026-06-15

All-platforms-green CI, **full hybrid post-quantum federation signatures**, and a
published interpreted benchmark page.

### Added
- **Full hybrid PQC federation signature (Ed25519 + ML-DSA-65).** The node mints
  (or **adopts**, on takeover) an `ml_dsa_65.seed` and signs every federation
  envelope with both halves (edge `LocalSigner` classical + pqc). `/v1/identity`
  now carries `ml_dsa_65_pubkey_b64` + `pqc_key_id`. Classical stays
  hardware-sealed; the ML-DSA half is a software seed (no sealed-ML-DSA backend
  exists — a TPM can't do ML-DSA).
  - **One remaining classical path**, filed upstream: persist's storage-tier
    scrub signature is Ed25519-only — `with_hardware_signer` is classical-only and
    `with_signer_arcs` (hybrid) needs a plaintext key. **CIRISPersist#224** adds a
    hybrid-hardware ctor to close it without un-sealing.
- **Interpreted benchmark page** → `https://cirisai.github.io/CIRISServer/`
  (`.github/workflows/bench.yml` + `scripts/bench_report.py`): video throughput
  (fps ceiling, sustainable mesh participants @30 fps), post-quantum handshake
  overhead, mesh fan-out, and **replication speed** (new `replication_ingest`
  bench, ~13K traces/s/core).
- Android arm32 (armeabi-v7a) + arm64 wheel lane (NDK cross-compile;
  `continue-on-error` while it iterates to green).

### Changed / Fixed
- **All CI platforms green** (was red on macOS/Windows/Win7). Root cause was our
  own feature wiring: a top-level `tpm` feature + unconditional `postgres`
  dragged `tss-esapi`/`openssl` onto platforms that can't build them. Fixed with
  per-target deps (`postgres` + `tpm` Linux-only; `android` keyring backend) and
  dropping `--all-features`.

## [0.1.2] — 2026-06-15

Substrate floor bump + the `/v1/identity` endpoint the migration runbook requires.

### Added
- **`GET /v1/identity`** — the node's `LocalIdentityAggregate` (CEG §5.6.8.8.2),
  merged onto the read-API listener (same port as `GET /lens/api/v1/*`). Serves
  `key_id`, the Ed25519 federation pubkey, the Reticulum transport pubkeys
  (x25519 ‖ ed25519), and `identity_hash` — the identity-continuity surface the
  CIRISLens→CIRISServer cutover verifies (runbook §4 step 1). Closes the gap that
  blocked the first cutover attempt (#5).
  - `content_x25519` / `content_ml_kem_768` are `null` for now: persist's
    `local_identity_aggregate` requires a software `LocalSigner`, and CIRISServer
    runs a hardware signer (`with_hardware_signer` → `local_signer: None`). The
    content-KEM halves fill in once persist exposes the aggregate for a
    hardware-signed Engine (tracked upstream).

### Changed
- Substrate floor → **persist v7.0.0 / edge v3.6.0 / verify-family v5.6.0**
  (the edge v3.6.0 "CEWP-ready" co-bump; CEG 1.0-RC6). Major persist 6→7, built
  clean with zero code changes.
- `build_edge` wires the Reticulum transport via the typed `.reticulum_transport()`
  builder so `Edge::local_transport_pubkey()` resolves (populates the
  RET-transport role of `/v1/identity`).

## [0.1.1] — 2026-06-15

Release-CI fixes only — **no change to the node**. 0.1.0 was tagged but did not
publish: `publish-pypi.yml`'s linux wheel built in a manylinux_2_28 (AlmaLinux 8)
container whose tpm2-tss is 2.3.2, too old for the keyring's `tss-esapi-sys`
(`tss2-sys not found`), and two lint gates failed.

### Fixed
- **Linux wheels** now build on the native runners (ubuntu-latest + ubuntu-24.04-arm)
  with apt `libtss2-dev` + `patchelf` — the same recipe the green conformance
  wheel job and the sister wheels (persist `manylinux_2_38`, edge `_2_39`) use —
  instead of the el8 container with its stale tss2.
- `rustfmt` (bench formatting) and `clippy` doc-list lints in
  `benches/pqc_av_streaming.rs` (allow the two stylized-doc lints).

## [0.1.0] — 2026-06-15

First release. **Lens-only fabric node** — the federation's headless cohabitation
runtime with only the observation slice live. Replaces both the deployed CIRISLens
server and the agent's direct `ciris-lens-core` cohabitation.

### Added
- **Zero-setup node** (`ciris-server`): one shared persist `Engine` + one shared
  Reticulum `Edge` (a single federation identity), mode defaults to `server`,
  no wizard. Data under `$CIRIS_HOME`; SQLite corpus by default, Postgres via
  `CIRIS_DB_URL`.
- **Lens slice**: relay ingest of CEG `AccordEventsBatch` (over Reticulum/HTTP)
  into the shared corpus, plus the seven frozen `GET /lens/api/v1/*` read
  endpoints. `ciris-lens-core` is absorbed in-tree (workspace member); the
  standalone CIRISLensCore library and the CIRISLens deployment retire.
- **Hardware key custody**, two classes: the RNS transport identity and the
  Ed25519 federation seed are TPM / Secure-Enclave / StrongBox sealed, with a
  software-encrypted fallback. Existing keys are **adopted byte-identically** —
  a CIRISLens host keeps its `key_id` and RNS destination on cutover (no re-key,
  no re-enroll). See `FSD/LENS_TO_SERVER_MIGRATION.md`.
- **Reticulum floor with capability gating**: always a routable RET node; the
  lens corpus + read API gate on a realistic free-disk minimum
  (`CIRIS_SERVER_LENS_STORE_MIN_GIB`), else the node runs as a relay.
- **`ciris-canonical` founder-quorum** (`src/quorum.rs`): the entrenched 2-of-3
  trust root that replaces the shared steward key (prep for the 0.5 registry
  fold; CEG §8.1.13.1.1).
- **PyO3 abi3 wheel**: `pip install ciris-server` → the `ciris-server` command,
  and the lens drop-in `from ciris_server import LensClient` for CIRISAgent.
- **Conformance + benchmarks**: cohabitation + CEG-profile gating via
  CIRISConformance; `benches/pqc_av_streaming.rs` (realtime-A/V two-layer
  hybrid-PQC mesh) and `tests/replication.rs` (CEG-RC5 corpus replication spine).

### Substrate
- persist **v7.0.0** · edge **v3.6.0** · verify-family **v5.6.0**
  (verify-core + keyring + crypto). CEG **1.0-RC6**.

### Notes
- Registry (0.5) and node (1.0) slices are scaffolded in `src/compose.rs` and
  fold in as their co-bumps land. Registry-fold prep: `FSD/REGISTRY_FOLD_DERISK.md`,
  [#2](https://github.com/CIRISAI/CIRISServer/issues/2).

[0.1.0]: https://github.com/CIRISAI/CIRISServer/releases/tag/v0.1.0
