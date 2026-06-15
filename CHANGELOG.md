# Changelog

All notable changes to CIRISServer. Format follows [Keep a Changelog](https://keepachangelog.com/);
this project uses [Semantic Versioning](https://semver.org/). The minor line tracks
the fabric-node scope (0.1 lens · 0.5 +registry · 1.0 +node), paced by the CIRISAgent train.

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
