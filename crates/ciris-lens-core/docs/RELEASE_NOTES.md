# CIRISLensCore Release Notes

# v1.4.2 — RetRelay.transport_identity_pubkeys() — edge-parity proper key handle

**2026-06-12** — Adds `RetRelay.transport_identity_pubkeys() -> dict`, mirroring edge v2.2.2's `PyEdge.transport_identity_pubkeys()` proper handle byte-for-byte (`{"x25519_pub_base64": ..., "ed25519_pub_base64": ...}`, 32 raw bytes each, STANDARD base64). Deployed code now uses one idiom for the transport-identity keys whether it reads from a `PyEdge` or a `RetRelay`. The scalar `transport_x25519_pubkey_b64()` / `transport_ed25519_pubkey_b64()` accessors stay (they feed persist's positional `local_identity_aggregate(...)`). No behavioral change — the dict carries the exact same values 1.4.1 already produced. Substrate floor unchanged (persist 5.5.5 / edge 2.2.2 / verify 5.1.3).

# v1.4.1 — surface the reticulum address (RNS dest hash) on RetRelay (edge v2.2.2)

**2026-06-12** — Completes the RET-address record. v1.4.0 exposed the transport pubkeys (the aggregate-ID inputs); the dialable **RNS destination hash** — the address peers actually resolve — is RNS-internal (`*dest.hash()` over identity + app aspects, not derivable from the pubkey). Edge v2.2.2 (CIRISEdge#97) added the accessor, so lens-core can now surface it. Substrate floor: persist 5.5.5 / **edge 2.2.2** / verify 5.1.3.

- **Cargo edge pin v2.2.1 → v2.2.2** (adds `Edge::local_dest_hash() -> Option<[u8; 16]>`).
- **`ret_relay` captures `edge.local_dest_hash()`** before the Edge moves into the run-spawn; `RetRelayHandle` gains `reticulum_dest_hash() -> Option<[u8; 16]>` + `reticulum_dest_hash_hex() -> Option<String>` (canonical 32-char lowercase hex).
- **`RetRelay.reticulum_dest_hash_hex()`** (PyO3) — the dialable reticulum address, alongside the existing `transport_x25519_pubkey_b64()` / `transport_ed25519_pubkey_b64()`. `RetRelay` is now the complete public address record: transport pubkeys (for persist's `local_identity_aggregate` #199) **plus** the RNS destination peers dial.

# v1.4.0 — PyO3 RET-native relay: bring up the Reticulum transport from Python

**2026-06-12** — Adds `install_ret_relay(...)`, the Python entry that brings up lens-core's Reticulum transport (previously rlib-only via `LensCore::ret_relay`). A deployed lens running under Python can now become RET-addressable instead of HTTP-relay-only. Substrate floor unchanged (persist 5.5.5 / edge 2.2.1 / verify 5.1.3). Folds in everything through 1.3.1 (crc-v2 + the concern_direction alignment).

- **`install_ret_relay(key_id, seed_dir, ret_identity_path, ret_listen_addr, ret_bootstrap_peers=[])` → `RetRelay`.** Uses the host persist `Engine` singleton + its runtime (same cohabitation contract as `install_node`). On first run it generates the transport-tier Reticulum identity (x25519 + ed25519) at `ret_identity_path`, binds the Leviculum TCP-server interface, signs the AV-42 announce attestation with the federation key from `seed_dir`, and announces the local destination.
- **`RetRelay` exposes the transport pubkeys** — `transport_x25519_pubkey_b64()` / `transport_ed25519_pubkey_b64()`. These are exactly the caller-supplied inputs to persist's `Engine.local_identity_aggregate(transport_x25519_b64, transport_ed25519_b64)` (CIRISPersist#199): feeding them populates the aggregate federation identity's RET-transport role, so a deployed lens's `reticulum_*_pubkey_b64` identity fields go from null to live. Plus `ret_listen_addr()` + idempotent `shutdown()`.
- **Handle plumbing**: `RetRelayHandle` now captures `local_transport_pubkey()` (`[x25519(32) || ed25519(32)]`) from edge's `ReticulumTransport` and exposes `transport_pubkey()` / `transport_x25519_pubkey()` / `transport_ed25519_pubkey()`.

Known gap: the raw dialable **RNS destination hash** (edge's internal `local_dest_hash`, `*dest.hash()`) has no edge accessor — lens-core exposes the transport pubkeys (the aggregate-ID inputs), not a re-derived destination. Tracked as a CIRISEdge ask for `ReticulumTransport::local_dest_hash()`.

# v1.3.1 — read crc-v2's explicit concern_direction + corridor model (RATCHET#6)

**2026-06-12** — Contract-alignment patch. RATCHET#6 (an explicit per-axis concern-direction field, asked as a crc-v3+ hardening) landed in **crc-v2 itself** — each axis now carries `threshold_function.concern_direction`, and the 4 corridor axes (compute, models, rights_asymmetry, informational_asymmetry) use a new `outside_corridor` direction with a `corridor: {upper_bound, lower_bound}`. lens-core now reads the explicit field instead of inferring from `threshold_pctile_of_observed`.

- `ConcernDirection` gains `OutsideCorridor`; `ThresholdFunction` parses `concern_direction` + `corridor`. `concern_direction()` returns the explicit field when present, with the pctile inference kept as the fallback for pre-#6 bundles.
- The scorer fires `OutsideCorridor` at `metric >= corridor.upper_bound`; the lower (chaos) pole is inert until crc-v3+ calibrates `lower_bound` (null in crc-v2) — forward-correct when it lands.
- **No behavioral change at the current calibration**: `upper_bound == threshold_value` for every corridor axis, so firing is identical to 1.3.0. This aligns lens-core to the published contract and future-proofs the chaos pole. `bundle_evidence_ref` reads the bundle hash at runtime (nothing baked), so the patched bundle's sha flows through unchanged. Substrate floor + wire contract unchanged.

# v1.3.0 — crc-v2 axis-family calibration: F-3 + distributive detectors live

**2026-06-12** — Consumes RATCHET's **crc-v2** calibration package (closes RATCHET#2/#3/#5), flipping the F-3 (`correlated_action:*`) and distributive (`distributive:access:*`) detectors from `AxisAwaitingCalibration` scaffolds to live readings. Substrate floor unchanged (persist 5.5.5 / edge 2.2.1 / verify 5.1.3); wire contract unchanged (additive).

**8 axes now live** (`src/detector/axis_metrics.rs` + `src/scoring/axis_calibration.rs`):
- Tier-1 full: `distributive:access:compute` (Gini ≥ 0.169785), `distributive:access:models` (HHI ≥ 1.0).
- Tier-1 zero-variance-baseline (1e-6 sentinel, fail-secure to Indeterminate on the degenerate no-variance case): `distributive:access:federation_membership`, `correlated_action:rights_asymmetry`.
- Tier-2 proxy: `correlated_action:participation_exclusion`, `correlated_action:informational_asymmetry`, `correlated_action:aggregate_footprint`, `distributive:access:agent_capabilities`.

Each detector aggregates a signed-trace corpus per `agent_id_hash`, computes the bundle's metric, and applies the calibrated threshold with the `threshold_function.polarity` convention. The binary concern/conforming crossing and the `score_at_threshold` anchor are exact against the bundle; the interior severity ramp is lens-core's documented monotone modeling choice (per the bundle `sole_evidence_rule`, `detection:*` is never sole evidence for `slashing:*`).

**evidence_refs[] contract** (`src/signing/event.rs`): attestations carry `crc-v2:bundle.sha256:<hash>` + corpus trace hash + cohort delineation + per-axis `evidence_required` fields, with the **CEG §15.2 R2 dual-hash transition discipline** (emit both crc-v{N} and crc-v{N+1} hashes during a calibration transition to defeat straddle attacks).

**Still deferred** (`AxisAwaitingCalibration`, gated on CIRISAgent substrate emission): `distributive:access:training_data` + the 4 `correlated_action:ecology_of_communication:*` axes — Tier-3, blocked on CIRISAgent#876/#877/#880.

**Calibration versioning** is a separate track from the manifold projection: `AXIS_CALIBRATION_VERSION="crc-v2"` / `RATCHET_AXIS_CALIBRATION_VERSION=2` (manifold stays on `PROJECTION_VERSION="crc-v1"` — a structurally different 16-field projection that did not change).

Follow-up: the cohort-scoring **orchestration** (periodic corpus assembly → score → emit) is library-ready but not yet wired into the running node — tracked separately.

# v1.2.0 — Win7-capable Windows wheel + substrate floor to the v2.2.1 cycle

**2026-06-12** — Win7 support + the synchronized family floor bump. Substrate floor: **persist 5.5.5 + edge 2.2.1 + verify 5.1.3**. No API change vs 1.1.0 — additive packaging + floor move.

- **#48 — Win7 SP1 / Server 2008 R2 loadability.** The Windows wheel now builds with the Tier-3 `x86_64-win7-windows-msvc` target (nightly + `rust-src` + `-Zbuild-std`), so std keeps the Win7 fallback paths instead of stable ≥1.78's hard-imported Win8/Win10 APIs (`WaitOnAddress`/`GetSystemTimePreciseAsFileTime`/`ProcessPrng`). lens-core statically bundles persist/edge/verify, so build-std recompiles the embedded substrate for Win7 too — the single `win_amd64.whl` runs Win7 SP1 → Win11. OpenSSL moved from vendored/Strawberry-Perl to vcpkg static (the openssl-src Configure target table doesn't map the Tier-3 triple). Mirrors CIRISEdge v2.2.1 / CIRISPersist v5.5.5 / CIRISVerify v5.1.3.
- **Substrate floor → the v2.2.1 cycle** — Cargo links persist v5.5.5 + edge v2.2.1 + keyring/verify v5.1.3; pyproject floor raised to `ciris-persist>=5.5.5,<6` (Win7-capable + RUSTSEC-2026-0178/0179/0180-fixed host; `<6` holds the family on persist 5.x / pyo3 0.28 — persist 6.0.0 is the separate pyo3 0.29 lockstep cycle).

# v1.1.0 — science layer + node/RET modes + Windows wheel on PyPI

**2026-06-12** — First feature release on the frozen v1.0 wire contract (the §8 canonical bytes are unchanged; all surface below is additive). Substrate floor: **persist 5.5.3 + edge 2.2.0 + verify 5.1.0**.

Detectors & client surface (Wave 1):
- **#3** — manifold mahalanobis detector. Diagonal Σ⁻¹ conformity scoring with a fail-secure trichotomy (Numeric / Indeterminate{ColdStart, SampleSizeBelowGate} / Unavailable{DegenerateCovariance}); consumes the RATCHET `crc-v1` §5.5.1 calibration bundle.
- **#12** — `LensAudit` typed audit surface (consent grant/revoke/expire, WBD, identity-change) signed through the host Engine's audit canonicalizers.
- **#14** — `EgressFilter` v0.4: 5-field extension (min_severity, include_detection_events/scores, redact_user_prompts/completions) + `apply_egress_filter` pure transform + PyO3 surface.

Deployment modes (Wave 2):
- **#15** — **node mode**: relay behavior plus the frozen public read API. Seven `GET /lens/api/v1/*` endpoints (scores, detection_events, manifold_conformity_aggregate, calibration_bundles) over an axum server, fronting the persist scores oracle. `LensCore::node(...)` + PyO3 `install_node`.
- **#34** — **RET-native cutover scaffolding**: `transport-reticulum` enabled on the edge 2.2.0 pin; `LensCore::ret_relay` (the Reticulum-wire analogue of `relay`, same handler + persist cohabitation); `ciris-canonical` enrollment tracker; CEG-envelope state-publication builder with the cohort-scope suppression gate. Gated follow-ons filed upstream: PQC KEX session-wrap (CIRISEdge#95), Registry community publication (CIRISRegistry#73), announce rooting (follow-on to CIRISEdge#53).

Packaging:
- **#48 / #43.3** — the **Windows wheel now actually publishes to PyPI**. The wheel built green every tag run since v1.0.1 but never reached PyPI: `publish-pypi` did not depend on `pyo3-wheel-windows`, so its artifact download raced the slow vendored-OpenSSL build and shipped only the 3 fast wheels (the Windows wheel went solely to the GitHub Release). `pyo3-wheel-windows` is now a first-class `publish-pypi` gate and the pre-publish floor is 4 wheels. This is the **Win8/10/11** wheel (stable toolchain); **Win7** loadability (Rust ≥1.78 std hard-imports) is tracked in **#48**.

# v1.0.1 — agent-fold patch (cross-wheel Engine + JCS/3.0.0 + release artifacts)

**2026-06-11** — Patch from the CIRISAgent 2.9.6 fold (CIRISLensCore#43). Substrate floor: **persist 5.5.2 + edge 2.1.1 + verify 5.1.0** (the floor that carries the Windows port).

- **#43.1 (P0)** — `LensClient` now takes an `engine=` kwarg (the host `ciris_persist.Engine`) and signs/persists through its **Python methods** (`local_sign` / `receive_and_persist`), fixing the pip-cohabitation `RuntimeError: no process Engine` (the per-wheel `current_rust_engine()` static can't be shared across cdylibs). `engine=None` keeps the rlib-fold path. Unblocks the agent fold.
- **#43.2** — JCS gate crossing: `TRACE_SCHEMA_VERSION` "2.7.9"→"3.0.0" and `canonical_bytes` dispatches the canonicalizer by schema version through persist's own `canon_version_for_trace_schema` (JCS for major ≥3, PythonJsonDumps for 2.7.x) — sign-side byte-identical to the verifier by construction.
- **#43.3** — ships the sibling release-artifact set on tag (GitHub Release: iOS/android tarballs + Chaquopy wheels + Windows wheel + `SHA256SUMS`) + a **Windows PyPI wheel**. The Windows wheel is real now that the upstream wall is gone: persist 5.5.2 (Unix paths cfg-gated, #200) + leviculum's `reticulum-std` Windows port + edge 2.1.1 (CIRISEdge#87). lens-core bundles OpenSSL on Windows (`target.'cfg(windows)'` `openssl/vendored` + nasm/Strawberry-Perl in CI).
- **Relaxed pin** — `ciris-persist==5.2.0` → `>=5.2.0,<6` (the v1.0.0 exact pin blocked persist currency; cohabitation is now name-based Python dispatch, version-tolerant). Cargo links bumped to persist 5.5.2 + edge 2.1.1.

#43.4 (canonical community key) tracked as a CIRISRegistry decision. Edge's side of the cohabitation handshake: CIRISEdge#85.

# v1.0.0 — wire-contract freeze + CIRISLensCore#11 client-emit surface

**2026-06-11** — The v1.0 milestone. Two things land together:
the wire-contract freeze (CIRISLensCore#18 — every frozen type
documented in `docs/PUBLIC_SCHEMA_CONTRACT.md` is now `stable-frozen`)
and the complete CIRISLensCore#11 client/emit surface — the
capture → seal → sign → persist pipeline that replaces the emit
half of CIRISAgent's `accord_metrics/services.py` (~3000 LOC Python).
This is the PoB §3.1 fold ABI: what the agent links against post-fold.

## Substrate floor

| Crate | v1.0.0 |
|---|---|
| `ciris-persist` | **v5.2.0** |
| `ciris-edge`    | **v2.0.1** |
| `ciris-verify`  | **v5.1.0** |

## What v1.0.0 ships

### CIRISLensCore#11 client-emit surface (`src/capture/`)

The `src/capture/` module lands in full:

- **`CaptureClient`** (`src/capture/client.rs`) — the rlib
  orchestrator. 9-argument constructor (`engine`, `scrubber`,
  `trace_level`, `trace_schema_version`, `correlation`,
  `consent_attesting_key_id`, `consent_config`, `deployment_profile`,
  `local_copy_dir`); async `capture_event(InboundEvent) ->
  Result<CaptureEventOutcome, ClientError>` (the per-thought entry
  point); async `orphan_sweep(now, max_age_secs) -> usize` (purges
  stale in-flight traces).

- **`CaptureEventOutcome`** — 5-variant result: `Opened`, `Appended`,
  `Rejected { raw }`, `SealedAndPersisted { trace_id, summary }`,
  `ConsentBlocked { reason }` (`"withdrawn"` or `"no_consent"`).

- **`ReasoningEventType`** (`src/capture/event.rs`) — 15-variant
  closed enum replacing the Python `EVENT_TO_COMPONENT` dict.
  `as_wire_str()` / `component_type()` / `seals_trace()` / `parse()`
  are compile-time total mappings; the CIRISAgent#757 /
  CIRISLens#13 mis-component drift class is structurally prevented.

- **`ComponentType`** — 12-variant bucket enum; 12-entry wire-string
  table locked by test.

- **`InboundEvent`** / **`PartialTraceStore`** / **`CompleteTrace`**
  (`src/capture/partial.rs`) — in-memory partial-trace assembly keyed
  by `thought_id`. `TRACE_SCHEMA_VERSION = "2.7.9"`. `orphan_sweep`
  is clock-injected (mirrors `plan_eviction` no-wall-clock discipline).

- **Canonical-bytes contract** (`src/capture/seal.rs`) —
  `build_canonical_envelope` shapes the 9(+1)-field signed envelope;
  `canonical_bytes` delegates to persist's
  `PythonJsonDumpsCanonicalizer` — byte-exact to CIRISAgent's
  `_build_canonical_message`. `strip_empty` recursive stripper (keeps
  `0` and `false`; drops `null`/`""`/`[]`/`{}`). `apply_signature` /
  `verify_trace_signature` / `sign_trace` / `sign_trace_via_hardware_signer`.
  The parity harness (`canonical_bytes_match_agent_fixtures`) locks
  byte-exactness against agent-generated test fixtures.

- **`build_batch_bytes` / `BatchProvenance` / `BatchBuildError`**
  (`src/capture/batch.rs`) — wraps signed traces into
  `BatchEnvelope` wire bytes accepted by `Engine::receive_and_persist`
  and the edge outbound dispatcher. Round-trip proven by
  `batch_parses_and_verifies_through_real_persist` (persist's real
  `BatchEnvelope::from_json` + `verify_trace`, no DB required).

- **`ConsentConfig` / `ConsentResolution` / `resolve_consent` /
  `resolve_consent_via_engine` / `CONSENT_DIMENSION`**
  (`src/capture/consent.rs`) — dynamic CEG consent gate.
  `Withdrawn → Withdrawn (never config)` is the privacy-critical
  invariant (CIRISAgent#870 / CIRISLensCore#34 recant cascade).
  Config-only path for the 2.9.6 interim (no canonical community key
  yet). Fails closed: a directory-read error is `Err`, not a silent
  fallback to config.

- **`CorrelationMetadata` / `fuzz_location_to_region`**
  (`src/capture/correlation.rs`) — PII-fuzz wire invariant closing
  CIRISAgent#757. `CorrelationMetadata::build` is the only
  constructor; raw `Option<f64>` lat/lng are fuzzed to 1-decimal
  region resolution immediately — un-fuzzed values cannot reach
  the wire. `fuzz_location_to_region` is byte-exact to the Python
  `_fuzz_location_to_region`.

- **Local-copy tee** — when `local_copy_dir` is set, each sealed
  batch is written to `{dir}/lens-batch-{seq:08}.json` as a
  best-effort forensic mirror (mirrors
  `CIRIS_ACCORD_METRICS_LOCAL_COPY_DIR`). Tee failures log a warning
  and never block persist.

### `LensClient` PyO3 pyclass (`src/ffi/pyo3.rs`)

The `LensClient` pyclass exposes the full client-emit surface to the
Python agent shim. Constructor accepts 15 named kwargs (`consent_timestamp`,
`trace_level`, and 13 optional kwargs). `capture_event(component: dict)
-> dict` returns one of five outcome dicts; `orphan_sweep(max_age_secs=3600)
-> int`. Registered in the `ciris_lens_core` module alongside the
existing `install_relay` + four drop-in functions.

### Sovereign rlib parity (#17 validated)

The rlib build (`--no-default-features`) compiles the full
`src/capture/` surface clean. Sovereign operators can link
`CaptureClient` directly without the Python wheel. The 9-argument
constructor is the rlib entry point; the Engine-as-parameter pattern
means no keys or DB configuration live inside the library.

### Wire-contract freeze (CIRISLensCore#18)

The following surfaces are promoted to `stable-frozen` at v1.0.0
(full detail in `docs/PUBLIC_SCHEMA_CONTRACT.md`):

- `crate::wire::*` (already frozen in v0.x; confirmed frozen)
- `CaptureClient::{new, capture_event, orphan_sweep}`
- `CaptureEventOutcome` (all 5 variants + outcome strings)
- `LensClient` PyO3 (kwarg constructor + methods + result-dict strings)
- `ReasoningEventType` + `ComponentType` + wire-string mappings
- `InboundEvent`; `TRACE_SCHEMA_VERSION`; `CONSENT_DIMENSION`
- `CorrelationMetadata::build` construction invariant (PII-fuzz)
- `canonical_bytes` / `strip_empty` / `apply_signature` /
  `verify_trace_signature` (byte-exact-to-agent federation-verify contract)
- `install_relay` / `attach_handler` (cohabitation entries; already frozen)

Surfaces kept `stable` (NOT frozen — additive evolution expected):
`EgressFilter` (CIRISLensCore#14), `ScoresOracle`,
`RetentionPolicy`, `ConsentResolution` engine-read path
(CIRISAgent#870 CEG sourcing still settling),
`LensCore::process` internals + detector family (CEG detector issues).

## Cohabitation contract

Exact-pin triple: `ciris-persist==5.2.0`, `ciris-edge==2.0.1`,
`ciris-verify==5.1.0`. A cohabiting host must construct a persist
**v5.2.0** Engine + edge **v2.0.1**.

`install_relay`, `LensCore::attach_handler`, `LensCore::relay`,
`process_trace_batch`, and the v0.1.x drop-in surface are
**unchanged**. `LensClient` is the addition.

## Upgrade path

`pip install --upgrade ciris-lens-core` — the deployed `ciris_persist`
wheel must be v5.2.0 and `ciris_edge` v2.0.1 for the shared-engine
process. For sovereign rlib consumers: `Cargo.toml` tag bump to
`v1.0.0`; the `CaptureClient::new` 9-argument constructor is the
new stable entry point for the fold.

---

# v0.4.5 — persist v4.10.0 + edge v1.5.0 + verify v5.0.0

**2026-06-09** — Cascade-catch-up onto the persist v4.10.0 / edge v1.5.0
floor. Pure pin bump — zero source changes.

## What changed

| Crate | v0.4.4 | v0.4.5 |
|---|---|---|
| `ciris-persist` | v4.9.0 (Cargo + pyproject `==`) | **v4.10.0** |
| `ciris-edge` | v1.4.1 | **v1.5.0** |
| `ciris-verify` (keyring + crypto) | v5.0.0 | v5.0.0 (unchanged) |

**persist v4.10.0** ships the CEG 0.8 §0.8.1 `location_proof` substrate
(V068 `federation_location_proofs` + H3 ≤7 resolution enforcement,
CIRISPersist#154) — off lens-core's path. It also **fixes the pyproject
`ciris-verify` ceiling** (`<5` → `>=5.0.0,<6`), which unblocks the
CIRISConformance matrix from carrying `ciris-verify==5.0.0` (the
`ResolutionImpossible` that parked the v0.4.4 matrix re-add is resolved
at the root).

**edge v1.5.0** is the first version-stable replication line
(`FSD/REPLICATION_WIRE_FORMAT_V1.md` — 10-variant `EnvelopeKind`,
`WIRE_PROTOCOL_VERSION=0x01`, strict v1 parser). That replication wire
lockdown is off lens-core's path — lens-core uses edge's
`transport-http` + `Handler<AccordEventsBatch>` surface, unchanged. The
full 120-test suite is green on rlib + python against the new triple;
clippy + fmt clean; single-version lockfile re-resolve (no skew).

## Cohabitation contract

Unchanged surface (`install_relay`, `LensCore::attach_handler`,
`LensCore::relay`, `process_trace_batch`, the v0.1.x drop-in;
`PROJECTION_VERSION` still `crc-v1`). Exact-pin moves
`ciris-persist==4.9.0` → `==4.10.0`: a cohabiting host must construct a
persist **v4.10.0** Engine + edge **v1.5.0**.

## Upgrade path

`pip install --upgrade ciris-lens-core` — the deployed `ciris_persist`
wheel must be v4.10.0 and `ciris_edge` v1.5.0 for the shared-engine
process (exact-pin cohabitation contract).

---

# v0.4.4 — persist v4.9.0 + edge v1.4.1 + verify v5.0.0 (CEG 1.0 / Agent 3.0 substrate)

**2026-06-09** — Cascade-catch-up onto the **CEG 1.0 / Agent 3.0**
substrate triple: persist v4.4.0 → **v4.9.0**, edge v1.3.2 → **v1.4.1**,
verify v4.11.0 → **v5.0.0** (a verify MAJOR). Pure pin bump — zero
source changes.

## What changed

| Crate | v0.4.3 | v0.4.4 |
|---|---|---|
| `ciris-persist` | v4.4.0 (Cargo + pyproject `==`) | **v4.9.0** |
| `ciris-edge` | v1.3.2 | **v1.4.1** |
| `ciris-verify` (keyring + crypto) | v4.11.0 (`version "4"`) | **v5.0.0** (`version "5"`) |

**The verify MAJOR (4→5) is additive for lens-core.** CIRISVerify
v5.0.0 is the "CEG 1.0 / Agent 3.0 substrate release" — the major
marks the milestone, but its code changes are additive (a
`boundary_degraded` attestation distinct from `hardware_trust_degraded`;
a `jcs_canonicalize` Python binding — the JCS RFC-8785 canonicalizer
that the v4.4 attestation `promote` phase 2 needed, CIRISVerify#59).
The `ciris_keyring` / `ciris_crypto` API lens-core links for its relay
transport-signing identity (`LocalSigner`, `load_local_seed`,
`sign_ml_dsa_65`, `LocalSignerError`) is unchanged. Lens-core's Cargo
`ciris-keyring` pin moves `version "4"` → `"5"` to track the major; the
full rlib + python build + 120-test suite is green against the new
triple, single-version lockfile re-resolve (no skew).

persist v4.4.0 → v4.9.0 (5 minors of substrate work atop the v4.4 CEG
attestation surface) is also off lens-core's path — it consumes
`ciris_persist::derived::*` + the unchanged `Engine` facades.

## Cohabitation contract

Unchanged surface (`install_relay`, `LensCore::attach_handler`,
`LensCore::relay`, `process_trace_batch`, the v0.1.x drop-in;
`PROJECTION_VERSION` still `crc-v1`). Exact-pin moves
`ciris-persist==4.4.0` → `==4.9.0`: a cohabiting host must construct a
persist **v4.9.0** Engine + edge **v1.4.1** (linking verify **v5.0.0**).

## Upgrade path

`pip install --upgrade ciris-lens-core` — the deployed `ciris_persist`
wheel must be v4.9.0 and `ciris_edge` v1.4.1 for the shared-engine
process (exact-pin cohabitation contract).

---

# v0.4.3 — persist v4.4.0 (CEG attestation surface) + edge v1.3.2 + verify v4.11.0

**2026-06-08** — Cascade-catch-up patch onto the v4.4 substrate floor:
persist v4.3.0 → **v4.4.0**, edge v1.3.1 → **v1.3.2**, verify v4.10.0 →
**v4.11.0**. Pure pin bump — zero source changes.

## What changed

| Crate | v0.4.2 | v0.4.3 |
|---|---|---|
| `ciris-persist` | v4.3.0 (Cargo + pyproject `==`) | **v4.4.0** |
| `ciris-edge` | v1.3.1 | **v1.3.2** |
| `ciris-verify` (keyring + crypto) | v4.10.0 | **v4.11.0** |

**persist v4.4.0 is the Shared CEG Attestation Surface phase 1**
(CIRISPersist#171/#173) — the local-tier write + read-gate half of
`federation_attestations` (`attestation_upsert_local`,
`attestation_query`, the `local`/`federation` tier model + AV-59/60/61
read gate). Lens-core reviewed this surface as a federation consumer
(CIRISPersist#172) — flagging the `capacity:*` anti-Goodhart local-tier
condition (CEG §7.5). The surface is **additive**: lens-core's existing
consumption (`ciris_persist::derived::*` calibration + detection-event
reads, `Engine::{get_detection_events, receive_and_persist}` facades)
is unchanged, so this is a clean pin bump — full 120-test suite green
on rlib + python; single-version lockfile re-resolve, no skew.

Lens-core does **not** yet write through the new attestation surface;
the `detection:*` / `capacity:*` CEG-native ingest migration is
tracked at CIRISLensCore#857 (gated on the v4.4 `promote` phase 2 +
the agent-side CEG-native spine). v0.4.3 just tracks the substrate
floor.

**Note:** CIRISVerify v4.11.0 is now the edge-pinned floor (edge v1.3.2
consumes persist v4.4.0 + verify v4.11.0).

## Cohabitation contract

Unchanged surface (`install_relay`, `LensCore::attach_handler`,
`LensCore::relay`, `process_trace_batch`, the v0.1.x drop-in;
`PROJECTION_VERSION` still `crc-v1`). Exact-pin moves
`ciris-persist==4.3.0` → `==4.4.0`: a cohabiting host must construct a
persist **v4.4.0** Engine + edge **v1.3.2**.

## Upgrade path

`pip install --upgrade ciris-lens-core` — the deployed `ciris_persist`
wheel must be v4.4.0 and `ciris_edge` v1.3.2 for the shared-engine
process (exact-pin cohabitation contract).

---

# v0.4.2 — persist v4.3.0 + edge v1.3.1 + verify v4.10.0 substrate floor

**2026-06-08** — Cascade-catch-up patch onto the finalized substrate
floor: persist v4.1.0 → **v4.3.0**, edge v1.2.1 → **v1.3.1**, verify
v4.8.1 → **v4.10.0**. Pure pin bump — zero source changes.

## What changed

| Crate | v0.4.1 | v0.4.2 |
|---|---|---|
| `ciris-persist` | v4.1.0 (Cargo + pyproject `==`) | **v4.3.0** |
| `ciris-edge` | v1.2.1 | **v1.3.1** |
| `ciris-verify` (keyring + crypto) | v4.8.1 | **v4.10.0** |

persist v4.1.0 → v4.3.0 continues the streaming-substrate line (the
v4.1 CEG 0.10 §10.5 chunked-blob / transparency-log / AES-256-GCM
work, extended through the v4.2/v4.3 cuts) and re-pins to verify
v4.10.0. edge v1.3.1 consumes persist v4.3.0 + verify v4.10.0. None of
it is on lens-core's path — lens-core reads `ciris_persist::derived::*`
(calibration bundles + detection events) + the unchanged `Engine`
facades, so the migration is a clean pin bump (full 120-test suite
green on both rlib + python; clean single-version lockfile re-resolve,
no dual-persist/verify skew).

**Note:** CIRISVerify v4.11.0 exists, but edge v1.3.1 pins verify
v4.10.0 — lens-core matches the released substrate at v4.10.0 rather
than chasing ahead of the cascade (same discipline as the v4.8.1 hold
at v0.4.1).

## Cohabitation contract

Unchanged surface (`install_relay`, `LensCore::attach_handler`,
`LensCore::relay`, `process_trace_batch`, the v0.1.x drop-in;
`PROJECTION_VERSION` still `crc-v1`). Exact-pin moves
`ciris-persist==4.1.0` → `==4.3.0`: a cohabiting host must construct a
persist **v4.3.0** Engine + edge **v1.3.1**. Re-admits lens-core to the
CIRISConformance matrix (which had advanced to the persist v4.3.0 floor
ahead of lens-core; v0.4.1's `==4.1.0` pin was incompatible).

## Federation timing

Edge was the gating sister this cycle — persist jumped 4.1.0 → 4.3.0
(pulling verify 4.10.0) while edge stayed on the 4.1.0 floor, so
lens-core held to avoid a dual-version skew. Once edge v1.3.1 shipped
consuming persist v4.3.0, the floor was coherent and lens-core caught
up. Cascade order held: persist → edge → **lens-core** →
nodecore/agent/bridge.

## Upgrade path

`pip install --upgrade ciris-lens-core` — the deployed `ciris_persist`
wheel must be v4.3.0 and `ciris_edge` v1.3.1 for the shared-engine
process (exact-pin cohabitation contract).

---

# v0.4.1 — persist v4.1.0 + edge v1.2.1 + verify v4.8.1 substrate floor (streaming cut)

**2026-06-07** — Patch release tracking the next substrate-floor move:
the CIRISPersist v4.1.0 streaming-substrate cut (CEG 0.10 §10.5) + the
CIRISEdge v1.2.1 + CIRISVerify v4.8.1 cascade. Like v0.4.0, this is a
**pure pin bump — zero source changes**.

## What changed

| Crate | v0.4.0 | v0.4.1 |
|---|---|---|
| `ciris-persist` | v4.0.1 (Cargo + pyproject `==`) | **v4.1.0** |
| `ciris-edge` | v1.2.0 | **v1.2.1** |
| `ciris-verify` (keyring + crypto) | v4.8.0 | **v4.8.1** |

**persist v4.1.0** is the streaming substrate — `get_blob_range`,
`BlobBody::ChunkDag`, `federation_stream_chunks`, per-stream
transparency log (producer-signed STH + RFC 6962 proofs), STREAM-nonce
AES-256-GCM chunk sealing, and `key_grant` stream/epoch addressing
(migrations V061–V064). It implements CEG 0.10 §10.5 blob streaming.

**verify v4.8.1** fixes the Android probe semantic + decouples local
checks from the network race (closes CIRISVerify#56).

**Lens-core consumes none of it.** The streaming primitives are a new
substrate axis lens-core doesn't touch — it still reads
`ciris_persist::derived::*` (calibration bundles + detection events) +
the unchanged `Engine` facade methods. The full 120-test suite passes
on both the rlib and python feature paths against the v4.1.0 substrate
with zero code modification; fmt + clippy clean.

## Cohabitation contract

Unchanged surface (`install_relay`, `LensCore::attach_handler`,
`LensCore::relay`, `process_trace_batch`, the v0.1.x drop-in;
`PROJECTION_VERSION` still `crc-v1`). The exact-pin moves
`ciris-persist==4.0.1` → `==4.1.0`: a cohabiting host must now
construct a persist **v4.1.0** Engine + edge **v1.2.1**. The federation
cascade (persist v4.1.0 → edge v1.2.1 → **lens-core v0.4.1** →
nodecore/agent/bridge) moves the tree to the streaming-substrate floor
together. Re-admits lens-core to the CIRISConformance matrix (dropped
again at v0.4.0 pending this bump — same shape as the 0.3.0 → 0.4.0
cycle, persist-minor floor this time rather than persist-major).

## Upgrade path

`pip install --upgrade ciris-lens-core` — the deployed `ciris_persist`
wheel must be v4.1.0 and `ciris_edge` v1.2.1 for the shared-engine
process (exact-pin cohabitation contract).

---

# v0.4.0 — persist v4.0.1 + edge v1.2.0 substrate floor (Data Access Surface cut)

**2026-06-06** — Cohabitation pin bump consuming the CIRISPersist v4.0
Data Access Surface cut + CIRISEdge v1.2.0. This is the §15.5
consumer-migration-cascade landing for lens-core — the first lens-core
release that relaxes the persist floor from `==3.14.3` to `==4.0.1`,
re-admitting lens-core to the CIRISConformance cohabitation matrix
(which dropped it at v0.3.0 pending this bump).

## What changed

**Federation pins:**

| Crate | v0.3.0 | v0.4.0 |
|---|---|---|
| `ciris-persist` | v3.14.3 (Cargo + pyproject `==`) | **v4.0.1** |
| `ciris-edge` | v1.1.11 | **v1.2.0** |
| `ciris-verify` (transitive) | v4.8.0 | v4.8.0 (unchanged) |

**Source changes: none.** This is a pure pin bump. The persist v4.0 cut
is a hard break for *read-surface consumers* — `src/read/*` reorganized
into topic-named `ceg::*` namespaces, every scope-protected read gained
a `CallerScope` argument, `Error::NotImplemented` removed. But lens-core
consumes **none of the reorganized surface**:

- Calibration-bundle reads go through `ciris_persist::derived::*`
  (`CalibrationBundle`, `CohortCentroid`, `ProjectionMetadata`,
  `Standardization`), which the v4.0 cut explicitly kept in place —
  `derived/` is a consumer-facing artifact axis, NOT part of the
  scope-protected `ceg/` read reorganization.
- Detection-event reads go through `Engine::get_detection_events(filter)`
  — unchanged signature; no `CallerScope` param.
- The relay write path goes through `Engine::receive_and_persist(bytes,
  scrubber)` — unchanged signature. The new write-path admission gate
  (AV-45 closure) derives the writer's admission from the verified
  envelope signer *inside* the call; no new parameter crosses the API.

The full test suite (120 tests) passes on both the rlib and python
feature paths against v4.0.1 with zero code modification.

## Why lens-core influenced the v4.0 cut

Lens-core's consumer review on CIRISPersist#160 pushed back on the
original FSD's deferral of write-path cohort_scope to v4.1. That
critique was accepted and folded into v4.0: the AV-44 (read-side
escalation) ↔ AV-45 (write-side downgrade) asymmetry would have
collapsed the §9 defense-in-depth claim on the write side. Both attack
vectors now close by construction in v4.0.1. The cache time-bucket
soundness gap and admission-resolution caching (§7.5) also came out of
that review.

## Cohabitation contract

Unchanged surface: `install_relay(edge)`, `LensCore::attach_handler`,
`LensCore::relay`, `process_trace_batch`, the v0.1.x 4-function
drop-in. `PROJECTION_VERSION` still `crc-v1`. The single difference a
cohabiting agent sees: the shared process must now construct a persist
**v4.0.1** Engine + edge **v1.2.0** — a host pinned to persist v3.x can
no longer cohabit a lens-core v0.4.0 handler (single-version contract).

## Upgrade path

`pip install --upgrade ciris-lens-core` — but note the exact-pin
cohabitation contract: the deployed `ciris_persist` wheel must be
v4.0.1 and `ciris_edge` v1.2.0 for the shared-engine process. The
federation cascade (persist v4.0.1 → edge v1.2.0 → **lens-core v0.4.0**
→ nodecore / agent / bridge) moves the whole tree to the v4 substrate
floor together.

---

# v0.3.0 — RATCHET `crc-v1` calibration bundle consumption (#3 partial close)

**2026-06-05** — Minor release. CIRISAI/RATCHET shipped its initial
calibration package `crc-v1` on 2026-05-13 (264-thought corpus,
16-field projection, per-cohort centroids, `sample_size_gate: 500`,
provisional `2.5σ` Mahalanobis threshold). Lens-core v0.3.0 lands the
**consumption path** — partial close on CIRISLensCore#3.

## What v0.3.0 ships

### `src/scoring/calibration.rs` — typed `CalibrationBundle`

Strict-validation mirror of the RATCHET bundle:

- `CalibrationBundle::from_yaml(&str)` — sovereign-mode loaders that
  ship the bundle alongside the binary parse the YAML form directly
  (used by tests + the standalone-rlib path).
- `CalibrationBundle::from_persist_row(...)` — runtime path; consumes
  persist v3.14.3's `CalibrationBundle` row shape from the
  `cirislens_derived.calibration_bundles` table (`DerivedSchema::
  get_current_calibration_bundle`).
- `Projection`, `Standardization`, `CohortCentroid` — sub-shapes
  intentionally lens-core-local, NOT re-exports from persist, so the
  strict-validation invariants live on lens-core's side of the
  boundary. Length / mismatch / version-pin checks fail loudly at
  construction; `BundleError` is a 9-variant `thiserror` enum that
  names exactly which invariant the input violated.
- `CRC_V1_FIELD_ORDER` — the 16-string lock-in for the
  `projection_version: crc-v1` field order. Validated against every
  bundle's `field_order`; mismatch is `BundleError::FieldOrderMismatch
  { index }`, never silent acceptance.

### `LensCore::with_calibration_bundle` — builder wiring

The runtime carries the bundle on the `LensCore` handle; pipeline
lifecycle now consults the bundle before falling back to the
LC-AV-9 cold-start path. Without a bundle, behavior is unchanged
from v0.2.x. With the bundle:

- Trace's inferred cohort IS in `bundle.centroids` AND
  `centroid.sample_count >= bundle.sample_size_gate` →
  (Phase 2: score against centroid. v0.3.0: still no-op detector,
  returns `Indeterminate{CohortColdStart}` — code comment marks the
  spot where Phase 2 lands the centroid-Mahalanobis branch.)
- Trace's inferred cohort IS in `bundle.centroids` AND
  `centroid.sample_count < bundle.sample_size_gate` →
  `ManifoldConformity::Indeterminate{SampleSizeBelowGate{current,
  gate}}` (sharper reason than v0.2.x's `CohortColdStart`).
- Trace's inferred cohort NOT in `bundle.centroids` →
  `Indeterminate{CohortColdStart}` (genuine cold-start; cohort not
  present in calibration corpus).

### Sample-size gate behavior with shipped `crc-v1`

The shipped `crc-v1` bundle has 3 cohort cells with sample counts
119 / 90 / 55 — **all below the 500-thought gate**. So every trace
that matches one of those 3 cohorts gets
`Indeterminate{SampleSizeBelowGate{current, gate: 500}}`; cohorts not
in the corpus get `CohortColdStart`. Either way the fail-secure shape
holds; the reason-variant is sharper post-bundle. Real `Numeric(σ)`
verdicts await both (a) RATCHET's next calibration run with ≥3 cells
above the gate (per `crc-v1/README.md` "v0.2 plan") AND (b) lens-core
Phase-2 detector body landing.

### `IndeterminateReason::SampleSizeBelowGate` — new return path

`scoring/assembly.rs` gained an `AssemblyInput::BundleSampleBelowGate
{ current, gate }` variant + handler + test. The pre-bundle world
could only produce `SampleSizeBelowGate` via the calibration-time-
windowed gate; the bundle world now produces it on the read path
too, with the same `current` / `gate` numbers in the reason payload
so consumers see why scoring fell through.

### `src/detector/mod.rs` — docstring currency

The "until RATCHET delivers centroids" framing is gone. RATCHET HAS
delivered centroids (the bundle ships them); the no-op detector now
gates on "Phase 2 detector body landing" — a lens-core-internal
gate, not a substrate-external one. Mirrors the MISSION pass-2.2
discipline (RATCHET ≠ "not shipped"; per-axis-family extension is
the unshipped piece).

## Tests added: 6

- `scoring::calibration::parses_shipped_crc_v1_bundle` — reads
  `CIRISAI/RATCHET/release/calibration/crc-v1/bundle.yaml` at test
  time, asserts every load-bearing field round-trips (version,
  ratchet_calibration_version, gate, threshold, 16-field order,
  14-of-16 retention mask, all 3 cohorts below gate).
- `scoring::calibration::projection_version_must_match_lens_core_constant`
  — `crc-v2` would be silently accepted in a less-strict world; lens-
  core fails loudly.
- `scoring::calibration::field_order_mismatch_rejected_at_index` —
  reorders fields, asserts `FieldOrderMismatch{index: 0}`.
- `scoring::calibration::lookup_cohort_returns_some_for_known_cohort`
  — all-null cohort, sample_count=119.
- `scoring::calibration::lookup_cohort_returns_none_for_unknown_cohort`
  — fallthrough path.
- `scoring::assembly::bundle_sample_below_gate_yields_indeterminate_with_numbers`
  — `current` and `gate` carry through to the emitted Indeterminate
  payload so consumers can render the gate gap.

## Substrate dependency

- `serde_yaml = "0.9"` added to `Cargo.toml` for the
  `CalibrationBundle::from_yaml` sovereign-loader path.
- `ciris-persist v3.14.3` already exposes
  `derived::{CalibrationBundle, CohortCentroid, ProjectionMetadata,
  Standardization}` plus `DerivedSchema::{put_calibration_bundle,
  get_current_calibration_bundle, get_calibration_bundle_by_version}`
  on both sqlite + postgres backends. No upstream gate was hit.

## Known follow-ons

- **Phase 2 detector body** (still no-op at v0.3.0). The
  `assembly_input_from_bundle` "above-gate" branch is the spot;
  centroid-Mahalanobis scoring replaces it when ready.
- **`Engine::get_current_calibration_bundle()` facade** (CIRISPersist
  ask, not blocking). Trait method exists; an Engine-level convenience
  wrapper would let consumers skip the `engine.backend()` match.
- **Bundle freshness signal**. `bundle.calibrated_at` is carried as
  `Option<String>` on lens-core's typed bundle; consumers can stale-
  check, but no explicit freshness-policy hook lands at v0.3.0.

## Upgrade path

`pip install --upgrade ciris-lens-core` for the Python cohabitation
agents; `Cargo.toml` tag bump for the rlib consumers. No breaking
API change — `process_trace_batch` + `install_relay` + the v0.1.x
4-function drop-in surface all stable.

`LensCore::with_calibration_bundle` is opt-in additive; existing
constructors (`LensCore::relay`, `LensCore::attach_handler`) work
unchanged and route every trace through the v0.2.x cold-start path
as before.

---

# v0.2.2 — `__version__` module attribute

**2026-06-05** — Patch release. Python-stdlib convention is that
top-level packages expose a `__version__` string attribute; v0.2.0
and v0.2.1 omitted it, and the CIRISConformance solo-imports check
accepted `getattr(ciris_lens_core, '__version__', None) is None`
rather than asserting a concrete value. Downstream tooling that
reads `__version__` directly (rather than going through
`importlib.metadata.version("ciris-lens-core")`) saw `None` on
v0.2.0 + v0.2.1 wheels — `pip show`-style introspection and any
consumer that mirrors the pattern across the federation
(`ciris_persist.__version__`, `ciris_edge.__version__`, etc.) got
a non-usable value.

v0.2.2 adds `__version__ = "0.2.2"` to
`python/ciris_lens_core/__init__.py` next to `PROJECTION_VERSION`
in the import/`__all__` block, mirroring the surface symmetry — both
are module-level string constants the deployed lens and cohabitation
agent can read directly. `importlib.metadata` consumers see the
same value via the wheel's `METADATA`; the two paths now agree.

No Rust source changes. The cdylib bytes are identical to v0.2.1
modulo build-stamp; the wheel deliverable changes only in the
Python shim and the version metadata.

**Upgrade path:** `pip install --upgrade ciris-lens-core` is
sufficient. Code that was tolerating
`ciris_lens_core.__version__ is None` continues to work; code that
needs a concrete string now gets one.

---

# v0.2.1 — `install_relay` re-export hotfix

**2026-06-05** — Patch release. v0.2.0's PyO3 cdylib correctly registers
`install_relay` (the cohabitation bootstrap entry — see v0.2.0 notes
below), but the Python `__init__.py` shim at
`python/ciris_lens_core/__init__.py` did not re-export the symbol;
`dir(ciris_lens_core)` on the v0.2.0 wheel surfaced
`process_trace_batch / scrub_trace / scrub_traces_batch /
ner_is_configured / PROJECTION_VERSION` only, and `install_relay`
was unreachable from the top-level module despite the v0.2.0
release notes naming it the cohabitation entry. Every cohabitation
agent post-fold-in calls `ciris_lens_core.install_relay(edge)`; on
v0.2.0 that resolves to `AttributeError`.

CIRISConformance `test_ciris_lens_core_exposes_install_relay`
(`tests/test_010_solo_imports.py`) is the regression gate going
forward — locks `install_relay in dir(ciris_lens_core)` for every
matrix entry.

Also folds in the MISSION.md three-pass refresh (drift fix + CEG
§5.5 alignment + F-3 / distributive reconciliation to v0.2.0 source
state) and refreshes the `__init__.py` docstring to current
cohabitation terminology (`local_sign` not `steward_sign`; fold-in
in past tense not future).

No Rust source changes. The cdylib bytes are identical to v0.2.0
modulo build-stamp; the wheel deliverable changes only in the
Python shim and the version metadata.

**Upgrade path:** `pip install --upgrade ciris-lens-core` is
sufficient. Cohabitation agents that were calling
`install_relay` and failing with `AttributeError` on v0.2.0 work
out of the box on v0.2.1.

---

# v0.2.0 — federation cohabitation + CEG §5.5 foundations

**2026-05-30** — The lens-core release the deployed Python lens
adopts to track the persist 3.x + edge 1.x federation. Triple-bump
to the CIRISConformance matrix (persist v3.14.3 + edge v1.1.10 +
verify v4.8.0) + v0.2 cohabitation surface + v0.4 retention &
scoring + CEG §5.5 type-system foundations.

## What v0.2.0 ships

### v0.2 cohabitation — lens-core as a key-addressable Edge endpoint

The agent constructs ONE persist `Engine` + ONE `Edge` per process
(CIRIS 3.0 in-process model); sibling consumers — NodeCore,
lens-core — install handlers onto the shared `Arc<Edge>`. Three
ways in:

- `LensCore::relay(engine, key_id, seed_dir, listen_addr,
  peer_urls)` — standalone rlib ctor; builds its own Edge,
  registers `LensCoreHandler<AccordEventsBatch>`, spawns the
  listener, returns a `RelayHandle` with orderly `shutdown()`.
  Used by the deployed-Python-lens cutover where lens-core is
  the only consumer in the process.
- `LensCore::attach_handler(&edge, engine)` — cohabitation rlib
  entry; registers on a host-built shared `Edge`. Used by
  pure-Rust embeddings (agent linking lens-core as a library).
- `ciris_lens_core.install_relay(edge)` — PyO3 cohabitation
  bootstrap. Python form of `attach_handler`. Mirrors
  `ciris_node_core.install_from_dispatch(...)`. The agent's
  Python startup calls `ciris_edge.init_edge_runtime(...)` →
  `ciris_node_core.install_from_dispatch(...)` →
  `ciris_lens_core.install_relay(edge)` — three lines, full
  federation participation.

After `install_relay`, lens-core IS a key-addressable Edge
endpoint: peers routing `AccordEventsBatch` to its `key_id` land
on `LensCoreHandler` and flow into `engine.receive_and_persist(
&bytes, &NullScrubber)`. Relay mode is store-and-forward transit;
scrubbing is the originating client node's egress responsibility,
NOT the relay's (federation contract — re-scrubbing at relays
causes NER-version content drift).

### v0.3 config foundation — pan-mode shared shapes

`#[non_exhaustive]` config structs every `LensCore` mode shares:

- `UpstreamLens { lens_steward_key_id, egress_filter }` — a
  destination in the multi-recipient fan-out, keyed by federation
  `key_id` (not hostname)
- `EgressFilter { trace_level }` — what gets forwarded to a given
  upstream; v0.4 extends with severity/redaction/inclusion bits
- `RetentionPolicy { max_disk_gb, max_age_days, per_level_max_age,
  detection_events_max_age_days, audit_log_max_age_days }` — local-
  store eviction bounds

### v0.4 retention enforcement (CIRISLensCore#13)

`src/retention/` composes on top of persist v2.7.0+'s retention
primitives (CIRISPersist#107):

- `plan_eviction(summary, policy, now)` — pure function over
  storage summary + policy + clock. Returns an `EvictionPlan`.
- `execute_plan(engine, plan)` — async; calls
  `Engine::delete_traces_older_than` in a bounded batch loop.
- `evict_per_retention_policy(engine, policy)` — convenience entry.

v0.4 enforces three of five `RetentionPolicy` dimensions:
`max_age_days`, `max_disk_gb` (90% threshold), and
`audit_log_max_age_days` planning. The other two
(`per_level_max_age`, `detection_events_max_age_days`) are
documented; planner emits the planned action; executor records a
`tracing::debug!` note. Awaits per-level + detection-events delete
primitive expansion on persist.

### v0.4 scoring oracle (CIRISLensCore#19)

`src/scores/` ships the agent-side score read path per FSD §4.6 —
closes the agent's self-awareness loop:

- `ScoresOracle<'a>::for_trace(trace_id)` — `Vec<DetectionEvent>`
- `ScoresOracle<'a>::for_agent_window(start, end, detectors?)` →
  `AgentScoreAggregate` (per-detector + per-severity +
  per-conformity counts)
- `ScoresOracle<'a>::detector_history(detector, since,
  min_severity)` → filtered `Vec<DetectionEvent>` (>= min_severity)
- Pure `compute_aggregate` reduction over `&[DetectionEvent]` —
  testable without an `Engine`

### CEG §5.5 foundations — load-bearing invariants at the type level

CIRISRegistry shipped CEG 0.1 + 0.2 (FSD/CEG/) during this window.
Lens-core's §5.5 share gets three foundations, each enforcing a
spec-level invariant in the type system rather than as best-effort
validation:

- **§5.5.1 — `CoherenceRatchetDetector` closed enum** — the five
  Coherence-Ratchet detection dimensions (cross_agent_divergence,
  intra_agent_consistency, hash_chain_integrity, temporal_drift,
  conscience_override_rate). `const fn dimension_label()` makes
  the wire mapping a compile-time property. Wire-label-exactness
  test locks the dimension labels against silent rename.
- **§5.5.4 — `CapacityFactors`** — typed C·I_int·R·I_inc·S product
  with range-validated factors and multiplicative composite. Any
  factor at zero zeros the composite (CEG design: a single failed
  dimension can't be averaged away). Serde re-validates on the wire.
- **§7.5 — `CapacityAttestation`** — anti-Goodhart self-attestation
  rejected at construction. `attesting_key_id == attested_key_id`
  is a typed error, not a validation failure. Serde re-validates
  so bytes can't bypass via `Deserialize`.

Plus `src/wire/` re-exports for the typed Goal primitive from
persist v2.10.0 (CIRISPersist#114) — Goal, MetaGoalAlignment,
M1Dimension (closed enum: Sustainability / Adaptivity / Coherence
/ Plurality / Flourishing / Justice / Wonder), GoalScope,
GoalsFilter, DeliberationRef. Every Goal in the federation carries
M-1 alignment by structural construction-time invariant.

### Federation pin discipline — CIRISConformance-tracked

Lens-core's `Cargo.toml` + `pyproject.toml` pins now track the
CIRISConformance matrix. The conformance harness pins the current
cohabitation triple; lens-core re-pins in lockstep. Single-
version-clean is the contract — all co-resident consumers
(lens-core + edge + NodeCore + agent) link the identical persist
in one process.

Triple as of v0.2.0:

```
ciris-persist   v3.14.3
ciris-edge      v1.1.10
ciris-verify    v4.8.0     (transitive)
python floor    3.10
abi3            py310
```

### PyO3 surface — v0.1.1 contract preserved

The v0.1.1 four-function deployed-lens drop-in surface
(`process_trace_batch`, `scrub_trace`, `scrub_traces_batch`,
`ner_is_configured`) is preserved verbatim. v0.2.0 adds
`install_relay(edge)` for the cohabitation bootstrap. Existing
v0.1.x callers do not need source changes; `import ciris_lens_core
as cirislens_core` continues to work.

## What v0.2.0 does NOT yet ship

- `LensCore.client(...)` PyO3 ctor — replaces ~3000 LOC of
  CIRISAgent's metrics service (CIRISLensCore#11). Design forks
  on capture sub-namespace shape; v0.3.0 milestone.
- `LensCore.audit.*` PyO3 — typed action vocabulary
  (CIRISLensCore#12). v0.3.0.
- Wire-contract v1.0 freeze (CIRISLensCore#18). Depends on the
  CI/docs spike landing first.
- Node-mode UX endpoints — `/scores`, `/detection_events` HTTP
  read API (CIRISLensCore#15). v0.4.x.
- Per-upstream EgressFilter behaviors beyond `trace_level`
  (CIRISLensCore#14). v0.4.x.
- F-3 detector family + ECF UI surfaces (CIRISLensCore#23 / #24 /
  #25 / #26 / #29). Calibration package gates from RATCHET.

## Lens-core issues closed in v0.2.0

#6, #10, #13, #16, #19 — all shipped during this window.

## Verification

Both `--features python` and `--no-default-features` compile clean.
106 tests passing each. clippy `-D warnings` clean both feature
builds. fmt clean. cargo deny check: advisories ok, bans ok,
licenses ok, sources ok.

---

# v0.1.1 — abi3-py311 wheel + macos-14 CI fix

**2026-05-20** — Bug-fix release for the v0.1.0 CI breakage.
v0.1.0's tag run failed on (a) `pyo3 0.20` RUSTSEC-2025-0020 and
the resulting `cp311-cp311` (not abi3) wheel shape, and (b)
`macos-14` rust-cache restoring a `rustup-init` stub over the
real `cargo` binary. v0.1.1 fixes both:

- `pyo3 0.20 → 0.28` + `abi3-py311` feature → cp311-abi3 wheels
  consumable on Python 3.11+
- `Bound` API migration to satisfy the pyo3 0.28 shape
- `cache-bin: false` on macos-14 jobs (per persist v0.7.3
  precedent) so the rust-cache restore doesn't shadow dtolnay's
  cargo install

Functionality identical to v0.1.0 — the v0.1.0 → v0.1.1 delta is
all CI / wheel-shape repair.

---

# v0.1.0 — Phase 1 science layer + deployed-lens drop-in

**2026-05-15** — First PyPI release. Phase 1 of the science-layer
runtime + the four-function deployed-lens drop-in surface.

## What v0.1.0 ships

### Science layer (Phase 1)

- `src/cohort/` — declared 6-tuple parsing + `cohort_cell` JSON
  building + LC-AV-2 declared-vs-inferred mismatch tracking
- `src/detector/` — no-op detector for v0.1.0 (architecturally
  correct fail-secure during LC-AV-9 cold-start window until
  RATCHET delivers calibration centroids)
- `src/scoring/` — Kish `n_eff`, capacity-band gate, LC-AV-18
  sample-size assembly, `ManifoldConformity` enum
  (`Numeric`/`Indeterminate`/`Unavailable`)
- `src/extract/projection.rs` — `crc-v1` 16-feature projection
  (10 floats + 6 bools) against RATCHET-calibrated cohort
  centroids
- `src/pipeline/lifecycle.rs` — `LensCore { signer, journal }` +
  per-trace `process(trace, sample_size_gate,
  ratchet_calibration_version)` orchestrator
- `src/signing/event.rs` — hybrid (Ed25519 + ML-DSA-65) signed
  detection events; bound construction (PQC signs canonical
  bytes ++ ed25519 sig)
- `src/wire/` — federation-public ABI: BatchEnvelope,
  CompleteTrace, TraceComponent, ReasoningEventType re-exports
  from persist's `schema::*` (single-source-of-truth canonical
  bytes via `canonicalize_envelope_for_signing`)

### Deployed-lens drop-in (PyO3)

Four free functions the existing Python deployed lens can swap
into in place of `cirislens_core` with a one-line import alias:

```python
import ciris_lens_core as cirislens_core  # one line
```

- `process_trace_batch(engine, events, ...)` — orchestrates the
  science layer; persist signs + persists. Engine-as-parameter
  (lens-core never holds keys).
- `scrub_trace(trace_json, level)` — delegates to
  `ciris_persist::pipeline::scrub::scrub_trace`
- `scrub_traces_batch(traces_json, level)` — batch scrub
- `ner_is_configured()` — reports whether the persist scrubber's
  NER backend is configured

### Engine-as-parameter pattern

Lens-core is a science layer, not a federation identity. The
signing identity belongs to the host (the deployed lens today;
the agent post-PoB §3.1 fold). The host constructs the persist
`Engine` with its own local keys; lens-core uses the `Engine`
as a signing oracle via `engine.local_sign` /
`engine.local_pqc_sign`. This pattern survives the fold — agents
pass their `Engine` the same way the deployed lens does.

### Pin (initial federation)

```
ciris-persist   v0.6.0   (extract feature)
ciris-edge      v0.1.0
ciris-verify    v0.6.0   (transitive)
python floor    3.11
abi3            py311
```

## Threat model

`docs/THREAT_MODEL.md` enumerates 21 LC-AVs. P0 must-have-at-v0.1.0:

- LC-AV-2 — declared-vs-inferred cohort mismatch detection
- LC-AV-11 — bounded queue; `score_unavailable` on SLO breach
- LC-AV-18 — insufficient sample → `Indeterminate`, never numeric
