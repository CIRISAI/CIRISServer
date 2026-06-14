# Cohabitation Doctrine — lens-core as a sibling consumer

**Status:** authoritative architecture for v0.2.0+. Companion to
[CIRISPersist `docs/COHABITATION.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/COHABITATION.md)
(persist as the runtime keyring authority) and CIRISVerify's
`HOW_IT_WORKS.md § Cohabitation Contract`.

---

## TL;DR

**Lens-core is a Rust crate + Python wheel, not a daemon.** Every
consumer imports it as a library, calls one bootstrap function
after the agent's `Engine` and `Edge` exist, and is done. Three
rules for hosts where lens-core co-resides with the agent +
NodeCore + edge + persist in one process:

1. **The agent builds `Engine` and `Edge`; lens-core attaches.**
   Lens-core never constructs its own `Engine` or `Edge` in the
   cohabitation path — it composes against the host's
   process-singleton instances.
2. **One persist `Engine` per process; one `Edge` per process.**
   `ciris_persist::ffi::pyo3::current_rust_engine()` returns the
   singleton `Arc<Engine>` (CIRISPersist#92, v1.13.0+);
   `PyEdge::edge_handle()` returns the singleton `Arc<Edge>`.
   Lens-core uses both directly — no second pool, no second
   listener, no second key load.
3. **Federation pins lock-step with CIRISConformance.** Lens-core's
   `Cargo.toml` + `pyproject.toml` pins track the
   [CIRISConformance matrix](https://github.com/CIRISAI/CIRISConformance).
   Re-pin in lockstep with edge + NodeCore + agent, never
   unilaterally.

---

## What "lens-core as sibling consumer" means

Lens-core's job in the CIRIS 3.0 cohabitation model:

> Lens-core is the science-layer consumer of the federation's signed
> trace corpus. The agent emits traces (via edge transport + persist
> ingest); lens-core scores them (cohort routing, manifold
> conformity, CEG §5.5 detectors) and signs detection events. The
> agent constructs the substrate; lens-core composes against it.

There's no `lens-core.service`. There's no init container. Three
composition patterns, one per deployment shape:

```
┌──────────────────────────────────────────────────────────────┐
│                  Cohabitation process                        │
│                                                              │
│   ┌────────────────────────────────────────────────────┐     │
│   │ CIRISAgent (Python) — process owner                │     │
│   │                                                    │     │
│   │   engine = ciris_persist.Engine(...)               │     │
│   │   edge   = ciris_edge.init_edge_runtime(           │     │
│   │              engine, identity_path, listen_addr,   │     │
│   │              bootstrap_peers, ...)                 │     │
│   │   ciris_node_core.install_from_dispatch(           │     │
│   │              engine.node_core_service(), edge)     │     │
│   │   ciris_lens_core.install_relay(edge)              │     │
│   │                                                    │     │
│   └────────────────────────────────────────────────────┘     │
│                                                              │
│   Inside the host's tokio runtime, with the host's           │
│   Arc<Engine> + Arc<Edge> singletons; lens-core gets         │
│   Arc<Engine> via current_rust_engine(); registers           │
│   Handler<AccordEventsBatch> on the shared Edge.             │
└──────────────────────────────────────────────────────────────┘
```

After `install_relay(edge)` returns, the lens is a key-addressable
Edge endpoint: peers routing `AccordEventsBatch` to its `key_id`
land on `LensCoreHandler` and flow into
`engine.receive_and_persist(&bytes, &NullScrubber)`. The lens
participates in the federation without owning a runtime, a port,
or a key.

---

## Three composition entry points

Lens-core ships three Rust entry points + one PyO3 wrapper. Pick
the one matching the deployment shape:

### 1. `LensCore::attach_handler(edge: &Edge, engine: Arc<Engine>)`

**Rust cohabitation rlib.** The host has built the `Edge` (via
`EdgeBuilder` or `init_edge_runtime`) and the `Engine` (via
`Engine::with_signer(...)`). Lens-core registers its
`Handler<AccordEventsBatch>` on the shared Edge.

Used by pure-Rust embeddings — the agent post-PoB §3.1 fold links
lens-core as an rlib and calls this directly.

```rust
let engine: Arc<Engine> = engine.clone();
LensCore::attach_handler(&edge, engine).await?;
```

### 2. `ciris_lens_core.install_relay(edge)` (PyO3)

**Python cohabitation bootstrap.** Wraps `attach_handler` for the
Python agent. Reaches into the persist singleton via
`current_rust_engine()` for the `Arc<Engine>`. The agent's three-
line cohabitation startup:

```python
import ciris_persist, ciris_edge, ciris_node_core, ciris_lens_core

engine = ciris_persist.Engine(...)                 # bootstraps keyring
edge   = ciris_edge.init_edge_runtime(engine, ...) # one Edge per process
ciris_node_core.install_from_dispatch(
    engine.node_core_service(), edge)              # NodeCore attaches
ciris_lens_core.install_relay(edge)                # lens attaches
```

After this, the agent is a fully-functioning federation peer:
emits traces, persists locally, accepts `AccordEventsBatch`
inbound on the shared Edge listener, and scores them via
lens-core.

### 3. `LensCore::relay(engine, key_id, seed_dir, listen_addr, peer_urls)`

**Standalone-mode rlib (legacy / cutover).** Lens-core builds its
*own* Edge listener — used in the deployed-Python-lens cutover
window where lens-core is the only consumer in the process and
the agent runs elsewhere. Returns a `RelayHandle` with orderly
`shutdown()`.

```rust
let handle = LensCore::relay(
    engine, "lens-prod-eu", seed_dir,
    listen_addr, peer_urls,
).await?;
// ... run ...
handle.shutdown().await?;
```

Not the v0.5+ primary path — cohabitation is the federation's
direction. Kept for the cutover and for deployments where
lens-core legitimately owns a transport.

---

## Cohabitation invariants lens-core enforces

### Engine-as-parameter — lens-core never holds keys

The signing identity belongs to the host. The host constructs the
persist `Engine` with its own local keys
(`ciris_keyring::load_local_seed` or `get_platform_signer`);
lens-core uses the `Engine` as a signing oracle via
`engine.sign_hybrid(...)` (CIRISPersist#112, v2.12.0+). Lens-core
never opens its own key file, never holds an `Arc<LocalSigner>`
without it coming from the engine, never bootstraps the keyring.

This survives the post-PoB §3.1 fold — the agent links lens-core
as an rlib and passes its `Engine` the same way the deployed lens
does today.

### Single Edge per process — relay = pass-through scrubbing

Relay mode is store-and-forward federation transit. Scrubbing is
the originating client node's egress-filter responsibility
(capture-locally / filter-on-egress per FSD §1, §2.2);
inter-node federation traffic is post-egress-filter by contract.
Lens-core's `LensCoreHandler` passes `&NullScrubber` to
`Engine::receive_and_persist` — re-scrubbing at relays causes
NER-version content drift across the federation (same trace
stored differently at relays with different NER versions) and
demands models relays aren't provisioned with.

A first-hop deployment where agents POST directly to a relay IS a
privacy boundary and would need a real scrubber. That's a
deployment-time decision (which scrubber the caller passes); the
type lets either path through.

### Anti-Goodhart for `capacity:*` — type-system-enforced

CEG §7.5: `capacity:*` attestations are surfaced **about** an agent
**by other federation members**, never self-reports. Lens-core's
`CapacityAttestation` type cannot be constructed with matching
`attesting_key_id` and `attested_key_id`. The constructor returns
`AntiGoodhartViolation::SelfAttestation`; the `Deserialize` impl
re-validates so wire bytes can't bypass.

This is the same posture `MetaGoalAlignment` takes for M-1
(CIRISPersist#114) and that `CapacityFactors` takes for the
range-validated five-factor product (CEG §5.5.4): load-bearing
spec invariants get the type system, not best-effort validation.

---

## Federation pins — CIRISConformance-tracked

Lens-core's pins follow the
[CIRISConformance](https://github.com/CIRISAI/CIRISConformance)
matrix. The conformance harness pins the current cohabitation
triple; lens-core re-pins lockstep with edge + NodeCore + agent.
**Never unilaterally** — single-version-clean is the contract:

> For agent + NodeCore + lens-core co-resident in one process,
> every consumer must link ONE identical `ciris-persist`: a
> single tokio runtime, a single process-singleton `Engine`,
> a single connection pool. A version range would let pip
> resolve lens-core to a different patch than NodeCore/agent
> and break the singleton.

The discipline:

1. **CIRISConformance bumps its matrix** → that's the federation's
   authoritative cohabitation point.
2. **Sister repos re-converge** (persist + edge + verify +
   NodeCore + agent) on the new triple, each tagging a release.
3. **Lens-core mirrors** — bump `Cargo.toml` pins + `pyproject.toml`
   exact pin, verify single-version-clean via `cargo tree`,
   commit + tag.

The conformance matrix's `matrix:` commits in CIRISConformance are
the upstream signal. Watch
[CIRISConformance commits](https://github.com/CIRISAI/CIRISConformance/commits/main)
or the matrix files directly.

---

## Why this works — sister-doctrine alignment

The three-repo cohabitation doctrine (persist + edge + lens-core)
composes:

- **Persist** (CIRISPersist `docs/COHABITATION.md`): one `Engine`
  per process; first `Engine::__init__` bootstraps the keyring;
  subsequent imports see the existing key. POSIX `flock`
  serializes cold-start.
- **Edge** (per `init_edge_runtime` design): one `Edge` per
  process; built from the shared `PyEngine`'s
  `federation_directory()` + `outbound_queue()` +
  `keyring_signer()`; `PyEdge::edge_handle()` hands the
  `Arc<Edge>` to sibling cdylibs.
- **Lens-core** (this doc): one handler per process; attaches to
  the shared `Edge`; uses the shared `Engine` for signing and
  ingest. No second runtime, no second port, no second key load.

Cohabitation is **structural** — the construction discipline
enforces it. Lens-core's `LensCore::attach_handler` takes
`&Edge` (not `Engine + listen_addr + ...`) because the Edge is
already someone else's. `install_relay(edge)` doesn't take an
engine arg because the engine is the persist process singleton.
The shapes make the rule.

---

## Threat model bearing

`docs/THREAT_MODEL.md § LC-AV-*` covers lens-core's adversaries.
Cohabitation-specific concerns:

- **LC-AV-19 (reproducibility):** lens-core's `lens_core_version`
  field on every signed detection event ties the score to the
  exact crate version. Cohabitation doesn't change this — the
  field is on the wire, not in the binary.
- **AV-43 → AV-49 (edge's seven-invariant security contract):**
  inherited via the shared Edge. Lens-core doesn't re-verify
  what Edge verified (AV-9 structural attestation); the
  `VerifyOutcome` on `HandlerContext` is authoritative.

---

## References

- [`Cargo.toml`](../Cargo.toml) — current cohabitation triple pin
- [`pyproject.toml`](../pyproject.toml) — `ciris-persist==` exact pin
- [`src/role/relay.rs`](../src/role/relay.rs) — the three entry
  points (standalone relay, `attach_handler`, `install_relay`) +
  the cohabitation comments
- [CIRISPersist `docs/COHABITATION.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/COHABITATION.md)
  — the persist-side doctrine
- [CIRISConformance README](https://github.com/CIRISAI/CIRISConformance)
  — the authoritative cohabitation matrix
- [FSD `LENS_CORE_V0_5.md` §3](../FSD/LENS_CORE_V0_5.md) — the
  three-mode design (client / relay / node)
