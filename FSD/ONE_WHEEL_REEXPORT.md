# FSD — One-Wheel Re-Export Surface (CIRISServer#4)

> **STATUS: RESOLVED (v0.5.39).** Both upstream `pub fn register` hooks now ship in
> our pinned substrate — persist **v10.0.0** (CIRISPersist#231, `reset_engine`) and
> edge **v7.0.2** (CIRISEdge#199, `init_edge_runtime`; the v4.3.1 hook had regressed
> out of the v7.x line and was restored). `src/lib.rs::register_persist`/`register_edge`
> now delegate to those `register` fns, so the wheel re-hosts the FULL persist+edge
> surface (free functions included). Verified on the built wheel: `from ciris_server
> import reset_engine, init_edge_runtime` resolve, and `ciris_server.Engine is
> ciris_server.persist.Engine` / `ciris_server.Edge is ciris_server.edge.Edge` both
> hold. The "two gaps" / "v8.4.0 / v4.3.0" analysis below is the historical record
> from when the hooks were private; kept for context, not as current state.

**Goal.** Let CIRISAgent consume the substrate as the SINGLE `ciris-server`
wheel and drop its three standalone substrate wheels (`ciris_persist`,
`ciris_edge`, `ciris_verify`) plus the in-tree `ciris_lens_core`.

**Load-bearing rationale.** One `.so` = one PyO3 type registry. When persist and
edge are separate `.so`s, PyO3 registers `Engine` (and every `#[pyclass]`) twice
— once per `.so` — and the two registrations are *distinct* Python types. The
agent hands a persist `Engine` PyObject into edge's `init_edge_runtime`; with two
registries edge sees a foreign `Engine` and raises `TypeError`
(`edge_runtime.py:107` literally catches this and degrades to a non-federated
boot). Re-hosting both crates' `#[pyclass]`es into ONE cdylib makes them share a
single registry — the CIRISPersist#109 cross-wheel type-identity bug class
**cannot occur**. This is the invariant CIRISConformance exists to police.

---

## STEP 1 — what each substrate crate exposes for re-export

| Crate | pyo3 surface | Re-host hook | Verdict |
|---|---|---|---|
| **lens-core** (in-tree) | `src/ffi/pyo3.rs` | `pub fn register(m)` — single source of truth; the `#[pymodule]` just calls it | **Re-hostable today** (already wired) |
| **ciris-persist** v8.4.0 (`7b40aae`) | `src/ffi/pyo3.rs`, `pub mod ffi::pyo3`, feature `pyo3` (implies `postgres`); `extension-module` feature | Only the **private** `#[pymodule] fn ciris_persist` (no `pub`). Pyclass `pub struct PyEngine` (Py name `Engine`) + `pub use` exceptions ARE reachable. The free `#[pyfunction] reset_engine` is **private**. | **Partial** — classes/exceptions re-hostable; `reset_engine` is a GAP (upstream ask) |
| **ciris-edge** v4.3.0 (`ab4f1bc`) | `src/ffi/pyo3.rs`, `pub mod ffi::pyo3`, feature `pyo3` (implies `transport-reticulum`, pulls `ciris-persist/pyo3`); `extension-module` feature | Only the **private** `#[pymodule] fn ciris_edge` (no `pub`). Pyclass `pub struct PyEdge` (Py name `Edge`) + the session/conformance pyclasses ARE reachable. The free `#[pyfunction] init_edge_runtime` (the `Edge` constructor the agent uses) is **private**. | **Partial** — classes re-hostable; `init_edge_runtime` is a GAP (upstream ask) |
| **ciris-verify** v5.10.0 (`be25114`) | NONE. `ciris-verify-ffi` is `crate-type = ["cdylib","staticlib"]` — a **C-ABI** dylib (`libciris_verify_ffi.so`). The Python `ciris_verify` wheel is hand-written pure-Python loading that `.so` via `ctypes.CDLL` (`ffi_bindings/client.py`). No `#[pymodule]` anywhere in the workspace. | **Out of scope** — not a PyO3 module; cannot be a pyo3 submodule of `ciris_server` |

### The PyO3 0.29 mechanism (why the private fns block us)

`#[pymodule]` and `#[pyfunction]` emit their `_PYO3_DEF` glue inside a generated
`mod` whose visibility is **inherited from the annotated item**
(`pyo3-macros-backend` `module.rs:491` / `pyfunction.rs:451`: `#vis mod #ident`).
`wrap_pymodule!`/`wrap_pyfunction!` reference `$path::_PYO3_DEF`. Persist's and
edge's module-init + free-function items are declared *private* (`fn ciris_*`,
`fn reset_engine`, `fn init_edge_runtime` — no `pub`), so their `_PYO3_DEF` is
unreachable from this crate. `#[pyclass]`es, by contrast, are declared
`pub struct …` and are reachable, so we re-register those directly.

### Cosmetic caveat (`module=` label)

Persist's classes are `#[pyclass(module = "ciris_persist")]` and edge's
`#[pyclass(module = "ciris_edge")]`. Re-hosted under `ciris_server`, the classes
still report `__module__ == "ciris_persist"` / `"ciris_edge"` (verified on the
built wheel). This is only a repr/pickle label — the *type identity* is correct
(one registered type, shared across `ciris_server.Engine` /
`ciris_server.persist.Engine`). The upstream `pub fn register` work should also
flip these to `module = "ciris_server.persist"` / `"ciris_server.edge"` (or make
the label parameterizable) for clean reprs once the agent cuts over.

### Verification (built wheel)

`maturin build --release --skip-auditwheel` produced an importable 22 MB abi3
wheel. Smoke test in a fresh venv confirmed: all re-hosted symbols importable
both top-level and via the submodules; `from ciris_server.persist import Engine,
NotFound` and `from ciris_server.edge import Edge` resolve; and the **type
identity holds** — `ciris_server.Engine is ciris_server.persist.Engine` and
`ciris_server.Edge is ciris_server.edge.Edge` are both `True` (one registry). The
two gaps are confirmed absent (`reset_engine`, `init_edge_runtime` not present),
exactly as expected. (The full manylinux-repaired wheel needs `patchelf` on the
build host — the cargo/cdylib compile itself is clean.)

### The upstream ask (two issues)

The clean, conflict-free fix mirrors lens-core: each crate adds a
`pub fn register(m: &Bound<PyModule>)` that its own `#[pymodule]` delegates to,
exposing ALL of its surface (including the free functions) for re-host.

- **CIRISPersist**: add `pub fn register(m)` exposing `reset_engine` (+ `Engine`,
  exceptions) so the one-wheel can re-host the FULL persist surface.
- **CIRISEdge**: add `pub fn register(m)` exposing `init_edge_runtime` (+ `Edge`,
  session/conformance pyclasses). Without this the agent cannot mint an `Edge`
  from the one-wheel — the federation boot path stays on the standalone
  `ciris_edge` wheel.

---

## STEP 2 — agent substrate import-site inventory → coverage map

Read-only sweep of `/home/emoore/CIRISAgent` (production paths
`ciris_engine/` + `ciris_adapters/`; tests noted separately).

### ciris_persist (production import sites)
| Site | Symbol | Covered by one-wheel? |
|---|---|---|
| `ciris_engine/logic/persistence/db/core.py:931` | `Engine` | ✅ `ciris_server.Engine` / `ciris_server.persist.Engine` |
| `ciris_engine/logic/persistence/models/graph.py:30` | `Engine`, `NotFound` | ✅ both re-hosted |
| `ciris_engine/logic/audit/chain_bridge.py:201` | `Engine` | ✅ |
| `ciris_engine/logic/persistence/db/core.py:1003,1101` | `reset_engine` | ❌ **GAP** — private upstream fn (CIRISPersist `pub fn register` ask) |

`Engine` is used as a callable constructor + ~33 distinct `engine.<method>()`
calls; those ride the re-hosted `PyEngine` pyclass (its `#[pymethods]` come with
the class) so they are all covered the moment `Engine` is re-hosted.

### ciris_edge (production import sites)
| Site | Symbol | Covered? |
|---|---|---|
| `ciris_engine/logic/runtime/edge_runtime.py:79` | `import ciris_edge` | ⚠️ module exists; see below |
| `ciris_engine/logic/runtime/edge_runtime.py:97` | `ciris_edge.ciris_edge.init_edge_runtime(engine, …)` | ❌ **GAP** — private upstream fn (CIRISEdge `pub fn register` ask) |

`Edge` (the handle returned by `init_edge_runtime`) + session/conformance
pyclasses ARE re-hosted, but the agent never imports `Edge` directly — it only
calls the `init_edge_runtime` constructor, which is the blocked symbol.

### ciris_lens_core (production import sites)
| Site | Symbol | Covered? |
|---|---|---|
| `ciris_adapters/ciris_accord_metrics/services.py:576` | `LensClient` | ✅ already re-hosted via `register(m)` (pre-existing) |

### ciris_verify
Out of scope (ctypes wheel — see Step 1). Agent imports `CIRISVerify`,
`verify_tree`, `TreeVerifyRequest`, `LicenseStatus`, `setup_logging`,
`AttestationInProgressError` from the `ciris-verify` wheel + its
`ciris_adapters/ciris_verify` adapter. These remain on the standalone ctypes
wheel; the one-wheel does NOT absorb them.

### Coverage summary
- **Covered: 4 of 6 production symbols** — `Engine`, `NotFound` (persist),
  `LensClient` (lens), plus the `Edge`/session pyclasses (re-hosted but unused
  directly by the agent).
- **Gaps: 2** — `reset_engine` (persist) and `init_edge_runtime` (edge), both
  blocked on a private upstream `#[pyfunction]`; both need a `pub fn register`.
- **Out of scope: ciris_verify** (ctypes, not pyo3).

---

## STEP 3 — what was built in `mod python` (`src/lib.rs`)

- `ciris_server.persist` submodule + flat top-level aliases: `Engine`,
  `NotFound`, `Conflict`, `Transient`, `Permanent`, `PersistError`,
  `EngineConfigMismatch`, `EngineClosed`, `EngineUsedAcrossFork`,
  `LensQueryError` (matches `from ciris_persist import Engine, NotFound`).
- `ciris_server.edge` submodule: `Edge` + `DurableHandle`,
  `SubscriptionHandle`, `VerifiedFeedSubscription`, `NetworkEventSubscription`,
  `ReplicationHandle`, `AvSession`, `RelayNode`.
- Submodules registered in `sys.modules` as `ciris_server.persist` /
  `ciris_server.edge` so `from ciris_server.persist import X` resolves.
- `ciris_server.main` + `ciris_server.import_traces` + the full lens surface
  (`LensClient`, …) preserved unchanged.

`Cargo.toml`: the `python` feature now also enables `ciris-persist/pyo3` +
`ciris-edge/pyo3`; `extension-module` propagates to both substrate crates.

---

## STEP 4 — build gate

- `cargo build` (no python) — **clean** (binary never links libpython).
- `cargo build --features python` — **clean** (the wheel surface).
- `cargo clippy` and `cargo clippy --features python` — **clean** (only the
  pre-existing non-root-package profile note from the lens-core member).

---

## Agent-migration delta

Once the two upstream `pub fn register` hooks land and the one-wheel re-hosts the
full surface, the agent:
- **Drops 2 substrate wheels** from `requirements.txt`: `ciris-persist`,
  `ciris-edge` (their surfaces come from `ciris-server`).
- **Drops the in-tree `ciris_lens_core`** wheel (already re-hosted).
- **Rewrites imports**: `from ciris_persist import Engine, NotFound, reset_engine`
  → `from ciris_server import Engine, NotFound, reset_engine`;
  `ciris_edge.ciris_edge.init_edge_runtime(...)` →
  `ciris_server.edge.init_edge_runtime(...)`;
  `from ciris_lens_core import LensClient` → `from ciris_server import LensClient`.
- **Keeps `ciris-verify`** as its own ctypes wheel (out of the pyo3 one-wheel).

So the agent drops **3 of its 4** substrate dependencies onto the single
`ciris-server` wheel; `ciris-verify` stays standalone (ctypes, architecturally
separate). The two `reset_engine` / `init_edge_runtime` gaps are the only thing
between the current state and the full cutover.
