# CIRISServer — Roadmap to 1.0, Dependencies & GANTT

> **Three increments, driven by the CIRISAgent train (the clock):**
> - **0.1 — lens-only** @ agent **~2.9.7**: CIRISServer composes *only* lens-core.
>   The agent stops importing `ciris_lens_core` directly and depends on the
>   `ciris-server` wheel; the **standalone CIRISLens server is retired** at the
>   same time (Grafana/TimescaleDB/Python ingest gone).
> - **0.5 — + registry** @ agent **~2.9.8**: add the authority slice; the three
>   canonical nodes become fabric nodes.
> - **1.0 — + node** @ agent **~2.9.10**: add consensus; the *complete* fabric node.
>
> Written against [`MISSION.md`](../MISSION.md). Scouted **2026-06-14**.
> **No time estimates** — lanes are ordered by dependency.

## 0. Operating principle — adapt, don't fix

> *We can't fix what isn't broken, and we can't break what isn't shipped.*

The cores and the agent are shipped and working; CIRISServer is the unshipped
thing, so **all** adaptation is ours. The wiring needs **no core API change**:
`LensCore::attach_handler(&edge, engine)` is unchanged; registry adapts via
`federation::build_client(Some(engine))` + `api::http::serve(..., transport_pubkeys)`;
edge is built in-Rust via lens-core's `ret_relay` pattern (single-process ⇒ no
leader election). The only cross-repo needs are the **family co-bump** of the
cores — no edge-tag gate (edge shipped).

## 1. Ground truth (2026-06-14) — the gate is gone

The substrate floor **shipped** and is pinnable now:

| Crate | Tag | State |
|---|---|---|
| ciris-persist | **v6.5.0** | tagged + PyPI (pyo3 0.29; cumulative 6.x read surface) |
| ciris-edge | **v3.2.0** | tagged + PyPI (4 wheels); the old "tag v3.0.0" gate is **closed** |
| ciris-verify | **v5.2.0** | tagged |

CIRISServer is **re-pinned** to these (Cargo.toml). The cores are **not yet
co-bumped** — both still on persist-5.5.5/edge-2.2.2:

| Core | Now | Co-bump issue | Blocks |
|---|---|---|---|
| ciris-lens-core | v1.4.2 | **[CIRISLensCore#53](https://github.com/CIRISAI/CIRISLensCore/issues/53)** (+#54 read accessors) | **0.1 (LIVE critical path)** |
| ciris-registry-core | v2.3.0 | **[CIRISRegistry#76](https://github.com/CIRISAI/CIRISRegistry/issues/76)** (co-bump only) | 0.5 |
| ciris-node-core | v0.1.0 (persist 4.10) | [#38](https://github.com/CIRISAI/CIRISNodeCore/issues/38) + de-stub | 1.0 |

**Single live blocker for 0.1: CIRISLensCore#53.** It is a *version-only* bump
(`attach_handler` unchanged) and no longer waits on anything — edge shipped. Once
#53 cuts a co-bumped tag, CIRISServer pins it and the lens-only node builds.

## 2. The product spec — `pip install ciris-server` just works

Cuts across all three increments (defaults mirrored from CIRISAgent):

- **One command, no wizard.** `pip install ciris-server` → the `ciris-server`
  console script (pyproject `[project.scripts]` → PyO3 `main` → `block_on(run())`).
  Starts a working node on first run.
- **Modes = transport posture** (`AgentMode`: `client` / `proxy` / `server`).
  CIRISServer **defaults to `server`** (the agent defaults `proxy`). NOTE: SERVER
  is disk-gated in the agent (`SERVER_MINIMUM_DISK_BYTES = 256 GiB`) — **open
  decision §7** whether CIRISServer keeps/relaxes that gate. This axis is
  orthogonal to CEG §3.3's self/family/server/agent (agency + cohort).
- **Trust the canonical trio by default** (a *default pin*, replaceable —
  MISSION §3.2). Mechanism exists in the agent (`CIRIS_CANONICAL_BOOTSTRAP_PEERS`,
  reseeded each boot with `trust=TRUSTED`) but the list is **empty today** — the
  trio addresses aren't published yet (**open decision §7**: chicken-and-egg —
  CIRISServer *becomes* those nodes at 0.5).

**Zero-setup defaults to adopt** (from `essential.py` / `path_resolution.py` /
`edge_runtime.py`):

| Concern | Default |
|---|---|
| Data dir | `~/ciris/data/` (installed) |
| Persist DSN | SQLite file `<data>/ciris_engine.db` (honor `CIRIS_DB_URL` for postgres) |
| Identity key | mint-on-first-boot, load thereafter (`edge_identity.rid`; one keyring identity per host) |
| Listen | `0.0.0.0:4242` (lens read-API binds `listen_addr`, relay `+1`) |
| occurrence_id | `"default"` |
| agent_mode | **`server`** |
| Logs | `~/ciris/logs/`, level INFO |

## 3. 0.1 — what the lens-only node must serve (retiring the lens server)

The standalone CIRISLens deployment is **retired**; its *function* moves into the
fabric node.

**Retired:** Grafana, TimescaleDB, the Python FastAPI ingest service, the prod
telemetry sidecars (Prometheus/Loki/Tempo/Mimir/MinIO), and the OAuth admin UI
(**no equivalent** in the fabric node's read-only surface — flag to operators).

**Survives, inside the node:**
- **Trace ingest** — CEG `AccordEventsBatch` over RET/HTTP → `engine.receive_and_persist`
  (scrub/classify/extract live in persist v6) → `LensCoreHandler`.
- **Detection events** — persist-owned storage; lens-core signs via `engine.local_sign`.
- **The 7 frozen read endpoints** (replace Grafana; GET-only, federation-signed):
  `GET /lens/api/v1/{scores, scores/{trace_id}, detection_events,
  detection_events/{detection_id}, manifold_conformity_aggregate,
  calibration_bundles, calibration_bundles/{version}}`.
- **Per-node identity** — `/v1/identity` six-key `LocalIdentityAggregate`.

**How CIRISServer composes lens-only:** `LensCore::node(engine, listen_addr,
key_id, seed_dir, peer_acl, upstream, retention, scoring, ux)` (relay + the 7-endpoint
read API) over the one shared persist Engine + one Rust Edge (`ret_relay` pattern).

**Migration concerns:**
- **Corpus starts FRESH at cutover**; old TimescaleDB kept read-only (dedup keys
  differ; legacy history is not re-imported).
- **Grafana consumers break** → move to the 7 JSON endpoints (programmatic, not
  interactive dashboards).
- **Carry the lens's existing Reticulum identity** into the node so `/v1/identity`
  + federation enrollment stay stable.

## 4. The agent-side swap (0.1)

Today the agent embeds lens-core **directly**: `ciris_adapters/ciris_accord_metrics/
services.py::_build_lens_client()` does `from ciris_lens_core import LensClient`,
and `logic/runtime/edge_runtime.py` calls `init_edge_runtime(...)`. At 0.1 these
collapse into **one dependency**: the agent pip-installs `ciris-server`, which does
the `init_edge_runtime` + `LensCore::node` composition internally; the accord-metrics
adapter consumes CIRISServer's surface instead of importing `ciris_lens_core`. The
shared-substrate contract (`current_rust_engine()`, one Edge) is unchanged — this is
*moving the composition call from the agent into the wheel*. (Tracked: Agent#885 is
the floor co-bump; an agent-side "swap lens-core → ciris-server" task is **to file
when 0.1 is buildable** — not before, per §0.)

## 5. GANTT (dependency lanes — no time)

```
EXTERNAL (owners; family-driven)            CIRISSERVER (ours; adapt-don't-fix)
──────────────────────────────────         ──────────────────────────────────────────
 SHIPPED: persist v6.5.0 · edge v3.2.0 ·    S0 spec refresh ............ [DONE]
          verify v5.2.0   (no gate left)    S1 lib.rs composition ...... [DONE]
                                            S2 hybrid CI matrix + abi3 wheel lane [now]
                                            S-repin to 6.5/3.2 ......... [DONE]
  ─── 0.1  LENS-ONLY · agent ~2.9.7 ───────────────────────────────────────────────
   G-L ─ LensCore#53 co-bump (LIVE) ──► S3 pin lens tag → first build (lens-only)
        (version-only; no edge gate)        └─► S4 compose LensCore::node (7 endpoints
                                                + /v1/identity) · S5 build Rust Edge
                                                  └─► S6 abi3 wheel + console script
                                                      + zero-setup defaults (mode=server)
                                                        └─► S7 agent ~2.9.7 swaps
                                                            lens-core → ciris-server
                                                            + RETIRE standalone lens server
                                                            = 0.1 Deployed
  ─── 0.5  + REGISTRY · agent ~2.9.8 ──────────────────────────────────────────────
   G-R ─ Registry#76 co-bump ──► S8 add authority (adapt wiring; unified /v1/identity)
                                   └─► S9 cut 3 canonical nodes → fabric nodes
                                       (founder-quorum) = 0.5 Deployed (canonical)
  ─── 1.0  + NODE · agent ~2.9.10 ─────────────────────────────────────────────────
   G-N ─ NodeCore#38 co-bump + de-stub ──► S10 add consensus (install(&edge);
        (file at this phase)                WBD route_deferral surface)
                                             └─► S11 agent ~2.9.10 = 1.0 Deployed
```

## 6. Open decisions (need a call)

1. **0.1 version label** — proposed `0.1.0` for lens-only (crate re-pinned to it).
   Confirm, or pick another scheme.
2. **SERVER disk gate** — the agent gates `server` mode on ≥256 GiB free. Keep it
   for CIRISServer, relax it, or make it warn-only? A lens-only node is light.
3. **Canonical trio pins** — `CIRIS_CANONICAL_BOOTSTRAP_PEERS` is empty today.
   "Default-trust the trio" needs published addresses/keys; those come into being
   *as 0.5 stands the trio up*. For 0.1, ship empty (or a seed)?
4. **Admin-UI gap** — the retired lens OAuth admin UI has no fabric-node
   equivalent. Accept the drop, or is a minimal operator surface needed?

## 7. Cross-references

- [`MISSION.md`](../MISSION.md) §3.3/§3.4 (modes + UX handles), §4 (floor/gate), §5 (agent train).
- Issues: [CIRISLensCore#53](https://github.com/CIRISAI/CIRISLensCore/issues/53) (0.1 blocker) · [CIRISRegistry#76](https://github.com/CIRISAI/CIRISRegistry/issues/76) (0.5) · [CIRISNodeCore#38](https://github.com/CIRISAI/CIRISNodeCore/issues/38) (1.0) · [CIRISAgent#885](https://github.com/CIRISAI/CIRISAgent/issues/885) (floor co-bump).
- CEG spec: `CIRISRegistry/FSD/CEG` (§7.0.1 fabric-node discipline; §5.6.8.8.2 identity aggregate).
