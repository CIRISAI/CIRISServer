# CIRISServer — Plan to 1.0 (via 0.5), Dependencies & GANTT

> **Two milestones, driven by the CIRISAgent train (not a 1.0/2.0 split):**
> - **Server 0.5** = lens + registry. The agent adopts it at **~2.9.8** *instead
>   of* folding registry into itself.
> - **Server 1.0** = + node — the **complete** fabric node. The agent adopts it at
>   **~2.9.10** *instead of* folding node into itself.
>
> Written against [`MISSION.md`](../MISSION.md). Scouted federation state of
> **2026-06-13**. **No time estimates** — lanes are ordered by dependency.

## 0. Operating principle — adapt, don't fix

> *We can't fix what isn't broken, and we can't break what isn't shipped.*

The cores and the agent are **shipped and working**. CIRISServer is the **unshipped**
thing, so the burden of adaptation is entirely ours. We wire the cores **as they
exist**; we do **not** ask a shipped, working core to grow new API for our
convenience. Concretely, the wiring needs **no core changes**:

- **registry** — replicate the bin's boot against the lib's public modules
  (`federation::build_client(Some(engine))`, `api::http::serve(..., persist_engine:
  Some(engine), transport_pubkeys: Some(...))`, the tonic services); pass the
  **shared** edge's transport pubkeys into `/v1/identity`.
- **lens** — `LensCore::attach_handler(&edge, engine)` (already the proven entry).
- **edge** — build one Rust `Edge` over the shared `Engine` following lens-core's
  `ret_relay` pattern. A single-process node needs **no** multi-worker leader
  election (`SharedInstanceLease` is for multi-worker one-host).

So the **only** cross-repo needs are the **family co-bump** and the **edge v3.0.0
tag** — both family-driven, not CIRISServer-imposed. (This is why the earlier
`compose()` / injectable-edge / Rust-acquisition asks were dropped:
CIRISRegistry#76 narrowed to co-bump-only; CIRISEdge#106 closed.)

## 1. The dependency gate

| # | Gate | Owner | Tracking | State |
|---|---|---|---|---|
| **G0** | **Tag CIRISEdge v3.0.0** (family lockstep: persist 6.0.1 + pyo3 0.29). Keystone — until tagged, persist 6.x + edge can't co-resolve (edge v2.4.0 pins persist `<6`). Family-driven (RUSTSEC), not ours. | CIRISEdge | **[#89](https://github.com/CIRISAI/CIRISEdge/issues/89)** | WIP, uncommitted |
| **G1** | **Co-bump `ciris-lens-core`** to 6.0.1/edge-3.0/verify-5.2.0. `attach_handler` already ready — version only. | CIRISLensCore | **[#53](https://github.com/CIRISAI/CIRISLensCore/issues/53)** | filed |
| **G2** | **Co-bump `ciris-registry-core`** to 6.0.1/edge-3.0/verify-5.2.0. No new API (we adapt). | CIRISRegistry | **[#76](https://github.com/CIRISAI/CIRISRegistry/issues/76)** | filed (narrowed) |
| **G3** | **Co-bump `ciris-node-core`** to 6.0.1/edge-3.0/verify-5.2.0 + de-stub its MockEngine surfaces. **1.0 phase only.** *File on CIRISNodeCore when the 1.0/2.9.10 phase begins* — not now (node-core is v0.1.0 pilot; we don't pile requirements on a barely-shipped core early). | CIRISNodeCore | *(deferred)* | — |

G0 is the keystone for both milestones. G1/G2 are the **0.5** floor; G3 is the
**1.0** floor.

## 2. GANTT (dependency lanes — no time)

```
EXTERNAL (owners; family-driven)            CIRISSERVER (ours; adapt-don't-fix)
──────────────────────────────────         ──────────────────────────────────────────

 G0 ─ Edge#89 ─ tag edge v3.0.0             S0 spec refresh ............ [DONE]
     (persist 6.0.1 + pyo3 0.29)            S1 lib.rs composition ...... [DONE]
        │  (pinnable artifact)              S2 hybrid CI matrix ........ [authorable now]
        │                                       (merge gate + abi3 wheel lane)
   ─── SERVER 0.5 (lens + registry · agent ~2.9.8) ───────────────────────────────
        ├──► G1 lens co-bump (#53) ───┐
        └──► G2 registry co-bump (#76)┤
                                      ▼
                               S3 first build  (deps: G0 + G1 + G2)
                                      │
                            ┌─────────┴──────────┬──────────────┐
                            ▼                    ▼              ▼
                    S4 wire authority      S5 wire lens    S6 build+share
                    (adapt registry        (attach_handler) one Rust Edge
                     wiring; /v1/identity   over shared      over shared Engine
                     via shared pubkeys)    Engine)          (no leader-elect)
                            └─────────┬──────────┴──────────────┘
                                      ▼
                            S7 abi3 wheel + agent adoption (agent ~2.9.8
                               drops registry-fold scaffolding) + S8 conformance
                               self-attest  ──►  S9 cut 3 canonical nodes over
                                                 = SERVER 0.5 Deployed (canonical)
   ─── SERVER 1.0 (+ node · agent ~2.9.10) ──────────────────────────────────────
        └──► G3 node co-bump + de-stub ──► S10 wire consensus slice
             (file when this phase begins)     (node-core install(&edge);
                                                WBD route_deferral surface)
                                                  ──► S11 agent ~2.9.10 adopts
                                                      the complete composition
                                                      = SERVER 1.0 Deployed (canonical)
```

## 3. Tasks (by lane, with explicit dependencies)

### External (tracked on owners; family-driven)
- **G0** edge v3.0.0 tag · #89 · *deps:* persist v6.0.1 (✅). **Keystone.**
- **G1** lens co-bump · #53 · *deps:* G0.
- **G2** registry co-bump · #76 · *deps:* G0.
- **G3** node co-bump + de-stub · *(file at 1.0 phase)* · *deps:* G0.

### CIRISServer — Server 0.5 (lens + registry)
- **S0** Spec refresh · *deps:* none · **DONE.**
- **S1** Composition library skeleton (`src/lib.rs`) · *deps:* none · **DONE.**
- **S2** Hybrid CI matrix · *deps:* authorable now (green needs S3). Merge gate
  (fmt · clippy/test ubuntu+macos+windows · cargo-deny · Win7 build-std smoke,
  nightly pinned `nightly-2026-06-12`, `CARGO_NET_RETRY:"10"`) + release sweep
  (linux x86_64/aarch64/armv7 · macos x86_64/arm64 · Win7 Tier-3 build-std ·
  aarch64-musl · **abi3 wheel lane** · Sigstore · build-manifest TODO).
- **S3** First real build · *deps:* G0 + G1 + G2. Pin co-bumped core tags + edge v3.0.0.
- **S4** Wire authority (adapt registry wiring; unified `/v1/identity` via the
  shared transport pubkeys) · *deps:* S3.
- **S5** Wire observation (`attach_handler`; the 7 frozen `GET /lens/api/v1/*`) · *deps:* S3 + G1.
- **S6** Build + share one Rust `Edge` over the shared Engine (lens-core `ret_relay`
  pattern; no leader election) · *deps:* S3.
- **S7** abi3 wheel + agent adoption (agent ~2.9.8 drops its registry-fold
  scaffolding, depends on the ciris-server wheel) · *deps:* S4+S5+S6 + S2 wheel lane.
- **S8** Conformance self-attestation (signed BuildManifest → registry) · *deps:* S4 + S2.
- **S9** Cut `lens` + `registry-us` + `registry-eu` over to `ciris-server` → three
  `ciris-canonical` fabric nodes · *deps:* S4+S5+S6+S7. **= Server 0.5 Deployed (canonical).**

### CIRISServer — Server 1.0 (+ node)
- **S10** Wire consensus slice (`ciris-node-core` `install(service, &edge)` over the
  shared Engine/Edge; expose the WBD `route_deferral` / Wise-Authority surface) ·
  *deps:* S9 + G3.
- **S11** agent ~2.9.10 adopts the complete three-core composition · *deps:* S10.
  **= Server 1.0 Deployed (canonical).**

## 4. Definition of done

**Server 0.5:** one `ciris-server` process composes registry + lens over one persist
Engine + one edge transport identity; `/v1/identity` emits the six-key aggregate; CEG
§7.0.1 holds by construction (a co-located node votes, never verdicts; `detection:*`
is never sole authority evidence); the abi3 wheel builds Win7-loadable; the agent
~2.9.8 consumes the wheel; the three `ciris-canonical` nodes run as fabric nodes with
2-of-3 founder-quorum over per-node keys (shared vaulted steward key retired).

**Server 1.0:** + node-core composed in-process; the WBD routing / Wise-Authority
surface served; the agent ~2.9.10 consumes the complete composition.

## 5. Cross-references

- [`MISSION.md`](../MISSION.md) §1.5 (CEG §7.0.1), §2 (boot), §4 (gate), §5 (agent train).
- Issues: [CIRISEdge#89](https://github.com/CIRISAI/CIRISEdge/issues/89) · [CIRISLensCore#53](https://github.com/CIRISAI/CIRISLensCore/issues/53) · [CIRISRegistry#76](https://github.com/CIRISAI/CIRISRegistry/issues/76). (Closed/narrowed per §0: CIRISEdge#106 closed; #76 narrowed to co-bump.)
- CEG spec: `CIRISRegistry/FSD/CEG` (§7.0.1 fabric-node discipline; §5.6.8.8.2 identity aggregate; §8.1.13.1.1 founder-quorum).
