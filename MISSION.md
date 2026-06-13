# MISSION — CIRISServer

> Mission Driven Development (MDD): the FSD names *what* we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. Methodology: [`~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`](../CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md)
> and the overview at [ciris.ai/mdd](https://ciris.ai/mdd).

**The fabric node** — the federation's headless cohabitation runtime. The
*same* composition of cores that folds into an agent, packaged **without a
reasoning brain**. The defining identity: **`agent = fabric node + brain`.**

**Status**: Spec (skeleton only; gated — see §4). The blockers this charter first
named (CIRISPersist#210 / CIRISEdge v2.3.0) have **shipped**; the substrate floor
is now the **6.x / edge-3.0 family** (persist v6.0.1, verify v5.2.0). The current
gate is the **[CIRISEdge v3.0.0 tag](https://github.com/CIRISAI/CIRISEdge/issues/89)**
+ a registry/lens co-bump + two adapter PRs ([CIRISRegistry#76](https://github.com/CIRISAI/CIRISRegistry/issues/76),
[CIRISEdge#106](https://github.com/CIRISAI/CIRISEdge/issues/106),
[CIRISLensCore#53](https://github.com/CIRISAI/CIRISLensCore/issues/53)) — the full
task graph, dependencies, and GANTT are in [`FSD/SERVER_1.0_PLAN.md`](FSD/SERVER_1.0_PLAN.md).
**Crate identifier (target)**: `ciris-server` (a thin composition *binary* — it
authors no primitives; it composes `ciris-registry-core` + `ciris-lens-core`
[+ `ciris-node-core`]).
**Deployed identifier (target)**: the three `ciris-canonical` founding nodes
(`lens` + `registry-us` + `registry-eu`), each a fabric node, replicating via
CEG/RET. Any operator MAY run one (the stewardship covenant: the work belongs to
whoever keeps it running, not to a name).
**Last updated**: 2026-06-13 (substrate scouted to the 6.x/edge-3.0 family; gate moved
to the CIRISEdge v3.0.0 tag + registry/lens co-bump + two adapter PRs; bin+abi3-wheel
shape and composition mechanism resolved; see [`FSD/SERVER_1.0_PLAN.md`](FSD/SERVER_1.0_PLAN.md)).
Preceded by the 2026-06-12 initial charter and the design discussion
in CIRISRegistry, the [#62](https://github.com/CIRISAI/CIRISRegistry/issues/62)
sibling epic, and the `ciris-canonical` decision at
[`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md) §2.1.1).
**Cross-references**: [`CIRISAgent`](https://github.com/CIRISAI/CIRISAgent)
(the *other* profile over this composition — fabric node **+** brain);
[`CIRISRegistry`](https://github.com/CIRISAI/CIRISRegistry) (`ciris-registry-core`
— the authority slice); [`CIRISLensCore`](https://github.com/CIRISAI/CIRISLensCore)
(`ciris-lens-core` — the observation slice); [`CIRISNodeCore`](https://github.com/CIRISAI/CIRISNodeCore)
(`ciris-node-core` — the consensus slice, folds in later); substrate trio
[`CIRISPersist`](https://github.com/CIRISAI/CIRISPersist) /
[`CIRISVerify`](https://github.com/CIRISAI/CIRISVerify) /
[`CIRISEdge`](https://github.com/CIRISAI/CIRISEdge); the wire grammar
[`CIRISRegistry/FSD/CEG`](../CIRISRegistry/FSD/CEG); the meta-goal
[`CIRISAgent/ACCORD.md`](https://github.com/CIRISAI/CIRISAgent) §M-1.

**Implementation Status Legend** (mirrors the sibling convention):
- **Spec** — specified here or in a referenced FSD; not implemented.
- **Impl** — implemented in the binary; in standalone testing.
- **Deployed** — running in production. Sub-states: *Deployed (canonical)* at the
  three `ciris-canonical` nodes; the fabric node is never *folded* (the agent is
  the folded form — see §1.4).

Every load-bearing claim carries one of these tags.

---

## 1. MISSION (WHY)

### 1.1 Meta-Goal — M-1

The CIRIS Accord names **Meta-Goal M-1**:

> *Promote sustainable adaptive coherence — the living conditions under which
> diverse sentient beings may pursue their own flourishing in justice and wonder.*

A fabric node serves M-1 by being **de-singletonized infrastructure**: trust
(authority), observation (science), consensus, storage, and transport, composed
into one runtime that **any operator can run** and that **no single instance is
load-bearing for**. The federation's deepest commitment — repeated in every
sibling MISSION — is that no component may become a single point of trust or
failure. The fabric node is how that commitment is *packaged*: the canonical
`ciris-canonical` nodes are **founding members of a governed community, not
dependencies** ([`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md) §2.1.1,
§5). Because the fabric node is the *same composition that folds into every
agent*, the capability it provides is held by every participant — the network
cannot be denied trust, observation, or consensus by any one node going down.

### 1.2 What CIRISServer is

A **thin composition crate** — shipped as both the headless `ciris-server`
**binary** (the canonical fabric-node deployment) and a **PyO3 abi3 wheel** that
CIRISAgent (pure Python) pip-installs and links *instead of composing the cores
itself* — that links the federation's cores as libraries over **one shared
substrate**:

```
ciris-server (the fabric node)
   ├── ciris-registry-core   — authority: identity / license / revocation / steward attestation
   ├── ciris-lens-core       — observation: Coherence Ratchet / Capacity Score (validated, not adjudicated)
   ├── ciris-node-core        — consensus: deferral routing / voting / expertise / moderation   [folds in later]
   │
   ├── one shared ciris-persist Engine     — the durable corpus + federation directory
   └── one shared ciris-edge singleton      — CEG/RET transport + the node's single federation identity
```

It **authors no primitives.** Its mission is to *compose the cores correctly* and
to *hold the invariants* (§1.5) that only become live when authority and
observation share a process. Its protocols, schemas, and logic (the MDD WHO/WHAT/HOW)
are **inherited** from the composed cores and from CEG; CIRISServer's own surface is
the wiring, the boot order, and the one unified identity endpoint (`/v1/identity`,
the §5.6.8.8.2 six-key `LocalIdentityAggregate`).

**CIRISServer *replaces* the CIRISRegistry *and* CIRISLens deployments.** The
*repos* stay — `ciris-registry-core` and `ciris-lens-core` are the libraries this
binary composes — but the deployed *servers* are retired in favor of three
identical fabric nodes. Two consequences:

1. **The registry singletons go away (key contention ends).** Today `registry-us`
   and `registry-eu` *share one vaulted steward key* replicated US↔EU — one secret,
   two boxes, the AV-14 single point of compromise. Under CIRISServer **every node
   handles its own key the way the lens already does**
   ([CIRISLens#20](https://github.com/CIRISAI/CIRISLens) `edge_runtime` — mint/load a
   per-node identity at boot, expose it at `/v1/identity`); the three per-node keys
   *become the quorum* (§3). Independent keys instead of a shared one — the
   occurrences stop fighting over a single identity.
2. **The centralized observability stack goes away (decentralization, not a
   dashboard).** The CIRISLens deployment's Python ingest API + **TimescaleDB +
   Grafana** are retired — a central dashboard the whole federation reads is itself
   the singleton this architecture forbids. The *lens function* survives as
   `ciris-lens-core` running **inside each fabric node** over the shared persist
   corpus: traces and detections flow as **CEG envelopes replicated over RET** (not
   POSTed to one ingest endpoint), the corpus is the durable persist substrate (not
   TimescaleDB), and observation is **queryable from any node** rather than rendered
   on one Grafana. An operator MAY run local viz over its own node's substrate, but
   no central dashboard is a federation dependency.

**`agent = fabric node + brain`.** CIRISAgent is the *other* profile over this
exact composition: the same cores, the same shared substrate, **plus** the
reasoning loop (PDMA / CSDMA / DSDMA / IDMA, the consciences, the action handlers,
Wisdom-Based Deferral). The fabric node is that runtime with the brain removed.
There is one cohabitation composition; CIRISServer and CIRISAgent are two
deployment shapes of it.

### 1.3 Apophatic bound — what the fabric node will NOT be

- **NOT an agent. It has no ethical agency, by design.** A fabric node runs no
  PDMA, holds no Autonomy Tier, takes no actions, and makes no decisions it could
  be argued into. It only *attests, stores, observes, reaches consensus, and
  transports* per deterministic protocol. This is the load-bearing safety property
  of the concept: **infrastructure must not have agency.** An agent can be
  socially engineered toward a harmful decision; a fabric node has no decision to
  engineer. Its blast radius is the integrity of its signatures and its uptime —
  not a judgment.
- **NOT a new authority.** It composes the registry's authority slice; it does not
  create authority. All authority remains quorum-signed and §7-role-gated
  ([CEG §7](../CIRISRegistry/FSD/CEG/07_reserved.md)). A fabric node holding the
  registry slice does **not** thereby gain unilateral power (§1.5).
- **NOT where primitives live.** No new `subject_kind`, envelope field, or wire
  surface originates here. CEG and the cores own the grammar; CIRISServer is a
  consumer.
- **NOT a singleton dependency.** The canonical nodes are *founding members* of the
  `ciris-canonical` community, reachable by quorum, replicated CEG-natively — not a
  service the federation depends on. They are the de-singletonized form, not a new
  singleton.
- **NOT the place authority and observation fuse.** They share a *process*; they
  never share *authority* (§1.5). Anything that would let observation manufacture
  authority in one binary is the wrong shape — fix the wiring, not the rule.

### 1.4 Position in CIRIS architecture — three shapes, one composition

```
                       ┌──────────────  ONE COHABITATION COMPOSITION  ──────────────┐
                       │  ciris-registry-core · ciris-lens-core · ciris-node-core    │
                       │  over one shared ciris-persist Engine + one ciris-edge      │
                       │  singleton (the node's single federation identity)          │
                       └────────────────────────────────────────────────────────────┘
                              │                    │                      │
            ┌─────────────────┘          ┌─────────┘            ┌─────────┘
            ▼                             ▼                      ▼
   AGENT (CIRISAgent)            FABRIC NODE (CIRISServer)   EMBEDDED (in any app)
   composition + reasoning       composition, headless       composition as libraries
   brain → a *participant*       → *infrastructure*,          → local self-service
   with ethical agency           deliberately agency-free

SUBSTRATE TIER (consumed by all three)
   ciris-verify   ciris-edge        ciris-persist
   authenticity   CEG/RET transport storage + federation directory
```

The fabric node sits at the **infrastructure** position: above the substrate trio,
composing the second-tier cores, but **below** ethical agency (it has none). The
canonical `ciris-canonical` nodes are fabric nodes; participants are agents; both
are the same cores. This reconciles the sibling missions' locked "fold the cores
into the agent / stop being a singleton" arc ([`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md)
§1.4/§5): the fold target is the agent (cores + brain); the fabric node is the
*headless* form of the *same* fold, run as canonical infrastructure.

### 1.5 The separation-of-powers invariant (load-bearing)

This is the single constraint that makes a combined binary safe, and the reason
this charter exists. A fabric node holds, in one process, both the **authority**
slice (registry/steward) and the **observation** slice (lens). The federation's own
caution is explicit: *"once the lenses become the gate, the lens-owners become the
governors."* The invariant that keeps that from happening is **cryptographic, not
procedural** — and is now **normative in [CEG §7.0.1](../CIRISRegistry/FSD/CEG/07_reserved.md)**
(the fabric-node discipline: holding the full role-set in one key/process is
*co-location of custody, not consolidation of authority*). The three properties
below are that section's conformance conditions verbatim:

1. **Authority is quorum-bound.** No single fabric node can issue a federation-scope
   attestation; steward authority is M-of-N over the `ciris-canonical` founding core
   ([`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md) §2.1, §2.1.1). A node
   running the registry slice gains a *vote*, never a *verdict*.
2. **Observation is non-authoritative by namespace.** Lens emissions are *signals* —
   "validated, not adjudicated" ([CEG §1.4](../CIRISRegistry/FSD/CEG/01_foundation.md);
   [`CIRISLensCore/MISSION.md`](../CIRISLensCore/MISSION.md)). They live under
   `detection:*`; they are never sole evidence for any authority action, and the
   reserved-prefix discipline ([CEG §7](../CIRISRegistry/FSD/CEG/07_reserved.md))
   forbids a detector key from emitting under authority prefixes.
3. **One key, role-separated.** A fabric node's key may hold a *set* of roles
   (`{substrate_persist, steward, witness, lenscore_detector}` — CEG §7.0.1
   `identity_type`-as-set), but the namespaces never merge: it emits authority under
   the steward role and observations under the detector role, and **observation can
   never manufacture authority** because authority is quorum-gated upstream of any
   single key.

If any wiring would let a node convert what it *observes* into what it can
*authorize*, the separation is broken at that point and the composition is the wrong
shape there. Fix the wiring; never weaken the rule.

### 1.6 Recursive Golden Rule — how it bites for a fabric node

*"We owe ourselves what we offer to others; no principal is exempt from the standard
it imposes."* Concretely:

- **The canonical nodes submit to the same admission door they enforce.** A new
  operator joins `ciris-canonical` by founding-core quorum; the founding core's own
  membership rides the same `supersedes`-gated, quorum-approved path. No founder can
  add a member the door would reject for anyone else.
- **The fabric node's authority emissions carry the operator's actor identity into
  the audit log** — including CIRIS L3C operators (the AV-35/W1 discipline inherited
  from `ciris-registry-core`). The trail does not soft-pedal steward operations.
- **Agency-free is enforced on the canonical infrastructure, not just recommended.**
  CIRIS L3C's flagship nodes run *as fabric nodes* — they do not get a brain that
  other operators are denied. The infrastructure tier has no agency for anyone.
- **The deliberate asymmetry (humanity accord)** carries over unchanged: the
  HUMANITY_ACCORD halt-authority ([`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md)
  §2.2) sits *above* the fabric node exactly as it sits above the bare stewards —
  revocability of consent requires a halt that lives outside the system being halted.

---

## 2. The composition contract (WHO / WHAT / HOW — inherited, not authored)

The fabric node's substance is *which cores it links and how it wires them*. Each
slice keeps its own MISSION; CIRISServer's job is to compose them without violating
any of them.

| Slice | Crate | Brings | Owns its mission at |
|---|---|---|---|
| Authority | `ciris-registry-core` | identity / license / revocation / steward attestation; the gRPC + HTTP trust surface | [`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md) |
| Observation | `ciris-lens-core` | Coherence Ratchet / Capacity Score / manifold conformity — *signals* | [`CIRISLensCore/MISSION.md`](../CIRISLensCore/MISSION.md) |
| Consensus *(later)* | `ciris-node-core` | deferral routing / voting / expertise / moderation | [`CIRISNodeCore/MISSION.md`](../CIRISNodeCore/MISSION.md) |
| Substrate | `ciris-persist` | one shared `Engine` — durable corpus + federation directory | [`CIRISPersist/MISSION.md`](../CIRISPersist/MISSION.md) |
| Transport / identity | `ciris-edge` | one shared singleton — CEG/RET transport + the node's single federation identity | [`CIRISEdge/MISSION.md`](../CIRISEdge/MISSION.md) |
| Authenticity | `ciris-verify` | hybrid Ed25519 + ML-DSA-65 signing/verification | [`CIRISVerify/MISSION.md`](../CIRISVerify/MISSION.md) |

**The two "one shared" invariants are the whole point of the binary:**

- **One persist `Engine`** — registry and lens read/write the same federation
  directory in-process; no cross-service RPC, no divergence between the authority
  view and the observation view.
- **One edge singleton → one federation identity per node** (CIRISPersist#210
  `SharedInstanceDirectory`). The node mints/holds *one* Reticulum transport
  identity; the registry slice and the lens slice both surface it. `/v1/identity`
  emits the single six-key `LocalIdentityAggregate` (signing + content-KEM +
  RET-transport) — **the federation ID by which `ciris-canonical` enrolls a
  member.** Not a registry identity and a lens identity; one node, one identity.

**Boot order (Spec; corrected to the 6.x substrate).** Construct the shared persist
`Engine` once via `Engine::with_signer(signer, &dsn)` (it builds *and* migrates) →
derive a per-slice view for each core via `Engine::from_shared(engine.backend().clone(),
engine.signer().clone())` (one connection pool, one signer, two views — the authority
view and the observation view never diverge) → acquire **one** shared edge runtime
(one Reticulum transport identity per node; leader election rides persist's
`SharedInstanceLease`) → hand the per-slice Engine + the shared edge to each core
(`ciris_lens_core::LensCore::attach_handler(&edge, engine)` is the proven entry; the
registry slice needs the [#76](https://github.com/CIRISAI/CIRISRegistry/issues/76)
`compose()` adapter) → expose the unified surface (registry gRPC/HTTP + lens read
surface + the one `/v1/identity`, the six-key aggregate via `Engine::local_identity_aggregate`).
No core constructs its own substrate or its own edge; the composition root owns the
singletons. (There is **no** separate "SharedInstanceDirectory / acquire shared edge
singleton" object — #210 shipped as `SharedInstanceLease`, cross-process *leader
election*, not an identity directory; the single federation identity is the
`local_identity_aggregate`.)

---

## 3. Trust shape — the canonical fabric nodes ARE `ciris-canonical`

The three canonical nodes are the **founding members of the `ciris-canonical`
governed community** ([`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md)
§2.1.1): `consensus_protocol: quorum:2/3`, `consensus_protocol_entrenched: true`,
admission of new operators gated by founding-core quorum. They replicate every
cross-region state change as **signed CEG envelopes over Reticulum** (the
[#58](https://github.com/CIRISAI/CIRISRegistry/issues/58) Spock-removal /
CEG-native replication endgame; no Spock, no DNS). The fabric node is the runtime
that *makes that community real* — three identical nodes, quorum-governed, any of
which can serve the trust + observation surface, none of which is depended upon.

**The three per-node keys ARE the registry-consensus quorum.** Migrating off the
shared vaulted steward key (§1.2) means registry authority is no longer "verify
against the one pinned steward fingerprint" — it is **2-of-3 founder-quorum over
the three nodes' own keys** (CEG 1.0-RC2 §8.1.13.1.1(a) founder-subset eval;
§5.6.8.10). Consumers re-root their pin from a steward fingerprint to the
**`ciris-canonical` `community_key_id`**, and Verify swaps its validation query
from single-key verification to `verify_founder_quorum`
([CIRISVerify#69](https://github.com/CIRISAI/CIRISVerify/issues/69); the verifier
shipped in v5.0.0 #31). Because `ciris-canonical` is `cohort_subkind: infrastructure`
it is **plaintext Commons, no DEK** (§8.1.13.3) — the trust root is world-auditable
by design; the quorum reads cleartext founder data. The high-blast-radius
break-glass (`EmergencyShutdown CONSTITUTIONAL`) remains the three human
accord-holder keys, hardware-rooted, **never on the fabric nodes** (§2.2 of the
registry mission) — the one authority the quorum cannot wield.

### 3.1 Trust is not consent — the role-scoped default

"Ships trusting the canonical group" decomposes per role, and **trust and consent
are orthogonal relationships in opposite directions**: trust is *inbound* (I accept
what you produce); consent is *outbound* (I let my data flow to you). Each fabric
role means something different on each axis:

| Role | **Trust** (I consume your output) | **Consent** (my data flows to you) |
|---|---|---|
| **Lens** (observation) | I accept lens's **scores / detections** | my **traces flow to lens** to be observed |
| **Registry** (authority) | I accept the registry's **identity / license / revocation verdicts** | **N/A** — registry is trust-only; the CIRIS-core group **only trust each other** (the founder-quorum *is* a closed mutual-trust set) |
| **Node** (consensus) | I accept node's **deferral / vote / moderation outcomes** | **medium-dependent** — moderation, routing, voting … vary by medium over **one** underlying CEG consent object |

So there is no single "trust the canonical group" switch — it is **per-role × per-axis**.
A deployment can keep registry verdicts while cutting traces-to-lens, or trust lens
scores while untrusting node moderation. Fine-grained sovereignty over the
trust/consent graph.

### 3.2 A default, not a forced root — the sovereign trust graph

Every CIRISServer and CIRISAgent **ships trusting `ciris-canonical`** out of the box —
but as a **default pin, never a forced root**. The operator is sovereign: it MAY
untrust the canonical group, trust other infrastructure communities instead or
alongside, or run with none. `cohort_subkind: infrastructure` is a **general
primitive** (CEG §5.6.8.10) — **anyone may stand up their own canonical group**;
`ciris-canonical` has no privileged wire status, only a default. And any group
**grows like every community: by its own `consensus_protocol` vote** (founder-quorum
admitting members), not by fiat. A walled garden has a forced root; a federation
ships a default and lets you replace it. (M-1's autonomy + justice: unregulated
standing is earnable without the steward's permission.)

### 3.3 One composition, any shape — self, family, server, agent

In 3.0 the lens / registry / node roles are **not separated into services** — they
cohabit this one composition, and the only architectural line is **agency**: a
**server** is the composition without a brain, an **agent** is the composition with
one (`agent = fabric node + brain`). So you can run a **server, an agent, both, or
either** — and a server occurrence is just another `identity_occurrence` (CEG
§5.6.8.8) you fold into your **`self`** (your private fabric across your devices),
your **`family`** (a shared household/group fabric), **or both**. The same runtime is
your personal infra, your family's shared infra, a public canonical member, or any
mix — chosen by the cohort you attach it to.

### 3.4 Fabric UX handles — CIRISServer is the control surface

CIRISServer is not merely a headless server; it **exposes every fabric control handle
upward to the agent client** — *everything the substrate exposes plus the fabric
level*:
- **Substrate handles** — the node's federation identity (`/v1/identity`, the six-key
  aggregate), federation-directory reads, content fetch, replication / health.
- **Fabric handles** — the per-role × per-axis **trust/consent toggles** (§3.1);
  **trust-graph management** (untrust, re-root, add / create groups — §3.2);
  **canonical-group membership + voting**; **self/family occurrence attachment**
  (§3.3); and the **NodeCode** peer-bootstrap shorthand — a compact, QR-able
  `CIRIS-V1-…` rendering of a peer's `key_id` + pubkey for add-by-code (→
  `trust=UNKNOWN`, then SAS-verify → `TRUSTED`). *NodeCode is the human shorthand for
  the otherwise-opaque federation `key_id`; it lives in CIRISAgent today
  (`node_code_codec`, 2.9.4) and **should be promoted to CEG as the canonical
  shorthand encoding** so every impl renders the same code for the same key — tracked
  as a follow-up.*

This is also where the Accord's **transparency requirement** lands operationally:
the fabric nodes are the surface that serves redacted PDMA logs / WBD tickets /
attestation reads for deployments above the public-accountability threshold. The
infrastructure that *holds* the audit corpus is the infrastructure that *publishes*
it.

---

## 4. Dependencies & gating

> **The full task graph, dependency lanes, and GANTT live in
> [`FSD/SERVER_1.0_PLAN.md`](FSD/SERVER_1.0_PLAN.md).** This section is the summary.

**What shipped (the old blockers are closed).** CIRISPersist#210 landed as
`SharedInstanceLease` (cross-process leader election) in persist v5.6.0; CIRISEdge's
shared-singleton acquisition shipped in v2.3.0. **persist v6.0.1** (pyo3-0.29 reland;
MSRV 1.83) and **verify v5.2.0** (MSRV 1.86) are tagged.

**Substrate floor (target):** the **6.x / edge-3.0 family** — `ciris-persist v6.0.1`,
`ciris-verify v5.2.0`, and `ciris-edge v3.0.0`. The cores (`ciris-registry-core`
v2.3.0, `ciris-lens-core` v1.4.2) are still on the **persist-5.5.5 / edge-2.2.2 /
verify-5.1.3** floor and must co-bump; a binary cannot link two persist majors.

**The current gate (four items; see the plan's §2 table):**
- **G0 — tag CIRISEdge v3.0.0** ([#89](https://github.com/CIRISAI/CIRISEdge/issues/89)):
  the family-lockstep WIP (persist 6.0.1 + pyo3 0.29) is uncommitted. **Keystone** —
  until edge v3.0.0 is a pinnable artifact, persist 6.x and edge cannot co-resolve.
- **G1 — co-bump `ciris-lens-core`** ([CIRISLensCore#53](https://github.com/CIRISAI/CIRISLensCore/issues/53)):
  version-only; `attach_handler` is already the proven cohabitation entry.
- **G2 — `ciris-registry-core` co-bump + `compose()` + injectable edge identity**
  ([CIRISRegistry#76](https://github.com/CIRISAI/CIRISRegistry/issues/76)): today the
  registry boot is hand-rolled in its bin's `main.rs` (no library `compose()`), and
  its edge identity mints from a filesystem path rather than accepting the shared one.
- **G3 — Rust-native edge-runtime acquisition** ([CIRISEdge#106](https://github.com/CIRISAI/CIRISEdge/issues/106)):
  `init_edge_runtime` is a PyO3 `#[pyfunction]`; a pure-Rust fabric node needs a Rust
  path. G2(b/c) and G3 can be *drafted* now; they only need G0 to *test*.

**Sequencing:** Path A — wait for G0, ship clean. **Server 0.5 = lens + registry**
(adopted by the agent ~2.9.8 train); **Server 1.0 = + node**, the complete fabric node
(agent ~2.9.10) — node-core is built last (a full substrate generation behind: persist
4.10; its WBD `route_deferral` surface already exists). Then: stand up `ciris-server`
→ cut the three canonical nodes (`lens` + `registry-us` + `registry-eu`) over to it →
all three become `ciris-canonical` fabric nodes. Landing window tracks the agent
~2.9.8 / 2.9.9 train (§5).

---

## 5. Lifecycle — the release plan

The **agent release train is the coordination clock**; the two Server releases hang
off it. The load-bearing move: registry-core stops folding into the *agent* and
instead lands in the *Server composition* the agent then adopts — one cohabitation
built once, not a per-shape fold built twice.

| Agent release | Server | Composition | What happens |
|---|---|---|---|
| **2.9.6** ✅ | — | + `ciris-lens-core` | LensCore cohabits the agent — proves the pattern. [Deployed] |
| **~2.9.8** | **Server 0.5** | lens + **registry** | Registry-core was slated to fold into the *agent* at 2.9.8 — **superseded**: the agent adopts **CIRISServer 0.5** (the lens+registry fabric node) as its composition instead of a bespoke agent fold. [Spec — gated §4] |
| **2.9.9** | — | (same) | **Cleanup**: retire the half-built agent-2.9.8 registry-fold scaffolding; align the agent onto the shared composition. [Spec] |
| **2.9.10** | **Server 1.0** | registry + lens + **node** | The **node fold completes the fabric node** — **CIRISServer 1.0** is the full three-core node; the agent adopts the complete composition instead of folding node itself. Gated additionally on node-core readiness. [Spec] |

**Why lens+registry first, node later.** Server 0.5 ships the two *ready* cores —
lens proven in 2.9.6, registry green on the substrate-trio branch. `ciris-node-core`
(the least-mature sibling) is deliberately held to Server 1.0 / 2.9.10: a third rlib
over the same singletons, no structural change.

**Why the supersession.** Registry-core was always going to cohabit; the fabric-node
realization only changed its *home*. Folding it into the agent specifically would
have built the registry cohabitation twice (once for the agent, once for the
canonical servers). Server 0.5 establishes the lens+registry composition once, and
because `agent = fabric node + brain` the agent adopts the *same* composition. This
**resolves §6's "composition home"**: the Server release is where the one shared
composition is defined; the agent consumes it. Server and agent move in lockstep —
each Server composition milestone is also an agent composition milestone.

The fabric node is **never** "folded" — the *agent* is the folded form (cores +
brain). The fabric node and the agent stay two profiles of one composition for as
long as both exist.

---

## 6. Open questions

- **Trace-corpus migration off TimescaleDB.** The lens corpus moves from
  TimescaleDB into the durable persist substrate (§1.2). Open: is the existing
  TimescaleDB history migrated, or does the corpus start fresh at cutover with the
  old store kept read-only for archival? (Decided when the lens-core / persist
  trace-storage path is wired.)

**Resolved (recorded here so they're not reopened):**
- **Composition mechanism** (resolved 2026-06-13). The one shared composition is a
  **literal `ciris-server` library** (`crate-type = ["cdylib", "rlib"]`): the binary
  links the rlib, and CIRISAgent — pure Python — pip-installs the **PyO3 abi3 wheel**
  and links *that* instead of composing the cores itself. Built once, two shapes. The
  "shared discipline doc" fork is dropped; the agent depends on `ciris-server`, not on
  the individual cores.
- **Headless WBD routing** (confirmed 2026-06-13). `ciris-node-core` already carries
  the `route_deferral` routing / Wise-Authority surface, confirming routing-to-WAs is a
  **fabric-node responsibility**, distinct from the agent's deferral *origination*. This
  is **Server 1.0** scope (the node fold — agent 2.9.10), wired after the 0.5 lens+registry node.
- **Surface scope** — the fabric node serves registry gRPC/HTTP + the lens read
  surface + `/v1/identity`. The central ingest API / TimescaleDB / Grafana are
  **retired**, not kept as a sidecar (§1.2); observation is substrate-resident and
  CEG-replicated.
- **Relationship to the singletons** — CIRISServer **replaces** the
  `*.registry.ciris-services-1.ai` *and* the CIRISLens deployments in place; the
  three become `ciris-canonical` fabric nodes (§1.2). Not retained beside it.

---

## 7. References

- [`CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`](../CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md) — the MDD methodology this charter is written against.
- [`CIRISAgent/ACCORD.md`](https://github.com/CIRISAI/CIRISAgent) §M-1 — the meta-goal; the six principles; Wisdom-Based Deferral; the Order-Maximisation Veto; the stewardship covenant; the >100k transparency requirement.
- [`CIRISRegistry/MISSION.md`](../CIRISRegistry/MISSION.md) §2.1 / §2.1.1 / §2.2 — per-install stewards; the `ciris-canonical` governed community; HUMANITY_ACCORD.
- [`CIRISRegistry/FSD/CEG`](../CIRISRegistry/FSD/CEG) — the wire grammar (1+4; §5.6.8.8.2 identity aggregate; §7 reserved-prefix discipline; §8.1.13 community).
- [`CIRISLensCore/MISSION.md`](../CIRISLensCore/MISSION.md) — the observation slice; "validated, not adjudicated."
- [`CIRISNodeCore/MISSION.md`](../CIRISNodeCore/MISSION.md) — the consensus slice; the cohabitation arc.
- [`CIRISPersist/MISSION.md`](../CIRISPersist/MISSION.md) / [`CIRISVerify/MISSION.md`](../CIRISVerify/MISSION.md) / [`CIRISEdge/MISSION.md`](../CIRISEdge/MISSION.md) — the substrate trio.
- CIRISPersist#210 (`SharedInstanceDirectory`) · CIRISEdge v2.3.0 · [CIRISRegistry#62](https://github.com/CIRISAI/CIRISRegistry/issues/62) (fabric-siblings CEG/RET) · [#58](https://github.com/CIRISAI/CIRISRegistry/issues/58) (Spock removal).

---

## Update cadence

This document is updated:
- On every change to the composition (a core added/removed; a substrate version bump).
- On every change to the separation-of-powers invariant (§1.5) or the agency-free bound (§1.3).
- On every lifecycle-stage transition (Spec → Impl → Deployed (canonical)).
- On every CIRISAccord revision affecting the fabric node's mission.

Last updated: 2026-06-13 (substrate scouted; gate moved to the CIRISEdge v3.0.0 tag + registry/lens co-bump + two adapter PRs [CIRISRegistry#76, CIRISEdge#106, CIRISLensCore#53]; bin+abi3-wheel shape fixed; see FSD/SERVER_1.0_PLAN.md). Preceded by the 2026-06-12 initial charter.
