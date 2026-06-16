# CIRISServer — the fabric node

> **The decentralized CEWP node/client.** `agent = fabric node + brain`.
> CIRISServer is the federation's headless cohabitation runtime: the *same*
> composition of cores that folds into a CIRISAgent, packaged **without a
> reasoning brain**. Infrastructure must not have agency — so the fabric node
> attests, stores, observes, reaches consensus, and transports, but it does
> **not** reason, decide, or act.

It is the node software for **CEWP** — the decentralized network formed by
[CEG](https://github.com/CIRISAI/CIRISRegistry/tree/main/FSD/CEG), the CIRIS
Epistemic Grammar. Any operator can run one; no single instance is load-bearing.

**Read [`MISSION.md`](MISSION.md) first** — the charter (why this exists, the
separation-of-powers invariant, the apophatic bounds), written against the
[CIRIS Accord](https://ciris.ai/ciris_accord.txt) (M-1), the
[CEG §7.0.1 fabric-node discipline](https://github.com/CIRISAI/CIRISRegistry/blob/main/FSD/CEG/07_reserved.md),
and [Mission Driven Development](https://github.com/CIRISAI/CIRISAgent/blob/main/FSD/MISSION_DRIVEN_DEVELOPMENT.md).
The build plan + dependency GANTT live in [`FSD/SERVER_1.0_PLAN.md`](FSD/SERVER_1.0_PLAN.md).

## What it is

A thin composition crate — shipped as both the headless **`ciris-server`
binary** and a **PyO3 abi3 wheel** that CIRISAgent (pure Python) links *instead
of composing the cores itself* — linking the federation's cores as libraries
over **one shared substrate**:

```
ciris-server (the fabric node)
  ├── ciris-registry-core   authority    — identity / license / revocation / steward attestation
  ├── ciris-lens-core       observation  — Coherence Ratchet / Capacity Score (validated, not adjudicated)
  ├── ciris-node-core       consensus    — deferral / voting / expertise / moderation        [folds in at 1.0]
  ├── one shared ciris-persist Engine    — the durable corpus + federation directory
  └── one shared ciris-edge runtime      — CEG/RET transport + the node's single federation identity
```

It authors no primitives; CEG and the cores own the grammar. CIRISServer is the
wiring, the boot order, one unified identity endpoint (`/v1/identity`, the
six-key `LocalIdentityAggregate`) — and the **control surface** below.

## A node *and* a client — the UX handles

CIRISServer renders **no UI of its own**. It is also the **client control
surface**: it exposes every fabric control handle upward, and rich UIs consume
them. The handles (MISSION §3.4):

- **Substrate handles** — the node's federation identity (`/v1/identity`),
  federation-directory reads, content fetch, replication / health.
- **Fabric handles** — the per-role × per-axis **trust/consent toggles**,
  **trust-graph management** (untrust, re-root, create/join groups),
  **canonical-group membership + voting**, **self/family occurrence
  attachment**, and the **NodeCode** QR-able peer-bootstrap shorthand.

Those handles are consumed by **rich clients** — [CIRISPortal](https://github.com/CIRISAI/CIRISPortal)
and [CIRISNode](https://github.com/CIRISAI/CIRISNode), and **chiefly the
[CIRISAgent](https://github.com/CIRISAI/CIRISAgent) client**, the Kotlin
Multiplatform (KMP) UI through which most people meet the fabric. The
infrastructure that *holds* the audit corpus is the surface that *publishes* it
(redacted PDMA logs / WBD tickets / attestation reads, per the Accord's
transparency requirement).

## What it replaces

The three canonical nodes (`lens` + `registry-us` + `registry-eu`) become
identical fabric nodes — the founding members of the `ciris-canonical` governed
community, replicating via CEG over Reticulum (no Spock, no DNS).

- **The CIRISRegistry singleton servers go away.** Each node handles its own key
  the way the lens already does (per-node identity, no shared vault key); the
  three per-node keys *are* the 2-of-3 registry-consensus quorum.
- **The CIRISLens deployment goes away** — Python ingest + TimescaleDB + Grafana
  retired. A central dashboard the whole federation reads is itself the singleton
  this architecture forbids. The lens *function* lives as `ciris-lens-core`
  inside every fabric node, over the shared substrate, queryable from any node.

The *repos* (`ciris-registry-core`, `ciris-lens-core`, `ciris-node-core`) stay —
they are the libraries this binary composes, the same cores that fold into
CIRISAgent.

## Install

```sh
pip install ciris-server      # the PyO3 abi3 wheel (or build the binary: cargo build --release)
ciris-server                  # boots a zero-setup node — mode=server, trusts ciris-canonical, no wizard
```

Defaults need no setup: data under `$CIRIS_HOME`, SQLite corpus (Postgres via
`CIRIS_DB_URL`), identity minted-or-migrated on first boot, Reticulum transport
up, the lens read API on `listen+1`. Migrating a deployed CIRISLens host? See
[`FSD/LENS_TO_SERVER_MIGRATION.md`](FSD/LENS_TO_SERVER_MIGRATION.md) — the
federation key and RNS address carry over byte-identically (no re-key).

The same wheel gives CIRISAgent the lens drop-in: `from ciris_server import
LensClient`.

## Status

**Shipped (0.2.x) — the lens-only fabric node, hardened.** `ciris-server` boots a
zero-setup node: relay ingest (CEG `AccordEventsBatch` over Reticulum/HTTP) + the
seven frozen `GET /lens/api/v1/*` read endpoints + the six-key `GET /v1/identity`,
over one shared persist Engine. Federation signatures are **100% hybrid
post-quantum** (Ed25519 + ML-DSA-65, hard cut — no classical-only path); the
sealed-Ed25519 federation seed and the RNS transport identity are TPM/SE/StrongBox
sealed (software-encrypted fallback) and adopted byte-identically on a CIRISLens
takeover (no re-key). Also shipped: legacy-trace import (`ciris-server
import-traces`) and an operator capability surface — the holonomic federation
scoreboard (`ciris-server scoreboard`) plus an interpreted benchmark/capability
page at <https://cirisai.github.io/CIRISServer/>. Below the lens-store disk minimum
the node degrades to a Reticulum relay node.

Substrate floor: **persist v8.2.0 / edge v4.2.0 / verify-family v5.9.0**
(CEG 1.0-RC12). `ciris-lens-core` is **absorbed in-tree** — the standalone
CIRISLensCore library and the CIRISLens deployment (Grafana/TimescaleDB/Python
ingest) retire. Cohabitation + CEG-profile conformance is gated by
[CIRISConformance](https://github.com/CIRISAI/CIRISConformance) against the
published wheels.

Roadmap (driven by the CIRISAgent train):

- **0.5** (+ registry authority) — agent **~2.9.8**. Prep:
  [`FSD/REGISTRY_FOLD_DERISK.md`](FSD/REGISTRY_FOLD_DERISK.md), [#2](https://github.com/CIRISAI/CIRISServer/issues/2).
- **1.0** (+ node consensus — the complete fabric node) — agent **~2.9.10**.

The wiring needs **no core changes** — CIRISServer adapts to what's shipped.
See [`FSD/SERVER_1.0_PLAN.md`](FSD/SERVER_1.0_PLAN.md).

## License

[AGPL-3.0-or-later](LICENSE) — matching the CIRIS ecosystem.
