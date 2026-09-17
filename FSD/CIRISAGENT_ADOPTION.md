# CIRISAgent Adoption Notes — `agent = fabric node + brain`

> **Thesis.** CIRISAgent stops being a self-contained Python monolith and becomes
> *exactly* **the `ciris-server` abi3 wheel (the Rust fabric node) + the agent
> "brain" (LLM cognition) mounted on the Adapter seam, and nothing else.** The
> fabric node already owns the entire substrate + everything that is not LLM
> cognition. This doc is the file-level migration map proving that out.
>
> **Scope of this doc.** Analysis only. Written from an isolated CIRISServer
> worktree (branch at the foot of this file). It does **not** modify any
> CIRISAgent file; the deletion map is the *plan*, executed in the agent repo by
> the agent team against the release-gate `stage7`/`stage8` (agent-adoption →
> cut 0.6).
>
> **Repos compared**
> - `/home/emoore/CIRISServer` — the Rust fabric node (`src/`, ~20.5k LOC of
>   Rust) + the vendored KMP UI under `client/`. Ships as the `ciris-server`
>   binary **and** a PyO3 abi3 wheel (`pip install ciris-server`,
>   `from ciris_server import …`). Pins persist `v10.0.0` / edge `v7.0.0` /
>   verify-family `v7.2.0` (see `Cargo.toml` lines 126-141).
> - `/home/emoore/CIRISAgent` — the Python agent. `ciris_engine/logic/` is
>   **~182,000 LOC** of Python today; `main.py` (944 LOC) is the entrypoint.

---

## 1. Rust-now-covers inventory (`CIRISServer/src/`)

What the fabric node provides today, with the `src/` location and the CIRISAgent
Python it displaces. Substrate crates (persist/edge/verify/lens-core) are consumed
as the same wheel; everything below is ciris-server's *own* Rust on top.

| Fabric capability | CIRISServer Rust (`src/…`) | Wheel / endpoint surface | Displaces (CIRISAgent Python) |
|---|---|---|---|
| **Composition root / boot** | `compose.rs` (1384), `lib.rs` (543) `serve`/`serve_with_adapter`, `main.rs` (339) | `from ciris_server import main`; `ciris-server` console-script (`py_main`, `lib.rs:377`) | `main.py` boot, `logic/runtime/` (11,570) — service construction, lifecycle |
| **Graph / storage / migrations** | substrate: `ciris_persist::Engine` (re-hosted, `lib.rs:446` `register_persist`) | `from ciris_server import Engine, NotFound` (top-level alias, `lib.rs:530`); `ciris_server.persist` submodule | `logic/persistence/` (8,445) — db/core.py sqlite, models/, stores |
| **Transport / replication / Reticulum-RNS** | substrate: `ciris_edge::Edge` (re-hosted, `lib.rs:476` `register_edge`); `replication_reconcile.rs` (172), `peer.rs` (340) | `ciris_server.edge` submodule; `/v1/federation/peers` (`federation_peers.rs`) | `logic/runtime/edge_runtime.py`, `logic/adapters/edge_communication/`, RNS/Reticulum bridges |
| **Attestation / crypto / fedcode / NodeCode / audit hash-chain** | substrate: `ciris_verify_core`; `nodecode.rs` (701), `federation_nodecode.rs` (124), `auth/attestation.rs` (153) | `/v1/federation/node-code`, `/v1/auth/attestation` | `services/infrastructure/authentication/attestation/tree_verify.py`, `logic/audit/` (1,344) chain_bridge.py |
| **Federation peering + identity** | `federation_admin.rs` (292), `federation_peers.rs` (191), `identity.rs` (909) | `/v1/federation/peering`, `/v1/federation/peers*`, `/v1/federation/identity`, `/v1/self/identity` | `logic/adapters/api/routes/federation/` (1,027), `ciris_adapters/cirisnode/` |
| **Config-as-CEG (ZERO env vars)** | `config.rs` (321), `graph_config.rs` (455), `config_api.rs` (239), `config_reconcile.rs` (388) | `/v1/config/{key}` (owner-gated), `/v1/setup/config` | `logic/config/` (794) env_utils.py, `os.environ`/`getenv` reads everywhere; `routes/setup/config.py` |
| **Auth subsystem (absorbed from agent — single authority)** | `auth/` dir (~6.7k LOC): `session.rs` (630), `roles.rs` (523), `oauth.rs` (1054), `api_keys.rs` (313), `ownership.rs` (1012), `store.rs`, `gate.rs`, `verify.rs`, `consent.rs`, `bootstrap.rs` (1152), `self_login.rs`, `erasure.rs` | `/v1/auth/login,logout,me,refresh`, `/v1/auth/native/google,apple`, `/v1/auth/consent`, `/v1/auth/erasure` | `logic/services/infrastructure/authentication/` (subset of 6,865), `routes/auth.py`, `services/governance/` WiseAuthority/consent (9,194 partial) |
| **WaCert + ownership / owner-binding** | `auth/ownership.rs` (1012), `auth/bootstrap.rs` (1152), `auth/roles.rs` | `/v1/setup/root`, `/v1/setup/owned-nodes`, `/v1/self/upgrade-owner` | WiseAuthority cert tables (`cirislens_wa_cert` persist feature, `Cargo.toml:126`), `routes/setup/complete.py` |
| **Device-grant (on-behalf-of, RFC-8628)** | `auth/device_grant.rs` (1198), `auth/device_auth.rs` (414) | `/v1/auth/device/{code,delegate,claim,approve,deny,token,grants,revoke}` | agent device-auth in `routes/setup/device_auth.py` |
| **NodeCode claim + first-run root claim** | `claim_remote.rs` (636), `nodecode.rs` (701), `auth/bootstrap.rs`, `main.rs` `run_claim` | `/v1/setup/claim-remote`, `/v1/setup/status`, `ciris-server claim` CLI | `logic/setup/` (802) wizard claim, `routes/setup/` claim paths |
| **Self-occurrence enrollment (multi-device self)** | `auth/occurrence.rs` (504) | `/v1/self/occurrence`, `/v1/self/occurrences`, `/v1/self/occurrence/revoke` | *new — no agent equivalent* |
| **Accord kill-switch (HUMANITY_ACCORD)** | `accord.rs` (1714), `accord_halt.rs` (126), `accord_custody.rs` (205), `accord_provision.rs` (1169), `accord_reactivate.rs` (256), `accord_pki/`, `quorum.rs` (137), `family.rs` (161) | `/v1/accord/holder`, `/v1/accord-holders`, `/v1/accord/message`, `/v1/accord/family*`, `/v1/accord/genesis/*`, `/v1/accord/invocation*`, `/v1/accord/provision-holder`, `/v1/accord/yubikey-status`; `ciris-server accord reactivate` CLI | `logic/accord/` (1,480) — the Python accord execution/verification |
| **Holonomic / FountainSwarm + capacity scoring** | `holonomic.rs` (228), `scorer.rs` (292) | capacity `n_eff` / `sustained_coherence` CEG emit; `/v1/my-data/capacity` data | agent telemetry/scoring (`logic/telemetry/` 694 partial) |
| **consent:replication** | `auth/consent.rs` (155), `replication_reconcile.rs` (172) | `/v1/auth/consent`, `/v1/federation/peering` | `services/governance/consent/service.py` (~1,800) |
| **Secrets / keystore** | substrate: `ciris_keyring` (software + pqc-ml-dsa + pkcs11; `Cargo.toml:141`); custody in `identity.rs`, `accord_custody.rs` | `ciris-server identity create --backend {tpm,yubikey,software}` | `logic/secrets/` (1,992) keystore/encryption, `secrets.db` |
| **Node read-API + health (port 4243)** | `health.rs` (122), `memory_api.rs` (615), `import.rs`/`ingest_http.rs` | `/health`, `/v1/health`, `/v1/system/health`, `/v1/memory/*` | agent's own health route; memory read surface |
| **Safety / moderation / age-assurance** | `safety/` (moderation.rs, watchlist.rs, age.rs) | `/v1/safety/{moderation,watchlist,age-assurance}` | `routes/` safety (CIRISServer#20-origin) |
| **Adapter seam (mirror of `BaseAdapterProtocol`)** | `adapter.rs` (131) — `Adapter` trait + `AdapterContext` + `serve_with_adapter` | the mount point for the brain | the agent's own adapter-orchestration plumbing in `logic/runtime/` |

**The defining identity** (Cargo.toml line 9 / MISSION.md): *"the fabric node …
packaged without a reasoning brain. `agent = fabric node + brain`."* The Rust
tree is the "without a reasoning brain" half, complete.

---

## 2. CIRISAgent Python deletion map

Per subsystem: the disposition and the specific Rust/wheel symbol that replaces
it. LOC are `wc -l` over each dir's `*.py` (measured 2026-06-23).

### 2a. The big deletions (substrate + fabric, ~covered today)

| Python module/dir | LOC | Disposition | Replaced by |
|---|---|---|---|
| `logic/persistence/` (db/core.py sqlite, models/, stores) | 8,445 | **DELETE** | `from ciris_server import Engine, NotFound` (`lib.rs:446/530`); persist `v10.0.0` Engine. db/core.py already late-imports `ciris_persist.Engine` (core.py:931) — flip to `ciris_server`. |
| `logic/audit/` (chain_bridge.py hash-chain) | 1,344 | **DELETE** | verify hash-chain + persist attestation rows; `auth/attestation.rs`. chain_bridge.py already imports `ciris_persist.Engine`. |
| `logic/secrets/` (keystore, encryption, secret store) | 1,992 | **DELETE** | `ciris_keyring` (software/pqc-ml-dsa/pkcs11, `Cargo.toml:141`); custody via `identity.rs`. Retire `secrets.db`. |
| `logic/config/` (env_utils.py, db paths, bootstrap) | 794 | **DELETE** | config-as-CEG: `config.rs`/`graph_config.rs`/`config_reconcile.rs`, `/v1/config`. **Kills env-var handling.** |
| `logic/registries/` (service/status registry) | 1,298 | **DELETE/SHRINK** | The fabric composition root *is* the registry; only a thin brain-service registry remains (see KEEP). |
| `logic/accord/` (Python accord exec/verify) | 1,480 | **DELETE** | `accord.rs` (+ halt/custody/provision/reactivate); kill-switch is now substrate-enforced (disk halt latch + `exit 42`), never Python-trusted. |
| `services/governance/` (WiseAuthority, consent, delegation) | 9,194 | **MOSTLY DELETE** | `auth/ownership.rs`, `auth/consent.rs`, `auth/roles.rs`, `replication_reconcile.rs`. WA-cert table is the `cirislens_wa_cert` persist feature. |
| `services/infrastructure/` (authn, attestation, tree_verify, db-maint) | 6,865 | **MOSTLY DELETE** | `auth/` subsystem + `ciris_verify_core`. tree_verify.py already imports `ciris_verify`. |
| `services/graph/` (graph memory, TSDB, metrics) | 14,682 | **DELETE → thin client** | persist Engine graph DX + `memory_api.rs` `/v1/memory/*`. The graph *store* is substrate; the brain keeps only a typed read client. |
| `logic/runtime/` (boot, lifecycle, edge_runtime.py, service init) | 11,570 | **DELETE → thin wrapper** | `compose.rs::serve_with_adapter` + `adapter.rs`. edge_runtime.py → `ciris_server.edge`. Only a brain-mount shim survives. |
| `routes/federation/` | 1,027 | **DELETE** | `federation_admin.rs`/`federation_peers.rs`/`federation_nodecode.rs` (`/v1/federation/*`). |
| `routes/setup/` (claim/attestation/device_auth/complete/config) | 7,150 | **DELETE** | `auth/bootstrap.rs`, `claim_remote.rs`, `auth/device_grant.rs`, `graph_config.rs` (`/v1/setup/*`, `/v1/auth/device/*`). |
| `routes/system/` (auth/identity/data-mgmt subset) | 7,579 | **SPLIT** | identity/key/data-mgmt → fabric (`identity.rs`, `auth/erasure.rs`); LLM/adapter/runtime status → KEEP (brain). |
| `routes/auth.py`, `routes/consent.py`, `routes/audit.py` | (in api 49,089) | **DELETE** | `auth/session.rs`/`oauth.rs`/`api_keys.rs`, `auth/consent.rs`; audit = verify chain. |
| `ciris_adapters/cirisnode/` (fabric node bridge) | 2,248 | **DELETE** | the node *is* ciris-server now; bridge is redundant. |
| `ciris_adapters/ciris_verify/` (FFI bindings) | 7,717 | **DELETE/SHRINK** | verify is re-hosted in the one wheel; raw FFI bindings collapse to the wheel import. |
| `ciris_adapters/a2a/`, `external_data_sql/` | ~1,300 | **REVIEW** | a2a federation comms → edge; SQL connector is a brain tool — KEEP if used for cognition. |

**Headline deletion total:** the substrate + fabric rows above are roughly
**80,000–95,000 LOC** of Python that dies or collapses to a wheel import (the
monsters alone — `services/graph` 14.7k, `logic/runtime` 11.6k,
`services/governance` 9.2k, `persistence` 8.4k, `services/infrastructure` 6.9k,
`routes/setup` 7.2k, `routes/federation` 1.0k, `accord` 1.5k, `secrets` 2.0k,
`audit` 1.3k, `config` 0.8k, plus the `cirisnode`+`ciris_verify` adapters ~10k).

### 2b. The KEEP-list — the real brain (cognition, stays Python)

| Python module/dir | LOC | Disposition | Why |
|---|---|---|---|
| `logic/processors/` | 12,910 | **KEEP** | the agent's state machine / cognitive loop |
| `logic/dma/` | 6,649 | **KEEP** | Decision-Making Algorithms (LLM calls + prompt loading) |
| `logic/handlers/` | 2,344 | **KEEP** | action handlers (speak/memorize/tool/…) |
| `logic/conscience/` | 1,893 | **KEEP** | guardrails / action validation |
| `logic/context/` | 3,475 | **KEEP** | context assembly for prompts |
| `logic/formatters/` | 756 | **KEEP** | LLM output formatting |
| `logic/buses/llm_bus.py` | (in 6,436) | **KEEP** | LLM provider abstraction (faculties/wise_bus reviewed) |
| `services/runtime/llm_service/` | (in 5,724) | **KEEP** | LLM provider selection / token handling |
| `services/tool/`, `services/tools/` | 1,411 + 1,011 | **KEEP** | tool discovery + execution (cognition tooling) |
| `services/skill_import/` | 1,941 | **KEEP** | skill authoring/import (agent feature) |
| `ciris_engine/ciris_templates/`, prompts | — | **KEEP** | agent templates / prompts |
| cognitive `ciris_adapters/*` (discord, slack, mcp_client/server, mock_llm, github, …) | ~46,000 | **KEEP** | genuinely *agent* I/O + tool connectors (NOT fabric transport) |

The brain that survives is roughly **~30k LOC of core cognition** (`processors`
+ `dma` + `conscience` + `context` + `handlers` + llm/tool services) **plus the
cognitive adapter connectors** (~46k, mostly optional integrations).

### 2c. The seams that confirm the deletions (grep findings)

- **Env vars (die under config-as-CEG):** primary gateway `logic/config/env_utils.py`;
  hotspots `main.py`, `routes/setup/config.py` (21 hits), `routes/auth.py` (11).
  All replaced by signed `config:*` CEG (`graph_config.rs`).
- **SQLite (dies under persist Engine):** `logic/persistence/db/core.py` (1,210 LOC,
  81 sqlite hits) — already late-imports `ciris_persist.Engine`; `routes/audit.py`
  (39 hits) → verify chain.
- **WA-cert / attestation (dies under auth subsystem):** `routes/setup/complete.py`
  (40 hits), `routes/setup/attestation.py` (45), `tree_verify.py` (imports
  `ciris_verify`). → `auth/ownership.rs`, `auth/attestation.rs`, persist
  `cirislens_wa_cert`.
- **Transport/RNS (dies under edge):** `logic/runtime/edge_runtime.py` (imports
  `ciris_edge`), `routes/federation/peers.py` (28). → `ciris_server.edge`, `peer.rs`.
- **Crypto/keystore (dies under keyring):** `routes/setup/device_auth.py` (13),
  `routes/system/data_management.py` (31). → `ciris_keyring` / `identity.rs`.

**Already-substrate imports today** (the wheel boundary is *already* threaded —
these flip from `ciris_persist`/`ciris_verify`/`ciris_edge` to `ciris_server`):
`persistence/models/graph.py:30`, `persistence/db/core.py:931/1003/1101`,
`audit/chain_bridge.py:201`, `authentication/attestation/tree_verify.py:156`,
`runtime/edge_runtime.py:79`.

---

## 3. The "literally just CIRISServer + brain" assembly

### Today (CIRISAgent `main.py`, 944 LOC)
`main.py` reads `.env` from 5+ paths → resolves `CIRIS_HOME` → click CLI →
`is_first_run()` → first-run wizard → validates LLM API keys → discovers modular
services → `load_config()` → constructs **`CIRISRuntime`** (which builds
GraphService, WiseAuthorityService, ConsentService, LLMService, AgentProcessor,
ActionDispatcher, all adapters) → `runtime.initialize()` → `runtime.run()`.
*Almost all of that (env, home, config, graph, WA, consent, federation, setup) is
fabric and dies.*

### Target — pip-depend on the wheel, boot the node, mount the brain

```toml
# pyproject.toml — the agent's ONLY substrate dependency becomes the one wheel
dependencies = [
    "ciris-server==0.5.x",   # the fabric node: persist+edge+verify+lens re-hosted
    # ... brain-only deps: the LLM SDKs, prompt libs, adapter connectors ...
]
```

```python
# main.py (target shape) — the agent is the node + a brain adapter
import ciris_server                      # the wheel: Engine, Edge, main, ...
from ciris_brain import BrainAdapter     # the surviving cognition (processors/dma/...)

def main():
    # No .env parsing, no CIRIS_HOME juggling, no load_config():
    # config is signed config:* CEG resolved by the node at boot (ZERO env vars).
    # The node owns home/key-id via --home/--key-id (lib.rs parse_serve_flags).
    ciris_server.main()      # boots compose::serve_with_adapter under the hood
                             # → one persist Engine + one Edge + the read-API (4243)
```

The brain is the **Adapter** (Rust `adapter.rs` mirrors the agent's
`BaseAdapterProtocol`: `get_config`/`get_status`/`get_services_to_register`/
`start`/`run_lifecycle`/`stop`). Concretely the agent provides an adapter whose
`run_lifecycle` *is* the cognitive loop (`processors`), receiving the shared
`Engine` via `AdapterContext`. The node contributes port 4243 (substrate read-API)
and the auth/federation/identity/accord/config surface; the brain contributes the
cognition endpoints (`/v1/chat/*`, memory writes via the loop, `/v1/system/*`
LLM status) on its own listener (8080).

> **Note on the Rust↔Python adapter bridge.** `serve_with_adapter` takes a Rust
> `Adapter`. The agent's brain is Python. The crisp boundary that exists *today*
> is the wheel: the agent boots the node via `ciris_server.main()` and runs its
> loop against the re-hosted `Engine`. A first-class **PyO3 adapter-registration
> hook** (so a Python object satisfies the `Adapter` trait and folds its routes
> into the node's router) is the one piece of the seam not yet exposed across the
> wheel — see Gap #2.

### What CIRISAgent's `setup.py` becomes
`setup.py` (10.6 KB) currently packages the whole engine. Target: package only
`ciris_brain` (processors/dma/conscience/context/handlers/llm+tool services +
templates) and the cognitive adapters; declare `ciris-server` as the runtime dep.
The fabric modules are removed from the wheel manifest entirely.

---

## 4. UI adoption + read-direct rewiring

### 4a. Adopt CIRISServer/`client` as the base (purely additive)
The two KMP clients are **identical at the directory level** — CIRISServer's
`client/` was vendored from CIRISAgent's and is a superset. Adopting it is
additive: same `shared/src/commonMain/kotlin/ai/ciris/mobile/shared/` tree, with
**+6 Screen/ViewModel pairs** the agent client lacks (the new substrate surfaces):

- `IdentityManagementScreen` + `…ViewModel` — self-identity + device roster
  (self-occurrence)
- `ContactsScreen` — federation peer contacts
- `DelegationsScreen` — device on-behalf-of grants (list/approve/revoke)
- `AccordScreen` — accord family + holder registry
- `AccordCeremonyScreen` — guided genesis ceremony
- `ProvisionAccordHolderScreen` — on-device YubiKey NFC fed-ID custody

Conversely the agent client's agent-cards (WiseAuthority/skill-studio/runtime
reasoning-stream surfaces) stay agent-side and read the brain API.

### 4b. The split-port wiring — the load-bearing latent bug
**API client:** `client/shared/src/commonMain/kotlin/ai/ciris/mobile/shared/api/CIRISApiClient.kt`.

The base URL is **hardcoded to a single port 4243**:
- `CIRISApiClient.kt:195` — constructor default `baseUrl: String = "http://127.0.0.1:4243"`
- `CIRISApiClient.kt:324` — `const val LOCAL_NODE_URL = "http://127.0.0.1:4243"`

`LOCAL_NODE_URL` is then used as the default-parameter for many methods
(`CIRISApiClient.kt:1352,1468,1507,1555,1590`), so it cannot be switched
per-endpoint without refactoring. Scattered 8080 references exist outside the
client (`ServerConnectionViewModel.kt`, `AdaptersViewModel.kt`) — i.e. the split
is *ad hoc*, not modeled.

**Where the split-port wiring must land:** introduce two base URLs in
`CIRISApiClient` —
- **4243 (substrate read-API, ciris-server Rust)** for node/health, federation,
  identity/occurrences, accord, trust/attestation, config, capacity scores;
- **8080 (brain API, agent Python)** for chat/cognition, memory writes via the
  loop, LLM/adapter/runtime status, skills.

`ServerConnectionViewModel` must probe **both** ports and degrade gracefully (a
ciris-server node with no brain still answers on 4243 — exactly the
`/v1/system/health` "CONNECTED on SERVER status:ok" posture shipped in 0.5.32).

### 4c. Read-direct mapping (move these reads from 8080 → 4243)

| UI area | Endpoint(s) | Move to | ViewModels |
|---|---|---|---|
| Node health | `/v1/health`, `/v1/system/health` | 4243 (`health.rs`) | `StartupViewModel`, `ServerConnectionViewModel` |
| Federation / peering | `/v1/federation/peering`, `/v1/federation/peers*`, `/v1/federation/identity`, `/v1/federation/self-key-record`, `/v1/federation/node-code`, `/v1/federation/metrics` | 4243 (`federation_*.rs`) | `NetworkPeersViewModel`, `NetworkPeerDetailViewModel`, `NetworkTrustGraphViewModel`, `NodeSwitcherViewModel` |
| Identity / occurrences | `/v1/self/identity`, `/v1/self/occurrence(s)`, `/v1/self/age`, `/v1/self/login`, `/v1/self/upgrade-owner` | 4243 (`identity.rs`, `auth/occurrence.rs`) | `IdentityManagementViewModel` |
| Trust / attestation | `/v1/federation/peers/{id}/{trust,sas,appearance}`, `/v1/auth/attestation` | 4243 | `NetworkPeerDetailViewModel`, `NetworkTrustGraphViewModel` |
| Accord | `/v1/accord/*`, `/v1/accord-holders`, `/v1/accord/yubikey-status` | 4243 (`accord*.rs`) | `AccordViewModel`, `AccordCeremonyViewModel`, `ProvisionAccordHolderViewModel` |
| Delegations / device-grant | `/v1/auth/device/*`, `/v1/auth/{login,me,owner-hint}` | 4243 (`auth/*.rs`) | `DelegationsViewModel`, `LoginScreen` |
| Config | `/v1/config/{key}`, `/v1/setup/config` | 4243 (`config_api.rs`/`graph_config.rs`) | `ConfigViewModel` |
| Capacity scores | `/v1/my-data/capacity` (substrate `n_eff`/`sustained_coherence` half) | 4243 (`scorer.rs`) | `HealthReputationScreen` |
| Setup / owned-nodes | `/v1/setup/{status,owned-nodes,root,claim-remote}` | 4243 (`auth/bootstrap.rs`, `claim_remote.rs`) | `SetupViewModel`, `NodeSwitcherViewModel` |
| Contacts / chat (person-to-person, **node chat — not the brain's `/v1/chat/completions`**) | `GET/POST /v1/contacts`, `POST /v1/chat`, `GET/POST /v1/chat/{community_id}/messages` | 4243 (`contacts_chat.rs`) | `ContactsScreen`, chat room screens — see §6 |
| Safety | `/v1/safety/{moderation,watchlist,age-assurance}` | 4243 (`safety/*.rs`) | `SafetyViewModel`, `ModerationScreen` |

**Stays on 8080 (brain):** `/v1/memory/*` (loop-written), `/v1/system/{llm,adapters,
runtime,fabric}`, `/v1/chat/completions`, reasoning-stream, `/v1/users`,
`/v1/wallet/*`, skills, telemetry/logs (agent half).

---

## 5. Phased migration plan (each phase independently shippable)

Ordered low-risk-first. The wheel boundary is **sharp** where the agent already
imports `ciris_persist`/`ciris_verify`/`ciris_edge` (those flip to `ciris_server`
mechanically); it is **leaky** at the Python-adapter mount (Gap #2) and at any
free `#[pyfunction]` not re-hosted (Gap #1). Verification per phase below.

**Phase 0 — Single-wheel swap (no behavior change).**
Replace the agent's standalone `ciris_persist` / `ciris_edge` / `ciris_verify`
wheels with the one `ciris-server` wheel; flip the import sites
(`graph.py:30`, `db/core.py:931`, `chain_bridge.py:201`, `tree_verify.py:156`,
`edge_runtime.py:79`) from `ciris_persist`→`ciris_server`. *Verify:* agent boots,
existing test suite green, one PyO3 type registry (no CIRISPersist#109).
*Load-bearing:* this is the cut `stage7` checks ("agent adoption evidence").

**Phase 1 — Delete persistence + audit + secrets (storage layer).**
Remove `logic/persistence/` (8.4k), `logic/audit/` (1.3k), `logic/secrets/`
(2.0k); route all graph/audit/keystore through the wheel `Engine` + keyring.
*Verify:* memory read/write through `/v1/memory/*`; audit chain verifies via
verify; no `secrets.db` created. *Risk:* db/core.py's iOS-compat + query-builder
shims — confirm persist Engine DX covers every call site before deleting.

**Phase 2 — Delete config + env-var handling (config-as-CEG).**
Remove `logic/config/` (0.8k) + every `os.environ`/`getenv`; the node resolves
all config from signed `config:*` CEG. *Verify:* agent boots with **zero env
vars** set (only `--home`/`--key-id`). *Risk:* find every stray getenv (LLM keys
included — those become brain config, not fabric env).

**Phase 3 — Delete auth + identity + federation + accord.**
Remove `services/governance/` (9.2k), `services/infrastructure/authentication/`,
`routes/{auth,setup,federation}` (8k+), `logic/accord/` (1.5k),
`ciris_adapters/cirisnode/` (2.2k). All auth/identity/federation/accord traffic
goes to the node's 4243 surface. *Verify:* login, OAuth, claim, peering,
device-grant, accord kill-switch end-to-end against ciris-server; the disk halt
latch gates the agent too (`compose.rs::check_halt_gate`). *Risk:* the **biggest
deletion**; stage behind a feature flag, ship the auth cut alone first.

**Phase 4 — Collapse runtime to a brain adapter.**
Reduce `logic/runtime/` (11.6k) to a thin shim that boots
`ciris_server.main()` and mounts the cognitive loop on the Adapter seam.
*Verify:* node + brain run as one process; brain receives the shared `Engine`;
ctrl-c stops both. *Risk:* **the leaky seam (Gap #2)** — until a PyO3
adapter-registration hook lands, the brain runs alongside the node rather than
*inside* its router; acceptable interim, tracked.

**Phase 5 — UI split-port + adopt the superset client.**
Refactor `CIRISApiClient` to dual base URLs (4243 substrate / 8080 brain), adopt
CIRISServer's `client/` as the base (+6 surfaces), move the §4c reads to 4243.
*Verify:* client connects to a brain-less ciris-server (4243 only) and to the
full agent (both ports); the 6 new screens function.

**Phase 6 — Cut agent 2.9.x adoption → unblock Server 0.6.**
With the above green, the agent is `node + brain`. This is `stage8` (agent 2.9.7
+ registry present → cut 0.6). *Verify:* the release-gate suite
(`tests/release_gates.rs`) stage7/stage8 flip green.

---

## 6. Chat on the node — adopting 0.5.209 (added 2026-09-16)

Everything above is the June inventory. This section is the one the agent
team needs for the 0.5.207 → 0.5.209 train: **person-to-person chat is a node
surface on 4243**, distinct from the brain's `/v1/chat/completions` on 8080.
Floor for this section: **ciris-server 0.5.209 = persist v44.4.0 / edge
v24.2.0 / verify v15.1.0** (CIRISServer#596). Do not land on 0.5.205
(CIRISServer#586).

### 6a. The surface (five routes, five capability verbs)

| route | verb | the CEG object it moves |
|---|---|---|
| `GET /v1/contacts` | `ChatRead` | live `consent:replication:v1` grants whose scope covers `chat:` |
| `POST /v1/contacts` | `Peer` | one `consent:replication:v1` grant (emitted, or a narrower standing one widened) |
| `POST /v1/chat` | `ChatCreate` | a 2-member `Community` row, id **derived** as `chat:pair:v1:<sha256(lo ‖ "\n" ‖ hi)>` from the two sorted key_ids — both ends compute it, nobody mints it |
| `POST /v1/chat/{community_id}/messages` | `ChatAuthor` | a `chat:message:v1` attestation in the community cohort; the **body is a sealed blob** under the room's community DEK and the attestation carries only the pointer |
| `GET /v1/chat/{community_id}/messages` | `ChatRead` | the same rows read back, hamburger-folded |

A contact **is** a replication-consent grant covering `chat:`; un-contacting is
the ordinary CEG withdraw of that grant. There is no contacts table.

### 6b. Preconditions the agent must satisfy once

1. **Owner claimed** (`POST /v1/setup/root` or claim-remote) — every chat route
   is an owner door (`dgrant:` delegates need the verb; an announce-only
   delegate reaches none of them).
2. **Announced** (`POST /v1/federation/announce`, loopback-only). An
   un-announced node is P2P-only: its owner→node binding is not federation
   visible, so no peer can put it in a room's audience and every room row is
   withheld both ways. The chat ladder's `bound` stage names exactly this.
3. **Both sides contacts of each other** — the grant is what carries the
   message to the other side.

### 6c. What the node does for you (and what changed at 0.5.209)

- **The reader is provisioned by the node; the agent provisions nothing.** At
  every owner door the node ensures its owner has a *content-only identity
  occurrence* carrying content-KEM pubkeys (x25519 + ML-KEM-768). Since
  0.5.209 this runs through edge's `provision_engine_occurrence` on persist's
  content-KEM identity; a 0.5.207 row is migrated in place (CIRISServer#596 §1).
- **The node's own boot self-occurrence is admitted again.** persist v44.4.0
  requires the typed `asserted_at` to be millisecond-exact and to match the
  signed envelope; 0.5.209 stamps it that way. (Under 0.5.207/0.5.208 on this
  persist the row would have been refused every boot.)
- **Grants are per identity occurrence.** The DEK is wrapped for every active
  occurrence of every member; the send response carries `fully_readable` and
  `excluded_key_ids` so the sender knows who cannot read.
- **A transcript row is either `body` or `unopened_reason`, never `""`.** A body
  sealed to the contact stays shut on your node by design; `status` is
  `live | superseded | withdrawn | recanted` from the same hamburger the memory
  projection uses.
- **Delivery of traces** (unrelated to chat, same train): `ciris_server.delivery_receipt(agent_id_hash=…)`
  / `GET /v1/node/delivery-receipt` — the canonical's own signed answer to
  "did my newest trace arrive" (0.5.208, CIRISServer#369).

### 6c′. Consent is by humans — what 0.5.210 changes about the grant you already write

Your wizard is correct and always was: the human's "Send traces" opt-in is
what authors the `consent:replication` grant, replayed by the fold
(`author_federation_consent`) and, in-band, by the setup-complete path. What
was wrong sat in the server (CIRISServer#599): from 0.5.203 to 0.5.209 the
node **signed that grant with a machine key** (the node key on a split-key
home) and **read consent back under a different machine key** (the engine
key), so every desktop/Android node converged to zero consent peers and
shipped nothing while the canonical saw it root, get admitted, and go quiet.

**0.5.210** (floor for this section from here on):
- The grant is **signed by the owner's fedID** — the steward the owner-binding
  names — using the software seed the wizard minted. A node or agent key holds
  topology, never consent. Nothing changes in what you call.
- Machine-authored grants from earlier wheels are **re-signed by the owner** at
  boot and after your fold's author door; the old rows stay as legacy grantors.
- Every read (delivery reconcile, `delivery_status`, the analyze-stance probe,
  the canonical's scorer) resolves a machine key to its steward first.
  `delivery_status` now reports `consent_grantor_key_ids`.
- Your `stance='unspecified' … ship=MISSING` was the same mismatch on the
  stance read; it reads `granted` under 0.5.210.
- A **hardware-custodied owner** (no software seed on the node) is refused,
  not downgraded to a machine key; the 2-phase client-signed consent door is
  not wired yet.
- Requisites in flight: CIRISEdge#609 (edge's own per-plane send set must union
  the steward's grants; until then server's `set_peers` drives delivery and
  traces ship), CIRISPersist#857 (a split home's AGENT key has no CEG link to
  its host node, so capacity scoring of such agents waits on it).

### 6d. Not in this cut (tracked)

- Rooms are **pairs only**: no create/invite/revoke, roster check is exactly
  two — CIRISServer#594.
- **Text only**: `send_message` refuses any other content type; file sharing
  waits on edge's chunk-DAG store gate and the pull-on-attestation hook
  (CIRISEdge#601). A member who missed roster anti-entropy sees `unopened_reason`
  until that hook exists.
- The user-signer alias flip (edge v24.2.0 §4) is deferred to CIRISServer#597;
  production is unaffected.
- Client-signed (2-phase) consent for hardware-custodied owners — CIRISServer#599.

## Top 3 gaps where Rust does NOT yet fully cover Python (block clean deletion)

1. **Free-`#[pyfunction]` re-export is incomplete (the wheel is leaky here).**
   `lib.rs:438-475` documents that persist's `reset_engine` and edge's
   `init_edge_runtime` are **private upstream fns** and CANNOT be re-hosted from
   the ciris-server wheel — they need an upstream `pub fn register` (the
   lens-core pattern). Until then **the agent cannot mint an `Edge` from the one
   wheel** (`register_edge` notes "edge re-export is INCOMPLETE until upstream").
   *Blocks:* fully deleting `edge_runtime.py`'s construction path in Phase 4.
   *Upstream issues:* `CIRISPersist: pub fn register`, `CIRISEdge: pub fn
   register` (the two asks in `FSD/ONE_WHEEL_REEXPORT.md`).

2. **No PyO3 adapter-registration hook across the wheel boundary.**
   `adapter.rs` mirrors `BaseAdapterProtocol` for *Rust* adapters
   (`serve_with_adapter` takes a Rust `Adapter`). There is no exposed way for a
   *Python* brain object to satisfy the trait and fold its routes/lifecycle into
   the node's router. *Blocks:* the literal "mount the brain on the seam"
   (Phase 4) — interim, the brain runs as a sibling process/listener (8080)
   rather than inside the node. *Needs:* a `ciris_server.register_adapter(py_obj)`
   PyO3 surface.

3. **Cognition has no Rust home (by design) — but the boundary at telemetry /
   capacity / safety is only partially substrate.** Capacity scoring's substrate
   half (`scorer.rs` `n_eff`/`sustained_coherence`) is covered, but agent
   telemetry (`logic/telemetry/` 694) and the agent-specific halves of
   safety/audit surfaces still mix cognition + fabric. These must be split, not
   bulk-deleted; mis-slicing risks dropping agent-only incident capture.
   *Also note:* the `#247` user-key-derived migration is wire-changing for
   already-claimed pre-0.5.14 nodes (Cargo.toml history) — agent adoption on an
   existing node re-emits its owner-binding under the derived id on re-claim
   (the key itself is preserved via `seal_alias`), which the migration must
   account for.

---

## Executive headline

- **Dies:** ~**80–95k LOC** of Python — `services/graph` (14.7k), `runtime`
  (11.6k), `services/governance` (9.2k), `persistence` (8.4k),
  `services/infrastructure` (6.9k), `routes/setup` (7.2k), plus
  config/secrets/audit/accord/federation and the `cirisnode`+`ciris_verify`
  adapters (~10k). Env-var handling and the SQLite layer disappear entirely.
- **Survives (the brain):** `processors` (12.9k) + `dma` (6.6k) + `conscience`
  (1.9k) + `context` (3.5k) + `handlers` (2.3k) + LLM/tool services + templates
  ≈ **~30k LOC of core cognition**, plus the cognitive adapter connectors.
- **Assembly:** `pip install ciris-server`; `main.py` → `ciris_server.main()` +
  a brain adapter; `setup.py` ships only `ciris_brain`.
- **UI:** adopt CIRISServer's superset `client/` (+6 substrate screens); split
  `CIRISApiClient` from its single hardcoded port 4243 (`CIRISApiClient.kt:195,324`)
  into 4243-substrate / 8080-brain and move all node/federation/identity/trust/
  config/score reads to 4243.

---

*Worktree branch:* `worktree-agent-ac63c467131649881` (committed here, not pushed).
