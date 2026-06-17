# CIRISServer fabric app (KMP)

The mesh/fabric half of **CIRISServer#15**: _"agent app = fabric app
(CIRISServer) + agent cards"_. CIRISServer ships the complete mesh/fabric KMP
client; the agent reasoning/persona **cards** stay in CIRISAgent.

## Why `app/` (the home choice)

The KMP client was copied here as a **standalone Gradle build** under a new
top-level `app/` directory, with its own `settings.gradle.kts` / wrapper, so it
does **not** couple to the Rust/Cargo workspace at the repo root. `cargo build`
at the root is untouched; open `app/` in an IDE / run `./app/gradlew` to build
the client. (`client/` was avoided as a name to prevent confusion with the
Rust `crates/` and because the agent repo already uses `client/` for the source
module — keeping the names distinct avoids cross-repo muscle-memory mistakes.)

The source CIRISAgent module (`client/shared`, 298 Kotlin files) is a monolith
entangled with agent surfaces (chat, runtime, cognitive-state, billing). Copying
it wholesale would drag in the agent cards. Instead, `fabric-client` is a fresh,
**minimal** module that copies only the fabric model/client/screen files,
repackaged `ai.ciris.mobile.shared.*` → `ai.ciris.fabric.*`, and repointed at
CIRISServer's real endpoints + auth.

## The split (fabric COPY vs agent cards STAY)

**Copied (fabric/mesh):** identity (`/v1/identity` six-key aggregate),
federation-directory reads, content fetch, replication/health metrics, peer
trust toggles, trust-graph data, NodeCode QR peer-bootstrap, CEG-native erasure,
and the governance/safety endpoint map (child-safety, takedown, accord/WBD/PDMA
transparency, groups+voting).

**NOT copied (agent cards — need a brain):** PDMA reasoning views, persona /
identity-of-the-agent UI, chat/Interact, runtime control + cognitive-state
transitions, billing/wallet, setup wizard, LLM settings, adapters/services,
telemetry, skill studio, scheduler, audit/users/sessions. These live in
CIRISAgent's `client/shared`.

## What is PROVEN vs SCAFFOLDED

**PROVEN (compiles + tested against the real wire shape):**
- `model/identity/LocalIdentityAggregate.kt` — matches persist v8.4.0
  `LocalIdentityAggregate` field-for-field (the body `compose.rs` serves).
- `net/FabricClient.getIdentity()` → `GET /v1/identity`.
- `auth/FederationSigner` — the `x-ciris-*` body-signed header contract
  (replaces the agent client's Bearer auth).
- `viewmodel/IdentityViewModel` + `ui/screens/IdentityScreen`.
- `commonTest/IdentitySliceTest` — decodes the exact persist JSON fixture
  (full six-key + minimal relay node).

**SCAFFOLDED (models + UI flow + wiring TODOs; network round-trip pending the
substrate slice that exposes the endpoint):**
- CEG-native erasure: `model/federation/Erasure.kt`, `ErasureViewModel`,
  `ui/screens/ErasureScreen.kt`, `FabricClient.withdrawContent()` (TODO POST).
- Federation directory / peers / trust / content / metrics / NodeCode models in
  `model/federation/`.
- The full endpoint map in `net/FabricEndpoints.kt`.

## Wiring map for the remaining surfaces

CIRISServer's HTTP listener today serves only `GET /v1/identity` +
`GET /lens/api/v1/*` (see `src/compose.rs` + `crates/ciris-lens-core/src/role/
node.rs`). The federation/governance endpoints land as two substrate slices that
are currently `todo!()` in `compose.rs`:

| Surface | Endpoint(s) | Lands with |
|---|---|---|
| Federation directory, peer trust toggles, trust-graph, NodeCode, content, metrics | `/v1/federation/*`, `/v1/system/peers/*` | **registry slice — Server 0.5** (`compose_registry`, CIRISRegistry#76) |
| Canonical groups + voting, Wise-Authority/WBD deferral routing, child-safety report→surface→act, takedown, accord/PDMA transparency | `/v1/groups/*`, `/v1/wa/*`, `/v1/safety/*`, `/v1/transparency` | **node slice — Server 1.0** (`compose_node`, CIRISNodeCore#38) |
| CEG-native erasure (signed `withdraws`) | `POST /v1/erasure/withdraw` | node slice (§19.7 hard-delete) |

For each scaffolded `FabricClient` method the wiring is the same recipe:
1. build the request body (empty for GETs, JSON for writes);
2. `signer.signHeaders(bodyBytes)` — **body**-signed `x-ciris-*` headers;
3. issue the request with those headers;
4. decode the typed model from `model/federation/`.

The auth repoint (Bearer → federation-signed, empty-body GET rule) is the one
load-bearing difference from the CIRISAgent client and is already correct in
`auth/FederationSigner.kt` + `net/FabricClient.signedGet()`.

## Build

```
cd app && ./gradlew :fabric-client:compileKotlinDesktop   # or allTests
```

Targets: commonMain + android (lib) + desktop (JVM) + iOS + wasmJs, matching the
source module's KMP target set.
