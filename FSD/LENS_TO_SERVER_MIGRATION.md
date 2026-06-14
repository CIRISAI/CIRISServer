# CIRISLens → CIRISServer — production migration guide

> **Audience:** the bridge / ops cutting the deployed **CIRISLens** server over to a
> **CIRISServer** fabric node in production. CIRISLens (FastAPI + TimescaleDB +
> Grafana) is **retired**; its lens-*core* function is absorbed into the fabric
> node. `agent = fabric node + brain`; the lens server is the fabric node with
> only the **observation** slice live (Server 0.1, lens-only).
>
> Companion: [`MISSION.md`](../MISSION.md), [`FSD/SERVER_1.0_PLAN.md`](SERVER_1.0_PLAN.md).

## 0. TL;DR

1. Stand up `ciris-server` on the lens host (zero-setup; mode defaults to `server`).
2. **Carry the two existing identities over** so the node keeps the same federation
   address — the RNS transport `.rid` (adopted byte-identically) and the federation
   `ed25519.seed` (adopted + TPM-sealed). **No re-key.**
3. Point trace emitters at the node; point read clients at `GET /lens/api/v1/*`.
4. Verify (`/v1/identity` shows the same `key_id`; read endpoints 200; ingest lands).
5. Tear down Grafana / TimescaleDB / the Python ingest API / the OAuth admin.

## 1. What changes

| CIRISLens (retired) | CIRISServer (the fabric node) |
|---|---|
| Python FastAPI ingest (`POST /api/v1/accord/events`, dual `/lens` vs `/lens-api`) | **CEG `AccordEventsBatch` over Reticulum/HTTP** into the shared persist corpus |
| TimescaleDB | **persist** substrate (SQLite default; Postgres via `CIRIS_DB_URL`) |
| Grafana dashboards / Explore / OAuth admin UI | **gone** — replaced by the 7 frozen `GET /lens/api/v1/*` JSON endpoints (federation-signed) |
| Prometheus / Loki / Tempo / Mimir / MinIO sidecars | **gone** (standalone-ops only) |
| Identity exposed for `/api/v1/identity` only | unified `GET /v1/identity` (six-key `LocalIdentityAggregate`) |
| Software keys on disk | **TPM-sealed** transport identity + **TPM-sealed Ed25519** federation key (software-encrypted fallback) |

**Nothing of the lens *science* is lost** — the Coherence Ratchet, Capacity Score,
manifold conformity, and the detection-event corpus all run inside the node over
the shared substrate, queryable from any node.

## 2. Prerequisites

- A host with the substrate build deps (Linux: `libsqlite3-dev`, `libtss2-dev` —
  the family links the TPM backend on Linux). A TPM/SE is **optional**: with one,
  keys are hardware-sealed; without, they fall back to encrypted-software (the node
  still runs — `is_hardware_backed=false`).
- The lens host's existing identity files (from the CIRISLens deployment):
  - the Reticulum transport identity, e.g. `CIRISLENS_EDGE_IDENTITY_PATH`
    (`…/lens-edge.identity`, 64 raw bytes), and
  - the federation Ed25519 signing seed (32 raw bytes), if the deployment held one
    separately. (If CIRISLens only ever had the transport `.rid`, the node will
    generate a fresh federation Ed25519 key on first boot — that is a **new
    federation signing identity**; coordinate enrollment if so.)

## 3. Cutover steps

### 3.1 Install
```
pip install ciris-server        # the abi3 wheel, or use the ciris-server binary
```

### 3.2 Place the identities (continuity — do this BEFORE first boot)
```
export CIRIS_HOME=/var/lib/ciris-server          # data + identity root
mkdir -p "$CIRIS_HOME/identity"
# Federation signing seed → adopted + TPM-sealed on first boot, byte-identical
cp /var/lib/cirislens/keyring/ed25519.seed "$CIRIS_HOME/identity/ed25519.seed"
# RNS transport identity → adopted into the keystore byte-identically (dest hash preserved)
export CIRIS_SERVER_RET_IDENTITY_PATH=/var/lib/cirislens/keyring/lens-edge.identity
```
On first boot the node:
- **adopts** `ed25519.seed` via `get_platform_ed25519_signer` → the **same** 32-byte
  Ed25519 pubkey ⇒ the **same `key_id`**, now custodied in the TPM (the original
  seed file remains the adoption source);
- **adopts** the `.rid` into `BlobTransportKeystore` → the **same Reticulum
  destination hash**, now TPM-sealed; the original is archived to
  `*.migrated-<ts>`.

So peers that already address this node keep reaching it; verifiers keep trusting
its `key_id`. **No re-enrollment, no re-key.**

### 3.3 Configure + start
```
export CIRIS_SERVER_LISTEN_ADDR=0.0.0.0:4242      # primary Reticulum port (read API = +1 = 4243)
# export CIRIS_DB_URL=postgresql://…              # optional; default is a local SQLite corpus
# export CIRIS_SERVER_LENS_STORE_MIN_GIB=5        # below this free disk → relay-only (no local corpus)
ciris-server
```
Defaults that need no setup: `mode=server`, data at `$CIRIS_HOME/data`, SQLite
corpus, identity minted/adopted on first boot, trusts `ciris-canonical` (a
replaceable default pin).

### 3.4 Re-point traffic
- **Ingest**: trace emitters send CEG `AccordEventsBatch` to the node (Reticulum
  dest hash, or the HTTP relay on `listen+1`). They stop POSTing to the old Python
  ingest API.
- **Reads** (the bridge's main job): clients/dashboards that hit Grafana or the old
  `/api/v1/...` move to the **frozen** `GET /lens/api/v1/*` endpoints, with the
  federation-signed request headers (`X-Lens-Signing-Key-Id` / `-Signature` /
  `-Signed-At`):
  ```
  GET /lens/api/v1/scores            GET /lens/api/v1/scores/{trace_id}
  GET /lens/api/v1/detection_events  GET /lens/api/v1/detection_events/{detection_id}
  GET /lens/api/v1/manifold_conformity_aggregate
  GET /lens/api/v1/calibration_bundles  GET /lens/api/v1/calibration_bundles/{version}
  ```
  If the bridge fronted the old Grafana/API, re-point it at these. There is **no
  interactive dashboard** — consumers render their own viz over the JSON, or use
  the agent's KMP client.

### 3.5 Corpus
The corpus **starts fresh** on the persist substrate. The legacy TimescaleDB
history is **not migrated** (the post-cutover dedup keys differ; pre-cutover quality
is the legacy pipeline's). Keep the old TimescaleDB **read-only** for archival as
long as you need it, then decommission.

## 4. Verify (before tearing anything down)
- `GET /v1/identity` returns the six-key `LocalIdentityAggregate` with the **same
  `key_id`** the CIRISLens node published (identity continuity confirmed).
- Boot log shows `transport-identity keystore opened hardware_backed=true` (TPM
  host) and, for the federation key, the keyring reports a sealed-Ed25519 / hardware
  posture (not `NO HARDWARE BINDING`) — or encrypted-software fallback on a
  no-TPM host.
- `curl` each `GET /lens/api/v1/*` → `200`.
- Send a test trace; confirm it lands (`/lens/api/v1/scores` non-empty).

## 5. Decommission CIRISLens
After the verification window, tear down: Grafana, TimescaleDB, the FastAPI ingest
service, the OAuth admin UI, and the prod telemetry sidecars
(Prometheus/Loki/Tempo/Mimir/MinIO). Archive the `*.migrated-<ts>` identity files
and the read-only TimescaleDB per your retention policy.

## 6. Rollback
The cutover is reversible until decommission: the old deployment runs read-only
alongside the node during the window. If the node misbehaves, re-point emitters/read
clients back to CIRISLens (its identity files are unchanged — the node *adopted*
copies). Investigate, then re-cut.

## 7. Notes for the bridge
- The lens host becomes one of the `ciris-canonical` fabric nodes (or a standalone
  observation node) — same composition, just headless.
- The **admin-UI capability** (agent/manager/telemetry management under
  `/cirislens/admin/`) has **no fabric-node equivalent** in the read-only surface —
  if any operator flow depended on it, raise it as a CIRISServer ticket; it is not
  ported by default.
- This guide covers **0.1 (lens-only)**. Registry (0.5) and node (1.0) slices fold
  into the same node later; they don't change the lens cutover.
