# Bridge upgrade — ciris-server `0.3.0` → `v0.4.9`

> **Audience:** the bridge / ops upgrading the deployed lens node (and, optionally,
> the status node) to the v0.4.9 family floor. This is the **2.9.7 fold** release.
> **Identity is preserved — no re-key.** Companion: [`LENS_TO_SERVER_MIGRATION.md`](LENS_TO_SERVER_MIGRATION.md).

## 0. TL;DR

1. **Back up** the corpus DB + the identity files (`*.rid`, `ed25519.seed`).
2. Install **`ciris-server==0.4.9`** (wheel) or drop the `x86_64-unknown-linux-gnu` binary.
3. Keep the **same `CIRIS_HOME` / identity dir** → same `key_id` + RNS dest (no re-key).
4. Add the **Caddy HTTP-ingest route** (the trace 404 fix).
5. Start, **verify** (`/v1/identity` 200 same `key_id`; ingest accepts a hybrid batch; transport-node + SAF up).
6. **Expect trace `401` until the agent ships the 2.9.7 fold** (hybrid signing rides in the lenscore→ciris-server swap — see §6). This is correct, not a regression.

## 1. What changes `0.3.0` → `v0.4.9`

| Area | 0.3.0 (deployed) | v0.4.9 |
|---|---|---|
| Family floor | persist 7.x / verify 5.x / edge 3.x | **persist v9.0.3 + verify v6.2.0 + edge v5.0.1** (ciris-server ≥ v0.4.11; v9.0.3/v5.0.1 are wheel-metadata fixes over v9.0.2/v5.0.0) |
| Trace ingest | **read-only — POST 404s** | **HTTP relay ingest** (`POST /lens-api/api/v1/accord/events`) + Reticulum relay |
| Trace wire | Ed25519 / Python-compat | **JCS hybrid** (`3.0.0` / RFC 8785, Ed25519 + ML-DSA-65) — hard cut |
| NAT traversal | none | **Transport-node + store-and-forward** (default on) |
| Identity / ownership | — | YubiKey fed-ID mint, NodeCode + PIN claim, CC owner-binding |
| Safety | — | `src/safety/*` — age-gate, moderation duty, named-moderator, watchlist |

## 2. Pre-flight (do NOT skip)

```sh
# Back up the corpus + identity (identity carries over byte-identically — but back up anyway)
cp -a "$CIRIS_HOME"/data        "$CIRIS_HOME"/data.bak.0.3.0          # SQLite corpus (or pg_dump if Postgres)
cp -a "$CIRIS_HOME"/identity    "$CIRIS_HOME"/identity.bak.0.3.0      # *.rid + ed25519.seed (the federation address)
ciris-server --version 2>/dev/null || true                            # record the current version for rollback
```
Identity continuity: v0.4.9 adopts the existing `*.rid` (RNS transport) + `ed25519.seed` (federation signing, TPM-sealed on adoption) **byte-identically** — the node keeps the **same `key_id` and RNS destination hash**. No re-key, no re-announce churn.

## 3. Install v0.4.9

```sh
# Option A — wheel (the agent/most deploys)
pip install --upgrade "ciris-server==0.4.9"

# Option B — release binary (headless host)
#   download ciris-server-x86_64-unknown-linux-gnu from the v0.4.9 GitHub release, chmod +x, place on PATH
```
(armv7 + aarch64-musl wheels are not published — known, non-blocking; use x86_64/aarch64-gnu or the binary.)

## 4. Environment

Keep the existing values; the new toggles default correctly for a public fabric node.

```sh
CIRIS_HOME=/opt/ciris                       # unchanged → same data/ + identity/ → same key_id (no re-key)
CIRIS_SERVER_LISTEN_ADDR=0.0.0.0:4242       # Reticulum node port (public warm-link target). read API = listen+1 = :4243
CIRIS_SERVER_MODE=server                    # default
# NAT-traversal (NEW, default ON for a public node — leave on):
CIRIS_SERVER_TRANSPORT_NODE=1               # forward inbound for NAT'd/mobile edges (Reticulum Transport node)
CIRIS_SERVER_STORE_AND_FORWARD=1            # store-and-forward for asleep edges (SAF)
# Identity dirs (defaults are $CIRIS_HOME/{data,identity}); RET identity:
CIRIS_SERVER_RET_IDENTITY_PATH=$CIRIS_HOME/identity/<the-existing>.rid
# Feed the status node — OPTIONAL BOOTSTRAP ONLY (v0.4.12+): replication is now
# CONSENT-DRIVEN. The owner creates a `consent:replication` object (via the desktop
# client / `POST /v1/federation/peering`) and the node's reconcile loop converges
# the live replication runtime to it. `CIRIS_PEER_B_*` is now just a convenience
# that WRITES THAT SAME consent object at boot — it is no longer the mechanism.
CIRIS_PEER_B_KEY_ID=<status node's key_id>
CIRIS_PEER_B_KEY_RECORD=<status node's self-signed SignedKeyRecord JSON>
# Reconcile cadence for the CEG-driven replication reconciler (default 30s). The
# loop also fires immediately on a peering write (Notify nudge), so this is just
# the steady-state convergence interval.
CIRIS_SERVER_REPLICATION_RECONCILE_SECS=30
```

> ### Replication is consent-driven (v0.4.12 — CEG-driven reconciler)
> The corpus's `consent:replication` objects ARE the desired replication topology.
> The API (`POST /v1/federation/peering`) only ever **writes CEG** (admits the peer
> key + emits this node's directed `consent:replication:v1` grant); a **reconcile
> loop** converges the live `ReplicationRuntime` to the consent objects. The owner
> sets up peering on demand from the desktop client / the peering endpoint —
> `CIRIS_PEER_B_*` is now an **optional boot bootstrap** that just writes a consent
> object so the env path flows through the same reconcile path as an owner-authored
> grant. **Honest interim note (edge v5.0.1):** a consent created at runtime
> registers the peer for **inbound** immediately, but the node begins **active pull
> only after the next restart** (boot re-derives the Initiator set from CEG), until
> the runtime Initiator-add lands — **CIRISEdge#173**.
**Corpus:** there is **no `CIRIS_DB_URL`/DSN env** — ciris-server always uses a SQLite corpus at `$CIRIS_HOME/data/ciris_engine.db` (override only the *directory* via `CIRIS_SERVER_DATA_DIR`). (Postgres is compiled in but not env-selectable; the migration lands on the SQLite corpus.)
The read API on **`:4243`** serves: `GET /v1/identity`, `GET /lens/api/v1/*` (the 7 frozen reads), `GET /v1/federation/node-code`, `POST /lens-api/api/v1/accord/events` (ingest), `/v1/safety/*`, `/v1/setup/*`.

## 5. Caddy — the HTTP trace-ingest route (the 404 fix)

The emitter's legacy POST path now lands directly on the node — **no path rewrite**:

```caddy
# bridge Caddyfile — route the legacy trace POST to the v0.4.9 read API
reverse_proxy /lens-api/api/v1/accord/events ciris-server:4243
# (existing reads stay as-is)
reverse_proxy /lens/api/v1/*   ciris-server:4243
reverse_proxy /v1/identity     ciris-server:4243
```
Canonical alias for new emitters: `POST /v1/ingest/accord-events`.

## 6. ⚠ Expected: traces `401` until the agent fold ships (NOT a regression)

persist v9.x is a **hybrid hard-cut** — it rejects classical-only Ed25519 traces (`verify_hybrid_required` / `verify_hybrid_failed` → HTTP `401`). The **deployed `CIRIS-AccordMetrics` emitter signs classical-only**, so right after the upgrade:

- the 404s become **`401`s** (good — the request now reaches the node; it's the signature tier that's rejecting), and
- traces resume persisting the moment the agent runs the **2.9.7 fold** (`pip install ciris-server==0.4.9`, swap `from ciris_lens_core import …` → `from ciris_server import …`). **lenscore is what signs traces**, so the swap upgrades the emitter to **JCS-hybrid 3.0.0** by construction — no separate emitter patch.

So: upgrade the node now (unblocks the path); the agent fold (same release) completes signing. A `401` window before the agent fold is correct.

## 7. Verify

```sh
# identity continuity — SAME key_id as 0.3.0:
curl -s http://127.0.0.1:4243/v1/identity | jq .signer_key_id
# read endpoints answer:
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4243/lens/api/v1/scores      # 200
# the node's public bootstrap handle:
curl -s http://127.0.0.1:4243/v1/federation/node-code | jq .code                       # CIRIS-V2-...
# ingest is live (a hybrid-signed batch → 200; a classical-only one → 401, as in §6):
#   tail the logs for "read API up", "transport_node=true", store-and-forward enabled, and
#   (on a fresh/unclaimed node) the "OWNERSHIP UNCLAIMED" banner with the NodeCode + one-time claim PIN.
```
Reticulum: `:4242` bound (UDP+TCP); `transport_node=true` + SAF in the boot log.

## 8. Ownership (founder, separate step)

On a fresh/unclaimed node the boot log prints **OWNERSHIP UNCLAIMED** with the NodeCode + a one-time **claim PIN** (console/log only). The founder claims it from the app/CLI (mint a YubiKey fed-ID, then NodeCode + PIN → `/v1/setup/claim-remote`). The PIN is **never** served over HTTP. An upgraded node that already carried an owner-bound identity stays owned.

## 9. Rollback

```sh
pip install "ciris-server==0.3.0"            # or restore the 0.3.0 binary
# identity files are untouched (no re-key) — restore data.bak only if the corpus migration must be reverted
# remove the Caddy ingest route line; the node returns to read-only
```
The v0.4.9 corpus is forward-compatible reads; a downgrade loses ingest + the new surfaces but keeps identity.

## 10. (Optional) status node — now `ciris-server` + a `StatusAdapter`

The status node (B) is **no longer a parallel implementation**. As of CIRISStatus **v0.2.0** it *is* a `ciris-server` node plus a thin `StatusAdapter` (mirroring CIRISAgent's adapter model: the agent = `ciris-server` + brain; the status node = `ciris-server` + status adapter). All the fabric — engine, edge, **consent:replication**, NodeCode, ownership, safety, NAT-traversal — comes from `ciris-server`'s `serve_with_adapter()`; the adapter only adds the status page (the uptime probes, the Flow-A roster, `/api/v1/scoring`, the live SSE/WS) and emits `health:liveness:v1`.

Consequences for the upgrade:
- **Same family floor** as the lens node (persist v9.0.3 / edge v5.0.1 / verify v6.2.0). Deploy the image **`ghcr.io/cirisai/cirisstatus:v0.2.3`** (multi-arch; `:latest` tracks it).
- **Config is now `ciris-server`'s** (`ciris_server::ServerConfig::from_env()`). The **old `STATUS_*` env is gone** (`STATUS_CORPUS_DSN`, `STATUS_NODE_*`, `STATUS_PEER_A_*`, `STATUS_REPLICATION_*`, `--features fabric`). The adapter keeps only probe-targets / poll-cadence / CORS env.

> ### ⚠ The status node has its OWN corpus — never point it at the lens node's DB
> This is the regression to avoid (the old "Node B reads Node A's DSN" model). There is **no DSN/`CIRIS_DB_URL` env**: ciris-server always writes a SQLite corpus at `$CIRIS_HOME/data/ciris_engine.db`. So the status node's corpus is simply its **own** `CIRIS_HOME` (its own container volume) — **distinct from the lens node's**. Do **not** share `CIRIS_HOME`/`CIRIS_SERVER_DATA_DIR`, and do **not** bind-mount the lens node's `data/` into the status node. Node A's `capacity:*` arrives **only** via consent:replication (below), into B's own DB. The roster is empty until replication delivers — expected, not a misconfig.

Status-node env:
```sh
CIRIS_HOME=/opt/ciris-status                 # the status node's OWN home/volume (NOT the lens node's)
CIRIS_SERVER_LISTEN_ADDR=0.0.0.0:4242        # its own Reticulum node; read API (the status page) = :4243
CIRIS_SERVER_KEY_ID=ciris-status             # its own federation key_id
# Reach + replicate-with the lens node (Node A) over Reticulum — directed consent:replication:
CIRIS_SERVER_BOOTSTRAP_PEERS=<lens-node-host>:4242   # find A on the mesh
CIRIS_PEER_B_KEY_ID=<lens node A's key_id>           # the peer = A
CIRIS_PEER_B_KEY_RECORD=<A's self-signed SignedKeyRecord JSON>
```
(The peer slot is named `CIRIS_PEER_B_*` on both sides — it means "the one peer." On A it points at the status node; on the status node it points at A. As of v0.4.12 this env is an **optional bootstrap**: each side just WRITES its own directed `consent:replication` grant from it at boot, and the **CEG-driven reconcile loop** converges the live runtime to those consent objects. Equivalently, the owner authors the grant on demand via `POST /v1/federation/peering` from the desktop client — same consent object, no env needed. Replication then rides Reticulum; per **CIRISEdge#173**, a runtime-created consent is inbound-active immediately but pull-active after the next restart on edge v5.0.1.)

- The status page is served from the node's **read API listener (`:4243`)** — the adapter's routers merge there. Point the status reverse-proxy at `:4243`.
- Identity continuity: if the status node already had a federation identity, keep its `CIRIS_HOME`/identity → same `key_id` (no re-key, and A's `CIRIS_PEER_B_*` keeps matching).
- See `CIRISStatus/DEPLOY.md` for the full deploy (docker-compose + the `SignedKeyRecord` exchange).
