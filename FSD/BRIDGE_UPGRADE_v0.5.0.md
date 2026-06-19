# Bridge upgrade — ciris-server `0.4.x` → `v0.5.0` (ZERO-ENV)

> **Audience:** the bridge / ops upgrading the lens node and the status node to
> **Server 0.5 — config-as-CEG, zero env vars**. This SUPERSEDES the env-based
> [`BRIDGE_UPGRADE_v0.4.9.md`](BRIDGE_UPGRADE_v0.4.9.md) for the config/boot model.
> **Identity is preserved — no re-key.**

## 0. TL;DR — what's breaking
**There are NO config environment variables any more.** A node boots from two CLI
flags and resolves everything else from signed `config:*` / consent **CEG objects
in its own corpus**, authored by the owner at runtime.

```sh
# was: a pile of CIRIS_* env vars
# now:
ciris-server --home /opt/ciris --key-id ciris-server
```
1. **Back up** the corpus + identity.
2. Point `--home` at the **existing** data/identity dir, pass `--key-id` = the node's
   **existing** key_id → same identity, no re-key.
3. **Drop every `CIRIS_*` / `AGENT_*` / `OAUTH_*` env var** — they are no longer read.
4. Defaults apply on boot; **author any non-default config + peering as CEG** after
   claiming ownership (NodeCode + PIN).
5. Keep the Caddy trace-ingest route; expect the `401`-until-agent-fold window (§6).

## 1. What changes `0.4.x` → `v0.5.0`

| Area | 0.4.x | v0.5.0 |
|---|---|---|
| Config source | `CIRIS_*` env vars | **signed `config:*` CEG objects** (owner-authored, runtime-reconciled, replicated) |
| Boot inputs | env | **`--home <dir>` + `--key-id <name>`** (the only inputs) |
| `LISTEN_ADDR`/`TRANSPORT_NODE`/`SCORER_*`/`MODE`/reconcile/ACL/OAuth | env | `config:*` keys (`net.listen_addr`, `transport.node`, `scorer.*`, `mode`, `replication.reconcile_secs`, `auth.admin_key_ids`, `auth.oauth_callback_base_url`, …), baked defaults |
| `ROOT_*` / `USER_*` env | pre-seed env | **gone** — fresh node trusts ciris-canonical + the founder claims via NodeCode+PIN; user identity via `identity create` |
| Mesh entry | `CIRIS_SERVER_BOOTSTRAP_PEERS` env | baked `CANONICAL_BOOTSTRAP_PEERS` + `net.bootstrap_peers` config:* |
| Replication | consent-driven (v0.4.12+), no-restart (v0.4.13/edge v5.1.0) | unchanged |

## 2. Pre-flight (do NOT skip)
```sh
cp -a "$OLD_CIRIS_HOME"/data     "$OLD_CIRIS_HOME"/data.bak.0.4.x      # SQLite corpus
cp -a "$OLD_CIRIS_HOME"/identity "$OLD_CIRIS_HOME"/identity.bak.0.4.x  # *.rid + ed25519.seed
```
**Record the node's existing `key_id`** (the old `CIRIS_SERVER_KEY_ID`, e.g. `ciris-server`
for the lens node, `ciris-status` for the status node) — you pass it as `--key-id` so the
identity + federation key_id carry over byte-identically. Mismatching it re-labels the key.

## 3. Install v0.5.0
```sh
pip install --upgrade "ciris-server==0.5.0"      # wheel (the agent fold; launches via ciris_server.run(home,key_id))
#   or drop the x86_64-unknown-linux-gnu binary from the v0.5.0 GitHub release on PATH
```

## 4. Boot — two CLI flags, zero env
```sh
# Lens node A — point --home at the EXISTING data/identity dir; pass the EXISTING key_id.
ciris-server --home /opt/ciris --key-id ciris-server
```
- `--home` (default `/var/lib/ciris`): `data_dir=<home>/data`, `identity_dir=<home>/identity`,
  corpus `<data_dir>/ciris_engine.db`, RET identity + `ed25519.seed` under `<home>/identity`.
  Adopted byte-identically → **same key_id + RNS dest, no re-key**.
- `--key-id` (default `ciris-server`): the federation key label. Pass the node's existing one.
- **Unset all `CIRIS_*`/`AGENT_*`/`OAUTH_*` env** — ignored now; remove them so nobody is misled.

> **Migrating old env overrides → config:* (after ownership, §7).** If 0.4.x set a
> non-default `CIRIS_SERVER_LISTEN_ADDR`, `CIRIS_SERVER_TRANSPORT_NODE`, any
> `CIRIS_SERVER_SCORER_*`, `OAUTH_CALLBACK_BASE_URL`, `CIRIS_ADMIN_KEY_IDS`, etc.,
> re-author each as a `config:*` object once the node is owned. If you were on
> defaults, do nothing — the baked defaults match.

## 5. Caddy — the HTTP trace-ingest route (unchanged from 0.4.9)
```caddy
reverse_proxy /lens-api/api/v1/accord/events ciris-server:4243   # the 404 fix (no path rewrite)
reverse_proxy /lens/api/v1/*   ciris-server:4243
reverse_proxy /v1/identity     ciris-server:4243
```
Read API binds `net.listen_addr` + 1 (default `:4243`).

## 6. ⚠ Expected: traces `401` until the agent fold (NOT a regression)
persist v9.x is a hybrid hard-cut; the deployed classical-only emitter's 404s become
`401`s until the agent ships the 2.9.7 fold (`pip install ciris-server`, swap the lens
imports), which upgrades the emitter to JCS-hybrid by construction. Same as 0.4.9 §6.

## 7. Ownership + config (the CEG authoring step — replaces env)
1. **Claim ownership.** Fresh/unclaimed boot prints **OWNERSHIP UNCLAIMED** + a NodeCode
   and a one-time **claim PIN** (console/log only, never over HTTP). The founder claims
   from the desktop client (mint a YubiKey fed-ID, then NodeCode + PIN → `POST /v1/setup/root`).
   An already-owned node stays owned across the upgrade.
2. **Author non-default config** (owner-gated `POST /v1/config`, or the client):
   ```sh
   curl -X POST https://<node>/v1/config -d '{"key":"net.listen_addr","value":"0.0.0.0:4242"}'
   curl -X POST https://<node>/v1/config -d '{"key":"scorer.cadence_secs","value":300}'
   ```
   Changes converge live (the config reconciler); boot-structural keys (`net.*`,
   `transport.*`, `mode`) apply on next boot.
3. **Author replication** (consent-driven, no-restart): `POST /v1/federation/peering`
   (or the client) naming the peer → the reconciler converges the live runtime.

## 8. Verify
```sh
curl -s http://127.0.0.1:4243/v1/identity | jq .signer_key_id            # SAME key_id as 0.4.x
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4243/lens/api/v1/scores   # 200
curl -s http://127.0.0.1:4243/v1/federation/node-code | jq .code          # CIRIS-V2-...
# boot log: "resolved initial config:* snapshot", transport/SAF, read API up,
# and (fresh node) OWNERSHIP UNCLAIMED + NodeCode + claim PIN.
```

## 9. Status node B — `ciris-status v0.3.0` (also zero-env)
```yaml
# docker-compose.yml
command: ["--home", "/data", "--key-id", "ciris-status"]   # the ONLY inputs; no environment: block
volumes: [ "status-data:/data" ]                            # its OWN corpus — never mount the lens node's data/
```
- Deploy `ghcr.io/cirisai/cirisstatus:v0.3.0`. Claim ownership, then author the adapter
  config:* (`status.poll_secs`, `status.region.*`, `status.cors_origins`, …) + the
  `consent:replication` peer (Node A) via `POST /v1/config` / `POST /v1/federation/peering`.
- A's `capacity:*` flows into B's own corpus by consent:replication; roster empty until it delivers.

## 10. Rollback
```sh
pip install "ciris-server==0.4.15"   # the last env-based release; restore the *.bak data if needed
# re-add the CIRIS_* env vars the 0.4.x deploy used
```
Identity files are untouched (no re-key) either way.

## 11. ⚠ Operator action — canonical mesh peers
`CANONICAL_BOOTSTRAP_PEERS` (src/config_reconcile.rs) ships **empty**. For a canonical
deploy, either fill it with the canonical CIRIS Reticulum entry `host:port` addresses
(code) or author `net.bootstrap_peers` as a `config:*` object per node. Until then,
cross-host nodes rely on Reticulum announce discovery over a shared interface.
