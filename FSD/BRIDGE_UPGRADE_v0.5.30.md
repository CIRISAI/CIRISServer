# Bridge upgrade — ciris-server `0.5.x` → `v0.5.30`

> **Audience:** the bridge / ops bringing **Node A (lens)** and **Node B (status)**
> up to **ciris-server 0.5.30** — the cut that completes the HUMANITY_ACCORD
> safe-mesh floor. **The boot model is UNCHANGED from
> [`v0.5.0`](BRIDGE_UPGRADE_v0.5.0.md): zero env, `--home` + `--key-id` only.
> Identity is preserved — no re-key. The corpus auto-migrates on first boot.**

## 0. TL;DR — there is NO migration script to run
The substrate jumped a long way (persist `9.0.3 → 9.10.0`, verify `6.2.0 → 6.11.0`,
edge `5.1.0 → 6.3.0`), but persist **builds + migrates the SQLite corpus
automatically on `Engine` open**. No env changed, no new CLI input. The upgrade is:

```sh
# Node A (lens): back up, upgrade the wheel, restart with the SAME flags.
pip install --upgrade "ciris-server==0.5.30"      # or drop the v0.5.30 release binary on PATH
ciris-server --home /opt/ciris --key-id ciris-canonical-trio-1   # the node's EXISTING key_id
```

```yaml
# Node B (status): rebuild the ciris-status image on ciris-server 0.5.30, redeploy.
command: ["--home", "/data", "--key-id", "ciris-status-1"]       # unchanged; its OWN volume
```

> ⚠ **ciris-server ships NO container image** — only PyPI wheels + GitHub-release
> binaries. **Node B's image is built in the CIRISStatus repo** with its
> `ciris-server` dependency pinned to `0.5.30`. Bumping Node B = a CIRISStatus
> release, not a `docker pull` of ciris-server.

## 1. What changed `0.5.0` → `0.5.30` (ops-relevant only)

| Area | Note |
|---|---|
| Boot model | **Unchanged** — `--home <dir> --key-id <name>`, zero env, baked defaults + `config:*` CEG. |
| Substrate | persist 9.0.3→9.10.0 / verify 6.2.0→6.11.0 / edge 5.1.0→6.3.0. **Corpus migrates automatically** on open — *back up first* (§2). |
| Node wire `key_id` | Derived `<label>-<fp>` since 0.5.1. The last PyPI release was **0.5.4**, which already derives — so a node coming from ≤0.5.4 sees **no key_id change**. (Identity files / RNS dest / seals are untouched regardless.) |
| Owner / USER binding (#247, 0.5.14) | The USER `key_id` moved to the FSD-003 derived `<alias>-user-<fp>`. **An already-owned node keeps serving unchanged** — the owner-binding re-emits under the derived id only on a *re-claim* or `POST /v1/self/upgrade-owner`. The key itself is **not re-keyed** (sealed under the stable keystore alias). **No action required to keep running.** |
| Halt gate (0.5.20) | Boot now **refuses to start while a `HUMANITY_ACCORD_HALT` latch exists** under `--home`. A normal node has none. If one is ever present, the conformant clear is `ciris-server accord reactivate --home <h> --proof <p.json>` — **not** `rm` (which is break-glass / non-conformant). |
| HUMANITY_ACCORD (#41) | **New** kill-switch surface. **Optional to run** — a node serves fine with no accord family entrenched; `GET /v1/accord-holders` simply reports `family_established:false`. The multi-party **genesis ceremony is a separate human op** and a **prerequisite for 0.6**, *not* for this upgrade (§8). |
| Holonomic swarm (#11) | Auto-activates when the node has the `lens_store` capability. No ops step. |
| Config-as-CEG / replication | **Unchanged** from 0.5.0 (owner-authored `config:*`, consent-driven peering, no-restart reconcilers). |

## 2. Pre-flight (do NOT skip — the corpus migrates forward)
```sh
cp -a "$CIRIS_HOME"/data     "$CIRIS_HOME"/data.bak.pre-0.5.30      # SQLite corpus
cp -a "$CIRIS_HOME"/identity "$CIRIS_HOME"/identity.bak.pre-0.5.30  # *.rid + ed25519.seed (+ sealed PQC)
```
Record the node's existing `--key-id` (e.g. `ciris-canonical-trio-1` for A,
`ciris-status-1` for B) — pass the **same** value so identity carries over.
The 9.10.0 migration is **forward-only**: a downgrade (§7) needs this backup.

## 3. Node A (lens) — upgrade + boot
```sh
pip install --upgrade "ciris-server==0.5.30"
ciris-server --home /opt/ciris --key-id ciris-canonical-trio-1
```
First boot applies the persist migration in place. Watch the log for the migration
line + `resolved initial config:* snapshot`, transport up, read API up. An
already-owned node stays owned; an unclaimed node prints `OWNERSHIP UNCLAIMED` +
NodeCode + claim PIN as before. **Drop any leftover `CIRIS_*`/`AGENT_*`/`OAUTH_*`
env** — still ignored, remove to avoid confusion.

## 4. Node B (status) — rebuild on 0.5.30
1. In **CIRISStatus**, pin `ciris-server == 0.5.30`, build + push the image to GHCR.
2. Redeploy with the unchanged command + its **own** volume (never the lens corpus):
   ```yaml
   command: ["--home", "/data", "--key-id", "ciris-status-1"]
   volumes: [ "status-data:/data" ]
   ```
3. Its `consent:replication` peering with Node A is already CEG-authored — it
   reconciles live; nothing to re-author unless the peer address changed.

## 5. Verify (both nodes)
```sh
curl -s http://127.0.0.1:4243/v1/identity | jq .signer_key_id           # SAME key_id as before
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4243/lens/api/v1/scores   # 200
curl -s http://127.0.0.1:4243/v1/accord-holders | jq '{family_established, registered_total}'
#   → {"family_established": false, ...} until the genesis ceremony — EXPECTED, not an error
# boot log: persist migration applied; no "HALT IN EFFECT".
```

## 6. Confirm no halt latch (sanity)
```sh
test -e "$CIRIS_HOME/HUMANITY_ACCORD_HALT" && echo "LATCHED — see §1 halt gate" || echo "clear"
```

## 7. Rollback
```sh
pip install "ciris-server==0.5.4"          # the last release published before this cut
# restore the pre-0.5.30 corpus backup (the 9.10.0 schema migration is forward-only):
rm -rf "$CIRIS_HOME"/data && cp -a "$CIRIS_HOME"/data.bak.pre-0.5.30 "$CIRIS_HOME"/data
```
Identity files are untouched either way (no re-key). Node B rolls back by
redeploying the prior ciris-status image.

## 8. After the upgrade — the GENESIS CEREMONY (before 0.6, NOT part of this upgrade)
0.5.30 makes the accord kill-switch **complete in code**, but the canonical mesh
still must run the multi-party **genesis ceremony** before 0.6 bakes
`CANONICAL_BOOTSTRAP_PEERS`:

- **3 humans × {primary, spare} = 6 FIPS YubiKeys + 6 USB keys.** Primaries are the
  family SEATS (entrenched `quorum:2/3`); spares are vaulted recovery keys (registered
  holders, NOT seats).
- Run it from the desktop client's guided **Accord ceremony wizard** (shown under the
  Accord screen only while no family is registered). The reference flow is
  `examples/qa_runner` `run_ceremony` (software-key, A1→A2→B1→B2→C1→C2).
- **The canonical TRIO (nodes — this runbook) and the accord HOLDERS (humans — the
  ceremony) are orthogonal trust roots. Do not conflate them.**
- Save the assembled genesis object — it is the cold-start recognition root baked into
  verify (CIRISVerify#107); until then `humanity_accord_genesis()` is `None` and a
  node recognizes the roster from its entrenched persist family.

Only after the ceremony + the verify bake is the safe-mesh floor COMPLETE and 0.6
(+registry / mesh bootstrap) unblocked.
