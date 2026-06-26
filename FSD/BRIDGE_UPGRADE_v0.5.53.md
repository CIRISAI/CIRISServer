# Bridge upgrade — ciris-server `0.5.x` → `v0.5.53`

> **Audience:** the bridge / ops re-installing **Node A (lens)** and **Node B (status)**
> at **ciris-server 0.5.53** — the cut that adopts the **edge v7.2.0 substrate triple**
> (the phone-radio / RNS transport floor) and carries the federation-identity fixes.
> **The boot model is UNCHANGED from [`v0.5.0`](BRIDGE_UPGRADE_v0.5.0.md): zero env,
> `--home` + `--key-id` only. NODE identity is preserved — no re-key. The corpus
> auto-migrates on first boot.**

## 0. TL;DR — re-install both nodes at 0.5.53, same flags
The substrate moved (persist `10.2.2 → 10.5.0`, verify family `7.5.0`, edge
`7.0.12 → 7.2.0`, leviculum `0.7.0 → 0.8.1+ciris.1`), but persist **builds + migrates
the SQLite corpus automatically on `Engine` open**. No env changed, no new CLI input.

```sh
# Node A (lens): back up, upgrade the wheel, restart with the SAME key_id.
pip install --upgrade "ciris-server==0.5.53"      # or drop the v0.5.53 release binary on PATH
ciris-server --home /opt/ciris --key-id ciris-canonical-trio-1   # the node's EXISTING key_id
```

```yaml
# Node B (status): rebuild the ciris-status image on ciris-server 0.5.53, redeploy.
command: ["--home", "/data", "--key-id", "ciris-status-1"]       # unchanged; its OWN volume
```

> ⚠ **ciris-server ships NO container image** — only PyPI wheels + GitHub-release
> binaries. **Node B's image is built in the CIRISStatus repo** with its
> `ciris-server` dependency pinned to `0.5.53`. Bumping Node B = a CIRISStatus
> release, not a `docker pull` of ciris-server.

## 1. What changed since `0.5.30` (ops-relevant only)

| Area | Note |
|---|---|
| Boot model | **Unchanged** — `--home <dir> --key-id <name>`, zero env, baked defaults + `config:*` CEG. |
| Substrate | persist 10.2.2→**10.5.0** / verify family **7.5.0** (verify-core + ciris-crypto + ciris-keyring) / edge 7.0.12→**7.2.0** / leviculum 0.7.0→**0.8.1+ciris.1**. **Corpus migrates automatically** on open — *back up first* (§2). |
| **Node logs (NEW, #120)** | A headless node now logs **reliably to a file**: `<home>/logs/ciris-server.log.<date>` (non-blocking daily-rolling), in addition to stdout. This is the first place to look when debugging a node. No flag — it follows `--home`. |
| Lens seal-sign (#118) | The lens trace seal path now stamps the **derived** federation `key_id` (matching what `receive_and_persist` verifies against), fixing `verify_unknown_key` on every seal. Relevant only when a brain ships traces; pure nodes unaffected. |
| Phone-radio / RNS (edge 7.2.0 + leviculum 0.8.1) | New **RNode LoRa channel** hot-plug path (`PyEdge.add_rnode_channel_interface`). **Optional** — a node serves fine with no radio attached; this only enables when a host app provisions an RNode interface. No ops step for A/B. |
| Node wire `key_id` | Derived `<label>-<fp>` (unchanged since 0.5.1). NODE identity is sealed under the stable keystore alias — **never re-keyed** by this upgrade. |
| Halt gate | Boot still **refuses to start while a `HUMANITY_ACCORD_HALT` latch exists** under `--home`. A normal node has none. Conformant clear: `ciris-server accord reactivate --home <h> --proof <p.json>` — **not** `rm`. |
| HUMANITY_ACCORD (#41) | Kill-switch surface present; **optional to run**. `GET /v1/accord-holders` reports `family_established:false` until the genesis ceremony (§8) — EXPECTED. |
| Config-as-CEG / replication | **Unchanged** — owner-authored `config:*`, consent-driven peering, no-restart reconcilers. |

## 2. Pre-flight (do NOT skip — the corpus migrates forward)
```sh
cp -a "$CIRIS_HOME"/data     "$CIRIS_HOME"/data.bak.pre-0.5.53      # SQLite corpus
cp -a "$CIRIS_HOME"/identity "$CIRIS_HOME"/identity.bak.pre-0.5.53  # ed25519.seed (+ sealed PQC)
cp -a "$CIRIS_HOME"/keys     "$CIRIS_HOME"/keys.bak.pre-0.5.53 2>/dev/null  # sealed ML-DSA-65 halves
```
Record each node's existing `--key-id` (`ciris-canonical-trio-1` for A,
`ciris-status-1` for B) — pass the **same** value so NODE identity carries over.
The 10.5.0 migration is **forward-only**: a downgrade (§7) needs this backup.

## 3. Node A (lens) — re-install + boot
```sh
pip install --upgrade "ciris-server==0.5.53"
ciris-server --home /opt/ciris --key-id ciris-canonical-trio-1
```
First boot applies the persist migration in place. Watch **`<home>/logs/ciris-server.log.<date>`**
(NEW) for: `logging to …` banner, the migration line, `resolved initial config:* snapshot`,
transport up, read API up. An already-owned node stays owned; an unclaimed node prints
`OWNERSHIP UNCLAIMED` + NodeCode + claim PIN. **Drop any leftover `CIRIS_*`/`AGENT_*`/`OAUTH_*`
env** — still ignored, remove to avoid confusion.

## 4. Node B (status) — rebuild on 0.5.53
1. In **CIRISStatus**, pin `ciris-server == 0.5.53`, build + push the image to GHCR.
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
curl -s http://127.0.0.1:4243/v1/system/verify-status | jq '{key_id, key_status, version}'  # version 0.5.53
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:4243/lens/api/v1/scores   # 200
curl -s http://127.0.0.1:4243/v1/accord-holders | jq '{family_established, registered_total}'
#   → {"family_established": false, ...} until the genesis ceremony — EXPECTED, not an error
ls -t "$CIRIS_HOME"/logs/ciris-server.log.* | head -1   # NEW: the node IS writing a log file
# log: persist migration applied; no "HALT IN EFFECT".
```

## 6. Confirm no halt latch (sanity)
```sh
test -e "$CIRIS_HOME/HUMANITY_ACCORD_HALT" && echo "LATCHED — see §1 halt gate" || echo "clear"
```

## 7. Rollback
```sh
pip install "ciris-server==0.5.52"          # the prior cut
# restore the pre-0.5.53 corpus backup (the 10.5.0 schema migration is forward-only):
rm -rf "$CIRIS_HOME"/data && cp -a "$CIRIS_HOME"/data.bak.pre-0.5.53 "$CIRIS_HOME"/data
```
NODE identity files are untouched either way (no re-key). Node B rolls back by
redeploying the prior ciris-status image.

## 8. Owner / USER fed-ID — mint FRESH on 0.5.53 (not a node step)
The NODE keys (A/B) carry over untouched. The **owner's USER fed-ID** is separate. If you
are (re)establishing ownership, **mint a fresh USER identity on 0.5.53** rather than
re-opening an older one across a different `--home`:

```sh
# desktop wizard "secure with 2FA / software", or:
ciris-server identity create --home <h> --backend software --label <node>-user
```

> ⚠ **Known issue — CIRISVerify#134 (fixed upstream; mitigated by minting fresh).** On
> re-open, the keyring's `SealedMlDsa65Signer::open()` **silently minted a fresh ML-DSA-65
> seed when the sealed half was absent at the resolved keys dir** (e.g. a `--home` change),
> producing a half-valid hybrid signer (Ed25519 OK, **ML-DSA-65 fails**). The symptom is a
> 500 on owner-binding / delegation: `federation-tier attestation … rejected: PQC signature
> verification failed: MlDsa65`. **A fresh mint seals both halves consistently and avoids
> this.** Verify after mint: a delegation/owner-binding succeeds (no `MlDsa65` reject).

## 9. After the upgrade — the GENESIS CEREMONY (before 0.6, NOT part of this upgrade)
0.5.53 keeps the accord kill-switch **complete in code**; the canonical mesh still must run
the multi-party **genesis ceremony** before 0.6 bakes `CANONICAL_BOOTSTRAP_PEERS`:

- **3 humans × {primary, spare} = 6 FIPS YubiKeys + 6 USB keys.** Primaries are the family
  SEATS (entrenched `quorum:2/3`); spares are vaulted recovery keys (registered holders, NOT seats).
- Run it from the desktop client's guided **Accord ceremony wizard** (shown under the Accord
  screen only while no family is registered). Reference flow: `examples/qa_runner` `run_ceremony`
  (software-key, A1→A2→B1→B2→C1→C2).
- **The canonical TRIO (nodes — this runbook) and the accord HOLDERS (humans — the ceremony)
  are orthogonal trust roots. Do not conflate them.**

Only after the ceremony + the verify bake is the safe-mesh floor COMPLETE and 0.6
(+registry / mesh bootstrap) unblocked.
