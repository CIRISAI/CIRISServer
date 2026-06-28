# Bridge runbook — FRESH SEED the canonical mesh (wipe + reclaim clean)

**This is NOT an in-place upgrade.** It wipes each bridge node's existing keys + data
and re-seeds the canonical mesh from scratch under the canonical node names, so Node A
and Node B come back CLEAN and owner-claimed. Use this when re-seeding the mesh (e.g.
after key custody drift, or to re-home onto a current substrate). For an in-place
version bump that PRESERVES identities, use the BRIDGE_UPGRADE_* runbooks instead.

⚠️ **Destructive.** Wiping a node destroys its federation signing keys. Only do this on
nodes you intend to re-seed; a node's old fed-ID does not survive.

## Substrate floor
edge **v7.4.4** · persist **v11.5.0** · verify family **v8.3.0** · Leviculum v0.8.1+ciris.1.
`pip install -U ciris-server` (the wheel carries the pinned substrate; persist auto-migrates
the fresh DB on first open). Boot model = zero-env: the ONE input is `--home`; the node
identity label is `--key-id`; everything else is baked constants or `config:*` CEG.

## Canonical node names (the `--key-id` for each node)
| Node | Role | `--key-id` | Source of truth |
|------|------|-----------|-----------------|
| **A** | lens / **canonical seed** (in-group; the mesh entry the others dial) | **`ciris-canonical-1`** | `tests/release_gates/support.rs::CANONICAL_TRANSPORT_KEY_ID` (Stage-5 gate target) |
| **B** | `ciris-status` node (OUT of the canonical group; bidirectional A↔B replication only) | **`ciris-status`** | `src/config.rs` / `src/peer.rs` |

`--key-id` is the keystore alias; the wire/directory `key_id` is the FSD-003 derived
`<label>-<fp(sha256(ed_pubkey))>` (so the public identity is e.g. `ciris-canonical-1-<fp>`).
The `ciris-canonical` 2-of-3 founder-quorum (the steward-key replacement, `src/quorum.rs`)
is the trust-root COMMUNITY — distinct from any one node's `--key-id`; every node ships
trusting it.

## Per node — WIPE, then re-seed
Run on EACH node (A and B). Pick the node's home + name from the table.

### 1. Stop the node + WIPE it clean
```sh
sudo systemctl stop ciris-server            # or: kill the running process
# Wipe the federation keys + data so first-run mints fresh. Operator-direct
# (filesystem) wipe — no owner session needed; the whole home goes:
sudo rm -rf /var/lib/ciris                  # the node's --home (default DEFAULT_CIRIS_HOME)
```
(If the node is owner-claimed and reachable, the owner can instead call
`POST /v1/system/data/wipe-signing-key {confirm:true,confirm_wallet_loss:true}` — it wipes
data+keys and the process exits ~800ms later so the supervisor restarts into first-run.
The filesystem `rm -rf <home>` above is the simplest for a re-seed.)

### 2. Boot → first-run (prints the NodeCode + one-time claim PIN on the console)
```sh
# Node A:
ciris-server --home /var/lib/ciris --key-id ciris-canonical-1
# Node B:
ciris-server --home /var/lib/ciris --key-id ciris-status
```
On a wiped/fresh home the node mints its hybrid (Ed25519 + ML-DSA-65) federation key under
the `--key-id` label, applies all persist migrations, and (no ROOT yet) prints the
**OWNERSHIP UNCLAIMED** banner with the `CIRIS-V1-…` NodeCode + a one-time `CLAIM PIN`
(also written `0600` to `<home>/claim_pin`). Capture both. Leave it running.

### 3. Mint the founder fed-ID (once, on whichever box you claim from)
The owner identity is `<key-id>-user` at the node's user-seed path. Mint it headless:
```sh
ciris-server identity create --home /var/lib/ciris --key-id ciris-canonical-1 \
  --backend platform-sealed      # TPM/Secure-Enclave; falls back to keychain/software
# (--backend yubikey for a PKCS#11 token, --backend software for dev)
```

### 4. Claim ownership of the node (headless; signs delegates_to(you → node, infra:*))
```sh
ciris-server claim --home /var/lib/ciris --key-id ciris-canonical-1 \
  --backend platform-sealed \
  --node-code "CIRIS-V1-…(from step 2)…" \
  --claim-pin "XXXX-YYYY" \
  --target-url http://127.0.0.1:4243 \
  --owner-username eric --owner-password '…'      # sets the ROOT login for a SYSTEM_ADMIN session
```
Repeat steps 2–4 on Node B with `--key-id ciris-status`. (The desktop/mobile wizard's
first-run flow does the equivalent — mint fed-ID → self-claim — if you prefer a GUI; the
0.5.61 custody ladder means no YubiKey is required.)

## Wire the mesh
### 5. Bidirectional A↔B consent replication (owner-gated; emits `consent:replication:v1`)
Each node prints its **self-signed `SignedKeyRecord`** JSON at boot — the log line
*"Node A's self-signed SignedKeyRecord (hand this JSON to peer B as
CIRIS_PEER_B_KEY_RECORD)"*. Exchange those two JSON blobs between operators, then POST
the directed consent on each node toward the other (`POST /v1/federation/peering`,
`src/federation_admin.rs`). The peer's record is verified (hybrid signature) by the
fail-secure admission gate before it's stored — a forged record is rejected:
```sh
# On A, consent to replicate with B (paste B's SignedKeyRecord verbatim):
curl -sS -X POST http://127.0.0.1:4243/v1/federation/peering \
  -H "Authorization: Bearer <owner session>" \
  -H "Content-Type: application/json" \
  -d '{
        "peer_key_id": "<B key_id, e.g. ciris-status-<fp>>",
        "peer_key_record": { …B's self-signed SignedKeyRecord JSON from B's boot log… },
        "attestation_prefixes": ["scores:", "capacity:"]
      }'
# …then the SYMMETRIC call on B toward A (paste A's SignedKeyRecord).
```
`peer_key_id` MUST equal `peer_key_record.record.key_id`. `attestation_prefixes` is the
namespace set THIS node consents to replicate to the peer (trailing ":" significant).
The CEG-driven replication reconciler converges the live `set_peers` with no restart
(CIRISEdge#173). A is in-group, B is out-of-group; each owns its own corpus.

### 6. Node A is the canonical seed
For 0.5.x, `CANONICAL_BOOTSTRAP_PEERS` is empty by design (`src/config_reconcile.rs`): the
mesh grows from A. Other nodes reach A operationally by setting `net.bootstrap_peers`
(a `config:*` key, owner-authored via `PUT /v1/config`) to A's Reticulum entry
`host:port`. This const is baked to `[A, registry1, registry2]` at Server 0.6.

## Verify
```sh
# Owner-claimed under the right identity:
curl -s http://127.0.0.1:4243/v1/setup/owned-nodes      # owner=<your fed-ID>, owned_count>=1
# Node A carries the canonical transport key:
curl -s http://127.0.0.1:4243/v1/federation/node-code   # key_id starts ciris-canonical-1-…
# Peering converged + scores flowing:
#   node logs: "replication converged to N consent peers"; A scores capacity:sustained_coherence:v1
```

## Checklist
- [ ] A + B both **wiped** (no stale keys/data)
- [ ] A booted as **`ciris-canonical-1`**, B as **`ciris-status`**
- [ ] Founder fed-ID minted; **both nodes owner-claimed** (owned-nodes shows your fed-ID)
- [ ] **Bidirectional** A↔B `consent:replication:v1` converged
- [ ] B's `net.bootstrap_peers` points at A (A is the seed)
- [ ] A emitting `capacity:sustained_coherence:v1`; B out-of-group; each owns its corpus

No env vars; no migration step beyond the auto-migrate. Supersedes the BRIDGE_UPGRADE_*
runbooks for a clean re-seed (those remain for identity-preserving in-place bumps).
