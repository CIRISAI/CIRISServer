# mesh-repro — a zero-confound local repro of the canonical delivery stall

Two `ciris-server` nodes on one isolated Docker bridge, to answer the one
question the WiFi→NAT→Vultr setup cannot: **when the IdentityOccurrence round
runs over a link with zero packet loss, does the resource transfer complete, or
does the link still establish → sit idle → die of `keepalive_timeout`?**

- **Completes** → the remote failure is *packet-loss resilience* of the multi-packet
  resource transfer (retry/re-key robustness), not a coordinator bug.
- **Still stalls** → it is a real *coordinator / resource-send-over-link* bug,
  reproducible and debuggable locally.

Either way it is a clean, repeatable verdict instead of another confounded run.

## Why this removes the confounds

| remote confound | removed here by |
|---|---|
| internet packet loss on the resource transfer | one Docker bridge, loopback-quality, zero loss |
| NAT idle / keepalive drop | no NAT — containers on the same host network |
| cross-version skew (Node A one behind, restarts under the agent) | both roles run the **same** `ciris-server==$CIRIS_SERVER_VERSION` wheel |
| stale identity / data carryover | `tmpfs` home → fresh, deterministic each run |
| 5-minute announce-heal wait distorting timing | link-local announce heals in seconds |

## Run

```bash
cd harness/mesh-repro
./run.sh                         # build + up + probe + verdict (0.5.113, 180s)
CIRIS_SERVER_VERSION=0.5.114 ./run.sh   # a fixed edge version
./run.sh 360                     # longer watch window
KEEP=1 ./run.sh                  # leave the stack up to poke at
```

Verdicts (exit codes): `SUCCESS`=0 · `REPRO`=2 · `STALLED`=3 · `INCONCLUSIVE`=4.

Manual:
```bash
CIRIS_SERVER_VERSION=0.5.113 docker compose -p ciris-mesh-repro up --build
docker compose -p ciris-mesh-repro logs -f agent
```

## What each node runs

- **canonical** — `ciris-server --home /var/lib/ciris --key-id ciris-canonical-1`,
  byte-for-byte the production Node A entrypoint (the seed / fabric node).
- **agent** — `agent_boot.py`, which reproduces CIRISAgent's embedded-edge
  federation boot from the one wheel: `Engine(sqlite://…, key_id)` →
  `init_edge_runtime(engine, …, bootstrap_peers=[canonical:4242], enable_transport=True)`
  → `start_federation_delivery()`. That last call is the machinery under test — it
  seeds the canonical as a replication target, authors the `consent:replication`
  grant, and drives the IdentityOccurrence round.

## Reading the result

`probe.sh` tails both logs and tracks: `heal`, `estab` (LINK_ESTAB), `died`
(keepalive_timeout), `inbound` (attributed frame at the canonical), `skipped`
(SkippedNoSourceKeyId), `kex`, `env` (envelopes). The verdict:

- **SUCCESS** — `kex`/`env`/`inbound` > 0: the round reached the canonical. Local
  zero-loss delivery works → chase remote loss-resilience.
- **REPRO** — `estab` > 0, `died` > 0, `env` == 0: links establish and die idle
  with the round never completing, **with zero loss** → a real bug. Dig:
  ```bash
  docker compose -p ciris-mesh-repro logs agent     | grep -iE 'send_resource|resource|LINK_DIED'
  docker compose -p ciris-mesh-repro logs canonical | grep -iE 'dispatch_inbound|source_key_id|resource'
  ```
- **STALLED** — `estab` == 0: the blocker is below the round (routing/heal/attribution).

## §Fidelity — the one coupling to know about

`start_federation_delivery` targets the **baked canonical key_id** from persist's
genesis (`ciris-canonical-1-d7bdeu223k`). A fresh `--key-id ciris-canonical-1`
home mints a *different* fingerprint, so the agent's auto-target and the harness
canonical's identity can differ. Symptom: the agent logs `seeded=0` and no link
forms (verdict `STALLED`).

Two ways to make the agent target THIS canonical:

1. **Seed the real canonical keystore (highest fidelity).** Swap the canonical's
   `tmpfs` for a bind mount of a home that already contains the baked
   `ciris-canonical-1` keystore (the operator has this — it is the same seed Node A
   runs). Then the harness canonical *is* `…-d7bdeu223k` and the agent's baked
   target matches:
   ```yaml
   canonical:
     volumes: ["/path/to/canonical-home:/var/lib/ciris"]   # remove the tmpfs block
   ```
2. **Point the agent explicitly.** Pass the harness canonical's minted key_id +
   dial to `init_edge_runtime(canonical_bootstrap_peers=[…])` in `agent_boot.py`
   (read the canonical's key_id from its `GET /v1/identity` on startup). This keeps
   fresh identities but explicitly targets the harness canonical.

The transport/link path (dial → root → heal → establish) reproduces either way;
the *round-drive* needs the identity match above. If you only need the
transport-layer repro (link establishes then dies), option (1)/(2) are optional.

## Notes

- Ports are internal to the `mesh` bridge; nothing is published to the host. Add a
  `ports:` mapping if you want to curl a node's `:4243` health/API from the host.
- `RUST_LOG` on the agent is set to `info,ciris_edge=debug,reticulum_core=debug`
  so the link/resource/heal lifecycle is visible. Raise/lower as needed.
