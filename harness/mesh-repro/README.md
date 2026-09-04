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

## scenarios/chat.sh — the cross-node chat proof (CIRISServer#455)

A THIRD topology, standalone rather than an overlay: `docker-compose.chat.yml`
brings up **canonical + node-a + node-b**, all three `ciris-server` processes
(the base file's python `agent` role mounts no HTTP router, so it can be no party
to a chat). Run it:

```bash
./run_scenario.sh chat            # 780s default window
KEEP=1 ./run_scenario.sh chat 480 # leave the stack up
```

The ladder: `rooted → peered → contact → room → dark → one_sided → bound →
sent → arrived → hamburger`. `arrived` is the one it exists for — the sender's
`attestation_id`, captured from its send response, must appear in the recipient's
transcript with its body intact and its status `live`. Keying on the SENDER's id
is what stops "the recipient derived the same room and is reading its own message
back" from passing for delivery.

The array is ordered by DEPENDENCY, not by narrative: the monotonic verdict
treats a positive later stage as proof of every earlier one, so `dark` and
`one_sided` — which pass or fail without any delivery — sit *before* `sent`.
Either one placed after it would silently certify a delivery that never happened.
`bound` sits before `sent` because `sent` depends on it: the room is an MLS pair
group, the creator can only speak once the joiner's KeyPackage has crossed, and
that row crosses only if each node can walk the OTHER node → its owner, which is
what `bound` measures (both directions, off the directories).

Three acts the driver performs that a first reading might not expect:

- **Announce, right after the claim.** Setup-complete writes the owner-binding
  at `cohort_scope: self`; that is the privacy default and a row no peer may
  ever hold (CC 5.2). `POST /v1/federation/announce` is the OWNER re-signing it
  at federation scope — the wizard's default, an opt-OUT — and it is
  loopback-only, so the scenario shell runs it on each node's console beside
  the claim and hands the result to the driver. A node that has not announced
  is P2P-only by design: it can dial, and it cannot be placed in anyone's
  audience. Edge's bench-mesh runner has no such step because its
  `owner_binding_attestation` mints the binding AT federation scope.
- **SEND opens the room; SPEAK sends.** The message moved out of phase SEND
  (where it ran before the joiner had even opened the room and measured
  `503 chat.room_key_failed` on every run) into phase SPEAK after JOIN, gated on
  the transcript's own `ready` field and logging the room's `chat.state.*` note
  on every poll. The one-sided window between SEND and JOIN is unchanged.
- **`bound` reads the result, the driver records the act.** A red `bound` prints
  each node's announce answer and each directory's copy of the other party's
  binding by cohort_scope, so it says whether the announce never ran or ran and
  never replicated.

`CHAT_NODES` is an ordered party list (first sends, the rest receive), so nothing
in the ladder is two-shaped:

```bash
COMPOSE_PROFILES=scale CHAT_NODES="node-a node-b node-c" ./run_scenario.sh chat
```

`one_sided` is declared **RED-EXPECTED** (`XFAIL_one_sided`). That is not a way
to make a ladder green: `lib/harness.sh` only accepts the marking with a value
that names the mechanism, and it prints every expected red beside the verdict, so
the union of a ladder's ⚠ lines is a readable list of asks. A stage whose redness
cannot be explained is a BREAK, not an XFAIL.

**As of 2026-08-20 (0.5.185) it is green through `dark` and carries two reds —
one expected, one not.** Both are deliverables: each names the wiring it is
missing, so the union of them is a readable list of asks.

- `one_sided` ⚠ RED-EXPECTED. While only the sender held the roster, the
  recipient answered `404 chat.unknown_community` and held zero
  `federation_communities` rows for that id; it then derived the identical id
  itself. `compose::build_replication_peers` registers coordinators for
  Attestation / Key / IdentityOccurrence / TransportDestination and none for
  Community, so no anti-entropy round for the roster plane ever runs. Edge
  implements the plane end to end and persist has `put_community` — only the
  registration is missing. Product consequence: a one-sided invitation is
  impossible; both parties must independently open the same room.
- `arrived` ✗ BREAK. The plane CARRIED the message — the recipient logged the
  envelope delivered ~30 s after the send — and refused it at persist's bulk
  ingest gate, because the row names the OWNER as `attesting_key_id` while its
  hybrid signature is the NODE's (`attestation_promote` signs with the Engine's
  own signer). `verify_row_hybrid_signature` checks that signature against the
  ATTESTER's registered key and never reads `scrub_key_id`. Seven other
  sender-authored rows in the same rounds, all with signer == attester, landed.
  Not XFAIL'd: declaring the delivery stage expected-red would make CI green over
  a feature that cannot cross a node boundary at all. The fix belongs in
  `src/contacts_chat.rs` (`owner_signer_capsule::acquire`, #342), not here.

On the projection question: `chat:message:v1` resolves `AttestationFamily::Unknown`,
and at `cohort_scope: community` the conservative default gives `Projection::Cohort`
— which IS advertised, confirmed by the delivery above, so chat is not blocked by
an undecided family. What `chat:*` still needs is a DECIDED row in persist's
registry (the `moderation:*` precedent, v37.0.1, which enumerated its commons
tiers explicitly so a later consistency sweep could not lift the ceiling by
accident). The answer chat wants is the community roster.

Two mechanics are worth knowing before editing it:

- **The console binary is bind-mounted.** `ciris-server identity create` and
  `ciris-server claim` exist only in the Rust `[[bin]]` target; the wheel's
  console script is `ciris_server.cli:main`, whose PyO3 `py_main` implements
  `import-traces`, `config set|get` and the serve path — and nothing else. So the
  wheel can set `net.bootstrap_peers` (which `node_boot.sh` does, since that knob
  is boot-structural and read once before the edge is built) and cannot mint a
  fed-ID or claim a node. `target/release/ciris-server` is mounted at
  `/opt/harness/ciris-server-bin`; it links the same shared libraries the wheel's
  abi3 `.so` does, so it runs unchanged on the image.
- **Static IPs, deliberately.** `net.bootstrap_peers` and a canonical's `ip`
  transport hint are both parsed as `SocketAddr`. A docker service NAME is not
  one — it is skipped with a warning and the node dials nothing.

**In CI it gates PRs, in parallel with traceflow.** `mesh-harness.yml` runs a
`fail-fast: false` matrix — `["traceflow","chat"]` on pull_request and the nightly
schedule, collapsing to the single scenario asked for on workflow_dispatch. They
are independent stacks on independent compose projects, so serializing them would
add ~20 min per PR for isolation the projects already give; `fail-fast: false`
because a red chat ladder must not cancel traceflow. `genesis_seed` stays
dispatch-only — it is an audit of unfinished genesis, red by design, and gating
PRs on it would gate on work nobody has claimed.

`run_scenario.sh` gained ONE optional hook for this, `harness_scenario_prepare`,
called between "the stack is up" and "start measuring". A carrier scenario needs
none (traceflow's agent drives itself from inside its container); a scenario
whose subject is an owner-gated HTTP surface does, because nothing in the
containers can claim a node and a claim is not a measurement. It is invoked only
when a scenario defines it, so traceflow and genesis_seed are untouched.

## Notes

- Ports are internal to the `mesh` bridge; nothing is published to the host. Add a
  `ports:` mapping if you want to curl a node's `:4243` health/API from the host.
- `RUST_LOG` on the agent is set to `info,ciris_edge=debug,reticulum_core=debug`
  so the link/resource/heal lifecycle is visible. Raise/lower as needed.
