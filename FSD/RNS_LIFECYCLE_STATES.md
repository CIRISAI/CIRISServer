# RNS/CRS lifecycle states — the layered reference

The one place every state on the mobile-trace delivery path is named, with its
transitions, its observable signal, and the incident history that proved it
matters. Extracted verbatim from the pinned sources (leviculum
`v0.9.4+ciris.1`, edge `v13.4.0`) — **never invent a state name; grep it
here first.** Born from the 2026-07 delivery saga, where three stacked silent
failures (keepalive death, driver frame destruction, resource contention) cost
a multi-repo RCA because no shared state map existed.

Harness coverage: `harness/mesh-repro/run_lifecycle.sh` drives and asserts
every state reachable from our tier (see §Harness at the bottom).

---

## OSI → RNS → CRS map

Reticulum positions itself as a **cryptography-based OSI Layer 3** (network
layer), carrier-agnostic below: LoRa, serial, WiFi, or TCP/UDP-as-carrier are
all "physical" from its perspective. RNS Links add L4/L5 semantics (reliable,
encrypted, session-ful channels); Resources/Channels add L6-ish framing
(sequencing, compression, checksumming). **CRS (the CIRIS stack) sits at
L5–L7.**

```
 OSI              RNS / leviculum                     CRS (CIRIS stack)
 ───              ───────────────                     ─────────────────
 L7 Application   —                                   federation delivery · traces/CEG
                                                      delivery_status() · prime/reprime
                                                      consent · scorer  [ciris-server]
 L6 Presentation  Resource (seq/compress/checksum)    CRPL planes (Key/IdentityOccurrence/
                  Channel messages                    Attestation) · hybrid seal (Ed25519+
                                                      ML-DSA) · KEX (x25519+ML-KEM)
                                                      [ciris-edge replication + persist]
 L5 Session       Link (encrypted, identified,        peer admission: Advisory→Rooted ·
                  keepalive, stale/close)             link→key_id attribution
                                                      [ciris-edge transport]
 L4 Transport     Link delivery semantics             —
                  (proof, retries, ChannelExhausted)
 L3 Network       RNS core: destinations, announce,   —
                  paths, transport nodes  [leviculum]
 L1/L2 Carrier    TCP client/server ifaces, serial,   —
                  RNode/LoRa  [reticulum-std driver]
```

The load-bearing consequence: **a failure below L5 is invisible to CRS unless
the lower layer emits an event.** Every incident in the saga was exactly this
shape. The event surface (`NodeEvent`) is therefore part of the contract, not
decoration.

---

## Layer 0 — Path / announce (pre-link, RNS L3)

| State | Meaning | Observable |
|---|---|---|
| announce heard | peer's identity announce received | `NodeEvent::AnnounceReceived` |
| path known / lost | route to a destination usable / dropped | `NodeEvent::PathFound` / `PathLost` |

Explicit-hash destinations (the canonical, `ciris-canonical-1`) **cannot
announce** (`ExplicitHashCannotAnnounce`) — they are only reachable after an
out-of-band root (prime). This is why `prime_canonicals` exists (L7).

## Layer 1 — Link (`LinkState`, leviculum `reticulum-core/src/link/mod.rs:157`)

| State | In | Out | Observable |
|---|---|---|---|
| `Pending` | link request sent | proof → `Handshake`; timeout → `Closed(Timeout)` | — |
| `Handshake` | proof verifying (ECDH) | done → `Active`; bad → `Closed(InvalidProof)` | `LinkProofRequested` |
| `Active` | established | keepalive lapse → `Stale`; close → `Closed` | `LinkEstablished`, then `LinkIdentified` (peer `identify()` → feeds `link_to_peer_key_id`) |
| `Stale` | no activity past stale time | recover → `Active` (`LinkRecovered`); else `Closed(Stale)` | `LinkStale` |
| `Closed` | terminal | — | `LinkClosed`/`LinkDropped` + reason |

`LinkCloseReason` (`link/mod.rs:225`): `Normal` · `Timeout` · `InvalidProof` ·
`PeerClosed` · `Stale` · `ChannelExhausted` (channel msg undeliverable after
max retries).

Timers: establishment 6s/hop (RNS default). **Ours: keepalive 30s, stale 60s
= 2× the anti-entropy cadence** (`link_keepalive: Some(30s)` in both server
`ReticulumTransportConfig` sites — CIRISEdge#363; Python-RNS defaults 360/720s
were never ours).

## Layer 2 — In-link data (two channels, one attribution)

| Mechanism | States | Observable |
|---|---|---|
| **Resource** (bulk; one transfer at a time per link) | `ResourceStatus` (`resource/mod.rs:159`): `None→Queued→Advertised→Transferring→AwaitingProof→Assembling→Complete` \| `Failed` \| `Corrupt` | `ResourceAdvertised/Progress/Completed/Failed` |
| **Link packet / channel message** (small; interleaves a busy Resource — CIRISEdge#353 ask 2) | delivered, or link closes `ChannelExhausted` | `MessageReceived` (channel-demuxed) / `LinkDataReceived` (raw). **Both** route through `attribute_and_deliver` since edge v13.4.0 |
| **Driver-layer loss** | frames destroyed when an iface dies mid-dispatch | `FramesDropped {iface_id, count, reason}` + `DispatchDisconnected` / `DeliveryFailed` (leviculum#25; silent before v0.9.3+ciris.1) |

## Layer 3 — Peer admission → KEX (edge transport + persist directory)

| State | Meaning | Out | Observable |
|---|---|---|---|
| **Admitted, `BindingProvenance::Advisory`** | transport identity taken from the announce itself; recorded, authority-unestablished | authoritative binding → `Rooted` (Advisory→Rooted is the only allowed upgrade direction, `transport/reticulum.rs:4098`) | `peer_admitted … provenance=Advisory` |
| **`Rooted`** | authoritative binding: authenticated cold-start announce, `prime_peer`/`inject_rooted_peer`, or a replicated directory row | — | `RNS announce rooted`; `transport.knows_peer(key_id) == true` |
| **KEX present** | the peer's IdentityOccurrence (x25519 + ML-KEM-768 enc keys) has replicated into the local directory | sealing to that peer possible | `resolve_peer_kex_pubkeys(key_id) → Some`; `delivery_status().peers[].kex_present` |
| **Deliverable** | `Rooted ∧ KEX` | sealed envelopes can ship | `delivery_status().peers[].deliverable == true` |

## Layer 4 — CRPL replication round (edge `src/replication/`)

| State | Meaning | Observable |
|---|---|---|
| `ReplicationOutcome::Send` | session emits ordered messages for the transport | round traffic |
| `ReplicationOutcome::Applied {kind, admitted, refused, staleness}` | peer envelopes applied (planes: `Key` · `IdentityOccurrence` · `Attestation`) | `dispatch_inbound`; staleness signal |
| `RoundEvent::Completed(report)` | round done | metrics |
| `RoundEvent::Refused` / `TimedOut` / transport-`Err` | session reset; retry on the next 30s cadence tick | scheduler WARNs |

All three planes are wired for every desired peer (`build_replication_peers`,
`compose.rs`) — a KEX gap is **not** a missing-plane-selector problem.

## Layer 5/7 — Server delivery (ciris-server)

`start_federation_delivery` (once per process, `is_started()`-guarded) →
`prime_canonicals` (baked hints → `consent:replication` → root each canonical)
→ reconcile loop (30s) → dispatcher with exponential backoff
(`mark_transport_failed`, 1s→3600s jittered) → teardown `shutdown_node()`
(releases :4243, `node_control` disarm) → post-restart
`reprime_federation_delivery()` (CIRISServer#288 — the restart re-prime; a
plain re-call of start no-ops).

**The accessors** (in-process, never over the wire — each one exists because a
silent state cost a full RCA):

| Accessor | Question it answers | Born from |
|---|---|---|
| `compose_status()` | which boot phase is the node in / stuck at? | #279 compose hang |
| `first_run_claim_pin()` | what PIN does the console-embedding app claim with? | #277 dark banner |
| `delivery_status()` | why isn't the trace sailing for peer X? | #294 delivery park |

`delivery_status()` decision tree: `delivery_started=false` → prime never
ran/re-fired · `knows_peer=false` → never promoted past Advisory ·
`kex_present=false` → IdentityOccurrence round not completing ·
`deliverable=true` but nothing lands → L2 driver loss (grep `FramesDropped`).

---

## Incident map (why each row exists)

| Incident | Layer | State involved | Fix |
|---|---|---|---|
| Keepalive death (#363) | L1 | `Active→Stale→Closed(Timeout)` faster than an L4 round | 30s/60s timers, edge v13.3.0 |
| Silent frame destruction (leviculum#25) | L2 | driver killed queued frames uncounted on iface death | `FramesDropped` event, leviculum v0.9.3+ciris.1 / edge v13.3.1 |
| Resource contention (#353 ask 2 / leviculum#27) | L2 | reverse-path reply lost the 8s window to a busy `Transferring` Resource | reply ships as link packet, edge v13.4.0 |
| Restart no-re-prime (#288) | L5/7 | `is_started()` guard froze the boot-time prime | `reprime_federation_delivery()`, 0.5.124 |
| KEX-none regression (open) | L3 | Advisory admit, IdentityOccurrence round never completes; L1 link storm | under repro; suspect = v13.4.0 `MessageReceived` attribution merge |

---

## Harness

`harness/mesh-repro/run_lifecycle.sh` — the lifecycle conformance gate. Boots
the two-node test-anchor mesh (no NAT, zero loss) and asserts each observable
in ladder order from our tier (L5+), reporting one PASS/FAIL row per state:

announce → advisory admit → rooted (`knows_peer`) → KEX present → deliverable
→ round `Applied`/`dispatch_inbound` → resource `Complete` → teardown
(`PeerClosed`) — plus, with `LIFECYCLE_KILL=1`, a hard agent kill mid-transfer
to assert `FramesDropped` surfaces (the leviculum#25 guard).

The agent side prints `[DELIVERY-STATUS] <json>` each poll
(`CIRIS_HARNESS_LIFECYCLE=true` in `agent_boot.py`), so every L3/L5 state is a
grep, not an inference. Exit code = number of ladder states missed.
