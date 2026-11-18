# FSD: The directory seat, the canonical's bare minimum

Status: **DRAFT for decision.** Asked for by Eric on 2026-11-18: what a minimum Rust server that only does the
canonical's bare-minimum job would look like, a directory for scaling that directs nodes to other nodes for the
actual connecting, with no Poisson cover traffic, formally modelled in TLA+, with the code tied to the model
explicitly. This FSD is an investigation, not a decision: section 7 lists the decisions it needs.

Companion files, beside this FSD in `FSD/directory_seat/`:
- `tla/DirectorySeat.tla` and the eight `tla/*.cfg`: the model, its main configurations and its planted twins;
- `tla/run_tlc.sh`, `tla/TLC_SUMMARY.txt` and `tla/TLC_RESULTS.txt`: how to run TLC, and the recorded results;
- `src/lib.rs`, `src/seat.rs` and `src/client.rs`: a dependency-free sketch whose functions carry the model's names;
- `scripts/trace_check.py` and `scripts/trace_check_selftest.sh`: the code-model traceability checker and its self-test.

The sketch is not a workspace crate and is not built; it exists to anchor the traceability check.

Method: every claim cites code (file:line) or text (CC section / CEREMONY.md).
Anything that could not be settled from code or docs is marked **open** and collected in section 7.

Sources read: CIRISServer at b450b969 (0.5.249); CIRISEdge `main` at eb9d474 (v45.1.5; edge citations are to that
commit unless noted); CIRISPersist at 32512f52; CIRISConstitution (the 1.0-rc20 text and `formal/ceremony/CEREMONY.md`).

## 0. What "no poisson" means in these repos

"Poisson" names edge's **link shaping**: on a shaped link both ends send constant-size frames (1,400 B) at Poisson
times at the negotiated class rate, real when the queue holds one and cover otherwise
(edge `src/transport/link_shaping.rs:5-31`, timer from `src/emission/poisson.rs:158` `PoissonScheduler::next_interval`;
cover is `KIND_COVER`, `link_shaping.rs:53`). The text is CC 5.4.3 "Link shaping" items 1-5 (part_5:961-967): "Frames
leave on a per-link Poisson timer at the negotiated rate λ."

- **Cost.** Budget per link per direction (CC 5.4.3 table, part_5:981-987; edge `link_shaping.rs:221-226`):
  `server` 7,000 B/s, `seat` 33,000 B/s. Spent whether or not anything real is sent (part_5:975). By the agent
  read of `FLEET_DEFAULTS` that is ~18 GB/month per server link and ~85 GB/month per seat-to-seat link each way; at
  the eight-link cap a server spends ~145 GB/month each way, and seat links sit outside the cap (part_5:1014,
  `link_shaping.rs:361,385`). CPU cost: not measured anywhere found (**open**).
- **The canonical is made to participate.** `compose.rs:5559-5608` `shaping_device`: when `engine.is_canonical(me)`
  the node reports `DeviceKind::Server` and runs the server fleet default, i.e. shaping ON ("Steward 2026-11-09
  (0.5.245): canonical shaping ON", `compose.rs:5544`). CC makes shaping on by default for the `server` class
  (part_5:969) and gives seats the `seat` class between them (part_5:1014).
- **The other Poisson machinery**, edge's scope emission scheduler (`src/emission/scheduler.rs`), is only re-exported
  and test-constructed; link shaping reuses its `PoissonScheduler` and `BudgetMeter` (`link_shaping.rs:41`).

The brief's wider reading also holds against the code: everything that is not directing (the capacity scorer, trace
capture, rooms, chat, files, A/V, retention, agent hosting) is incidental to the seat (section 1.2). Dropping
cover at the seat is **non-goal N1** (section 3). Section 3.1 states what that gives up.

## 1. The canonical's duties

### 1.1 Essential: what a joining node needs from a seat

| # | Duty | Today (code) | Edition 2 (text) |
|---|---|---|---|
| E1 | **Serve the genesis bundle** so a node holding only an anchor can root | `GET /v1/trust-root/bundle`, `trust_root_api.rs:541-620`, public router `:678-689`; the bytes are compiled in (persist `federation/genesis/mod.rs:779` `canonical_genesis_bundle`) | CEREMONY.md section 1 "The server: the route serving the bundle of this form and its object id"; CC 5.3.4 (part_5:699-721): no response signature; the node verifies against its own out-of-band anchor |
| E2 | **Be dialable first**: hold the transit pair the bundle seeds, and keep it valid until a re-mint propagates | the seat's route row with its transit KEX pair, `GET /v1/trust-root/transit-row` `trust_root_api.rs:622`; edge's self-route producer (`compose.rs` comment at the `transport_binding` phase, ~1275-1285) | CC 5.3.4 "Seeding at first open", "Overlap rule", "A rotation is a quorum act" (part_5:756-766); CC 3.3.6.2 "A seat's transit key" (part_3:1851): only the bundle or a `transport:canonical_rebind` moves it |
| E3 | **Admit a stranger's bootstrap kinds before Rooted** (its key record, occurrence, route) | edge `EnvelopeKind::BOOTSTRAP_PLANES` = Key, IdentityOccurrence, TransportDestination (`replication/protocol.rs:420`); bundle-seeded rounds on those plus revocations (`replication/runtime.rs` `bundle_bootstrap_peers`); opaque first contact with per-sender/link/node budgets (`first_contact.rs:208-216`) | CC 3.3.6.2 "Rooted standing is not required to seal" (part_3:1873); CC 5.3.4 "What crosses before Rooted" (part_5:774-781) |
| E4 | **Serve the public self-authenticating rows to anyone**: key records and revocations, identity occurrences, unowned nodes' routes, the federation-scope owner-binding of announced nodes | `announced_relay.rs:1-100` (the canonical relays Key + IdentityOccurrence of every announced node and its owner; routes are not relayed, `:52-55`); edge `serve_policy.rs:34-66` | CC 5.4.6 forwarder list (part_5:1139-1143) and "What it serves openly" (part_5:1163-1168); CC 3.3.6.2: "The directory holds it as the durable source of truth" (part_3:1839) |
| E5 | **Refer**: answer a refusal or a load-shed with up to three routes of announced nodes that offer relay and report a free slot | not built as such; today the canonical carries the load itself | CC 5.4.3 "A refusal is never bare", "Every refusal may refer ... This is how a canonical sheds load" (part_5:1004-1008); CC 5.4.6 "A referred peer is a proxy" (part_5:1159) |
| E6 | **Carry the accord's rows** (halt, notify, drill, lifecycle) so a halt reaches nodes | accord routes `accord.rs:2875`, halt gate `halt_gate.rs` | CC 5.4.6 (part_5:1143): any node carries an accord row that verifies as a seated holder's; CEREMONY.md P8 (a halt available from the first moment) |
| E7 | **Copy the directory among seats** | full anti-entropy on every plane (`compose.rs:2271` replication loop) | CC 5.2 (part_5:139): "Anti-entropy over the commons is what serve seats do among themselves" |
| E8 | **Conferral is not a duty but a precondition**: the seat is canonical by the genesis count, owns nothing by it, and serves only with an announced owner | earlier form: `identity_type ∋ canonical` (persist `admission.rs:13205-13221` `is_canonical`) | CEREMONY.md:59-61 ("canonical standing is the genesis's own count, not a row of its own"); CC 4.2.1 (part_4:80); CC 5.4.6 `serve_seat_owner_unannounced` (part_5:1091) |

Text that binds a seat and is **not** directory work (each one a conflict with "bare minimum", section 7):

- **Onion relay.** "A serve node MUST NOT opt out: a seat carrying the marker is out of conformance as
  `seat_opted_out`, and a seat without a valid hop key as `seat_without_hop_key`" (CC 5.4.6 item 1, part_5:1195).
- **Shaping on request.** "Shaping is always available on a direct link. A node's setting says only whether it
  offers shaping by default, never whether it accepts it" (CC 5.4.3, part_5:995).
- **Forwarder of last resort.** A scoped body crosses "a consented contact or, as last resort, a serve seat"
  (part_5:1147). It is a MAY, so a directory seat can decline it.

### 1.2 Incidental: there only because the seat runs a whole node

All of these start in `compose.rs` for every node, the canonical included:

- the capacity scorer (`compose.rs:2367-2376`, `scorer.rs`) and the capacity monitor / load ladder (`capacity_monitor.rs`);
- trace capture and the trace plane (`compose.rs:2151` `trace_plane_watch::spawn`, `ingest_http.rs`, `trace_receipt.rs`);
- rooms, chat and pair rooms (`compose.rs:1516-1530`), the self-room drive (`compose.rs:2446-2620`), session claims (`compose.rs:2643`);
- files and drive (`drive/`, `self_room_drive.rs`), A/V (`call_routes.rs`, `call_frames.rs`);
- retention and config-reconcile loops (`compose.rs:2642`, `compose.rs:2341`);
- remote admin (`mesh_relay.rs`), the accord ceremony routes (`accord_provision.rs`; the ceremony is offline by CEREMONY.md section 2);
- the Python agent adapter (`compose.rs:2683`);
- anti-entropy on every plane, the Attestation plane included. The canonical's base load on 11-13 was advertise rounds
  toward five unowned bootstrap peers, each listing about 477 rows and withholding 86%, plus about 3.1k refusals an
  hour redelivered forever (edge's trace of the canonical on v45.0.0, 2026-11-13). That is a
  consequence of a seat running full anti-entropy toward peers it owes almost nothing.
- link shaping (section 0).

The server mounts 248 `route(` calls across `src/`. The directory seat needs four.

### 1.3 Two field findings, read as design rules

- **CIRISEdge#1004** (open on GitHub; fixed on edge main 229ade0): a first-seen **Advisory** bind made a later
  announce from another transport identity `IgnoreStale` until the key's Key row landed, and the Key row could not
  land because the links were torn down at attribution. The fix proves ownership by `key_id_binds_pubkey` when the
  resident bind is not Rooted (edge main `reticulum.rs:21396-21411`). **Rule:** the seat keeps no first-come state.
  Admission is a function of the row alone (TLA+ `Admissible`, `Inv_NoLockout`), and the record and the route arrive
  in one message, so no route ever waits for its key.
- **CIRISEdge#1005** (open; fixed on main 428fa9e): recovery rounds replaced the ordinary round, so a node's own Key
  never reached the seat. **Rule:** registration is its own request/response, never a round that another queue can
  displace. The seat side of this is `WF(Admit)` in the model. The node side lives in the node's scheduler and is
  outside this design.

## 2. The minimal design

### 2.1 Responsibilities (exactly these)

1. **Serve the bundle** this release carries (E1), unsigned, with its object id.
2. **Admit a registration**: one message = the node's `key:record` + its signed `transport_destination` binding
   (+ for an announced node, the owner's record and the federation-scope owner-binding) (E3). Checks: `key_id = H(pub)`,
   record signature, `valid_until`, the binding signed by the same key, in-row key separation (CC 3.3.6.2), the
   owner-binding's scope and liveness. Nothing else.
3. **Answer a lookup** for a key (E4): the newest binding by its own signed instant **if** the route is one a forwarder
   may serve (unowned node, or announced and relay-offered); otherwise the key record and occurrence only.
4. **Refer** (E5): on a refusal or under load, up to three relay-offering announced nodes' routes.
5. **Carry revocations and accord rows** (E6), verified against the bundle's holders.
6. **Sync with sibling seats** (E7): set union of verified rows, each re-verified on arrival.

### 2.2 Non-goals

- **N1. No cover traffic (no Poisson link shaping).** The seat neither offers nor accepts shaped links. Section 3.1
  covers the trade-off. Conflicts with CC 5.4.3 part_5:995 (**open Q2**).
- **N2. No onion relay** (no hop key, no layer links). Conflicts with CC 5.4.6 item 1 (**open Q1**).
- **N3. No forwarding of scoped bodies**, no rooms, chat, files, A/V, streams, MLS.
- **N4. No scorer, no capacity measurement, no trace capture, no telemetry rows.** A referral orders by transport bytes,
  or by the node's self-reported free-slot hint, which is never stored as a row (CC 5.4.3 part_5:1008).
- **N5. No authority.** It signs no row, holds no signing key beyond its own key record and binding, never
  "primes" a binding as Rooted (the pre-#413 "authoritative-by-assumption" default, persist
  `self_at_login.rs:234-241`), votes on nothing, and keeps no config rows (the standing rule that infrastructure does not vote).
- **N6. No full anti-entropy.** No Attestation plane beyond announces, no consent plane, no content planes.
- **N7. No owner/claim/setup surface beyond its own first boot**, no agent hosting, no remote admin.

### 2.3 State

`held: Map<KeyId, Vec<Registration>>`, plus revocations and the accord's rows. These are all signed rows the seat
did not author. There is no residency, hint cache, score, counter, consent row or config row. The answer is a fold
over `held` (newest `asserted_at`, ties by transport bytes), so two replicas holding the same rows answer the same
(CC 3.2 T8 vii: the verdict is order-free). Bound: one live binding per key and per transport, expired by the record's
`valid_until` (at most 365 days, CEREMONY.md step 2). Whether the seat also bounds strangers per window like edge's
`first_contact.rs:208-216` is **open Q5**.

### 2.4 Protocol surface

| Face | Route / plane | Admission |
|---|---|---|
| HTTP, public, cacheable | `GET /v1/trust-root/bundle` (and its object id) | none: the node verifies against its anchor |
| HTTP, public, cacheable | `GET /v1/directory/{key_id}`: record, occurrence, route if servable | none: every row self-authenticates; the node re-verifies (`client::accept_answer`) |
| HTTP, public | `GET /v1/directory/referrals` | none |
| Sealed link (`CTKX` 0x02, first-contact plane) | register (the bootstrap kinds, one message), lookup, referral | `Admissible`: the row's own signatures and `key_id = H(pub)`; nothing the seat heard before |
| Seat to seat | sync of `held` | the same `Admissible`, per row |

Whether registration may also be an HTTP POST (it would serve nodes that cannot yet seal) is **open Q4**.

### 2.5 Trust model: infrastructure does not vote

- The seat is a **source of rows, never of trust**. CC 5.3.4: "A canonical node is one source of route rows, never a
  required party" (part_5:752). Every answer self-authenticates and the node checks it again
  (`Inv_NodeNeverSwapped` holds even with a Byzantine replica). A lying replica can withhold an answer or serve a
  stale one. It cannot swap a key or a root (`Inv_RootIsAnchor`).
- The seat's standing is the genesis count (E8). It confers nothing and emits nothing about anyone.

### 2.6 Scaling

- **Reads**: the state is a grow-only set folded deterministically, so a snapshot is an immutable artifact. Lookups and
  the bundle are HTTP GETs that a CDN or any proxy can cache with ETags. Referred full nodes proxy federation-tier rows,
  which is CC 5.4.6's own load-shedding path (part_5:1159).
- **Writes**: any replica admits; replicas converge by set union in any order (`Sync`). There is no leader, consensus
  or quorum, because no write needs agreement (each row is its author's).
- **Replicas behind one seat**: the bundle seats a key with one transit pair (CC 3.3.6.2). N replicas either share that
  custody (a key-custody question) or are N seats in the bundle. **Open Q3.**

### 2.7 Dependency budget

| Crate | Needed? | For |
|---|---|---|
| verify (ciris-verify / ciris-crypto) | **yes** | composite signature, `key_id`, bundle quorum, and the link handshake (CEREMONY.md section 1: "The verifier: the composite, the row reader and the link handshake") |
| leviculum-core | yes, for the sealed face | Reticulum destination and link framing |
| edge | **not the runtime**. It needs the CRPL frame codec (`src/replication/wire_frame.rs`) and the bootstrap-plane messages only | edge is one crate with no workspace (`Cargo.toml:1-11`) and pulls persist (`Cargo.toml:454`). A `ciris-wire` extraction is **open Q6** |
| persist | **no store**. It needs only the pure row admission for `key:record` and `transport_destination` (in-row separation) | today those rules live in persist's admission. Copying them would be the mirrored-rule class. Ask persist (or verify) for a pure, engine-free `admit_*` (**open Q6**) |

The sketch in `directory_seat/src/` has zero dependencies. Crypto sits behind the `Verifier` trait.

### 2.8 Composition with full nodes

A fresh node anchors, fetches the bundle (from any seat or its own release), dials a seat by the seeded pair, registers
in one message, and looks up or is referred. From then on everything that connects people happens on full nodes:
contacts and first contact through relay-offering homes and servers, shaping, the onion tier, rooms, files and calls.
A full node pulls directory rows from the seat as its own pull and serves them as a proxy (CC 5.4.6 part_5:1159).
The canonical's full node, if Eric keeps one, becomes an ordinary relay-offering server homed on the seat.

## 3. Trade-offs

### 3.1 Dropping cover at the seat (N1)

What shaping claims, against an observer of a link: it hides the timing and volume of what rides it, not that the link
exists (CC 5.4.3 item 5, part_5:967). Without it, an observer of a node-seat link sees **when** a node registers or looks
something up, and the **size** of each exchange. What the seat serves is federation-public (key records, announced
bindings, unowned routes), so the content leaks nothing. The timing does: "X looked something up at t", and, by size, maybe
what kind of row. Mitigations that are not cover:

1. Pad every directory request and reply to one fixed size. This is cheap, with no stream.
2. A node that needs unobservability (shaped-only, Anonymous Tier) does not talk to the seat directly. It is referred,
   or reaches a shaped full node, which pulls from the seat as its own pull (CC 5.4.6 part_5:1159: "the seat sees the
   proxy's pull and not the asker's").
3. Seat-to-seat sync carries only public rows, so its volume reveals the mesh's registration rate. That is already
   public, because the rows are.

The TLA+ model is untimed and does **not** cover this property. It is stated here, not checked.

### 3.2 Not relaying onion (N2)

Fewer relays at the seats' tier. CC chose "a relay set made only of volunteers would make its operators targets"
(part_5:1195). If the seats stop relaying, the default-on relays on full nodes have to carry that load.

## 4. The model: `directory_seat/tla/DirectorySeat.tla`

World: three node keys (`a` unowned, `b` announced and relay-offering, `c` owned and not referable); honest transports
`t1, t2`; the adversary's transport `t0`; two seats. Each node roots on the bundle, joins and may move once to another
transport (the #1004 shape). Before anything happens, the adversary has sent, for every key, a record under that key's
name carrying its own public key, a registration signed by its own key that claims the name, and an announce of the key
from `t0`. Only the seat is fair (`WF` on Admit and Sync).

| Property | Kind | Statement |
|---|---|---|
| `Inv_RootIsAnchor` | safety | a node roots only on the bundle its anchor names, even when it asks a Byzantine replica |
| `Inv_NoAuthority` | safety | every row an honest seat holds was signed by the key it is about |
| `Inv_NeverSwapped` | safety | an honest seat answers only with a binding the key signed, under its own record, for a transport it really used |
| `Inv_NodeNeverSwapped` | safety | the node dials only a transport the key itself published, whatever replica it asked |
| `Inv_OwnedRouteUnserved` | safety | an owned node that does not offer relay never has its route served (CC 5.4.6) |
| `Inv_NoLockout` | safety | every genuine registration on the wire is admissible at every honest seat, whatever it heard first |
| `Prop_Registered` | liveness | a node that registers is eventually known at every honest seat by its current binding |
| `Prop_Discoverable` | liveness | where its route is servable, every honest seat eventually answers with its current transport |

Planted twins (each must fail on its own property):

| Config | Plant | Must violate |
|---|---|---|
| `DirectorySeat_firstcome` | an unauthenticated first announce binds the key (#1004) | `Inv_NoLockout` |
| `DirectorySeat_firstcome_live` | same | `Prop_Registered` |
| `DirectorySeat_noderive` | admission skips `key_id = H(pub)` | `Inv_NeverSwapped` |
| `DirectorySeat_seatauthority` | the seat may write a binding itself | `Inv_NoAuthority` |
| `DirectorySeat_serveowned` | the seat serves an owned node's route | `Inv_OwnedRouteUnserved` |
| `DirectorySeat_noanchor` | a node accepts a bundle off its anchor (Byzantine replica) | `Inv_RootIsAnchor` |

Results: section 4.1 and `directory_seat/tla/TLC_RESULTS.txt`.

### 4.1 TLC results

TLC 2.19 (tla2tools 1.7.4), 2 workers, `-deadlock`, run by `directory_seat/tla/run_tlc.sh` (summary `directory_seat/tla/TLC_SUMMARY.txt`, full output
and counterexample traces `directory_seat/tla/TLC_RESULTS.txt`): **ok=8 bad=0**.

| Config | Result | States |
|---|---|---|
| `DirectorySeat` (all six invariants + both liveness properties, two honest seats) | **closes** | 933,873 generated, **74,088 distinct**, depth 17, 36 s; temporal properties checked |
| `DirectorySeat_byz` (safety, replica `s2` Byzantine: serves any row it saw and any bundle) | **closes** | 38,649 generated, **2,744 distinct**, depth 13 |
| `_firstcome` | fails `Inv_NoLockout` | 4-state trace: node `a` roots, the seat hears the adversary's announce of `a` from `t0`, `a` joins on `t1` -> `a`'s genuine registration is inadmissible |
| `_firstcome_live` | fails `Prop_Registered` | 8-state lasso: the same, and the seat never learns `a` (#1004 as a liveness bug, triggered by a **stranger**, not just a stray process) |
| `_noderive` | fails `Inv_NeverSwapped` | 3 states: the forged record under `a`'s name is admitted and answered |
| `_seatauthority` | fails `Inv_NoAuthority` | 2 states |
| `_serveowned` | fails `Inv_OwnedRouteUnserved` | 4 states |
| `_noanchor` | fails `Inv_RootIsAnchor` | 3 states: a node roots on the Byzantine replica's bundle |

The first configuration tracked each node's dial table. Its safety-only run passed 1 M distinct states in 2 minutes,
and the run with liveness did not finish in 10 minutes. So the dial table became one `misdirected` bit, with
`published` and the announces derived from `net`.
The verdicts did not change. The cost is that a two-move or four-key model has not been run.

The sketch type-checked as a standalone crate when it was written: `cargo check --all-targets` passed in 1.1 s with no
warnings. The test bodies are empty, so `cargo test` would pass vacuously, and it was not run.

Not modelled: revocations and the accord's rows (E6), `valid_until` expiry, referral ordering, more than one move per
node, ties of `asserted_at` (the code breaks them by transport bytes; the model has none), timing (3.1).

## 5. Code-model traceability

- **Model side.** Every action and every operator the seat implements carries `\* @trace action=<Name> impl=<module>::<fn>`
  (or `op=`). World actions are tagged `env`, planted breaks `plant`.
- **Code side.** In the guarded modules (`directory_seat/src/seat.rs`, `directory_seat/src/client.rs`) every `fn` carries `/// @tla <Name>` or
  `/// @tla-none: <reason>`. Every test carries `/// @tla-inv <Inv_|Prop_>`.
- **Checker.** `directory_seat/scripts/trace_check.py` matches both directions and writes `TRACE.md`. It fails when:
  - an action in `Next` has no tag;
  - an `impl=` target has no annotated fn, or that fn names something else;
  - a guarded fn carries no annotation, or an opt-out gives no reason;
  - a fn names an action the model lacks, or claims two names;
  - a property is not checked by the main config;
  - a property has no witnessing test.
- **Self-test.** `directory_seat/scripts/trace_check_selftest.sh` plants seven drifts and requires the checker to catch each one
  (7/7 caught).
- **CI gate** (proposal, the pattern of `CIRISConstitution/formal/ceremony/run_tlc.sh`): on any PR touching `directory_seat/tla/` or a
  guarded module, run (1) `trace_check.py`, (2) `trace_check_selftest.sh`, (3) `directory_seat/tla/run_tlc.sh` (the main config closes;
  every twin fails on its named property), (4) `cargo test`. Steps 1-2 take seconds and need no Java. Step 3 needs
  `tla2tools.jar` 1.7.4 (the same pin the constitution's CI uses).
- **What it does not prove.** It proves that names correspond, not that bodies refine the actions. The next step is
  trace validation: log `(action, pre, post)` from the Rust tests and replay them against the spec with TLC.

## 6. Files and how to re-run

- `FSD/DIRECTORY_SEAT.md`: this document.
- `FSD/directory_seat/tla/`: the model, eight configurations, `run_tlc.sh`, and the recorded results.
- `FSD/directory_seat/src/`: the sketch (`lib.rs`, `seat.rs`, `client.rs`). It is not a workspace crate and is not built.
- `FSD/directory_seat/scripts/`: the traceability checker and its self-test. The checker writes `TRACE.md` beside them.

Re-run the checks:

```
python3 FSD/directory_seat/scripts/trace_check.py FSD/directory_seat
bash FSD/directory_seat/scripts/trace_check_selftest.sh
bash FSD/directory_seat/tla/run_tlc.sh /path/to/tla2tools.jar   # tla2tools 1.7.4, the constitution CI's pin
```

## 7. Decisions needed (open questions for Eric)

1. **Q1 Onion relay.** CC 5.4.6 forbids a serve node to opt out of onion relaying (`seat_opted_out`,
   `seat_without_hop_key`). Should a directory seat be a distinct conferral (a "directory" role in the bundle's
   `serve_nodes`) that the relay duty does not bind? Or must the seat relay?
2. **Q2 Shaping.** CC 5.4.3 says a node never refuses a shaped link to a peer that asks. Is the seat exempt? Recommended:
   exempt, with fixed-size padding (3.1), and shaped-only peers sent to a shaped proxy.
3. **Q3 Replicas.** Are N replicas N seats in the bundle (each with its own key and transit pair), or one seat whose
   custody is shared? The first keeps custody simple. The second keeps the bundle small.
4. **Q4 HTTP registration.** May a node register over HTTP before it can seal? CC 5.3.3.10 E1 has no classical lane for
   content. Registration rows are public, but HTTP exposes the registrant's IP to the seat.
5. **Q5 Flood bound.** Is a per-link or per-window stranger budget (edge's `first_contact.rs` quotas) allowed under
   "no rate machinery"? Without one, a swarm of minted keys fills `held` until `valid_until`. CC 5.4.6 (part_5:1175)
   already concedes first contact under a flood.
6. **Q6 Wire and rules without the runtimes.** Edge has no wire-only crate, and persist owns the row rules. Should we
   extract a `ciris-wire` (CRPL frames and bootstrap planes) from edge, and an engine-free `admit_key_record` /
   `admit_transport_destination` from persist (or move them into verify)? Copying either one is the mirrored-rule class.
7. **Q7 Accord rows and revocations.** Should they be in the seat's state (E6), so that a halt reaches a node that talks
   only to a seat? The model leaves them out.
8. **Q8 What the full canonical becomes.** Does Eric's current canonical keep running as an ordinary relay-offering
   server homed on the directory seat, or is it retired at the edition-2 genesis?
