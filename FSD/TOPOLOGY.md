# TOPOLOGY — the trust topology a use case requires, from the root(s) down

**Owner:** CIRISServer (the state lives here). **Consumers:** CIRISClient's CSD/4
`topology:` block, `harness/native build`, the CSD checker.

## 1. Why this exists

A CSD/3 states what a screen shows and which routes it reads. It does not state
who must exist, in what trust relation, for those states to be reachable. The
first day of the native harness (2026-09-29) found five faults, each in a
different layer of that unstated structure: a pair never Rooted (root layer),
`reachable_nodes=0` at contact time (owner-binding layer, CIRISServer#699), a
body that could not cross two relay hops (transport layer, CC 5.4.6), a
multi-fragment frame that never left a direct link (CIRISEdge#716), a chunk-DAG
served as its manifest (content layer, CIRISEdge#717). A fixture cannot be
derived from prose, and a red cannot be placed by it. So each use case declares
its topology in this vocabulary, the checker verifies it is realizable, and the
harness builds exactly it.

The vocabulary is ordered by dependency. Nothing in a lower layer can hold
unless the layer above it holds; a failed run names the first layer whose
predicate did not.

## 2. The layers

```yaml
topology:
  roots:        # 1. CC 3.2 — the same parameters as CIRISConstitution formal/trust_root/TrustRootVerdict.cfg
  canonicals:   # 2. the nodes that HOLD a root (charter, capability grant, trust edge)
  nodes:        # 3. every node, what it dials, which root it accepts, whether it announced
  persons:      # 4. owners: which nodes they own, which root THEY accept (the pair fact needs the owner)
  relations:    # 5. peering, rooting, reachability, contacts, rooms, grants, messages, files — in build order
  actor:        # 6. whose screen the flow drives
  negatives:    # what must NOT be true, by name
```

### 2.1 `roots`

| field | values | meaning |
|---|---|---|
| `id` | name | referenced by `holds` / `accepts` |
| `kind` | `key` \| `family` | a single holder key, or an accord family (founders, quorum) |
| `holders` | int | key roots: holder keys |
| `founders` | `{n, human, node_bearing}` | family roots (TLC: `Founders`, `NodeKeys`) |
| `quorum` | int | M of `quorum:M/N` (TLC: `M`) |
| `witnesses` | `{n, k, independent_custody}` | rc6 heads (TLC: `Witnesses`, `K`) |
| `lifecycle` | `active` \| `stalled` \| `halted` | the T8 state under test (T7 stalled = attached pairs stay rooted, new members refused) |
| `custody` | `software_test` \| `hardware` | what the anchor mints vs what a CSD reading holder evidence needs |

**Buildable today:** one `key` root, one holder, `software_test`, `active` — the
synthetic anchor (`test_bless`: `test-accord-holder-0`, charter root→root,
capability grant root→node, trust edge node→root). A `family` root, more than
one holder, `stalled`/`halted`, or `hardware` is declared and REFUSED by the
builder by name until the ceremony can mint it; the declaration stays true.

### 2.2 `canonicals`

`{id, holds: <root>, serves: [infra:serve, infra:attest]}`. A canonical is a
node that holds the root; every other node dials at least one. The synthetic
anchor blesses exactly the nodes the builder tells it to.

### 2.3 `nodes`

`{id, dials: [<node ids>], accepts: <root>, announced: bool}`.

`dials` is the transport topology and it is load-bearing: scoped content (chat
bodies, files) reaches DIRECTLY-ATTACHED peers only (CC 5.4.6, CIRISEdge#499).
Two nodes that reach each other only through a canonical key a room but never
exchange a body. A node that dials another is its direct neighbour; on that
link, today, multi-fragment frames stall (CIRISEdge#716).

### 2.4 `persons`

`{id, owns: [<node ids>], accepts: <root>}`. The first owned node is claimed
with a freshly minted identity; further owned nodes are that person's other
DEVICES (the owner's key material carried, then claimed — what
`POST /v1/self/associate` does with a portable keyset). `accepts` on the PERSON
is the acceptance `rooted_with` walks (CIRISEdge#659, CIRISServer#632): a node
that accepted a root whose owner did not is Attributed, never Rooted.

### 2.5 `relations` (build order)

| relation | builds / checks |
|---|---|
| `peered(A, B, prefixes?)` | production peering both ways: `GET /v1/federation/self-key-record` + `POST /v1/federation/peering` |
| `rooted_with(p, q)` | edge's pair verdict from the log (`rooted_with: a valid root in common`); `require: true` waits, else observed and recorded |
| `reachable(A, q) >= n` | `POST /v1/contacts` on A for q reports `reachable_nodes >= n` (q's owner→node binding held on A at federation scope); the gate CIRISServer#699 needs |
| `contact(p, q, via: owner\|code)` | p adds q by owner key or by q's contact code (`GET /v1/self/contact-code`) |
| `room(pair\|self, members, keyed: true, epoch?)` | the pair room opened on both sides and keyed; the self room joined by every device |
| `message(from, to, room)` | sent by `from`; the row AND its body on `to`'s node |
| `file(person, device, size, cohort)` | written on `device`; byte-identical on every other device of `person` |
| `member(p, community, role)`, `quorum_change(...)` | declared; builder refuses until the community/household scenarios exist |

### 2.6 `actor` and `negatives`

`actor: {person, device}` names the screen the client flow drives; the
builder's `values.json` is written from its point of view (the client
fixture's `${PEER_KEY_ID}`, `${ROOM_ID}`, `${MESSAGE_ATTESTATION_ID}`, …).

`negatives` are checked last: `cannot_list_room(p, room)`,
`holds_no_row(node, dimension_prefix, person)`.

## 3. Realizability rules (the checker refuses, by name)

1. `quorum: M` needs `founders.n >= M + 1` (one over and one under the line);
   a witnessed head needs `witnesses.n >= 2K - 1` and `independent_custody`.
2. A person `accepts` a root only if every node they own `accepts` it.
3. `rooted_with(p, q)` needs both persons to `accept` a common root.
4. `message`/`file` between two persons needs their devices to be direct
   neighbours (`dials`) or a relay-routable scoped address (none exists).
5. `reachable(A, q)` needs one of q's nodes `announced: true`.
6. `contact(p, q, via: code)` needs q's node `announced` (the code names
   announced devices) and the route (0.5.218+).
7. Everything in `roots` must be within what the ceremony mints today, or the
   declaration is `buildable: false` and says which field.

## 4. Derivations

`nodes = |nodes| + |canonicals|`; `persons = |persons|`; `devices(p) =
|p.owns|`; the root ceremony from `roots`; the build order from the layers. A
flow may not advance to `testable` while its fixture's topology is smaller than
its CSD's on any layer.

## 5. The proving set

`harness/native/topologies/csd-091-user-chat.yaml`,
`csd-092-share-contact-code.yaml`, `csd-093-second-device.yaml` — the three
0.5.218 flows. `python -m harness.native build --topology <file> --binary <test-anchor ciris-server>`.
