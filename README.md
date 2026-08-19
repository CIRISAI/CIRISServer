# `ciris-server` — the fabric node

**The node of the CIRIS Epistemic Web ([CEWP](https://ciris.ai/cewp)).** One
Rust crate that composes the federation's cores — `ciris-persist` (corpus +
admission), `ciris-edge` (transport + replication), `ciris-verify` (hybrid
post-quantum crypto) — into a runnable federation node, shipped as the headless
`ciris-server` binary **and** the PyO3 abi3 wheel a
[CIRISAgent](https://github.com/CIRISAI/CIRISAgent) embeds. The defining
identity: **`agent = fabric node + brain`** — the same composition folds into an
agent; packaged alone it attests, stores, replicates, scores, and serves, but it
does **not** reason, decide, or act. Infrastructure must not have agency.

Server is built on two disciplines: **the API never touches the runtime — it
writes CEG, and the runtime is CEG-driven** (every control surface authors a
signed claim; controller loops converge the live node to the corpus, hot, no
restart), and **zero environment variables** — a node's entire configuration is
signed `config:*` CEG resolved at boot (`--home` + key identity, nothing else).
The fabric IS the config, the same way the agent IS its graph.

> **🌐 Rendered: [cirisai.github.io/CIRISServer](https://cirisai.github.io/CIRISServer/)** ·
> siblings: [CIRISPersist](https://cirisai.github.io/CIRISPersist/) ·
> [CIRISEdge](https://cirisai.github.io/CIRISEdge/)

> **📖 The model: [`FSD/CEG_REPLICATION_MODEL.md`](FSD/CEG_REPLICATION_MODEL.md)** —
> the 3-gate replication model, the 14 EnvelopeKinds carrying all 95 CC-3.1
> claim families, and the classical-edge audit. The per-family card/vocabulary
> manifest lives in [`FSD/NAMESPACE_SUPERSETS.md`](FSD/NAMESPACE_SUPERSETS.md)
> (versioned; regenerated against pinned constitution + registry revs). Start there.

## What ciris-server does

```
rich clients (KMP app · CIRISAgent · status)          ┌─ owner ops: claim (NodeCode+PIN),
    │ consume the control surface                     │  consent grants, config:*, trust roots
    ▼                                                 │
ciris-server ── writes CEG ── controller loops ───────┤  reconcile: consent topology → live
    │  compose · identity · owner-binding · scorer    │  replication peers (4 planes/peer),
    ▼  safety (age·moderation·watchlist) · genesis    │  config re-resolve, announce rooting
ciris-edge ──── anti-entropy over Reticulum/HTTPS ────┘
    ▼
ciris-persist ── keys · attestations · trace · admission (Registry-of-Record)
```

One identity per node, **by construction** — `cfg.key_id` derives from the
engine's own signing identity, so every plane (claim, NodeCode, owned-nodes,
self-publish, edge signer) agrees on who this node is. Library composition, not
sidecars: the agent links the same wheel instead of assembling cores itself.

## What this is, relative to its siblings

The three cores are **libraries that decide**. Server is **the node that answers
for those decisions to a person.**

| | Decides | Has an operator? |
|---|---|---|
| `ciris-verify` | whether evidence about a machine, build or key is worth believing | no — embedded |
| `ciris-persist` | which claims are allowed to become state | no — embedded |
| `ciris-edge` | who is allowed to learn a claim exists | no — embedded |
| **`ciris-server`** | **nothing, on its own** — it composes the three, runs the loops, and exposes every decision to a human who is accountable for it | **yes** |

That last row is the whole job. A library refuses; a node has to *say why*, keep
running afterwards, and give somebody a way to respond. Everything distinctive
here follows from having an operator: the graded ladder instead of a boolean,
the surfaces that state what an op does **not** reach, the insistence that a
zero name its cause. Persist can return `Err`; a node has to render that to a
tired human at 2am who then does something irreversible.

## What we uniquely claim to solve

The siblings do nothing on their own. They are libraries: verify decides whether
evidence is believable, persist decides what becomes state, edge decides who may
learn a claim exists — and none of them runs, holds a corpus, or answers to
anyone. **Server makes the net-claims for the mesh.** It is the thing with an
operator, a running loop, and a row it will defend.

So the claim is not "signed claims" or "post-quantum" or "consent-based routing".
Those have prior art and the section below says so. It is this:

> **A decentralized mesh that is manageable and moderatable *at scale*, with no
> privileged party anywhere in the path. We posit that the ALM tree plus a
> CEG-native operator surface is what makes those two compatible.**

Pick any two of {scale, decentralization, moderation} and there is prior art.
All three is the open problem:

- **A CDN scales and is moderatable — because it is privileged.** Someone owns
  the middle, sees the traffic, and can be compelled. That is the property being
  refused here.
- **A flat P2P mesh is decentralized but does not scale.** Everyone-to-everyone
  at 720p30 caps around **13 participants** on a home uplink; the bandwidth is
  N², and no amount of protocol fixes that.
- **Most decentralized systems that do scale gave up moderation** to get there,
  and then discovered the commons was the product.

**ALM is the scale half.** One sealed copy enters a tree of relays; per-node
fan-out is bounded by *measured* uplink, depth is O(log_f N). At f≈12 and
N=2,000 that is four tiers — 2000 → 167 → 14 → 2 → root — deterministic,
leaderless, primary plus two backup parents, healing when a subtree goes dark.
Each hop opens the inbound per-link AEAD and re-seals for its downstream link
**without ever touching the epoch DEK**, so a relay carries payload it cannot
read. That last part is not a design intention: `tests/alm_chain.rs` recovers the
publisher's plaintext byte-identical at the viewer after an arbitrary number of
relay hops, and it is a gate.

**The operator surfaces are the moderation half.** Because no relay is
privileged, every hop is just another node — with an owner, a consent edge, and
the same graded ladder as any peer. Moderation is not applied *to* the tree from
outside it; it is available at every point *in* it, by authoring claims other
nodes may fold. That is why the ladder states what each op does not reach, and
why the commons resolves by reverse quorum rather than by an admin: **there is
no seat to appeal to, so the mechanism has to work without one.**

The honest status: the E2E-through-N-hops property is **proven and gated**; the
2,000-participant topology is **modelled** from measured per-core egress and is
not yet run at that size; and the claim that this composition *solves*
manageable-and-moderatable-at-scale is a **posit** we are building to, not a
result we are reporting.

## Near peers, and where the resemblance stops

Server is a **federated node you run and are responsible for**, so its nearest
relatives are the other things shaped like that. Each gets one honest sentence
and one real difference.

- **Matrix homeserver** (Synapse/Dendrite) — the closest operational analogue:
  you run one, identities belong to it, it federates with peers you do not
  control. The difference is where authority lives. Matrix federates *events*
  and trusts *servers*; CIRIS federates *claims* whose admission is decided
  per-row from the signature and the consent edge, so **a server has no
  authority its rows do not carry.** A compromised homeserver speaks for its
  users; a compromised CIRIS node can only replay rows that already verify.
- **Bluesky PDS** — closest on "your data lives on a host you can leave", and
  the account-portability instinct is the same one. But a PDS is a repo host
  whose network authority sits downstream in relays and AppViews; here the
  admission decision is *in the node*, and there is no privileged aggregator to
  be the exception.
- **Nostr relay** — closest on "store and forward signed events, verify the
  signature, hold no opinion". That last part is the split: a relay's virtue is
  having no policy, and a CIRIS node's entire contribution is **typed refusal** —
  a `put` that says which delegated scope was missing, so the emitter can fix it.
- **Certificate Transparency log** — closest on append-only, self-proving state,
  and the lineage is real. CT proves *inclusion*; CIRIS additionally has to
  prove **authority to include**, which is why admission is the API rather than
  a layer above it.
- **Syncthing / IPFS** — closest on replication driven by a topology rather than
  a server. They move bytes because someone asked; CIRIS moves a row because a
  **consent edge says a peer may hold it**, and revoking the consent stops the
  flow with no other coordination. Consent is not a permission check in front of
  replication — it *is* the routing table.
- **Tor directory authority / CA quorum** — closest on multi-party control of a
  root. Ours is deliberately a **keyless family**: one holder roots only to
  itself, a quorum roots to `humanity-accord`, and every attestation carries its
  own m-of-n into the graph, so a replicated row proves its quorum rather than
  deferring to the bundle it arrived in.

The through-line: most of these move **content** and add authority as a layer.
This moves **claims**, where the authority is part of the record and the routing
is the consent graph. That is also why the operator surfaces exist — when
authority is in the data, governing the mesh means authoring claims, not
flipping flags, and a human needs somewhere to do that.

## Joining the mesh — the two rules

Anyone can stand up a server and contribute capability. Two rules govern what
you get back. Both are worth reading before you deploy.

### 1. Announce, or you get nothing

**A node that does not announce gets no service access on the mesh and no agent
services.** This is not a throttle or a penalty tier — it is the floor.

The reason is the kill switch. The accord's halt is only meaningful against a
node it can *reach*; an unreachable node cannot be stopped, so it is never
served in the first place. Every canonical record carries both halves for
exactly this reason: its **trust** (the `canonical` role) and its
**reachability** (the signed envelope transport hint). Baking canonical records
was gated on the kill switch being enforceable *first*.

So reachability is not an operational detail here. It is the price of admission,
and it is charged up front.

### 2. There are TWO consents, and they are different edges

|  | grant | what it permits |
|---|---|---|
| **send traces** | `consent:replication:v1` | a peer may **hold** your traces |
| **be scored** | `consent:state:granted:v1`, scope `analyze` | a peer may **score** them |

Authoring one implies **nothing** about the other. They are distinct CEG objects
on opposite edge directions, separately withdrawable. `capacity:*` claims about
you are refused unless a live `analyze` consent from you covers the attester, in
*that attester's own corpus* (CIRISConstitution#46).

**You may send traces without consenting to be analyzed.** That is a legitimate
choice and traces will flow. What it costs:

1. **You build no reputation.** Every `capacity:*` claim about you is refused, so
   none can ever exist.
2. **You cannot use streams or services that require third-party capability
   attestations** — you will not have any.
3. **Some peers may refuse to interact with you at all.**

Being scored is normally *why* the traces are sent. If that is your intent, both
grants are required — say so explicitly, because neither is implied.

> Measured on the production canonical, 2026-08-01: **240** replication grants
> replicated in from **240 distinct** peers, and **zero** `analyze` grants
> mesh-wide. Until 0.5.151 the in-fold consent path could not author the second
> grant under any argument, so every one of those nodes reached rule 2's degraded
> state by silence rather than by choice.

## Read in this order

1. **[`MISSION.md`](MISSION.md)** — the WHY. M-1 (sustainable adaptive coherence),
   the fabric-node discipline, de-singletonized infrastructure, the stewardship
   covenant ("the work belongs to whoever keeps it running").
2. **[`FSD/CEG_REPLICATION_MODEL.md`](FSD/CEG_REPLICATION_MODEL.md)** — how state
   moves: every flow gated by a verified signed claim; no copies, no outboxes.
3. **[`FSD/THREAT_MODEL.md`](FSD/THREAT_MODEL.md)** — "ingest is open and cheap;
   admission is the gate." **[`FSD/TRUST_ROOT_CAPABILITY_GATE.md`](FSD/TRUST_ROOT_CAPABILITY_GATE.md)** —
   how `infra:serve` / `infra:attest` are conferred and why no root ⇒ no capability.
4. **[`FSD/SERVER_1.0_PLAN.md`](FSD/SERVER_1.0_PLAN.md)** — the build plan on the
   agent train (0.5 config-as-CEG → 0.6 +registry → 1.0 +node consensus).

## The shape of the node (one-paragraph tour)

A node boots from the **baked genesis** — the canonical seed minted in a human
co-scrub ceremony ships inside persist, so a fresh node starts **already rooted
to a real trust root** — and resolves its config from signed `config:*` claims.
An owner **claims** it (NodeCode + one-time PIN); ownership is an
**owner-binding** (`delegates_to` + identity occurrence + cohort scope), never
an auth role. The owner authors **`consent:replication:v1` grants** through the
API — and those consent objects **ARE the replication topology**: a reconciler
loop converges the live runtime to them (four anti-entropy planes per consented
peer — Attestation, Key, IdentityOccurrence, TransportDestination), adds
becoming active initiators at runtime, revocations stopping cold, no restart.
Payloads follow the consent edge: promotion inherits the grant's full audience
(tier **and** cohort scope). Serving is capability-gated — a canonical is, by
definition, a node whose record carries accord-conferred
`infra:serve`+`infra:attest` roles rooted to a root this node trusts: **being a
server IS the consent to serve**. Consumer policy stays constitutional at
runtime too (CC 4.1.4: a consent peer that turns `withdraws`-arbitrager is
refused per-tick, and re-admitted when it mends). The scorer folds inbound
traces into `capacity:*` attestations; the safety surfaces (age assurance,
moderation, watchlist) emit their own signed, federation-visible claims. All of
it hybrid Ed25519 + ML-DSA-65, and the replication/serve policy manifests are
**drift-witnessed** — hash-pinned by gate tests that fail the build if policy
moves without a deliberate cut.

## Governing the node (the operator surfaces)

A mesh you cannot see is a mesh you cannot run, and a control you cannot reach
is not a control. Four signed surfaces make the node legible and steerable, and
all four are CEG all the way down — every act authors a claim:

| Surface | What it answers |
|---|---|
| **`/v1/node/state`** | Is this node alive, and is anything *arriving*? Trace-plane liveness banded green/yellow/red, refusal rate read as its own condition, edge carriage and receive folded in |
| **`/v1/admin/*`** | The graded enforcement ladder — annotate, throttle, quarantine, descend, de-admit, plus **tier S** (shed / stop accepting / declare legal compulsion: the only rung that works under partition) and **tier R** (this reader's own accept-or-decline policy) |
| **`/v1/commons/*`** | Reverse quorum: **one** objection raises a brake, **m-of-n** lifts it, and silence past the steward deadline escalates to a quorum of *respondents rather than roster* — which is what lets a quiet community still resolve |
| **`/v1/mesh-config`** | What a subscribed trust root has set, folded most-restrictive across roots, with a TTL that expires without anyone filing anything |

Two rules run through all of it. **An op says what it does *not* reach**, in the
response, before you commit: quarantine is a marker and deletes nothing;
de-admission is evidence a reader folds, not a door that slams; descent is
irreversible and never terminates at zero. And **a zero always names its
cause** — "we could not ask", "we asked and there is nothing", and "nothing has
ever been recorded" are three different facts, and collapsing them is how a
trace plane stayed dark for two days with every layer individually correct
([`FSD/RCA_INGEST_REJECTION_2026-08-05.md`](FSD/RCA_INGEST_REJECTION_2026-08-05.md)).

That second rule is the discipline this repo contributes to the triple. Persist
has admission gates, edge has fail-secure routing, verify has attestation
chains; server's is that **an instrument must be shown able to fail, and a
reading must name what it could not see.** Every gate here is mutation-verified
— broken deliberately, observed red, restored — because a check that has never
failed is not evidence, and this codebase has now found checks that could not
fail, that failed correctly and unread, that were never run on the broken tree,
that fired when nothing was wrong, and that reported success without running.

## A node *and* a client

`ciris-server` renders no UI; it exposes the full control surface, and rich
clients consume it. The vendored [`client/`](client/) — the same
Kotlin-Multiplatform app as CIRISAgent's, minus the agent (brain) cards — mints
hardware-rooted federation IDs (YubiKey / TPM / Secure Enclave, software
fallback), claims nodes, manages trust roots and consent objects, and renders
every surface above: node liveness, the enforcement ladder, tiers S and R, the
commons, and the mesh-config plane, in 29 languages.

The client renders the *distinctions*, not just the values. An unreadable
reading prints no instant and no row count, because both would be inventions.
An unrecognised token from a newer server reads "uncomputed", never green.
Raising a brake is one button; lifting one is a ceremony whose submit stays
disabled until a dry run has produced the bytes co-signatures must cover — the
UI shape mirrors the substrate's asymmetry rather than flattening it into a
vote. Declining to honour a judgement renders as the ordinary outcome it is.
Headless works too:

```sh
pip install ciris-server        # the abi3 wheel (or: cargo build --release)
ciris-server                    # boots a zero-setup node; unclaimed → prints NodeCode + claim PIN
ciris-server identity create --backend pkcs11   # YubiKey-backed CIRIS-V2- fedcode
```

Data under `$CIRIS_HOME`, SQLite corpus (Postgres via config), Reticulum
transport up by default. The same wheel is CIRISAgent's substrate: one PyO3
registry, one shared engine, one edge runtime.

## Status

**v0.5.x — the CEG-native node, rooted, and carrying live traffic.**
Config-as-CEG shipped (zero env vars, owner-authored, hot-reconciled). The
federation trace arc is proven end to end across the substrate triple — seal →
consent → converge → bootstrap → root → heal → publish → transfer → admit →
attribute → serve — with each gate named, logged, and regression-pinned (the
#315 saga). One-node-identity closed by construction (0.5.138).

**Traces are flowing on the production mesh (2026-07-31).** A real agent's
signed traces now reach the canonical over Reticulum and materialize into its
corpus — sealed on one node, consented, replicated, attributed, and admitted on
another, with no HTTP anywhere in the path. The trace is a CEG object that
replicates because consent and trust say it may; nothing pushes it.

**Both trace paths are proven, and scoring closed the loop.** HTTP ingest and
the peer anti-entropy round each carry `trace:*` end to end, gated separately so
the working half can never vouch for the other. The scorer folds inbound traces
into `capacity:*` with day-bucket coalescing — measured in production at 900
rows/day down to 21, holding — and refuses to score a subject that has not
granted `analyze`, which is a different edge from the grant that lets a peer
merely hold the trace.

**The production trust root is minted and baked (2026-07-31).** A hardware
ceremony on three YubiKeys produced the genesis bundle persist now ships as
`canonical_seed.json`, so every node boots rooted with no operator step. The
root is the **keyless family, not a seat**: one holder alone roots only to
itself, while a quorum roots to `humanity-accord`. The charter is 2-of-2 over a
3-seat roster, and every genesis attestation carries its quorum *into the graph*
— a replicated row proves its own m-of-n rather than deferring to the bundle it
arrived in. Two humans to halt, two to legitimize.

Substrate pins: **persist v37.1.0 / edge v18.0.2 / verify v13.6.1** — hybrid PQ
throughout, Registry-of-Record admission, drift-witnessed policy hashes. Edge
v15.7.x adds the realtime A/V spine (MLS X-Wing epoch keys, signed Welcome,
fragment ARQ); the server exercises publisher → relay → subscriber
glass-to-glass against the public API from outside the crate, so the surface is
proven consumable rather than only internally green.

`ciris-lens-core` is absorbed in-tree
([`crates/ciris-lens-core`](crates/ciris-lens-core)); the standalone lens
deployment is retired — a central dashboard the whole federation reads is
itself the singleton this architecture forbids.

Roadmap (the CIRISAgent train): **0.5** config-as-CEG (here) → **0.6**
+registry authority → **1.0** +node consensus, the complete fabric node.

## Sister repos

- [`CIRISConstitution`](https://github.com/CIRISAI/CIRISConstitution) — the
  canonical CEG spec; Part 3's namespace registry is vendored and hash-pinned
  into persist.
- [`CIRISPersist`](https://github.com/CIRISAI/CIRISPersist)
  ([site](https://cirisai.github.io/CIRISPersist/)) — substrate: keys,
  attestations, trace, admission; ships the baked genesis seed. *Decides which
  claims become state.*
- [`CIRISEdge`](https://github.com/CIRISAI/CIRISEdge)
  ([site](https://cirisai.github.io/CIRISEdge/)) — transport + replication: the
  14 kinds over Reticulum/HTTPS/packet-radio; consent *is* routing. *Decides who
  may learn a claim exists.*
- [`CIRISVerify`](https://github.com/CIRISAI/CIRISVerify) — hybrid crypto
  primitives (Ed25519 + ML-DSA-65, X-Wing), consumed via persist. *Decides
  whether evidence about a machine, build or key is worth believing.*
- [`CIRISAgent`](https://github.com/CIRISAI/CIRISAgent) — the brain; embeds this
  node via the one wheel and emits the signed traces it federates.

## License

[AGPL-3.0-or-later](LICENSE) — matching the CIRIS ecosystem.
