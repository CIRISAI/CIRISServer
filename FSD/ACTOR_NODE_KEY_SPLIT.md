# The actor/node key split — which key does what, and why

CC **3.4.7.3** (CIRISConstitution#95, rc4.5) forbids `node` cohabiting with
`agent` or `user` on one key. This document is the mechanism: which identity
signs what, what moves during migration, and the one prior failure the move must
not re-earn.

Substrate: persist **v38.6.0**, edge **v18.9.0**.

---

## The defect this closes

A node's substrate identity was whatever key the host handed it. Standalone that
is `node`-typed and correct. In the **embedded fold** it is CIRISAgent's own
bootstrap key, `identity_type = agent`, and one key answered two questions:

```
key_id         ciris-agent-bootstrap-mplbdbzbed
identity_type  agent
self_key_id=ciris-agent-bootstrap-mplbdbzbed
Reticulum transport identity: … key_id=ciris-agent-bootstrap-mplbdbzbed
```

`compose::register_self_key` asserts `identity_type = node` for that id and
**cannot make it true**: persist refuses with a typed `Conflict`, and we mapped
that Conflict to `Ok(())` at debug under a comment calling it benign. Benign is
right for re-registering an identical trust-root row. It is exactly wrong when
the differing row says `agent` — which is how a node ran for months on the
brain's key with every gate green.

**Not fixable by adding `node` to that key's role set.** persist's agency gate
constrains a recipient resolving to a **node-only** identity, so a `{node,agent}`
hybrid passes it. Fusing does not blur "infrastructure must not have agency" —
it switches it off. That is why Clause A exists and why the cure is a second KEY.

---

## Three keys, three jobs

| key | alias | `identity_type` | signs |
|---|---|---|---|
| **actor** (host-supplied) | `<alias>` | `agent` / `user` | authorship: traces, attestations, `on_behalf_of` |
| **node** | `<alias>-node` | `node` | carriage: transport, replication, consent, de-admission |
| **substrate** | `<alias>-substrate` | `substrate_persist` | reserved prefixes (`content_class:*`) |

All three are registered in `federation_keys`. Registration is what makes a
signature verifiable at a peer — an unregistered attester is refused
`attesting_key_id … does not exist in federation_keys`, which is the 3,404-refusal
storm observed on `datum-j7xp3i7quf`.

The `<alias>-substrate` key is the precedent, not a new idea: this repo already
mints a second key rather than adding a second role, for the same reason —
**one authority per key**.

### Lightnet / darknet

The public/gated split is **per envelope kind**, not per key
(`edge::replication::serve_policy`):

```
Key | IdentityOccurrence | TransportDestination   → serve: public
Family | Community | LocationProof                → serve: public
the four revocation planes                        → serve: public
Organization | OrgMembership | PartnerRecord      → serve: public

Attestation → "trace:* → capability:infra:serve; else public"
```

> *E3: the trace plane is the **sole** capability-gated serve path.*

So almost everything is lightnet. The darknet is `trace:*`, gated on
`capability:infra:serve`, plus consent deciding **which peers** a round runs with.

This is why the transport identity must be the node key specifically:

1. **The lightnet door.** `is_bootstrap()` = `Key | IdentityOccurrence |
   TransportDestination` is exempt from `Rooted ∧ owns_key` and attributed via the
   link's transport identity. Whatever key walks through it is publicly visible to
   anyone on the interface.
2. **The darknet gate.** `Rooted ∧ owns_key` (#393 item 1) plus a hybrid-verified
   `SignedTransportDestination` binding `(peer, dest)` (item 2), both resolved
   against the transport identity.
3. **De-admission.** `arm_peer_deadmission_gate` compares writers to
   `self_key_id()`.

Under the fused key an agency-bearing identity did the lightnet's most public
work — and satisfied a gate keyed on `capability:infra:serve`, an `infra:*` scope
a node key may hold and an actor key may not. **The gate passed for the wrong
reason.**

---

## The brain never chooses

`attest::KeySigner::{Engine, Local}` already selects a signer at the one door
that mints a row. The selection is **ours**, made by which route the request
arrived on:

- brain-facing routes → the **actor** signer
- infra paths → the **node** signer

CIRISAgent keeps passing the key it always passed. We stop treating it as the
node and start treating it as the actor. **No change is required on the agent
side**, and no wire field or localized string changes, so the client is unaffected.

---

## The #312 constraint — the failure this must not re-earn

`compose.rs` collapses three roles into one identity, deliberately:

> *`node_key_id` is the local federation signing key (the consent AUTHOR, the KERI
> publish-own selector, and the trace-gate leg-B "I"): BOTH callers pass
> `edge.signer_key_id()`. … reading consent by the alias yields an empty topology
> from a corpus whose grants the signer wrote (the #312 field failure).*

The observed failure was **zero peers and zero envelopes under a fully green
transport** — a silent withhold, not an error.

So the three roles move **together**, and all three are carriage:

| role | goes to | because |
|---|---|---|
| consent author (`consent:replication:v1`) | node | replication topology is carriage |
| publish-own self (`SignedTransportDestination`) | node | it *is* the transport binding |
| trace-gate "I" (`Rooted ∧ owns_key`, `infra:serve`) | node | `infra:serve` is node-holdable; on an actor key it is the CC violation |

**Grants authored by the actor key become unreadable the moment the node reads as
NodeID.** That is #312 exactly. The migration therefore re-authors them.

### Consent moves WITHOUT an engine swap — the substrate signs with either

An earlier draft staged consent behind an engine-signer swap, on the reading that
a grant can only be self-attested by the engine. Half right: it must be
self-attested, and the engine is not the only key we hold.

`emit_replication_consent` defaults to `emit_attestation_self` — the engine's own
signer — which is correct for every ordinary caller. `ConsentGrantOptions::author_signer`
supplies a key we hold instead, and the row is stamped, signed and put through
the same door (`attest::Emit` → `KeySigner::Local` → `attest::put`) that
`build_signed_owner_binding` already uses. **Self-attestation is preserved: the
signature really is the named author's.** What is refused is signing *silently*
as someone else.

That matters because the embedded fold cannot swap engines at all —
CIRISServer#221 is explicit that there is one pool, one sweeper, no second
writer, and `serve_with_adapter` folds onto `current_rust_engine()` rather than
building one. A design requiring the engine to become the node key would have
been undeliverable there, which is the case that actually needs it.

The invariant was also documented and unchecked, which the TDD pass surfaced as a
live defect: any mismatched `node_key_id` SUCCEEDED and produced a grant authored
by the engine —

```
emit(node_key_id = NODE) -> Ok
read as NODE   -> []
read as ENGINE -> [peer]
```

— zero peers under a green transport, the #312 shape, reachable by a
one-argument mistake, and the same "quietly downgraded rather than refused" class
as the phantom `[node]` extra and the `Conflict`-at-debug. `emit_grant_row` now
refuses a mismatch unless a signer for the named author is supplied.

The owner-binding moves the same way, and the asymmetry is principled:
`build_signed_owner_binding` takes an explicit signer because an owner-binding is
authored BY THE OWNER about a node; a consent grant is authored BY THE GRANTING
PARTY about itself — so the grant's signer must BE the author, and is checked.

---

## Migration — unattended, at boot

Installing the app **is** claiming ownership, so a claimed node holds its owner's
fed-ID and no operator step exists. In order:

1. **Classify** the configured key (`node_key::classify`).
2. `SubstrateOnly` / `Unregistered` ⇒ **stop.** Standalone CIRISServer is unchanged.
3. `Actor` / `Fused` ⇒ mint + register `<alias>-node` as `identity_type = node`.
4. **Move the owner-binding** onto the node key — same owner, same `infra:*`
   scopes, same cohort. Refuses if this node holds a signer for anyone other than
   the actor key's owner.
5. **Re-author consent** as the node, using the node's own signer. Same peers,
   same prefixes, a new author — and the engine keeps signing as the actor, so the
   embedded fold keeps its one engine.

Every step is idempotent: a re-boot after a successful migration writes nothing.

### Fail-closed, deliberately

A failure at 4 or 5 leaves the node **unowned or unpeered**, and that is correct.
CC 3.4.7.3 Clause D is fail-closed — `owner_of` unresolved is a refusal, never an
unknown that reads as permission. The errors propagate rather than being logged
and swallowed, because logged-and-swallowed is the exact shape
(`Conflict` at debug) that produced the original defect.

### No ordering constraint against peers

`Key`, `IdentityOccurrence` and `TransportDestination` are `is_bootstrap()` kinds,
exempt from `Rooted ∧ owns_key` and verified at persist admission. The carve-out
(CIRISEdge#402) exists to break exactly this deadlock: *"a fresh peer is
`UnknownKeyId` until its `Key` is admitted, but the `Key` frame is what admits
it."* A freshly-minted node key KEXes and is admitted with no pre-registration.

---

## What is verified, and where

| claim | proof |
|---|---|
| re-registering an actor key as `node` is refused, row unchanged | `tests/node_key_is_not_the_actor_key.rs` |
| `{node,agent}` registers and is still refused as a node identity | same |
| a node-only key is usable; unregistered is its own verdict | same |
| the owner-binding move refuses a signer that is not the owner | same |
| the move is idempotent | same |
| consent grants re-author, and the node reads back a non-empty topology | **`tests/consent_survives_the_key_split.rs`** |
| the three #312 roles resolve to ONE identity after the split | same |

The consent proofs are the #312 regression surface and are written **first**.

---

## Open

- **The wire identity** — closed by CIRISEdge#541 (`use_node_identity`, edge
  v18.10.0) plus provisioning below. Edge resolves the node key itself; no signer
  crosses FFI.

---

## The wire identity — one binding, several jobs

CIRISEdge#541's review found three defects from ONE root cause: a single
`reticulum_identity_signer` binding serving three jobs that coincided only while
the transport identity and the actor were the same key. **The same shape existed
on this side**, found by auditing for it rather than by it failing:

| site | read | should read | consequence |
|---|---|---|---|
| `publish_self_transport_destination` | `cfg.key_id` (ACTOR) | wire identity | the signed route names a key that is not on the link — CIRISEdge#393 item 2 fails and the route **never roots** |
| `arm_peer_deadmission_gate` | `engine.local_derived_key_id()` (ACTOR) | wire identity | the node advertises an identity a sanction can name while being **un-de-admittable through it** — a gate that reports armed and refuses nothing |

Both are the same mistake in the same direction: reaching for "the node's key"
and getting whichever key was at hand.

`node_key::wire_identity()` is the one binding transport-plane callers read. It
is a `OnceLock` rather than a threaded parameter because these callers are
reached from **two entry points** — `compose::serve_with_adapter` and
`federation_delivery::start_and_hold` — and a parameter added to one of them is
exactly how they drift apart.

It is recorded at **provisioning**, not only in compose: the embedded path arms
de-admission from `federation_delivery` and never runs `serve_with_adapter`, so a
value set only in compose would be unset there and the gate would arm the actor.
That is the ordering half of the same defect edge hit (`set_self_key_id` running
before the node identity was resolved).

Absent — every standalone node, every pre-split boot — callers fall back to the
previous value, byte-identically.
---

## Provisioning is a readiness gate — edge must not start on a half state

`init_edge_runtime(use_node_identity=True)` resolves the node key by
`open_existing` and **refuses** when it is absent. Correct: a key edge minted
would be registered by no directory and owner-bound by nobody. But edge inits
BEFORE compose folds on, so on a first boot there is nothing to open.

Softening edge's refusal would put the node-identity lifecycle in the party that
does not own it. The mint moves earlier instead —
`ciris_server.provision_node_identity(keystore_alias, identity_dir,
actor_key_id=None)`, called after the engine is built and before edge init. A
`key_id` comes back; the signer stays in Rust, the same property
`resolve_user_signer` and `ConsentGrantOptions::author_signer` hold.

It **verifies by reading the directory back**, never by trusting the write —
`register_federation_key` treats a benign `Conflict` as `Ok`, which is precisely
how a node once ran for months on a key that never said `node`.

| requirement | gated? | why |
|---|---|---|
| node key registered `node`-only | **yes** | local, always satisfiable, and it is the key that walks the lightnet door |
| actor key registered `agent` (agent-carrying node) | **yes** | an unregistered attester has every row refused — 3,404 on one key in production |
| owner-binding present | **no** | see below |

**Ownership is deliberately not gated.** A fresh node has no owner until someone
completes OAuth and claims it — that is what first-run is FOR. Requiring a human
would mean a node cannot start its transport until it is claimed. Verified that
this is safe: `oauth.rs` has zero edge references, the claim path touches edge
exactly once via a **fire-and-forget** `pull_owner_testimony` whose own comment
says the response "must not wait on a peer being reachable", and LLM checks are
outbound HTTPS. Gating on an owner would make that pull permanently dead on first
run and deadlock any future claim path that does want a peer.

The defect still closes: the lightnet door is walked by a `node`-typed key from
the first packet, claimed or not. Ownership is a separate readiness question,
answered by `owner_of` at the point that needs it — fail-closed, per Clause D.
- **Existing fused deployments** re-author on next boot. Mesh is in development;
  a break-and-repair-on-update is the accepted cost (operator decision, recorded
  here so it is not re-litigated as an oversight).
