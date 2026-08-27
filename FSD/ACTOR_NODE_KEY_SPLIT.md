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

### Consent cannot be re-authored ahead of the engine — the tests found this

An earlier draft of this document had the migration re-author grants as the node
while the engine still signed as the actor. **The substrate does not permit
that, and is right not to.**

`emit_replication_consent` takes a `node_key_id` that reads like a selector and
is not one. The row is written by `emit_attestation_self`, which signs with the
engine's own composed signer; `peer.rs` documents the parameter as an assertion
that it EQUALS the engine's derived id ("wire-preserving"). Consent is
self-attested by construction — CEG 1.0-RC29 §5.6.8.15 forecloses third-party
authorship precisely so a grant cannot be produced on your behalf.

So the ordering inverts: **the engine-signer swap is a PREREQUISITE for moving
consent, not a follow-on.** They are one indivisible change, and this cut ships
the key split without them.

The invariant was documented and unchecked, which the TDD pass surfaced as a live
defect: passing any other id SUCCEEDED and produced a grant authored by the
engine —

```
emit(node_key_id = NODE) -> Ok
read as NODE   -> []
read as ENGINE -> [peer]
```

— zero peers under a green transport, the #312 shape, reachable by a
one-argument mistake, and the same "quietly downgraded rather than refused" class
as the phantom `[node]` extra and the `Conflict`-at-debug. `emit_grant_row` now
refuses a mismatch and says why.

The owner-binding moves fine, and the asymmetry is principled:
`build_signed_owner_binding` takes an explicit signer because an owner-binding is
authored BY THE OWNER about a node; a consent grant is authored BY THE GRANTING
PARTY about itself.

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
5. **STAGED — not in this cut.** The engine's signer becomes the node key, and
   only then can consent grants be re-authored. One indivisible change (see
   above); until it lands the node keeps the actor's transport identity and its
   existing topology, which is the pre-split behaviour and therefore safe.

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

- **The engine's signer + consent, together.** Edge takes its transport identity
  from `engine.local_signer_capsule()`, and consent can only follow the engine.
  These move as ONE change; `tests/consent_survives_the_key_split.rs` already
  pins the post-swap property
  (`an_engine_signing_as_the_node_authors_and_reads_its_own_topology`), so the
  check that proves it landed exists before the change does.
- **Existing fused deployments** re-author on next boot. Mesh is in development;
  a break-and-repair-on-update is the accepted cost (operator decision, recorded
  here so it is not re-litigated as an oversight).
