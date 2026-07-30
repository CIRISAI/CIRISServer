# The trust-root vocabulary

The settled names, and the distinctions they exist to keep visible. Shipped in
persist **v23.0.0** (CIRISPersist#551) and adopted here in **0.5.140**.

Read this before touching genesis, the serve gate, or the seed. Every distinction
below was previously carried by context rather than by a name, and each one cost
real debugging time when the context was missing.

---

## The seed is a bundle, and it is the only shape

There is exactly **one** artifact type. `canonical_seed.json` is a
`GenesisBundle`:

```
version · family_key_id · holders · serve_nodes · consensus_protocol
        · attestations · authorizations · produced_at
```

persist owns the type; we produce it. A bare `[{record}]` file is **not a seed**
and does not parse.

"Valid seed" is therefore a type question, not a judgement call. A bundle that
verifies carries its own authority graph; a key record alone never could.

**Never say "seed" for key material.** `CIRIS_TEST_TRUST_ROOT_PRIVATE_KEY` is 32
bytes of Ed25519 private key. The bundle is an artifact. They are unrelated.

---

## `delegates_to` does three jobs — always name which

One attestation type, three roles, distinguished by the envelope dimension:

| dimension | shape | question it answers |
|---|---|---|
| `trust:charter:v1` | `R → R` | *is R a trust root?* |
| `trust:confers:v1` | `R → subject` | *did R grant this subject a capability?* |
| `trust:accepts:v1` | `node → R` | *does this node accept R's authority?* |

The middle two point **opposite ways**. Reading a conferral as a trust edge (or
vice versa) is the single easiest mistake to make here, and direction alone is a
poor guard — name the job.

`trust:accepts` is the **un-trust lever**: the operator deletes that one row and
the whole cascade fails closed on its own — the walk returns `None`, the serve
gate withholds, agent capabilities gate off, manifests stop. Nothing about that
is special-cased, and nothing may replace it with a universal rule.

---

## Two conferral planes, named

A capability can be conferred two ways. Use `ConferralPlane`, never "leg A/leg B":

| plane | question | evidence |
|---|---|---|
| `ConferralPlane::AccordCoScrub` | *did the accord bless this identity?* | m-of-n co-scrub on the key record (`registration_envelope.roles`) |
| `ConferralPlane::Delegation` | *did a root I accept confer this capability?* | a `trust:confers` grant walked to a trusted root |

`capability_roots_to_trusted_root` tries delegation first (cheap), then the
co-scrub (a 2-of-3 hybrid verification). Either plane can supply the candidate;
**both then require the asking node's own `trust:accepts` edge** via
`trust_root_valid`. The planes differ in who conferred, never in whether you
accepted.

Readers:

- `has_accord_conferred_role` — the co-scrub plane
- `has_root_delegated_role` — the delegation plane

---

## Validity is four things. Liveness is not one of them.

```rust
let valid = edge_exists            // this node's trust:accepts edge
         && root_self_declares     // the root's trust:charter
         && charter_has_recovery   // its pre-rotation commitment
         && halt_latched != Some(true);
```

The **accord heartbeat** (`ACCORD_HEARTBEAT_DIMENSION`) is a liveness *signal*,
reported beside the verdict as a banded `drill_freshness` — green / yellow / red
by age. It never gates.

This is what makes a seed durable: **valid until revoked, withdrawn or
superseded**, never until it expires. A validity gate on freshness would give
every baked artifact a shelf life and take the whole mesh dark on the same day,
with no error at the point of use.

Surface the band, don't branch on it (CIRISServer#332).

---

## Capability roles vs identity type

Two different fields, gating different things — they are not synonyms:

- **`KeyRecord.capability_roles`** — capabilities the key claims (`infra:serve`, …)
- **`identity_type`** — what the key *is* (`canonical`, `witness`, `accord_holder`, …)

Reserved dimension prefixes (`age_assurance:`, `system:`, `detection:`, …) gate on
**`identity_type`**, via `required_identity_types`. Not on `capability_roles`. Say
`identity_type` when that is what the gate reads, because assuming otherwise leads
directly to the wrong threat model.

---

## Words that mean one thing each

| word | means | does **not** mean |
|---|---|---|
| **trust root** | a key with a `trust:charter` | an accord holder; the ROOT user; edge's "rooted peer" |
| **charter key** | the holder key acting as a trust root | anything else called `root` |
| **owner** | the ROOT user (auth) | a trust root |
| **reachability** | edge's rooting — can I dial you | trust of any kind |
| **bundle** | the genesis artifact | key material |
| **heartbeat** | accord liveness signal | a lifecycle state machine; a gate |

Edge's `RootedPeer` is about **dialling**, not trust. `⚠️ ROOTING ≠ ROUTING` is in
the source already; it is also ≠ *trust*-rooting.

---

## Ours, by name

- `install_trust_root_records` — installs a bundle's records. Deliberately does
  **not** write `trust:accepts`; accepting a root is the node's own act.
- `accept_trust_root` — writes `trust:accepts`. The deletable lever.
- `mint_trust_root` — the ceremony.

The split between the first two is the whole design: a bundle may seed records, and
may never assign a stranger a trust root.
