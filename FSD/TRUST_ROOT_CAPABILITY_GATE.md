# FSD — Trust-Root Capability Gate (no valid trust-rooted humanity accord ⇒ no agent capabilities)

**Status:** PROPOSED (spec). Enforcement + the un-trust warning ship with the CEG
trust-card work (CIRISServer#304); this document is the normative contract the gate
implements. Not law — derives from the constitution below.

**Constitution baseline:** CC 3.4.1 / 4.2.1 (the `accord:*` asymmetry — the humanity
accord's 2-of-3 halt is the federation's one constitutional control plane) + the
pluggable-trust-root model (trust is an explicit `trust(user → root)` edge, chosen, not
hardcoded). Layers ON the existing CEG authority model — no new trust root, no new key.
**Subsystem:** `src/auth/` (the capability gate) + the claim-time trust-edge write
(`src/auth/ownership.rs` / `src/claim_remote.rs`) + the CEG projection (`#304`).
**Companion specs:** `FSD/DELEGATION_CONSTRAINTS.md` (the `CapabilityVerb` gate this
extends), CIRISConstitution `FSD-002` §7.2 (the kill switch), CIRISServer#300/#304,
CIRISEdge#379, CIRISPersist#480.

---

## 1. The model this enforces

Trust is a layered graph of `attestation` / `delegates_to` objects — no bespoke "trust"
kind, one immutable base.

**Base — the self-root (first run).** The user signs a plain `attestation(user → user)`
— "I trust my own attestations and service." No scopes, no purpose, no structural
modifiers. It is the immutable identity floor: the user is their own root. Nothing later
touches it.

**Inheritance — downward, over edges that already exist.** The **node** picks up the
self-root through the `delegates_to(user → node)` owner-binding; the **agent** inherits it
through the partnership object (agent ↔ node/user). A node's/agent's trust roots to the
user's self-attestation.

**External roots — `delegates_to` hung off the base.** A trust root is a *self-referential*
declaration `delegates_to(root → root, [infra:attest, infra:serve])` (it roots to itself —
that is what makes it a root). The user trusts one by signing
`delegates_to(user → root, [infra:attest, infra:serve])` — "I delegate to this root for
attest and serve." As many external roots as desired hang off the base this way; adding or
removing one **never touches the base self-attestation**. Each external root **confers**
infra:attest / infra:serve + cross-node score validity + vouching, and **holds over you**
the kill switch (the accord's 2-of-3 `accord:*` halt) — all on that one `user → root` edge.

**The charter model (RC3).** The self-declaration is the root's **charter**: because
down-chain grants are **attenuation-bound** (a `delegates_to` only resolves if the chain
bears the scope from a holder of it — no amplification, ever), the charter is the
capability ceiling of the entire trust domain. A root may amend its own charter at any
point (self-referential — no higher authority exists), but amendment is a governance
ceremony: the scopes live in the signed bytes, so it is an m-of-n re-scrub. Because the
gate is a live graph walk, a charter amendment immediately re-resolves existing
down-chain grants — declarative state, no re-issuance.

**Charter recovery is IN the record, or it does not exist (prior-art REQUIREMENT,
`FSD/PRIOR_ART.md` §2.1).** Tombstone-revocation assumes the revoker's key is honest —
compromise the charter key and the attacker owns the tombstoning pen. A self-referential
root has no superior to appeal to, so the charter record itself MUST carry:
(a) a **pre-rotation commitment** — the hash of the next key set, KERI-style, published
before it is ever needed — and (b) an **m-of-n recovery ceremony** by which the holder
roster rotates a compromised charter to the pre-committed successor. Without both,
root-key compromise is unrecoverable *by construction* (the Parity lesson: powers not
pre-committed do not exist when needed). The m-of-n itself must be audited for holder
**independence**, not signature count (Ronin: 5-of-9 that was one org).

**The halt carries a severance window (prior-art REQUIREMENT, `FSD/PRIOR_ART.md`
§2.6).** A mandatory delay stands between a halt's m-of-n signing and its landing,
during which any node may sever its trust edge and exit the domain — MakerDAO's GSM
delay generalized into the consent model. This is what makes "consensual" mechanical
rather than rhetorical at the moment it is tested: the first real halt will face a
legitimacy crisis (every surveyed system's did), and the window converts "who elected
these three?" into "you had your exit." Halts are pre-committed powers, never
act-then-ratify (Arbitrum AIP-1's failure).

- **Root validity minimum** (what makes *any* root a root, what the gate checks): the
  self-loop carries at least `[infra:serve, infra:attest]` — a root serves and vouches,
  or it is inert.
- **The humanity accord's charter:** `[infra:attest, infra:serve, infra:store,
  infra:transport]` — all four bare-verb infrastructure capabilities it will confer on
  blessed nodes (a canonical *stores* the traces it receives; relays *transport*).
- **Deliberately NOT in a root charter:** `infra:network_presence` and
  `infra:hold_*_membership` — those flow from the **owner**, not the domain. Two
  granters, cleanly split: the owner grants the node's *standing* (presence, seats);
  the root blesses its *infrastructure role* (serve, store, transport, attest). Note
  `infra:serve` appears in both chains: a personal node's serve authority roots to its
  owner; a canonical's roots to the accord.

  **Why presence is owner-only (load-bearing, not taxonomic).** "Presence"
  decomposes four ways: (1) *raw reachability* (announce/listen) is permissionless at
  the transport layer — no token can gate it, and claiming otherwise is a fiction;
  (2) *presence as the owner's device* (`infra:network_presence` — binding a
  `transport_destination` under the owner's standing) is attribution, grantable only
  by the owner whose standing is bound; (3) *attested reachability of blessed
  infrastructure* (the transport hints inside the scrub envelope, #172) is the root
  **witnessing an address**, which rides the charter's `attest` — the root never
  confers presence, it attests facts about it; (4) *extending others' presence*
  (relay) is `infra:transport`, charter-grantable. The split is what makes **nuclear
  un-trust recoverable**: an un-trusted node keeps its owner-granted presence, so it
  can still announce, reach a new root, and ingest a genesis bundle. If presence
  flowed from the root, deleting the trust edge would unplug the device — un-trust
  would self-brick, and the consensual kill switch would silently escalate from
  "halt agent capabilities" to "unperson the device." It must never be that.

**Why serve+attest as the minimum, and why "observe" is deliberately unmarked (RC3).**
The validity minimum is `[infra:serve, infra:attest]` — the two *outward* acts (serving
touches others' data; attesting vouches to others). A trust root is *that which serves
and vouches*.
**There is no `infra:observe`, on purpose**: in the CC's model observation is the unmarked
zero state — the Foreword's Listener precedes every grant ("an observer arrived… by
noticing, kept the pattern"). What you may observe is governed by the **subject's consent**
(cohort_scope, `key_grant` / observer-share), never by a capability the observer carries.
Making `observe` a scope would invert consent. "We begin as an observer" is expressed by
the base self-attestation existing at all. (This is also why `observer` was a phantom token
in the substrate: the system never needed it.)

**Membership vs. bestowed roles (the layering).** *Membership is standing, not
stewardship.* A roster seat is capability-free presence — which is exactly why it is an
`infra:` scope a node can hold. **Judgment roles** (steward, moderator, founder-authority)
are bestowed *on the member* via their own attestations (member-role fields, the CC
4.4.3.4.3.1 role-chain, `moderate|takedown|review` duty scopes) and are **never bestowable
on a pure node** — CC 4.4.3.4.3's conformance rule (node-only keys carry only `infra:*`)
makes CC 1.13.5 wire-checkable: the node holds your standing; you (or your agent) wield the
judgment. Ladder: observer (unmarked) → member (standing) → server/attester (capability) →
steward/moderator (judgment — requires a brain).

**RC3 crystal scope vocabulary (no aliases, hard cut — pre-fleet).** Every `infra:` token
must state *act/standing + object* on its face:

| token | normative one-liner |
|---|---|
| `infra:network_presence` | be reachable on the mesh as the delegator's device (announce + `transport_destination`) |
| `infra:hold_community_membership` | occupy a member seat on **community** rosters under the delegator's standing |
| `infra:hold_family_membership` | occupy a member seat on **family** rosters under the delegator's standing |
| `infra:serve` | answer reads / serve stored content and requests to authorized peers |
| `infra:store` | hold the delegator's/cohort's data at rest |
| `infra:transport` | relay ciphertext between peers |
| `infra:attest` | sign infrastructure attestations (build manifests, self-reports, vouches) |

`infra:membership` (server legacy) and `infra:join_communities` (CC RC2 / persist) are
**both retired** — they were vague AND, because scope matching is exact-string, they never
even matched each other on the wire (a live interop hole). `hold_` names the persistent
standing (not the join ceremony, not grant/manage authority); the community/family split
exists because they are distinct CEG objects in different sensitivity classes — a user can
give a node community standing while keeping it out of the family.

Trust roots are **pluggable** (the humanity accord is *a* valid root, not the only one).
Un-trust is **nuclear but recoverable**: deleting a `delegates_to(user → root)` edge revokes
that root's roles, score validity, vouching, **and** kill-switch authority at once — but the
base self-root remains, so the node keeps running its read/local surfaces and can attach a
new root and resume. **The base is why the app never bricks; the external delegation is what
unlocks *federated* capability.**

## 2. The invariant (the gate)

> **A node MAY run FEDERATED agent capabilities only while it holds a VALID EXTERNAL
> trust-rooted humanity accord** — a `delegates_to(user → external root)` distinct from the
> base self-root. Absent one, federated agent capabilities and manifest validation are
> DISABLED at the server tier, fail-closed, until a new trust root is attached and its kill
> switch is re-enabled. The base self-root keeps the shell alive but does NOT by itself
> satisfy the gate — self-trusted scores are an island; validity + the kill switch require a
> **shared external** root.

**"Valid external trust-rooted humanity accord"** — ALL of:
1. a `delegates_to(user → root)` edge exists for this node's bound owner with `root != user`
   (i.e. NOT the base self-root), not tombstoned;
2. `root` self-declares (`delegates_to(root → root, infra:*)`) and is a valid humanity-accord
   trust root — active `accord:lifecycle` (≤90-day refresh, CC), holder roster resolvable,
   chain from this node's records roots to it (`has_effective_role` / `provenance_chain`
   confirm, graph state only);
3. the root's **kill switch is enabled** — the accord's control plane is present and not in a
   latched halt, so the emergency brake the user consented to actually exists.

Any one failing ⇒ **not valid** ⇒ federated capabilities OFF (the base self-root floor
remains — the app runs, un-federated). `trust_root_valid(node)` is a pure graph predicate
over the `delegates_to` edges + rooting + the accord lifecycle — never a client assertion,
never a cached flag (no fingers on the scale).

## 3. What is disabled vs. what keeps working

**DISABLED (fail-closed) when `trust_root_valid(node) == false`:**
- **All agent capabilities** — every `CapabilityVerb` that runs or acts as the agent
  (the H3ERE runtime, tool invocation, emitting signed attestations/scores, outbound
  federation acts). The gate refuses with a distinct `NoValidTrustRoot` denial.
- **Manifest validation** — the node will not validate build manifests or treat any
  peer's scores/manifests as valid: with no trusted root, nothing cross-attests, so a
  score is unrooted noise (validity flows only from a shared trusted root, §1).

**KEEPS WORKING (the app does not brick):**
- Read/local surfaces (status, node list, the trust card itself), first-run + claim, and
  crucially **attaching a new trust root** (`trust(user → new_root)`). The whole point of
  nuclear-but-recoverable is that the operator can always re-root and resume.

## 4. Enforcement point

Server tier, in the capability gate (`src/auth/gate.rs`, beside `authorize_delegated` /
the `never_delegatable()` floor). Before authorizing any agent capability verb, the gate
evaluates `trust_root_valid(node)` against the graph; `false` ⇒ deny with
`DenyReason::NoValidTrustRoot`. Fail-closed: an indeterminate evaluation (roster
unresolvable, lifecycle unknown) is treated as NOT valid — the safe-mesh floor never
opens on doubt. The predicate is cheap-cached only within a request; it is re-derived from
graph state each authorization, so a mid-session un-trust takes effect on the next verb.

## 5. The un-trust warning (client, #304)

Deleting a `trust(user → root)` edge is a nuclear act and MUST be gated by an explicit,
un-pre-checked confirmation carrying this exact consequence text:

> **You will not be able to validate manifests, and you will not be able to run any agent
> capabilities until a new trust root is attached and the kill switch is re-enabled.**

The CEG hamburger's "un-trust (nuclear)" surfaces this; the server enforces the reality
whether or not the client showed it (the warning informs; the gate binds).

## 6. Re-enablement

Attach a new trust root — write `trust(user → new_root)` for a root that offers the
`infra:` roles and whose kill switch is present/enabled. On the next authorization
`trust_root_valid(node)` returns true and capabilities + manifest validation resume. No
restart, no re-claim: the gate is a live function of the trust edge.

## 7. Non-goals / boundaries

- Not a new kill switch — it is the *consensual* face of the existing one: capabilities
  ride the same edge the halt does, so opting out of the accord opts out of both.
- Does not scope per-canonical revocation — that is the accord-side `withdraw_canonical_role`
  (a different actor/op). This gate is about the *node's own* trust-rootedness.
- Does not touch data at rest — un-trust disables *acting*, not the local corpus; a
  re-rooted node resumes over its existing state.
