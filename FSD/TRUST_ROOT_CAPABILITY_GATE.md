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
