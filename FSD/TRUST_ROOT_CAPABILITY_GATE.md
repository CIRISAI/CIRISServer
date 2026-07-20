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

Trust is an **explicit, deletable CEG object**: claiming ownership writes a
`trust(user → humanity_accord)` edge alongside the `delegates_to(user → node)`
owner-bindings. Everything the trust root confers **and** everything it may do to you
ride that one edge:

- **confers:** `infra:attest` (authority to sign/vouch manifests + scores) and
  `infra:serve` (authority to serve/receive traces), plus cross-node score validity and
  vouching for any node sharing the trusted root;
- **holds over you:** the kill switch (the accord's 2-of-3 `accord:*` halt).

Trust roots are **pluggable**: the humanity accord is *a* valid root, not the only one —
a user may attach any root that offers the `infra:` roles. Un-trust is **nuclear but
recoverable**: deleting the `trust(user → root)` edge revokes the roles, the score
validity, the vouching, **and** the kill switch's authority over the node — all at once —
and the node keeps running its *read/local* surfaces so the user can attach a new root
and resume.

## 2. The invariant (the gate)

> **A node MAY run agent capabilities only while it holds a VALID trust-rooted humanity
> accord.** Absent one, agent capabilities and manifest validation are DISABLED at the
> server tier, fail-closed, until a new trust root is attached and its kill switch is
> re-enabled.

**"Valid trust-rooted humanity accord"** — ALL of:
1. a `trust(user → root)` edge exists for this node's bound owner (not tombstoned);
2. `root` is a valid humanity-accord trust root — active `accord:lifecycle` (≤90-day
   refresh, CC), holder roster resolvable, chain from this node's records roots to it
   (`has_effective_role` / `provenance_chain` confirm, from graph state only);
3. the root's **kill switch is enabled** — the accord's control plane is present and not
   in a latched halt, so the emergency brake the user consented to actually exists.

Any one failing ⇒ **not valid** ⇒ capabilities OFF. This is a graph-state predicate:
`trust_root_valid(node)` is computed purely from the `trust` edge + rooting + the accord
lifecycle/roster — never a client assertion, never a cached flag (no fingers on the scale).

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
