# Mesh governance and admin operations

Supersedes `ADMIN_OPS_TAXONOMY.md` and `MESH_CONFIG_AND_ADMIN_OPS.md`. Both were
written before the 344-issue survival audit and both contained errors the audit
found. This document keeps what survived, corrects what did not, and states the
corrections explicitly so the next reader can check them rather than inherit
them.

---

## 0. What the audit changed

Six enumerator lenses over real federated-system failures produced 344 issues,
311 unique. Verdicts against the shipped code: 12 structurally-immune, 16
handled, 186 partial, 97 unhandled. A second pass classified 228 of those
against eight proposed resolutions; 206 survived.

Five things in the prior FSDs were wrong.

**1. The adversarial framing was mis-aimed.** Nine of the top twelve kill risks
have no adversary. The prior taxonomy was organized around attack because attack
is what one thinks about; the failure data is dominated by succession, funding,
adoption, operational neglect and legal duty. The largest family — 107 issues,
58 of them mesh-killing — had no home in the six families at all.

**2. "Consent routing makes spam unrepresentable" is false.** `consent_grammar`
carries no rate, volume, byte or purpose term. **Consent bounds WHO, never HOW
MUCH.** A consented peer can flood freely. Consent is also SEND-only — the
receive plane is peer-blind, and CC 3.3.7 ratifies that in terms ("admission is
by key registration; consent is the governance record"). The claim was stretched
past what the code supports.

**3. Illegal content was routed to the wrong tier.** The prior ladder sent it to
tier 2 (quarantine — *"withhold from serving, retain locally"*) and tier 3
(forced descent, which preserves the blur by design). Retain-locally is knowing
possession. Illegal content is not a moderation problem with a proportionate
response; see §4.

**4. Governability was confused with compellability.** The audit priced
"unsatisfiable global deletion" as a permanent cost. It is not. See §2 — this is
the correction that most changes the legal posture.

**5. The tier ladder addressed a third of the failure space.** 200 of 311 issues
carry no tier at all. The ladder also asserted reversibility for tiers 1/2/4 and
provided no reversal route, gated its only irreversible op more weakly than its
reversible one, and lost NoCeM's actual property (per-reader authority) on every
rung except tier 0.

---

## 1. Two planes, and only one of them is a policing problem

**No one sees what they did not consent to see.** Replication requires a signed
directed grant; `promote_consented_backlog` sweeps only rows a live grant covers.
That is real and it is proven — it was proven the hard way when 240 peers had
consented to send and none could consent to be scored, and the scoring plane was
simply dead.

The consequence is a split the prior FSDs did not make:

| plane | protection | policing need |
|---|---|---|
| **private** — directed, consent-gated flows | structural: no grant, no delivery | low — the recipient already chose |
| **commons** — federation-scoped, publicly readable | none from consent | **this is the whole problem** |

Almost every harm scenario worth designing against lives in the commons.
Consent is not the commons' defence, because in the commons everyone has
consented to look.

**What consent does NOT do**, stated plainly so it is not stretched again:

- it does not bound volume, rate, or size
- it does not gate the receive plane (peer-blind by CC 3.3.7)
- it does not cover trace-ingest (`ingest_http.rs`) or the deliberately
  unauthenticated `POST /v1/accord/canonical/gossip-partial`
- it is not transitive and cannot be enforced downstream

---

## 2. Governability is per-mesh; ungovernability is only of the set

The prior design treated "no party can compel deletion" as a feature and the
audit priced it as an irreducible cost. **Both were wrong, for the same reason:
they conflated one ungovernable mesh with many governable ones.**

A CIRIS mesh **is** governed. The accord trio hold decisive authority over
theirs — halt, purge, de-admit, erase. What prevents that authority becoming
tyranny is **not** that it is weak. It is that trust roots are pluggable and
exit is cheap: anyone can mint a root and take their cohort with them.

```
one ungovernable mesh      →  nobody can fix anything; abuse is permanent;
                              a court gets contempt; the criticism is fair
many governable meshes     →  each has an authority that can act decisively;
                              the check on that authority is exit, not impotence
```

Consequences that follow directly:

- **Deletion is satisfiable within a mesh.** A court order is met by the accord
  purging its own mesh. That is compliance, not contempt.
- **It is not satisfiable across all meshes** — but neither is it for the web,
  email, or BitTorrent. That is a property of information existing in more than
  one place, not a CIRIS liability.
- **Decisive authority is legitimate here** precisely because it is escapable.
  A design that made the accord weak would buy nothing and cost the ability to
  respond.

This is also why the fundraising and legal asks are ordinary rather than
apologetic: an operator with full purge authority, an audit trail, and a
documented removal SLA is answering a normal question.

---

## 3. The operations ladder, v2

Every op remains a signed, attributed CEG object. What changes is the rungs.

| tier | verb | reaches | reversible | authority |
|---|---|---|---|---|
| 0 | **annotate** — signed judgement, no effect until honoured | row / key | trivially | `review` |
| 1 | **throttle** — accept, deprioritise | key | **`un-throttle`** | `moderate` |
| 2 | **quarantine** — withhold from serving, retain locally | row set | **`un-quarantine`** | `moderate` |
| 3 | **force descent** — CC 6.1.2 pressure; blur + tombstone remain | row set | no, by design | `slash` + **quorum** |
| 4 | **de-admit** — key may no longer write | key | **`re-admit`** | `slash` |
| 5 | **halt** — kill switch | node | accord | accord quorum |
| **S** | **self-directed** — shed my own load, stop accepting, descend my own corpus, declare legal compulsion | **self** | yes | owner |
| **R** | **subject-side** — a reader's own accept/refuse policy over others' judgements | **the reader's view** | yes | reader |

Four corrections embedded there:

**Reversal ops exist.** The prior ladder claimed reversibility and shipped no
route that reverses anything.

**Tier S is new.** Every prior tier acted on someone else. Nothing expressed
*shed my own load*, *stop accepting*, or *I am under legal compulsion* — which
are the operator's most common needs and the only ones available under partition.

**Tier R restores NoCeM.** The historical mechanism's actual property is
**per-reader authority**: a signed judgement takes effect at a consumer that
chose to honour that signer. Tiers 1–4 apply automatically at the consumer,
which is the property NoCeM was invented to avoid. Tier R is the subscribable
policy — a reader adopts another party's judgements deliberately, and can drop
them.

**Gating is re-ordered by irreversibility, not blast radius.** Tier 3 is the
only irreversible op and previously needed one delegation chain; tier 5 (halt,
reversible by accord) needed quorum. Inverted. Tier 3 now takes quorum.

Two properties on every tier ≥ 1, unchanged and load-bearing:

- **preview before commit**, with a selection hash the commit must present —
  what was previewed is what executes. This is also the agent/human seam:
  an agent computes and proposes; a human ratifies a hash.
- **authority in the artifact** — the authorizing `delegates_to` id and a
  mandatory reason, in the tombstone. An action that does not carry its own
  authority cannot be told from an unauthorized one once the actor is gone.

---

## 4. Content classes: retirement is not removal

CC 6.1.2 is right that revocation, retirement, eviction and aging are one
pressure-driven descent, and that **descent never terminates at zero — the blur
survives forever**. That is correct for the retirement of ordinary content and
it is what lets right-to-be-forgotten and durability-of-history share a
mechanism.

**It is a liability for one class.** You cannot keep a blur of illegal content,
and "withhold from serving, retain locally" is possession. Illegal content needs
a carve-out with the opposite terminal condition:

| class | pressure | terminal state | authority |
|---|---|---|---|
| ordinary retirement | aging → eviction → revocation | blur + tombstone, forever | owner / subject |
| **prohibited content** | immediate | **zero: payload gone, only the content hash survives** | **accord** |

The surviving hash is doing real work: it lets other nodes **refuse the same
payload on arrival without ever holding it**. That is the SKS lesson answered
properly — not "we cannot remove it", but "we removed it, and everyone else can
decline it sight-unseen."

Erasure must be **object-keyed**. Every primitive persist exposes today is keyed
by a *role* — agent, actor, content_id, tier — and six arbitrary-payload fields
(`attestation_envelope`, `registration_envelope`, `attestation_evidence` (raw
bytes), `policy_blob` ×2, `HardCaseEvent.detail`) are reachable by none of them.
Filed as CIRISPersist#573. Note the recursion: the tombstone recording a removal
is itself an unbounded-payload object.

---

## 5. Policing the commons: reverse quorum

Communities and affiliations are meant to police themselves. The mechanism is
**reverse quorum** — an action takes effect immediately and is undone if *m*
members object within a window. Not approve-to-act; **act-unless-objected**.

That resolves speed against legitimacy in the only way that works at mesh scale:
a single member can respond to a flood *now*, and the community can reverse them.
Requiring approval first means the response arrives after the harm; requiring
nothing means one member governs.

**It is not implemented, at two layers:**

1. The `consensus_protocol` vocabulary is `founder_only | unanimous | majority |
   quorum:{m}/{n} | weighted:{rubric} | custom:{id}` — **every form is
   approve-to-act.** No objection form exists.
2. CIRISServer#111 is open: *"no consensus engine — `consensus_protocol` is a
   stored label, nothing reaches consensus."* Communities cannot do forward
   quorum either.

This is the keystone gap. The private plane is protected by consent and proven;
the commons is protected by community self-policing and that mechanism does not
exist at any layer.

Required shape:

```
reverse_quorum:{m}/{n}:{window}    act now; reversed if m of n object within window
```

with the objection itself a signed CEG object, and the reversal automatic rather
than discretionary.

---

## 6. Rate, quota, and the censorship trap

There is **zero rate limiting, zero quota, zero write price anywhere** — and
`DEFAULT_OPERATIONAL_PAGE_LIMIT` is `u32::MAX`. Volume has no constitutional
standing: CC bounds WHO may send, WHAT scope a row carries, and HOW MANY BYTES
may rest, but never RATE.

Heuristic response is wanted — *X takedowns in Y period*, inauthentic storage
patterns — and the substrate has to carry the primitives:

- per-(peer, dimension) admission budget, recipient-authored
- observed-rate and storage-pattern signals a policy can key on
- an automatic tier-1 throttle on threshold, reversible, with the evidence in
  the tombstone

**One caveat that must ship with the caps:** *bounded caps convert a flood into
a censorship primitive.* A quota-compliant Sybil that fills the budget crowds out
everyone else — including an accord-signed kill-switch entry. Any cap therefore
needs a **reserved admission class** for accord-signed rows, which cannot be
consumed by ordinary traffic.

---

## 7. What is actually permanent

The audit's test: *an item is irreducible only if closing it requires abandoning
a design goal you will not abandon. Name the goal, or it is not irreducible.*

Three survive:

| permanent cost | entailed by |
|---|---|
| metadata survives content confidentiality | public third-party verifiability |
| protestware / owner self-sabotage | owner sovereignty — the property consent is built from |
| m-of-n counts keys, not independent humans | cryptographic rather than legal identity |

Two the audit listed do **not** survive §2: jurisdiction shopping and
court-ordered global deletion both dissolve once governability is per-mesh. One
more — the mobile push chokepoint — is a platform constraint, not a design cost.

**Everything else is unpaid, not impossible.** 201 of 206 residual items have a
known shape, a known cost, and nobody assigned. There is no discovery risk in a
rate limiter, a VACUUM call, a jitter term, a dead-man heartbeat, a reproducible
build, or a `SECURITY.md`. The mesh is not threatened by the unknown; it is
threatened by a backlog.

---

## 8. Open substrate asks

| ask | repo | status |
|---|---|---|
| mesh_config plane, `slash` scope, attributed hard_case, time-bounded de-admission, quarantine marker | persist | #570 |
| object-keyed erasure | persist | #573 |
| **reverse quorum + a consensus engine** | persist | **to file — the keystone** |
| rate/quota plane with reserved admission class | persist | to file |
| mesh-config consumption, ConfigRelief, quarantine-aware offers | edge | #440 |
| per-row delivery receipts | edge | to file |
| four-tab card, graded routes, preview hash | server | #346 |
| consensus engine (`consensus_protocol` is a stored label) | server | #111, open |
