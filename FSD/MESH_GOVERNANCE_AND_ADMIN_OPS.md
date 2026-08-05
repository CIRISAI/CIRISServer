# Mesh governance and admin operations

Supersedes `ADMIN_OPS_TAXONOMY.md` and `MESH_CONFIG_AND_ADMIN_OPS.md`. Both were
written before the 344-issue survival audit and both contained errors the audit
found. This document keeps what survived, corrects what did not, and states the
corrections explicitly so the next reader can check them rather than inherit
them.

---

## 0. The baseline: what actually killed the others

Three audits over 344 enumerated failures from real federated systems. The most
useful output was not a defect list — it was the observation that the same four
**preconditions** appear in every death.

| system | died of | precondition required |
|---|---|---|
| Usenet | spam → forged cancels → cancel wars | propagate-by-default, no authority |
| SMTP | spam economics | accept-from-anyone |
| SKS keyservers | certificate poisoning | obligation to accept + **no removal primitive at all** |
| IPFS / Freenet | unwanted content, permanently | permanence with no authority |
| Fediverse | harassment waves, admin burnout | federation-on-by-default, moderation as unpaid human labour |
| XMPP | fragmentation, embrace-extend | optional extensions, one dominant implementer |
| CA / PKI | DigiNotar, Symantec | monolithic trust + revocation that never arrives |
| Blockchains | 51%, DAO fork, block-size war | **one global state to fight over** |
| SSB | feed fork = identity death | single-writer log, no recovery |

**Deliver-by-default · one shared namespace · human-bound labour · no honest
removal.** Every one of them, over and over.

### What is structurally different here

Not "better" — *different in a way that removes a precondition*.

1. **Consent-directed replication** removes deliver-by-default. There is no open
   relay because there is no relay: bytes move only along a signed directed
   grant. (It does NOT bound volume — see §1.)
2. **Multi-polar roots** remove the single shared namespace. Schism becomes a
   routing change rather than an existential fight. See §2.
3. **Agents** remove human-bound labour. Every prior system's fatal costs —
   moderation triage, configuration, onboarding, ops — were labour costs, and
   none of those systems had anything that could do the labour.
4. **Descent** removes the no-honest-removal problem. One pressure operator where
   hard-delete is simply the fastest descent, so erasure and durability share a
   mechanism instead of contradicting.

A fifth has no historical analogue at all: **the CEG makes automated action
accountable.** Every prior attempt at automated moderation was opaque; here an
action is a signed object carrying its own authority and reason, previewable and
reversible. That is what makes (3) safe rather than alarming.

### The proportion rule

An audit graded against perfection returns everything. Findings are only
architectural if they are **inherited by any mesh built this way**. Everything
else is an operations concern — real, schedulable, and not a property of
federating.

> "The package registry could be unavailable" is true of Linux and Postgres.
> It is not a mesh-design finding.

Applying that rule, four findings survive as genuinely architectural, and §§4–6
address them:

- **the receive plane has no subject** — any admitted key writes signed rows
  *naming anyone*; subject-side consent exists for `capacity:*` alone (CC#46)
- **equivocation is free** — a key can sign contradictory claims to different
  peers at the same `asserted_at`; both verify; nothing compares them
- **every removal is an append on a pull-only plane** — revoke, purge, erase,
  de-admit and halt alike; unreached holders never learn
- **authority propagates automatically; recovery does not** — the halt latch.
  Structural and permanent for *delivery* (a dark node pulls nothing); §3 records
  how #347 routes around it by making recovery something the node **finds on
  disk** rather than something the mesh delivers

### Corrections to earlier drafts of this document

1. *"Consent routing makes spam unrepresentable"* — **false**. Consent bounds
   WHO, never HOW MUCH; and it is SEND-only.
2. Illegal content was routed to tiers 2/3. Retain-locally is possession; the
   blur must not survive. See §4.
3. Governability was confused with compellability — and then over-corrected into
   dismissing delivery. Authority is per-mesh; **delivery is not**. See §2.
4. Tier 5 was described as reversible. It is the least reversible op in the
   system. See §3.
5. The ladder addressed a third of the failure space and claimed reversibility it
   did not implement.

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

## 2. Multi-polar roots are the design, not the escape hatch

Every federated system that died had **one shared trust anchor**: one CA root
store, one set of Tor directory authorities, one chain state, one Usenet
namespace, one instance you happened to be on. That single anchor is why every
governance dispute in their histories was existential — the block-size war, the
DAO fork, XMPP extension fragmentation, the CA distrust wind-downs. **When there
is one namespace, schism is death.**

CIRIS is built for many roots coexisting *from the start*. A root is a family of
keys; a node trusts one by holding an attestation and un-trusts it by deleting
one. Schism is a routing change.

Two consequences that the earlier drafts got backwards:

**Decisive authority is affordable *because* roots are plural.** An accord holds
halt/purge authority over its own mesh. That is not a compromise of
decentralization — it is what plural roots buy you. A single-root system cannot
afford a decisive authority, because there is nowhere to go; a multi-polar one
can, because the check is exit rather than impotence.

**"Anyone can mint a root" is a design property, not a consolation prize.** It
is the reason a failing steward, a captured accord, and a legitimate
disagreement all have the same remedy, and why none of them is fatal to the
model.

### What this does NOT excuse

The prior draft used per-mesh governability to dismiss the deletion question.
That was wrong on delivery, and the correction matters:

> **Authority is per-mesh. Delivery is not.**

A purge is an accord-signed row on the same pull-only plane as everything else.
A holder that is offline, forked, de-admitted, or joins later never receives it.
*"We emitted a purge"* is not *"the bytes are gone"*, and cannot be evidenced as
such. Any legal or safety posture that rests on purge must state what it does
about unreached holders — see §4 and the delivery-receipt ask.

## 3. The operations ladder, v2

Every op remains a signed, attributed CEG object. What changes is the rungs.

| tier | verb | reaches | reversible | authority |
|---|---|---|---|---|
| 0 | **annotate** — signed judgement, no effect until honoured | row / key | trivially | `review` |
| 1 | **throttle** — accept, deprioritise | key | **`un-throttle`** | `moderate` |
| 2 | **quarantine** — withhold from serving, retain locally | row set | **`un-quarantine`** | `moderate` |
| 3 | **force descent** — CC 6.1.2 pressure; blur + tombstone remain | row set | no, by design | `slash` + **quorum** |
| 4 | **de-admit** — key may no longer write | key | **`re-admit`** | `slash` |
| 5 | **halt** — kill switch | node | **offline release token — see below** | accord quorum |
| **S** | **self-directed** — shed my own load, stop accepting, descend my own corpus, declare legal compulsion | **self** | yes | owner |
| **R** | **subject-side** — a reader's own accept/refuse policy over others' judgements | **the reader's view** | yes | reader |

**Tier 5 is not reversible over the network, and the prior draft said it was.**
`accord_halt.rs` replicates the halt to all known peers, latches it to disk, and
`exit(42)`s; `check_halt_gate` then refuses boot. A halted node is not running,
so the un-halt cannot be *delivered* to it — replication is pull-based and a dark
node pulls nothing. That is a permanent property of the mechanism and no amount
of protocol work changes it.

**What changed (CIRISServer#347): the un-halt is no longer delivered, it is
found.** The latch now records **what would lift it** — a release binding naming
`{node_id, halt_invocation_id, halt_payload_sha256, latch_id}` — and
`src/accord_release.rs` verifies an accord-cosigned `accord:lifecycle:active`
token against that binding **entirely offline**: the family and its `quorum:M/N`
from verify's baked `humanity_accord_genesis()`, the holders' hybrid pubkeys from
persist's baked `accord_holder_genesis_records()`, the binding from the latch
file. No network, no peer, no live quorum, no database. Any transport works — file
drop, USB, QR, operator paste — because the token is read off disk by the boot
gate, not delivered to a process. Recovery therefore costs one act *per mesh
ceremony* plus a file copy per node, not a physical visit per node.

It does not soften the halt. The token needs the same authority class that fires
one (an accord quorum, never a single party, never the operator), it is bound so
narrowly that it is not a skeleton key (another node, another halt, or an earlier
latch of the *same* halt all fail: the `latch_id` is fresh CSPRNG per latch, so a
token cannot even be minted against a halt that has not happened), and every
attempt — honoured or refused — lands in an append-only journal surfaced at
`GET /v1/accord/halt-status`. A release is a governance act and is as auditable
as the halt.

Two paths back now exist, and they are the same rung reached with different
material — not two ladders:

| | `accord release` (#347) | `accord reactivate` |
|---|---|---|
| authority | **baked** genesis family, M-of-N | **live** family from persist, M-of-N + ≥1 original seat |
| needs | two files in `home` | the DB + the keystore |
| handles | a family that still has its founders | a family that has rotated past them |

The offline path deliberately uses the *pinned* half of the reactivation floor
and drops the DB half, because the DB half is the forgeable one on a captured
host — that is the same B2 reasoning that put the genesis floor into
`accord_reactivate` in the first place.

**Still open from #347.** The release token is ask (1) of four. A halt still
carries **no TTL** (ask 2), still has **no cohort scope** (ask 3, arguably a CC
4.2 change), and still has **no dry-run/preview** (ask 4). Tier 5 remains the
op with the largest blast radius and the thinnest ceremony, and must be gated and
previewed accordingly.

One thing the release token explicitly does **not** claim: durability against an
operator with filesystem write. Deleting the latch was always possible and still
is. The property is narrower and checkable — *nobody without an accord quorum can
produce a release the node will honour and log as authorized.*

Four further corrections embedded there:

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

### Corrections the implementation forced (tiers 0–4, `src/admin_ops.rs`)

Building the routes against persist v28.2.0 falsified four things this table
said. They are corrected here rather than in the code alone, because a design
doc that keeps asserting them is how the next reader inherits them.

1. **Tier 2 is `slash`, not `moderate`.** `check_delegated_duty_scores_admission`
   gates the quarantine dimension arm on `slash` — *"a quarantine marker takes
   something away… there is no laxer path for the harsher op"*. A route
   advertising `moderate` would advertise an authority the substrate refuses at
   its own door.
2. **Tier 1 has no substrate at all.** There is no recipient-authored per-key
   admission budget; `PeerWriteQuota` is a fixed runaway-loop backstop, not a
   policy surface a throttle can key on. `throttle` / `un-throttle` are
   attributed judgements and nothing more, and the route says so in its
   response. This is §6's ask, restated as a shipped gap.
3. **Tier 4 is NOT reversible.** Revocations are append-only,
   `fold_key_statement_standing` composes restrictions and never leniencies, and
   no layer exposes an un-revoke. `re-admit` exists and records an attributed
   reversal; the revocation row survives and every reader still folds it. Of the
   three reversals only tier 2's reaches the substrate.
4. **The time bound lives on tier 4, not tier 3.** `Revocation::revoked_after`
   is the only time-bounded removal persist implements. Tier 3 accepts `after:`
   as a selection window and records it, but refuses to drive the unbounded
   actor eviction from a bounded judgement — that is the DigiNotar error, and
   the coherent op is a bounded de-admission.

And one that is not a correction but a wall: **no primitive descends an
attestation row set.** Every payload carrier is sealed inside its own signature
(`erasable` decides erasability at mint, and nothing minted today is erasable),
so tier 3 reaches the actor's blob corpus and nothing else. §4's object-keyed
erasure ask is what closes it.

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

**Correction to an earlier draft of this section**, which said there is "zero
rate limiting anywhere". That was false, and it is the kind of claim this project
keeps having to unlearn: `PeerWriteQuota`
(`federation::replication::admission`, v22.0.0/AV-76) ships, is constructed in
all three backends, and LEADS the check chain in `put_attestation` — it consults
no shared state, so it also bounds the recursive directory walk the trust scorer
runs.

What is actually true is narrower and more useful:

```
PER_PEER_ATTESTATION_WRITES_PER_WINDOW = 600      // 864,000 rows/day/peer
PER_PEER_ATTESTATION_WRITE_WINDOW      = 60s
PER_PEER_QUOTA_TRACKED_PEERS_CAP       = 4096
buckets: Mutex<HashMap<..>>                       // per-backend-instance, in-memory
```

It is a **runaway-loop backstop, not an abuse control**: 600/min permits a flood
indefinitely, the buckets reset on restart, only `put_attestation` is guarded,
bytes are not counted at all, and the 4096-peer cap evicts honest peers' buckets
under Sybil pressure — so the limiter's own memory bound favours the attacker.
`DEFAULT_OPERATIONAL_PAGE_LIMIT` is `u32::MAX`, so the read plane is unbounded.

Volume still has no *constitutional* standing: CC bounds WHO may send, WHAT scope
a row carries, and HOW MANY BYTES may rest, but never RATE. Filed as
CIRISPersist#575.

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
| four-tab card, graded routes, preview hash | server | #346 — tiers 0–4 landed as `src/admin_ops.rs` |
| consensus engine (`consensus_protocol` is a stored label) | server | #111, open |

Three further asks the tier 0–4 implementation surfaced, all persist:

| ask | why |
|---|---|
| `list_attestations` must honour `AttestationFilter::window` | the v17.4.0 window / tier / attester_filter axes are read only by the `list_scores` / `resolve_scores` handles; the general read silently ignores them. Same silent-narrowing class `dimension_exact` was in until v17.5.2 (#461) — a caller sets a predicate and gets rows that do not satisfy it. `src/admin_ops.rs` enforces `after:` in-process and labels the response `window_enforced: "application"` rather than hand an operator a hash over twice the blast radius they ratified. |
| an assemble-only companion to `emit_attestation_self` | `record_quarantine_marker` takes an already-signed `Attestation`, and every sanctioned emit helper canonicalizes-signs-assembles **and puts**. The one door built for tier 2 cannot be reached through the chokepoint built to stop hand-rolled rows. |
| export a "does THIS delegation row carry scope S" predicate | `delegation_scope_set` is `pub(crate)`, so the only public authority question is `reachable_under_scope(issuer → actor, S)` — which is true the moment the issuer granted S by ANY edge. On its own that lets a `review` delegation be *recorded* as the authority for a `slash` act. |
