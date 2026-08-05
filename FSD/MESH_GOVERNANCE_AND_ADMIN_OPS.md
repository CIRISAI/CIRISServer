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

### The subject's consent gates `capacity:*` and nothing else — on purpose

CIRISServer#351 read the fourth line of the table above the other way round: any
admitted key can write a signed row *naming anyone*, subject-side consent covers
`capacity:*` alone, and that looked like the SKS attach-anything shape with one
family accidentally fenced. CC 3.4.5 has since ruled, and the ruling inverts the
reading — **the fence is the design, and one family is its intended extent**:

- **Consent-before-scoring is family-scoped to `capacity:*`.** Federation-tier
  admission requires a live `consent:scope:analyze` grant from the subject
  covering the scoring community. It is the one place in the whole substrate
  where a consent record is load-bearing at *admission* rather than only in
  governance (CC 3.3.7 says so in terms).
- **The abuse-response families stay open, and generalising the gate would be
  the bug.** `detection:*`, `moderation:*`, `slashing:*` — *"an abuser never
  consents to the response to their abuse."*
- **The fourteen verify families are adjudicated ungated, per family**, on the
  integrity-not-conduct line: *"a forger never consents to verification"*, and
  `rollback_detected:{revision_field}` is an adversarial detector nobody may opt
  out of. Consent gates the family that judges **agents**, never the families
  that verify **artifacts**. (Filed upstream as CIRISPersist#569; adjudicated,
  and pinned as `bootstrap_admission` B5/B7.)
- **A new family cannot land ungated by accident** — CC 3.1.7 R2 makes
  provisional registration *carrying the intended emitter rule* a producer
  obligation at mint, and an emission on an unregistered family a conformance
  failure (`namespace_family_unregistered`) rather than a quiet admit under the
  ProducerSteward fallback.
- **The subject's lever is a counter-claim, not a veto or an erasure.**
  `reconsideration:{grounds}`, on which CC 4.5.5 grants the subject standing
  explicitly as *"the CC 3.4.5 contestation pair"* — contestation at zero
  disclosure. It is what makes the CC 2.4.1.1 rule admissible that a subject may
  **not** withdraw a third-party `capacity:*` or `detection:*` row about itself:
  selective erasure of adverse evidence is reputation laundering, so the door
  closes only because a contest path is open. The two are one ruling.

So the asymmetry #351 named is real and it is deliberate: the subject cannot
refuse attachment, and gets contest instead of veto. What the server owes this
model is not a second gate — persist's admission gate is the boundary, and a
second implementation of a rule is a second answer that can disagree — but an
**honest instrument on the one gate that exists**. `src/scorer.rs` was not one:
`resolve_scoped_consent` returns `Result<ConsentState, _>` and the gate asked
`!matches!(stance, Ok(Granted))`, so a consent read that *failed* was reported as
the subject having *declined* — the one outcome that module declares must never
alarm, and one of the two triggers for its INFO "steady state, not a fault" pass
line. A corpus-wide failure of the CC#46 fold therefore logged, once a minute,
that every agent had declined and all was well. Three zeroes, one arm. Fixed and
mutation-pinned; the remaining upstream ask is in §8.

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

**It was not implemented, at two layers**, and both statements below were true
when this section was written:

1. The `consensus_protocol` vocabulary was `founder_only | unanimous | majority |
   quorum:{m}/{n} | weighted:{rubric} | custom:{id}` — **every form is
   approve-to-act.** No objection form existed.
2. CIRISServer#111 is open: *"no consensus engine — `consensus_protocol` is a
   stored label, nothing reaches consensus."* Communities cannot do forward
   quorum either. **Still true** — forward quorum is untouched by any of this.

### Landed (CIRISPersist#574 / #591, CIRISServer#367)

Persist shipped the mechanism in v25.0.0 and v26.0.0 and this node reaches it as
of `src/commons_surface.rs`. The shape:

```
reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}
```

- the objection IS a signed CEG object (`objection:raised:v1`, a `scores` row),
  so it replicates on the ordinary attestation plane and a peer partitioned
  during the window still counts it when it arrives;
- the reversal is **derived, not discretionary** — `fold_reverse_quorum` is pure
  and evaluated at read time, so every node holding the rows folds to the same
  answer with no coordination and nothing is mutated by an objection's arrival;
- **one objection raises the brake, m-of-n dismisses it**, and the undo side is
  floored at a strict majority of the LIVE roster while the protective side is
  never floored at all;
- **silence is its own arm.** Past the steward deadline with no upholding
  ruling, the escalated undo counts **respondents, not the roster** — the
  property that lets a burned-out commons still resolve — bounded below by
  `ESCALATION_RESPONDENT_FLOOR = 3`, which no policy string may lower
  (`ReverseQuorumPolicy::parse` refuses a sub-floor declaration outright, so a
  cohort configured below it cannot exist).

Two corrections to this section's own framing, forced by the implementation:

1. *"an action takes effect immediately and is undone if m members object"* —
   persist does **not** undo anything. `ReverseQuorumStanding::Reversed` is a
   derived state over held rows in exactly the sense `ConsentState::Revoked` is;
   the objected-to row is never deleted, tombstoned or rewritten. "Undone" is
   what a reader that honours the fold does, and honouring is the reader's.
2. Escalation is **not an op**. Nobody performs it, it grants nobody anything,
   and its instant is a function of the ACTION's `asserted_at` and the cohort's
   declaration alone — so no objector can advance the clock by writing anything.
   The only thing it changes is which denominator the undo is priced against.

The surface (`GET /v1/commons/standing`, `POST /v1/commons/{objections,ballots,
dismissals}`) is deliberately **not** under `/v1/admin/*`: those routes are
authority acting *on* the commons, and this is the commons acting on itself.

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
| **reverse quorum** | persist | **SHIPPED** — #574 (v25.0.0) + #591 escalation-on-silence (v26.0.0); consumed here as `src/commons_surface.rs` (CIRISServer#367) |
| a consensus engine (FORWARD quorum) | server | #111, open — untouched by the above |
| rate/quota plane with reserved admission class | persist | to file |
| mesh-config consumption, ConfigRelief, quarantine-aware offers | edge | #440 |
| per-row delivery receipts | edge | to file |
| four-tab card, graded routes, preview hash | server | #346 — tiers 0–4 landed as `src/admin_ops.rs` |
| consensus engine (`consensus_protocol` is a stored label) | server | #111, open |

Three further asks the tier 0–4 implementation surfaced, all persist:

| ask | why |
|---|---|
| **make CC 4.5.5 subject standing on `reconsideration:{grounds}` substrate-reachable** (persist) | The one part of CIRISServer#351 that is ratified but not yet enforceable. CC 4.5.5 grants the **subject of the target attestation** standing to file a contest — normatively, and as *"the CC 3.4.5 contestation pair"* — but its own target→duty-holder resolution table gives `reconsideration:{grounds}` only `is_named_moderator(·, C, review)`. `takedown_notice` got a subject clause; this did not. Persist implements the table (`check_delegated_duty_scores_admission` routes `reconsideration:` → `review`, `duty_holders_for_community`), correctly: #517 removed the earlier seeding from the row's own `subject_key_ids`, because a self-declared subject set lets any Rooted producer file over any community action. So a subject who is not a named moderator cannot file the contest CC says they hold standing to file — and CC 2.4.1.1 closes the `withdraws` path for `capacity:*` / `detection:*` **on the strength of that contest existing**. Persist has already named the resolver: key it on the referenced prior action, not the row's own envelope (`references_attestation_id_from_envelope` + the retained-but-unreachable `duty_holders_from_signed_subjects`, the `subject_of`-style fail-secure shape `takedown_notice` already uses). Needs the CC table row and the persist wiring in one change; **not** a server gate. |
| `list_attestations` must honour `AttestationFilter::window` | the v17.4.0 window / tier / attester_filter axes are read only by the `list_scores` / `resolve_scores` handles; the general read silently ignores them. Same silent-narrowing class `dimension_exact` was in until v17.5.2 (#461) — a caller sets a predicate and gets rows that do not satisfy it. `src/admin_ops.rs` enforces `after:` in-process and labels the response `window_enforced: "application"` rather than hand an operator a hash over twice the blast radius they ratified. |
| an assemble-only companion to `emit_attestation_self` | `record_quarantine_marker` takes an already-signed `Attestation`, and every sanctioned emit helper canonicalizes-signs-assembles **and puts**. The one door built for tier 2 cannot be reached through the chokepoint built to stop hand-rolled rows. |
| export a "does THIS delegation row carry scope S" predicate | `delegation_scope_set` is `pub(crate)`, so the only public authority question is `reachable_under_scope(issuer → actor, S)` — which is true the moment the issuer granted S by ANY edge. On its own that lets a `review` delegation be *recorded* as the authority for a `slash` act. |

---

## 9. The residual abuse surface, measured (0.5.156 release gate)

Everything above this section is design. This section is what a hostile peer can
actually do against the shipped code, established by running it, and what the
operator can actually do back. The evidence is `tests/abuse_surface.rs` — ten
tests against a real sqlite engine, real `register_federation_key`, real
`put_attestation`, no test doubles, every assertion mutation-verified (the
guarded thing broken, the test RED, the break reverted).

The rule this section keeps: **a control is only claimed if it was seen to
fire.** §6 of this document had to be rewritten once already because it asserted
"zero rate limiting anywhere" about a limiter that shipped. The cure is not more
careful prose.

### 9.1 What fires

| control | demonstrated by | reach |
|---|---|---|
| **reverse quorum** — 1 objection raises the brake, below-*m* does not lift it, *m*-of-*n* does, and `ESCALATION_RESPONDENT_FLOOR` cannot be lowered by a policy string | `tests/commons_surface.rs` `property_1_*` / `property_2_*` / `property_4_*`, all four mutation-verified | commons actions in a cohort that declared a protocol |
| **`PeerWriteQuota`** — one key flooding is refused at the documented allowance with `Error::RateLimited`, and the reserved class keeps `accord:` / `objection:` writable through a flood | `the_peer_write_quota_refuses_a_flood_and_nothing_here_counts_it` | every `put_attestation`, per backend instance, in memory |
| **`capacity:*` anti-Goodhart wall** — self-attestation refused at the federation tier (AV-62/74), refused at the local tier (AV-83), and third-party scoring refused without the subject's `analyze` grant (CC#46) | `capacity_self_inflation_is_refused_at_every_door`, each arm required to name its own rule | the `capacity:*` family |
| **`accord_holder` is not self-assertable** | `a_self_asserted_accord_holder_is_refused_at_the_door` | the halt/kill-switch plane |
| **AV-77 peer de-admission** — a de-admitted key's next write is refused before any DB-walking gate | `av77_deadmission_stops_the_writes_and_no_route_here_emits_it` | this node's own corpus |
| **tier 5 halt is now releasable offline** (#347) | `src/accord_release.rs` + its suite | a halted node, by file drop |

Two of those deserve their qualifier stated rather than implied. The quota is
per **backend instance and in memory**: a restart returns every budget to full,
and a multi-process deployment holds N independent quotas. And AV-77 is **local
by design** — a node refusing an author's writes is that node's sovereignty, not
a federation ban; isolation of a real abuser is emergent across many nodes
reaching the same conclusion independently.

### 9.2 What does not

**The recourse gap, stated plainly.** AV-77 is the only primitive in the stack
that stops a hostile admitted peer from writing. `src/compose.rs` arms it at
boot, reads the value back, and refuses to serve if it did not stick — because
*"a silently-dormant sanction gate is strictly worse than no gate."* **No route
in this server emits the row.** `POST /v1/admin/deadmit` — tier 4, the rung
§3 labels *"key may no longer write"* — writes a `Revocation` on the append-only
key plane and says so itself: *"evidence a reader folds, not a door that
slams … the replication cursors and row ingest all deliberately keep working."*
That is the right act for a **compromised** key and the wrong one for a
**hostile** one. Filed as CIRISServer#375; the gate itself is proven working, so
this is a caller, not a design.

Until it lands, the honest answer to *"a peer we admitted is writing rows we do
not want"* is: **annotate it (tier 0, no effect), quarantine the rows it already
wrote (tier 2, the only reversal that reaches the substrate), or halt the whole
node (tier 5).** Nothing in between stops the next write.

**Four privileged identity types are self-assertable**, and the doors they open
are pure `identity_type` membership tests rather than the re-derivation their
conferral modes promise (CIRISPersist#607, mutation-verified repro):

| self-asserted claim | unlocks | about |
|---|---|---|
| `witness` | `age_assurance:*`, `capacity_assurance:*`, `transparency_log:cosigned:*` | any third party |
| `lenscore_detector` | the whole `detection:*` wildcard | any third party |
| `trusted_publisher` | the `content_rating:` read chain (`lookup_trusted_publisher_chain`) | any third party |
| `substrate_persist` | `system:` / `audit_chain:` / `corpus_health:` / `identity_continuity:` / `federation_directory:` / **`hard_case:`** | its own node — **except `hard_case:`** |

The last cell is the sharp one. `hard_case:` is where `src/admin_ops.rs` writes
every tier 0–4 tombstone, and a tombstone's whole job is to carry the authorizing
`delegates_to` id and reason for an act about **someone else**. persist's own
mode table sets the retirement condition — *"if a `system:*` row ever becomes an
input to a decision ABOUT ANOTHER PARTY, this must move to `AccordCoScrubbed`"* —
and `hard_case:` is not on the list it checks. So the ladder's accountability
plane rests on a claim anybody can make.

These are reachable **over replication**, not only by an operator's own admit
ceremony: `apply_replicated_key_record` → `ReplicatedKeyPlan::Insert` →
`put_public_key`, the same gate chain.

Scope of what was RUN, so the table is not read as more than it is. The
self-assertability of all four is demonstrated
(`which_privileged_claims_are_self_assertable_and_which_are_gated` registers
every member of `AUTHORITY_CONFERRING_IDENTITY_TYPES` and pins the exact
admitted/refused split — seven and two). The *emission* consequence is
demonstrated for `witness` (`age_assurance:level:adult` about a third party),
`lenscore_detector` (`detection:correlated_action`) and `substrate_persist`
(`hard_case:admin_action`). The `trusted_publisher` → `content_rating:` read
chain is **by inspection of `lookup_trusted_publisher_chain`, not run** — treat
it as the weakest cell in the table until someone drives it.

Not every self-assertable claim is a hole: `steward`, `partner` and
`wise_authority` are also in the admitted set and are fine, because their
authority genuinely is re-derived at each use (the steward-binding walk, the
licensure quorum, the WA adjudication edge). The defect is not "a claim is
self-assertable" — it is *a claim whose conferral mode promises re-derivation
opening a door that does a membership test instead.*

**The receive plane still has no subject** — §0's first architectural finding,
unchanged. Any admitted key writes signed rows naming anyone; subject-side
consent exists for `capacity:*` alone. Edge #426 threaded the authenticated
`source_peer` to the apply layer so a per-peer receive decision is *expressible*;
`dispatch_apply` does not take it, and nothing expresses one.

**A sanctioned key keeps the sanctioning dimension.** `check_peer_deadmission`'s
exemption is a disjunction that never asks who is writing, so a de-admitted key
may go on writing `revocation:peer_admission:v1` rows about anyone
(CIRISPersist#608). They have no local effect and they replicate.

**The quota's refusal has no reader.** The refusal is correct and nothing counts
it: `PeerQuotaObservation` exposes only the #583 tail-squeeze tripwire, so a node
refusing 100% of a peer's writes renders `peer_quota: clean`, band **green**.
This is the 2026-08-05 shape exactly (`FSD/RCA_INGEST_REJECTION_2026-08-05.md`) —
a correct refusal nobody is reading — on the one control a hostile peer will
actually trip. Filed as CIRISPersist#609.

**Two keys defeat every consent wall.** The `capacity:*` gate is satisfied by the
abuser granting `analyze` to its own second key. That is §7's *"m-of-n counts
keys, not independent humans"* and it is not payable here; it is pinned
(`a_two_key_sybil_still_inflates_its_own_capacity`) so it stays a measured fact
rather than a paragraph.

### 9.3 Corrections to §6

§6 describes the v22/v24 quota. At the pinned persist v29.0.0 it is materially
stronger and the stale text should not be inherited:

- **bytes ARE metered** (`QuotaDimension::Bytes`, #583) — "bytes are not counted
  at all" is false;
- the tracked-peer cap is **8192**, not 4096, and rotation buys nothing: an
  untracked identity spends a **shared tail budget**, so a Sybil wave contends
  with itself rather than with honest peers;
- a **reserved admission class** ships (`accord:` / `objection:`, charged against
  its own bucket and nothing else), which is §6's own must-ship caveat, closed;
- a restart is worth **one node-wide burst (6 000 writes)**, not the
  2 611 200 it was, because the node-wide budget is charged by every ordinary
  write regardless of how many identities produce them.

What remains true from §6: only `put_attestation` is guarded, the buckets are
in-memory and reset on restart, and the reserved class is decided by a **pure,
therefore forgeable, predicate** — traffic shaped as `accord:*` exhausts the
reserve before the emitter rule refuses it a few gates later (persist's #575 ask
(d)).

### 9.4 The one-paragraph answer

An attacker who gets one key admitted — which costs a self-signed
proof-of-possession — can write signed rows naming anyone on every ungated
dimension, can self-assert `witness`, `lenscore_detector`, `trusted_publisher` or
`substrate_persist` and reach the age-assurance, detection, publisher and
hard-case planes about third parties, can inflate its own capacity score with a
second key, and can flood at 600 rows/minute sustained with the refusals landing
in a counter nobody reads and resetting on every restart. The operator's answer
is: quarantine what was already written, or halt the node. **The one control that
would stop the next write is built, armed, proven, and has no caller.** That is
CIRISServer#375, and it is the smallest change on this page with the largest
effect on what an operator can actually do.
