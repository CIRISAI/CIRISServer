# Admin operations — failure taxonomy first

Written for 0.5.154, the last of the 0.5 series. Two threads: *what do we need
from the substrate*, and *what is the exhaustive set of admin ops*. The second
determines the first, so this document is the second — and it starts with what
has actually gone wrong on real meshes, because an op set derived from
imagination protects against imagined things.

Every family below names at least one real incident. Where our own mesh has
already produced an instance, it is marked **[ours]** — four of the six families
have one, which is the strongest argument that this is not a theoretical
exercise.

---

## The lesson that outranks the others

**Usenet, 1994–1996.** The Green Card spam made mass posting a real problem, and
the response was the `cancel` control message: a post that deletes another post.
It worked, briefly. Then people forged cancels. *Cancel wars* followed —
attackers deleting legitimate posts at scale, and the removal primitive became a
larger attack surface than the spam it was built for.

The fix was **NoCeM** (1996, "no see 'em"): instead of a message that *deletes*,
a **signed notice that says "I judge this to be spam"**, which clients and
servers may choose to honour based on whether they trust the signer. Nothing is
destroyed. Authority is per-reader. A forged notice is worthless because it does
not verify.

Every durable system since has re-derived this shape:

| system | the primitive | who decides |
|---|---|---|
| Usenet NoCeM | signed judgement notice | each server/client |
| Matrix policy rooms (mjolnir/draupnir) | ban list as a subscribable room | each server subscribes |
| Fediverse | suspend / silence / limit, per-instance | each instance |
| Tor | directory-authority *flags* on relays | consensus of authorities |
| CT | distrust *dated and graded*, with wind-down | each browser |

**Design principle, stated once and applied throughout:** a mesh-native admin op
is *a signed, attributable, subscribable marker* — never a destructive global
command. CEG already has this shape (`withdraws`, `HardCaseEvent`,
`delegates_to` duty scopes). We should not invent a second one.

The corollary matters as much: **the removal primitive is itself an attack
surface.** Any op below that can destroy must answer "what happens when it is
issued wrongly, or by a compromised authority?" before it ships.

---

## The taxonomy

Six families. The axis that matters for op design is **what the response must
reach** — a key, a set of rows, a content item, or a whole node — because that is
what determines the substrate primitive.

### 1. VOLUME — the corpus grows faster than anyone reads it

| # | Failure | Real precedent | **[ours]** |
|---|---|---|---|
| 1a | Honest churn — a well-behaved participant re-establishing state on a loop | SSB feed bloat; every append-only log | QA agent re-establishing "as practice" |
| 1b | Misconfigured cadence — a correct emitter at a wrong rate | Usenet loops; monitoring-agent storms | **0.5.148**: cadence 3600→60 produced 1,527 identical capacity rows against a 7-day validity |
| 1c | Deliberate flood | Usenet Green Card (1994); Mastodon automated-signup spam (2022–23); Matrix (2019) | — |
| 1d | Unbounded derived state | SMTP backscatter; DNS amplification | leviculum: 67,118 packet hashes + 6,081 destinations loaded synchronously at boot |
| 1e | Accumulation with no retirement | Freenet/IPFS have no deletion primitive by design | 9,811 `health:liveness:v1` rows → a 152s `config_resolution` boot phase (#343) |

**Note the split.** 1a/1b/1e are *not adversarial*. They are the common case, and
three of the five are ours. An admin toolkit that only handles malice will be
used mostly on honest mistakes, which is an argument for the response being
graded and reversible rather than punitive.

### 2. IDENTITY — who is permitted to speak

| # | Failure | Real precedent | **[ours]** |
|---|---|---|---|
| 2a | Sybil — many cheap identities | Tor relay-early attack (2014); BitTorrent DHT | Bootstrap is deliberately cheap: a self-signed hybrid PoP and nothing else |
| 2b | Key compromise — a legitimate identity, now hostile | DigiNotar (2011); npm account takeovers | — |
| 2c | Impersonation / squatting | PyPI + npm typosquatting; dependency confusion | — |
| 2d | Identity loss / feed fork — the holder cannot recover, or two devices fork one identity | SSB's canonical unrecoverable failure | — |
| 2e | Eclipse — isolating a node's view of the mesh | Bitcoin eclipse attacks | — |

2b is the hardest and the least served today: the key is *valid*, its history is
*legitimate*, and everything it says from time T is suspect. This needs a
**time-bounded** response, which nothing in the current model expresses.

### 3. CONTENT — what was said

| # | Failure | Real precedent |
|---|---|---|
| 3a | Illegal content | Every federated system with media has faced CSAM: fediverse, Freenet, IPFS |
| 3b | Accidental PII / wrong-scope publication | Routine; the reason GDPR Art. 17 exists |
| 3c | Targeted harassment | Fediverse harassment waves; the driver of instance-level blocking |
| 3d | Misinformation at scale | Out of scope for substrate ops — a composition/policy question |

3a is the one with legal urgency and the only family where "leave the blur" needs
explicit legal review. CC 6.1.2's forced descent purges only *still-recoverable*
tiers — that is likely correct but it is a claim worth having counsel confirm
before it is the answer to a takedown order.

### 4. TRUST — claims about others

| # | Failure | Real precedent | **[ours]** |
|---|---|---|---|
| 4a | False attestation — a scorer lying about a subject | CT misissuance (Symantec, DigiNotar) | Persist's own honest limit: `n_eff` masses are aggregator-attested and unverifiable (R9) |
| 4b | Collusion / reputation farming — mutual scoring rings | Every reputation system; link farms | — |
| 4c | Revocation that does not propagate | The CRL/OCSP soft-fail problem — revocation famously does not work | `consent:state:*` rows: 240 peers, zero grants, until 0.5.151 |
| 4d | Stale trust — a compromised key still trusted downstream | DigiNotar's long tail | — |

4c deserves emphasis. **The single most-repeated lesson in PKI is that
revocation does not arrive.** Any op below that depends on a revocation reaching
peers must state how it fails when it does not — and must fail closed.

### 5. MISTAKE — operator error, no adversary

| # | Failure | Real precedent | **[ours]** |
|---|---|---|---|
| 5a | Wrong-scope publish — self/family data emitted at federation | Routine | `config:*` was stamped `cohort_scope=FEDERATION` (SRV-4/#324) |
| 5b | Test data escaping to production | Every system | QA agent traffic on the production canonical |
| 5c | Bad migration / schema | Routine | — |
| 5d | Clock skew — signed rows with impossible times | NTP failures; the reason `fresh_as_of` has a future-skew guard | — |
| 5e | Accidental mass-revoke — the destructive op fired wrongly | npm left-pad (2016) → the unpublish-window policy | — |
| 5f | Wrong bless — an authority admitted the wrong node/key | CA misissuance | Four genesis mints before one was correct |

5e is the reason every op in the next section needs a **preview**. left-pad
un-published one small package and broke a large fraction of the JavaScript
ecosystem; the lesson npm drew was not "never retract" but "retraction needs a
window and a blast-radius check."

### 6. AVAILABILITY

| # | Failure | Real precedent | **[ours]** |
|---|---|---|---|
| 6a | Resource exhaustion | Routine | 909s boot; 21 MB DB with a 9.5 MB WAL |
| 6b | Partition / netsplit | IRC netsplits | — |
| 6c | Poison pill — one row that breaks every consumer | Protocol fuzzing | Signed-row divergence #541: one malformed row, every peer refused it |

---

## What this implies for the op set

Reading the six families together, responses fall into **five graded tiers**, and
the grading is the point — the fediverse's suspend/silence/limit trio exists
because a single "ban" verb was too blunt, and Tor flags rather than erases for
the same reason.

| tier | verb | reaches | reversible | family served |
|---|---|---|---|---|
| 0 | **annotate** — signed judgement, no effect until honoured | a row / a key | trivially | all — the NoCeM shape |
| 1 | **throttle / limit** — accept but deprioritise | a key | yes | 1a 1b 1c 2a |
| 2 | **quarantine** — withhold from serving, retain locally | a row set | yes | 1c 3a 3c 4a 5a 5b |
| 3 | **force descent** — CC 6.1.2 revocation pressure, purge still-recoverable tiers, keep the blur + tombstone | a row set | no (by design) | 3a 3b 4a 5a 5b |
| 4 | **de-admit** — the key may no longer write | a key | yes, by re-admission | 2a 2b 2c 4b |
| 5 | **halt** — accord kill switch, node-wide | a node | yes, accord | constitutional only |

**Today we have tier 0 (partially) and tier 5. Nothing in between.** That is the
gap: the only tool between "write a note" and "stop the whole node" is nothing.

Two properties every tier ≥1 op must carry, derived from 5e and the cancel wars:

- **Preview before commit** — the exact row set, count, and blast radius, computed
  and shown before anything is written. The UI asks for this ("selection of nodes
  by filter and preview of ops"); the taxonomy says it is not a nicety.
- **Authority recorded in the artifact** — the authorizing `delegates_to`
  attestation id and a reason string, in the tombstone. An admin action that does
  not carry its own authority is indistinguishable from an unauthorized one the
  moment the actor is gone, and *that* is the property that makes a compromised
  authority survivable: you can enumerate everything it did.

And one that applies to tier 3 alone: **time-bounding**. Family 2b (key
compromise) needs "everything this key said after T is suspect" — not "this key
is bad." Nothing in the current model expresses a time-bounded judgement, and
without it the response to a compromise is to discard the key's entire honest
history.

---

## Status

This document is the taxonomy half of #344 and the input to the 0.5.154 op-set
and substrate-ask work. It is deliberately written before any op is designed, so
that the op set can be checked against it rather than justified by it.
