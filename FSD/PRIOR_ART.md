# FSD — Prior Art & Lessons: TOFU-less, Moderated, Decentralized Networks

**Status:** Research synthesis (2026-07-22), four adversarial lenses — identity/trust
bootstrapping, federated moderation, capability/delegation systems, governance & kill
switches — each briefed to attack our specific invariants, not to reassure. Full cited
reports live in the session record; key sources inline. Companion to
`FSD/TRUST_ROOT_CAPABILITY_GATE.md` and `FSD/MESH_GENESIS.md`; feeds the RC3
ratification (CIRISConstitution#40).

**The one-paragraph verdict.** The architecture is not novel where it matters — it is
the *convergence point* that four separate lineages backed into after their failures:
revocation converged on complete-state-at-the-verifier (CRLite), trust ceremonies on
public m-of-n with named humans (ICANN KSK), moderation on signed labels under local
policy (Bluesky) with consent-gated replication (Freenet darknet, SSB), and identity on
pre-rotated key-event records (KERI/vLEI). Every prior death was **economics,
ergonomics, defaults, or recovery** — never the security architecture. So history's
message is precise: the wire model is validated; the failure modes that remain are
operational, and each has a name below.

---

## 1. Invariant-by-invariant verdict

| Our invariant | History's verdict | Decisive precedents |
|---|---|---|
| Pluggable, user-chosen trust roots | **Validated — it is the escape valve** | Steem→Hive re-rooted around a captured root in 3 weeks, state intact, captor excluded; single mandatory roots (DNSSEC/ICANN, eIDAS Art. 45) are the attack surface |
| Self-referential root charter | **Validated as model, BROKEN as shipped** — no recovery from charter-key compromise | KERI: without a pre-rotation commitment *in the root record*, the attacker owns the tombstoning pen; Parity/EIP-999: powers not pre-committed don't exist when needed |
| Portable self-verifying genesis | **Validated (Keybase-in-reverse), but "self-verifying" is overclaimed** | An attacker's bundle self-verifies identically (KERI/OOBI concedes the same); the TOFU moment moves to the distribution channel |
| Attenuation-bound `delegates_to` | **Architecture validated 4× over; practice fails at the default** | SPKI→macaroons→Biscuit/UCAN all sound; lnd users still ship `admin.macaroon` — narrow-by-default or attenuation is theater |
| Live-graph-walk revocation, no caches | **Validated as endgame, threatened by ops** | CRLite (93% of Firefox checks) proved complete-state-at-verifier; OCSP hard-fail lost — cache creep returns unless every edge also *expires* |
| Exact-string scopes, two-prefix split | **Validated** | SPKI died partly of its tag algebra; enforcement-optional restriction fields (proxy certs) = impersonation |
| Consent-gated replication | **The only design that never had a spam/deliverability crisis** | Freenet darknet + SSB follow-graph — both paid in **growth**, not oligopoly (the tax is real) |
| Infrastructure cannot judge; judgment roles on members | **Validated by the disease it cures** | Mastodon's admin=judge=host=key-custodian conflation; Usenet ISPs amputating what they couldn't judge; Bluesky labels work at 25M+ users |
| Consensual m-of-n kill switch riding the trust edge | **Directionally validated; first use will be a legitimacy crisis** | The anti-baseline is Apple's 2020 OCSP outage ("your computer isn't yours"); DAO fork won on 5% turnout and is still relitigated; Maker: costly-to-trigger + time-delay are the legitimacy currencies |
| Halt = agent capabilities, never device presence | **Validated — and it is legal armor** | Chat Control/OSA mandate *capabilities*; a power that provably doesn't exist can't be compelled (§4.3) |
| 90-day lifecycle refresh | **Double-edged** | ICANN's funded quarterly cadence works; Sovrin died in year 4 — an unfunded refresh is a network-wide expiry bomb |
| No global truth, local policy | **Validated with a warning** | CT per-browser policy broke Symantec; but "local policy" everywhere outsourced to the same three oracles (DNSBL→Spamhaus; blocklist cartels) — defaults are destiny |

## 2. The forced design changes

Numbered; each names where it lands. These are **requirements extracted from failures**,
not suggestions.

1. **Charter pre-rotation + recovery ceremony** *(CRITICAL — TRUST_ROOT FSD §1, RC3)*.
   The self-referential charter record MUST carry a pre-rotation commitment (hash of the
   next key set) and an m-of-n recovery path, or root-key compromise is unrecoverable by
   construction (KERI's raison d'être; the revoker's pen problem).
2. **Genesis honesty scoping** *(MESH_GENESIS FSD §2)*. "Self-verifying" =
   tamper-evident + internally rooted, **never** "the right bundle." The attacker's
   genesis self-verifies too. Add: out-of-band fingerprint comparison as a first-class
   step of attach, and say plainly that the distribution channel is the attack surface.
3. **Recovery is a drill, not a document** *(capability-gate FSD §6; ops)*. HPKP, SSB
   forks, and PGP revocation all failed **at the moment of first real use**. The
   un-trust → re-attach flow must be exercised on live nodes on a schedule. Device
   CEG-log fork/divergence semantics must be specified before 0.6 (SSB: fork = brick).
4. **Expiry on every delegation edge** *(persist/verify; RC3)*. Grants outliving their
   purpose are the dominant real-world breach class (Ronin's stale allowlist; OZ role
   sprawl); short-lived-plus-live-walk is the proven pair, and expiry bounds any illicit
   cache (the OCSP lesson).
5. **Narrow-by-default delegation; full-scope delegation is ceremony-gated** *(server
   gate)*. The `admin.macaroon` pattern is a law of nature: holders delegate everything
   unless narrowing is the path of least resistance.
6. **Halt time-delay window** *(accord design, RC3)*. A mandatory delay between a halt's
   signing and its landing, during which any node may sever its trust edge — Maker's GSM
   72h generalized. This is the consent escape valve made mechanical; it converts
   "who elected these three?" into "you had the window." Pair with pre-commitment
   (powers exist only if declared in advance — Parity) and never act-then-ratify
   (Arbitrum AIP-1).
7. **Holder-independence audit + custody honesty** *(accord ops)*. m-of-n is a property
   of *independence*, not of n (Ronin: 5-of-9 = one org). ICANN under COVID showed
   custody silently degrades to the institution; publish where custody actually lives.
   Note our 2-of-3 is a compromise-any-2 model — the inverse of Zcash's any-1-honest;
   coercing two named humans is cheaper than ML-DSA. The deletable edge + halt-scope
   limit are what make coercion low-yield: keep them provable.
8. **Blessing plurality economics** *(the open bet — RC3 must name it)*. The
   deliverability trap is not in the wire: SPF/DKIM/DMARC was also signed-attestations-
   plus-local-policy, and it centralized because *evaluation* concentrated. If minting a
   new accord and getting it genuinely trusted by senders is not kept as cheap as
   joining an existing one, blessed-serve is Spamhaus with better cryptography, and a
   new node's first experience is email's default-dead. Track it as a measured metric.
9. **The default is the governance** *(client/#304)*. ICP's default-follow neuron and
   mastodon.social prove defaults capture networks. The `trust(user → root)` edge must
   be an explicit, user-signed act at claim (it is), and the UI must never pre-check it.
10. **Judge protection** *(moderation design)*. Attributable judges are doxxable judges
    (Aegis quit in months; #Fediblock curators embattled). Judgment roles need rotation,
    m-of-n cover, and accord-backed legitimacy — attribution alone conscripts volunteers
    into harassment.
11. **Retrospective purge speed** *(accord + storage)*. Consent-gating is prospective;
    Usenet/Freenet died of content already replicated when identified (CSAM). If the
    m-of-n purge path cannot act in hours across jurisdictions, operators will amputate
    unilaterally — quietly reinstating admin-as-judge.
12. **No open-write surface, anywhere** *(standing rule)*. SKS keyserver poisoning is
    the generalized #11-Cut-4 anti-pattern: any unauthenticated write path into a
    replicated store is a poisoning DoS. Consent-gating must hold on every plane,
    including future ones.
13. **Ceremony cadence is an opex line** *(org)*. Sovrin and CAcert died of funding and
    audit labor, not cryptography. ICANN survives because an institution pays for four
    ceremonies a year, forever. Budget the accord's refresh cadence like infrastructure,
    and specify dead-man successor behavior for root-institution death.

## 3. The two-sided ledger

**Strongest precedents in our favor:**
- **CT + ICANN KSK jointly validate the exact combination** we ship: signed append-only
  records, public m-of-n human ceremonies, independent witnesses, per-verifier local
  policy — the only architecture surveyed that measurably broke a CA's power.
- **Steem→Hive is our whole playbook run once in production**: root captured → users
  re-root cheaply, state intact, captor's stake excluded. Forkability is the real
  constitution.
- **CRLite + on-chain permission state**: complete authoritative revocation state at
  the verifier works at planetary scale — we state directly what WebPKI took 25 years
  to back into.
- **KERI/GLEIF vLEI** in regulated production validates pre-rotated, witnessed key
  records; **Keybase-in-reverse** validates the portable genesis; **Freenet darknet +
  SSB** validate consent-gated replication (no spam crisis, ever); **Bluesky at 25M+**
  validates judgment-as-signed-labels under local policy.

**The three bets history says we are making** (name them in RC3, Part 8 style):
1. **The growth tax**: consent-gated replication has never coexisted with mass
   adoption (SSB's visibility wall). We bet the genesis bundle + blessed-serve makes
   joining cheap enough that the spam-proof network is also a growable one.
2. **Blessing plurality**: we bet accord issuance stays economically plural under the
   same cost pressures that gave email Spamhaus and browsers a root-store oligopoly.
3. **First-halt legitimacy**: we bet a 2-of-3 halt with pre-commitment, a severance
   window, and public ceremony survives its first real use with legitimacy intact —
   something no surveyed system achieved on its first emergency.

## 4. Standing design rules (the one-line forms)

- Never accept unauthenticated attachments into a replicated store (SKS).
- Any irreversible commitment needs a recovery path shorter than its blast radius;
  when in doubt, witness instead of commit (HPKP → CT).
- Identity is key *records*, never raw keys (Nostr); rotation is in the record (KERI).
- Fork handling specified on day one or portability is fiction (SSB).
- A restriction the verifier may ignore is not a restriction (proxy certs).
- Freshness is never an optional network fetch (OCSP); completeness or expiry.
- The default issued credential is narrow; fat delegation is a ceremony (macaroons).
- Emergency powers exist only if pre-committed (Parity); costly to trigger (Maker);
  windowed for exit (GSM); never ratified retroactively (Arbitrum).
- m-of-n counts independence, not signatures (Ronin); publish where custody lives
  (ICANN/COVID).
- The institution dies before the ledger; specify the dead-man path (Sovrin).
- Capabilities that provably don't exist can't be legally compelled (OSA/Chat Control);
  un-deletable trust edges are the modern capture attempt (eIDAS Art. 45).
- Defaults are destiny (ICP, mastodon.social, Spamhaus): the default IS the governance.
- Hosting and judging must be different people with different keys (Mastodon), and the
  judges need protection, not just attribution (Aegis).
