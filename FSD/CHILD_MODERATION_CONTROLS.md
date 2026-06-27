# FSD — Child Moderation & Content Controls Through an Adult Steward

**Status:** Draft for human review + ratification. Not law.
**Constitution baseline:** CC 0.5.1 (`ciris-constitution-0.5.1.tex`).
**Companion specs:** `FSD/MODERATION_CHILD_SAFETY.md` (the delegable-duty spine + named-moderator invariant), `FSD/SAFETY_LANDSCAPE.md` (comparative posture).
**Feeds:** the under-18 stewardship wizard and the reverse-quorum moderation UI (in build).

---

## 0. One-paragraph thesis

"Teens are children." Under CC 0.5.1 the I1 age band is **binary** — `minor` (< 18) / `adult` (≥ 18) — and a minor `user` identity **MUST** carry a live `delegates_to(adult-user → minor-user)` at all times or it does not operate (CC 0.5.1 §2580, the minor-stewardship rule). This spec defines, on top of that one structural fact, an **age-graduated control surface**: what a minor may do alone vs. what requires their accountable adult steward, the **protective cohort-scope default** for everything a minor creates, the **child's own moderation/help path**, the steward's **accountability (not surveillance)** oversight surface, and **transfer/revocation** of guardianship. Every mechanism below **rides an existing CC primitive — no new wire shape** (CC 0.5.1 §2600, "1+4 preserved").

> **Honest boundary up front.** The protocol declines client-side scanning (CC 4.5.7) and provides structural invisibility for self/family content (CC 5.2). An adult steward is therefore **accountable for** a minor, never **omniscient over** them. The steward cannot read the child's private cohort content any more than anyone else can — E2E encryption is symmetric, it does not exempt the guardian. The steward's power is **structural and accountability-based**, not content-inspection. This is a feature, not a gap (see §5).

---

## 1. The relationship model — responsibility, not property

### 1.1 What the binding *is*

| Property | Value | CC cite |
|---|---|---|
| Wire shape | `delegates_to(adult-user S → minor-user T)` | §2580 (CC 2.4.1) |
| Agreement-to-stewardship | `S` is the `attesting_key_id`; **its signature on the envelope IS the consent** to be the accountable responsible party | §2580 |
| Admission predicate | `admit_user_steward_binding`: `T` is `user` ∧ `age_band(T)==minor` ∧ `S` is `user` ∧ `age_band(S)==adult` ∧ `S == attesting_key_id` — else **REJECT** | §2589–2595 |
| Liveness requirement | binding MUST be **live** (non-superseded, non-withdrawn) at **all times** | §2580 |
| Fail-secure | a minor whose binding goes non-live is **steward-less and MUST NOT operate** until re-stewarded — identical posture to a steward-less node/agent | §2580 |
| Lifecycle | transfer rides `supersedes`; revocation rides `withdraws` (CC 2.4.1.1) — **no new primitive** | §2580, §2600 |

### 1.2 The no-slavery guarantee (what responsibility grants and does NOT)

CC 0.5.1 §2569–2578 is explicit: **"a steward is responsible *for* a ward, never a holder *of* one."** A minor is one of exactly three stewardable subjects (node / agent / minor); a self-sovereign adult is **un-stewardable** (no `delegates_to` targeting an adult is ever admissible — §2595).

**The steward's responsibility concretely GRANTS the adult:**
- **Co-signature authority** on the minor's authority-acts (publishing at wider scope, accepting agency/partnership, settings changes) — see §2.
- **Standing to act on the minor's behalf** in moderation (propose, escalate, defend/keep, or request takedown) as a delegated `moderate`/`review`/`takedown` duty (CC 4.5.5, §4767).
- **Receipt of escalations** routed from the child's account (reports the child files, safety interstitials) — §4.
- **An accountability surface** — the metadata/standing/structural view in §5.

**The binding does NOT grant the adult:**
- ❌ Read access to the minor's `self`/`family` private content — **no surveillance backdoor**; CC 4.5.7 declines client-side scanning and §6747/§5828 keep self/family bytes off the discovery surface for everyone, the steward included.
- ❌ Ownership of the minor's identity, keys, or corpus — the minor **owns their own corpus** and key material; the steward holds **no decryption capability** by virtue of the binding.
- ❌ Power to act *as* the minor (impersonation). The steward acts **as the steward, on-behalf-of**, with their own signature carried into `actor_user_id` (CC §641 audit discipline) — every steward act is attributable to the steward, never disguised as the child.
- ❌ Any authority over the minor after the binding goes non-live, or once the minor reaches `adult` band (the binding becomes inadmissible — §2595 — and self-sovereignty attaches).

---

## 2. Age-graduated capability — child alone vs. steward-mediated

### 2.1 The hard constitutional floor (binary) and the soft policy gradient (graduated)

CC 0.5.1 gives **one** band boundary: `minor`/`adult` at 18 (§2597). Everything finer-grained — "younger child" vs. "teen" — is **a CIRIS policy layer, not constitutional fact**, and is a **decision for the human ratifier** (see §7). This spec proposes a default gradient but flags the thresholds as contested.

Proposed graduation bands (all are sub-bands of the constitutional `minor`):

| Band (proposed) | Age (proposed) | Posture |
|---|---|---|
| **C — younger child** | < 13 | Maximal protection; steward co-signs nearly all authority-acts. |
| **T — teen** | 13–17 | Graduated autonomy; child acts alone at narrow scope, steward gates the wide-scope/agency acts. |
| **A — adult** | ≥ 18 | Self-sovereign; binding inadmissible (§2595). |

> All three are **age-graduated UX defaults over a single structural fact**. The substrate only knows `minor`/`adult`; the C/T split is enforced by the wizard + fabric policy and is **fully overridable by the steward** (a steward may tighten a teen toward C, or loosen within bounds), and is **ratifier-tunable**.

### 2.2 Who may do what

| Act | Younger child (C) | Teen (T) | Mechanism / CC cite |
|---|---|---|---|
| Read/consume (age-appropriate, gated) | ✅ alone (content-class gated, §3789) | ✅ alone | viewer below `adult` assurance **BLOCKED** from `adult` content_class — §3789 |
| Create content at `self` | ✅ alone | ✅ alone | CC 5.2 structural invisibility; never leaves the device-cohort |
| Publish at `family` | ✅ alone (family-internal) | ✅ alone | CC 3.3.4; family-roster-gated, not advertised out (§4256) |
| Publish at `community` | ⚠️ **steward co-sign** | ✅ alone | community DEK cascade, federates-within-cohort (§2290, §4262) |
| Widen scope to `federation`/public | ❌ **steward co-sign required** | ⚠️ **steward co-sign required** | the opt-in public-commons step (§697); scope-widening is the high-water act for a minor — §3 |
| Accept partnership / agency / a bound agent | ❌ steward acts | ⚠️ **steward co-sign** | agency is an authority-act rooting in an accountable human (§622, §2573) |
| **Propose** a moderation action (report) | ✅ alone | ✅ alone | open labeling — **anyone MAY file a `scores`** Contribution (§5459, §5853) — a child must be able to report |
| **Resolve** moderation as a named moderator/steward | ❌ | ❌ (not until adult) | `moderate` duty roots in an accountable human (§4767); a minor is not the accountable root |
| Change security/identity settings (key rotation, recovery) | ❌ steward acts | ⚠️ **steward co-sign** | custody-sensitive; rooting in the accountable adult |
| Change own content/privacy settings (tighter only) | ✅ alone | ✅ alone | a minor may always tighten their own protection; only **loosening** gates |
| Operate at all | only while steward-bound | only while steward-bound | **fail-secure** — §2580 |

**Rule of thumb:** a minor may always **narrow** (tighten privacy, restrict scope, report harm). **Widening** — scope, agency, security posture — gates on the steward, graduated by band. "Co-sign" = the act is composed of the minor's `Contribution` **plus** a steward `delegates_to`/co-signature carried in the same window; absent it, the act does not admit at the wider scope.

---

## 3. Content controls — the protective default

### 3.1 The protective cohort-scope default (structural-invisibility primitive)

CC 0.5.1 §697 makes **cohort-scoped confidentiality and structural initiator anonymity the DEFAULT**, with **federation/public scope as the explicit opt-in** — corrected precisely *because* the non-savvy vulnerable (the constitution names **"a teenager in a hostile household"**) lose protection under an opt-in model. For a minor this default is **mandatory baseline, not a flag to remember**:

- Everything a minor creates is **born at `self`/`family`/`community`** and **never advertised to outsiders** — CC 5.2 structural invisibility: `self`/`family` content emits **no** `holds_bytes:sha256:*` at all (§6747, §4256), so outsiders cannot even discover the content exists.
- `community`-scoped minor content is encrypted at rest under the per-community DEK and federates **within the cohort only** (§2290, §4262) — cleartext *provenance* federates, never cleartext bytes.
- The default for a minor SHOULD be the **smallest cohort consistent with intent** (§697), biased one rung tighter than the adult default (propose: minor's create-default = `family`, vs. an adult's intent-driven default).

### 3.2 Scope-widening gates for minor-authored content

Widening `community → federation` (public commons) is the **high-water act** (§697). For minor-authored content:

| Transition | Younger child (C) | Teen (T) |
|---|---|---|
| `self → family` | child alone | child alone |
| `family → community` | steward co-sign | child alone |
| `community → federation`/public | **steward co-sign (hard gate)** | **steward co-sign (hard gate)** |

What the steward can review/approve at the widening seam:
- The **act of widening** (the steward co-signs the scope-change `Contribution`), **not the plaintext** beyond what the minor chooses to show the steward out-of-band. The steward approves *that this goes public*, structurally — they are not granted a decryption capability by approving.
- A **perceptual-hash tripwire fires at scope-widening only** (the publish/share seam), never over the private content (§5896, §2228): widening to a watchlist-enabled scope runs the matcher at that seam; a CSAM match auto-fires `takedown_notice{PerceptualHashCsam}` (CC 4.5.3). This is the **only** point detection touches minor content, and it is **at the moment of widening, on the way out**, consistent with CC 4.5.7's refusal of client-side scanning of private content.

> **No client-side scanning of the child's private life.** The fabric does not, and MUST not, scan a minor's `self`/`family` content — not for the steward, not for safety, not for anyone (CC 4.5.7, §5896). The tripwire lives at the **widening seam**, where the child is choosing to make content cross a trust boundary.

---

## 4. Moderation controls a child gets — the help path

**Principle: a child must be able to report and seek help, and a steward-less minor cannot operate at all (fail-secure).**

### 4.1 What the child can do directly

- **File a report** on anything they see — `scores` Contribution, **open labeling, no authority required** (§5459, §5853: "Anyone MAY propose a moderation action"). A younger child and a teen both have this, unconditionally.
- **Tighten their own exposure** — block, mute, restrict scope, leave a community — always available, never gated (§2.2).
- **Trigger the protective-default removal** — a harm report defaults to **removal**; content survives only by an affirmative on-record keep-decision (§5871). A child's report against harmful content directed at them is therefore **structurally strong**: silence removes it.

### 4.2 Routing — direct and escalated

A minor's report routes on **two rails simultaneously**:

1. **Direct into the community reverse-quorum** (CC 4.5.13, §5845) — opens the 48 h window; the community's named moderator/steward may act unilaterally by a single signature, else the live-majority community vote carries. The child's report enters this exactly as any member's would.
2. **Escalated to / through the adult steward** — the report (and any safety interstitial the child hits) emits an escalation to the steward's oversight surface (§5), and the steward MAY act as a **delegated `moderate`/`takedown`/`review` duty-holder on the child's behalf** (CC 4.5.5, §4767/§5452): propose, defend, request takedown, or escalate further. The steward is the child's **accountable advocate in the adjudication**, not a filter on their voice — the direct rail fires regardless.

### 4.3 Fail-secure posture

- A minor whose steward-binding is **non-live MUST NOT operate** (§2580) — including not silently losing their help path. The wizard MUST surface "you need a steward to continue" rather than degrade to a silent read-only/limbo state, and MUST preserve the **emergency-report path** as the one capability that should remain reachable while re-stewardship is arranged (**OPEN — see §7**: whether *any* capability survives a non-live binding, or whether the report path is a constitutional exception, is a ratifier decision; the constitution's literal text is "MUST NOT operate").
- The named-moderator existence invariant (CC 4.5.4, §5446) guarantees the community the child reports into **always has an accountable moderator or fails-secure** (does not federate at moderated capability) — there is never a moderator-less group silently swallowing a child's report.

---

## 5. The steward's oversight surface — accountability, not surveillance

The steward's panel is framed and built as **accountability**, and is honest about the **E2E wall**.

### 5.1 What the steward SEES

| Surface | Visible? | Why |
|---|---|---|
| The live binding + its lifecycle (when granted, by whom, supersession/withdrawal history) | ✅ | public structural facts (`delegates_to`, `supersedes`, `withdraws`) |
| The minor's **standing**: communities joined, agency/partnerships accepted, moderator-track-record | ✅ | authority-acts the steward co-signed or is accountable for |
| **Scope-widening events** the minor proposes (the co-sign queue) | ✅ | the steward is the gate (§3.2) |
| Escalations: reports the child filed, safety interstitials the child hit, takedown actions touching the child | ✅ | the §4.2 escalation rail |
| `hard_case:*` flags touching the child's communities (e.g. `watchlist_match`, `moderation_filed`) | ✅ | federation-health observability (§2224) — never silent |
| **The minor's `self`/`family` private content (plaintext)** | ❌ **NEVER** | CC 5.2 / CC 4.5.7 — no decryption capability rides the binding |
| `community` content the steward is not a member of | ❌ | community DEK is wrapped to **members** only (§4262) |
| The minor's location, device chatter, message contents | ❌ | structural invisibility (§6038) — the steward is an outsider to it like anyone else |

### 5.2 What the steward can ACT on

Co-sign/deny scope-widening and agency acts (§2); act as delegated moderation duty-holder for the child (§4.2); set the child's content/privacy defaults **tighter** (and, within band-policy bounds, looser — §2.1); initiate transfer/revocation of their own stewardship (§6). Every steward action carries the **steward's** identity into `actor_user_id` (§641) — the steward's oversight is itself **on the record and auditable**, symmetric with everything else (the Recursive Golden Rule is structural — §622: no principal, including the steward, is exempt).

### 5.3 The honest framing (must be in the UI copy)

> The steward sees **that** the child acts, joins, reports, and widens — **structural facts and accountability metadata**. The steward does **not** see **what** the child says, holds, or reads privately. Encryption is symmetric: being the responsible adult does not hand you a key the child did not give you. Your power is to **gate the child's outward steps and to advocate for them in moderation** — not to read their diary. A surveillance backdoor is exactly what CC 4.5.7 refuses, for the child as for everyone.

---

## 6. Transfer & revocation of guardianship

All of this rides existing structural composers — **no new primitive** (§2580, §2600).

| Event | Mechanism | Effect on the minor |
|---|---|---|
| **Transfer to a new guardian** | new guardian's `delegates_to(new-adult → minor)` carried as a **`supersedes`** (CC 2.4.1.1) of the prior binding | seamless — binding stays live across the swap; the minor never enters steward-less state if supersession is atomic |
| **Revocation by current steward** | current steward emits **`withdraws`** of their binding | minor becomes **steward-less → MUST NOT operate** until re-stewarded (§2580) — fail-secure |
| **Revocation by a party with revocation authority over the binding** | `withdraws` by that subject | same fail-secure outcome |
| **Minor reaches adulthood** | `age_band(T)` flips to `adult`; any `delegates_to` targeting them becomes **inadmissible** (§2595) | self-sovereignty attaches; the binding falls away; the (former) ward is now un-stewardable |

### 6.1 What happens to the child's data/standing on transfer

- **The minor owns their corpus and keys** — these do **not** transfer with guardianship. A guardianship change re-points *accountability*, not *ownership*. The new steward inherits **no decryption capability** and **no claim on the data** (consistent with §1.2 and §5.1).
- **Standing persists** — communities, moderation track-record, content lineage are the minor's; they survive the steward swap.
- **Co-sign authority re-roots** — pending scope-widening/agency co-signs now route to the new steward; the prior steward's co-sign queue for this minor closes.
- **Audit continuity** — the prior steward's acts remain attributable to them (`actor_user_id`); they are not retroactively reassigned. Transfer is forward-looking.
- **Atomicity requirement (implementation):** the wizard SHOULD perform transfer as `supersedes` so the binding is **never momentarily non-live** (which would fail-secure the minor mid-transfer). A revoke-then-re-add sequence MUST warn that it parks the minor in steward-less limbo in between.

---

## 7. Open questions / decisions for the human ratifier

These are **genuinely contested or under-determined by CC 0.5.1** — not for an implementer to invent:

1. **Age-graduation thresholds (the C/T split).** CC 0.5.1 is binary (`minor`/`adult` at 18, §2597). The "younger child < 13 / teen 13–17" split in §2.1 is a **proposed default, not constitutional**. The 13 boundary echoes COPPA but is **jurisdiction-variant** (GDPR Art. 8 lets member states set 13–16; other regimes differ). **Decision:** ratify a default split, and decide whether it is fixed, steward-tunable, or jurisdiction-resolved.

2. **Jurisdiction variance generally.** Age of majority, age of digital consent, and mandated-reporting obligations vary by jurisdiction. CC offers `lawful_access` (§4556, declared/scope-bounded/never-covert) and the I1 age bands, but **no built-in jurisdiction resolver**. **Decision:** does CIRIS resolve jurisdiction at all, or stay jurisdiction-agnostic and push it to deployment policy?

3. **Age assurance rung.** CC 3.3.12 ladder is `age_self_declared` (self) → `age_assurance:provider` → `age_assurance:government` (§3766). **Decision:** what rung is required to *be* a minor vs. to *steward* a minor? Self-declared is trivially gameable; provider/government assurance is privacy-invasive. Where on the ladder is the minimum, and does it differ for the steward (whose adulthood gates the binding, §2592)?

4. **The fail-secure exception for the help path.** §2580 says a steward-less minor **MUST NOT operate**. §4.3 proposes preserving an emergency-report capability through steward-less limbo. **These are in tension.** **Decision:** is the report path a ratified constitutional exception to "MUST NOT operate," or does a steward-less minor truly go dark (relying on the speed of re-stewardship)?

5. **Steward-set "looser" bound.** §2.1 lets a steward loosen a teen's defaults "within band-policy bounds." **Decision:** what is the floor a steward may *not* loosen below (e.g. can a steward authorize a 14-year-old to publish at federation unilaterally)? Define the non-overridable protective minimum.

6. **Co-sign UX vs. a standing pre-authorization.** Must every teen scope-widening be individually co-signed, or may a steward grant a **bounded standing pre-authorization** (e.g. "this teen may publish to community X at will for 6 months") via `delegates_to` with `delegation_valid_until` (the §4547 term-bound hierarchy pattern)? **Decision:** per-act co-sign vs. attenuable standing grant — a real autonomy/safety trade-off.

7. **Multi-steward / split guardianship.** Real custody is often shared (two parents, a parent + agency). CC's `delegates_to` is a DAG and supports multi-parent roles (§4547), but the minor-stewardship admission rule (§2589) is written for a single `S`. **Decision:** does CIRIS support *co-stewardship* (M-of-N adult sign-off for the child's acts), and if so, how does revocation by one of N behave?

---

## 8. Implementation hand-off summary (no new primitives)

Everything above rides existing CC 0.5.1 shapes — the build is **composition, not new wire**:

- Binding + lifecycle: `delegates_to` / `supersedes` / `withdraws` (§2580, §2600).
- Admission gate: `admit_user_steward_binding` (§2589) — substrate-enforced at admission.
- Content default: cohort-scope + CC 5.2 structural invisibility (§697, §6747).
- Scope-widening tripwire: per-group watchlist at the publish/share seam (§2228, §5896) — never on private content.
- Child report + adjudication: open-labeling `scores` + reverse-quorum (CC 4.5.13, §5845); protective default-remove (§5871).
- Steward-as-advocate: delegated `moderate`/`takedown`/`review` duty (CC 4.5.5, §4767/§5452).
- Content gating for the child as viewer: `content_class` + `age_assurance` protective gate (§3789, §5200).
- Audit: every steward act carries `actor_user_id` (§641).

The named-moderator existence invariant (CC 4.5.4) and the delegable-duty spine are already specced in `FSD/MODERATION_CHILD_SAFETY.md`; this document is the **minor-specific overlay** on that spine.
