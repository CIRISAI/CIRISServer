# Rostered-group key ops — the complete catalog (HUMANITY_ACCORD + any cohort)

**Status:** living spec / coverage checklist. **Scope:** CIRISServer (the fabric-node
surface). **Normative roots:** CC 4.2 (HUMANITY_ACCORD), the CEG/accord runbook
(§5 holder records, §7 family/genesis, §11.7.1 membership revocations, §11.10
withdraws/recants), and the verify quorum spine (`verify_quorum_policy`,
`federation_keyset`, `accord_genesis`).

This document answers one question durably: **"have we covered every key/membership
operation a rostered group needs across its whole lifecycle?"** It does so by
mapping our ops onto an external, exhaustive lifecycle standard, then listing each
op with its authorization, mechanism, and status.

---

## 1. The model: rostered groups on a visibility gradient

Persist backs **three rostered groups** — a `members[]` roster + an append-only
membership-revocation table + the load-bearing `active = roster − effective
revocations` fold:

| Cohort | Members are | Visibility | Governance |
|---|---|---|---|
| `self` (identity_occurrences) | occurrences of **one** identity (your devices/keys) | local-only (no `holds_bytes`) | none |
| `family` | **N distinct** identities | **structurally invisible** (`holds_bytes` suppressed, DEK-wrapped) | `consensus_protocol` + **entrenchment** |
| `community` | **N distinct** identities | federates normally (discoverable) | `consensus_protocol` + **moderation** |

`affiliations` / `species` / `biosphere` / `federation` are **audience/visibility
tiers only — not rostered** (no member table). Whether `affiliations` should become
a fourth rostered group is an open question to persist (CIRISPersist#249).

**HUMANITY_ACCORD = an *entrenched family* (`consensus_protocol: quorum:2/3`) + a
kill-switch.** The roster lifecycle below is **generic to any rostered group**; the
kill-switch layer (custody gate, CONSTITUTIONAL halt + disk latch + startup gate,
invocation surface, reactivation) is accord-specific.

> Implication: `ciris_server::family` is the family-bound instance of a generic
> rostered-group layer. The ops in §4 are written once and parameterized by cohort;
> `community` is a thin instantiation, `self` omits the quorum ops.

---

## 2. Standards basis (so "complete" is provable, not asserted)

- **NIST SP 800-57 Part 1 Rev.5 — Key Management.** The canonical key **lifecycle
  state machine** (§3 below). Every op is a transition in it; if every state +
  transition is reachable, coverage is complete.
- **ICANN DNSSEC Root KSK ceremony + DPS, RFC 7583 / RFC 6781.** The closest
  real-world analogue: a root key held by **distinct human trusted representatives
  under quorum ceremonies**, with defined rollover / replacement / recovery rituals.
  Our operational model copies this.
- **FROST / DKG + proactive secret sharing.** The threshold-crypto basis for
  changing `N` / replacing a share. (We use distinct keys + a quorum-authorized
  roster supersede rather than secret resharing — same goal, simpler custody.)
- **In-house executable spec:** CC 4.2 + the CEG runbook + the verify primitives.
  Load-bearing fact: *genesis and every later supersede use the same 2/3 path*
  (`accord_genesis`), and `verify_quorum_policy` enforces strict majority (`2M>N`),
  `N == roster size`, and `M` distinct founder cosignatures.

---

## 3. The NIST 800-57 lifecycle, mapped

```
pre-activation ──provision──▶ active ──(planned)rotate──▶ active'   (key state, per holder seat)
       │                        │
       │                        ├──suspend?── (N/A: accord is binary, no suspended state)
       │                        ├──compromise──▶ revoked  (emergency, 2/3)
       │                        └──deactivate──▶ retired ──destroy──▶ destroyed
recover: lost active ──(2/3 supersede)──▶ spare promoted to active
```
The roster is a *set* of these per-seat lifecycles, plus group-level transitions
(genesis, expand/shrink N, change threshold, dissolve) and the accord governance
loop (halt → latched → reactivate).

---

## 4. The full op catalog

Legend: ✅ have · ⚠️ mechanism exists, no endpoint · ❌ gap (blocked on a filed ask).

### A. Holder-key lifecycle (per seat)
| # | Op | Authorized by | Mechanism | Status |
|---|----|----|----|----|
| A1 | Provision (gen + custody attestation) | holder device | `accord_custody::provision_portable_holder` | ✅ |
| A2 | Admit / register a seat | owner + custody gate | `POST /v1/accord/holder` | ✅ |
| A3 | Rotate a seat's key (planned) | **2/3 quorum** | supersede (new member + revoke old) | ⚠️ |
| A4 | Recover (lost primary → spare) | **2/3 quorum** | supersede | ⚠️ |
| A5 | Emergency-revoke (compromise) | **2/3 quorum** | revocation + `deregister_federation_key` | ⚠️ |
| A6 | Retire / destroy | 2/3 + key destruction | revoke + discard | ⚠️ |

### B. Roster / membership lifecycle (the group)
| # | Op | Authorized by | Mechanism | Status |
|---|----|----|----|----|
| B1 | Genesis (establish N seats + threshold) | 2/3 founders | `POST /v1/accord/genesis/{envelope,assemble}` | ✅ |
| B2 | Replace a member (swap one seat, same N) | **2/3 quorum** | `family::swap_member` + `verify_quorum_policy` over a supersede payload | ⚠️ buildable now |
| B3 | Expand N (3→5; **forces** `2/3→3/5`) | 2/3 (old) quorum | `supersede_group` + re-entrench | ❌ persist#249 §3 |
| B4 | Shrink N (5→3) | quorum | `supersede_group` | ❌ persist#249 §3 |
| B5 | Change threshold M | quorum (out-of-band) | re-entrench | ❌ persist#249 §3 |
| B6 | Dissolve the group | quorum | terminal | ❌ persist#249 §3 |

### C. Spare / custody lifecycle
| # | Op | Authorized by | Mechanism | Status |
|---|----|----|----|----|
| C1 | Provision a spare (vaulted, NOT seated) | owner | provision + register as non-member | ✅ |
| C2 | Add another spare (2 cold spares/seat) | owner | just provision + register more | ✅ (no roster change) |
| C3 | Promote spare → seat | = A4/B2 | supersede | ⚠️ |
| C4 | Refresh / retire a spare | owner / 2/3 | re-provision / revoke | ⚠️ |

### D. Invocation / governance lifecycle (accord-specific)
| # | Op | Authorized by | Mechanism | Status |
|---|----|----|----|----|
| D1 | Halt (CONSTITUTIONAL) | 2/3 | `POST /v1/accord/message` → latch + halt | ✅ |
| D2 | Reactivate (`accord:lifecycle:active`) | **2/3** | clear the latch under quorum | ❌ verify#95 Gap 1 (no `lifecycle` kind) |
| D3 | Notify / Drill | 2/3 | same path, no halt | ✅ |
| D4 | Re-entrench / amend consensus | quorum (out-of-band) | supersede the group | ❌ persist#249 §3 |

---

## 5. Authorization matrix

- **Owner-gated, NOT quorum** (custody plumbing, no governance weight): A1, A2, C1,
  C2, C4 (provision/register/vault). The owner can add a *spare* or admit a
  genesis-established seat, but cannot change *who holds power*.
- **2/3-quorum-authorized** (governance — changes the seat set or halts the mesh):
  A3, A4, A5, A6, B1–B6, C3, D1, D2, D4. Each routes through `verify_quorum_policy`
  over a canonical payload signed by ≥M of the **current** roster. One-seat-per-human
  is enforced by `accord_roster` = the family SEATS (CIRISServer v0.5.22).

---

## 6. Op surface (how the ⚠️/❌ ops collapse)

Every governance op is the same shape — **the current 2/3 sign a canonical payload,
verify checks it, then the cohort mutation runs** — so they collapse to a small set:

- **`supersede`** — replace / rotate / recover / emergency-revoke a seat (same N).
  Covers A3, A4, A5, C3. *Buildable now* (`family::swap_member` + `verify_quorum_policy`
  over a re-signed family envelope as the interim payload).
- **`reconstitute`** — expand / shrink N + set the new threshold; re-entrench.
  Covers B3–B6, D4. *Blocked on CIRISPersist#249 §3 (group supersede / consensus
  amend) + CIRISVerify#95 Gap 2 (membership-change payload).* 
- **`reactivate`** — `accord:lifecycle:active` 2/3 clears the latch. Covers D2.
  *Blocked on CIRISVerify#95 Gap 1 (no `lifecycle` InvocationKind).*

---

## 7. Primitive coverage — verify & persist

**verify HAS** the authorization spine: `verify_quorum_policy` / `verify_founder_quorum`
(strict-majority, role-gated, distinct-signer), `federation_keyset` rotation (#31),
`build_accord_family_envelope` + `accord_family_signing_bytes` + `co_sign_accord_family`
+ `assemble_accord_family_genesis`, and the invocation surface (`verify_invocation`,
`InvocationDedup`). **verify GAPS (CIRISVerify#95):** (1) no `lifecycle` InvocationKind
for reactivation; (2) no blessed membership-change / supersede object (we reuse the
family envelope as an interim payload, which doesn't bind out→in / prior-roster-hash
/ new consensus_protocol).

**persist HAS** the rostered-group storage + the active-fold per cohort (`put_*`,
`add_*_member`, `active_*_members`, `*_membership_revocation`, `lookup_*`,
`list_*_for_member`). **persist GAPS / asks (CIRISPersist#249 comment):** uniform
cohort dispatch; `active_member_keys` (roster→pubkeys); **`supersede_group`** (change
roster/consensus for an entrenched group — the B3–B6 blocker); **finish the deferred
v3.13+ quorum-authorized membership gate** (enforce ≥M cosignatures in the substrate
— make one-seat-per-human + 2/3-to-change a graph invariant, not just our server's
check); a canonical membership-change payload (shared with verify#95 Gap 2); atomic
`swap_member`; forward-secrecy re-key on remove/swap; group versioning/history; a
membership-change event hook; and the `self` + `affiliations` coverage question.

---

## 8. Coverage statement

Against NIST 800-57's lifecycle, **every state and transition is reachable** by the
catalog in §4 (no suspended state — the accord is intentionally binary). Against the
CEG rostered-group model, **every cohort write op** (create / add / remove / swap /
supersede / reconstitute / active-roster / threshold-roster) is enumerated. The
remaining ❌ items are **upstream-blocked, tracked, and named** (CIRISPersist#249,
CIRISVerify#95) — not unknown. That is the bar for "we covered everything": the set
is closed, and each member is either shipped, buildable, or a filed dependency.
