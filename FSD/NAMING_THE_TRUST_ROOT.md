# Naming the trust root — what confused me, and what would be Stupid Clear

Every item below is a name that produced a **real, traceable error** in one working session. This is not stylistic. Each entry lists the name, the mistake it caused, and the proposed replacement.

The through-line: **several names carry two or three unrelated referents, and the code silently picks one.** That is the same "one name, two axes" class this project has been curing in data (CIRISPersist#532, #541, #547) — here it is in the vocabulary.

---

## 1. "seed" — THREE unrelated things

| what | today | what it actually is |
|---|---|---|
| the baked genesis artifact | `canonical_seed.json` | a list of `SignedKeyRecord` |
| the ceremony's output | "the seed" (prose) | a `GenesisBundle` |
| **32 bytes of Ed25519 private key material** | `CIRIS_TEST_TRUST_ROOT_SEED` | a cryptographic seed |

**The error it caused:** "create a valid seed" was ambiguous across all three for an entire exchange. Worse, dropping `CIRIS_TEST_TRUST_ROOT_SEED` is how you disable the *ceremony* — so "no seed" means both "no key material" and "no trust root," and a compose overlay named `unblessed` silently did neither.

**Stupid Clear:**
- `canonical_seed.json` → **`trust_root_bundle.json`**
- `CIRIS_TEST_TRUST_ROOT_SEED` → **`CIRIS_TEST_TRUST_ROOT_PRIVATE_KEY`**
- retire the bare word "seed" in prose; say **bundle** (artifact) or **key material** (bytes)

---

## 2. "root" — at least FOUR referents

- the **trust root** (a key that charters itself)
- `let root = req.holder_key_id` — a *seated accord holder* acting as the trust root
- the **ROOT user** (auth role: `WaRole::Root`, `bootstrap_if_needed`)
- **"rooting"** in edge — *reachability*, not trust at all (`RootedPeer`, `rooting directory`, "peer roots")

**The error it caused:** I repeatedly read edge's "rooted peer" (can I dial you) as "trust-rooted" (do I accept your authority). The codebase already warns `⚠️ ROOTING ≠ ROUTING` — it needs the same warning against *trust*-rooting, or better, a different word.

**Stupid Clear:**
- trust root → always **`trust_root`**, never bare `root`
- the holder key that charters → **`charter_key`**
- ROOT user → **`owner`**
- edge's rooting → **`reachability`** / **`dialable_peer`**

---

## 3. `delegates_to` — ONE type doing THREE opposite jobs

| job | shape | meaning |
|---|---|---|
| **charter** | `delegates_to(R → R)` | "I am a trust root" |
| **conferral** | `delegates_to(R → subject, scope)` | "I grant this subject a capability" |
| **trust edge** | `delegates_to(node → R)` | "I accept R's authority over me" |

Same `attestation_type`. The direction is the *only* discriminator, and the middle two point opposite ways.

**The error it caused — the worst of the session.** I conflated the conferral with the trust edge and twice gave wrong guidance: first that the seed lacked authority (it has the conferral, as a co-scrub), then that the canonical must self-charter (it must not — the charter is on the accord holder). Both were "which `delegates_to` is this?" failures.

**Stupid Clear** — name the job in the envelope dimension, even if the wire type stays `delegates_to`:

```
trust:charter:v1     R → R          the self-declaration
trust:confers:v1     R → subject    the capability grant
trust:accepts:v1     node → R       the deletable un-trust lever
```

Then the predicates read as English: `root_self_declares` looks for `trust:charter`, candidates look for `trust:confers`, `edge_exists` looks for `trust:accepts`. No direction-arithmetic at any call site.

---

## 4. "leg A" / "leg B" — opaque, and they are really two CONFERRAL PLANES

`#379`/`#386` names them leg A and leg B. Nothing in either name says what it reads. In fact:

- **leg A** = *"did the accord bless this identity?"* — the **co-scrub** plane
- **leg B** = *"did a trust root I accept confer this capability?"* — the **delegation** plane

**The error it caused:** I could not hold which leg read which plane, and wrote a persist issue whose proposed remedy would have deleted the un-trust lever — because "leg B" told me nothing about what it consulted.

**Stupid Clear:** persist v22.1.0 already invented the right vocabulary — `ConferralPlane::{AccordCoScrub, Delegation}`. Adopt it everywhere and **retire leg A / leg B**. The gate should log `conferral_plane=AccordCoScrub` rather than "leg A passed."

---

## 5. `accord:lifecycle:v1` — sounds durable, is a heartbeat

It is **freshness-windowed at 90 days**. "Lifecycle" reads like a durable state machine (created → active → retired), so I assumed a genesis artifact could carry one. It cannot: a baked heartbeat ages out and every node fails together, three months later, with no error at the point of use.

**Stupid Clear:** **`accord:liveness_heartbeat:v1`**. A name that makes "bake this into a durable artifact" feel obviously wrong.

---

## 6. `attach_genesis` — does not attach the thing you need

It installs holders, serve nodes and attestations, and **deliberately refuses** to write the trust edge. That refusal is correct and completely invisible in the name.

**Stupid Clear:** **`install_trust_root_records`** (what it does) plus a separate, obvious **`accept_trust_root`** (the deliberate act that writes `trust:accepts`). Two names, two acts, no surprise.

---

## 7. `has_effective_role` vs `has_delegated_capability_role`

Near-identical names, **different planes**: the first reads the co-scrub, the second reads the delegation graph. Nothing distinguishes them at a call site.

**Stupid Clear:** **`has_accord_conferred_role`** and **`has_root_delegated_role`**.

---

## 8. `roles` vs `identity_type` — the gate reads the one you don't expect

Reserved prefixes (`age_assurance:`, `system:`, `detection:` …) gate on **`identity_type`**, via `required_identity_types` — *not* on `roles`.

**The error it caused:** I asserted a Sybil could not mint reserved-prefix rows without roles. Wrong — `identity_type` is self-assertable, which is the whole of CIRISPersist#543 hole 3.

**Stupid Clear:** rename the rule field to **`required_identity_types`** at every mention (it already is in code — the *prose* everywhere says "roles"), and rename `KeyRecord.roles` → **`capability_roles`** so the two are never read as synonyms.

---

## 9. `bless` — identity scrub, or the whole ceremony?

`test_bless` does both: it scrubs the key record (identity) **and** runs the trust-root ceremony (authority). "Blessed" then means either.

**Stupid Clear:** **`scrub_identity`** (the record) and **`mint_trust_root`** (the ceremony). "Bless" retires.

---

## THE STRUCTURAL ONE: there must be exactly ONE seed shape

Today there are two, and that ambiguity *is* Δ3:

| shape | where | contents |
|---|---|---|
| bare record list | `canonical_seed.json` (baked) | `[{record}]` — identity only |
| `GenesisBundle` | ceremony output | holders + serve nodes + charter + conferrals + m-of-n authorizations |

A node seeded with the first can never satisfy the delegation plane; only the second carries the authority graph. Having both means "is this node seeded?" has two answers.

**Proposal: the portable trust root bundle is the only valid seed shape.**

- `canonical_seed.json` becomes a **`TrustRootBundle`** — the same artifact the ceremony emits.
- `canonical_genesis_records()` returns the bundle, not `&[SignedKeyRecord]`.
- The bare-record path is **deleted**, not deprecated. A `[{record}]` file fails to parse rather than silently seeding an inert node.
- Boot then has one job: install the bundle's records, and write `trust:accepts` to the bundle's trust root as default trust (deletable — the un-trust lever).

That collapses Δ3 and Δ4 into "install the one artifact," and makes "valid seed" a type rather than a judgement call.

---

## Why this is worth doing before minting

The production trust root is minted once and lives a long time. Every ambiguity above is currently resolved by *reading the implementation* — which is how a session with full source access still produced four wrong statements about what the seed contains and who must sign what.

An operator minting the real root will not read `trust_root.rs`. The names have to carry the meaning.
