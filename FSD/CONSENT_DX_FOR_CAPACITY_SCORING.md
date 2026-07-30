# DX — how to form the consent objects that make capacity actually get scored

**Audience:** anyone wiring an agent (or any node) so a canonical will score it.
**Substrate floor:** persist **v22.0.1**, edge **v15.4.2**, server **0.5.139**.

Getting scored needs **two different consents, in two different directions, from two different families.** Neither is optional, neither substitutes for the other, and both fail *quietly* if formed wrong — which is why this document exists rather than a one-line README note.

If you only remember one thing: **consent is directional, and the two consents point in opposite directions.**

```
  replication consent      SENDER  ──grants──▶  RECIPIENT     (I will send to you)
  analyze consent          SUBJECT ──grants──▶  ATTESTER      (you may score me)
```

---

## Consent #1 — `consent:replication:v1` (so the bytes move at all)

**Who authors it:** the **sender**, naming the **recipient**.
**Why:** edge resolves its send-set from `list_consent_peers(local)` — grants **this node authored**. A peer absent from that set gets the **whole attestation plane withheld**, not a partial view.

```
attesting_key_id = <me, the sender>
attested_key_id  = <the peer I want to send to>
dimension        = consent:replication:v1
```

### Three traps, all of which we hit

1. **It is not symmetric.** An agent granting the canonical does **not** let the canonical send back. Both directions need their own grant. Our canonical withheld its entire plane for hours because it had never granted back — its send-set was simply empty.

2. **Assert the PROJECTION, not the row.** Edge reads `list_consent_peers`, which is backed by the `consent_peer_set` projection maintained transactionally at write time. A `consent:replication:v1` attestation can **exist in the table while being invisible to edge**. Always verify:

   ```rust
   let peers = replication_peers_from_consent(&engine, &my_key_id).await?;
   assert!(peers.contains(&peer_key_id));   // NOT: "a consent row exists"
   ```

   Use `emit_replication_consent` rather than hand-building the attestation — it goes through the path that maintains the projection. A hand-rolled row reads as consented and still darkens the plane.

3. **`attestation_prefixes` do NOT filter what the peer receives.** This surprised us twice. Send-set membership is **prefix-independent** — any grant naming a peer opens the whole non-`trace:` plane. The prefixes select which **producer-declared `recipient_capability` restrictions** apply (`#396` item 6). Per-row gating comes from elsewhere:
   - `trace:*` rows → the `#379`/`#386` serve gate (the recipient needs `infra:serve` rooted to a root the sender trusts)
   - everything else → item-6 restrictions

   So do not reach for a narrow prefix set expecting it to contain blast radius. It does not.

---

## Consent #2 — `consent:state:granted:v1` scope `analyze` (so scoring is permitted)

**New in persist v22 / CIRISConstitution#46.** This is the one that silently produces "traces arrived but nothing was scored."

**Who authors it:** the **subject** (the agent being scored), naming the **attester** (the canonical that will score it).

The claim is the edge `attester → subject`. The consent is the **reverse** edge `subject → attester`:

```
attesting_key_id = <the SUBJECT — the agent being scored>
attested_key_id  = <the ATTESTER — the node that will author capacity:*>
dimension        = consent:state:granted:v1
envelope.scope   = "analyze"
tier             = federation
```

### The refusal you get without it

```
emit_attestation_self(capacity): invalid argument: no live consent covers this
capacity:sustained_coherence:v1 emission: subject <agent> has not granted attester
<canonical> the "analyze" scope (resolved stance: Unspecified) — a party MUST NOT
emit a capacity:* score about a subject unless a live consent:scope:analyze from
that subject covers the attester (CIRISConstitution#46).
```

Note the shape of the failure: the scorer **runs, sees your traces, and authors nothing.** `n_summaries=3` with `emitted=0`. From outside it looks like the trace plane failed. It did not.

### How to form it correctly

```rust
use ciris_persist::federation::admission::CAPACITY_CONSENT_SCOPE;   // "analyze"
use ciris_persist::federation::consent::consent_dimension;          // STATE_GRANTED_PREFIX
use ciris_persist::federation::envelope::paths;                     // DIMENSION

let envelope = serde_json::json!({
    (paths::DIMENSION): format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
    "scope": CAPACITY_CONSENT_SCOPE,
});

let mut input = EmitAttestationInput::with_envelope(
    "consent",
    EnvelopeCore::from_value(envelope)?,
    cohort_scope::FEDERATION,     // NOT self — see trap 3
);
input.attested_key_id = Some(attester_key_id.clone());
engine.emit_attestation_self(input).await?;
```

### Four traps

1. **The attester is the node's DERIVED federation key id**, not a friendly alias. It must be the id `emit_attestation_self` stamps — `engine.local_derived_key_id()`. Consenting to the alias leaves the *real* attester unconsented and the gate still refuses. (This is the 0.5.138 identity-fork class in miniature, and it bit our own test fixture.)

2. **`cohort_scope: federation`, not `self`.** The row is read on the **scoring** node, not on yours, so it has to replicate. A `self`-scoped grant resolves locally, looks correct in your own DB, and is invisible where it actually matters.

3. **A grant must name its scope EXACTLY.** `granted` is the only fail-open stance, so persist requires it to be precise: a grant with an absent, `null`, `[]`, or `""` scope matches **nothing**. (By contrast a scope-less *revocation* is blanket — it closes everything. Both directions fail closed, deliberately.) Accepted shapes: `"scope": "analyze"` or `"scope": ["analyze", …]`.

4. **Assert the RESOLVED STANCE, not the row.** Same class as trap 2 above:

   ```rust
   let stance = engine.federation_directory()
       .resolve_scoped_consent(attester, subject, CAPACITY_CONSENT_SCOPE, None, Utc::now())
       .await?;
   assert!(matches!(stance, ConsentState::Granted));   // NOT: "a row exists"
   ```

   A row that exists but folds to `Unspecified` is exactly the silent-false we keep curing. `resolve_scoped_consent` is the one canonical fold (a default trait method, identical across all three backends) — do not write a parallel lookup, that is the two-lists-that-disagree class.

---

## The checklist

For an agent that wants to be scored by canonical `C`:

| # | Consent | Author | Names | Verify by |
|---|---|---|---|---|
| 1 | `consent:replication:v1` | agent | `C` | `list_consent_peers(agent)` contains `C` |
| 2 | `consent:replication:v1` | `C` | agent | `list_consent_peers(C)` contains agent |
| 3 | `consent:state:granted:v1` scope `analyze` | agent | `C`'s **derived** key id | `resolve_scoped_consent(...) == Granted` |

Plus, independent of consent, `C` needs `infra:serve` **both** ways for `trace:*` to cross — a role on its key record (leg A) *and* a `delegates_to` trust-root walk that resolves (leg B). Leg A alone is not sufficient; that distinction cost this project a full day.

## Verifying end to end

`harness/mesh-repro/run_scenario.sh traceflow` walks all eight stages and, on failure, names the first broken one plus the likely fix. Stage 7 (`score`) keys on `emitted=[1-9]` — an authored capacity attestation — because the scorer logs a "completed pass" in both directions and matching the pass alone would report success for a pass that scored nothing.

Success looks like:

```
emitted capacity:sustained_coherence:v1 attestation attested=<agent> samples=3
capacity scorer pass complete (capacity attestations authored → replication) emitted=1
```

## Why it is built this way

CC 3.4.5 previously let **any** registered key score any third party, and admission is deliberately cheap (a self-signed hybrid proof-of-possession — key custody only). On a bootstrap that cheap, "any registered key" means anyone. CC#46 inverts the default for this one family and asks the contextual-integrity question directly: *were you permitted to compute and publish this about me?*

The two consents are not redundant. #1 is transport-layer ("may these bytes move between us"). #2 is a transmission principle about a **third party's** data — the subject's own behavioural record. A node can be fully consented for replication and still have no right to score you.
