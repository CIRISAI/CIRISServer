# RCA — the trace plane, 2026-07-31

Nine faults in one day, between an agent sealing a trace and the canonical
scoring it. **Four were defects. Five were instruments that could not say which
branch fired**, and the instruments cost more hours than the defects.

This document exists so the next person does not re-derive it. The pattern is
more valuable than any individual fix.

---

## The one-line finding

> Every layer reported healthy while shipping nothing, because **"healthy" was
> measured as absence-of-error rather than presence-of-progress.**

`envelopes_sent_total: 0` was the honest number from the first run. Six layers
above it said fine.

---

## The chain, and where each link broke

```
seal → carrier row → consent → promote → offer → send → attribute → admit
     → materialize → summarize → score
```

| # | Link | What broke | Fixed in |
|---|---|---|---|
| 1 | consent | `DEFAULT_GRANT_ATTESTATION_PREFIXES = ["capacity:"]` — never covered `trace:`, so `promote_consented_backlog` skipped every trace row | 0.5.146 |
| 2 | consent | the fold had **no route to author consent at all** — the owner-gated POST is mounted in `serve_with_adapter`, the embedded agent boots via `start_and_hold`, which mounts no router | 0.5.147 |
| 2b | consent | …and the wizard **still 404'd two releases later**, because the pyo3 docstring for the new path still read *"production consent is exclusively the owner-gated POST"*. The code was fixed in 0.5.147; the sentence telling callers so was not | 0.5.150 |
| 3 | send | `canonical_boot_prime` rooted the canonical at the **base** dest hash, not the **named** one; reported `primed=1, refused=0` while the peer was unaddressable | 0.5.145 |
| 4 | stage 1 | not idempotent — `UNIQUE constraint` on every boot after the first, then claimed "this node has no trust root" **without evaluating it** | 0.5.145 |
| 5 | attribute | the live peers map never upgraded Advisory→Rooted after boot; persist held `rooted`, the resolver said `Advisory` | CIRISEdge#432 |
| 6 | summarize | rows in the corpus, `n_summaries=0` | **open** |

---

## The five instruments (the expensive half)

1. **`stage 1` claimed "no trust root"** without calling `trust_root_valid`. The
   node's charter, grant, trust edge and heartbeat were all present and correct.
2. **The filmstrip printed PASS** beside `ship-unconfirmed`.
3. **The ship detector matched `envelopes_sent_total` as a substring** while its
   value was `0` — the gate built to catch sealed-but-undelivered passed the
   sealed-but-undelivered case on its first green run.
4. **`ReplicatedKeyOutcome::Refused`** named five possible causes and committed
   to none. Not edge's fault — persist's enum carried no reason.
5. **`envelopes_sent_total` read `0`** while 56 trace rows from that exact key
   sat in the canonical's database. The same class inverted: broken-while-working
   after eight cases of healthy-while-broken.

And one that contradicted itself on its own line: CIRISEdge#404's message says
*"provenance=Advisory + owns_key=true ⇒ a churn downgrade"* — printed on a line
whose operands read `owns_key=false`. The hint actively pointed at the wrong
cause.

---

## What actually told the truth

Two signals, both **receiver-side**:

- `SELECT COUNT(*) FROM trace_events` on the canonical
- the **disappearance** of the `inbound frame NOT attributed` WARN

Both are presence-of-progress. Every sender-side number lied at least once, in
one direction or the other.

**Rule: a sender cannot attest its own delivery.** Delivery has three states, not
two — `confirmed` (receiver-side evidence), `unverified` (no receiver evidence
reachable), `failed` (positive evidence of a stop). Treating `unverified` as
success is what hid this for two days; treating it as failure would have broken a
working chain.

---

## The structural fix, and what shipped

**CIRISEdge#433** — a withhold ledger. Every gate that narrows the served set
must count and attribute it. A silent `return None` on a serving path is an
event, not a non-event.

**CIRISPersist#565** — typed refusals. Landed as **v24.2.0** with nine variants
and a stable token, plus `already_anchored_identical` → `Duplicate` — persist
caught that `Unchanged` needed the same treatment, which is the *common* path on
every baked-seed node.

**CIRISEdge v15.9.0** — the receive-plane mirror:
`apply_refusals_by_kind[EnvelopeKind]` and `key_apply_refusals_by_reason[token]`
in `metrics_snapshot`.

Between them a node can now answer **"did anything move, and if not, what
stopped it?"** from a metrics scrape.

---

## The open link: `n_summaries=0`

Excluded **by measurement**, not argument:

- **not projection** — 56 `trace_events` rows exist, from the right producer,
  grouping into 4 `trace_id`s
- **not scope** — all rows are `cohort_scope=federation`, and the Unauthenticated
  gate admits `affiliations|species|biosphere|federation`
- **not the filter** — `TraceFilter::default()` is all-`None`

The scorer's own query, run by hand against the same database, returns **4
summaries**. The scorer logs **0**.

Remaining candidate: the scorer's `backend` handle is not the one replication
writes through. `run_pass` takes `engine.sqlite_backend()?.clone()` at pass time;
if replication lands rows via a different handle or attached database, the scorer
queries an empty view of the same file forever — and every symptom looks exactly
like this.

**The zero path now names its own cause** (`src/scorer.rs`). It probes the plane
below its own read and reports `raw_trace_events` alongside `n_summaries`, so the
next pass distinguishes:

```
raw == 0                  → nothing arrived (delivery, not scoring)
raw > 0, summaries == 0   → THE READ IS NARROWING  ← today's state
summaries > 0, emitted 0  → feature semantics (matrices, sample gate, CC#46)
```

That is the instrument this RCA is about, applied to our own code.

---

## The sixth instrument: a stale doc

Fault 2 was fixed in 0.5.147. A production wizard hit the **same 404** on
0.5.149, because the docstring on the replacement path still said the replaced
thing was the only one. It was not stale by neglect — it was written true, and
the change that falsified it did not touch the line.

This is the RCA's own thesis pointed at prose: **a doc is an instrument, and it
reports a branch.** It had every property the five code instruments had — it was
confident, specific, and wrong in the direction that reads as "you are holding it
wrong."

Two things make it durable rather than a one-off correction:

- **the reason travels with the instruction.** `tests/fold_consent_surface.rs`
  requires the doc to say *why* HTTP cannot work in the fold (`start_and_hold`
  mounts no router ⇒ 404 by construction), not merely *what to call instead*. A
  caller told only "call this" reads a 404 as a transient and retries; a caller
  told "that route does not exist here" stops.
- **the false sentence is banned by name**, so it cannot come back on the next
  edit that copies a neighbouring docstring.

## What we did NOT ship, and why

A `consent_to_canonicals()` one-call convenience — write it, and the fold's
consent step becomes a single unmissable call. It was written, and reverted.

It decided **which** peers ("all canonicals") and **what** policy ("our
defaults"). Neither is the substrate's to decide. The exhaustive consent form
belongs to the agent — *"traces to canonicals blessed by a trust root I trust"*,
*"medical data to medical providers my providers trust"* — and it changes per
deployment. A caller whose policy is anything else gets no help from the
convenience and composes by hand anyway, now working around a function shaped
for someone else's case.

The DX fix that survives that objection is **smaller**: make
`attestation_prefixes` optional, so omitting it means *this build's production
default* rather than a set the caller must restate. That is where the actual
defect lived — a restated default forks silently, and did, for eight releases.
Peer selection stays where it belongs.

    enumerate (your predicate) → filter (your policy) → author per peer

Two calls when our default suits you, three when it does not. Nothing in the
middle is baked.

## Heuristics worth keeping

1. **A zero is not evidence unless the instrument can fail.** Verify every gate
   bites before trusting it green. A `*.log` glob that skips a rotated file, an
   ANSI-coloured probe, a substring match on a metric name — all returned zero and
   all read as absence.
2. **A fixture that supplies the value production defaults cannot prove the
   default.** mesh-repro passed `["trace:","capacity:"]` explicitly and stayed
   green for eight releases while production shipped `["capacity:"]`.
3. **A test that pins a defect as expected behaviour makes it permanent.** Two
   did.
4. **When a check green-lights but behaviour is wrong, suspect one name
   answering two questions.** `root` meant both "the signing holder" and "the
   trust root"; `carries_infra_serve` asked about one scope of four.
5. **Prefer receiver-side evidence.** See the delivery rule above.
6. **A docstring is an instrument.** It survives the change that falsifies it,
   because nothing compiles against prose. Pin the sentences whose falsity
   already cost you something — and pin the *reason*, not just the instruction.
7. **A convenience that bakes a policy is a defect with good ergonomics.** Ask
   which of the caller's decisions it is making. If the answer includes one that
   varies per deployment, ship the primitives and a good default instead.
