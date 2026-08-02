# Contributing

This is not a style guide. `cargo fmt --all --check` and `cargo clippy
--all-targets -- -D warnings` are the style guide, CI runs both, and there is
nothing to discuss.

This document is the other thing — the operational knowledge that makes this
codebase tractable and that has, until now, existed only in one person's head and
one private notes file. It is written as findings with paths attached, because
every rule below was paid for by a defect that reached production or nearly did.
If a rule here seems fussy, look up the citation; the fussiness is the scar.

Read [`FSD/RCA_TRACE_PLANE_2026-07-31.md`](FSD/RCA_TRACE_PLANE_2026-07-31.md)
first. Nine faults in one day; four were defects and five were instruments that
could not say which branch fired, and the instruments cost more hours than the
defects. Almost everything below is a generalization of that document.

---

## 1. The dominant defect class: one name, two axes

**Name it before debugging anything in this stack.** A single field, function,
predicate or constant answers **two different questions**, and one of the two
answers is wrong.

It is invisible to review because the name is honest about one of its two jobs.
It compiles. It passes clippy. It usually passes the tests, because the wrong
answer is a *semantic* mismatch, not a type error. Umbrella issue:
`CIRISPersist#532`.

**Nine instances, four repositories, one arc:**

| | the name | axis A | axis B |
|---|---|---|---|
| 1 | `subject_key_ids` | naming the data subject | revocation **authority** |
| 2 | `goal_id` | a UUID identity (persist / edge / lens) | a seven-value **scale token** (NodeCore) |
| 3 | `reconsideration` | a typed FK to the slashing schema | a CEG dimension schema |
| 4 | `cohort_scope` default | READ-path back-compatibility | WRITE-path constructor |
| 5 | the `#396` consent gate | **send** (offer + delivery) | **receive** (round participation) |
| 6 | `list_attestations` | advertise listing (projection-filtered) | **holdings** listing (must be raw) |
| 7 | `config:*` cohort scope | the typed, load-bearing column | the envelope JSON copy, never read back |
| 8 | signed-state | an **integrity** property | spent as **authority** |
| 9 | the `trace_plane` detector | the mirrored variant: two names computing one meaning, and drifted apart |

Two more from the trust-root ceremony, which took four mints, each failure a
check that asked one question and read as a verdict on the whole set:

- `carries_infra_serve` asked about **one** scope of four, so an already-blessed
  record was reused verbatim and the other three could never enter the signed
  envelope.
- `root` meant both "the signing holder" and "the trust root" — two answers that
  diverge precisely under family rooting, which is the case that mattered.

**Why nothing catches it.** The `field_processor_matrix` rows carry
field / owner_component / processor / enforcement_point / status / typing /
asymmetry_kind / demanded_by — and **no axis column**. So the matrix catches
unassigned fields and wrong values, and axis fusion is structurally
inexpressible. `processors_all` even de-duplicates, so it reports zero
multi-processor fields — the exact signal that would have surfaced instance 6.
The cure (`CIRISPersist#532`) adds a `ci_axis` column from a closed rubric and
three gate tests, so a symbol living under two axes must either split or declare
a reviewed exemption, making the fusion visible in the artefact.

**The diagnostic signature that proves this needs mechanism rather than
attention:** each of the nine was found by a *different* method — a live harness
run, a manifest walk, an adoption compile error, an audit sweep, a cross-repo
grep, a feature-flag review, a doc read, a self-review — and **none by review of
the code containing it**.

### The heuristic

> When the symptom is **"it works in direction A but not direction B"**, or
> **"the check is green but the behaviour is wrong"** — suspect axis fusion
> first, and ask: *which two questions is this one name answering?*

Do that before you add logging, before you reach for a debugger, and before you
believe any test result on either side.

---

## 2. A design doc is not an implementation

Verify every claim against the code, every time, including claims in documents
written by the person asking you to trust them. This repository's own FSDs
contain errors that survived multiple readings; that is why
`FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` opens with an explicit list of the
corrections it makes to its predecessors.

Three recent, concrete examples:

- **A name that did not exist.** An erasure primitive was referred to as
  `erase_agent_traces`. Grep found nothing, because persist ships it as
  `Engine::delete_traces_for_agent_id_hash` — since v6.9.0, and with **no caller
  anywhere in this repo**. The capability was built, atomic, tombstoning and
  audited, and unreachable. The route now at `src/federation_admin.rs` is what
  was written *afterwards*, in response to checking.
- **"Zero rate limiting, zero quota, zero write price anywhere"** —
  `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §6 says this and it is **false**.
  `PeerWriteQuota` ships in persist v22.0.0
  (`federation/replication/admission.rs`), guards `put_attestation`, and runs
  ahead of every other gate including the trust gate. The sentence is true of
  every *other* plane, which is exactly how a false generalization survives.
- **An issue marked fixed that was half fixed.** `#343`'s filter pushdown fixed
  the outer scan and left a nested one: `config_key_revoked` was still called per
  surviving config row, each call doing its own `list_attestations_by(self)` over
  every attestation the node had ever authored — 9,824 rows on the production
  status node. Fifteen full scans became thirteen. The only reason anyone looked
  was that `grep` still showed `list_attestations_by` in the file after the issue
  said "fixed".

The same rule applies to prose *inside* the code. **A docstring is an instrument
and it reports a branch.** It survives the change that falsifies it, because
nothing compiles against prose. A production wizard 404'd on 0.5.149 against a
path that had been fixed in 0.5.147, because the docstring on the replacement
still said the replaced thing was the only option. It was not stale by neglect —
it was written true, and the change that falsified it did not touch the line.

When a sentence's falsity has already cost you something, pin it
(`tests/fold_consent_surface.rs`), ban the false sentence **by name** so it
cannot return on the next edit that copies a neighbouring docstring, and pin the
**reason**, not merely the instruction. A caller told only "call this instead"
reads a 404 as transient and retries; a caller told "that route does not exist
here, because `start_and_hold` mounts no router" stops.

---

## 3. Gates must be mutation-verified

**A green test proves nothing until you have watched it fail for the right
reason.** Not "for a reason" — for the reason it exists.

The procedure is unglamorous and takes about ninety seconds: write the gate,
reintroduce the defect it is meant to catch, run it, confirm it goes red *with
its own message*, revert. Do this for every gate, including the ones that seem
too simple to be wrong. Commit messages in this repo say "mutation-verified"
because the author actually did it; do not write the phrase otherwise.

**A gate that matches its own explanatory comment is measuring prose, not code.**
This has happened twice:

- `src/graph_config.rs` — the gate pinning that the config read is scoped as the
  node itself rather than `Unauthenticated`. The function's own doc comment
  documents the `Unauthenticated` bug **by name**, so the gate's first draft
  passed by matching the comment describing the defect. The shipped version
  strips comment lines before asserting, and says so inline:

  > *"a gate that matches its own explanation is measuring prose, not code — the
  > exact instrument failure the RCA catalogues. Only executable text counts."*

- The ship detector in the trace-plane arc matched `envelopes_sent_total` as a
  **substring** while the metric's value was `0`. The gate built specifically to
  catch sealed-but-undelivered passed the sealed-but-undelivered case on its
  first green run.

Both are the same failure: the gate matched the *description* of the thing
instead of the thing. `tests/envelope_vocabulary_single_source.rs` shows the
pattern to copy — it skips comment lines deliberately and says why.

Two corollaries:

- **Assert the property where it lives.** `every_non_emitting_outcome_is_counted_into_the_accounting`
  asserts the accounting *expression*, because the property lives in the
  expression rather than in any value it produces.
- **A test that pins a defect as expected behaviour makes it permanent.** Two
  did. If you are writing an assertion that encodes something you believe is
  wrong, say so in the test name and the message, or do not write it.

---

## 4. A zero is not evidence unless the instrument can fail

`envelopes_sent_total: 0` was the honest number from the first run of the trace
arc. Six layers above it reported healthy. The one-line finding of the whole RCA:

> Every layer reported healthy while shipping nothing, because **"healthy" was
> measured as absence-of-error rather than presence-of-progress.**

Zeros that were absence-of-instrument rather than absence-of-event, all in one
arc: a `*.log` glob that skipped a rotated file; an ANSI-coloured probe that
never matched; a substring match on a metric name. Each returned zero and each
read as a clean result.

**Before you trust any zero, make the instrument report non-zero on purpose.**
If you cannot make it fire, you have not measured anything.

The other half of the rule: **a zero must name its own cause.** The scorer
(`src/scorer.rs`) probes the plane below its own read and reports
`raw_trace_events` alongside `n_summaries`, so a zero is self-classifying:

```
raw == 0                  → nothing arrived (delivery, not scoring)
raw > 0, summaries == 0   → the read is narrowing
summaries > 0, emitted 0  → feature semantics
```

And the inverse trap, which cost a cut of its own: **a fully explained zero that
nothing counted reads as an unexplained one.** The scorer reported "emitted zero
and the agents do not account for it" while the agents accounted for it
completely — 3 unchanged + 17 legitimately unconsented = 20 — because nothing
counted the unconsented. Alongside it, 17 of 20 agents produced a WARN on every
60-second pass, roughly 24,500 a day, none actionable. **An alarm that fires on
a legitimate steady state is how a real one gets missed.** Declining to be scored
is an allowed choice, not a fault; model it as an outcome, not an error.

Structurally: every gate that narrows a served set must **count and attribute**
what it withheld (`CIRISEdge#433`). A silent `return None` on a serving path is
an event, not a non-event. Refusals carry typed reasons and stable tokens
(`CIRISPersist#565`, landed in v24.2.0); if you add a refusal path that says only
"refused", you have added the next instrument failure.

---

## 5. A fixture that supplies the value production defaults cannot prove the default

The mesh harness passed `attestation_prefixes = ["trace:", "capacity:"]`
explicitly and stayed green for **eight releases** while production shipped
`DEFAULT_GRANT_ATTESTATION_PREFIXES = ["capacity:"]`. Every trace row was skipped
by `promote_consented_backlog`, on every node, the entire time. The carrier was
never broken; the default was. (Fixed in 0.5.146 — `src/peer.rs` now reads
`["capacity:", "trace:"]`, and three copies of the list had agreed with each
other and disagreed with production.)

So: if a test passes a value that production computes or defaults, that test
proves the code path works **when handed the right value**, and proves nothing at
all about the value. Either omit it and let the default flow through, or add a
separate assertion on the default itself, sourced from the same constant — never
a second literal.

The related rule, from the same defect: **a restated default forks silently.**
Wherever a caller must repeat a value the substrate already knows, make the
parameter optional so omitting it means *this build's production default*. That
is where the actual defect lived.

---

## 6. Prefer receiver-side evidence

**A sender cannot attest its own delivery.**

In the trace arc, exactly two signals told the truth, and both were
receiver-side: `SELECT COUNT(*) FROM trace_events` on the canonical, and the
*disappearance* of the `inbound frame NOT attributed` WARN. Both are
presence-of-progress. Every sender-side number lied at least once, in one
direction or the other — including `envelopes_sent_total: 0` while 56 trace rows
from that exact key sat in the receiver's database.

Delivery has **three** states, not two:

| state | meaning |
|---|---|
| `confirmed` | receiver-side evidence exists |
| `unverified` | no receiver-side evidence is reachable |
| `failed` | positive evidence of a stop |

Treating `unverified` as success hid this for two days. Treating it as failure
would have broken a working chain. Keep the third state.

The same rule generalizes past delivery: when a claim can be checked at the
consumer, check it there. Two validators over the same bytes have returned
opposite verdicts in this stack — `verify_bundle` passed a genesis bundle that
`put_public_key` refused — so a producer-side green light is not evidence the
artefact installs.

---

## 7. A convenience that bakes a policy is a defect with good ergonomics

A `consent_to_canonicals()` one-call helper was written and reverted. It decided
**which** peers ("all canonicals") and **what** policy ("our defaults"), and
neither is the substrate's to decide. The exhaustive consent form belongs to the
caller — *"traces to canonicals blessed by a trust root I trust"*, *"medical data
to medical providers my providers trust"* — and it changes per deployment. A
caller whose policy differs gets no help and composes by hand anyway, now working
around a function shaped for someone else's case.

Before adding a convenience, ask which of the caller's decisions it is making. If
any of them varies per deployment, ship the primitives and a good default
instead:

```
enumerate (your predicate) → filter (your policy) → author per peer
```

Two calls when the default suits you, three when it does not, and nothing baked
in the middle.

---

## 8. Building and testing without wrecking your machine

### The one hard rule

**Never run `cargo build`, `cargo check` or `cargo test` with `--workspace` or
`--all-targets` on this tree.** The dependency graph — persist, edge, verify,
lens-core, pyo3, Reticulum and the full integration-test surface — will exhaust
memory on an ordinary development machine, and an OOM kill mid-link leaves a
`target/` you will spend longer cleaning than the build would have taken. Build
the specific target you care about:

```sh
cargo build                            # default features, the binary path
cargo test --test trace_round_e2e      # one integration binary
cargo clippy --lib -- -D warnings      # the library surface
```

CI runs the broad invocations on dedicated runners with a warm four-layer cache;
your laptop is not that.

### `--all-features` is wrong for a second, unrelated reason

It drags `extension-module` (libpython, no-link) into the test binary. There are
three surfaces that must each be checked separately, and CI does exactly this:

| surface | command | why it is separate |
|---|---|---|
| default | `cargo clippy --all-targets -- -D warnings` | sqlite + the binary |
| python | `cargo clippy --lib --features python` | the feature is used **only** in the lib; `--all-targets` would also build the binary, which must never link libpython |
| test-anchor | `cargo clippy --all-targets --features test-anchor` | a `cfg(test)` initializer lives here; a `--lib` check cannot see it — and shipped past a `--lib` version of this very step once |

The test-anchor surface is not optional politeness. A cut that does not compile
under `--features test-anchor` breaks the mesh harness for every downstream
consumer, which is the audience least able to diagnose it. That happened when
persist v24.0.0 added `Attestation.additional_scrubs` and the one initializer
behind the feature gate was invisible to CI.

### What to run, in ascending cost

1. **`cargo test --test trace_round_e2e`** — the in-process two-node Attestation
   round. A sealed `trace:*` actually crossing from an agent-shaped node to a
   canonical-shaped one, roughly three seconds, no Docker, no transport. It
   exists because every predicate in the trace arc was previously found the
   expensive way — one full harness run per predicate — and because the *seam*
   between our surfaces and the substrate's was covered by neither side's tests,
   while being the thing that was broken every single time.
2. **`cargo test`** — the suite, default features.
3. **`cargo test --test release_gates`** — one module per stage of the release
   countdown. These are **red by design** until reality satisfies them; a red
   release gate is information, not a broken test.
4. **`CIRIS_GENESIS_BUNDLE=<path> cargo test --test genesis_bundle_validate --
   --nocapture`** — validates a real ceremony bundle: every scope on both planes,
   `root_kind` and conferral plane per scope, the 2-of-3 co-scrubs, and the drill
   target. Skips loudly without the environment variable.
5. **`harness/mesh-repro/`** — two nodes on an isolated Docker bridge, running a
   test-anchor wheel packed from the **current working tree**, so a tree-local
   fix is verdict-testable before any cut. `./run_traceflow.sh` gives a graded
   exit code (0 success / 2 no-carrier / 3 seal-failed / 4 inconclusive);
   `KEEP=1` leaves the stack up for inspection.

**On red-by-design gates.** `tests/genesis_bundle_validate.rs` stayed red through
three cuts. Keeping it red rather than weakening it to match the stale artefact is
the reason the eventual bake was verifiable the instant it landed — the
delegation-only version of that gate would have passed the third, wrong bundle
clean. Do not soften a gate to make a build green.

### Working on the substrate from here

To verdict an unreleased `ciris-edge` or `ciris-persist` change end to end, add a
Cargo `[patch]` pointing at your local checkout and run the harness; the packed
wheel then carries your working tree. **Remove the patch before any cut.** A
tagged release that silently depended on an unpublished local checkout is a class
of mistake that is very cheap to make and very expensive to discover.

---

## 9. Where the truth actually lives

Vocabulary and policy have single sources, and hand-mirroring them compiles
while skewing the wire.

- **Envelope keys** come from `ciris_persist::…::envelope::paths::*`;
  consent-state prefixes from `consent::consent_dimension::STATE_*_PREFIX`.
  Never write the literal. `tests/envelope_vocabulary_single_source.rs` enforces
  it and has bitten for real.
- **Substrate versions** are git tags in `Cargo.toml`. Moving a pin is a cut with
  a changelog entry, not a tidy-up.
- **Replication and serve policy manifests** are hash-pinned by gate tests that
  fail the build if policy moves without a deliberate cut.
- **Constitutional claims** live in `evidence/cc_impl.tsv`, resolved against the
  pinned crate versions by `tools/check_evidence.py` in CI. A moved or renamed
  symbol is a spec regression, not a refactor. Gaps are declared in code
  (`SERVER_DECLARED_GAPS`) and carry `open`; do not mint a claim id to make a
  control resolvable, because that is precisely the overclaim the registry exists
  to prevent. Nine claims were once marked `established` citing a closed *issue*
  as their evidence — a pointer at an issue and a pointer at a symbol are not the
  same kind of object, and only one of them goes stale in silence.

---

## 10. Commit messages

The commit message is this project's decision record
([`GOVERNANCE.md`](GOVERNANCE.md) §2.2). Write it as though the reader is a
stranger debugging your change in eighteen months, because that is the actual
audience.

A good one here states: what broke, **measured** rather than described; why the
fix is shaped the way it is, including the constraints that ruled out the obvious
shape; what was mutation-verified and how; what was deliberately **not** done and
why; and what you got wrong on the way, if anything.

That last one is not humility theatre. One commit in this history retracts a
false alarm the author raised about their own fix, in the same message that ships
the fix — because the retraction is the part a future reader needs in order to
trust the rest.

---

## 11. Getting started as a second pair of hands

The fastest route to being useful, in order:

1. Read `FSD/RCA_TRACE_PLANE_2026-07-31.md`, then §1 and §3 above. That is most
   of the vocabulary.
2. Stand up a node from scratch: `pip install ciris-server && ciris-server`. It
   boots unclaimed and prints a NodeCode and a claim PIN. Claim it, author a
   consent grant, check the trust root resolved.
3. Run `cargo test --test trace_round_e2e`. Break something in the middle of the
   round on purpose and watch which layer notices. Most of them will not.
4. Pick an item from `GOVERNANCE.md` §6. Every one of them is unpaid rather than
   impossible, and none needs permission.

If something in this file turns out to be false, that is a finding — fix the
file and say in the commit which artefact makes the old sentence false. This
document is an instrument, and it reports a branch.
