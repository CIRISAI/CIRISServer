# The constitutional halt on a node — CC 4.2 as amended by CIRISConstitution#146 (rc7/rc8)

**Status:** 0.5.225 implements this. It replaces the 0.5.1xx–0.5.224 model, in which a
verified halt terminated the process (`exit 42`) and `check_halt_gate` refused every later
boot until a roster majority released it. That model is withdrawn by the steward ruling of
2026-10-05 (CIRISConstitution#146, entrenched CC 4.2, founder-ratified): a `constitutional`
halt is **an agent pause with zero data disruption**, and **one holder MUST NOT be able to
keep the agents stopped alone**.

Statement of record: CC 4.2.1.1 (the halt row, the fuse, signatures per kind), CC 4.2.1.3
(`accord:lifecycle:active` / `lifecycle:confirmed`), CC 4.2.6 (fire ≤ roster-change ≤
standing), CC 1.13.6 (the agent act gate). Formal model: CIRISConstitution
`formal/accord_halt/AccordHalt.tla`, `AccordHaltFuse.tla`. Verify's implementation:
CIRISVerify#305 (v20.1.0). The agent's half: CIRISAgent#1231.

## 1. What a halt is

| | Before (0.5.224) | Now (rc7, 0.5.225) |
|---|---|---|
| Fires at | family quorum M of the roster (2 of 3) | **one** seated holder's hybrid signature |
| Effect on the node | process exits 42; boot refused while the latch stands | **the node keeps running and serving** — replication, storage, holding claims, serving, messaging, streams, files, communities and every consent/audience rule continue; only the agent's act gate reads the latch |
| Effect on agents | the node was gone | every agent on the node **pauses its effectful acts** with state preserved (CC 1.13.6) |
| Duration of a lone halt | until a majority released it | **lapses `halt_fuse_secs` after this node received it** (charter member; absent means 86 400 s = 24 h) |
| Keeping it | n/a | a cosigned `accord:lifecycle:confirmed` by a **strict majority of the standing roster**, naming the halt (`confirms_halt_id`), received **within the fuse** |
| Ending it | offline release token / `accord reactivate` at M | `accord:lifecycle:active` by a strict majority, naming the halt (`resumes_halt_id`); the offline token and `reactivate` remain as its carriers |
| Who decides thresholds | the server (`kill_switch_quorum_m`) | **verify** — `InvocationKind::required_signatures(roster_len)` (CIRISVerify#305): constitutional / drill / notify = 1; lifecycle:confirmed / lifecycle:active = `roster_len / 2 + 1` |

Why fire-at-one and the fuse ship together: a missed fire is the one unrecoverable failure
(so the floor is 1), and a lone key keeping every agent stopped is the failure the fuse
exists to prevent. Under the old exit model, fire-at-one would have let one holder take the
mesh down for good. The two are one change.

## 2. The latch

`<home>/HUMANITY_ACCORD_HALT` stays the durable record, extended:

```jsonc
{
  "invocation_kind": "constitutional",
  "invocation_id": "halt-…",
  "valid_signers": ["A1"],            // the holder(s) whose signatures verified
  "quorum_threshold": 1,              // verify's required_signatures for the kind
  "latched_at": "…",                  // when this node wrote the latch
  "received_at": "…",                 // the fuse clock starts HERE (node clock), never at the signer's asserted_at
  "fuse_secs": 86400,                 // charter `halt_fuse_secs`, else 86400
  "confirmed": null | { "invocation_id": "…", "signers": [...], "received_at": "…" },
  "node_id": "…", "halt_payload_sha256": "…", "latch_id": "…",
  "release_payload_sha256": "…", "release_binding": {…}   // unchanged (CIRISServer#347)
}
```

**In effect** is computed on every read, never stored:

```
in_effect(now) = latch present
              && not released
              && ( confirmed.is_some() || now < received_at + fuse_secs )
```

A lapsed, unconfirmed latch is left on disk as history and reads `halted: false,
lapsed: true`; a fresh halt overwrites it. A node that boots with a latch present loads it
and serves it; it does **not** refuse to start.

## 3. Rows and doors

All accord rows reach a node the way they always have: `POST /v1/accord/message` (peer
fan-out over HTTP; replicate-before-latch is kept) and the local initiating doors. None of
them ride edge's replication planes.

| Row | Kind (verify) | Threshold | Server action on a verified row |
|---|---|---|---|
| `accord:invoke` constitutional | `Constitutional` | 1 | replicate to peers, write/overwrite the latch with `received_at = now`, keep running |
| `accord:invoke` drill | `Drill` | 1 | surface as a drill event; never latches |
| `accord:invoke` notify | `Notify` | 1 | surface as an announce |
| `accord:lifecycle:confirmed` | `LifecycleConfirmed` | majority | if `confirms_halt_id` = the latched halt and `now < received_at + fuse_secs`: record `confirmed`, replicate; else refuse `halt_fuse_lapsed` / `confirms_unknown_halt` |
| `accord:lifecycle:active` | `LifecycleActive` | majority | if `resumes_halt_id` = the latched halt: clear the latch, journal, replicate; else refuse `resumes_unknown_halt`. Also accepted offline (token) and via `accord reactivate` as before |

Thresholds come from verify only. `family_quorum_m` (the family's entrenched `quorum:M/N`)
remains the threshold for **roster changes** (`family/supersede`), per CC 4.2.6; it no longer
decides any halt-plane row. Domain prefixes are verify's: invoke rows sign
`ciris.accord_invoke.v2`, lifecycle rows `ciris.accord_lifecycle.v1`.

## 4. The agent contract — `GET /v1/accord/halt-status`

Unauthenticated, loopback and remote. The agent's act gate reads it before every effectful
act (CIRISAgent#1231 may also verify the row itself through the verify wheel; both read the
same latch).

```jsonc
{
  "halted": true,                       // in_effect(now)
  "lapsed": false,                      // latch present, unconfirmed, fuse passed
  "halt": { "invocation_id": "…", "received_at": "…", "fuse_secs": 86400,
            "lapses_at": "…" | null,    // null once confirmed
            "confirmed": null | {…}, "valid_signers": [...] },
  "latch_path": "…", "releases": [...], "release_token_path": "…"
}
```

`halted` is the only field the gate needs. `lapses_at` lets a UI say how long a lone halt
has left; the mandatory visual distinction between a notify and a halt (CC 4.2.1.2) is the
client's.

## 4a. The latch has ONE reader: the agent's act gate (0.5.226, CC re-pin 17)

`src/halt_gate.rs` is the node's halt predicate — read from the latch on every call,
with the fuse computed for that instant, fail-closed on an unreadable latch — and it
is served, not enforced, by the node:

| reader | ask | what happens |
|---|---|---|
| the agent's act gate (CIRISAgent#1231 → PR #1262) | `ciris_engine/logic/utils/halt_latch.py#read_halt_latch`: `GET /v1/accord/halt-status` → `halted`, cached ≤ 1 s, before every effectful act in `ActionDispatcher._dispatch_inner`; unreachable or `halted: null` = halted | `ActionDispatcher._refuse_under_accord_halt`: exactly one terminal `ACTION_RESULT` with `error=accord_halt_in_effect:<invocation_id>` plus the audit row, through the normal trace pipeline; the agent's own `/v1/agent/interact` and `/v1/agent/message` answer `423 {error: accord_halt_in_effect, reason: ACCORD_HALT, halt: …}` |

**No data door reads it.** Trace ingest (`ingest_http`), the relay's opaque trace
batches (lens-core `LensCoreHandler::persist_batch`), both local capture paths, files,
roster, consent, replication and every serving read do their ordinary work under a
halt. Why, in one sentence: *a refused act's terminal `ACTION_RESULT` must reach the
record, or the pause erases its own evidence.* The agent-side design (Eric,
2026-10-14, on CIRISAgent#1231) ships that `ACTION_RESULT` through the HTTP ingest or
the in-process capture — exactly the doors 0.5.225 refused.

History: 0.5.225 installed the predicate into those four doors and refused them
`423 accord_halt_in_effect` ("the node's ONE absolute gate", Eric 2026-10-13). CC's
rule on re-pin 17 (4.2.1.1, "zero data disruption by construction"): the latch is
read by exactly one thing, the agent's act gate; gating any data path is a violation.
0.5.226 removed every node-side reader and lens-core's `set_halt_gate` hook (an
installed-but-unasked hook is the arming≠driving class). The witness is
`tests/halt_gate.rs::no_data_door_reads_the_latch`: a source scan over `src/` and
`crates/ciris-lens-core/src/` that goes red the moment any file but `halt_gate.rs`
and `compose.rs` (install + assert only) names the predicate — the L3 mutant for
4.2.1.1 — plus an HTTP test that the ingest door answers the same with and without
a standing latch.

Absolute where it is read: no caller, role, tier or flag reads past it (CC 4.2.1.3);
it ends only as the latch ends. Not cached: the latch is one small file and the act
cadence is the bound CC sets on a reader.

What the node cannot do alone: an agent's effectful acts — all of them — are stopped
only by the agent's reader. The node serves that reader; the agent's half is
CIRISAgent#1231, implemented as CIRISAgent PR #1262 (2026-10-14, against 0.5.225, not
yet merged). Its refusal `ACTION_RESULT` lands only on a 0.5.226+ node; the agent's QA
module targets 0.5.226.

## 4b. Test anchor doors (never on a production build)

- `test_holder_seed_b64` on `/v1/accord/{invocation,drill,halt,announce,invocation/concur}`
  (feature `test-anchor` AND `CIRIS_TESTING_MODE=true`): sign as the software holder
  derived from the seed, exactly as the final-genesis dry-run holders are derived.
- `CIRIS_TEST_HALT_FUSE_SECS` (`CIRIS_TESTING_MODE=true`): the fuse, because the
  ceremony's charter names none and a ladder cannot wait a day.

## 4c. Where it is proven

- `tests/accord.rs`: one holder fires and the node keeps serving; a lone
  `lifecycle:active` releases nothing and a majority naming the halt releases it; a
  majority `lifecycle:confirmed` within the fuse keeps the halt and after it confirms
  nothing; thresholds are verify's (source scan + table).
- `tests/halt_gate.rs` (0.5.226): the ingest door does its ordinary work while the latch
  stands (same answer as with no latch); `no_data_door_reads_the_latch` source-scans
  `src/` and lens-core for any reader outside `halt_gate.rs` / `compose.rs`; compose
  installs the predicate; lens-core carries no hook.
- `harness/native`: catalogue entry **T8** (`topologies/t8-accord-halt.yaml`, built by
  the 0.5.220 ceremony with three software holders) and the **`halt`** scenario =
  CSD-129 "Drill, halt, announce: end to end" (federation → safety): drill, announce,
  fire from one node and hand out of band to the others, every node latched and still
  serving, ingest STILL ADMITTING (0.5.226; it was "refused" on 0.5.225), confirm,
  resume, a short-fused halt lapsing, a late confirmation refused. **Ran green 2026-10-13** on the first run (26 steps, 20 s fuse,
  `first_failure: null`; `python -m harness.native halt --binary target/debug/ciris-server`
  with `CIRIS_TEST_HALT_FUSE_SECS=20`). Not covered yet: an agent process whose act gate
  reads the status (CIRISAgent#1231); `rows.jsonl` per node for CC's offline replay (T8 iii).

## 5. What is removed

- `AccordHalt::exit_on_halt` and the `exit(42)` / `abort()` paths. A node does not stop.
- `check_halt_gate` as a boot refusal. It becomes `load_halt_latch` (read, never refuse);
  a presented offline release token is still consumed at boot and journaled.
- `kill_switch_quorum_m` on the halt plane. The QA scenario's `quorum_met == false` after
  one signature flips: one signature **is** the fire.

## 6. Tests (named)

- `one_holder_constitutional_latches_and_the_node_keeps_serving`
- `a_lone_halt_lapses_after_the_fuse_and_reads_halted_false`
- `a_majority_lifecycle_confirmed_within_the_fuse_keeps_the_halt`
- `a_confirmation_after_the_fuse_confirms_nothing`
- `a_majority_lifecycle_active_naming_the_halt_clears_it_and_a_lone_one_does_not`
- `boot_with_a_latch_present_serves_it_and_does_not_refuse`
- `thresholds_are_verifys_not_ours` (source scan: no `kill_switch_quorum_m` on the halt plane)
- QA runner `accord.rs`: one signature → `halted == true`; node still answers `/health`.
