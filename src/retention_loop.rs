//! The **retention / eviction control loop** (CIRISServer#348) — the periodic
//! pass that enforces the node's [`RetentionPolicy`] against its local store.
//!
//! ## Why this file exists
//!
//! lens-core has shipped the whole eviction stack since v0.4 — `plan_eviction`
//! (pure planner), `execute_plan` (the persist calls), `evict_per_retention_policy`
//! (the two composed) — with unit tests across the threshold matrix. Nothing
//! called any of it. The primitives were correct, tested, and never once run on a
//! live node, so the store's only bound was the disk. A production canonical
//! reached 9,811 rows of a single dimension in a 21 MB database with a 9.5 MB
//! WAL, and would have kept going.
//!
//! Capability built and never invoked is this codebase's recurring defect, and it
//! is invisible to review of the capability: `retention/eviction.rs` reads as
//! finished work, because it IS finished work. The thing missing was a caller.
//!
//! ## Shape (mirrors [`crate::scorer`])
//!
//! A periodic task spawned from [`crate::compose::serve`], never in a request
//! path. Cadence + every threshold come from the resolved `config:*` snapshot
//! ([`crate::config_reconcile::ResolvedConfig`]) and are HOT: the pass reads the
//! live snapshot each cycle and the sleep re-arms mid-flight when the cadence
//! changes, so an operator watching a disk fill can tighten the bound and see it
//! act without a restart.
//!
//! ## The steady state is not an alarm
//!
//! On a healthy node this pass evicts nothing, forever. That is the system
//! working: the store is inside every bound the operator set. It logs at INFO and
//! says which bounds it checked and what it measured.
//!
//! 0.5.152 got the sibling case wrong — the scorer WARNed on a zero that its own
//! counters fully explained, 51 lines every three minutes on the production
//! canonical — and 0.5.153 fixed it. The lesson is cheap to restate and expensive
//! to relearn: an alarm that fires on the happy path teaches operators to skip
//! the log, and then the real alarm arrives into a habit of not looking. Here the
//! only WARN is a pass that FAILED, and the only place a zero raises its voice is
//! [`RetentionOutcome::Unbounded`] — which is not a fault either, just the one
//! outcome where "nothing was evicted" and "nothing ever will be" are the same
//! sentence.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ciris_lens_core::{
    evict_per_retention_policy, EvictionError, RetentionPolicy, DISK_EVICTION_THRESHOLD,
};
use ciris_persist::prelude::Engine;
use tokio::sync::watch;

use crate::config_reconcile::ResolvedConfig;

/// The retention pass's configuration — cadence plus the policy it enforces.
///
/// Projected from the live `config:*` snapshot by [`Self::from_resolved`], the
/// same seam [`crate::scorer::ScorerConfig::from_resolved`] uses: knob DECODING
/// lives with the consumer that understands the knobs, `config_reconcile` stays a
/// typed reader of the corpus.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// How often the pass runs.
    pub cadence: Duration,
    /// The bounds to enforce.
    pub policy: RetentionPolicy,
}

impl RetentionConfig {
    /// Project the resolved `config:*` snapshot onto a [`RetentionConfig`].
    ///
    /// The `0 ⇒ None` decode happens HERE and only here. `ResolvedConfig` holds
    /// the wire shape (`u32`/`u64`, because the config store has no null) and
    /// `RetentionPolicy` holds the semantic shape (`Option`, because "no bound"
    /// is a real state); this is the one function that knows both, so there is
    /// one place to look when a zero behaves surprisingly.
    pub fn from_resolved(r: &ResolvedConfig) -> Self {
        let bound = |v: u32| (v > 0).then_some(v);
        RetentionConfig {
            cadence: r.retention_cadence(),
            policy: RetentionPolicy::indefinite()
                .with_max_age_days(bound(r.retention_max_age_days))
                .with_max_disk_gb((r.retention_max_disk_gb > 0).then_some(r.retention_max_disk_gb))
                .with_audit_log_max_age_days(bound(r.retention_audit_log_max_age_days)),
        }
    }
}

/// What one retention pass actually did.
///
/// Three outcomes, three questions, one answer each — the discipline the
/// scorer's `ScoreOutcome` was carved out of a `bool` to get. The
/// distinction that matters is between the two zeroes: a store INSIDE its bounds
/// and a store with NO bounds both evict nothing, and they are opposite
/// conditions. Collapsed into one "evicted 0" they would share a log line, and
/// the node that is quietly filling its disk would look exactly like the node
/// that is fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetentionOutcome {
    /// The policy bounds nothing that lens-core can enforce, so no sweep ran.
    ///
    /// A legitimate operator choice (a sovereign anchor keeps everything) and
    /// therefore never an error — but it is also the exact state the node was in
    /// when it grew unbounded, so it names itself on every pass instead of
    /// looking like a quiet success.
    Unbounded,
    /// The policy is bounded and the store is inside every bound — nothing was
    /// eligible. **THE STEADY STATE on a healthy node.** Carries what it
    /// measured so the zero names its own cause: an operator can see the store
    /// is small and young rather than infer it from silence.
    WithinBounds {
        trace_rows: u64,
        oldest_trace: Option<DateTime<Utc>>,
        total_disk_bytes: u64,
    },
    /// Rows left the store this pass.
    Evicted {
        evicted_traces: usize,
        archived_audit_entries: u64,
        freed_bytes_estimate: u64,
        total_disk_bytes: u64,
    },
    /// **A CONFIGURED BOUND IS EXCEEDED AND NO LEVER REACHES THE BYTES**
    /// (CIRISServer#476). The one arm here that IS a fault.
    ///
    /// `retention.max_disk_gb` measures the whole database; the only levers
    /// this policy owns delete `trace_events` and archive `audit_log`. A node
    /// whose mass is in neither class can sail past its cap while every pass
    /// correctly decides there is nothing to evict.
    ///
    /// Measured, not hypothesised: ciris-status carried a 389 MB store —
    /// 52,125 attestations, 52,160 wire-index rows, ZERO traces — and reported
    /// "inside every configured bound" every hour. The cap was never the
    /// protection anyone believed it was.
    BoundUnenforceable {
        used_bytes: u64,
        cap_bytes: u64,
        /// Rows the levers CAN reach. Near-zero here is the whole diagnosis.
        evictable_rows: u64,
    },
}

impl RetentionOutcome {
    /// Whether an operator should be ALARMED by this outcome.
    ///
    /// This was `false` for every arm, written down deliberately so nobody
    /// could quietly add a WARN to a happy path: evicting, finding nothing to
    /// evict, and having been told not to evict are all the system working,
    /// and the only alarm-worthy event was an `Err`.
    ///
    /// **CIRISServer#476 found a fourth state that is none of those.** A
    /// configured bound can be EXCEEDED and simultaneously unenforceable — the
    /// disk cap reads the whole store while the levers reach only traces and
    /// audit. That is not the system working: the operator asked for a limit
    /// the node cannot honour, and silence there is the most expensive kind.
    /// So the invariant is now "exactly one arm is a fault, and it is the one
    /// where a bound cannot bite" — still checkable, still pinned, and the
    /// happy paths are still forbidden from alarming.
    pub fn is_fault(&self) -> bool {
        match self {
            RetentionOutcome::Unbounded
            | RetentionOutcome::WithinBounds { .. }
            | RetentionOutcome::Evicted { .. } => false,
            RetentionOutcome::BoundUnenforceable { .. } => true,
        }
    }
}

/// Run **one** retention pass. Public so a test can drive a single deterministic
/// pass without waiting on the timer (the same seam as
/// [`crate::scorer::run_pass`] and [`crate::replication_reconcile::reconcile_once`]).
///
/// Emits exactly one INFO pass line — a pass is AUDIBLE whether or not it acted,
/// so "the loop is not running" and "the loop ran and found nothing" are never
/// the same observation from outside (the #315 lesson, paid for once already on
/// the scorer's silent zero).
///
/// Returns `Err` only when persist itself refused (a summary read or a delete);
/// the caller logs + skips the tick.
pub async fn run_pass(
    engine: &Engine,
    cfg: &RetentionConfig,
) -> Result<RetentionOutcome, EvictionError> {
    // Asked BEFORE the store is touched. An unbounded policy cannot produce a
    // plan that acts, so running the sweep to discover that would be three
    // table scans an hour to re-derive a fact already sitting in the config.
    if !cfg.policy.is_bounded() {
        tracing::info!(
            "retention pass: no enforceable bound configured (retention.max_age_days = 0, \
             retention.max_disk_gb = 0, retention.audit_log_max_age_days = 0) — the local store \
             is unbounded and will grow until the disk does. Legitimate for an archive node; set \
             `retention.max_age_days` via POST /v1/config if it is not deliberate."
        );
        // No bound is configured, so "the configured bound cannot bite" is not
        // a claim this node can make. Clearing is NOT reassurance — an
        // unbounded store still grows, and the INFO above says so; it is
        // refusing to leave a warning standing that has stopped being true.
        crate::degradation::clear(RETENTION_BOUND_CODE);
        return Ok(RetentionOutcome::Unbounded);
    }

    // The pre-state, read BEFORE the sweep, so a zero pass can report what it
    // was looking at rather than only that it found nothing. `oldest_trace` is
    // the load-bearing field: it is the direct answer to "is there anything old
    // enough for the cutoff to have caught?", which is otherwise the operator's
    // first question and an hour-long round trip to answer.
    let before = engine.storage_summary().await?;

    // The whole stack in one call: `evict_per_retention_policy` reads the
    // summary, runs `plan_eviction`, and drives `execute_plan`. Calling the
    // composed entry point rather than re-composing it here keeps lens-core the
    // single owner of the planner→executor order; a second composition in the
    // caller is how the two drift.
    let summary = evict_per_retention_policy(engine, &cfg.policy).await?;

    // What the operator needs to read the outcome: which bounds are live, and
    // (for a disk cap) how close the store is to the threshold that would fire.
    // The threshold comes from lens-core's own const — writing `90%` here would
    // be a second literal that stays at 90 while the planner moves.
    let bounds = describe_bounds(&cfg.policy, before.total_disk_bytes);

    // THE VERDICT OUTRANKS THE COUNT. "Evicted nothing" and "could not evict
    // anything, while over the cap" produce the same zero and mean opposite
    // things — checking the count first is exactly how the production node
    // reported steady state for weeks while it grew.
    if let ciris_lens_core::retention::DiskPressure::Unreachable {
        used_bytes,
        cap_bytes,
        evictable_rows,
    } = summary.disk_pressure
    {
        tracing::error!(
            used_bytes,
            cap_bytes,
            evictable_rows,
            trace_rows = before.trace_events.rows,
            audit_rows = before.audit_log.rows,
            %bounds,
            "retention BOUND EXCEEDED AND UNENFORCEABLE — the store is over its \
             configured disk cap and NO configured lever reaches the bytes. This \
             policy can delete `trace_events` and archive `audit_log`; the mass is \
             in neither (see evictable_rows). No future pass changes this on its \
             own: narrow what this node ACCEPTS (consent prefixes / replication \
             planes) or give the node more disk. Raising max_disk_gb silences the \
             alarm without freeing a byte."
        );
        // The ERROR above goes to a log nobody is tailing. This puts the same
        // fact on `GET /v1/node/health`, where the client already renders it —
        // which is the whole point of #446: ciris-status carried an
        // unenforceable cap for weeks and every surface it had said "ok".
        crate::degradation::raise(crate::degradation::Warning::error(
            RETENTION_BOUND_CODE,
            format!(
                "the configured disk cap cannot be enforced: {used} of {cap} used, and only \
                 {evictable_rows} rows are reachable by any configured lever. Narrow what this \
                 node ACCEPTS (consent prefixes / replication planes) or give it more disk. \
                 Raising max_disk_gb silences this without freeing a byte.",
                used = human_bytes(used_bytes),
                cap = human_bytes(cap_bytes),
            ),
        ));
        return Ok(RetentionOutcome::BoundUnenforceable {
            used_bytes,
            cap_bytes,
            evictable_rows,
        });
    }

    // A STALE alarm must come down — a warning that only ever goes up is one
    // operators learn to ignore, which is the same silence #476 set out to fix
    // approached from the other side. But only POSITIVE EVIDENCE takes it down,
    // and `Relieving` is not that (codex review, PR #483).
    //
    // `Relieving` means "the plan CAN act" — a claim made from the PRE-pass
    // summary, before anything executed. It is an intention, not an outcome, and
    // two things routinely make it a false one: an `audit_log_max_age_days`
    // range flips `Unreachable` to `Relieving` while the lens executor does not
    // execute audit archival at all, and a SQLite delete need not reduce
    // `total_disk_bytes` because freed pages go on the freelist. An over-cap
    // store could therefore clear its own alarm every hour, forever, on the
    // strength of a plan that frees nothing.
    //
    // So `Relieving` leaves a standing alarm standing and waits. The NEXT pass
    // classifies from a FRESH summary — `Within` if the bytes really went, or
    // `Unreachable` again if they did not — which uses lens-core's own verdict
    // rather than re-deriving the decision here.
    let acted = summary.evicted_traces > 0 || summary.archived_audit_entries > 0;
    // The POST-pass state, read once and used for BOTH the verdict and the
    // outcome. A pass that acted must be judged on what it achieved, not on
    // what it set out to do — see the `Relieving` arm below.
    let after = if acted {
        Some(engine.storage_summary().await?)
    } else {
        None
    };
    match summary.disk_pressure {
        // Genuinely under the trigger. A pass only removes bytes, so the
        // post-state is under it too.
        // **`Within` IS A PRE-PASS READING TOO** (codex review, PR #483).
        //
        // When the pass ACTED — a long `max_age_days` deletion, say — ingestion
        // continues throughout it, and the post-pass byte count already in hand
        // can be ABOVE the trigger even though the pre-pass classification said
        // `Within`. Clearing on the older reading reports `ok` until the next
        // cadence over a store that is pressured right now.
        //
        // So when there IS a disk cap and the pass acted, this arm judges from
        // the same post-pass number the `Relieving` arm does. Without a cap
        // there is no trigger to be above, and `Within` is the whole answer.
        ciris_lens_core::retention::DiskPressure::Within { cap_bytes, .. } => {
            #[allow(clippy::cast_precision_loss)]
            let still_pressured = after.as_ref().is_some_and(|a| {
                (a.total_disk_bytes as f64) >= (cap_bytes as f64) * DISK_EVICTION_THRESHOLD
            });
            if still_pressured {
                // **RAISE, not merely preserve** (codex review, PR #483; the
                // same third side as the `Relieving` arm). `no_evidence` keeps
                // a standing alarm — and on the FIRST pass that crosses the
                // trigger there is none to keep, so health read `ok` over a
                // store that is pressured right now. The measurement is in
                // hand; it is evidence, not an absence of it.
                let used_after = after.as_ref().map_or(0, |a| a.total_disk_bytes);
                tracing::error!(
                    used_bytes = used_after,
                    cap_bytes,
                    %bounds,
                    "retention pass finished ABOVE the eviction trigger — the pre-pass reading \
                     was inside bounds and ingestion outran the pass. The next cadence will \
                     plan against the new state; this is the node saying so now rather than \
                     in an hour."
                );
                crate::degradation::raise(crate::degradation::Warning::error(
                    RETENTION_BOUND_CODE,
                    format!(
                        "the store crossed its eviction trigger DURING this pass: {used} of \
                         {cap} used, and eviction starts at {pct:.0}% of the cap. Ingestion is \
                         outrunning retention.",
                        used = human_bytes(used_after),
                        cap = human_bytes(cap_bytes),
                        pct = DISK_EVICTION_THRESHOLD * 100.0,
                    ),
                ));
                // AND RETURN A FAULT, exactly as the `Relieving` arm does. The
                // previous cut raised the alarm and then fell through to the
                // ordinary `Evicted` outcome, whose `is_fault()` is false — so
                // the registry and the returned verdict disagreed about one
                // measured state for the SECOND time on this arm. Raising
                // without returning is half a fix, and the half that a caller
                // reading the outcome never sees.
                return Ok(RetentionOutcome::BoundUnenforceable {
                    used_bytes: used_after,
                    cap_bytes,
                    evictable_rows: summary.evicted_traces as u64
                        + summary.archived_audit_entries as u64,
                });
            } else {
                crate::degradation::clear(RETENTION_BOUND_CODE);
            }
        }
        // No disk bound is configured, so "the configured bound cannot bite" is
        // not a claim this node can make.
        ciris_lens_core::retention::DiskPressure::Unbounded => {
            crate::degradation::clear(RETENTION_BOUND_CODE);
        }
        // **A RELIEVING PLAN THAT MOVED NOTHING IS AN UNENFORCEABLE BOUND**
        // (codex review, PR #483 — the second half of this defect).
        //
        // The first fix stopped `Relieving` from CLEARING a standing alarm, and
        // that is only half: on the FIRST such pass there is no alarm to
        // preserve, so an over-cap store fell straight through to the
        // zero-action branch below, reported `WithinBounds`, and stayed `ok`
        // forever. Silence restored through the other side of the same arm.
        //
        // The reproducing case is not exotic. With `audit_log_max_age_days` the
        // only configured lever, lens-core plans an archive range and returns
        // `Relieving` on EVERY pass, while its executor leaves
        // `archived_audit_entries` at zero because archival is not implemented.
        // The plan is a claim about what a lever COULD do; `acted` is what
        // happened.
        ciris_lens_core::retention::DiskPressure::Relieving {
            used_bytes,
            cap_bytes,
        } if !acted => {
            // Rows the levers CAN reach — the whole diagnosis, exactly as for
            // `Unreachable`, and read from the PRE-pass summary because the
            // pass removed nothing.
            let evictable_rows = before.trace_events.rows + before.audit_log.rows;
            tracing::error!(
                used_bytes,
                cap_bytes,
                evictable_rows,
                %bounds,
                "retention BOUND EXCEEDED AND UNENFORCEABLE — the plan named a lever and the \
                 pass freed NOTHING. A planned-but-inert lever reports the same zero as a \
                 healthy sweep; it is not one. Narrow what this node ACCEPTS (consent \
                 prefixes / replication planes) or give the node more disk."
            );
            crate::degradation::raise(crate::degradation::Warning::error(
                RETENTION_BOUND_CODE,
                format!(
                    "the configured disk cap cannot be enforced: {used} of {cap} used. This \
                     pass PLANNED to free bytes and freed none, so no future pass changes \
                     this on its own. Narrow what this node accepts, or give it more disk; \
                     raising max_disk_gb silences this without freeing a byte.",
                    used = human_bytes(used_bytes),
                    cap = human_bytes(cap_bytes),
                ),
            ));
            return Ok(RetentionOutcome::BoundUnenforceable {
                used_bytes,
                cap_bytes,
                evictable_rows,
            });
        }
        // **PLANNED, ACTED — AND STILL OVER CAP** (codex review, PR #483; the
        // THIRD side of this one arm).
        //
        // Deferring to "the next pass will classify from a fresh summary" is
        // only true if some pass eventually classifies differently, and under
        // sustained ingestion none does: every hour there are rows to evict, so
        // `acted` is true every hour, and the verdict is deferred forever while
        // the file walks toward exhaustion reporting `ok`.
        //
        // Worse on SQLite, where evicting rows routinely leaves
        // `total_disk_bytes` UNCHANGED — freed pages go on the freelist and
        // `PRAGMA page_count` does not fall without a VACUUM. A pass can then
        // act, report progress, and free nothing the operating system can see,
        // every hour, indefinitely.
        //
        // So the post-pass BYTES decide, not the plan and not the action.
        ciris_lens_core::retention::DiskPressure::Relieving { cap_bytes, .. } => {
            // `after` is Some here by construction: this arm requires `acted`.
            let used_after = after.as_ref().map_or(u64::MAX, |a| a.total_disk_bytes);
            // **COMPARE AGAINST THE PLANNER'S TRIGGER, NOT THE HARD CAP**
            // (codex review, PR #483).
            //
            // lens-core classifies disk pressure from
            // `cap_bytes * DISK_EVICTION_THRESHOLD`, so a store that finishes a
            // pass at 95% of its cap is BELOW the cap and still ABOVE the
            // trigger: this arm would clear, and the very next planner pass
            // would classify `Relieving` again. Under sustained ingestion or
            // SQLite freelist behaviour that repeats every hour, and health
            // reads `ok` while pressure never once falls below the line that
            // defines it.
            //
            // Read from lens-core's own const rather than written as `0.9`
            // here: a second literal is how the caller and the planner end up
            // disagreeing about the same store.
            #[allow(clippy::cast_precision_loss)]
            let still_pressured =
                (used_after as f64) >= (cap_bytes as f64) * DISK_EVICTION_THRESHOLD;
            if still_pressured {
                tracing::error!(
                    used_bytes = used_after,
                    cap_bytes,
                    evicted_traces = summary.evicted_traces,
                    archived_audit_entries = summary.archived_audit_entries,
                    freed_bytes_estimate = summary.freed_bytes_estimate,
                    %bounds,
                    "retention acted and the store is STILL AT OR ABOVE ITS EVICTION TRIGGER — the levers are \
                     working and are not keeping up. On SQLite a delete need not shrink the \
                     file at all (freed pages go on the freelist), so 'evicted N rows' is not \
                     evidence the disk was relieved."
                );
                crate::degradation::raise(crate::degradation::Warning::error(
                    RETENTION_BOUND_CODE,
                    format!(
                        "the store is still at or above its eviction trigger after a pass that DID \
                         evict: {used} of {cap} used, and eviction starts at {pct:.0}% of the \
                         cap. The levers work but are not keeping up with what this node \
                         accepts. Narrow the consent prefixes / replication planes, give the \
                         node more disk, or VACUUM — on SQLite a delete need not shrink the \
                         file.",
                        used = human_bytes(used_after),
                        cap = human_bytes(cap_bytes),
                        pct = DISK_EVICTION_THRESHOLD * 100.0,
                    ),
                ));
                // **AND THE RETURNED OUTCOME MUST AGREE WITH THE REGISTRY**
                // (codex review, PR #483). Falling through to `Evicted` — whose
                // `is_fault()` is explicitly false — left this function saying
                // "recovered" about the same measured state the alarm above
                // calls a fault. Two answers to one question, from one pass,
                // eight lines apart; a caller or test reading the public
                // outcome would classify a still-pressured store as healthy.
                //
                // `evictable_rows` is what the levers reached THIS pass: the
                // bound is unenforceable in the sense that matters — the levers
                // ran, and the store is still over the line.
                return Ok(RetentionOutcome::BoundUnenforceable {
                    used_bytes: used_after,
                    cap_bytes,
                    evictable_rows: summary.evicted_traces as u64
                        + summary.archived_audit_entries as u64,
                });
            } else {
                // Measured, post-pass, under the trigger. Real evidence of
                // recovery.
                crate::degradation::clear(RETENTION_BOUND_CODE);
            }
        }
        // Handled above, and returned from — listed so a new variant is a
        // compile error rather than a silent fall-through to "cleared".
        ciris_lens_core::retention::DiskPressure::Unreachable { .. } => {}
    }

    if summary.evicted_traces == 0 && summary.archived_audit_entries == 0 {
        let outcome = RetentionOutcome::WithinBounds {
            trace_rows: before.trace_events.rows,
            oldest_trace: before.trace_events.oldest_ts,
            total_disk_bytes: before.total_disk_bytes,
        };
        tracing::info!(
            trace_rows = before.trace_events.rows,
            oldest_trace = ?before.trace_events.oldest_ts,
            total_disk_bytes = before.total_disk_bytes,
            %bounds,
            "retention pass evicted nothing — the store is inside every configured bound \
             (steady state, not a fault)"
        );
        return Ok(outcome);
    }

    // Read above, before the verdict, so the judgement and the report describe
    // the same instant.
    let after = after.expect("`acted` is true on this path, so `after` was read");
    tracing::info!(
        evicted_traces = summary.evicted_traces,
        archived_audit_entries = summary.archived_audit_entries,
        // On SQLite this is routinely 0 even for a large eviction: deleted pages
        // go on the freelist and `PRAGMA page_count` does not fall without a
        // VACUUM. `evicted_traces` is the signal that the pass did work;
        // `freed_bytes_estimate` is the signal that the OS got the space back,
        // and they are genuinely different questions.
        freed_bytes_estimate = summary.freed_bytes_estimate,
        trace_rows_remaining = after.trace_events.rows,
        total_disk_bytes = after.total_disk_bytes,
        %bounds,
        "retention pass EVICTED — rows removed from the local store per policy"
    );
    Ok(RetentionOutcome::Evicted {
        evicted_traces: summary.evicted_traces,
        archived_audit_entries: summary.archived_audit_entries,
        freed_bytes_estimate: summary.freed_bytes_estimate,
        total_disk_bytes: after.total_disk_bytes,
    })
}

/// The degradation code for an unenforceable bound. One constant, because the
/// raise site and BOTH clear sites must agree on the string or a stale alarm
/// never comes down.
const RETENTION_BOUND_CODE: &str = "retention.bound_unenforceable";

/// Bytes as an operator reads them. The log line beside this raise carries the
/// exact integers; the warning goes to a phone screen, where `202135808` and
/// `209715200` are the same number at a glance and `192.8 MiB of 200.0 MiB` is
/// the sentence that makes someone act.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// One operator-readable line naming the live bounds — so a zero pass says what
/// it checked, not merely that it found nothing.
fn describe_bounds(policy: &RetentionPolicy, total_disk_bytes: u64) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(3);
    if let Some(days) = policy.max_age_days {
        parts.push(format!("max_age_days={days}"));
    }
    if let Some(gb) = policy.max_disk_gb {
        // Report the DISTANCE to the trigger, not just the cap: "you are at 12%"
        // answers the question the cap alone only poses.
        let cap_bytes = (gb as f64) * 1_000_000_000.0;
        let pct = if cap_bytes > 0.0 {
            (total_disk_bytes as f64) / cap_bytes * 100.0
        } else {
            0.0
        };
        parts.push(format!(
            "max_disk_gb={gb} (at {pct:.1}% of cap; evicts from {trigger:.0}%)",
            trigger = DISK_EVICTION_THRESHOLD * 100.0,
        ));
    }
    if let Some(days) = policy.audit_log_max_age_days {
        parts.push(format!("audit_log_max_age_days={days}"));
    }
    parts.join(", ")
}

/// Spawn the retention controller loop. Returns the task handle (held by the
/// caller for the node's lifetime). The loop ticks on the configured cadence,
/// re-arms mid-sleep when that cadence changes, and exits when `shutdown` flips
/// to `true`.
///
/// The first pass runs after one full tick rather than at boot: a node that just
/// started has nothing to evict that it did not also have a moment before, and
/// deleting during the boot storm competes with the ingest/replication work that
/// actually has a deadline.
pub fn spawn(
    engine: Arc<Engine>,
    mut config_rx: watch::Receiver<ResolvedConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut cadence = RetentionConfig::from_resolved(&config_rx.borrow()).cadence;
        let mut tick = tokio::time::interval(cadence);
        // Consume the immediate first tick — see the boot note above.
        tick.tick().await;
        tracing::info!(
            cadence_secs = cadence.as_secs(),
            "retention loop started (CIRISServer#348: lens-core's eviction stack now has a \
             caller; bounds + cadence HOT from config:* retention.*)"
        );

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let cfg = RetentionConfig::from_resolved(&config_rx.borrow());
                    if cfg.cadence != cadence {
                        cadence = cfg.cadence;
                        tick = tokio::time::interval(cadence);
                        tick.tick().await;
                        tracing::info!(
                            cadence_secs = cadence.as_secs(),
                            "retention cadence retuned from config:* (hot)"
                        );
                    }
                    if let Err(e) = run_pass(&engine, &cfg).await {
                        // The ONE alarm in this module. Never panics the
                        // controller: a transient substrate error must cost one
                        // pass, not the node's only defence against a full disk.
                        tracing::warn!(
                            error = %e,
                            "retention pass FAILED — the store was not swept this cycle and \
                             stays at its current size; retrying next cadence"
                        );
                    }
                }
                changed = config_rx.changed() => {
                    if changed.is_err() {
                        // Config sender dropped — the serve stack is tearing down.
                        break;
                    }
                    // Re-arm on a cadence change instead of waiting out an
                    // in-flight sleep. At the hourly default that sleep is the
                    // difference between "tightened the bound" and "tightened
                    // the bound an hour ago and nothing has happened" — which is
                    // the moment an operator is most likely to be watching.
                    let cfg = RetentionConfig::from_resolved(&config_rx.borrow());
                    if cfg.cadence != cadence {
                        cadence = cfg.cadence;
                        tick = tokio::time::interval(cadence);
                        tick.tick().await;
                        tracing::info!(
                            cadence_secs = cadence.as_secs(),
                            "retention cadence retuned from config:* (hot, mid-sleep re-arm)"
                        );
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("retention loop shutting down");
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_reconcile::{
        DEFAULT_RETENTION_AUDIT_LOG_MAX_AGE_DAYS, DEFAULT_RETENTION_MAX_AGE_DAYS,
        DEFAULT_RETENTION_MAX_DISK_GB,
    };

    /// The baked defaults must project to a policy that actually BOUNDS
    /// something. A default-configured node running an eviction loop whose
    /// policy can never act is the same defect this whole file exists to fix,
    /// one level up: a caller that is wired to a no-op.
    #[test]
    fn the_baked_default_policy_is_bounded() {
        let cfg = RetentionConfig::from_resolved(&ResolvedConfig::default());
        assert!(
            cfg.policy.is_bounded(),
            "the default retention policy bounds nothing, so the loop is wired to a guaranteed \
             no-op on every node that has not been configured — which is every node. \
             DEFAULT_RETENTION_MAX_AGE_DAYS = {DEFAULT_RETENTION_MAX_AGE_DAYS}"
        );
        assert_eq!(
            cfg.policy.max_age_days,
            Some(DEFAULT_RETENTION_MAX_AGE_DAYS),
            "the age bound must come from the single baked const, not a second literal"
        );
    }

    /// `0` means "no bound" for the BOUNDS and "use the default" for the
    /// CADENCE. Same literal, two questions — pin both directions, because the
    /// tempting refactor is one shared "0 means off" helper and it would turn an
    /// operator's deliberate opt-out into a busy-spin (or their busy-spin into a
    /// silent opt-out).
    #[test]
    fn zero_disables_a_bound_but_never_the_cadence() {
        let r = ResolvedConfig {
            retention_max_age_days: 0,
            retention_max_disk_gb: 0,
            retention_audit_log_max_age_days: 0,
            retention_cadence_secs: 0,
            ..ResolvedConfig::default()
        };
        let cfg = RetentionConfig::from_resolved(&r);
        assert_eq!(
            cfg.policy.max_age_days, None,
            "0 days must mean NO time bound — an archive node's explicit opt-out"
        );
        assert!(
            !cfg.policy.is_bounded(),
            "an all-zero retention config must resolve to an unbounded policy"
        );
        assert!(
            cfg.cadence.as_secs() > 0,
            "a 0 cadence must fall back to the default, not produce a zero-period interval that \
             busy-spins a sweep over the whole store"
        );
    }

    /// The defaults that are deliberately OFF must stay off. Baking a disk cap
    /// would be actively unsafe on SQLite (freed pages stay in `page_count`, so
    /// the pressure signal that triggered the eviction cannot be cleared by it —
    /// every pass would halve the remaining window until the table is empty),
    /// and baking an audit cap would plan an archival lens-core's executor
    /// declines to run, on every pass, forever.
    #[test]
    fn the_unsafe_bounds_are_opt_in() {
        let cfg = RetentionConfig::from_resolved(&ResolvedConfig::default());
        assert_eq!(
            cfg.policy.max_disk_gb, None,
            "disk-pressure eviction must be opt-in ({DEFAULT_RETENTION_MAX_DISK_GB})"
        );
        assert_eq!(
            cfg.policy.audit_log_max_age_days, None,
            "audit archival must be opt-in ({DEFAULT_RETENTION_AUDIT_LOG_MAX_AGE_DAYS})"
        );
    }
}
