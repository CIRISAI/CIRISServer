//! **CC 4.1.4 `withdraws-arbitrage`** — the `withdraws`:`recants` arbitrage
//! countermeasure (CIRISServer#159; evidence row `4.1.4 / CLM-withdraws-arbitrage`).
//!
//! # The arbitrage, precisely
//!
//! CEG types FOUR structural composers ([CC 2.4.1](../../../CIRISConstitution/constitution/part_2_the_grammar.md)).
//! Two of them retract a prior row of the attester's own making, and they differ
//! ONLY in what they admit about the attester:
//!
//! | composer | meaning | what it costs the attester |
//! |---|---|---|
//! | `withdraws` | "I retract my prior attestation" — does **NOT** claim it was false | nothing (a retraction is epistemically neutral) |
//! | `recants`   | "my prior attestation **was false at issuance**" — admits epistemic error ([CC 2.4.1.3](#)) | a trust penalty: consumers downweight acknowledged-error chains |
//!
//! Persist implements the *structural* half of that distinction faithfully
//! (`ciris_persist::federation::precedence` — `recants` outranks `withdraws`
//! outranks `supersedes`, regardless of `signed_at`). What persist does NOT — and
//! by [CC 4.1.4](#) MUST NOT — do is *refuse* the cheap primitive: [CC 2.4.1.1]
//! makes `withdraws` admission a **MUST** for the substrate. So the substrate
//! cannot close the hole, and the hole is real:
//!
//! > **The arbitrage:** a misattester whose claim turns out to have been false at
//! > issuance emits `withdraws` (free) where an honest attester emits `recants`
//! > (costly), and thereby buys the *effect* of a retraction — the row stops
//! > counting — **without paying the epistemic-error price**. Iterated, it is a
//! > spray-and-retract engine: assert aggressively, retract whatever fails to
//! > stick, never once admit error. The attester's `recants` count stays at zero
//! > while its `withdraws` count grows without bound — and its trust weight, which
//! > only the `recants` channel would have decayed, never moves.
//!
//! CC 4.1.4 names the countermeasure and it is deliberately **not** a wire change
//! (a new prefix or a refusal at admission would be exactly the [CC 4.1.2]
//! anti-pattern — "extending the wire format so single attesters can pre-declare
//! their own state more richly"). Verbatim:
//!
//! > *Consumer policy MUST track per-attester `withdraws:recants` ratio over a
//! > rolling window; attesters whose ratio exceeds a configured threshold
//! > (default 5:1) SHOULD be downweighted regardless of which structural
//! > primitive they use. The `recants` distinction matters (CC 2.4.1.3), but the
//! > practical anti-arbitrage countermeasure is consumer-policy behavioral
//! > analysis, not a wire-format change.*
//!
//! # What this module is (and is NOT)
//!
//! It is **consumer policy**, run at the layer ABOVE the substrate:
//!
//!   - It **never** refuses a `withdraws` at `put_attestation`. Substrate
//!     admission stays exactly as [CC 2.4.1.1] requires (`MUST` admit from the
//!     producer / subject / proxy / delegate) — the audit chain keeps every row.
//!   - It refuses/downweights **our consumption of the arbitrager's corpus**:
//!     who we agree to replicate with ([`crate::federation_admin`] peering) and
//!     who we keep pulling from ([`crate::replication_reconcile`]). That is the
//!     one lever a consumer legitimately holds, and taking it away from an
//!     attester whose behavior is over-threshold is precisely the CC's
//!     "downweighted regardless of which structural primitive they use".
//!
//! # The ledger (how the ratio is counted — three non-obvious rules)
//!
//! 1. **Precedence-collapsed, not row-counted.** We do NOT count raw rows; we
//!    group the attester's in-window composers by the upstream row they target
//!    (`references_attestation_id`, via persist's
//!    [`references_attestation_id_from_envelope`]) and count ONE winner per group
//!    ([`precedence_winner`], CEG §6.1). One upstream row = one retraction act =
//!    one tally mark, on exactly one side of the ratio. An attester that emits
//!    BOTH a `withdraws` and a `recants` against the same upstream cannot have that
//!    single act counted twice: `recants` outranks `withdraws`, the group's
//!    effective state is `recants`, and the row leaves the numerator entirely. This
//!    is the CEG-faithful count (§6.1 defines the consumer-visible effective state
//!    of a composer group), and it is what makes the ratio mean "of the rows this
//!    attester retracted, what fraction did it own as *false*".
//!
//!    **The residual, stated honestly:** an attester CAN lower its ratio by
//!    emitting more `recants`. That is not a dodge — it is the countermeasure
//!    working. To buy denominator it must publicly admit, on the record and
//!    permanently, that its own claims were false at issuance — which is precisely
//!    the price CC 4.1.4 says the arbitrager is dodging, and each such admission is
//!    itself an acknowledged-error chain consumers downweight ([CC 2.4.1.3](#)).
//!    The one thing the countermeasure must never allow is buying that credit
//!    *without paying* — hence rule 1.
//! 2. **Add-one smoothing on the denominator.** `ratio = withdraws / max(recants, 1)`.
//!    An attester with zero `recants` is the *canonical* arbitrager, so the ratio
//!    must stay finite and comparable; smoothing also gives the sample floor for
//!    free — with `recants == 0` an attester must exceed `threshold` *withdraws*
//!    before it trips, so the honest attester who legitimately withdraws once or
//!    twice (a stale row, a superseded scope) is never flagged.
//! 3. **Rolling window.** Only composers with `asserted_at >= now - window` count
//!    ([`DEFAULT_WINDOW_DAYS`]) — CC 4.1.4's "rolling window". Behavior is
//!    forgiven with age; an attester that mends its ways ages out of the verdict.
//!
//! `supersedes` is *not* counted on either side: it replaces a row rather than
//! retracting it, and it is not the primitive the arbitrage trades in.
//!
//! # Fail closed
//!
//! [`enforce`] returns `Err` BOTH when the attester is over-threshold AND when
//! the ledger cannot be read at all ([`Refusal::LedgerUnavailable`]). An attester
//! whose behavior we cannot assess is an attester we do not consume: the whole
//! point of the countermeasure is that the cheap primitive must stop being free,
//! and a read error must not be a way to buy back the discount.
//!
//! # Configuration (CC 4.1.4 "a configured threshold")
//!
//! Both knobs are config-as-CEG keys ([`crate::graph_config`]), so an owner
//! retunes them with a signed `POST /v1/config` and no restart:
//!
//!   - [`RATIO_THRESHOLD_KEY`] (`f64`, default [`DEFAULT_RATIO_THRESHOLD`] = 5.0 —
//!     the CC's 5:1)
//!   - [`WINDOW_DAYS_KEY`] (`i64`, default [`DEFAULT_WINDOW_DAYS`] = 30)
//!
//! A malformed / out-of-range value falls back to the default and warns (a typo in
//! a config row must not silently disable the countermeasure — nor, in the other
//! direction, brick every peer).

use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};

use ciris_persist::federation::precedence::{
    is_structural_composer, precedence_winner, references_attestation_id_from_envelope,
};
use ciris_persist::federation::types::{attestation_type, Attestation};
use ciris_persist::prelude::Engine;

use crate::graph_config::{self, ConfigValue};

/// Config-as-CEG key for the CC 4.1.4 ratio threshold (`f64`).
pub const RATIO_THRESHOLD_KEY: &str = "policy.withdraws_arbitrage.ratio_threshold";

/// Config-as-CEG key for the CC 4.1.4 rolling-window length in days (`i64`).
pub const WINDOW_DAYS_KEY: &str = "policy.withdraws_arbitrage.window_days";

/// CC 4.1.4's **default 5:1** `withdraws:recants` threshold. An attester whose
/// in-window ratio *exceeds* this is in arbitrage.
pub const DEFAULT_RATIO_THRESHOLD: f64 = 5.0;

/// Default rolling window. CC 4.1.4 says "rolling window" without pinning a
/// length; 30 days matches the other behavioral cadences on this node (the
/// scorer's long window) and is long enough that a spray-and-retract engine
/// cannot simply pace itself under the ratio by spreading emissions over weeks.
pub const DEFAULT_WINDOW_DAYS: i64 = 30;

/// The resolved CC 4.1.4 consumer policy (threshold + rolling window).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArbitragePolicy {
    /// `withdraws:recants` ratio above which an attester is in arbitrage.
    pub ratio_threshold: f64,
    /// Rolling window over which composers are counted.
    pub window: Duration,
}

impl Default for ArbitragePolicy {
    fn default() -> Self {
        ArbitragePolicy {
            ratio_threshold: DEFAULT_RATIO_THRESHOLD,
            window: Duration::days(DEFAULT_WINDOW_DAYS),
        }
    }
}

/// Resolve the policy from the node's signed config graph, falling back to the
/// CC defaults for an absent / malformed / non-positive value (and warning — a
/// bad config row must not silently disable the countermeasure).
pub async fn load_policy(engine: &Arc<Engine>) -> ArbitragePolicy {
    let mut policy = ArbitragePolicy::default();

    match graph_config::get_config(engine, RATIO_THRESHOLD_KEY).await {
        Ok(Some(entry)) => match entry.value {
            ConfigValue::F64(v) if v > 0.0 && v.is_finite() => policy.ratio_threshold = v,
            ConfigValue::I64(v) if v > 0 => policy.ratio_threshold = v as f64,
            other => tracing::warn!(
                key = RATIO_THRESHOLD_KEY,
                value = ?other,
                default = DEFAULT_RATIO_THRESHOLD,
                "CC 4.1.4: unusable withdraws-arbitrage ratio threshold in config — using default"
            ),
        },
        Ok(None) => {}
        Err(e) => tracing::warn!(
            key = RATIO_THRESHOLD_KEY,
            error = %e,
            "CC 4.1.4: config read failed — using the default withdraws-arbitrage threshold"
        ),
    }

    match graph_config::get_config(engine, WINDOW_DAYS_KEY).await {
        Ok(Some(entry)) => match entry.value {
            ConfigValue::I64(v) if v > 0 => policy.window = Duration::days(v),
            other => tracing::warn!(
                key = WINDOW_DAYS_KEY,
                value = ?other,
                default = DEFAULT_WINDOW_DAYS,
                "CC 4.1.4: unusable withdraws-arbitrage window in config — using default"
            ),
        },
        Ok(None) => {}
        Err(e) => tracing::warn!(
            key = WINDOW_DAYS_KEY,
            error = %e,
            "CC 4.1.4: config read failed — using the default withdraws-arbitrage window"
        ),
    }

    policy
}

/// The per-attester behavioral ledger CC 4.1.4 makes a **MUST** ("Consumer policy
/// MUST track per-attester `withdraws:recants` ratio over a rolling window").
///
/// Counts are **precedence-collapsed** per upstream row (see module docs "The
/// ledger"), not raw row counts.
#[derive(Debug, Clone, PartialEq)]
pub struct AttesterLedger {
    /// The attester this ledger describes.
    pub attester_key_id: String,
    /// Upstream rows this attester *withdrew* in-window (precedence winners).
    pub withdraws: u64,
    /// Upstream rows this attester *recanted* in-window (precedence winners).
    pub recants: u64,
    /// `withdraws / max(recants, 1)` — add-one smoothed, see module docs.
    pub ratio: f64,
    /// The threshold this ledger was judged against (echoed for the audit line).
    pub ratio_threshold: f64,
    /// Start of the rolling window (`now - policy.window`).
    pub window_start: DateTime<Utc>,
}

impl AttesterLedger {
    /// The CC 4.1.4 verdict: `true` iff the in-window ratio **exceeds** the
    /// configured threshold. Strict `>` — an attester sitting exactly at 5:1 is
    /// at the line, not over it.
    pub fn is_arbitrage(&self) -> bool {
        self.ratio > self.ratio_threshold
    }

    /// The CC 4.1.4 **SHOULD**-downweight multiplier for consumers that compose a
    /// trust weight rather than making a binary consume / refuse call (the ratio
    /// is behavioral evidence, so the downweight is graded, not a cliff):
    ///
    ///   - at or under threshold → `1.0` (no adjustment);
    ///   - over threshold → `threshold / ratio` ∈ (0, 1) — an attester at 10:1
    ///     against a 5:1 threshold keeps half its weight, one at 50:1 a tenth.
    ///
    /// The binary consume-side gate ([`enforce`]) is the *stronger* reading and is
    /// what this node's replication paths take; this multiplier exists for scoring
    /// consumers (and is the honest surface to expose to downstream composition).
    pub fn trust_multiplier(&self) -> f64 {
        if !self.is_arbitrage() || self.ratio <= 0.0 {
            return 1.0;
        }
        (self.ratio_threshold / self.ratio).clamp(0.0, 1.0)
    }
}

/// A CC 4.1.4 consumer-policy refusal. **Typed**, so callers can distinguish "this
/// attester is arbitraging" from "we could not tell" — both fail closed, but they
/// are different operational stories.
#[derive(Debug, Clone)]
pub enum Refusal {
    /// The attester's in-window `withdraws:recants` ratio exceeds the threshold.
    Arbitrage(Box<AttesterLedger>),
    /// The ledger could not be read (substrate error). Fail closed: an attester we
    /// cannot assess is an attester we do not consume (module docs "Fail closed").
    LedgerUnavailable {
        /// The attester we failed to assess.
        attester_key_id: String,
        /// The underlying substrate error, stringified.
        source: String,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Arbitrage(l) => write!(
                f,
                "CC 4.1.4 withdraws-arbitrage refusal: attester {} has an in-window \
                 withdraws:recants ratio of {:.2}:1 ({} withdraws / {} recants since {}), \
                 exceeding the configured {:.2}:1 threshold — it retracts instead of recanting \
                 and never pays the epistemic-error price",
                l.attester_key_id,
                l.ratio,
                l.withdraws,
                l.recants,
                l.window_start.to_rfc3339(),
                l.ratio_threshold,
            ),
            Refusal::LedgerUnavailable {
                attester_key_id,
                source,
            } => write!(
                f,
                "CC 4.1.4 withdraws-arbitrage refusal: the behavioral ledger for attester \
                 {attester_key_id} could not be read ({source}) — failing closed",
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Build the CC 4.1.4 ledger for `attester_key_id` from THIS node's corpus (the
/// rows we, the consumer, actually hold — behavioral analysis over observed
/// history, exactly the CC's framing).
///
/// The MUST half of CC 4.1.4. Never refuses: it reports. [`enforce`] is the gate.
pub async fn assess(
    engine: &Arc<Engine>,
    attester_key_id: &str,
    policy: ArbitragePolicy,
    now: DateTime<Utc>,
) -> Result<AttesterLedger, Refusal> {
    let rows = engine
        .federation_directory()
        .list_attestations_by(attester_key_id)
        .await
        .map_err(|e| Refusal::LedgerUnavailable {
            attester_key_id: attester_key_id.to_owned(),
            source: e.to_string(),
        })?;

    let window_start = now - policy.window;
    Ok(ledger_from_rows(
        attester_key_id,
        &rows,
        policy,
        window_start,
    ))
}

/// The pure counting core (no I/O) — precedence-collapse the attester's in-window
/// structural composers and compute the smoothed ratio. Split out so the rule
/// itself is unit-testable without a substrate.
fn ledger_from_rows(
    attester_key_id: &str,
    rows: &[Attestation],
    policy: ArbitragePolicy,
    window_start: DateTime<Utc>,
) -> AttesterLedger {
    // In-window structural composers authored BY this attester. `list_attestations_by`
    // already filters on `attesting_key_id`, but re-assert it: the ledger is
    // per-attester by definition and a mis-scoped read must not silently borrow
    // someone else's behavior.
    let composers: Vec<&Attestation> = rows
        .iter()
        .filter(|a| {
            a.attesting_key_id == attester_key_id
                && is_structural_composer(&a.attestation_type)
                && a.asserted_at >= window_start
        })
        .collect();

    // Group by the upstream row each composer targets (CEG §6.1's grouping key,
    // minus `attesting_key_id` — every row here is already the same attester).
    // A composer whose envelope omits `references_attestation_id` is its own group
    // (keyed by its row id): it is schema-broken, but it is still a retraction the
    // attester emitted, and dropping it would hand the arbitrager a free pass by
    // simply omitting a field.
    let mut groups: std::collections::BTreeMap<&str, Vec<&Attestation>> =
        std::collections::BTreeMap::new();
    for a in &composers {
        let key = references_attestation_id_from_envelope(&a.attestation_envelope)
            .unwrap_or(a.attestation_id.as_str());
        groups.entry(key).or_default().push(a);
    }

    // ONE precedence winner per upstream row (CEG §6.1: recants > withdraws >
    // supersedes). This is what makes the denominator un-gameable — see module
    // docs "The ledger" rule 1.
    let (mut withdraws, mut recants) = (0u64, 0u64);
    for (_upstream, group) in groups {
        match precedence_winner(&group).map(|w| w.attestation_type.as_str()) {
            Some(attestation_type::WITHDRAWS) => withdraws += 1,
            Some(attestation_type::RECANTS) => recants += 1,
            // `supersedes` (a replacement, not a retraction) and anything else are
            // not part of the arbitrage trade — neither numerator nor denominator.
            _ => {}
        }
    }

    // Add-one smoothing: zero recants is the canonical arbitrager, so the ratio
    // must stay finite AND an attester must exceed `threshold` withdraws before a
    // zero-recants history trips (module docs "The ledger" rule 2).
    let ratio = withdraws as f64 / recants.max(1) as f64;

    AttesterLedger {
        attester_key_id: attester_key_id.to_owned(),
        withdraws,
        recants,
        ratio,
        ratio_threshold: policy.ratio_threshold,
        window_start,
    }
}

/// The CC 4.1.4 **gate**: assess `attester_key_id` and refuse to consume from it
/// when it is in arbitrage — or when it cannot be assessed at all (fail closed).
///
/// Wired at the two points where THIS node decides to consume a foreign attester's
/// corpus (never at substrate admission — see module docs "What this module is"):
///
///   - [`crate::federation_admin`] `POST /v1/federation/peering` — do not enter a
///     replication consent with an arbitraging attester;
///   - [`crate::replication_reconcile::reconcile_once`] — and do not keep pulling
///     from one that turned into an arbitrager after consent was granted (the
///     window is rolling, so this is re-judged every tick, in both directions).
pub async fn enforce(
    engine: &Arc<Engine>,
    attester_key_id: &str,
    policy: ArbitragePolicy,
    now: DateTime<Utc>,
) -> Result<AttesterLedger, Refusal> {
    let ledger = assess(engine, attester_key_id, policy, now).await?;
    if ledger.is_arbitrage() {
        return Err(Refusal::Arbitrage(Box::new(ledger)));
    }
    Ok(ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::types::attestation_tier;

    /// A composer row by `attester` against upstream `refs`, `age_days` old.
    fn composer(id: &str, attester: &str, kind: &str, refs: &str, age_days: i64) -> Attestation {
        let now = Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: "subject".to_owned(),
            attestation_type: kind.to_owned(),
            weight: None,
            asserted_at: now - Duration::days(age_days),
            expires_at: None,
            attestation_envelope: serde_json::json!({ "references_attestation_id": refs }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
        }
    }

    fn ledger(rows: &[Attestation]) -> AttesterLedger {
        let policy = ArbitragePolicy::default();
        ledger_from_rows("bad-attester", rows, policy, Utc::now() - policy.window)
    }

    /// The honest attester: a couple of legitimate withdraws (stale rows), no
    /// recants — under the 5:1 line thanks to add-one smoothing.
    #[test]
    fn a_few_honest_withdraws_are_not_arbitrage() {
        let rows = vec![
            composer("w1", "bad-attester", attestation_type::WITHDRAWS, "u1", 1),
            composer("w2", "bad-attester", attestation_type::WITHDRAWS, "u2", 2),
        ];
        let l = ledger(&rows);
        assert_eq!((l.withdraws, l.recants), (2, 0));
        assert!(!l.is_arbitrage(), "2:0 is under the 5:1 threshold");
        assert_eq!(l.trust_multiplier(), 1.0);
    }

    /// The arbitrager: 6 withdraws, never a recant → 6:1 > 5:1.
    #[test]
    fn spray_and_retract_trips_the_ratio() {
        let rows: Vec<Attestation> = (0..6)
            .map(|i| {
                composer(
                    &format!("w{i}"),
                    "bad-attester",
                    attestation_type::WITHDRAWS,
                    &format!("u{i}"),
                    1,
                )
            })
            .collect();
        let l = ledger(&rows);
        assert_eq!((l.withdraws, l.recants), (6, 0));
        assert!(l.is_arbitrage());
        assert!(l.trust_multiplier() < 1.0);
    }

    /// One upstream row is ONE retraction act: an attester that emits both a
    /// `withdraws` and a `recants` against the same upstream does not get it
    /// counted on both sides of the ratio. Precedence collapses each group to its
    /// `recants` winner (0 withdraws, 6 recants) — it did admit those claims were
    /// false, and it pays (and is credited) for that exactly once.
    #[test]
    fn same_upstream_recants_cannot_inflate_the_denominator() {
        let mut rows = Vec::new();
        for i in 0..6 {
            let u = format!("u{i}");
            rows.push(composer(
                &format!("w{i}"),
                "bad-attester",
                attestation_type::WITHDRAWS,
                &u,
                1,
            ));
            rows.push(composer(
                &format!("r{i}"),
                "bad-attester",
                attestation_type::RECANTS,
                &u,
                1,
            ));
        }
        let l = ledger(&rows);
        assert_eq!(
            (l.withdraws, l.recants),
            (0, 6),
            "precedence collapses each (attester, upstream) group to its recants winner"
        );
        assert!(!l.is_arbitrage());
    }

    /// Rolling window: the same spray, but stale (beyond the window) → forgiven.
    #[test]
    fn stale_withdraws_age_out_of_the_window() {
        let rows: Vec<Attestation> = (0..20)
            .map(|i| {
                composer(
                    &format!("w{i}"),
                    "bad-attester",
                    attestation_type::WITHDRAWS,
                    &format!("u{i}"),
                    DEFAULT_WINDOW_DAYS + 1,
                )
            })
            .collect();
        let l = ledger(&rows);
        assert_eq!((l.withdraws, l.recants), (0, 0));
        assert!(!l.is_arbitrage());
    }

    /// A `supersedes` is a replacement, not a retraction — it trades in neither
    /// side of the arbitrage.
    #[test]
    fn supersedes_is_counted_on_neither_side() {
        let rows = vec![composer(
            "s1",
            "bad-attester",
            attestation_type::SUPERSEDES,
            "u1",
            1,
        )];
        let l = ledger(&rows);
        assert_eq!((l.withdraws, l.recants), (0, 0));
    }

    /// Exactly at the line is not over it (strict `>`), per CC 4.1.4 "exceeds".
    #[test]
    fn exactly_at_threshold_is_not_arbitrage() {
        let rows: Vec<Attestation> = (0..5)
            .map(|i| {
                composer(
                    &format!("w{i}"),
                    "bad-attester",
                    attestation_type::WITHDRAWS,
                    &format!("u{i}"),
                    1,
                )
            })
            .collect();
        let l = ledger(&rows);
        assert_eq!(l.ratio, 5.0);
        assert!(!l.is_arbitrage());
    }
}
