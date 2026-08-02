//! Same-key equivocation detection — the CC 6.1.1 N4 `hard_case` for the
//! attestation plane (CIRISServer#350).
//!
//! A key can sign two contradictory claims, hand one to peer A and the other to
//! peer B, and both verify. CC 6.1.1 N4 already says what the substrate owes in
//! that case — two validly-signed objects from one issuer at one version
//! coordinate, with different content, are *non-repudiable equivocation proof*;
//! retain and surface them as a `hard_case:*`, **never silently reconcile**.
//! persist implements exactly that for `wholeness_witness:` objects
//! (`witness::compare::equivocation_hard_case`, keyed on `(peer_id, epoch_id,
//! namespace_set)`). Nothing implements it for **attestations**, which is where
//! every reputational, consent, moderation and location claim in this system
//! lives. This module is that comparison, for the rows one node happens to hold.
//!
//! ## The predicate
//!
//! Two live federation-tier rows equivocate when they share
//!
//!   `(attesting_key_id, attested_key_id, dimension, SIGNED assertion instant)`
//!
//! and their `original_content_hash` differs. Nothing weaker works. "Same
//! subject and dimension at overlapping validity, different content" — the ask
//! as first written — fires on every honest restatement: a `capacity:*` row
//! stays live for seven days while the scorer re-measures hourly, so two live
//! rows carrying different scores is the NORMAL state of a moving score, not a
//! contradiction. What makes a pair unresolvable is that **neither supersedes
//! the other**: same instant, so no consumer's latest-wins fold can pick one.
//! That is the same shape as N4's `epoch_id` — an issuer who wants both claims
//! believed as current cannot advance the coordinate, because advancing it
//! concedes that one of them is stale.
//!
//! ## Which `asserted_at` (one name, two axes)
//!
//! [`Attestation::asserted_at`] — the ROW COLUMN — is `chrono::Utc::now()` at
//! write time (`Engine::emit_attestation_assemble`). It is local bookkeeping,
//! it is not covered by `original_content_hash`, and no ingest gate checks it
//! against the envelope. The instant this module compares is the one INSIDE the
//! signed envelope, because an equivocation proof may rest only on bytes the
//! attester signed — a third party re-verifies the pair from the two envelopes
//! alone, with no trust in either holder's columns. The two axes disagree in
//! practice, not just in theory: the scorer's coalescing floors the ENVELOPE
//! instant to an hour bucket while the column keeps microsecond wall-clock, so
//! keying on the column would silently detect nothing.
//!
//! The cost is coverage: an envelope carrying no signed instant is **not
//! comparable** and is counted, not guessed at ([`PairVerdict::NoSignedInstant`]).
//! persist's `envelope::paths` does not own this key — it is a producer
//! convention (`scorer`, `peer`, `graph_config`, `auth::ownership` all emit it),
//! so producers that omit it are outside this detector's reach.
//!
//! ## What this deliberately does NOT do
//!
//! **No global consistency, no consensus, no total order.** This compares rows
//! that HAPPENED TO LAND on this node. A pair split cleanly across two peers is
//! invisible here and stays invisible — that is the issue's ask #2 (replicate
//! the proof), not this. Nothing here votes, gossips, or asks a peer anything.
//!
//! **No penalty, no score, no de-admission.** Detection only. The signal is
//! manufacturable — anyone who can get two rows into one corpus can make a key
//! look like an equivocator to a naive consumer — so wiring an automatic
//! consequence onto it would build the attack it is trying to expose. CC 6.1.1
//! N4 asks for *retain and surface*; a graded, per-reader consequence is
//! CIRISServer#346's ladder, and it belongs behind a signed human judgement.
//!
//! **No cross-dimension contradiction.** In this grammar the sharpest
//! contradiction available — "I consented" to one peer, "I did not" to another —
//! is expressed as two DIFFERENT dimensions (`consent:state:granted:*` vs
//! `consent:state:revoked:*`), not as two contents under one. Grouping by
//! dimension cannot see it, and inferring that granted/revoked are two values of
//! one axis requires a mutual-exclusion declaration the namespace manifest does
//! not carry (the missing `ci_axis` column, CIRISPersist#532). Widening the
//! group key to the family prefix instead would flag
//! `capacity:sustained_coherence:v1` against `capacity:something_else:v1` — two
//! measurements, not a contradiction — so the honest answer is to detect what
//! the coordinate can prove and name the gap rather than guess.
//!
//! **No retraction fold.** A later `withdraws`/`recants` against one half does
//! not clear the pair: the two rows were both signed at one instant and that is
//! non-repudiable. N4 says never silently reconcile, and folding a retraction in
//! here would be exactly that.
//!
//! ## The first thing it finds is ours
//!
//! On a node running the capacity scorer, this fires on the scorer's OWN rows.
//! `scorer::coalesced_assertion` floors the envelope instant to an hour bucket,
//! and `standing_assertion` only suppresses a re-emission when the score is
//! UNCHANGED — so a score that moves twice inside one hour authors two rows at
//! one signed instant carrying different scores. Under this predicate that is a
//! contradiction, and it is: a peer holding both cannot tell which is current.
//! There is no exemption for the local key here, deliberately — a detector that
//! trusts its own node is not a detector.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::hard_case::HardCaseEvent;
use ciris_persist::federation::types::attestation_tier;
use ciris_persist::federation::Attestation;
use ciris_persist::prelude::{CallerScope, Engine};

/// The `hard_case:{kind}` this emits. persist's kind vocabulary is open (the
/// column is free TEXT) and carries no attestation-plane equivocation kind, so
/// this is declared server-side — named as the sibling of persist's
/// `witness::WITNESS_EQUIVOCATION` so the two N4 emitters read as one family.
pub const HARD_CASE_KIND: &str = "attestation_equivocation";

/// The envelope field naming the instant the attester CLAIMS (as opposed to
/// [`Attestation::asserted_at`], the local write column — see the module doc).
/// Not a persist-owned key: `envelope::paths` has no constant for it, so this
/// is the server's one spelling of a producer convention rather than a mirror
/// of someone else's vocabulary.
const ENVELOPE_ASSERTED_AT: &str = "asserted_at";

/// Detector configuration. Deliberately not a `config:*` knob: unlike the
/// scorer's gates, nothing about this pass is a calibration choice a deployment
/// would want to retune, and every knob added to the hot config surface is a
/// value that can disagree with its baked default.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// How often the pass runs. Equivocation is not a race — the corpus keeps
    /// both rows and the `event_id` is idempotent, so a slow cadence costs
    /// latency-to-notice and nothing else.
    pub cadence: Duration,
    /// Rows per read page.
    pub page: i64,
    /// Hard ceiling on rows scanned per pass. A pass that hits it is REPORTED
    /// as truncated (never silently short): partial coverage that reads as full
    /// coverage is the failure mode this codebase keeps paying for.
    pub max_rows: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        DetectorConfig {
            cadence: Duration::from_secs(900),
            page: 512,
            max_rows: 4096,
        }
    }
}

/// What comparing two rows at the same `(attester, subject, dimension)`
/// coordinate actually found.
///
/// Named outcomes rather than a `bool`, for the reason `scorer::ScoreOutcome`
/// exists: three of these four are perfectly healthy and they are healthy for
/// DIFFERENT reasons — a restatement, a superseded revision, and an envelope
/// this detector cannot read are not one "not a contradiction" case, and
/// collapsing them would hide the third (the coverage hole) behind the first
/// two (the steady state).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairVerdict {
    /// Byte-identical claims (same content hash). A re-recorded row, a
    /// replicated duplicate, or the coalescing working. Nothing to say.
    SameStatement,
    /// Different signed instants: time orders them, and every consumer's
    /// latest-wins fold resolves it the same way. A revision, not a
    /// contradiction — the attester changed its mind in public.
    Superseded,
    /// One or both envelopes carry no signed assertion instant, so the pair
    /// cannot be ordered and cannot be shown simultaneous. NOT a clean bill of
    /// health — an unmeasurable case, counted so the coverage hole is visible.
    NoSignedInstant,
    /// Same signed instant, different content. Nothing orders these two and
    /// both are validly signed by one key: the CC 6.1.1 N4 case.
    Contradiction,
}

/// The signed assertion instant an envelope claims, if it declares one.
fn signed_instant(envelope: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    envelope
        .get(ENVELOPE_ASSERTED_AT)
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// The dimension a row claims under, or `None` for an undimensioned row
/// (a structural composer, say). Read through persist's helper so the envelope
/// key stays single-sourced.
fn dimension_of(a: &Attestation) -> Option<String> {
    ciris_persist::federation::admission::envelope_dimension(&a.attestation_envelope)
        .map(str::to_owned)
}

/// Classify one pair of rows that already share `(attester, subject,
/// dimension)`. THE predicate — every arm of the detector routes through here,
/// so there is one place where "what is a contradiction" is decided.
pub fn classify_pair(a: &Attestation, b: &Attestation) -> PairVerdict {
    // Identical signed bytes are the same statement however they are dated —
    // checked first so a duplicate never has to survive the instant logic.
    if a.original_content_hash == b.original_content_hash {
        return PairVerdict::SameStatement;
    }
    let (Some(ta), Some(tb)) = (
        signed_instant(&a.attestation_envelope),
        signed_instant(&b.attestation_envelope),
    ) else {
        return PairVerdict::NoSignedInstant;
    };
    if ta == tb {
        PairVerdict::Contradiction
    } else {
        PairVerdict::Superseded
    }
}

/// One detected contradiction: the two rows, and the coordinate they both
/// claim. This IS the evidence — a third party re-verifies it from the two
/// envelopes and their signatures without holding anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contradiction {
    /// The key that signed both.
    pub attesting_key_id: String,
    /// The subject both claims are about.
    pub subject_key_id: String,
    /// The dimension both claim under.
    pub dimension: String,
    /// The instant BOTH envelopes claim (the signed one).
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// The two rows, sorted by `attestation_id`.
    pub attestation_ids: (String, String),
    /// Their content hashes, in the same order as [`Self::attestation_ids`].
    pub content_hashes: (String, String),
    /// Top-level envelope fields whose values differ — the legible half of the
    /// proof. The hashes are what a verifier checks; this is what a reader
    /// looks at first.
    pub differing_fields: Vec<String>,
}

impl Contradiction {
    /// Build from an unordered pair. SORTS the two rows by `attestation_id`
    /// here, once, so that the identity of a contradiction never depends on
    /// which row this node happened to read first — `event_id`, `detail` and
    /// equality all inherit the normalization instead of each re-deriving it.
    fn new(
        a: &Attestation,
        b: &Attestation,
        dimension: String,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let (lo, hi) = if a.attestation_id <= b.attestation_id {
            (a, b)
        } else {
            (b, a)
        };
        Contradiction {
            attesting_key_id: lo.attesting_key_id.clone(),
            subject_key_id: lo.attested_key_id.clone(),
            dimension,
            asserted_at,
            attestation_ids: (lo.attestation_id.clone(), hi.attestation_id.clone()),
            content_hashes: (
                lo.original_content_hash.clone(),
                hi.original_content_hash.clone(),
            ),
            differing_fields: differing_fields(&lo.attestation_envelope, &hi.attestation_envelope),
        }
    }

    /// The idempotency key — DETERMINISTIC over the sorted pair of
    /// `attestation_id`s and nothing else.
    ///
    /// persist's `record_hard_case` is `ON CONFLICT(event_id) DO NOTHING`, so
    /// this is what makes a re-scan a no-op instead of a duplicate row, and
    /// this pass re-scans every cadence forever. Nothing time-varying may enter
    /// it: the observation instant lives in `emitted_at`, which is a column, not
    /// part of the key.
    ///
    /// `attestation_id`s survive replication (the wire row carries the
    /// producer's id), so two nodes that independently hold the same pair derive
    /// the SAME `event_id` — which is what would let these proofs merge if the
    /// issue's ask #2 (replicate the evidence) is built on top.
    #[must_use]
    pub fn event_id(&self) -> String {
        format!(
            "{HARD_CASE_KIND}:{}:{}",
            self.attestation_ids.0, self.attestation_ids.1
        )
    }

    /// The CC 6.1.1 N4 `hard_case`. `target_key_id` is the equivocating key and
    /// `subject_key_id` the party it equivocated about — the same split
    /// persist's witness emitter uses (`target` = the peer that published two
    /// roots), so a consumer reading both kinds reads one shape.
    #[must_use]
    pub fn hard_case(&self, emitted_at: chrono::DateTime<chrono::Utc>) -> HardCaseEvent {
        HardCaseEvent {
            event_id: self.event_id(),
            kind: HARD_CASE_KIND.to_owned(),
            target_key_id: Some(self.attesting_key_id.clone()),
            subject_key_id: Some(self.subject_key_id.clone()),
            detail: serde_json::json!({
                "attesting_key_id": self.attesting_key_id,
                "subject_key_id": self.subject_key_id,
                (paths::DIMENSION): self.dimension,
                "signed_asserted_at": self.asserted_at.to_rfc3339(),
                "attestation_ids": [self.attestation_ids.0, self.attestation_ids.1],
                "content_hashes": [self.content_hashes.0, self.content_hashes.1],
                "differing_fields": self.differing_fields,
                "rule": "CC 6.1.1 N4",
                "detection": "local — this node holds both rows; no consensus, no penalty",
            }),
            emitted_at,
        }
    }
}

/// Top-level envelope keys whose values differ (including keys present in only
/// one). Sorted, so the evidence reads the same on every node.
fn differing_fields(a: &serde_json::Value, b: &serde_json::Value) -> Vec<String> {
    let (Some(oa), Some(ob)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = oa.keys().chain(ob.keys()).collect();
    keys.sort_unstable();
    keys.dedup();
    keys.into_iter()
        .filter(|k| oa.get(*k) != ob.get(*k))
        .cloned()
        .collect()
}

/// What one pass saw. Every non-contradiction verdict is counted, for the
/// reason the scorer counts its non-emitting outcomes: a zero has to be able to
/// name its own cause. `contradictions == 0` because nothing was comparable is
/// a different fact from `contradictions == 0` because everything agreed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectorReport {
    /// Live federation-tier dimensioned rows this pass compared.
    pub rows_scanned: usize,
    /// Pairs classified.
    pub pairs_compared: usize,
    /// [`PairVerdict::SameStatement`] count.
    pub same_statement: usize,
    /// [`PairVerdict::Superseded`] count.
    pub superseded: usize,
    /// [`PairVerdict::NoSignedInstant`] count — the coverage hole, measured.
    pub no_signed_instant: usize,
    /// The contradictions, in a stable order.
    pub contradictions: Vec<Contradiction>,
    /// The `max_rows` ceiling was hit: this pass did NOT see the whole live
    /// corpus and its zero (or its count) is a floor, not a total.
    pub truncated: bool,
}

/// Compare every pair of rows sharing `(attester, subject, dimension)`. Pure —
/// no engine, no clock — so the predicate is testable without a corpus.
///
/// Quadratic WITHIN a coordinate group only. Group sizes are small by
/// construction (one live row per coalescing bucket per coordinate) and the
/// caller caps the total row count, so the worst case is bounded by
/// `max_rows²`, once per cadence.
#[must_use]
pub fn detect(rows: &[&Attestation]) -> DetectorReport {
    let mut groups: std::collections::BTreeMap<(String, String, String), Vec<&Attestation>> =
        std::collections::BTreeMap::new();
    for r in rows {
        // An undimensioned row (a structural composer) has no claim coordinate
        // to contradict at — it is a statement ABOUT another row, and its
        // grouping key would be a different one entirely.
        let Some(dim) = dimension_of(r) else { continue };
        groups
            .entry((r.attesting_key_id.clone(), r.attested_key_id.clone(), dim))
            .or_default()
            .push(r);
    }

    let mut report = DetectorReport {
        rows_scanned: rows.len(),
        ..Default::default()
    };
    for ((_, _, dim), group) in groups {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (a, b) = (group[i], group[j]);
                report.pairs_compared += 1;
                match classify_pair(a, b) {
                    PairVerdict::SameStatement => report.same_statement += 1,
                    PairVerdict::Superseded => report.superseded += 1,
                    PairVerdict::NoSignedInstant => report.no_signed_instant += 1,
                    PairVerdict::Contradiction => {
                        // `classify_pair` only reaches this arm with both
                        // instants present and equal, so either one is THE
                        // coordinate; taking `a`'s is not a choice between them.
                        let at = signed_instant(&a.attestation_envelope)
                            .expect("classify_pair returns Contradiction only when both parse");
                        report
                            .contradictions
                            .push(Contradiction::new(a, b, dim.clone(), at));
                    }
                }
            }
        }
    }
    report
}

/// The live federation-tier rows this node holds, read with the filter PUSHED
/// INTO THE QUERY (CIRISServer#343).
///
/// Two narrowings, and they are not the same kind of thing:
///
/// - `valid_at = now` is a REAL pushdown (`asserted_at <= now AND (expires_at IS
///   NULL OR expires_at > now)`) and it is also the semantic bound: rows live at
///   one instant all overlap at that instant, which is the "overlapping
///   validity" leg of the predicate.
/// - `tier` is filtered in RUST, on purpose. `AttestationFilter::tier` exists
///   and `list_attestations` (sqlite) silently ignores it — the field is honored
///   by the `list_scores` handles and dropped by this one, along with `window`,
///   `lifecycle` and `attester_filter`. Setting it here would read as a bound
///   and be none. Federation tier is the right restriction on its own merits: a
///   local-tier row was never published to anyone, so it cannot be evidence that
///   a key told two peers different things.
///
/// The scope is the node authenticated AS ITSELF (`build_caller_admission` —
/// the only public path to an admission, so this cannot fabricate reach it does
/// not have). `Unauthenticated` would drop every `self`-scoped row, which is the
/// narrowing-that-reads-as-healthy that cost `graph_config` a nine-test cut.
async fn live_rows(
    engine: &Engine,
    node_key_id: &str,
    cfg: &DetectorConfig,
) -> Result<(Vec<Attestation>, bool)> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    let admission = ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned())
        .await
        .map_err(|e| anyhow::anyhow!("resolve equivocation-scan caller admission: {e}"))?;
    let scope = CallerScope::Authenticated { admission };
    let now = chrono::Utc::now();

    let mut out: Vec<Attestation> = Vec::new();
    let mut scanned = 0usize;
    let mut cursor = None;
    let truncated = loop {
        // `AttestationFilter` is #[non_exhaustive] — build-then-set so a new
        // predicate arrives as a default rather than a compile break.
        let mut filter = AttestationFilter::default();
        filter.valid_at = Some(now);
        let page = engine
            .list_attestations(filter, cursor, cfg.page, scope.clone())
            .await
            .map_err(|e| anyhow::anyhow!("list live attestations: {e}"))?;
        scanned += page.items.len();
        out.extend(
            page.items
                .into_iter()
                .filter(|a| a.tier == attestation_tier::FEDERATION),
        );
        match page.next_cursor {
            None => break false,
            Some(_) if scanned >= cfg.max_rows => break true,
            Some(c) => cursor = Some(c),
        }
    };
    Ok((out, truncated))
}

/// Run one detection pass and record a `hard_case` for every contradiction
/// found. Public so a test can drive one deterministic pass without the timer.
///
/// Recording is idempotent on [`Contradiction::event_id`], so this re-records
/// the same standing contradictions every cadence and writes nothing new. That
/// is the intended steady state: the condition does not clear, and the pass
/// re-asserting it costs one no-op INSERT.
pub async fn run_pass(
    engine: &Engine,
    node_key_id: &str,
    cfg: &DetectorConfig,
) -> Result<DetectorReport> {
    let (rows, truncated) = live_rows(engine, node_key_id, cfg)
        .await
        .context("equivocation detector: read live rows")?;
    let refs: Vec<&Attestation> = rows.iter().collect();
    let mut report = detect(&refs);
    report.truncated = truncated;

    let now = chrono::Utc::now();
    for c in &report.contradictions {
        // A pair that fails to record is NOT dropped from the report — the
        // contradiction was observed either way, and a failed write must not be
        // able to make an observation disappear.
        if let Err(e) = engine
            .federation_directory()
            .record_hard_case(c.hard_case(now))
            .await
        {
            tracing::warn!(
                error = %e,
                event_id = %c.event_id(),
                "equivocation detector: hard_case NOT recorded (the contradiction stands; \
                 the next pass re-records it)"
            );
        }
    }

    if report.contradictions.is_empty() {
        tracing::debug!(
            rows_scanned = report.rows_scanned,
            pairs_compared = report.pairs_compared,
            same_statement = report.same_statement,
            superseded = report.superseded,
            no_signed_instant = report.no_signed_instant,
            truncated = report.truncated,
            "equivocation detector: no same-key contradictions in the live corpus"
        );
    } else {
        // WARN, not INFO: a standing contradiction is a claim by one key that
        // no consumer can resolve, and it stays true until someone acts.
        for c in &report.contradictions {
            tracing::warn!(
                attesting_key_id = %c.attesting_key_id,
                subject_key_id = %c.subject_key_id,
                dimension = %c.dimension,
                signed_asserted_at = %c.asserted_at,
                row_a = %c.attestation_ids.0,
                row_b = %c.attestation_ids.1,
                differing_fields = ?c.differing_fields,
                "SAME-KEY EQUIVOCATION (CC 6.1.1 N4): one key signed two different claims about \
                 one subject at one instant — both rows retained as evidence, neither reconciled"
            );
        }
    }
    Ok(report)
}

/// Spawn the periodic detector. Returns the join handle; the task runs for the
/// node's lifetime.
pub fn spawn(engine: Arc<Engine>, cfg: DetectorConfig) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // The node's own derived key — needed for the read admission, not for
        // any exemption. Resolve once: it cannot change under a running node.
        let node_key_id = match engine.local_derived_key_id().await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "equivocation detector: cannot resolve the node identity — detector NOT running"
                );
                return;
            }
        };
        let mut tick = tokio::time::interval(cfg.cadence);
        // Skip missed ticks rather than burst-catch-up: a delayed pass has
        // nothing to catch up on (the rows are still there).
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate first tick — the corpus at boot is whatever the
        // last run left; one cadence of patience costs nothing.
        tick.tick().await;
        tracing::info!(
            cadence_secs = cfg.cadence.as_secs(),
            max_rows = cfg.max_rows,
            "same-key equivocation detector started (CC 6.1.1 N4; local detection only — \
             no consensus, no automatic penalty)"
        );
        loop {
            tick.tick().await;
            if let Err(e) = run_pass(&engine, &node_key_id, &cfg).await {
                tracing::warn!(
                    error = %e,
                    "equivocation detector pass failed (will retry next cadence)"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, attester: &str, subject: &str, envelope: serde_json::Value) -> Attestation {
        let hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(
                serde_json::to_vec(&envelope).expect("envelope"),
            ))
        };
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: "scores".to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
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
            additional_scrubs: Vec::new(),
        }
    }

    fn claim(dim: &str, at: &str, rating: f64) -> serde_json::Value {
        serde_json::json!({
            (paths::DIMENSION): dim,
            "asserted_at": at,
            "rating": rating,
        })
    }

    const DIM: &str = "moderation:conduct:v1";
    const T0: &str = "2026-08-01T17:00:00Z";
    const T1: &str = "2026-08-01T18:00:00Z";

    /// **The whole point.** One key, one subject, one dimension, one signed
    /// instant, two different claims — nothing orders them, so nothing can
    /// resolve them.
    #[test]
    fn one_key_two_claims_at_one_signed_instant_is_a_contradiction() {
        let a = row("id-a", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let b = row("id-b", "peer-1", "agent-x", claim(DIM, T0, 0.1));
        assert_eq!(classify_pair(&a, &b), PairVerdict::Contradiction);
        let report = detect(&[&a, &b]);
        assert_eq!(
            report.contradictions.len(),
            1,
            "two same-instant claims differing in content must produce exactly one \
             contradiction, got {:?}",
            report.contradictions
        );
        let c = &report.contradictions[0];
        assert_eq!(c.attesting_key_id, "peer-1");
        assert_eq!(c.subject_key_id, "agent-x");
        assert_eq!(c.attestation_ids, ("id-a".to_owned(), "id-b".to_owned()));
        assert_eq!(
            c.differing_fields,
            vec!["rating".to_owned()],
            "the evidence must name the field the two claims disagree on"
        );
    }

    /// A LATER claim is a revision, and every consumer's latest-wins fold
    /// resolves it identically. Flagging it would flag every honest producer
    /// that ever changed its mind — the reason the predicate is not "overlapping
    /// validity, different content".
    #[test]
    fn a_later_claim_supersedes_and_is_not_equivocation() {
        let a = row("id-a", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let b = row("id-b", "peer-1", "agent-x", claim(DIM, T1, 0.1));
        assert_eq!(classify_pair(&a, &b), PairVerdict::Superseded);
        let report = detect(&[&a, &b]);
        assert!(
            report.contradictions.is_empty(),
            "a revision at a later signed instant was reported as equivocation: {:?}",
            report.contradictions
        );
        assert_eq!(report.superseded, 1);
    }

    /// Byte-identical claims are one statement recorded twice (a replicated
    /// duplicate, or the coalescing working). Two rows is not two claims.
    #[test]
    fn identical_content_is_one_statement_not_a_contradiction() {
        let env = claim(DIM, T0, 0.9);
        let a = row("id-a", "peer-1", "agent-x", env.clone());
        let b = row("id-b", "peer-1", "agent-x", env);
        assert_eq!(classify_pair(&a, &b), PairVerdict::SameStatement);
        let report = detect(&[&a, &b]);
        assert!(
            report.contradictions.is_empty(),
            "the same signed statement stored twice was reported as a contradiction"
        );
        assert_eq!(report.same_statement, 1);
    }

    /// Without a signed instant a pair can be neither ordered nor shown
    /// simultaneous. It must be COUNTED, not silently treated as agreement —
    /// the difference between "we checked and they agree" and "we could not
    /// check" is the whole reason `PairVerdict` has four arms.
    #[test]
    fn an_envelope_with_no_signed_instant_is_counted_not_cleared() {
        let a = row(
            "id-a",
            "peer-1",
            "agent-x",
            serde_json::json!({ (paths::DIMENSION): DIM, "rating": 0.9 }),
        );
        let b = row(
            "id-b",
            "peer-1",
            "agent-x",
            serde_json::json!({ (paths::DIMENSION): DIM, "rating": 0.1 }),
        );
        assert_eq!(classify_pair(&a, &b), PairVerdict::NoSignedInstant);
        let report = detect(&[&a, &b]);
        assert!(report.contradictions.is_empty());
        assert_eq!(
            report.no_signed_instant, 1,
            "an uncomparable pair must be reported as uncomparable, not folded into the \
             healthy counts"
        );
    }

    /// Different attesters saying different things is the ordinary state of a
    /// federation — two independent chains, resolved by consumer policy. Only a
    /// SINGLE key contradicting itself is non-repudiable.
    #[test]
    fn two_different_keys_disagreeing_is_not_equivocation() {
        let a = row("id-a", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let b = row("id-b", "peer-2", "agent-x", claim(DIM, T0, 0.1));
        let report = detect(&[&a, &b]);
        assert!(
            report.contradictions.is_empty(),
            "two DIFFERENT keys disagreeing was reported as one key equivocating: {:?}",
            report.contradictions
        );
        assert_eq!(
            report.pairs_compared, 0,
            "rows from different attesters are not one coordinate and must not be paired"
        );
    }

    /// One key rating two DIFFERENT subjects differently, and one subject on two
    /// DIFFERENT dimensions, are both ordinary. The coordinate is all three
    /// fields; dropping any one of them manufactures accusations.
    #[test]
    fn the_coordinate_is_attester_and_subject_and_dimension() {
        let a = row("id-a", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let other_subject = row("id-b", "peer-1", "agent-y", claim(DIM, T0, 0.1));
        let other_dim = row(
            "id-c",
            "peer-1",
            "agent-x",
            claim("moderation:tone:v1", T0, 0.1),
        );
        let report = detect(&[&a, &other_subject, &other_dim]);
        assert!(
            report.contradictions.is_empty(),
            "different subjects / different dimensions were paired as one claim: {:?}",
            report.contradictions
        );
    }

    /// The `event_id` is a function of the sorted pair and NOTHING else — it is
    /// the idempotency key persist dedupes on, and this pass re-derives it every
    /// cadence forever.
    #[test]
    fn the_event_id_is_deterministic_over_the_sorted_pair() {
        let a = row("id-zzz", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let b = row("id-aaa", "peer-1", "agent-x", claim(DIM, T0, 0.1));
        let forward = detect(&[&a, &b]);
        let reverse = detect(&[&b, &a]);
        assert_eq!(forward.contradictions.len(), 1);
        assert_eq!(reverse.contradictions.len(), 1);
        assert_eq!(
            forward.contradictions[0].event_id(),
            reverse.contradictions[0].event_id(),
            "the id changed with the order the rows were read. persist dedupes on it, so an \
             order-dependent id makes every re-scan a NEW hard_case row."
        );
        assert_eq!(
            forward.contradictions[0].event_id(),
            format!("{HARD_CASE_KIND}:id-aaa:id-zzz"),
            "the id must be the kind plus the two attestation_ids in sorted order"
        );
        // Twice at two instants: the observation time is a column, never key
        // material.
        let t = chrono::Utc::now();
        let c = &forward.contradictions[0];
        assert_eq!(
            c.hard_case(t).event_id,
            c.hard_case(t + chrono::Duration::hours(3)).event_id,
            "the observation instant leaked into the idempotency key — every pass would \
             record a fresh row for one standing condition"
        );
    }

    /// Three mutually contradictory rows are three pairwise proofs, each
    /// independently verifiable. Reporting one "the contradiction" would throw
    /// away evidence.
    #[test]
    fn three_conflicting_rows_yield_every_pair() {
        let a = row("id-a", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let b = row("id-b", "peer-1", "agent-x", claim(DIM, T0, 0.5));
        let c = row("id-c", "peer-1", "agent-x", claim(DIM, T0, 0.1));
        let report = detect(&[&a, &b, &c]);
        assert_eq!(report.contradictions.len(), 3);
        let ids: std::collections::BTreeSet<_> =
            report.contradictions.iter().map(|c| c.event_id()).collect();
        assert_eq!(
            ids.len(),
            3,
            "each pair is its own proof and its own event_id"
        );
    }

    /// **The read must stay a filtered query** (CIRISServer#343).
    ///
    /// `list_attestations_by(k)` / `list_attestations_for(k)` read as narrow
    /// queries and are not — the narrowing is the caller's `.filter()`, and the
    /// measured instance of that shape was a 152-second boot phase (9,824 rows
    /// scanned fifteen times to read twelve values). Every behavioural test here
    /// would still pass if this pass switched to one of them: the rows come back
    /// either way. Only the source can say which read produced them.
    ///
    /// Asserted over the CODE, with comment lines stripped — a gate that a
    /// mention in prose could satisfy is a gate that tests its own docstring.
    #[test]
    fn the_scan_never_loads_every_row() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/equivocation.rs"),
        )
        .expect("readable");
        let code: String = src
            .split("#[cfg(test)]")
            .next()
            .expect("code")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for banned in ["list_attestations_by(", "list_attestations_for("] {
            assert!(
                !code.contains(banned),
                "`{banned}` is back in the scan. It loads every attestation for a key and \
                 narrows in Rust; this pass runs on a timer over a growing corpus. Push the \
                 predicate into `list_attestations`' filter instead."
            );
        }
        assert!(
            code.contains("filter.valid_at = Some("),
            "the live-validity predicate left the query. Without it this scans the whole \
             corpus and reports expired rows as live contradictions."
        );
    }

    /// The `hard_case` must carry BOTH rows: the pair IS the proof, and a case
    /// naming one row is an accusation rather than evidence.
    #[test]
    fn the_hard_case_names_both_rows_as_evidence() {
        let a = row("id-a", "peer-1", "agent-x", claim(DIM, T0, 0.9));
        let b = row("id-b", "peer-1", "agent-x", claim(DIM, T0, 0.1));
        let report = detect(&[&a, &b]);
        let ev = report.contradictions[0].hard_case(chrono::Utc::now());
        assert_eq!(ev.kind, HARD_CASE_KIND);
        assert_eq!(ev.target_key_id.as_deref(), Some("peer-1"));
        assert_eq!(ev.subject_key_id.as_deref(), Some("agent-x"));
        let ids = ev.detail["attestation_ids"]
            .as_array()
            .expect("attestation_ids array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec!["id-a", "id-b"],
            "both rows must be named in the evidence"
        );
        let hashes = ev.detail["content_hashes"]
            .as_array()
            .expect("content_hashes array");
        assert_eq!(hashes.len(), 2);
        assert_ne!(
            hashes[0], hashes[1],
            "the two hashes are the verifiable half of the proof; equal hashes would mean \
             the pair was never a contradiction"
        );
    }
}
