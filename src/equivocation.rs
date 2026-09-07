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
//! and their CLAIM differs — see [`claim_view`] for what "the claim" is, and why
//! `original_content_hash` stopped being able to answer that. Nothing weaker
//! works than this predicate itself, though: "same
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
//! ## Except one fold, and why it is not the same thing (CIRISServer#355)
//!
//! A row whose attester's statements are revoked *from an instant* covering it
//! (`revoked_after`, [`crate::key_standing`]) is dropped before comparison and
//! counted as [`DetectorReport::suspect_rows`].
//!
//! That is not the retraction fold refused above. A `withdraws` is the attester
//! saying "ignore what I said" — accepting it would let an equivocator retire
//! its own proof, which is precisely the silent reconciliation N4 forbids. A
//! revocation is a *third party with revocation authority* saying "this key's
//! word stopped counting at T", and refusing to honour it would make this
//! detector build the attack it exists to expose: steal a key, sign two
//! contradictory rows at one instant, and the victim equivocates on every node
//! holding both. The bound is the instrument that says the thief's rows are not
//! the victim's statements. Retraction is self-serving; revocation is not.
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
//!
//! ## How a pass reads the corpus (0.5.200, CIRISServer#553)
//!
//! Until 0.5.199 a pass collected up to `max_rows` full rows — each carrying a
//! parsed `serde_json::Value` envelope averaging 10 KiB on the canonical — into
//! one `Vec<Attestation>` and compared them: ~54 MiB of raw envelopes and a few
//! hundred MB of transient heap every fifteen minutes, freed into glibc's free
//! lists and never returned (CIRISServer#552). And because every pass restarted
//! its cursor from the beginning and stopped at `max_rows`, it scanned the SAME
//! lowest-id rows forever and never saw the rest of the tier.
//!
//! Now a pass **streams one page at a time** and keeps only a [`RowClaim`] per
//! row — the coordinate, the claim digest, the content hash, the signed instant
//! and the row id, a few hundred bytes — digesting each page off the runtime
//! workers (`spawn_blocking`) and dropping the envelopes before the next page is
//! fetched. The claims accumulate in a [`ClaimIndex`] that lives for the life of
//! the detector task; each pass walks a `max_rows` window from a **persisted
//! cursor**, so consecutive passes cover the whole tier and keep covering it,
//! and a wrap evicts the claims of rows the cycle no longer saw. A candidate
//! contradiction found in the index is **verified before it is recorded**: both
//! rows are fetched by id and must still be live federation-tier rows, so a
//! stale claim can never accuse a key on the strength of a row that is gone.
//!
//! The pass also no longer fires in the same second as the trace-plane watch or
//! on edge's 300 s announce grid ([`PHASE_OFFSET`]), and it says what it cost
//! every time it runs (one INFO line per pass), because a silent-when-fine pass
//! is how a 23 s boot phase and a fifteen-minute accept stall hid for days.

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

// The envelope field naming the instant the attester CLAIMS (as opposed to
// `Attestation::asserted_at`, the local write column — see the module doc), and
// the reader for it, now live in `crate::key_standing`. They started here, and
// CIRISServer#355 needed the same instant on four more read paths: a second
// spelling of the key is how two consumers end up asking different questions
// about one field, which is the defect class this module was built to detect.
use crate::key_standing::{self, signed_instant, HeldRevocations};

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
    /// Rows per read page — and the size of the transient the pass holds at
    /// once, since a page's envelopes are dropped before the next is fetched.
    pub page: i64,
    /// Rows scanned per PASS. The pass resumes from where the previous one
    /// stopped and wraps at the end of the tier, so this bounds the cost of one
    /// pass, not the coverage of the detector; a pass that stops here reports
    /// `truncated` (more of the tier remains for the next pass), never silently
    /// short.
    pub max_rows: usize,
}

/// How far past its own cadence the detector's first pass fires, and therefore
/// the phase its ticks keep for the life of the process.
///
/// Two things must not share this pass's second (CIRISServer#553): the
/// trace-plane watch, whose ticks sit at [`crate::trace_plane_watch::PHASE_OFFSET`]
/// past boot, and edge's default 300 s announce grid, which `900 = 3 × 300`
/// would otherwise land on every time. 150 s is half an announce interval, so
/// the pass is as far from an announce as it can be; the test
/// `the_two_timers_do_not_share_a_second` keeps the pair apart.
pub const PHASE_OFFSET: Duration = Duration::from_secs(150);

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
    // The same CLAIM is the same statement however it is dated or whichever row
    // carried it — checked first so a duplicate never has to survive the instant
    // logic.
    //
    // This compared `original_content_hash`, on the reasoning that identical
    // signed bytes are identical statements. True, and no longer sufficient in
    // the direction that matters: since CIRISPersist#643 those bytes include the
    // row's own `attestation_id`, so two byte-identical CLAIMS hash differently
    // and this arm stopped firing entirely. A peer restating itself, or a
    // replicated copy of one row, then fell through to the instant logic and was
    // classified a CONTRADICTION — the detector accusing an honest peer of
    // equivocating, on a mesh with no one to appeal to.
    //
    // `claim_digest` compares the envelope MINUS the row's bookkeeping, through
    // the substrate's own canonicalizer so two nodes agree on the bytes. The
    // fallback to the stored hash keeps the old behaviour for an envelope that
    // will not canonicalize rather than silently calling such a pair distinct.
    //
    // The predicate itself lives on the CLAIM (`classify_claims`): the streaming
    // pass never holds two rows at once, so the rows' reduction is what gets
    // compared, and this row-shaped door is that same comparison spelled over
    // rows — one rule, one implementation.
    classify_claims(&RowClaim::of(a), &RowClaim::of(b))
}

/// The coordinate two rows must share before they can contradict:
/// `(attester, subject, dimension)`. The signed instant is compared inside the
/// group, not keyed on, because a differing instant is a verdict
/// ([`PairVerdict::Superseded`]) and not a different group.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClaimCoordinate {
    pub attesting_key_id: String,
    pub subject_key_id: String,
    pub dimension: String,
}

/// Everything the predicate needs from one row, and nothing else — a few
/// hundred bytes against a parsed envelope's tens of KiB. This is what the
/// [`ClaimIndex`] holds between passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowClaim {
    pub attestation_id: String,
    /// `original_content_hash` — the fallback comparison for an envelope that
    /// will not canonicalize (see `classify_claims`).
    pub content_hash: String,
    /// [`claim_digest`] of the envelope, `None` when it would not canonicalize.
    pub claim_digest: Option<String>,
    /// The SIGNED assertion instant (module doc: "which `asserted_at`").
    pub signed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The pass that last saw this row live. Eviction on wrap reads it.
    pub seen_pass: u64,
}

impl RowClaim {
    /// Reduce one row. Does the canonicalization — this is the CPU of a pass,
    /// and the streaming scan runs it off the runtime workers.
    #[must_use]
    pub fn of(a: &Attestation) -> Self {
        RowClaim {
            attestation_id: a.attestation_id.clone(),
            content_hash: a.original_content_hash.clone(),
            claim_digest: claim_digest(&a.attestation_envelope),
            signed_at: signed_instant(&a.attestation_envelope),
            seen_pass: 0,
        }
    }
}

/// The coordinate a row claims at, or `None` for an undimensioned row (a
/// structural composer): a statement ABOUT another row, whose grouping key
/// would be a different one entirely.
#[must_use]
pub fn coordinate_of(a: &Attestation) -> Option<ClaimCoordinate> {
    dimension_of(a).map(|dimension| ClaimCoordinate {
        attesting_key_id: a.attesting_key_id.clone(),
        subject_key_id: a.attested_key_id.clone(),
        dimension,
    })
}

/// THE predicate, over two claims that already share a [`ClaimCoordinate`].
///
/// Same digest (or, for an envelope that would not canonicalize, the same
/// stored hash) is one statement however it is dated. Otherwise the two signed
/// instants decide: different instants order the pair (a revision); equal
/// instants with different content is the CC 6.1.1 N4 case; a missing instant
/// on either side is counted as unmeasurable, never cleared.
#[must_use]
pub fn classify_claims(a: &RowClaim, b: &RowClaim) -> PairVerdict {
    let same_claim = match (&a.claim_digest, &b.claim_digest) {
        (Some(da), Some(db)) => da == db,
        _ => a.content_hash == b.content_hash,
    };
    if same_claim {
        return PairVerdict::SameStatement;
    }
    let (Some(ta), Some(tb)) = (a.signed_at, b.signed_at) else {
        return PairVerdict::NoSignedInstant;
    };
    if ta == tb {
        PairVerdict::Contradiction
    } else {
        PairVerdict::Superseded
    }
}

/// A contradiction found among CLAIMS: the coordinate, the shared signed
/// instant, and the two row ids (sorted). Not yet evidence — the pass turns it
/// into a [`Contradiction`] only after fetching both rows and confirming they
/// are still live (`verify_candidate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimContradiction {
    pub coordinate: ClaimCoordinate,
    pub signed_at: chrono::DateTime<chrono::Utc>,
    /// Sorted, so a candidate's identity never depends on read order.
    pub attestation_ids: (String, String),
}

/// What comparing a set of claims found — the counts of [`DetectorReport`]
/// without the rows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimVerdicts {
    pub pairs_compared: usize,
    pub same_statement: usize,
    pub superseded: usize,
    pub no_signed_instant: usize,
    pub candidates: Vec<ClaimContradiction>,
}

/// Compare every pair of claims within each coordinate group. Pure.
/// Quadratic WITHIN a group only; group sizes are small by construction (one
/// live row per coalescing bucket per coordinate).
#[must_use]
pub fn detect_claims<'a, I>(groups: I) -> ClaimVerdicts
where
    I: IntoIterator<Item = (&'a ClaimCoordinate, &'a [RowClaim])>,
{
    let mut out = ClaimVerdicts::default();
    for (coord, group) in groups {
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let (a, b) = (&group[i], &group[j]);
                out.pairs_compared += 1;
                match classify_claims(a, b) {
                    PairVerdict::SameStatement => out.same_statement += 1,
                    PairVerdict::Superseded => out.superseded += 1,
                    PairVerdict::NoSignedInstant => out.no_signed_instant += 1,
                    PairVerdict::Contradiction => {
                        let at = a
                            .signed_at
                            .expect("classify_claims returns Contradiction only when both parse");
                        let (lo, hi) = if a.attestation_id <= b.attestation_id {
                            (a, b)
                        } else {
                            (b, a)
                        };
                        out.candidates.push(ClaimContradiction {
                            coordinate: coord.clone(),
                            signed_at: at,
                            attestation_ids: (lo.attestation_id.clone(), hi.attestation_id.clone()),
                        });
                    }
                }
            }
        }
    }
    out
}

/// The claims this detector holds between passes, grouped by coordinate.
///
/// One entry per live row id; an upsert replaces a row's claim (a re-recorded
/// row lands in the same slot), and [`ClaimIndex::evict_unseen_since`] drops
/// the rows a full cycle of passes no longer produced — expired, withdrawn,
/// evicted by retention. Bounded by the size of the live federation tier at a
/// few hundred bytes per row.
#[derive(Debug, Default)]
pub struct ClaimIndex {
    groups: std::collections::BTreeMap<ClaimCoordinate, Vec<RowClaim>>,
    rows: usize,
}

impl ClaimIndex {
    /// Insert or replace one row's claim.
    pub fn upsert(&mut self, coord: ClaimCoordinate, claim: RowClaim) {
        let group = self.groups.entry(coord).or_default();
        if let Some(slot) = group
            .iter_mut()
            .find(|c| c.attestation_id == claim.attestation_id)
        {
            *slot = claim;
        } else {
            group.push(claim);
            self.rows += 1;
        }
    }

    /// Drop every claim last seen BEFORE `pass` — called once per wrap, with
    /// the pass number the finished cycle started at, so a row the cycle did
    /// not re-produce leaves the index. Returns how many left.
    pub fn evict_unseen_since(&mut self, pass: u64) -> usize {
        let mut evicted = 0;
        self.groups.retain(|_, group| {
            let before = group.len();
            group.retain(|c| c.seen_pass >= pass);
            evicted += before - group.len();
            !group.is_empty()
        });
        self.rows -= evicted;
        evicted
    }

    /// Live row claims held.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Coordinates held.
    #[must_use]
    pub fn coordinates(&self) -> usize {
        self.groups.len()
    }

    /// Compare everything held.
    #[must_use]
    pub fn verdicts(&self) -> ClaimVerdicts {
        detect_claims(self.groups.iter().map(|(k, v)| (k, v.as_slice())))
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

/// A stable digest of [`claim_view`] — the replacement for comparing
/// `original_content_hash`, which now covers the row's identity and so differs
/// on every pair by construction.
///
/// Canonicalized through the SAME producer gate the substrate signs with, so two
/// nodes computing this over the same claim get the same bytes; a local
/// `to_string()` would make the answer depend on serde's map ordering.
fn claim_digest(envelope: &serde_json::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(
        &crate::attest::claim_view(envelope),
    )
    .ok()?;
    Some(hex::encode(Sha256::digest(&canonical)))
}

/// Top-level CLAIM keys whose values differ (including keys present in only
/// one). Sorted, so the evidence reads the same on every node.
fn differing_fields(a: &serde_json::Value, b: &serde_json::Value) -> Vec<String> {
    let (a, b) = (crate::attest::claim_view(a), crate::attest::claim_view(b));
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
    /// CIRISServer#355 — live rows this pass DROPPED before comparing because
    /// a revocation this node holds covers the instant their attester signed
    /// for (`revoked_after`). Counted, never silent: a pass that compared
    /// fewer rows than the corpus holds must say so, or `rows_scanned` starts
    /// meaning two things.
    pub suspect_rows: usize,
    /// The contradictions, in a stable order.
    pub contradictions: Vec<Contradiction>,
    /// The `max_rows` window ended before the tier did: this pass did NOT see
    /// the whole live tier, its zero (or its count) is a floor, and the NEXT
    /// pass continues from where this one stopped.
    pub truncated: bool,
    /// Pages read this pass.
    pub pages: usize,
    /// This pass continued from a cursor left by the previous one.
    pub resumed: bool,
    /// This pass reached the end of the tier and the next starts over.
    pub wrapped: bool,
    /// Candidates found in the index whose rows were no longer both live when
    /// fetched for verification — counted, never recorded.
    pub candidates_unverified: usize,
    /// Row claims held in the index after this pass (0 for a rowset-only
    /// [`detect`]).
    pub index_rows: usize,
    /// Coordinates held in the index after this pass.
    pub index_coordinates: usize,
    /// Wall time reading pages.
    pub read_ms: u64,
    /// Wall time digesting rows (off the runtime workers).
    pub digest_ms: u64,
    /// Wall time of the whole pass.
    pub elapsed_ms: u64,
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
    let mut index = ClaimIndex::default();
    let mut by_id: std::collections::BTreeMap<&str, &Attestation> = Default::default();
    for r in rows {
        by_id.insert(r.attestation_id.as_str(), r);
        let Some(coord) = coordinate_of(r) else {
            continue;
        };
        index.upsert(coord, RowClaim::of(r));
    }
    let verdicts = index.verdicts();
    let mut report = DetectorReport {
        rows_scanned: rows.len(),
        pairs_compared: verdicts.pairs_compared,
        same_statement: verdicts.same_statement,
        superseded: verdicts.superseded,
        no_signed_instant: verdicts.no_signed_instant,
        ..Default::default()
    };
    for c in verdicts.candidates {
        // Both rows are in hand here; the streaming pass fetches them instead.
        let (Some(a), Some(b)) = (
            by_id.get(c.attestation_ids.0.as_str()),
            by_id.get(c.attestation_ids.1.as_str()),
        ) else {
            report.candidates_unverified += 1;
            continue;
        };
        report.contradictions.push(Contradiction::new(
            a,
            b,
            c.coordinate.dimension,
            c.signed_at,
        ));
    }
    report
}

/// Per-detector state that outlives a pass: where the next pass resumes, the
/// pass counter, and the claims held so far.
#[derive(Debug, Default)]
pub struct ScanState {
    cursor: Option<ciris_persist::ceg::AttestationCursor>,
    pass: u64,
    /// The pass number the current walk of the tier started at. On wrap, every
    /// claim not seen since it leaves the index.
    cycle_started_at: u64,
    index: ClaimIndex,
}

impl ScanState {
    /// Claims held.
    #[must_use]
    pub fn index(&self) -> &ClaimIndex {
        &self.index
    }
}

/// One page's reduction, computed off the runtime workers.
struct DigestedPage {
    claims: Vec<(ClaimCoordinate, RowClaim)>,
    suspect_rows: usize,
    undimensioned: usize,
}

/// Stream one `max_rows` window of live federation-tier rows from `state`'s
/// cursor into `state`'s index, page by page — the filter PUSHED INTO THE
/// QUERY (CIRISServer#343), one page of envelopes in memory at a time.
///
/// Two narrowings, and they are not the same kind of thing:
///
/// - `valid_at = now` is a REAL pushdown (`asserted_at <= now AND (expires_at IS
///   NULL OR expires_at > now)`) and it is also the semantic bound: rows live at
///   one instant all overlap at that instant, which is the "overlapping
///   validity" leg of the predicate.
/// - `tier` is a REAL pushdown as of persist v30.0.0 (CIRISPersist#596 item 2),
///   set EXPLICITLY (`Tier::Federation`, never `None`, whose meaning on this
///   handle is deliberately "no predicate"). A local-tier row was never
///   published to anyone, so it cannot be evidence that a key told two peers
///   different things.
///
/// The scope is the node authenticated AS ITSELF (`build_caller_admission` —
/// the only public path to an admission, so this cannot fabricate reach it does
/// not have). `Unauthenticated` would drop every `self`-scoped row, which is the
/// narrowing-that-reads-as-healthy that cost `graph_config` a nine-test cut.
///
/// CIRISServer#355 / CIRISPersist#570 ask 4: a row whose attester's statements
/// are revoked from an instant covering it is not evidence — it is the attack
/// this detector would otherwise BUILD (steal a key, sign two contradictory
/// rows at one instant, and the victim equivocates on every node holding
/// both). Such rows are dropped per page before digesting and COUNTED
/// (`suspect_rows`), never silently absent.
async fn scan_window(
    engine: &Engine,
    node_key_id: &str,
    cfg: &DetectorConfig,
    state: &mut ScanState,
    report: &mut DetectorReport,
) -> Result<()> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    let admission = ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned())
        .await
        .map_err(|e| anyhow::anyhow!("resolve equivocation-scan caller admission: {e}"))?;
    let scope = CallerScope::Authenticated { admission };
    let now = chrono::Utc::now();
    let pass = state.pass;

    report.resumed = state.cursor.is_some();
    let mut scanned = 0usize;
    loop {
        // `AttestationFilter` is #[non_exhaustive] — build-then-set so a new
        // predicate arrives as a default rather than a compile break.
        let mut filter = AttestationFilter::default();
        filter.valid_at = Some(now);
        filter.tier = Some(ciris_persist::ceg::list::federation::Tier::Federation);
        let t_read = std::time::Instant::now();
        let page = engine
            .list_attestations(filter, state.cursor.take(), cfg.page, scope.clone())
            .await
            .map_err(|e| anyhow::anyhow!("list live attestations: {e}"))?;
        report.read_ms += t_read.elapsed().as_millis() as u64;
        report.pages += 1;
        scanned += page.items.len();
        report.rows_scanned += page.items.len();

        // The in-process re-check is kept as a WITNESS, not as the enforcement:
        // a local-tier row surviving the push-down would mean the axis stopped
        // binding, and this detector must narrow correctly either way.
        debug_assert!(
            page.items
                .iter()
                .all(|a| a.tier == attestation_tier::FEDERATION),
            "AttestationFilter::tier did not bind on list_attestations"
        );

        // Revocation standing for the keys ON THIS PAGE only: the page is the
        // unit of memory, so it is the unit of everything else too.
        let held = HeldRevocations::for_keys(engine, key_standing::attesting_keys(&page.items))
            .await
            .context("equivocation detector: read held revocations")?;

        // Reduce the page OFF the runtime workers: canonicalizing a few hundred
        // 10 KiB envelopes is CPU, and on a two-vCPU node the acceptor was
        // waiting behind it (CIRISServer#553). The envelopes move into the
        // blocking task and are dropped there — they never outlive the page.
        let t_digest = std::time::Instant::now();
        let rows = page.items;
        let digested = tokio::task::spawn_blocking(move || {
            let mut out = DigestedPage {
                claims: Vec::with_capacity(rows.len()),
                suspect_rows: 0,
                undimensioned: 0,
            };
            for a in &rows {
                if a.tier != attestation_tier::FEDERATION {
                    continue;
                }
                if held.suspects(a, now) {
                    key_standing::warn_suspect("equivocation", a, &held.statement_standing(a, now));
                    out.suspect_rows += 1;
                    continue;
                }
                let Some(coord) = coordinate_of(a) else {
                    out.undimensioned += 1;
                    continue;
                };
                let mut claim = RowClaim::of(a);
                claim.seen_pass = pass;
                out.claims.push((coord, claim));
            }
            out
        })
        .await
        .context("equivocation detector: digest page")?;
        report.digest_ms += t_digest.elapsed().as_millis() as u64;
        report.suspect_rows += digested.suspect_rows;
        for (coord, claim) in digested.claims {
            state.index.upsert(coord, claim);
        }

        match page.next_cursor {
            None => {
                // End of the tier: the cycle that started at `cycle_started_at`
                // has now produced every live row once, so anything it did not
                // produce is gone. Evict, and start the next cycle from the top.
                let evicted = state.index.evict_unseen_since(state.cycle_started_at);
                if evicted > 0 {
                    tracing::debug!(
                        evicted,
                        "equivocation detector: index dropped rows the finished cycle no longer produced"
                    );
                }
                state.cycle_started_at = pass + 1;
                state.cursor = None;
                report.wrapped = true;
                report.truncated = false;
                break;
            }
            Some(c) if scanned >= cfg.max_rows => {
                state.cursor = Some(c);
                report.truncated = true;
                break;
            }
            Some(c) => state.cursor = Some(c),
        }
    }
    report.index_rows = state.index.rows();
    report.index_coordinates = state.index.coordinates();
    Ok(())
}

/// Turn an index candidate into evidence — or refuse to. Both rows are fetched
/// by id and must still be live federation-tier rows at `now`; a claim the
/// index kept from an earlier pass may describe a row that has since expired
/// or been withdrawn, and an accusation must rest on rows a third party can
/// fetch and re-verify today.
async fn verify_candidate(
    engine: &Engine,
    c: &ClaimContradiction,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Contradiction>> {
    let dir = engine.federation_directory();
    let live = |a: &Attestation| {
        a.tier == attestation_tier::FEDERATION
            && a.asserted_at <= now
            && a.expires_at.is_none_or(|e| e > now)
    };
    let (a, b) = (
        dir.get_attestation(&c.attestation_ids.0).await?,
        dir.get_attestation(&c.attestation_ids.1).await?,
    );
    Ok(match (a, b) {
        (Some(a), Some(b)) if live(&a) && live(&b) => Some(Contradiction::new(
            &a,
            &b,
            c.coordinate.dimension.clone(),
            c.signed_at,
        )),
        _ => None,
    })
}

/// Run one detection pass against `state` and record a `hard_case` for every
/// contradiction found. The detector task calls this every cadence with the
/// same `state`; [`run_pass`] is the one-shot form.
///
/// Recording is idempotent on [`Contradiction::event_id`], so this re-records
/// the same standing contradictions every cadence and writes nothing new. That
/// is the intended steady state: the condition does not clear, and the pass
/// re-asserting it costs one no-op INSERT.
pub async fn run_pass_with(
    engine: &Engine,
    node_key_id: &str,
    cfg: &DetectorConfig,
    state: &mut ScanState,
) -> Result<DetectorReport> {
    let t0 = std::time::Instant::now();
    state.pass += 1;
    let mut report = DetectorReport::default();
    scan_window(engine, node_key_id, cfg, state, &mut report)
        .await
        .context("equivocation detector: scan window")?;

    let verdicts = state.index.verdicts();
    report.pairs_compared = verdicts.pairs_compared;
    report.same_statement = verdicts.same_statement;
    report.superseded = verdicts.superseded;
    report.no_signed_instant = verdicts.no_signed_instant;

    let now = chrono::Utc::now();
    for c in &verdicts.candidates {
        match verify_candidate(engine, c, now).await {
            Ok(Some(contradiction)) => report.contradictions.push(contradiction),
            Ok(None) => report.candidates_unverified += 1,
            Err(e) => {
                report.candidates_unverified += 1;
                tracing::warn!(
                    error = %e,
                    row_a = %c.attestation_ids.0,
                    row_b = %c.attestation_ids.1,
                    "equivocation detector: could not fetch a candidate pair for verification \
                     (not recorded; the next pass retries)"
                );
            }
        }
    }

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
    report.elapsed_ms = t0.elapsed().as_millis() as u64;

    // ONE line per pass, at INFO, whatever it found. A pass that is silent when
    // fine is a pass whose cost nobody can see (CIRISServer#553).
    tracing::info!(
        pass = state.pass,
        rows = report.rows_scanned,
        pages = report.pages,
        resumed = report.resumed,
        wrapped = report.wrapped,
        truncated = report.truncated,
        index_rows = report.index_rows,
        index_coordinates = report.index_coordinates,
        pairs = report.pairs_compared,
        contradictions = report.contradictions.len(),
        candidates_unverified = report.candidates_unverified,
        suspect_rows = report.suspect_rows,
        no_signed_instant = report.no_signed_instant,
        read_ms = report.read_ms,
        digest_ms = report.digest_ms,
        elapsed_ms = report.elapsed_ms,
        "equivocation pass"
    );
    // WARN, not INFO: a standing contradiction is a claim by one key that no
    // consumer can resolve, and it stays true until someone acts.
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
    Ok(report)
}

/// One deterministic pass from the start of the tier with a fresh index —
/// the form a test drives without the timer. For a tier smaller than
/// `max_rows` this is the whole detector; for a larger one it is its first
/// window.
pub async fn run_pass(
    engine: &Engine,
    node_key_id: &str,
    cfg: &DetectorConfig,
) -> Result<DetectorReport> {
    let mut state = ScanState::default();
    run_pass_with(engine, node_key_id, cfg, &mut state).await
}

/// Spawn the periodic detector. Returns the join handle; the task runs for the
/// node's lifetime and keeps one [`ScanState`] across passes.
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
        // First pass one cadence PLUS the phase offset after spawn — the corpus
        // at boot is whatever the last run left, and the offset keeps every
        // later tick off the trace-plane watch's second and off edge's announce
        // grid (`PHASE_OFFSET`). Skip missed ticks rather than burst-catch-up: a
        // delayed pass has nothing to catch up on (the rows are still there).
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + cfg.cadence + PHASE_OFFSET,
            cfg.cadence,
        );
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            cadence_secs = cfg.cadence.as_secs(),
            phase_offset_secs = PHASE_OFFSET.as_secs(),
            rows_per_pass = cfg.max_rows,
            page = cfg.page,
            "same-key equivocation detector started (CC 6.1.1 N4; local detection only — \
             no consensus, no automatic penalty; streams a window per pass from a persisted \
             cursor, CIRISServer#553)"
        );
        let mut state = ScanState::default();
        loop {
            tick.tick().await;
            if let Err(e) = run_pass_with(&engine, &node_key_id, &cfg, &mut state).await {
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
        assert!(
            !code.contains("fn live_rows("),
            "the collect-every-row scan is back. The pass streams one page at a time \
             into the claim index (CIRISServer#553); do not rebuild the Vec<Attestation>."
        );
        assert!(
            code.contains("spawn_blocking("),
            "the page digest left the blocking pool: canonicalizing a page of 10 KiB \
             envelopes on a runtime worker is what starved the acceptor on a two-vCPU node."
        );
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

    /// The row predicate and the claim predicate are ONE predicate: every row
    /// pair classifies identically through either door.
    #[test]
    fn the_row_door_and_the_claim_door_agree() {
        let a = row("a", "k", "s", claim(DIM, T0, 0.1));
        let b = row("b", "k", "s", claim(DIM, T0, 0.9));
        let c = row("c", "k", "s", claim(DIM, T1, 0.9));
        let d = row("d", "k", "s", claim(DIM, T0, 0.1));
        let mut e = row(
            "e",
            "k",
            "s",
            serde_json::json!({(paths::DIMENSION): DIM, "rating": 1.0}),
        );
        e.original_content_hash = "x".to_owned();
        for (x, y) in [(&a, &b), (&b, &c), (&a, &d), (&a, &e), (&e, &c)] {
            assert_eq!(
                classify_pair(x, y),
                classify_claims(&RowClaim::of(x), &RowClaim::of(y)),
                "{} vs {}",
                x.attestation_id,
                y.attestation_id
            );
        }
    }

    /// An upsert replaces a row's claim in place, and a wrap evicts what the
    /// finished cycle did not re-produce — the index tracks the live tier, it
    /// does not accumulate its history.
    #[test]
    fn the_index_replaces_by_id_and_evicts_the_unseen() {
        let mut ix = ClaimIndex::default();
        let coord = coordinate_of(&row("a", "k", "s", claim(DIM, T0, 0.1))).unwrap();
        let mut c1 = RowClaim::of(&row("a", "k", "s", claim(DIM, T0, 0.1)));
        c1.seen_pass = 1;
        let mut c2 = RowClaim::of(&row("b", "k", "s", claim(DIM, T0, 0.9)));
        c2.seen_pass = 1;
        ix.upsert(coord.clone(), c1.clone());
        ix.upsert(coord.clone(), c2);
        assert_eq!((ix.rows(), ix.coordinates()), (2, 1));
        assert_eq!(ix.verdicts().candidates.len(), 1, "a and b contradict");
        // Pass 2 re-sees `a` only (with a new digest); `b` is gone from the tier.
        let mut c1b = RowClaim::of(&row("a", "k", "s", claim(DIM, T0, 0.5)));
        c1b.seen_pass = 2;
        ix.upsert(coord.clone(), c1b);
        assert_eq!(ix.rows(), 2, "upsert replaced, did not add");
        assert_eq!(ix.evict_unseen_since(2), 1, "b left");
        assert_eq!((ix.rows(), ix.coordinates()), (1, 1));
        assert!(
            ix.verdicts().candidates.is_empty(),
            "one row cannot contradict itself"
        );
        assert_eq!(
            ix.evict_unseen_since(3),
            1,
            "and a wrap that saw nothing empties it"
        );
        assert_eq!((ix.rows(), ix.coordinates()), (0, 0));
    }

    /// The two 900 s timers must not share a second, and neither may sit on
    /// edge's 300 s announce grid (CIRISServer#553). 300 is edge's default
    /// `announce_interval`, stated here as the grid this repo phases against —
    /// if edge changes it, this test is the reminder to re-phase.
    #[test]
    fn the_two_timers_do_not_share_a_second() {
        const ANNOUNCE_GRID_SECS: u64 = 300;
        let cadence = DetectorConfig::default().cadence.as_secs();
        let here = PHASE_OFFSET.as_secs();
        let watch = crate::trace_plane_watch::PHASE_OFFSET.as_secs();
        assert_eq!(
            cadence,
            crate::trace_plane_watch::WATCH_CADENCE.as_secs(),
            "same cadence, so phase is everything"
        );
        assert_ne!(
            here % cadence,
            watch % cadence,
            "the two timers share a second"
        );
        assert!(
            here % ANNOUNCE_GRID_SECS != 0,
            "the detector sits on the announce grid"
        );
        assert!(
            watch % ANNOUNCE_GRID_SECS != 0,
            "the watch sits on the announce grid"
        );
        assert!(
            cadence % ANNOUNCE_GRID_SECS == 0,
            "if this stops being true, the offsets can be revisited"
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
