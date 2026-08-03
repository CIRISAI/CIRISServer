//! **`revoked_after` enforcement** — the consumer-side read of persist's
//! time-bounded de-admission (CIRISServer#355 / CIRISPersist#570 ask 4).
//!
//! ## What the field is, and why this module exists
//!
//! persist v25.1.0 put a history bound on the revocation plane. A revocation
//! carrying `revoked_after: Tuesday 09:00` says *this key's statements stand up
//! to that instant and no further* — so a key compromised on Tuesday no longer
//! costs every honest signature it made on Monday. The bound is signed
//! (`check_revocation_bound` refuses a typed bound the envelope does not
//! mirror, to the second), replicated, and re-derivable.
//!
//! It was also **read by nothing in this repo**. persist says so itself, in the
//! doc on `resolve_key_statement_standing`: *"the enforcement point is the
//! consumer's read"* — ours. A wire field that announces "claims after Tuesday
//! are revoked" while this node admits them anyway is worse than an absent
//! capability: an absent one is honest, and a producer setting this one in good
//! faith gets the reassurance without the enforcement.
//!
//! This module is the one place the server asks the question, and every read
//! path that resolves whether a key's claim stands routes through it.
//!
//! ## The comparison is against the SIGNED instant
//!
//! [`Attestation::asserted_at`] — the row column — is `Utc::now()` at write
//! time. It is not covered by `original_content_hash` and no ingest gate checks
//! it. The instant the attester actually claimed lives inside the signed
//! envelope, and the two disagree **in practice**, not just in theory: the
//! capacity scorer floors the envelope instant to an hour bucket while the
//! column keeps wall clock. A `revoked_after` check keyed on the column would
//! compare against a number the attester never signed — and, worse, would find
//! nothing and look healthy doing it (CIRISServer#350, the same lesson).
//!
//! So [`signed_instant`] reads `attestation_envelope["asserted_at"]`, and it is
//! the ONLY spelling of that key in the server ([`equivocation`] shares it —
//! that module found the axis first, and a second copy of the key is how the
//! two would drift apart).
//!
//! [`equivocation`]: crate::equivocation
//!
//! ## An envelope with no signed instant is dated at the worst case
//!
//! [`UNDATED_STATEMENT_AT`]. A row whose envelope declares no `asserted_at`
//! cannot be placed relative to a bound, and the fail-open reading — "cannot
//! prove it is after the bound, so admit it" — hands an attacker the bypass for
//! free: omit the field, keep the signature, keep standing. Dating an
//! unreadable statement at the end of time makes every covering revocation
//! cover it, so an undated row from a **revoked** key is suspect and an undated
//! row from a key with no revocations still [`Stands`] (the fold considers
//! nothing, so nothing covers it). The common case is untouched; only the
//! unmeasurable one fails closed.
//!
//! [`Stands`]: ciris_persist::federation::KeyStatementStanding::Stands
//!
//! ## The temporal rule itself is persist's, called and never copied
//!
//! [`HeldRevocations::fold`] delegates to persist's
//! [`fold_key_statement_standing`] — the pure `(key, revocations, statement_at,
//! now)` function that decides which revocations are in effect, which cover the
//! statement, and how bounded and unbounded ones compose (restrictions
//! compose, leniencies do not). Reimplementing `statement_at > revoked_after`
//! here would be a second copy of a temporal rule, which is the drift shape
//! CIRISServer#283 finding 3 named. What this module adds is the two things
//! persist cannot do from inside the substrate: **hoisting** the revocation
//! read out of a per-row loop, and **dating** a row from its signed envelope.
//!
//! ## Which read paths honour the bound — the honest list
//!
//! Stated rather than implied, because partial adoption is the dangerous
//! outcome: if some paths honour it and some do not, the mesh answers
//! differently about one key depending which question you ask, and the ones
//! that do not are where an attacker aims.
//!
//! **Honour it** (all five landed together, CIRISServer#355):
//!
//! | Path | What a suspect statement does |
//! |---|---|
//! | [`compose_policy`](crate::compose_policy) — the CC 4.4 composed verdict | refused, as `RefusalReason::KeyStatementSuspect` |
//! | [`scorer`](crate::scorer) — the `capacity:*` standing read | the row does not count as a standing assertion |
//! | [`auth::ownership`](crate::auth::ownership) — owner-binding resolution | the node reads as unowned (fail closed) |
//! | [`equivocation`](crate::equivocation) — the live-row evidence read | the row is not evidence, and is counted |
//! | [`graph_config`](crate::graph_config) — the config plane | the config row reads as absent |
//!
//! **Do not honour it, deliberately** — persist draws three of these lines
//! itself and they are inherited, not re-decided:
//!
//! - **Signature verification** ([`crate::sign_object`], the accord threshold
//!   verifies). These answer a mathematical question: do these bytes carry this
//!   key's signature. A compromised key's signature still verifies — that is
//!   what makes compromise dangerous. Wiring admission into the verifier fuses
//!   integrity with admission, one name on two axes.
//! - **Replication cursors and `put_attestation`.** Dropping a revoked key's
//!   history on the wire would impose this node's revocation policy on every
//!   subscriber; refusing to ingest it would destroy the evidence needed to
//!   adjudicate the compromise. Store everything, adjudicate at the read.
//! - **The scoped-consent fold** (`resolve_scoped_consent`) and the roster
//!   reads (`list_keys_by_identity_type`, `active_members`, `owner_of`'s own
//!   internals). These are not exemptions on the merits — they are **shape
//!   gaps**: `resolve_scoped_consent` returns a bare `ConsentState` enum with
//!   no row and no instant, and the roster readers return `KeyRecord`s that
//!   carry no statement timestamp at all. Honouring the bound there means
//!   either persist surfaces the winning row, or the server re-implements
//!   persist's fold — and the second is the drift shape again. Filed as such
//!   rather than papered over.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ciris_persist::federation::register::fold_key_statement_standing;
use ciris_persist::federation::{
    Attestation, Error as FederationError, KeyStatementFold, Revocation,
};
use ciris_persist::prelude::Engine;

/// The envelope field naming the instant the attester CLAIMS, as opposed to
/// [`Attestation::asserted_at`], the local write column.
///
/// Not a persist-owned key — `federation::envelope::paths` has no constant for
/// it, so this is the server's ONE spelling of a producer convention
/// (`scorer`, `peer`, `graph_config` and `auth::ownership` all emit it) rather
/// than a mirror of someone else's vocabulary. Every consumer of the signed
/// instant reads it through [`signed_instant`].
pub const ENVELOPE_ASSERTED_AT: &str = "asserted_at";

/// The instant a statement carrying no readable signed `asserted_at` is dated
/// at: **the end of time**, so every revocation that covers anything covers it.
///
/// Fail-closed by construction — see the module doc. This is a policy constant,
/// not a clock value, and it is named so the choice is visible at each call
/// site rather than hidden behind an `unwrap_or_default()`.
pub const UNDATED_STATEMENT_AT: DateTime<Utc> = DateTime::<Utc>::MAX_UTC;

/// The signed assertion instant an envelope claims, if it declares a readable
/// one.
///
/// `None` means *unmeasurable*, never *now* and never *epoch*: the caller
/// decides what an undated statement is worth, and every caller in this repo
/// decides [`UNDATED_STATEMENT_AT`].
#[must_use]
pub fn signed_instant(envelope: &serde_json::Value) -> Option<DateTime<Utc>> {
    envelope
        .get(ENVELOPE_ASSERTED_AT)
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

/// The distinct attesting keys of a corpus, in a stable order — the exact key
/// set [`HeldRevocations::for_keys`] must be given so every row in that corpus
/// can be folded.
///
/// Deriving the key set from the SAME slice that will be folded is what keeps
/// the hoisted read complete; a hand-written key list is how a row ends up
/// folded against revocations that were never fetched.
#[must_use]
pub fn attesting_keys(corpus: &[Attestation]) -> BTreeSet<String> {
    corpus
        .iter()
        .map(|a| a.attesting_key_id.clone())
        .collect::<BTreeSet<String>>()
}

/// The revocation rows this node holds against a fixed set of keys, read ONCE.
///
/// # Why a hoisted set rather than a per-row call
///
/// persist exposes `Engine::resolve_key_statement_standing(key, at, now)`,
/// which fetches and folds in one call. That is the right shape for a single
/// question (and [`auth::ownership`](crate::auth::ownership) uses this type for
/// exactly one key). It is the wrong shape inside a corpus loop: a config pass
/// over twelve rows would issue twelve `revocations_for` reads, which is the
/// N+1 that cost `graph_config` a 152-second boot phase (CIRISServer#343). The
/// revocation set is a property of the KEY, not of the row, so it is fetched
/// per distinct key and the per-row work is the pure fold.
///
/// # Fail-closed on an unfetched key? No — and deliberately
///
/// A key with no entry folds against an empty revocation set and therefore
/// [`Stands`](ciris_persist::federation::KeyStatementStanding::Stands). That has
/// to be the default: a node
/// holding no revocations must compose normally, and [`Default`] is what the
/// pure `Composer::compose` sees when a caller supplies no substrate. The
/// protection against a caller that holds revocations and forgets to pass them
/// is structural — [`attesting_keys`] derives the key set from the corpus — not
/// a runtime guess.
#[derive(Debug, Clone, Default)]
pub struct HeldRevocations {
    by_key: BTreeMap<String, Vec<Revocation>>,
}

impl HeldRevocations {
    /// Read every revocation this node holds against each of `keys`, one
    /// targeted lookup per DISTINCT key.
    ///
    /// A backend that does not implement the revocation plane
    /// ([`FederationError::Unsupported`]) reads as "holds none" — the same
    /// degradation persist's own `resolve_key_statement_standing` applies, so
    /// an FFI directory capsule does not turn into a hard error. Any other
    /// backend error is propagated: a revocation read that FAILED is not a
    /// revocation read that returned nothing, and collapsing the two is how a
    /// broken substrate starts reading as a clean one.
    ///
    /// # Errors
    /// Propagates a backend failure from `revocations_for`.
    pub async fn for_keys<I>(engine: &Engine, keys: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let dir = engine.federation_directory();
        let mut by_key: BTreeMap<String, Vec<Revocation>> = BTreeMap::new();
        for key in keys {
            if by_key.contains_key(&key) {
                continue;
            }
            let rows = match dir.revocations_for(&key).await {
                Ok(rows) => rows,
                Err(FederationError::Unsupported { .. }) => Vec::new(),
                Err(e) => return Err(anyhow!("revocations_for({key}): {e}")),
            };
            by_key.insert(key, rows);
        }
        Ok(Self { by_key })
    }

    /// Build from already-held rows, keyed by revoked key. For tests and for
    /// callers that fetched the rows for another reason.
    #[must_use]
    pub fn from_map(by_key: BTreeMap<String, Vec<Revocation>>) -> Self {
        Self { by_key }
    }

    /// True when this node holds NO revocation against any of the fetched keys
    /// — the overwhelmingly common case, and the cheap path a caller can use to
    /// skip work that only a revoked key makes necessary.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key.values().all(Vec::is_empty)
    }

    /// What this node's held revocations say about a statement `key_id` made at
    /// `statement_at` — persist's pure fold, called, never re-derived.
    #[must_use]
    pub fn fold(
        &self,
        key_id: &str,
        statement_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> KeyStatementFold {
        const NONE: &[Revocation] = &[];
        let rows = self.by_key.get(key_id).map_or(NONE, Vec::as_slice);
        fold_key_statement_standing(key_id, rows, statement_at, now)
    }

    /// The standing of the statement `att` makes, dated by its SIGNED envelope
    /// instant (or [`UNDATED_STATEMENT_AT`] when the envelope declares none).
    #[must_use]
    pub fn statement_standing(&self, att: &Attestation, now: DateTime<Utc>) -> KeyStatementFold {
        let at = signed_instant(&att.attestation_envelope).unwrap_or(UNDATED_STATEMENT_AT);
        self.fold(&att.attesting_key_id, at, now)
    }

    /// Does a revocation this node holds put `att` in doubt? The one-line form
    /// every read path filters on.
    #[must_use]
    pub fn suspects(&self, att: &Attestation, now: DateTime<Utc>) -> bool {
        self.statement_standing(att, now).standing.is_suspect()
    }
}

/// Log one refused statement at WARN, in one shape, from every path.
///
/// WARN and not DEBUG: this node just declined to believe something a
/// registered key signed. That is never routine, and the operator needs the
/// bound that did it (`covered_by`) to tell an enforced revocation from a
/// misconfigured one.
pub fn warn_suspect(path: &'static str, att: &Attestation, fold: &KeyStatementFold) {
    tracing::warn!(
        read_path = path,
        attesting_key_id = %att.attesting_key_id,
        attestation_id = %att.attestation_id,
        signed_asserted_at = ?signed_instant(&att.attestation_envelope),
        standing = fold.standing.as_str(),
        covered_by = ?fold.covered_by,
        considered = fold.considered,
        "revoked_after: statement NOT admitted — a revocation this node holds covers the \
         instant the attester signed for (CIRISServer#355)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::KeyStatementStanding;

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339")
    }

    fn rev(id: &str, key: &str, effective_at: &str, bound: Option<&str>) -> Revocation {
        Revocation {
            revocation_id: id.into(),
            revoked_key_id: key.into(),
            revoking_key_id: "authority".into(),
            reason: None,
            revoked_at: ts(effective_at),
            effective_at: ts(effective_at),
            revocation_envelope: serde_json::json!({}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "authority".into(),
            scrub_timestamp: ts(effective_at),
            pqc_completed_at: None,
            observed_region: "us".into(),
            revoked_after: bound.map(ts),
            persist_row_hash: String::new(),
        }
    }

    fn att(key: &str, envelope: serde_json::Value) -> Attestation {
        Attestation {
            attestation_id: "att-1".into(),
            attesting_key_id: key.into(),
            attested_key_id: "subject".into(),
            attestation_type: "scores".into(),
            weight: None,
            // Deliberately WRONG relative to the envelope: the row column is
            // `Utc::now()` at write time and a check keyed on it would find
            // nothing. Every test here proves the envelope instant is the one
            // being read.
            asserted_at: ts("2020-01-01T00:00:00Z"),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: key.into(),
            additional_scrubs: Vec::new(),
            scrub_timestamp: ts("2020-01-01T00:00:00Z"),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
        }
    }

    fn held(rows: Vec<Revocation>) -> HeldRevocations {
        let mut m = BTreeMap::new();
        m.insert("compromised".to_owned(), rows);
        HeldRevocations::from_map(m)
    }

    #[test]
    fn a_bound_revocation_keeps_the_key_s_earlier_statements_standing() {
        let h = held(vec![rev(
            "r1",
            "compromised",
            "2026-07-01T00:00:00Z",
            Some("2026-06-10T09:00:00Z"),
        )]);
        let now = ts("2026-08-01T00:00:00Z");

        let monday = att(
            "compromised",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2026-06-09T09:00:00Z" }),
        );
        assert!(
            !h.suspects(&monday, now),
            "a statement made BEFORE the bound survives the revocation"
        );

        let tuesday = att(
            "compromised",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2026-06-11T09:00:00Z" }),
        );
        assert!(
            h.suspects(&tuesday, now),
            "a statement made AFTER the bound does not"
        );
        assert_eq!(
            h.statement_standing(&tuesday, now).standing,
            KeyStatementStanding::SuspectAfterBound
        );
    }

    #[test]
    fn the_boundary_instant_itself_survives() {
        let h = held(vec![rev(
            "r1",
            "compromised",
            "2026-07-01T00:00:00Z",
            Some("2026-06-10T09:00:00Z"),
        )]);
        let at_the_bound = att(
            "compromised",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2026-06-10T09:00:00Z" }),
        );
        assert!(
            !h.suspects(&at_the_bound, ts("2026-08-01T00:00:00Z")),
            "the bound says AFTER this — a signature made exactly at T is not \
             retroactively poisoned"
        );
    }

    #[test]
    fn the_comparison_reads_the_signed_instant_not_the_row_column() {
        // The row column says 2020 (before every bound in this test); the
        // signed envelope says 2026-06-11 (after the bound). A check keyed on
        // the column would report Stands and look healthy doing it — this is
        // the CIRISServer#350 axis, pinned.
        let h = held(vec![rev(
            "r1",
            "compromised",
            "2026-07-01T00:00:00Z",
            Some("2026-06-10T09:00:00Z"),
        )]);
        let a = att(
            "compromised",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2026-06-11T09:00:00Z" }),
        );
        assert_eq!(a.asserted_at, ts("2020-01-01T00:00:00Z"));
        assert!(h.suspects(&a, ts("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn an_undated_envelope_is_suspect_only_when_the_key_is_revoked() {
        let undated = att("compromised", serde_json::json!({ "score": 1.0 }));
        let now = ts("2026-08-01T00:00:00Z");

        assert!(
            !HeldRevocations::default().suspects(&undated, now),
            "no revocation held ⇒ nothing considered ⇒ the statement stands"
        );

        let h = held(vec![rev(
            "r1",
            "compromised",
            "2026-07-01T00:00:00Z",
            Some("2026-06-10T09:00:00Z"),
        )]);
        assert!(
            h.suspects(&undated, now),
            "an undated statement from a revoked key cannot be placed before the \
             bound, and fail-open would be the bypass: omit the field, keep standing"
        );
    }

    #[test]
    fn an_unbounded_revocation_still_takes_the_whole_corpus() {
        let h = held(vec![rev("r1", "compromised", "2026-07-01T00:00:00Z", None)]);
        let ancient = att(
            "compromised",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2001-01-01T00:00:00Z" }),
        );
        let f = h.statement_standing(&ancient, ts("2026-08-01T00:00:00Z"));
        assert_eq!(f.standing, KeyStatementStanding::SuspectUnbounded);
    }

    #[test]
    fn a_revocation_not_yet_in_effect_is_not_considered() {
        let h = held(vec![rev("r1", "compromised", "2026-09-01T00:00:00Z", None)]);
        let a = att(
            "compromised",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2026-07-01T00:00:00Z" }),
        );
        let f = h.statement_standing(&a, ts("2026-08-01T00:00:00Z"));
        assert_eq!(f.standing, KeyStatementStanding::Stands);
        assert_eq!(f.considered, 0);
    }

    #[test]
    fn an_unrelated_key_is_untouched() {
        let h = held(vec![rev("r1", "compromised", "2026-07-01T00:00:00Z", None)]);
        let other = att(
            "honest",
            serde_json::json!({ ENVELOPE_ASSERTED_AT: "2026-07-30T00:00:00Z" }),
        );
        assert!(!h.suspects(&other, ts("2026-08-01T00:00:00Z")));
    }

    #[test]
    fn attesting_keys_are_the_distinct_set() {
        let corpus = vec![
            att("a", serde_json::json!({})),
            att("b", serde_json::json!({})),
            att("a", serde_json::json!({})),
        ];
        let keys = attesting_keys(&corpus);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("a") && keys.contains("b"));
    }

    #[test]
    fn is_empty_distinguishes_no_keys_from_no_revocations() {
        assert!(HeldRevocations::default().is_empty());
        let mut m = BTreeMap::new();
        m.insert("k".to_owned(), Vec::new());
        assert!(HeldRevocations::from_map(m).is_empty());
        assert!(!held(vec![rev("r1", "compromised", "2026-07-01T00:00:00Z", None)]).is_empty());
    }
}
