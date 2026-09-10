//! **The capacity READ surface** — `GET /v1/my-data/capacity`.
//!
//! The capacity scorer emits `capacity:*` attestations and, until this module,
//! nothing served them back: every capacity route a client tried answered 404
//! against a real 0.5.204 (CIRISServer#580). A client card built on them could
//! only render a permanent "warming up" placeholder — a screen that reads "not
//! yet" when the truth is "not ever, on this build", which is the dishonest
//! metric the anti-Goodhart rules exist to prevent. The write path was never
//! the gap.
//!
//! # What it serves, and why by SUBJECT
//!
//! Every `capacity:*` family carries **no-self-emit** at CC 3.4.5
//! (`attesting_key_id != attested_key_id`), so a capacity score is a
//! third-party statement by construction. Two consequences shape this surface:
//!
//! * **Every row carries its `attesting_key_id`.** A capacity value with no
//!   visible attester invites exactly the reading CC 3.4.5 forbids — that the
//!   subject scored itself.
//! * **The query is by subject, not by "mine".** An operator wants what others
//!   have attested about the keys they are responsible for. Their own node is
//!   one of those keys, and the scores about it are third-party by
//!   construction, so "mine" is not even expressible here.
//!
//! # Responsible keys
//!
//! A key is this operator's responsibility if it is:
//!
//! 1. **this node's own** registered federation key;
//! 2. **a node they steward** — [`nodes_stewarded_by`] over the responsible
//!    user this node is bound to (the owned-nodes projection);
//! 3. **an agent this node carries** — every subject this node has itself
//!    attested capacity about. The scorer attests about the agent keys on its
//!    own traces, so the rows it wrote ARE the roster of agents bound here, and
//!    they cost nothing extra to derive: they come out of the same read.
//!
//! Most scored subjects are agents, so (3) is the case that carries the screen.
//!
//! # A canonical row about our key must appear
//!
//! The read filters by subject and **not** by attester, so a row the canonical
//! attested about one of our agents is served exactly like one we attested
//! ourselves, distinguished by `attested_by_this_node`. That is the point: a
//! capacity score is worth reading precisely because someone else made it.
//!
//! # Cost
//!
//! ONE `list_attestations` with the `capacity:` family prefix and no attester
//! pin. Since persist v42.1.0 that compiles to a range on V137's index, and the
//! prefix is selective — the shape measured 2,191 read syscalls before the
//! index and 25 after, on a 27k-row corpus (CIRISServer#575). Deriving the
//! agent roster from the same page rather than a second query is what keeps
//! this one read rather than one-per-subject.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ciris_persist::prelude::Engine;
use serde_json::json;

/// The most capacity rows one read will return.
///
/// A bound, not a page: the surface reports `truncated` when it hits this, so a
/// client renders "showing the newest N" rather than silently the wrong set. A
/// node scoring a handful of agents on an hourly cadence sits far below it.
pub const CAPACITY_READ_LIMIT: i64 = 2_000;

/// One capacity row as it arrives from the substrate, reduced to what this
/// surface reads.
///
/// A local shape rather than persist's `Attestation` so [`project`] — where all
/// the judgement lives — is testable without standing up a corpus, and so a new
/// field on the substrate row is not a compile break here.
#[derive(Debug, Clone)]
pub struct RawCapacityRow {
    pub attesting_key_id: String,
    pub attested_key_id: String,
    pub dimension: String,
    pub score: Option<f64>,
    pub asserted_at: String,
    pub expires_at: Option<String>,
    /// Why this row does or does not stand right now — decided by the caller
    /// with the SAME rule the scorer applies, never re-derived here.
    pub standing: Standing,
}

/// Whether a capacity row still counts, and if not, why not.
///
/// A surface that serves an expired or revoked score as though it were current
/// is the dishonest metric CIRISServer#580 is about, one layer in: the client
/// renders a confident number that the node itself would not act on. The
/// scorer's own read treats a row as standing only when it is unexpired AND its
/// attester's key has not been revoked, and this surface must not be looser —
/// the ONE place that decides is `key_standing`, consulted by both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Standing {
    /// Unexpired, and its attester holds standing.
    Standing,
    /// Past its `expires_at`. Capacity scores carry a 7-day validity, so this
    /// is the ordinary fate of a subject that stopped being scored.
    Expired,
    /// Its ATTESTER's key was revoked. The row is still in the corpus and still
    /// signed; what it lost is the standing of whoever said it.
    AttesterRevoked,
}

/// One capacity attestation, flattened for the wire.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapacityRow {
    /// Whether this row still counts — see [`Standing`]. Served on every row so
    /// a client never has to decide liveness itself, and never renders a dead
    /// score as a current one.
    pub standing: Standing,
    /// The subject — whose capacity this describes.
    pub attested_key_id: String,
    /// **Who says so.** Never omitted: see the CC 3.4.5 note in the module docs.
    pub attesting_key_id: String,
    /// `true` when this node is the attester, so a client can distinguish our
    /// own reading from a peer's without string-matching key ids.
    pub attested_by_this_node: bool,
    /// The versioned dimension leaf (`capacity:sustained_coherence:v1`, …).
    pub dimension: String,
    /// The score, when the envelope carries one.
    pub score: Option<f64>,
    /// When the attester signed it.
    pub asserted_at: String,
    /// When it stops standing, if it says.
    pub expires_at: Option<String>,
}

/// What the surface knows about one subject.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapacitySubject {
    /// `true` when at least one row about this subject stands. Distinct from an
    /// empty `rows`: "scored, and none of it counts any more" is a different
    /// fact from "never scored", and CIRISServer#374 is the whole argument for
    /// keeping those apart.
    pub any_standing: bool,
    pub key_id: String,
    /// Why this key is ours: `"self"`, `"stewarded"`, or `"agent"`.
    pub relation: &'static str,
    /// Newest first.
    pub rows: Vec<CapacityRow>,
}

/// The whole answer.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapacityReport {
    pub node_key_id: String,
    /// The responsible user this node is bound to, when it is bound.
    pub responsible_user_key_id: Option<String>,
    pub subjects: Vec<CapacitySubject>,
    /// Subjects with no capacity row yet. Named rather than omitted: "we are
    /// responsible for this key and nobody has scored it" is a different fact
    /// from "this key is not ours", and a client that cannot tell them apart
    /// renders the warming-up placeholder #580 is about.
    pub unscored: Vec<String>,
    /// `true` when the read hit [`CAPACITY_READ_LIMIT`].
    pub truncated: bool,
}

/// Build the report. Separate from the HTTP handler so it is testable without a
/// listener, and reusable by any other surface that needs the same projection.
///
/// # Errors
/// The substrate read failing. A responsible-key lookup that fails degrades to
/// a smaller set rather than an error: a node that cannot resolve its steward
/// still knows its own key and its own agents.
pub async fn report(engine: &Arc<Engine>, node_key_id: &str) -> Result<CapacityReport, String> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    // ── one read: every capacity row in the corpus, whoever attested it ──────
    let mut filter = AttestationFilter::default();
    filter.dimension_prefixes = vec![crate::scorer::capacity_family_prefix()];
    let page = engine
        .list_attestations(
            filter,
            None,
            CAPACITY_READ_LIMIT,
            ciris_persist::prelude::CallerScope::Unauthenticated,
        )
        .await
        .map_err(|e| format!("list_attestations(capacity): {e}"))?;
    let truncated = i64::try_from(page.items.len()).unwrap_or(i64::MAX) >= CAPACITY_READ_LIMIT;

    // ── who we are responsible for ───────────────────────────────────────────
    let responsible_user_key_id =
        crate::auth::ownership::is_steward_bound(engine, node_key_id).await;
    let mut stewarded: BTreeSet<String> = BTreeSet::new();
    if let Some(user) = responsible_user_key_id.as_deref() {
        stewarded.extend(crate::auth::ownership::nodes_stewarded_by(engine, user).await);
    }
    // Envelope KEYS come from persist's constants, never a literal: a
    // hand-mirrored `"dimension"` compiles and skews the wire on a persist
    // rename (`envelope_vocabulary_single_source`, CIRISServer#322). `score` is
    // this family's own payload field rather than envelope vocabulary, so it
    // has no constant to import.
    // ── standing: the SAME rule the scorer applies, not a looser one ────────
    //
    // A capacity row counts only if it is unexpired AND its attester still
    // holds standing. `key_standing` is the one place that decides the second
    // half; this surface consults it rather than re-deriving it, so a surface
    // and the scorer cannot come to different conclusions about the same row
    // (the mirrored-rule trap: one rule, two implementations, and a drift test
    // that can only compare a copy to itself).
    let now = chrono::Utc::now();
    let held = crate::key_standing::HeldRevocations::for_keys(
        engine,
        crate::key_standing::attesting_keys(&page.items),
    )
    .await
    .map_err(|e| format!("revocations_for(attesters): {e}"))?;

    let raw: Vec<RawCapacityRow> = page
        .items
        .iter()
        .map(|a| RawCapacityRow {
            attesting_key_id: a.attesting_key_id.clone(),
            attested_key_id: a.attested_key_id.clone(),
            dimension: a
                .attestation_envelope
                .get(ciris_persist::federation::envelope::paths::DIMENSION)
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_owned(),
            score: a
                .attestation_envelope
                .get("score")
                .and_then(serde_json::Value::as_f64),
            asserted_at: a.asserted_at.to_rfc3339(),
            expires_at: a.expires_at.map(|e| e.to_rfc3339()),
            standing: if a.expires_at.is_some_and(|exp| exp <= now) {
                Standing::Expired
            } else if !held.is_empty() && held.suspects(a, now) {
                Standing::AttesterRevoked
            } else {
                Standing::Standing
            },
        })
        .collect();

    let mut report = project(&raw, node_key_id, &stewarded);
    report.responsible_user_key_id = responsible_user_key_id;
    report.truncated = truncated;
    Ok(report)
}

/// The judgement: which of these rows are ours, and how each key is ours.
///
/// Pure, so the rules that matter — a peer's row about our agent is served, a
/// row about a stranger is not, an unscored responsible key is NAMED — are
/// tested without a corpus.
#[must_use]
pub fn project(
    rows: &[RawCapacityRow],
    node_key_id: &str,
    stewarded: &BTreeSet<String>,
) -> CapacityReport {
    // The agents this node carries: the subjects it has itself attested about.
    // The scorer attests about the agent keys on its own traces, so the rows it
    // wrote ARE that roster — derived from the same page, not a second read.
    let agents: BTreeSet<String> = rows
        .iter()
        .filter(|r| r.attesting_key_id == node_key_id)
        .map(|r| r.attested_key_id.clone())
        .collect();

    let mut relation: BTreeMap<String, &'static str> = BTreeMap::new();
    // Most specific last: this node is "self" even if it also appears in its
    // steward's roster or has somehow attested about itself.
    for k in &agents {
        relation.insert(k.clone(), "agent");
    }
    for k in stewarded {
        relation.insert(k.clone(), "stewarded");
    }
    relation.insert(node_key_id.to_owned(), "self");

    let mut by_subject: BTreeMap<String, Vec<CapacityRow>> = BTreeMap::new();
    for r in rows {
        if !relation.contains_key(&r.attested_key_id) {
            continue;
        }
        by_subject
            .entry(r.attested_key_id.clone())
            .or_default()
            .push(CapacityRow {
                standing: r.standing,
                attested_key_id: r.attested_key_id.clone(),
                attesting_key_id: r.attesting_key_id.clone(),
                attested_by_this_node: r.attesting_key_id == node_key_id,
                dimension: r.dimension.clone(),
                score: r.score,
                asserted_at: r.asserted_at.clone(),
                expires_at: r.expires_at.clone(),
            });
    }
    for v in by_subject.values_mut() {
        v.sort_by(|a, b| b.asserted_at.cmp(&a.asserted_at));
    }

    let mut subjects = Vec::new();
    let mut unscored = Vec::new();
    for (key_id, rel) in &relation {
        match by_subject.remove(key_id) {
            Some(rows) => subjects.push(CapacitySubject {
                any_standing: rows.iter().any(|r| r.standing == Standing::Standing),
                key_id: key_id.clone(),
                relation: rel,
                rows,
            }),
            None => unscored.push(key_id.clone()),
        }
    }

    CapacityReport {
        node_key_id: node_key_id.to_owned(),
        responsible_user_key_id: None,
        subjects,
        unscored,
        truncated: false,
    }
}

/// The report as the client's Data page expects it.
#[must_use]
pub fn to_json(report: &CapacityReport) -> serde_json::Value {
    json!({ "data": report })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "ciris-node-bootstrap-abc";
    const AGENT: &str = "agent-datum-1";
    const CANONICAL: &str = "ciris-canonical-1";
    const STRANGER: &str = "somebody-elses-agent";

    fn row(attesting: &str, attested: &str, at: &str, score: f64) -> RawCapacityRow {
        row_with(attesting, attested, at, score, Standing::Standing)
    }

    fn row_with(
        attesting: &str,
        attested: &str,
        at: &str,
        score: f64,
        standing: Standing,
    ) -> RawCapacityRow {
        RawCapacityRow {
            standing,
            attesting_key_id: attesting.to_owned(),
            attested_key_id: attested.to_owned(),
            dimension: crate::scorer::CAPACITY_DIMENSION.to_owned(),
            score: Some(score),
            asserted_at: at.to_owned(),
            expires_at: None,
        }
    }

    fn find<'a>(r: &'a CapacityReport, key: &str) -> Option<&'a CapacitySubject> {
        r.subjects.iter().find(|s| s.key_id == key)
    }

    /// THE ask on CIRISServer#580: a capacity score the CANONICAL attested about
    /// a key we are responsible for must be visible here. It is the reason the
    /// query is by subject and not by attester — a score is worth reading
    /// precisely because someone else made it.
    #[test]
    fn a_canonical_row_about_our_agent_is_served() {
        let rows = vec![
            row(NODE, AGENT, "2026-09-10T01:00:00Z", 0.71),
            row(CANONICAL, AGENT, "2026-09-10T02:00:00Z", 0.66),
        ];
        let report = project(&rows, NODE, &BTreeSet::new());

        let agent = find(&report, AGENT).expect("the agent we score is ours");
        assert_eq!(agent.relation, "agent");
        assert_eq!(agent.rows.len(), 2, "both attesters' rows, not just ours");

        let from_canonical = agent
            .rows
            .iter()
            .find(|r| r.attesting_key_id == CANONICAL)
            .expect("the canonical's row about our agent must be served");
        assert!(
            !from_canonical.attested_by_this_node,
            "a peer's row must not read as our own"
        );
        assert_eq!(from_canonical.score, Some(0.66));
    }

    /// Newest first, so a client renders the current reading without sorting.
    #[test]
    fn rows_are_newest_first() {
        let rows = vec![
            row(NODE, AGENT, "2026-09-10T01:00:00Z", 0.71),
            row(CANONICAL, AGENT, "2026-09-10T02:00:00Z", 0.66),
        ];
        let report = project(&rows, NODE, &BTreeSet::new());
        let agent = find(&report, AGENT).expect("agent");
        assert_eq!(agent.rows[0].asserted_at, "2026-09-10T02:00:00Z");
    }

    /// Every row names its attester. A capacity value with no visible attester
    /// invites the exact reading CC 3.4.5 forbids — that the subject scored
    /// itself.
    #[test]
    fn every_row_names_its_attester() {
        let rows = vec![
            row(NODE, AGENT, "2026-09-10T01:00:00Z", 0.7),
            row(CANONICAL, AGENT, "2026-09-10T02:00:00Z", 0.6),
        ];
        let report = project(&rows, NODE, &BTreeSet::new());
        for s in &report.subjects {
            for r in &s.rows {
                assert!(!r.attesting_key_id.is_empty(), "attester must be present");
            }
        }
    }

    /// A score about somebody else's agent is not ours to serve, even though it
    /// sits in the same corpus — replication brings in rows about keys we have
    /// no responsibility for.
    #[test]
    fn a_row_about_a_key_we_are_not_responsible_for_is_excluded() {
        let rows = vec![
            row(NODE, AGENT, "2026-09-10T01:00:00Z", 0.7),
            row(CANONICAL, STRANGER, "2026-09-10T01:00:00Z", 0.9),
        ];
        let report = project(&rows, NODE, &BTreeSet::new());
        assert!(
            find(&report, STRANGER).is_none(),
            "a stranger's score must not appear on our page"
        );
        assert!(!report.unscored.iter().any(|k| k == STRANGER));
    }

    /// A node we steward is ours whether or not we have ever scored it — that
    /// is what the owned-nodes projection is for, and the scores about it come
    /// from peers by construction.
    #[test]
    fn a_stewarded_node_is_ours_and_a_peers_row_about_it_is_served() {
        let ward = "ciris-node-bootstrap-ward";
        let stewarded: BTreeSet<String> = [ward.to_owned()].into_iter().collect();
        let rows = vec![row(CANONICAL, ward, "2026-09-10T03:00:00Z", 0.5)];
        let report = project(&rows, NODE, &stewarded);

        let w = find(&report, ward).expect("a node we steward is ours");
        assert_eq!(w.relation, "stewarded");
        assert_eq!(w.rows.len(), 1);
        assert!(!w.rows[0].attested_by_this_node);
    }

    /// "Responsible for it, nobody has scored it" is a different fact from "not
    /// ours", and a client that cannot tell them apart renders the permanent
    /// warming-up placeholder #580 is about.
    #[test]
    fn a_responsible_key_with_no_rows_is_named_as_unscored() {
        let report = project(&[], NODE, &BTreeSet::new());
        assert!(
            report.unscored.iter().any(|k| k == NODE),
            "our own key is ours even before anyone scores it"
        );
        assert!(report.subjects.is_empty());
    }

    /// Our own node key is always ours, and CC 3.4.5 makes every score about it
    /// third-party — so "self" here means the SUBJECT is us, never the attester.
    #[test]
    fn our_own_node_is_a_subject_scored_only_by_others() {
        let rows = vec![row(CANONICAL, NODE, "2026-09-10T04:00:00Z", 0.8)];
        let report = project(&rows, NODE, &BTreeSet::new());
        let me = find(&report, NODE).expect("our own key is a subject");
        assert_eq!(me.relation, "self");
        assert!(
            me.rows.iter().all(|r| !r.attested_by_this_node),
            "a self-attested capacity row would violate CC 3.4.5 no-self-emit"
        );
    }

    /// The roster of agents comes from the rows this node attested, so an agent
    /// only the canonical has ever scored is NOT yet claimed as ours. Recorded
    /// as a known edge of the definition rather than left for someone to
    /// discover: it resolves the moment our own scorer attests about them.
    #[test]
    fn an_agent_only_a_peer_has_scored_is_not_yet_claimed() {
        let rows = vec![row(
            CANONICAL,
            "agent-we-never-scored",
            "2026-09-10T01:00:00Z",
            0.4,
        )];
        let report = project(&rows, NODE, &BTreeSet::new());
        assert!(find(&report, "agent-we-never-scored").is_none());
    }

    /// **The anti-Goodhart half of honesty.** An expired score must not render
    /// as a current one: capacity scores carry a 7-day validity, and a subject
    /// that stopped being scored keeps a stale number on the page unless the
    /// surface says so. The scorer would not act on this row; neither should a
    /// client.
    #[test]
    fn an_expired_row_is_served_but_marked_and_does_not_make_a_subject_standing() {
        let rows = vec![row_with(
            CANONICAL,
            AGENT,
            "2026-09-01T00:00:00Z",
            0.9,
            Standing::Expired,
        )];
        // The agent is ours only because we scored it; give it a row of ours too.
        let mut rows = rows;
        rows.push(row_with(
            NODE,
            AGENT,
            "2026-09-01T00:00:00Z",
            0.9,
            Standing::Expired,
        ));
        let report = project(&rows, NODE, &BTreeSet::new());
        let agent = find(&report, AGENT).expect("agent");
        assert!(
            !agent.any_standing,
            "every row is expired — the subject must not read as currently scored"
        );
        assert!(agent.rows.iter().all(|r| r.standing == Standing::Expired));
    }

    /// A revoked attester's score is still in the corpus and still signed; what
    /// it lost is the standing of whoever said it. Serving it as current would
    /// let a key keep influencing a metric after the federation withdrew its
    /// standing — which is exactly what revocation is for.
    #[test]
    fn a_revoked_attesters_row_does_not_count_as_standing() {
        let rows = vec![
            row(NODE, AGENT, "2026-09-10T01:00:00Z", 0.4),
            row_with(
                CANONICAL,
                AGENT,
                "2026-09-10T02:00:00Z",
                0.99,
                Standing::AttesterRevoked,
            ),
        ];
        let report = project(&rows, NODE, &BTreeSet::new());
        let agent = find(&report, AGENT).expect("agent");
        let revoked = agent
            .rows
            .iter()
            .find(|r| r.attesting_key_id == CANONICAL)
            .expect("the row is still served");
        assert_eq!(revoked.standing, Standing::AttesterRevoked);
        assert!(
            agent.any_standing,
            "our own live row still stands — one revoked attester does not blank the subject"
        );
    }

    /// "Scored, and none of it counts any more" is a THIRD state, distinct from
    /// both "never scored" and "currently scored" (CIRISServer#374's three
    /// zeroes, one surface out).
    #[test]
    fn none_standing_is_distinguishable_from_never_scored() {
        let scored_but_dead = vec![row_with(
            NODE,
            AGENT,
            "2026-09-01T00:00:00Z",
            0.9,
            Standing::Expired,
        )];
        let report = project(&scored_but_dead, NODE, &BTreeSet::new());
        let agent = find(&report, AGENT).expect("still a subject: we scored it");
        assert!(!agent.rows.is_empty(), "the rows are served, not hidden");
        assert!(!agent.any_standing);

        let never = project(&[], NODE, &BTreeSet::new());
        assert!(never.unscored.iter().any(|k| k == NODE));
    }
}
