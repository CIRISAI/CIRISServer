//! **CC 4.5.2.2 `compliance-vertical` — the machine-readable vertical/statutory
//! compliance map** (CIRISServer#159).
//!
//! CC 4.5.2.2 publishes the vertical compliance mapping (regulatory framework → CEG
//! wire primitive) and CC 8.8.5 Annex C publishes the statutory/standards cross-walk
//! (external framework → CIRIS Book/Annex §). Both existed as **prose tables only**.
//! This module makes them a checked-in, machine-readable, parse-at-boot artifact:
//! [`evidence/cc_compliance_map.tsv`](../../evidence/cc_compliance_map.tsv) is baked in
//! via `include_str!` and resolved into typed [`ComplianceRow`]s by [`ComplianceMap`].
//!
//! # The chain: `statute → CIRIS document → SHIPPING SYMBOL + TEST`
//!
//! A Book/Annex reference is a pointer to *prose*, not evidence. What makes a compliance
//! claim **defensible** is the third tier: [`ComplianceRow::implementing_evidence`] — the
//! concrete shipping artifact (a `path#symbol`, and/or the test that proves it) that
//! actually discharges the obligation. Every evidence token in the artifact was established
//! by **reading the code**, never inferred from a filename.
//!
//! ## The transcription tiers vs the evidence tier
//!
//! Columns 1-5 and 7-9 are a TRANSCRIPTION, not an interpretation — every cell comes from
//! the Constitution's own table cells, and a mapping the source does not state is written
//! [`UNMAPPED`], never invented:
//!
//! - CC 4.5.2.2 rows state a CEG wire primitive but **no** Book/Annex reference
//!   → `ciris_mapping = unmapped`.
//! - CC 8.8.5 Annex C rows state a Book/Annex reference but **no** CEG wire primitive
//!   and **no** substrate symbol → `ceg_primitive = unmapped`.
//!
//! `implementing_evidence` is the one column NOT from the Constitution. Its rules:
//!
//! - **Accuracy over coverage.** A cited symbol that does not actually discharge the
//!   obligation is worse than [`UNMAPPED`]. Unsure ⇒ `unmapped`.
//! - A whole-cell [`PARTIAL_PREFIX`] means the cited artifact discharges only *part* of the
//!   obligation; the remainder is a real gap, and [`ComplianceRow::tracking_issue`] names it.
//! - [`UNMAPPED`] means **no enforcer ships**. These holes are the *point* of the artifact.
//!   The canonical one: EU AI Act Art 14 (human oversight — intervene/interrupt/stop).
//!   `oversight_mode` is a wire field with no enforcer in any shipping artifact
//!   (CIRISServer#115); it stays `unmapped`, and [`tests`] forbids filling it in.
//!
//! An honest gap with a tracking issue is defensible; a blank is not — so every gap carries
//! a [`ComplianceRow::tracking_issue`], and [`TRACKING_UNTRACKED`] explicitly flags the ones
//! that still need an issue filed.
//!
//! Per CC 8.8.5 §3 (the graduation rule) the statutory rows are *informative engineering
//! correspondences*, not legal opinions; a row graduates to "verified" only on qualified
//! legal review. This artifact carries the source's own `source_status` verbatim and makes
//! **no** compliance claim of its own.
//!
//! [`ComplianceRow::cc_refs`] carries only the CC sections the row's own source cells
//! cross-reference verbatim — it is the join key into `evidence/cc_impl.tsv`, so a claim
//! this map leans on cannot silently regress to `open` (asserted by `tests/compliance_map.rs`).

use std::collections::BTreeSet;

/// The compliance map artifact, baked in at compile time so the map ships with the node
/// (and cannot drift from the binary that serves it).
pub const CC_COMPLIANCE_MAP_TSV: &str = include_str!("../evidence/cc_compliance_map.tsv");

/// The literal cell value for "the Constitution states no mapping here".
///
/// Load-bearing: it is the difference between an honest hole and a fabricated statutory
/// mapping. Never replace an `unmapped` cell without a corresponding change to the
/// Constitution prose.
pub const UNMAPPED: &str = "unmapped";

/// Whole-cell prefix on `implementing_evidence`: the cited artifact discharges only PART of
/// the obligation. The remainder is a real gap and MUST carry a `tracking_issue`.
pub const PARTIAL_PREFIX: &str = "partial:";

/// `tracking_issue` value for a fully-mapped row — no gap to track.
pub const TRACKING_NONE: &str = "none";

/// `tracking_issue` value for a gap with **no tracker**. Needs an issue filed. This is a
/// deliberate flag, not a resting state.
pub const TRACKING_UNTRACKED: &str = "untracked";

/// `tracking_issue` value for a row Annex C itself assigns to CIRISAgent's `compliance/`
/// cross-walk + the Covenant Books — i.e. not this repo's substrate to discharge.
pub const TRACKING_AGENT: &str = "CIRISAgent:compliance";

/// The exact TSV header the artifact must carry (column order is part of the format).
pub const COLUMNS: [&str; 10] = [
    "cc_section",
    "framework",
    "provision",
    "ceg_primitive",
    "ciris_mapping",
    "implementing_evidence",
    "composition",
    "source_status",
    "cc_refs",
    "tracking_issue",
];

/// The two Constitution sections this map transcribes.
pub const CC_SECTIONS: [&str; 2] = ["4.5.2.2", "8.8.5"];

/// The `source_status` vocabulary — CC 4.5.2.2's heading (`informational`) plus Annex C's
/// own Status column (`informative` / `partial` / `evidence-bearing`).
pub const SOURCE_STATUS: [&str; 4] = [
    "informational",
    "informative",
    "partial",
    "evidence-bearing",
];

/// One `implementing_evidence` token: the shipping artifact that discharges an obligation.
///
/// Wire form `Repo:path#symbol` or `Repo:path` (a whole test file). `repo` is the CIRIS repo
/// the artifact lives in (`CIRISServer` = this repo; `CIRISPersist` / `CIRISVerify` /
/// `CIRISEdge` = the pinned substrate crates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRef {
    /// `CIRISServer` | `CIRISPersist` | `CIRISVerify` | `CIRISEdge`.
    pub repo: String,
    /// Repo-relative path to the file that ships the enforcer (or the test that proves it).
    pub path: String,
    /// The load-bearing fn/struct/const, when the token names one.
    pub symbol: Option<String>,
}

impl EvidenceRef {
    /// True when the artifact lives in THIS repo — i.e. its path is checkable on disk here
    /// (see the `implementing_evidence_paths_exist` gate in `tests/compliance_map.rs`).
    pub fn is_local(&self) -> bool {
        self.repo == "CIRISServer"
    }
}

/// One transcribed row of the Constitution's compliance tables, plus its evidence tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceRow {
    /// Source section: `4.5.2.2` (vertical map) or `8.8.5` (Annex C statutory cross-walk).
    pub cc_section: String,
    /// Normalized framework id (`GDPR`, `EU-AI-ACT`, `NIST-AI-RMF`, …).
    pub framework: String,
    /// The article / clause / provision as the source names it.
    pub provision: String,
    /// The CEG wire primitive the source names, or [`UNMAPPED`].
    pub ceg_primitive: String,
    /// The CIRIS Book/Annex § the source names, or [`UNMAPPED`].
    pub ciris_mapping: String,
    /// **The evidence tier** — the shipping symbols/tests that discharge the obligation.
    /// Empty when no enforcer ships (the honest holes).
    pub implementing_evidence: Vec<EvidenceRef>,
    /// True when the cited evidence discharges only PART of the obligation ([`PARTIAL_PREFIX`]).
    pub evidence_is_partial: bool,
    /// The source's "How it composes" cell, or [`UNMAPPED`].
    pub composition: String,
    /// The source's own status for the row (see [`SOURCE_STATUS`]).
    pub source_status: String,
    /// CC section decimals cross-referenced verbatim by this row's source cells (may be empty).
    pub cc_refs: Vec<String>,
    /// [`TRACKING_NONE`] | `CIRISServer#N` | [`TRACKING_AGENT`] | [`TRACKING_UNTRACKED`].
    pub tracking_issue: String,
}

impl ComplianceRow {
    /// True when the Constitution names a CEG wire primitive for this provision.
    pub fn is_wire_mapped(&self) -> bool {
        self.ceg_primitive != UNMAPPED
    }

    /// True when the Constitution names a CIRIS Book/Annex § for this provision.
    pub fn is_document_mapped(&self) -> bool {
        self.ciris_mapping != UNMAPPED
    }

    /// True when a shipping artifact discharges this obligation — fully or [partially].
    ///
    /// [partially]: ComplianceRow::evidence_is_partial
    pub fn has_implementing_evidence(&self) -> bool {
        !self.implementing_evidence.is_empty()
    }

    /// True when the row's obligation is fully discharged by shipping code — the only state
    /// that needs no tracking issue.
    pub fn is_fully_evidenced(&self) -> bool {
        self.has_implementing_evidence() && !self.evidence_is_partial
    }

    /// True when this row is a REAL GAP: no enforcer ships, or only part of one does.
    pub fn is_gap(&self) -> bool {
        !self.is_fully_evidenced()
    }

    /// True when the row is a gap that nobody is tracking — needs an issue filed.
    pub fn is_untracked_gap(&self) -> bool {
        self.is_gap() && self.tracking_issue == TRACKING_UNTRACKED
    }
}

/// Parse one `implementing_evidence` cell into (`is_partial`, tokens).
fn parse_evidence(cell: &str) -> Result<(bool, Vec<EvidenceRef>), String> {
    if cell == UNMAPPED {
        return Ok((false, Vec::new()));
    }
    let (is_partial, body) = match cell.strip_prefix(PARTIAL_PREFIX) {
        Some(rest) => (true, rest),
        None => (false, cell),
    };

    let mut refs = Vec::new();
    for tok in body.split(';').map(str::trim).filter(|t| !t.is_empty()) {
        let (repo, rest) = tok
            .split_once(':')
            .ok_or_else(|| format!("evidence token {tok:?} must be `Repo:path[#symbol]`"))?;
        if repo.is_empty() || rest.is_empty() {
            return Err(format!("evidence token {tok:?} has an empty repo or path"));
        }
        let (path, symbol) = match rest.split_once('#') {
            Some((p, s)) if !p.is_empty() && !s.is_empty() => (p, Some(s.to_string())),
            Some(_) => {
                return Err(format!(
                    "evidence token {tok:?} has an empty path or symbol"
                ))
            }
            None => (rest, None),
        };
        refs.push(EvidenceRef {
            repo: repo.to_string(),
            path: path.to_string(),
            symbol,
        });
    }
    if refs.is_empty() {
        return Err(format!(
            "evidence cell {cell:?} names no artifact — use `{UNMAPPED}`"
        ));
    }
    Ok((is_partial, refs))
}

/// The parsed compliance map.
#[derive(Debug, Clone, Default)]
pub struct ComplianceMap {
    rows: Vec<ComplianceRow>,
}

impl ComplianceMap {
    /// Parse the baked-in artifact. Infallible in practice — `tests/compliance_map.rs` is
    /// the CI gate that keeps it so.
    pub fn load() -> Result<Self, String> {
        Self::parse(CC_COMPLIANCE_MAP_TSV)
    }

    /// Parse a compliance-map TSV: `#` comments, one header row, then 10 tab-columns each.
    pub fn parse(tsv: &str) -> Result<Self, String> {
        let mut rows = Vec::new();
        let mut saw_header = false;

        for (n, raw) in tsv.lines().enumerate() {
            let line = raw.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').map(str::trim).collect();

            if !saw_header {
                if cols != COLUMNS {
                    return Err(format!(
                        "L{}: header must be exactly {:?}, got {:?}",
                        n + 1,
                        COLUMNS,
                        cols
                    ));
                }
                saw_header = true;
                continue;
            }

            if cols.len() != COLUMNS.len() {
                return Err(format!(
                    "L{}: expected {} tab-columns, got {}: {line:?}",
                    n + 1,
                    COLUMNS.len(),
                    cols.len()
                ));
            }
            if let Some(i) = cols.iter().position(|c| c.is_empty()) {
                return Err(format!(
                    "L{}: column `{}` is empty — use `{UNMAPPED}`, never a blank",
                    n + 1,
                    COLUMNS[i]
                ));
            }

            let cc_refs = if cols[8] == UNMAPPED {
                Vec::new()
            } else {
                cols[8]
                    .split(';')
                    .map(|r| r.trim().to_string())
                    .filter(|r| !r.is_empty())
                    .collect()
            };

            let (evidence_is_partial, implementing_evidence) =
                parse_evidence(cols[5]).map_err(|e| format!("L{}: {e}", n + 1))?;

            let row = ComplianceRow {
                cc_section: cols[0].to_string(),
                framework: cols[1].to_string(),
                provision: cols[2].to_string(),
                ceg_primitive: cols[3].to_string(),
                ciris_mapping: cols[4].to_string(),
                implementing_evidence,
                evidence_is_partial,
                composition: cols[6].to_string(),
                source_status: cols[7].to_string(),
                cc_refs,
                tracking_issue: cols[9].to_string(),
            };

            // The defensibility invariant: a gap MUST name a tracker (even if that tracker
            // is the literal `untracked` flag), and a fully-evidenced row must NOT claim one.
            if row.is_fully_evidenced() && row.tracking_issue != TRACKING_NONE {
                return Err(format!(
                    "L{}: row is fully evidenced but claims tracking_issue {:?} — expected `{TRACKING_NONE}`",
                    n + 1,
                    row.tracking_issue
                ));
            }
            if row.is_gap() && row.tracking_issue == TRACKING_NONE {
                return Err(format!(
                    "L{}: row is a GAP (no/partial implementing_evidence) but tracking_issue is \
                     `{TRACKING_NONE}` — name the issue, or flag it `{TRACKING_UNTRACKED}`",
                    n + 1
                ));
            }

            rows.push(row);
        }

        if !saw_header {
            return Err("no header row found".to_string());
        }
        if rows.is_empty() {
            return Err("compliance map has no rows".to_string());
        }
        Ok(Self { rows })
    }

    /// Every transcribed row.
    pub fn rows(&self) -> &[ComplianceRow] {
        &self.rows
    }

    /// Rows transcribed from one Constitution section (`4.5.2.2` / `8.8.5`).
    pub fn rows_for_section(&self, cc_section: &str) -> Vec<&ComplianceRow> {
        self.rows
            .iter()
            .filter(|r| r.cc_section == cc_section)
            .collect()
    }

    /// Every framework the map covers, deduplicated.
    pub fn frameworks(&self) -> BTreeSet<&str> {
        self.rows.iter().map(|r| r.framework.as_str()).collect()
    }

    /// Every CC section decimal the map's rows cross-reference — the join key set into
    /// `evidence/cc_impl.tsv`.
    pub fn cc_refs(&self) -> BTreeSet<&str> {
        self.rows
            .iter()
            .flat_map(|r| r.cc_refs.iter().map(String::as_str))
            .collect()
    }

    /// Rows for which the Constitution names NO CEG wire primitive — the honest holes.
    /// Every Annex C statutory row lands here: Annex C maps to CIRIS *documents*, not to
    /// substrate symbols.
    pub fn unmapped_wire(&self) -> Vec<&ComplianceRow> {
        self.rows.iter().filter(|r| !r.is_wire_mapped()).collect()
    }

    /// Rows whose obligation IS discharged by shipping code, end to end.
    pub fn fully_evidenced(&self) -> Vec<&ComplianceRow> {
        self.rows
            .iter()
            .filter(|r| r.is_fully_evidenced())
            .collect()
    }

    /// Rows where a shipping artifact discharges only PART of the obligation.
    pub fn partially_evidenced(&self) -> Vec<&ComplianceRow> {
        self.rows
            .iter()
            .filter(|r| r.has_implementing_evidence() && r.evidence_is_partial)
            .collect()
    }

    /// The REAL GAPS — no enforcer ships, or only part of one does.
    pub fn gaps(&self) -> Vec<&ComplianceRow> {
        self.rows.iter().filter(|r| r.is_gap()).collect()
    }

    /// Gaps nobody is tracking. **Every one of these needs an issue filed** — an honest gap
    /// with a tracking issue is defensible, a blank is not.
    pub fn untracked_gaps(&self) -> Vec<&ComplianceRow> {
        self.rows.iter().filter(|r| r.is_untracked_gap()).collect()
    }

    /// Every evidence token the map cites, across all rows.
    pub fn evidence(&self) -> impl Iterator<Item = &EvidenceRef> {
        self.rows
            .iter()
            .flat_map(|r| r.implementing_evidence.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal well-formed row builder: 10 columns, tab-joined.
    fn row(evidence: &str, tracking: &str) -> String {
        format!(
            "{}\n4.5.2.2\tGDPR\tArticle 7\tconsent:state:granted\tunmapped\t{evidence}\tcomposes\tinformational\tunmapped\t{tracking}\n",
            COLUMNS.join("\t")
        )
    }

    #[test]
    fn baked_artifact_parses() {
        let map = ComplianceMap::load().expect("baked compliance map must parse");
        assert!(!map.rows().is_empty());
        assert_eq!(
            map.rows_for_section("4.5.2.2").len() + map.rows_for_section("8.8.5").len(),
            map.rows().len()
        );
    }

    #[test]
    fn blank_cell_is_rejected() {
        let tsv = format!(
            "{}\n4.5.2.2\tGDPR\tArticle 7\t\tunmapped\tunmapped\tx\tinformational\tunmapped\tuntracked\n",
            COLUMNS.join("\t")
        );
        assert!(ComplianceMap::parse(&tsv).is_err());
    }

    #[test]
    fn evidence_token_shapes() {
        let map = ComplianceMap::parse(&row("CIRISServer:tests/accord.rs", TRACKING_NONE)).unwrap();
        let e = &map.rows()[0].implementing_evidence[0];
        assert!(e.is_local() && e.symbol.is_none() && e.path == "tests/accord.rs");

        let map = ComplianceMap::parse(&row("CIRISPersist:src/engine.rs#evict_x", TRACKING_NONE))
            .unwrap();
        let e = &map.rows()[0].implementing_evidence[0];
        assert!(!e.is_local());
        assert_eq!(e.symbol.as_deref(), Some("evict_x"));

        // A malformed token (no `Repo:` prefix) must not silently become a path.
        assert!(ComplianceMap::parse(&row("src/engine.rs#evict_x", TRACKING_NONE)).is_err());
    }

    #[test]
    fn partial_evidence_is_a_tracked_gap() {
        let tsv = row("partial:CIRISServer:tests/accord.rs", "CIRISServer#243");
        let map = ComplianceMap::parse(&tsv).unwrap();
        let r = &map.rows()[0];
        assert!(r.evidence_is_partial && r.has_implementing_evidence());
        assert!(r.is_gap() && !r.is_fully_evidenced());

        // …and a partial row may NOT claim `none` — a gap must name its tracker.
        let tsv = row("partial:CIRISServer:tests/accord.rs", TRACKING_NONE);
        assert!(ComplianceMap::parse(&tsv).is_err());
    }

    #[test]
    fn an_unmapped_row_may_not_claim_it_is_untracked_free() {
        // `unmapped` evidence + `none` tracker = a blank. Rejected.
        assert!(ComplianceMap::parse(&row(UNMAPPED, TRACKING_NONE)).is_err());
        // The honest forms both parse.
        assert!(ComplianceMap::parse(&row(UNMAPPED, TRACKING_UNTRACKED)).is_ok());
        assert!(ComplianceMap::parse(&row(UNMAPPED, "CIRISServer#115")).is_ok());
    }

    #[test]
    fn a_fully_evidenced_row_may_not_claim_a_tracker() {
        assert!(
            ComplianceMap::parse(&row("CIRISServer:tests/accord.rs", "CIRISServer#115")).is_err()
        );
    }
}
