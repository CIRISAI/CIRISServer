//! **CC 4.5.2.2 gate** — the compliance map cannot silently rot (CIRISServer#159).
//!
//! `evidence/cc_compliance_map.tsv` is the machine-readable publication of the
//! Constitution's two compliance tables (CC 4.5.2.2 vertical map + CC 8.8.5 Annex C
//! statutory cross-walk). This test is its spec-regression gate. It asserts the artifact
//! is:
//!
//! 1. **well-formed** — parses, exact header, 10 columns, no blank cells, no dup rows;
//! 2. **complete against the source claim set** — every framework/provision row the
//!    Constitution's tables carry is present, at the row counts the source tables have
//!    (a row silently dropped, or a row silently *added*, fails);
//! 3. **honest** — the tier invariants hold. CC 4.5.2.2 states a CEG wire primitive and
//!    no Book/Annex §; Annex C states a Book/Annex § and NO wire primitive / substrate
//!    symbol. A fabricated statutory→substrate mapping fails here;
//! 4. **evidenced, and the evidence is real** — every `implementing_evidence` path in THIS
//!    repo must EXIST on disk, so a citation can neither rot nor be invented. Substrate
//!    paths resolve in the cargo-vendored checkout when present (mirroring
//!    `tools/check_evidence.py`, which WARNs rather than fails when it is absent);
//! 5. **gap-honest** — EU AI Act Art 14 (human oversight) MUST stay `unmapped`:
//!    `oversight_mode` is a wire field with **no enforcer in any shipping artifact**
//!    (CIRISServer#115, proven by grep). This test pins that hole open;
//! 6. **joined to `evidence/cc_impl.tsv`** — every CC section this map leans on (its
//!    `cc_refs`) that carries an `impl:` row must still resolve to a symbol (not `open`),
//!    and cc_impl.tsv's own `4.5.2.2` row must point back at this map's loader.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ciris_server::compliance::{
    ComplianceMap, ComplianceRow, CC_SECTIONS, COLUMNS, SOURCE_STATUS, TRACKING_AGENT,
    TRACKING_NONE, TRACKING_UNTRACKED, UNMAPPED,
};

/// Row counts of the two source tables, as they stand in the Constitution prose.
/// CC 4.5.2.2 table: 10 rows. CC 8.8.5 Annex C §2 table: 17 rows.
const EXPECT_4522_ROWS: usize = 10;
const EXPECT_885_ROWS: usize = 17;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load() -> ComplianceMap {
    ComplianceMap::load().expect("evidence/cc_compliance_map.tsv must parse")
}

/// (1) Well-formedness — the loader enforces header/columns/blank-cells; here we add the
/// vocabularies and the no-duplicate-provision rule.
#[test]
fn artifact_is_well_formed() {
    let map = load();

    let sections: BTreeSet<&str> = CC_SECTIONS.into_iter().collect();
    let statuses: BTreeSet<&str> = SOURCE_STATUS.into_iter().collect();
    let mut seen: BTreeSet<(&str, &str, &str)> = BTreeSet::new();

    for r in map.rows() {
        assert!(
            sections.contains(r.cc_section.as_str()),
            "unknown cc_section {:?} — the map transcribes only {CC_SECTIONS:?}",
            r.cc_section
        );
        assert!(
            statuses.contains(r.source_status.as_str()),
            "row {}/{}: source_status {:?} outside the source vocabulary {SOURCE_STATUS:?}",
            r.framework,
            r.provision,
            r.source_status
        );
        assert!(
            seen.insert((
                r.cc_section.as_str(),
                r.framework.as_str(),
                r.provision.as_str()
            )),
            "duplicate row: {} / {} / {}",
            r.cc_section,
            r.framework,
            r.provision
        );
        for cc_ref in &r.cc_refs {
            assert!(
                cc_ref.chars().all(|c| c.is_ascii_digit() || c == '.'),
                "row {}/{}: cc_ref {cc_ref:?} is not a CC section decimal",
                r.framework,
                r.provision
            );
        }

        // tracking_issue vocabulary.
        let t = r.tracking_issue.as_str();
        assert!(
            t == TRACKING_NONE
                || t == TRACKING_UNTRACKED
                || t == TRACKING_AGENT
                || t.starts_with("CIRISServer#"),
            "row {}/{}: tracking_issue {t:?} outside the vocabulary \
             (`{TRACKING_NONE}` | `{TRACKING_UNTRACKED}` | `{TRACKING_AGENT}` | `CIRISServer#N`)",
            r.framework,
            r.provision
        );

        // Evidence tokens must name a known repo.
        for e in &r.implementing_evidence {
            assert!(
                matches!(
                    e.repo.as_str(),
                    "CIRISServer" | "CIRISPersist" | "CIRISVerify" | "CIRISEdge"
                ),
                "row {}/{}: evidence repo {:?} is not a CIRIS repo",
                r.framework,
                r.provision,
                e.repo
            );
        }
    }

    // The raw file must actually be tab-separated at the declared arity (guards against a
    // spaces-for-tabs edit that the trimming parser might otherwise wave through).
    let raw = std::fs::read_to_string(repo_root().join("evidence/cc_compliance_map.tsv"))
        .expect("artifact must exist at evidence/cc_compliance_map.tsv");
    for (n, line) in raw.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert_eq!(
            line.split('\t').count(),
            COLUMNS.len(),
            "L{}: not {} tab-columns",
            n + 1,
            COLUMNS.len()
        );
    }
}

/// (2) Completeness against the claim set — the exact frameworks and provision counts the
/// Constitution's tables carry. A dropped row (rot) OR an invented row (fabrication) fails.
#[test]
fn artifact_is_complete_against_the_constitution_tables() {
    let map = load();

    let vertical = map.rows_for_section("4.5.2.2");
    let annex_c = map.rows_for_section("8.8.5");
    assert_eq!(
        vertical.len(),
        EXPECT_4522_ROWS,
        "CC 4.5.2.2 has {EXPECT_4522_ROWS} table rows"
    );
    assert_eq!(
        annex_c.len(),
        EXPECT_885_ROWS,
        "CC 8.8.5 Annex C §2 has {EXPECT_885_ROWS} table rows"
    );
    assert_eq!(map.rows().len(), EXPECT_4522_ROWS + EXPECT_885_ROWS);

    // Per-framework provision counts, read straight off the source tables.
    let expect_vertical: BTreeMap<&str, usize> = BTreeMap::from([
        ("GDPR", 4),         // Art 7, 9, 17, 20
        ("HIPAA", 2),        // 164.502, 164.524
        ("FERPA", 1),        // 34 CFR Part 99
        ("CCPA", 1),         // §1798.105
        ("EU-AI-ACT", 1),    // Art 50
        ("CIRIS-ACCORD", 1), // M-1
    ]);
    let expect_annex_c: BTreeMap<&str, usize> = BTreeMap::from([
        ("EU-AI-ACT", 9), // Art 9, 10, 12, 13, 14, 15, 16, 50, 72
        ("NIST-AI-RMF", 1),
        ("ISO-IEC-42001", 2), // Cl 6.2, Annex A controls
        ("OSHA-ROBOTICS", 1),
        ("EU-HLEG", 1),
        ("IEEE-EAD", 1),
        ("ASEAN-AI-GG", 1),
        ("MAGNIFICA-HUMANITAS", 1),
    ]);

    fn tally<'a>(rows: &[&'a ComplianceRow]) -> BTreeMap<&'a str, usize> {
        let mut m: BTreeMap<&'a str, usize> = BTreeMap::new();
        for r in rows {
            *m.entry(r.framework.as_str()).or_default() += 1;
        }
        m
    }
    assert_eq!(
        tally(&vertical),
        expect_vertical,
        "CC 4.5.2.2 framework coverage drifted"
    );
    assert_eq!(
        tally(&annex_c),
        expect_annex_c,
        "CC 8.8.5 Annex C framework coverage drifted"
    );
}

/// (3) Honesty — the tier invariants. This is the anti-fabrication gate: Annex C's
/// statutory rows map to CIRIS *documents*, and the Constitution names NO CEG wire
/// primitive (and no substrate symbol) for any of them. If someone "helpfully" fills one
/// in without the Constitution changing, this fails.
#[test]
fn unmapped_cells_are_explicit_and_no_statutory_row_is_fabricated() {
    let map = load();

    for r in map.rows_for_section("4.5.2.2") {
        assert!(
            r.is_wire_mapped(),
            "CC 4.5.2.2 names a CEG primitive for every row; {}/{} has none",
            r.framework,
            r.provision
        );
        assert!(
            !r.is_document_mapped(),
            "CC 4.5.2.2 states NO Book/Annex § — {}/{} must stay `{UNMAPPED}`",
            r.framework,
            r.provision
        );
        assert_ne!(
            r.composition, UNMAPPED,
            "CC 4.5.2.2 states a composition for every row"
        );
        assert_eq!(
            r.source_status, "informational",
            "CC 4.5.2.2 is informational"
        );
    }

    for r in map.rows_for_section("8.8.5") {
        assert!(
            !r.is_wire_mapped(),
            "Annex C names NO CEG wire primitive — {}/{} must stay `{UNMAPPED}` (a statutory \
             mapping to the substrate is not stated in the Constitution and MUST NOT be invented)",
            r.framework,
            r.provision
        );
        assert_eq!(
            r.composition, UNMAPPED,
            "Annex C's table has no `How it composes` column"
        );
        assert!(
            r.is_document_mapped(),
            "Annex C names a CIRIS Book/Annex § for every row; {}/{} has none",
            r.framework,
            r.provision
        );
    }

    // The honest holes are exactly the Annex C rows plus nothing else.
    assert_eq!(map.unmapped_wire().len(), EXPECT_885_ROWS);
}

/// (4) The join into `evidence/cc_impl.tsv` — the rot gate.
#[test]
fn cc_impl_join_holds() {
    let map = load();
    let impl_tsv = std::fs::read_to_string(repo_root().join("evidence/cc_impl.tsv"))
        .expect("evidence/cc_impl.tsv must exist");

    // decimal_id -> (path#symbol, crate@version)
    let mut impl_rows: BTreeMap<String, (String, String)> = BTreeMap::new();
    for line in impl_tsv.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with("decimal_id\t") {
            continue;
        }
        let c: Vec<&str> = line.split('\t').collect();
        assert_eq!(c.len(), 5, "cc_impl.tsv row is not 5 columns: {line:?}");
        impl_rows.insert(c[0].to_string(), (c[3].to_string(), c[4].to_string()));
    }

    // (a) cc_impl.tsv's own 4.5.2.2 row must point back at THIS map's loader — the claim
    //     is no longer `open`, and the pointer cannot rot to a moved symbol.
    let (pathsym, cratever) = impl_rows
        .get("4.5.2.2")
        .expect("cc_impl.tsv must carry the 4.5.2.2 row");
    assert_eq!(
        pathsym, "src/compliance.rs#ComplianceMap",
        "cc_impl.tsv 4.5.2.2 must resolve to the compliance-map loader"
    );
    assert_eq!(cratever, "ciris-server@main");
    assert!(
        repo_root().join("src/compliance.rs").is_file(),
        "the resolved path must exist"
    );

    // (b) every CC section this map cross-references, IF cc_impl.tsv carries it, must still
    //     resolve to a symbol — a claim the map leans on may not regress to `open`.
    for cc_ref in map.cc_refs() {
        if let Some((pathsym, cratever)) = impl_rows.get(cc_ref) {
            assert_ne!(
                cratever, "open",
                "compliance map leans on CC {cc_ref}, but its cc_impl.tsv row went `open`"
            );
            assert!(
                pathsym.contains('#'),
                "CC {cc_ref}: cc_impl.tsv row must resolve to a path#symbol"
            );
        }
    }
}

/// (4) **The evidence is REAL.** Every `implementing_evidence` path in this repo must exist
/// on disk. A citation cannot rot (file moved/renamed) and cannot be invented (a path that
/// was never there). Substrate paths resolve in the cargo-vendored checkout when it is
/// present; absent, they are skipped — the same deferral `tools/check_evidence.py` makes.
#[test]
fn implementing_evidence_paths_exist() {
    let map = load();
    let root = repo_root();

    let mut checked_local = 0usize;
    let mut checked_substrate = 0usize;

    for r in map.rows() {
        for e in &r.implementing_evidence {
            if e.is_local() {
                let p = root.join(&e.path);
                assert!(
                    p.is_file(),
                    "row {}/{}: implementing_evidence cites {}:{} — NO SUCH FILE. A compliance \
                     citation that does not resolve is worse than `{UNMAPPED}`.",
                    r.framework,
                    r.provision,
                    e.repo,
                    e.path
                );
                if let Some(sym) = &e.symbol {
                    let src = std::fs::read_to_string(&p).expect("read cited file");
                    assert!(
                        src.contains(sym.as_str()),
                        "row {}/{}: symbol `{sym}` not found in {}",
                        r.framework,
                        r.provision,
                        e.path
                    );
                }
                checked_local += 1;
            } else if let Some(base) = substrate_checkout(&e.repo) {
                let p = base.join(&e.path);
                assert!(
                    p.is_file(),
                    "row {}/{}: implementing_evidence cites {}:{} — not in the pinned checkout",
                    r.framework,
                    r.provision,
                    e.repo,
                    e.path
                );
                if let Some(sym) = &e.symbol {
                    let src = std::fs::read_to_string(&p).expect("read cited substrate file");
                    assert!(
                        src.contains(sym.as_str()),
                        "row {}/{}: symbol `{sym}` not found in {}:{} at the pinned version",
                        r.framework,
                        r.provision,
                        e.repo,
                        e.path
                    );
                }
                checked_substrate += 1;
            }
        }
    }

    assert!(
        checked_local > 0,
        "the map must cite at least one in-repo artifact"
    );
    eprintln!("evidence resolved: {checked_local} local, {checked_substrate} substrate");
}

/// The vendored checkout for a pinned substrate repo, if `cargo fetch` has populated it.
/// Mirrors `tools/check_evidence.py::checkout_dir` — absent => the caller skips (WARN, not FAIL).
fn substrate_checkout(repo: &str) -> Option<PathBuf> {
    let glob = match repo {
        "CIRISPersist" => "cirispersist-",
        "CIRISVerify" => "cirisverify-",
        "CIRISEdge" => "cirisedge-",
        _ => return None,
    };
    let checkouts = PathBuf::from(std::env::var("HOME").ok()?).join(".cargo/git/checkouts");
    let parent = std::fs::read_dir(&checkouts)
        .ok()?
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with(glob))?
        .path();
    // Any populated rev directory: the pinned rev is the one cargo built with.
    newest_rev_dir(&parent)
}

fn newest_rev_dir(parent: &Path) -> Option<PathBuf> {
    std::fs::read_dir(parent)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("Cargo.toml").is_file())
        .max_by_key(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        })
}

/// (5) **The gap that is the point.** EU AI Act Art 14 (human oversight — intervene /
/// interrupt / stop) has NO enforcer in any shipping artifact: `oversight_mode` is a wire
/// field nothing reads (CIRISServer#115). This test pins the hole OPEN — a future edit that
/// quietly claims evidence for Art 14 without an enforcer actually shipping must fail here.
#[test]
fn eu_ai_act_art14_human_oversight_stays_unmapped() {
    let map = load();

    let art14 = map
        .rows_for_section("8.8.5")
        .into_iter()
        .find(|r| r.provision.starts_with("Art 14 Human oversight"))
        .expect("Annex C carries the Art 14 human-oversight row");

    assert!(
        !art14.has_implementing_evidence(),
        "EU AI Act Art 14 must stay `{UNMAPPED}`: `oversight_mode` is a wire field with no \
         enforcer in any shipping artifact (CIRISServer#115). If an enforcer has genuinely \
         shipped, close #115 and cite it — do NOT cite a symbol that does not enforce."
    );
    assert_eq!(
        art14.tracking_issue, "CIRISServer#115",
        "the Art 14 gap is tracked by CIRISServer#115"
    );
}

/// (6) **Gap discipline.** Every gap names a tracker; every fully-evidenced row names none.
/// `untracked` is a legal value — it is the flag that an issue still needs filing — but it
/// must be a deliberate, visible choice, so this test pins the exact untracked set.
#[test]
fn every_gap_is_tracked_or_explicitly_flagged() {
    let map = load();

    for r in map.gaps() {
        assert_ne!(
            r.tracking_issue, TRACKING_NONE,
            "row {}/{} is a gap but claims no tracker",
            r.framework, r.provision
        );
    }
    for r in map.fully_evidenced() {
        assert_eq!(
            r.tracking_issue, TRACKING_NONE,
            "row {}/{} is fully evidenced — it must not claim a tracker",
            r.framework, r.provision
        );
    }

    // The untracked gaps, pinned. These need issues FILED — the set may only shrink (an
    // issue gets filed) or grow deliberately (a new honest hole is surfaced).
    let untracked: BTreeSet<(&str, &str)> = map
        .untracked_gaps()
        .iter()
        .map(|r| (r.framework.as_str(), r.provision.as_str()))
        .collect();
    let expect: BTreeSet<(&str, &str)> = BTreeSet::from([
        ("GDPR", "Article 9 (special category — health, biometric, sexual orientation, etc.)"),
        ("GDPR", "Article 20 (data portability)"),
        ("HIPAA", "45 CFR 164.524 (patient right of access)"),
        (
            "EU-AI-ACT",
            "Art 50 Transparency (50(1) AI-interaction disclosure; 50(2) machine-readable AI-content marking)",
        ),
    ]);
    assert_eq!(
        untracked, expect,
        "the UNTRACKED-gap set drifted — file an issue and name it, or surface the new hole deliberately"
    );
}
