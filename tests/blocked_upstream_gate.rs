//! **The `state:blocked-upstream` → `state:unwired` gate** (CIRISServer#361 §"one
//! thing to fix", asked for on #361, #355 and #356 and never built).
//!
//! Sibling of [`substrate_contract_gate`](../substrate_contract_gate.rs): that file
//! pins the substrate contracts this repo CONSUMES so a change cannot ride a
//! version bump in silently. This file pins the substrate facts this repo is
//! WAITING ON, so their arrival cannot ride a version bump in silently either.
//!
//! # Why a test and not a document
//!
//! Filing an upstream issue creates a tracked obligation *there* and nothing
//! *here*. #361 found seven capabilities this repo had specified itself, all seven
//! shipped, all seven with zero callers; six were adopted only because somebody
//! re-enumerated them by hand. A document describing that asymmetry is the thing
//! that did not get run three times. A red test is read on the substrate bump that
//! causes it.
//!
//! # What it reads
//!
//! `evidence/blocked_upstream.tsv` — one row per blocking predicate (an issue may
//! wait on more than one). For each row the gate resolves the upstream repo's rev
//! **out of `Cargo.lock`** — the revision the build actually resolves, not "newest
//! directory by mtime" — locates `~/.cargo/git/checkouts/<repo>-<hash>/<rev>/`, and
//! counts matching files and lines under `scan_root`.
//!
//! Two arms, deliberately different in character:
//!
//! - **absence** (`files = 0`) — a marker that cannot exist until the capability
//!   does. Sharp: red means go adopt. Its coverage is bounded by our ability to
//!   name the marker in advance, which is why the markers chosen are ones CC or an
//!   upstream const already fixes (`oversight_mode`, `SCCACHE_BUCKET`), not names
//!   we invented.
//! - **drift** (`files > 0`) — the blocked area pinned as it stands. Blunt: red
//!   means upstream touched the code this issue is about, so re-read the blocker
//!   now rather than a year later. This arm needs no name to be guessed, which is
//!   the false-negative #361's own closing note is the cautionary tale for
//!   (`fold_reverse_quorum` still has zero callers *correctly* — the adoption went
//!   through persist's resolver, and a grep for the capability name would have said
//!   "not shipped").
//!
//! **A red row is an instruction to read the issue. It is never permission to
//! relabel on the strength of the grep.**
//!
//! # What it cannot do, stated plainly
//!
//! It cannot tell you a NEW issue has been labelled `state:blocked-upstream`
//! without a manifest row — that needs the GitHub API, which a test must not have.
//! [`manifest_issue_set_is_pinned`] holds the line offline by pinning the issue set
//! in this file, independently of the manifest, so the two must be changed
//! together. The API-side reconciliation is `tools/check_blocked_upstream.sh`.
//!
//! Swept and pinned at persist v30.3.0 / edge v15.19.1 / verify v13.0.0.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The issues carrying `state:blocked-upstream` at the sweep that created this
/// file. Pinned HERE rather than derived from the manifest on purpose: a manifest
/// that describes only itself agrees with itself. Changing the labelled set means
/// changing this list AND the manifest, and [`manifest_issue_set_is_pinned`] fails
/// if only one of them moves.
///
/// The 2026-08-06 sweep resolved six others: #334 / #321 / #219 / #113 / #112 →
/// `state:unwired` (the capability had shipped), #111 closed as overtaken by the
/// reverse-quorum plane. Do not re-add them here without re-blocking them.
const BLOCKED_UPSTREAM_ISSUES: &[u32] = &[2, 114, 115, 285, 333, 534];

const MANIFEST: &str = "evidence/blocked_upstream.tsv";
const COLUMNS: [&str; 9] = [
    "issue",
    "repo",
    "scan_root",
    "glob",
    "needle",
    "files",
    "lines",
    "kind",
    "predicate",
];

#[derive(Debug)]
struct Row {
    issue: u32,
    repo: String,
    scan_root: String,
    glob: String,
    needle: String,
    files: usize,
    lines: usize,
    kind: String,
    predicate: String,
}

impl Row {
    fn is_untestable(&self) -> bool {
        self.kind == "untestable"
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn load() -> Vec<Row> {
    let path = repo_root().join(MANIFEST);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{MANIFEST} must exist and be readable: {e}"));

    let mut lines = raw
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty());

    let header: Vec<&str> = lines
        .next()
        .expect("manifest must carry a header row")
        .split('\t')
        .collect();
    assert_eq!(
        header, COLUMNS,
        "{MANIFEST} header drifted — the loader and the artifact are two statements of one schema"
    );

    let mut out = Vec::new();
    for (i, line) in lines.enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            f.len(),
            COLUMNS.len(),
            "{MANIFEST} row {} has {} columns, expected {}: {line:?}",
            i + 1,
            f.len(),
            COLUMNS.len()
        );
        for (c, v) in COLUMNS.iter().zip(&f) {
            assert!(
                !v.trim().is_empty(),
                "{MANIFEST} row {}: column `{c}` is blank — use `-` for deliberately absent",
                i + 1
            );
        }
        let num = |s: &str, what: &str| -> usize {
            if s == "-" {
                return 0;
            }
            s.parse().unwrap_or_else(|_| {
                panic!(
                    "{MANIFEST} row {}: `{what}` must be an integer or `-`, got {s:?}",
                    i + 1
                )
            })
        };
        out.push(Row {
            issue: f[0].parse().unwrap_or_else(|_| {
                panic!(
                    "{MANIFEST} row {}: `issue` must be a number, got {:?}",
                    i + 1,
                    f[0]
                )
            }),
            repo: f[1].to_owned(),
            scan_root: f[2].to_owned(),
            glob: f[3].to_owned(),
            needle: f[4].to_owned(),
            files: num(f[5], "files"),
            lines: num(f[6], "lines"),
            kind: f[7].to_owned(),
            predicate: f[8].to_owned(),
        });
    }
    assert!(
        !out.is_empty(),
        "{MANIFEST} carries no rows — a gate over nothing"
    );
    out
}

/// The rev `Cargo.lock` resolves for a pinned substrate repo. Read from the lock
/// rather than guessed from the checkout directory, because "newest directory by
/// mtime" can silently answer about a version this build is not using — a gate
/// reading the wrong tree looks exactly like a gate that passed.
fn locked_rev(repo: &str) -> String {
    let lock = std::fs::read_to_string(repo_root().join("Cargo.lock")).expect("read Cargo.lock");
    let needle = format!("git+https://github.com/CIRISAI/{repo}?tag=");
    let line = lock
        .lines()
        .find(|l| l.contains(&needle))
        .unwrap_or_else(|| {
            panic!("Cargo.lock has no git dependency on {repo} — did the pin move?")
        });
    let sha = line
        .rsplit_once('#')
        .unwrap_or_else(|| panic!("Cargo.lock {repo} source line carries no `#<sha>`: {line}"))
        .1
        .trim_end_matches('"');
    assert_eq!(sha.len(), 40, "{repo} rev is not a full sha: {sha:?}");
    sha[..7].to_owned()
}

/// The vendored checkout for `repo` at the rev `Cargo.lock` pins.
///
/// `Ok(None)` — `~/.cargo/git/checkouts` does not exist at all, i.e. an unfetched
/// or vendored environment. The row is passed over with a loud note; if EVERY row
/// is passed over the non-vacuity assertion at the end still fails the test, so an
/// environment that can read no substrate at all cannot discharge this gate by
/// silence. (`tests/compliance_map.rs` treats the same absence as a WARN because
/// its other arms still run; here there would be nothing left.)
///
/// `Err` — the checkouts directory exists but the PINNED rev is not in it. That is
/// not a missing environment, it is a resolution that would have had this gate read
/// some other version of the substrate, so it fails.
fn checkout(repo: &str) -> Result<Option<PathBuf>, String> {
    let prefix = match repo {
        "CIRISPersist" => "cirispersist-",
        "CIRISEdge" => "cirisedge-",
        "CIRISVerify" => "cirisverify-",
        other => return Err(format!("unknown substrate repo {other:?} in {MANIFEST}")),
    };
    // CARGO_HOME first, because it is the variable that actually decides where
    // these checkouts live — deriving the path from HOME ignores anyone who has
    // relocated their cargo home and silently reads the wrong tree, or none.
    // CI sets it explicitly (`CARGO_HOME: /home/runner/.cargo`).
    //
    // The HOME/USERPROFILE fallbacks exist because HOME alone is a POSIX
    // assumption: it is unset on Windows runners, where this gate panicked with
    // "HOME unset" and took all of CI red with it — which in turn blocked the
    // iOS release asset, since that job harvests only from a GREEN ci.yml run.
    // A gate for upstream blockers has no business having an opinion about the
    // host OS.
    let checkouts = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join(".cargo")))
        .ok_or_else(|| "none of CARGO_HOME, HOME or USERPROFILE is set".to_string())?
        .join("git")
        .join("checkouts");
    let Ok(entries) = std::fs::read_dir(&checkouts) else {
        return Ok(None);
    };
    let rev = locked_rev(repo);
    let base = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix))
        })
        .ok_or_else(|| format!("no `{prefix}*` checkout under {}", checkouts.display()))?;
    let at_rev = base.join(&rev);
    if !at_rev.is_dir() {
        return Err(format!(
            "{repo}: Cargo.lock pins rev {rev} but {} does not exist. This gate would otherwise \
             have read a DIFFERENT revision of the substrate and reported a verdict about it. \
             Run `cargo fetch` and re-run.",
            at_rev.display()
        ));
    }
    Ok(Some(at_rev))
}

/// Files and lines under `root` matching `needle` (`|`-separated alternatives).
/// Returns `(files, lines, candidates)` — `candidates` is the DENOMINATOR: how many
/// files were actually looked at. A zero denominator is itself an error, because a
/// scan that saw nothing agrees with every expectation.
fn scan(root: &Path, glob: &str, needle: &str) -> (usize, usize, usize) {
    let alts: Vec<&str> = needle.split('|').filter(|s| !s.is_empty()).collect();
    let suffix = glob.trim_start_matches('*');
    let mut files = 0usize;
    let mut hit_lines = 0usize;
    let mut candidates = 0usize;

    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            let Ok(rd) = std::fs::read_dir(&p) else {
                continue;
            };
            for e in rd.filter_map(Result::ok) {
                let child = e.path();
                // `target/` inside a checkout is build output, never source.
                if child.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                stack.push(child);
            }
            continue;
        }
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        // A single-file scan_root is scanned whatever its name; inside a directory
        // the glob filters.
        if p != root && !name.ends_with(suffix) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&p) else {
            continue;
        };
        candidates += 1;
        let n = src
            .lines()
            .filter(|l| alts.iter().any(|a| l.contains(a)))
            .count();
        if n > 0 {
            files += 1;
            hit_lines += n;
        }
    }
    (files, hit_lines, candidates)
}

/// **The gate.** Every checkable row, evaluated against the pinned substrate.
#[test]
fn blocked_upstream_predicates_still_hold() {
    let rows = load();
    let mut checked = 0usize;
    let mut skipped_untestable = 0usize;

    for r in &rows {
        if r.is_untestable() {
            skipped_untestable += 1;
            continue;
        }
        let base = match checkout(&r.repo) {
            Err(e) => panic!("CIRISServer#{}: {e}", r.issue),
            Ok(None) => {
                eprintln!(
                    "SKIP CIRISServer#{}: no ~/.cargo/git/checkouts (unfetched or vendored build)",
                    r.issue
                );
                continue;
            }
            Ok(Some(b)) => b,
        };
        let root = base.join(&r.scan_root);
        assert!(
            root.exists(),
            "CIRISServer#{}: scan_root `{}` does not exist in {} at the pinned rev. The path \
             MOVED upstream, so this row is reading nothing — which is indistinguishable from a \
             clean pass. Re-read the issue and re-point the row.",
            r.issue,
            r.scan_root,
            r.repo
        );

        let (files, lines, candidates) = scan(&root, &r.glob, &r.needle);
        assert!(
            candidates > 0,
            "CIRISServer#{}: scanned 0 files under {}:{} matching `{}` — the denominator is zero, \
             so this row cannot fail and is not a check.",
            r.issue,
            r.repo,
            r.scan_root,
            r.glob
        );

        match r.kind.as_str() {
            "absence" => {
                assert_eq!(
                    r.files, 0,
                    "CIRISServer#{}: an `absence` row must pin files = 0",
                    r.issue
                );
                assert_eq!(
                    (files, lines),
                    (0, 0),
                    "\n\n>>> CIRISServer#{} MAY BE UNBLOCKED <<<\n\
                     `{}` now resolves in {}:{} at the pinned rev ({} file(s), {} line(s)) and \
                     did not before.\n\n\
                     What this issue waits on: {}\n\n\
                     Read the issue, confirm the capability it needs actually landed (a name \
                     match is NOT an adoption — #361 closed tracking `fold_reverse_quorum`, \
                     which correctly still has zero callers because the adoption went through \
                     persist's resolver), then relabel `state:blocked-upstream` → \
                     `state:unwired` and comment with the symbol and where it lives.\n",
                    r.issue,
                    r.needle,
                    r.repo,
                    r.scan_root,
                    files,
                    lines,
                    r.predicate,
                );
            }
            "drift" => {
                assert!(
                    r.files > 0,
                    "CIRISServer#{}: a `drift` row pins the area AS IT STANDS, so files must be \
                     > 0; use `absence` for a marker that must not exist",
                    r.issue
                );
                assert_eq!(
                    (files, lines),
                    (r.files, r.lines),
                    "\n\n>>> the code CIRISServer#{} IS ABOUT MOVED UPSTREAM <<<\n\
                     `{}` in {}:{} was {} file(s) / {} line(s) at the last sweep and is now {} / \
                     {}.\n\n\
                     What this issue waits on: {}\n\n\
                     This is not proof the blocker cleared; it is the substrate bump on which to \
                     find out. Read the issue and the changed code. If the processor landed, \
                     relabel to `state:unwired` and name the symbol. If it did not, re-pin these \
                     two numbers — deliberately, in the commit that moves the substrate.\n",
                    r.issue,
                    r.needle,
                    r.repo,
                    r.scan_root,
                    r.files,
                    r.lines,
                    files,
                    lines,
                    r.predicate,
                );
            }
            other => panic!(
                "CIRISServer#{}: unknown kind {other:?} — expected absence | drift | untestable",
                r.issue
            ),
        }
        checked += 1;
    }

    // Non-vacuity. This repo has shipped gates that reconciled nothing and passed
    // forever; the denominator is reported so a shrinking one is visible.
    assert!(
        checked > 0,
        "no row was evaluated — {} untestable of {} total. A manifest of nothing-but-excuses is a \
         document wearing a test's clothes.",
        skipped_untestable,
        rows.len()
    );
    eprintln!(
        "blocked-upstream: {checked} predicate(s) evaluated, {skipped_untestable} untestable, \
         {} row(s) total",
        rows.len()
    );
}

/// Coverage, to the limit an offline test can reach: the manifest must account for
/// every issue in [`BLOCKED_UPSTREAM_ISSUES`] and invent none. The two lists are
/// maintained separately and compared, which is the only reason either is evidence.
#[test]
fn manifest_issue_set_is_pinned() {
    let rows = load();
    let in_manifest: BTreeSet<u32> = rows.iter().map(|r| r.issue).collect();
    let pinned: BTreeSet<u32> = BLOCKED_UPSTREAM_ISSUES.iter().copied().collect();

    assert_eq!(
        in_manifest, pinned,
        "{MANIFEST} covers {in_manifest:?} but BLOCKED_UPSTREAM_ISSUES pins {pinned:?}.\n\n\
         An issue labelled `state:blocked-upstream` with no row here is invisible to the gate — \
         it is exactly the issue that will sit blocked for a year after its blocker clears. Add \
         the row AND the constant. If an issue was relabelled or closed, remove both.\n\n\
         This test cannot see GitHub. `tools/check_blocked_upstream.sh` reconciles this list \
         against the live label."
    );
}

/// Every `untestable` row must justify itself, and must not smuggle a scannable
/// predicate past the gate by leaving the columns blank. The honest answer to "a
/// test cannot express this" is a row that says why — not a missing row.
#[test]
fn untestable_rows_are_declared_not_defaulted() {
    let rows = load();
    let mut untestable = 0usize;
    for r in rows.iter().filter(|r| r.is_untestable()) {
        untestable += 1;
        assert_eq!(
            (r.repo.as_str(), r.scan_root.as_str(), r.needle.as_str()),
            ("-", "-", "-"),
            "CIRISServer#{}: an `untestable` row must leave repo/scan_root/needle as `-`. If \
             there IS something to scan, it is not untestable — make it a row that runs.",
            r.issue
        );
        assert!(
            r.predicate.len() > 80,
            "CIRISServer#{}: an `untestable` row's `predicate` must say WHY no symbol can express \
             it and what would change that — {} chars is a shrug, not a reason.",
            r.issue,
            r.predicate.len()
        );
    }
    eprintln!("blocked-upstream: {untestable} untestable row(s), each justified");
}
