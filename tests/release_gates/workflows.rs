//! # Local `uses:` targets resolve
//!
//! A reusable workflow referenced by `uses: ./.github/workflows/x.yml` is a
//! CONTRACT between files, and deleting the callee does not fail like a broken
//! contract. The YAML stays valid — `yaml.safe_load` on the whole tree passes —
//! and GitHub reports it on the CALLERS, as "this run likely failed because of a
//! workflow file issue", with every job in them simply absent. Absent jobs read
//! as "not triggered by these paths", which is a normal thing to see.
//!
//! Paid for on 0.5.189: the #471 sweep deleted `ios-asset.yml` because it matched
//! `grep client/`. Its only reference to that tree was a COMMENT explaining why
//! its CPython pin is 3.10 — the workflow itself builds the iOS SUBSTRATE slices
//! that CIRISAgent's `tools/update_substrate_libs.py` consumes, and BOTH `ci.yml`
//! and `release.yml` call it. `grep client/` finds files that MENTION a tree, not
//! files that DEPEND on it.
//!
//! This is a link check, not a schema check: it answers "does the thing this file
//! points at exist", which is the half no YAML validator covers.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The `uses:` value on a line, when it names something in THIS repo (`./…`).
///
/// Deliberately dumb: `uses:` values are inline scalars in every workflow here,
/// and a parser would need a dependency to answer a question string handling
/// answers exactly. Quotes are stripped because both forms appear in the wild.
fn local_uses_target(line: &str) -> Option<&str> {
    let after = line.split_once("uses:")?.1.trim();
    // A `#` inside a quoted path would break this; none exists, and a path with
    // a comment marker in it would be a worse problem than this test.
    let value = after.split('#').next()?.trim();
    let value = value
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_end_matches(|c: char| c.is_whitespace());
    value.starts_with("./").then_some(value)
}

fn workflow_files() -> Vec<PathBuf> {
    let dir = repo_root().join(".github/workflows");
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|s| s.to_str()),
                Some("yml") | Some("yaml")
            )
        })
        .collect();
    out.sort();
    out
}

/// A local `uses:` target resolves: a `.yml` is a file, anything else is an
/// action directory holding `action.yml`.
fn resolves(root: &Path, target: &str) -> bool {
    let path = root.join(target.trim_start_matches("./"));
    match path.extension().and_then(|s| s.to_str()) {
        Some("yml") | Some("yaml") => path.is_file(),
        _ => path.join("action.yml").is_file() || path.join("action.yaml").is_file(),
    }
}

#[test]
fn every_local_uses_target_exists() {
    let root = repo_root();
    let mut examined = 0usize;
    let mut dangling = Vec::new();

    for wf in workflow_files() {
        let text = std::fs::read_to_string(&wf).unwrap_or_else(|e| panic!("read {wf:?}: {e}"));
        for (n, line) in text.lines().enumerate() {
            let Some(target) = local_uses_target(line) else {
                continue;
            };
            examined += 1;
            if !resolves(&root, target) {
                let name = wf.file_name().unwrap().to_string_lossy().to_string();
                dangling.push(format!("{name}:{} -> {target}", n + 1));
            }
        }
    }

    // The denominator guard this repo has now paid for seven times: a link check
    // that finds no links passes, and reads exactly like one that checked them.
    assert!(
        examined > 0,
        "DEAD GATE: examined 0 local `uses:` references across {} workflow file(s). \
         Either the reference syntax changed or the scan is looking in the wrong \
         place — this test cannot pass by finding nothing.",
        workflow_files().len()
    );

    assert!(
        dangling.is_empty(),
        "{} local `uses:` reference(s) point at a file that does not exist.\n{}\n\n\
         The callers will fail with \"this run likely failed because of a workflow \
         file issue\" and ALL their jobs will be missing — not a YAML error, so \
         validating the tree parses will not catch it.",
        dangling.len(),
        dangling.join("\n")
    );
}

/// Every reusable workflow (`on: workflow_call`) has at least one caller.
///
/// The inverse of the gate above, and the reason the deletion looked safe: a
/// reusable workflow has no triggers of its own, so it never appears in a run
/// list, and nothing about it says who depends on it. This does not fail — a
/// workflow may be called from ANOTHER REPO, which is exactly what `ios-asset`
/// serves — it prints, so the callee/caller map is visible in the log where a
/// reviewer deciding whether something is dead can actually see it.
#[test]
fn reusable_workflows_report_their_callers() {
    let root = repo_root();
    let files = workflow_files();

    let callers: Vec<(String, Vec<String>)> = files
        .iter()
        .map(|wf| {
            let text = std::fs::read_to_string(wf).unwrap_or_default();
            let targets = text
                .lines()
                .filter_map(local_uses_target)
                .map(str::to_string)
                .collect();
            (
                wf.file_name().unwrap().to_string_lossy().to_string(),
                targets,
            )
        })
        .collect();

    for wf in &files {
        let text = std::fs::read_to_string(wf).unwrap_or_default();
        if !text.contains("workflow_call") {
            continue;
        }
        let name = wf.file_name().unwrap().to_string_lossy().to_string();
        let rel = format!("./.github/workflows/{name}");
        let who: Vec<&str> = callers
            .iter()
            .filter(|(_, t)| t.contains(&rel))
            .map(|(c, _)| c.as_str())
            .collect();
        assert!(
            resolves(&root, &rel),
            "{name} is reusable but does not resolve from {rel}"
        );
        println!(
            "reusable {name} <- {}",
            if who.is_empty() {
                "(no in-repo caller; may be called from another repo)".to_string()
            } else {
                who.join(", ")
            }
        );
    }
}
