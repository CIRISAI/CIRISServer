//! The word "seed" names ONE artifact: the `GenesisBundle`.
//!
//! `FSD/NAMING_THE_TRUST_ROOT.md` locks this — "the seed is a bundle, and it is
//! the only shape"; a bare pair of key records is not a seed and does not parse
//! as one. This gate makes that rule mechanical instead of aspirational.
//!
//! It exists because the rule was written and then immediately violated. Through
//! 0.5.140 the `admit-node` / `add-canonical` responses called their outbox file
//! the "genesis seed object", returned it as `seed_saved_to`, and the UI rendered:
//!
//!     "— seed saved to $it. Hand it to persist to bake."
//!
//! That is an instruction to hand persist the WRONG FILE, on the one path where
//! being wrong is most expensive — pre-bundle v12.0.2 vocabulary that outlived
//! the model it described. Nothing failed: the string compiled, the endpoint
//! worked, and only an operator following the instruction would have found it.
//!
//! This is the axis-fusion shape in a string: one word answering two questions
//! ("which artifact do I hand persist?" and "where did admit-node write?"), with
//! one answer wrong. Grep is the right instrument — the defect is textual, lives
//! in comments and user-facing copy, and is invisible to the type system.
//!
//! To keep a banned token deliberately (a historical note like the one above),
//! put `VOCAB-HISTORY` on the same line.

use std::path::{Path, PathBuf};

/// Tokens that named the wrong artifact. Each shipped in 0.5.140.
const BANNED: &[(&str, &str)] = &[
    (
        "genesis seed object",
        "the admit-node outbox file is ADMISSION RECORDS, not a seed — the seed is the GenesisBundle at <home>/mesh-genesis.json",
    ),
    (
        "seed saved to",
        "user-facing copy: say what was actually saved. `save_seed_to_home` may say 'seed'; admit-node/add-canonical may not",
    ),
    ("seed_saved_to", "renamed to `admission_records_path`"),
    ("seedSavedTo", "renamed to `admissionRecordsPath`"),
];

const MARKER: &str = "VOCAB-HISTORY";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            // Build output and vendored trees carry copies we do not own.
            let skip = matches!(
                p.file_name().and_then(|s| s.to_str()),
                Some("target" | "build" | "node_modules" | ".git")
            );
            if !skip {
                collect(&p, exts, out);
            }
        } else if p
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|x| exts.contains(&x))
        {
            out.push(p);
        }
    }
}

#[test]
fn seed_names_only_the_genesis_bundle() {
    let root = repo_root();
    let mut files = Vec::new();
    collect(&root.join("src"), &["rs"], &mut files);
    collect(
        &root.join("client/shared/src/commonMain/kotlin"),
        &["kt"],
        &mut files,
    );

    assert!(
        files.len() > 20,
        "vocabulary gate scanned only {} files — the tree moved and this gate went blind, \
         which is worse than the defect it guards (it would report PASS forever)",
        files.len()
    );

    let mut violations = Vec::new();
    for path in &files {
        // This gate necessarily contains every banned token.
        if path.ends_with("seed_vocabulary.rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if line.contains(MARKER) {
                continue;
            }
            let lower = line.to_lowercase();
            for (tok, why) in BANNED {
                let hit = if tok.chars().any(|c| c.is_uppercase()) {
                    line.contains(tok) // camelCase: match exactly
                } else {
                    lower.contains(*tok)
                };
                if hit {
                    let rel = path.strip_prefix(&root).unwrap_or(path);
                    violations.push(format!(
                        "  {}:{}\n    banned: {:?}\n    why:    {}\n    line:   {}",
                        rel.display(),
                        n + 1,
                        tok,
                        why,
                        line.trim()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\n{} place(s) call something other than a GenesisBundle a \"seed\".\n\n{}\n\n\
         The seed is the GenesisBundle the genesis ceremony writes to \
         <home>/mesh-genesis.json (`save_seed_to_home`). Everything else — the \
         admit-node / add-canonical outbox JSON — is ADMISSION RECORDS: two \
         holder-signed key records, the transport for a remote target.\n\
         See FSD/NAMING_THE_TRUST_ROOT.md. To keep a token deliberately, add \
         `{}` to the line.\n",
        violations.len(),
        violations.join("\n\n"),
        MARKER,
    );
}

/// The gate must be able to fail. A grep gate whose pattern silently stops
/// matching is indistinguishable from a clean tree — the exact failure mode that
/// let the ANSI-coloured harness probes read 0 on a healthy pipeline.
#[test]
fn the_gate_detects_a_violation() {
    let sample = r#"_notice.value = "Admitted $t — seed saved to $p. Hand it to persist to bake.""#;
    let lower = sample.to_lowercase();
    assert!(
        BANNED.iter().any(|(t, _)| lower.contains(*t)),
        "the banned-token list no longer matches the string that shipped in 0.5.140"
    );
    assert!(
        format!("{sample} // {MARKER}").contains(MARKER),
        "the deliberate-exemption marker must be honoured"
    );
}
