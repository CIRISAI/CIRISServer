//! **Every dimension this server spells out is one the registry registers.**
//!
//! Since persist v50 the dimension grammar is data (the vendored CC namespace
//! registry, CIRISPersist#924) and the put door refuses a dimension outside a
//! registered family: `age_self_declared:adult:v1` — the family is
//! `age_self_declared:band:{band}:{version}` — was refused at the door, and only
//! a test that happened to emit that one row noticed. A dimension no test emits
//! would fail the same way in production.
//!
//! So: every string literal in `src/` shaped like a full versioned dimension
//! (`a:b…:vN`) goes through persist's ONE matcher, and none may come back with
//! a REFUSAL. "No registered family" alone is not a refusal: an unreserved stem
//! (`device:label:v1` before rc6 registered it) is admitted under its producer as steward. What the
//! door refuses is a malformed dimension, or one on a stem persist RESERVES but
//! the registry does not register (`age_self_declared:`). Comments are skipped.
//! A dimension assembled with `format!` is not seen here; its builder's own
//! unit test is the check.

use std::path::Path;

fn literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' && bytes[j] != b'\n' {
                if bytes[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                out.push(src[start..j].to_owned());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// `a:…:vN`, lowercase segments, no placeholders or spaces.
fn is_versioned_dimension(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() >= 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        && parts
            .last()
            .and_then(|v| v.strip_prefix('v'))
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

/// Spellings kept on purpose, each with why. Reading is not writing: these
/// are the OLD forms a node must still READ from rows written before the
/// registry was strict, and appear in src only as parser inputs.
const READ_ONLY_LEGACY: &[(&str, &str)] = &[
    (
        "age_self_declared:adult:v1",
        "pre-v50 self-declared age rows; age.rs parses them, never writes them",
    ),
    (
        "need:shelter:v1",
        "field_conformance's polarity table: a classifier input, never a row",
    ),
];

fn walk(dir: &Path, found: &mut Vec<(String, String)>) {
    for e in std::fs::read_dir(dir).expect("read src") {
        let p = e.expect("entry").path();
        if p.is_dir() {
            walk(&p, found);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let text = std::fs::read_to_string(&p).expect("read file");
            let code: String = text
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            for lit in literals(&code) {
                if is_versioned_dimension(&lit) {
                    found.push((p.display().to_string(), lit));
                }
            }
        }
    }
}

#[test]
fn every_dimension_literal_in_src_is_registered() {
    use ciris_persist::federation::namespace::matcher::match_family;
    let mut found = Vec::new();
    walk(
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut found,
    );
    assert!(
        // 18 on 2026-09-28 (14 distinct), counted independently with grep.
        found.len() >= 10,
        "the scan found only {} dimension literals — the literal reader is broken, and a \
         gate that reads nothing passes everything",
        found.len()
    );
    // Positive control: the spelling that WAS refused still is. Without this a
    // matcher that stopped refusing would turn the gate green by itself.
    assert!(
        match_family("age_self_declared:adult:v1").refusal.is_some(),
        "the matcher no longer refuses the unregistered-reserved-stem spelling this gate \
         was written for — re-read what `refusal` means before trusting a green run"
    );
    let refused: Vec<String> = found
        .iter()
        .filter(|(_, dim)| !READ_ONLY_LEGACY.iter().any(|(l, _)| l == dim))
        .filter_map(|(file, dim)| {
            match_family(dim)
                .refusal
                .map(|r| format!("{file}: {dim} — {r:?}"))
        })
        .collect();
    assert!(
        refused.is_empty(),
        "{} dimension literal(s) in src/ are not registered families — persist's put door \
         refuses each one:\n  {}",
        refused.len(),
        refused.join("\n  ")
    );
}
