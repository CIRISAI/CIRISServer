//! Localization reachability gate (CIRISServer#366).
//!
//! The operator surfaces never send a sentence. They send `{id, text}` — a
//! stable id a UI resolves in the reader's language, plus the English source to
//! fall back to (`operator_surface.rs::SOURCE_LOCALE`). That id is a
//! localization key with **no Kotlin call site**, so nothing that scans
//! `commonMain` has ever looked at it.
//!
//! The client resolves it with `LocalizationManager.resolveKey`
//! (client/shared/src/commonMain/…/localization/LocalizationManager.kt:296),
//! which ALWAYS splits the key on `.` and walks nested JSON objects, and never
//! falls back to an exact top-level match. So a key stored flat —
//! `{"mesh_config.ttl.expired": "…"}` — resolves to null. The English fallback
//! path calls the same function, so a flat key in `en.json` is dead for every
//! reader in every language.
//!
//! That is not hypothetical: commit `0c728b1` shipped all 53 ids flat. They were
//! present, byte-identical across all four runtime bundles, and completely
//! unreachable — and `check_localization_sync.py` was green throughout, because
//! it compared FLATTENED key sets, and flattening maps the nested form and the
//! flat form onto the same dotted string. To a key-set comparison a flat key and
//! a nested key are the same key. Data fixed in `26605b5`.
//!
//! This file is the release-gate rung. It ports `resolveKey` into Rust and
//! asserts against the real bundle, so the invariant is checked by `cargo test`
//! and not only by the Python guard. The Python guard's own mutation self-test
//! is asserted here too — a gate that has never been shown able to fail is not
//! evidence, and that includes this one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

const CANONICAL_BUNDLE: &str = "client/shared/src/desktopMain/resources/localization";
const GUARD: &str = "client/tools/check_localization_sync.py";

/// **Faithful port of `LocalizationManager.resolveKey`.** Keep in step with the
/// Kotlin; it is the definition of "this id works at runtime".
///
/// ```kotlin
/// val parts = key.split(".")
/// var current: JsonElement = obj
/// for (part in parts) {
///     current = when (current) { is JsonObject -> current[part] ?: return null; else -> return null }
/// }
/// return when (current) { is JsonPrimitive -> current.contentOrNull; else -> null }
/// ```
///
/// Note what it does NOT do: there is no exact top-level match anywhere in it.
fn resolve_key(obj: &Value, key: &str) -> Option<String> {
    let mut current = obj;
    for part in key.split('.') {
        current = match current {
            Value::Object(map) => map.get(part)?,
            _ => return None,
        };
    }
    match current {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Every leaf address in the document, in the dotted form a caller would use.
/// Deliberately blind to nested-vs-flat — that blindness is what made the old
/// key-parity check green over #366, and it is why "defined" and "reachable"
/// are asked as two separate questions below.
fn leaf_addresses(obj: &Value, prefix: &str, out: &mut Vec<String>) {
    if let Value::Object(map) = obj {
        for (k, v) in map {
            if prefix.is_empty() && k == "_meta" {
                continue;
            }
            let addr = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            match v {
                Value::Object(_) => leaf_addresses(v, &addr, out),
                _ => out.push(addr),
            }
        }
    }
}

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Scrape the server's localizable strings: an `(id, english_text)` literal
/// pair, whatever helper wraps it — `m(id, text)`, `refusal(code, token, id,
/// text)`, or a bare `Msg` tuple. Matching the PAIR rather than one helper name
/// is what makes this cover all three emitters.
///
/// Returns id -> first emission site (repo-relative).
fn server_message_ids() -> BTreeMap<String, String> {
    let root = repo_root();
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    files.sort();

    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        let c: Vec<char> = text.chars().collect();
        // Scan for the PATTERN at every position, exactly as the Python guard's
        // regex does — deliberately NOT a string-state machine.
        //
        // The first cut of this tried to track string state, and on hitting a
        // `\` inside a literal it resynced mid-string, which flipped quote
        // parity for the rest of the file. Every English text in
        // operator_surface.rs is a `\`-continued multi-line literal, so it
        // desynced on the first one and found 9 ids instead of 137 — caught
        // only by the `ids.len() >= 100` denominator assert below, which is the
        // entire argument of #366 landing on its own author.
        let mut i = 0usize;
        while i + 1 < c.len() {
            if c[i] != '"' {
                i += 1;
                continue;
            }
            let Some(id) = read_plain_literal(&c, i, 200) else {
                i += 1;
                continue;
            };
            if !is_message_id(&id.0) {
                i += 1;
                continue;
            }
            // `, "` — the (id, english_text) pair shape
            let mut j = id.1;
            while j < c.len() && c[j].is_whitespace() {
                j += 1;
            }
            if j >= c.len() || c[j] != ',' {
                i += 1;
                continue;
            }
            j += 1;
            while j < c.len() && c[j].is_whitespace() {
                j += 1;
            }
            if j >= c.len() || c[j] != '"' {
                i += 1;
                continue;
            }
            // Only the head of the text matters: an English sentence has a space.
            let tstart = j + 1;
            let tend = (tstart..c.len().min(tstart + 80))
                .find(|&k| c[k] == '"' || c[k] == '\\')
                .unwrap_or(c.len().min(tstart + 80));
            if !c[tstart..tend].contains(&' ') {
                i += 1;
                continue; // not an English sentence — not an (id, text) pair
            }
            ids.entry(id.0).or_insert_with(|| rel.clone());
            i += 1;
        }
    }
    ids
}

/// Read a plain (unescaped, single-line) string literal opening at `open`.
/// Returns (contents, index just past the closing quote). `None` if the literal
/// contains a backslash or newline, or runs past `max_len` — a message id never
/// does any of those, so rejecting them costs nothing and keeps this from
/// having to understand Rust string escaping.
fn read_plain_literal(c: &[char], open: usize, max_len: usize) -> Option<(String, usize)> {
    let start = open + 1;
    let mut k = start;
    while k < c.len() && k - start <= max_len {
        match c[k] {
            '"' => return Some((c[start..k].iter().collect(), k + 1)),
            '\\' | '\n' => return None,
            _ => k += 1,
        }
    }
    None
}

fn is_message_id(s: &str) -> bool {
    if !s.contains('.') {
        return false;
    }
    let mut segments = s.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if !first.starts_with(|c: char| c.is_ascii_lowercase()) {
        return false;
    }
    s.split('.').all(|seg| {
        !seg.is_empty()
            && seg
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    })
}

/// Scrape the emission sites and REFUSE to return a suspiciously small set.
///
/// Every test that reasons about server ids goes through here. The first cut of
/// this file had a scraper bug that found 9 ids instead of 137; the reachability
/// test caught it, but the coverage ratchet went green — `9 uncovered <= 84`
/// is true, and completely meaningless. A ratchet over a broken instrument is
/// the #366 defect wearing a different hat, so the floor lives here, not in one
/// test.
fn scraped_server_ids() -> BTreeMap<String, String> {
    let ids = server_message_ids();
    assert!(
        ids.len() >= 100,
        "scraped only {} server-emitted message ids from src/**/*.rs — the scraper has stopped \
         seeing the emission sites, so EVERY assertion built on it is now vacuous (a finding of \
         zero over a denominator of zero is not evidence). Expected ~137; fix the scraper before \
         trusting any green result here.",
        ids.len()
    );
    ids
}

fn load_en() -> Value {
    let path = repo_root().join(CANONICAL_BUNDLE).join("en.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("canonical en.json unreadable at {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("canonical en.json is not valid JSON")
}

/// **The #366 invariant.** Every server-emitted id that `en.json` DEFINES must
/// be REACHABLE by the loader. Defined-but-unreachable is strictly worse than
/// absent: the bundle claims the string is localized, all four runtime bundles
/// agree, and the lookup still returns null with no diagnostic anywhere.
#[test]
fn server_emitted_message_ids_resolve_under_loader_semantics() {
    let en = load_en();
    let ids = scraped_server_ids();

    let mut defined = Vec::new();
    leaf_addresses(&en, "", &mut defined);
    let defined: std::collections::BTreeSet<String> = defined.into_iter().collect();

    let unreachable: Vec<(&String, &String)> = ids
        .iter()
        .filter(|(id, _)| defined.contains(*id) && resolve_key(&en, id).is_none())
        .collect();

    assert!(
        unreachable.is_empty(),
        "{} server-emitted id(s) are DEFINED in en.json but UNREACHABLE by \
         LocalizationManager.resolveKey — stored as flat dotted keys, so the lookup returns \
         null and the operator sees the raw id in every language including English \
         (this is CIRISServer#366, shipped in 0c728b1): {:?}",
        unreachable.len(),
        unreachable
            .iter()
            .take(10)
            .map(|(id, site)| format!("{id} ({site})"))
            .collect::<Vec<_>>()
    );
}

/// The other half of the same surface: ids the bundle never defines at all.
///
/// These degrade to the English `text` the wire already carries, so they are not
/// a runtime break — but they cannot be localized into ANY of the 29 languages.
/// This is a RATCHET, not a pass: the count may only go down. Adding a new
/// un-localizable operator sentence turns this red.
#[test]
fn server_emitted_message_id_coverage_does_not_regress() {
    /// Measured on 26605b5: 137 emitted ids, 53 defined in en.json, 84 with no
    /// entry (operator_surface.rs 62, admin_ops.rs 13, mesh_config_surface.rs 9).
    /// Lower this as `localize-ui` works the list off. Never raise it.
    const MAX_UNCOVERED: usize = 84;

    let en = load_en();
    let ids = scraped_server_ids();
    let mut defined = Vec::new();
    leaf_addresses(&en, "", &mut defined);
    let defined: std::collections::BTreeSet<String> = defined.into_iter().collect();

    let uncovered: Vec<&String> = ids.keys().filter(|id| !defined.contains(*id)).collect();

    assert!(
        uncovered.len() <= MAX_UNCOVERED,
        "server-emitted message ids with no en.json entry grew from {} to {} — an operator \
         sentence was added that cannot be localized into any of the 29 languages. Add the id \
         to en.json (NESTED, never flat) and run the `localize-ui` workflow.\n\
         This ratchet stores only a count, so it cannot tell you WHICH id is new; diff this \
         list against the previous run. All {} uncovered, sorted: {:?}",
        MAX_UNCOVERED,
        uncovered.len(),
        uncovered.len(),
        uncovered
    );
}

/// The Python guard must pass on the committed tree.
#[test]
fn localization_bundles_pass_the_guard() {
    let out = Command::new("python3")
        .arg(repo_root().join(GUARD))
        .current_dir(repo_root())
        .output()
        .expect("python3 not available to run the localization guard");
    assert!(
        out.status.success(),
        "{GUARD} failed on the committed tree:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// **The gate on the gate.** `--self-test` breaks a synthetic bundle 23 ways —
/// flattening a nested key, desyncing each of the three mirror bundles,
/// corrupting a named and a printf placeholder, invalid JSON, a zero
/// denominator — and asserts every check fires with a message naming the break.
/// If the guard has lost the ability to fail, its green run above proves
/// nothing, so this asserts the ability first.
#[test]
fn localization_guard_self_test_proves_it_can_fail() {
    let out = Command::new("python3")
        .arg(repo_root().join(GUARD))
        .arg("--self-test")
        .current_dir(repo_root())
        .output()
        .expect("python3 not available to run the localization guard self-test");
    assert!(
        out.status.success(),
        "the localization guard can no longer detect one of the breaks it claims to \
         detect — every green run of it is therefore worthless:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// The Rust port here and the Python port in the guard must agree, or one of
/// them is quietly measuring something else and only one of them is a gate.
///
/// This compares DENOMINATORS, not verdicts. Two implementations that both say
/// "0 findings" while looking at different-sized populations agree on nothing —
/// which is precisely how this file's first scraper (9 ids) sat next to the
/// Python one (137) and produced a green test.
#[test]
fn rust_and_python_resolvers_agree_on_the_bundle() {
    let en = load_en();
    let mut addrs = Vec::new();
    leaf_addresses(&en, "", &mut addrs);
    assert!(
        addrs.len() > 2000,
        "only {} leaf addresses in en.json — the walker is not seeing the bundle",
        addrs.len()
    );
    let unreachable = addrs
        .iter()
        .filter(|a| resolve_key(&en, a).is_none())
        .count();
    assert_eq!(
        unreachable, 0,
        "{unreachable} address(es) in en.json are unreachable by the ported resolver"
    );

    // The guard prints every check's denominator; hold the two scrapers to the
    // same number of emission sites.
    let out = Command::new("python3")
        .arg(repo_root().join(GUARD))
        .current_dir(repo_root())
        .output()
        .expect("python3 not available to run the localization guard");
    let stdout = String::from_utf8_lossy(&out.stdout);

    // EXACTLY ONE line may name the check. A `find()` here — first match wins —
    // is correct today only because `_print_report` happens to emit the
    // check-summary block before the ERRORS block, so the summary is always the
    // first hit. That is ordering luck, not construction: the day an error
    // message quotes the check name, the parse reads a number off the wrong line
    // and this test goes on reporting that the two scrapers agree.
    //
    // The failure mode is worth naming because this suite has now produced it
    // twice from two directions. The release ladder's own mutation harness read
    // the FIRST `test result:` line out of cargo's output and reported PASS for
    // runs that had failed — because the gate's failure MESSAGE quotes the string
    // "test result: ok. 0 passed". An instrument that locates its input by
    // first-match text search is measuring position, not content.
    let named: Vec<&str> = stdout
        .lines()
        .filter(|l| l.contains("server-id-reachable"))
        .collect();
    assert_eq!(
        named.len(),
        1,
        "the guard's output names `server-id-reachable` on {} lines, so there is no single \
         denominator to read. Whichever line a first-match parse picked would be a number this \
         test then compared with confidence it had not earned.\n\
         lines:\n{}\n\nfull output:\n{stdout}",
        named.len(),
        named.join("\n"),
    );
    let python_ids = named[0]
        .split("over ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or_else(|| {
            panic!("could not read the server-id denominator from the guard output:\n{stdout}")
        });
    let rust_ids = scraped_server_ids().len();
    assert_eq!(
        rust_ids, python_ids,
        "the Rust scraper in this file sees {rust_ids} server-emitted ids and the Python guard \
         sees {python_ids}. One of them has drifted, and whichever sees fewer is silently \
         exempting emission sites from its gate."
    );
}
