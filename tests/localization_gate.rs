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

/// The client's locale bundle, resolved from the INSTALLED package.
///
/// It used to be `client/shared/src/desktopMain/resources/localization`, one of
/// four byte-identical copies this repo carried by hand. `ciris-client[node]`
/// is the tree of record now (CIRISServer#471); the bundle is an artifact, and
/// where it lands is the package's business rather than a path we can hardcode.
fn locale_bundle() -> std::path::PathBuf {
    let out = std::process::Command::new("python3")
        .args([
            "-c",
            "import ciris_client;print(ciris_client.locale_bundle())",
        ])
        .output()
        .expect("resolve the ciris-client locale bundle");
    assert!(
        out.status.success(),
        "ciris-client is not importable, so this gate would examine NOTHING and \
         report clean — the zero-denominator failure it exists to prevent.\n\
         install it with: pip install 'ciris-client[node]==0.5.188'\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::path::PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

const GUARD: &str = "tools/check_server_localization.py";

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

/// Blank out every `#[cfg(test)]` item, so a test fixture cannot be mistaken
/// for a server-emitted message id.
///
/// A test has exactly the shape this file hunts for:
///
/// ```ignore
/// raise(Warning::error("t.reduced", "a plane is shed"));
/// ```
///
/// `src/degradation.rs` produced three such phantoms on first contact — ids no
/// server will ever emit, each demanding an en.json entry that would put test
/// strings into the shipped product bundle in 29 languages. Failing in the
/// direction of MORE findings is what made it look like diligence.
///
/// **This must stay byte-for-byte equivalent in behaviour to
/// `_without_test_modules` in `tools/check_server_localization.py`.** The
/// two scrapers exist to disagree — that is the whole point of
/// `rust_and_python_resolvers_agree_on_the_bundle` — so a rule added to one and
/// not the other is a red gate, and was: this fix landed on the Python side
/// first and the counts went 244 vs 241 within the hour.
///
/// Brace-matched rather than pattern-matched, because a test module nests and
/// the literals inside it carry braces, quotes and comment markers of their
/// own. Replaced with spaces rather than deleted, so byte offsets — and every
/// line number reported from them — stay honest.
/// Index of the closing quote if `c[start]` opens a Rust char literal.
///
/// `None` means the apostrophe is a LIFETIME or label tick, which closes
/// nothing and must be stepped over rather than tracked. Both directions are
/// load-bearing and they fail oppositely: treating `'{'` as two ordinary
/// characters runs the brace matcher past a test module's end and eats the
/// production emission sites after it, while treating `&'static str` as an
/// open char literal swallows the rest of the file the same way.
///
/// Escapes whose payload can itself contain braces (`'\u{7d}'`) are handled by
/// scanning to the terminating quote rather than assuming a fixed width, and
/// the scan is bounded so a malformed literal cannot run to EOF.
///
/// **Must stay behaviourally identical to `_char_literal_end` in
/// `tools/check_server_localization.py`.**
/// Index of the `{` opening the body of the item attributed at `attr_start`.
///
/// `None` when the item has NO body (`use`, `const`, `static`, a type alias) —
/// those end at a top-level semicolon, and treating the next item's `{` as
/// theirs is how a production emission site gets blanked.
///
/// Decided by which comes first at NESTING DEPTH ZERO, skipping the attribute's
/// own brackets and any string content, so `#[cfg(test)] const S: &str = "a {";`
/// is still recognised as brace-less.
///
/// **Must stay behaviourally identical to `_attributed_item_body` in
/// `tools/check_server_localization.py`.**
fn attributed_item_body(c: &[char], attr_start: usize) -> Option<usize> {
    let mut j = attr_start;
    let mut depth_brack = 0i32;
    let mut in_str = false;
    let mut esc = false;
    while j < c.len() {
        let ch = c[j];
        if esc {
            esc = false;
        } else if ch == '\\' && in_str {
            esc = true;
        } else if in_str {
            if ch == '"' {
                in_str = false;
            }
        } else if ch == 'r' && raw_string_end(c, j).is_some() {
            j = raw_string_end(c, j).unwrap_or(j) + 1;
            continue;
        } else if ch == '"' {
            in_str = true;
        } else if ch == '[' {
            depth_brack += 1;
        } else if ch == ']' {
            depth_brack -= 1;
        } else if depth_brack == 0 {
            if ch == '{' {
                return Some(j);
            }
            if ch == ';' {
                return None;
            }
        }
        j += 1;
    }
    None
}

/// Index of the final `"` of a Rust raw string starting at `c[start]`.
///
/// `None` if it does not begin one. Recognises `r"..."` and `r#*"..."#*`,
/// matching the closer to the SAME number of hashes — which is what lets a raw
/// string legally contain `"#` sequences.
///
/// **Must stay behaviourally identical to `_raw_string_end` in the Python
/// guard.**
fn raw_string_end(c: &[char], start: usize) -> Option<usize> {
    if c.get(start) != Some(&'r') {
        return None;
    }
    let mut k = start + 1;
    let mut hashes = 0usize;
    while c.get(k) == Some(&'#') {
        hashes += 1;
        k += 1;
    }
    if c.get(k) != Some(&'"') {
        return None;
    }
    let mut j = k + 1;
    while j < c.len() {
        if c[j] == '"' && (1..=hashes).all(|h| c.get(j + h) == Some(&'#')) {
            return Some(j + hashes);
        }
        j += 1;
    }
    None
}

fn char_literal_end(c: &[char], start: usize) -> Option<usize> {
    if c.get(start) != Some(&'\'') {
        return None;
    }
    let k = start + 1;
    if k >= c.len() {
        return None;
    }
    if c[k] == '\\' {
        let limit = c.len().min(start + 12);
        return (k + 1..limit).find(|&x| c[x] == '\'');
    }
    if c.get(k + 1) == Some(&'\'') {
        return Some(k + 1);
    }
    None
}

fn without_test_modules(text: &str) -> String {
    let mut out: Vec<char> = text.chars().collect();
    let len = out.len();
    let marker: Vec<char> = "#[cfg(test)]".chars().collect();
    let mut i = 0usize;
    while i < out.len() {
        if !out[i..].starts_with(&marker[..]) {
            i += 1;
            continue;
        }
        // Find this item's opening brace, then its match. Anything before the
        // brace (`mod tests`, further attributes) is inert either way.
        // A BRACE-LESS item (`use`, `const`, `static`, a type alias) ends at
        // its semicolon. Searching blindly for `{` adopts the opening brace of
        // the NEXT — production — item and blanks it. See
        // `attributed_item_body`.
        let Some(brace) = attributed_item_body(&out, i) else {
            let Some(semi) = (i..out.len()).find(|&k| out[k] == ';') else {
                break;
            };
            for slot in out.iter_mut().take(semi + 1).skip(i) {
                if *slot != '\n' {
                    *slot = ' ';
                }
            }
            i = semi + 1;
            continue;
        };
        let mut depth = 0i32;
        let mut j = brace;
        let (mut in_str, mut esc, mut in_line_comment) = (false, false, false);
        let mut block_depth = 0i32;
        while j < out.len() {
            let ch = out[j];
            if esc {
                esc = false;
            } else if ch == '\\' && in_str {
                esc = true;
            } else if in_line_comment {
                if ch == '\n' {
                    in_line_comment = false;
                }
            } else if block_depth > 0 {
                // NESTED: Rust block comments nest, so a boolean exits at the
                // first `*/` and counts the braces after it as syntax.
                if ch == '/' && out.get(j + 1) == Some(&'*') {
                    block_depth += 1;
                    j += 2;
                    continue;
                }
                if ch == '*' && out.get(j + 1) == Some(&'/') {
                    block_depth -= 1;
                    j += 2;
                    continue;
                }
            } else if in_str {
                if ch == '"' {
                    in_str = false;
                }
            } else if ch == '"' {
                in_str = true;
            } else if ch == 'r' && raw_string_end(&out, j).is_some() {
                // A RAW string. Its content may hold bare quotes AND braces,
                // and the ordinary state machine flips out of the string at the
                // first inner quote, then counts what follows as syntax.
                // Measured both ways: `r#"a" } "#` stops early (phantom
                // survives) and `r#"a" { "#` eats the production emission after
                // the module.
                j = raw_string_end(&out, j).unwrap_or(j) + 1;
                continue;
            } else if ch == '\'' {
                // CHAR LITERAL or LIFETIME — see `char_literal_end`. `'{'`
                // inside a test module would otherwise run this matcher past
                // the module's real end and blank every production emission
                // site after it.
                if let Some(e) = char_literal_end(&out, j) {
                    j = e + 1;
                    continue;
                }
            } else if ch == '/' && out.get(j + 1) == Some(&'/') {
                in_line_comment = true;
            } else if ch == '/' && out.get(j + 1) == Some(&'*') {
                block_depth = 1;
                j += 2;
                continue;
            } else if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            j += 1;
        }
        for slot in out.iter_mut().take((j + 1).min(len)).skip(i) {
            if *slot != '\n' {
                *slot = ' ';
            }
        }
        i = j + 1;
    }
    out.into_iter().collect()
}

/// Scrape the server's localizable strings: an `(id, english_text)` literal
/// pair, whatever helper wraps it — `m(id, text)`, `refusal(code, token, id,
/// text)`, or a bare `Msg` tuple. Matching the PAIR rather than one helper name
/// is what makes this cover all three emitters.
///
/// Returns id -> first emission site (repo-relative).
/// Dotted-id literals appearing as ARGUMENTS to an emitter helper, whatever
/// the remaining arguments look like.
///
/// The pair-matching scan above keys on the TEXT — a literal, or a `format!`.
/// An emission whose text is any other expression matched neither, so its id
/// was excluded from every server-id check and removing its bundle entry left
/// the strict gate green. Live at the time: `auth.oauth.provider_unavailable`
/// (followed by `&e.message()`) and `accord.duty.holder_custody` (followed by a
/// bound `msg`).
///
/// The helper list is derived from the source, not guessed: these are the
/// identifiers that actually enclose dotted-id literals in `src/`. "Any dotted
/// literal followed by a comma" sweeps in hostnames (`accounts.google.com`),
/// filenames (`libykcs11.dll`) and machine-only degradation CODES, which are a
/// different contract entirely.
///
/// **Must stay behaviourally identical to `_emitter_call_ids` in
/// `tools/check_server_localization.py`.**
fn emitter_call_ids(c: &[char], out: &mut Vec<String>) {
    const EMITTERS: [&str; 6] = ["m", "err", "msg", "refuse", "refusal", "browser_refusal"];
    let mut i = 0usize;
    while i < c.len() {
        if c[i] != '(' {
            i += 1;
            continue;
        }
        // The identifier immediately before this paren.
        let mut k = i;
        while k > 0 && c[k - 1].is_whitespace() {
            k -= 1;
        }
        let end = k;
        while k > 0
            && (c[k - 1].is_ascii_lowercase() || c[k - 1] == '_' || c[k - 1].is_ascii_digit())
        {
            k -= 1;
        }
        let name: String = c[k..end].iter().collect();
        // A QUALIFIED path is still an emitter call: `super::refusal::refuse(
        // ..., "auth.oauth.native_token_invalid", ...)` is the real site that
        // made these two scrapers disagree 302 vs 303. Only the final segment
        // identifies the helper, and the Python guard's `\b` boundary treats it
        // the same way — which is the behaviour of record, and what the
        // cross-check is comparing against.
        if EMITTERS.contains(&name.as_str()) {
            let mut depth = 0i32;
            let mut j = i;
            while j < c.len() {
                if c[j] == '(' {
                    depth += 1;
                } else if c[j] == ')' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            let mut p = i + 1;
            while p < j {
                if c[p] == '"' {
                    if let Some(lit) = read_plain_literal(c, p, 200) {
                        if is_message_id(&lit.0) {
                            out.push(lit.0);
                        }
                        p = lit.1;
                        continue;
                    }
                }
                p += 1;
            }
        }
        i += 1;
    }
}

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
        // Same rule as the Python guard, or the cross-check below goes red.
        let text = without_test_modules(&text);
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        let c: Vec<char> = text.chars().collect();
        // Ids in emitter-call argument position, whatever follows them.
        let mut emitted: Vec<String> = Vec::new();
        emitter_call_ids(&c, &mut emitted);
        for mid in emitted {
            ids.entry(mid).or_insert_with(|| rel.clone());
        }
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
                // **THE SAME ID POSITION WITH A COMPUTED TEXT** — `format!(...)`
                // rather than a literal. Neither scraper could see these, so
                // every server-id check silently excluded them and the
                // denominator overstated coverage. Live example:
                // `mesh_config.refusal.store_unavailable`, absent from en.json
                // while the guard reported all 241 examined ids covered.
                //
                // The ID is taken from both shapes; the exact SOURCE-TEXT
                // comparison stays restricted to the literal shape, because a
                // `format!` template is not a string this checker can evaluate.
                //
                // Must stay behaviourally identical to
                // `_SERVER_MSG_ID_FORMATTED` in the Python guard — the
                // cross-check below is what caught this one mirrored and one
                // not, within a single test run.
                if c[j..].starts_with(&"format!".chars().collect::<Vec<_>>()[..]) {
                    let mut k = j + "format!".len();
                    while k < c.len() && c[k].is_whitespace() {
                        k += 1;
                    }
                    if k < c.len() && c[k] == '(' {
                        ids.entry(id.0.clone()).or_insert_with(|| rel.clone());
                    }
                }
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
    let path = locale_bundle().join("en.json");
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

/// The Python guard must pass on the committed tree — **at the strictness CI
/// uses**.
///
/// # Why `--strict`, and why that word is load-bearing
///
/// `.github/workflows/localization.yml` runs the guard with `--strict`, which
/// fails on WARNINGS as well as errors. This test ran it bare, so a tree with
/// translation drift — 28 languages missing a key someone added after the last
/// fan-out — was GREEN locally and RED in CI. That happened, on this branch.
///
/// A local gate weaker than the CI gate it mirrors is worse than no local gate:
/// it does not merely fail to catch the problem, it actively reports that there
/// isn't one. The developer pushes on its word. Two invocations of one script,
/// disagreeing about what counts as a failure, is the same two-authors shape this
/// repo keeps paying for — one plane over, in the tooling rather than the data.
#[test]
fn localization_bundles_pass_the_guard() {
    let out = Command::new("python3")
        .arg(repo_root().join(GUARD))
        // The SAME flag CI passes. If CI's invocation changes, this must follow it
        // — a green `cargo test` has to mean a green pipeline or it means nothing.
        .arg("--strict")
        .current_dir(repo_root())
        .output()
        .expect("python3 not available to run the localization guard");
    assert!(
        out.status.success(),
        "{GUARD} --strict failed on the committed tree:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// **The local gate must invoke the guard exactly as CI does.**
///
/// The drift above was invisible because nothing compared the two call sites.
/// This reads the workflow and asserts every flag CI passes to the guard is
/// passed here too — so the next flag CI gains cannot silently make this test
/// the weaker of the pair.
#[test]
fn the_local_gate_matches_ci_strictness() {
    let wf = std::fs::read_to_string(repo_root().join(".github/workflows/localization.yml"))
        .expect("read the localization workflow")
        .replace("\r\n", "\n");
    let this = std::fs::read_to_string(repo_root().join("tests/localization_gate.rs"))
        .expect("read this file")
        .replace("\r\n", "\n");

    // Every flag CI hands the guard, other than the self-test rung this file
    // exercises separately.
    let mut ci_flags: Vec<&str> = wf
        .lines()
        .filter(|l| l.contains(GUARD))
        .flat_map(|l| l.split_whitespace())
        .filter(|w| w.starts_with("--") && *w != "--self-test")
        .collect();
    ci_flags.sort_unstable();
    ci_flags.dedup();
    assert!(
        !ci_flags.is_empty(),
        "found no guard flags in the workflow — this check is now vacuous, which is worse than \
         absent. Did the workflow stop invoking {GUARD} by that path?"
    );
    for f in ci_flags {
        assert!(
            this.contains(&format!("\"{f}\"")),
            "CI runs the localization guard with `{f}` and this test does not. A local gate that \
             is weaker than its CI twin reports success on a tree CI will reject — the developer \
             pushes on its word. Add `.arg(\"{f}\")` above."
        );
    }
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

/// **A `#[cfg(test)]` fixture is not a server emission** — pinned HERE, not
/// only through the Python cross-check.
///
/// `rust_and_python_resolvers_agree_on_the_bundle` compares the two scrapers
/// and is what caught this rule landing on the Python side alone (244 vs 241).
/// But agreement is not correctness: if both scrapers drifted the same way,
/// that check would stay green over two identically-wrong answers. So each side
/// pins the RULE directly — this test, and
/// `_prove_test_fixtures_are_not_server_emissions` in the Python guard.
///
/// The fixture below is deliberately awkward: a literal containing a brace and
/// an escaped quote, a `//` comment holding an unbalanced brace, and a nested
/// module. A naive brace-counter walks off the end of any one of them and eats
/// the rest of the file — which reads as "no findings", the most expensive way
/// for a gate to fail.
#[test]
fn a_cfg_test_module_contributes_no_message_ids() {
    // Each case carries ONE hostile construct, UNBALANCED. The first cut put
    // `'{'` and `'}'` in the same fixture, where they cancel — so removing the
    // char-literal handling entirely still passed. A fixture whose hazards
    // balance is not a test of anything.
    //
    // And the production emission sites bracket the test module on BOTH sides:
    // appended at EOF, over-eating is invisible, because blanking to
    // end-of-file destroys nothing.
    let cases: [(&str, &str); 12] = [
        ("open brace char literal", "fn f() -> char { '{' }"),
        ("close brace char literal", "fn f() -> char { '}' }"),
        ("escaped quote char literal", r"fn f() -> char { '\'' }"),
        ("unicode close brace", r"fn f() -> char { '\u{7d}' }"),
        (
            "lifetime, which closes nothing",
            "fn f() -> &'static str { \"x\" }",
        ),
        ("unbalanced brace in a line comment", "// a stray } here"),
        (
            "unbalanced brace in a block comment",
            "/* a stray { here */",
        ),
        // Rust block comments NEST: a boolean exits at the first `*/` and
        // counts what follows as syntax.
        (
            "nested block comment, close brace after inner",
            "/* outer /* inner */ } still outer */",
        ),
        (
            "nested block comment, open brace after inner",
            "/* outer /* inner */ { still outer */",
        ),
        // Raw strings: the content may hold BARE quotes and braces, and the
        // ordinary string state machine flips out at the first inner quote and
        // then counts what follows as syntax. Both directions measured.
        (
            "raw string, bare quote then close",
            "const S: &str = r#\"a\" } \"#;",
        ),
        (
            "raw string, bare quote then open",
            "const S: &str = r#\"a\" { \"#;",
        ),
        (
            "raw string with a hash inside",
            "const S: &str = r##\"a \"# } \"##;",
        ),
    ];

    for (label, hostile) in cases {
        let src = format!(
            "fn before() -> Value {{ m(\"nav.home\", \"Home, the operator landing surface.\") }}\n\
             \n\
             #[cfg(test)]\n\
             mod tests {{\n    {hostile}\n    \
             fn phantom() {{ raise(m(\"t.phantom\", \"an id no server will ever emit\")); }}\n\
             }}\n\
             \n\
             fn after() -> Value {{ m(\"nav.away\", \"Away, the other operator surface.\") }}\n"
        );
        let stripped = without_test_modules(&src);

        assert!(
            stripped.contains("nav.home"),
            "[{label}] the stripper ate a production emission site BEFORE the test module"
        );
        assert!(
            stripped.contains("nav.away"),
            "[{label}] the stripper ran past the test module's real end and ate the production \
             emission site AFTER it. That reads as 'no findings', which is indistinguishable \
             from a clean file — the most expensive way for this gate to fail:\n{stripped}"
        );
        assert!(
            !stripped.contains("t.phantom"),
            "[{label}] the matcher stopped early and left the fixture in the scan, so a test \
             string will be demanded in en.json in 29 languages:\n{stripped}"
        );
        assert_eq!(
            stripped.lines().count(),
            src.lines().count(),
            "[{label}] the stripper must replace with spaces, never delete — byte offsets and \
             every line number derived from them have to stay honest"
        );
    }
}

/// **A brace-less `#[cfg(test)]` item ends at its SEMICOLON.**
///
/// `use`, `const`, `static` and type aliases are all valid attribute targets
/// and have no body. Searching blindly for the next `{` adopts the opening
/// brace of the following — production — item and blanks it, so a real
/// server-emitted id silently disappears from both coverage checks. Measured:
/// `#[cfg(test)] use foo::bar;` ate the emission after it.
#[test]
fn a_brace_less_cfg_test_item_does_not_swallow_the_next_item() {
    let items: [(&str, &str); 6] = [
        ("use", "use foo::bar;"),
        ("const", "const N: usize = 3;"),
        ("static", "static S: u8 = 1;"),
        (
            "type alias",
            "type T = std::collections::HashMap<String, u8>;",
        ),
        // The semicolon search must not be fooled by a brace inside a literal.
        ("const holding a brace", "const S: &str = \"a { brace\";"),
        (
            "const holding a raw brace",
            "const S: &str = r#\"a { brace\"#;",
        ),
    ];
    for (label, item) in items {
        let src = format!(
            "#[cfg(test)]\n{item}\n\
             fn after() -> Value {{ m(\"nav.away\", \"Away, the other operator surface.\") }}\n"
        );
        let stripped = without_test_modules(&src);
        assert!(
            stripped.contains("nav.away"),
            "[{label}] a brace-less #[cfg(test)] item swallowed the production item after it. \
             The emission disappears from the scan, which reads as a clean file:\n{stripped}"
        );
    }
}

/// A NESTED test module must go too — a matcher that stops at the first inner
/// `}` leaves the deeper fixture in the scan.
#[test]
fn a_nested_test_module_is_stripped_with_its_parent() {
    let src = "fn before() -> Value { m(\"nav.home\", \"Home, the operator landing surface.\") }\n\
               #[cfg(test)]\n\
               mod tests {\n\
                   mod nested { fn d() { raise(m(\"t.deeper\", \"a phantom one level down\")); } }\n\
               }\n\
               fn after() -> Value { m(\"nav.away\", \"Away, the other operator surface.\") }\n";
    let stripped = without_test_modules(src);
    assert!(
        !stripped.contains("t.deeper"),
        "a nested module survived the strip:\n{stripped}"
    );
    assert!(
        stripped.contains("nav.home") && stripped.contains("nav.away"),
        "the nested strip ate production emission sites:\n{stripped}"
    );
}
