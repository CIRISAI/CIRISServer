//! **No raw roster reads** — `FSD/ROSTER_AND_DRIVE_CRUD.md` §1 rule 3.
//!
//! persist v48 (CIRISPersist#860) keeps a room's roster as ONE record plus two
//! append-only planes — widenings and revocations — and never rewrites the
//! record to grow. So `community.members` / `family.members` is the FOUNDING
//! roster: it misses every member added since and still names every member
//! removed. A membership decision made on it is wrong the moment a room
//! changes, and wrong silently — five sites in `src/` did exactly that until
//! 0.5.216 (`start_chat`'s pair check twice, `other_member`, `send_message`'s
//! recipient, `safety/named.rs`'s existence verdict and auto-promotion).
//!
//! Membership goes through the fold: persist's `effective_roster` /
//! `is_active_community_member` / `active_*_members` (or this crate's
//! `contacts_chat::active_roster`, which is `effective_roster`).
//!
//! # What this gate does
//!
//! Reads every `.rs` under `src/` with comments stripped (a comment that
//! EXPLAINS the rule must not trip it — the lesson of the
//! `owner_signer_capsule` gate), attributes every `.members` field access to
//! the WHOLE function body it sits in (no fixed-size windows: a window both
//! misses a long function's tail and bleeds into the next function), and
//! fails on any access that is not on [`ALLOWED`] — keyed by file, function
//! AND receiver, each with the reason it is not a membership decision.
//!
//! It also fails on an allow-list entry that no longer matches anything, so
//! the list can only describe code that exists.

use std::path::{Path, PathBuf};

/// `(file under src/, enclosing fn, receiver expression, why it is allowed)`.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "src/family_api.rs",
        "create_family",
        "req",
        "REQUEST VALIDATION: the members the caller asked to found the family with, checked for registration before any record exists",
    ),
    (
        "src/family_api.rs",
        "add_member",
        "grown",
        "RECORD CONSTRUCTION: the grown record this handler signs and submits (families have no widening plane at persist v48; the record IS how a family grows)",
    ),
    (
        "src/family_api.rs",
        "check_addable",
        "loaded.family",
        "REFUSES A RE-ADD ONLY: a key already on the record is refused (`family.already_member` / `family.readd_unsupported`); membership itself is decided through the fold",
    ),
    (
        "src/family_api.rs",
        "leave_inner",
        "loaded.family",
        "RECORD CONSTRUCTION: a quorum family's record is rewritten minus the leaver so verify's prior-roster binding (persist builds it from the record, not the fold) stays satisfiable",
    ),
    (
        "src/family_api.rs",
        "leave_inner",
        "next",
        "RECORD CONSTRUCTION: the rewritten roster assigned to the record being signed",
    ),
    (
        "src/family_api.rs",
        "change_role",
        "next",
        "RECORD CONSTRUCTION: setting the role on the record being signed",
    ),
    (
        "src/family_api.rs",
        "terminal_dissolve",
        "next",
        "RECORD CONSTRUCTION: the empty roster of the terminal supersede",
    ),
    (
        "src/family_api.rs",
        "change_envelope",
        "loaded.family",
        "VERIFY'S BINDING: `supersedes.prior_member_key_ids` must equal the RECORD's roster in order; a quorum family's record is kept equal to its fold",
    ),
    (
        "src/family_api.rs",
        "assemble",
        "loaded.family",
        "VERIFY'S BINDING: joined_at of an envelope member is read from the record the quorum verifies against",
    ),
    (
        "src/family_api.rs",
        "assemble",
        "next",
        "RECORD CONSTRUCTION: the assembled roster assigned to the record being signed",
    ),
    (
        "src/accord.rs",
        "family_supersede",
        "new.family",
        "RECORD CONSTRUCTION: the count of the family record this handler just \
         built from a quorum-verified change envelope, reported in the response",
    ),
    (
        "src/accord_reactivate.rs",
        "reactivate_accord",
        "family",
        "the FOUNDING roster is the question: the genesis-continuity check wants the \
         accord as originally constituted (version 1, or the never-superseded \
         record), deliberately not today's fold",
    ),
    (
        "src/quorum.rs",
        "verify_canonical_quorum",
        "community",
        "not a persist Community: verify's `InfrastructureCommunity` founder set, \
         which has no widening or revocation plane",
    ),
    (
        "src/compose_policy.rs",
        "pin_founder_quorum",
        "community",
        "not a persist Community: verify's `InfrastructureCommunity` founder set",
    ),
    (
        "src/communities.rs",
        "create_community",
        "req",
        "not a roster: the create request's list of initial members, validated \
         and turned INTO the record",
    ),
    (
        "src/contacts_chat.rs",
        "ensure_room_addresses",
        "installed",
        "not a persist roster: edge's MLS `RosterSnapshot` of the room's group \
         (node members for the scope-address table)",
    ),
    (
        "src/self_room_drive.rs",
        "*",
        "snap",
        "not a persist roster: edge's MLS snapshot of the self room, logged",
    ),
];

/// Strip `//` and `/* */` comments, keeping string and char literals intact
/// (a `//` inside a string is not a comment) and every newline (so reported
/// line numbers stay true).
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if b[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
            continue;
        }
        if c == b'"' {
            // A (non-raw) string literal: copy through, honouring escapes.
            out.push('"');
            i += 1;
            while i < b.len() {
                let d = b[i];
                if d == b'\\' && i + 1 < b.len() {
                    out.push_str(&src[i..i + 2]);
                    i += 2;
                    continue;
                }
                let ch_len = utf8_len(d);
                out.push_str(&src[i..i + ch_len]);
                i += ch_len;
                if d == b'"' {
                    break;
                }
            }
            continue;
        }
        let ch_len = utf8_len(c);
        out.push_str(&src[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// Every function in `text`, as `(name, body byte range)` — the body from the
/// opening `{` to its matching `}`. Nested functions (closures are not `fn`)
/// appear as their own entries; an access is attributed to the INNERMOST one.
fn functions(text: &str) -> Vec<(String, std::ops::Range<usize>)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(pos) = text[search..].find("fn ") {
        let at = search + pos;
        search = at + 3;
        // `fn` must be a whole word.
        if at > 0 && (b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_') {
            continue;
        }
        let name: String = text[at + 3..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // The body's `{`: the first one at paren/angle depth 0 before a `;`
        // (a `;` first means a declaration with no body — a trait method).
        let mut j = at + 3 + name.len();
        let mut paren = 0i32;
        let mut open = None;
        while j < b.len() {
            match b[j] {
                b'(' | b'[' => paren += 1,
                b')' | b']' => paren -= 1,
                b';' if paren == 0 => break,
                b'{' if paren == 0 => {
                    open = Some(j);
                    break;
                }
                b'"' => {
                    j += 1;
                    while j < b.len() && b[j] != b'"' {
                        if b[j] == b'\\' {
                            j += 1;
                        }
                        j += 1;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let Some(open) = open else { continue };
        let mut depth = 0i32;
        let mut k = open;
        while k < b.len() {
            match b[k] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b'"' => {
                    k += 1;
                    while k < b.len() && b[k] != b'"' {
                        if b[k] == b'\\' {
                            k += 1;
                        }
                        k += 1;
                    }
                }
                b'\'' => {
                    // A char literal like '{' must not count; a lifetime has no
                    // closing quote within two chars and is stepped over.
                    if b.get(k + 2) == Some(&b'\'') {
                        k += 2;
                    } else if b.get(k + 1) == Some(&b'\\') && b.get(k + 3) == Some(&b'\'') {
                        k += 3;
                    }
                }
                _ => {}
            }
            k += 1;
        }
        out.push((name, open..k.min(b.len())));
    }
    out
}

/// The receiver expression just before `.members` at byte `dot`: the
/// identifier chain (`a.b.c`), whitespace-tolerant across a line break.
fn receiver(text: &str, dot: usize) -> String {
    let b = text.as_bytes();
    let mut j = dot;
    while j > 0 && b[j - 1].is_ascii_whitespace() {
        j -= 1;
    }
    let end = j;
    while j > 0 && (b[j - 1].is_ascii_alphanumeric() || b[j - 1] == b'_' || b[j - 1] == b'.') {
        j -= 1;
    }
    text[j..end].trim_matches('.').to_owned()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src/") {
        let p = entry.expect("dir entry").path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

struct Access {
    file: String,
    function: String,
    receiver: String,
    line: usize,
}

fn accesses() -> Vec<Access> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    let mut out = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(root)
            .expect("under the manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let text = strip_comments(&std::fs::read_to_string(&f).expect("read"));
        let fns = functions(&text);
        let mut search = 0;
        while let Some(pos) = text[search..].find(".members") {
            let at = search + pos;
            search = at + ".members".len();
            // A whole field name: `.members_json` / `.members()` are others.
            let next = text.as_bytes().get(search).copied();
            if next.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'(') {
                continue;
            }
            let function = fns
                .iter()
                .filter(|(_, r)| r.contains(&at))
                .min_by_key(|(_, r)| r.len())
                .map_or_else(|| "<module>".to_owned(), |(n, _)| n.clone());
            out.push(Access {
                file: rel.clone(),
                function,
                receiver: receiver(&text, at),
                line: text[..at].matches('\n').count() + 1,
            });
        }
    }
    out
}

fn allowed(a: &Access) -> bool {
    ALLOWED.iter().any(|(file, function, recv, _)| {
        *file == a.file && (*function == "*" || *function == a.function) && *recv == a.receiver
    })
}

#[test]
fn no_membership_decision_reads_the_raw_roster() {
    let all = accesses();
    assert!(
        !all.is_empty(),
        "the gate found no `.members` access at all — it is looking at nothing"
    );
    let bad: Vec<String> = all
        .iter()
        .filter(|a| !allowed(a))
        .map(|a| {
            format!(
                "  {}:{} in fn {} — `{}.members`",
                a.file, a.line, a.function, a.receiver
            )
        })
        .collect();
    assert!(
        bad.is_empty(),
        "raw roster read(s) — v48 never grows the record, so `.members` is the FOUNDING \
         roster, not who is in the room. Read through persist's `effective_roster` / \
         `is_active_community_member` (or `contacts_chat::active_roster`). If this is \
         not a membership decision, add it to ALLOWED in tests/no_raw_roster_reads.rs \
         with the reason:\n{}",
        bad.join("\n")
    );
}

#[test]
fn every_allow_list_entry_still_matches_code() {
    let all = accesses();
    let stale: Vec<String> = ALLOWED
        .iter()
        .filter(|(file, function, recv, _)| {
            !all.iter().any(|a| {
                a.file == *file
                    && (*function == "*" || a.function == *function)
                    && a.receiver == *recv
            })
        })
        .map(|(file, function, recv, _)| format!("{file} fn {function} `{recv}.members`"))
        .collect();
    assert!(
        stale.is_empty(),
        "allow-list entries that match nothing (remove them — an exemption that \
         outlives its code silently covers the next raw read): {stale:?}"
    );
}

/// The gate can fail: a synthetic raw read is found and attributed to its
/// whole function, past a comment that mentions `.members` and past a long
/// body a fixed window would have cut.
#[test]
fn the_gate_sees_a_raw_read_in_a_long_function_and_not_in_a_comment() {
    let src = format!(
        "fn a() {{ let x = 1; }}\n\
         // community.members in a comment is not a read\n\
         fn decide(c: &Community) -> bool {{\n{}    c.members.iter().any(|m| m.key_id == \"k\")\n}}\n\
         fn b() {{ let s = \"{{ community.members }}\"; }}\n",
        "    let pad = 0;\n".repeat(400)
    );
    let text = strip_comments(&src);
    let fns = functions(&text);
    let hits: Vec<(String, String)> = text
        .match_indices(".members")
        .map(|(at, _)| {
            let f = fns
                .iter()
                .filter(|(_, r)| r.contains(&at))
                .min_by_key(|(_, r)| r.len())
                .map(|(n, _)| n.clone())
                .unwrap_or_default();
            (f, receiver(&text, at))
        })
        .collect();
    assert!(
        hits.contains(&("decide".to_owned(), "c".to_owned())),
        "the raw read deep in a long fn is found and attributed: {hits:?}"
    );
    assert!(
        !text.contains("// community.members"),
        "the comment is stripped before scanning"
    );
}
