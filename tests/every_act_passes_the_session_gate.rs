//! Gate: **every ACT in the session-claims inventory calls the handler check
//! before it acts** (CC 3.1.3.1; `FSD/SESSION_CLAIMS.md` §2.1).
//!
//! The inventory is the FSD's table, not a second list here: a copy of "which
//! sites are gated" in this file is the one thing guaranteed to drift from the
//! document a reviewer reads (the mirrored-rule class). So this reads every
//! `**gated**` row of §2.1 — `file`, `fn`, `act call` — and for each checks,
//! over the function's body with comments stripped, that
//! `session_claims::gate(` appears and appears BEFORE the act call. An act
//! reached without the gate runs on every device the person owns.
//!
//! It also refuses a gated act called from anywhere ELSE in `src/` (a second
//! caller of `rekey_self_occurrence_add` in a loop would be a fresh ungated
//! site), except the named, user-initiated door.

use std::path::Path;

/// `(file, fn, act)` for every `**gated**` row of FSD §2.1.
fn gated_rows() -> Vec<(String, String, String)> {
    let fsd = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("FSD/SESSION_CLAIMS.md"),
    )
    .expect("FSD/SESSION_CLAIMS.md is readable");
    let strip = |c: &str| c.trim().trim_matches('`').to_owned();
    let mut out = Vec::new();
    for line in fsd.lines() {
        if !line.starts_with('|') || !line.contains("**gated**") {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').collect();
        // | act | file | fn | act call | gated | community_id | session_id |
        assert!(
            cells.len() >= 7,
            "a gated row must have seven cells: {line}"
        );
        out.push((strip(cells[1]), strip(cells[2]), strip(cells[3])));
    }
    out
}

/// The body of `fn name` in `src`, comments stripped: from its signature to
/// the first line that is exactly `}` at column 0.
fn fn_body(src: &str, name: &str) -> Option<String> {
    let code: String = src
        .replace("\r\n", "\n")
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let start = [
        format!("pub async fn {name}("),
        format!("async fn {name}("),
        format!("pub fn {name}("),
        format!("fn {name}("),
    ]
    .iter()
    .find_map(|sig| code.find(sig.as_str()))?;
    let rest = &code[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 2);
    Some(rest[..end].to_owned())
}

#[test]
fn the_inventory_names_at_least_the_three_gated_acts() {
    let rows = gated_rows();
    assert!(
        rows.len() >= 3,
        "FSD/SESSION_CLAIMS.md §2.1 lost its gated rows (found {rows:?}) — the gate test \
         would then check nothing"
    );
}

#[test]
fn every_gated_act_calls_the_session_gate_first() {
    let mut failures = Vec::new();
    for (file, func, act) in gated_rows() {
        let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&file))
            .unwrap_or_else(|e| panic!("{file}: {e}"));
        let Some(body) = fn_body(&src, &func) else {
            failures.push(format!(
                "{file}: no fn `{func}` — the FSD names a site that is gone"
            ));
            continue;
        };
        let Some(act_at) = body.find(&act) else {
            failures.push(format!(
                "{file}::{func}: the act `{act}` is not called here any more — update the FSD row"
            ));
            continue;
        };
        match body.find("session_claims::gate(") {
            Some(g) if g < act_at => {}
            Some(_) => failures.push(format!(
                "{file}::{func}: `session_claims::gate(` comes AFTER `{act}` — the act runs \
                 before anyone asked whether this device handles it"
            )),
            None => failures.push(format!(
                "{file}::{func}: `{act}` is reached with no `session_claims::gate(` — it runs \
                 on every device the person owns (CC 3.1.3.1)"
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The re-wrap door has exactly two callers: the gated loop pass, and
/// `auth::occurrence::bind_occurrence_core` — which wraps self DEKs to an
/// occurrence bound ON THIS DEVICE (the person's own `POST /v1/self/occurrence`,
/// the portable-occurrence doors, and this node's own actor occurrence at
/// boot): the device doing its own binding, never a reaction to a sibling's
/// row (FSD §2.2 / §2.3).
#[test]
fn the_rewrap_door_has_no_ungated_loop_caller() {
    let mut callers = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("read src") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let body = std::fs::read_to_string(&p).expect("read");
                for (n, line) in body.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    if code.contains("rekey_self_occurrence_add(") {
                        callers.push(format!(
                            "{}:{}",
                            p.file_name().unwrap().to_string_lossy(),
                            n + 1
                        ));
                    }
                }
            }
        }
    }
    let unexpected: Vec<&String> = callers
        .iter()
        .filter(|c| !c.starts_with("self_rewrap.rs:") && !c.starts_with("occurrence.rs:"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "a new caller of the self re-wrap door outside the gated pass and the person's own \
         request: {unexpected:?} — gate it (FSD/SESSION_CLAIMS.md §2.1) or name it in §2.3"
    );
}
