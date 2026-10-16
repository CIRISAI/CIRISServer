//! **A warning that cites an issue says whether it is history or still open**
//! (CIRISServer#782).
//!
//! Eric and the agent session both read steady-state WARNs that cite issue
//! numbers as live bugs; every one they quoted had closed months earlier — the
//! citation was the gate's HISTORY, the line was the gate working. So in every
//! `tracing::warn!` / `tracing::error!` message in this crate, an issue
//! citation is written `history: X#N` (closed: why this gate exists) or
//! `tracked: X#N` (open: work still owed). A bare `X#N` fails here.
//! `tools/check_log_citations.py` re-checks the open/closed state against
//! GitHub (network; run before a cut).
use std::path::Path;

fn rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// String literals inside `body`, escapes kept verbatim (we only look for `#N`).
fn literals(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = body.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            out.push(body[i + 1..j.min(b.len())].to_string());
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Every `[Repo]#NNN` in `text` with its start offset.
fn citations(text: &str) -> Vec<(usize, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    for (i, &c) in b.iter().enumerate() {
        if c != b'#' {
            continue;
        }
        let digits = b[i + 1..].iter().take_while(|d| d.is_ascii_digit()).count();
        if !(2..=4).contains(&digits)
            || b.get(i + 1 + digits)
                .is_some_and(|d| d.is_ascii_alphanumeric())
        {
            continue;
        }
        let mut s = i;
        while s > 0 && b[s - 1].is_ascii_alphabetic() {
            s -= 1;
        }
        out.push((s, text[s..i + 1 + digits].to_string()));
    }
    out
}

#[test]
fn every_issue_cited_in_a_warning_is_marked_history_or_tracked() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    let mut bare = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap().replace("\r\n", "\n");
        for open in ["tracing::warn!(", "tracing::error!("] {
            let mut from = 0;
            while let Some(k) = src[from..].find(open) {
                let start = from + k;
                let end = src[start..]
                    .find(");")
                    .map(|e| start + e)
                    .unwrap_or(src.len());
                let line = src[..start].matches('\n').count() + 1;
                for text in literals(&src[start..end]) {
                    for (at, cite) in citations(&text) {
                        let before = &text[..at];
                        if !(before.ends_with("history: ") || before.ends_with("tracked: ")) {
                            let rel = f
                                .strip_prefix(root)
                                .unwrap()
                                .to_string_lossy()
                                .replace('\\', "/");
                            bare.push(format!("{rel}:{line}: {cite}"));
                        }
                    }
                }
                from = end.max(start + 1);
            }
        }
    }
    assert!(
        bare.is_empty(),
        "issue citations in WARN/ERROR text must read `history: X#N` (closed) or `tracked: X#N` \
         (open) — a bare number reads as a live bug to operators:\n{}",
        bare.join("\n")
    );
}
