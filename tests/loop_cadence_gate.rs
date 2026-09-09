//! Gate: the node's periodic loops must not tick on a bare interval, and no two
//! may share a phase.
//!
//! CIRISServer#575 measured what a shared phase costs. The config reconciler and
//! the replication reconciler both ran at 30 s on `tokio::time::interval`, which
//! starts at boot — so every tick of one landed on a tick of the other. Each
//! tick's reads run inline-sync on the request-serving runtime behind a single
//! connection mutex, so the collision is the node's own read API stalling: `GET
//! /v1/identity` p50 1.1 ms → 780 ms, ~700×, on 6.9% of wall time, with zero
//! non-200s. Nothing failed. It hung.
//!
//! This gate scrapes `src/` rather than restating the loop list in a constant:
//! a second copy of "which loops exist" is the one thing guaranteed to drift
//! from the loops themselves.

use std::collections::BTreeMap;
use std::time::Duration;

use ciris_server::loop_cadence::Cadence;

/// The cadence names a file declares, in source order. Plain scanning rather
/// than pulling in a pattern-matching dependency: the call shape is
/// `Cadence::new("name", …)`, and a gate that needs a parser to read one string
/// literal is over-built.
fn declared_names(body: &str) -> Vec<String> {
    const MARK: &str = "Cadence::new(";
    let code = code_only(body);
    let mut out = Vec::new();
    let mut rest = code.as_str();
    while let Some(i) = rest.find(MARK) {
        rest = &rest[i + MARK.len()..];
        let Some(open) = rest.find('"') else { break };
        let after = &rest[open + 1..];
        let Some(close) = after.find('"') else { break };
        out.push(after[..close].to_owned());
        rest = &after[close..];
    }
    out
}

fn src_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let name = path.to_string_lossy().into_owned();
                out.push((name, std::fs::read_to_string(&path).expect("read file")));
            }
        }
    }
    out
}

/// Strip `//` line comments so a doc comment naming the old API does not read as
/// a call site.
fn code_only(body: &str) -> String {
    body.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_periodic_loop_ticks_on_a_bare_interval() {
    let mut offenders = Vec::new();
    for (name, body) in src_files() {
        if name.ends_with("loop_cadence.rs") {
            continue; // the replacement itself
        }
        for (n, line) in code_only(&body).lines().enumerate() {
            if line.contains("tokio::time::interval(") {
                offenders.push(format!("{name}:{}", n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these loops tick on a bare interval, so they start on the same instant at \
         boot and re-collide at every common multiple — use \
         `loop_cadence::Cadence::new(\"<loop name>\", period)`:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_loop_declares_a_distinct_name() {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (file, body) in src_files() {
        if file.ends_with("loop_cadence.rs") {
            continue;
        }
        for name in declared_names(&body) {
            if let Some(first) = seen.insert(name.clone(), file.clone()) {
                if first != file {
                    panic!(
                        "two loops share the cadence name {name:?} ({first} and {file}) — \
                         the name IS the phase, so they would tick together"
                    );
                }
            }
        }
    }
    assert!(
        seen.len() >= 6,
        "expected the node's periodic loops to declare cadence names; found {:?}",
        seen.keys().collect::<Vec<_>>()
    );
}

#[test]
fn declared_loops_are_spread_across_a_shared_period() {
    // Every loop's phase is a pure function of its name, so the spread can be
    // checked here without running any of them. The 30 s period is the one
    // #575 measured: the two reconcilers share it.
    let mut names: Vec<String> = Vec::new();
    for (file, body) in src_files() {
        if file.ends_with("loop_cadence.rs") {
            continue;
        }
        for n in declared_names(&body) {
            if !names.contains(&n) {
                names.push(n);
            }
        }
    }
    let period = Duration::from_secs(30);
    // Leak is fine and deliberate: `Cadence::new` takes a `&'static str` because
    // a loop's name is a fixed property of the binary, and this gate builds the
    // list by scraping that same binary's source.
    let phases: Vec<(String, Duration)> = names
        .iter()
        .map(|n| {
            let leaked: &'static str = Box::leak(n.clone().into_boxed_str());
            (n.clone(), Cadence::new(leaked, period).phase())
        })
        .collect();
    for (i, (a, pa)) in phases.iter().enumerate() {
        for (b, pb) in phases.iter().skip(i + 1) {
            let gap = pa.abs_diff(*pb);
            let gap = gap.min(period - gap);
            assert!(
                gap >= Duration::from_secs(1),
                "{a} and {b} sit {gap:?} apart in a {period:?} period — a tick is \
                 longer than that, so they would still overlap"
            );
        }
    }
}
