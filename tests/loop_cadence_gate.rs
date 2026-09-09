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

use std::collections::{BTreeMap, BTreeSet};

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
fn no_two_loops_share_a_cadence_name() {
    // ANY duplicate, including two in the same file. The name is the slot, so a
    // duplicate is two loops ticking together — which is #575 exactly. The
    // first version of this gate only rejected duplicates ACROSS files and
    // would have passed the one case that matters least distinguishable from
    // the bug (Codex, PR #576).
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (file, body) in src_files() {
        if file.ends_with("loop_cadence.rs") {
            continue;
        }
        for name in declared_names(&body) {
            if let Some(first) = seen.insert(name.clone(), file.clone()) {
                panic!(
                    "two loops declare the cadence name {name:?} ({first} and {file}) —                      the name IS the slot, so they would tick together"
                );
            }
        }
    }
    assert!(
        seen.len() >= 6,
        "expected the node's periodic loops to declare cadence names; found {:?}",
        seen.keys().collect::<Vec<_>>()
    );
}

/// The registry and the call sites must name the same set, in both directions.
///
/// `LOOPS` is the phase allocation: a loop missing from it silently shares slot
/// 0, and a stale entry in it steals a slot from the loops that remain, spacing
/// them further apart than they need to be. Checking only one direction would
/// let either happen.
#[test]
fn the_registry_and_the_call_sites_name_the_same_loops() {
    let declared: BTreeSet<String> = src_files()
        .into_iter()
        .filter(|(f, _)| !f.ends_with("loop_cadence.rs"))
        .flat_map(|(_, body)| declared_names(&body))
        .collect();
    let registered: BTreeSet<String> = ciris_server::loop_cadence::LOOPS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    let unregistered: Vec<_> = declared.difference(&registered).collect();
    assert!(
        unregistered.is_empty(),
        "these loops call Cadence::new with a name that is not in loop_cadence::LOOPS,          so they share slot 0 with the first registered loop: {unregistered:?}"
    );
    let unused: Vec<_> = registered.difference(&declared).collect();
    assert!(
        unused.is_empty(),
        "these names are in loop_cadence::LOOPS but no loop uses them — they hold a slot          that spreads the real loops no further apart than they need: {unused:?}"
    );
}

/// Slots are evenly spread by construction; this is the gate-level statement of
/// it, against the loops that actually exist rather than the list in isolation.
#[test]
fn every_declared_loop_clears_a_burst_from_its_neighbours() {
    use std::time::Duration;
    let period = Duration::from_secs(30);
    let phases: Vec<(String, Duration)> = ciris_server::loop_cadence::LOOPS
        .iter()
        .map(|n| {
            (
                (*n).to_owned(),
                ciris_server::loop_cadence::phase_for(n, period),
            )
        })
        .collect();
    for (i, (a, pa)) in phases.iter().enumerate() {
        for (b, pb) in phases.iter().skip(i + 1) {
            let gap = pa.abs_diff(*pb);
            let gap = gap.min(period - gap);
            assert!(
                gap >= ciris_server::loop_cadence::SLOT_SPACING,
                "{a} and {b} sit {gap:?} apart in a {period:?} period — the slot spacing is {:?} and #575 measured bursts 1-2 s wide",
                ciris_server::loop_cadence::SLOT_SPACING
            );
        }
    }
}
