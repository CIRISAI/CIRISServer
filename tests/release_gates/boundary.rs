//! **The boundary** — the two forward gates that are RED BY DESIGN, the one
//! external-fact gate, and the live watcher that keeps all three honest.
//!
//! This module is the whole of the ladder's non-hermetic surface, kept small and
//! kept separate on purpose. Everything in it is `#[ignore]`d, and every
//! `#[ignore]` here is on [`crate::ladder::IGNORE_ALLOWLIST`] — so
//! [`crate::ladder::gate0_no_gate_is_silently_ignored`] fails the moment a fourth
//! one appears anywhere in the suite.
//!
//! The previous ladder's ignored gates rotted because nothing watched them:
//! "persist v10 ships and we re-pin" sat ignored through twenty releases. So each
//! forward gate here has a LIVE counterpart —
//! [`gate0_no_forward_rung_has_quietly_become_satisfiable`] — which runs on every
//! `cargo test --test release_gates` and FAILS the moment the forward condition
//! is met. An ignored gate that has come true cannot stay ignored.

use std::path::PathBuf;

use crate::ladder::{blocked, repo};

// ─────────────────────────────────────────────────────────────────────────────
// The forward predicates, evaluated in exactly ONE place each
// ─────────────────────────────────────────────────────────────────────────────

/// 0.6's defining surface: the registry that bootstraps the canonical mesh.
fn registry_surface_present() -> bool {
    let src = repo().join("src");
    src.join("registry.rs").exists() || src.join("registry").is_dir()
}

/// Does the two-node replication round ASSERT that a trace arrived?
///
/// It currently does not. `tests/trace_round_e2e.rs` ends with a named soft
/// frontier — `if traces.is_empty() { eprintln!("FRONTIER: …") }` — which keeps
/// the suite green while the gap stays visible. That is the right call for that
/// file and the wrong thing for a release gate to read as "traces flow".
fn replication_round_asserts_arrival() -> bool {
    let Ok(src) = std::fs::read_to_string(repo().join("tests/trace_round_e2e.rs")) else {
        return false;
    };
    !src.contains("if traces.is_empty() {")
}

// ─────────────────────────────────────────────────────────────────────────────
// The live watcher
// ─────────────────────────────────────────────────────────────────────────────

/// **The watcher.** Runs always; fails when a forward gate has come true.
///
/// This is the ratchet that the previous ladder lacked. Its gates went stale
/// silently because being ignored and being unmet are indistinguishable from the
/// outside — so a requisite that had been satisfied for twenty releases still
/// read as "pending". Here, satisfying a forward condition BREAKS the build until
/// someone promotes the gate to a live one and removes it from the allowlist.
#[test]
fn gate0_no_forward_rung_has_quietly_become_satisfiable() {
    let mut ripe: Vec<&str> = Vec::new();
    if registry_surface_present() {
        ripe.push(
            "  `gate_registry_surface_present` — src/registry.rs now EXISTS. This is the 0.6\n\
             \x20   boundary: the +registry surface is built. Promote the gate (drop its\n\
             \x20   #[ignore] and its IGNORE_ALLOWLIST entry) and decide deliberately whether\n\
             \x20   this cut is still 0.5.",
        );
    }
    if replication_round_asserts_arrival() {
        ripe.push(
            "  `gate_trace_flow_over_replication` — tests/trace_round_e2e.rs no longer carries\n\
             \x20   the soft frontier, so the round now ASSERTS a trace arrives. CIRISEdge#455\n\
             \x20   is closed. Promote the gate to a live rung and add trace_round_e2e to the\n\
             \x20   ladder registry — noting it is behind `--features test-anchor`, so CI must\n\
             \x20   run it WITH that feature or it is an empty instrument.",
        );
    }
    assert!(
        ripe.is_empty(),
        "\n\
         🔔 RELEASE LADDER — a forward gate has come true and is still switched off.\n\
         \n\
         Unsafe to ship: an #[ignore]d gate whose condition is now MET reports nothing,\n\
         and 'pending forever' is exactly how the previous ladder died. Reality moved;\n\
         the ladder must move with it in the same commit.\n\
         \n\
         {}\n",
        ripe.join("\n\n"),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward gate 1 — the 0.6 boundary
// ─────────────────────────────────────────────────────────────────────────────

/// **The 0.6 boundary, carried forward from the previous ladder unchanged.**
///
/// It is the one gate of that suite that still means exactly what it says: 0.6 is
/// the registry fold, and 0.6 must not tag until `src/registry.rs` exists. While
/// we are on 0.5.X it is correctly RED and correctly ignored.
#[test]
#[ignore = "RED BY DESIGN — the 0.6 boundary: `src/registry.rs` does not exist while we are on 0.5.X. Watched live by gate0_no_forward_rung_has_quietly_become_satisfiable. Run with --include-ignored."]
fn gate_registry_surface_present() {
    assert!(
        registry_surface_present(),
        "\n\
         🚫 RELEASE GATE [0.6-boundary] — DO NOT TAG 0.6.\n\
         \n\
         Unsafe to ship as 0.6: `src/registry.rs` is absent, so the +registry surface —\n\
         the thing that bootstraps the canonical mesh and the whole content of the 0.6\n\
         fold — is not built. A 0.6 tag without it is a version number claiming a\n\
         capability the binary does not have, and downstream floors are written against\n\
         the number.\n\
         \n\
         (This is expected and correct on 0.5.X. It is here so 0.6 cannot be tagged by\n\
         momentum.)\n"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward gate 2 — trace delivery over an anti-entropy round
// ─────────────────────────────────────────────────────────────────────────────

/// **Traces do not yet cross a replication round, and this gate says so.**
///
/// HTTP ingest carries traces end to end and is gated live
/// (`planes::gate_trace_flow_over_http_ingest`). Peer replication does NOT: on
/// persist v30 / edge v15.18 a sealed `trace:*` still does not reach the
/// canonical over an anti-entropy round, filed as **CIRISEdge#455**. The round
/// test names that as a soft frontier so the suite stays green and the gap stays
/// visible, which is right for that file — but a release gate that read it as
/// "traces flow" would be false, and it would let the working half vouch for the
/// broken one.
///
/// So the two paths are two rungs. This one is red, and its being red is the most
/// important thing the new ladder encodes.
#[test]
#[ignore = "RED BY DESIGN — CIRISEdge#455: a sealed trace does not reach the canonical over an anti-entropy round. Watched live by gate0_no_forward_rung_has_quietly_become_satisfiable. Run with --include-ignored."]
fn gate_trace_flow_over_replication() {
    assert!(
        replication_round_asserts_arrival(),
        "\n\
         🚫 RELEASE GATE [trace-flow-replication] — RED, and correctly so.\n\
         \n\
         Unsafe to claim: traces do NOT flow over an anti-entropy replication round.\n\
         `tests/trace_round_e2e.rs` still ends in the soft frontier\n\
         `if traces.is_empty() {{ eprintln!(\"FRONTIER: …\") }}` — it drives the round,\n\
         asserts everything upstream of the serve gate, and does NOT assert the trace\n\
         arrived, because on persist v30 / edge v15.18 it does not (CIRISEdge#455).\n\
         \n\
         What 0.5.156 may honestly claim: traces flow over HTTP ingest, proven end to end.\n\
         What it may not claim: peer-to-peer trace replication.\n\
         \n\
         When CIRISEdge#455 lands, flip that frontier to an `assert!`, then promote this\n\
         gate — and note the file is behind `#![cfg(feature = \"test-anchor\")]`, so CI\n\
         must run it WITH that feature or the promotion buys an empty instrument.\n"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The external-fact plane — the whole of it
// ─────────────────────────────────────────────────────────────────────────────

fn node_url(which: &str) -> Option<String> {
    std::env::var(format!("CIRIS_GATE_NODE_{which}"))
        .ok()
        .filter(|s| !s.trim().is_empty())
}

fn http_get(url: &str) -> Result<(u16, String), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let body = resp.text().await.map_err(|e| e.to_string())?;
        Ok((status, body))
    })
}

fn parse_semver(v: &str) -> Option<(u32, u32, u32)> {
    let core = v.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut it = core.split('.');
    Some((
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ))
}

/// **The one external-fact gate: the peers are on the floor this cut ships.**
///
/// This is the only rung in the ladder that cannot be answered from the tree, and
/// it is here because the fact genuinely is a release requisite: a mesh whose
/// bridge nodes run an older floor will refuse rows this cut emits, and the
/// refusal presents as "the mesh is quiet".
///
/// Its absence reads **BLOCKED, never PASSED** — [`blocked`] panics with wording
/// chosen so an un-evaluable gate can never be mistaken for a satisfied one. That
/// is the whole lesson of the ladder this replaced: its evidence gates defaulted
/// to silence, and silence read as fine.
///
/// Why `/v1/health`.`data.version` and not `/health`: a node may wrap ciris-server
/// in an adapter (CIRISStatus = ciris-server + StatusAdapter) whose own `/health`
/// reports the WRAPPER's version. The adapter does not override `/v1/health`, so
/// that route reports the EMBEDDED ciris-server version — the floor signal, read
/// uniformly across a bare node and a wrapped one.
#[test]
#[ignore = "RED BY DESIGN — external fact: needs a reachable peer (CIRIS_GATE_NODE_A/_B). BLOCKED, never passed, without one. Run with --include-ignored."]
fn gate_peer_nodes_on_the_shipping_floor() {
    let floor = parse_semver(env!("CARGO_PKG_VERSION")).expect("our own version parses");
    let mut probed = 0usize;
    for which in ["A", "B"] {
        let Some(base) = node_url(which) else {
            blocked(
                "peer-nodes-on-floor",
                &format!(
                    "CIRIS_GATE_NODE_{which} is unset, so whether peer {which} runs this cut's\n\
                     floor is UNKNOWN. Unknown is not 'yes'. A peer on an older floor refuses\n\
                     rows this cut emits, and that refusal presents as a quiet mesh rather than\n\
                     as an error — which is the 2026-08-03 shape exactly.\n\
                     \n\
                     Set CIRIS_GATE_NODE_{which}=<base-url> and re-run, or record explicitly\n\
                     that this release ships without confirming the peer floor."
                ),
            );
        };
        let url = format!("{}/v1/health", base.trim_end_matches('/'));
        let (status, body) = match http_get(&url) {
            Ok(r) => r,
            Err(e) => blocked(
                "peer-nodes-on-floor",
                &format!(
                    "{url} is UNREACHABLE ({e}), so peer {which}'s floor is unknown. An\n\
                     unreachable peer is not a peer on the right floor — and it is not a peer\n\
                     on the wrong one either. Nothing was measured."
                ),
            ),
        };
        assert_eq!(
            status, 200,
            "\n\
             🚫 RELEASE GATE [peer-nodes-on-floor] — DO NOT TAG.\n\
             Unsafe to ship: {url} answered {status}. A bridge node that cannot answer its own\n\
             health route is not a node this cut can be released against.\n"
        );
        let v: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("{url} body is not JSON ({e}) — peer floor UNKNOWN"));
        let ver = v
            .get("data")
            .and_then(|d| d.get("version"))
            .or_else(|| v.get("version"))
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("{url} carries no data.version — peer floor UNKNOWN"));
        let got = parse_semver(ver).unwrap_or_else(|| panic!("unparseable version {ver:?}"));
        assert!(
            got >= floor,
            "\n\
             🚫 RELEASE GATE [peer-nodes-on-floor] — DO NOT TAG.\n\
             \n\
             Unsafe to ship: peer {which} runs {ver}, below this cut's floor {floor:?}. It will\n\
             refuse rows this cut emits, and the refusal is silent from our side — the plane\n\
             just goes quiet. Upgrade the peer first; a cut released into a mesh that cannot\n\
             read it is a cut nobody can roll back from safely.\n"
        );
        probed += 1;
    }
    assert_eq!(probed, 2, "both bridge nodes must be probed");
}

/// The evidence-file mechanism is GONE, and must stay gone.
///
/// Ten of the previous ladder's nineteen tests gated on
/// `tests/release_gates/evidence/stageN.json` — files an operator had to remember
/// to write, and never did. The directory held only `.tsv`. So the gates carrying
/// the most weight defaulted to silence.
///
/// This is not a style rule. An operator-dropped JSON file is an ASSERTION BY A
/// HUMAN that something is true, checked by nothing: it passes when someone
/// writes it, whether or not the fact holds, and it fails identically whether the
/// fact is false or the human was busy. Where an external fact really is the gate,
/// it must be PROBED (see above) — measured, or BLOCKED.
#[test]
fn gate0_no_gate_depends_on_an_operator_dropped_evidence_file() {
    // The needles are ASSEMBLED rather than written, so this file does not
    // contain them verbatim and the scan below cannot match its own source. A
    // gate that has to exempt itself by filename would stop covering the module
    // it lives in — which is one of the six modules it must cover.
    let ev: String = ['e', 'v', 'i', 'd', 'e', 'n', 'c', 'e'].iter().collect();
    let dir_needle = format!("{ev}/");
    let fn_needle = format!("fn {ev}(");

    let evidence_dir: PathBuf = repo().join("tests/release_gates").join(&ev);
    assert!(
        !evidence_dir.exists(),
        "\n\
         🚫 RELEASE LADDER — the evidence-file mechanism is back.\n\
         \n\
         Unsafe to ship: {} exists. A gate that reads an operator-dropped JSON file is a\n\
         human assertion checked by nothing — it passes because someone wrote a file, not\n\
         because the fact holds, and it is silent in exactly the case that matters. Ten of\n\
         nineteen gates in the ladder this replaced worked that way, and not one evidence\n\
         file was ever written.\n\
         \n\
         Probe the fact, or mark the gate BLOCKED.\n",
        evidence_dir.display(),
    );

    let mut readers: Vec<String> = Vec::new();
    let dir = repo().join("tests/release_gates");
    for entry in std::fs::read_dir(&dir).expect("tests/release_gates readable") {
        let p = entry.expect("dir entry").path();
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&p).expect("gate source");
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains(&dir_needle) || code.contains(&fn_needle) {
                readers.push(format!(
                    "  {}:{}",
                    p.file_name().and_then(|f| f.to_str()).unwrap_or_default(),
                    n + 1
                ));
            }
        }
    }
    assert!(
        readers.is_empty(),
        "\n\
         🚫 RELEASE LADDER — a gate reads an operator-dropped evidence file.\n{}\n",
        readers.join("\n"),
    );
}
