//! Shared helpers for the release-gate QA suite (`tests/release_gates.rs`).
//!
//! The gates are a LIVING release checklist for the verify-7 → persist-10 → 0.6
//! countdown. Each gate FAILS (red) until its stage's requisite is cleared, and
//! turns GREEN the moment reality satisfies it — so the suite is run before each
//! step is executed in the mesh ("test before execute"). Everything here uses
//! SOFTWARE keys / file + HTTP probes so the suite runs in CI with no YubiKey and
//! no operator in the loop.
//!
//! Gate kinds:
//!   - **pin gates** read the workspace `Cargo.toml` (e.g. "verify is v7.2.0").
//!   - **capability gates** call real substrate APIs with software keys (e.g.
//!     "persist admits an ExternalSecureElement accord_holder").
//!   - **probe gates** hit a running node over HTTP (`CIRIS_GATE_NODE_A/_B`).
//!   - **evidence gates** require an operator-dropped JSON file recording an
//!     out-of-band fact (a merged PR, an upstream release, an adoption report).
//!     Absent/!valid → red, with a message telling the operator what to drop.

#![allow(dead_code)]

use std::path::PathBuf;

// ── Target substrate floor (Stage 1) ─────────────────────────────────────────
// 0.5.36: edge v6.4.0→v7.0.0 (CIRISEdge#191 — N1 explicit-hash on the IP transport,
// so the node code determines the routable RNS destination) + persist v9.11.0→v10.0.0
// (FederationDirectory carries fountain evict directly). verify stays v7.2.0.
// 0.5.39: edge v7.0.0→v7.0.2 (CIRISEdge#199 — restores the `pub fn register` /
// `init_edge_runtime` re-export hook that regressed out of the v7.x line; completes
// the one-wheel re-export, CIRISServer#4).
pub const TARGET_VERIFY: &str = "v8.3.0";
pub const TARGET_PERSIST: &str = "v11.2.0";
pub const TARGET_EDGE: &str = "v7.3.1";
/// Stage 6/7: the persist tag that bakes Node A as the canonical seed.
pub const TARGET_PERSIST_V10: &str = "v10";

/// The canonical-seed transport key id Node A must carry (Stage 5).
pub const CANONICAL_TRANSPORT_KEY_ID: &str = "ciris-canonical-1";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read the pinned git `tag` of a substrate crate from the workspace `Cargo.toml`.
/// Returns the FIRST `<crate> = { … tag = "…" }` occurrence (the root [dependencies]
/// pin, which is what ships). `None` if the crate or tag isn't found.
pub fn cargo_pin(crate_name: &str) -> Option<String> {
    let toml = std::fs::read_to_string(manifest_dir().join("Cargo.toml")).ok()?;
    for line in toml.lines() {
        let t = line.trim_start();
        // Match `<crate>` followed by whitespace then `=` (avoids matching
        // `ciris-persist-foo`), and only lines that carry a tag. NB: `continue`
        // on a non-match — a `?` here would abort the whole scan on line 1.
        let Some(rest) = t.strip_prefix(crate_name) else {
            continue;
        };
        if !rest.trim_start().starts_with('=') {
            continue;
        }
        if let Some(i) = line.find("tag = \"") {
            let after = &line[i + "tag = \"".len()..];
            if let Some(end) = after.find('"') {
                return Some(after[..end].to_string());
            }
        }
    }
    None
}

/// Path to the evidence dir; operators drop `<stage>.json` here when an
/// out-of-band requisite is met.
pub fn evidence_dir() -> PathBuf {
    manifest_dir().join("tests/release_gates/evidence")
}

/// Load an operator-dropped evidence file, if present + valid JSON.
pub fn evidence(stage: &str) -> Option<serde_json::Value> {
    let p = evidence_dir().join(format!("{stage}.json"));
    let s = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&s).ok()
}

/// Fail a gate with a clear, actionable BLOCKED message (used for unmet requisites).
#[track_caller]
pub fn blocked(stage: &str, why: &str) -> ! {
    panic!(
        "\n  ⛔ GATE {stage} BLOCKED — requisite not yet cleared.\n     {why}\n     (this gate is RED by design; it turns green when the requisite is met)\n"
    );
}

/// Resolve a node base URL from env (probe gates). Stage 2/4 read these; absent →
/// the gate is BLOCKED with instructions rather than a confusing connection error.
pub fn node_url(which: &str) -> Option<String> {
    std::env::var(format!("CIRIS_GATE_NODE_{which}")).ok()
}

/// Blocking HTTP GET returning `(status, body)`; `Err` on transport failure.
pub fn http_get(url: &str) -> Result<(u16, String), String> {
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
