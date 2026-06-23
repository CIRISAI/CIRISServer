//! STAGE 4 gate — ciris-scores (`capacity:sustained_coherence:v1` / n_eff) are
//! being SERVED on nodes A & B. Evidence-driven: after confirming scores serve
//! in-mesh, drop tests/release_gates/evidence/stage4.json:
//!   { "nodes": { "A": {"factor":"sustained_coherence","value":0.83,
//!                       "served_at":"2026-06-23T18:00:00Z"},
//!                "B": { … } } }
//! RED until that evidence exists with a fresh sustained_coherence score for BOTH
//! nodes (served_at within 24h).

use chrono::{DateTime, Duration, Utc};

use crate::support::{blocked, evidence};

fn assert_node_score(ev: &serde_json::Value, which: &str) {
    let node = ev
        .get("nodes")
        .and_then(|n| n.get(which))
        .unwrap_or_else(|| blocked("4", &format!("evidence has no nodes.{which} score")));
    let factor = node.get("factor").and_then(|f| f.as_str()).unwrap_or("");
    assert_eq!(
        factor, "sustained_coherence",
        "node {which} score factor must be sustained_coherence"
    );
    assert!(
        node.get("value").and_then(|v| v.as_f64()).is_some(),
        "node {which} score must have a numeric value"
    );
    let served = node
        .get("served_at")
        .and_then(|s| s.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .unwrap_or_else(|| blocked("4", &format!("node {which} served_at missing/!rfc3339")))
        .with_timezone(&Utc);
    assert!(
        Utc::now() - served < Duration::hours(24),
        "node {which} score is stale (served_at {served} > 24h ago)"
    );
}

#[test]
#[ignore = "release gate (external fact): RED until ciris-scores are served on A & B (evidence/stage4.json); run with --include-ignored"]
fn gate4_scores_served_on_a_and_b() {
    let Some(ev) = evidence("stage4") else {
        blocked(
            "4",
            "no evidence/stage4.json — confirm capacity:sustained_coherence is served on A & B, then record it",
        );
    };
    assert_node_score(&ev, "A");
    assert_node_score(&ev, "B");
}
