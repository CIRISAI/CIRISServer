//! `ciris-server import-traces <dump-dir>` — import the legacy CIRISLens
//! TimescaleDB trace dump into the persist-v7 corpus as **CEG objects**
//! (`CompleteTrace` / `BatchEnvelope`), for posterity + to show the ragged edge.
//!
//! The dump's `accord_traces.jsonl.gz` is the **flat** lens row (schema 1.9.x,
//! ~90 denormalized columns), NOT CEG wire. This maps each row → a
//! `CompleteTrace`: the seven reasoning dict-columns become `TraceComponent`s
//! (thought_start→Observation/ThoughtStart, dma_results→Rationale/DmaResults,
//! conscience_result→Conscience/ConscienceResult, action_result→Action/
//! ActionResult, …). The original `signature` + `signature_key_id` are preserved
//! as provenance; the trace is imported **pre-verified** (the legacy signature
//! signed the 1.9.x bytes, not the reconstructed trace, so it is not
//! re-verifiable — `receive_and_persist_pre_verified`). Content-addressed dedup
//! makes re-runs idempotent.
//!
//! Robust to the ragged edge: a streaming JSON-value reader (not line-split)
//! recovers rows with embedded newlines, and persist's `#[serde(other)]`
//! component fallbacks keep odd rows from hard-failing.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ciris_persist::prelude::Engine;
use ciris_persist::scrub::NullScrubber;
use flate2::read::GzDecoder;
use serde_json::{json, Map, Value};

use crate::compose::{federation_pqc_signer, federation_signer};
use crate::config::ServerConfig;

/// (flat column, component_type, event_type, timestamp column) — the mapping.
const COMPONENTS: &[(&str, &str, &str, &str)] = &[
    (
        "thought_start",
        "observation",
        "thought_start",
        "thought_start_at",
    ),
    (
        "snapshot_and_context",
        "context",
        "snapshot_and_context",
        "snapshot_at",
    ),
    ("dma_results", "rationale", "dma_results", "dma_results_at"),
    ("idma_result", "rationale", "idma_result", "idma_at"),
    ("aspdma_result", "rationale", "aspdma_result", "aspdma_at"),
    (
        "conscience_result",
        "conscience",
        "conscience_result",
        "conscience_at",
    ),
    (
        "action_result",
        "action",
        "action_result",
        "action_result_at",
    ),
];

/// Entry point for the `import-traces` subcommand.
pub async fn run(dump_dir: &str) -> Result<()> {
    let cfg = ServerConfig::defaults()?;
    cfg.ensure_dirs()?;
    let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::from(federation_signer(&cfg)?);
    // Hard cut to hybrid (CIRISVerify#75): even the legacy-import Engine signs its
    // storage-tier scrub envelopes as a FULL HYBRID (sealed Ed25519 + ML-DSA-65).
    // The imported traces' OWN 1.9.x Ed25519 signatures ride along as provenance
    // only — pre-verified, exempt from the hybrid-required ingest gate
    // (CIRISPersist#225 legacy carve-out).
    let pqc = federation_pqc_signer(&cfg)?;
    // KEYSTORE alias for the PQC blob (matches `federation_pqc_signer`). The
    // import path uses `ServerConfig::defaults()` and never derives a key_id, so
    // here `keystore_alias == key_id`; using the alias keeps it correct + explicit.
    let pqc_key_id = format!("{}-pqc", cfg.keystore_alias);
    let engine =
        Engine::with_hardware_signer_hybrid(signer, Some(pqc), Some(pqc_key_id), &cfg.dsn())
            .await
            .context("open persist Engine for import (hybrid hardware signer)")?;

    let path = Path::new(dump_dir).join("accord_traces.jsonl.gz");
    let path = if path.exists() {
        path
    } else {
        Path::new(dump_dir).join("accord_traces.jsonl") // accept a pre-gunzipped dump too
    };
    tracing::info!(dump = %path.display(), dsn = %cfg.dsn(), "importing legacy traces as CEG objects");

    let file = std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let reader: Box<dyn std::io::Read> = if path.extension().is_some_and(|e| e == "gz") {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    // Tolerant JSONL reader: accumulate lines until a complete JSON value parses
    // (recovers multi-line records — the ragged ~30%), and skip a genuinely
    // corrupt record by resyncing at the next line (serde's streaming reader
    // can't — it halts at the first bad value).
    use std::io::BufRead;
    let lines = std::io::BufReader::new(reader).lines();
    let mut buf = String::new();

    let (mut seen, mut inserted, mut conflicted, mut errored, mut unparsed, mut salvaged) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for line in lines {
        let line = line.context("read dump line")?;
        if buf.is_empty() {
            buf.push_str(&line);
        } else {
            buf.push('\n');
            buf.push_str(&line);
        }
        let mut was_salvaged = false;
        let row: Value = match serde_json::from_str(&buf) {
            Ok(v) => {
                buf.clear();
                v
            }
            Err(e) if e.is_eof() => continue, // incomplete multi-line record — keep accumulating
            Err(_) => {
                // Complete but malformed: the dump's systematic export bug —
                // stringified-JSON fields escape inner quotes as `\\"` (escaped
                // backslash + bare quote, which closes the string early) instead
                // of `\"`. Salvage by un-doubling `\\"` → `\"` and retrying
                // (a few passes for multi-level nesting).
                let mut repaired = buf.clone();
                buf.clear();
                let mut got: Option<Value> = None;
                for _ in 0..4 {
                    let next = repaired.replace("\\\\\"", "\\\"");
                    if next == repaired {
                        break;
                    }
                    repaired = next;
                    if let Ok(v) = serde_json::from_str::<Value>(&repaired) {
                        got = Some(v);
                        break;
                    }
                }
                match got {
                    Some(v) => {
                        salvaged += 1;
                        was_salvaged = true;
                        v
                    }
                    None => {
                        unparsed += 1;
                        if unparsed <= 5 {
                            tracing::warn!("skipping unparseable dump record (unrepairable)");
                        }
                        continue;
                    }
                }
            }
        };
        seen += 1;
        let bytes = match reconstruct_batch(&row, was_salvaged) {
            Some(b) => b,
            None => {
                errored += 1;
                continue;
            }
        };
        match engine
            .receive_and_persist_pre_verified(&bytes, &NullScrubber)
            .await
        {
            Ok(s) => {
                inserted += s.trace_events_inserted as u64;
                conflicted += s.trace_events_conflicted as u64;
            }
            Err(e) => {
                errored += 1;
                if errored <= 10 {
                    let tid = row.get("trace_id").and_then(Value::as_str).unwrap_or("?");
                    tracing::warn!(trace_id = %tid, error = %e, "import: row rejected");
                }
            }
        }
        if seen % 1000 == 0 {
            tracing::info!(seen, inserted, conflicted, errored, "import progress");
        }
    }
    tracing::info!(
        seen,
        inserted,
        conflicted,
        errored,
        unparsed,
        salvaged,
        "legacy trace import complete"
    );
    Ok(())
}

/// Reconstruct one flat 1.9.x lens row into a CEG `BatchEnvelope` JSON (bytes).
/// Returns `None` if the row lacks the minimum identity fields.
fn reconstruct_batch(row: &Value, salvaged: bool) -> Option<Vec<u8>> {
    let s = |k: &str| row.get(k).and_then(Value::as_str);
    let trace_id = s("trace_id")?;
    let thought_id = s("thought_id")?;
    let started_at = s("started_at")?;
    let completed_at = s("completed_at").unwrap_or(started_at);
    let level = s("trace_level").unwrap_or("generic");
    // persist accepts a CLOSED schema set; "2.7.legacy" is its designated bucket
    // for pre-2.7.8.9 traces. The original lens schema (e.g. 1.9.3) + signature
    // are preserved in a provenance component below — the auditable ragged edge.
    let orig_schema = s("schema_version").unwrap_or("(absent)");
    let schema_version = "2.7.legacy";

    let mut components = Vec::new();
    for (col, ctype, etype, ts_col) in COMPONENTS {
        if let Some(data) = row.get(*col).filter(|v| v.is_object()) {
            let ts = s(ts_col).unwrap_or(started_at);
            components.push(json!({
                "component_type": ctype,
                "event_type": etype,
                "timestamp": ts,
                "data": data,
            }));
        }
    }
    // Provenance component — the ragged edge, made auditable: original lens
    // schema + the legacy signature that signed the 1.9.x bytes (not re-verifiable
    // against this reconstruction). `unknown` event_type rides persist's
    // serde(other) fallback.
    components.push(json!({
        "component_type": "observation",
        "event_type": "unknown",
        "timestamp": started_at,
        "data": {
            "_imported_from": "cirislens-timescaledb",
            "legacy_schema_version": orig_schema,
            "legacy_signature": s("signature").unwrap_or(""),
            "legacy_signature_key_id": s("signature_key_id").unwrap_or(""),
            // The raggedest edge: this record's JSON was repaired (the export's
            // `\\"`→`\"` mis-escaping in stringified-JSON fields) before import.
            "_salvaged": salvaged,
        },
    }));

    let mut trace = Map::new();
    trace.insert("trace_id".into(), json!(trace_id));
    trace.insert("thought_id".into(), json!(thought_id));
    if let Some(t) = s("task_id") {
        trace.insert("task_id".into(), json!(t));
    }
    trace.insert(
        "agent_id_hash".into(),
        json!(s("agent_id_hash").unwrap_or("legacy")),
    );
    trace.insert("started_at".into(), json!(started_at));
    trace.insert("completed_at".into(), json!(completed_at));
    trace.insert("trace_level".into(), json!(level));
    trace.insert("trace_schema_version".into(), json!(schema_version));
    trace.insert("components".into(), json!(components));
    trace.insert("cohort_scope".into(), json!("federation"));
    // Provenance: the legacy signature signed the 1.9.x payload, not this
    // reconstruction — preserved, not re-verified (imported pre-verified).
    trace.insert("signature".into(), json!(s("signature").unwrap_or("")));
    trace.insert(
        "signature_key_id".into(),
        json!(s("signature_key_id").unwrap_or("imported:legacy")),
    );

    let consent = s("consent_timestamp").unwrap_or(started_at);
    let envelope = json!({
        "events": [{ "event_type": "complete_trace", "trace_level": level, "trace": Value::Object(trace) }],
        "batch_timestamp": started_at,
        "consent_timestamp": consent,
        "trace_level": level,
        "trace_schema_version": schema_version,
    });
    Some(envelope.to_string().into_bytes())
}
