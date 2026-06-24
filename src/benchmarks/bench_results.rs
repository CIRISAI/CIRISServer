//! **`bench_results.json` — the unified, honest bench contract (schema v2).**
//!
//! Every entry is `"measured"` or `"gated"` — never `"modeled"`/`"attested"`. This is
//! the new source of truth the published page reads. It folds together:
//!   - substrate throughput/scoring/KEX/fanout/signature metrics, each derived from a
//!     REAL criterion bench median (`target/criterion/<group>/<id>/new/estimates.json`);
//!   - in-process MESH measurements (cohort propagation + isolation + A↔B replication)
//!     run live over the real `FountainSwarmRuntime`;
//!   - the EMPIRICAL erasure-survival curve produced by `benches/erasure_survival.rs`
//!     (read from `target/erasure_survival.json`), or an honest GATED entry if absent.
//!
//! Nothing here invents a number: a metric exists only if its bench/measurement produced
//! it, otherwise it is listed in `gated` with the reason.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::mesh;

// ── Schema ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct BenchResults {
    pub schema: &'static str,
    pub commit: String,
    pub date: String,
    pub runner: String,
    pub metrics: Vec<Metric>,
    pub mesh: Mesh,
    pub erasure: Erasure,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_overhead: Option<SignatureOverhead>,
    pub gated: Vec<Gated>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Metric {
    pub id: &'static str,
    pub value: f64,
    pub unit: &'static str,
    pub bench: String,
    pub status: &'static str, // always "measured" here
    pub plain: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mesh {
    pub cohort: Vec<CohortPoint>,
    pub replication: Replication,
}

#[derive(Debug, Clone, Serialize)]
pub struct CohortPoint {
    pub n_total: usize,
    pub group_a_converged: usize,
    pub group_a_expected: usize,
    pub group_b_leaks: usize,
    pub latency_ms: f64,
    pub deliveries: usize,
    /// `true` iff group A fully converged AND group B saw zero leaks (the cohort gate).
    pub passed: bool,
    pub status: &'static str, // "measured"
}

#[derive(Debug, Clone, Serialize)]
pub struct Replication {
    pub emitted_at_a: usize,
    pub observed_at_b: usize,
    pub latency_ms: f64,
    pub status: &'static str, // "measured" | "gated"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub plain: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Erasure {
    Measured {
        codec: String,
        n_source: u32,
        k_repair: u32,
        holders: u32,
        survival: Vec<SurvivalPoint>,
        plain: &'static str,
    },
    Gated {
        status: &'static str, // "gated"
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct SurvivalPoint {
    pub q: f64,
    pub label: String,
    pub p_reconstruct: f64,
    pub trials: u64,
    pub mean_survivors: f64,
    pub status: &'static str, // "measured"
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureOverhead {
    pub classical_sign_verify_us: f64,
    pub hybrid_sign_verify_us: f64,
    pub overhead_pct: f64,
    pub status: &'static str, // "measured"
    pub plain: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Gated {
    pub id: &'static str,
    pub reason: &'static str,
}

// ── Criterion estimate ingestion (median ns per "<group>/<id>") ───────────────

/// Walk `dir` for `**/new/estimates.json`, keying each by `<group>/<id>` and recording
/// `median.point_estimate` (ns). Mirrors the loader in `scoreboard.rs` but kept local so
/// this module is self-contained.
fn load_medians_ns(dir: &Path) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn walk(root: &Path, cur: &Path, out: &mut BTreeMap<String, f64>) {
    let Ok(entries) = std::fs::read_dir(cur) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
        } else if path.file_name().and_then(|f| f.to_str()) == Some("estimates.json") {
            let Some(new_dir) = path.parent() else {
                continue;
            };
            if new_dir.file_name().and_then(|f| f.to_str()) != Some("new") {
                continue;
            }
            let Some(id_dir) = new_dir.parent() else {
                continue;
            };
            let Ok(rel) = id_dir.strip_prefix(root) else {
                continue;
            };
            let key = rel.to_string_lossy().replace('\\', "/");
            if key.starts_with("report") {
                continue;
            }
            if let Some(ns) = read_median_ns(&path) {
                out.insert(key, ns);
            }
        }
    }
}

fn read_median_ns(path: &Path) -> Option<f64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v.get("median")?.get("point_estimate")?.as_f64()
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

const BYTES_PER_GIB: f64 = 1024.0 * 1024.0 * 1024.0;
const FPS: f64 = 30.0;

/// A criterion-derived metric spec: how to turn a `<group>/<id>` median (ns) into a
/// published value/unit/plain-sentence.
struct Derive {
    id: &'static str,
    group: &'static str,
    crit_id: &'static str,
    unit: &'static str,
    plain: &'static str,
    /// median_ns → value.
    map: fn(f64) -> f64,
}

fn substrate_derivations() -> Vec<Derive> {
    vec![
        Derive {
            id: "aead_throughput_per_core",
            group: "av_frame_halves",
            crit_id: "open/16384",
            unit: "GiB/s/core",
            plain: "One CPU core can decrypt about this many gigabytes of video per second on the receive side.",
            map: |ns| round2((16.0 * 1024.0 / (ns * 1e-9)) / BYTES_PER_GIB),
        },
        Derive {
            id: "replication_ingest_per_sec",
            group: "replication_ingest",
            crit_id: "ingest_new",
            unit: "traces/s/core",
            plain: "One CPU core absorbs about this many fresh signed traces per second (verify + decompose + persist).",
            map: |ns| round2(1e9 / ns),
        },
        Derive {
            id: "replication_dedup_per_sec",
            group: "replication_ingest",
            crit_id: "ingest_dedup",
            unit: "traces/s/core",
            plain: "Re-delivered (already-seen) traces are rejected at about this rate — still paying full signature verify, so a gossip flood is bounded by verify speed.",
            map: |ns| round2(1e9 / ns),
        },
        Derive {
            id: "alm_relay_hop_us",
            group: "alm_chain_hop",
            crit_id: "208",
            unit: "µs/hop",
            plain: "Relaying one small (~208 B) blinking-dot frame through one mesh hop costs about this many microseconds of CPU.",
            map: |ns| round4(ns / 1_000.0),
        },
        Derive {
            id: "stream_fanout_core_frac",
            group: "stream_fanout_seal_tick",
            crit_id: "2000",
            unit: "core-fraction @ N=2000, 30fps",
            plain: "Sealing 2,000 simultaneous blob streams at 30 fps uses about this fraction of one CPU core.",
            map: |ns| round4((ns * 1e-9) * FPS),
        },
        Derive {
            id: "n_eff_scoring_per_agent_us",
            group: "n_eff_e2e",
            crit_id: "500",
            unit: "µs/agent @ N=500 traces",
            plain: "Computing one agent's coherence-capacity score over a full 500-trace window takes about this many microseconds.",
            map: |ns| round2(ns / 1_000.0),
        },
        Derive {
            id: "kex_hybrid_initiate_us",
            group: "pqc_kex",
            crit_id: "hybrid_initiate",
            unit: "µs",
            plain: "Starting one post-quantum key exchange (X25519 + ML-KEM-768) takes about this many microseconds.",
            map: |ns| round2(ns / 1_000.0),
        },
        Derive {
            id: "kex_classical_initiate_us",
            group: "pqc_kex",
            crit_id: "classical_initiate",
            unit: "µs",
            plain: "Starting one classical-only (X25519) key exchange takes about this many microseconds.",
            map: |ns| round2(ns / 1_000.0),
        },
        Derive {
            id: "av_frame_e2e_16384_us",
            group: "av_frame_e2e",
            crit_id: "16384",
            unit: "µs/frame",
            plain: "Sealing then opening one 16 KiB 720p video frame end-to-end takes about this many microseconds.",
            map: |ns| round2(ns / 1_000.0),
        },
    ]
}

fn build_metrics(medians: &BTreeMap<String, f64>, gated: &mut Vec<Gated>) -> Vec<Metric> {
    let mut metrics = Vec::new();
    for d in substrate_derivations() {
        let key = format!("{}/{}", d.group, d.crit_id);
        match medians.get(&key) {
            Some(&ns) if ns > 0.0 => metrics.push(Metric {
                id: d.id,
                value: (d.map)(ns),
                unit: d.unit,
                bench: key,
                status: "measured",
                plain: d.plain,
            }),
            _ => gated.push(Gated {
                id: d.id,
                reason: "criterion result absent (bench not run)",
            }),
        }
    }
    metrics
}

fn build_signature_overhead(medians: &BTreeMap<String, f64>) -> Option<SignatureOverhead> {
    let c = medians.get("signature/classical_sign_verify").copied()?;
    let h = medians.get("signature/hybrid_sign_verify").copied()?;
    if c <= 0.0 {
        return None;
    }
    let classical_us = round2(c / 1_000.0);
    let hybrid_us = round2(h / 1_000.0);
    let overhead_pct = round2((h - c) / c * 100.0);
    Some(SignatureOverhead {
        classical_sign_verify_us: classical_us,
        hybrid_sign_verify_us: hybrid_us,
        overhead_pct,
        status: "measured",
        plain: format!(
            "Post-quantum provenance (Ed25519+ML-DSA-65) costs about {overhead_pct}% more CPU per signed event than classical Ed25519 alone."
        ),
    })
}

// ── Erasure sidecar ingestion ─────────────────────────────────────────────────

fn build_erasure(sidecar: &Path) -> Erasure {
    let Ok(raw) = std::fs::read_to_string(sidecar) else {
        return Erasure::Gated {
            status: "gated",
            reason: format!(
                "erasure survival not benched: {} absent (run `cargo bench --bench erasure_survival`)",
                sidecar.display()
            ),
        };
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Erasure::Gated {
            status: "gated",
            reason: "erasure survival sidecar present but unparseable".into(),
        };
    };
    let codec = v
        .get("codec")
        .and_then(|c| c.as_str())
        .unwrap_or("ciris_edge codec-fountain")
        .to_string();
    let n_source = v.get("n_source").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let k_repair = v.get("k_repair").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let holders = v.get("holders").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let Some(arr) = v.get("survival").and_then(|s| s.as_array()) else {
        return Erasure::Gated {
            status: "gated",
            reason: "erasure survival sidecar missing `survival` array".into(),
        };
    };
    let mut survival = Vec::new();
    for p in arr {
        survival.push(SurvivalPoint {
            q: p.get("q").and_then(|x| x.as_f64()).unwrap_or(0.0),
            label: p
                .get("label")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            p_reconstruct: p
                .get("p_reconstruct")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0),
            trials: p.get("trials").and_then(|x| x.as_u64()).unwrap_or(0),
            mean_survivors: p
                .get("mean_survivors")
                .and_then(|x| x.as_f64())
                .unwrap_or(0.0),
            status: "measured",
        });
    }
    if survival.is_empty() {
        return Erasure::Gated {
            status: "gated",
            reason: "erasure survival sidecar had an empty `survival` array".into(),
        };
    }
    Erasure::Measured {
        codec,
        n_source,
        k_repair,
        holders,
        survival,
        plain: "Content is split into redundant fountain shares across holders; this is the measured chance it can still be rebuilt as each tier's fraction of holders goes offline.",
    }
}

// ── Top-level build ───────────────────────────────────────────────────────────

/// Build the full `bench_results.json` model. `criterion_dir` is `target/criterion`;
/// `erasure_sidecar` is `target/erasure_survival.json`. The mesh measurements run live
/// in-process here (a tokio runtime is spun up for them).
pub fn build(
    commit: &str,
    date: &str,
    criterion_dir: &Path,
    erasure_sidecar: &Path,
) -> BenchResults {
    let medians = load_medians_ns(criterion_dir);
    let mut gated: Vec<Gated> = Vec::new();

    let metrics = build_metrics(&medians, &mut gated);

    // Always-gated metrics: no MLS-commit-barrier or cold-join-burst-latency bench
    // exists yet, so we list them honestly rather than inventing a number.
    gated.push(Gated {
        id: "mls_commit_barrier",
        reason: "no MLS-commit-barrier bench yet",
    });
    gated.push(Gated {
        id: "cold_join_burst_latency",
        reason: "no cold-join-burst-latency bench yet",
    });

    let signature_overhead = build_signature_overhead(&medians);
    if signature_overhead.is_none() {
        gated.push(Gated {
            id: "signature_overhead",
            reason: "sig_overhead bench not run (no classical/hybrid criterion medians)",
        });
    }
    let erasure = build_erasure(erasure_sidecar);

    // Run the in-process mesh measurements on their OWN runtime. The caller may already
    // be inside a tokio runtime (the binary's `#[tokio::main]`), so we drive a fresh
    // multi-thread runtime on a dedicated thread to avoid the "runtime within a runtime"
    // panic from `block_on`.
    let (cohort, replication) = std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for mesh measurements");
        rt.block_on(async {
            let mut cohort = Vec::new();
            for &n in &[50usize, 100, 200, 400] {
                let r = mesh::measure_cohort(n, 64).await;
                cohort.push(CohortPoint {
                    n_total: r.n_total,
                    group_a_converged: r.group_a_converged,
                    group_a_expected: r.group_a_expected,
                    group_b_leaks: r.group_b_leaks,
                    latency_ms: round2(r.latency_ms),
                    deliveries: r.deliveries,
                    passed: r.ok,
                    status: "measured",
                });
            }
            let rep = mesh::measure_replication().await;
            (cohort, rep)
        })
    })
    .join()
    .expect("mesh measurement thread");

    let replication = if replication.ok {
        Replication {
            emitted_at_a: replication.emitted_at_a,
            observed_at_b: replication.observed_at_b,
            latency_ms: round2(replication.latency_ms),
            status: "measured",
            reason: None,
            plain: "A signed holding-claim emitted at node A is observed at node B over the real in-process swarm path in about this many milliseconds.",
        }
    } else {
        Replication {
            emitted_at_a: replication.emitted_at_a,
            observed_at_b: replication.observed_at_b,
            latency_ms: f64::NAN,
            status: "gated",
            reason: Some("A→B observation did not converge within the deadline".into()),
            plain: "Node A emits a signed holding-claim; node B should observe it over the real in-process swarm path.",
        }
    };

    BenchResults {
        schema: "ciris-server/bench-results/2",
        commit: commit.to_string(),
        date: date.to_string(),
        runner: runner_string(),
        metrics,
        mesh: Mesh {
            cohort,
            replication,
        },
        erasure,
        signature_overhead,
        gated,
    }
}

fn runner_string() -> String {
    format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
}

impl BenchResults {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("bench_results serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn metrics_derive_from_medians_or_gate() {
        let mut m: BTreeMap<String, f64> = BTreeMap::new();
        // Only replication ran → only that metric is measured; the rest gate honestly.
        m.insert("replication_ingest/ingest_new".into(), 200_000.0); // ns
        let mut gated = Vec::new();
        let metrics = build_metrics(&m, &mut gated);
        let repl = metrics
            .iter()
            .find(|x| x.id == "replication_ingest_per_sec")
            .expect("replication metric present");
        // 1e9 / 200_000 ns = 5000 traces/s.
        assert!((repl.value - 5000.0).abs() < 1.0, "repl {}", repl.value);
        assert_eq!(repl.status, "measured");
        // A metric with no median is gated, not invented.
        assert!(gated.iter().any(|g| g.id == "aead_throughput_per_core"));
        assert!(!metrics.iter().any(|x| x.id == "aead_throughput_per_core"));
    }

    #[test]
    fn signature_overhead_computes_pct() {
        let mut m: BTreeMap<String, f64> = BTreeMap::new();
        m.insert("signature/classical_sign_verify".into(), 35_000.0); // 35 µs
        m.insert("signature/hybrid_sign_verify".into(), 535_000.0); // 535 µs
        let so = build_signature_overhead(&m).expect("overhead present");
        assert_eq!(so.status, "measured");
        assert!((so.classical_sign_verify_us - 35.0).abs() < 0.01);
        assert!((so.hybrid_sign_verify_us - 535.0).abs() < 0.01);
        // (535-35)/35*100 = 1428.57%.
        assert!(
            (so.overhead_pct - 1428.57).abs() < 0.5,
            "pct {}",
            so.overhead_pct
        );
    }

    #[test]
    fn erasure_gates_when_sidecar_absent() {
        let e = build_erasure(Path::new("/nonexistent/erasure_survival.json"));
        match e {
            Erasure::Gated { status, reason } => {
                assert_eq!(status, "gated");
                assert!(reason.contains("not benched"), "reason: {reason}");
            }
            Erasure::Measured { .. } => panic!("absent sidecar must gate, not measure"),
        }
    }

    #[test]
    fn erasure_parses_real_sidecar() {
        let dir = std::env::temp_dir().join("ciris_bench_results_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("erasure_survival.json");
        std::fs::write(
            &path,
            r#"{"schema":"x","codec":"ciris_edge codec-fountain","n_source":20,"k_repair":10,"holders":30,
               "survival":[{"q":0.95,"label":"datacenter","p_reconstruct":1.0,"trials":4000,"mean_survivors":28.5}]}"#,
        )
        .unwrap();
        match build_erasure(&path) {
            Erasure::Measured {
                holders, survival, ..
            } => {
                assert_eq!(holders, 30);
                assert_eq!(survival.len(), 1);
                assert_eq!(survival[0].status, "measured");
                assert!((survival[0].p_reconstruct - 1.0).abs() < 1e-9);
            }
            Erasure::Gated { reason, .. } => panic!("should measure, gated: {reason}"),
        }
        let _ = std::fs::remove_file(&path);
    }
}
