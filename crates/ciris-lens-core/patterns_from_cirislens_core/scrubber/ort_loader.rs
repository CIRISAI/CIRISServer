//! ONNX Runtime backend for XLM-R token-classification NER.
//!
//! Path: ONNX-exported XLM-R + INT8 dynamic quantization (per
//! `optimum-cli export onnx ... && onnxruntime.quantize_dynamic`).
//! Run via `ort` 2.x with the prebuilt onnxruntime shared library
//! (load-dynamic). Lives behind the `ner-ort` feature flag.
//!
//! Why ort: candle's pure-Rust forward path is convenient but
//! significantly slower than ort's optimized CPU kernels (oneDNN /
//! MKL-DNN under the hood). With INT8 dynamic quantization on top,
//! typically 3–4× faster than candle FP32 on the same model with no
//! measurable accuracy loss for NER tasks.
//!
//! The model directory must contain:
//!   - `model.onnx`         (the ONNX model, fp32 or int8-quantized)
//!   - `tokenizer.json`     (HuggingFace fast tokenizer)
//!   - `config.json`        (id2label mapping)
//!
//! Pre-fetch via `optimum-cli export onnx --model <repo-id> <dir>`
//! and quantize via `onnxruntime.quantization.quantize_dynamic`.

#![cfg(feature = "ner-ort")]

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use ndarray::Array2;
use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::Tensor;
use serde::Deserialize;
use tokenizers::Tokenizer;

#[derive(Debug, Deserialize)]
struct HfConfig {
    #[serde(default)]
    id2label: serde_json::Value,
    #[serde(default)]
    num_labels: Option<usize>,
}

pub struct OrtTokenClassifier {
    session: Session,
    pub labels: Vec<String>,
}

impl OrtTokenClassifier {
    pub fn from_dir(dir: &Path) -> Result<(Self, Tokenizer)> {
        Self::from_files(
            &dir.join("model.onnx"),
            &dir.join("tokenizer.json"),
            &dir.join("config.json"),
        )
    }

    fn from_files(
        model_path: &Path,
        tokenizer_path: &Path,
        config_path: &Path,
    ) -> Result<(Self, Tokenizer)> {
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        let hf_config: HfConfig =
            serde_json::from_str(&config_str).context("parse HF metadata from config.json")?;
        let labels = parse_labels(&hf_config)?;

        // intra_threads: workers that parallelize within a single op (e.g.
        // matmul). Tunable via `CIRISLENS_NER_ORT_INTRA_THREADS`. Default
        // is min(8, available_parallelism) — empirically, beyond 8 the
        // matmul shapes in XLM-R-base don't have enough work to amortize
        // thread coordination, and oversubscription on shared hosts hurts
        // tail latency.
        let intra = std::env::var("CIRISLENS_NER_ORT_INTRA_THREADS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| num_cpus_or_default().min(8));
        let session = Session::builder()
            .context("ort SessionBuilder")?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .context("set optimization level")?
            .with_intra_threads(intra)
            .context("set intra threads")?
            .commit_from_file(model_path)
            .with_context(|| format!("load ONNX model {}", model_path.display()))?;

        let mut tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| anyhow!("Tokenizer::from_file: {e}"))?;
        // Backstop truncation; chunked NER stays well below 512 already.
        tokenizer
            .with_truncation(Some(tokenizers::TruncationParams {
                max_length: 512,
                strategy: tokenizers::TruncationStrategy::LongestFirst,
                stride: 0,
                direction: tokenizers::TruncationDirection::Right,
            }))
            .map_err(|e| anyhow!("set truncation: {e}"))?;

        Ok((Self { session, labels }, tokenizer))
    }

    /// Run a forward pass on padded `[batch, seq_len]` int64 inputs.
    /// Returns logits `[batch, seq_len, num_labels]` as a flat Vec along
    /// with the (num_labels) trailing dim so the caller can reshape /
    /// argmax.
    pub fn forward(
        &mut self,
        input_ids: Array2<i64>,
        attention_mask: Array2<i64>,
    ) -> Result<(Vec<f32>, usize, usize, usize)> {
        let (batch, seq_len) = input_ids.dim();
        let num_labels = self.labels.len();

        let ids_tensor = Tensor::from_array(input_ids).context("input_ids tensor")?;
        let mask_tensor = Tensor::from_array(attention_mask).context("attention_mask tensor")?;

        let outputs = self
            .session
            .run(ort::inputs![
                "input_ids" => ids_tensor,
                "attention_mask" => mask_tensor,
            ])
            .context("ort session.run")?;

        // The token-classifier output is named `logits` after optimum's
        // ONNX export. Shape: [batch, seq_len, num_labels].
        let (shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .context("extract logits tensor")?;
        let n = shape.len();
        if n < 1 {
            return Err(anyhow!("logits has no dims"));
        }
        let last = shape[n - 1] as usize;
        if last != num_labels {
            return Err(anyhow!(
                "logits last dim {last} != num_labels {num_labels}"
            ));
        }
        Ok((data.to_vec(), batch, seq_len, num_labels))
    }
}

fn parse_labels(cfg: &HfConfig) -> Result<Vec<String>> {
    use serde_json::Value;
    if let Value::Object(map) = &cfg.id2label {
        let mut items: Vec<(usize, String)> = map
            .iter()
            .filter_map(|(k, v)| {
                let id: usize = k.parse().ok()?;
                let label = v.as_str()?.to_string();
                Some((id, label))
            })
            .collect();
        items.sort_by_key(|(id, _)| *id);
        let labels: Vec<String> = items.into_iter().map(|(_, l)| l).collect();
        if !labels.is_empty() {
            return Ok(labels);
        }
    }
    if cfg.num_labels == Some(7) || cfg.num_labels.is_none() {
        return Ok(
            ["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
    }
    Err(anyhow!(
        "config.json missing id2label and num_labels != 7; cannot infer label set"
    ))
}

fn num_cpus_or_default() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

pub enum OrtSource {
    LocalDir(PathBuf),
}

impl OrtSource {
    pub fn from_env() -> Result<Self> {
        let dir = std::env::var("CIRISLENS_NER_ORT_DIR")
            .map_err(|_| anyhow!("CIRISLENS_NER_ORT_DIR not set"))?;
        Ok(OrtSource::LocalDir(PathBuf::from(dir)))
    }

    pub fn load(&self) -> Result<(OrtTokenClassifier, Tokenizer)> {
        match self {
            OrtSource::LocalDir(p) => OrtTokenClassifier::from_dir(p),
        }
    }
}
