//! XLM-RoBERTa loader for token classification.
//!
//! `candle-transformers` ships `XLMRobertaModel` (the backbone) and
//! `XLMRobertaForSequenceClassification` (with pooled output for sequence
//! tasks), but no `XLMRobertaForTokenClassification`. We assemble that
//! variant locally: backbone → optional dropout → linear classifier head
//! over the per-token hidden states.
//!
//! HF's `Davlan/xlm-roberta-base-wikiann-ner` checkpoint stores the
//! classifier weights at `classifier.weight` / `classifier.bias` (sibling
//! of the `roberta.*` namespace). This module is structured to match.

#![cfg(feature = "ner")]

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use candle_core::{DType, Device, Tensor};
use candle_nn::{Linear, Module, VarBuilder};
use candle_transformers::models::xlm_roberta::{Config, XLMRobertaModel};
use serde::Deserialize;
use tokenizers::Tokenizer;

/// Parsed `config.json`. We only need `num_labels` and the id-to-label
/// mapping; the rest is consumed by candle's `Config`.
#[derive(Debug, Deserialize)]
struct HfConfig {
    #[serde(default)]
    id2label: serde_json::Value,
    #[serde(default)]
    num_labels: Option<usize>,
}

/// Locally-assembled XLM-R for token classification.
pub struct XLMRTokenClassifier {
    backbone: XLMRobertaModel,
    classifier: Linear,
    pub labels: Vec<String>,
    pub device: Device,
    pub dtype: DType,
}

impl XLMRTokenClassifier {
    /// Load weights + tokenizer from a local directory (config.json,
    /// tokenizer.json, model.safetensors). For air-gapped deploys.
    pub fn from_dir(dir: &Path) -> Result<(Self, Tokenizer)> {
        let model_path = dir.join("model.safetensors");
        let tokenizer_path = dir.join("tokenizer.json");
        let config_path = dir.join("config.json");
        Self::from_files(&model_path, &tokenizer_path, &config_path)
    }

    /// Load weights + tokenizer from Hugging Face Hub (default code path).
    /// Files are cached to `HF_HOME` / `~/.cache/huggingface/hub/`.
    pub fn from_hf_hub(model_id: &str) -> Result<(Self, Tokenizer)> {
        let api = hf_hub::api::sync::Api::new()
            .context("hf-hub Api::new")?;
        let repo = api.model(model_id.to_string());
        let model_path = repo
            .get("model.safetensors")
            .with_context(|| format!("fetch model.safetensors from {model_id}"))?;
        let tokenizer_path = repo
            .get("tokenizer.json")
            .with_context(|| format!("fetch tokenizer.json from {model_id}"))?;
        let config_path = repo
            .get("config.json")
            .with_context(|| format!("fetch config.json from {model_id}"))?;
        Self::from_files(&model_path, &tokenizer_path, &config_path)
    }

    fn from_files(
        model_path: &Path,
        tokenizer_path: &Path,
        config_path: &Path,
    ) -> Result<(Self, Tokenizer)> {
        // 1. Parse config — both candle's structural Config and the HF metadata.
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        let candle_config: Config = serde_json::from_str(&config_str)
            .context("parse candle Config from config.json")?;
        let hf_config: HfConfig =
            serde_json::from_str(&config_str).context("parse HF metadata from config.json")?;
        let labels = parse_labels(&hf_config)?;
        let num_labels = labels.len();

        // 2. Load weights via mmap'd safetensors.
        let device = pick_device();
        let dtype = DType::F32;
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(
                &[model_path.to_path_buf()],
                dtype,
                &device,
            )
        }
        .with_context(|| format!("mmap {}", model_path.display()))?;

        // 3. Build the backbone (under `roberta.*`) and a token-classification
        //    head (Linear at `classifier.*`). The HF token-classification
        //    checkpoints store the head this way.
        let backbone = XLMRobertaModel::new(&candle_config, vb.pp("roberta"))
            .context("XLMRobertaModel::new")?;
        let classifier =
            candle_nn::linear(candle_config.hidden_size, num_labels, vb.pp("classifier"))
                .context("classifier head linear")?;

        // 4. Tokenizer. Configure truncation at 512 tokens as a backstop:
        //    chunked NER (`scrubber::ner`) keeps each chunk below 384 raw
        //    tokens already, but if BPE re-fragmentation pushes any chunk
        //    over 512, truncation prevents the forward pass from
        //    out-of-bounds-indexing the position embeddings (XLM-R caps
        //    at position 513, sequence length 514).
        let mut tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| anyhow!("Tokenizer::from_file: {e}"))?;
        tokenizer
            .with_truncation(Some(tokenizers::TruncationParams {
                max_length: 512,
                strategy: tokenizers::TruncationStrategy::LongestFirst,
                stride: 0,
                direction: tokenizers::TruncationDirection::Right,
            }))
            .map_err(|e| anyhow!("set truncation: {e}"))?;

        Ok((
            Self {
                backbone,
                classifier,
                labels,
                device,
                dtype,
            },
            tokenizer,
        ))
    }

    /// Forward pass — returns per-token logits of shape
    /// `[batch, seq_len, num_labels]`. Caller does argmax along the
    /// last axis. Preserves the batch dim so this works for batched
    /// inference (multiple chunks in one forward call).
    pub fn forward(&self, input_ids: &Tensor, attention_mask: &Tensor) -> Result<Tensor> {
        // XLM-R takes `token_type_ids` even though it only uses one segment;
        // zeros matching input_ids shape is the standard default.
        let token_type_ids = input_ids
            .zeros_like()
            .context("zeros_like for token_type_ids")?;

        let hidden = self
            .backbone
            .forward(
                input_ids,
                attention_mask,
                &token_type_ids,
                None,
                None,
                None,
            )
            .context("backbone forward")?;

        // hidden: [batch, seq_len, hidden_size]
        // logits: [batch, seq_len, num_labels]
        let logits = self.classifier.forward(&hidden).context("classifier forward")?;
        Ok(logits)
    }
}

fn parse_labels(cfg: &HfConfig) -> Result<Vec<String>> {
    use serde_json::Value;
    if let Value::Object(map) = &cfg.id2label {
        // HF stores id2label as `{"0": "O", "1": "B-PER", ...}` — string keys.
        // Sort by integer key value to get a deterministic ordering.
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

    // Fallback: wikiann default ordering when the checkpoint omits id2label.
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

fn pick_device() -> Device {
    // CPU is the v2 baseline. Future: detect CUDA/Metal via candle features.
    Device::Cpu
}

/// Resolve the model source from env vars. Returns either a local dir
/// (when `CIRISLENS_NER_MODEL_DIR` is set) or an HF hub ID (default
/// `Davlan/xlm-roberta-base-wikiann-ner`).
pub enum ModelSource {
    LocalDir(PathBuf),
    HfHub(String),
}

impl ModelSource {
    pub fn from_env() -> Self {
        if let Ok(dir) = std::env::var("CIRISLENS_NER_MODEL_DIR") {
            return ModelSource::LocalDir(PathBuf::from(dir));
        }
        let id = std::env::var("CIRISLENS_NER_MODEL_ID")
            .unwrap_or_else(|_| "Davlan/xlm-roberta-base-wikiann-ner".to_string());
        ModelSource::HfHub(id)
    }

    pub fn load(&self) -> Result<(XLMRTokenClassifier, Tokenizer)> {
        match self {
            ModelSource::LocalDir(p) => XLMRTokenClassifier::from_dir(p),
            ModelSource::HfHub(id) => XLMRTokenClassifier::from_hf_hub(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_labels_from_id2label() {
        let cfg = HfConfig {
            id2label: serde_json::json!({"0": "O", "1": "B-PER", "2": "I-PER"}),
            num_labels: Some(3),
        };
        let labels = parse_labels(&cfg).unwrap();
        assert_eq!(labels, vec!["O", "B-PER", "I-PER"]);
    }

    #[test]
    fn parse_labels_falls_back_to_wikiann_default() {
        let cfg = HfConfig {
            id2label: serde_json::Value::Null,
            num_labels: Some(7),
        };
        let labels = parse_labels(&cfg).unwrap();
        assert_eq!(labels.len(), 7);
        assert_eq!(labels[0], "O");
        assert_eq!(labels[1], "B-PER");
    }
}
