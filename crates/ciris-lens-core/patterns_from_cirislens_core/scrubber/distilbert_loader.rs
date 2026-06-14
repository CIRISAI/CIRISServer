//! DistilBERT-multilingual loader for token classification.
//!
//! Pairs with [`crate::scrubber::xlm_r_loader`]. Same input/output
//! contract: load + tokenizer from a directory or HF hub, expose a
//! `forward(input_ids, attention_mask) -> logits[batch, seq, num_labels]`
//! API. The token-classification head is a single Linear layer over the
//! per-token hidden state — HF's
//! `Davlan/distilbert-base-multilingual-cased-ner-hrl` checkpoint
//! stores it at `classifier.{weight,bias}`.
//!
//! Why DistilBERT for v2 NER: 6 layers vs XLM-R-base's 12, same hidden
//! width, ~½ the params and roughly ½ the inference cost on CPU. The
//! HF NER checkpoint also adds B-DATE/I-DATE labels (XLM-R-WikiANN
//! doesn't tag DATE), so we get freer year-context coverage.

#![cfg(feature = "ner")]

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use candle_core::{DType, Device, Tensor};
use candle_nn::{Linear, Module, VarBuilder};
use candle_transformers::models::distilbert::{Config as DistilConfig, DistilBertModel};
use serde::Deserialize;
use tokenizers::Tokenizer;

#[derive(Debug, Deserialize)]
struct HfConfig {
    #[serde(default)]
    id2label: serde_json::Value,
    #[serde(default)]
    num_labels: Option<usize>,
}

pub struct DistilBertTokenClassifier {
    backbone: DistilBertModel,
    classifier: Linear,
    pub labels: Vec<String>,
    pub device: Device,
    pub dtype: DType,
}

impl DistilBertTokenClassifier {
    pub fn from_dir(dir: &Path) -> Result<(Self, Tokenizer)> {
        Self::from_files(
            &dir.join("model.safetensors"),
            &dir.join("tokenizer.json"),
            &dir.join("config.json"),
        )
    }

    pub fn from_hf_hub(model_id: &str) -> Result<(Self, Tokenizer)> {
        let api = hf_hub::api::sync::Api::new().context("hf-hub Api::new")?;
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
        let config_str = std::fs::read_to_string(config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        let candle_config: DistilConfig = serde_json::from_str(&config_str)
            .context("parse candle DistilConfig from config.json")?;
        let hf_config: HfConfig =
            serde_json::from_str(&config_str).context("parse HF metadata from config.json")?;
        let labels = parse_labels(&hf_config)?;
        let num_labels = labels.len();

        let device = Device::Cpu;
        let dtype = DType::F32;
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[model_path.to_path_buf()], dtype, &device)
        }
        .with_context(|| format!("mmap {}", model_path.display()))?;

        // The candle DistilBertModel::load already handles the optional
        // `distilbert.*` prefix internally (see its source). The classifier
        // sits at the top level under `classifier.{weight,bias}`.
        let backbone = DistilBertModel::load(vb.clone(), &candle_config)
            .context("DistilBertModel::load")?;
        let classifier = candle_nn::linear(candle_config.dim, num_labels, vb.pp("classifier"))
            .context("classifier head linear")?;

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

    /// Forward pass — returns logits `[batch, seq_len, num_labels]`.
    ///
    /// **Mask transform.** Two corrections vs the standard HF
    /// attention_mask (shape `[batch, seq]`, `1` = valid):
    ///
    ///   1. **Polarity inversion.** candle's DistilBERT attention does
    ///      `masked_fill(scores, mask, -inf)`, so `1` in its mask means
    ///      *mask out*. Invert: `1 - mask`.
    ///   2. **Shape.** The attention block broadcasts the mask across
    ///      heads and query rows: scores are `[batch, n_heads, q, k]`,
    ///      so the mask must be `[batch, 1, 1, seq]`. We reshape after
    ///      inverting.
    pub fn forward(&self, input_ids: &Tensor, attention_mask: &Tensor) -> Result<Tensor> {
        let (batch, seq_len) = attention_mask.dims2().context("mask dims")?;

        // 1. Invert (HF 1=valid → candle 0=attend).
        let one = Tensor::ones_like(attention_mask).context("ones for mask invert")?;
        let inverted = (one - attention_mask).context("invert mask")?;
        // 2. Reshape [batch, seq] → [batch, 1, 1, seq] for broadcast over
        //    heads and query rows in the attention scores.
        let candle_mask = inverted
            .reshape((batch, 1usize, 1usize, seq_len))
            .context("reshape mask for broadcast")?;

        let hidden = self
            .backbone
            .forward(input_ids, &candle_mask)
            .context("backbone forward")?;
        // hidden: [batch, seq_len, hidden_dim]
        let logits = self
            .classifier
            .forward(&hidden)
            .context("classifier forward")?;
        Ok(logits)
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
    if cfg.num_labels == Some(9) || cfg.num_labels.is_none() {
        // hrl default: O B-DATE I-DATE B-PER I-PER B-ORG I-ORG B-LOC I-LOC
        return Ok(vec![
            "O".into(),
            "B-DATE".into(),
            "I-DATE".into(),
            "B-PER".into(),
            "I-PER".into(),
            "B-ORG".into(),
            "I-ORG".into(),
            "B-LOC".into(),
            "I-LOC".into(),
        ]);
    }
    Err(anyhow!(
        "config.json missing id2label and num_labels != 9; cannot infer label set"
    ))
}

/// Resolve a DistilBERT model source from env vars. Mirrors XLM-R's
/// `ModelSource`. Local dir takes priority over HF hub id.
pub enum DistilBertSource {
    LocalDir(PathBuf),
    HfHub(String),
}

impl DistilBertSource {
    pub fn from_env() -> Self {
        if let Ok(dir) = std::env::var("CIRISLENS_NER_MODEL_DIR") {
            return DistilBertSource::LocalDir(PathBuf::from(dir));
        }
        let id = std::env::var("CIRISLENS_NER_MODEL_ID")
            .unwrap_or_else(|_| "Davlan/distilbert-base-multilingual-cased-ner-hrl".to_string());
        DistilBertSource::HfHub(id)
    }

    pub fn load(&self) -> Result<(DistilBertTokenClassifier, Tokenizer)> {
        match self {
            DistilBertSource::LocalDir(p) => DistilBertTokenClassifier::from_dir(p),
            DistilBertSource::HfHub(id) => DistilBertTokenClassifier::from_hf_hub(id),
        }
    }
}
