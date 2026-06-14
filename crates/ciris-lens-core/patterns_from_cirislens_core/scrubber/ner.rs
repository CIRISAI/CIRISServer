//! NER inference path — XLM-RoBERTa NER via candle.
//!
//! Inference backend: [`candle`](https://github.com/huggingface/candle),
//! HuggingFace's pure-Rust ML framework. Selected over ort/ONNX after a
//! cross-comparison (see FSD §10): native XLM-R support, no native deps,
//! HF-maintained, optional CUDA/Metal acceleration, immune to the
//! ort/ort-sys version-skew issues.
//!
//! Behind the `ner` feature flag (see `Cargo.toml`). Default builds skip
//! candle entirely; CI stays fast.
//!
//! ## Status
//!
//! [`is_configured`] currently returns `false` even when the feature is on
//! — the candle XLM-R backend is scaffolded with the right API surface
//! but not yet loading model weights. Per FSD §6, this means full_traces
//! traces are correctly rejected with `ScrubError::NerNotConfigured`.
//!
//! The remaining work to flip `is_configured` to `true`:
//!
//! 1. Add a `xlm_r_loader` submodule that wraps
//!    `candle_transformers::models::xlm_roberta::XLMRobertaModel`
//!    plus a token-classification head.
//! 2. Lazy-load weights from `safetensors` or HF Hub via `hf-hub` crate.
//! 3. Tokenize with `tokenizers::Tokenizer`.
//! 4. Forward pass: `model.forward(input_ids, attention_mask)?` →
//!    classifier head → logits → argmax.
//! 5. BIO collapse → span replacement (the [`collapse_bio`] +
//!    [`replace_spans`] helpers in this module already do this; they're
//!    framework-agnostic).
//!
//! The post-inference logic (BIO collapse, char-offset span replacement,
//! per-tag counter) is unit-tested here and ready for whichever backend
//! produces the per-token label IDs.

use super::{ScrubError, ScrubStats};

/// Returns `true` only when an NER backend is fully loaded and ready.
/// Caller (see `scrubber::scrub_trace`) must reject `FullTraces` traces
/// when this returns `false`.
#[cfg(feature = "ner")]
pub fn is_configured() -> bool {
    #[cfg(feature = "ner-ort")]
    if backend_choice() == BackendChoice::Ort {
        return ort_backend::is_configured();
    }
    backend::is_configured()
}

#[cfg(not(feature = "ner"))]
pub fn is_configured() -> bool {
    false
}

/// Backend selector. ort wins when `CIRISLENS_NER_BACKBONE=ort` AND the
/// `ner-ort` feature was compiled in. Otherwise we fall through to the
/// candle backend (which itself can dispatch xlm-r vs distilbert via the
/// same env var).
#[cfg(feature = "ner")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendChoice {
    Candle,
    #[cfg(feature = "ner-ort")]
    Ort,
}

#[cfg(feature = "ner")]
fn backend_choice() -> BackendChoice {
    #[cfg(feature = "ner-ort")]
    {
        match std::env::var("CIRISLENS_NER_BACKBONE")
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
        {
            Ok(s) if s == "ort" || s == "ort-int8" || s == "onnx" => return BackendChoice::Ort,
            _ => {}
        }
    }
    BackendChoice::Candle
}

/// Run NER over a single text and replace entity spans with placeholders.
/// Returns `Err(ScrubError::NerNotConfigured)` when the `ner` feature is
/// disabled or the backend isn't ready.
///
/// Prefer [`scrub_batch`] when scrubbing more than one text — a single
/// forward pass over a batch of texts is 5–10× faster than this loop.
pub fn scrub_with_ner(text: &str, stats: &mut ScrubStats) -> Result<String, ScrubError> {
    if !is_configured() {
        return Err(ScrubError::NerNotConfigured);
    }

    #[cfg(feature = "ner")]
    {
        // Single-text path: just route through the batched scrub with batch=1.
        let mut out = backend::scrub_batch(&[text.to_string()], stats)?;
        Ok(out.pop().unwrap_or_default())
    }
    #[cfg(not(feature = "ner"))]
    {
        let _ = (text, stats);
        Err(ScrubError::NerNotConfigured)
    }
}

/// Run NER over a batch of texts in a single forward pass. Returns the
/// scrubbed strings in the same order as the input. Long texts are
/// chunked transparently. Cached content (same input string seen
/// before) is served from an in-process cache; only cache misses
/// reach the model. On the production HF corpus the dedup ratio is
/// ~98.8% (858K eligible strings → 10K unique), so the cache turns
/// model-bound throughput into hash-bound throughput for repeat
/// content.
///
/// The cache is per-process, salted by `CACHE_VERSION`. Bump the salt
/// whenever scrubbing rules change so stale entries don't bleed into
/// new ruleset outputs.
pub fn scrub_batch(texts: &[String], stats: &mut ScrubStats) -> Result<Vec<String>, ScrubError> {
    if !is_configured() {
        return Err(ScrubError::NerNotConfigured);
    }

    if texts.is_empty() {
        return Ok(Vec::new());
    }

    // Split inputs into cache hits and misses. **Within-batch dedupe**:
    // if the same novel string appears N times in this batch, we only
    // send it to the model once and broadcast the result. On the
    // production HF corpus a single batch can contain hundreds of
    // occurrences of the same schema label.
    let cache = ner_cache();
    let mut out: Vec<Option<String>> = vec![None; texts.len()];
    // For each input, either (a) it hit the cache and out[i] is set,
    // or (b) it's a miss; we record the dedup-index it maps to so we
    // can fill out[i] after running the model on the dedup'd misses.
    let mut miss_dedup_index: Vec<usize> = vec![usize::MAX; texts.len()];
    let mut deduped_misses: Vec<String> = Vec::new();
    let mut miss_lookup: HashMap<String, usize> = HashMap::new();
    {
        let guard = cache.lock();
        for (i, t) in texts.iter().enumerate() {
            if let Some(cached) = guard.get(t) {
                out[i] = Some(cached.clone());
                stats.ner_cache_hits += 1;
            } else if let Some(&dedup_idx) = miss_lookup.get(t) {
                // Same novel string seen earlier in this batch; reuse slot.
                miss_dedup_index[i] = dedup_idx;
            } else {
                let dedup_idx = deduped_misses.len();
                miss_lookup.insert(t.clone(), dedup_idx);
                deduped_misses.push(t.clone());
                miss_dedup_index[i] = dedup_idx;
            }
        }
    }

    // Run NER on the deduped misses only (single batched forward pass).
    if !deduped_misses.is_empty() {
        stats.ner_cache_misses += deduped_misses.len();
        #[cfg(feature = "ner")]
        let computed = match backend_choice() {
            #[cfg(feature = "ner-ort")]
            BackendChoice::Ort => ort_backend::scrub_batch(&deduped_misses, stats)?,
            BackendChoice::Candle => backend::scrub_batch(&deduped_misses, stats)?,
        };
        #[cfg(not(feature = "ner"))]
        let computed: Vec<String> = {
            let _ = stats;
            return Err(ScrubError::NerNotConfigured);
        };

        // Populate cache and broadcast the deduped results back to all
        // occurrences in the input order.
        {
            let mut guard = cache.lock();
            for (text, scrubbed) in deduped_misses.iter().zip(computed.iter()) {
                guard.insert(text.clone(), scrubbed.clone());
            }
        }
        for (i, dedup_idx) in miss_dedup_index.iter().enumerate() {
            if *dedup_idx != usize::MAX {
                out[i] = Some(computed[*dedup_idx].clone());
            }
        }
    }

    Ok(out.into_iter().map(|x| x.unwrap_or_default()).collect())
}

// ───────────────────────────────────────────────────────────────────────────
// Content cache
//
// Keyed by the raw input text (String). Hit rate on repeated boilerplate
// (schema labels, canonical prompts, recurring metadata values) is
// dominant on real workloads — see the corpus measurement in
// scripts/scrubber_bench.py.
//
// No eviction yet: at unique-string bound (~10K entries × ~200 bytes avg
// on the production corpus = ~2 MB) it doesn't matter for the rescrub.
// For long-running prod processes, swap to an LRU once we measure the
// growth curve under live ingest.
// ───────────────────────────────────────────────────────────────────────────

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::OnceLock;

static NER_CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn ner_cache() -> &'static Mutex<HashMap<String, String>> {
    NER_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Reset the NER cache. Test-only; production processes leave the
/// cache populated for the lifetime of the worker.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn clear_ner_cache_for_tests() {
    if let Some(c) = NER_CACHE.get() {
        c.lock().clear();
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Framework-agnostic post-inference helpers (BIO collapse, span replacement)
// ───────────────────────────────────────────────────────────────────────────
//
// These work regardless of which inference framework produces the per-token
// labels. They live outside the `backend` module so they're available to
// both unit tests and any future framework swap.

/// Collapse BIO-tagged sub-tokens into character-offset entity spans.
/// Returns `(start_byte, end_byte, tag)` triples in token order.
#[cfg_attr(not(any(feature = "ner", test)), allow(dead_code))]
pub(crate) fn collapse_bio(
    label_ids: &[usize],
    offsets: &[(usize, usize)],
    labels: &[String],
) -> Vec<(usize, usize, String)> {
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    let mut current: Option<(usize, usize, String)> = None;

    for (i, &lid) in label_ids.iter().enumerate() {
        let (start, end) = offsets.get(i).copied().unwrap_or((0, 0));
        if start == end {
            // Special token (CLS, SEP, PAD) — break any in-progress span.
            if let Some(span) = current.take() {
                spans.push(span);
            }
            continue;
        }

        let label = labels.get(lid).map(String::as_str).unwrap_or("O");
        if label == "O" {
            if let Some(span) = current.take() {
                spans.push(span);
            }
            continue;
        }

        let (prefix, tag) = label.split_once('-').unwrap_or(("I", label));
        let tag = tag.to_string();

        match (&mut current, prefix) {
            (Some((_, ce, ct)), "I") if *ct == tag => {
                *ce = end; // continue current span
            }
            _ => {
                if let Some(span) = current.take() {
                    spans.push(span);
                }
                current = Some((start, end, tag));
            }
        }
    }
    if let Some(span) = current.take() {
        spans.push(span);
    }
    spans
}

/// Replace byte-offset spans with `[<TAG>_<n>]` placeholders. Per-tag
/// counter so two PERSON spans become `[PER_1]` and `[PER_2]`.
#[cfg_attr(not(any(feature = "ner", test)), allow(dead_code))]
pub(crate) fn replace_spans(
    text: &str,
    spans: &[(usize, usize, String)],
    stats: &mut ScrubStats,
) -> String {
    if spans.is_empty() {
        return text.to_string();
    }

    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut cursor = 0usize;

    let mut sorted: Vec<&(usize, usize, String)> = spans.iter().collect();
    sorted.sort_by_key(|s| s.0);

    for (start, end, tag) in sorted {
        if *start < cursor || *end > bytes.len() {
            continue; // overlap or out-of-bounds — defensive
        }
        out.push_str(std::str::from_utf8(&bytes[cursor..*start]).unwrap_or(""));
        let n = counts.entry(tag.clone()).or_insert(0);
        *n += 1;
        out.push_str(&format!("[{}_{}]", tag, n));
        stats.entities_redacted += 1;
        cursor = *end;
    }
    if cursor < bytes.len() {
        out.push_str(std::str::from_utf8(&bytes[cursor..]).unwrap_or(""));
    }
    out
}

// ───────────────────────────────────────────────────────────────────────────
// candle backend (behind `ner` feature)
// ───────────────────────────────────────────────────────────────────────────

#[cfg(feature = "ner")]
mod backend {
    //! candle-based XLM-R NER inference.
    //!
    //! Lazy-loads model + tokenizer from HF Hub (or a local dir via
    //! `CIRISLENS_NER_MODEL_DIR`). On first call, attempts to construct
    //! the backend; on success caches it; on failure logs and stays
    //! unconfigured (full_traces traces will be rejected).

    use super::{collapse_bio, replace_spans, ScrubError, ScrubStats};
    use crate::scrubber::distilbert_loader::{DistilBertSource, DistilBertTokenClassifier};
    use crate::scrubber::xlm_r_loader::{ModelSource as XlmrSource, XLMRTokenClassifier};
    use candle_core::Tensor;
    use parking_lot::Mutex;
    use std::sync::OnceLock;
    use tokenizers::Tokenizer;

    /// Per-process backend. `OnceLock` ensures init runs at most once;
    /// `Mutex` serializes concurrent inference calls (candle is not
    /// thread-safe by default for shared models without external sync).
    static BACKEND: OnceLock<Option<Mutex<Backend>>> = OnceLock::new();

    /// Two model variants: distilbert (default — half the layers of XLM-R,
    /// roughly 2× faster on CPU, includes B-DATE/I-DATE labels) and
    /// xlm-r (legacy / bigger). Pick via `CIRISLENS_NER_BACKBONE=distilbert|xlm-r`.
    enum Model {
        DistilBert(DistilBertTokenClassifier),
        XlmR(XLMRTokenClassifier),
    }

    impl Model {
        fn forward(&self, ids: &Tensor, mask: &Tensor) -> anyhow::Result<Tensor> {
            match self {
                Self::DistilBert(m) => m.forward(ids, mask),
                Self::XlmR(m) => m.forward(ids, mask),
            }
        }
        fn device(&self) -> &candle_core::Device {
            match self {
                Self::DistilBert(m) => &m.device,
                Self::XlmR(m) => &m.device,
            }
        }
        fn labels(&self) -> &[String] {
            match self {
                Self::DistilBert(m) => &m.labels,
                Self::XlmR(m) => &m.labels,
            }
        }
        fn name(&self) -> &'static str {
            match self {
                Self::DistilBert(_) => "DistilBERT-multilingual",
                Self::XlmR(_) => "XLM-R-base",
            }
        }
    }

    struct Backend {
        model: Model,
        tokenizer: Tokenizer,
    }

    fn pick_backbone() -> &'static str {
        // Defaults to XLM-R. DistilBERT-multilingual was tested as a
        // smaller/faster alternative but candle's reference DistilBERT
        // implementation regressed end-to-end throughput vs XLM-R on
        // the production HF corpus benchmark (0.78 vs 2.0 traces/sec) —
        // probably a combination of less-optimized layer code and
        // WordPiece producing slightly more tokens than XLM-R's
        // sentencepiece on the same text. Kept the loader as an option
        // (`CIRISLENS_NER_BACKBONE=distilbert`) so we can re-evaluate
        // when candle's distilbert improves or we swap to a
        // quantized backend.
        match std::env::var("CIRISLENS_NER_BACKBONE")
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
        {
            Ok(s) if s == "distilbert" => "distilbert",
            _ => "xlm-r",
        }
    }

    fn init() -> Option<Mutex<Backend>> {
        let backbone = pick_backbone();
        let load_result: anyhow::Result<(Model, Tokenizer)> = match backbone {
            "xlm-r" => XlmrSource::from_env()
                .load()
                .map(|(m, t)| (Model::XlmR(m), t)),
            _ => DistilBertSource::from_env()
                .load()
                .map(|(m, t)| (Model::DistilBert(m), t)),
        };
        match load_result {
            Ok((model, tokenizer)) => {
                let msg = format!(
                    "NER backend ready (candle / {}): {} labels",
                    model.name(),
                    model.labels().len()
                );
                log::info!("{msg}");
                // Also surface to stderr so it's visible without a configured
                // logger (PyO3 callers don't always wire one up).
                eprintln!("[cirislens_core] {msg}");
                Some(Mutex::new(Backend { model, tokenizer }))
            }
            Err(e) => {
                let msg = format!("NER backend load failed: {e:#}");
                log::error!("{msg}");
                eprintln!("[cirislens_core] {msg}");
                None
            }
        }
    }

    pub fn is_configured() -> bool {
        BACKEND.get_or_init(init).is_some()
    }

    /// Chunk size has two competing effects:
    ///   1. Attention is O(n²) per chunk — smaller `n` → faster per chunk.
    ///   2. Smaller chunks → more total chunks per text → more forward calls.
    ///
    /// XLM-R caps at 514 position embeddings (510 content + 2 specials).
    /// We deliberately stay well below to give margin against BPE
    /// re-fragmentation when slicing the original text on boundaries
    /// from the full encoding. 192 was empirically the sweet spot on
    /// the production HF corpus benchmark: dropping from 384 → 192
    /// roughly halved per-chunk forward time without noticeably
    /// increasing total chunk count (most fields are short enough to
    /// fit in one 192-token chunk anyway).
    ///
    /// The tokenizer-side `with_truncation(512)` added in the loader is
    /// the hard backstop that protects the position-embedding lookup
    /// even if a chunk re-fragments past this target.
    const MAX_TOKENS_PER_CHUNK: usize = 192;

    /// Cap on the number of chunks per forward call. Empirically 64 is
    /// the sweet spot on the corpus — larger batches (128, 256) regress
    /// because cache lines / SIMD utilization don't scale linearly with
    /// batch dim once the tensors exceed L2.
    const MAX_BATCH_CHUNKS: usize = 64;

    /// Pre-chunk a single text into MAX_TOKENS_PER_CHUNK windows. Returns
    /// `(byte_offset_in_text, chunk_str)` pairs — the offsets are the
    /// byte positions of each chunk's start in the original text, used
    /// to translate chunk-local entity spans back to global positions.
    fn pre_chunk<'a>(
        text: &'a str,
        tokenizer: &Tokenizer,
    ) -> Result<Vec<(usize, &'a str)>, ScrubError> {
        let full = tokenizer
            .encode(text, false)
            .map_err(|e| ScrubError::NerFailed(format!("tokenize: {e}")))?;
        let total = full.get_ids().len();
        if total == 0 {
            return Ok(Vec::new());
        }
        let offsets = full.get_offsets();

        let mut chunks = Vec::new();
        let mut tok_start = 0usize;
        while tok_start < total {
            let tok_end = (tok_start + MAX_TOKENS_PER_CHUNK).min(total);
            let byte_start = offsets[tok_start].0;
            let byte_end = offsets[tok_end - 1].1;
            if byte_end > byte_start {
                chunks.push((byte_start, &text[byte_start..byte_end]));
            }
            tok_start = tok_end;
        }
        Ok(chunks)
    }

    pub fn scrub_batch(
        texts: &[String],
        stats: &mut ScrubStats,
    ) -> Result<Vec<String>, ScrubError> {
        let backend = BACKEND
            .get_or_init(init)
            .as_ref()
            .ok_or(ScrubError::NerNotConfigured)?;
        let backend = backend.lock();

        if texts.is_empty() {
            return Ok(Vec::new());
        }

        // 1. Pre-chunk every text. `flat_chunks[i] = (origin_text_idx, byte_offset_in_origin, chunk_str)`.
        let mut flat_chunks: Vec<(usize, usize, &str)> = Vec::new();
        for (i, text) in texts.iter().enumerate() {
            for (offset, chunk) in pre_chunk(text, &backend.tokenizer)? {
                flat_chunks.push((i, offset, chunk));
            }
        }

        // Per-text accumulator of entity spans (offsets are global to each text).
        let mut per_text_spans: Vec<Vec<(usize, usize, String)>> = vec![Vec::new(); texts.len()];

        // 2. Sort chunks by length, then bucket into mini-batches of up to
        //    MAX_BATCH_CHUNKS. With sort+bucket the padded sequence
        //    length within a batch is bounded by the variance of similar-
        //    length chunks rather than by the global max — short
        //    schema-label chunks no longer get padded out to the
        //    longest reasoning-text chunk in the batch. Empirically
        //    this is the difference between cross-trace batching helping
        //    and hurting on real corpus shape.
        flat_chunks.sort_by_key(|(_, _, s)| s.len());

        for batch in flat_chunks.chunks(MAX_BATCH_CHUNKS) {
            run_batch(&backend, batch, &mut per_text_spans)?;
        }

        // 3. Per text, replace its accumulated spans on the original string.
        let mut out = Vec::with_capacity(texts.len());
        for (i, text) in texts.iter().enumerate() {
            out.push(replace_spans(text, &per_text_spans[i], stats));
        }
        Ok(out)
    }

    /// Run one batched forward pass over `batch` chunks. Each chunk's
    /// entity spans get appended to `per_text_spans[origin_idx]` with
    /// global byte offsets (chunk-local span + chunk's byte_offset_in_origin).
    fn run_batch(
        backend: &Backend,
        batch: &[(usize, usize, &str)],
        per_text_spans: &mut [Vec<(usize, usize, String)>],
    ) -> Result<(), ScrubError> {
        if batch.is_empty() {
            return Ok(());
        }

        // Tokenize all chunks together. encode_batch handles per-text encoding
        // independently; we'll pad ourselves so we can build a single tensor.
        let chunk_strs: Vec<&str> = batch.iter().map(|(_, _, s)| *s).collect();
        let encodings = backend
            .tokenizer
            .encode_batch(chunk_strs, true)
            .map_err(|e| ScrubError::NerFailed(format!("encode_batch: {e}")))?;

        // Pad to the longest sequence in the batch (right-pad with the
        // tokenizer's pad token; tokenizers crate fills in pad ids only when
        // padding is configured globally — we pad manually here using ids
        // from the model config to avoid a stateful tokenizer setup).
        let pad_id = backend
            .tokenizer
            .token_to_id("<pad>")
            .or_else(|| backend.tokenizer.token_to_id("[PAD]"))
            .unwrap_or(1);

        let max_len = encodings.iter().map(|e| e.get_ids().len()).max().unwrap_or(0);
        if max_len == 0 {
            return Ok(());
        }
        let batch_size = encodings.len();

        let mut ids_flat = Vec::with_capacity(batch_size * max_len);
        let mut mask_flat = Vec::with_capacity(batch_size * max_len);
        for enc in &encodings {
            let ids = enc.get_ids();
            let mask = enc.get_attention_mask();
            ids_flat.extend(ids.iter().map(|&x| x as i64));
            mask_flat.extend(mask.iter().map(|&x| x as i64));
            // Right-pad
            for _ in ids.len()..max_len {
                ids_flat.push(pad_id as i64);
                mask_flat.push(0);
            }
        }

        let device = backend.model.device();
        let input_ids = Tensor::from_vec(ids_flat, (batch_size, max_len), device)
            .map_err(|e| ScrubError::NerFailed(format!("ids tensor: {e}")))?;
        let attention_mask = Tensor::from_vec(mask_flat, (batch_size, max_len), device)
            .map_err(|e| ScrubError::NerFailed(format!("mask tensor: {e}")))?;

        // Forward → logits [batch, seq_len, num_labels]
        let logits = backend
            .model
            .forward(&input_ids, &attention_mask)
            .map_err(|e| ScrubError::NerFailed(format!("forward: {e:#}")))?;

        // Argmax over label axis (dim=2) → [batch, seq_len]
        let label_ids_tensor = logits
            .argmax(2)
            .map_err(|e| ScrubError::NerFailed(format!("argmax: {e}")))?;
        let label_ids_2d: Vec<Vec<u32>> = label_ids_tensor
            .to_vec2::<u32>()
            .map_err(|e| ScrubError::NerFailed(format!("argmax to_vec: {e}")))?;

        // Per chunk: BIO collapse → translate offsets to global.
        for (i, &(origin_idx, byte_offset_in_origin, _)) in batch.iter().enumerate() {
            let label_ids: Vec<usize> = label_ids_2d[i].iter().map(|&x| x as usize).collect();
            let offsets = encodings[i].get_offsets();
            let chunk_spans = collapse_bio(&label_ids, offsets, backend.model.labels());
            for (s, e, tag) in chunk_spans {
                per_text_spans[origin_idx]
                    .push((s + byte_offset_in_origin, e + byte_offset_in_origin, tag));
            }
        }
        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────────────
// ort backend (behind `ner-ort` feature) — INT8-quantized ONNX Runtime
// ───────────────────────────────────────────────────────────────────────────

#[cfg(feature = "ner-ort")]
mod ort_backend {
    use super::{collapse_bio, replace_spans, ScrubError, ScrubStats};
    use crate::scrubber::ort_loader::{OrtSource, OrtTokenClassifier};
    use ndarray::Array2;
    use parking_lot::Mutex;
    use std::sync::OnceLock;
    use tokenizers::Tokenizer;

    static BACKEND: OnceLock<Option<Mutex<Backend>>> = OnceLock::new();

    struct Backend {
        model: OrtTokenClassifier,
        tokenizer: Tokenizer,
    }

    fn init() -> Option<Mutex<Backend>> {
        let load_result = OrtSource::from_env().and_then(|src| src.load());
        match load_result {
            Ok((model, tokenizer)) => {
                let msg = format!(
                    "NER backend ready (ort / ONNX): {} labels",
                    model.labels.len()
                );
                log::info!("{msg}");
                eprintln!("[cirislens_core] {msg}");
                Some(Mutex::new(Backend { model, tokenizer }))
            }
            Err(e) => {
                let msg = format!("ort NER backend load failed: {e:#}");
                log::error!("{msg}");
                eprintln!("[cirislens_core] {msg}");
                None
            }
        }
    }

    pub fn is_configured() -> bool {
        BACKEND.get_or_init(init).is_some()
    }

    /// Same chunking + bucketing strategy as the candle backend, but
    /// running through ort INT8.
    const MAX_TOKENS_PER_CHUNK: usize = 192;
    const MAX_BATCH_CHUNKS: usize = 64;

    fn pre_chunk<'a>(
        text: &'a str,
        tokenizer: &Tokenizer,
    ) -> Result<Vec<(usize, &'a str)>, ScrubError> {
        let full = tokenizer
            .encode(text, false)
            .map_err(|e| ScrubError::NerFailed(format!("tokenize: {e}")))?;
        let total = full.get_ids().len();
        if total == 0 {
            return Ok(Vec::new());
        }
        let offsets = full.get_offsets();
        let mut chunks = Vec::new();
        let mut tok_start = 0usize;
        while tok_start < total {
            let tok_end = (tok_start + MAX_TOKENS_PER_CHUNK).min(total);
            let byte_start = offsets[tok_start].0;
            let byte_end = offsets[tok_end - 1].1;
            if byte_end > byte_start {
                chunks.push((byte_start, &text[byte_start..byte_end]));
            }
            tok_start = tok_end;
        }
        Ok(chunks)
    }

    pub fn scrub_batch(
        texts: &[String],
        stats: &mut ScrubStats,
    ) -> Result<Vec<String>, ScrubError> {
        let backend = BACKEND
            .get_or_init(init)
            .as_ref()
            .ok_or(ScrubError::NerNotConfigured)?;
        let mut backend = backend.lock();

        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let mut flat_chunks: Vec<(usize, usize, &str)> = Vec::new();
        for (i, text) in texts.iter().enumerate() {
            for (offset, chunk) in pre_chunk(text, &backend.tokenizer)? {
                flat_chunks.push((i, offset, chunk));
            }
        }
        flat_chunks.sort_by_key(|(_, _, s)| s.len());

        let mut per_text_spans: Vec<Vec<(usize, usize, String)>> = vec![Vec::new(); texts.len()];
        for batch in flat_chunks.chunks(MAX_BATCH_CHUNKS) {
            run_batch(&mut backend, batch, &mut per_text_spans)?;
        }

        let mut out = Vec::with_capacity(texts.len());
        for (i, text) in texts.iter().enumerate() {
            out.push(replace_spans(text, &per_text_spans[i], stats));
        }
        Ok(out)
    }

    fn run_batch(
        backend: &mut Backend,
        batch: &[(usize, usize, &str)],
        per_text_spans: &mut [Vec<(usize, usize, String)>],
    ) -> Result<(), ScrubError> {
        if batch.is_empty() {
            return Ok(());
        }

        let chunk_strs: Vec<&str> = batch.iter().map(|(_, _, s)| *s).collect();
        let encodings = backend
            .tokenizer
            .encode_batch(chunk_strs, true)
            .map_err(|e| ScrubError::NerFailed(format!("encode_batch: {e}")))?;

        let pad_id = backend
            .tokenizer
            .token_to_id("<pad>")
            .or_else(|| backend.tokenizer.token_to_id("[PAD]"))
            .unwrap_or(1);

        let max_len = encodings.iter().map(|e| e.get_ids().len()).max().unwrap_or(0);
        if max_len == 0 {
            return Ok(());
        }
        let batch_size = encodings.len();

        // Build padded ndarray inputs.
        let mut ids = Array2::<i64>::zeros((batch_size, max_len));
        let mut mask = Array2::<i64>::zeros((batch_size, max_len));
        for (b, enc) in encodings.iter().enumerate() {
            let e_ids = enc.get_ids();
            let e_mask = enc.get_attention_mask();
            for j in 0..max_len {
                if j < e_ids.len() {
                    ids[(b, j)] = e_ids[j] as i64;
                    mask[(b, j)] = e_mask[j] as i64;
                } else {
                    ids[(b, j)] = pad_id as i64;
                    mask[(b, j)] = 0;
                }
            }
        }

        let (logits_flat, batch_out, seq_out, num_labels) =
            backend.model.forward(ids, mask).map_err(|e| {
                ScrubError::NerFailed(format!("ort forward: {e:#}"))
            })?;
        debug_assert_eq!(batch_out, batch_size);
        debug_assert_eq!(seq_out, max_len);

        // Argmax along label axis. logits shape [batch, seq, num_labels].
        let mut label_ids_2d: Vec<Vec<usize>> = vec![Vec::with_capacity(seq_out); batch_out];
        for b in 0..batch_out {
            let row = &mut label_ids_2d[b];
            for s in 0..seq_out {
                let base = (b * seq_out + s) * num_labels;
                let mut best = 0usize;
                let mut best_v = f32::NEG_INFINITY;
                for k in 0..num_labels {
                    let v = logits_flat[base + k];
                    if v > best_v {
                        best_v = v;
                        best = k;
                    }
                }
                row.push(best);
            }
        }

        let labels = &backend.model.labels;
        for (i, &(origin_idx, byte_offset_in_origin, _)) in batch.iter().enumerate() {
            let offsets = encodings[i].get_offsets();
            let chunk_spans = collapse_bio(&label_ids_2d[i], offsets, labels);
            for (s, e, tag) in chunk_spans {
                per_text_spans[origin_idx]
                    .push((s + byte_offset_in_origin, e + byte_offset_in_origin, tag));
            }
        }
        Ok(())
    }
}

// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapse_bio_simple_per() {
        let labels: Vec<String> = ["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let label_ids = vec![0, 1, 2, 0]; // O B-PER I-PER O
        let offsets = vec![(0, 0), (5, 10), (10, 15), (0, 0)];
        let spans = collapse_bio(&label_ids, &offsets, &labels);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0], (5, 15, "PER".to_string()));
    }

    #[test]
    fn collapse_bio_multi_entity() {
        let labels: Vec<String> = ["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // O B-PER O B-LOC I-LOC O
        let label_ids = vec![0, 1, 0, 5, 6, 0];
        let offsets = vec![(0, 0), (5, 10), (10, 14), (15, 20), (20, 25), (0, 0)];
        let spans = collapse_bio(&label_ids, &offsets, &labels);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0], (5, 10, "PER".to_string()));
        assert_eq!(spans[1], (15, 25, "LOC".to_string()));
    }

    #[test]
    fn replace_spans_counts_per_tag() {
        let text = "Alice and Bob met in Paris.";
        let spans = vec![
            (0, 5, "PER".to_string()),
            (10, 13, "PER".to_string()),
            (21, 26, "LOC".to_string()),
        ];
        let mut stats = ScrubStats::default();
        let out = replace_spans(text, &spans, &mut stats);
        assert_eq!(out, "[PER_1] and [PER_2] met in [LOC_1].");
        assert_eq!(stats.entities_redacted, 3);
    }

    #[test]
    fn replace_spans_handles_empty() {
        let mut stats = ScrubStats::default();
        let out = replace_spans("nothing", &[], &mut stats);
        assert_eq!(out, "nothing");
        assert_eq!(stats.entities_redacted, 0);
    }

    #[test]
    fn stub_returns_not_configured_without_setup() {
        let mut s = ScrubStats::default();
        let result = scrub_with_ner("Alice met Bob in Paris.", &mut s);
        if !is_configured() {
            assert!(matches!(result, Err(ScrubError::NerNotConfigured)));
        }
    }
}
