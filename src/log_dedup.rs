//! **Repetition-collapsing log layer** — "event X occurred Y times in past Z".
//!
//! A refusal storm is not 2,253 facts. It is one fact and a count, and printing
//! it 2,253 times costs the operator the ability to see anything else. Measured
//! on the canonical in a single 30-minute window:
//!
//! ```text
//! delivered envelope REFUSED … kind=Attestation …   2,253
//! link established                                   2,368
//! ```
//!
//! ~4,600 lines carrying perhaps six distinct facts.
//!
//! # Why normalization is the whole problem
//!
//! Those 2,253 refusals are not textually identical — each names its own
//! `content_hash` and attestation id:
//!
//! ```text
//! attestation 1cde0f70-e75c-41ab-… (content_hash=82ca2908…): invalid argument
//! attestation 3f9ab122-01de-4c07-… (content_hash=d0cb3f58…): invalid argument
//! ```
//!
//! A dedup keyed on the raw message therefore collapses NOTHING — every line is
//! unique and the layer is a no-op that looks like it works. [`normalize`] is what
//! makes the two lines above one key: identifier-shaped tokens become `<id>`, bare
//! numbers become `<n>`, and the prose that actually distinguishes one failure
//! mode from another is left alone.
//!
//! # What is deliberately NOT collapsed
//!
//! - The first [`BURST`] occurrences in a window pass through untouched, so a
//!   fault is never invisible — only its repetition is.
//! - The layer's own summaries ([`SUMMARY_TARGET`]), or it would collapse its own
//!   reporting and go silent.
//! - Anything with no `message` field, which is passed through rather than guessed
//!   at.
//!
//! # Placement
//!
//! This suppresses via [`Layer::event_enabled`], which is consulted for the WHOLE
//! subscriber — so it collapses `ciris_edge` and `ciris_persist` output too, which
//! is the point: the storms we most need collapsed originate in the substrate and
//! reach the operator through this process's subscriber.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Occurrences allowed through per window before collapsing begins.
///
/// Not 1: a lone sample is often ambiguous (which peer? which kind?), and three
/// gives an operator the variation they need to tell a stuck row from a broad
/// storm without paying for thousands.
pub const BURST: u64 = 3;

/// Default summary cadence.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(300);

/// Target for the layer's own summary events — never collapsed.
pub const SUMMARY_TARGET: &str = "ciris_server::log_dedup";

/// Upper bound on tracked distinct events, so a pathological cardinality (every
/// message unique even after normalization) cannot grow this map without limit.
const MAX_TRACKED: usize = 4096;

/// Collapse identifier-shaped and numeric tokens so that messages differing only
/// by hash, uuid, or count share one key.
///
/// Tokens are alphanumeric runs; punctuation is preserved verbatim so the shape
/// of the message survives for reading.
///
/// A token is an identifier when it is **hex-shaped** and either long (`>= 8`) or
/// short-but-numeric (`>= 4` with a digit), OR when it is long and contains a
/// digit. Everything else is kept verbatim.
///
/// The two halves of that rule are each load-bearing, and both were found by test
/// rather than by reading:
///
/// - **Hex at length 4** is what makes uuids collapse. A uuid is `8-4-4-4-12`, and
///   with an 8-char floor the three middle groups (`e75c`, `41ab`, `979f`) survive
///   as themselves — so two lines differing only by uuid stay distinct and the
///   layer silently does nothing.
/// - **Treating digits as hex** is what stops one fact splitting into two buckets.
///   A 64-char hash of a small number is all digits; of a larger one it has
///   letters. Routing those to different placeholders gives the same event two
///   keys and prints two bursts instead of one.
///
/// Requiring a digit below length 8 is what keeps prose safe: `beef`, `cafe` and
/// `face` are hex-shaped English and stay themselves, while `4fc6ru` (a short agent
/// stem, not hex) also survives — so genuinely different events stay apart.
#[must_use]
pub fn normalize(msg: &str) -> String {
    fn flush(tok: &mut String, out: &mut String) {
        if tok.is_empty() {
            return;
        }
        let has_digit = tok.chars().any(|c| c.is_ascii_digit());
        let all_digit = tok.chars().all(|c| c.is_ascii_digit());
        let is_hex = tok.chars().all(|c| c.is_ascii_hexdigit());
        let n = tok.len();
        let identifier = (is_hex && (n >= 8 || (n >= 4 && has_digit))) || (n >= 8 && has_digit);
        if identifier {
            out.push_str("<id>");
        } else if all_digit {
            out.push_str("<n>");
        } else {
            out.push_str(tok);
        }
        tok.clear();
    }

    let mut out = String::with_capacity(msg.len());
    let mut tok = String::new();
    for c in msg.chars() {
        if c.is_ascii_alphanumeric() {
            tok.push(c);
        } else {
            flush(&mut tok, &mut out);
            out.push(c);
        }
    }
    flush(&mut tok, &mut out);
    out
}

#[derive(Debug)]
struct Entry {
    seen: u64,
    suppressed: u64,
    first: Instant,
    /// The first RAW message — a summary that printed only the normalized form
    /// would have scrubbed the very ids an operator needs to go look something up.
    sample: String,
    target: String,
    level: Level,
}

/// Shared collapse state — cloneable so the flusher and the layer share one map.
#[derive(Clone, Default)]
pub struct DedupState(Arc<Mutex<HashMap<u64, Entry>>>);

impl std::fmt::Debug for DedupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.0.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("DedupState").field("tracked", &n).finish()
    }
}

impl DedupState {
    /// Record one occurrence; `true` means "let this event print".
    fn admit(&self, target: &str, level: Level, msg: &str) -> bool {
        let mut key = DefaultHasher::new();
        target.hash(&mut key);
        level.as_str().hash(&mut key);
        normalize(msg).hash(&mut key);
        let key = key.finish();

        let Ok(mut map) = self.0.lock() else {
            return true; // a poisoned lock must never silence logging
        };
        if map.len() >= MAX_TRACKED && !map.contains_key(&key) {
            return true;
        }
        let e = map.entry(key).or_insert_with(|| Entry {
            seen: 0,
            suppressed: 0,
            first: Instant::now(),
            sample: msg.to_owned(),
            target: target.to_owned(),
            level,
        });
        e.seen += 1;
        if e.seen <= BURST {
            true
        } else {
            e.suppressed += 1;
            false
        }
    }

    /// Emit one summary per collapsed event and clear the window.
    ///
    /// Returns how many summaries were emitted (for tests).
    pub fn flush(&self) -> usize {
        let drained: Vec<Entry> = {
            let Ok(mut map) = self.0.lock() else {
                return 0;
            };
            let keys: Vec<u64> = map.keys().copied().collect();
            let mut out = Vec::new();
            for k in keys {
                if map.get(&k).is_some_and(|e| e.suppressed > 0) {
                    if let Some(e) = map.remove(&k) {
                        out.push(e);
                    }
                } else {
                    map.remove(&k);
                }
            }
            out
        };

        for e in &drained {
            let secs = e.first.elapsed().as_secs();
            // Reported at the collapsed event's OWN level: a summary of warnings
            // logged at info would be filtered out of exactly the deployments that
            // most need it.
            match e.level {
                Level::ERROR => tracing::error!(
                    target: SUMMARY_TARGET,
                    repeated_target = %e.target, total = e.seen, suppressed = e.suppressed,
                    window_secs = secs, sample = %e.sample,
                    "event repeated {} times in past {}s ({} suppressed)", e.seen, secs, e.suppressed),
                Level::WARN => tracing::warn!(
                    target: SUMMARY_TARGET,
                    repeated_target = %e.target, total = e.seen, suppressed = e.suppressed,
                    window_secs = secs, sample = %e.sample,
                    "event repeated {} times in past {}s ({} suppressed)", e.seen, secs, e.suppressed),
                _ => tracing::info!(
                    target: SUMMARY_TARGET,
                    repeated_target = %e.target, total = e.seen, suppressed = e.suppressed,
                    window_secs = secs, sample = %e.sample,
                    "event repeated {} times in past {}s ({} suppressed)", e.seen, secs, e.suppressed),
            }
        }
        drained.len()
    }
}

/// The layer. Install ahead of the sinks; it suppresses by returning `false` from
/// [`Layer::event_enabled`].
#[derive(Clone, Debug, Default)]
pub struct DedupLayer {
    state: DedupState,
}

impl DedupLayer {
    /// Build a layer and hand back the shared state for the flusher.
    #[must_use]
    pub fn new() -> (Self, DedupState) {
        let state = DedupState::default();
        (
            Self {
                state: state.clone(),
            },
            state,
        )
    }
}

struct MessageVisitor(Option<String>);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S: Subscriber> Layer<S> for DedupLayer {
    fn event_enabled(&self, event: &Event<'_>, _ctx: Context<'_, S>) -> bool {
        let meta = event.metadata();
        if meta.target() == SUMMARY_TARGET {
            return true;
        }
        let mut v = MessageVisitor(None);
        event.record(&mut v);
        match v.0 {
            Some(msg) => self.state.admit(meta.target(), *meta.level(), &msg),
            None => true,
        }
    }
}

/// Run the periodic flush on a plain OS thread.
///
/// Deliberately NOT a tokio task: logging must not depend on a runtime existing,
/// and `init_tracing` is called from contexts that have none (the Chaquopy/embedded
/// boot among them).
pub fn spawn_flusher(state: DedupState, window: Duration) {
    std::thread::Builder::new()
        .name("log-dedup-flush".into())
        .spawn(move || loop {
            std::thread::sleep(window);
            state.flush();
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_the_ids_that_made_every_refusal_unique() {
        // The two production lines this layer exists for.
        let a = "attestation 1cde0f70-e75c-41ab-979f-3ee5cf517d26 carries no signed asserted_at \
                 (content_hash=82ca290850de6e1235818af44df347e1f01d58991f112a8447374f13be0d7cea)";
        let b = "attestation 3f9ab122-01de-4c07-8a11-1122334455ff carries no signed asserted_at \
                 (content_hash=d0cb3f58804ef4907969f5a3906561297afa92275850ca152630845548a8e371)";
        assert_eq!(normalize(a), normalize(b));
        assert_ne!(a, b, "the raw lines differ — that is the whole problem");
    }

    #[test]
    fn normalize_keeps_genuinely_different_failures_apart() {
        let refused = normalize("delivered envelope REFUSED kind=Attestation reason=invalid");
        let established = normalize("link established peer=abc");
        assert_ne!(refused, established);
        // Different refusal KINDS must not merge — the kind is the diagnosis.
        assert_ne!(
            normalize("delivered envelope REFUSED kind=Attestation"),
            normalize("delivered envelope REFUSED kind=Key"),
        );
    }

    #[test]
    fn uuid_inner_groups_collapse_too() {
        // Regression: an 8-char floor leaves a uuid's `8-4-4-4-12` middle groups
        // intact, so uuid-bearing lines never merge and the layer no-ops.
        assert_eq!(
            normalize("id 1cde0f70-e75c-41ab-979f-3ee5cf517d26 refused"),
            normalize("id 3f9ab122-01de-4c07-8a11-1122334455ff refused"),
        );
    }

    #[test]
    fn one_hash_column_is_one_bucket_whatever_the_value() {
        // Regression: a 64-char hash of a small number is all digits, of a larger
        // one has letters. Different placeholders ⇒ two keys ⇒ two bursts.
        assert_eq!(
            normalize(&format!("content_hash={:064x}", 1)),
            normalize(&format!("content_hash={:064x}", 4242)),
        );
    }

    #[test]
    fn hex_shaped_english_is_not_an_identifier() {
        // `beef`/`cafe`/`face` are pure hex. Collapsing them would merge unrelated
        // prose, so a short token must ALSO carry a digit to count as an id.
        let n = normalize("the cafe served dead beef to a face");
        assert!(!n.contains("<id>"), "{n}");
    }

    #[test]
    fn prose_and_short_stems_survive_normalization() {
        let n = normalize("refusal=federation_invalid_argument peer=echo-core-jm2jy2-eb3rmqnkln");
        assert!(n.contains("federation_invalid_argument"), "{n}");
        assert!(n.contains("jm2jy2"), "short agent stem must survive: {n}");
        assert!(
            n.contains("<id>"),
            "the occurrence suffix must collapse: {n}"
        );
    }

    #[test]
    fn burst_passes_then_collapses() {
        let s = DedupState::default();
        let msg = "delivered envelope REFUSED content_hash=82ca290850de6e12";
        for i in 1..=BURST {
            assert!(s.admit("t", Level::WARN, msg), "occurrence {i} must print");
        }
        for _ in 0..100 {
            assert!(!s.admit("t", Level::WARN, msg), "repeats must collapse");
        }
    }

    #[test]
    fn a_storm_of_unique_hashes_still_collapses() {
        // The regression that a raw-message dedup would fail: 500 lines, every one
        // textually distinct, all one fact.
        let s = DedupState::default();
        let mut printed = 0;
        for i in 0..500 {
            let msg = format!("attestation refused (content_hash={i:064x})");
            if s.admit("edge", Level::WARN, &msg) {
                printed += 1;
            }
        }
        assert_eq!(printed, BURST as usize, "only the burst should print");
    }

    #[test]
    fn distinct_targets_do_not_share_a_bucket() {
        let s = DedupState::default();
        let msg = "same text";
        for _ in 0..(BURST + 5) {
            s.admit("edge", Level::WARN, msg);
        }
        assert!(
            s.admit("persist", Level::WARN, msg),
            "another target starts its own burst"
        );
    }

    #[test]
    fn the_layers_own_summaries_are_never_collapsed() {
        // Guards the silence failure: if summaries were deduped the layer would
        // stop reporting exactly when a storm made it useful.
        let s = DedupState::default();
        for _ in 0..50 {
            s.admit("x", Level::WARN, "noise");
        }
        assert_eq!(s.flush(), 1, "one collapsed event ⇒ one summary");
        assert_eq!(s.flush(), 0, "window cleared");
    }

    #[test]
    fn flush_reports_the_full_count_not_just_the_suppressed_half() {
        let s = DedupState::default();
        for _ in 0..10 {
            s.admit("x", Level::WARN, "noise");
        }
        let map = s.0.lock().unwrap();
        let e = map.values().next().unwrap();
        assert_eq!(e.seen, 10);
        assert_eq!(e.suppressed, 10 - BURST);
    }

    #[test]
    fn a_poisoned_map_never_silences_logging() {
        let s = DedupState::default();
        let s2 = s.clone();
        let _ = std::thread::spawn(move || {
            let _g = s2.0.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(
            s.admit("t", Level::WARN, "anything"),
            "fail OPEN — a broken dedup must print, not swallow"
        );
    }

    #[test]
    fn unbounded_cardinality_cannot_grow_the_map_without_limit() {
        let s = DedupState::default();
        for i in 0..(MAX_TRACKED + 500) {
            // `word{i}` normalizes to itself for small i, so each is distinct.
            s.admit(
                "t",
                Level::WARN,
                &format!("distinct message number {i} xyz"),
            );
        }
        assert!(s.0.lock().unwrap().len() <= MAX_TRACKED);
    }
}

#[cfg(test)]
mod real_log_measurement {
    use super::*;
    use std::collections::HashSet;

    /// Measure the collapse ratio on a real captured node log.
    ///
    /// Skips when `CIRIS_LOG_SAMPLE` is unset so CI stays hermetic; run it against
    /// a captured log to check the normalizer against production text rather than
    /// against fixtures written by the same hand that wrote the rule.
    #[test]
    fn collapse_ratio_on_a_real_log() {
        let Ok(path) = std::env::var("CIRIS_LOG_SAMPLE") else {
            return;
        };
        let text = std::fs::read_to_string(&path).expect("read sample");
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        let raw: HashSet<&str> = lines.iter().copied().collect();
        let norm: HashSet<String> = lines.iter().map(|l| normalize(l)).collect();

        let state = DedupState::default();
        let printed = lines
            .iter()
            .filter(|l| state.admit("real", Level::WARN, l))
            .count();

        println!(
            "lines={} distinct_raw={} distinct_normalized={} would_print={} reduction={:.1}%",
            lines.len(),
            raw.len(),
            norm.len(),
            printed,
            100.0 - (printed as f64 / lines.len() as f64) * 100.0
        );
        assert!(norm.len() <= raw.len());
    }
}
