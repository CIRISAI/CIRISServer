//! **The one line an operator reads** — an error with its whole cause chain.
//!
//! CIRISServer#586: 0.5.205 crash-looped the canonical sixteen times reporting
//! `build shared persist Engine (hybrid hardware signer)` — a `.context()`
//! string of ours, wrapped around a refinery checksum mismatch that the message
//! never mentioned. `Display` on an `anyhow::Error` renders only the outermost
//! context and drops every `source()` beneath it, so the answer was produced
//! and then deleted on its way out.
//!
//! # Why not just `{:#}`
//!
//! anyhow's alternate form carries the chain, and that alone fixed the outage's
//! diagnosis. But many substrate errors embed their cause in their OWN
//! `Display` — `Error::Backend(format!("sqlite open readers: {e}"))` is the
//! shape — while also exposing it through `source()`. Rendering both then
//! prints the innermost text twice, which reads like two different failures to
//! someone scanning a crash-loop at 00:20 UTC.
//!
//! So: walk the chain, and skip a layer whose message the layer above already
//! contains. Every distinct fact exactly once, outermost first.

/// The error and its causes, outermost first, joined by `: `, with layers that
/// merely repeat their parent's text suppressed.
#[must_use]
pub fn render(e: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in e.chain() {
        let text = cause.to_string();
        if text.trim().is_empty() {
            continue;
        }
        // The layer above already said this — an error whose Display embeds its
        // own source. Printing it again invents a second failure.
        if parts
            .last()
            .is_some_and(|prev: &String| prev.contains(&text))
        {
            continue;
        }
        parts.push(text);
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {

    fn wrapped() -> anyhow::Error {
        let root = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "applied migration V070 checksum mismatch",
        );
        anyhow::Error::new(root)
            .context("run_migrations")
            .context("build shared persist Engine (hybrid hardware signer)")
    }

    /// The property #586 needed: the operator sees the cause, not our wrapper.
    #[test]
    fn every_layer_survives_outermost_first() {
        let out = super::render(&wrapped());
        assert!(out.starts_with("build shared persist Engine"), "{out}");
        assert!(out.contains("run_migrations"), "{out}");
        assert!(
            out.contains("applied migration V070 checksum mismatch"),
            "the ROOT CAUSE is the part an operator acts on: {out}"
        );
    }

    /// A substrate error that embeds its own source — persist's
    /// `Error::Backend(format!("...: {e}"))` shape — must not print the
    /// innermost text twice. Two renderings of one fact read as two failures.
    #[test]
    fn a_layer_that_repeats_its_parent_is_not_printed_twice() {
        let root = std::io::Error::other("checksum mismatch");
        let embedding = anyhow::Error::new(root).context("sqlite: checksum mismatch");
        let out = super::render(&embedding);
        assert_eq!(
            out.matches("checksum mismatch").count(),
            1,
            "the innermost fact appears more than once: {out}"
        );
        assert_eq!(out, "sqlite: checksum mismatch");
    }

    /// Distinct layers that merely SHARE a word are both kept — suppression is
    /// for containment, not resemblance.
    #[test]
    fn distinct_layers_are_all_kept() {
        let root = std::io::Error::other("disk full");
        let e = anyhow::Error::new(root)
            .context("write wal")
            .context("commit batch");
        assert_eq!(super::render(&e), "commit batch: write wal: disk full");
    }

    /// An empty context contributes nothing rather than a stray `: `.
    #[test]
    fn empty_layers_do_not_produce_dangling_separators() {
        let e = anyhow::Error::new(std::io::Error::other("real cause")).context("");
        let out = super::render(&e);
        assert_eq!(out, "real cause");
        assert!(!out.contains(": :"), "{out}");
    }
}
