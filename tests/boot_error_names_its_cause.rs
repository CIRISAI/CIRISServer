//! **A boot failure must name what failed, not what we wrapped it in.**
//! CIRISServer#586.
//!
//! 0.5.205 crash-looped the canonical sixteen times and never said why. The
//! operator got one line:
//!
//! ```text
//! RuntimeError: build shared persist Engine (hybrid hardware signer)
//! ```
//!
//! That is a `.context()` string from `compose.rs`, unchanged since 0.1. The
//! real error — whatever the substrate actually complained about — was produced
//! and then **discarded at the FFI boundary**, because the conversion was:
//!
//! ```rust
//! .map_err(|e| PyRuntimeError::new_err(e.to_string()))
//! ```
//!
//! `Display` on an `anyhow::Error` renders only the outermost context. Every
//! `source()` under it is dropped silently. So the message named a REQUIREMENT
//! and not one fact about what was missing, and the first hypothesis off the
//! back of it — mine — went after the hybrid signer, which turned out to be
//! byte-identical between the two persist versions. A diagnosis-destroying
//! error costs more than the failure it hides: it sends the next person the
//! wrong way with confidence.
//!
//! This pins the property rather than the wording: **every layer survives**.

/// Build the shape a boot failure actually has: a root cause from the
/// substrate, wrapped by the layer that called it, wrapped by the phase.
fn layered() -> anyhow::Error {
    let root = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "unable to open database file",
    );
    anyhow::Error::new(root)
        .context("sqlite open readers: /var/lib/ciris/ciris_engine.db")
        .context("build shared persist Engine (hybrid hardware signer)")
}

/// The regression: `to_string()` shows the wrapper ALONE. This is what shipped,
/// and it is why #586 could not be diagnosed from its own error.
#[test]
fn display_alone_hides_the_cause_which_is_why_this_test_exists() {
    let e = layered();
    let shown = e.to_string();
    assert!(
        shown.contains("build shared persist Engine"),
        "the outermost context is all Display gives: {shown}"
    );
    assert!(
        !shown.contains("unable to open database file"),
        "if Display ever starts carrying the chain, this file's reason to exist changed: {shown}"
    );
}

/// What the boundary must send instead: the whole chain, outermost first.
#[test]
fn the_alternate_form_carries_every_layer() {
    let rendered = ciris_server::error_chain::render(&layered());
    for layer in [
        "build shared persist Engine (hybrid hardware signer)",
        "sqlite open readers",
        "unable to open database file",
    ] {
        assert!(
            rendered.contains(layer),
            "layer {layer:?} missing from the rendered chain: {rendered}"
        );
    }
}

/// The root cause is the part an operator acts on, so it must survive however
/// deep the wrapping goes. A boot path that grows another context layer must
/// not quietly start hiding the answer again.
#[test]
fn the_root_cause_survives_arbitrary_wrapping() {
    let mut e = anyhow::Error::new(std::io::Error::other("the thing that actually broke"));
    for n in 0..12 {
        e = e.context(format!("layer {n}"));
    }
    let rendered = ciris_server::error_chain::render(&e);
    assert!(
        rendered.contains("the thing that actually broke"),
        "twelve layers of context buried the cause: {rendered}"
    );
}

/// The FFI boundary must not reintroduce `to_string()` on an anyhow error.
///
/// Scrapes `src/lib.rs` rather than trusting a comment: the two serve paths are
/// where a boot failure crosses into Python, and a future edit that "simplifies"
/// the conversion back would silently restore #586.
#[test]
fn no_serve_path_converts_an_anyhow_error_by_display_alone() {
    let lib = std::fs::read_to_string("src/lib.rs").expect("read src/lib.rs");
    let offenders: Vec<String> = lib
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("rt.block_on(fut)"))
        .map(|(n, l)| format!("src/lib.rs:{}: {}", n + 1, l.trim()))
        .filter(|l| l.contains("e.to_string()"))
        .collect();
    assert!(
        offenders.is_empty(),
        "a serve path converts its anyhow error with Display alone, which drops the cause \
         chain — use the `error_chain::render` helper (CIRISServer#586):\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        lib.contains("fn py_err("),
        "the chain-preserving conversion helper is gone; #586 will recur"
    );
}
