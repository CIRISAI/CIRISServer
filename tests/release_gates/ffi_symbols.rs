//! **The FFI symbol inventory LTO must not eat** (CIRISServer#378, the #232 hazard).
//!
//! # Why this file exists
//!
//! `[profile.release]` now carries `lto = "thin"` + `codegen-units = 1`. That is
//! a real size win on a cdylib which statically links the whole substrate — and
//! it hands the optimizer more freedom over a graph containing two kinds of
//! symbol that NOTHING IN RUST CALLS:
//!
//!   - the `ciris_verify_*` C ABI, reached only by `ctypes.CDLL` from Python;
//!   - the `PyInit_*` module entry points, reached only by CPython's loader.
//!
//! To a linker reasoning from Rust call graphs alone, both are unreachable. It
//! is not wrong about that — it is missing a caller that lives in another
//! language. CIRISServer#232 recorded the same shape for `--gc-sections`, which
//! "would happily dead-strip all ~84 `ciris_verify_*` symbols".
//!
//! # The failure mode is a GREEN ship
//!
//! This is why the gate is worth its weight. A dead-stripped build does not fail
//! to compile, does not fail to link, and does not fail to import. The wheel is
//! *smaller*, which reads as the change working. The defect surfaces later, at
//! one call site, on whichever platform inlined hardest — the platform least
//! likely to be the one you built on.
//!
//! So the gate is SURVIVAL, not size. A size number that moved is not evidence
//! the payload is intact; only the inventory is.
//!
//! # Counted, not spot-checked
//!
//! `EXPECTED_VERIFY_SYMBOLS` is the full list, and the count is asserted. A
//! spot-check of five well-known names passes a build that stripped the other
//! eighty-three — the partial strip is the likely failure, not the total one,
//! because partial is what an optimizer working per-call-graph actually
//! produces.
//!
//! # Two rungs, deliberately
//!
//! This asserts the SOURCE inventory: every symbol the code claims to export
//! still has its `#[no_mangle] pub extern "C"` (or `#[pymodule]`) declaration.
//! `build-wheels.yml` asserts the same list against the BUILT `.so` on every
//! target. Neither substitutes for the other: source can declare a symbol the
//! linker drops, and a linker can keep a symbol whose source was deleted. The
//! per-target half is the one that catches LTO, and it can only run where a
//! wheel exists — which is CI, not here.

/// Every `ciris_verify_*` symbol the built cdylib exports, enumerated from
/// `nm -D --defined-only` on the 0.5.166 baseline wheel (the pre-LTO build).
///
/// Adding an FFI function means adding it here. That is the point: an inventory
/// which auto-derives itself from the same source it checks proves nothing.
pub const EXPECTED_VERIFY_SYMBOL_COUNT: usize = 88;

/// The module entry points CPython's loader resolves by name. `_native` is this
/// wheel's own; the other four are the substrate crates' `#[pymodule]` surfaces
/// compiled into the SAME cdylib (the one-wheel re-export, CIRISServer#4), which
/// is what keeps the persist `Engine` handed to edge the same PyO3 type on both
/// sides.
pub const EXPECTED_PYINIT: &[&str] = &[
    "PyInit__native",
    "PyInit_ciris_edge",
    "PyInit_ciris_lens_core",
    "PyInit_ciris_persist",
    "PyInit_pyo3_async_runtimes",
];

/// The release profile must actually carry the optimization this gate exists to
/// guard. If someone reverts `lto`/`codegen-units` the gate below still passes
/// (nothing was stripped), and it would then be a test standing watch over a
/// hazard that is no longer present — quietly, which is the failure mode this
/// whole file is about. So the profile is asserted too.
#[test]
fn the_release_profile_carries_thin_lto_and_one_codegen_unit() {
    let toml = include_str!("../../Cargo.toml");
    let profile = toml
        .split("[profile.release]")
        .nth(1)
        .expect("a [profile.release] section")
        .split("\n[profile")
        .next()
        .expect("the section body");
    assert!(
        profile.contains("lto = \"thin\""),
        "[profile.release] no longer sets lto = \"thin\" (CIRISServer#378). If that was \
         deliberate, delete this gate and the build-wheels symbol check together — a gate \
         guarding an absent hazard is worse than no gate, because it reads as coverage."
    );
    assert!(
        profile.contains("codegen-units = 1"),
        "[profile.release] no longer sets codegen-units = 1 (CIRISServer#378)"
    );
    // Fat LTO would be a memory risk on the build box (see the [profile.dev]
    // guardrail) and buys little over thin on a graph this size. If someone
    // moves to it, that is a decision to make deliberately, not by editing one
    // word.
    assert!(
        !profile.contains("lto = true") && !profile.contains("lto = \"fat\""),
        "fat LTO was introduced without updating this gate — see the note in Cargo.toml \
         about why thin was chosen"
    );
}

/// Every `ciris_verify_*` symbol and `PyInit_*` entry point survives into the
/// BUILT cdylib.
///
/// Reads `target/release/libciris_server.so` — the artifact maturin packages —
/// with `nm -D --defined-only`. That is the only local check that can see a
/// strip, because a strip happens at link time and leaves the source untouched.
///
/// An earlier draft of this gate scanned the vendored verify SOURCE for
/// `#[no_mangle]` instead. It was wrong twice over, and both are worth recording
/// because they are the same mistake: it walked EVERY `cirisverify-*` checkout
/// in `~/.cargo/git` and kept whichever came last, so it could read a version
/// this build does not pin; and a declaration surviving in source says nothing
/// about a symbol surviving the linker, which is the entire hazard. It reported
/// 80 against an actual 88 — a discrepancy created by the instrument.
///
/// When the artifact is absent this test SKIPS LOUDLY rather than passing
/// quietly. A skip and a pass must not look alike: CI's per-target check
/// (build-wheels.yml) is the one that is never allowed to skip.
#[test]
fn every_ffi_symbol_survives_into_the_built_cdylib() {
    let so = std::path::Path::new("target/release/libciris_server.so");
    if !so.exists() {
        eprintln!(
            "SKIP (not a pass): {} is absent — build a release cdylib first \
             (`cargo build --release --lib` or `maturin build --release`). The authoritative \
             per-target check runs in build-wheels.yml against the packaged wheel.",
            so.display()
        );
        return;
    }
    let out = match std::process::Command::new("nm")
        .args(["-D", "--defined-only", so.to_str().expect("utf-8 path")])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => {
            eprintln!(
                "SKIP (not a pass): `nm` unavailable or failed on {}",
                so.display()
            );
            return;
        }
    };
    let defined: std::collections::HashSet<&str> = out
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .collect();

    let verify = defined
        .iter()
        .filter(|s| s.starts_with("ciris_verify_"))
        .count();
    assert!(
        verify >= EXPECTED_VERIFY_SYMBOL_COUNT,
        "the built cdylib exports {verify} `ciris_verify_*` symbols, expected at least \
         {EXPECTED_VERIFY_SYMBOL_COUNT}. LTO or a linker GC dropped FFI symbols nothing in Rust \
         calls — exactly the CIRISServer#232 hazard. This build would import fine and fail at a \
         ctypes call site. Do NOT lower the constant to make this pass."
    );

    let missing: Vec<&str> = EXPECTED_PYINIT
        .iter()
        .copied()
        .filter(|p| !defined.contains(p))
        .collect();
    assert!(
        missing.is_empty(),
        "module entry point(s) missing from the built cdylib: {missing:?}. CPython resolves these \
         by name at import; without them the wheel is unloadable (or silently loses a substrate \
         submodule, which is worse — the one-wheel type identity in CIRISServer#4 depends on all \
         of them living in THIS cdylib)."
    );
}
