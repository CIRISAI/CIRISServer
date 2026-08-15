//! **A feature must not reach a target that cannot link it.**
//!
//! `scrub-ner` pulls a C-dependency chain — `tokenizers → onig_sys` (oniguruma)
//! and `hf-hub → native-tls → openssl-sys`. Neither cross-compiles for the
//! release's mobile and embedded targets:
//!
//! ```text
//! iOS arm64:  Undefined symbols: ___chkstk_darwin, from _match_at in libonig_sys
//! armv7:      Could not find openssl via pkg-config … required by openssl-sys
//! ```
//!
//! Both shipped. The iOS one was caught by CI on a PR; the armv7 and
//! aarch64-musl ones only surfaced at TAG time, because those lanes are
//! allow-fail and the release published without them.
//!
//! # Why a test and not care
//!
//! The feature was scoped to a narrow `cfg(...)` and I verified the scoping by
//! COUNTING declarations — "2 sites" — without asking which two. One of them was
//! `[target.'cfg(target_os = "linux")']`, which matches armv7-gnueabihf and
//! aarch64-musl as surely as it matches x86_64.
//!
//! Then I verified with `cargo tree` against iOS and android. Neither is linux.
//! So the check confirmed the two targets that were already fine and never
//! touched the family that broke — a passing verification of the wrong
//! configuration, which is the defect class this repo keeps paying for.
//!
//! Counting is not checking. This asks the actual question, per target.

/// Targets the release builds that CANNOT link the NER C-chain. Each is a real
/// lane in `release.yml` / `publish-pypi.yml`.
const NO_NATIVE_DEPS: &[(&str, &str)] = &[
    (
        "aarch64-apple-ios",
        "iOS: onig_sys fails on ___chkstk_darwin",
    ),
    ("aarch64-linux-android", "android wheel"),
    ("armv7-linux-androideabi", "android wheel"),
    ("x86_64-linux-android", "android wheel"),
    (
        "armv7-unknown-linux-gnueabihf",
        "armv7 cross: no OpenSSL for the target",
    ),
    (
        "aarch64-unknown-linux-musl",
        "musl cross: no OpenSSL for the target",
    ),
];

/// Crates whose presence means the NER chain leaked in.
const FORBIDDEN: &[&str] = &["hf-hub", "onig", "tokenizers", "candle", "openssl-sys"];

fn tree_for(target: &str) -> Option<String> {
    let out = std::process::Command::new(env!("CARGO"))
        .args(["tree", "--target", target, "-e", "normal"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn no_release_target_pulls_a_dependency_it_cannot_link() {
    let mut checked = 0usize;
    let mut offenders: Vec<String> = Vec::new();

    for (target, why) in NO_NATIVE_DEPS {
        let Some(tree) = tree_for(target) else {
            // `cargo tree` needs the resolved graph; if it cannot run we must NOT
            // report that as a pass. Say so and keep going, then fail below if
            // nothing was examined.
            eprintln!("could not resolve the graph for {target} — not counted as checked");
            continue;
        };
        checked += 1;
        for bad in FORBIDDEN {
            if tree.lines().any(|l| l.contains(bad)) {
                offenders.push(format!("  {target} ({why}) pulls `{bad}`"));
            }
        }
    }

    assert!(
        checked > 0,
        "examined NO targets — `cargo tree --target` could not resolve any graph, so \
         this test proved nothing. That is a failure, not a pass."
    );
    assert!(
        offenders.is_empty(),
        "\nA RELEASE TARGET PULLS A DEPENDENCY IT CANNOT LINK.\n\n{}\n\n\
         These lanes fail at BUILD time, and two of them (armv7, aarch64-musl) are \
         allow-fail — so the release publishes WITHOUT those tarballs and the failure \
         is only visible if someone counts the assets.\n\n\
         A feature with C dependencies belongs in a target section narrow enough to \
         exclude every one of these. `cfg(target_os = \"linux\")` is NOT narrow enough: \
         it matches armv7-gnueabihf and aarch64-musl.\n\n\
         Checked {checked} target(s).\n",
        offenders.join("\n")
    );
}

/// The complement: the platforms that SHOULD carry NER still do. A scoping fix
/// that quietly removed the feature everywhere would pass the test above.
#[test]
fn the_platforms_that_can_link_ner_still_get_it() {
    let expect = ["x86_64-unknown-linux-gnu", "x86_64-apple-darwin"];
    for target in expect {
        let Some(tree) = tree_for(target) else {
            eprintln!("could not resolve {target}; skipping this arm");
            continue;
        };
        assert!(
            tree.lines().any(|l| l.contains("hf-hub")),
            "{target} no longer pulls the NER chain — the scoping fix went too far and \
             disabled the feature on a platform that supports it. full_traces would \
             silently downgrade to detailed everywhere."
        );
    }
}
