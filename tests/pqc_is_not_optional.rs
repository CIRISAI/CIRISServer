//! **There is no classical-only path, and no knob that could make one.**
//!
//! The mesh is pre-release and fully PQC-provisioned, so every
//! "hybrid-pending" / "when available" admission path is pure downgrade
//! surface with no remaining legitimate user. CIRISEdge#481 found the cost of
//! keeping one: the federation-session responder accepted a classical handshake
//! unconditionally — an active downgrade in a single message — while the
//! envelope-verify path beside it was already `HybridPolicy::Strict`.
//!
//! Adopting edge v17.4.0 retires that seam upstream. This gate closes ours.
//!
//! # What was here
//!
//! `ciris-lens-core`'s `NodeState` carried a `hybrid_policy` field and a
//! `with_hybrid_policy` setter "for operators mid-PQC-rollout". It had **zero
//! callers**, no config or env path, both constructors hard-coded `Strict` —
//! and an `#[allow(dead_code)]` keeping it quiet under `-D warnings`. A
//! downgrade affordance surviving on an allow is the optional-half shape this
//! project keeps paying for: the guard is dead, so nothing tests it, so nobody
//! notices when something wakes it up.
//!
//! Deleting it makes `Strict` true by construction rather than by convention.
//! This gate is what keeps it that way, because the cheapest way to reintroduce
//! the hazard is a well-meaning "make the policy configurable" patch.

/// Every file that performs or configures hybrid verification.
const SOURCES: &[&str] = &["src", "crates/ciris-lens-core/src"];

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_hybrid_policy_but_strict() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for s in SOURCES {
        rust_files(&root.join(s), &mut files);
    }
    assert!(
        !files.is_empty(),
        "examined ZERO files — the scan roots moved, so this gate proved nothing. \
         A zero denominator is the error, not a pass."
    );

    // SPLIT so this predicate cannot match itself.
    let banned = format!("HybridPolicy::{}", "Ed25519Fallback");
    let mut offenders = Vec::new();
    let mut examined = 0usize;

    for f in &files {
        let Ok(src) = std::fs::read_to_string(f) else {
            continue;
        };
        examined += 1;
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            // Comments may DISCUSS the retired policy — this file's own header
            // does. Only code counts.
            if t.starts_with("//") || t.starts_with("///") || t.starts_with("//!") {
                continue;
            }
            if line.contains(banned.as_str()) {
                offenders.push(format!(
                    "  {}:{}  {}",
                    f.strip_prefix(root).unwrap_or(f).display(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }

    assert_eq!(
        examined,
        files.len(),
        "some files could not be read — a partial scan must not report a pass"
    );
    assert!(
        offenders.is_empty(),
        "\nA CLASSICAL-ONLY VERIFY PATH IS BACK.\n\n{}\n\n\
         `Ed25519Fallback` admits a request carrying no ML-DSA-65 signature. With the \
         mesh fully PQC-provisioned there is no caller this serves, and one accepting \
         seam is all a downgrade needs — CIRISEdge#481 was exactly this, on the KEX \
         side, reachable in a single message.\n\n\
         If a rollout genuinely needs it, make it explicit and time-boxed rather than a \
         silent default, and say so here.\n\
         Examined {} file(s).\n",
        offenders.join("\n"),
        examined
    );
}
