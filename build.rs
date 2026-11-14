//! Names the substrate this build links (0.5.247): the persist, edge and verify
//! versions and commits, read from `Cargo.lock`, so `--version` and the boot
//! log say which pair a node runs without anyone opening the wheel. A build
//! with no lock file (an sdist without one) says "unknown"; it never fails.

use std::fmt::Write as _;

const CRATES: [(&str, &str); 3] = [
    ("ciris-persist", "persist"),
    ("ciris-edge", "edge"),
    ("ciris-verify-core", "verify"),
];

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=build.rs");
    let lock = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
    let mut found: Vec<(String, String, String)> = Vec::new();
    for block in lock.split("[[package]]") {
        let field = |k: &str| {
            block.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(k)
                    .and_then(|r| r.trim().strip_prefix('='))
                    .map(|v| v.trim().trim_matches('"').to_owned())
            })
        };
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        let commit = field("source")
            .and_then(|s| s.rsplit_once('#').map(|(_, c)| c.chars().take(8).collect()))
            .unwrap_or_default();
        found.push((name, version, commit));
    }
    let mut line = String::new();
    for (krate, short) in CRATES {
        if !line.is_empty() {
            line.push_str(", ");
        }
        match found.iter().find(|(n, _, _)| n == krate) {
            Some((_, v, c)) if !c.is_empty() => {
                let _ = write!(line, "{short} {v} ({c})");
            }
            Some((_, v, _)) => {
                let _ = write!(line, "{short} {v}");
            }
            None => {
                let _ = write!(line, "{short} unknown");
            }
        }
    }
    println!("cargo:rustc-env=CIRIS_LINKED_SUBSTRATE={line}");
}
