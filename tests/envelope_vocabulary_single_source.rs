//! Single-source envelope-vocabulary gate (CIRISServer#322 / SRV-1).
//!
//! Persist owns the attestation-envelope key vocabulary as exported constants
//! (`ciris_persist::federation::envelope::paths::*`) and the consent-state
//! dimension prefixes (`ciris_persist::federation::consent::consent_dimension::*`).
//! Persist pins that vocabulary on ITS side with `ENVELOPE_VOCABULARY_SHA256`;
//! the server must speak the SAME constants at every emit/read site rather than
//! hand-mirror a raw string literal. A hand-mirror is the exact silent-skew
//! defect this cut closes: a raw `"dimension"` still COMPILES after persist
//! renames the key, then diverges on the wire (the withdraws/supersedes
//! `references_attestation_id` link, the consent-revocation fold, …).
//!
//! This gate walks `src/**/*.rs` and fails if a forbidden envelope-key /
//! consent-state string literal reappears in a *code* (non-comment) line
//! outside a narrow, explicitly-justified allow-list. It is the ratchet that
//! stops the hand-mirror from growing back — that ratchet is the point of the
//! exercise, not the substitutions themselves.

use std::path::{Path, PathBuf};

/// The raw literals that MUST NOT appear in server emit/read code — each has an
/// exported persist constant that is the single source of truth:
///   `"dimension"`                -> `…::federation::envelope::paths::DIMENSION`
///   `"references_attestation_id"`-> `…::envelope::paths::REFERENCES_ATTESTATION_ID`
///   `"consent:state:…"`          -> `…::consent::consent_dimension::STATE_*_PREFIX`
const FORBIDDEN: &[&str] = &[
    "\"dimension\"",
    "\"references_attestation_id\"",
    "\"consent:state:",
];

/// Whole files where these literals are genuinely NOT persist envelope emit/read
/// keys, with the reason each is a different contract surface.
const FULL_FILE_ALLOW: &[(&str, &str)] = &[
    (
        // The server-owned conformance manifest: `field:` values are
        // `field_processor_matrix` identifiers matched against the edge/persist
        // MANIFEST, not envelope keys. Sibling entries in the same table
        // (`aggregation_policy`, `achieved_tier`, `conformity_variant`, …) are
        // not `envelope::paths` constants at all, so sourcing only `"dimension"`
        // / `"references_attestation_id"` from persist would misrepresent them
        // and split the manifest's vocabulary across two owners.
        "field_conformance.rs",
        "conformance-manifest field_processor_matrix identifiers, not envelope keys",
    ),
    // (`trust_root_qa.rs` was listed here while it was a `src/` module. It moved
    // to `tests/` in CIRISServer#362 — this gate only walks `src/`, so the entry
    // was dead config, and dead config is a claim about the tree that stops
    // being true without anything failing.)
];

/// Specific production lines where the literal is deliberately NOT the persist
/// key. Matched by (file suffix, distinctive substring) so a line-number shift
/// does not silence the gate.
const LINE_ALLOW: &[(&str, &str, &str)] = &[
    (
        "memory_api.rs",
        "\"dimension\": dim",
        // A client-facing CEG projection-node property (siblings `kind`,
        // `status`, `name`, `description`) — deliberately DECOUPLED from the
        // persist envelope key so a persist rename never silently reshapes the
        // graph the client renders.
        "CEG projection-node property, decoupled from the envelope key on purpose",
    ),
    (
        "compose_policy.rs",
        "MalformedEnvelope(\"dimension\"",
        // A human diagnostic field-name label in an error variant; its sibling
        // labels (`"score"`, `"confidence"`) are not persist constants, so
        // substituting only this one would be inconsistent and it is not a
        // wire/SQL key.
        "error-message field label, not a wire/SQL key",
    ),
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => panic!("cannot read {}: {e}", dir.display()),
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_hand_mirrored_envelope_vocabulary_literals() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "found no .rs files under {}",
        src.display()
    );

    let mut violations: Vec<String> = Vec::new();

    for file in &files {
        let name = file.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if FULL_FILE_ALLOW.iter().any(|(f, _)| *f == name) {
            continue;
        }
        let text = std::fs::read_to_string(file).expect("read source file");
        // Test fixtures below a file's `#[cfg(test)]` boundary are unit-test
        // scaffolding, not production emit/read paths — allowed. (Test modules
        // are conventionally the tail of the file.)
        let mut in_test = false;
        for (idx, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#[cfg(test)]") || trimmed.starts_with("#[cfg(all(test") {
                in_test = true;
            }
            if in_test {
                continue;
            }
            // Doc comments / line comments describe the vocabulary in prose —
            // allowed.
            if trimmed.starts_with("//") {
                continue;
            }
            for needle in FORBIDDEN {
                if !line.contains(needle) {
                    continue;
                }
                let allowed = LINE_ALLOW
                    .iter()
                    .any(|(f, sub, _)| *f == name && line.contains(sub));
                if !allowed {
                    violations.push(format!(
                        "{}:{}: raw `{}` — import the persist constant instead \
                         (envelope::paths::* / consent::consent_dimension::*)",
                        file.display(),
                        idx + 1,
                        needle,
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "hand-mirrored envelope-vocabulary string literal(s) reappeared in src/ \
         emit/read code — persist exports these as constants; import and use them \
         so a persist rename cannot silently skew the wire (CIRISServer#322):\n{}",
        violations.join("\n"),
    );
}
