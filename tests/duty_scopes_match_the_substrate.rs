//! **Our conferrable-duty list must equal the substrate's** (CIRISServer#399).
//!
//! # What went wrong
//!
//! `CONFERRABLE_DUTIES` shipped with three of the five delegated-duty scopes
//! persist defines. `takedown` and `consent_revocation` were absent, so the card
//! could not confer them — and nothing anywhere said so. The menu looked
//! deliberate. A missing option is invisible in a way a wrong option is not:
//! nobody scans a dropdown wondering what is not on it.
//!
//! # Why importing the constants is not enough
//!
//! The list now imports persist's own `pub const`s instead of repeating literals,
//! which makes the SPELLINGS impossible to get wrong. It does nothing for
//! MEMBERSHIP: a sixth scope added upstream still silently fails to appear here,
//! because "every `DELEGATION_SCOPE_*` const in another crate" is not something
//! this crate can enumerate at compile time.
//!
//! That is the real defect and it is upstream: persist declares five consts and
//! exports no array over them. With nothing importable, every consumer
//! hand-picks, and every hand-picked mirror drifts. Filed as the proper fix.
//!
//! Until it lands, the guard is this test, which reads persist's OWN SOURCE out
//! of the vendored checkout and compares the two sets. It is a grep, and a grep
//! is a poor substitute for a type — but it fails loudly on the exact event that
//! already happened once, which is the bar.
//!
//! # Deliberately excluded
//!
//! `owner_binding_recovery` (`federation/ownership_reclaim.rs`) is a
//! `DELEGATION_SCOPE_*` const but NOT a delegated DUTY — it is the ownership
//! reclaim path, a different plane with a different walk. It is named here rather
//! than filtered silently, so a reader can see the exclusion was a decision.

use std::path::{Path, PathBuf};

/// Locate the vendored persist checkout cargo actually built against, by reading
/// the locked revision out of `Cargo.lock`. Pinning by rev (not by "newest
/// directory") means this test reads the source that produced OUR binary.
fn persist_admission_source() -> Option<PathBuf> {
    let lock =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")).ok()?;
    let idx = lock.find("name = \"ciris-persist\"")?;
    let after = &lock[idx..];
    let src_line = after
        .lines()
        .find(|l| l.trim_start().starts_with("source ="))?;
    let rev = src_line.rsplit('#').next()?.trim_end_matches('"');
    let short = &rev[..7.min(rev.len())];

    let home = std::env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cargo")
        });
    let checkouts = home.join("git/checkouts");
    let entries = std::fs::read_dir(&checkouts).ok()?;
    for e in entries.flatten() {
        if !e.file_name().to_string_lossy().starts_with("cirispersist-") {
            continue;
        }
        let candidate = e.path().join(short).join("src/federation/admission.rs");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Every `DELEGATION_SCOPE_*` the substrate declares in `admission.rs`, by VALUE.
fn substrate_scopes(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let l = line.trim();
        if !l.starts_with("pub const DELEGATION_SCOPE_") {
            continue;
        }
        // `pub const DELEGATION_SCOPE_X: &str = "x";`
        if let Some(eq) = l.find('=') {
            let rhs = l[eq + 1..].trim().trim_end_matches(';').trim();
            if let Some(v) = rhs.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                out.push(v.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn every_substrate_duty_scope_is_conferrable() {
    let Some(path) = persist_admission_source() else {
        // A skip that SAYS it skipped. A silent pass here would make the whole
        // test decorative on any machine without the checkout — which is most CI
        // legs, i.e. exactly where it would be believed.
        eprintln!(
            "SKIP (not a pass): could not locate the vendored ciris-persist checkout for the \
             locked revision; the duty-scope drift guard did not run"
        );
        return;
    };
    let src = std::fs::read_to_string(&path).expect("read persist admission.rs");
    let substrate = substrate_scopes(&src);
    assert!(
        !substrate.is_empty(),
        "found no DELEGATION_SCOPE_* consts in {} — the grep shape changed and this guard is now \
         green by construction, which is worse than red",
        path.display()
    );

    let mut ours: Vec<String> = ciris_server::accord_duty::CONFERRABLE_DUTIES
        .iter()
        .map(|s| s.to_string())
        .collect();
    ours.sort();

    let missing: Vec<&String> = substrate.iter().filter(|s| !ours.contains(s)).collect();
    let extra: Vec<&String> = ours.iter().filter(|s| !substrate.contains(s)).collect();

    assert!(
        missing.is_empty(),
        "the substrate defines duty scopes this server cannot confer: {missing:?}\n\nsubstrate: \
         {substrate:?}\nours:      {ours:?}\n\nThis is the defect that shipped: `takedown` and \
         `consent_revocation` existed upstream and were simply absent from the card. Add them to \
         CONFERRABLE_DUTIES — or, if one is genuinely not a delegated duty, exclude it BY NAME in \
         this test with the reason, the way `owner_binding_recovery` is."
    );
    assert!(
        extra.is_empty(),
        "this server offers duty scopes the substrate does not define: {extra:?}. A conferral the \
         gate does not recognize renders as authority in the UI and admits nothing — the #333 \
         'stored label' shape."
    );
}

/// The list must be sourced from persist's constants, not re-spelled. Catches the
/// regression where someone "fixes" a missing scope by adding a string literal.
#[test]
fn the_list_is_imported_not_respelled() {
    let src =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/accord_duty.rs"))
            .expect("read accord_duty.rs");
    let start = src.find("pub const CONFERRABLE_DUTIES").expect("the list");
    let end = start + src[start..].find("];").expect("list end");
    let body = &src[start..end];
    assert!(
        !body.contains('"'),
        "CONFERRABLE_DUTIES must contain only imported constants — a string literal here is the \
         same hand-mirroring that let the set drift in the first place (CIRISServer#322):\n{body}"
    );
    for expected in [
        "DELEGATION_SCOPE_CONSENT_REVOCATION",
        "DELEGATION_SCOPE_MODERATE",
        "DELEGATION_SCOPE_TAKEDOWN",
        "DELEGATION_SCOPE_REVIEW",
        "DELEGATION_SCOPE_SLASH",
    ] {
        assert!(
            body.contains(expected),
            "{expected} must be in CONFERRABLE_DUTIES — all five, or the card silently cannot \
             grant what the substrate can gate on"
        );
    }
}
