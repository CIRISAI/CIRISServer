//! **Backend parity is not a discipline — it must be a build failure.**
//!
//! persist enforces parity with TRAITS: every capability is a `*Service` trait
//! implemented by `SqliteBackend`, `PostgresBackend` and `MemoryBackend`, so a
//! new method is a compile error in any backend that has not implemented it.
//!
//! A consumer only loses that guarantee by reaching PAST the trait for a
//! concrete backend. `engine.sqlite_backend()` is that reach, and this crate had
//! it in 30 places. What it cost:
//!
//! - **twelve sites in `src/safety/`** — watchlists, named-entity promotion,
//!   moderation duties, age assurance and infohazard flags each returned "no
//!   directory" on a PostgreSQL node. Not degraded. Absent, and silent.
//! - **auth** — killed the process at boot on postgres (CIRISServer#397), loud
//!   only because `bootstrap_if_needed` fails the boot deliberately.
//! - **the capacity scorer** — 21 cadence ticks, 21 failures, zero `capacity:*`
//!   attestations, observed live on the postgres scout node while the node
//!   itself reported healthy.
//!
//! Every one of those was invisible to review, because `sqlite_backend()` reads
//! as a perfectly ordinary accessor at the call site. Only counting them across
//! the tree makes the pattern visible — which is what this test does.
//!
//! ## The rule
//!
//! Reach for a concrete backend ONLY where no backend-agnostic door exists, and
//! say so in the exemption list below. In order of preference:
//!
//! 1. `engine.federation_directory()` → `Arc<dyn FederationDirectory>` — ~200
//!    methods, every backend, and no `Option` to unwrap.
//! 2. `Engine`'s own dispatch methods (`list_attestations`, …).
//! 3. `crate::backend::*` — this crate's dispatch for traits persist implements
//!    on every backend but exposes no accessor for.

use std::collections::BTreeSet;
use std::path::Path;

/// Files permitted to name a concrete backend, each with the reason no
/// backend-agnostic door exists. **Adding an entry here is the reviewable act** —
/// that is the whole point of the list.
const EXEMPT: &[(&str, &str)] = &[
    (
        "src/backend.rs",
        "IS the dispatch — persist declares ReadEngine on every backend and \
         exposes no accessor for it, so this module supplies one",
    ),
    (
        "src/auth/store.rs",
        "IS the dispatch for WaCertService / ServiceTokenRevocationService \
         (CIRISServer#397); both arms present, postgres gated to Linux where \
         persist's `postgres` feature lives",
    ),
    (
        "src/memory_api.rs",
        "SqliteGraphBackend is built over a raw rusqlite `conn_handle()`; there \
         is no postgres graph backend to dispatch to yet. TRACKED — this is a \
         real parity gap, not a resolved one",
    ),
    (
        "src/compose.rs",
        "the RET relay holds a raw SQLite handle; same gap as memory_api. \
         TRACKED",
    ),
];

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Strip line comments and doc comments — a backend named in prose is not a
/// backend reached for in code, and this file's own module doc would otherwise
/// trip the gate it defines.
fn code_only(src: &str) -> String {
    src.lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with("///") || t.starts_with("//!"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn nothing_reaches_for_a_concrete_backend_outside_the_door() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);

    let exempt: BTreeSet<&str> = EXEMPT.iter().map(|(f, _)| *f).collect();
    let mut offenders: Vec<String> = Vec::new();

    for f in &files {
        let rel = f
            .strip_prefix(&root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        if exempt.contains(rel.as_str()) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(f) else {
            continue;
        };
        let code = code_only(&src);
        for needle in ["sqlite_backend()", "postgres_backend()"] {
            let n = code.matches(needle).count();
            if n > 0 {
                offenders.push(format!("{rel}: {n}× {needle}"));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "\nA CONCRETE BACKEND IS REACHED FOR OUTSIDE THE DOOR.\n\
         \n\
         {}\n\
         \n\
         `sqlite_backend()` compiles, passes review, and returns None in \
         production on every PostgreSQL node — so the feature above it does not \
         degrade, it DISAPPEARS, silently. Twelve safety checks were exempt on \
         postgres this way, and the capacity scorer failed every cadence for as \
         long as anyone had been watching.\n\
         \n\
         Use a backend-agnostic door instead:\n\
         \n\
           1. engine.federation_directory()  -> Arc<dyn FederationDirectory>\n\
              ~200 methods, every backend, returns no Option to unwrap.\n\
           2. Engine's own dispatch methods (list_attestations, ...).\n\
           3. crate::backend::*  for traits persist implements on every backend\n\
              but exposes no accessor for.\n\
         \n\
         If none exists, add the file to EXEMPT in this test WITH the reason. \
         That entry is the reviewable act, and a reviewer can then ask the only \
         question that matters: why can this not be backend-agnostic?\n",
        offenders.join("\n")
    );
}

/// An exemption that no longer names a real file is a stale licence to reach for
/// a concrete backend. Expire them.
#[test]
fn every_exemption_still_names_a_real_file() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (f, why) in EXEMPT {
        assert!(
            root.join(f).exists(),
            "EXEMPT names `{f}` ({why}) but that file does not exist — remove the \
             entry rather than leaving a licence nobody needs"
        );
    }
}

/// The exemptions must still be REACHING for a concrete backend. One that has
/// been migrated should lose its licence, or the list slowly becomes a list of
/// files nobody has to justify.
#[test]
fn every_exemption_is_still_load_bearing() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (f, why) in EXEMPT {
        let Ok(src) = std::fs::read_to_string(root.join(f)) else {
            continue;
        };
        let code = code_only(&src);
        assert!(
            code.contains("sqlite_backend()") || code.contains("postgres_backend()"),
            "`{f}` is EXEMPT ({why}) but no longer reaches for a concrete backend. \
             Drop the exemption — it now licenses nothing, and a list of \
             unnecessary exemptions is how the next one slips in unnoticed."
        );
    }
}
