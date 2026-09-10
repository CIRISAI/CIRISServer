//! Gate: every multi-thread runtime this crate builds goes through
//! `node_runtime::build`.
//!
//! CIRISServer#577 measured the embedded fold from outside: four independent
//! multi-thread runtimes, each sized to `available_parallelism()`, for a
//! single-user workload that is mostly idle. An 8-core handset got tens of
//! native worker threads, and thread count is the multiplier in every
//! allocator's per-thread cache — glibc arenas, Scudo's TSD on Android,
//! libmalloc's magazines on iOS. Unlike `M_ARENA_MAX` (CIRISServer#552) it is a
//! lever that exists on every platform the fold ships to.
//!
//! A bare `Builder::new_multi_thread()` anywhere in this crate is a runtime the
//! host's `worker_threads=` cannot reach — and it also misses the #501 worker
//! floor on a small host, which is the same bug from the other end. The two
//! reasons share one fix: one builder, every runtime.

fn src_files() -> Vec<(String, String)> {
    let mut out = Vec::new();
    // `benches/` as well as `src/`: a benchmark that reports RSS while ignoring
    // the worker cap measures a thread count nobody asked for, and the gate
    // claimed to cover every runtime in the crate while looking at one
    // directory (Codex, PR #578).
    let mut stack = vec![
        std::path::PathBuf::from("src"),
        std::path::PathBuf::from("benches"),
    ];
    while let Some(dir) = stack.pop() {
        let Ok(listing) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in listing {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((
                    path.to_string_lossy().into_owned(),
                    std::fs::read_to_string(&path).expect("read file"),
                ));
            }
        }
    }
    out
}

/// Strip `//` line comments, so prose naming the old API does not read as a
/// call site — this gate's own rationale mentions it, and so does the comment
/// at each site that was converted.
fn code_only(body: &str) -> String {
    body.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_runtime_is_built_outside_the_shared_builder() {
    let mut offenders = Vec::new();
    for (name, body) in src_files() {
        if name.ends_with("node_runtime.rs") {
            continue; // the shared builder itself
        }
        for (n, line) in code_only(&body).lines().enumerate() {
            if line.contains("new_multi_thread()") {
                offenders.push(format!("{name}:{}", n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these runtimes are built directly, so an embedded host's `worker_threads=` \
         cannot reach them and the #501 floor does not apply — build them with \
         `node_runtime::build(\"<thread name>\")`:\n  {}",
        offenders.join("\n  ")
    );
}

/// Both Python entry points must expose the knob: an embedded host that can cap
/// the serve runtime but not the delivery runtime has capped half the threads.
#[test]
fn both_python_entry_points_accept_worker_threads() {
    let lib = std::fs::read_to_string("src/lib.rs").expect("read lib.rs");
    for entry in ["serve_with_python_adapter", "start_federation_delivery"] {
        let at = lib
            .find(&format!("name = \"{entry}\""))
            .unwrap_or_else(|| panic!("{entry} not found in src/lib.rs"));
        // The pyo3 signature follows the name within the same attribute.
        let window = &lib[at..(at + 400).min(lib.len())];
        assert!(
            window.contains("worker_threads=None"),
            "{entry} does not take `worker_threads=` — CIRISServer#577 asks for one \
             knob honoured by every runtime the entry points create"
        );
    }
}
