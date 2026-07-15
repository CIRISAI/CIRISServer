//! CIRISServer#264 regression — `init_tracing_with` MUST NOT panic when a global
//! subscriber is already installed. In the Python-embedded agent the host calls
//! `ciris_server.init_tracing()` (CIRISAgent#919) before the node fold's
//! `serve_with_python_adapter`, and an in-process node restart re-enters the fn;
//! `.init()` panicked, crossed pyo3 as PanicException (BaseException — invisible
//! to the fold's `except Exception`), and the fold died SILENTLY pre-first-log:
//! the deterministic configured-home hang. This pins the non-panicking contract.

#[test]
fn init_tracing_with_is_reentrant_after_a_subscriber_exists() {
    // Install a first subscriber (stands in for the agent's init_tracing()).
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(sub).expect("first install");

    // Re-entry must fall through gracefully — a panic here IS the #264 bug.
    ciris_server::init_tracing_with(Some(std::env::temp_dir().join("ciris-264-test").as_path()));
    ciris_server::init_tracing_with(None); // and again (in-process restart shape)
}
