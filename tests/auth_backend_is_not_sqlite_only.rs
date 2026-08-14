//! **PostgreSQL nodes must be able to start** (CIRISServer#397).
//!
//! # The outage
//!
//! `wa_cert_backend` and `revocation_backend` reached for `engine.sqlite_backend()`
//! UNCONDITIONALLY, so the auth substrate — WA certs and service-token revocation
//! — was SQLite-only while the rest of the Engine is backend-agnostic.
//!
//! That is not a degraded mode on postgres, it is a dead process. `compose.rs`
//! calls `bootstrap_if_needed` at boot and **fails the boot on `Err`** (by design:
//! a bad seed must not silently downgrade owner-claim to "open forever"). On a
//! postgres node that call returned `NoSqliteBackend`, so the node never came up
//! — no federation, no `/v1/self`, no accord, no auth. PostgreSQL is a supported
//! deployment.
//!
//! # Nothing upstream was missing
//!
//! persist has shipped `impl WaCertService for PostgresBackend`, `impl
//! ServiceTokenRevocationService for PostgresBackend`, and
//! `Engine::postgres_backend()` all along. This crate simply never asked. The
//! fix is a two-arm dispatch, not a new backend.
//!
//! # The cutover did not cause it
//!
//! The constraint predates the agent's auth cutover (CIRISAgent#1028/#396). What
//! changed is that auth now genuinely depends on the node: postgres agents used to
//! run their own auth implementation that never consulted it — precisely the
//! duplication the cutover set out to remove. Deleting that Python exposed a real
//! gap rather than creating one, which is the correct outcome of removing a
//! shadow implementation and an argument for having removed it.
//!
//! # Why these tests read source
//!
//! Proving the postgres path end-to-end needs a live postgres Engine, which the
//! unit suite has no business standing up. What can be proven cheaply is the
//! property that actually broke: **no unconditional reach for a single backend**.
//! That is the regression, and it is visible in the code.

use std::path::Path;

fn store_src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth/store.rs"))
        .expect("read src/auth/store.rs")
        .replace("\r\n", "\n")
}

/// Strip `//` comments — the module header discusses `sqlite_backend()` at
/// length, and a check that counts prose would pass on the broken code.
fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Body of a named fn, so assertions cannot be satisfied elsewhere in the file.
fn fn_body(code: &str, sig: &str) -> String {
    let i = code
        .find(sig)
        .unwrap_or_else(|| panic!("{sig} must exist in src/auth/store.rs"));
    let rest = &code[i..];
    let end = rest.find("\n}").map(|j| j + 2).unwrap_or(rest.len());
    rest[..end].to_string()
}

/// **The regression.** Neither accessor may make SQLite a precondition.
#[test]
fn neither_auth_backend_requires_sqlite() {
    let code = code_only(&store_src());
    for sig in ["pub fn wa_cert_backend(", "pub fn revocation_backend("] {
        let body = fn_body(&code, sig);
        assert!(
            body.contains("engine.postgres_backend()"),
            "{sig} must fall through to the PostgreSQL backend. Requiring SQLite here does not \
             degrade a postgres node — `bootstrap_if_needed` fails the BOOT on Err, so the \
             process never starts:\n{body}"
        );
        assert!(
            !body.contains("ok_or(StoreError::NoAuthBackend)?")
                && !body.contains("ok_or(StoreError::NoSqliteBackend)?"),
            "{sig} must not make ONE backend a hard precondition with `?` — that is the exact \
             shape that shipped:\n{body}"
        );
    }
}

/// The error must name the LIMITATION, not the storage detail. "engine is not
/// SQLite-backed" tells an operator on a healthy postgres node that the wrong
/// database is missing, pointing debugging at storage instead of at auth support.
#[test]
fn the_failure_names_the_limitation_not_the_storage_detail() {
    let src = store_src();
    assert!(
        !code_only(&src).contains("NoSqliteBackend"),
        "the SQLite-specific error variant must be gone — its name IS the misdirection"
    );
    assert!(
        src.contains("no auth-capable backend"),
        "the message must say auth has no usable backend"
    );
    for consequence in ["login", "accord", "federation"] {
        assert!(
            src.contains(consequence),
            "the message must name what is unavailable ({consequence}) — an operator reading it \
             should not have to discover the blast radius by testing each surface"
        );
    }
}

/// Both backends must implement the FULL trait by delegation. A partial impl
/// would compile only if the missing methods were never called — i.e. it would
/// fail in production, on the path the caller happened not to exercise in test.
#[test]
fn every_trait_method_is_delegated_for_both_backends() {
    let code = code_only(&store_src());
    let cert = fn_body(&code, "impl WaCertService for AuthCertBackend");
    for m in [
        "upsert_wa_cert",
        "get_wa_cert",
        "get_by_kid",
        "get_by_oauth",
        "list_by_role",
        "set_active",
        "update_last_login",
    ] {
        assert!(
            cert.contains(&format!("Self::Postgres(b) => b.{m}(")),
            "WaCertService::{m} must delegate to the postgres arm — a method that only handles \
             SQLite fails at the first postgres caller, in production"
        );
    }
    // Anchored on the ENUM name, not the impl header: rustfmt wraps that header
    // across lines and a test pinned to one wrapping breaks on a reformat while
    // saying nothing about the behaviour.
    let rev = fn_body(&code, "for AuthRevocationBackend");
    for m in ["record_revocation", "list_revocations", "check_revocation"] {
        assert!(
            rev.contains(&format!("Self::Postgres(b) => b.{m}(")),
            "ServiceTokenRevocationService::{m} must delegate to the postgres arm"
        );
    }
}
