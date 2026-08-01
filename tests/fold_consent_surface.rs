//! The in-fold consent surface — pinned so it cannot silently regress.
//!
//! # The defect this exists for
//!
//! A production wizard running inside the fold called
//! `GET /v1/accord/canonical-servers` and got a **404**, then never authored
//! consent. Two separate causes, and the second is the durable one:
//!
//!   * the path was wrong — it is `/v1/accord/canonical/servers`;
//!   * **no HTTP path could have worked.** The embedded agent boots through
//!     `start_and_hold`, which mounts no router at all. Every owner-gated route
//!     is mounted in `serve_with_adapter`, the compose path. Inside the fold,
//!     `POST /v1/federation/consent` 404s by construction.
//!
//! The wizard reached for HTTP because our own docstring told it to: it said
//! *"production consent is exclusively the owner-gated POST
//! /v1/federation/consent"*, which stopped being true in 0.5.147 and was still
//! there in 0.5.149. **A stale doc is an instrument that reports the wrong
//! branch** — the same class as everything in `FSD/RCA_TRACE_PLANE_2026-07-31.md`.
//!
//! # What is deliberately NOT here
//!
//! There is no `consent_to_canonicals()` convenience. It was written and
//! reverted: it decided both *which* peers ("all canonicals") and *what* policy
//! ("our defaults"), and neither is ours to decide. The exhaustive consent form
//! is the agent's — *"traces to canonicals blessed by a trust root I trust"*,
//! *"medical data to medical providers my providers trust"* — and it changes per
//! deployment. Collapsing peer selection into the call makes every one of those
//! unreachable and pushes the caller straight back to composing by hand, around
//! a function that no longer fits.
//!
//! So the surface stays decomposed: **enumerate → filter on your own predicate →
//! author per peer.** Two calls when our default policy suits you, three when it
//! does not.

use std::path::Path;

fn lib_rs() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs must be readable")
}

/// The fold must be able to author consent WITHOUT an HTTP router.
#[test]
fn author_federation_consent_is_exported_to_the_fold() {
    let src = lib_rs();
    assert!(
        src.contains(r#"name = "author_federation_consent""#),
        "the fold's only consent path must stay exported from the pymodule — without it an \
         embedded agent has no way to author consent at all, because start_and_hold mounts no \
         HTTP router"
    );
    assert!(
        src.contains("wrap_pyfunction!(py_author_federation_consent"),
        "exported is not enough — it must also be REGISTERED on the module, or the wizard sees \
         AttributeError and falls back to the HTTP path that 404s"
    );
}

/// Omitting the prefixes must mean "this build's production default", so a
/// caller with no policy of its own cannot restate — and thereby fork — ours.
#[test]
fn prefixes_are_optional_so_the_default_is_exercised_not_restated() {
    let src = lib_rs();
    let sig = src
        .lines()
        .find(|l| l.contains(r#"name = "author_federation_consent""#))
        .expect("the pyo3 signature line must exist");
    assert!(
        sig.contains("attestation_prefixes = None"),
        "attestation_prefixes must default to None (⇒ the production default). Required-arg \
         form forces every caller to name a set, and the harness named ['trace:','capacity:'] \
         for eight releases while production shipped ['capacity:'] and moved ZERO traces. A \
         fixture that supplies the value production defaults cannot prove the default.\n\
         got: {sig}"
    );
}

/// Peer selection must NOT be baked into the consent call.
#[test]
fn the_surface_does_not_decide_which_peers_to_consent_to() {
    let src = lib_rs();
    for banned in ["consent_to_canonicals", "consent_to_all_peers"] {
        assert!(
            !src.contains(banned),
            "`{banned}` bakes a peer-selection policy into the substrate. Who to consent to is \
             the agent's exhaustive consent form and it changes per deployment ('traces to \
             canonicals blessed by a trust root I trust', 'medical data to medical providers my \
             providers trust'). Enumerate + filter belongs to the caller; this crate authors one \
             grant to one named peer."
        );
    }
}

/// The docstring must not send an in-fold caller to HTTP. This is the exact
/// sentence that produced the 404.
#[test]
fn the_docstring_does_not_point_the_fold_at_a_route_the_fold_cannot_serve() {
    let src = lib_rs();
    let start = src
        .find("name = \"author_federation_consent\"")
        .expect("signature present");
    let doc_start = src[..start]
        .rfind("#[pyfunction]")
        .expect("attribute present");
    let doc = &src[doc_start..start];

    assert!(
        !doc.contains("exclusively the owner-gated POST"),
        "the doc claimed production consent is EXCLUSIVELY the owner-gated POST. That stopped \
         being true in 0.5.147 (author_consent_embedded, gated on the node being CLAIMED), and \
         a wizard believing it called HTTP inside the fold and got a 404."
    );
    assert!(
        doc.contains("start_and_hold") && doc.contains("404"),
        "the doc must state WHY HTTP cannot work in the fold — start_and_hold mounts no router, \
         so the owner-gated routes 404 by construction. Saying 'use this instead' without the \
         reason invites the next caller to try HTTP first and read the 404 as a transient."
    );
}
