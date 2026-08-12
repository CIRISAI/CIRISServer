//! **`ciris_server.resolve_bearer(token)` — the binding that retires the agent's
//! auth** (CIRISServer#396, from CIRISAgent#1029).
//!
//! # Why it exists
//!
//! The brain and the node minted disjoint token families and neither verified the
//! other's, measured by the agent team on one instance:
//!
//! ```text
//! token                          :8080 brain   :4243 node
//! sess:wa-2026-08-12-F7D74E:…        401           200
//! ciris_system_admin_29Dpb…          200           401
//! ```
//!
//! So proxying `POST /v1/auth/login` to the node SUCCEEDS, and then the client
//! calls a brain route with the token it was just issued and is refused. The
//! cutover fails at the second hop, not the first.
//!
//! The only alternative was the brain calling `/v1/auth/me` over loopback on every
//! authenticated request — a round trip per call and a second code path, which is
//! the thing being deleted.
//!
//! # One verifier, every mechanism
//!
//! Password login, Google native `id_token`, Apple native `id_token`, the OAuth
//! callback and the delegated device-grant all funnel through a single
//! `issue_session_token(wa_id)` — deliberately the only caller outside tests. One
//! minter means one VERIFIER answers for all of them, and for whatever is added
//! next. That is why this is a single binding rather than one per provider.
//!
//! # What these tests pin
//!
//! Not "it returns a dict" — that would pass on a binding that swallows outages.
//! The load-bearing property is that **`None` means INVALID and an exception means
//! COULD NOT CHECK**, because a verifier that cannot tell "forged" from "I could
//! not look" admits both. Collapsed the wrong way, a store outage becomes a silent
//! total lockout that looks exactly like everyone presenting bad tokens at once.

use std::path::Path;

fn lib_src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read src/lib.rs")
        .replace("\r\n", "\n")
}

/// The binding's body, so assertions cannot be satisfied by unrelated code.
fn binding_body(src: &str) -> String {
    let i = src
        .find("fn py_resolve_bearer(")
        .expect("the resolve_bearer binding must exist — CIRISServer#396");
    let rest = &src[i..];
    let end = rest.find("\n    }\n").map(|j| j + 6).unwrap_or(rest.len());
    rest[..end]
        .lines()
        .map(|l| match l.find("//") {
            Some(k) => &l[..k],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// It must be registered on the module, or it is unreachable from Python no
/// matter how correct the function is.
#[test]
fn the_binding_is_exported_to_python() {
    let src = lib_src();
    assert!(
        src.contains("wrap_pyfunction!(py_resolve_bearer, m)"),
        "resolve_bearer must be added to the pyo3 module — an unregistered #[pyfunction] compiles \
         fine and is simply absent at runtime, which reads to the caller as 'the binding was \
         never built'"
    );
    assert!(
        src.contains("#[pyo3(name = \"resolve_bearer\", signature = (token))]"),
        "the Python-visible name must be `resolve_bearer` — the agent's dependency injection is \
         written against that spelling"
    );
}

/// **The distinction the whole binding rests on.** A store failure must RAISE.
#[test]
fn a_store_outage_raises_rather_than_returning_none() {
    let body = binding_body(&lib_src());
    let map_err_at = body
        .find("resolve_bearer: identity store unavailable")
        .expect(
            "a store error must produce an explicit, self-describing exception. Mapping it to \
             `Ok(None)` tells the caller the token is INVALID when it was never judged — every \
             session in the fleet fails closed at once and the logs say 'bad token'",
        );
    let ok_none_at = body
        .find("return Ok(None)")
        .expect("the invalid-token path");
    assert!(
        map_err_at < ok_none_at,
        "the outage arm must come BEFORE the None arm in the body — if resolution is folded into \
         the None path first, the raise is dead code"
    );
    assert!(
        body.contains("do not treat this as a rejection"),
        "the exception text must SAY that the token was not judged. A caller reading \
         `except: return None` around this is the exact collapse the split exists to prevent, \
         and the message is the only place they will be told"
    );
}

/// An absent engine or runtime is also "cannot check", not "invalid".
#[test]
fn a_missing_engine_or_runtime_is_not_a_verdict() {
    let body = binding_body(&lib_src());
    for needle in [
        "no in-process persist Engine",
        "federation delivery not started",
    ] {
        assert!(
            body.contains(needle),
            "the {needle:?} case must raise with its own message — it means the node is not \
             composed in this process, which cannot be read as a judgement about the token"
        );
    }
    assert!(
        body.contains("CANNOT be read as 'the token is invalid'")
            || body.contains("NOT the same as a bad token"),
        "both unavailability messages must state that they are not rejections"
    );
}

/// `actor` is the attribution axis and must survive to Python. Dropping it makes
/// a delegated action indistinguishable from the owner performing it.
#[test]
fn the_attribution_axis_is_returned() {
    let body = binding_body(&lib_src());
    assert!(
        body.contains("d.set_item(\"actor\", caller.actor)"),
        "`actor` must be returned. For a delegated device-grant the caller wields the OWNER's \
         authority while every action is attributable to the actor — logging `wa_id` alone \
         records the owner as having done something a delegate did"
    );
    for field in ["wa_id", "name", "role", "scopes"] {
        assert!(
            body.contains(&format!("d.set_item(\"{field}\"")),
            "the returned dict must carry `{field}` — the agent's dependency reads all of them"
        );
    }
}

/// Scopes must use the SERDE spelling, which is the wire form clients already
/// check. A hand-rolled second spelling is how two surfaces come to disagree
/// about what a permission is called.
#[test]
fn scopes_use_the_wire_spelling_not_a_second_one() {
    let body = binding_body(&lib_src());
    assert!(
        body.contains("serde_json::to_value(p)"),
        "permissions must serialize through serde — `Permission` is documented as \"preserved \
         verbatim for client compatibility\" and serde produces that exact spelling. Deriving \
         the strings here would create a second vocabulary over one enum"
    );
}
