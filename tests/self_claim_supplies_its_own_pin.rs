//! **The first-run self-claim must not need a PIN from the client**
//! (CIRISServer#395).
//!
//! The one-time claim PIN proves OPERATOR PRESENCE at the target: you read it off
//! that node's console. That is exactly right for a REMOTE target and vacuous for
//! this one — on a self-claim the target's console IS this process.
//!
//! The PIN is documented, in `announce_ownership_unclaimed`, as "console-only —
//! NEVER over HTTP", and it is served by no route. So the co-located wizard has no
//! supported way to obtain it. Forwarding `req.claim_pin` on a self-claim therefore
//! demanded a secret the caller was structurally unable to hold:
//!
//! ```text
//! POST /v1/setup/claim-remote  →  POST /v1/setup/root  →  401 invalid one-time claim PIN
//! ```
//!
//! and first-run setup could never complete. The wizard looped back to local
//! login, and the client rendered the 401 as "node already claimed" — which is the
//! opposite of true; the node was still `is_first_run: true`, `<UNCLAIMED>`.
//!
//! # The shape, not the string
//!
//! This is the [[distinct-zeroes]] family again, one level up: "I asked and the
//! PIN was wrong" and "I could not have asked, because the secret is unreachable
//! from here" are different states, and the code had only one branch for both. The
//! second is not an authentication failure — it is a category error about who the
//! console is.
//!
//! The claim runs ONCE, automatically, at wizard completion — after every
//! selection is made, before any is applied. There is no point in that flow at
//! which a human types anything, so any design that requires typing is broken by
//! construction rather than broken in a case.
//!
//! # What must NOT change
//!
//! A REMOTE claim keeps requiring the operator-supplied PIN. That is the whole
//! reason the field exists, and weakening it would let any loopback caller claim
//! an arbitrary reachable node. The substitution is gated on the target being THIS
//! node — the same `nc.key_id == st.node_key_id` discriminator the local-directory
//! bookkeeping already used after the fact.

use std::path::Path;

fn src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/claim_remote.rs"))
        .expect("read src/claim_remote.rs")
}

/// Strip `//` line comments so a prose mention of a symbol cannot satisfy a check
/// that is supposed to be about CODE. This has bitten three separate gates in this
/// repo — a comment naming the thing is not the thing.
fn code_only(s: &str) -> String {
    s.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The handler must consult the in-process PIN, and must decide on the SELF
/// discriminator rather than on "the client sent nothing" (which a remote caller
/// could also produce).
#[test]
fn the_self_claim_substitutes_the_in_process_pin() {
    let code = code_only(&src());
    assert!(
        code.contains("first_run_claim_pin"),
        "the self-claim must read this boot's in-process PIN (#277) — it is the only reader the \
         console-only PIN has, and without it the automated wizard step cannot complete"
    );
    assert!(
        code.contains("nc.key_id == st.node_key_id"),
        "the substitution must be gated on the target being THIS node. Gating on an empty \
         client-supplied PIN instead would let a loopback caller claim an arbitrary REMOTE node \
         by simply omitting the field"
    );
}

/// The remote path must still forward the operator's PIN. If this ever regresses
/// to always using the local PIN, a loopback caller could claim any reachable node
/// without ever proving presence at it.
#[test]
fn a_remote_target_still_requires_the_operator_supplied_pin() {
    let code = code_only(&src());
    assert!(
        code.contains("Cow::Borrowed(req.claim_pin.as_str()")
            || code.contains("Cow::Borrowed(req.claim_pin"),
        "a non-self target must fall back to the CLIENT-supplied PIN — that is the operator \
         presence proof for a node whose console this process is not"
    );
    // …and the local PIN must not be reachable on the remote path at all: the
    // `.then(...)` is what makes `first_run_claim_pin` unreachable unless self.
    assert!(
        code.contains("self_target") && code.contains(".then("),
        "the in-process PIN must be behind the self_target predicate, not merely preferred over \
         an empty string"
    );
}

/// `claim_pin` must be `#[serde(default)]`. A required field would 400 the very
/// request that is not supposed to carry one, turning the fix into a different
/// error at the same step.
#[test]
fn the_wizard_need_not_invent_a_value_it_cannot_read() {
    let raw = src();
    // Scope to the INBOUND request. `RemoteSetupRootRequest` (the outbound body we
    // POST to the target) has a same-named field, and it must stay mandatory —
    // asserting against whichever one `find` reaches first would pin the wrong
    // struct and pass while the real one regressed.
    let start = raw
        .find("struct ClaimRemoteRequest {")
        .expect("the inbound request struct");
    let body = &raw[start..];
    let idx = start
        + body
            .find("    claim_pin: String,")
            .expect("the ClaimRemoteRequest field");
    let preceding = &raw[..idx];
    assert!(
        preceding.ends_with("#[serde(default)]\n"),
        "`claim_pin` must default: the self-claim omits it, and a mandatory field would answer \
         400 instead of 401 — the same dead end wearing a different status code"
    );
}
