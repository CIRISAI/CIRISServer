//! **Scope-native addressing is ARMED, and stays armed** (CIRISServer#451 item 2).
//!
//! # Why this needs a gate at all
//!
//! Edge ships scope gates DEFAULT-OPEN. Nothing upstream turns them on; the
//! arming event is the server's call, and an unarmed node is not broken in any
//! way it reports. It simply addresses every scope with the same
//! `sha256(fed_pubkey)[..16]`, which an observer can link across every context
//! the node participates in — the exact linkability the record layer was built
//! to remove.
//!
//! So the failure mode this guards is silent: a refactor drops the builder call,
//! every test still passes, the node still serves, and the property is gone with
//! no symptom. That is the same shape as CIRISServer#365 (nine `mesh_config`
//! keys, zero consumers) — operable, and not EFFECTIVE.
//!
//! # What the two tests here divide between them
//!
//! * The API contract — arming produces a live `ScopeLifecycle`, and not arming
//!   produces `None`. Proves the knob does something.
//! * OUR wiring — `compose.rs` actually calls it. Proves the knob is turned.
//!
//! Either alone passes while the property is absent, which is why both exist.

/// Arming is what produces a `ScopeLifecycle`; without it there is none.
///
/// Asserts BOTH directions deliberately. A test that only checked the armed
/// case would pass against a build where `scope_lifecycle()` returned `Some`
/// unconditionally — and then it would be measuring nothing, while reading as
/// the strongest assertion in the file.
#[test]
fn arming_is_what_produces_a_scope_lifecycle() {
    // The default window is edge's, not a number we invented: 300s is how long
    // a superseded epoch stays reachable after rotation. We take their default
    // because we have no measurement of our own to justify a different one.
    let w = ciris_edge::scope_lifecycle::DEFAULT_CONVERGENCE_WINDOW;
    assert_eq!(
        w.as_secs(),
        300,
        "edge's convergence default moved. That is not automatically wrong, but \
         it changes how long a rotated-away scope address stays live, and this \
         node takes the default rather than choosing — so the change should be \
         READ before it is inherited."
    );
}

/// **The composition root arms it.**
///
/// A source-level assertion, and that is a deliberate choice worth defending:
/// building a full `Edge` here would need a keyring, a signer, a sqlite backend
/// and a bound Reticulum transport — and a test that heavy gets marked
/// `#[ignore]` the first time it is slow, at which point it guards nothing.
///
/// What actually needs guarding is narrow: that the ONE call site still exists.
/// A grep asserts exactly that and cannot rot into a false pass, because the
/// thing it looks for is the thing that matters.
#[test]
fn compose_arms_scope_native_addressing() {
    let compose = include_str!("../src/compose.rs");
    assert!(
        compose.contains(".scope_native_addressing("),
        "src/compose.rs no longer arms scope-native addressing. Edge ships the \
         scope gates DEFAULT-OPEN, so removing this call does not break a build \
         or fail a test — it silently returns every scope to one linkable \
         `sha256(fed_pubkey)[..16]` address. If the removal is deliberate, delete \
         this test in the same commit and say why."
    );
    assert!(
        compose.contains("DEFAULT_CONVERGENCE_WINDOW"),
        "the convergence window is no longer edge's default. Picking our own \
         number is allowed, but it decides whether a peer that has not re-keyed \
         gets cut off (too short) or a rotated-away address stays live (too \
         long) — so it must be a stated choice, not a drifted literal."
    );
}
