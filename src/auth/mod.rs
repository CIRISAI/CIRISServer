//! The fabric auth subsystem — **CIRISServer as the single auth authority**
//! (CIRISServer#9).
//!
//! Consolidates what lived in the agent (WiseAuthority certs, OAuth→WA→JWT, the
//! agent's own user store + role taxonomy) onto the CEG substrate: one
//! federation identity, one hybrid request contract, one role model, self-at-
//! login as the login ceremony, and the owner-binding gate. "Infra must not have
//! agency / the human acts through the node" ⇒ the auth **authority** is the
//! fabric; the agent becomes a consumer/delegate (that migration is a later
//! slice). Bolting auth onto the agent while the fabric also signs would create
//! the two-authority conflict #9 exists to remove.
//!
//! ## This (core-first) pass
//! - [`verify`] — the one `x-ciris-*` hybrid request verifier (user-direct **or**
//!   agent-delegate — the §9 "as the user" / "on behalf of" split).
//! - [`self_login`] — the self-at-login ceremony (§8.1.12.7): co-admit the
//!   user's app + agent occurrences; the prerequisite for user-signed
//!   consent/erasure.
//! - [`roles`] — the CEG role-set `{user,node,agent,steward,witness,accord_holder}`
//!   + the infra/agency reserved-scope split.
//! - [`gate`] — the owner-binding gate (user-before-non-canonical-groups).
//! - [`session`] — the login session issuer (scaffold).
//!
//! ## Next slices (NOT this pass)
//! - Fold the registry user/org store onto CEG communities (rides the registry
//!   fold, CIRISServer#2).
//! - Migrate the agent to consumer/delegate (drop its WA / JWT / own identity;
//!   it acts under `delegates_to(user → agent)` — cross-repo).

pub mod api_keys;
pub mod attestation;
pub mod consent;
pub mod device_auth;
pub mod erasure;
pub mod gate;
pub mod oauth;
pub mod roles;
pub mod self_login;
pub mod session;
pub mod store;
pub mod verify;
