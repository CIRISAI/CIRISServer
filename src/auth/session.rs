#![allow(dead_code)] // scaffold surface — wired by the next auth slices (registry-fold #2 + agent migration).

//! The login session — the one token issuer (CIRISServer#9), replacing the
//! agent's OAuth → WA → HS256-JWT chain. **Login *is* self-at-login**
//! ([`super::self_login`]); a session binds the verified occurrence for as long
//! as the human is present ("as the user" — log out and nothing acts).
//!
//! Scaffold: the session shape + the bind point. The issuer/store is the next
//! increment — it composes the substrate (the session is a short-lived binding
//! over an already-admitted `identity_occurrence`, not a new credential type),
//! so it carries no new primitive.

use super::roles::Role;

/// A bound login session — issued on a successful self-at-login.
#[derive(Debug, Clone)]
pub struct Session {
    /// The signed-in occurrence key (`device_class: phone | laptop`).
    pub occurrence_key_id: String,
    /// The identity this occurrence belongs to.
    pub identity_key_id: String,
    /// The roles the identity holds (the CEG role-set).
    pub roles: Vec<Role>,
}

// TODO(CIRISServer#9): issue/verify a session token (the fabric is the single
// token issuer), keyed off the self-at-login outcome; expire on logout. The
// token attests "this occurrence is present" — accountability is "as the user"
// (direct), distinct from the agent's standing `delegates_to(act_on_behalf)`.
