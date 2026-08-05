//! **This node's own signing identity — resolved, never accepted.**
//! (CIRISServer#372 Level 2, off the 2026-08-05 ingest-rejection RCA.)
//!
//! # The defect this module removes
//!
//! `main.rs` takes `--key-id <name>`, an operator-supplied **label**, and
//! threads it through [`crate::run`] into the surfaces. `Engine::local_derived_key_id()`
//! is what the engine **actually signs with**. Those are two different facts
//! wearing one name — the house "one name, two axes" class — and
//! [`crate::scorer`] already says so in as many words:
//!
//! > ONE identity (#312/#315): the producer named INSIDE the capacity envelope
//! > must be the same identity `emit_attestation_self` stamps as the attester —
//! > the ENGINE signer's derived key, never a config alias **(in the embedded
//! > fold they differ**, and an alias here would make the envelope's producer
//! > disagree with the row's own attester).
//!
//! The scorer's cure was to shadow its `node_key_id` parameter with the derived
//! value on the first line of the task. That works, but it leaves the parameter
//! standing — and a parameter that exists is a parameter a caller can disagree
//! with. A harness restated `["trace:","capacity:"]` for eight releases while
//! production shipped `["capacity:"]` and moved zero traces; the cure there was
//! removing the caller's opportunity to disagree, not documenting the correct
//! value.
//!
//! **So: the surfaces do not take a key id. They ask the engine.** You cannot
//! pass the wrong id when there is no argument for it.
//!
//! # What is NOT in scope
//!
//! A `key_id` naming a **subject being read about** — `read_age_level(subject_key_id)`,
//! `family::lookup(family_key_id)`, `peer_not_found(key_id)` — is a legitimate
//! parameter. The subject is not the signer. This module is only about the
//! identity a surface acts and signs AS.
//!
//! # Failure is loud
//!
//! [`resolve`] is fallible and has **no fallback**. A surface that cannot
//! resolve its own identity refuses; it does not quietly reach for the CLI
//! label, because a silent fallback recreates the original bug with extra
//! steps. This is the same shape [`crate::scorer::spawn`] uses (log and refuse
//! to run) and the same shape
//! [`crate::mesh_config_surface`]'s baseline read uses (a failed read is fatal
//! to the surface, never a permissive default).
//!
//! # Distinct zero
//!
//! "This node cannot resolve its own identity" is a DIFFERENT condition from
//! "the plane is empty" and from "the store could not be read", and it renders
//! differently: [`REFUSAL_TOKEN`] / [`MESSAGE_ID`] are its own, so an operator
//! reading a surface can tell a node that has nothing to say from a node that
//! does not know who it is.

use ciris_persist::prelude::Engine;

/// The refusal token every surface renders when [`resolve`] fails. Distinct
/// from `store_unavailable` (the substrate could not be read) and from any
/// emptiness token — a node that does not know who it is is its own condition.
pub const REFUSAL_TOKEN: &str = "self_identity_unresolved";

/// The localizable message id paired with [`REFUSAL_TOKEN`].
pub const MESSAGE_ID: &str = "server.self_identity.unresolved";

/// The English source text for [`MESSAGE_ID`]. Carried here so every surface
/// renders the SAME sentence for the same condition — a restated sentence is a
/// second place the two can diverge.
pub const MESSAGE_TEXT: &str =
    "This node cannot resolve the identity its own signer uses, so it will not act or sign \
     under a guessed one. This is a node-configuration fault, not a fault of the request.";

/// This node's signing identity could not be resolved from the engine.
///
/// Deliberately carries no "the label was `X`" fallback: there is nothing to
/// fall back TO. The cause string is the engine's own, unedited.
#[derive(Debug, Clone)]
pub struct Unresolved {
    /// The surface that asked (so the log line names the caller, not just the
    /// substrate).
    pub surface: &'static str,
    /// The engine's own error text.
    pub cause: String,
}

impl std::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: cannot resolve this node's own signing identity: {}",
            self.surface, self.cause
        )
    }
}

impl std::error::Error for Unresolved {}

/// Resolve THIS node's signing identity — the id the engine's own signer
/// actually produces (`derive_key_id(<keystore alias>, <ed25519 pubkey>)`),
/// **never** a CLI label, config alias or caller-supplied string.
///
/// `surface` names the caller so a failure is attributable in one log line.
///
/// # Errors
///
/// [`Unresolved`] when the engine cannot answer — a non-Ed25519 signer, an
/// unreadable hardware key, no local signer at all. There is no fallback: see
/// the module docs.
pub async fn resolve(engine: &Engine, surface: &'static str) -> Result<String, Unresolved> {
    match engine.local_derived_key_id().await {
        Ok(id) => Ok(id),
        Err(e) => {
            let unresolved = Unresolved {
                surface,
                cause: e.to_string(),
            };
            // AUDIBLE, always. The 2026-08-05 outage was 71 hours of correct
            // refusals nobody read; an identity that cannot be resolved must
            // never be a silent condition.
            tracing::error!(
                surface = surface,
                error = %unresolved.cause,
                "cannot resolve this node's own signing identity — refusing to act under a \
                 guessed one (CIRISServer#372: the identity is DERIVED from the signer in use, \
                 never a CLI label)"
            );
            Err(unresolved)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unresolved_zero_is_its_own_token() {
        // Distinct zeroes: this is not `store_unavailable`, and it is not an
        // emptiness token. If these ever collide, an operator cannot tell a
        // node with nothing to say from a node that does not know who it is.
        assert_ne!(REFUSAL_TOKEN, "store_unavailable");
        assert_ne!(REFUSAL_TOKEN, "node_unowned");
        assert!(MESSAGE_ID.starts_with("server."));
    }

    #[test]
    fn display_names_the_surface_that_asked() {
        let u = Unresolved {
            surface: "mesh_config_surface",
            cause: "no local signer".into(),
        };
        let s = u.to_string();
        assert!(s.contains("mesh_config_surface"), "{s}");
        assert!(s.contains("no local signer"), "{s}");
    }
}
