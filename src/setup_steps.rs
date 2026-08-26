//! # What this node still needs from an operator — computed ONCE
//!
//! Two wizards ask the same question. The **first-run** wizard asks it of a node
//! that has never been claimed; the **catch-up** wizard asks it of a node that
//! was complete under an older rule and is not under the current one. They are
//! the same question at different times, and before this they had different
//! answers because there was only ever one bit to answer with.
//!
//! `GET /v1/setup/status` reported `setup_required == is_first_run`, and the
//! comment beside it said so plainly: *"ciris-server's only setup-needed state is
//! 'no ROOT yet'"*. That was true when claiming a root was the only thing an
//! operator could owe. CC 3.4.7.3 adds a second thing — a node running on an
//! actor's key owes a split — and a boolean has nowhere to put it.
//!
//! So the model is a LIST, computed in one place, and the booleans are derived
//! from it rather than computed beside it. A new obligation is one variant plus
//! one detector; it reaches both wizards without either one learning about it.
//!
//! ## Why derived, not parallel
//!
//! `is_first_run` keeps its meaning and its seven callers — it is a real
//! predicate about a real condition. What changes is that `setup_required` stops
//! being an alias for it. A claimed node that owes a key split is emphatically
//! not "first run", and reporting `setup_required: false` for it would tell the
//! wizard there is nothing to do while the node runs on an identity the
//! constitution forbids.

use crate::node_key::IdentityVerdict;
use serde::Serialize;

/// One outstanding obligation. Machine tokens — the client renders its own
/// localized prose from `code`, never from a message the server composes
/// (the `Warning.code` discipline: consumers key on the token, never on prose).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupStep {
    /// No ROOT has claimed this node. The original — and until now, only — step.
    ClaimRoot,
    /// The node is operating on a key that carries `agent` or `user`. CC 3.4.7.3
    /// Clause A: `node` is non-cohabitable with an actor role, so this node needs
    /// an identity of its own before it is conformant.
    SplitNodeKey,
    /// A node key exists, but the owner-binding still names the ACTOR key — so
    /// `owner_of(node)` does not resolve and CC 3.4.7.3 Clause D cannot be
    /// answered for anything running here. Fail-closed means this is not a
    /// cosmetic leftover: an unowned node refuses rather than answers.
    MoveOwnerBinding,
}

impl SetupStep {
    /// The stable token. Named `code` to match the degradation `Warning`
    /// contract, which the client already keys on.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::ClaimRoot => "setup.claim_root",
            Self::SplitNodeKey => "setup.split_node_key",
            Self::MoveOwnerBinding => "setup.move_owner_binding",
        }
    }

    /// Does this step block the node from being constitutionally conformant, as
    /// opposed to merely unconfigured?
    ///
    /// `ClaimRoot` is unconfigured — a fresh node legitimately sits there. The
    /// other two are a node running in a shape CC forbids, which is a different
    /// urgency and the wizard should be able to say so without parsing prose.
    #[must_use]
    pub fn is_conformance(self) -> bool {
        matches!(self, Self::SplitNodeKey | Self::MoveOwnerBinding)
    }
}

/// Everything the operator still owes, in the order a wizard should present it.
///
/// Order is deliberate and not alphabetical: claiming a root is the prerequisite
/// for an owner-binding existing at all, so a wizard that walked these in a
/// different order would ask for a move before there was an owner to move.
#[must_use]
pub fn outstanding(
    is_first_run: bool,
    node_verdict: &IdentityVerdict,
    owner_binding_on_actor: bool,
) -> Vec<SetupStep> {
    let mut steps = Vec::new();
    if is_first_run {
        steps.push(SetupStep::ClaimRoot);
    }
    if !node_verdict.usable_as_node() && !matches!(node_verdict, IdentityVerdict::Unregistered) {
        steps.push(SetupStep::SplitNodeKey);
    }
    if owner_binding_on_actor {
        steps.push(SetupStep::MoveOwnerBinding);
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> IdentityVerdict {
        IdentityVerdict::Actor {
            roles: vec!["agent".into()],
        }
    }

    #[test]
    fn a_fresh_node_owes_only_a_root() {
        assert_eq!(
            outstanding(true, &IdentityVerdict::SubstrateOnly, false),
            vec![SetupStep::ClaimRoot]
        );
    }

    /// The case the boolean could not express: claimed, so NOT first-run, and
    /// still owing work. Under the old model this node reported
    /// `setup_required: false` while running on an actor key.
    #[test]
    fn a_claimed_node_on_an_actor_key_still_owes_a_split() {
        let steps = outstanding(false, &actor(), false);
        assert_eq!(steps, vec![SetupStep::SplitNodeKey]);
        assert!(
            !steps.is_empty(),
            "this is the whole reason the model is a list: `is_first_run` is false \
             here and there is still work owed"
        );
    }

    /// A fused key is a split too — it is not usable as the node identity even
    /// though it does carry `node`.
    #[test]
    fn a_fused_key_owes_a_split_as_much_as_a_pure_actor_does() {
        let fused = IdentityVerdict::Fused {
            roles: vec!["node".into(), "agent".into()],
        };
        assert_eq!(
            outstanding(false, &fused, false),
            vec![SetupStep::SplitNodeKey]
        );
    }

    /// An unregistered key is NOT a split obligation — it is the ordinary
    /// first-boot path, where the node registers itself. Filing it as a split
    /// would put every fresh node into the catch-up wizard.
    #[test]
    fn an_unregistered_key_is_not_an_outstanding_split() {
        assert!(!outstanding(false, &IdentityVerdict::Unregistered, false)
            .contains(&SetupStep::SplitNodeKey));
    }

    /// Prerequisite order: the root comes before the binding that depends on it.
    #[test]
    fn the_root_is_asked_for_before_the_binding_that_needs_it() {
        let steps = outstanding(true, &actor(), true);
        assert_eq!(
            steps,
            vec![
                SetupStep::ClaimRoot,
                SetupStep::SplitNodeKey,
                SetupStep::MoveOwnerBinding
            ]
        );
        let root = steps.iter().position(|s| *s == SetupStep::ClaimRoot);
        let mv = steps.iter().position(|s| *s == SetupStep::MoveOwnerBinding);
        assert!(
            root < mv,
            "a wizard must not ask to move a binding that cannot exist yet"
        );
    }

    #[test]
    fn a_complete_node_owes_nothing() {
        assert!(outstanding(false, &IdentityVerdict::SubstrateOnly, false).is_empty());
    }

    /// Unconfigured and non-conformant are different urgencies, and the wizard
    /// must be able to tell them apart without reading prose.
    #[test]
    fn conformance_steps_are_distinguishable_from_mere_configuration() {
        assert!(!SetupStep::ClaimRoot.is_conformance());
        assert!(SetupStep::SplitNodeKey.is_conformance());
        assert!(SetupStep::MoveOwnerBinding.is_conformance());
    }

    /// Codes are the wire contract the client keys on — pin them.
    #[test]
    fn the_codes_are_stable_tokens() {
        assert_eq!(SetupStep::ClaimRoot.code(), "setup.claim_root");
        assert_eq!(SetupStep::SplitNodeKey.code(), "setup.split_node_key");
        assert_eq!(
            SetupStep::MoveOwnerBinding.code(),
            "setup.move_owner_binding"
        );
    }
}
