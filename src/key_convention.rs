//! # The keys a CIRIS node holds — the single source of truth
//!
//! Every CIRIS node holds **two or three** keys. Not "some keys", not "an
//! identity". Two, or three, with fixed roles and fixed names:
//!
//! | role      | present          | identity_type | alias                               |
//! |-----------|------------------|---------------|-------------------------------------|
//! | **node**  | ALWAYS           | `node`        | [`NODE_ALIAS`] — one fixed literal  |
//! | **fed**   | once CLAIMED     | `user`        | owner-chosen (e.g. `eric-moore-v1`) |
//! | **agent** | ONLY if an agent | `agent`       | host-supplied, never reconstructed  |
//!
//! - The **node** key is the fabric identity: the RNS transport identity, the
//!   announce, the destination a peer dials, and **the only one of the three that
//!   is advertised**. Bootstrapped on first run; present on every node, headless
//!   relay and full agent alike.
//! - The **fed** key is the CLAIM identity — the owner's own federation identity,
//!   the one that claims this node. It is owner-chosen and commonly lives *off
//!   this box* (the owner's phone or laptop), so a node holds a claim BY it,
//!   which is not the same as holding it. An UNCLAIMED node has none at all, and
//!   that is a supported state, not a defect — see [`KeyRole::always_present`].
//! - The **agent** key is minted only when an agent is installed — at first run
//!   or later as an upgrade. A relay-only node never has one, and that absence is
//!   a fact about the deployment, never a defect. Its alias is **host-supplied**
//!   and this module deliberately publishes no literal for it (I2).
//!
//! # Which key is advertised, and how an owner is reached
//!
//! **The node id is what we advertise. The fed id is not addressable.** This is
//! structural, not a convention we could reverse:
//!
//! - The address a peer dials is `local_named_dest_hash()`, computed over the
//!   node's TRANSPORT keypair — `sha256(name_hash("ciris","edge") ‖
//!   identity_hash)[..16]`. It is derived from no federation key.
//! - The signed transport binding is published under the WIRE identity, the node
//!   key (`compose::publish_self_transport_destination`). A binding that named the
//!   actor would hand a peer a route whose key is not the one it is talking to;
//!   CIRISEdge#393 item 2 then refuses it and the route never roots.
//! - A destination derived from a federation pubkey —
//!   `reticulum_destination_for_pubkey(fed_ed25519)` = `sha256(fed)[..16]` — is an
//!   EXPLICIT-HASH dest, and explicit-hash dests categorically cannot be
//!   announced. No peer can ever self-learn a route to one.
//!
//! That last point is not theory. CIRISServer#335: the canonical was primed at
//! `1fc232535a…` while it served federation traffic on `81cabcf78a…`. Every node
//! reported `knows_peer=true, provenance=Rooted, primed=1, refused=0` — and zero
//! traces reached the canonical from anyone. The false rooting also *blocked*
//! recovery, because a node that believes it knows a peer never learns its real
//! address. What made it survive review: transport and federation share the
//! Ed25519 half, but sharing a key does NOT make its base hash and its named hash
//! the same address.
//!
//! So an owner is reached the other way round — **look up the owner, walk to the
//! nodes they advertise, dial the node**:
//!
//! ```text
//!   fed key (owner)  --delegates_to, purpose=owner_binding-->  node key
//!                                                                  |
//!                                            named dest over the transport keypair
//! ```
//!
//! [`crate::auth::ownership::nodes_stewarded_by`] is that walk; `memory_api`
//! projects its result as the "owned nodes" view. (Verified here as a LOCAL
//! resolution. Whether a remote peer can perform the same walk depends on those
//! owner-binding rows having replicated to it, which is not asserted here.)
//!
//! # The invariants
//!
//! ## I1 — The alias is part of the identity
//!
//! `fedcode::derive_key_id(alias, ed_pub)` takes the alias as an INPUT. The name
//! is not a lookup convenience each component may choose for itself: the same key
//! material under two aliases is two `key_id`s, which is two identities. Renaming
//! a key re-identifies it.
//!
//! ## I2 — Exactly one component names a key: the one that mints it
//!
//! I1's direct consequence. A component needing a key BY NAME must be handed the
//! name, never re-derive it. Re-derivation is the defect in CIRISServer#511:
//! server minted `ciris-node-bootstrap-<fp>` while edge, handed the agent's
//! alias, independently derived `ciris-agent-bootstrap-node`. Both rules were
//! internally correct; the halves addressed different identities. Edge cannot
//! import this module — CIRISServer rides edge, and a dependency that way inverts
//! the substrate relationship — so the name must travel as a PARAMETER.
//!
//! A mirrored copy is not single-sourcing. Edge held one, pinned by a test called
//! `node_alias_matches_the_server_rule` that asserted edge's copy against a
//! hardcoded literal rather than against this crate. When the rule changed in
//! 0.5.195 the mirror forked and that test still passed.
//!
//! ## I3 — `node` is non-cohabitable with `agent`/`user`
//!
//! CC 3.4.7.3 Clause A. persist's agency gate constrains a recipient resolving to
//! a node-only identity; fusing the roles onto one key does not widen the node,
//! it stops the gate firing at all. This is why an agent node holds a node key
//! AND an agent key, never one dual-purpose key.
//!
//! ## I4 — The node key always exists; the agent key may not
//!
//! "No agent key" is a legitimate terminal state (a relay node); "no node key"
//! never is. Code reporting on the agent key must distinguish *absent* from
//! *empty* — `null` is not `[]`.
//!
//! ## I5 — A question about a key is asked about THAT key
//!
//! Capability, role, and conferral questions name a subject. When the named
//! subject cannot be resolved the answer is *unknown*; it is never silently
//! re-asked about a different key. Falling back from the node key to whatever the
//! engine happens to derive answers a question nobody asked, in a form
//! indistinguishable from an answer to the real one.

/// The keystore alias of the node's own key. **One fixed literal, every node.**
///
/// Not derived from the host, the deployment, or the caller's alias. A node is a
/// node: `ciris-node`, bootstrapped. Deployment identity comes from the
/// fingerprint the federation appends (`ciris-node-bootstrap-peulxofzaj`), not
/// from the alias — so two nodes never collide despite sharing this literal, each
/// having its own keystore and its own key material.
pub const NODE_ALIAS: &str = "ciris-node-bootstrap";

/// The three key roles, and what each one is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// The fabric identity: transport, announce, the dialed destination.
    Node,
    /// The owner's claim identity. Often held off this box.
    Fed,
    /// The brain's authorship identity. Only on an agent node.
    Agent,
}

impl KeyRole {
    /// The `identity_type` this role's key carries in the federation directory.
    #[must_use]
    pub const fn identity_type(self) -> &'static str {
        use ciris_persist::federation::types::identity_type;
        match self {
            Self::Node => identity_type::NODE,
            Self::Fed => identity_type::USER,
            Self::Agent => identity_type::AGENT,
        }
    }

    /// Does every node hold a key in this role?
    ///
    /// **Only the node key.** An earlier draft said `Fed` too, on the reasoning
    /// that "every node is claimed" — but an UNCLAIMED node is a state this
    /// repository explicitly supports and builds for: `owner_of` returns `None`
    /// until the setup claim completes, and a brain-carrying node with no owner
    /// is meant to hold at "waiting for claim" rather than proceed. A caller
    /// enumerating required keys from this would have invented a fed identity
    /// for a node that correctly has none.
    ///
    /// So the fed relationship is OPTIONAL here, and that is distinct again from
    /// off-box key custody: "no owner yet" and "the owner's key lives on their
    /// phone" are different facts, and neither is "this node holds a fed key".
    #[must_use]
    pub const fn always_present(self) -> bool {
        matches!(self, Self::Node)
    }

    /// Is this the role we ADVERTISE — the one carrying a dialable route?
    ///
    /// Only the node key. See the module note: a fed-derived destination is an
    /// explicit-hash dest and cannot be announced at all.
    #[must_use]
    pub const fn is_advertised(self) -> bool {
        matches!(self, Self::Node)
    }

    /// The fixed keystore alias, where one exists.
    ///
    /// `Fed` returns `None`: the owner chooses their own federation name, and
    /// there is no literal for us to assert.
    #[must_use]
    pub const fn fixed_alias(self) -> Option<&'static str> {
        match self {
            Self::Node => Some(NODE_ALIAS),
            // NOT `ciris-agent-bootstrap`. That is a conventional default, not
            // a rule: the actor key's alias is host-supplied
            // (`ServerConfig::keystore_alias` / `--key-id`) and legitimately
            // differs. Returning a literal here would have a caller mint or
            // look up a DIFFERENT federation identity — I2's exact failure, in
            // the module that states I2.
            Self::Agent | Self::Fed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::types::identity_type;

    /// **I1/I2.** The node alias is a fixed literal, not a function of anything.
    ///
    /// Unlike edge's mirror test this pins no *rule* that another crate separately
    /// implements — it pins the one literal that travels to those crates as a
    /// value. A second implementation of a rule can fork; a passed value cannot.
    #[test]
    fn node_alias_is_a_fixed_literal() {
        assert_eq!(NODE_ALIAS, "ciris-node-bootstrap");
        assert_eq!(KeyRole::Node.fixed_alias(), Some(NODE_ALIAS));
    }

    /// **I3.** Three roles, three distinct `identity_type`s. If any two collapsed,
    /// cohabitation would stop being detectable.
    #[test]
    fn the_three_roles_are_three_distinct_identity_types() {
        let t = [
            KeyRole::Node.identity_type(),
            KeyRole::Fed.identity_type(),
            KeyRole::Agent.identity_type(),
        ];
        let mut sorted = t.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            3,
            "roles must not share an identity_type: {t:?}"
        );
        assert_eq!(KeyRole::Node.identity_type(), identity_type::NODE);
    }

    /// **I4.** Node always, agent only sometimes — the asymmetry is the point.
    #[test]
    fn only_the_node_key_is_mandatory() {
        assert!(KeyRole::Node.always_present());
        assert!(!KeyRole::Agent.always_present());
        assert!(
            !KeyRole::Fed.always_present(),
            "an unclaimed node has no fed identity — `owner_of` returns None until \
             the setup claim completes, and that is a supported state"
        );
    }

    /// **I2.** Only the node alias is fixed. The actor key's alias is
    /// host-supplied, so publishing a literal for it would invite exactly the
    /// re-derivation this module exists to forbid.
    #[test]
    fn only_the_node_role_publishes_a_fixed_alias() {
        assert_eq!(KeyRole::Node.fixed_alias(), Some(NODE_ALIAS));
        assert_eq!(KeyRole::Agent.fixed_alias(), None);
        assert_eq!(KeyRole::Fed.fixed_alias(), None);
    }

    /// **The advertised role is the node, and ONLY the node.**
    ///
    /// CIRISServer#335 is what the `Fed` arm costs when it is wrong: a fed-derived
    /// dest is an explicit-hash address that can never be announced, and priming
    /// it reported every green signal while no trace reached the canonical at all.
    #[test]
    fn only_the_node_key_is_advertised() {
        assert!(KeyRole::Node.is_advertised());
        assert!(
            !KeyRole::Fed.is_advertised(),
            "a fed-derived destination is an explicit-hash dest — unannounceable \
             (CIRISServer#335); owners are reached by walking owner_binding to a node"
        );
        assert!(!KeyRole::Agent.is_advertised());
    }

    /// **I2, enforced instead of promised.** The node alias literal appears
    /// ONCE in the tree.
    ///
    /// This module shipped its first revision asserting that a second
    /// implementation of a rule is the defect — while itself introducing a
    /// second `"ciris-node-bootstrap"` literal beside the one in `node_key`,
    /// referenced by nothing but its own tests. Both could have drifted, and
    /// every test would have passed: precisely the failure the module describes,
    /// committed in the module describing it.
    ///
    /// A doc paragraph saying "do not duplicate this" is not a mechanism. This
    /// is the mechanism. It scrapes rather than trusting a re-export to stay put,
    /// because a future edit that reintroduces the literal would not otherwise
    /// fail anything.
    #[test]
    fn the_node_alias_literal_exists_exactly_once_in_the_tree() {
        fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let path = e.path();
                if path.is_dir() {
                    scan(&path, hits);
                } else if path.extension().is_some_and(|x| x == "rs") {
                    let Ok(text) = std::fs::read_to_string(&path) else {
                        continue;
                    };
                    for (n, line) in text.lines().enumerate() {
                        // The LITERAL, not a mention of it in prose.
                        if line.contains(&format!("\"{NODE_ALIAS}\""))
                            && !line.trim_start().starts_with("//")
                        {
                            hits.push(format!("{}:{}", path.display(), n + 1));
                        }
                    }
                }
            }
        }
        let mut hits = Vec::new();
        scan(std::path::Path::new("src"), &mut hits);
        // This file defines it and asserts it; every other site must import.
        let foreign: Vec<&String> = hits
            .iter()
            .filter(|h| !h.starts_with("src/key_convention.rs"))
            .collect();
        assert!(
            foreign.is_empty(),
            "the node alias literal must exist ONCE — `key_convention::NODE_ALIAS`. \
             A second spelling can drift from the first without any test failing \
             (CIRISEdge#548). Import it instead. Found: {foreign:?}"
        );
    }

    /// **I3.** The node alias says `node` and nothing else. An alias carrying
    /// `agent` or `user` would put a cohabitation claim in the name of the very
    /// key that must not cohabit.
    #[test]
    fn the_node_alias_names_node_and_no_other_role() {
        let segments: Vec<&str> = NODE_ALIAS.split('-').collect();
        assert!(segments.contains(&identity_type::NODE));
        for foreign in [identity_type::AGENT, identity_type::USER] {
            assert!(
                !segments.contains(&foreign),
                "NODE_ALIAS must not carry `{foreign}`: {NODE_ALIAS}"
            );
        }
    }
}
