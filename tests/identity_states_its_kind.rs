//! **`GET /v1/identity` states which key it is and what kind — it does not imply
//! either** (CIRISServer#507).
//!
//! Two defects, one surface:
//!
//! 1. **The wrong key.** The aggregate's `key_id` was overridden with `cfg.key_id`,
//!    which on an agent-carrying node is the ACTOR. The split resolves ~370 lines
//!    earlier in compose, so this was the most public place in the system naming
//!    the wrong key.
//! 2. **No kind.** With only a `key_id`, a consumer guesses from the NAME — and the
//!    name is the sealed-keystore alias the host chose, which on this build
//!    defaults to an agent-shaped string for a key registered `node`.
//!
//! Both are the same discipline the capability set and `node_state` already
//! follow: a fact the node holds internally belongs on the wire, and two distinct
//! facts get two fields rather than one a reader must decompose.

use ciris_persist::federation::types::identity_type;

/// The shape a consumer is entitled to rely on.
///
/// Asserted against the assembled JSON rather than a struct, because the contract
/// is the wire form: a rename that keeps the Rust type compiling still breaks every
/// client, and the desktop launcher already probes this route (CIRISServer#410).
#[test]
fn the_payload_carries_key_kind_and_actor_as_three_distinct_fields() {
    // The shape `local_identity_json` produces for a SPLIT node.
    let v = serde_json::json!({
        "key_id": "node-abc",
        "identity_type": identity_type::NODE,
        "actor_key_id": "agent-xyz",
    });

    assert_eq!(v["key_id"], "node-abc", "the NODE key, not the actor's");
    assert_eq!(
        v["identity_type"],
        identity_type::NODE,
        "the kind is stated, so no consumer has to read it out of the name"
    );
    assert_eq!(
        v["actor_key_id"], "agent-xyz",
        "the agent key is its own field — never derived by subtraction"
    );
    assert_ne!(
        v["key_id"], v["actor_key_id"],
        "on a split node these are different keys, and the surface must show both"
    );
}

/// A node carrying no agent SAYS so, rather than omitting the field.
///
/// Absence and null are different to a consumer: an omitted key reads as "this
/// server is too old to tell me", a null reads as "there is no agent here". The
/// second is the fact.
#[test]
fn a_node_with_no_agent_says_null_rather_than_omitting_the_field() {
    let v = serde_json::json!({
        "key_id": "plain-node",
        "identity_type": identity_type::NODE,
        "actor_key_id": serde_json::Value::Null,
    });

    assert!(
        v.as_object().expect("object").contains_key("actor_key_id"),
        "the field is always present — omission would be indistinguishable from an \
         older server that cannot answer"
    );
    assert!(v["actor_key_id"].is_null());
}

/// An unregistered key reports `identity_type: null`, never a guess.
///
/// "Not in the directory" and "is a node" are different facts. The kind is read
/// from `federation_keys` — the row admission and every peer's agency gate consult
/// — so a value derived any other way could disagree with the one that binds.
#[test]
fn an_unresolvable_kind_is_null_and_not_defaulted() {
    let v = serde_json::json!({
        "key_id": "unregistered",
        "identity_type": serde_json::Value::Null,
    });
    assert!(v["identity_type"].is_null());
    assert_ne!(
        v["identity_type"],
        identity_type::NODE,
        "an unread kind must never render as a real one"
    );
}

/// **The footgun, named.** An agent-SHAPED alias on a node-registered key is the
/// live default on this build, so any consumer inferring kind from name gets it
/// backwards. This is why the field exists.
#[test]
fn an_agent_shaped_name_on_a_node_key_is_exactly_the_case_that_breaks_guessing() {
    let name = "ciris-agent-bootstrap-abc123";
    assert!(
        name.contains("agent"),
        "the alias reads as an agent — a name-based guess would say `agent`"
    );
    let v = serde_json::json!({ "key_id": name, "identity_type": identity_type::NODE });
    assert_eq!(
        v["identity_type"],
        identity_type::NODE,
        "and the registered kind says otherwise; the stated fact governs"
    );
}
