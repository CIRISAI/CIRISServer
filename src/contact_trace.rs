//! **One line per contact transition, naming the side that is missing what**
//! (steward ruling 2026-10-30: phone↔desktop chat across NAT is the test
//! harness, and a failure must say which side lacks which row).
//!
//! The phone↔desktop run accepted a contact and then sat at `mutual=false` for
//! 180 s with nothing on either node saying why: the accept wrote its grants,
//! the reconcilers reported "converged", and the only trace was a stream of
//! edge `withheld` lines about other parties' rows. Each line here is a
//! snapshot of the facts a mutual contact and a chat room are made of, read
//! from this node's own directory:
//!
//! - `CONTACT` — at add/accept, at the first sight of a request, at the first
//!   sight of mutual: the grant as STORED (attester, `for_key_id`, subject),
//!   the peer's nodes, and whether each is in this node's consent send set.
//! - `OWNER-BINDING` — at boot and after announce: for each key this node is
//!   known by, whom `owner_of` resolves to and whether that binding is
//!   announced, or why nothing resolved.
//! - `CHAT READINESS` — when a pair room is asked for: both owners resolved,
//!   each peer node in our send set, their grant to us held, the path.
//!
//! Diagnostic only: every read is best-effort and a failed read is printed as
//! the error, never as a verdict.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use ciris_persist::prelude::Engine;

/// The keys whose consent the send set reads — the same union
/// `compose::start_replication_runtime` hands edge: the wire (node) key and,
/// on a split home, the engine (agent) key.
async fn consent_keys(engine: &Engine) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(w) = crate::node_key::wire_identity() {
        keys.push(w.to_owned());
    }
    if let Ok(k) = engine.local_derived_key_id().await {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    keys
}

/// This node's consent send set — the union of `consent_peers_by_principals`
/// over [`consent_keys`] — and the keys it was read for.
pub async fn send_set(engine: &Engine) -> (Vec<String>, Result<Vec<String>, String>) {
    let keys = consent_keys(engine).await;
    let mut peers: Vec<String> = Vec::new();
    for k in &keys {
        // persist's by-principals fold, the read edge's send set makes.
        match engine.consent_peers_by_principals(k).await {
            Ok(p) => {
                for x in p {
                    if !peers.contains(&x) {
                        peers.push(x);
                    }
                }
            }
            Err(e) => return (keys, Err(e.to_string())),
        }
    }
    (keys, Ok(peers))
}

/// The grant as stored: `(attester, for_key_id, subjects)`.
async fn grant_facts(engine: &Engine, grant_id: &str) -> String {
    match engine
        .federation_directory()
        .get_attestation(grant_id)
        .await
    {
        Ok(Some(g)) => {
            let for_key = g
                .attestation_envelope
                .pointer("/payload/for_key_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            format!(
                "grant={grant_id} attester={} for_key_id={for_key} subject={:?} scope={}",
                g.attesting_key_id, g.subject_key_ids, g.cohort_scope
            )
        }
        Ok(None) => format!("grant={grant_id} NOT HELD"),
        Err(e) => format!("grant={grant_id} unreadable: {e}"),
    }
}

/// Whether each of `nodes` is in this node's send set, as `node=in|out: why`.
async fn membership(engine: &Engine, nodes: &[String]) -> String {
    let (keys, set) = send_set(engine).await;
    match set {
        Err(e) => format!("send_set(read for {keys:?}) unreadable: {e}"),
        Ok(set) => {
            let each: Vec<String> = nodes
                .iter()
                .map(|n| {
                    if set.contains(n) {
                        format!("{n}=in")
                    } else {
                        format!(
                            "{n}=out: no live consent:replication grant names it with for_key_id \
                             in {keys:?}"
                        )
                    }
                })
                .collect();
            if each.is_empty() {
                format!("send_set(read for {keys:?}): the peer has NO bound node here — nothing to send to")
            } else {
                format!("send_set(read for {keys:?}): [{}]", each.join(", "))
            }
        }
    }
}

/// **`CONTACT <transition>`** — one line naming the peer person, their nodes,
/// the grant as stored, mutual, and send-set membership of each node.
pub async fn contact(
    engine: &Engine,
    transition: &str,
    owner_key_id: &str,
    peer_person: &str,
    grant_id: Option<&str>,
    mutual: Option<bool>,
) {
    let nodes = crate::peer::bound_nodes_of(engine, peer_person)
        .await
        .unwrap_or_default();
    let grant = match grant_id {
        Some(g) => grant_facts(engine, g).await,
        None => "grant=-".to_owned(),
    };
    let members = membership(engine, &nodes).await;
    tracing::info!(
        target: "ciris_server::contact_trace",
        "CONTACT {transition} owner={owner_key_id} peer_person={peer_person} peer_nodes={nodes:?} \
         {grant} mutual={} -> {members}",
        mutual.map_or("-".to_owned(), |m| m.to_string()),
    );
}

/// Log `CONTACT <transition>` for `(transition, key)` once per process — for
/// states a poll re-reads (a request in the list, a contact reading mutual).
pub async fn contact_once(
    engine: &Engine,
    transition: &'static str,
    owner_key_id: &str,
    peer_person: &str,
    grant_id: Option<&str>,
    mutual: Option<bool>,
) {
    static SEEN: OnceLock<Mutex<HashSet<(String, String)>>> = OnceLock::new();
    let key = (
        transition.to_owned(),
        grant_id.unwrap_or(peer_person).to_owned(),
    );
    let fresh = SEEN
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map(|mut s| s.insert(key))
        .unwrap_or(false);
    if fresh {
        contact(
            engine,
            transition,
            owner_key_id,
            peer_person,
            grant_id,
            mutual,
        )
        .await;
    }
}

/// **`OWNER-BINDING`** — for each key this node is known by, whom `owner_of`
/// resolves to and whether that binding is announced; or why not.
pub async fn owner_binding(engine: &Engine, when: &str) {
    let dir = engine.federation_directory();
    let mut lines = Vec::new();
    for k in consent_keys(engine).await {
        let line = match ciris_persist::federation::admission::owner_of(dir.as_ref(), &k).await {
            Ok(Some(owner)) => {
                match crate::auth::ownership::owner_binding_is_announced(engine, &k, &owner).await {
                    Ok(true) => format!("{k} -> owner {owner} (announced: federation)"),
                    Ok(false) => format!(
                        "{k} -> owner {owner} (NOT announced: self only — peers cannot place this \
                         node; POST /v1/federation/announce)"
                    ),
                    Err(e) => format!("{k} -> owner {owner} (announce state unreadable: {e})"),
                }
            }
            Ok(None) => format!(
                "{k} -> UNRESOLVED: no live owner-binding names this key here (a split home binds \
                 the NODE key; the agent key resolves through it only once the owner's binding \
                 to the node is held)"
            ),
            Err(e) => format!("{k} -> unreadable: {e}"),
        };
        lines.push(line);
    }
    tracing::info!(
        target: "ciris_server::contact_trace",
        "OWNER-BINDING ({when}): {}",
        lines.join("; ")
    );
}

/// **`CHAT READINESS`** — when a pair room is asked for: our owner resolved,
/// the peer's nodes and their owners, each peer node in our send set, the
/// peer's grant to us held, and `path` (edge's standing hint, or `-`).
pub async fn chat_readiness(
    engine: &Engine,
    owner_key_id: &str,
    peer_person: &str,
    inbound_grant_held: bool,
    path: Option<&str>,
) {
    let dir = engine.federation_directory();
    let nodes = crate::peer::bound_nodes_of(engine, peer_person)
        .await
        .unwrap_or_default();
    let mut owners = Vec::new();
    for n in &nodes {
        let o = ciris_persist::federation::admission::owner_of(dir.as_ref(), n)
            .await
            .map(|o| o.unwrap_or_else(|| "UNRESOLVED".to_owned()))
            .unwrap_or_else(|e| format!("unreadable: {e}"));
        owners.push(format!("{n}->{o}"));
    }
    let members = membership(engine, &nodes).await;
    tracing::info!(
        target: "ciris_server::contact_trace",
        "CHAT READINESS owner={owner_key_id} peer_person={peer_person} peer_node_owners=[{}] \
         their_grant_to_us={} {members} path={}",
        owners.join(", "),
        if inbound_grant_held { "held" } else { "NOT HELD (they have not added us, or it has not arrived)" },
        path.unwrap_or("-"),
    );
    owner_binding(engine, "chat readiness").await;
}
