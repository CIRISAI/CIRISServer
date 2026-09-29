//! **Room MLS state lives in the node's ONE store** (CIRISServer#630).
//!
//! Every room used to open its own in-memory store keyed by its room id:
//! `XChaChaKvStore::open_in_memory(room.as_bytes())`. A restart lost every
//! group and the KeyPackage material its Welcome was sealed to, and a room id
//! is public, so no such store could ever have been made durable. The rooms
//! now take `crate::mls_state::store_for(node)`. This gate keeps them there: a
//! room store keyed by the room id reappearing is the regression.

fn src(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\\r\\n", "\\n")
}

#[test]
fn no_room_opens_a_store_keyed_by_its_room_id() {
    for path in ["src/contacts_chat.rs", "src/self_room_drive.rs"] {
        let s = src(path);
        for needle in [
            "open_in_memory(room.as_bytes())",
            "open_in_memory(room_id.as_bytes())",
        ] {
            assert!(
                !s.contains(needle),
                "{path} opens a room's MLS store keyed by the room id ({needle}) — use \
                 crate::mls_state::store_for(node) so the state is the node's one durable store"
            );
        }
        assert!(
            s.contains("mls_state::store_for("),
            "{path} no longer takes the node's store from crate::mls_state"
        );
    }
}

#[test]
fn compose_opens_the_store_once_and_readdresses_at_boot() {
    let s = src("src/compose.rs");
    assert_eq!(
        s.matches("mls_state::open_for_node(").count(),
        1,
        "the node's MLS store is opened exactly once, at boot"
    );
    assert!(
        s.contains("readdress_persisted_rooms("),
        "persisted rooms must be re-addressed at boot (CIRISEdge#676 §5)"
    );
}
