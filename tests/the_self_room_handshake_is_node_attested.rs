//! **A self room's handshake rows are attested by the NODE, because that is the
//! key every reader looks them up by** (CIRISServer#622).
//!
//! # The two axes
//!
//! Edge's chat helpers resolve a room's rows through
//! `chat::rows_in_room(dir, participants, room)` → `list_attestations_by(who)`
//! — "rows THAT KEY attested". They were written for a chat room, where a
//! participant IS a person and their rows carry their own key, so the two
//! questions *who is a participant* and *who attested this row* have one answer.
//!
//! A SELF room breaks that. Its participants are **nodes** (FSD
//! `CONTENT_TRANSFER.md` §5.3 R5: "the room installed in the scope table —
//! nodes, not persons") while the person is a single owner. Sign the handshake
//! with the owner's pen and every lookup keyed by node returns `None`.
//!
//! # What that cost, measured
//!
//! On the self-files ladder the creator HELD the joiner's KeyPackage — the row
//! had crossed, both nodes had it in `federation_attestations` — and
//! `key_package_from(dir, <joiner node>, room)` could not see it, because the
//! row's attester was the owner. So the creator added nobody, the room stayed
//! at one member, the scope-address table listed one node, and the joiner's
//! `GET /v1/drive` listed both files and read `not_fetched` on both: 2 blobs on
//! the author's node, 0 on the second device. Every rung below was green and
//! every log line was an INFO.
//!
//! The node is also the right signer on the merits: a KeyPackage is a DEVICE
//! announcing its own MLS leaf, and edge's own `files::publish` builds its row
//! from `signers.node`. The owner's pen remains the crossing ACTOR, which is
//! what carries the person's authority for the placement.

/// Source with line endings normalised — CRLF checkouts break multi-line needles.
fn read_src(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// Every handshake row builder takes the NODE signer. The crossing actor is a
/// separate argument and is allowed — indeed required — to be the owner.
#[test]
fn every_handshake_row_is_built_from_the_node_signer() {
    let src = read_src("src/self_room_drive.rs");
    // The row BUILDERS, by the edge fn each reader pairs with:
    //   key_package_attestation  ↔ chat::key_package_from(dir, node, room)
    //   welcome_attestation      ↔ chat::welcome_from(dir, creator_node, room)
    //   commit_attestation_in    ↔ chat::commits_from(dir, node, room_id)
    for builder in [
        "key_package_attestation(",
        "welcome_attestation(",
        "commit_attestation_in(",
    ] {
        let mut found = 0;
        let mut cursor = 0;
        while let Some(rel) = src[cursor..].find(builder) {
            let at = cursor + rel;
            found += 1;
            // The signer is the FIRST argument; rustfmt puts it on its own line.
            let args_start = at + builder.len();
            let head = &src[args_start..src.len().min(args_start + 120)];
            let first_arg = head
                .split(',')
                .next()
                .unwrap_or("")
                .trim_matches(|c: char| c.is_whitespace());
            assert!(
                first_arg.contains("node_signer"),
                "{builder} is built from `{first_arg}` — it must be the NODE signer. \
                 Its reader looks the row up with `list_attestations_by(<node>)`, so an \
                 owner-attested row is INVISIBLE to the node that needs it, and the \
                 second device silently never joins the room."
            );
            cursor = args_start;
        }
        assert!(found > 0, "no call to {builder} found — did it move?");
    }
}

/// The owner's pen is still used — as the crossing ACTOR. If this disappears the
/// rows stop carrying the person's authority, which is the opposite mistake.
#[test]
fn the_owner_pen_remains_the_crossing_actor() {
    let src = read_src("src/self_room_drive.rs");
    assert!(
        src.contains("actor: Some(capsule.edge_signer())"),
        "a self-room row crosses as the OWNER even though the NODE attests it — the \
         attester says which device produced it, the actor says whose authority places \
         it (CC 3.3.6). Dropping the actor would author a person's placement as \
         infrastructure."
    );
}
