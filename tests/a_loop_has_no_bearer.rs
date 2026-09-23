//! **A background loop cannot authorize itself with a session it does not have**
//! (CIRISServer#622).
//!
//! # The shape
//!
//! `owner_signer_capsule::acquire` authorizes a CALLER: it reads a bearer,
//! refuses a delegated session, and checks the role. Its very first statement
//! is `let Some(token) = bearer … else { return Err(NotSignedIn) }`.
//!
//! A daemon has no caller. So a daemon that reaches for that door can only pass
//! `bearer: None`, and the call is `NotSignedIn` before it touches anything —
//! not sometimes, not under load, but on every tick forever.
//!
//! That is what `self_room_drive` did. The one arm that signs as the NODE
//! (`Create`) worked, so the node created its self room, logged `self room
//! CREATED`, and looked healthy. Every arm that authors a row AS THE OWNER —
//! the KeyPackage a second device publishes, the Add that admits it, the Remove
//! that evicts it — refused. A person's two devices would each hold a room the
//! other could not join, and the only symptom was a WARN.
//!
//! # Why a source gate
//!
//! The refusal is total and silent-by-shape: there is no state to set up, no
//! race, and a behavioural test would need a claimed two-node mesh to observe
//! something that is decidable by reading one line. The gate is the cheap half
//! of a fix whose expensive half was finding it on a live ladder.
//!
//! The rule it keeps: **a caller-less path uses `for_owned_node`, which is
//! authorized by the node's owner binding and verifies the resolved signer
//! against `owner_of`.** Not a machine-key fallback — signing a person's
//! content as infrastructure is its own defect (CC 3.3.6).

/// Source with line endings normalised — the needles below span lines, and a
/// CRLF checkout on Windows makes them match nothing against correct source.
fn read_src(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// Every `acquire` call site presents a bearer. `None` there is always the bug.
#[test]
fn no_call_site_hands_the_session_door_a_missing_bearer() {
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir("src").expect("read src/") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path.to_string_lossy().to_string();
        let src = read_src(&name);
        for (i, window) in src.match_indices("owner_signer_capsule::acquire(") {
            let _ = window;
            // The bearer is the SECOND argument. Read to the end of the call's
            // argument list rather than one line: rustfmt splits these across
            // five lines, so a line-local scan would see nothing.
            let tail = &src[i..src.len().min(i + 400)];
            let args = tail.split_once(')').map_or(tail, |(a, _)| a);
            if args.contains("None") {
                let line = src[..i].matches('\n').count() + 1;
                offenders.push(format!("{name}:{line}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these call sites pass `bearer: None` to the SESSION door, which returns \
         NotSignedIn before doing anything — every one of them refuses on every \
         call, forever: {offenders:?}. A path with no caller is authorized by the \
         node's OWNER BINDING instead: `owner_signer_capsule::for_owned_node`."
    );
}

/// The self-room drive, specifically — it is the loop this was found in, and
/// the one most likely to grow another owner-authored arm.
#[test]
fn the_self_room_drive_opens_its_pen_through_the_binding() {
    let src = read_src("src/self_room_drive.rs");
    assert!(
        src.contains("owner_signer_capsule::for_owned_node"),
        "the self-room drive must open the owner's pen through the door authorized \
         by the node's owner binding — it has no session to present"
    );
    assert!(
        !src.contains("owner_signer_capsule::acquire("),
        "the self-room drive reached for the SESSION door again. It is a loop: \
         that door refuses it on every tick and the node silently stops admitting \
         the owner's other devices"
    );
}

/// The binding door must CHECK the binding, not just read it. A door that
/// resolved the owner and then signed with whatever seed happened to be on disk
/// would put one person's name on another's content — and `active_user_alias`
/// is a file, so "whatever is on disk" is not hypothetical.
#[test]
fn the_binding_door_verifies_the_seed_derives_the_owner() {
    let src = read_src("src/owner_signer_capsule.rs");
    let start = src
        .find("pub async fn for_owned_node")
        .expect("for_owned_node is the caller-less door and must exist");
    let body = &src[start..];
    assert!(
        body.contains("owner_of("),
        "for_owned_node must resolve the owner from the node's binding"
    );
    assert!(
        body.contains("signer_holds("),
        "for_owned_node must verify the resolved signer actually derives the key \
         `owner_of` named — resolving an owner and then signing with an unchecked \
         seed is how a node signs one person's content as another"
    );
    let holds = body.find("signer_holds(").expect("checked above");
    let unowned = body.find("CapsuleRefusal::Unowned").expect("refusal arm");
    assert!(
        unowned < holds,
        "an UNCLAIMED node must be refused by name before any seed is opened"
    );
}
