//! **A drive read is gated on the CALLER, not on the machine's state**
//! (CIRISServer#628, found by Codex).
//!
//! # What went wrong
//!
//! `drive_auth::owner` took `headers` and discarded them (`let _ = headers;`),
//! returning the owner whenever `require_owner_bound` said the NODE had one —
//! true on every claimed node. Writes survived by accident: they go on to open
//! the owner's pen through `owner_signer_capsule::acquire`, which reads the
//! bearer. **Reads did not.** `GET /v1/drive`, `GET /v1/files/{id}` and
//! `GET /v1/notes` authorized on machine state alone, so anything that could
//! reach the port could list and open the owner's files and notes.
//!
//! # The distinction this gate keeps
//!
//! **A binding is not a session.** `require_owner_bound` answers *who owns this
//! machine* — a fact about the node with no caller in it. That is exactly right
//! for a background loop, whose authority IS the owner binding
//! (`owner_signer_capsule::for_owned_node`), and exactly wrong for an HTTP
//! request, which has a caller and must prove it.
//!
//! The two live one file apart and read almost identically, which is why this
//! is a gate and not a comment.

fn read_src(path: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"))
        .replace("\r\n", "\n")
}

/// The guard must actually consult the request.
#[test]
fn the_drive_guard_reads_the_bearer() {
    let src = read_src("src/drive_auth.rs");
    // CODE only: this file deliberately DESCRIBES the old bug in prose, and a
    // scan that cannot tell an explanation from an instance would fire on the
    // very comment that prevents the bug recurring.
    let code: String = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !t.starts_with("//") && !t.starts_with("///") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("let _ = headers"),
        "drive_auth::owner is discarding the request headers again. That authorizes on the \
         NODE's owner binding alone, which is true on every claimed node — every drive READ \
         becomes unauthenticated while writes stay safe by accident (the capsule reads the \
         bearer). Taking a parameter and ignoring it is what made this invisible."
    );
    assert!(
        code.contains("resolve_bearer"),
        "the drive guard must resolve a bearer into a session — a binding says who owns the \
         MACHINE, not who is asking"
    );
    assert!(
        code.contains("caller.actor.is_some()"),
        "the drive guard must refuse a DELEGATED session: a `dgrant:` token carries the \
         owner's role and FullAccess by design, so role alone cannot tell the owner from \
         someone acting for them, and a drive is every private note and file at every cohort"
    );
    assert!(
        code.contains("UserRole::SystemAdmin") && code.contains("Permission::FullAccess"),
        "the drive guard must check the owner's role and permission"
    );
}

/// Every drive route goes through that guard — none rolls its own.
#[test]
fn every_drive_route_goes_through_the_guard() {
    let src = read_src("src/drive.rs");
    // Each handler that serves or accepts a person's content.
    for handler in [
        "async fn write_file(",
        "async fn read_drive(",
        "async fn read_file(",
        "async fn write_note(",
        "async fn read_notes(",
    ] {
        let start = src
            .find(handler)
            .unwrap_or_else(|| panic!("{handler} not found — did it move?"));
        let body = &src[start..src.len().min(start + 900)];
        assert!(
            body.contains("drive_auth::owner("),
            "{handler} must call `drive_auth::owner` before doing anything with the \
             person's content — a route that answers on its own is how the READ side \
             drifted away from the WRITE side in the first place"
        );
    }
}
