//! The owner guard the drive routes share — one question ("is the CALLER the
//! person who owns this node?"), asked the same way for every file route.
//!
//! # The bug this file was, and why the shape invited it
//!
//! The first cut took `headers` and threw them away (`let _ = headers;`),
//! answering only "does this node have an owner binding?" — which is true on
//! every claimed node. Writes survived it by accident, because they go on to
//! open the owner's pen through `owner_signer_capsule::acquire`, which *does*
//! read the bearer. **Reads did not**: `GET /v1/drive`, `GET /v1/files/{id}`
//! and `GET /v1/notes` authorized on the machine's state alone, so anything
//! that could reach the port could list and open the owner's files and notes
//! (found by Codex on CIRISServer#628).
//!
//! Two lessons are worth keeping in the code rather than the commit message:
//!
//! * **Taking a parameter you do not use is worse than not taking it.** The
//!   signature said "this consults the request" and the body did not; every
//!   call site read the signature.
//! * **A binding is not a session.** `require_owner_bound` answers *who owns
//!   this machine* — a fact about the node, with no caller in it. That is the
//!   right question for a background loop, whose authority IS the binding
//!   (`owner_signer_capsule::for_owned_node`), and the wrong one for an HTTP
//!   request, which has a caller and must be checked.

use axum::http::HeaderMap;

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;

pub struct DriveOwner {
    pub key_id: String,
}

/// The owner of this node **when the caller has proved they are that person**.
///
/// `None` when there is no valid owner session. Deliberately not a `Result`:
/// every caller answers a 403 with its own wording, and threading a Response
/// through here would make this module decide what a file route says.
///
/// # What is checked, and why each one
///
/// 1. a bearer is present and `resolve_bearer` accepts it — otherwise this is
///    an anonymous request;
/// 2. the session is **not delegated** (`caller.actor.is_none()`). A `dgrant:`
///    token carries the owner's role AND FullAccess by design, so role alone
///    cannot tell the owner from someone acting for them. A drive is one
///    person's view of their own reach; handing a temporary delegate the whole
///    of it — every private note, every file at every cohort — is not what a
///    delegation is for. Same discriminator `owner_signer_capsule::acquire`
///    uses, and refusing here keeps read and write symmetric;
/// 3. the session is the owner's (`SystemAdmin` + `FullAccess`);
/// 4. the node HAS an owner binding, and that owner is who the files belong to.
pub async fn owner(st: &crate::drive::DriveState, headers: &HeaderMap) -> Option<DriveOwner> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())?;
    let caller = resolve_bearer(&st.engine, token).await.ok()??;
    if caller.actor.is_some() {
        return None;
    }
    if caller.role != UserRole::SystemAdmin || !caller.permissions.contains(&Permission::FullAccess)
    {
        return None;
    }
    let node = st.engine.local_derived_key_id().await.ok()?;
    let bound = crate::auth::gate::require_owner_bound(&st.engine, &node)
        .await
        .ok()?;
    Some(DriveOwner { key_id: bound })
}
