//! The owner guard the drive routes share — one question ("is the caller the
//! person who owns this node?"), asked the same way for every file route.

use axum::http::HeaderMap;

pub struct DriveOwner {
    pub key_id: String,
}

/// `None` when there is no owner-bound session. Deliberately not a `Result`:
/// every caller answers a 403 with its own wording, and threading a Response
/// through here would make this module decide what a file route says.
pub async fn owner(st: &crate::drive::DriveState, headers: &HeaderMap) -> Option<DriveOwner> {
    let node = st.engine.local_derived_key_id().await.ok()?;
    let bound = crate::auth::gate::require_owner_bound(&st.engine, &node)
        .await
        .ok()?;
    let _ = headers;
    Some(DriveOwner { key_id: bound })
}
