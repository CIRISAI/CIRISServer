//! **The registry slice's surfaces** — `ciris-registry-core`'s fold routes,
//! ported onto this server's substrate (CIRISServer#537, CIRISRegistry#62).
//!
//! The registry repo split its slice into a no-`standalone` fold surface
//! (`fold.rs`, `fold_builds.rs`, `fold_evidence.rs`) that compiles on a persist
//! `Engine` with no sqlx, no tonic and no Edge of its own. Those modules are
//! ported here rather than pinned as a crate: registry-core at its last release
//! (v4.1.0, `f04b149`) sits on persist v59 / edge v43 / verify v20, and the pins
//! are coupled — a second substrate revision in one graph does not build, and
//! its `proto` module would drag prost and `tonic-build` along for a `crypto`
//! module the server does not use. The lens slice was absorbed the same way.
//!
//! **Mounted only on a node the accord conferred the slice on.** Compose merges
//! [`router`] iff [`crate::registry_slice::RegistrySlice::serves`]. Everything
//! here is self-authenticating (a Contribution re-verifies against its signer's
//! key, and the signer's blessing is re-walked on every read), so the gate is
//! not what makes a served build true. It decides which nodes take on the
//! registry's job: holding manifests and answering for them.
//!
//! The trust-root broadcast (`GET /v1/trust-root/bundle`) is NOT here: every
//! node relays the root it runs on, conferred or not
//! ([`crate::trust_root_api::public_router`]).

pub mod builds;

use std::sync::Arc;

use axum::Router;
use ciris_persist::federation::attestation_query::AttestationQuery;
use ciris_persist::federation::{Attestation, Error, FederationDirectory};
use ciris_persist::prelude::Engine;

/// The registry slice's router over the shared Engine. `node_key_id` is the key
/// this node operates as on the wire — the one the conferral walk ran for, and
/// the one every blessing walk asks "from a root I accept?" on behalf of.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    builds::router(engine, node_key_id)
}

/// [`router`] on a node the slice is conferred on, an empty router anywhere
/// else — so a node that was never blessed answers `/v1/builds` with the
/// ordinary 404 of a route it does not serve.
pub fn router_if_conferred(
    slice: &crate::registry_slice::RegistrySlice,
    engine: Arc<Engine>,
    node_key_id: String,
) -> Router {
    if slice.serves() {
        router(engine, node_key_id)
    } else {
        Router::new()
    }
}

/// Every row of a bounded query, page by page. persist v56 (CIRISPersist#1001)
/// demoted the unbounded whole-key reads to test builds; a production read pages
/// [`AttestationQuery`] and stops when the cursor stops advancing.
pub(crate) async fn collect_pages(
    dir: &dyn FederationDirectory,
    query: AttestationQuery,
) -> Result<Vec<Attestation>, Error> {
    let mut out = Vec::new();
    let mut pages = query.pages();
    while let Some(rows) = pages.next(dir).await? {
        out.extend(rows);
    }
    Ok(out)
}
