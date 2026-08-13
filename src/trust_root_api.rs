//! **The portable trust root: import, list, delete** (CIRISServer#400).
//!
//! CREATE already existed — the genesis ceremony on the Accord card mints a root
//! from 2-of-3 holders. The other three verbs did not, which left the operator of
//! a rootless node with exactly one option: run a full hardware ceremony. If they
//! already HELD a portable root — the ordinary case for a second device, a rebuilt
//! host, or a node joining a mesh someone else founded — there was no way to say
//! so.
//!
//! persist v31.0.0 makes this urgent rather than convenient. A fresh node boots
//! `PreGenesis`: no valid root, every root-requiring gate refusing, no `trace:*`
//! row served. That is the *correct* state and the node runs fine in it — but it
//! stays that way until someone can put a root in.
//!
//! # Import is not "trust this"
//!
//! Installing records makes a root KNOWN. **Accepting** it is this node's own
//! signed `trust:accepts` edge — a separate act, and the one row an operator
//! deletes to un-trust. A bundle may seed records; it may never assign a stranger
//! a trust root. Import does both, in that order, and says which succeeded:
//! partial success is a real state and reporting it as failure would send an
//! operator re-importing a bundle that is already installed.
//!
//! # Loopback-gated, like the rest of the setup surface
//!
//! Choosing a node's trust root is the most consequential local act there is.
//! These routes sit behind the same loopback guard as the first-run claim reads —
//! the operator's own machine, not the network.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct TrustRootState {
    pub engine: Arc<Engine>,
    /// THIS node's federation key — the `user_key_id` side of the trust edge, and
    /// therefore the identity whose acceptance is being read or revoked.
    pub node_key_id: String,
}

fn err(code: StatusCode, reason: &str, msg: impl Into<String>) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": msg.into(), "reason_id": reason })),
    )
        .into_response()
}

/// What this node currently trusts, and what state its genesis is in.
#[derive(Debug, Serialize)]
struct TrustRootListing {
    /// `entrenched` / `pre_genesis` / `divergent`, from persist.
    posture: serde_json::Value,
    /// The operator-facing sentence. `null` once entrenched.
    banner: Option<String>,
    /// True iff every root-requiring gate will pass.
    entrenched: bool,
    /// The roots this node has records for and has accepted.
    roots: Vec<RootEntry>,
}

#[derive(Debug, Serialize)]
struct RootEntry {
    root_key_id: String,
    /// `family` when the root is a keyless FAMILY (the accord shape — the root is
    /// the family id, never a seat), `key` for a single-key root.
    root_kind: String,
    /// Does this node's OWN `trust:accepts` edge reach it?
    accepted: bool,
    /// The full verdict, verbatim — `valid`, the per-leg findings, drill
    /// freshness. Passed through rather than summarised: a caller deciding
    /// whether to delete a root should see persist's reasoning, not ours.
    verdict: serde_json::Value,
}

/// `GET /v1/trust-root` — what is installed, and what posture the node is in.
async fn list_roots(State(st): State<TrustRootState>) -> Response {
    let posture = st.engine.genesis_posture().await;
    let entrenched = posture.entrenched();
    let banner = posture.banner();

    let mut roots = Vec::new();
    for root_ref in candidate_roots(&st).await {
        let verdict = ciris_persist::federation::trust_root::trust_root_valid(
            st.engine.federation_directory().as_ref(),
            &st.node_key_id,
            &root_ref,
        )
        .await;
        match verdict {
            Ok(v) => {
                let json = serde_json::to_value(&v).unwrap_or(serde_json::Value::Null);
                roots.push(RootEntry {
                    root_key_id: root_ref,
                    root_kind: json
                        .get("root_kind")
                        .and_then(|k| k.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    accepted: json
                        .get("user_accepts")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    verdict: json,
                });
            }
            // A root we cannot EVALUATE is reported, not dropped. Silently
            // omitting it would render as "you trust nothing", which is a
            // different and false claim.
            Err(e) => roots.push(RootEntry {
                root_key_id: root_ref,
                root_kind: "unreadable".to_string(),
                accepted: false,
                verdict: serde_json::json!({ "error": e.to_string() }),
            }),
        }
    }

    (
        StatusCode::OK,
        Json(TrustRootListing {
            posture: serde_json::to_value(&posture).unwrap_or(serde_json::Value::Null),
            banner,
            entrenched,
            roots,
        }),
    )
        .into_response()
}

/// The roots this node might have: the accord family, plus any charter-declared
/// root in the baked bundle. Deliberately a small, named set rather than a scan —
/// a trust-root list assembled by pattern-matching the graph would grow entries
/// nobody chose.
async fn candidate_roots(st: &TrustRootState) -> Vec<String> {
    let mut out =
        vec![ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID.to_string()];
    if let Ok(Some(bundle)) = baked_bundle() {
        if let Some(r) = crate::mesh_genesis::charter_root_key_id(bundle) {
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    let _ = st;
    out
}

/// The baked bundle, via the SAME accessor stage 1 uses — not a second path to
/// the same bytes.
fn baked_bundle() -> Result<Option<&'static crate::mesh_genesis::GenesisBundle>, ()> {
    Ok(Some(
        ciris_persist::federation::genesis::canonical_genesis_bundle(),
    ))
}

#[derive(Debug, Deserialize)]
struct ImportRequest {
    /// A portable genesis bundle — the artifact a ceremony produced.
    bundle: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ImportResponse {
    /// Records installed (the root became KNOWN).
    installed: bool,
    /// This node's `trust:accepts` edge written (the root became TRUSTED).
    accepted: bool,
    /// Posture AFTER the import — re-derived, so the caller sees the effect
    /// rather than being told it worked.
    posture: serde_json::Value,
    entrenched: bool,
    banner: Option<String>,
}

/// `POST /v1/trust-root/import` — install and accept a portable trust root.
///
/// Verifies the bundle BEFORE installing anything. A bundle that does not verify
/// is refused whole: there is no partial-install-then-check path, because a
/// half-installed root is indistinguishable from a tampered one at the next read.
async fn import_root(State(st): State<TrustRootState>, body: axum::body::Bytes) -> Response {
    let req: ImportRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "trust_root.bad_request",
                format!("bad request: {e}"),
            )
        }
    };
    let bundle: crate::mesh_genesis::GenesisBundle = match serde_json::from_value(req.bundle) {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "trust_root.bad_bundle",
                format!("not a genesis bundle: {e}"),
            )
        }
    };

    // VERIFY FIRST. The signatures are the whole claim; installing before
    // checking them would mean a refused bundle still moved rows.
    if let Err(e) = crate::mesh_genesis::verify_bundle(&bundle) {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "trust_root.bundle_refused",
            format!(
                "this bundle does not verify and was NOT installed: {e}. Nothing on this node \
                 changed."
            ),
        );
    }

    let dir = st.engine.federation_directory();
    let installed =
        match crate::mesh_genesis::install_trust_root_records(dir.as_ref(), &bundle).await {
            Ok(_) => true,
            Err(e) => {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "trust_root.install_failed",
                    format!("bundle verified but its records did not install: {e}"),
                )
            }
        };

    // ACCEPT is a SECOND act, and its failure is not the first one's failure.
    // Records installed + acceptance failed leaves the root KNOWN but not
    // TRUSTED, which is a real state an operator can retry from — reporting the
    // whole import as failed would send them re-importing what is already here.
    let accepted = match crate::mesh_genesis::accept_trust_root(&st.engine, &bundle).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!(error = %e, "trust root INSTALLED but not ACCEPTED — records are known, this node's trust:accepts edge was not written");
            false
        }
    };

    let posture = st.engine.genesis_posture().await;
    tracing::warn!(
        installed,
        accepted,
        entrenched = posture.entrenched(),
        "TRUST ROOT IMPORTED — the node's root changed by operator action"
    );
    (
        StatusCode::OK,
        Json(ImportResponse {
            installed,
            accepted,
            entrenched: posture.entrenched(),
            banner: posture.banner(),
            posture: serde_json::to_value(&posture).unwrap_or(serde_json::Value::Null),
        }),
    )
        .into_response()
}

/// `DELETE /v1/trust-root/{root_key_id}` — UN-TRUST a root.
///
/// Withdraws this node's own `trust:accepts` edge. It does **not** delete the
/// root's records: they are signed history and this node's opinion of them is not
/// a reason to forget they exist. After this the root is KNOWN and not TRUSTED,
/// which is exactly the state an import leaves half-done — one axis, both
/// directions.
///
/// This is the nuclear local act: a node with no accepted root serves no
/// `trace:*` row. It is loopback-gated and logged at WARN with the root named.
async fn delete_root(State(st): State<TrustRootState>, Path(root): Path<String>) -> Response {
    let root = root.trim().to_string();
    if root.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "trust_root.no_root",
            "which root? the path must name the root_key_id to un-trust",
        );
    }
    match crate::mesh_genesis::withdraw_trust_acceptance(&st.engine, &root).await {
        Ok(withdrawn) => {
            let posture = st.engine.genesis_posture().await;
            tracing::warn!(
                root = %root, withdrawn, entrenched = posture.entrenched(),
                "TRUST ROOT UN-TRUSTED by operator action — records retained, acceptance withdrawn"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "root_key_id": root,
                    "withdrawn": withdrawn,
                    "records_retained": true,
                    "entrenched": posture.entrenched(),
                    "banner": posture.banner(),
                })),
            )
                .into_response()
        }
        Err(e) => err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "trust_root.withdraw_failed",
            format!("could not withdraw acceptance of {root}: {e}"),
        ),
    }
}

/// The trust-root router. Loopback-gated with the setup reads.
pub fn router(engine: Arc<Engine>, node_key_id: String) -> Router {
    let state = TrustRootState {
        engine,
        node_key_id,
    };
    Router::new()
        .route("/v1/trust-root", axum::routing::get(list_roots))
        .route("/v1/trust-root/import", axum::routing::post(import_root))
        .route(
            "/v1/trust-root/{root_key_id}",
            axum::routing::delete(delete_root),
        )
        .with_state(state)
        .layer(axum::middleware::from_fn(
            crate::auth::loopback::require_loopback,
        ))
}
