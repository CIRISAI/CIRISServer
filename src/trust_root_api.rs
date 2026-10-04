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
                let mut json = serde_json::to_value(&v).unwrap_or(serde_json::Value::Null);
                // THE WITNESSED HEAD (persist v51 #938, CC T6/T8 (vii)): the
                // digest of the signed roster row at the version this node
                // witnessed, and its instant. Every node holding the same rows
                // reports the same pair — the one-line multi-node predicate the
                // topology harness reports per node (CIRISConstitution#131).
                let head = match st.engine.lineage_head(&root_ref).await {
                    Ok(Some(view)) => serde_json::json!({
                        "digest": view.witnessed_head.as_ref().map(|(d, _)| d.clone()),
                        "at": view.witnessed_head.as_ref().map(|(_, at)| at.to_rfc3339()),
                        "quorum": view.quorum,
                        "judged": view.community.as_ref().and_then(|c| c.judged),
                        "latest_cosign_at": view.latest_cosign_at.map(|t| t.to_rfc3339()),
                    }),
                    Ok(None) => serde_json::Value::Null,
                    Err(e) => serde_json::json!({ "error": e.to_string() }),
                };
                // STANDING, one word, as the T8 verdict names it: `not_rooted`
                // when the five-conjunct verdict fails or a halt is latched;
                // `stalled` when the root is valid but its community resolves
                // with `live: false` (CC T7: fewer than M+1 active founders —
                // attached pairs stay rooted, new members are refused, edge's
                // FIRST_CONTACT.md I12); `rooted` otherwise. A key root has no
                // community to resolve and is never stalled.
                let live = match ciris_persist::federation::canonical_community::resolve_community(
                    st.engine.federation_directory().as_ref(),
                    &root_ref,
                )
                .await
                {
                    Ok(Some(c)) => Some(c.live),
                    Ok(None) | Err(_) => None,
                };
                let standing = if !v.valid || v.halt_latched == Some(true) {
                    "not_rooted"
                } else if live == Some(false) {
                    "stalled"
                } else {
                    "rooted"
                };
                if let serde_json::Value::Object(m) = &mut json {
                    m.insert("lineage_head".into(), head);
                    m.insert(
                        "standing".into(),
                        serde_json::Value::String(standing.into()),
                    );
                    m.insert("live".into(), serde_json::json!(live));
                }
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

/// The roots this node might have: the accord family, any charter-declared root
/// in the baked bundle, and **every root this node has actually accepted**.
///
/// Deliberately not a scan — a trust-root list assembled by pattern-matching the
/// graph would grow entries nobody chose. But the first two alone were too small
/// in the direction that matters: `POST /v1/trust-root/import` installs and
/// ACCEPTS a root whose charter names a custom or solo identity, and such a root
/// appeared nowhere here. The node could be entrenched under a root this endpoint
/// did not list — so an operator could not read its id, and could not pass it to
/// `DELETE /v1/trust-root/{id}` to un-trust it. A root you cannot name is a root
/// you cannot revoke.
///
/// The third source is not a scan either: acceptance is a `delegates_to(node ->
/// root)` this node AUTHORED (see [`crate::mesh_genesis::accept_trust_root`]), so
/// listing the roots of this node's own outbound edges lists exactly the roots
/// someone chose here. Nothing arrives from a peer.
async fn candidate_roots(st: &TrustRootState) -> Vec<String> {
    use ciris_persist::federation::types::attestation_type;

    let mut out =
        vec![ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID.to_string()];
    if let Ok(Some(bundle)) = baked_bundle() {
        if let Some(r) = crate::mesh_genesis::charter_root_key_id(bundle) {
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }

    // The accepted set. A read failure is NOT silently an empty set — that would
    // render as "you accepted nothing", which is a different and false claim than
    // "we could not look". The named defaults are still returned, and the caller
    // sees the same `unreadable` treatment the per-root evaluation already uses.
    match st
        .engine
        .federation_directory()
        .list_attestations_by(&st.node_key_id)
        .await
    {
        Ok(rows) => {
            for a in rows {
                if a.attestation_type == attestation_type::DELEGATES_TO
                    && !a.attested_key_id.is_empty()
                    && !out.contains(&a.attested_key_id)
                {
                    out.push(a.attested_key_id);
                }
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            "trust-root listing: could not read this node's acceptance edges — an IMPORTED root \
             may be missing from the list. The named defaults are still shown"
        ),
    }
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
    /// Optional: the read-API base URL of the node this bundle came from. Its
    /// allegiance facts (owner-binding, root acceptances) are carried in the
    /// same act, so the Rooted walk toward it works from first contact
    /// (CIRISServer#632 / CIRISEdge#671). Loopback-gated like the import.
    #[serde(default)]
    allegiance_from: Option<String>,
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

    // A bundle minted before persist v53 carries an UNLABELLED charter. It
    // still verifies, but outside the one pinned genesis it installs as no
    // charter (CC 3.2 T4a), so the root would look imported and never be
    // valid. Say so instead of reporting a success.
    if let Some(row) = crate::mesh_genesis::unlabelled_trust_row(&bundle) {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "trust_root.bundle_unlabelled",
            format!(
                "this bundle was minted before the trust-root rows carried their job labels \
                 (trust:charter:v1 / trust:confers:v1 — {row} carries none); on this node it \
                 would install as no charter or no grant. Import a bundle from the final \
                 genesis (FSD/FINAL_GENESIS.md) instead. Nothing on this node changed."
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
        Ok(Some(_)) => true,
        // Nothing was accepted: the acceptance names the root's head, and a
        // bundle whose genesis records this node does not hold yet (a v3
        // bundle's family/community heads are seeded only from the baked one)
        // defers. Reported as NOT accepted — `Ok` alone used to read as
        // accepted (Codex on #725).
        // This node IS the charter's root (a solo 1-of-1 bundle): the charter's
        // self-loop is the trust, and no acceptance is written (Codex on #726).
        Ok(None)
            if crate::mesh_genesis::charter_root_key_id(&bundle).as_deref()
                == Some(st.node_key_id.as_str()) =>
        {
            true
        }
        Ok(None) => {
            tracing::warn!(
                "trust root INSTALLED but not ACCEPTED — this node does not hold the root's \
                 head yet; the acceptance is retried at the next boot or import"
            );
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, "trust root INSTALLED but not ACCEPTED — records are known, this node's trust:accepts edge was not written");
            false
        }
    };

    // The OWNER's acceptance rides the same import when the pen is here
    // (CIRISServer#632 step 2): the node→root edge above is default trust; the
    // owner→root edge is what a peer's Rooted walk reads (CIRISEdge#659).
    match crate::node_key::accept_roots_as_owner(&st.engine).await {
        Ok(Some(newly)) if !newly.is_empty() => {
            tracing::info!(roots = ?newly, "trust root import: the OWNER accepted the root(s)")
        }
        Ok(Some(_)) => {
            tracing::info!("trust root import: the owner's acceptance already on record")
        }
        Ok(None) => tracing::info!(
            "trust root import: no owner pen on this node yet — the owner's acceptance is \
             written at the claim"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "trust root import: the owner's acceptance FAILED (non-fatal)"
        ),
    }
    if let Some(base) = req
        .allegiance_from
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(client) => {
                match crate::mesh_genesis::carry_allegiance_from(&st.engine, &client, base).await {
                    Ok(adopted) => tracing::info!(
                        from = %base,
                        keys_registered = adopted.keys_registered,
                        rows_inserted = adopted.rows_inserted,
                        rows_already_held = adopted.rows_already_held,
                        refused = ?adopted.refused,
                        "trust root import: the source node's allegiance facts carried (CIRISEdge#671)"
                    ),
                    Err(e) => {
                        tracing::warn!(from = %base, error = %e, "trust root import: allegiance carry FAILED (non-fatal)")
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "trust root import: no HTTP client for the allegiance carry")
            }
        }
    }
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

/// `GET /v1/trust-root/bundle` — the genesis bundle this node runs on, in the
/// shape the registry serves (`FSD/FINAL_GENESIS.md` §3 item 8):
/// `{bundle, community, bundle_fingerprint, charter_root_key_id, served_by}`.
/// The bundle is its own proof (every row is holder-signed and the
/// authorizations cover the whole), so there is no wrapper signature; a reader
/// verifies it with `POST /v1/trust-root/import`. `community` is the
/// `ciris-canonical` birth the bundle carries, `null` on a bundle without one.
///
/// The contract is "the bake this node runs on": served only while the node
/// is entrenched on its compiled bake (persist compares the stored legs to
/// that artifact, so an imported root never makes it so), trusts its root,
/// and the bake is importable (labelled). Anything else answers 409
/// `trust_root.bundle_not_in_force` — an imported root is the importer's to
/// hand on, not this route's.
async fn serve_bundle(State(st): State<TrustRootState>) -> Response {
    // Only the bundle this node RUNS ON. The compiled bake is that bundle only
    // while the posture is entrenched; a bake this node did not adopt (an older
    // root still in force, or none) must not be advertised as its root (Codex
    // on #726).
    let posture = st.engine.genesis_posture().await;
    if !posture.entrenched() {
        return err(
            StatusCode::CONFLICT,
            "trust_root.bundle_not_in_force",
            format!(
                "this node is not entrenched on the bundle it carries, so it serves none: {}",
                posture.banner().unwrap_or_default()
            ),
        );
    }
    let bundle = ciris_persist::federation::genesis::canonical_genesis_bundle();
    // ...and only if this node actually TRUSTS that bundle's root — an
    // entrenched posture after importing some other root must not advertise
    // the compiled one (Codex on #726).
    let root = crate::mesh_genesis::charter_root_key_id(bundle);
    let trusted = match ciris_persist::federation::trust_root::trusted_roots_of(
        st.engine.federation_directory().as_ref(),
        &st.node_key_id,
        chrono::Utc::now(),
    )
    .await
    {
        Ok(roots) => root.as_ref().is_some_and(|r| roots.contains(r)),
        Err(_) => false,
    };
    if !trusted {
        return err(
            StatusCode::CONFLICT,
            "trust_root.bundle_not_in_force",
            format!(
                "this node does not trust the root of the bundle it carries ({}), so it serves none",
                root.as_deref().unwrap_or("no charter")
            ),
        );
    }
    // A bundle a peer could not import is not served: the July bake predates
    // the trust-row labels and `POST /v1/trust-root/import` refuses it (Codex
    // on #726). The final genesis's bake is labelled and serves.
    if let Some(row) = crate::mesh_genesis::unlabelled_trust_row(bundle) {
        return err(
            StatusCode::CONFLICT,
            "trust_root.bundle_not_in_force",
            format!(
                "the bundle this node carries predates the trust-row labels ({row} carries none), \
                 so no peer could import it; it is not served"
            ),
        );
    }
    let fingerprint = match crate::mesh_genesis::fingerprint(bundle) {
        Ok(f) => f,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "trust_root.bad_bundle",
                format!("fingerprint the baked bundle: {e}"),
            )
        }
    };
    Json(serde_json::json!({
        "bundle": bundle,
        "community": bundle.community_record(crate::final_genesis::COMMUNITY_KEY_ID),
        "bundle_fingerprint": fingerprint,
        "charter_root_key_id": crate::mesh_genesis::charter_root_key_id(bundle),
        "served_by": st.node_key_id,
    }))
    .into_response()
}

/// The PUBLIC trust-root read: the bundle (signed public rows, served to any
/// peer or client — the registry serves the same shape).
pub fn public_router(engine: Arc<Engine>, node_key_id: String) -> Router {
    Router::new()
        .route("/v1/trust-root/bundle", axum::routing::get(serve_bundle))
        .with_state(TrustRootState {
            engine,
            node_key_id,
        })
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
