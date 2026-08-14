//! **Link an OAuth identity onto an existing certificate** — the Rust port of the
//! agent's `AuthenticationService.link_oauth_identity`
//! (`infrastructure/authentication/service.py:468`).
//!
//! # The primitive the conversion was missing
//!
//! Sign-in RESOLVES `(oauth_provider, oauth_external_id)` to a cert
//! ([`super::oauth::resolve_oauth_user`]). That answers "which local identity is
//! this human", but nothing could ever *establish* the answer for a human who
//! already had a certificate: the claim path stamps the pair at claim time
//! (CIRISServer#384) and there was no other way in. So an owner who set the node
//! up with a portable federation ID, then signed in with Google, became a
//! SECOND identity on their own node rather than the same person twice.
//!
//! That is the "join your existing self" case, and it is what makes multi-self
//! coherent: one certificate, one set of federation keys, several ways the human
//! proves they are the holder.
//!
//! # Two axes, kept apart deliberately
//!
//! `oauth_provider`/`oauth_external_id` are the PRIMARY pair — the columns the
//! substrate's partial index keys, and the only thing
//! `WaCertService::get_by_oauth` matches. `oauth_links` is the SET of every
//! identity linked to this certificate. A link is therefore not automatically a
//! login: promoting one to primary is a separate, explicit act (`primary:
//! true`), because "this account belongs to me" and "this account is how I sign
//! in" are different claims and only the second one moves an index the whole
//! node authenticates against.
//!
//! # Refusals are typed
//!
//! Every failure here is something an operator can act on — the certificate does
//! not exist, or the identity is already spoken for by someone else — so each
//! carries a stable `reason_id` the client binds to a localized string, never a
//! store-internal message. A silent success that linked nothing would be worse
//! than any of them.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::store;

/// `POST /v1/self/oauth-link` — bind an OAuth identity to an existing cert.
pub const ROUTE: &str = "/v1/self/oauth-link";

#[derive(Clone)]
pub struct OAuthLinkState {
    pub engine: Arc<Engine>,
}

#[derive(Debug, Deserialize)]
struct LinkRequest {
    /// The certificate receiving the link. Omitted ⇒ the node's ROOT (the owner),
    /// which is the case this exists for.
    #[serde(default)]
    wa_id: Option<String>,
    provider: String,
    external_id: String,
    #[serde(default)]
    account_name: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    /// Promote this identity to the PRIMARY pair — i.e. make it a way to sign in,
    /// not merely an identity this human owns. Default `false`: the permissive
    /// reading of an absent field would silently repoint the index the whole node
    /// authenticates against.
    #[serde(default)]
    primary: bool,
}

#[derive(Debug, Serialize)]
struct LinkResponse {
    wa_id: String,
    provider: String,
    /// Whether this call CHANGED anything — a re-link is a no-op and says so,
    /// rather than reporting success indistinguishable from the first time.
    linked: bool,
    /// True when this identity is now the primary sign-in pair.
    is_primary: bool,
    /// Every identity linked to this certificate after the call.
    links: serde_json::Value,
}

/// SYSTEM_ADMIN + FullAccess, same gate the other owner-only routes use.
/// Refusals carry a `reason_id` like every other refusal here, so "you are not
/// signed in" and "you are signed in but not the owner" are DIFFERENT answers a
/// UI can render — a single "forbidden" tells an operator nothing about which.
/// Owner gate for linking a sign-in identity.
///
/// **Refuses a delegated session.** This writes `oauth_provider` /
/// `oauth_external_id` onto a `wa_cert` row — with `wa_id` omitted, onto the
/// node's ROOT. `store::get_by_oauth` then resolves that provider pair to ROOT
/// forever, so a delegate could attach its own Google account and hold
/// SYSTEM_ADMIN across revocation and restart: the grant is in-memory, the link
/// is a stored row. `CapabilityVerb::Delegate` is never-delegatable precisely so
/// a delegate cannot mint further delegations; this mints something strictly
/// stronger and had no gate at all.
async fn require_owner(engine: &Engine, headers: &HeaderMap) -> Result<(), Response> {
    use crate::auth::roles::{Permission, UserRole};
    use crate::auth::session::resolve_bearer;

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(refuse(
            StatusCode::UNAUTHORIZED,
            "auth.not_signed_in",
            "You are not signed in. Sign in as this node's owner, then try again.",
        ));
    };
    match resolve_bearer(engine, token).await {
            // A DELEGATE MAY NOT DO THIS. `resolve_bearer` hands a `dgrant:`
            // token the owner's role and FullAccess by design — that is what
            // makes a delegation useful — so role alone does not distinguish the
            // owner from someone acting for them. `/v1/accord/*` and
            // `/v1/auth/device/*` both exclude delegated actors this way; the
            // omission here was what made those two readable as policy rather
            // than accident.
        Ok(Some(caller)) if caller.actor.is_some() => Err(refuse(
            StatusCode::FORBIDDEN,
            "auth.oauth_link.not_delegatable",
            "Linking a sign-in identity is the owner's own act. A delegated session cannot do \
             it — the link outlives the delegation, so it would hand permanent access to \
             whoever holds a temporary grant.",
        )),
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(())
        }
        Ok(Some(caller)) => Err(refuse(
            StatusCode::FORBIDDEN,
            "auth.not_the_owner",
            format!(
                "Signed in as {} ({}), which is not the node's owner. This act needs                  the owner (SYSTEM_ADMIN with full access).",
                caller.wa_id,
                caller.role.as_str()
            ),
        )),
        Ok(None) => Err(refuse(
            StatusCode::UNAUTHORIZED,
            "auth.session_expired",
            "Your session is no longer valid. Sign in again to continue.",
        )),
        Err(e) => Err(refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.oauth_link.store_unavailable",
            format!("identity store unavailable: {e}"),
        )),
    }
}

fn refuse(status: StatusCode, reason_id: &str, msg: impl Into<String>) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": msg.into(),
            "reason_id": reason_id,
        })),
    )
        .into_response()
}

async fn link_handler(
    State(st): State<OAuthLinkState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st.engine, &headers).await {
        return resp;
    }
    let req: LinkRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "auth.oauth_link.bad_request",
                format!("bad request: {e}"),
            )
        }
    };
    if req.provider.trim().is_empty() || req.external_id.trim().is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "auth.oauth_link.incomplete_pair",
            "Both the provider and the account id are required. Half of a pair links \
             an account that nothing can find again.",
        );
    }
    let provider = req.provider.trim().to_ascii_lowercase();
    let external_id = req.external_id.trim().to_string();

    // Target: the named cert, else the node's ROOT (the owner).
    let target = match &req.wa_id {
        Some(id) => match store::get(&st.engine, id).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                return refuse(
                    StatusCode::NOT_FOUND,
                    "auth.oauth_link.no_such_identity",
                    format!("no certificate {id} on this node"),
                )
            }
            Err(e) => {
                return refuse(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "auth.oauth_link.store_unavailable",
                    format!("identity store unavailable: {e}"),
                )
            }
        },
        None => {
            match store::list_by_role(&st.engine, ciris_persist::wa_cert::WaRole::Root, 1).await {
                Ok(v) if !v.is_empty() => v.into_iter().next().expect("non-empty"),
                Ok(_) => {
                    return refuse(
                        StatusCode::CONFLICT,
                        "auth.oauth_link.node_unowned",
                        "This node has no owner yet, so there is no identity to link an account \
                     to. Claim the node first.",
                    )
                }
                Err(e) => {
                    return refuse(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "auth.oauth_link.store_unavailable",
                        format!("identity store unavailable: {e}"),
                    )
                }
            }
        }
    };

    // REFUSE a steal. If this pair already resolves to a DIFFERENT certificate,
    // linking would either silently move an identity between people or leave two
    // certs claiming one human. Mirrors the upstream ValueError.
    match store::get_by_oauth(&st.engine, &provider, &external_id).await {
        Ok(Some(other)) if other.wa_id != target.wa_id => {
            return refuse(
                StatusCode::CONFLICT,
                "auth.oauth_link.already_linked_elsewhere",
                format!(
                    "{provider} identity is already linked to {} on this node. \
                     Unlink it there first — one provider identity belongs to one certificate.",
                    other.wa_id
                ),
            );
        }
        Ok(_) => {}
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.oauth_link.store_unavailable",
                format!("identity store unavailable: {e}"),
            )
        }
    }

    // Merge into oauth_links, which is a LIST of link objects upstream
    // (`authority_core.py:39`). Re-linking updates in place rather than
    // appending a duplicate.
    let now = chrono::Utc::now();
    let mut links: Vec<serde_json::Value> = target
        .oauth_links
        .as_ref()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let mut changed = false;
    let mut found = false;
    for link in links.iter_mut() {
        let same = link.get("provider").and_then(|v| v.as_str()) == Some(provider.as_str())
            && link.get("external_id").and_then(|v| v.as_str()) == Some(external_id.as_str());
        if same {
            found = true;
            if let Some(obj) = link.as_object_mut() {
                if let Some(n) = &req.account_name {
                    obj.insert("account_name".into(), serde_json::json!(n));
                    changed = true;
                }
                if let Some(m) = &req.metadata {
                    obj.insert("metadata".into(), m.clone());
                    changed = true;
                }
                if obj.get("linked_at").is_none() {
                    obj.insert("linked_at".into(), serde_json::json!(now.to_rfc3339()));
                    changed = true;
                }
            }
            break;
        }
    }
    if !found {
        links.push(serde_json::json!({
            "provider": provider,
            "external_id": external_id,
            "account_name": req.account_name,
            "metadata": req.metadata.clone().unwrap_or_else(|| serde_json::json!({})),
            "linked_at": now.to_rfc3339(),
            "is_primary": req.primary,
        }));
        changed = true;
    }

    let mut cert = target.clone();
    cert.oauth_links = Some(serde_json::Value::Array(links.clone()));
    // Promote to the primary pair ONLY when asked, or when the cert has no
    // primary at all — an unset pair is not a decision to leave it unset, it is
    // a certificate nobody can sign into.
    let becomes_primary =
        req.primary || (cert.oauth_provider.is_none() && cert.oauth_external_id.is_none());
    if becomes_primary {
        cert.oauth_provider = Some(provider.clone());
        cert.oauth_external_id = Some(external_id.clone());
        changed = true;
    }

    if changed {
        if let Err(e) = store::upsert(&st.engine, cert).await {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth.oauth_link.store_unavailable",
                format!("could not write the link: {e}"),
            );
        }
    }
    tracing::info!(
        wa_id = %target.wa_id, provider = %provider, primary = becomes_primary, changed,
        "oauth identity linked to an existing certificate"
    );
    (
        StatusCode::OK,
        Json(LinkResponse {
            wa_id: target.wa_id,
            provider,
            linked: changed,
            is_primary: becomes_primary,
            links: serde_json::Value::Array(links),
        }),
    )
        .into_response()
}

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route(ROUTE, axum::routing::post(link_handler))
        .with_state(OAuthLinkState { engine })
}
