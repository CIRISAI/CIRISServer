//! **Portable software identity occurrence** — the owner's deliberate, labeled
//! trade-off: a fresh *software* hybrid keyset (Ed25519 + ML-DSA-65) that the
//! local TPM-bound primary authorizes as an **occurrence of the same self**, so a
//! second device can be recognized as "him" during the bootstrap period.
//!
//! The owner's federation identity is TPM-bound on this laptop — sealed,
//! non-exportable, so it cannot move to another device. This surface mints a
//! **portable software copy** (NOT a "backup" — the owner was specific about the
//! wording) written to a directory the owner picks (a USB key), and binds that new
//! software key as a genuine, primary-authorized active occurrence of the owner's
//! self. A software keyset is inherently insecure; that is the explicitly-accepted
//! trade-off, labeled as such in the UI + the on-disk manifest.
//!
//! Two endpoints, both **owner-gated** (the same `require_owner` SYSTEM_ADMIN +
//! FullAccess gate the other owner-only routes use) and **loopback-only** (wired in
//! `compose.rs`, matching `/v1/self/identity` + the accord-provision routes):
//!
//!   1. `POST /v1/self/occurrence/portable` — MINT a fresh Software hybrid keyset
//!      into `target_dir` and bind it as an occurrence of the owner's self.
//!   2. `POST /v1/self/associate` — INSTALL a portable keyset from `source_dir` as
//!      THIS device's active user fed-ID (so this device signs as that occurrence).
//!
//! ## Security model — how the new key becomes an occurrence of the self
//!
//! [`super::occurrence::bind_occurrence_core`] performs the three persist effects
//! (register_federation_key + put_identity_occurrence + rekey_self_occurrence_add),
//! exactly as the signed `POST /v1/self/occurrence` HTTP path does. The
//! authorization is discharged HERE before that call:
//!
//!   - The route is **owner-gated**: a live SYSTEM_ADMIN + FullAccess session IS
//!     the bound owner's login (`require_owner`).
//!   - The `identity_key_id` we bind under is resolved from
//!     `ownership::is_owner_bound(node)` — i.e. the owner's OWN primary fed-ID, not
//!     an attacker-supplied value.
//!   - We OPEN the local primary signer via
//!     `compose::resolve_user_signer(OwnerSession)` and assert its `key_id()` IS
//!     that `identity_key_id` — proving the node holds the primary that the new
//!     software key is being made an occurrence of. The owner authorizing an
//!     occurrence of their own self is the apex authority.
//!
//! After the mint+bind, `verify::signer_acts_for(engine, new_software_key_id,
//! identity_key_id) == true` — the integration test asserts exactly this.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::prelude::Engine;
use serde::Deserialize;

use crate::auth::ownership;
use crate::compose::{resolve_user_signer, FedIdUse};
use crate::ServerConfig;

/// State for the portable-occurrence routes.
#[derive(Clone)]
struct PortableState {
    engine: Arc<Engine>,
    /// THIS node's federation `key_id` — used to resolve the bound owner's self.
    node_key_id: String,
    /// The node config — the source of `keystore_alias` (the user alias prefix) and
    /// the conventional user seed dir, for minting + installing keysets.
    cfg: Arc<ServerConfig>,
}

fn http_err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// Owner gate — minting a portable copy of the owner's identity is an apex act.
/// Reuses the same SYSTEM_ADMIN + FullAccess session check the other owner-only
/// routes use (mirrors `identity::require_owner`).
async fn require_owner(engine: &Engine, headers: &HeaderMap) -> Result<(), Response> {
    use crate::auth::roles::{Permission, UserRole};
    use crate::auth::session::resolve_bearer;

    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(http_err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(engine, token).await {
        Ok(Some(caller))
            if caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(())
        }
        Ok(Some(_)) => Err(http_err(
            StatusCode::FORBIDDEN,
            "creating a portable software identity occurrence requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(http_err(
            StatusCode::UNAUTHORIZED,
            "invalid or expired session",
        )),
        Err(e) => Err(http_err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("store: {e}"),
        )),
    }
}

/// The owner's primary user alias (`<keystore_alias>-user`) — the keystore blob the
/// local primary signer re-opens under (matches `compose.rs` claim-remote wiring).
fn owner_user_alias(cfg: &ServerConfig) -> String {
    format!("{}-user", cfg.keystore_alias)
}

/// Resolve `(identity_key_id, primary_signer)` for the bound owner, PROVING the node
/// holds the primary whose self we are about to add an occurrence of. Returns a
/// ready error Response on any failure.
///
/// SECURITY: `identity_key_id` comes from `is_owner_bound(node)` (the durable
/// owner-binding), never the request. The primary signer is opened only under a
/// verified owner session (`FedIdUse::OwnerSession`), and we assert its `key_id()`
/// matches — so a portable occurrence can ONLY ever be minted against the owner's
/// own, locally-held primary.
async fn resolve_owner_primary(
    st: &PortableState,
) -> Result<(String, Arc<ciris_persist::prelude::LocalSigner>), Response> {
    let identity_key_id = match ownership::is_owner_bound(&st.engine, &st.node_key_id).await {
        Some(id) => id,
        None => {
            return Err(http_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "this node has no bound owner fed-ID yet — claim ownership (mint a fed-ID and \
                 bind it) before creating a portable occurrence of it",
            ))
        }
    };
    let alias = owner_user_alias(&st.cfg);
    let seed_dir = crate::user_seed_dir(&st.cfg);
    let signer =
        match resolve_user_signer(&st.engine, FedIdUse::OwnerSession, &alias, seed_dir).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return Err(http_err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the owner's primary fed-ID is not present on this node — cannot authorize a \
                 portable occurrence without the primary that anchors the self",
                ))
            }
            Err(e) => return Err(http_err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}"))),
        };
    // THE proof-of-possession check: the locally-held primary signer must BE the
    // bound owner's self. (Defense-in-depth; the alias re-open already targets the
    // owner's keystore blob, but we never bind under an id the node can't sign for.)
    if signer.key_id() != identity_key_id {
        return Err(http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "owner primary mismatch: bound owner is {identity_key_id} but the local primary \
                 signer is {} — refusing to bind a portable occurrence",
                signer.key_id()
            ),
        ));
    }
    Ok((identity_key_id, signer))
}

// ─── POST /v1/self/occurrence/portable (MINT + BIND) ──────────────────────────

/// `POST /v1/self/occurrence/portable` request — the one user choice is `target_dir`
/// (the USB directory the fresh software seeds land in).
#[derive(Debug, Deserialize)]
struct PortableRequest {
    /// The filesystem directory (a mounted USB folder) the fresh Software keyset is
    /// written to. The node does the file I/O — key material never crosses the wire.
    target_dir: String,
    /// Optional human display label flowed into the fedcode's alias hint.
    #[serde(default)]
    label: Option<String>,
}

async fn portable_handler(
    State(st): State<PortableState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st.engine, &headers).await {
        return resp;
    }
    let req: PortableRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return http_err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    let target = req.target_dir.trim();
    if target.is_empty() {
        return http_err(
            StatusCode::BAD_REQUEST,
            "target_dir must not be empty — insert your USB key and choose its folder",
        );
    }
    let target_dir = PathBuf::from(target);
    if let Err(e) = std::fs::create_dir_all(&target_dir) {
        return http_err(
            StatusCode::BAD_REQUEST,
            format!(
                "could not create / open the target directory {}: {e} — check the USB is mounted \
                 read-write",
                target_dir.display()
            ),
        );
    }

    // (1) Authorize: resolve the bound owner's self + PROVE the node holds its
    // primary. This is the security gate — see `resolve_owner_primary`.
    let (identity_key_id, _primary) = match resolve_owner_primary(&st).await {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    // (2) Mint a FRESH portable SOFTWARE hybrid keyset — BOTH seed halves land in
    //     the chosen directory (the USB), with a self-signed PoP record for the
    //     bind. NO private bytes cross the wire. The seeds are keyed by a stable
    //     ALIAS so a device re-opening them reproduces the SAME occurrence key_id;
    //     the label (or the owner alias) + a short unique suffix forms it, so
    //     multiple portable copies on one USB never collide.
    let base = req
        .label
        .clone()
        .map(|l| slug(&l))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| owner_user_alias(&st.cfg));
    let alias = format!("{base}-portable-{}", short_unique());
    let keyset = match crate::identity::mint_portable_software_occurrence(&target_dir, &alias).await
    {
        Ok(k) => k,
        Err(e) => {
            return http_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("mint portable software keyset: {e}"),
            )
        }
    };

    // (3) THE security-critical bind: register the fresh software key + make it an
    //     ACTIVE occurrence of the OWNER's self, authorized by the owner session +
    //     the locally-held primary proven above. Same three persist effects as the
    //     signed HTTP `add_occurrence`; the self-signed PoP record admits the key.
    if let Err(e) = crate::auth::occurrence::bind_occurrence_core(
        &st.engine,
        &identity_key_id,
        &keyset.key_id,
        "laptop",
        None,
        None,
        Some(keyset.key_record.clone()),
    )
    .await
    {
        return http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("bind portable key as an occurrence of the owner's self: {e}"),
        );
    }

    // (4) Write a human-readable manifest beside the seeds (NO private bytes).
    let mut files_written = keyset.files_written.clone();
    let manifest_path = target_dir.join("manifest.json");
    let manifest = serde_json::json!({
        "key_id": keyset.key_id,
        "fedcode": keyset.fedcode,
        "identity_type": keyset.identity_type,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "device_class": "portable_software",
        "note": "portable software identity occurrence — INSECURE software keyset",
    });
    match serde_json::to_vec_pretty(&manifest)
        .map_err(|e| e.to_string())
        .and_then(|b| std::fs::write(&manifest_path, b).map_err(|e| e.to_string()))
    {
        Ok(()) => files_written.push("manifest.json".to_string()),
        Err(e) => tracing::warn!(path = %manifest_path.display(), error = %e,
            "portable occurrence: could not write manifest.json (the keyset + binding succeeded)"),
    }

    tracing::info!(
        identity_key_id = %identity_key_id,
        occurrence_key_id = %keyset.key_id,
        target_dir = %target_dir.display(),
        "portable software identity occurrence minted + bound as an occurrence of the owner's self"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "key_id": keyset.key_id,
            "fedcode": keyset.fedcode,
            "target_dir": target_dir.display().to_string(),
            "device_class": "portable_software",
            "files_written": files_written,
        })),
    )
        .into_response()
}

// ─── POST /v1/self/associate (INSTALL as this device's fed-ID) ────────────────

/// `POST /v1/self/associate` request. Two shapes:
///   - directory: `{ source_dir }` — adopt a portable software keyset.
///   - yubikey: `{ yubikey: true, … }` — GATED (not yet implemented in this pass).
#[derive(Debug, Default, Deserialize)]
struct AssociateRequest {
    /// The directory a portable software keyset was written to (the USB folder).
    #[serde(default)]
    source_dir: Option<String>,
    /// Alternative: associate a YubiKey-backed fed-ID instead of a directory.
    /// GATED in this pass — see the handler.
    #[serde(default)]
    yubikey: bool,
}

async fn associate_handler(
    State(st): State<PortableState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st.engine, &headers).await {
        return resp;
    }
    let req: AssociateRequest = if body.is_empty() {
        AssociateRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => return http_err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
        }
    };

    if req.yubikey {
        // HONESTLY GATED: associating a YubiKey-backed fed-ID as THIS device's user
        // identity needs the on-device PKCS#11 read wired through here (the accord
        // provision path has the machinery, but adopting it as the *user fed-ID*
        // signer — re-keying the local primary to a token — is a deeper change than
        // this pass covers). Ship the directory path; gate the token branch clearly.
        return http_err(
            StatusCode::NOT_IMPLEMENTED,
            "associating a YubiKey-backed fed-ID is not yet implemented — use the directory \
             (source_dir) path to associate a portable software keyset for now",
        );
    }

    let Some(source) = req
        .source_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return http_err(
            StatusCode::BAD_REQUEST,
            "source_dir must not be empty — choose the folder holding the portable keyset",
        );
    };
    let source_dir = PathBuf::from(source);
    if !source_dir.is_dir() {
        return http_err(
            StatusCode::BAD_REQUEST,
            format!(
                "source_dir is not a directory: {} — insert the USB key and choose its folder",
                source_dir.display()
            ),
        );
    }

    // Find the portable keyset's ALIAS in source_dir (the `<alias>.ed25519.seed`
    // stem). The alias is what the install + re-open key on, so re-opening
    // reproduces the occurrence key_id.
    let alias = match crate::identity::find_portable_alias(&source_dir) {
        Ok(a) => a,
        Err(e) => return http_err(StatusCode::BAD_REQUEST, format!("{e}")),
    };

    // INSTALL: copy the Ed25519 seed + re-seal the ML-DSA half + write the `.backend`
    // marker into THIS node's user_seed_dir under the SAME alias, so the local user
    // signer re-opens as this occurrence (its key_id reproduces). (The keyset is
    // already a registered occurrence of the self from the portable-mint step, so
    // this device is recognized as the owner.)
    let dest_dir = crate::user_seed_dir(&st.cfg);
    if let Err(e) = std::fs::create_dir_all(&dest_dir) {
        return http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("create user seed dir {}: {e}", dest_dir.display()),
        );
    }
    match crate::identity::install_portable_software_keyset(&source_dir, &alias, &dest_dir) {
        Ok(installed) => {
            // Re-open under the alias to report the resolved occurrence key_id.
            let resolved_key_id = match crate::identity::hardware_user_local_signer(
                crate::identity::UserIdentityBackend::Software,
                &alias,
                dest_dir.clone(),
            )
            .await
            {
                Ok(s) => Some(s.key_id().to_string()),
                Err(e) => {
                    tracing::warn!(alias = %alias, error = %e,
                        "associate: installed but could not re-open to report the key_id");
                    None
                }
            };
            tracing::info!(
                alias = %alias,
                resolved_key_id = ?resolved_key_id,
                "associated a portable software keyset as this device's user fed-ID"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "alias": alias,
                    "associated_key_id": resolved_key_id,
                    "device_class": "portable_software",
                    "files_installed": installed,
                })),
            )
                .into_response()
        }
        Err(e) => http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("install portable keyset: {e}"),
        ),
    }
}

/// Slugify a human label into an alias-safe token (`[a-z0-9-]`), so a portable
/// keyset's seed filenames are filesystem-safe and the `key_id` derivation is
/// stable. Empty when the label has no usable chars.
fn slug(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut last_dash = false;
    for c in label.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// A short, unique-enough suffix (12 hex chars from random bytes) so two portable
/// copies minted under the same label/owner don't collide on one USB.
fn short_unique() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The portable-occurrence router — merge onto the read-API listener behind the
/// loopback guard (see `compose.rs`). Owner-gated per-handler.
pub fn router(engine: Arc<Engine>, node_key_id: String, cfg: Arc<ServerConfig>) -> Router {
    let state = PortableState {
        engine,
        node_key_id,
        cfg,
    };
    Router::new()
        .route(
            "/v1/self/occurrence/portable",
            axum::routing::post(portable_handler),
        )
        .route("/v1/self/associate", axum::routing::post(associate_handler))
        .with_state(state)
}
