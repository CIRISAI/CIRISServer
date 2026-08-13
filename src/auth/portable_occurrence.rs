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
//!     `ownership::is_steward_bound(node)` — i.e. the owner's OWN primary fed-ID, not
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
    /// The node config — the source of `keystore_alias` (the user alias prefix) and
    /// the conventional user seed dir, for minting + installing keysets.
    ///
    /// NOTE: read for the KEYSTORE alias and the seed dir only. `cfg.key_id` is
    /// never read here — this node's own signing identity comes from the engine
    /// (CIRISServer#372 Level 2).
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
    // Read the active-alias pointer the mint wrote (CIRISServer 0.5.59) so the
    // owner's portable occurrence resolves the signer under the user's CHOSEN name
    // (e.g. `eric-moore-v1`), not the conventional `<keystore_alias>-user`. Falls
    // back to the convention for a pre-pointer identity.
    crate::active_user_alias(
        &crate::user_seed_dir(cfg),
        &format!("{}-user", cfg.keystore_alias),
    )
}

/// Resolve `(identity_key_id, primary_signer)` for the bound owner, PROVING the node
/// holds the primary whose self we are about to add an occurrence of. Returns a
/// ready error Response on any failure.
///
/// SECURITY: `identity_key_id` comes from `is_steward_bound(node)` (the durable
/// owner-binding), never the request. The primary signer is opened only under a
/// verified owner session (`FedIdUse::OwnerSession`), and we assert its `key_id()`
/// matches — so a portable occurrence can ONLY ever be minted against the owner's
/// own, locally-held primary.
///
/// The `node` the owner-binding is looked up FOR is resolved from the engine
/// (CIRISServer#372 Level 2), not threaded in: "who owns this node" must be
/// asked about the key this node actually signs as, or a fold whose engine
/// identity differs from the CLI label would read a *different* node's
/// owner-binding and mint a portable copy of the wrong person's self.
async fn resolve_owner_primary(
    st: &PortableState,
) -> Result<(String, Arc<ciris_persist::prelude::LocalSigner>), Response> {
    let node_key_id = crate::self_identity::resolve(&st.engine, "auth::portable_occurrence")
        .await
        .map_err(|e| {
            http_err(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("{} ({e})", crate::self_identity::MESSAGE_TEXT),
            )
        })?;
    let identity_key_id = match ownership::is_steward_bound(&st.engine, &node_key_id).await {
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
    // THE proof-of-possession check: the locally-held signer must be able to ACT
    // FOR the bound owner's self — either it IS the primary, or it is an active
    // occurrence of it.
    //
    // An OCCURRENCE of the owner is the owner (CIRISServer#391). `signer_acts_for`
    // is the predicate — `signer == identity || signer is an ACTIVE occurrence of
    // it` — and comparing key ids directly is the identity-vs-occurrence axis
    // fused into one name. A device enrolled the CORRECT way holds its own fresh
    // key bound as an occurrence, so its `key_id()` is deliberately NOT the
    // identity's; an equality check refuses exactly the devices the umbrella model
    // exists to admit.
    if !crate::auth::verify::signer_acts_for(&st.engine, signer.key_id(), &identity_key_id).await {
        return Err(http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "owner primary mismatch: bound owner is {identity_key_id} and the local signer \
                 {} is neither that identity nor an active occurrence of it — refusing to bind \
                 a portable occurrence",
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
        // Self content-enc pubkeys derived from the portable seed (#151): admits this
        // occurrence into the self-DEK cascade so a restore of this keyset decrypts
        // the self's at-rest content. None only if the derive failed (excluded).
        keyset.encryption_pubkeys.clone(),
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

/// `POST /v1/self/associate` — **enrol THIS device as an occurrence of the
/// identity whose keyset is in `source_dir`.**
///
/// # What changed, and why (CIRISServer#391)
///
/// This used to COPY the Ed25519 seed off the USB onto this device and re-seal the
/// ML-DSA half into `keys_dir()`, so the identity's private half then existed in
/// two places. It was written as a last-resort recovery path and documented as
/// one — but nothing enforced that, and the first-run wizard's "import my existing
/// fed-ID" button called it. So the ORDINARY new-device flow was the
/// key-duplicating one, which is what makes `/v1/self/occurrence/revoke`
/// meaningless: revoking a shared key kills every device holding it.
///
/// It now does what the umbrella model always said: **mint a fresh key HERE, and
/// let the existing identity merely AUTHORIZE the binding.** A self is a roster of
/// `identity_occurrence` rows, and `signer_acts_for` treats any ACTIVE occurrence
/// as a full stand-in — so this device gets the identical privileges of the
/// identity, and gets them under a key only it holds. One device, one key,
/// separately revocable.
///
/// # The authorization
///
/// **Possession of the identity's private key IS the authorization** to enrol a
/// device under it. That is the same standard the mint path applies to the
/// locally-held primary (`resolve_owner_primary` proves possession and calls it
/// apex authority); here the primary is on the USB rather than in the keystore.
/// The consequence is deliberate and worth stating plainly: whoever holds the
/// keyset can enrol a device. That is what holding a private key means, and it is
/// why the seeds are read transiently, never written, and zeroized — see
/// [`crate::identity::open_portable_identity_transiently`].
async fn associate_handler(
    State(st): State<PortableState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Owner-gated ONCE the node is owned (enrolling another device is the owner's
    // own act). During first-run (no ROOT yet) there is no owner to authenticate
    // as, and enrolling the founder's identity is itself how the node becomes
    // owned — so the gate opens (the route is loopback-only). Mirrors
    // self_identity_handler / claim_remote_handler.
    if !crate::auth::bootstrap::is_first_run(&st.engine).await {
        if let Err(resp) = require_owner(&st.engine, &headers).await {
            return resp;
        }
    } else {
        tracing::info!(
            "associate: first-run (no ROOT) — enrolling this device under the supplied fed-ID \
             without an owner session (loopback-only)"
        );
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
        return http_err(
            StatusCode::NOT_IMPLEMENTED,
            "enrolling this device from a YubiKey-held fed-ID is not yet implemented — use the \
             directory (source_dir) path for a portable software keyset for now",
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

    // (1) Which identity is on the USB?
    let alias = match crate::identity::find_portable_alias(&source_dir) {
        Ok(a) => a,
        Err(e) => return http_err(StatusCode::BAD_REQUEST, format!("{e}")),
    };

    // (2) PROVE possession — open the keyset transiently. The seeds are read into
    //     memory, used to build the authorizing identity, and zeroized. Nothing is
    //     written to this device. This is the whole authorization.
    let authorizer = match crate::identity::open_portable_identity_transiently(&source_dir, &alias)
    {
        Ok(id) => id,
        Err(e) => return http_err(StatusCode::BAD_REQUEST, format!("{e}")),
    };
    let identity_key_id =
        ciris_verify_core::self_at_login::SelfSigner::key_id(&authorizer).to_string();

    // (3) Admit the identity's PUBLIC key if this node has never seen it (a fresh
    //     device has not). Public only — produced by the authorizer we just proved
    //     possession of, through the fail-secure registration gate.
    let known = match st
        .engine
        .federation_directory()
        .lookup_public_key(&identity_key_id)
        .await
    {
        Ok(k) => k.is_some(),
        Err(e) => return http_err(StatusCode::SERVICE_UNAVAILABLE, format!("directory: {e}")),
    };
    if !known {
        let now = chrono::Utc::now().to_rfc3339();
        let v_rec = match ciris_verify_core::federation_self_record::produce_self_key_record(
            &authorizer,
            ciris_persist::federation::types::identity_type::USER,
            &now,
            &[],
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                return http_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("produce the identity's self-signed record: {e}"),
                )
            }
        };
        let signed: ciris_persist::federation::SignedKeyRecord =
            match serde_json::to_value(&v_rec).and_then(serde_json::from_value) {
                Ok(r) => r,
                Err(e) => {
                    return http_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("bridge verify->persist SignedKeyRecord: {e}"),
                    )
                }
            };
        if let Err(e) = st.engine.register_federation_key(signed).await {
            return http_err(
                StatusCode::BAD_REQUEST,
                format!("admit the identity's public key: {e}"),
            );
        }
    }

    // (4) Mint a FRESH keyset for THIS device, in this node's own seed dir. This is
    //     the key the device will sign as, and the only device that will ever hold
    //     it — which is what makes revoking this one device possible.
    let dest_dir = crate::user_seed_dir(&st.cfg);
    let device_alias = format!("{alias}-device-{}", short_unique());
    let keyset =
        match crate::identity::mint_portable_software_occurrence(&dest_dir, &device_alias).await {
            Ok(k) => k,
            Err(e) => {
                return http_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("mint this device's occurrence keyset: {e}"),
                )
            }
        };

    // (5) BIND it as an active occurrence of the identity — the three persist
    //     effects (register + put_identity_occurrence + self-DEK cascade). After
    //     this, `signer_acts_for(device_key, identity) == true`, so this device
    //     holds the identity's full privileges.
    if let Err(e) = crate::auth::occurrence::bind_occurrence_core(
        &st.engine,
        &identity_key_id,
        &keyset.key_id,
        "portable_software",
        None,
        keyset.encryption_pubkeys.clone(),
        Some(keyset.key_record.clone()),
    )
    .await
    {
        return http_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("bind this device as an occurrence of {identity_key_id}: {e}"),
        );
    }

    // (6) Point this device's active user alias at ITS OWN keyset, so claim-remote
    //     / upgrade-owner / set-age (all resolve the alias at request time) operate
    //     as this occurrence — which acts for the identity.
    if let Err(e) = crate::write_active_user_alias(&dest_dir, &device_alias) {
        tracing::warn!(error = %e, alias = %device_alias,
            "associate: could not record active_user_alias pointer — owner-signer resolution may fall back to <node>-user");
    }

    tracing::info!(
        identity_key_id = %identity_key_id,
        occurrence_key_id = %keyset.key_id,
        device_alias = %device_alias,
        "enrolled this device as an OCCURRENCE of {identity_key_id} — a fresh key was minted \
         here and the supplied keyset only authorized the binding. No private key material was \
         copied (CIRISServer#391)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "alias": device_alias,
            "identity_key_id": identity_key_id,
            "associated_key_id": keyset.key_id,
            "device_class": "portable_software",
            // The wire contract keeps this key; it now names what was MINTED here
            // rather than what was copied, and copying is no longer a thing that
            // happens.
            "files_installed": keyset.files_written,
        })),
    )
        .into_response()
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
    ciris_crypto::random::fill(&mut b).expect("CSPRNG for occurrence suffix");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn router(engine: Arc<Engine>, cfg: Arc<ServerConfig>) -> Router {
    let state = PortableState { engine, cfg };
    Router::new()
        .route(
            "/v1/self/occurrence/portable",
            axum::routing::post(portable_handler),
        )
        .route("/v1/self/associate", axum::routing::post(associate_handler))
        .with_state(state)
}
