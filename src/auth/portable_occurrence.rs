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
/// Owner gate for the occurrence surfaces.
///
/// **Refuses a delegated session.** An ACTIVE occurrence of the owner's self IS
/// the owner to every signature gate (`verify::signer_acts_for`), so minting one
/// hands out a key that outranks any delegation and outlives it. In the fold
/// topology the agent shares the node's host and therefore passes
/// `require_loopback`, so loopback-gating is not the boundary here — this is.
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
            // A DELEGATE MAY NOT DO THIS. `resolve_bearer` hands a `dgrant:`
            // token the owner's role and FullAccess by design — that is what
            // makes a delegation useful — so role alone does not distinguish the
            // owner from someone acting for them. `/v1/accord/*` and
            // `/v1/auth/device/*` both exclude delegated actors this way; the
            // omission here was what made those two readable as policy rather
            // than accident.
        Ok(Some(caller)) if caller.actor.is_some() => Err(http_err(
            StatusCode::FORBIDDEN,
            "minting or enrolling an occurrence of the owner's self is the owner's own act and \
             is not delegatable — an active occurrence IS the identity to every signature gate, \
             so it would outrank and outlive the grant that asked for it",
        )),
        Ok(Some(caller))
            if caller.actor.is_none()
                && caller.role == UserRole::SystemAdmin
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

/// `POST /v1/self/associate` request. Two shapes, one flow:
///   - directory: `{ source_dir }` — a portable SOFTWARE keyset (both seeds on
///     a USB folder).
///   - yubikey: `{ yubikey: true, key_id, mldsa_usb_dir, pkcs11? }` — a
///     HARDWARE-custodied fed-ID: the Ed25519 half on the token, the ML-DSA-65
///     half AEAD-wrapped on a USB key under the token's own signature
///     (CIRISServer#618).
///
/// Both resolve to a `&dyn SelfSigner` and the rest of the handler is
/// identical — the authorization is possession, and possession is proven the
/// same way whether the key is a seed on a stick or a token that signs.
#[derive(Debug, Default, Deserialize)]
struct AssociateRequest {
    /// The directory a portable software keyset was written to (the USB folder).
    #[serde(default)]
    source_dir: Option<String>,
    /// Enrol from a YubiKey-held fed-ID instead of a directory.
    #[serde(default)]
    yubikey: bool,
    /// YubiKey shape: the identity's federation `key_id` — WHICH identity on
    /// the token this device is being enrolled under. Required, and checked
    /// against the inserted token before a PIN attempt is spent.
    #[serde(default)]
    key_id: Option<String>,
    /// YubiKey shape: the USB folder holding the AEAD-wrapped ML-DSA-65 seed.
    ///
    /// The token carries the CLASSICAL half only — no PKCS#11 token performs
    /// ML-DSA-65 — so the post-quantum half travels on a USB key, wrapped under
    /// a key derived from the token's deterministic signature over a
    /// domain-separated challenge. Unwrapping needs BOTH (touch + PIN), and the
    /// token gains no decrypt capability (`ciris_keyring::usb_wrapped_mldsa65`).
    /// This is the same portable hardware custody the accord-holder flow uses.
    #[serde(default)]
    mldsa_usb_dir: Option<String>,
    /// Hardware shape: PIN / PIV slot / module path, exactly as
    /// `POST /v1/accord/provision-holder` takes them (slot defaults to `9c`).
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
    /// Hardware shape: custody of the CLASSICAL (Ed25519) half —
    /// `yubikey` | `tpm` | `software`. Defaults to `yubikey` (the only reason
    /// to take this arm at all); `yubikey: true` is the legacy spelling.
    #[serde(default)]
    classical: Option<String>,
    /// Hardware shape: custody of the POST-QUANTUM (ML-DSA-65) half —
    /// `usb` | `tpm` | `software`. Defaults to `usb` when `mldsa_usb_dir` is
    /// given, else `tpm`. INDEPENDENT of the classical half: a token for the
    /// classical half with the PQC half sealed on this host is the ordinary
    /// laptop case, and `usb` is the portable high-secure one.
    #[serde(default)]
    pqc: Option<String>,
    /// The custody of the DEVICE key this enrolment MINTS — `tpm` seals its
    /// classical half to this host (nothing at rest in the clear), `software`
    /// writes a seed file. Default `software`, which is today's behaviour; see
    /// `identity::DeviceCustody` for why `tpm` is not yet the default.
    ///
    /// Independent of every field above: those say who AUTHORIZES, this says
    /// what the device will hold afterwards. A manager-client enrolled from a
    /// portable keypair on a USB stick wants `device: "tpm"` — the authorizing
    /// keypair stays on the stick, the key this host acts with is sealed here.
    #[serde(default)]
    device: Option<String>,
    /// Hardware shape: where a `tpm` / `software` half lives. Defaults to THIS
    /// home's user-seed directory (`<home>/identity/user`), which is what makes
    /// a dedicated `--home` a dedicated identity: the TPM-sealed master is
    /// `{alias}.tpmplugin_seal` INSIDE that directory, so two homes never share
    /// sealed material or collide on an alias.
    #[serde(default)]
    seed_dir: Option<String>,
}

/// The DIRECTORY arm's authorizer: a portable SOFTWARE keyset on a USB folder.
///
/// Reads both seeds transiently, builds the hybrid identity, zeroizes. Nothing
/// is written to this device; possession is the authorization and this is how
/// it is proven without persisting it.
fn open_directory_authorizer(
    req: &AssociateRequest,
) -> Result<ciris_verify_core::self_at_login::HybridSigningIdentity, Box<Response>> {
    let Some(source) = req
        .source_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(Box::new(http_err(
            StatusCode::BAD_REQUEST,
            "source_dir must not be empty — choose the folder holding the portable keyset \
             (or pass yubikey:true with key_id + mldsa_usb_dir to enrol from a token)",
        )));
    };
    let source_dir = PathBuf::from(source);
    if !source_dir.is_dir() {
        return Err(Box::new(http_err(
            StatusCode::BAD_REQUEST,
            format!(
                "source_dir is not a directory: {} — insert the USB key and choose its folder",
                source_dir.display()
            ),
        )));
    }
    let alias = crate::identity::find_portable_alias(&source_dir)
        .map_err(|e| Box::new(http_err(StatusCode::BAD_REQUEST, format!("{e}"))))?;
    crate::identity::open_portable_identity_transiently(&source_dir, &alias)
        .map_err(|e| Box::new(http_err(StatusCode::BAD_REQUEST, format!("{e}"))))
}

/// The HARDWARE arm's authorizer — **the custody MATRIX** (CIRISServer#618).
///
/// A federation identity is two keys, and their custodies are INDEPENDENT.
/// Nothing binds them together: `HardwareRootedIdentity` takes
/// `Arc<dyn HardwareSigner>` and `Arc<dyn PqcSigner>`, the wire bytes are
/// identical whichever each one is, and verify's own doc says so. So this
/// resolves them separately and composes:
///
/// | | classical (Ed25519) | post-quantum (ML-DSA-65) |
/// |---|---|---|
/// | `yubikey` / `pkcs11` | PIV slot, `C_Sign` on the token, never exported | — no token does ML-DSA |
/// | `tpm` / `platform-sealed` | TPM/SE-sealed seed on this host | TPM/SE-sealed seed on this host |
/// | `software` | seed file in a directory | seed file in a directory |
/// | `usb` | — | AEAD-wrapped on a USB key, unwrappable only WITH the token |
///
/// So `yubikey + usb` is the high-secure portable pair the accord-holder flow
/// uses, and it is one cell, not the shape. `yubikey + tpm` (token for the
/// classical half, this host's sealed store for the PQC half) is the ordinary
/// laptop case; `tpm + tpm` is a machine with no token; `yubikey + software`
/// is a dev box. Each combination is honest about what it is, and the response
/// names the pair so nobody has to infer the custody from the request.
///
/// The PQC half cannot be derived from the token — no PKCS#11 token performs
/// ML-DSA-65 — so SOMETHING must supply it, and refusing to guess is why the
/// arms are named rather than defaulted. What is NOT acceptable is silently
/// proceeding classical-only: step (3) registers the identity with a
/// self-signed HYBRID record and verify refuses a classical-only registration
/// at the #425 gate (the unbound-owner-record arc, CIRISServer#606).
///
/// Nothing is copied onto this host either way: the halves authorize, and step
/// (4) mints a FRESH device key whose private half only this device holds.
async fn open_hardware_authorizer(
    req: &AssociateRequest,
    cfg: &ServerConfig,
) -> Result<
    (
        ciris_verify_core::self_at_login::HardwareRootedIdentity,
        String,
    ),
    Box<Response>,
> {
    use std::sync::Arc;

    use ciris_keyring::PqcSigner;
    use ciris_verify_core::self_at_login::HardwareRootedIdentity;

    let bad = |msg: String| -> Box<Response> { Box::new(http_err(StatusCode::BAD_REQUEST, msg)) };

    let Some(key_id) = req
        .key_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Err(bad(
            "key_id is required — name WHICH identity this device is being enrolled under \
             (the fed-ID's key_id, from `ciris-server identity create` or GET \
             /v1/federation/identity on the device that minted it)"
                .into(),
        ));
    };

    // ── ARGUMENTS FIRST, HARDWARE SECOND ────────────────────────────────────
    //
    // Every custody name and every required path is checked BEFORE the token is
    // opened, because opening it spends a PIN attempt (and a touch): a request
    // that was malformed anyway must not cost the operator one of five tries.
    // The accord flow learned this as `piv_preflight_matches_holder` ("No PIN
    // attempt has been spent"); this is the same rule for the argument shape.
    // Found by the test below, which asked for `pqc:"usb"` with no folder on a
    // box with no reader and got the TOKEN's error back.
    let classical_name = req.classical.as_deref().map_or("yubikey", str::trim);
    if !matches!(
        classical_name,
        "yubikey" | "pkcs11" | "tpm" | "platform-sealed" | "platform_sealed" | "software"
    ) {
        return Err(bad(format!(
            "unknown classical custody {classical_name:?} — use yubikey | tpm | software"
        )));
    }
    let pqc_name = req.pqc.as_deref().map(str::trim).unwrap_or({
        if req.mldsa_usb_dir.is_some() {
            "usb"
        } else {
            "tpm"
        }
    });
    if !matches!(
        pqc_name,
        "usb" | "tpm" | "platform-sealed" | "platform_sealed" | "software"
    ) {
        return Err(bad(format!(
            "unknown pqc custody {pqc_name:?} — use usb | tpm | software"
        )));
    }
    let usb_dir: Option<&str> = req
        .mldsa_usb_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if pqc_name == "usb" {
        let Some(dir) = usb_dir else {
            return Err(bad(
                "pqc:\"usb\" needs mldsa_usb_dir — the folder holding the ML-DSA-65 seed \
                 wrapped under this token's own signature. Nothing was asked of the token"
                    .into(),
            ));
        };
        // The PATH too, not just the string: an unmounted stick or a typo would
        // otherwise be discovered after the token had been opened and a PIN
        // attempt spent (Codex review on PR #620). The directory arm and the
        // accord path both check this before they touch anything.
        if !std::path::Path::new(dir).is_dir() {
            return Err(bad(format!(
                "mldsa_usb_dir is not a directory: {dir} — insert the USB key and name its \
                 folder. Nothing was asked of the token"
            )));
        }
    }

    // ── the POST-QUANTUM half, WHEN IT DOES NOT NEED THE TOKEN ──────────────
    //
    // `tpm` and `software` read local material and depend on nothing the token
    // provides, so they are resolved BEFORE it is opened: a missing or corrupt
    // local half would otherwise cost a PIN interaction to discover, for a
    // request that was going to fail either way (Codex review on PR #620). Only
    // `usb` is ordered after the classical open, because its wrap key IS the
    // token's signature.
    let local_mldsa: Option<Arc<dyn PqcSigner>> = if pqc_name == "usb" {
        None
    } else {
        Some(match pqc_name {
            "tpm" | "platform-sealed" | "platform_sealed" => {
                let seed_dir = pqc_or_seed_dir(req, cfg);
                match ciris_keyring::get_platform_sealed_mldsa65_signer(key_id, seed_dir.clone()) {
                    Ok(s) => Arc::from(s),
                    Err(e) => {
                        return Err(bad(format!(
                            "no TPM/SE-sealed ML-DSA-65 for {key_id} in {}: {e} — a token carries \
                         the classical half only, so the post-quantum half must be sealed on \
                         this host (pqc:\"tpm\"), wrapped on a USB (pqc:\"usb\" + \
                         mldsa_usb_dir), or a seed file (pqc:\"software\"). It is never \
                         derived from the token, and enrolling without it would register a \
                         classical-only identity that verify refuses",
                            seed_dir.display()
                        )))
                    }
                }
            }
            "software" => {
                let seed_dir = pqc_or_seed_dir(req, cfg);
                let path = seed_dir.join(format!("{key_id}.mldsa65.seed"));
                match ciris_keyring::MlDsa65SoftwareSigner::from_seed_file(path.clone(), key_id) {
                    Ok(s) => Arc::new(s) as Arc<dyn PqcSigner>,
                    Err(e) => {
                        return Err(bad(format!(
                            "no ML-DSA-65 seed file at {}: {e}",
                            path.display()
                        )))
                    }
                }
            }
            // Unreachable: checked above, before anything was touched.
            other => {
                return Err(bad(format!(
                    "unknown pqc custody {other:?} — use usb | tpm | software"
                )))
            }
        })
    };

    // ── the CLASSICAL half ──────────────────────────────────────────────────
    let ed: Arc<dyn ciris_keyring::HardwareSigner> = match classical_name {
        "yubikey" | "pkcs11" => {
            let piv_slot = req
                .pkcs11
                .piv_slot
                .clone()
                .unwrap_or_else(|| crate::identity::DEFAULT_PIV_SLOT.to_string());
            let opts = crate::identity::Pkcs11Options {
                piv_slot,
                module_path: req
                    .pkcs11
                    .module_path
                    .clone()
                    .map_or_else(crate::identity::default_ykcs11_module, Into::into),
                user_pin: req.pkcs11.user_pin.clone(),
                ..crate::identity::Pkcs11Options::default()
            };
            match crate::identity::open_yubikey_ed25519_signer(opts) {
                Ok(s) => Arc::from(s),
                // A build without the `pkcs11` feature cannot open ANY token, which
                // is a property of the server, not of the request: 501, exactly as
                // the accord endpoints answer and as this route answered before
                // #618. Anything else is the operator's to fix: 400.
                Err(e) if e.to_string().contains("not supported") => {
                    return Err(Box::new(http_err(
                        StatusCode::NOT_IMPLEMENTED,
                        format!(
                            "this server was built without the `pkcs11` feature, so it cannot \
                             open a hardware token: {e}"
                        ),
                    )))
                }
                Err(e) => {
                    return Err(bad(format!(
                        "could not open the token's PIV key for {key_id}: {e} — check the \
                         YubiKey is inserted, the slot provisioned, and the PIN correct"
                    )))
                }
            }
        }
        "tpm" | "platform-sealed" | "platform_sealed" => {
            let backend = crate::identity::UserIdentityBackend::PlatformSealed;
            let seed_dir = pqc_or_seed_dir(req, cfg);
            let ucfg = crate::identity::user_identity_config(&backend, key_id, seed_dir.clone());
            match crate::identity::open_user_signer(&backend, &ucfg, false) {
                Ok(s) => Arc::from(s),
                Err(e) => {
                    return Err(bad(format!(
                        "no TPM/SE-sealed Ed25519 for {key_id} in {}: {e} — this host must \
                         already hold that identity's sealed classical half (it is not \
                         re-sealed here; that is what makes it non-portable)",
                        seed_dir.display()
                    )))
                }
            }
        }
        "software" => {
            let backend = crate::identity::UserIdentityBackend::Software;
            let seed_dir = pqc_or_seed_dir(req, cfg);
            // EXISTENCE FIRST. `open_user_signer` delegates software custody to
            // `open_software_ed25519_signer`, which MINTS a random seed when the
            // file is absent — `create: false` does not reach it. A path meant to
            // PROVE possession must never manufacture the thing it is proving
            // (Codex review on PR #620); without this, a typo'd key_id would
            // silently enrol a brand-new identity and leave an orphan seed.
            let seed_path = seed_dir.join(format!("{key_id}.ed25519.seed"));
            if !seed_path.is_file() {
                return Err(bad(format!(
                    "no software Ed25519 seed for {key_id} at {} — this arm opens an existing \
                     key, it never mints one",
                    seed_path.display()
                )));
            }
            let ucfg = crate::identity::user_identity_config(&backend, key_id, seed_dir.clone());
            match crate::identity::open_user_signer(&backend, &ucfg, false) {
                Ok(s) => Arc::from(s),
                Err(e) => {
                    return Err(bad(format!(
                        "no software Ed25519 seed for {key_id} in {}: {e}",
                        seed_dir.display()
                    )))
                }
            }
        }
        // Unreachable: the name was checked above, before the token was touched.
        other => {
            return Err(bad(format!(
                "unknown classical custody {other:?} — use yubikey | tpm | software"
            )))
        }
    };

    // ── the POST-QUANTUM half ───────────────────────────────────────────────
    //
    // ── the POST-QUANTUM half, WHEN IT DOES need the token ──────────────────
    let mldsa: Arc<dyn PqcSigner> = match local_mldsa {
        Some(m) => m,
        None => {
            let usb = usb_dir.unwrap_or_default();
            match ciris_keyring::usb_wrapped_mldsa65::UsbWrappedMlDsa65Signer::open(
                ed.as_ref(),
                key_id,
                std::path::PathBuf::from(usb),
            )
            .await
            {
                Ok(s) => Arc::new(s) as Arc<dyn PqcSigner>,
                Err(e) => {
                    return Err(bad(format!(
                        "could not unwrap the ML-DSA-65 half from {usb}: {e} — the wrap is \
                         bound to THIS token (touch + PIN), so check the USB is the one \
                         provisioned with {key_id} and the same token is inserted"
                    )))
                }
            }
        }
    };

    // THE LABEL COMES FROM BOTH SIGNERS, not from the request's words. A sealed
    // half falls back to encrypted software where there is no TPM/SE and says
    // so through `hardware_type()`; echoing the request would report
    // software-custodied material as `tpm` in the log and on the wire (Codex
    // review on PR #620, twice — once per half).
    let label = format!(
        "{}+{}",
        custody_word(ed.hardware_type(), classical_name),
        custody_word(mldsa.hardware_type(), pqc_name)
    );

    let id = HardwareRootedIdentity::new(key_id, ed, mldsa).map_err(|e| {
        bad(format!(
            "compose the hardware-rooted identity for {key_id}: {e}"
        ))
    })?;
    Ok((id, label))
}

/// The honest custody word for one half: what the SIGNER reports, falling back
/// to the requested name only when the signer says "hardware" and cannot say
/// which kind. `SoftwareOnly` always wins — a seal that degraded to encrypted
/// software is software, whatever was asked for.
fn custody_word(actual: ciris_keyring::HardwareType, asked: &str) -> &str {
    match actual {
        ciris_keyring::HardwareType::SoftwareOnly => "software",
        _ => asked,
    }
}

/// Where a `tpm` / `software` half is read from: the caller's `seed_dir` when
/// given, else this node's conventional user-seed directory — the same path
/// `resolve_user_signer` uses, so "the identity this host already holds" means
/// one directory and not two.
fn pqc_or_seed_dir(req: &AssociateRequest, cfg: &ServerConfig) -> PathBuf {
    req.seed_dir
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| crate::user_seed_dir(cfg), PathBuf::from)
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
/// # Two custodies (CIRISServer#618)
///
/// - `{ source_dir }` — a portable SOFTWARE keyset: both seeds on a USB folder,
///   read transiently and zeroized.
/// - `{ yubikey: true, key_id, mldsa_usb_dir, pkcs11? }` — HARDWARE custody:
///   the Ed25519 half signs on the token (`C_Sign`, never exported), the
///   ML-DSA-65 half is AEAD-wrapped on a USB key under the token's own
///   deterministic signature, so unwrapping needs both plus touch + PIN. This
///   arm returned 501 from v0.5.43 until #618, which forced a hardware-held
///   fed-ID through a software keyset to reach this endpoint — the one artifact
///   the token exists to avoid.
///
/// Both arms end at a `&dyn SelfSigner`; everything after the open is identical,
/// which is the point — the authorization is possession, and a token proves it
/// by signing exactly as a seed does.
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

    // THE DEVICE CUSTODY IS PARSED FIRST. A typo like `device:"tpn"` used to be
    // discovered after the authorizer had been opened — a YubiKey PIN and touch
    // spent, and for an unknown identity a self-signed record already registered
    // into the federation directory — before answering 400 (Codex review on
    // PR #620). Nothing is opened, signed or written until every argument has
    // been read.

    let device_custody = match req.device.as_deref().map(str::trim) {
        None | Some("software") => crate::identity::DeviceCustody::Software,
        Some("tpm" | "platform-sealed" | "platform_sealed") => {
            crate::identity::DeviceCustody::PlatformSealed
        }
        Some(other) => {
            return http_err(
                StatusCode::BAD_REQUEST,
                format!("unknown device custody {other:?} — use tpm | software"),
            )
        }
    };

    // ── (1+2) WHICH identity, and PROVE possession of it ────────────────────
    //
    // Two custodies, one authorization. Both arms end at a `&dyn SelfSigner`
    // that can produce a HYBRID signature, which is the whole requirement:
    // step (3) below registers the identity's public key with a self-signed
    // record, and a classical-only signer cannot make one (verify refuses it
    // at the #425 gate — the unbound-owner-record arc, CIRISServer#606).
    let (authorizer, custody): (
        Box<dyn ciris_verify_core::self_at_login::SelfSigner>,
        String,
    ) = if req.yubikey
        || req.classical.is_some()
        || req.pqc.is_some()
        || req.mldsa_usb_dir.is_some()
        || (req.key_id.is_some() && req.source_dir.is_none())
    {
        match open_hardware_authorizer(&req, &st.cfg).await {
            Ok((id, label)) => (
                Box::new(id) as Box<dyn ciris_verify_core::self_at_login::SelfSigner>,
                label,
            ),
            Err(resp) => return *resp,
        }
    } else {
        match open_directory_authorizer(&req) {
            Ok(id) => (
                Box::new(id) as Box<dyn ciris_verify_core::self_at_login::SelfSigner>,
                "portable_software".to_string(),
            ),
            Err(resp) => return *resp,
        }
    };
    let supplied_key_id = authorizer.key_id().to_string();

    // WHICH identity is this device being enrolled under? (CIRISServer#401)
    //
    // If the supplied keyset is itself an OCCURRENCE of some parent self — which
    // is exactly what `/v1/self/occurrence/portable` produces — then binding under
    // the keyset's own key builds `new_device -> occurrence`, and
    // `signer_acts_for` walks ONE level: it asks whether the signer is in
    // `list_identity_occurrences_active(identity)`, not whether some chain reaches
    // it. So the new device would inherit none of the parent's standing while
    // looking enrolled.
    //
    // The parent cannot be discovered here. There is no reverse
    // (occurrence -> identity) lookup in the substrate — `list_identity_occurrences_for`
    // is forward-only — and a fresh device's directory is empty by definition. Nor
    // may the parent be TAKEN FROM the artifact on trust: a manifest claiming
    // `"parent": "<someone else>"` beside an attacker's own keyset would enrol a
    // device holding that person's standing. The claim has to be PROVEN, and today
    // the mint writes no proof (the local bind stores NULL signature columns, so
    // there is no signed parent->occurrence row to carry).
    //
    // So this binds under the key it can actually verify — the one it just proved
    // possession of — and the response says which, rather than implying an
    // inheritance that did not happen. CIRISServer#401 carries the artifact change:
    // the mint emits a signed parent->occurrence attestation into the keyset folder,
    // and this path verifies it and binds under the attester.
    let identity_key_id = supplied_key_id.clone();

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
            &*authorizer,
            ciris_persist::federation::types::identity_type::USER,
            &now,
            None,
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
    // Named after the IDENTITY, not the source artifact: the directory arm used
    // the USB folder's alias, which the token arm has no equivalent of (a token
    // names slots, not aliases). `slug` of the identity's key_id is stable across
    // both custodies and is what a second device under the same identity reads
    // as, which is the point of the name.
    let device_alias = format!("{}-device-{}", slug(&supplied_key_id), short_unique());
    let keyset = match crate::identity::mint_local_device_occurrence_with(
        &dest_dir,
        &device_alias,
        device_custody,
    )
    .await
    {
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
        // `laptop`, from persist's CLOSED set (§5.6.8.8:
        // phone|laptop|server|embedded|agent|service). This passed
        // `"portable_software"` — not in the set — so `check_device_class`
        // refused and the route answered 500 AFTER minting and registering the
        // occurrence key, leaving an orphan. Latent on main and untested end to
        // end; the response object next to it had already been corrected to
        // `laptop` and the bind was left behind (Codex review on PR #620).
        crate::auth::occurrence::DEVICE_CLASS_LAPTOP,
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
        authorized_by = %custody,
        "enrolled this device as an OCCURRENCE of {identity_key_id} — a fresh key was minted \
         here and the supplied keyset only authorized the binding. No private key material was \
         copied (CIRISServer#391). NOTE: if that keyset is itself an occurrence of a parent \
         self, this device does NOT inherit the parent's standing — the parent binding is not \
         carried in the artifact and cannot be proven here (CIRISServer#401)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "alias": device_alias,
            "identity_key_id": identity_key_id,
            // Stated explicitly so a caller cannot read "enrolled" as "inherited
            // everything the supplied fed-ID has". This device acts for the key
            // named above and for nothing further up a chain — see #405.
            "acts_for": identity_key_id,
            "associated_key_id": keyset.key_id,
            // What was actually BOUND. The old value named a class persist does
            // not accept — nothing noticed, because that path bound nothing.
            "device_class": "laptop",
            // WHICH custody authorized this enrolment: `yubikey+usb` (the
            // identity's classical half never left the token) or
            // `portable_software` (a software keyset existed on a USB and is
            // as secure as that USB was). The operator asked for one of them;
            // the response says which one answered (CIRISServer#618).
            "authorized_by": custody,
            // And what this device now HOLDS — the other axis. `tpm` means the
            // classical half is sealed to this host with no seed at rest;
            // `software` means a seed file. Reported because "enrolled" says
            // nothing about what the enrolled key is (CIRISServer#621).
            "device_custody": match keyset.device_hardware_type {
                // What the SEAL is, not what was asked for:
                // `SealedEd25519Signer::open_or_create` falls back to encrypted
                // software where there is no TPM/SE, and reporting `tpm` anyway
                // would let an audit log call a software-custodied occurrence
                // hardware-backed (Codex review on PR #620).
                Some(ciris_keyring::HardwareType::SoftwareOnly) | None => "software",
                Some(_) => "tpm",
            },
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

#[cfg(test)]
mod custody_matrix_tests {
    use super::*;

    /// A `ServerConfig` rooted at a throwaway home — which is also the point of
    /// CIRISServer#618's `seed_dir` default: identity material lives under the
    /// HOME, so a dedicated `--home` is a dedicated, isolated identity (the
    /// TPM-sealed master is `{alias}.tpmplugin_seal` inside that directory).
    fn cfg_at(tag: &str) -> ServerConfig {
        let home = std::env::temp_dir().join(format!(
            "ciris-custody-{tag}-{}-{}",
            std::process::id(),
            short_unique()
        ));
        std::fs::create_dir_all(&home).expect("temp home");
        ServerConfig::from_home(home, "test-node".into()).expect("config from home")
    }

    /// The refusal's TEXT is the contract here — an operator reads it and knows
    /// which half is missing — so the assertions are on the words, not the code.
    /// (`HardwareRootedIdentity` has no `Debug`, so the openers' results are
    /// matched rather than `expect_err`'d.)
    async fn refusal_of(req: &AssociateRequest, cfg: &ServerConfig) -> String {
        match open_hardware_authorizer(req, cfg).await {
            Ok(_) => panic!("expected a refusal, got an identity"),
            Err(resp) => {
                let bytes = axum::body::to_bytes((*resp).into_body(), 64 * 1024)
                    .await
                    .expect("read body");
                String::from_utf8_lossy(&bytes).into_owned()
            }
        }
    }

    /// No `key_id` → say which identity is missing, never guess one from the
    /// node's own alias (enrolling under the wrong self is unrecoverable).
    #[tokio::test]
    async fn the_hardware_arm_refuses_without_an_identity_to_enrol_under() {
        let req = AssociateRequest {
            yubikey: true,
            ..AssociateRequest::default()
        };
        let body = refusal_of(&req, &cfg_at("no-key-id")).await;
        assert!(
            body.contains("key_id is required"),
            "the refusal names the missing field: {body}"
        );
    }

    /// `pqc: "usb"` with no folder → name the folder. The token carries the
    /// classical half ONLY; enrolling without the PQC half would register a
    /// classical-only identity that verify refuses at the #425 gate.
    #[tokio::test]
    async fn the_usb_pqc_arm_refuses_without_a_folder() {
        let req = AssociateRequest {
            yubikey: true,
            key_id: Some("somebody-v1-abcdef".into()),
            pqc: Some("usb".into()),
            ..AssociateRequest::default()
        };
        let body = refusal_of(&req, &cfg_at("usb-no-dir")).await;
        assert!(
            body.contains("mldsa_usb_dir"),
            "the refusal names the folder it needs: {body}"
        );
    }

    /// An unknown custody is refused WITH the closed set — never defaulted to a
    /// weaker one, which is the whole failure mode this arm exists to avoid.
    #[tokio::test]
    async fn an_unknown_classical_custody_is_refused_with_the_closed_set() {
        let req = AssociateRequest {
            classical: Some("smartcard-of-the-future".into()),
            key_id: Some("somebody-v1-abcdef".into()),
            ..AssociateRequest::default()
        };
        let body = refusal_of(&req, &cfg_at("bad-classical")).await;
        assert!(
            body.contains("unknown classical custody") && body.contains("yubikey | tpm | software"),
            "the refusal states the closed set: {body}"
        );
    }

    /// A `tpm` PQC half this home does not hold is refused by NAME, and the
    /// message enumerates where the half can come from — the failure an
    /// operator meets first on a machine that never held the identity.
    #[tokio::test]
    async fn a_missing_sealed_pqc_half_is_refused_and_lists_the_alternatives() {
        let req = AssociateRequest {
            classical: Some("software".into()),
            key_id: Some("nobody-here-v1-abcdef".into()),
            pqc: Some("tpm".into()),
            ..AssociateRequest::default()
        };
        let body = refusal_of(&req, &cfg_at("no-sealed")).await;
        assert!(
            body.contains("nobody-here-v1-abcdef"),
            "the refusal names the identity: {body}"
        );
    }

    /// The custody word is what the SIGNER reports, not what was asked for. A
    /// seal that degraded to encrypted software is software, on either half
    /// (Codex review on PR #620 — raised once per half, fixed once here).
    #[test]
    fn a_degraded_seal_labels_as_software_however_it_was_asked_for() {
        use ciris_keyring::HardwareType;
        assert_eq!(custody_word(HardwareType::SoftwareOnly, "tpm"), "software");
        assert_eq!(
            custody_word(HardwareType::SoftwareOnly, "yubikey"),
            "software"
        );
        assert_eq!(custody_word(HardwareType::SoftwareOnly, "usb"), "software");
        // Real hardware keeps the requested word, which is the only thing that
        // distinguishes a USB-wrapped half from a locally-sealed one — both are
        // "sealed" to `hardware_type()`.
        assert_eq!(custody_word(HardwareType::TpmDiscrete, "tpm"), "tpm");
        assert_eq!(custody_word(HardwareType::TpmDiscrete, "usb"), "usb");
    }
}
