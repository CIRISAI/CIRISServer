//! Self-occurrence **enrollment** — "add a second device (e.g. a phone) as an
//! occurrence of my self", and its inverse, "revoke the lost / stolen one"
//! (CIRISServer#76, CEG §5.6.8.8 / §11.7).
//!
//! A "self" is a roster of `identity_occurrence` rows over ONE root identity
//! key. [`super::verify::signer_acts_for`] treats any ACTIVE occurrence as a
//! full stand-in for the self, so adding a second device makes the founder's
//! fed-ID survive the loss of the first device — the OR-of-N redundancy a
//! single hardware-sealed key cannot give you.
//!
//! This is the **clean, single-purpose** version of what today can only be done
//! by abusing the `app` occurrence slot of `POST /v1/self/login` (which co-admits
//! an app + an agent + a partnership + a delegation in one ceremony). Enrolling
//! a backup *device* is none of that: it is one occurrence binding + the Self-DEK
//! cascade so the new device decrypts the self's at-rest content.
//!
//! Three routes, on the read-API listener (the signature is the gate — no
//! loopback), default [`HybridPolicy::Strict`]:
//!
//!   1. `POST /v1/self/occurrence` — ADD an occurrence (this device, or a new
//!      backup). Auth: the request is hybrid-signed by an EXISTING active
//!      occurrence of the self, OR by the identity root itself
//!      ([`super::verify::signer_acts_for`]). The new device's `federation_keys`
//!      row is admitted via the proof-of-possession gate (`register_federation_key`)
//!      when a `occurrence_key_record` is supplied and the key is not yet known.
//!   2. `POST /v1/self/occurrence/revoke` — REVOKE a (lost/stolen) occurrence.
//!      Auth: a SURVIVING active occurrence (or the root). For a *stolen* device
//!      you MUST sign with a different surviving key — never the compromised one
//!      (CEG §11.7.4). A *voluntary* self-revoke (signer == revoked) is allowed.
//!   3. `GET /v1/self/occurrences?identity_key_id=…` — LIST the active
//!      occurrences of a self (for the client identity page's device list).
//!      Read-only; unauthenticated by design (an occurrence roster is public
//!      §5.6.8.8 binding metadata — pubkeys + device_class — and a peer must be
//!      able to read it to resolve who-acts-for-whom; there is nothing secret to
//!      gate, same posture as `GET /v1/federation/self-key-record`).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::types::{
    IdentityOccurrence, IdentityOccurrenceRevocation, SignedIdentityOccurrence,
    SignedIdentityOccurrenceRevocation,
};
use ciris_persist::federation::{EncryptionPubkeys, SignedKeyRecord};
use ciris_persist::prelude::{Engine, HybridPolicy};
use ciris_persist::FederationDirectory;
use serde::{Deserialize, Serialize};

use super::verify::{self, VerifyError};

#[derive(Clone)]
struct OccurrenceState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

// ─── shared DTOs ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
struct EncPubkeysDto {
    x25519_base64: String,
    ml_kem_768_base64: String,
}

impl From<EncPubkeysDto> for EncryptionPubkeys {
    fn from(d: EncPubkeysDto) -> Self {
        EncryptionPubkeys {
            x25519_base64: d.x25519_base64,
            ml_kem_768_base64: d.ml_kem_768_base64,
        }
    }
}

impl From<EncryptionPubkeys> for EncPubkeysDto {
    fn from(e: EncryptionPubkeys) -> Self {
        EncPubkeysDto {
            x25519_base64: e.x25519_base64,
            ml_kem_768_base64: e.ml_kem_768_base64,
        }
    }
}

#[derive(Debug, Deserialize)]
struct OccurrenceDto {
    /// The new device's signing key (a `federation_keys.key_id`). It must already
    /// exist in the directory, OR be admitted via `occurrence_key_record` below.
    occurrence_key_id: String,
    /// Closed set: `phone | laptop | agent` (persist's `check_device_class`).
    device_class: String,
    /// Opaque base64 hardware attestation (TPM / Secure Enclave / StrongBox).
    /// `None` for software-only occurrences.
    #[serde(default)]
    hardware_attestation: Option<String>,
    /// The device's content-encryption pubkeys (the `wrap_algorithm: v2` recipient
    /// inputs). **Required for the device to decrypt the self's at-rest content** —
    /// an occurrence WITHOUT them is fail-secure EXCLUDED from the Self-DEK cascade
    /// (§10.1.4); it can still SIGN as the self, but cannot read encrypted blobs.
    #[serde(default)]
    encryption_pubkeys: Option<EncPubkeysDto>,
    /// Optional reachability rows `[(transport_kind, destination)]` (§5.6.8.8.1).
    #[serde(default)]
    transport_destinations: Vec<(String, String)>,
}

// ─── reusable occurrence-binding core (shared with portable_occurrence) ───────

/// The bound-state of a freshly-admitted occurrence (the three persist effects).
pub struct OccurrenceBindOutcome {
    /// `true` when this call admitted the device's `federation_keys` row from a
    /// supplied `occurrence_key_record`; `false` when the key already existed.
    pub key_freshly_registered: bool,
    /// How many `cohort_scope: self` at-rest DEKs were (re-)wrapped to the newcomer.
    pub self_dek_granted: usize,
    /// Occurrence key_ids fail-secure EXCLUDED from the cascade (no encryption pubkeys).
    pub self_dek_excluded: Vec<String>,
}

/// **THE occurrence-binding core** — register the occurrence's signing key (if a
/// PoP record is supplied and the key is fresh), bind it under `identity_key_id`,
/// and run the Self-DEK cascade. This is the exact three-effect sequence
/// [`add_occurrence`] performs after its authorization gate; factored out so the
/// owner-gated portable-occurrence path ([`super::portable_occurrence`]) can bind a
/// node-minted software key as an occurrence of the OWNER's self under the OWNER's
/// authority — without going back over the signed-request HTTP path.
///
/// ## Authorization contract (the security-critical invariant)
///
/// This fn performs NO authorization itself — the CALLER must already have proven
/// that the act of binding `occurrence_key_id` under `identity_key_id` is
/// authorized by an active occurrence of (or the root of) that self. The two
/// call sites discharge that obligation differently but equivalently:
///   - [`add_occurrence`]: the request is hybrid-signed by an active occurrence
///     of the self (`verify::signer_acts_for(caller, identity_key_id)`).
///   - [`super::portable_occurrence`]: the route is owner-gated (a live SYSTEM_ADMIN
///     owner session == the bound owner's login) AND `identity_key_id` is resolved
///     from `is_owner_bound(node)` — i.e. the owner's OWN primary fed-ID. The
///     local primary signer is opened (`resolve_user_signer(OwnerSession)`) to
///     PROVE possession before this binds. The owner authorizing an occurrence of
///     their own self is the apex authority.
///
/// After this returns Ok, `verify::signer_acts_for(engine, occurrence_key_id,
/// identity_key_id) == true`.
pub async fn bind_occurrence_core(
    engine: &Engine,
    identity_key_id: &str,
    occurrence_key_id: &str,
    device_class: &str,
    hardware_attestation: Option<String>,
    encryption_pubkeys: Option<EncryptionPubkeys>,
    occurrence_key_record: Option<SignedKeyRecord>,
) -> Result<OccurrenceBindOutcome, String> {
    let directory = engine.federation_directory();

    // (1) Admit the new device's signing key if a record was supplied and the key
    // is not yet known. register_federation_key hybrid-verifies the self-signed
    // proof-of-possession BEFORE store (fail-secure) — a forged record is rejected.
    let already_known = directory
        .lookup_public_key(occurrence_key_id)
        .await
        .map_err(|e| format!("directory lookup: {e}"))?
        .is_some();
    let mut key_freshly_registered = false;
    if !already_known {
        let record = occurrence_key_record.ok_or_else(|| {
            "occurrence_key_id is not a registered federation key and no \
             occurrence_key_record was supplied to admit it"
                .to_string()
        })?;
        if record.record.key_id != occurrence_key_id {
            return Err(
                "occurrence_key_record.record.key_id does not match occurrence_key_id".to_string(),
            );
        }
        engine
            .register_federation_key(record)
            .await
            .map_err(|e| format!("occurrence key registration rejected: {e}"))?;
        key_freshly_registered = true;
    }

    // (2) Bind the occurrence under the identity (idempotent on the
    // (identity, occurrence) PK; persist runs check_device_class admission).
    let now = chrono::Utc::now();
    let row = IdentityOccurrence {
        identity_key_id: identity_key_id.to_string(),
        occurrence_key_id: occurrence_key_id.to_string(),
        device_class: device_class.to_string(),
        hardware_attestation,
        asserted_at: now,
        valid_until: None,
        encryption_pubkeys,
        persist_row_hash: String::new(),
    };
    directory
        .put_identity_occurrence(SignedIdentityOccurrence {
            identity_occurrence: row,
        })
        .await
        .map_err(|e| format!("put_identity_occurrence: {e}"))?;

    // (3) Self-DEK cascade: retroactively wrap every existing cohort_scope:self
    // at-rest DEK to the newcomer so the new key decrypts the self's content.
    // Idempotent + fail-secure (a keyless occurrence is EXCLUDED, never granted).
    let newcomers = [occurrence_key_id.to_string()];
    let rekey = engine
        .rekey_self_occurrence_add(identity_key_id, &newcomers)
        .await
        .map_err(|e| format!("self-DEK cascade: {e}"))?;

    Ok(OccurrenceBindOutcome {
        key_freshly_registered,
        self_dek_granted: rekey.granted.len(),
        self_dek_excluded: rekey.excluded,
    })
}

// ─── POST /v1/self/occurrence (ADD) ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddOccurrenceRequest {
    /// The root identity (the "self") this device is being enrolled under.
    identity_key_id: String,
    /// The occurrence to admit.
    occurrence: OccurrenceDto,
    /// OPTIONAL self-signed `SignedKeyRecord` for the new device's signing key.
    /// When present AND the key is not yet in the directory, it is admitted via
    /// the fail-secure `register_federation_key` gate (hybrid PoP verified before
    /// store). When the key already exists this is ignored. When absent the key
    /// MUST already exist (else 400) — key registration is a precondition of an
    /// occurrence binding (persist `engine.rs:2447-2451`).
    #[serde(default)]
    occurrence_key_record: Option<SignedKeyRecord>,
}

#[derive(Debug, Serialize)]
struct AddOccurrenceResponse {
    /// The root identity the occurrence now speaks for.
    identity_key_id: String,
    /// The admitted occurrence's signing `key_id`.
    occurrence_key_id: String,
    /// `phone | laptop | agent` (echo).
    device_class: String,
    /// `true` when this call admitted the device's `federation_keys` row from the
    /// supplied `occurrence_key_record`; `false` when the key already existed.
    key_freshly_registered: bool,
    /// How many `cohort_scope: self` at-rest DEKs were (re-)wrapped to this device
    /// by the Self-DEK cascade — `0` when the self holds no encrypted content yet,
    /// or when the occurrence supplied no `encryption_pubkeys`.
    self_dek_granted: usize,
    /// Occurrence key_ids fail-secure EXCLUDED from the cascade (no
    /// `encryption_pubkeys`). If THIS occurrence appears here, it can sign as the
    /// self but cannot decrypt the self's at-rest content.
    self_dek_excluded: Vec<String>,
    /// Reachability rows registered for this occurrence.
    transport_destinations_registered: usize,
}

async fn add_occurrence(
    State(st): State<OccurrenceState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // (1) Verify the request hybrid signature over its exact body bytes.
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("signature verification failed: {e}"),
            )
        }
    };

    // (2) Parse.
    let req: AddOccurrenceRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request body: {e}")),
    };

    // (3) Admission (§5.6.8.8): the signer must be the identity itself or an
    // already-admitted ACTIVE occurrence of it — i.e. a key you already control
    // authorizes enrolling the next device. A fresh device cannot self-enroll.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.identity_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the identity key nor an active occurrence of it — \
             enroll a new device by signing with a key you already control",
        );
    }

    let directory = st.engine.federation_directory();

    // (4a-c) Admit the new key (PoP-gated), bind the occurrence, and run the
    // Self-DEK cascade — the three-effect core shared with the owner-gated
    // portable-occurrence path. Authorization was discharged above by the
    // signed-request gate (`signer_acts_for`).
    let outcome = match bind_occurrence_core(
        &st.engine,
        &req.identity_key_id,
        &req.occurrence.occurrence_key_id,
        &req.occurrence.device_class,
        req.occurrence.hardware_attestation.clone(),
        req.occurrence.encryption_pubkeys.map(Into::into),
        req.occurrence_key_record,
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            // The "fresh key with no PoP record" / mismatch cases are caller errors
            // (400); the rest are storage failures (500). Disambiguate on the text.
            let code = if e.contains("occurrence_key_record")
                || e.contains("not a registered federation key")
                || e.contains("registration rejected")
            {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return err(code, e);
        }
    };
    let key_freshly_registered = outcome.key_freshly_registered;

    // (4d) Reachability rows (§5.6.8.8.1).
    let now = chrono::Utc::now();
    let mut transport_rows = 0usize;
    for (kind, dest) in &req.occurrence.transport_destinations {
        if let Err(e) = directory
            .put_transport_destination(&ciris_persist::federation::TransportDestination {
                occurrence_key_id: req.occurrence.occurrence_key_id.clone(),
                transport_kind: kind.clone(),
                destination: dest.clone(),
                asserted_at: now,
                last_seen_at: Some(now),
            })
            .await
        {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("put_transport_destination: {e}"),
            );
        }
        transport_rows += 1;
    }

    (
        StatusCode::OK,
        Json(AddOccurrenceResponse {
            identity_key_id: req.identity_key_id,
            occurrence_key_id: req.occurrence.occurrence_key_id,
            device_class: req.occurrence.device_class,
            key_freshly_registered,
            self_dek_granted: outcome.self_dek_granted,
            self_dek_excluded: outcome.self_dek_excluded,
            transport_destinations_registered: transport_rows,
        }),
    )
        .into_response()
}

// ─── POST /v1/self/occurrence/revoke (REVOKE) ────────────────────────────────

#[derive(Debug, Deserialize)]
struct RevokeOccurrenceRequest {
    /// The root identity the occurrence speaks for.
    identity_key_id: String,
    /// The occurrence (device) to remove from the self.
    occurrence_key_id: String,
    /// Optional operator/ceremony annotation (e.g. "laptop lost 2026-06-23").
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct RevokeOccurrenceResponse {
    identity_key_id: String,
    /// The occurrence that was revoked. After this it fails `signer_acts_for`.
    occurrence_key_id: String,
    /// The surviving key that authorized the revocation (the request signer; the
    /// recorded `witness_set` single-vouch, §11.7.4).
    revoked_by: String,
    /// RFC-3339 effective time (== now; the active-state filter is
    /// `effective_at <= now`, so the revocation is effective immediately).
    effective_at: String,
}

async fn revoke_occurrence(
    State(st): State<OccurrenceState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // (1) Verify the request hybrid signature.
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(
                StatusCode::UNAUTHORIZED,
                format!("signature verification failed: {e}"),
            )
        }
    };

    // (2) Parse.
    let req: RevokeOccurrenceRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request body: {e}")),
    };

    // (3) Admission: a SURVIVING active occurrence (or the root) authorizes the
    // removal (§11.7.4 single-vouch — "the revoking occurrence OR the identity").
    // For a STOLEN device you MUST sign with a different surviving key, never the
    // compromised one — that is exactly why a backup occurrence is enrolled. A
    // VOLUNTARY self-revoke (signer == revoked) is permitted (a device leaving on
    // its own); the producer-side helper (verify::sign_occurrence_revocation) does
    // not forbid it, and the surviving-key requirement is a flow property of the
    // stolen-device case, not a server invariant we can enforce (the server cannot
    // know the key is compromised). We DO require the signer to currently act for
    // the self, so a revoked / unrelated key cannot revoke another's device.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.identity_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the identity key nor an active occurrence of it — \
             revoke a device by signing with a surviving key you still control",
        );
    }

    // (4) Record the append-only revocation. persist's *_active reads compose it,
    // so after this the revoked key fails signer_acts_for. The witness_set carries
    // the single vouch [revoker] (§11.7.4); persist computes persist_row_hash.
    let now = chrono::Utc::now();
    let revocation = IdentityOccurrenceRevocation {
        identity_key_id: req.identity_key_id.clone(),
        occurrence_key_id: req.occurrence_key_id.clone(),
        revoked_at: now,
        effective_at: now,
        reason: req.reason,
        witness_set: vec![caller.key_id.clone()],
        persist_row_hash: String::new(),
    };
    if let Err(e) = st
        .engine
        .federation_directory()
        .put_identity_occurrence_revocation(SignedIdentityOccurrenceRevocation {
            identity_occurrence_revocation: revocation,
        })
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("put_identity_occurrence_revocation: {e}"),
        );
    }

    (
        StatusCode::OK,
        Json(RevokeOccurrenceResponse {
            identity_key_id: req.identity_key_id,
            occurrence_key_id: req.occurrence_key_id,
            revoked_by: caller.key_id,
            effective_at: now.to_rfc3339(),
        }),
    )
        .into_response()
}

// ─── GET /v1/self/occurrences (LIST) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ListQuery {
    identity_key_id: String,
}

#[derive(Debug, Serialize)]
struct OccurrenceView {
    occurrence_key_id: String,
    device_class: String,
    /// `true` when this occurrence registered content-encryption pubkeys (i.e. it
    /// is a Self-DEK recipient and can decrypt the self's at-rest content).
    has_encryption_pubkeys: bool,
    /// Present when the occurrence carries hardware attestation.
    #[serde(skip_serializing_if = "Option::is_none")]
    hardware_attestation: Option<String>,
    /// RFC-3339 binding-asserted time.
    asserted_at: String,
}

#[derive(Debug, Serialize)]
struct ListOccurrencesResponse {
    identity_key_id: String,
    /// The currently-ACTIVE occurrences (admitted, not revoked) — the device list.
    occurrences: Vec<OccurrenceView>,
}

async fn list_occurrences(
    State(st): State<OccurrenceState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let Some(directory) = st.engine.sqlite_backend() else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory");
    };
    match directory
        .list_identity_occurrences_active(&q.identity_key_id)
        .await
    {
        Ok(occs) => {
            let occurrences = occs
                .into_iter()
                .map(|o| OccurrenceView {
                    occurrence_key_id: o.occurrence_key_id,
                    device_class: o.device_class,
                    has_encryption_pubkeys: o.encryption_pubkeys.is_some(),
                    hardware_attestation: o.hardware_attestation,
                    asserted_at: o.asserted_at.to_rfc3339(),
                })
                .collect();
            (
                StatusCode::OK,
                Json(ListOccurrencesResponse {
                    identity_key_id: q.identity_key_id,
                    occurrences,
                }),
            )
                .into_response()
        }
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("list_identity_occurrences_active: {e}"),
        ),
    }
}

/// The self-occurrence-enrollment router — merge onto the read-API listener
/// beside `self_login::router`. Default [`HybridPolicy::Strict`] (no
/// classical-only path). The signature is the gate (no loopback layer) — exactly
/// the posture of `self_login`.
pub fn router(engine: Arc<Engine>, policy: HybridPolicy) -> Router {
    Router::new()
        .route("/v1/self/occurrence", axum::routing::post(add_occurrence))
        .route(
            "/v1/self/occurrence/revoke",
            axum::routing::post(revoke_occurrence),
        )
        .route("/v1/self/occurrences", axum::routing::get(list_occurrences))
        .with_state(OccurrenceState { engine, policy })
}
