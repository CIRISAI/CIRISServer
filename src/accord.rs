//! **HUMANITY_ACCORD server surface** (CIRISServer#41, CC 4.2 / §9.2) — the
//! safe-mesh kill-switch + the accord-holder registry. This is the server-side
//! half that is buildable TODAY on verify v6.6.x's accord verification surface
//! (`humanity_accord::{Invocation, verify_invocation, InvocationDedup}` +
//! `threshold`) and persist v9.4.0's `accord_holder` `federation_keys` rows
//! (`list_keys_by_identity_type`, CIRISPersist#105):
//!
//!   1. `POST /v1/accord/holder` (OWNER-GATED) — admit a holder's **self-signed**
//!      `accord_holder` `SignedKeyRecord` through the canonical
//!      [`Engine::register_federation_key`] gate. Holders self-provision their OWN
//!      keys at genesis (no human provisions another's — runbook §3/§6); the node
//!      owner registers the genesis-established holder records here.
//!   2. `GET /v1/accord-holders` — the **cold-start recognition** roster (runbook
//!      §10.2): a fresh consumer reads the accord-holder pubkeys with NO TOFU, so
//!      it can verify a 2-of-3 invocation against pinned keys.
//!   3. `POST /v1/accord/verify-invocation` — the **authoritative server-side
//!      2-of-3** verification of a HUMANITY_ACCORD invocation (the operational
//!      kill-switch, CC 4.2.1 / §9.2.1): [`verify_invocation`] over the registered
//!      holder set + an [`InvocationDedup`] anti-replay window. The verify CLI's
//!      local quorum is advisory; THIS is canonical (against `federation_keys`).
//!
//! ## Genesis ceremony + invocation concurrence (v0.5.17, verify v6.7.1)
//!
//! - `POST /v1/accord/genesis/envelope` → `assemble` (`accord_genesis`,
//!   2-of-3 distinct-founder quorum, fail-closed) → the verified
//!   `accord_family_genesis` is durably recorded as a node-authored CEG
//!   attestation (the accord family is FOUNDER-signed — it has no family keypair,
//!   so it is NOT stored in `federation_families`, whose `family_key_id` FKs to
//!   `federation_keys`; the signed genesis object IS the record). `GET
//!   /v1/accord/family` projects the entrenched `quorum:2/3` family from it.
//! - `POST /v1/accord/invocation` (open) / `…/concur` (advance) + `GET
//!   /v1/accord/invocations` — the multi-party path that accumulates holder
//!   cosignatures toward the 2-of-3 (advisory status; `verify-invocation` is
//!   authoritative against `federation_keys`).
//!
//! ## Custody gate (v0.5.19 — the safe-mesh FLOOR pin)
//!
//! `POST /v1/accord/holder` accepts an optional `custody_attestation` (the
//! holder's `portable_2fa` YubiKey PIV `9c → f9 → …intermediates… → Yubico
//! Attestation Root 1` chain). When present it is verified via
//! [`verify_accord_custody_attestation`] against the PINNED durable root
//! ([`YUBICO_ATTESTATION_ROOT_1_DER`]) + the FIPS-certified + touch-always floor +
//! the attested-key==holder bind — BEFORE the key is admitted. CIRISVerify#91 +
//! #62 are both resolved + validated on a real YubiKey 5 FIPS (fw 5.7.4); the real
//! `ciris_keyring::pkcs11` cryptoki backend is live (no longer stubbed).
//!
//! ## What is NOT here yet (and why the mesh still waits)
//!
//! The remaining floor work is the **foolproof holder-provisioning UI** (drive
//! [`crate::accord_custody::provision_portable_holder`] from a guided desktop flow
//! — the holder selects the ML-DSA USB path on an already-FIPS-approved key) + the
//! **operational genesis ceremony RUN** (mint the canonical holders on real
//! YubiKeys, register them with their custody attestations, assemble the family).
//! The canonical mesh stays on 0.5.X — 0.6 (+registry) bakes
//! `CANONICAL_BOOTSTRAP_PEERS` and bootstraps the mesh, which MUST NOT happen
//! before the kill-switch is enforceable AND the accord keys are under genuine
//! 2-factor distributed-human custody (now gate-enforced).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_persist::federation::types::{identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::Engine;
use ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation;
use ciris_verify_core::accord_genesis::{
    accord_invocation_status, assemble_accord_family_genesis, build_accord_family_envelope,
    build_accord_invocation_object, parse_accord_invocation, ACCORD_CONSENSUS_PROTOCOL,
    ACCORD_FAMILY_GENESIS_KIND, ACCORD_QUORUM_THRESHOLD, HUMANITY_ACCORD_FAMILY_KEY_ID,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::humanity_accord::{verify_invocation, Invocation, InvocationDedup};
use ciris_verify_core::threshold::{ThresholdMember, ThresholdSignature};

use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;

/// The §9.2.1 2-of-3 holder threshold (verify enforces this internally; surfaced
/// here for the response + the cold-start roster sanity check).
const ACCORD_THRESHOLD: usize = 2;

/// The PINNED durable accord-custody trust anchor — **Yubico Attestation Root 1**
/// (`developers.yubico.com/PKI/yubico-ca-1.pem`, CN="Yubico Attestation Root 1",
/// DER). The safe-mesh floor pins THIS durable root, NOT the rotating "Yubico PIV
/// Attestation B 1" intermediate; the f9 device cert + the two PIV intermediates
/// ride in the holder's custody-attestation chain
/// (`yubikey_attestation_chain_hex`), which `verify_accord_custody_attestation`
/// walks (variable length) up to this anchor. Validated against a real YubiKey 5
/// FIPS (fw 5.7.4) by the verify team. See the `accord-custody-gate-pinning` note.
const YUBICO_ATTESTATION_ROOT_1_DER: &[u8] =
    include_bytes!("accord_pki/yubico_attestation_root_1.der");

#[derive(Clone)]
struct AccordState {
    engine: Arc<Engine>,
    /// §9.2.1 anti-replay window — rejects a duplicate `(kind, invocation_id)`
    /// within its `valid_until`. In-memory (a node restart re-opens the window);
    /// the canonical 2-of-3 holder signatures are the load-bearing check.
    dedup: Arc<Mutex<InvocationDedup>>,
    /// Pending accord-invocation objects keyed by `(invocation_kind, invocation_id)`
    /// while holders concur toward the 2-of-3. Ephemeral coordination state (a node
    /// restart drops in-flight invocations); the durable artifact is the assembled
    /// invocation's holder cosignatures, re-verifiable against `federation_keys`.
    pending: Arc<Mutex<HashMap<(String, String), SignedCegObject>>>,
}

/// Build the registered accord-holder set as `threshold::ThresholdMember`s (the
/// roster the genesis/invocation producers + `verify_invocation` resolve against).
async fn registered_holders(engine: &Engine) -> Result<Vec<ThresholdMember>, Response> {
    let rows: Vec<KeyRecord> = engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")))?;
    Ok(rows
        .into_iter()
        .map(|r| ThresholdMember {
            member_id: r.key_id,
            ed25519_public_key_base64: r.pubkey_ed25519_base64,
            mldsa65_public_key_base64: r.pubkey_ml_dsa_65_base64,
            role: None,
        })
        .collect())
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

/// Require a live OWNER session — the SAME apex gate `POST /v1/federation/peering`
/// and the device-grant approval use (`SYSTEM_ADMIN` with
/// [`Permission::FullAccess`], and NOT itself a delegated actor — registering an
/// accord holder is a constitutional governance act, never a self-amplifying
/// delegated one).
async fn require_owner(st: &AccordState, headers: &HeaderMap) -> Result<(), Response> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "missing bearer session token",
        ));
    };
    match resolve_bearer(&st.engine, token).await {
        Ok(Some(caller))
            if caller.actor.is_none()
                && caller.role == UserRole::SystemAdmin
                && caller.permissions.contains(&Permission::FullAccess) =>
        {
            Ok(())
        }
        Ok(Some(_)) => Err(err(
            StatusCode::FORBIDDEN,
            "registering an accord holder requires the owner (SYSTEM_ADMIN) role",
        )),
        Ok(None) => Err(err(StatusCode::UNAUTHORIZED, "invalid or expired session")),
        Err(e) => Err(err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}"))),
    }
}

// ─── POST /v1/accord/holder (OWNER-GATED) ─────────────────────────────────────

/// A holder's self-signed `accord_holder` key record (the genesis-established
/// holder identity the node admits). Same `SignedKeyRecord` shape a peer presents
/// — the canonical gate hybrid-verifies the self-signed proof-of-possession.
#[derive(Debug, Deserialize)]
struct RegisterHolderRequest {
    key_record: SignedKeyRecord,
    /// The holder's `portable_2fa` custody attestation (a YubiKey PIV `9c → f9 →
    /// …intermediates… → Yubico Attestation Root 1` chain, produced at
    /// provisioning). When present it is verified against the PINNED durable root
    /// (the safe-mesh FIPS floor) BEFORE the key is admitted. Optional only so the
    /// software test path can exercise the persist `attestation_evidence` gate
    /// alone; the canonical accord holders ARE provisioned with it.
    #[serde(default)]
    custody_attestation: Option<SignedCegObject>,
}

async fn register_holder(
    State(st): State<AccordState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: RegisterHolderRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    // The record MUST declare identity_type = accord_holder — this is the role the
    // 2-of-3 kill-switch recognizes; admitting any other type here would be a
    // silent role confusion.
    if req.key_record.record.identity_type != identity_type::ACCORD_HOLDER {
        return err(
            StatusCode::BAD_REQUEST,
            "key_record.identity_type must be \"accord_holder\"",
        );
    }
    let key_id = req.key_record.record.key_id.clone();

    // FIPS portable-2FA CUSTODY GATE (the safe-mesh floor): if a YubiKey PIV
    // custody attestation is supplied, it MUST verify against the PINNED durable
    // Yubico Attestation Root 1 + meet the FIPS-certified + touch-always floor +
    // bind to THIS holder's Ed25519 — else the key is refused. The f9 + the two
    // PIV intermediates ride in the attestation's chain; we pin only the root.
    let custody = if let Some(custody) = &req.custody_attestation {
        let holder_member = ThresholdMember {
            member_id: req.key_record.record.key_id.clone(),
            ed25519_public_key_base64: req.key_record.record.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: req.key_record.record.pubkey_ml_dsa_65_base64.clone(),
            role: None,
        };
        match verify_accord_custody_attestation(
            custody,
            &holder_member,
            YUBICO_ATTESTATION_ROOT_1_DER,
        ) {
            Ok(v) => serde_json::json!({
                "verified": true,
                "hardware_class": v.hardware_class,
                "custody_tier": v.custody_tier,
                "fips_certified": v.fips_certified,
                "touch_always": v.touch_always,
                "firmware": v.firmware,
            }),
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!(
                        "accord custody attestation rejected (must be a FIPS YubiKey PIV chain to \
                         Yubico Attestation Root 1): {e}"
                    ),
                )
            }
        }
    } else {
        serde_json::Value::Null
    };

    match st.engine.register_federation_key(req.key_record).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "registered": true, "key_id": key_id, "custody": custody })),
        )
            .into_response(),
        Err(e) => err(
            StatusCode::BAD_REQUEST,
            &format!("register accord holder (admission gate): {e}"),
        ),
    }
}

// ─── GET /v1/accord-holders (cold-start recognition) ──────────────────────────

#[derive(Debug, Serialize)]
struct HolderSummary {
    key_id: String,
    pubkey_ed25519_base64: String,
    pubkey_ml_dsa_65_base64: Option<String>,
}

/// `GET /v1/accord-holders` — the cold-start recognition roster (runbook §10.2):
/// every `accord_holder` `federation_keys` row, so a fresh consumer can pin the
/// holder pubkeys and verify a 2-of-3 invocation with NO trust-on-first-use.
async fn list_holders(State(st): State<AccordState>) -> Response {
    let rows = match st
        .engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    let holders: Vec<HolderSummary> = rows
        .into_iter()
        .map(|r| HolderSummary {
            key_id: r.key_id,
            pubkey_ed25519_base64: r.pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64: r.pubkey_ml_dsa_65_base64,
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "threshold": ACCORD_THRESHOLD,
            "holder_count": holders.len(),
            "holders": holders,
        })),
    )
        .into_response()
}

// ─── POST /v1/accord/verify-invocation (the kill-switch, server-canonical 2/3) ─

#[derive(Debug, Deserialize)]
struct VerifyInvocationRequest {
    invocation: Invocation,
    /// The (≤ N) holder cosignatures toward the 2-of-3. Each `member_id` MUST be a
    /// registered `accord_holder` `key_id`.
    signatures: Vec<ThresholdSignature>,
    /// §9.2.1 canonical RFC-3339 "now" the dedup window evicts against. Supplied by
    /// the caller (the node has no wall-clock injection seam in this handler).
    now: String,
}

/// `POST /v1/accord/verify-invocation` — the AUTHORITATIVE server-side 2-of-3
/// verification of a HUMANITY_ACCORD invocation (CC 4.2.1 / §9.2.1). Builds the
/// holder set from the registered `accord_holder` rows, runs [`verify_invocation`]
/// (2-of-3 hybrid sigs over the §9.2.1 canonical bytes), and applies the
/// [`InvocationDedup`] anti-replay window. NOT owner-gated: the 2-of-3 holder
/// signatures ARE the authority; this endpoint is the canonical recognizer a
/// relying node / consumer calls (the verify CLI's local quorum is advisory).
async fn verify_invocation_handler(
    State(st): State<AccordState>,
    body: axum::body::Bytes,
) -> Response {
    let req: VerifyInvocationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };

    // The holder set the threshold verifies against = the registered accord_holder
    // rows (NOT caller-supplied — the registry is the authority on WHO can halt).
    let rows = match st
        .engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    if rows.len() < ACCORD_THRESHOLD {
        return err(
            StatusCode::CONFLICT,
            "fewer registered accord holders than the 2-of-3 threshold — accord not established",
        );
    }
    let holders: Vec<ThresholdMember> = rows
        .into_iter()
        .map(|r| ThresholdMember {
            member_id: r.key_id,
            ed25519_public_key_base64: r.pubkey_ed25519_base64,
            mldsa65_public_key_base64: r.pubkey_ml_dsa_65_base64,
            role: None,
        })
        .collect();

    // Anti-replay FIRST (fail-closed on a duplicate id within its window).
    {
        let mut dedup = st.dedup.lock().expect("invocation dedup lock");
        if let Err(e) = dedup.record_or_reject(&req.invocation, &req.now) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "verified": false,
                    "reason": "duplicate_invocation",
                    "detail": e.to_string(),
                })),
            )
                .into_response();
        }
    }

    match verify_invocation(&req.invocation, &holders, &req.signatures) {
        Ok(valid) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": true,
                "kind": req.invocation.invocation_kind.as_str(),
                "invocation_id": req.invocation.invocation_id,
                "valid_signatures": valid,
                "threshold": ACCORD_THRESHOLD,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": false,
                "reason": "quorum_not_met",
                "detail": e.to_string(),
                "threshold": ACCORD_THRESHOLD,
            })),
        )
            .into_response(),
    }
}

// ─── Genesis ceremony (CC 4.2 / §9 — build envelope → assemble 2/3 → entrench) ─

#[derive(Debug, Deserialize)]
struct GenesisEnvelopeRequest {
    #[serde(default)]
    family_name: Option<String>,
    /// The accord-holder `key_id`s, in a FIXED order (JCS-significant — every
    /// holder + the assembler MUST co-sign the SAME envelope byte-for-byte).
    member_key_ids: Vec<String>,
}

/// `POST /v1/accord/genesis/envelope` (owner-gated) — build the canonical
/// `accord_family` envelope the holders co-sign. Returns it verbatim; the holders
/// sign `accord_family_signing_bytes(envelope)` on their OWN tokens.
async fn genesis_envelope(
    State(st): State<AccordState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: GenesisEnvelopeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let family_name = req
        .family_name
        .unwrap_or_else(|| "HUMANITY_ACCORD".to_string());
    let envelope = build_accord_family_envelope(
        HUMANITY_ACCORD_FAMILY_KEY_ID,
        &family_name,
        &req.member_key_ids,
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "envelope": envelope })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct GenesisAssembleRequest {
    /// The exact envelope from [`genesis_envelope`] (re-canonicalized; never re-built).
    envelope: serde_json::Value,
    /// The founder set (`role: Founder`), one per co-signing holder.
    founders: Vec<ThresholdMember>,
    /// The collected founder co-signatures (≥ 2 distinct, 2-of-3).
    signatures: Vec<ThresholdSignature>,
}

/// `POST /v1/accord/genesis/assemble` (owner-gated) — verify the 2-of-3 founder
/// quorum over the envelope ([`assemble_accord_family_genesis`], distinct-key +
/// founder-role gated, fail-closed) and, on success, ENTRENCH the family as a
/// `quorum:2/3` `Family` row ([`FederationDirectory::put_family`]). The assembled
/// genesis `SignedCegObject` is returned for relay/audit. (Holders are registered
/// separately via `POST /v1/accord/holder`.)
async fn genesis_assemble(
    State(st): State<AccordState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: GenesisAssembleRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let now = chrono::Utc::now();
    let genesis = match assemble_accord_family_genesis(
        &req.envelope,
        &req.founders,
        &req.signatures,
        &now.to_rfc3339(),
    ) {
        Ok(obj) => obj,
        // Fail-closed: a short/duplicate/non-founder quorum is a 409, not a 500.
        Err(e) => return err(StatusCode::CONFLICT, &format!("assemble genesis: {e}")),
    };

    // The verified genesis is durably recorded as a node-authored CEG attestation
    // (`accord_family_genesis`) carrying `genesis.body` = `{ family, founder_signatures }`.
    // (We do NOT use the federation_families table: its family_key_id FKs to
    // federation_keys, but the accord family is FOUNDER-signed — it has no family
    // keypair to register. The signed genesis object IS the durable record.)
    let member_ids: Vec<String> = req.envelope["members"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m.get("key_id").and_then(|v| v.as_str()).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut input =
        EmitAttestationInput::with_envelope(ACCORD_FAMILY_GENESIS_KIND, genesis.body.clone());
    input.subject_key_ids = member_ids.clone();
    if let Err(e) = st.engine.emit_attestation_self(input).await {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("record accord family genesis: {e}"),
        );
    }
    tracing::info!(
        family = %HUMANITY_ACCORD_FAMILY_KEY_ID,
        holders = member_ids.len(),
        "assembled + recorded the HUMANITY_ACCORD family genesis (quorum:2/3, entrenched)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "family_key_id": HUMANITY_ACCORD_FAMILY_KEY_ID,
            "entrenched": true,
            "consensus_protocol": ACCORD_CONSENSUS_PROTOCOL,
            "genesis": genesis,
        })),
    )
        .into_response()
}

/// `GET /v1/accord/family` — the entrenched HUMANITY_ACCORD family (cold-start
/// read), projected from the latest `accord_family_genesis` CEG record. 404 until
/// genesis is assembled.
async fn get_family(State(st): State<AccordState>) -> Response {
    let node_id = match st.engine.local_derived_key_id().await {
        Ok(id) => id,
        Err(e) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("derive node id: {e}"),
            )
        }
    };
    let rows = match st
        .engine
        .federation_directory()
        .list_attestations_by(&node_id)
        .await
    {
        Ok(r) => r,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    // The latest genesis record (by asserted_at); its envelope is the genesis body
    // `{ family, founder_signatures }` — the `family` is the §9 entrenched envelope.
    let latest = rows
        .into_iter()
        .filter(|a| a.attestation_type == ACCORD_FAMILY_GENESIS_KIND)
        .max_by_key(|a| a.asserted_at);
    let Some(att) = latest else {
        return err(StatusCode::NOT_FOUND, "no HUMANITY_ACCORD family yet");
    };
    let family = &att.attestation_envelope["family"];
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "family_key_id": family.get("family_key_id").cloned().unwrap_or(serde_json::json!(HUMANITY_ACCORD_FAMILY_KEY_ID)),
            "family_name": family.get("family_name").cloned().unwrap_or(serde_json::Value::Null),
            "consensus_protocol": family.get("consensus_protocol").cloned().unwrap_or(serde_json::json!(ACCORD_CONSENSUS_PROTOCOL)),
            "entrenched": family.get("consensus_protocol_entrenched").cloned().unwrap_or(serde_json::json!(true)),
            "members": family.get("members").cloned().unwrap_or(serde_json::json!([])),
        })),
    )
        .into_response()
}

// ─── Invocation concurrence (the multi-party path to the 2/3 kill-switch) ──────

#[derive(Debug, Deserialize)]
struct CreateInvocationRequest {
    invocation: Invocation,
    /// The initiating holder's cosignature (produced on the holder's device).
    signature: ThresholdSignature,
}

/// `POST /v1/accord/invocation` — open a pending invocation with the initiating
/// holder's cosignature. The roster is the registered accord-holder set. Returns
/// the invocation object + its (sub-quorum) status.
async fn create_invocation(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let req: CreateInvocationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let roster = match registered_holders(&st.engine).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let now = chrono::Utc::now().to_rfc3339();
    let obj = build_accord_invocation_object(
        HUMANITY_ACCORD_FAMILY_KEY_ID,
        &roster,
        &req.invocation,
        &[req.signature],
        &now,
    );
    let key = (
        req.invocation.invocation_kind.as_str().to_string(),
        req.invocation.invocation_id.clone(),
    );
    st.pending
        .lock()
        .expect("pending lock")
        .insert(key, obj.clone());
    invocation_response(&obj)
}

#[derive(Debug, Deserialize)]
struct ConcurRequest {
    invocation_kind: String,
    invocation_id: String,
    /// A concurring holder's cosignature (produced on the holder's device).
    signature: ThresholdSignature,
}

/// `POST /v1/accord/invocation/concur` — append a concurring holder's cosignature
/// to a pending invocation, advancing it toward the 2-of-3. The submitted
/// signature is the holder's (the server holds no holder key); an invalid one
/// simply does not count toward the quorum that `accord_invocation_status` reads.
async fn concur_invocation(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let req: ConcurRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let key = (req.invocation_kind.clone(), req.invocation_id.clone());
    let existing = {
        let pending = st.pending.lock().expect("pending lock");
        pending.get(&key).cloned()
    };
    let Some(existing) = existing else {
        return err(StatusCode::NOT_FOUND, "unknown pending invocation");
    };
    let parsed = match parse_accord_invocation(&existing) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("parse: {e}")),
    };
    let mut signatures = parsed.signatures;
    signatures.push(req.signature);
    let now = chrono::Utc::now().to_rfc3339();
    let rebuilt = build_accord_invocation_object(
        &parsed.family_key_id,
        &parsed.roster,
        &parsed.invocation,
        &signatures,
        &now,
    );
    st.pending
        .lock()
        .expect("pending lock")
        .insert(key, rebuilt.clone());
    invocation_response(&rebuilt)
}

/// `GET /v1/accord/invocations` — the pending invocations + their concurrence
/// status (advisory; the authoritative 2/3 check is `verify-invocation`).
async fn list_invocations(State(st): State<AccordState>) -> Response {
    let objs: Vec<SignedCegObject> = st
        .pending
        .lock()
        .expect("pending lock")
        .values()
        .cloned()
        .collect();
    let invocations: Vec<serde_json::Value> = objs
        .iter()
        .filter_map(|o| parse_accord_invocation(o).ok())
        .filter_map(|p| accord_invocation_status(&p).ok())
        .map(|s| {
            serde_json::json!({
                "invocation_kind": s.invocation_kind,
                "invocation_id": s.invocation_id,
                "quorum_met": s.quorum_met,
                "quorum_threshold": s.quorum_threshold,
                "valid_signers": s.valid_signers,
                "roster_member_ids": s.roster_member_ids,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "invocations": invocations })),
    )
        .into_response()
}

/// Build the per-invocation response (object + parsed status).
fn invocation_response(obj: &SignedCegObject) -> Response {
    let status = parse_accord_invocation(obj)
        .ok()
        .and_then(|p| accord_invocation_status(&p).ok());
    let (quorum_met, valid_signers, threshold) = match &status {
        Some(s) => (s.quorum_met, s.valid_signers.clone(), s.quorum_threshold),
        None => (false, Vec::new(), ACCORD_QUORUM_THRESHOLD),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "invocation": obj,
            "quorum_met": quorum_met,
            "valid_signers": valid_signers,
            "quorum_threshold": threshold,
        })),
    )
        .into_response()
}

/// The accord router — merge onto the read-API listener.
pub fn router(engine: Arc<Engine>) -> Router {
    let state = AccordState {
        engine,
        dedup: Arc::new(Mutex::new(InvocationDedup::new())),
        pending: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new()
        .route("/v1/accord/holder", axum::routing::post(register_holder))
        .route("/v1/accord-holders", axum::routing::get(list_holders))
        .route(
            "/v1/accord/verify-invocation",
            axum::routing::post(verify_invocation_handler),
        )
        // genesis ceremony
        .route(
            "/v1/accord/genesis/envelope",
            axum::routing::post(genesis_envelope),
        )
        .route(
            "/v1/accord/genesis/assemble",
            axum::routing::post(genesis_assemble),
        )
        .route("/v1/accord/family", axum::routing::get(get_family))
        // invocation concurrence
        .route(
            "/v1/accord/invocation",
            axum::routing::post(create_invocation),
        )
        .route(
            "/v1/accord/invocation/concur",
            axum::routing::post(concur_invocation),
        )
        .route(
            "/v1/accord/invocations",
            axum::routing::get(list_invocations),
        )
        .with_state(state)
}
