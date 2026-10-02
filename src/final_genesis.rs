//! **The final genesis** (`FSD/FINAL_GENESIS.md`) — the ceremony routes over
//! persist's assembler (`ciris_persist::federation::genesis::ceremony`,
//! CIRISPersist#973).
//!
//! One ceremony mints the whole root at once: every serve node's record, the
//! labelled charter (successor and per-holder recovery commitments), one
//! quorum-scrubbed grant per serve node, the lifecycle row, the
//! `humanity-accord` family record and the `ciris-canonical` birth record — all
//! carried in ONE bundle, which is the only genesis artifact.
//!
//! The server holds no envelope rules of its own. persist plans the items,
//! recomputes their bytes on every call, verifies each partial as it arrives
//! and runs `verify_ceremony_outputs` at `finish`. The server's part:
//!
//! - **plan** — gather the inputs (the compiled holder roster, the serve nodes,
//!   the operator's successor and recovery keys), stamp `produced_at` ONCE from
//!   this host's clock, and store the state;
//! - **sign** — open one holder's YubiKey + USB pair, sign every item persist
//!   says that holder owes NOW (`next_items`), hand each partial to
//!   `add_partial`, store the state. A holder signs twice: round one (records
//!   and rows), then round two (the two genesis records and the authorization),
//!   which opens once every holder has signed the charter;
//! - **status** — what is owed, by whom;
//! - **finish** — assemble, verify, and write the bundle beside the state.
//!
//! The state lives in `<home>/final-genesis/state.json`, so a restart mid-
//! ceremony resumes with byte-identical items. Every route is loopback-only
//! (it is merged into the accord router's loopback half).

// The helpers return a ready refusal (`Response`) as their error so each route
// can `?`/`return` it as-is; boxing it buys nothing on a loopback ceremony.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;

use ciris_persist::federation::genesis::ceremony::{
    CeremonyError, CeremonyInputs, CeremonyState, CommunityInput, ServeNodeInput,
};
use ciris_persist::federation::trust_root::CommittedKey;
use ciris_persist::prelude::Engine;

/// The `ciris-canonical` community's display name.
pub const COMMUNITY_NAME: &str = "CIRIS Canonical Services";
/// The infrastructure community's key id.
pub const COMMUNITY_KEY_ID: &str = "ciris-canonical";
/// What the charter and every grant confer (the existing charter's set).
pub const GENESIS_SCOPE: [&str; 4] = [
    "infra:attest",
    "infra:serve",
    "infra:store",
    "infra:transport",
];
/// A serve node's roles: `infra:serve` alone was withheld on the mesh; the
/// registry slice walks for `infra:attest`.
pub const SERVE_NODE_ROLES: [&str; 4] = GENESIS_SCOPE;

#[derive(Clone)]
struct FinalGenesisState {
    engine: Arc<Engine>,
    home: std::path::PathBuf,
}

fn dir(home: &std::path::Path) -> std::path::PathBuf {
    home.join("final-genesis")
}
fn state_path(home: &std::path::Path) -> std::path::PathBuf {
    dir(home).join("state.json")
}
fn bundle_path(home: &std::path::Path) -> std::path::PathBuf {
    dir(home).join("canonical_seed.json")
}
fn recovery_path(home: &std::path::Path) -> std::path::PathBuf {
    dir(home).join("recovery-keys.json")
}

/// The recovery keys recorded so far (holder key id → committed key).
fn load_recovery(home: &std::path::Path) -> BTreeMap<String, CommittedKey> {
    std::fs::read_to_string(recovery_path(home))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn refuse(code: StatusCode, reason: &str, detail: impl Into<String>) -> Response {
    (
        code,
        Json(serde_json::json!({ "error": reason, "reason_id": reason, "detail": detail.into() })),
    )
        .into_response()
}

fn ceremony_refusal(e: &CeremonyError) -> Response {
    let status = match e.as_str() {
        "ceremony_incomplete" | "ceremony_item_not_ready" => StatusCode::CONFLICT,
        "ceremony_outputs_refused" => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::BAD_REQUEST,
    };
    refuse(status, e.as_str(), format!("{e}"))
}

fn load(home: &std::path::Path) -> Result<CeremonyState, Response> {
    let raw = std::fs::read_to_string(state_path(home)).map_err(|_| {
        refuse(
            StatusCode::NOT_FOUND,
            "final_genesis.not_planned",
            "no ceremony is planned on this node — POST /v1/accord/final-genesis/plan first",
        )
    })?;
    CeremonyState::from_json(&raw).map_err(|e| ceremony_refusal(&e))
}

fn store(home: &std::path::Path, state: &CeremonyState) -> Result<(), Response> {
    let json = state.to_json().map_err(|e| ceremony_refusal(&e))?;
    let d = dir(home);
    std::fs::create_dir_all(&d).map_err(|e| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "final_genesis.store_failed",
            format!("create {}: {e}", d.display()),
        )
    })?;
    // Write-then-rename: a crash mid-write never leaves half a state.
    let tmp = d.join("state.json.tmp");
    std::fs::write(&tmp, json)
        .and_then(|()| std::fs::rename(&tmp, state_path(home)))
        .map_err(|e| {
            refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "final_genesis.store_failed",
                format!("write the ceremony state: {e}"),
            )
        })
}

// ─── plan ───────────────────────────────────────────────────────────────────

/// One serve node: either just its key id (its record is read from this
/// node's directory) or its full input (a node minted elsewhere whose record
/// has not reached this directory yet).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ServeNodeSpec {
    Id(String),
    Full(ServeNodeInput),
}

#[derive(Debug, Deserialize)]
struct PlanRequest {
    /// The canonicals the bundle seats. Every one must be a FRESH, unique key
    /// (`FSD/FINAL_GENESIS.md` §6: never a key two hosts hold).
    serve_nodes: Vec<ServeNodeSpec>,
    /// CC 3.2 T3 — the successor set, as key material.
    successor_keys: Vec<CommittedKey>,
    /// CC 4.2.6 — holder key id → that holder's recovery key. Omitted: the
    /// keys recorded through `POST /recovery-key` (read off each spare).
    #[serde(default)]
    recovery_keys: BTreeMap<String, CommittedKey>,
    /// The operator confirms this host's clock is synchronized. Required where
    /// the server cannot read the sync state itself; refused if it can and the
    /// clock is NOT synchronized.
    #[serde(default)]
    clock_checked: bool,
    /// Replace a ceremony already planned on this node.
    #[serde(default)]
    replace: bool,
}

/// Is this host's clock NTP-synchronized? `Some(answer)` where it can be read
/// (Linux `timedatectl`), `None` where it cannot.
fn clock_synchronized() -> Option<bool> {
    let out = std::process::Command::new("timedatectl")
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    match String::from_utf8_lossy(&out.stdout).trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

async fn serve_node_input(
    engine: &Engine,
    spec: ServeNodeSpec,
) -> Result<ServeNodeInput, Response> {
    let key_id = match spec {
        ServeNodeSpec::Full(input) => return Ok(input),
        ServeNodeSpec::Id(k) => k,
    };
    let rec = match engine
        .federation_directory()
        .lookup_public_key(&key_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Err(refuse(
                StatusCode::BAD_REQUEST,
                "final_genesis.serve_node_unknown",
                format!(
                    "{key_id} has no key record on this node — pass its full record \
                     ({{key_id, identity_type, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, \
                     capability_roles, registration_envelope}}) instead of its id"
                ),
            ))
        }
        Err(e) => {
            return Err(refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "final_genesis.store_unavailable",
                format!("lookup_public_key({key_id}): {e:#}"),
            ))
        }
    };
    let Some(pqc) = rec.pubkey_ml_dsa_65_base64.clone() else {
        return Err(refuse(
            StatusCode::BAD_REQUEST,
            "final_genesis.serve_node_no_pqc",
            format!("{key_id}'s record carries no ML-DSA-65 key; a genesis node needs both halves"),
        ));
    };
    // The envelope the node registered under, carried; the roles are the
    // genesis set (persist adds the #659 subject binding).
    let mut envelope = rec.registration_envelope.clone();
    if !envelope.is_object() {
        envelope = serde_json::json!({});
    }
    envelope["roles"] = serde_json::json!(SERVE_NODE_ROLES);
    Ok(ServeNodeInput {
        key_id,
        identity_type: "canonical,node".to_string(),
        pubkey_ed25519_base64: rec.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: pqc,
        capability_roles: SERVE_NODE_ROLES.iter().map(|s| (*s).to_string()).collect(),
        registration_envelope: envelope,
        attestation_evidence: rec.attestation_evidence.clone(),
    })
}

/// `POST /v1/accord/final-genesis/plan` — stamp the ceremony once and store it.
async fn plan(State(st): State<FinalGenesisState>, body: axum::body::Bytes) -> Response {
    let req: PlanRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "final_genesis.bad_request",
                e.to_string(),
            )
        }
    };
    if state_path(&st.home).exists() && !req.replace {
        return refuse(
            StatusCode::CONFLICT,
            "final_genesis.already_planned",
            "a ceremony is already planned on this node; pass \"replace\": true to discard it",
        );
    }
    match (clock_synchronized(), req.clock_checked) {
        (Some(false), _) => {
            return refuse(
                StatusCode::PRECONDITION_FAILED,
                "final_genesis.clock_not_synchronized",
                "this host's clock is not NTP-synchronized; every instant in the genesis is \
                 stamped from it, and a receiver refuses one more than 300 s in its future",
            )
        }
        (None, false) => {
            return refuse(
                StatusCode::PRECONDITION_FAILED,
                "final_genesis.clock_unverified",
                "this server cannot read the host's clock-sync state; confirm the clock is \
                 synchronized and pass \"clock_checked\": true",
            )
        }
        _ => {}
    }
    if req.serve_nodes.is_empty() {
        return refuse(
            StatusCode::BAD_REQUEST,
            "final_genesis.no_serve_nodes",
            "a genesis seats at least one canonical",
        );
    }
    let mut serve_nodes = Vec::with_capacity(req.serve_nodes.len());
    for spec in req.serve_nodes {
        match serve_node_input(&st.engine, spec).await {
            Ok(n) => serve_nodes.push(n),
            Err(r) => return r,
        }
    }
    let inputs = CeremonyInputs {
        family_key_id: ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID.to_owned(),
        consensus_protocol: ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL.to_owned(),
        holders: ciris_persist::federation::genesis::effective_accord_holder_records().to_vec(),
        serve_nodes,
        successor_keys: req.successor_keys,
        recovery_keys: if req.recovery_keys.is_empty() {
            load_recovery(&st.home)
        } else {
            req.recovery_keys
        },
        scope: GENESIS_SCOPE.iter().map(|s| (*s).to_string()).collect(),
        community: CommunityInput {
            community_key_id: COMMUNITY_KEY_ID.to_owned(),
            community_name: COMMUNITY_NAME.to_owned(),
            consensus_protocol: "quorum:2/3".to_owned(),
            policy_blob: serde_json::json!({
                "cohort_subkind": "infrastructure",
                "cohort_subkind_payload": {
                    "infrastructure_constraint": {
                        "service_class": "canonical",
                        "admission_quorum_basis": "founders",
                    }
                },
                "consensus_protocol_entrenched": true,
            }),
        },
        produced_at: chrono::Utc::now(),
    };
    let state = match CeremonyState::plan(inputs) {
        Ok(s) => s,
        Err(e) => return ceremony_refusal(&e),
    };
    if let Err(r) = store(&st.home, &state) {
        return r;
    }
    let _ = std::fs::remove_file(bundle_path(&st.home));
    tracing::warn!(
        state = %state_path(&st.home).display(),
        "FINAL GENESIS planned — every holder now signs twice (records and rows, then the \
         genesis records and the authorization)"
    );
    status_body(&state).into_response()
}

// ─── recovery keys ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct RecoveryKeyRequest {
    /// The seated holder this recovery key belongs to (A1, B1, C1).
    holder_key_id: String,
    /// The spare's seal alias (A2, B2, C2) — what its YubiKey + USB open.
    recovery_key_id: String,
    mldsa_usb_path: String,
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
}

/// `POST /v1/accord/final-genesis/recovery-key` — read a holder's SPARE key
/// off its YubiKey + USB and record its public halves as that holder's
/// recovery key (CC 4.2.6; the maintainer: A2 recovers A1, B2 B1, C2 C1).
/// Nothing is signed: the charter commits to the key material, so only the
/// public keys are needed, and reading them from the hardware means nobody
/// copies key material by hand.
async fn record_recovery_key(
    State(st): State<FinalGenesisState>,
    body: axum::body::Bytes,
) -> Response {
    let req: RecoveryKeyRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "final_genesis.bad_request",
                e.to_string(),
            )
        }
    };
    record_recovery_key_impl(st, req).await
}

#[cfg(not(feature = "pkcs11"))]
async fn record_recovery_key_impl(_st: FinalGenesisState, _req: RecoveryKeyRequest) -> Response {
    refuse(
        StatusCode::NOT_IMPLEMENTED,
        "final_genesis.no_hardware_signer",
        "signing needs the `pkcs11` feature (the holder's YubiKey + USB ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn record_recovery_key_impl(st: FinalGenesisState, req: RecoveryKeyRequest) -> Response {
    use base64::Engine as _;
    let holder = req.holder_key_id.trim().to_string();
    let spare = req.recovery_key_id.trim().to_string();
    let roster = ciris_persist::federation::genesis::effective_accord_holder_records();
    if !roster.iter().any(|h| h.record.key_id == holder) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "final_genesis.not_a_holder",
            format!("{holder} is not a seated accord holder"),
        );
    }
    if roster.iter().any(|h| h.record.key_id == spare) {
        return refuse(
            StatusCode::BAD_REQUEST,
            "final_genesis.recovery_key_is_a_holder",
            format!("{spare} is a seated holder's signing key; a recovery key must be a spare"),
        );
    }
    let (ed, pqc) = match crate::accord_provision::open_holder_signers(
        &spare,
        req.mldsa_usb_path.trim(),
        &req.pkcs11,
    )
    .await
    {
        Ok(s) => s,
        Err((code, msg)) => return refuse(code, "final_genesis.signer_unavailable", msg),
    };
    let (ed_pub, pqc_pub) = match (ed.public_key().await, pqc.public_key().await) {
        (Ok(e), Ok(p)) => (e, p),
        (Err(e), _) | (_, Err(e)) => {
            return refuse(
                StatusCode::BAD_GATEWAY,
                "final_genesis.signer_unavailable",
                format!("read {spare}'s public keys: {e}"),
            )
        }
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let key = CommittedKey {
        key_id: spare.clone(),
        pubkey_ed25519_base64: b64.encode(ed_pub),
        pubkey_ml_dsa_65_base64: b64.encode(pqc_pub),
    };
    let mut all = load_recovery(&st.home);
    if all
        .iter()
        .any(|(h, k)| h != &holder && k.key_id == key.key_id)
    {
        return refuse(
            StatusCode::CONFLICT,
            "final_genesis.recovery_key_shared",
            format!("{spare} is already recorded as another holder's recovery key"),
        );
    }
    all.insert(holder.clone(), key.clone());
    let d = dir(&st.home);
    if let Err(e) = std::fs::create_dir_all(&d).and_then(|()| {
        std::fs::write(
            recovery_path(&st.home),
            serde_json::to_string_pretty(&all).unwrap_or_default(),
        )
    }) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "final_genesis.store_failed",
            format!("record the recovery key: {e}"),
        );
    }
    tracing::warn!(holder = %holder, recovery_key = %spare, "FINAL GENESIS: recovery key recorded");
    Json(serde_json::json!({
        "holder_key_id": holder,
        "recovery_key": key,
        "recorded": all.keys().collect::<Vec<_>>(),
    }))
    .into_response()
}

// ─── status ─────────────────────────────────────────────────────────────────

fn status_body(state: &CeremonyState) -> Response {
    let owed = match state.status() {
        Ok(o) => o,
        Err(e) => return ceremony_refusal(&e),
    };
    let ready: Vec<String> = match state.next_items() {
        Ok(items) => items
            .into_iter()
            .filter(|i| i.waits_on.is_empty())
            .map(|i| i.id)
            .collect(),
        Err(e) => return ceremony_refusal(&e),
    };
    let complete = owed.values().all(Vec::is_empty);
    Json(serde_json::json!({
        "complete": complete,
        "signable_now": ready,
        "owed": owed,
    }))
    .into_response()
}

/// `GET /v1/accord/final-genesis` — what is owed, by whom, and what can be
/// signed now.
async fn status(State(st): State<FinalGenesisState>) -> Response {
    match load(&st.home) {
        Ok(state) => status_body(&state),
        Err(r) => r,
    }
}

// ─── sign ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct SignRequest {
    /// The holder signing — the seal alias their YubiKey + USB open.
    key_id: String,
    mldsa_usb_path: String,
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
    /// TEST-ANCHOR ONLY — the DRY RUN: sign as a software test-anchor holder
    /// from its Ed25519 seed (base64), instead of a YubiKey + USB. Compiled
    /// out of production builds, and refused at runtime unless
    /// `CIRIS_TESTING_MODE=true` (the same fence every test-anchor door uses).
    #[cfg(feature = "test-anchor")]
    #[serde(default)]
    test_holder_seed_b64: Option<String>,
}

/// `POST /v1/accord/final-genesis/sign` — sign everything this holder owes now.
async fn sign(State(st): State<FinalGenesisState>, body: axum::body::Bytes) -> Response {
    let req: SignRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "final_genesis.bad_request",
                e.to_string(),
            )
        }
    };
    #[cfg(feature = "test-anchor")]
    if req.test_holder_seed_b64.is_some() {
        return sign_software(st, req);
    }
    sign_impl(st, req).await
}

/// The dry run's signer: a software test-anchor holder, the same identity
/// persist's own minter signs with (`Identity::from_seeds` over the Ed25519
/// seed and its derived ML-DSA-65 seed).
#[cfg(feature = "test-anchor")]
fn sign_software(st: FinalGenesisState, req: SignRequest) -> Response {
    use base64::Engine as _;
    use ciris_persist::federation::accord_test_support::Identity;
    use ciris_persist::federation::genesis::ceremony::Partial;
    use ciris_persist::federation::genesis::test_anchor_mldsa_seed;

    if std::env::var("CIRIS_TESTING_MODE").ok().as_deref() != Some("true") {
        return refuse(
            StatusCode::FORBIDDEN,
            "final_genesis.not_testing_mode",
            "a software holder seed is accepted only with CIRIS_TESTING_MODE=true (the dry run)",
        );
    }
    let seed: [u8; 32] = match req
        .test_holder_seed_b64
        .as_deref()
        .and_then(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s.trim())
                .ok()
        })
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
    {
        Some(s) => s,
        None => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "final_genesis.bad_request",
                "test_holder_seed_b64 must be base64 of exactly 32 bytes",
            )
        }
    };
    let holder = req.key_id.trim().to_string();
    let identity = match Identity::from_seeds(&holder, &seed, &test_anchor_mldsa_seed(&seed)) {
        Ok(i) => i,
        Err(e) => {
            return refuse(
                StatusCode::BAD_REQUEST,
                "final_genesis.signer_unavailable",
                format!("{e}"),
            )
        }
    };
    let mut state = match load(&st.home) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let items = match state.next_items() {
        Ok(items) => items,
        Err(e) => return ceremony_refusal(&e),
    };
    let mut signed = Vec::new();
    for item in items
        .into_iter()
        .filter(|i| i.waits_on.is_empty() && i.owed.iter().any(|h| h == &holder))
    {
        let (classical, pqc) = identity.sign_bytes(&item.bytes);
        if let Err(e) = state.add_partial(Partial {
            item: item.id.clone(),
            holder_key_id: holder.clone(),
            signature_classical: classical,
            signature_pqc: pqc,
        }) {
            let _ = store(&st.home, &state);
            return ceremony_refusal(&e);
        }
        signed.push(item.id);
    }
    if signed.is_empty() {
        return refuse(
            StatusCode::CONFLICT,
            "final_genesis.nothing_to_sign",
            format!("{holder} owes nothing signable right now"),
        );
    }
    if let Err(r) = store(&st.home, &state) {
        return r;
    }
    match state.status() {
        Ok(owed) => Json(serde_json::json!({ "signed": signed, "owed": owed })).into_response(),
        Err(e) => ceremony_refusal(&e),
    }
}

#[cfg(not(feature = "pkcs11"))]
async fn sign_impl(_st: FinalGenesisState, _req: SignRequest) -> Response {
    refuse(
        StatusCode::NOT_IMPLEMENTED,
        "final_genesis.no_hardware_signer",
        "signing needs the `pkcs11` feature (the holder's YubiKey + USB ML-DSA signer)",
    )
}

#[cfg(feature = "pkcs11")]
async fn sign_impl(st: FinalGenesisState, req: SignRequest) -> Response {
    use ciris_persist::federation::genesis::ceremony::Partial;
    use ciris_verify_core::self_at_login::SelfSigner;

    let mut state = match load(&st.home) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let items = match state.next_items() {
        Ok(items) => items,
        Err(e) => return ceremony_refusal(&e),
    };
    let holder = req.key_id.trim().to_string();
    let mine: Vec<_> = items
        .into_iter()
        .filter(|i| i.waits_on.is_empty() && i.owed.iter().any(|h| h == &holder))
        .collect();
    if mine.is_empty() {
        return refuse(
            StatusCode::CONFLICT,
            "final_genesis.nothing_to_sign",
            format!(
                "{holder} owes nothing signable right now — either every item it owes is \
                 signed, or the next round waits on another holder signing the charter \
                 (GET /v1/accord/final-genesis)"
            ),
        );
    }
    // ONE YubiKey + USB session for the whole batch.
    let identity = match crate::accord_provision::open_holder_identity(
        &holder,
        req.mldsa_usb_path.trim(),
        &req.pkcs11,
    )
    .await
    {
        Ok(i) => i,
        Err((code, msg)) => return refuse(code, "final_genesis.signer_unavailable", msg),
    };
    let mut signed = Vec::with_capacity(mine.len());
    for item in mine {
        let (ed, pqc) = match identity.sign_bound(&item.bytes).await {
            Ok(s) => s,
            Err(e) => {
                // Keep what was already signed: each partial is verified and
                // stored as it lands, so a retry signs only the rest.
                let _ = store(&st.home, &state);
                return refuse(
                    StatusCode::BAD_GATEWAY,
                    "final_genesis.sign_failed",
                    format!("sign {}: {e}", item.id),
                );
            }
        };
        if let Err(e) = state.add_partial(Partial {
            item: item.id.clone(),
            holder_key_id: holder.clone(),
            signature_classical: ed,
            signature_pqc: pqc,
        }) {
            let _ = store(&st.home, &state);
            return ceremony_refusal(&e);
        }
        signed.push(item.id);
        if let Err(r) = store(&st.home, &state) {
            return r;
        }
    }
    tracing::warn!(holder = %holder, items = ?signed, "FINAL GENESIS: a holder signed");
    let mut body = match state.status() {
        Ok(owed) => serde_json::json!({ "signed": signed, "owed": owed }),
        Err(e) => return ceremony_refusal(&e),
    };
    body["complete"] = serde_json::json!(body["owed"]
        .as_object()
        .is_some_and(|o| o.values().all(|v| v.as_array().is_some_and(Vec::is_empty))));
    Json(body).into_response()
}

// ─── finish ─────────────────────────────────────────────────────────────────

/// `POST /v1/accord/final-genesis/finish` — assemble, verify (the same doors a
/// booting node runs), and write the bundle.
async fn finish(State(st): State<FinalGenesisState>) -> Response {
    let state = match load(&st.home) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let done = match state.finish().await {
        Ok(d) => d,
        Err(e) => return ceremony_refusal(&e),
    };
    let path = bundle_path(&st.home);
    if let Err(e) = std::fs::write(&path, &done.bundle_json) {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "final_genesis.store_failed",
            format!("write {}: {e}", path.display()),
        );
    }
    let fingerprint = {
        use sha2::{Digest, Sha256};
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(done.bundle_json.as_bytes()))
        )
    };
    tracing::warn!(
        bundle = %path.display(),
        %fingerprint,
        "FINAL GENESIS complete and verified — hand canonical_seed.json to persist to bake"
    );
    Json(serde_json::json!({
        "complete": true,
        "bundle_path": path.display().to_string(),
        "bundle_sha256": fingerprint,
        "verified": {
            "quorum_verified": done.verified.quorum_verified,
            "serve_nodes": done.verified.serve_nodes,
            "attestations": done.verified.attestations,
            "community_key_id": done.verified.community_key_id,
            "founders": done.verified.founders,
        },
    }))
    .into_response()
}

/// `POST /v1/accord/genesis/{propose,cosign}` — the retired 2-of-3 re-mint.
/// On persist v53 its charter lacks the per-holder recovery commitments and
/// the genesis records, so it could only ever be refused; it answers 410 and
/// names the one genesis.
pub(crate) async fn remint_superseded() -> Response {
    refuse(
        StatusCode::GONE,
        "accord.genesis_superseded",
        "the 2-of-3 propose/cosign re-mint is retired; the genesis is one ceremony signed by \
         all three holders at /v1/accord/final-genesis (plan, sign, finish)",
    )
}

/// The routes, loopback-only (merged into the accord router's loopback half).
pub fn router(engine: Arc<Engine>, home: std::path::PathBuf) -> Router {
    Router::new()
        .route("/v1/accord/final-genesis", axum::routing::get(status))
        .route(
            "/v1/accord/final-genesis/recovery-key",
            axum::routing::post(record_recovery_key),
        )
        .route("/v1/accord/final-genesis/plan", axum::routing::post(plan))
        .route("/v1/accord/final-genesis/sign", axum::routing::post(sign))
        .route(
            "/v1/accord/final-genesis/finish",
            axum::routing::post(finish),
        )
        .with_state(FinalGenesisState { engine, home })
}
