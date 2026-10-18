//! **Add a device** — a new device joins its owner's identity as a new
//! occurrence, peer to peer, with the owner's consent (CIRISServer#177,
//! `FSD/ADD_DEVICE.md`, model `formal/add_device`).
//!
//! Edge owns the plane: CIRISEdge#683's first contact on the opaque plane, the
//! server's device-join kind [`DEVICE_JOIN_KIND`]. A never-seen device B sends an
//! `OpaqueRequest` signed by its NODE key carrying its self-signed key record;
//! edge rate-limits it per sender, per link and node-wide BEFORE any
//! cryptography, proves possession, admits the key (which grants nothing) and
//! hands this module the request. This module owns the rest:
//!
//! * **On A (the owner's device)** — a synchronous answerer
//!   ([`register_answerer`]) that holds `join` requests only while the owner has
//!   opened "add a device", bounds them ([`PENDING_CEILING`], one per sender),
//!   derives the MATCHING CODE itself (N1), and answers `status` polls; and the
//!   owner's routes under `/v1/self/device-requests`, where approval signs the
//!   owner-binding to B's node and B's occurrence under the owner's self, records
//!   both here, and re-wraps the self DEKs to B. A decided request frees its slot
//!   at once (N3 — the starvation TLC found).
//! * **On B (the new device)** — `POST /v1/setup/add-device` (loopback,
//!   first-run): resolve the person's code, mint B's own device occurrence keys,
//!   send the join, then poll until the owner answers; on approval apply the
//!   binding through B's own `/v1/setup/root` with B's own claim PIN (binding
//!   first), then the occurrence (N4). The wizard collects its session with the
//!   existing `POST /v1/setup/claimed-session`.
//!
//! No key material crosses in either direction (N6).
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use ciris_persist::federation::{EncryptionPubkeys, SignedIdentityOccurrence, SignedKeyRecord};
use ciris_persist::prelude::{Engine, HybridPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::refusal::refuse;

/// The server's device-join kind on edge's opaque plane (CIRISEdge#683,
/// `FSD/FIRST_CONTACT.md` §2.2).
pub const DEVICE_JOIN_KIND: u32 = 0x0000_0002;
/// The most join requests A holds at once (N3).
pub const PENDING_CEILING: usize = 8;
/// How long an undecided request is held, and how long B keeps asking.
pub const REQUEST_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a decided answer stays collectable by B's poll.
pub const DECIDED_TTL: Duration = Duration::from_secs(15 * 60);
/// The default and maximum "add a device" window on A.
pub const WINDOW_DEFAULT: Duration = Duration::from_secs(10 * 60);
pub const WINDOW_MAX: Duration = Duration::from_secs(30 * 60);
/// B's poll cadence while waiting for the owner.
pub const POLL_EVERY: Duration = Duration::from_secs(3);
/// One opaque round trip.
const ROUND_TIMEOUT_MS: u64 = 20_000;

// ─── wire ──────────────────────────────────────────────────────────────────

/// B → A, opaque payload of kind [`DEVICE_JOIN_KIND`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum JoinOp {
    /// Ask to join. Signed (by edge) with B's node key.
    Join(Box<JoinRequest>),
    /// Ask how the owner answered.
    Status {
        request_id: String,
        challenge: String,
    },
}

/// What B asks A to sign. Public halves only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub v: u32,
    /// B's NodeCode — what the owner-binding pins, and the node it names MUST be
    /// the request's signer.
    pub node_code: String,
    /// 32 fresh random bytes, hex. Correlates B's polls and seeds the code.
    pub challenge: String,
    pub label: String,
    pub device_class: String,
    /// B's new device occurrence key, self-signed (proof of possession).
    pub occurrence_key_record: SignedKeyRecord,
    /// B's content-KEM keys for that occurrence (the self-DEK recipient).
    pub encryption_pubkeys: EncryptionPubkeys,
}

/// A → B, the answer payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JoinAnswer {
    Pending {
        request_id: String,
        match_code: String,
    },
    Approved(Box<Approval>),
    Denied,
    /// The request is not (or no longer) known to A.
    Unknown,
    /// A is not taking join requests now (window closed, or full). Generic on
    /// purpose: a refusal that says why is a tuning oracle (#554 D3).
    NotAccepting,
}

/// What the owner signed for B.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub node_code: String,
    pub cohort_scope: String,
    pub owner_binding: crate::auth::ownership::SignedOwnerBinding,
    /// A's own key record: B's setup/root admits the device that claimed it.
    #[serde(default)]
    pub claimer_key_record: Option<SignedKeyRecord>,
    /// B's occurrence under the owner's self, signed by the owner.
    pub occurrence: SignedIdentityOccurrence,
    /// The owner's full v3 code (key id, Ed25519 key, ML-DSA-65 commitment, and
    /// the approving node with its transport key). The signer is REMOTE, so B
    /// validates the whole approval against this and the fedID the person
    /// entered, offline: no canonical lookup.
    #[serde(default)]
    pub owner_code: Option<String>,
}

/// N1: the matching code, derived by A from (requester key, challenge). Six
/// digits; an attacker who copies B's challenge still gets a different code.
pub fn match_code(sender_key_id: &str, challenge: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ciris-device-join-code-v1\n");
    h.update(sender_key_id.as_bytes());
    h.update(b"\n");
    h.update(challenge.as_bytes());
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

fn opaque(status: u16, answer: &JoinAnswer) -> ciris_edge::OpaqueResponse {
    ciris_edge::OpaqueResponse {
        kind: DEVICE_JOIN_KIND,
        status,
        payload: serde_json::to_vec(answer).unwrap_or_default(),
    }
}

// ─── A: the host side ──────────────────────────────────────────────────────

struct Held {
    id: String,
    sender: String,
    req: JoinRequest,
    code: String,
    at: Instant,
}

enum Decision {
    Approved(Box<Approval>, ciris_edge::Introductions),
    Denied,
}

struct Decided {
    sender: String,
    challenge: String,
    decision: Decision,
    at: Instant,
}

#[derive(Default)]
struct Host {
    window_until: Option<Instant>,
    pending: Vec<Held>,
    decided: HashMap<String, Decided>,
}

fn host() -> &'static Mutex<Host> {
    static H: OnceLock<Mutex<Host>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(Host::default()))
}

impl Host {
    fn sweep(&mut self) {
        let now = Instant::now();
        let before = self.pending.len();
        self.pending
            .retain(|h| now.duration_since(h.at) < REQUEST_TTL);
        if self.pending.len() != before {
            tracing::info!(
                expired = before - self.pending.len(),
                "device-join: undecided requests expired"
            );
        }
        self.decided
            .retain(|_, d| now.duration_since(d.at) < DECIDED_TTL);
        if self.window_until.is_some_and(|w| now >= w) {
            self.window_until = None;
        }
    }

    fn open(&self) -> bool {
        self.window_until.is_some_and(|w| Instant::now() < w)
    }
}

/// The synchronous edge answerer for [`DEVICE_JOIN_KIND`].
fn answer(ctx: ciris_edge::OpaqueRequestContext) -> ciris_edge::OpaqueAnswer {
    let op: JoinOp = match serde_json::from_slice(&ctx.payload) {
        Ok(op) => op,
        Err(_) => return opaque(400, &JoinAnswer::Unknown).into(),
    };
    let mut h = match host().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    h.sweep();
    match op {
        JoinOp::Join(req) => {
            // N2: held only inside the owner's window; otherwise refused, not queued.
            if !h.open() {
                tracing::info!(sender = %ctx.sender_key_id, "device-join: refused — the owner has not opened \"add a device\"");
                return opaque(403, &JoinAnswer::NotAccepting).into();
            }
            // The NodeCode must name the request's signer: the binding the owner
            // will sign pins that node, and nobody may ask on another node's behalf.
            let names_signer = crate::nodecode::decode(&req.node_code)
                .map(|nc| nc.key_id == ctx.sender_key_id)
                .unwrap_or(false);
            if !names_signer || req.challenge.len() < 32 {
                tracing::info!(sender = %ctx.sender_key_id, "device-join: refused — malformed request (node code does not name the signer, or no challenge)");
                return opaque(400, &JoinAnswer::NotAccepting).into();
            }
            // One per sender: a repeat returns the held request (idempotent).
            if let Some(held) = h.pending.iter().find(|p| p.sender == ctx.sender_key_id) {
                return opaque(
                    202,
                    &JoinAnswer::Pending {
                        request_id: held.id.clone(),
                        match_code: held.code.clone(),
                    },
                )
                .into();
            }
            if h.pending.len() >= PENDING_CEILING {
                tracing::warn!(
                    ceiling = PENDING_CEILING,
                    "device-join: refused — pending ceiling reached"
                );
                return opaque(503, &JoinAnswer::NotAccepting).into();
            }
            let code = match_code(&ctx.sender_key_id, &req.challenge);
            let id = uuid::Uuid::new_v4().to_string();
            tracing::info!(
                sender = %ctx.sender_key_id, request_id = %id, label = %req.label,
                first_contact = ctx.first_contact,
                "device-join: request held — waiting for the owner's consent"
            );
            h.pending.push(Held {
                id: id.clone(),
                sender: ctx.sender_key_id,
                req: *req,
                code: code.clone(),
                at: Instant::now(),
            });
            opaque(
                202,
                &JoinAnswer::Pending {
                    request_id: id,
                    match_code: code,
                },
            )
            .into()
        }
        JoinOp::Status {
            request_id,
            challenge,
        } => {
            if let Some(d) = h.decided.get(&request_id) {
                if d.sender != ctx.sender_key_id || d.challenge != challenge {
                    return opaque(404, &JoinAnswer::Unknown).into();
                }
                return match &d.decision {
                    Decision::Approved(a, intro) => ciris_edge::OpaqueAnswer {
                        response: opaque(200, &JoinAnswer::Approved(a.clone())),
                        introductions: intro.clone(),
                    },
                    Decision::Denied => opaque(200, &JoinAnswer::Denied).into(),
                };
            }
            match h.pending.iter().find(|p| {
                p.id == request_id && p.sender == ctx.sender_key_id && p.req.challenge == challenge
            }) {
                Some(p) => opaque(
                    202,
                    &JoinAnswer::Pending {
                        request_id,
                        match_code: p.code.clone(),
                    },
                )
                .into(),
                None => opaque(404, &JoinAnswer::Unknown).into(),
            }
        }
    }
}

/// Register the device-join answerer on this node's edge. Called once at compose.
pub fn register_answerer(edge: &ciris_edge::Edge) {
    edge.register_opaque_answerer(DEVICE_JOIN_KIND, answer);
}

// ─── B: the requester side ─────────────────────────────────────────────────

/// The live edge, for B's sends. Set once at compose.
static EDGE: OnceLock<Arc<ciris_edge::Edge>> = OnceLock::new();

/// Hand this module the composition root's edge (B sends through it).
pub fn set_edge(edge: Arc<ciris_edge::Edge>) {
    let _ = EDGE.set(edge);
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct JoinProgress {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrence_key_id: Option<String>,
    /// The identity this device is joining, once the owner's approval verified.
    /// The wizard SHOWS it; it never asks for a fedID name on this path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn progress() -> &'static Mutex<JoinProgress> {
    static P: OnceLock<Mutex<JoinProgress>> = OnceLock::new();
    P.get_or_init(|| {
        Mutex::new(JoinProgress {
            state: "idle".into(),
            ..Default::default()
        })
    })
}

fn set_progress(f: impl FnOnce(&mut JoinProgress)) {
    if let Ok(mut p) = progress().lock() {
        f(&mut p);
    }
}

// ─── HTTP ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AddDeviceState {
    pub engine: Arc<Engine>,
    /// THIS node's federation key id (the node being added, on B; the owner's
    /// node, on A).
    pub node_key_id: String,
    /// THIS node's NodeCode (B sends it; the owner-binding pins it).
    pub node_code: String,
    /// THIS node's self-signed key record (A hands it to B as the claimer).
    pub self_key_record: Option<SignedKeyRecord>,
    /// The owner user alias fallback and seed dir (A resolves the owner's pen).
    pub user_key_id: String,
    pub user_seed_dir: std::path::PathBuf,
    /// Where B's device occurrence keys are minted.
    pub identity_dir: std::path::PathBuf,
    /// This node's own read-API base (B applies the binding to itself).
    pub local_self_url: String,
    /// This node's claim PIN file (B's local presence for its own setup/root).
    pub claim_pin_file: std::path::PathBuf,
    pub policy: HybridPolicy,
}

#[derive(Debug, Deserialize)]
struct StartRequest {
    contact: String,
    #[serde(default)]
    label: Option<String>,
}

/// `POST /v1/setup/add-device` — B asks the person's existing device to add it.
async fn start(State(st): State<AddDeviceState>, Json(req): Json<StartRequest>) -> Response {
    if !crate::auth::bootstrap::is_first_run(&st.engine).await {
        return refuse(
            StatusCode::CONFLICT,
            "add_device.already_owned",
            "this device already has an owner",
        );
    }
    let Some(edge) = EDGE.get().cloned() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "add_device.no_transport",
            "this device has no mesh transport running, so it cannot reach your other device",
        );
    };
    // 1. Who: resolve the person's code (QR / long form / short form) to their nodes.
    let directory = st.engine.federation_directory();
    let lens = ciris_edge::contact::PersistLens::new(&*directory);
    let subject = match ciris_edge::contact::resolve_contact(&lens, req.contact.trim()).await {
        Ok(ciris_edge::contact::ContactResolution::Known(s)) => s,
        Ok(ciris_edge::contact::ContactResolution::ReadyFromCode { subject, .. }) => subject,
        Err(stall) => {
            return refuse(
                StatusCode::NOT_FOUND,
                "add_device.unknown_identity",
                format!("could not find that identity: {stall:?}"),
            )
        }
    };
    let Some(target) = subject
        .nodes
        .iter()
        .find(|n| **n != st.node_key_id)
        .cloned()
    else {
        return refuse(
            StatusCode::NOT_FOUND,
            "add_device.no_device",
            "that code names no device to ask — open Share my ID on your other device and use its QR or long form",
        );
    };
    // 2. Mint B's own device occurrence keys (public halves travel; N6).
    let label = req.label.unwrap_or_else(|| "new device".into());
    let alias = format!(
        "device-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let occurrence_dir = st.identity_dir.join("user");
    let keyset = match crate::identity::mint_local_device_occurrence(&occurrence_dir, &alias).await
    {
        Ok(k) => k,
        Err(e) => {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "add_device.mint_failed",
                format!("mint device keys: {e:#}"),
            )
        }
    };
    // The occurrence the owner will sign references this key: register it here
    // now (proof of possession through the fail-secure gate), or B's own
    // directory refuses the owner-signed occurrence on a foreign key.
    if directory
        .lookup_public_key(&keyset.key_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        if let Err(e) = crate::hardware_attestation::register_attested_federation_key(
            &st.engine,
            keyset.key_record.clone(),
        )
        .await
        {
            return refuse(
                StatusCode::INTERNAL_SERVER_ERROR,
                "add_device.mint_failed",
                format!("register this device's new occurrence key: {e:#}"),
            );
        }
    }
    let Some(enc) = keyset.encryption_pubkeys.clone() else {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "add_device.mint_failed",
            "device keys carry no encryption keys",
        );
    };
    let mut ch = [0u8; 32];
    if ciris_crypto::random::fill(&mut ch).is_err() {
        return refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "add_device.rng",
            "no randomness for the challenge",
        );
    }
    let challenge = hex::encode(ch);
    let join = JoinOp::Join(Box::new(JoinRequest {
        v: 1,
        node_code: st.node_code.clone(),
        challenge: challenge.clone(),
        label,
        device_class: crate::auth::occurrence::DEVICE_CLASS_LAPTOP.into(),
        occurrence_key_record: keyset.key_record.clone(),
        encryption_pubkeys: enc,
    }));
    // 3. Ask — a first contact: the request carries this node's own key record.
    let exchange = match edge
        .send_opaque_request_introducing(
            &target,
            DEVICE_JOIN_KIND,
            serde_json::to_vec(&join).unwrap_or_default(),
            ROUND_TIMEOUT_MS,
        )
        .await
    {
        Ok(x) => x,
        Err(e) => {
            return refuse(
                StatusCode::BAD_GATEWAY,
                "add_device.unreachable",
                format!("could not reach your other device: {e}"),
            )
        }
    };
    let ans: JoinAnswer =
        serde_json::from_slice(&exchange.response.payload).unwrap_or(JoinAnswer::Unknown);
    let (request_id, code) = match ans {
        JoinAnswer::Pending { request_id, match_code } => (request_id, match_code),
        JoinAnswer::NotAccepting => {
            return refuse(
                StatusCode::CONFLICT,
                "add_device.not_accepting",
                "your other device is not accepting new devices — open Add a device on it, then try again",
            )
        }
        other => {
            return refuse(StatusCode::BAD_GATEWAY, "add_device.unexpected", format!("unexpected answer: {other:?}"))
        }
    };
    set_progress(|p| {
        *p = JoinProgress {
            state: "requested".into(),
            match_code: Some(code.clone()),
            target_node: Some(target.clone()),
            occurrence_key_id: Some(keyset.key_id.clone()),
            owner_key_id: None,
            detail: None,
        }
    });
    tracing::info!(target = %target, request_id = %request_id, "add-device: request sent — waiting for the owner's consent");
    tokio::spawn(poll_until_answered(
        st,
        edge,
        Asked {
            target: target.clone(),
            request_id,
            challenge,
            alias,
            expected_owner: subject.fed_id.clone(),
            occurrence_key: keyset.key_id.clone(),
        },
    ));
    (
        StatusCode::ACCEPTED,
        Json(progress().lock().map(|p| p.clone()).unwrap_or_default()),
    )
        .into_response()
}

/// One outstanding join request on B: where it went and what it expects back.
struct Asked {
    target: String,
    request_id: String,
    challenge: String,
    /// The alias B minted its occurrence keys under.
    alias: String,
    /// The fedID the person entered; the approval must be for exactly it.
    expected_owner: String,
    /// The occurrence key B minted; the owner's occurrence must name it.
    occurrence_key: String,
}

/// B's poll: ask until the owner answers, then verify and hold (§2.1).
async fn poll_until_answered(st: AddDeviceState, edge: Arc<ciris_edge::Edge>, asked: Asked) {
    let Asked {
        target,
        request_id,
        challenge,
        alias,
        expected_owner,
        occurrence_key,
    } = asked;
    let deadline = Instant::now() + REQUEST_TTL;
    while Instant::now() < deadline {
        tokio::time::sleep(POLL_EVERY).await;
        let op = JoinOp::Status {
            request_id: request_id.clone(),
            challenge: challenge.clone(),
        };
        let x = match edge
            .send_opaque_request_introducing(
                &target,
                DEVICE_JOIN_KIND,
                serde_json::to_vec(&op).unwrap_or_default(),
                ROUND_TIMEOUT_MS,
            )
            .await
        {
            Ok(x) => x,
            Err(e) => {
                tracing::debug!(error = %e, "add-device: status poll failed; retrying");
                continue;
            }
        };
        match serde_json::from_slice::<JoinAnswer>(&x.response.payload) {
            Ok(JoinAnswer::Pending { .. }) => continue,
            Ok(JoinAnswer::Approved(a)) => {
                // VALIDATE now, APPLY at the end of the wizard: the claim then
                // lands at the same point in first run as a new identity's.
                match preflight(&st, &a, &expected_owner, &occurrence_key) {
                    Ok(owner) => {
                        let held = Pending {
                            approval: *a,
                            alias: alias.clone(),
                            owner: owner.clone(),
                        };
                        if let Err(e) = hold(&st, held) {
                            tracing::warn!(error = %e, "add-device: verified approval could not be kept on disk; held in memory only");
                        }
                        set_progress(|p| {
                            p.state = "approved".into();
                            p.owner_key_id = Some(owner.clone());
                        });
                        tracing::info!(owner = %owner, "add-device: the owner's approval VERIFIED offline and HELD — the claim applies when first run completes (POST /v1/setup/add-device/complete)");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "add-device: the owner's approval did NOT verify — nothing applied");
                        set_progress(|p| {
                            p.state = "failed".into();
                            p.detail = Some(e);
                        });
                    }
                }
                return;
            }
            Ok(JoinAnswer::Denied) => {
                set_progress(|p| p.state = "denied".into());
                return;
            }
            Ok(other) => {
                set_progress(|p| {
                    p.state = "failed".into();
                    p.detail = Some(format!("{other:?}"));
                });
                return;
            }
            Err(e) => tracing::debug!(error = %e, "add-device: unreadable status answer; retrying"),
        }
    }
    set_progress(|p| p.state = "expired".into());
}

// ─── B: validate now, apply at the end of first run ────────────────────────

/// A verified approval waiting for the wizard to finish.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pending {
    approval: Approval,
    alias: String,
    owner: String,
}

fn pending() -> &'static Mutex<Option<Pending>> {
    static P: OnceLock<Mutex<Option<Pending>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

fn pending_path(st: &AddDeviceState) -> std::path::PathBuf {
    st.identity_dir
        .parent()
        .unwrap_or(&st.identity_dir)
        .join("add_device_pending.json")
}

/// Keep a verified approval in memory and on disk (0600), so a restart mid-
/// wizard still completes. It holds only public, signed material.
fn hold(st: &AddDeviceState, p: Pending) -> Result<(), String> {
    let path = pending_path(st);
    let bytes = serde_json::to_vec(&p).map_err(|e| format!("serialize: {e}"))?;
    if let Ok(mut g) = pending().lock() {
        *g = Some(p);
    }
    std::fs::write(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// On boot: a verified approval written before a restart is held again.
fn restore_pending(st: &AddDeviceState) {
    let path = pending_path(st);
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    match serde_json::from_slice::<Pending>(&bytes) {
        Ok(p) => {
            let owner = p.owner.clone();
            if let Ok(mut g) = pending().lock() {
                *g = Some(p);
            }
            set_progress(|pr| {
                pr.state = "approved".into();
                pr.owner_key_id = Some(owner);
            });
            tracing::info!(path = %path.display(), "add-device: a verified approval from before this boot is HELD — complete first run to apply it");
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "add-device: unreadable held approval ignored")
        }
    }
}

/// **Verify the owner's approval offline, without applying it.** The signer is
/// remote, so everything is checked against the owner's v3 code carried in the
/// approval and the fedID the person entered:
/// 1. the approval pins THIS node's NodeCode;
/// 2. the v3 code names the identity the person entered;
/// 3. the code's fedID fingerprint matches its Ed25519 key;
/// 4. the binding's Ed25519 key is the code's, and its full ML-DSA-65 key
///    matches the code's commitment;
/// 5. the owner-binding verifies (structure + hybrid signature, Strict);
/// 6. the occurrence names this identity and this device's minted key, and its
///    hybrid signature verifies under the same owner keys;
/// 7. this device still has its claim PIN (local presence for the apply).
///
/// Returns the owner's fedID.
fn preflight(
    st: &AddDeviceState,
    a: &Approval,
    expected_owner: &str,
    occurrence_key: &str,
) -> Result<String, String> {
    use base64::Engine as _;
    use ciris_verify_core::fedcode;
    let b64 = base64::engine::general_purpose::STANDARD;
    if a.node_code != st.node_code {
        return Err("the approval pins a different node than this one".into());
    }
    let node_key = crate::nodecode::decode(&st.node_code)
        .map_err(|e| format!("this node's own NodeCode: {e}"))?
        .key_id;
    let code = a
        .owner_code
        .as_deref()
        .ok_or("the approval carries no owner code (v3); the approving device must be upgraded")?;
    let fc = fedcode::decode(code).map_err(|e| format!("the owner's code: {e}"))?;
    if fc.key_id != expected_owner {
        return Err(format!(
            "the approval is for {} but you entered {expected_owner}",
            fc.key_id
        ));
    }
    let ed = b64
        .decode(&fc.pubkey_ed25519_base64)
        .map_err(|e| format!("the code's Ed25519 key: {e}"))?;
    let derived = fedcode::derive_key_id("x", &ed);
    let fp = derived.rsplit('-').next().unwrap_or_default();
    if fp.is_empty() || !fc.key_id.ends_with(fp) {
        return Err("the code's fedID does not match its own Ed25519 key".into());
    }
    let b = &a.owner_binding;
    if b.attesting_key_id != fc.key_id {
        return Err("the owner-binding is signed by someone other than the code's identity".into());
    }
    if b.ed25519_pubkey_b64 != fc.pubkey_ed25519_base64 {
        return Err("the owner-binding's Ed25519 key is not the code's".into());
    }
    let pqc = b64
        .decode(&b.ml_dsa_65_pubkey_b64)
        .map_err(|e| format!("the owner-binding's ML-DSA-65 key: {e}"))?;
    fedcode::AdmittedHybridKey::admit(&fc, &pqc)
        .map_err(|e| format!("the owner's ML-DSA-65 key vs the code's commitment: {e}"))?;
    crate::auth::ownership::verify_signed_owner_binding(&node_key, st.policy, b)
        .map_err(|e| format!("the owner-binding: {e}"))?;
    let occ = &a.occurrence;
    let row = &occ.identity_occurrence;
    if occ.attesting_key_id != fc.key_id || row.identity_key_id != fc.key_id {
        return Err("the occurrence is not the owner's".into());
    }
    if row.occurrence_key_id != occurrence_key {
        return Err("the occurrence names a different key than this device minted".into());
    }
    let bytes = ciris_persist::verify::canonical::ceg_produce_canonicalize(&occ.signed_envelope)
        .map_err(|e| format!("the occurrence envelope: {e}"))?;
    let members = [ciris_verify_core::threshold::ThresholdMember {
        member_id: fc.key_id.clone(),
        ed25519_public_key_base64: fc.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: Some(b.ml_dsa_65_pubkey_b64.clone()),
        role: None,
    }];
    let sigs = [ciris_verify_core::threshold::ThresholdSignature {
        member_id: fc.key_id.clone(),
        ed25519_signature_base64: occ.signature.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: occ.signature.mldsa65_signature_base64.clone(),
    }];
    ciris_verify_core::threshold::verify_threshold_signatures(&bytes, &members, &sigs, 1)
        .map_err(|e| format!("the occurrence signature: {e}"))?;
    let pin = std::fs::read_to_string(&st.claim_pin_file).unwrap_or_default();
    if pin.trim().is_empty() {
        return Err("this device has no claim PIN left; it may already be claimed".into());
    }
    Ok(fc.key_id)
}

/// `POST /v1/setup/add-device/complete` — the end of first run on a device
/// joining an existing identity: apply the verified, held approval (the claim
/// through this node's own setup/root, then the occurrence and the active
/// identity). The wizard then collects its session with `claimed-session`, as
/// the new-identity path does.
async fn complete(State(st): State<AddDeviceState>) -> Response {
    let held = pending().lock().ok().and_then(|g| g.clone());
    let Some(p) = held else {
        return refuse(
            StatusCode::CONFLICT,
            "add_device.not_approved",
            "your other device has not approved this one yet",
        );
    };
    match apply(&st, p.approval, &p.alias).await {
        Ok(()) => {
            if let Ok(mut g) = pending().lock() {
                *g = None;
            }
            let _ = std::fs::remove_file(pending_path(&st));
            set_progress(|pr| pr.state = "applied".into());
            tracing::info!(owner = %p.owner, "add-device: APPLIED at first-run completion — this device is now an occurrence of its owner's identity");
            (
                StatusCode::OK,
                Json(progress().lock().map(|pr| pr.clone()).unwrap_or_default()),
            )
                .into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "add-device: applying the held approval failed");
            refuse(StatusCode::BAD_GATEWAY, "add_device.apply_failed", e)
        }
    }
}

/// The owner's v3 code, built from the owner's registered key and this
/// (approving) node's transport key, so B can verify and reach A offline.
async fn owner_code(st: &AddDeviceState, owner: &str) -> Result<String, String> {
    use base64::Engine as _;
    use ciris_verify_core::fedcode;
    let directory = st.engine.federation_directory();
    let rec = directory
        .lookup_public_key(owner)
        .await
        .map_err(|e| format!("look up the owner's key: {e}"))?
        .ok_or("the owner's key is not registered on this device")?;
    let pqc_b64 = rec
        .pubkey_ml_dsa_65_base64
        .as_deref()
        .ok_or("the owner's key record carries no ML-DSA-65 half")?;
    let pqc = base64::engine::general_purpose::STANDARD
        .decode(pqc_b64)
        .map_err(|e| format!("the owner's ML-DSA-65 key: {e}"))?;
    let commitment = hex::encode(Sha256::digest(&pqc));
    let mut fc = fedcode::FedCode::new(
        fedcode::FedKind::User,
        owner.to_string(),
        rec.pubkey_ed25519_base64.clone(),
    )
    .with_ml_dsa_65_pubkey_sha256(commitment);
    let me = crate::node_key::wire_identity()
        .map(str::to_owned)
        .unwrap_or_else(|| st.node_key_id.clone());
    if let Ok(routes) = directory.list_transport_destinations_for(&me).await {
        if let Some(t) = routes
            .into_iter()
            .find_map(|d| d.transport_ed25519_pubkey_base64)
        {
            fc = fc.with_owned_nodes(vec![fedcode::OwnedNode::new(me, t)]);
        }
    }
    fedcode::encode(&fc).map_err(|e| format!("encode the owner's code: {e}"))
}

/// Apply the owner's approval on B: the binding through B's OWN setup/root with
/// B's own claim PIN (local presence), then the owner-signed occurrence.
async fn apply(st: &AddDeviceState, a: Approval, alias: &str) -> Result<(), String> {
    let pin = std::fs::read_to_string(&st.claim_pin_file)
        .map_err(|e| format!("read this device's claim PIN file: {e}"))?;
    let body = serde_json::json!({
        "node_code": a.node_code,
        "cohort_scope": a.cohort_scope,
        "claim_pin": pin.trim(),
        "owner_binding": a.owner_binding,
        "claimer_key_record": a.claimer_key_record,
    });
    let url = format!("{}/v1/setup/root", st.local_self_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("setup/root: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "setup/root answered {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    // Binding first, occurrence second: the owner's key is registered now.
    st.engine
        .federation_directory()
        .put_identity_occurrence(a.occurrence)
        .await
        .map_err(|e| format!("admit the owner-signed occurrence: {e}"))?;
    // This device now speaks for the identity with ITS OWN key: make it the
    // active user identity here, so every owner act on this device (the self
    // room, consent, re-wraps) signs as the occurrence the owner admitted.
    crate::write_active_user_alias(&st.identity_dir.join("user"), alias)
        .map_err(|e| format!("make the occurrence this device's active identity: {e}"))?;
    crate::replication_reconcile::nudge("add-device: applied the owner's approval");
    Ok(())
}

/// `GET /v1/setup/add-device` — where B's request stands.
async fn status(State(_st): State<AddDeviceState>) -> Response {
    (
        StatusCode::OK,
        Json(progress().lock().map(|p| p.clone()).unwrap_or_default()),
    )
        .into_response()
}

// ── A's owner routes ──

#[derive(Debug, Deserialize, Default)]
struct OpenRequest {
    #[serde(default)]
    seconds: Option<u64>,
}

/// `POST /v1/self/device-requests/open` — the owner opens "add a device".
async fn open_window(
    State(st): State<AddDeviceState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(r) = crate::federation_peers::require_owner_session(&st.engine, &headers).await {
        return r;
    }
    let req: OpenRequest = if body.is_empty() {
        OpenRequest::default()
    } else {
        serde_json::from_slice(&body).unwrap_or_default()
    };
    let dur = req
        .seconds
        .map(Duration::from_secs)
        .unwrap_or(WINDOW_DEFAULT)
        .min(WINDOW_MAX);
    let mut h = host().lock().unwrap_or_else(|p| p.into_inner());
    h.window_until = Some(Instant::now() + dur);
    tracing::info!(
        seconds = dur.as_secs(),
        "device-join: the owner opened \"add a device\""
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({ "open": true, "seconds": dur.as_secs() })),
    )
        .into_response()
}

/// `GET /v1/self/device-requests` — what is waiting for the owner.
async fn list_requests(State(st): State<AddDeviceState>, headers: HeaderMap) -> Response {
    if let Err(r) = crate::federation_peers::require_owner_session(&st.engine, &headers).await {
        return r;
    }
    let mut h = host().lock().unwrap_or_else(|p| p.into_inner());
    h.sweep();
    let rows: Vec<_> = h
        .pending
        .iter()
        .map(|p| {
            serde_json::json!({
                "request_id": p.id,
                "label": p.req.label,
                "device_class": p.req.device_class,
                "match_code": p.code,
                "node_key_id": p.sender,
                "requested_secs_ago": p.at.elapsed().as_secs(),
            })
        })
        .collect();
    let window = h
        .window_until
        .map(|w| w.saturating_duration_since(Instant::now()).as_secs());
    (
        StatusCode::OK,
        Json(serde_json::json!({ "requests": rows, "window_secs_left": window })),
    )
        .into_response()
}

/// `POST /v1/self/device-requests/{id}/deny`.
async fn deny(
    State(st): State<AddDeviceState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    if let Err(r) = crate::federation_peers::require_owner_session(&st.engine, &headers).await {
        return r;
    }
    let mut h = host().lock().unwrap_or_else(|p| p.into_inner());
    let Some(pos) = h.pending.iter().position(|p| p.id == id) else {
        return refuse(
            StatusCode::NOT_FOUND,
            "add_device.request_unknown",
            "no such pending request",
        );
    };
    let held = h.pending.remove(pos); // N3: a decided request frees its slot at once
    h.decided.insert(
        id,
        Decided {
            sender: held.sender,
            challenge: held.req.challenge,
            decision: Decision::Denied,
            at: Instant::now(),
        },
    );
    (StatusCode::OK, Json(serde_json::json!({ "denied": true }))).into_response()
}

/// `POST /v1/self/device-requests/{id}/approve` — the owner's consent.
async fn approve(
    State(st): State<AddDeviceState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    if let Err(r) = crate::federation_peers::require_owner_session(&st.engine, &headers).await {
        return r;
    }
    let (sender, req, code) = {
        let h = host().lock().unwrap_or_else(|p| p.into_inner());
        match h.pending.iter().find(|p| p.id == id) {
            Some(p) => (p.sender.clone(), p.req.clone(), p.code.clone()),
            None => {
                return refuse(
                    StatusCode::NOT_FOUND,
                    "add_device.request_unknown",
                    "no such pending request",
                )
            }
        }
    };
    match sign_and_record(&st, &sender, &req).await {
        Ok((approval, intro, granted)) => {
            let occurrence_key_id = approval
                .occurrence
                .identity_occurrence
                .occurrence_key_id
                .clone();
            let mut h = host().lock().unwrap_or_else(|p| p.into_inner());
            h.pending.retain(|p| p.id != id); // N3
            h.decided.insert(
                id.clone(),
                Decided {
                    sender: sender.clone(),
                    challenge: req.challenge.clone(),
                    decision: Decision::Approved(Box::new(approval), intro),
                    at: Instant::now(),
                },
            );
            tracing::info!(
                request_id = %id, node = %sender, occurrence = %occurrence_key_id, self_dek_granted = granted,
                "device-join: APPROVED — owner-binding and occurrence signed by the owner; self DEKs re-wrapped"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "approved": true,
                    "match_code": code,
                    "node_key_id": sender,
                    "occurrence_key_id": occurrence_key_id,
                    "self_dek_granted": granted,
                })),
            )
                .into_response()
        }
        Err(e) => refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            "add_device.approve_failed",
            e,
        ),
    }
}

/// Sign the owner-binding to B's node and B's occurrence under the owner's self
/// with the OWNER's pen; record both here; re-wrap the self DEKs to B.
async fn sign_and_record(
    st: &AddDeviceState,
    sender: &str,
    req: &JoinRequest,
) -> Result<(Approval, ciris_edge::Introductions, usize), String> {
    let alias = crate::active_user_alias(&st.user_seed_dir, &st.user_key_id);
    let (pen, _edge_pen) = crate::compose::resolve_user_signers(
        &st.engine,
        crate::compose::FedIdUse::OwnerSession,
        &alias,
        st.user_seed_dir.clone(),
    )
    .await
    .map_err(|e| format!("open the owner's pen: {e:#}"))?
    .ok_or_else(|| "no owner pen on this device".to_string())?;
    // `key_id()` IS the registered id; `derived_key_id()` re-derives a
    // `<alias>-<fp>-<fp>` that is registered nowhere (pen-named-by-derived-id).
    let owner = pen.key_id().to_string();
    let cohort = "self".to_string();

    // (1) The owner-binding owner → B-node, pinned to B's NodeCode.
    let (nc, owner_binding) =
        crate::claim_remote::build_claim_for_target(&pen, &req.node_code, &cohort)
            .await
            .map_err(|e| format!("build the owner-binding: {e}"))?;
    if nc.key_id != sender {
        return Err("the request's NodeCode does not name its signer".into());
    }
    // Recorded HERE too, so this node knows its owner's new device (B's node key
    // was admitted by edge's first contact).
    crate::auth::ownership::apply_signed_owner_binding(
        &st.engine,
        &nc.key_id,
        &cohort,
        st.policy,
        &owner_binding,
    )
    .await
    .map_err(|e| format!("record the owner-binding locally: {e}"))?;

    // (2) B's occurrence key, then the occurrence signed by the owner.
    let occ_key = req.occurrence_key_record.record.key_id.clone();
    let directory = st.engine.federation_directory();
    if directory
        .lookup_public_key(&occ_key)
        .await
        .map_err(|e| e.to_string())?
        .is_none()
    {
        crate::hardware_attestation::register_attested_federation_key(
            &st.engine,
            req.occurrence_key_record.clone(),
        )
        .await
        .map_err(|e| format!("register the device occurrence key: {e}"))?;
    }
    let asserted_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .unwrap_or_else(chrono::Utc::now);
    let envelope = serde_json::json!({
        "attesting_key_id": owner,
        "identity_key_id": owner,
        "occurrence_key_id": occ_key,
        "device_class": req.device_class,
        "encryption_pubkeys": {
            "x25519_base64": req.encryption_pubkeys.x25519_base64,
            "ml_kem_768_base64": req.encryption_pubkeys.ml_kem_768_base64,
        },
        "asserted_at": asserted_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": serde_json::Value::Null,
        "hardware_attestation": serde_json::Value::Null,
    });
    let (signed_envelope, signature) =
        ciris_verify_core::transport_binding::produce_signed_identity_occurrence(
            &ciris_persist::signing::LocalSelfSigner::new(&pen),
            envelope,
        )
        .await
        .map_err(|e| format!("sign the occurrence: {e}"))?;
    let occurrence = SignedIdentityOccurrence {
        identity_occurrence: ciris_persist::federation::IdentityOccurrence {
            identity_key_id: owner.clone(),
            occurrence_key_id: occ_key.clone(),
            device_class: req.device_class.clone(),
            hardware_attestation: None,
            asserted_at,
            valid_until: None,
            encryption_pubkeys: Some(req.encryption_pubkeys.clone()),
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        attesting_key_id: owner.clone(),
        signed_envelope,
        signature,
    };
    directory
        .put_identity_occurrence(occurrence.clone())
        .await
        .map_err(|e| format!("record the occurrence: {e}"))?;

    // (3) The self DEKs, re-wrapped to B's occurrence (the owner's act).
    let granted = match st
        .engine
        .rekey_self_occurrence_add(&owner, std::slice::from_ref(&occ_key))
        .await
    {
        Ok(r) => r.granted.len(),
        Err(e) => {
            tracing::warn!(error = %e, "device-join: self-DEK re-wrap to the new occurrence failed (retried by self_rewrap)");
            0
        }
    };

    // (4) What B needs beside the signed rows: the owner's key and the owner's
    //     binding to THIS node (I14), so B links its sibling.
    let mut intro = ciris_edge::Introductions::default();
    if let Ok(Some(rec)) = directory.lookup_public_key(&owner).await {
        intro.keys.push(SignedKeyRecord { record: rec });
    }
    let own = ciris_edge::first_contact::DirectoryOwnerBinding::new(
        Arc::clone(&directory),
        st.node_key_id.clone(),
    );
    if let Some(att) = own.own_owner_binding().await {
        intro
            .attestations
            .push(ciris_persist::federation::SignedAttestation { attestation: att });
    }
    crate::replication_reconcile::nudge("device-join: the owner added a device");

    Ok((
        Approval {
            node_code: req.node_code.clone(),
            cohort_scope: cohort,
            owner_binding,
            claimer_key_record: st.self_key_record.clone(),
            occurrence,
            owner_code: Some(owner_code(st, &owner).await?),
        },
        intro,
        granted,
    ))
}

/// The routes. B's are loopback-only (first-run, no session); A's are
/// owner-session gated.
pub fn router(state: AddDeviceState) -> Router {
    restore_pending(&state);
    let setup = Router::new()
        .route(
            "/v1/setup/add-device",
            axum::routing::post(start).get(status),
        )
        .route(
            "/v1/setup/add-device/complete",
            axum::routing::post(complete),
        )
        .layer(axum::middleware::from_fn(
            crate::auth::loopback::require_loopback,
        ))
        .with_state(state.clone());
    let owner = Router::new()
        .route(
            "/v1/self/device-requests",
            axum::routing::get(list_requests),
        )
        .route(
            "/v1/self/device-requests/open",
            axum::routing::post(open_window),
        )
        .route(
            "/v1/self/device-requests/{id}/approve",
            axum::routing::post(approve),
        )
        .route(
            "/v1/self/device-requests/{id}/deny",
            axum::routing::post(deny),
        )
        .with_state(state);
    setup.merge(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_matching_code_depends_on_the_requester_not_only_the_challenge() {
        let ch = "ab".repeat(32);
        let b = match_code("ciris-node-b", &ch);
        let m = match_code("attacker-node", &ch);
        assert_eq!(b.len(), 6);
        assert_ne!(
            b, m,
            "an attacker who copies B's challenge must show a different code (N1)"
        );
        assert_eq!(b, match_code("ciris-node-b", &ch), "deterministic");
    }
}
