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
//! ## The accord IS a persist family (generic family ops + accord specialization)
//!
//! The HUMANITY_ACCORD kill-switch roster is the LIVE membership of a first-class
//! persist *family* (`federation_families`, `consensus_protocol: quorum:2/3`,
//! entrenched), read through the GENERIC [`crate::family`] layer
//! (`active_family_members`). The accord is the specialization on top — it adds the
//! founder-signed genesis, the custody gate, the 2/3 invocation verify, and the
//! disk halt. The **authoritative kill-switch roster is [`accord_roster`] =
//! `family::active_threshold_roster("humanity-accord")`** — the family SEATS, NOT
//! "every `accord_holder` row": a vaulted cold-spare is a registered identity but
//! NOT a member, so it can never be a seat (closing the one-human-two-keys
//! self-quorum hole). A spare is swapped into a seat only via a family member
//! SWAP (revoke primary + add spare — [`crate::family::swap_member`]), preserving
//! exactly N distinct-human seats.
//!
//! ## Genesis ceremony + invocation concurrence (v0.5.17, verify v6.7.1)
//!
//! - `POST /v1/accord/genesis/envelope` → `assemble` (`accord_genesis`, 2-of-3
//!   distinct-founder quorum, fail-closed) → on success the node (1) records the
//!   2/3-founder-signed genesis as a node-authored `accord_family_genesis` CEG
//!   attestation (the signed AUTHORIZATION proof) AND (2) entrenches the family in
//!   `federation_families` via the generic layer — registering a CEREMONIAL anchor
//!   key for the FK (private half discarded; the family never signs) + `put_family`.
//!   `GET /v1/accord/family` projects the entrenched family + its live roster.
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
//! ## Operational halt — the ENFORCEABLE kill-switch (CC 4.2.1 / 4.2.3 / §9.2.1)
//!
//! `POST /v1/accord/message` is the inbound accord-message sink (a peer or a
//! holder app delivers a signed invocation object here). The node:
//!
//!   1. replicates any authentic accord-holder-signed message onward to all known
//!      peers (concurrence-seeking gossip; loop-stopped by a seen-set);
//!   2. for a verified 2-of-3 `CONSTITUTIONAL` quorum — the global halt —
//!      replicates to all peers FIRST, then latches the disk halt
//!      ([`crate::accord_halt`]) and terminates (fail-secure, full halt). The
//!      latch gates every future startup until it is manually removed ("not a
//!      recoverable pause"). `create`/`concur` share this path, so a concurring
//!      cosignature that reaches 2-of-3 halts too.
//!   3. `notify` / `drill` messages flow through the SAME replicate-and-surface
//!      path but NEVER halt (a drill is the EAS-style test of the delivery path).
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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use ciris_persist::federation::cohort::Cohort;
use ciris_persist::federation::types::{
    identity_type, Family, FamilyMember, SignedFamily, SignedKeyRecord,
};
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::Engine;
use ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation;
use ciris_verify_core::accord_genesis::{
    accord_invocation_status, accord_roster_from_family, assemble_accord_family_genesis,
    build_accord_family_envelope, build_accord_invocation_object, humanity_accord_genesis,
    parse_accord_invocation, strict_majority, ACCORD_CONSENSUS_PROTOCOL,
    ACCORD_FAMILY_GENESIS_KIND, HUMANITY_ACCORD_FAMILY_KEY_ID,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::federation_self_record::produce_self_key_record;
use ciris_verify_core::humanity_accord::{Invocation, InvocationDedup, InvocationKind};
use ciris_verify_core::self_at_login::HybridSigningIdentity;
use ciris_verify_core::threshold::{
    verify_threshold_signatures, QuorumPolicy, ThresholdMember, ThresholdSignature,
};

use crate::accord_halt::{latch_halt, HaltRecord, HALT_EXIT_CODE};
use crate::auth::roles::{Permission, UserRole};
use crate::auth::session::resolve_bearer;

/// The §9.2.1 2-of-3 holder threshold (verify enforces this internally; surfaced
/// here for the response + the cold-start roster sanity check).
const ACCORD_THRESHOLD: usize = 2;

/// Backstop caps on the in-memory coordination tables (defense-in-depth: only
/// holder-signed traffic reaches them now, but bound them anyway so a compromised
/// holder — or a flood of distinct ids — cannot exhaust memory). `pending` is
/// also pruned of expired invocations on every insert; `seen` is cleared when it
/// overflows (re-gossip is idempotent — a duplicate halt just re-latches).
const MAX_PENDING_INVOCATIONS: usize = 4096;
const MAX_SEEN_INVOCATIONS: usize = 16_384;

/// Per-peer replication request budget — a hung/stalling peer MUST NOT be able to
/// block the local halt from latching. With the concurrent fan-out the whole
/// round is bounded by this, not the sum across peers.
const REPLICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REPLICATION_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

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
/// The node-boot wiring the operational halt needs: WHERE to latch the disk halt,
/// WHO the known peers are to replicate to, and (in prod) that a verified halt
/// terminates the process. Built from [`crate::config::ServerConfig`] in
/// `compose.rs`; [`AccordHalt::disabled`] is the inert default used by unit tests
/// that don't exercise the halt path.
#[derive(Clone)]
pub struct AccordHalt {
    /// The node `home` the [`crate::accord_halt::HALT_LATCH_FILE`] is written
    /// under. `None` disables the disk latch (test / no-home contexts).
    pub home: Option<PathBuf>,
    /// Known-peer base URLs (e.g. `http://10.0.0.2:4243`) the node replicates
    /// authentic accord messages to — and, for a global halt, replicates to FIRST
    /// (before latching). From `bootstrap_peers`; may be empty (0.5 canonical mesh).
    pub peers: Vec<String>,
    /// Whether a verified 2-of-3 `CONSTITUTIONAL` halt terminates the process after
    /// latching (`true` in prod; `false` in tests so the runner survives).
    pub exit_on_halt: bool,
}

impl AccordHalt {
    /// The inert default — no disk latch, no peers, no process exit.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            home: None,
            peers: Vec::new(),
            exit_on_halt: false,
        }
    }
}

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
    /// `(invocation_kind, invocation_id, is_global_halt)` already gossiped — the
    /// loop-stop so a replicated message isn't re-fanned-out endlessly. The
    /// `is_global_halt` discriminator (B3 fix) keeps the SUB-quorum sighting of an
    /// invocation from suppressing the later QUORUM-meeting halt's propagation: a
    /// sub-quorum gossip (`false`) and the quorum-completing halt (`true`) are
    /// tracked independently, so the halt always relays even after sub-quorum churn.
    seen: Arc<Mutex<HashSet<(String, String, bool)>>>,
    /// HTTP client for the peer replication fan-out.
    http: reqwest::Client,
    /// Disk-latch + peer + process-exit wiring for the operational halt.
    halt: AccordHalt,
}

fn err(code: StatusCode, error: &str) -> Response {
    (code, Json(serde_json::json!({ "error": error }))).into_response()
}

/// The **AUTHORITATIVE kill-switch roster** (CC 4.2.1 / §9.2.1) — the LIVE members
/// of the HUMANITY_ACCORD *family* (the 3 primary SEATS), resolved to their pinned
/// pubkeys via the generic family layer ([`crate::family::active_threshold_roster`]).
///
/// This is deliberately NOT "every `accord_holder` row". A vaulted COLD-SPARE is a
/// registered + steward-attested `accord_holder` identity (so a recovery swap is
/// fast), but it is **not a family member**, so it is **not a live seat** — counting
/// it would let one human's two distinct keys self-satisfy the 2-of-3 (the family
/// roster is the only thing that pins one-seat-per-human; verify's distinct-key gate
/// only stops the *same* key in two seats). A spare becomes a counted seat ONLY via
/// a family member SWAP that simultaneously revokes the primary it replaces — never
/// as an added 4th seat. Errs `409` until the family is entrenched.
/// The outcome of resolving the kill-switch roster — distinguished so callers
/// (the strict [`accord_roster`] vs the informational [`list_holders`]) can each
/// choose how to render "no usable roster yet".
enum RosterResolution {
    /// A usable kill-switch roster (from the entrenched persist family OR, at
    /// cold-start, the baked genesis recognition root).
    Resolved(Vec<ThresholdMember>),
    /// No persist family AND no baked genesis — the kill-switch roster is undefined.
    Undefined,
    /// A family/genesis is present but its roster cannot be fully resolved to pinned
    /// holder keys yet (a seat's `accord_holder` record hasn't replicated in, or a
    /// malformed bake) — fail-closed: NOT a usable roster.
    Incomplete(String),
    /// A persist store fault.
    Store(String),
}

/// Resolve the authoritative kill-switch roster, with **cold-start fallback to the
/// BAKED genesis recognition root** (CIRISVerify#107). Order:
///   1. the entrenched persist FAMILY (the live SEATS) — authoritative when present;
///   2. else the **baked** `humanity_accord_genesis()` resolved against the node's
///      PINNED `accord_holder` keys via [`accord_roster_from_family`] — the no-TOFU
///      recognition path a node that was NOT at the ceremony uses (NEVER fetched
///      from a peer). Inert until verify bakes the genesis (`None` today).
async fn resolve_kill_switch_roster(engine: &Engine) -> RosterResolution {
    // (1) An entrenched persist family is authoritative.
    match crate::family::active_threshold_roster(engine, HUMANITY_ACCORD_FAMILY_KEY_ID).await {
        Ok(roster) if !roster.is_empty() => return RosterResolution::Resolved(roster),
        Ok(_) => {} // empty → try the baked recognition root below
        Err(crate::family::RosterError::Store(e)) => return RosterResolution::Store(e.to_string()),
        Err(e @ crate::family::RosterError::UnregisteredMember(_)) => {
            return RosterResolution::Incomplete(e.to_string())
        }
    }

    // (2) Cold-start, no-TOFU recognition: resolve the roster from the BAKED genesis
    // against the node's PINNED accord_holder keys. verify's resolver picks exactly
    // the genesis members out of the directory and fail-closes on any missing.
    let Some(genesis) = humanity_accord_genesis() else {
        return RosterResolution::Undefined;
    };
    let directory: Vec<ThresholdMember> = match engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|r| ThresholdMember {
                member_id: r.key_id,
                ed25519_public_key_base64: r.pubkey_ed25519_base64,
                mldsa65_public_key_base64: r.pubkey_ml_dsa_65_base64,
                role: None,
            })
            .collect(),
        Err(e) => return RosterResolution::Store(e.to_string()),
    };
    match accord_roster_from_family(genesis, &directory) {
        Ok(roster) => RosterResolution::Resolved(roster),
        Err(e) => RosterResolution::Incomplete(format!(
            "baked HUMANITY_ACCORD genesis present but its roster is not yet \
             resolvable from pinned holder keys: {e}"
        )),
    }
}

async fn accord_roster(engine: &Engine) -> Result<Vec<ThresholdMember>, Response> {
    match resolve_kill_switch_roster(engine).await {
        RosterResolution::Resolved(roster) => Ok(roster),
        RosterResolution::Undefined => Err(err(
            StatusCode::CONFLICT,
            "no HUMANITY_ACCORD family entrenched and no baked genesis — the kill-switch roster is undefined",
        )),
        RosterResolution::Incomplete(detail) => Err(err(StatusCode::CONFLICT, &detail)),
        RosterResolution::Store(e) => {
            Err(err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")))
        }
    }
}

/// The live kill-switch quorum **M**. Anchored to the family's ENTRENCHED
/// `consensus_protocol` (`quorum:M/N`) — the M the founders voted to entrench and the
/// SAME one [`crate::accord_reactivate`] honors — so the irreversible-kill bar can
/// never silently drop below the entrenched quorum (e.g. via an unpaired revocation
/// shrinking the live roster). Falls back to strict-majority of the roster only when
/// no family is entrenched (cold-start / baked-genesis recognition). NEVER a
/// hard-coded 2 (N1 review finding: the halt paths previously used the literal `2`).
async fn kill_switch_quorum_m(engine: &Engine, roster: &[ThresholdMember]) -> usize {
    if let Ok(Some(family)) = crate::family::lookup(engine, HUMANITY_ACCORD_FAMILY_KEY_ID).await {
        if let Some(m) = family
            .consensus_protocol
            .strip_prefix("quorum:")
            .and_then(QuorumPolicy::parse)
            .map(|p| p.m)
        {
            return m;
        }
    }
    strict_majority(roster.len())
}

/// Defense-in-depth distinct-key gate on the kill-switch roster (N2): the family
/// seats are distinct by construction (genesis/supersede enforce one-seat in the
/// substrate), but the verifier must never count one human's key as two seats. Re-
/// assert it here so the property holds at the verification point, not only upstream.
fn assert_distinct_roster(roster: &[ThresholdMember]) -> Result<(), String> {
    let mut ed = HashSet::new();
    let mut pq = HashSet::new();
    for m in roster {
        if !ed.insert(m.ed25519_public_key_base64.as_str()) {
            return Err(format!(
                "kill-switch roster has a DUPLICATE Ed25519 key (member {}) — one key cannot hold two seats",
                m.member_id
            ));
        }
        if let Some(p) = &m.mldsa65_public_key_base64 {
            if !pq.insert(p.as_str()) {
                return Err(format!(
                    "kill-switch roster has a DUPLICATE ML-DSA-65 key (member {})",
                    m.member_id
                ));
            }
        }
    }
    Ok(())
}

/// Evict expired (`valid_until` ≤ now, or unparseable) pending invocations — keeps
/// the table bounded by the count of LIVE holder-driven invocations.
fn prune_pending(
    pending: &mut HashMap<(String, String), SignedCegObject>,
    now: chrono::DateTime<chrono::Utc>,
) {
    pending.retain(|_, obj| {
        parse_accord_invocation(obj)
            .ok()
            .and_then(|p| chrono::DateTime::parse_from_rfc3339(&p.invocation.valid_until).ok())
            .map(|vu| vu.with_timezone(&chrono::Utc) > now)
            .unwrap_or(false)
    });
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

    // FIPS portable-2FA CUSTODY GATE (the safe-mesh floor — B1 fix: MANDATORY).
    // An accord holder wields the 2-of-3 kill-switch, so it is admitted ONLY with a
    // YubiKey PIV custody attestation that verifies against the PINNED durable Yubico
    // Attestation Root 1 + meets the FIPS-certified + touch-always floor + binds to
    // THIS holder's Ed25519. A software-only or non-FIPS key CANNOT hold the
    // kill-switch. (Previously the attestation was optional, so the persist
    // attestation_evidence gate — which accepts any non-Software hardware — was the
    // only thing standing; that hole is closed here.) The f9 + the two PIV
    // intermediates ride in the attestation's chain; we pin only the root.
    let Some(custody) = &req.custody_attestation else {
        return err(
            StatusCode::BAD_REQUEST,
            "an accord_holder MUST present a portable_2fa custody_attestation (a FIPS YubiKey PIV \
             chain to Yubico Attestation Root 1) — a software-only or unattested key cannot hold \
             the HUMANITY_ACCORD kill-switch",
        );
    };
    let holder_member = ThresholdMember {
        member_id: req.key_record.record.key_id.clone(),
        ed25519_public_key_base64: req.key_record.record.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: req.key_record.record.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    };
    let custody = match verify_accord_custody_attestation(
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

/// `GET /v1/accord-holders` — the cold-start recognition roster (runbook §10.2).
///
/// `holders` is the **AUTHORITATIVE kill-switch roster** — the LIVE seats of the
/// HUMANITY_ACCORD family (the 3 primaries), what a fresh consumer pins to verify a
/// 2-of-3 invocation with NO trust-on-first-use. `registered` additionally lists
/// every `accord_holder` identity on file (including vaulted COLD-SPARES, which are
/// registered but are NOT seats) so an operator can see custody at a glance.
async fn list_holders(State(st): State<AccordState>) -> Response {
    // All registered accord_holder identities (incl vaulted spares — informational).
    let registered: Vec<HolderSummary> = match st
        .engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|r| HolderSummary {
                key_id: r.key_id,
                pubkey_ed25519_base64: r.pubkey_ed25519_base64,
                pubkey_ml_dsa_65_base64: r.pubkey_ml_dsa_65_base64,
            })
            .collect(),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    // The authoritative seats = the live family roster, with the same cold-start
    // fallback to the BAKED genesis recognition root the kill-switch itself uses
    // ([`resolve_kill_switch_roster`]) — so a node that was NOT at the ceremony lists
    // the seats it recognizes with no trust-on-first-use.
    let (family_established, seats): (bool, Vec<HolderSummary>) =
        match resolve_kill_switch_roster(&st.engine).await {
            RosterResolution::Resolved(roster) => (
                true,
                roster
                    .into_iter()
                    .map(|m| HolderSummary {
                        key_id: m.member_id,
                        pubkey_ed25519_base64: m.ed25519_public_key_base64,
                        pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64,
                    })
                    .collect(),
            ),
            RosterResolution::Undefined => (false, Vec::new()),
            // A genesis is present but a seat's key hasn't replicated in yet ⇒ surface
            // as not-established (informational endpoint, fail-closed).
            RosterResolution::Incomplete(_) => (false, Vec::new()),
            RosterResolution::Store(e) => {
                return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}"))
            }
        };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "threshold": ACCORD_THRESHOLD,
            "family_established": family_established,
            "seat_count": seats.len(),
            "holders": seats,
            "registered_total": registered.len(),
            "registered": registered,
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

    // The holder set the threshold verifies against = the entrenched FAMILY SEATS
    // (the 3 primaries), NOT every accord_holder row. A vaulted spare is a
    // registered identity but NOT a counted seat — see [`family_roster`]. The
    // registry/family is the authority on WHO can halt; the caller-supplied roster
    // (if any) is ignored.
    let holders = match accord_roster(&st.engine).await {
        Ok(h) => h,
        Err(resp) => return resp,
    };

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

    // N2: re-assert one-key-one-seat on the roster at the verification point.
    if let Err(e) = assert_distinct_roster(&holders) {
        return err(StatusCode::CONFLICT, &e);
    }
    // N1: the threshold is the family's LIVE strict-majority M (a grown 3/5 needs 3),
    // not a hard-coded 2. Verify the hybrid cosignatures over §9.2.1 canonical bytes
    // against the seated roster at M (the same primitive reactivate uses).
    let m = kill_switch_quorum_m(&st.engine, &holders).await;
    let canonical = req.invocation.canonical_bytes();
    match verify_threshold_signatures(&canonical, &holders, &req.signatures, m) {
        Ok(valid) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": true,
                "kind": req.invocation.invocation_kind.as_str(),
                "invocation_id": req.invocation.invocation_id,
                "valid_signatures": valid,
                "threshold": m,
                "roster_size": holders.len(),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "verified": false,
                "reason": "quorum_not_met",
                "detail": e.to_string(),
                "threshold": m,
                "roster_size": holders.len(),
            })),
        )
            .into_response(),
    }
}

// ─── Genesis ceremony (CC 4.2 / §9 — build envelope → assemble 2/3 → entrench) ─

/// Ensure the HUMANITY_ACCORD family's **ceremonial anchor key** exists in
/// `federation_keys` (the FK `federation_families` requires). Idempotent: a no-op
/// if already registered. Mints a fresh hybrid keypair, self-signs the `family`
/// registration record, registers it, and **discards the private half** — the
/// family key never signs anything (founders sign genesis; holders sign
/// invocations), it is purely the §5.6.8.9 family identity anchor.
async fn ensure_accord_family_anchor(
    engine: &Engine,
    now: &chrono::DateTime<chrono::Utc>,
) -> Result<(), Response> {
    let exists = engine
        .federation_directory()
        .lookup_public_key(HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")))?;
    if exists.is_some() {
        return Ok(());
    }
    // Mint on a dedicated LARGE-STACK thread: ML-DSA-65 keygen + sign hold big
    // buffers across `.await`s that overflow a default (~2 MiB) async worker stack —
    // this would crash the genesis handler in prod, not just tests. The private half
    // never leaves this thread; only the self-signed PUBLIC record is returned (as
    // JSON), and the keypair is dropped when the thread ends — the ceremonial anchor
    // has no retained signer anywhere.
    let now_s = now.to_rfc3339();
    let minted: serde_json::Value = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .name("accord-family-anchor-mint".into())
        .spawn(move || -> Result<serde_json::Value, String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(async move {
                let anchor = HybridSigningIdentity::generate(HUMANITY_ACCORD_FAMILY_KEY_ID)
                    .map_err(|e| e.to_string())?;
                let v_rec = produce_self_key_record(&anchor, "family", &now_s)
                    .await
                    .map_err(|e| e.to_string())?;
                serde_json::to_value(&v_rec).map_err(|e| e.to_string())
            })
        })
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("spawn anchor mint: {e}"),
            )
        })?
        .join()
        .map_err(|_| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "anchor mint thread panicked",
            )
        })?
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("mint family anchor: {e}"),
            )
        })?;

    // verify's SignedKeyRecord → persist's (structurally identical JSON; the wire
    // shape the holder-registration path round-trips too).
    let p_rec: SignedKeyRecord = serde_json::from_value(minted).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("anchor record conversion: {e}"),
        )
    })?;
    engine.register_federation_key(p_rec).await.map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("register family anchor: {e}"),
        )
    })?;
    Ok(())
}

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
    // The full member set (with founder roles) from the verified envelope.
    let members: Vec<FamilyMember> = req.envelope["members"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let key_id = m.get("key_id")?.as_str()?.to_owned();
                    let role = m.get("role").and_then(|v| v.as_str()).map(str::to_owned);
                    Some(FamilyMember {
                        key_id,
                        joined_at: now,
                        role,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let member_ids: Vec<String> = members.iter().map(|m| m.key_id.clone()).collect();

    // Safe-mesh floor (B1): every entrenched SEAT MUST be a registered `accord_holder`
    // — which (since the holder-admission gate now mandates a verified FIPS YubiKey
    // custody attestation) means every seat is custody-verified. This is the chokepoint
    // that makes "seat ⟹ accord_holder ⟹ FIPS custody" hold regardless of how any
    // OTHER key reached `federation_keys` (e.g. the non-custody peering route): a key
    // that is not a custody-admitted accord_holder can never be seated.
    let accord_holder_ids: std::collections::HashSet<String> = match st
        .engine
        .federation_directory()
        .list_keys_by_identity_type(identity_type::ACCORD_HOLDER)
        .await
    {
        Ok(rows) => rows.into_iter().map(|r| r.key_id).collect(),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    if let Some(missing) = member_ids
        .iter()
        .find(|id| !accord_holder_ids.contains(*id))
    {
        return err(
            StatusCode::CONFLICT,
            &format!(
                "cannot entrench {missing} as a HUMANITY_ACCORD seat — it is not a registered, \
                 custody-verified accord_holder (every seat must be admitted via the FIPS \
                 custody-gated POST /v1/accord/holder)"
            ),
        );
    }

    // (1) Durably record the 2/3-FOUNDER-SIGNED genesis as a node-authored CEG
    // attestation — the signed AUTHORIZATION proof (the founder signatures) that the
    // family table itself does not carry. Audit + cold-start legitimacy of the
    // 2/3-founding.
    let mut input =
        EmitAttestationInput::with_envelope(ACCORD_FAMILY_GENESIS_KIND, genesis.body.clone());
    input.subject_key_ids = member_ids.clone();
    if let Err(e) = st.engine.emit_attestation_self(input).await {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("record accord family genesis: {e}"),
        );
    }

    // (2) Entrench the HUMANITY_ACCORD family as a FIRST-CLASS persist family (via
    // the generic family layer): register its CEREMONIAL anchor key (private half
    // discarded — it never signs; founders signed genesis, holders sign invocations)
    // so the `federation_families` FK holds, then `put_family` with the founders as
    // members + entrenched `quorum:2/3`. From here the kill-switch roster IS
    // `active_family_members` (see [`accord_roster`]) — generic + swap-capable.
    if let Err(resp) = ensure_accord_family_anchor(&st.engine, &now).await {
        return resp;
    }
    let family_name = req.envelope["family_name"]
        .as_str()
        .unwrap_or("HUMANITY_ACCORD")
        .to_string();
    let family = Family {
        family_key_id: HUMANITY_ACCORD_FAMILY_KEY_ID.to_string(),
        family_name,
        members,
        founded_at: now,
        consensus_protocol: ACCORD_CONSENSUS_PROTOCOL.to_string(),
        consensus_protocol_entrenched: true,
        persist_row_hash: String::new(),
    };
    if let Err(e) = crate::family::create_family(&st.engine, family).await {
        return err(
            StatusCode::CONFLICT,
            &format!("entrench accord family: {e}"),
        );
    }
    tracing::info!(
        family = %HUMANITY_ACCORD_FAMILY_KEY_ID,
        holders = member_ids.len(),
        "assembled + entrenched the HUMANITY_ACCORD family (quorum:2/3) — genesis recorded + family put"
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

/// `GET /v1/accord/family` — the entrenched HUMANITY_ACCORD family, read from the
/// persist `federation_families` row via the generic family layer
/// ([`crate::family::lookup`]) + its LIVE roster ([`crate::family::active_members`],
/// revocation-folded). 404 until genesis is assembled.
async fn get_family(State(st): State<AccordState>) -> Response {
    let family = match crate::family::lookup(&st.engine, HUMANITY_ACCORD_FAMILY_KEY_ID).await {
        Ok(Some(f)) => f,
        Ok(None) => return err(StatusCode::NOT_FOUND, "no HUMANITY_ACCORD family yet"),
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    // The live seats (admitted MINUS revoked) — what a swap reflects immediately.
    let live = match crate::family::active_members(&st.engine, HUMANITY_ACCORD_FAMILY_KEY_ID).await
    {
        Ok(m) => m,
        Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "family_key_id": family.family_key_id,
            "family_name": family.family_name,
            "consensus_protocol": family.consensus_protocol,
            "entrenched": family.consensus_protocol_entrenched,
            "founded_at": family.founded_at,
            "members": live,
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
    let roster = match accord_roster(&st.engine).await {
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
    // Replicate the new invocation to peers (concurrence-seeking gossip) + honor a
    // halt if it already meets 2/3. This ALSO tells us if the opener's signature is
    // an authentic registered-holder one — we only persist authentic invocations
    // (an unauthenticated opener cannot grow the pending table).
    let outcome = match replicate_and_maybe_halt(&st, &obj).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if !outcome.authentic {
        return err(
            StatusCode::UNAUTHORIZED,
            "invocation carries no valid registered-holder signature — not opened",
        );
    }
    {
        let mut pending = st.pending.lock().expect("pending lock");
        prune_pending(&mut pending, chrono::Utc::now());
        if pending.len() >= MAX_PENDING_INVOCATIONS && !pending.contains_key(&key) {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many pending invocations — retry later",
            );
        }
        pending.insert(key, obj.clone());
    }
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
    // A concurring cosignature can be the one that reaches the 2-of-3: replicate to
    // peers and, for a CONSTITUTIONAL quorum, replicate-first → latch → halt.
    let outcome = match replicate_and_maybe_halt(&st, &rebuilt).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    // The pending entry it concurs to is already authentic, so this holds; persist
    // the advanced object (pruning expired entries to keep the table bounded).
    if outcome.authentic {
        let mut pending = st.pending.lock().expect("pending lock");
        prune_pending(&mut pending, chrono::Utc::now());
        pending.insert(key, rebuilt.clone());
    }
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
        None => (false, Vec::new(), ACCORD_THRESHOLD),
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

// ─── Accord message handling (replicate → maybe-halt) — CC 4.2.1 / §9.2.1 ─────

/// The result of folding an accord object through the replicate/halt path.
struct AccordOutcome {
    /// At least one cosignature is from a REGISTERED holder (so the message is an
    /// authentic accord message and was replicated). A node only relays/acts on
    /// holder-signed traffic — anything else is dropped.
    authentic: bool,
    invocation_kind: String,
    invocation_id: String,
    quorum_met: bool,
    valid_signers: Vec<String>,
    /// A 2-of-3 `CONSTITUTIONAL` halt was honored (latched; process termination
    /// scheduled in prod).
    halted: bool,
}

/// Replicate an authentic accord object to every known peer's `/v1/accord/message`.
/// Best-effort + bounded; per-peer failures are logged, never fatal (a node that
/// can't reach a peer must still honor its own halt). Awaited on the halt path
/// (replicate-BEFORE-halt); spawned for ordinary concurrence gossip.
async fn replicate_to_peers(http: &reqwest::Client, peers: &[String], obj: &SignedCegObject) {
    // CONCURRENT fan-out (the whole round is bounded by REPLICATION_TIMEOUT, not the
    // sum across peers) so ONE stalling peer can never block the local halt path.
    let mut set = tokio::task::JoinSet::new();
    for peer in peers {
        let http = http.clone();
        let peer = peer.clone();
        let obj = obj.clone();
        set.spawn(async move {
            let url = format!("{}/v1/accord/message", peer.trim_end_matches('/'));
            match http.post(&url).json(&obj).send().await {
                Ok(r) => {
                    tracing::info!(peer = %peer, status = %r.status(), "replicated accord message")
                }
                Err(e) => {
                    tracing::warn!(peer = %peer, error = %e, "accord replication to peer failed")
                }
            }
        });
    }
    while set.join_next().await.is_some() {}
}

/// The single replicate + halt path (CC 4.2.1 / §9.2.1), shared by the inbound
/// `/v1/accord/message` ingest and the local `create`/`concur` producers:
///
///   1. Re-bind the object's signatures to THIS node's registered holder roster
///      (the authority on WHO can halt — never the object's embedded roster) and
///      compute the concurrence status.
///   2. If authentic (≥1 valid holder cosignature): **replicate to peers** — the
///      requirement that any accord-holder-signed message is gossiped onward.
///   3. If a 2-of-3 `CONSTITUTIONAL` quorum is met: this is a GLOBAL HALT — replicate
///      to all known peers FIRST (so the kill propagates before this node goes
///      dark), then latch the disk halt + (in prod) terminate. `notify`/`drill`/
///      sub-quorum messages are surfaced, never halt (a drill exercises exactly
///      this delivery path without the kill — EAS-style).
async fn replicate_and_maybe_halt(
    st: &AccordState,
    obj: &SignedCegObject,
) -> Result<AccordOutcome, Response> {
    let roster = accord_roster(&st.engine).await?;
    let parsed_in = parse_accord_invocation(obj).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("parse accord object: {e}"),
        )
    })?;
    // Re-bind to MY roster so authenticity + quorum are judged against the registered
    // holders, not whatever roster the producer embedded.
    let now = chrono::Utc::now().to_rfc3339();
    let rebound = build_accord_invocation_object(
        &parsed_in.family_key_id,
        &roster,
        &parsed_in.invocation,
        &parsed_in.signatures,
        &now,
    );
    let parsed = parse_accord_invocation(&rebound)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("re-bind: {e}")))?;
    let status = accord_invocation_status(&parsed)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("status: {e}")))?;

    // N1: judge quorum at the family's LIVE strict-majority M (a grown 3/5 needs 3),
    // NOT the hard-coded 2 in accord_invocation_status. valid_signers is the set of
    // distinct, validly-hybrid-signed seats; the roster is the seated family.
    let _ = assert_distinct_roster(&roster); // defense-in-depth; roster is seat-distinct
    let m = kill_switch_quorum_m(&st.engine, &roster).await;
    let quorum_met = status.valid_signers.len() >= m;

    let mut outcome = AccordOutcome {
        authentic: !status.valid_signers.is_empty(),
        invocation_kind: status.invocation_kind.clone(),
        invocation_id: status.invocation_id.clone(),
        quorum_met,
        valid_signers: status.valid_signers.clone(),
        halted: false,
    };
    if !outcome.authentic {
        return Ok(outcome);
    }

    let is_global_halt =
        status.invocation_kind == InvocationKind::Constitutional.as_str() && quorum_met;
    // B3: the loop-stop key includes `is_global_halt`, so a SUB-quorum sighting of
    // this invocation (gossiped earlier with <M sigs) does NOT suppress the later
    // QUORUM-meeting halt — the halt relays on its own first quorum-sighting even if
    // the sub-quorum object was already seen.
    let key = (
        status.invocation_kind.clone(),
        status.invocation_id.clone(),
        is_global_halt,
    );
    let first_sight = {
        let mut seen = st.seen.lock().expect("seen lock");
        // Bounded backstop: clearing only costs a possible re-gossip, which is
        // idempotent (a duplicate halt re-latches; a duplicate notify re-fans once).
        if seen.len() >= MAX_SEEN_INVOCATIONS {
            seen.clear();
        }
        seen.insert(key)
    };

    if is_global_halt {
        // Requirement: replicate to known peers BEFORE initiating the halt (so the
        // kill propagates before this node goes dark). AWAITED but bounded by
        // REPLICATION_TIMEOUT — a hung peer can never delay the latch. Deduped on
        // first QUORUM-sighting (A→B→A storms stopped; the halt still reaches every
        // peer because each node relays its OWN first quorum-sighting before going dark).
        if first_sight {
            replicate_to_peers(&st.http, &st.halt.peers, obj).await;
        }
        // The disk latch is the load-bearing, LOCAL, fast gate. B4: a halt must NEVER
        // resurrect — so the clean exit is GATED on a durable latch. We retry with
        // backoff; if the latch can NOT be written, we do NOT take the exit(42) path
        // (which would let the next startup boot un-gated). Instead we abort() loudly
        // AFTER replicating to peers — a crash an auto-restarter must NOT silently
        // bring back, and the peers already hold the halt.
        if let Some(home) = &st.halt.home {
            let record = HaltRecord {
                invocation_kind: status.invocation_kind.clone(),
                invocation_id: status.invocation_id.clone(),
                valid_signers: status.valid_signers.clone(),
                quorum_threshold: m,
                latched_at: now.clone(),
            };
            let mut latched = None;
            for attempt in 1..=8u32 {
                match latch_halt(home, &record) {
                    Ok(p) => {
                        latched = Some(p);
                        break;
                    }
                    Err(e) => {
                        tracing::error!(attempt, error = %e, "halt latch write failed — retrying");
                        // Backoff (capped) so a transient disk fault can clear.
                        tokio::time::sleep(std::time::Duration::from_millis(
                            (50u64 << attempt.min(6)).min(2000),
                        ))
                        .await;
                    }
                }
            }
            match latched {
                Some(p) => tracing::error!(
                    latch = %p.display(),
                    invocation_id = %status.invocation_id,
                    "HUMANITY_ACCORD HALT honored — node latched down (full halt, CC 4.2.1)"
                ),
                None => {
                    // B4 fail-secure: the latch is the ONLY thing that gates the next
                    // boot. Without it we must NOT exit into a restartable, un-gated
                    // serving state. Abort hard (the halt is already replicated to
                    // peers) — a node that cannot latch its own halt must be treated
                    // as compromised and NOT auto-restarted without a manual latch.
                    if st.halt.exit_on_halt {
                        tracing::error!(
                            invocation_id = %status.invocation_id,
                            "HALT LATCH WRITE FAILED after retries — ABORTING (NOT a clean halt \
                             exit). The latch is NOT durable: do NOT auto-restart this node; an \
                             operator MUST create the halt latch before it may run again."
                        );
                        // Flush the response, then abort (distinct from the clean exit 42).
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        std::process::abort();
                    } else {
                        tracing::error!(
                            invocation_id = %status.invocation_id,
                            "HALT LATCH WRITE FAILED after retries and the latch is NOT durable \
                             (exit_on_halt off) — an operator MUST create the halt latch."
                        );
                    }
                }
            }
        }
        outcome.halted = true;
        // Full halt, fail-secure: terminate after a short grace so the HTTP
        // response flushes. The disk latch blocks the next startup. (Only reached
        // when the latch is durable OR no home is configured — the no-durable-latch
        // case aborted above.)
        if st.halt.exit_on_halt {
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                std::process::exit(HALT_EXIT_CODE);
            });
        }
    } else if first_sight {
        // Ordinary accord-holder-signed traffic (concurrence-seeking notify/drill/
        // sub-quorum): gossip onward once, fire-and-forget (the holder isn't blocked).
        let http = st.http.clone();
        let peers = st.halt.peers.clone();
        let obj = obj.clone();
        tokio::spawn(async move { replicate_to_peers(&http, &peers, &obj).await });
    }
    Ok(outcome)
}

/// `POST /v1/accord/message` — the inbound accord-message sink a peer (or a holder
/// app) delivers a signed invocation object to. Authentic holder-signed messages
/// are replicated onward; a 2-of-3 `CONSTITUTIONAL` triggers the global halt
/// (replicate-first → latch → terminate). Unauthenticated: the holder cosignatures
/// ARE the authority (a message with no valid holder signature is dropped).
async fn ingest_message(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let obj: SignedCegObject = match serde_json::from_slice(&body) {
        Ok(o) => o,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad accord object: {e}")),
    };
    match replicate_and_maybe_halt(&st, &obj).await {
        Ok(o) if !o.authentic => err(
            StatusCode::UNAUTHORIZED,
            "accord message carries no valid registered-holder signature — dropped",
        ),
        Ok(o) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "accepted": true,
                "invocation_kind": o.invocation_kind,
                "invocation_id": o.invocation_id,
                "quorum_met": o.quorum_met,
                "valid_signers": o.valid_signers,
                "halted": o.halted,
            })),
        )
            .into_response(),
        Err(resp) => resp,
    }
}

// ─── Family membership change: supersede / reconstitute (CC 4.2 §9 / runbook §10) ─
//
// The recovery + governance write path, authorized by the CURRENT 2/3 roster. ONE
// primitive covers replace-a-seat (same N), recover-from-spare, expand/shrink N, and
// the threshold change those force (3→5 ⇒ quorum:2/3→3/5). The flow mirrors genesis
// (envelope → quorum-signed → apply), but the authority is the CURRENT roster, and
// persist (CIRISPersist#249 G3/G3.5, composing verify v6.9.0 `verify_membership_change`)
// enforces ≥M valid prior-roster hybrid cosignatures + the `supersedes` anti-replay
// binding + one-seat key-distinctness IN THE SUBSTRATE before applying as a new version.

#[derive(Debug, Deserialize)]
struct ChangeEnvelopeRequest {
    /// The NEW full roster (registered `accord_holder` `key_id`s). Same N with one
    /// swapped = replace/recover; different N = expand/shrink.
    new_member_key_ids: Vec<String>,
    /// The NEW consensus protocol (e.g. `"quorum:3/5"`). `None` ⇒ persist derives the
    /// strict-majority default for the new N. (Expanding past the `2M>N` boundary
    /// REQUIRES a threshold change — 3→5 forces `quorum:3/5`.)
    #[serde(default)]
    consensus_protocol: Option<String>,
}

/// `POST /v1/accord/family/change/envelope` (owner-gated) — build the canonical
/// membership-change payload the CURRENT roster cosigns. Returns the change envelope
/// plus the exact JCS bytes to sign (base64); each current holder signs those bytes on
/// their own device (Ed25519 + ML-DSA-65 bound), and the cosignatures go to
/// `/v1/accord/family/supersede`.
async fn family_change_envelope(
    State(st): State<AccordState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: ChangeEnvelopeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let change = match st
        .engine
        .federation_directory()
        .build_membership_change_envelope(
            Cohort::Family,
            HUMANITY_ACCORD_FAMILY_KEY_ID,
            &req.new_member_key_ids,
            true,
            req.consensus_protocol.as_deref(),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => return err(StatusCode::CONFLICT, &format!("build change envelope: {e}")),
    };
    let signing_bytes = match ciris_verify_core::jcs::canonicalize(&change) {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("canonicalize change: {e}"),
            )
        }
    };
    use base64::Engine as _;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "change_envelope": change,
            "signing_bytes_base64": base64::engine::general_purpose::STANDARD.encode(&signing_bytes),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct SupersedeRequest {
    /// The exact change envelope from `…/change/envelope` (re-canonicalized; never rebuilt).
    change_envelope: serde_json::Value,
    /// The CURRENT roster's cosignatures over `jcs(change_envelope)` (≥ M of N).
    signatures: Vec<ThresholdSignature>,
}

/// Build a [`SignedFamily`] from the verified change envelope (the roster + protocol
/// the quorum authorized — persist's "verify-A-store-B" guard rejects any mismatch).
#[allow(clippy::result_large_err)] // mirrors the rest of the module's Result<_, Response> handlers
fn signed_family_from_envelope(env: &serde_json::Value) -> Result<SignedFamily, Response> {
    let consensus_protocol = env
        .get("consensus_protocol")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "change envelope missing consensus_protocol",
            )
        })?
        .to_string();
    let members = env
        .get("members")
        .and_then(|v| v.as_array())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "change envelope missing members[]"))?;
    let now = chrono::Utc::now();
    let members: Vec<FamilyMember> = members
        .iter()
        .filter_map(|m| {
            Some(FamilyMember {
                key_id: m.get("key_id")?.as_str()?.to_owned(),
                joined_at: now,
                role: m.get("role").and_then(|v| v.as_str()).map(str::to_owned),
            })
        })
        .collect();
    Ok(SignedFamily {
        family: Family {
            family_key_id: env
                .get("family_key_id")
                .and_then(|v| v.as_str())
                .unwrap_or(HUMANITY_ACCORD_FAMILY_KEY_ID)
                .to_string(),
            family_name: env
                .get("family_name")
                .and_then(|v| v.as_str())
                .unwrap_or("HUMANITY_ACCORD")
                .to_string(),
            members,
            founded_at: now,
            consensus_protocol,
            consensus_protocol_entrenched: env
                .get("consensus_protocol_entrenched")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            persist_row_hash: String::new(),
        },
    })
}

/// `POST /v1/accord/family/supersede` (owner-gated submission; **2/3-authorized** by
/// the prior roster's cosignatures) — apply a membership change. persist re-verifies
/// ≥M prior-roster hybrid cosignatures over the change payload, the `supersedes`
/// anti-replay binding, and one-seat key-distinctness, then re-baselines the family
/// as a NEW version. Covers replace / recover / expand / shrink (+ threshold) — the
/// whole `supersede`/`reconstitute` surface. The kill-switch roster ([`accord_roster`])
/// reflects the new seats immediately.
async fn family_supersede(
    State(st): State<AccordState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Err(resp) = require_owner(&st, &headers).await {
        return resp;
    }
    let req: SupersedeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let new = match signed_family_from_envelope(&req.change_envelope) {
        Ok(f) => f,
        Err(resp) => return resp,
    };
    let new_count = new.family.members.len();
    let new_protocol = new.family.consensus_protocol.clone();
    match st
        .engine
        .federation_directory()
        .supersede_family_with_quorum(new, req.change_envelope, req.signatures)
        .await
    {
        Ok(valid) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "superseded": true,
                "valid_signatures": valid,
                "consensus_protocol": new_protocol,
                "member_count": new_count,
            })),
        )
            .into_response(),
        // Fail-closed: insufficient quorum / anti-replay / one-seat violation ⇒ 409,
        // and persist leaves the live family row untouched.
        Err(e) => err(
            StatusCode::CONFLICT,
            &format!("supersede rejected (quorum / anti-replay / one-seat): {e}"),
        ),
    }
}

/// `GET /v1/accord/family/history` — the family's supersede chain (audit: who
/// superseded whom, each version's roster + consensus_protocol).
async fn family_history(State(st): State<AccordState>) -> Response {
    match st
        .engine
        .federation_directory()
        .group_history(Cohort::Family, HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
    {
        Ok(versions) => (
            StatusCode::OK,
            Json(serde_json::json!({ "versions": versions })),
        )
            .into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
    }
}

/// The accord router — merge onto the read-API listener. [`router`] uses the inert
/// [`AccordHalt::disabled`] (no disk latch / peers / exit); `compose.rs` wires the
/// live halt config via [`router_with_halt`].
pub fn router(engine: Arc<Engine>) -> Router {
    router_with_halt(engine, AccordHalt::disabled())
}

/// The accord router with an explicit [`AccordHalt`] (the prod entry — disk latch
/// under `home`, replication to `peers`, process-exit on a verified halt).
pub fn router_with_halt(engine: Arc<Engine>, halt: AccordHalt) -> Router {
    let state = AccordState {
        engine,
        dedup: Arc::new(Mutex::new(InvocationDedup::new())),
        pending: Arc::new(Mutex::new(HashMap::new())),
        seen: Arc::new(Mutex::new(HashSet::new())),
        // A hung peer MUST NOT block the local halt — bound every replication request.
        http: reqwest::Client::builder()
            .timeout(REPLICATION_TIMEOUT)
            .connect_timeout(REPLICATION_CONNECT_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
        halt,
    };
    Router::new()
        .route("/v1/accord/holder", axum::routing::post(register_holder))
        .route("/v1/accord-holders", axum::routing::get(list_holders))
        .route(
            "/v1/accord/verify-invocation",
            axum::routing::post(verify_invocation_handler),
        )
        .route("/v1/accord/message", axum::routing::post(ingest_message))
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
        // family membership change — supersede / reconstitute (2/3-authorized)
        .route(
            "/v1/accord/family/change/envelope",
            axum::routing::post(family_change_envelope),
        )
        .route(
            "/v1/accord/family/supersede",
            axum::routing::post(family_supersede),
        )
        .route(
            "/v1/accord/family/history",
            axum::routing::get(family_history),
        )
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
