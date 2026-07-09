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
//!   attestation (the signed AUTHORIZATION proof) AND (2) CONFIRMS the entrenched
//!   `federation_families` row. persist v13.3.0 (CIRISPersist#386) SEEDS that keyless
//!   2/3 row at boot on every node and V097 drops the old `family_key_id` FK, so
//!   assemble is IDEMPOTENT — no ceremonial anchor key, and it never re-inserts (an
//!   insert-or-replace would let an owner overwrite the baked constitutional family).
//!   `GET /v1/accord/family` reads the entrenched row + its live roster.
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
//! The canonical mesh grows by baking accord-scrubbed canonical records (the seed
//! op) — each carrying its trust (the `canonical` role) AND its reachability (the
//! signed envelope transport hint, CIRISPersist#381) — which MUST NOT happen before
//! the kill-switch is enforceable AND the accord keys are under genuine 2-factor
//! distributed-human custody (now gate-enforced).

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
use ciris_verify_core::accord_custody_attestation::{
    custody_attestation_to_platform_attestation, verify_accord_custody_attestation,
};
use ciris_verify_core::accord_genesis::{
    accord_invocation_status, accord_roster_from_family, assemble_accord_family_genesis,
    build_accord_family_envelope, build_accord_invocation_object, humanity_accord_genesis,
    parse_accord_invocation, strict_majority, ACCORD_CONSENSUS_PROTOCOL,
    ACCORD_FAMILY_GENESIS_KIND, HUMANITY_ACCORD_FAMILY_KEY_ID,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::humanity_accord::{Invocation, InvocationDedup, InvocationKind};
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

/// Backstop cap on the in-memory surfaced-events log (completed drills +
/// announcements). Oldest entries are dropped on overflow — the log is an operator
/// convenience surface, NOT a durable audit ledger (the durable artifact is each
/// holder-cosigned invocation object, re-verifiable against `federation_keys`).
const MAX_ACCORD_EVENTS: usize = 1024;

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
    /// Surfaced NON-BINDING events (completed drills + announcements), oldest-first.
    /// A record is appended the moment a VALID, quorum-COMPLETE drill or a valid
    /// single-holder announce is observed — whether initiated locally or received
    /// via gossip. De-duplicated by `(event_type, invocation_id)` so re-gossip is
    /// idempotent; bounded by [`MAX_ACCORD_EVENTS`] (oldest dropped). Ephemeral, like
    /// [`AccordState::pending`] — a node restart drops it; the durable artifacts are
    /// the holder-cosigned objects themselves.
    events: Arc<Mutex<Vec<AccordEvent>>>,
}

/// A surfaced, NON-BINDING accord event (CC 4.2.1 / §9.2.1) — a completed **drill**
/// (a rehearsed exercise of the 2-of-3 kill-switch delivery path) or an
/// **announce** (a single-holder `notify`). Recorded the instant it is observed
/// quorum-COMPLETE (a sub-quorum invocation is NEVER recorded here — it only
/// accumulates cosignatures in [`AccordState::pending`]). Neither a drill nor an
/// announce ever latches a halt (only a 2-of-3 `CONSTITUTIONAL` does).
#[derive(Clone, Debug, Serialize)]
struct AccordEvent {
    /// `"drill"` or `"announce"`.
    event_type: String,
    /// The invocation id (`drill_id` / `notify_id`).
    invocation_id: String,
    /// RFC-3339 instant THIS node recorded the completed event.
    recorded_at: String,
    /// The registered holder `key_id`s whose cosignatures were counted — the
    /// quorum-meeting seats for a drill, the single signer for an announce.
    signers: Vec<String>,
    /// The quorum threshold the event met (drill: the family M; announce: 1).
    quorum_threshold: usize,
    /// **Announce ONLY** — the free-text message, surfaced iff it BINDS to the
    /// signed `payload_sha256` (`sha256(message) == payload_sha256`); an absent or
    /// unbound message is `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl AccordState {
    /// Record a completed non-binding event, **idempotently** (re-gossip of the same
    /// `(event_type, invocation_id)` is a no-op) and **bounded** (oldest dropped on
    /// overflow). Returns whether it was newly recorded (for logging).
    fn record_event(&self, event: AccordEvent) -> bool {
        let mut events = self.events.lock().expect("accord events lock");
        if events
            .iter()
            .any(|e| e.event_type == event.event_type && e.invocation_id == event.invocation_id)
        {
            return false;
        }
        if events.len() >= MAX_ACCORD_EVENTS {
            let overflow = events.len() + 1 - MAX_ACCORD_EVENTS;
            events.drain(0..overflow);
        }
        events.push(event);
        true
    }
}

/// Lowercase-hex SHA-256 — the §0.6 payload-hash form an announce's `message` binds
/// to (`payload_sha256`), so a tampered plaintext fails the binding and is dropped.
fn payload_hash_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
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
    // Verify the custody attestation (fail-closed: admit only on Ok) and keep the verdict.
    let verdict = match verify_accord_custody_attestation(
        custody,
        &holder_member,
        YUBICO_ATTESTATION_ROOT_1_DER,
    ) {
        Ok(v) => v,
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

    // v7.1 BRIDGE (CIRISVerify#117 + CIRISPersist#268, v9.11.0): turn the VERIFIED
    // custody attestation into a `PlatformAttestation::ExternalSecureElement` and
    // package it in persist's `{platform_attestation, nonce_captured_at}`
    // `AttestationEvidence` shape — the EXACT shape the accord_holder admission gate
    // (`HardwareAttestationPolicy::check`) deserializes, with ExternalSecureElement
    // now an accepted hardware type. The old hand-rolled `{verified, hardware_class,
    // …}` JSON did NOT match the gate and was the #268 entrenchment blocker.
    let platform_attestation = match custody_attestation_to_platform_attestation(custody, &verdict)
    {
        Ok(pa) => pa,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                &format!("custody → platform attestation bridge failed: {e}"),
            )
        }
    };
    let attestation_evidence = serde_json::json!({
        "platform_attestation": platform_attestation,
        // The registrar captures the admission nonce now; persist checks this is
        // within `max_nonce_age` (24h) — same-session entrench is well inside it.
        "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
    });
    // Human-readable custody summary for the API response (NOT the row evidence).
    let custody_summary = serde_json::json!({
        "verified": true,
        "hardware_class": verdict.hardware_class,
        "custody_tier": verdict.custody_tier,
        "fips_certified": verdict.fips_certified,
        "touch_always": verdict.touch_always,
        "firmware": verdict.firmware,
    });

    // Attach the bridged evidence to the row — persist's accord_holder admission gate
    // requires this non-null, correctly-shaped `attestation_evidence`. It is row
    // metadata, NOT part of the signed `registration_envelope`, so setting it
    // post-verification does not disturb the proof-of-possession gate.
    let mut key_record = req.key_record;
    key_record.record.attestation_evidence = Some(attestation_evidence);

    match st.engine.register_federation_key(key_record).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({ "registered": true, "key_id": key_id, "custody": custody_summary })),
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

    // OUTBOX: the quorum is already cryptographically verified here — `genesis.body`
    // = { family, founder_signatures } carries the 2-of-3 cosignatures (the holders'
    // consent). Save it to the SHARED CEG outbox NOW, BEFORE the (deferred)
    // seat-registration entrench check below, so the holders' cosign TOUCHES are
    // never wasted even when the seats aren't admitted yet. verify wraps the holder
    // bundles + this genesis to entrench later.
    {
        let dir = ciris_verify_core::ceg_outbox::ceg_outbox().join("accord_family_genesis");
        let path = dir.join("humanity_accord_genesis.json");
        // Save the WHOLE founder-signed `SignedCegObject` (not just `.body`) — this
        // is exactly what verify bakes into `HUMANITY_ACCORD_GENESIS_JSON`
        // (`humanity_accord_genesis()`), so the file is directly pasteable.
        match std::fs::create_dir_all(&dir)
            .map_err(|e| e.to_string())
            .and_then(|()| serde_json::to_vec_pretty(&genesis).map_err(|e| e.to_string()))
            .and_then(|b| std::fs::write(&path, b).map_err(|e| e.to_string()))
        {
            Ok(()) => tracing::info!(path = %path.display(),
                "accord genesis-assemble: assembled genesis (2/3 cosigns verified) saved to the CEG outbox"),
            Err(e) => tracing::warn!(error = %e,
                "accord genesis-assemble: could NOT write the assembled genesis to the outbox"),
        }
    }

    // The verified genesis is durably recorded as a node-authored CEG attestation
    // (`accord_family_genesis`) carrying `genesis.body` = `{ family, founder_signatures }`
    // — the signed AUTHORIZATION proof the `federation_families` row itself does not hold.
    // The entrenched row is KEYLESS (V097 drops the family_key_id FK): a constitutional
    // family is constituted by its founder quorum, not by owning a keypair.
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

    // (2) Entrench the HUMANITY_ACCORD family as a FIRST-CLASS persist family.
    //
    // persist v13.3.0 (CIRISPersist#386) SEEDS this keyless 2/3 row (A1/B1/C1) at boot on
    // every node, and V097 drops the old `family_key_id -> federation_keys` FK — so the
    // ceremonial anchor-key mint is gone, and assemble is now IDEMPOTENT: on a seeded node
    // it records the founder-signed genesis proof (above) and CONFIRMS the entrenched row,
    // it does NOT insert. That is deliberate — an insert-or-replace here would let an owner
    // who admits their own 3 holders OVERWRITE the constitutional trust root. We only create
    // the row defensively when none exists (a pre-v13.3.0 store); the seed makes that rare.
    let already_entrenched =
        match crate::family::lookup(&st.engine, HUMANITY_ACCORD_FAMILY_KEY_ID).await {
            Ok(f) => f.is_some(),
            Err(e) => return err(StatusCode::SERVICE_UNAVAILABLE, &format!("store: {e}")),
        };
    if !already_entrenched {
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
/// revocation-folded). persist v13.3.0 (CIRISPersist#386) seeds this row at boot on every
/// node (idempotent), so the read resolves with zero ceremony; `404` only on a genuinely
/// family-less store. (The 0.5.83 baked-genesis projection is retired — the durable row
/// supersedes it.)
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
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct CreateInvocationRequest {
    invocation: Invocation,
    /// The initiating holder's cosignature — supplied by a holder app that already
    /// holds a key. OPTIONAL: when absent, the hardware-scrub inputs below drive the
    /// node to open the holder's YubiKey + USB-wrapped ML-DSA and PRODUCE it.
    #[serde(default)]
    signature: Option<ThresholdSignature>,
    /// Hardware-sign path (mirrors admit-node): the holder's federation `key_id`.
    #[serde(default)]
    key_id: Option<String>,
    /// Hardware-sign path: the USB directory holding the wrapped ML-DSA-65 half.
    #[serde(default)]
    mldsa_usb_path: Option<String>,
    /// Hardware-sign path: the holder's YubiKey PKCS#11 / PIV knobs (PIN, slot, …).
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
}

/// Resolve the cosignature for an accord invocation op: use a client-submitted
/// `signature` if present (a holder app that already holds a key), else HARDWARE-SIGN
/// on the node from the holder's YubiKey + USB-wrapped ML-DSA (the same custody path
/// admit-node / add-canonical use). The produced signature's `member_id` is the
/// holder's federation `key_id` — exactly the roster `member_id` the family / registered
/// -holder verification (`verify_threshold_signatures`) matches against.
async fn resolve_holder_signature(
    invocation: &Invocation,
    submitted: Option<ThresholdSignature>,
    holder_key_id: Option<&str>,
    usb_path: Option<&str>,
    pkcs11: &crate::accord_provision::ProvisionPkcs11,
) -> Result<ThresholdSignature, Response> {
    if let Some(sig) = submitted {
        return Ok(sig);
    }
    let holder = holder_key_id.map(str::trim).filter(|s| !s.is_empty());
    let usb = usb_path.map(str::trim).filter(|s| !s.is_empty());
    let (Some(holder), Some(usb)) = (holder, usb) else {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "provide either a `signature` (from a holder app) or `key_id` + `mldsa_usb_path` to \
             hardware-sign the invocation on this node",
        ));
    };
    hardware_sign_invocation(holder, usb, pkcs11, invocation).await
}

/// Produce a holder [`ThresholdSignature`] over an invocation's §9.2.1 canonical
/// bytes by opening the holder's YubiKey (slot-9c Ed25519) + the USB-wrapped
/// ML-DSA-65 as a `HardwareRootedIdentity` and calling its bound signer. The
/// `member_id` is the identity's federation `key_id` (see [`co_sign_accord_family`]
/// for the same derivation). `pkcs11`-gated.
#[cfg(feature = "pkcs11")]
async fn hardware_sign_invocation(
    holder_key_id: &str,
    usb_path: &str,
    pkcs11: &crate::accord_provision::ProvisionPkcs11,
    invocation: &Invocation,
) -> Result<ThresholdSignature, Response> {
    use ciris_verify_core::self_at_login::SelfSigner;
    let identity = crate::accord_provision::open_holder_identity(holder_key_id, usb_path, pkcs11)
        .await
        .map_err(|(code, msg)| err(code, &msg))?;
    // Ed25519 over canonical_bytes; ML-DSA-65 over canonical_bytes ‖ ed_sig — the same
    // bound construction `sign_bound` produces for the family-cosign path.
    let (ed_b64, pqc_b64) = identity
        .sign_bound(&invocation.canonical_bytes())
        .await
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("hardware-sign the invocation: {e}"),
            )
        })?;
    Ok(ThresholdSignature {
        member_id: identity.key_id().to_string(),
        ed25519_signature_base64: ed_b64,
        mldsa65_signature_base64: Some(pqc_b64),
    })
}

#[cfg(not(feature = "pkcs11"))]
async fn hardware_sign_invocation(
    _holder_key_id: &str,
    _usb_path: &str,
    _pkcs11: &crate::accord_provision::ProvisionPkcs11,
    _invocation: &Invocation,
) -> Result<ThresholdSignature, Response> {
    Err(err(
        StatusCode::NOT_IMPLEMENTED,
        "hardware-signing an accord invocation needs the `pkcs11` feature (the holder's YubiKey + \
         USB-wrapped ML-DSA signer). Supply a pre-produced `signature`, or rebuild with \
         `--features pkcs11` on a host with the token attached.",
    ))
}

/// Synthesize a fresh NON-BINDING invocation (a `drill` rehearsal or a `notify`
/// announce) the node hardware-signs on the holder's behalf. The app supplies only
/// the id / message — never a signed envelope (it holds no keys and fabricates no
/// crypto), so the node mints the CSPRNG nonce, the §0.5 timestamps (a 1-hour
/// validity window), and the §0.6 `payload_sha256` (binding the notify's `message`;
/// the empty payload for a drill). Used for the non-binding kinds AND for RAISING a
/// `CONSTITUTIONAL` halt ([`initiate_halt`]) — the synthesized halt carries ONE opener
/// signature, which is sub-quorum and cannot latch; only the family M-of-N does.
fn synth_invocation(kind: InvocationKind, invocation_id: &str, payload: &[u8]) -> Invocation {
    use base64::Engine as _;
    let mut nonce = [0u8; 32];
    // Best-effort CSPRNG; a drill / notify is non-binding, so a fill fault (never
    // observed on a supported target) degrades to a zero nonce rather than failing.
    let _ = getrandom::fill(&mut nonce);
    let now = chrono::Utc::now();
    Invocation {
        invocation_kind: kind,
        invocation_id: invocation_id.to_string(),
        resumes_halt_id: None,
        nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
        asserted_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        valid_until: (now + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        payload_sha256: payload_hash_hex(payload),
    }
}

/// `POST /v1/accord/invocation` — open a pending invocation with the initiating
/// holder's cosignature. The roster is the registered accord-holder set. Returns
/// the invocation object + its (sub-quorum) status. The cosignature is client-
/// submitted OR hardware-signed on the node (see [`resolve_holder_signature`]).
async fn create_invocation(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let req: CreateInvocationRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    open_invocation(
        &st,
        req.invocation,
        req.signature,
        req.key_id,
        req.mldsa_usb_path,
        &req.pkcs11,
    )
    .await
}

/// `POST /v1/accord/drill` request. Supply EITHER a full `invocation` (holder-app
/// path) OR just an `invocation_id` for the node to synthesize the non-binding drill.
/// The cosignature is client-submitted OR hardware-signed on the node.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct DrillRequest {
    #[serde(default)]
    invocation: Option<Invocation>,
    #[serde(default)]
    invocation_id: Option<String>,
    #[serde(default)]
    signature: Option<ThresholdSignature>,
    /// Hardware-sign path (mirrors admit-node): the holder's federation `key_id`.
    #[serde(default)]
    key_id: Option<String>,
    /// Hardware-sign path: the USB directory holding the wrapped ML-DSA-65 half.
    #[serde(default)]
    mldsa_usb_path: Option<String>,
    /// Hardware-sign path: the holder's YubiKey PKCS#11 / PIV knobs.
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
}

/// `POST /v1/accord/drill` — open a **DRILL** invocation (a non-binding rehearsal of
/// the 2-of-3 kill-switch delivery path). Identical to [`create_invocation`] but the
/// kind is pinned to `drill`; it accumulates cosignatures toward the family quorum
/// via `/v1/accord/invocation/concur` and, on reaching it (locally OR via inbound
/// gossip), is RECORDED as a surfaced drill event ([`AccordEvent`]) — it NEVER
/// latches a halt (that is exclusively the 2-of-3 `CONSTITUTIONAL` path).
async fn initiate_drill(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let req: DrillRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    // A full drill invocation (holder-app path) takes precedence; otherwise the node
    // synthesizes the non-binding drill from just the id (the app holds no keys).
    let invocation = match req.invocation {
        Some(inv) => {
            if inv.invocation_kind != InvocationKind::Drill {
                return err(
                    StatusCode::BAD_REQUEST,
                    "the drill endpoint requires invocation_kind \"drill\"",
                );
            }
            inv
        }
        None => {
            let id = req
                .invocation_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let Some(id) = id else {
                return err(
                    StatusCode::BAD_REQUEST,
                    "provide a full drill `invocation`, or an `invocation_id` to synthesize one",
                );
            };
            synth_invocation(InvocationKind::Drill, id, b"")
        }
    };
    open_invocation(
        &st,
        invocation,
        req.signature,
        req.key_id,
        req.mldsa_usb_path,
        &req.pkcs11,
    )
    .await
}

/// `POST /v1/accord/halt` request. Mirror of [`DrillRequest`] — supply a full
/// `constitutional` `invocation` (holder-app path) OR just an `invocation_id` (or nothing,
/// for a fresh `halt-<uuid>`) for the node to synthesize it. The cosignature is client-
/// submitted OR hardware-signed on the node.
#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct HaltRequest {
    #[serde(default)]
    invocation: Option<Invocation>,
    #[serde(default)]
    invocation_id: Option<String>,
    #[serde(default)]
    signature: Option<ThresholdSignature>,
    /// Hardware-sign path (mirrors admit-node): the holder's federation `key_id`.
    #[serde(default)]
    key_id: Option<String>,
    /// Hardware-sign path: the USB directory holding the wrapped ML-DSA-65 half.
    #[serde(default)]
    mldsa_usb_path: Option<String>,
    /// Hardware-sign path: the holder's YubiKey PKCS#11 / PIV knobs.
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
}

/// `POST /v1/accord/halt` — **RAISE** a 2-of-3 `CONSTITUTIONAL` kill-switch invocation.
///
/// The initiating holder hardware-signs ONE signature — which is **sub-quorum**, so this
/// does **NOT** latch anything: a halt latches ONLY when the family M-of-N is met
/// ([`replicate_and_maybe_halt`]'s `is_global_halt` requires `quorum_met`). Raising is thus
/// safe to expose from the app; the gravity is protected by the QUORUM, not by making the
/// switch un-raisable. The raised invocation gossips to peers and surfaces in their pending
/// set; the other holders cosign via `/v1/accord/invocation/concur`, and the quorum-
/// completing signature is what replicates-first-then-latches the disk halt.
///
/// This is the binding twin of [`initiate_drill`] (identical opener; the kind is
/// `constitutional` instead of `drill`). Unlike a drill, a synthesized halt is a REAL
/// kill-switch once it reaches quorum — the sub-quorum raise is the deliberately safe part.
async fn initiate_halt(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let req: HaltRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    // A full constitutional invocation (holder-app path) takes precedence; otherwise the
    // node synthesizes it from the id (the app holds no keys). The single opener signature
    // is sub-quorum — it gossips but cannot latch.
    let invocation = match req.invocation {
        Some(inv) => {
            if inv.invocation_kind != InvocationKind::Constitutional {
                return err(
                    StatusCode::BAD_REQUEST,
                    "the halt endpoint requires invocation_kind \"constitutional\"",
                );
            }
            inv
        }
        None => {
            let id = req
                .invocation_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map_or_else(|| format!("halt-{}", uuid::Uuid::new_v4()), str::to_string);
            synth_invocation(InvocationKind::Constitutional, &id, b"")
        }
    };
    open_invocation(
        &st,
        invocation,
        req.signature,
        req.key_id,
        req.mldsa_usb_path,
        &req.pkcs11,
    )
    .await
}

/// Shared opener for [`create_invocation`] / [`initiate_drill`]: resolve the
/// initiating cosignature (client-submitted OR hardware-signed on the node), build the
/// invocation object over the registered roster, replicate + maybe-halt (which
/// authenticates the opener's signature AND surfaces a quorum-complete drill), then
/// persist the pending object iff authentic. An unauthenticated opener cannot grow the
/// pending table.
async fn open_invocation(
    st: &AccordState,
    invocation: Invocation,
    submitted: Option<ThresholdSignature>,
    holder_key_id: Option<String>,
    usb_path: Option<String>,
    pkcs11: &crate::accord_provision::ProvisionPkcs11,
) -> Response {
    let roster = match accord_roster(&st.engine).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // The initiating cosignature: client-submitted OR hardware-signed on the node.
    let signature = match resolve_holder_signature(
        &invocation,
        submitted,
        holder_key_id.as_deref(),
        usb_path.as_deref(),
        pkcs11,
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let now = chrono::Utc::now().to_rfc3339();
    let obj = build_accord_invocation_object(
        HUMANITY_ACCORD_FAMILY_KEY_ID,
        &roster,
        &invocation,
        &[signature],
        &now,
    );
    let key = (
        invocation.invocation_kind.as_str().to_string(),
        invocation.invocation_id.clone(),
    );
    // Replicate the new invocation to peers (concurrence-seeking gossip) + honor a
    // halt if it already meets 2/3. This ALSO tells us if the opener's signature is
    // an authentic registered-holder one — we only persist authentic invocations
    // (an unauthenticated opener cannot grow the pending table).
    let outcome = match replicate_and_maybe_halt(st, &obj).await {
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

// ─── Announce (single-holder notify) + halt-status + surfaced events ──────────

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct AnnounceRequest {
    /// A full `notify`-kind invocation (threshold 1 — holder-app path). OPTIONAL:
    /// absent it, the node synthesizes the notify from `message` (+ `invocation_id`).
    #[serde(default)]
    invocation: Option<Invocation>,
    /// The synthesized notify's id (only when `invocation` is absent). Defaults to a
    /// fresh `notify-<uuid>`.
    #[serde(default)]
    invocation_id: Option<String>,
    /// The announcing holder's cosignature over the invocation's canonical bytes —
    /// OPTIONAL: absent it, the hardware-scrub inputs below produce it on the node.
    #[serde(default)]
    signature: Option<ThresholdSignature>,
    /// Hardware-sign path (mirrors admit-node): the holder's federation `key_id`.
    #[serde(default)]
    key_id: Option<String>,
    /// Hardware-sign path: the USB directory holding the wrapped ML-DSA-65 half.
    #[serde(default)]
    mldsa_usb_path: Option<String>,
    /// Hardware-sign path: the holder's YubiKey PKCS#11 / PIV knobs.
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
    /// The free-text announcement, cryptographically BOUND: `sha256(message)` MUST
    /// equal `invocation.payload_sha256`, so the holder's signature covers the text.
    /// Optional — an announce may carry only the (hashed) payload commitment.
    #[serde(default)]
    message: Option<String>,
}

/// `POST /v1/accord/announce` — post a single-holder **announce** (an
/// `InvocationKind::Notify` message, CC 4.2.1 §9.2.1). Verifies the ONE holder
/// signature (threshold 1 — a valid signed notify is complete on arrival), gossips
/// it to every announced peer, and RECORDS it as a surfaced announcement. Never
/// halts. The `message` (if present) is bound to the signed `payload_sha256` and
/// rides the gossiped object so peers surface the same verbatim, re-bound, text.
async fn initiate_announce(State(st): State<AccordState>, body: axum::body::Bytes) -> Response {
    let req: AnnounceRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    // A full notify invocation (holder-app path) takes precedence; otherwise the node
    // synthesizes it from the message (the app holds no keys), so `payload_sha256`
    // binds `sha256(message)` by construction.
    let invocation = match req.invocation {
        Some(inv) => {
            if inv.invocation_kind != InvocationKind::Notify {
                return err(
                    StatusCode::BAD_REQUEST,
                    "the announce endpoint requires invocation_kind \"notify\"",
                );
            }
            inv
        }
        None => {
            let id = req
                .invocation_id
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map_or_else(
                    || format!("notify-{}", uuid::Uuid::new_v4()),
                    str::to_string,
                );
            synth_invocation(
                InvocationKind::Notify,
                &id,
                req.message.as_deref().unwrap_or("").as_bytes(),
            )
        }
    };
    // Bind the plaintext to the signed payload hash — a mismatched message is a
    // malformed announce (the holder signed `payload_sha256`, not the plaintext). This
    // is trivially satisfied on the synthesized path and validates the holder-app one.
    if let Some(msg) = &req.message {
        if payload_hash_hex(msg.as_bytes()) != invocation.payload_sha256 {
            return err(
                StatusCode::BAD_REQUEST,
                "message does not match invocation.payload_sha256 (unbound announcement text)",
            );
        }
    }
    let roster = match accord_roster(&st.engine).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // The announcing cosignature: client-submitted OR hardware-signed on the node.
    let signature = match resolve_holder_signature(
        &invocation,
        req.signature,
        req.key_id.as_deref(),
        req.mldsa_usb_path.as_deref(),
        &req.pkcs11,
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut obj = build_accord_invocation_object(
        HUMANITY_ACCORD_FAMILY_KEY_ID,
        &roster,
        &invocation,
        &[signature],
        &now,
    );
    // Carry the (bound) plaintext alongside the object so peers surface it verbatim;
    // it rides the gossiped object and re-binds to payload_sha256 on every hop.
    if let Some(msg) = &req.message {
        if let Some(map) = obj.body.as_object_mut() {
            map.insert(
                "message".to_string(),
                serde_json::Value::String(msg.clone()),
            );
        }
    }
    // replicate_and_maybe_halt authenticates the signature, gossips onward, AND (for
    // a valid single-holder notify) records the surfaced announcement.
    let outcome = match replicate_and_maybe_halt(&st, &obj).await {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    if !outcome.authentic {
        return err(
            StatusCode::UNAUTHORIZED,
            "announcement carries no valid registered-holder signature — not posted",
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "posted": true,
            "invocation_id": invocation.invocation_id,
            "from": outcome.valid_signers,
            "message": req.message,
        })),
    )
        .into_response()
}

/// `GET /v1/accord/halt-status` — read-only view of the disk halt latch (the
/// enforceable kill-switch state, [`crate::accord_halt`]). `halted` is derived from
/// the latch file's PRESENCE (fail-secure: a present-but-unreadable latch still reads
/// `halted: true`, matching [`crate::accord_halt::check_halt_gate`]); `record` is the
/// best-effort parsed [`HaltRecord`] (who/when/invocation_id) or `null`. Halt
/// ENFORCEMENT is unchanged — this endpoint never writes or clears the latch.
async fn halt_status(State(st): State<AccordState>) -> Response {
    let Some(home) = &st.halt.home else {
        // No disk-latch configured (test / no-home context) — never halted.
        return (
            StatusCode::OK,
            Json(serde_json::json!({ "halted": false, "record": null })),
        )
            .into_response();
    };
    let path = crate::accord_halt::halt_latch_path(home);
    let halted = path.exists();
    let record: Option<HaltRecord> = if halted {
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "halted": halted,
            "latch_path": path.display().to_string(),
            "record": record,
        })),
    )
        .into_response()
}

/// `GET /v1/accord/events` — the surfaced NON-BINDING accord events (completed
/// drills + announcements), split by type and **most-recent-first**. Advisory
/// operator surface; the authoritative kill-switch remains the 2-of-3 verify path.
async fn list_events(State(st): State<AccordState>) -> Response {
    let (drills, announcements) = {
        let events = st.events.lock().expect("accord events lock");
        let mut drills = Vec::new();
        let mut announcements = Vec::new();
        // Stored oldest-first; reverse for most-recent-first.
        for e in events.iter().rev() {
            match e.event_type.as_str() {
                "drill" => drills.push(e.clone()),
                "announce" => announcements.push(e.clone()),
                _ => {}
            }
        }
        (drills, announcements)
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "drills": drills,
            "announcements": announcements,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
struct ConcurRequest {
    invocation_kind: String,
    invocation_id: String,
    /// A concurring holder's cosignature — OPTIONAL: absent it, the hardware-scrub
    /// inputs below produce it on the node over the pending invocation's bytes.
    #[serde(default)]
    signature: Option<ThresholdSignature>,
    /// Hardware-sign path (mirrors admit-node): the holder's federation `key_id`.
    #[serde(default)]
    key_id: Option<String>,
    /// Hardware-sign path: the USB directory holding the wrapped ML-DSA-65 half.
    #[serde(default)]
    mldsa_usb_path: Option<String>,
    /// Hardware-sign path: the holder's YubiKey PKCS#11 / PIV knobs.
    #[serde(default)]
    pkcs11: crate::accord_provision::ProvisionPkcs11,
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
    // The concurring cosignature: client-submitted OR hardware-signed on the node over
    // THIS pending invocation's canonical bytes.
    let signature = match resolve_holder_signature(
        &parsed.invocation,
        req.signature,
        req.key_id.as_deref(),
        req.mldsa_usb_path.as_deref(),
        &req.pkcs11,
    )
    .await
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let mut signatures = parsed.signatures;
    signatures.push(signature);
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

    // ── Surface COMPLETE, NON-BINDING events (drill / announce) — CC 4.2.1 §9.2.1.
    // The operator's rule: a VALID, quorum-COMPLETE event triggers its surfacing the
    // moment it is observed (locally-initiated OR inbound via gossip); a SUB-quorum
    // event only accumulates in `pending` (recorded nowhere). A drill is complete at
    // the family quorum M and NEVER halts; an announce (`notify`) has threshold 1 — a
    // single valid holder signature is complete on arrival. Recording is idempotent
    // ([`AccordState::record_event`] de-dups by id), so re-gossip re-surfaces nothing.
    if status.invocation_kind == InvocationKind::Drill.as_str() && quorum_met {
        let newly = st.record_event(AccordEvent {
            event_type: "drill".to_string(),
            invocation_id: status.invocation_id.clone(),
            recorded_at: now.clone(),
            signers: status.valid_signers.clone(),
            quorum_threshold: m,
            message: None,
        });
        if newly {
            tracing::info!(
                invocation_id = %status.invocation_id,
                signers = ?status.valid_signers,
                "accord DRILL surfaced (quorum-complete, NON-BINDING — never halts)"
            );
        }
    } else if status.invocation_kind == InvocationKind::Notify.as_str()
        && !status.valid_signers.is_empty()
    {
        // Threshold 1: a single valid holder cosignature completes an announce. The
        // free-text message is surfaced ONLY when it BINDS to the signed payload hash
        // (`sha256(message) == payload_sha256`) — a tampered/unbound plaintext is
        // dropped to `None` while the (still-authentic) announce is recorded.
        let message = obj
            .body
            .get("message")
            .and_then(|v| v.as_str())
            .filter(|m| payload_hash_hex(m.as_bytes()) == parsed.invocation.payload_sha256)
            .map(str::to_string);
        let newly = st.record_event(AccordEvent {
            event_type: "announce".to_string(),
            invocation_id: status.invocation_id.clone(),
            recorded_at: now.clone(),
            signers: status.valid_signers.clone(),
            quorum_threshold: 1,
            message,
        });
        if newly {
            tracing::info!(
                invocation_id = %status.invocation_id,
                from = ?status.valid_signers,
                "accord ANNOUNCE surfaced (single-holder notify)"
            );
        }
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

// ─── Trust Root — canonical-server ops (accord-authorized) ───────────────────
//
// A1/B1/C1 manage the canonical mesh from the Trust Root card. The quorum for
// EVERY canonical op is resolved in ONE place ([`canonical_op_quorum_m`]) from the
// LIVE roster + the op class — never hard-coded. So as the founder set grows the
// same ops scale: structural ops already read the family's entrenched `quorum:M/N`
// (via [`kill_switch_quorum_m`]); operational ops are a single-holder bootstrap
// today, and moving them to m-of-n is a one-line change in that one function.

/// The authority class of a canonical-server op → its required quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanonicalOpClass {
    /// Additive / operational (add a canonical server, update its address) — a
    /// single accord holder suffices today (the address is pubkey-authenticated
    /// regardless).
    Operational,
    /// Destructive / structural (supersede or withdraw a canonical server) — the
    /// family's entrenched M-of-N; no single holder may remove/replace an anchor.
    #[allow(dead_code)] // consumed by the supersede/withdraw ops (follow-ups)
    Structural,
}

/// Required signature count **M** for a canonical op — resolved from the live
/// roster + the op class. THE single quorum-policy chokepoint: to move the
/// operational ops to m-of-n as we scale, change ONLY the `Operational` arm here.
async fn canonical_op_quorum_m(
    engine: &Engine,
    roster: &[ThresholdMember],
    class: CanonicalOpClass,
) -> usize {
    match class {
        // Additive bootstrap — 1-of-N today (policy knob). Swap to
        // `kill_switch_quorum_m(engine, roster).await` to make it m-of-n.
        CanonicalOpClass::Operational => 1,
        // Structural — the family's entrenched `quorum:M/N` (already m-of-n).
        CanonicalOpClass::Structural => kill_switch_quorum_m(engine, roster).await,
    }
}

const CANONICAL_ADDRESS_OP: &str = "canonical:address";

/// The accord-signed **canonical address update** invocation (CC 3.3.6.2). Holders
/// hybrid-sign the JCS-canonical bytes of this object; the endpoint verifies the
/// quorum, then emits the `transport_destination` binding — so a canonical
/// server's address is a pubkey-authenticated, replaceable record (the Option-A
/// bootstrap, CIRISPersist#342), never a hard-coded IP.
#[derive(Debug, Clone, Deserialize, Serialize)]
struct CanonicalAddressUpdate {
    /// Domain separator — MUST be `"canonical:address"` (anti cross-op replay).
    op: String,
    /// The canonical node whose address is being (re)bound.
    canonical_key_id: String,
    /// Transport kind (e.g. `"reticulum"`, `"ip"`).
    transport_kind: String,
    /// The new destination / address.
    destination: String,
    /// Anti-replay nonce.
    invocation_id: String,
    /// RFC3339 assertion time.
    asserted_at: String,
    /// v13.5.0 (#397) — the canonical's transport-tier Ed25519 pubkey (base64,
    /// 32 raw bytes), pairing with a `reticulum` `destination` dest-hash so any
    /// peer can `prime_peer` this explicit-hash canonical (which cannot announce).
    /// Optional; `skip_serializing_if` keeps a pre-#397 invocation's JCS bytes —
    /// and its threshold signatures — byte-identical when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport_ed25519_pubkey_base64: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AddressUpdateRequest {
    invocation: CanonicalAddressUpdate,
    signatures: Vec<ThresholdSignature>,
}

/// `POST /v1/accord/canonical/address` — accord-authorized (1-of-N operational)
/// (re)binding of a canonical server's transport address.
async fn update_canonical_address(
    State(st): State<AccordState>,
    body: axum::body::Bytes,
) -> Response {
    let req: AddressUpdateRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    let inv = &req.invocation;
    if inv.op != CANONICAL_ADDRESS_OP {
        return err(
            StatusCode::BAD_REQUEST,
            &format!("op must be {CANONICAL_ADDRESS_OP:?}"),
        );
    }
    if inv.canonical_key_id.trim().is_empty()
        || inv.transport_kind.trim().is_empty()
        || inv.destination.trim().is_empty()
        || inv.invocation_id.trim().is_empty()
    {
        return err(
            StatusCode::BAD_REQUEST,
            "canonical_key_id, transport_kind, destination, invocation_id are all required",
        );
    }
    let asserted_at = match chrono::DateTime::parse_from_rfc3339(inv.asserted_at.trim()) {
        Ok(t) => t.with_timezone(&chrono::Utc),
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                &format!("asserted_at not RFC3339: {e}"),
            )
        }
    };

    // Live accord roster + one-key-one-seat (N2).
    let roster = match accord_roster(&st.engine).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(e) = assert_distinct_roster(&roster) {
        return err(StatusCode::CONFLICT, &e);
    }

    // Quorum — resolved from the roster + op class, never hard-coded.
    let m = canonical_op_quorum_m(&st.engine, &roster, CanonicalOpClass::Operational).await;

    // Verify the hybrid cosignatures over the JCS-canonical invocation bytes.
    let canonical = match ciris_verify_core::jcs::canonicalize(
        &serde_json::to_value(inv).unwrap_or(serde_json::Value::Null),
    ) {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("canonicalize: {e}"),
            )
        }
    };
    let valid = match verify_threshold_signatures(&canonical, &roster, &req.signatures, m) {
        Ok(v) => v,
        Err(e) => {
            return err(
                StatusCode::FORBIDDEN,
                &format!("accord quorum not met for canonical address update (need {m}): {e}"),
            )
        }
    };

    // Admit the (re)binding — the authenticated identity↔address record.
    if let Err(e) = st
        .engine
        .federation_directory()
        .put_transport_destination(&ciris_persist::federation::TransportDestination {
            occurrence_key_id: inv.canonical_key_id.trim().to_string(),
            transport_kind: inv.transport_kind.trim().to_string(),
            destination: inv.destination.trim().to_string(),
            asserted_at,
            last_seen_at: None,
            // v13.5.0 (#397): the transport-tier Ed25519 that pairs with the
            // dest-hash so peers can prime_peer this (explicit-hash) canonical.
            // Carried on the address-update invocation when present.
            transport_ed25519_pubkey_base64: inv.transport_ed25519_pubkey_base64.clone(),
        })
        .await
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("put_transport_destination: {e}"),
        );
    }

    tracing::info!(
        canonical_key_id = %inv.canonical_key_id.trim(),
        transport_kind = %inv.transport_kind.trim(),
        destination = %inv.destination.trim(),
        quorum_m = m,
        valid_signatures = valid,
        "Trust Root: canonical server address (re)bound (accord-authorized)"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "updated": true,
            "canonical_key_id": inv.canonical_key_id.trim(),
            "transport_kind": inv.transport_kind.trim(),
            "destination": inv.destination.trim(),
            "quorum_m": m,
            "valid_signatures": valid,
            "roster_size": roster.len(),
        })),
    )
        .into_response()
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
        events: Arc::new(Mutex::new(Vec::new())),
    };
    Router::new()
        .route("/v1/accord/holder", axum::routing::post(register_holder))
        .route("/v1/accord-holders", axum::routing::get(list_holders))
        .route(
            "/v1/accord/verify-invocation",
            axum::routing::post(verify_invocation_handler),
        )
        .route("/v1/accord/message", axum::routing::post(ingest_message))
        // drill (non-binding rehearsal) + announce (single-holder notify) + the
        // read-only halt-status + the surfaced non-binding events log
        .route("/v1/accord/drill", axum::routing::post(initiate_drill))
        .route(
            "/v1/accord/announce",
            axum::routing::post(initiate_announce),
        )
        // RAISE a 2-of-3 CONSTITUTIONAL halt (one opener signature — sub-quorum, cannot
        // latch; the family M-of-N cosign latches). The binding twin of /drill.
        .route("/v1/accord/halt", axum::routing::post(initiate_halt))
        .route("/v1/accord/halt-status", axum::routing::get(halt_status))
        .route("/v1/accord/events", axum::routing::get(list_events))
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
        // Trust Root — canonical-server ops (accord-authorized; quorum via
        // canonical_op_quorum_m so they scale to m-of-n as the founder set grows).
        .route(
            "/v1/accord/canonical/address",
            axum::routing::post(update_canonical_address),
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal `notify` invocation for the signature-resolver tests.
    fn sample_invocation() -> Invocation {
        Invocation {
            invocation_kind: InvocationKind::Notify,
            invocation_id: "notify-test-1".to_string(),
            resumes_halt_id: None,
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            asserted_at: "2026-07-05T00:00:00.000Z".to_string(),
            valid_until: "2026-07-05T01:00:00.000Z".to_string(),
            payload_sha256: "0".repeat(64),
        }
    }

    fn sample_signature() -> ThresholdSignature {
        ThresholdSignature {
            member_id: "accord-holder-1".to_string(),
            ed25519_signature_base64: "AA".to_string(),
            mldsa65_signature_base64: Some("BB".to_string()),
        }
    }

    /// A client-submitted signature is passed through verbatim (the holder-app
    /// contract keeps working, feature-independent).
    #[tokio::test]
    async fn resolve_prefers_a_submitted_signature() {
        let inv = sample_invocation();
        let sig = sample_signature();
        let out = resolve_holder_signature(
            &inv,
            Some(sig.clone()),
            None,
            None,
            &crate::accord_provision::ProvisionPkcs11::default(),
        )
        .await
        .expect("a submitted signature is returned verbatim");
        assert_eq!(out.member_id, sig.member_id);
        assert_eq!(out.ed25519_signature_base64, sig.ed25519_signature_base64);
    }

    /// Neither a signature NOR the hardware-scrub inputs → a plain 400 (before any
    /// token open), so a caller that forgets both fails loudly.
    #[tokio::test]
    async fn resolve_rejects_when_no_signature_and_no_hardware_inputs() {
        let inv = sample_invocation();
        let resp = resolve_holder_signature(
            &inv,
            None,
            None,
            None,
            &crate::accord_provision::ProvisionPkcs11::default(),
        )
        .await
        .expect_err("no signature + no hardware inputs must be rejected");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Blank hardware inputs are treated as absent (trimmed-empty) → 400, not a
    /// half-open hardware attempt.
    #[tokio::test]
    async fn resolve_rejects_blank_hardware_inputs() {
        let inv = sample_invocation();
        let resp = resolve_holder_signature(
            &inv,
            None,
            Some("   "),
            Some(""),
            &crate::accord_provision::ProvisionPkcs11::default(),
        )
        .await
        .expect_err("blank holder/usb inputs must be rejected");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// A synthesized notify binds its `payload_sha256` to `sha256(message)` — the
    /// exact equality `initiate_announce` re-checks, so the node-built envelope always
    /// passes the message-binding gate. A drill synthesizes with the empty payload.
    #[test]
    fn synth_invocation_binds_the_notify_payload() {
        let notify = synth_invocation(InvocationKind::Notify, "notify-x", b"hello mesh");
        assert_eq!(notify.invocation_kind, InvocationKind::Notify);
        assert_eq!(notify.payload_sha256, payload_hash_hex(b"hello mesh"));
        assert!(notify.resumes_halt_id.is_none());
        // The nonce is base64url(32 bytes) and the window is non-empty + parseable.
        assert!(!notify.nonce.is_empty());
        assert!(chrono::DateTime::parse_from_rfc3339(&notify.valid_until).is_ok());

        let drill = synth_invocation(InvocationKind::Drill, "drill-x", b"");
        assert_eq!(drill.invocation_kind, InvocationKind::Drill);
        assert_eq!(drill.payload_sha256, payload_hash_hex(b""));
    }

    /// Without the `pkcs11` feature the hardware-sign path is an honest 501 (mirrors
    /// admit-node) — the node cannot open a token, so it says so rather than 400ing.
    #[cfg(not(feature = "pkcs11"))]
    #[tokio::test]
    async fn resolve_hardware_path_without_pkcs11_is_not_implemented() {
        let inv = sample_invocation();
        let resp = resolve_holder_signature(
            &inv,
            None,
            Some("accord-holder-1"),
            Some("/tmp/usb"),
            &crate::accord_provision::ProvisionPkcs11::default(),
        )
        .await
        .expect_err("the hardware path needs pkcs11");
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
