//! **Config-as-CEG** (Server 0.5 Phase 1) — a signed, owner-gated config store
//! over the CEG, mirroring CIRISAgent's `GraphConfigService` but with the
//! substrate's hybrid-signature + owner-binding discipline.
//!
//! ## The model (mirrors [`crate::peer`] exactly, different dimension)
//!
//! A config entry is a **self-attested `scores` attestation** authored by THIS
//! node (`attesting_key_id == node_key_id`), carried on the open-vocab dimension
//! [`CONFIG_DIMENSION`] (`config:v1`). The config KEY lives **in the envelope**
//! (`envelope["key"]`), NOT as a federation `subject_key_id` — a config row is
//! about the node's own runtime, not directed at a peer. The full
//! [`ConfigEntry`] (`{key, value, version, updated_by, scope, previous_version}`)
//! rides in the envelope as JSON so it round-trips byte-for-byte.
//!
//! Writes reuse the EXACT signing path [`crate::peer::emit_replication_consent`]
//! uses: `ceg_produce_canonicalize` → `SHA-256` → `engine.sign_hybrid` →
//! `put_attestation`. Reads mirror
//! [`crate::peer::replication_peers_from_consent`]:
//! `list_attestations_by(node) → filter SCORES && envelope["dimension"] ==
//! CONFIG_DIMENSION`.
//!
//! ## Versioning (latest-wins)
//!
//! `scores` rows are NOT collapsed by dimension on the federation tier (each
//! `put_attestation` mints a fresh `attestation_id`), so a `set_config` never
//! mutates a prior row — it appends a NEW row with `version = prev + 1` and
//! `previous_version = <prior row id>`. A read folds all rows for a key and
//! returns the **highest `version`** (latest-wins, ties broken by `asserted_at`).
//!
//! ## Revocation (stubbed — flagged)
//!
//! Like [`crate::peer::replication_peers_from_consent`], **presence == active**:
//! a `withdraws`/`recants` against a config row's `attestation_id` is honored
//! here (a recanted key reads as absent), via [`config_key_revoked`], which is
//! the same `withdraws`/`recants`-by-the-node + `revocations_for` shape
//! [`crate::auth::ownership::is_owner_bound`]'s `delegation_revoked` uses. There
//! is no substrate `supersede`-aware reader yet (the finer RC29 §5.6.8.15
//! supersede flow is TODO upstream); the version-fold already gives last-write-
//! wins for the common path.
//!
//! ## Scope (declared now; finer enforcement is Phase 2)
//!
//! [`ConfigScope::Identity`] marks an owner-binding-sensitive key; [`ConfigScope::Local`]
//! is owner-runtime-tunable. The **write API** owner-gate (same gate peering
//! uses) is what currently protects every write; per-scope differentiation is a
//! Phase-2 enforcement TODO (see [`crate::config_api`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ciris_persist::federation::types::{
    attestation_tier, attestation_type, Attestation, SignedAttestation,
};
use ciris_persist::prelude::Engine;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

/// The open-vocab config dimension every config row rides on. **Versioned**
/// (`:v1`) to satisfy persist's `DimensionAdmissionPolicy { require_version_segment:
/// true }`, exactly like [`crate::peer::CONSENT_DIMENSION`]. `config:` is NOT a
/// reserved prefix, so a node-keyed self-attestation on it is admitted without a
/// reserved-prefix role.
pub const CONFIG_DIMENSION: &str = "config:v1";

/// A typed config value — the Rust mirror of CIRISAgent's `GraphConfigService`
/// discriminated value union. Serialized **untagged** so the envelope JSON
/// carries the natural JSON shape (`"x"`, `7`, `1.5`, `true`, `[...]`, `{...}`)
/// and round-trips byte-for-byte through `ceg_produce_canonicalize`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfigValue {
    /// A boolean. (Declared BEFORE the integer arms: serde's untagged matcher
    /// tries variants top-down, and a JSON `true`/`false` must not be coerced
    /// into an integer arm.)
    Bool(bool),
    /// A signed 64-bit integer.
    I64(i64),
    /// A 64-bit float.
    F64(f64),
    /// A UTF-8 string.
    Str(String),
    /// A heterogeneous JSON array.
    List(Vec<serde_json::Value>),
    /// A JSON object.
    Dict(serde_json::Map<String, serde_json::Value>),
}

impl ConfigValue {
    /// The string value, iff this is a [`ConfigValue::Str`].
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConfigValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
    /// The integer value, iff this is a [`ConfigValue::I64`].
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ConfigValue::I64(i) => Some(*i),
            _ => None,
        }
    }
    /// The float value, iff this is a [`ConfigValue::F64`] (or an [`ConfigValue::I64`]
    /// widened to `f64` — the natural numeric read).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ConfigValue::F64(f) => Some(*f),
            ConfigValue::I64(i) => Some(*i as f64),
            _ => None,
        }
    }
    /// The boolean value, iff this is a [`ConfigValue::Bool`].
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConfigValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Where a config key lives on the trust/authority spectrum.
///
/// - [`ConfigScope::Local`] — owner-runtime-tunable knobs (cadences, limits).
/// - [`ConfigScope::Identity`] — owner-binding-sensitive (touches identity /
///   ownership). Declared now; finer per-scope enforcement is a Phase-2 TODO —
///   today BOTH are protected by the same write-API owner-gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigScope {
    /// Owner-runtime-tunable.
    #[default]
    Local,
    /// Owner-binding-sensitive (declared; Phase-2 enforcement TODO).
    Identity,
}

/// A resolved config entry — the latest-wins fold of a key's `config:v1` rows.
/// Mirrors CIRISAgent's `ConfigNode`: the key, its typed value, a monotonically
/// increasing `version`, who wrote it, its scope, and the prior row id it chains
/// from (`None` for the first write).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigEntry {
    /// The config key (e.g. `replication.reconcile_secs`).
    pub key: String,
    /// The typed value.
    pub value: ConfigValue,
    /// Monotonic version (first write = 1, then +1 per write).
    pub version: u64,
    /// The identity that authored the write (the owner/user identity, or the
    /// node key_id when the API uses the node's authority).
    pub updated_by: String,
    /// The key's trust/authority scope.
    pub scope: ConfigScope,
    /// The `attestation_id` of the prior version's row, or `None` for the first.
    pub previous_version: Option<String>,
}

/// Build the `config:v1` envelope for an entry — the JSON that is JCS-canonicalized
/// into the signing basis. Mirrors [`crate::peer::emit_replication_consent`]'s
/// envelope shape (same envelope fields: `dimension`, `attesting_key_id`,
/// `score`, `cohort_scope`, `asserted_at`), plus the entry fields carried inline.
fn config_envelope(node_key_id: &str, entry: &ConfigEntry, asserted_at: &str) -> serde_json::Value {
    serde_json::json!({
        "dimension": CONFIG_DIMENSION,
        "attesting_key_id": node_key_id,
        "score": 1.0,
        // `federation` is the closed-set cohort the substrate admits for a
        // federation-tier row; the config row is self-directed at THIS node (a
        // node-local entry), with the key carried inline (NOT as a subject).
        "cohort_scope": "federation",
        "witness_relation": "self",
        "asserted_at": asserted_at,
        // The config entry, carried inline so a read reconstructs it verbatim.
        "key": entry.key,
        "value": entry.value,
        "version": entry.version,
        "updated_by": entry.updated_by,
        "scope": entry.scope,
        "previous_version": entry.previous_version,
    })
}

/// Parse a stored `config:v1` row's envelope back into a [`ConfigEntry`].
/// Returns `None` for a row whose envelope is not a well-formed config entry
/// (defensive — a malformed row is skipped, not fatal).
fn entry_from_envelope(env: &serde_json::Value) -> Option<ConfigEntry> {
    let key = env.get("key")?.as_str()?.to_owned();
    let value: ConfigValue = serde_json::from_value(env.get("value")?.clone()).ok()?;
    let version = env.get("version")?.as_u64()?;
    let updated_by = env.get("updated_by")?.as_str()?.to_owned();
    let scope: ConfigScope = serde_json::from_value(env.get("scope")?.clone()).ok()?;
    let previous_version = env
        .get("previous_version")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Some(ConfigEntry {
        key,
        value,
        version,
        updated_by,
        scope,
        previous_version,
    })
}

/// A stored config row paired with the substrate row id + assertion time, so the
/// version-fold can break version ties deterministically and chain `previous_version`.
struct StoredRow {
    attestation_id: String,
    asserted_at: chrono::DateTime<chrono::Utc>,
    entry: ConfigEntry,
}

/// Read every LIVE (unrevoked) `config:v1` row this node authored, parsed into
/// [`StoredRow`]s. Mirrors [`crate::peer::replication_peers_from_consent`]'s read
/// (`list_attestations_by(node) → filter SCORES && dimension`).
async fn live_config_rows(engine: &Arc<Engine>, node_key_id: &str) -> Result<Vec<StoredRow>> {
    let directory = engine.federation_directory();
    let rows = directory
        .list_attestations_by(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list attestations by {node_key_id}: {e}"))?;

    let mut out = Vec::new();
    for a in rows {
        if a.attestation_type != attestation_type::SCORES {
            continue;
        }
        if a.attestation_envelope
            .get("dimension")
            .and_then(|d| d.as_str())
            != Some(CONFIG_DIMENSION)
        {
            continue;
        }
        // Revocation: a recanted/withdrawn config row reads as absent.
        if config_key_revoked(engine, node_key_id, &a.attestation_id).await {
            continue;
        }
        if let Some(entry) = entry_from_envelope(&a.attestation_envelope) {
            out.push(StoredRow {
                attestation_id: a.attestation_id,
                asserted_at: a.asserted_at,
                entry,
            });
        }
    }
    Ok(out)
}

/// True iff a config row (`attestation_id`) authored by `node_key_id` has been
/// revoked — by a `withdraws`/`recants` the node authored against it, or by a
/// `revocations_for` row. Same shape as
/// `crate::auth::ownership`'s `delegation_revoked`, scoped to the config row id.
///
/// NOTE (flagged): the substrate has no `supersede`-aware federation-tier reader
/// yet, so partial-narrowing supersede (RC29 §5.6.8.15) is NOT honored — only
/// explicit withdraws/recants/revocation. For the common last-write-wins path the
/// version-fold already supersedes prior values.
async fn config_key_revoked(engine: &Arc<Engine>, node_key_id: &str, attestation_id: &str) -> bool {
    let directory = engine.federation_directory();
    if let Ok(by_node) = directory.list_attestations_by(node_key_id).await {
        for a in by_node {
            let is_retraction = a.attestation_type == attestation_type::WITHDRAWS
                || a.attestation_type == attestation_type::RECANTS;
            // A retraction can target the row either via attested_key_id or via
            // its subject_key_ids carrying the row id.
            if is_retraction
                && (a.attested_key_id == attestation_id
                    || a.subject_key_ids.iter().any(|s| s == attestation_id))
            {
                return true;
            }
        }
    }
    if let Ok(revs) = directory.revocations_for(attestation_id).await {
        if !revs.is_empty() {
            return true;
        }
    }
    false
}

/// Fold a key's rows to the latest-wins [`ConfigEntry`] + its row id: highest
/// `version`, ties broken by the later `asserted_at`.
fn latest_for_key<'a>(rows: &'a [StoredRow], key: &str) -> Option<&'a StoredRow> {
    rows.iter().filter(|r| r.entry.key == key).max_by(|a, b| {
        a.entry
            .version
            .cmp(&b.entry.version)
            .then(a.asserted_at.cmp(&b.asserted_at))
    })
}

/// Read the latest [`ConfigEntry`] for `key` (highest version, latest-wins), or
/// `None` if the key has no live row. A recanted/withdrawn key reads as absent
/// (see [`config_key_revoked`]).
pub async fn get_config(
    engine: &Arc<Engine>,
    node_key_id: &str,
    key: &str,
) -> Result<Option<ConfigEntry>> {
    let rows = live_config_rows(engine, node_key_id).await?;
    Ok(latest_for_key(&rows, key).map(|r| r.entry.clone()))
}

/// List the latest [`ConfigEntry`] per key (latest-wins fold), optionally filtered
/// to keys starting with `prefix`. Returns a sorted [`BTreeMap`] keyed by config key.
pub async fn list_configs(
    engine: &Arc<Engine>,
    node_key_id: &str,
    prefix: Option<&str>,
) -> Result<BTreeMap<String, ConfigEntry>> {
    let rows = live_config_rows(engine, node_key_id).await?;

    // Distinct keys (filtered by prefix), then latest-fold each.
    let mut out = BTreeMap::new();
    for r in &rows {
        if let Some(p) = prefix {
            if !r.entry.key.starts_with(p) {
                continue;
            }
        }
        if out.contains_key(&r.entry.key) {
            continue;
        }
        if let Some(latest) = latest_for_key(&rows, &r.entry.key) {
            out.insert(latest.entry.key.clone(), latest.entry.clone());
        }
    }
    Ok(out)
}

/// Write a config entry: compute `version = current.version + 1` (or `1`),
/// `previous_version = current row id`, build the `config:v1` envelope, hybrid-sign
/// it (the SAME path [`crate::peer::emit_replication_consent`] uses), and
/// `put_attestation` the row. Returns the freshly-written [`ConfigEntry`].
///
/// The signing identity is the node's `Engine` signer (`attesting_key_id =
/// node_key_id`) — the node authors the row on the owner's behalf; the API layer
/// ([`crate::config_api`]) enforces the owner-gate. `updated_by` records who
/// directed the write (the authenticated owner/user identity).
pub async fn set_config(
    engine: &Arc<Engine>,
    node_key_id: &str,
    key: &str,
    value: ConfigValue,
    updated_by: &str,
    scope: ConfigScope,
) -> Result<ConfigEntry> {
    // Current latest (for version + previous_version chaining).
    let rows = live_config_rows(engine, node_key_id).await?;
    let current = latest_for_key(&rows, key);
    let version = current.map(|r| r.entry.version + 1).unwrap_or(1);
    let previous_version = current.map(|r| r.attestation_id.clone());

    let entry = ConfigEntry {
        key: key.to_owned(),
        value,
        version,
        updated_by: updated_by.to_owned(),
        scope,
        previous_version,
    };

    let now = chrono::Utc::now();
    let envelope = config_envelope(node_key_id, &entry, &now.to_rfc3339());

    // ── Emit recipe — the EXACT path emit_replication_consent uses ───────────
    // 1. CEG produce-canonical bytes (V2/JCS — the signing basis).
    let canonical = ceg_produce_canonicalize(&envelope)
        .map_err(|e| anyhow::anyhow!("ceg_produce_canonicalize config envelope: {e}"))?;
    // 2. original_content_hash = hex(SHA-256(canonical)).
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    // 3. Hybrid sign (Ed25519 + ML-DSA-65) over the canonical bytes — same signer.
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .context("hybrid-sign config envelope")?;
    let classical_b64 = B64.encode(&sig.classical.signature);
    let pqc_b64 = B64.encode(&sig.pqc.signature);

    // 4. Assemble the FEDERATION-tier, self-directed row (the config key lives in
    //    the envelope, NOT as a subject_key_id — subject is the node itself).
    let attestation_id = new_uuid_v4();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: node_key_id.to_owned(),
        attested_key_id: node_key_id.to_owned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: Some(1.0),
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: classical_b64,
        scrub_signature_pqc: Some(pqc_b64),
        scrub_key_id: node_key_id.to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(), // server-computed on insert
        subject_key_ids: vec![node_key_id.to_owned()],
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
    };

    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| anyhow::anyhow!("put_attestation(config:v1): {e}"))?;

    tracing::info!(
        key,
        version,
        updated_by,
        dimension = CONFIG_DIMENSION,
        attestation_id = %attestation_id,
        "wrote config:v1 entry (signed, owner-gated at the API layer)"
    );
    Ok(entry)
}

/// Typed convenience: the latest string value for `key` (iff it is a [`ConfigValue::Str`]).
pub async fn get_str(engine: &Arc<Engine>, node_key_id: &str, key: &str) -> Result<Option<String>> {
    Ok(get_config(engine, node_key_id, key)
        .await?
        .and_then(|e| e.value.as_str().map(str::to_owned)))
}

/// Typed convenience: the latest integer value for `key` (iff it is a [`ConfigValue::I64`]).
pub async fn get_i64(engine: &Arc<Engine>, node_key_id: &str, key: &str) -> Result<Option<i64>> {
    Ok(get_config(engine, node_key_id, key)
        .await?
        .and_then(|e| e.value.as_i64()))
}

/// Typed convenience: the latest float value for `key` (iff it is a [`ConfigValue::F64`]
/// or an [`ConfigValue::I64`] widened).
pub async fn get_f64(engine: &Arc<Engine>, node_key_id: &str, key: &str) -> Result<Option<f64>> {
    Ok(get_config(engine, node_key_id, key)
        .await?
        .and_then(|e| e.value.as_f64()))
}

/// Typed convenience: the latest boolean value for `key` (iff it is a [`ConfigValue::Bool`]).
pub async fn get_bool(engine: &Arc<Engine>, node_key_id: &str, key: &str) -> Result<Option<bool>> {
    Ok(get_config(engine, node_key_id, key)
        .await?
        .and_then(|e| e.value.as_bool()))
}

/// Minimal RFC-4122 v4 row id (no `uuid` dep) — same recipe as
/// `peer.rs::new_uuid_v4`. The content hash is the integrity anchor, not this id.
fn new_uuid_v4() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let t = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() as u64;
    let a = t ^ (n.rotate_left(17));
    let b = t.rotate_left(31) ^ n;
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        (a as u16) & 0x0fff,
        ((b >> 48) as u16 & 0x3fff) | 0x8000,
        b & 0xffff_ffff_ffff,
    )
}
