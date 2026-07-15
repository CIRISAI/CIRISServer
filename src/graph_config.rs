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
//! `put_attestation`. Reads are the persist v17.4.0 `list_scores` seek
//! (CIRISServer#267, FSD-005 Appendix C): ONE cursor-paged
//! `{attester: node, subject: node, dimension_exact: config:v1, lifecycle:
//! Live}` query — the substrate excludes retracted rows server-side.
//!
//! ## Versioning (latest-wins)
//!
//! `scores` rows are NOT collapsed by dimension on the federation tier (each
//! `put_attestation` mints a fresh `attestation_id`), so a `set_config` never
//! mutates a prior row — it appends a NEW row with `version = prev + 1` and
//! `previous_version = <prior row id>`. A read folds all rows for a key and
//! returns the **highest `version`** (latest-wins, ties broken by `asserted_at`).
//! (That per-key version fold is CONFIG semantics — chained by
//! `envelope["version"]`, not by the CEG lifecycle — so it stays client-side
//! by design; the substrate fold retires only the retraction re-scan.)
//!
//! ## Revocation (CEG §6.1, substrate-side since #267)
//!
//! A `withdraws`/`recants` the node authors against a config row's
//! `attestation_id` still makes the key read as absent — but the fold moved
//! into persist: `lifecycle: Live` excludes any row a same-attester structural
//! composer names via the CEG §6.1 canonical envelope member
//! `references_attestation_id`. This RETIRES the pre-#267 `config_key_revoked`
//! N+1 (a full `list_attestations_by(node)` re-scan per row, plus a
//! `revocations_for` probe) and, with it, that helper's ad-hoc targeting
//! conventions (`attested_key_id`/`subject_key_ids` carrying the row id, and
//! attestation-ids probed through the key-revocation table): nothing in
//! production ever emitted those shapes — a retraction now speaks CEG §6.1 or
//! it does not retract. The RC29 §5.6.8.15 partial-narrowing supersede remains
//! TODO upstream; the version-fold already gives last-write-wins for the
//! common path.
//!
//! ## Scope (declared now; finer enforcement is Phase 2)
//!
//! [`ConfigScope::Identity`] marks an owner-binding-sensitive key; [`ConfigScope::Local`]
//! is owner-runtime-tunable. The **write API** owner-gate (same gate peering
//! uses) is what currently protects every write; per-scope differentiation is a
//! Phase-2 enforcement TODO (see [`crate::config_api`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::Engine;

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
    /// A tombstone (JSON `null`) — the canonical "deleted" marker. A `DELETE`
    /// writes a new version carrying this; the latest-wins fold makes the key read
    /// as absent ([`get_config`]/[`list_configs`] skip a Null-valued latest). Mirrors
    /// CIRISAgent's "set to None as deletion" (the agent will adopt THIS Rust impl as
    /// the common one). Declared FIRST so the untagged matcher maps `null` here before
    /// any value arm (no value arm matches `null` anyway).
    Null,
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
    /// The list value as `Vec<String>`, iff this is a [`ConfigValue::List`] —
    /// every element coerced to its string form (a JSON string yields its inner
    /// value; other scalars yield their JSON text). Non-list values yield `None`.
    /// Used by the boot reads for list-valued config:* keys (`net.bootstrap_peers`,
    /// `auth.admin_key_ids`).
    pub fn as_str_list(&self) -> Option<Vec<String>> {
        match self {
            ConfigValue::List(items) => Some(
                items
                    .iter()
                    .map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect(),
            ),
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
        "cohort_scope": cohort_scope::FEDERATION,
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

/// Page size for the [`live_config_rows`] `list_scores` seek. Config stores
/// are small (tens of keys × a few versions); one page is the common case and
/// the cursor loop stays correct for any size.
const CONFIG_SCORES_PAGE: i64 = 512;

/// Read every LIVE (unretracted) `config:v1` row this node authored, parsed
/// into [`StoredRow`]s — the persist v17.4.0 `list_scores` read
/// (CIRISServer#267, FSD-005 Appendix C, CIRISPersist#455/#456).
///
/// ## Why one seek and not a scan + re-scan (#267)
///
/// Pre-#267 this was `list_attestations_by(node)` (EVERY row the node ever
/// attested, every type, every dimension) filtered client-side to
/// `SCORES && dimension == config:v1` — and then, PER surviving row, a second
/// full `list_attestations_by(node)` walk + a `revocations_for` probe to
/// decide revocation (`config_key_revoked`): the O(N²) N+1 the 2026-07-14
/// demand survey flagged. `list_scores` is the ordered V106 subject+dimension
/// seek with `lifecycle: Live` — withdrawn/recanted/superseded rows are
/// excluded server-side by the CEG §6.1 fold (composers match via the
/// canonical `references_attestation_id` envelope member), so the whole
/// revocation re-scan is gone.
///
/// The ONE [`AttestationFilter`](ciris_persist::read::AttestationFilter) is
/// built once and reused across pages (the pin-once contract, Appendix C.4 —
/// `#[non_exhaustive]`, so it is mutated from `Default` rather than
/// struct-literal-constructed). Both attester AND subject pin to the node:
/// config rows are self-directed (`subject_key_ids == [node]`, see
/// [`set_config`]), and the attester pin keeps a peer-replicated row about us
/// from ever reading as OUR config.
///
/// The read is unauthenticated (`caller = ""`): config rows are
/// `cohort_scope: federation` by construction ([`config_envelope`]), which the
/// §4.3 gate admits to any caller — so the empty caller skips the per-page
/// admission resolution without narrowing the result.
async fn live_config_rows(engine: &Arc<Engine>, node_key_id: &str) -> Result<Vec<StoredRow>> {
    use ciris_persist::read::{AttestationFilter, LifecycleView};

    let directory = engine.federation_directory();

    let mut filter = AttestationFilter::default();
    filter.attesting_key_id = Some(node_key_id.to_owned());
    filter.subject_key_id = Some(node_key_id.to_owned());
    filter.attestation_type = Some(attestation_type::SCORES.to_owned());
    filter.dimension_exact = Some(CONFIG_DIMENSION.to_owned());
    filter.lifecycle = LifecycleView::Live;

    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = directory
            .list_scores("", filter.clone(), cursor.take(), CONFIG_SCORES_PAGE)
            .await
            .map_err(|e| anyhow::anyhow!("list_scores(config:v1, {node_key_id}): {e}"))?;
        for a in page.items {
            // Defensive: a malformed envelope is skipped, not fatal.
            if let Some(entry) = entry_from_envelope(&a.attestation_envelope) {
                out.push(StoredRow {
                    attestation_id: a.attestation_id,
                    asserted_at: a.asserted_at,
                    entry,
                });
            }
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(out)
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
/// (excluded substrate-side by [`live_config_rows`]' `lifecycle: Live` seek).
pub async fn get_config(
    engine: &Arc<Engine>,
    node_key_id: &str,
    key: &str,
) -> Result<Option<ConfigEntry>> {
    let rows = live_config_rows(engine, node_key_id).await?;
    Ok(latest_for_key(&rows, key)
        // A Null-valued latest is a tombstone (deleted) — reads as absent.
        .filter(|r| !matches!(r.entry.value, ConfigValue::Null))
        .map(|r| r.entry.clone()))
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
            // Skip a tombstoned key (latest value is Null = deleted).
            if matches!(latest.entry.value, ConfigValue::Null) {
                continue;
            }
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

    // ── Emit (CIRISPersist#253 collapse) ─────────────────────────────────────
    // node-self emit over the engine's OWN composed signer: the hand-rolled
    // canonicalize→hash→hybrid-sign→assemble→put recipe is now
    // `Engine::emit_attestation_self`. Attester/scrub = the node's #247 DERIVED
    // federation key_id (`local_derived_key_id()` == `node_key_id` here —
    // wire-preserving). The config key lives in the envelope; the subject is the
    // node itself; `weight = Some(1.0)` matches the prior row.
    let mut input = EmitAttestationInput::with_envelope(attestation_type::SCORES, envelope);
    input.attested_key_id = Some(node_key_id.to_owned());
    input.subject_key_ids = vec![node_key_id.to_owned()];
    input.weight = Some(1.0);
    let attestation_id = engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| anyhow::anyhow!("emit_attestation_self(config:v1): {e}"))?;

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

/// Delete a config `key` by writing a tombstone — a new version carrying
/// [`ConfigValue::Null`]. The latest-wins fold makes the key read as absent
/// thereafter ([`get_config`]/[`list_configs`] skip a Null latest). Append-only and
/// signed like any other write (no destructive row removal); the tombstone preserves
/// the key's current [`ConfigScope`] (or the default when the key was absent).
/// Mirrors CIRISAgent's "set to None as deletion" — this Rust impl is the common one.
pub async fn delete_config(
    engine: &Arc<Engine>,
    node_key_id: &str,
    key: &str,
    updated_by: &str,
) -> Result<ConfigEntry> {
    let scope = get_config(engine, node_key_id, key)
        .await?
        .map(|e| e.scope)
        .unwrap_or_default();
    set_config(
        engine,
        node_key_id,
        key,
        ConfigValue::Null,
        updated_by,
        scope,
    )
    .await
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

/// Typed convenience: the latest list value for `key` as `Vec<String>` (iff it is
/// a [`ConfigValue::List`]). Used by the boot reads for list-valued config:* keys
/// (`net.bootstrap_peers`, `auth.admin_key_ids`).
pub async fn get_str_list(
    engine: &Arc<Engine>,
    node_key_id: &str,
    key: &str,
) -> Result<Option<Vec<String>>> {
    Ok(get_config(engine, node_key_id, key)
        .await?
        .and_then(|e| e.value.as_str_list()))
}
