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
//! [`crate::auth::ownership::is_steward_bound`]'s `delegation_revoked` uses. There
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

use anyhow::Result;
use serde::{Deserialize, Serialize};

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::EmitAttestationInput;
use ciris_persist::prelude::{CallerScope, Engine};

/// The open-vocab config dimension every config row rides on. **Versioned**
/// (`:v1`) to satisfy persist's `DimensionAdmissionPolicy { require_version_segment:
/// true }`, exactly like [`crate::peer::CONSENT_DIMENSION`]. `config:` is NOT a
/// reserved prefix, so a node-keyed self-attestation on it is admitted without a
/// reserved-prefix role.
pub const CONFIG_DIMENSION: &str = "config:v1";

/// The `cohort_scope` EVERY config row is authored at (CIRISServer#324). `self` —
/// a config row is a self-report about THIS node's own runtime, so it is normatively
/// `cohort_scope::self` (CC 4.4.3.4.3; `FSD/namespace_supersets.json` `config:*`
/// invariant): one of the two scopes persist's `cohort_scope::suppresses_holds_bytes`
/// protects (`SELF | FAMILY`), making the row structurally invisible — no
/// `holds_bytes:sha256:*` directory attestation, not cohort-replicable. `federation`
/// (the pre-#324 assigned-but-wrong value) is the ONE scope that protection does NOT
/// cover, which had left every node-local config key (`auth.admin_key_ids`,
/// `net.bootstrap_peers`, `federation.peer_sideband.<peer>`, …) directory-advertised
/// and replicable.
///
/// BOTH producer sites route through this ONE const so they cannot drift:
/// [`config_envelope`]'s inline envelope JSON AND — load-bearingly —
/// [`set_config`]'s typed `EmitAttestationInput::cohort_scope` (the field persist's
/// admission, `suppresses_holds_bytes`, the DEK cascade, and the directory projection
/// actually read; the envelope JSON alone lands in `EnvelopeCore::extra` and is never
/// lifted onto the row, T3's #324 finding). Single source of truth so the §5
/// conformance check ([`crate::field_conformance::check_config_cohort_scope_self`])
/// asserts on the value this repo actually emits — repointing it at `federation`
/// reds that check, exactly the regression it exists to catch.
pub const CONFIG_COHORT_SCOPE: &str = cohort_scope::SELF;

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
        (paths::DIMENSION): CONFIG_DIMENSION,
        "attesting_key_id": node_key_id,
        "score": 1.0,
        // Config-class content is normatively self-scoped — see [`CONFIG_COHORT_SCOPE`]
        // for why (structural invisibility, CC 4.4.3.4.3) and why BOTH this envelope
        // field and `set_config`'s typed input route through the ONE const rather
        // than repeating the literal.
        "cohort_scope": CONFIG_COHORT_SCOPE,
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
/// The config plane's identity — resolved from the ONE authority (the engine's
/// own signer), never caller-supplied. `set_config` emits via
/// `Engine::emit_attestation_self`, which stamps the attester as the signer's
/// DERIVED federation key_id; a caller-passed "node_key_id" on the READ side is
/// therefore an invitation to the CIRISServer#312 disease — and in the embedded
/// fold it accepted: callers passed the config ALIAS, every read filtered by an
/// identity that authored nothing, and `GET /v1/config` returned `{}` over a
/// corpus full of 200-OK signed writes (CIRISServer#315 finding 2). The write
/// and the read now derive the SAME identity from the SAME source, so the fork
/// is structurally unwritable.
pub async fn self_key_id(engine: &Arc<Engine>) -> Result<String> {
    engine
        .local_derived_key_id()
        .await
        .map_err(|e| anyhow::anyhow!("resolve config-plane identity: {e}"))
}

/// Page size for the filtered config read. `config:*` is a small,
/// node-local plane (a dozen keys on a real node); this is a bound, not a
/// working set.
const CONFIG_READ_LIMIT: i64 = 512;

/// Every live `config:*` row this node authored.
///
/// # Why the filter is in the QUERY (CIRISServer#343)
///
/// This used to be `list_attestations_by(self)` — every attestation the node
/// had ever authored — followed by two `continue`s in Rust. Measured on the
/// production status node 2026-08-02: **9,824** self-authored rows, of which
/// **12** were config; the other 9,811 were `health:liveness:v1`. Each row was
/// loaded and its envelope JSON-parsed to be discarded.
///
/// Worse than a bad constant factor: `Config::resolve` calls a `get_*` fifteen
/// times, each one a full scan — 147,360 row loads to read twelve values — and
/// `refresh_config` runs it every poll cycle, not once at boot. The node spent
/// roughly half its wall clock re-reading its own liveness history. Boot phase
/// `config_resolution` took **152 seconds**.
///
/// It was never a regression; it was linear in a corpus that grows 288 rows a
/// day forever, so it degraded daily and worst on the longest-lived nodes.
///
/// `AttestationFilter` already carried every predicate this needs. The fix is
/// to stop doing the substrate's job in application code.
async fn live_config_rows(engine: &Arc<Engine>) -> Result<Vec<StoredRow>> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    let node_key_id = self_key_id(engine).await?;
    let node_key_id = node_key_id.as_str();

    // `AttestationFilter` is #[non_exhaustive] — persist owns its shape and may
    // add predicates. Build-then-set so a new field arrives as a default we did
    // not have to notice, rather than as a compile break on every consumer.
    let mut filter = AttestationFilter::default();
    filter.attesting_key_id = Some(node_key_id.to_owned());
    filter.attestation_type = Some(attestation_type::SCORES.to_owned());
    // Derived from CONFIG_DIMENSION, never written twice. A prefix literal
    // beside the dimension is the hand-mirrored-vocabulary shape
    // tests/envelope_vocabulary_single_source.rs exists to stop.
    filter.dimension_prefixes = vec![CONFIG_DIMENSION
        .split_once(':')
        .map(|(fam, _)| format!("{fam}:"))
        .unwrap_or_else(|| CONFIG_DIMENSION.to_owned())];

    // ── The scope gate is REAL and this read must pass it honestly ──────────
    //
    // `list_attestations` is scope-gated on the row's `cohort_scope`;
    // `list_attestations_by` (what this used to call) is not. `config:*` rows
    // are stamped `cohort_scope=SELF` (SRV-4/#324) — a node's configuration is
    // not federation-visible — and `CallerScope::Unauthenticated` admits only
    // `{affiliations, species, biosphere, federation}`.
    //
    // The first version of this change passed `Unauthenticated` and therefore
    // returned ZERO config rows against a corpus full of them. Nine tests caught
    // it. Same defect class as everything else in this arc — a narrowing that
    // reads as a healthy empty result — and far worse than the 152s it fixed.
    //
    // The honest scope is the node authenticated AS ITSELF: `self` is admitted
    // when `target == admission.identity_key_id`, and a config row's
    // `attested_key_id` IS this node. `build_caller_admission` is the only
    // public path to an admission (AV-44 forge resistance: no public
    // constructor), so this cannot fabricate authority it does not hold.
    let admission = ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned())
        .await
        .map_err(|e| anyhow::anyhow!("resolve config-plane caller admission: {e}"))?;
    let page = engine
        .list_attestations(
            filter,
            None,
            CONFIG_READ_LIMIT,
            CallerScope::Authenticated { admission },
        )
        .await
        .map_err(|e| anyhow::anyhow!("list config attestations for {node_key_id}: {e}"))?;

    let mut out = Vec::new();
    for a in page.items {
        // `dimension_prefixes` matches a PREFIX; this plane wants the exact
        // dimension, so the equality check stays. It now runs over the dozen
        // rows the query returned rather than every row the node ever wrote.
        if a.attestation_envelope
            .get(paths::DIMENSION)
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
pub async fn get_config(engine: &Arc<Engine>, key: &str) -> Result<Option<ConfigEntry>> {
    let rows = live_config_rows(engine).await?;
    Ok(latest_for_key(&rows, key)
        // A Null-valued latest is a tombstone (deleted) — reads as absent.
        .filter(|r| !matches!(r.entry.value, ConfigValue::Null))
        .map(|r| r.entry.clone()))
}

/// List the latest [`ConfigEntry`] per key (latest-wins fold), optionally filtered
/// to keys starting with `prefix`. Returns a sorted [`BTreeMap`] keyed by config key.
pub async fn list_configs(
    engine: &Arc<Engine>,
    prefix: Option<&str>,
) -> Result<BTreeMap<String, ConfigEntry>> {
    let rows = live_config_rows(engine).await?;

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
    key: &str,
    value: ConfigValue,
    updated_by: &str,
    scope: ConfigScope,
) -> Result<ConfigEntry> {
    // Current latest (for version + previous_version chaining).
    let rows = live_config_rows(engine).await?;
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
    let node_key_id = self_key_id(engine).await?;
    let envelope = config_envelope(&node_key_id, &entry, &now.to_rfc3339());

    // ── Emit (CIRISPersist#253 collapse) ─────────────────────────────────────
    // node-self emit over the engine's OWN composed signer: the hand-rolled
    // canonicalize→hash→hybrid-sign→assemble→put recipe is now
    // `Engine::emit_attestation_self`. Attester/scrub = the node's #247 DERIVED
    // federation key_id (`local_derived_key_id()` == `node_key_id` here —
    // wire-preserving). The config key lives in the envelope; the subject is the
    // node itself; `weight = Some(1.0)` matches the prior row.
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)?,
        // #324: node-local config is structurally invisible — SELF, never the
        // old fail-open federation default. persist v21.11.0 (#527) made this a
        // required argument precisely so it cannot be forgotten again.
        CONFIG_COHORT_SCOPE,
    );
    input.attested_key_id = Some(node_key_id.clone());
    input.subject_key_ids = vec![node_key_id.to_owned()];
    input.weight = Some(1.0);
    // THE load-bearing scope fix (CIRISServer#324). The STORED, typed
    // `Attestation.cohort_scope` — the value persist's admission,
    // `cohort_scope::suppresses_holds_bytes`, the DEK cascade, and the directory
    // projection actually read — is `EmitAttestationInput::cohort_scope`, NOT the
    // envelope's inline `cohort_scope` JSON (which lands in `EnvelopeCore::extra`
    // and is never lifted onto the row). `with_envelope` hardcodes this field to
    // `federation`; left unset, `emit_attestation_assemble` stamps every config
    // row `federation` — the ONE scope `suppresses_holds_bytes` (`SELF | FAMILY`)
    // does NOT protect, so config was directory-advertised + cohort-replicable.
    // Setting it to `self` (config is a self-report about THIS node's own runtime,
    // CC 4.4.3.4.3) makes the row structurally invisible. UNIFORM across every
    // config key; `check_write_cohort_scope` always permits SELF for the writer.
    // This is the load-bearing half of the [`CONFIG_COHORT_SCOPE`] pair — the same
    // const the envelope JSON above uses, so the two provenance points cannot drift.
    input.cohort_scope = CONFIG_COHORT_SCOPE.to_string();
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
    key: &str,
    updated_by: &str,
) -> Result<ConfigEntry> {
    let scope = get_config(engine, key)
        .await?
        .map(|e| e.scope)
        .unwrap_or_default();
    set_config(engine, key, ConfigValue::Null, updated_by, scope).await
}

/// Typed convenience: the latest string value for `key` (iff it is a [`ConfigValue::Str`]).
pub async fn get_str(engine: &Arc<Engine>, key: &str) -> Result<Option<String>> {
    Ok(get_config(engine, key)
        .await?
        .and_then(|e| e.value.as_str().map(str::to_owned)))
}

/// Typed convenience: the latest integer value for `key` (iff it is a [`ConfigValue::I64`]).
pub async fn get_i64(engine: &Arc<Engine>, key: &str) -> Result<Option<i64>> {
    Ok(get_config(engine, key)
        .await?
        .and_then(|e| e.value.as_i64()))
}

/// Typed convenience: the latest float value for `key` (iff it is a [`ConfigValue::F64`]
/// or an [`ConfigValue::I64`] widened).
pub async fn get_f64(engine: &Arc<Engine>, key: &str) -> Result<Option<f64>> {
    Ok(get_config(engine, key)
        .await?
        .and_then(|e| e.value.as_f64()))
}

/// Typed convenience: the latest boolean value for `key` (iff it is a [`ConfigValue::Bool`]).
pub async fn get_bool(engine: &Arc<Engine>, key: &str) -> Result<Option<bool>> {
    Ok(get_config(engine, key)
        .await?
        .and_then(|e| e.value.as_bool()))
}

/// Typed convenience: the latest list value for `key` as `Vec<String>` (iff it is
/// a [`ConfigValue::List`]). Used by the boot reads for list-valued config:* keys
/// (`net.bootstrap_peers`, `auth.admin_key_ids`).
pub async fn get_str_list(engine: &Arc<Engine>, key: &str) -> Result<Option<Vec<String>>> {
    Ok(get_config(engine, key)
        .await?
        .and_then(|e| e.value.as_str_list()))
}

#[cfg(test)]
mod scope_gate_tests {
    /// **A filtered read must not silently narrow itself out of existence.**
    ///
    /// `list_attestations` is scope-gated on the row's `cohort_scope`;
    /// `list_attestations_by` is not. Swapping one for the other to push a
    /// filter into the query — the right move for #343 — silently changed the
    /// authority model too, and `CallerScope::Unauthenticated` admits only
    /// `{affiliations, species, biosphere, federation}`.
    ///
    /// `config:*` is `cohort_scope=SELF`. So the first version of that change
    /// returned ZERO rows against a corpus full of them, and every config value
    /// read as absent. Nine tests failed — the system working — but the failure
    /// mode is a healthy-looking empty result, and this pins the CAUSE rather
    /// than leaving the next person to rediscover it from nine unrelated
    /// assertions.
    #[test]
    fn the_config_read_is_scoped_as_the_node_itself_not_unauthenticated() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/graph_config.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        let body = code
            .split_once("fn live_config_rows")
            .expect("live_config_rows must exist")
            .1;
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        // Strip comments: the function's own comment DOCUMENTS the
        // Unauthenticated bug by name, and a gate that matches its own
        // explanation is measuring prose, not code — the exact instrument
        // failure the RCA catalogues. Only executable text counts.
        let body: String = body
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            body.contains("build_caller_admission"),
            "the config read must resolve a REAL admission. `self`-scoped rows are admitted only \
             when target == admission.identity_key_id, and build_caller_admission is the only \
             public path to one (AV-44: no public constructor) — which is also what stops this \
             read fabricating authority it does not hold."
        );
        assert!(
            !body.contains("CallerScope::Unauthenticated"),
            "Unauthenticated admits only {{affiliations, species, biosphere, federation}}. \
             config:* is cohort_scope=SELF, so this read would return nothing, every config \
             value would resolve as absent, and the node would silently run on defaults over a \
             corpus of signed writes."
        );
        assert!(
            body.contains("list_attestations(") && !body.contains("list_attestations_by"),
            "the filter must stay IN THE QUERY (#343): list_attestations_by(self) loads every \
             attestation the node ever authored — 9,824 rows scanned fifteen times per resolve \
             to read twelve values, a 152s boot phase, repeated every poll cycle."
        );
    }
}
