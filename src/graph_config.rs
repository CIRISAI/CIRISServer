//! **Config-as-CEG** (Server 0.5 Phase 1) — a signed, owner-gated config store
//! over the CEG, mirroring CIRISAgent's `GraphConfigService` but with the
//! substrate's hybrid-signature + owner-binding discipline.
//!
//! ## The model (mirrors [`crate::peer`] exactly, different dimension)
//!
//! A config entry is a **self-attested attestation** authored by THIS node
//! (`attesting_key_id == node_key_id`), carried on the key's OWN leaf of the
//! `config:` family — [`config_dimension`]`(key)` = `config:{key}:v1`. The config
//! KEY lives **in the envelope** (`envelope["key"]`) as well, NOT as a federation
//! `subject_key_id` — a config row is about the node's own runtime, not directed
//! at a peer. The full
//! [`ConfigEntry`] (`{key, value, version, updated_by, scope, previous_version}`)
//! rides in the envelope as JSON so it round-trips byte-for-byte.
//!
//! Writes reuse the EXACT signing path [`crate::peer::emit_replication_consent`]
//! uses: `ceg_produce_canonicalize` → `SHA-256` → `engine.sign_hybrid` →
//! `put_attestation`. Reads mirror
//! [`crate::peer::replication_peers_from_consent`]:
//! ONE scan of `list_attestations(attesting = node, dimension_prefixes =
//! ["config:"])`, folded per key into a process snapshot ([`ConfigSnapshot`]).
//!
//! ## Versioning (latest-wins) and renewal (persist v42, CC 3.4.5.1)
//!
//! A `set_config` never mutates a prior row — it appends a NEW row with
//! `version = prev + 1` and `previous_version = <prior row id>`. A read folds all
//! rows for a key and returns the **highest `version`** (latest-wins, ties broken
//! by `asserted_at`).
//!
//! Since persist v42.0.0 (CIRISPersist#814 part 3) the substrate admits ONE live
//! row per `(subject, cohort_scope, leaf)` in the `config:` family, where the
//! leaf is the envelope dimension string: a second plain row is refused, and a
//! renewal must be a `supersedes` whose `references_attestation_id` names the
//! row it replaces on the SAME leaf. So the plane is shaped for it:
//!
//!   * **the leaf is the key** — `config:{key}:v1`, one leaf per key, so two
//!     keys are never two live rows on one leaf;
//!   * **the first write of a key is a `scores` row**, every later write of that
//!     key is a **`supersedes`** naming the newest row on the key's leaf (the
//!     chain head — revoked or not, because the substrate's check does not fold
//!     a recant out of the live set), and the fold reads both types;
//!   * **rows written before 0.5.201** all sit on the single legacy leaf
//!     [`LEGACY_CONFIG_DIMENSION`] (`config:v1`). They still read (same prefix,
//!     same envelope shape). A renewal cannot cross leaves, so the first write of
//!     such a key after the move OPENS the key's own leaf with a `scores` row at
//!     `version = legacy + 1`; the legacy row is shadowed by version, not retired.
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

/// The `config:` family prefix every config row rides under (persist's
/// `CONFIG_DIMENSION_PREFIX`; catalogued as `config:{scope}` with the second
/// segment classed `vocab`). The read scans this prefix on the indexed
/// `dimension` column; the write puts each key on its own leaf below it.
pub const CONFIG_DIMENSION_PREFIX: &str = "config:";

/// The ONE leaf every config row rode on before 0.5.201 (`config:v1`). Read for
/// compatibility — a node's corpus carries these rows for as long as it keeps
/// its history — never written: persist v42 admits one live row per leaf, and
/// this leaf already holds one per key ever written.
pub const LEGACY_CONFIG_DIMENSION: &str = "config:v1";

/// The leaf a config key lives on: `config:{key}:v1`. **Versioned** (`:v1`) to
/// satisfy persist's `DimensionAdmissionPolicy { require_version_segment: true }`,
/// exactly like [`crate::peer::CONSENT_DIMENSION`]; keyed per config key because
/// persist v42 (CIRISPersist#814 part 3, CC 3.4.5.1) keys the config live set by
/// the leaf, and a key is the unit this plane renews. `config:` is reserved as a
/// SELF-REPORT (attester = subject, or its owner), which every write here is.
#[must_use]
pub fn config_dimension(key: &str) -> String {
    format!("{CONFIG_DIMENSION_PREFIX}{key}:v1")
}

/// Whether an envelope dimension is a config row this plane reads: any leaf of
/// the `config:` family — a per-key leaf or the legacy single leaf.
#[must_use]
pub fn is_config_dimension(dimension: Option<&str>) -> bool {
    dimension.is_some_and(|d| d.starts_with(CONFIG_DIMENSION_PREFIX))
}

/// A config key must be able to name a leaf: one `vocab` segment of
/// `config:{key}:v1` under CC 3.1.7 R3 (lowercase ASCII letters, digits, `_`,
/// `.`, `-`; first character a letter or digit; never `:`, which would split the
/// segment). persist v42 refuses a malformed segment at the door (CIRISPersist#815,
/// "a wrong-case segment is malformed, never a sibling"), so the refusal is made
/// here first, with the reason. Every key this node writes today fits
/// (`net.radio.tx_power_dbm`, `federation.peer_sideband.<key_id>`, …).
pub fn config_key_is_a_leaf(key: &str) -> Result<()> {
    let first_ok = key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = key
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-'));
    if first_ok && rest_ok {
        return Ok(());
    }
    anyhow::bail!(
        "config key {key:?} cannot name a leaf: a key is one `vocab` segment of \
         `config:{{key}}:v1` (CC 3.1.7 R3 — lowercase ASCII letters, digits, `_`, `.`, `-`, \
         starting with a letter or digit; no `:`), because persist v42 keys the config live \
         set by the leaf (CIRISPersist#814 part 3)"
    )
}

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

/// A resolved config entry — the latest-wins fold of a key's `config:*` rows.
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

/// Build the `config:{key}:v1` envelope for an entry — the JSON that is JCS-canonicalized
/// into the signing basis. Mirrors [`crate::peer::emit_replication_consent`]'s
/// envelope shape (same envelope fields: `dimension`, `attesting_key_id`,
/// `score`, `cohort_scope`), plus the entry fields carried inline. The signed
/// instant is NOT among them — the emit stamp owns it (CIRISPersist#598).
fn config_envelope(
    node_key_id: &str,
    entry: &ConfigEntry,
    renews: Option<&str>,
) -> serde_json::Value {
    let mut env = serde_json::json!({
        (paths::DIMENSION): config_dimension(&entry.key),
        "attesting_key_id": node_key_id,
        "score": 1.0,
        // Config-class content is normatively self-scoped — see [`CONFIG_COHORT_SCOPE`]
        // for why (structural invisibility, CC 4.4.3.4.3) and why BOTH this envelope
        // field and `set_config`'s typed input route through the ONE const rather
        // than repeating the literal.
        "cohort_scope": CONFIG_COHORT_SCOPE,
        "witness_relation": "self",
        // NO `asserted_at` HERE (CIRISServer#402 / CIRISPersist#598). The stamp
        // writes it — once, truncated to the substrate's resolution — and
        // `assemble` reads the row column back out of it. A producer that sets it
        // is honoured and NOT truncated, so a hand-written `Utc::now()` lands with
        // nanoseconds postgres cannot store and the put is refused. It made every
        // write on this path fail on v31.
        // The config entry, carried inline so a read reconstructs it verbatim.
        "key": entry.key,
        "value": entry.value,
        "version": entry.version,
        "updated_by": entry.updated_by,
        "scope": entry.scope,
        "previous_version": entry.previous_version,
    });
    // A renewal is a `supersedes` and MUST name the row it replaces on this
    // leaf (persist v42, CC 3.4.5.1) — the CEG §3.2 composer pointer, read by
    // persist's `check_config_renewal_supersedes` and its precedence fold.
    if let Some(prior) = renews {
        env[paths::REFERENCES_ATTESTATION_ID] = serde_json::Value::String(prior.to_owned());
    }
    env
}

/// Parse a stored config row's envelope back into a [`ConfigEntry`].
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
#[derive(Debug, Clone)]
struct StoredRow {
    attestation_id: String,
    asserted_at: chrono::DateTime<chrono::Utc>,
    entry: ConfigEntry,
}

/// The newest row on one key's leaf (see [`ConfigSnapshot::heads`]).
#[derive(Debug, Clone)]
struct ChainHead {
    attestation_id: String,
    version: u64,
    asserted_at: chrono::DateTime<chrono::Utc>,
}

/// How long a loaded [`ConfigSnapshot`] serves reads before the next read
/// re-scans (CIRISServer#557).
///
/// Every in-process write door invalidates the snapshot explicitly
/// ([`set_config`], [`delete_config`], and `attest`'s withdraw/recant emits),
/// so this bound only governs writes this process cannot see: the
/// `ciris-server config set` CLI running against the same store, a revocation
/// landing by a door that forgot to call [`invalidate`]. Two seconds is long
/// enough that a consumer's burst of fifty reads is one scan, and short enough
/// that an external write is live before anyone notices it was not.
pub const CONFIG_SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// How many times the config plane has been SCANNED from the store. A test
/// asserts that fifty reads move it by one; an operator can read it beside
/// the per-scan log line to see whether a consumer is defeating the cache.
pub static SCANS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The config plane as of one scan: every live `config:*` row this node
/// authored, folded for revocations, with the newest version per key
/// resolvable without touching the store again.
///
/// This is the shape that makes the cost visible (CIRISServer#557): one
/// `load`, then any number of reads that are lookups. The per-key
/// [`get_config`] / [`get_i64`] family still exists for callers that read one
/// value once; they share this snapshot through the process cache, so fifty
/// of them in a row are ALSO one scan — but a consumer that resolves a struct
/// should hold a snapshot and say so.
#[derive(Debug)]
pub struct ConfigSnapshot {
    node_key_id: String,
    rows: Vec<StoredRow>,
    /// Per key, the newest row on the key's OWN leaf whether or not it is still
    /// live — the row the next renewal must supersede (persist v42, CC 3.4.5.1).
    /// A recanted head is still the head: persist's renewal check does not fold
    /// a recant out of the live set, so a plain `scores` after a recant is
    /// refused; a `supersedes` naming the dead row is admitted.
    heads: std::collections::HashMap<String, ChainHead>,
    loaded_at: std::time::Instant,
    /// Ordinal of the scan that produced this snapshot (see [`SCANS`]).
    pub scan: u64,
}

impl ConfigSnapshot {
    /// The node whose config plane this is.
    #[must_use]
    pub fn node_key_id(&self) -> &str {
        &self.node_key_id
    }

    /// Live rows held (every version of every key that has not been revoked).
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows.len()
    }

    /// The newest live entry for `key`, unless it is a tombstone.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&ConfigEntry> {
        latest_for_key(&self.rows, key)
            .filter(|r| !matches!(r.entry.value, ConfigValue::Null))
            .map(|r| &r.entry)
    }

    #[must_use]
    pub fn str(&self, key: &str) -> Option<String> {
        self.get(key)
            .and_then(|e| e.value.as_str().map(str::to_owned))
    }

    #[must_use]
    pub fn i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|e| e.value.as_i64())
    }

    #[must_use]
    pub fn f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|e| e.value.as_f64())
    }

    #[must_use]
    pub fn bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|e| e.value.as_bool())
    }

    #[must_use]
    pub fn str_list(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).and_then(|e| e.value.as_str_list())
    }

    /// Newest live entry per key, optionally under a key prefix.
    #[must_use]
    pub fn list(&self, prefix: Option<&str>) -> BTreeMap<String, ConfigEntry> {
        let mut out = BTreeMap::new();
        for r in &self.rows {
            if let Some(p) = prefix {
                if !r.entry.key.starts_with(p) {
                    continue;
                }
            }
            if out.contains_key(&r.entry.key) {
                continue;
            }
            if let Some(latest) = latest_for_key(&self.rows, &r.entry.key) {
                if matches!(latest.entry.value, ConfigValue::Null) {
                    continue;
                }
                out.insert(latest.entry.key.clone(), latest.entry.clone());
            }
        }
        out
    }

    fn fresh(&self) -> bool {
        self.loaded_at.elapsed() < CONFIG_SNAPSHOT_TTL
    }
}

/// The process-wide cache: one snapshot, replaced on scan, dropped on
/// [`invalidate`]. A `Mutex<Option<Arc<_>>>` rather than an `RwLock`: the
/// critical section is a pointer clone.
/// (engine identity, snapshot) — the one cached slot.
type CachedSnapshot = Option<(usize, Arc<ConfigSnapshot>)>;

fn cache() -> &'static std::sync::Mutex<CachedSnapshot> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<CachedSnapshot>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(None))
}

/// The identity a snapshot is valid for: the `Engine` it was scanned from. A
/// process normally holds one engine, but a test binary holds many at once
/// (one `sqlite::memory:` each), and the embedded fold may re-serve on
/// another home; a snapshot must never answer for a store it did not read.
fn engine_identity(engine: &Arc<Engine>) -> usize {
    Arc::as_ptr(engine) as usize
}

/// Drop the cached snapshot: the next read scans. Called by every in-process
/// door that changes the config plane ([`set_config`], the withdraw/recant
/// emits in `attest`), and by compose at serve start so an in-process
/// re-serve on another home never reads the previous node's config.
pub fn invalidate() {
    *cache().lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// The current config snapshot: cached if fresh, else one scan. THE read
/// door — every getter below goes through it.
pub async fn snapshot(engine: &Arc<Engine>) -> Result<Arc<ConfigSnapshot>> {
    let me = engine_identity(engine);
    if let Some((owner, snap)) = cache().lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
        if *owner == me && snap.fresh() {
            return Ok(Arc::clone(snap));
        }
    }
    let snap = Arc::new(live_config_rows(engine).await?);
    *cache().lock().unwrap_or_else(|p| p.into_inner()) = Some((me, Arc::clone(&snap)));
    Ok(snap)
}

/// Read every LIVE (unrevoked) `config:*` row this node authored, parsed into
/// [`StoredRow`]s. Mirrors [`crate::peer::replication_peers_from_consent`]'s read
/// (one prefix scan of the `config:` family, both `scores` and `supersedes`).
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
/// ONE scan of the config plane into a [`ConfigSnapshot`]. Callers go through
/// [`snapshot`], which caches the result; this is the cost the cache amortises.
async fn live_config_rows(engine: &Arc<Engine>) -> Result<ConfigSnapshot> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    let t0 = std::time::Instant::now();
    let scan = SCANS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

    let node_key_id = self_key_id(engine).await?;
    let node_key_id = node_key_id.as_str();

    // `AttestationFilter` is #[non_exhaustive] — persist owns its shape and may
    // add predicates. Build-then-set so a new field arrives as a default we did
    // not have to notice, rather than as a compile break on every consumer.
    let mut filter = AttestationFilter::default();
    filter.attesting_key_id = Some(node_key_id.to_owned());
    // The FAMILY prefix, not one exact leaf: since persist v42 every key is
    // its own leaf (`config:{key}:v1`), and the legacy single leaf `config:v1`
    // matches the same prefix, which is how a corpus written before 0.5.201
    // keeps reading. On this handle persist compiles `dimension_prefixes` to
    // `json_extract(attestation_envelope, '$.dimension') LIKE 'config:%'` —
    // still a per-row JSON parse of everything this node authored, exactly as
    // `dimension_exact` was (CIRISServer#557); the `attesting_key_id` predicate
    // is what bounds it. That is why the result is cached as a snapshot, and
    // why the indexed family seek is asked of persist (CIRISPersist#817)
    // rather than papered over here. No type filter: the first write of a key
    // is a `scores` row and every renewal is a `supersedes` (CC 3.4.5.1); both
    // carry the entry and both are folded below.
    filter.dimension_prefixes = vec![CONFIG_DIMENSION_PREFIX.to_owned()];

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
    // Every page: the plane is small (a dozen keys, a few versions each) but
    // the bound is a page size, not a promise about the corpus.
    let mut items = Vec::new();
    let mut cursor = None;
    loop {
        let page = engine
            .list_attestations(
                filter.clone(),
                cursor,
                CONFIG_READ_LIMIT,
                CallerScope::Authenticated {
                    admission: admission.clone(),
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("list config attestations for {node_key_id}: {e}"))?;
        let got = page.items.len();
        items.extend(page.items);
        match page.next_cursor {
            Some(next) if got > 0 => cursor = Some(next),
            _ => break,
        }
    }

    let revoked = revoked_config_rows(engine, node_key_id).await;
    let held = crate::key_standing::HeldRevocations::for_keys(engine, [node_key_id.to_owned()])
        .await
        .map_err(|e| anyhow::anyhow!("read revocations for the config-plane author: {e}"))?;
    let now = chrono::Utc::now();

    let mut out = Vec::new();
    let mut heads: std::collections::HashMap<String, ChainHead> = std::collections::HashMap::new();
    for a in items {
        let Some(dimension) = a
            .attestation_envelope
            .get(paths::DIMENSION)
            .and_then(|d| d.as_str())
        else {
            continue;
        };
        if !is_config_dimension(Some(dimension)) {
            continue;
        }
        if a.attestation_type != attestation_type::SCORES
            && a.attestation_type != attestation_type::SUPERSEDES
        {
            continue;
        }
        let Some(entry) = entry_from_envelope(&a.attestation_envelope) else {
            continue;
        };
        // The chain head is the newest row on the key's OWN leaf, revoked or
        // not (see `ConfigSnapshot::heads`). A legacy `config:v1` row is never
        // a head: a renewal cannot cross leaves, so the first write after the
        // move opens the key's leaf with a `scores` row instead.
        if dimension == config_dimension(&entry.key) {
            let newer = heads
                .get(&entry.key)
                .is_none_or(|h| (entry.version, a.asserted_at) > (h.version, h.asserted_at));
            if newer {
                heads.insert(
                    entry.key.clone(),
                    ChainHead {
                        attestation_id: a.attestation_id.clone(),
                        version: entry.version,
                        asserted_at: a.asserted_at,
                    },
                );
            }
        }
        if revoked.contains(a.attestation_id.as_str())
            || config_row_revoked_externally(engine, &a.attestation_id).await
        {
            continue;
        }
        {
            // Fold the author's standing (CIRISServer#355): a row asserted after
            // its author's key was revoked is not a live config value.
            let fold = held.statement_standing(&a, now);
            if fold.standing.is_suspect() {
                crate::key_standing::warn_suspect("graph_config", &a, &fold);
                continue;
            }
        }
        out.push(StoredRow {
            attestation_id: a.attestation_id,
            asserted_at: a.asserted_at,
            entry,
        });
    }
    tracing::debug!(
        scan,
        config_rows = out.len(),
        keys = heads.len(),
        elapsed_ms = t0.elapsed().as_millis() as u64,
        ttl_s = CONFIG_SNAPSHOT_TTL.as_secs(),
        "config plane scanned into a snapshot"
    );
    Ok(ConfigSnapshot {
        node_key_id: node_key_id.to_owned(),
        rows: out,
        heads,
        loaded_at: std::time::Instant::now(),
        scan,
    })
}

/// Every config row id this node has retracted, in ONE pass.
///
/// # Why hoisted (CIRISServer#343, the second half)
///
/// This logic used to live in a per-row `config_key_revoked`, each call doing
/// its own `list_attestations_by(self)`. With twelve config rows that was twelve
/// full scans of every attestation the node ever authored — on the production
/// status node, 9,824 rows each time. Pushing the config filter into the query
/// fixed the outer scan and left this one, so the pass went from fifteen scans
/// to thirteen: a real fix that measured as almost nothing.
///
/// Two filtered reads (withdraws, recants) replace all of them. Both return only
/// retraction rows, which are rare, so the cost is bounded by retractions rather
/// than by corpus size.
async fn revoked_config_rows(
    engine: &Arc<Engine>,
    node_key_id: &str,
) -> std::collections::HashSet<String> {
    use ciris_persist::ceg::list::federation::AttestationFilter;

    let mut out = std::collections::HashSet::new();
    let Ok(admission) =
        ciris_persist::scope::build_caller_admission(engine, &node_key_id.to_owned()).await
    else {
        return out;
    };
    for kind in [attestation_type::WITHDRAWS, attestation_type::RECANTS] {
        let mut filter = AttestationFilter::default();
        filter.attesting_key_id = Some(node_key_id.to_owned());
        filter.attestation_type = Some(kind.to_owned());
        let Ok(page) = engine
            .list_attestations(
                filter,
                None,
                CONFIG_READ_LIMIT,
                CallerScope::Authenticated {
                    admission: admission.clone(),
                },
            )
            .await
        else {
            continue;
        };
        for a in page.items {
            // A retraction targets the row either via attested_key_id or via its
            // subject_key_ids carrying the row id.
            out.insert(a.attested_key_id.clone());
            for s in a.subject_key_ids {
                out.insert(s);
            }
        }
    }
    out
}

/// A revocation authored by SOMEONE ELSE against this config row.
///
/// Kept per-row because `revocations_for` is a targeted lookup by the row id,
/// not a scan — the thing the hoist above was curing.
///
/// # This gate is inert, and saying so is the point (CIRISServer#355)
///
/// `revocations_for` takes a **`revoked_key_id`**. The revocation plane revokes
/// KEYS, never attestation rows — `federation_revocations` has no column naming
/// a row — so passing an `attestation_id` here can only ever match a key whose
/// id happens to equal a row id, i.e. never. This has therefore always returned
/// `false`, and it reads as a revocation check while being none: the exact
/// present-but-unread shape #355 was filed about, one plane over.
///
/// It is left in place rather than deleted because the intent behind it is
/// real — "someone else revoked this row" — and the substrate does not express
/// it yet; deleting it would erase the ask along with the defect. The check
/// that DOES bite now is the `revoked_after` fold in [`live_config_rows`],
/// which asks the question the revocation plane can actually answer: was this
/// row's author's key revoked from an instant this row falls after.
async fn config_row_revoked_externally(engine: &Arc<Engine>, attestation_id: &str) -> bool {
    matches!(
        engine.federation_directory().revocations_for(attestation_id).await,
        Ok(revs) if !revs.is_empty()
    )
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
    // Reads the process snapshot ([`snapshot`]): fifty of these in a row are
    // one scan. A consumer resolving a whole struct should hold a
    // [`ConfigSnapshot`] and read from it — same cost, stated at the call site.
    Ok(snapshot(engine).await?.get(key).cloned())
}

/// List the latest [`ConfigEntry`] per key (latest-wins fold), optionally filtered
/// to keys starting with `prefix`. Returns a sorted [`BTreeMap`] keyed by config key.
pub async fn list_configs(
    engine: &Arc<Engine>,
    prefix: Option<&str>,
) -> Result<BTreeMap<String, ConfigEntry>> {
    // Same snapshot as [`get_config`].
    Ok(snapshot(engine).await?.list(prefix))
}

/// Write a config entry: compute `version = current.version + 1` (or `1`),
/// `previous_version = prior row id`, build the `config:{key}:v1` envelope, hybrid-sign
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
    config_key_is_a_leaf(key)?;
    // A write reads the plane first (the version chain and the head to
    // supersede), and that read must not be a cached one another writer has
    // since made stale — nor may the next read be served from before this row.
    invalidate();
    let snap = snapshot(engine).await?;
    let current = latest_for_key(&snap.rows, key);
    let head = snap.heads.get(key);
    // The version advances past everything ever written for the key: the
    // newest LIVE row (which may be a legacy `config:v1` row) and the head of
    // the key's own leaf (which may be recanted, and so absent from `rows`).
    let version = current
        .map(|r| r.entry.version)
        .into_iter()
        .chain(head.map(|h| h.version))
        .max()
        .unwrap_or(0)
        + 1;
    // `previous_version` is the row this one follows: the leaf head when the
    // key's leaf is open, else the newest live row (a legacy-leaf row).
    let previous_version = head
        .map(|h| h.attestation_id.clone())
        .or_else(|| current.map(|r| r.attestation_id.clone()));
    let entry = ConfigEntry {
        key: key.to_owned(),
        value,
        version,
        updated_by: updated_by.to_owned(),
        scope,
        previous_version,
    };
    let node_key_id = self_key_id(engine).await?;
    // persist v42 (CIRISPersist#814 part 3, CC 3.4.5.1): the first row on a leaf
    // is a `scores`; every row after it is a `supersedes` naming the head. The
    // leaf is `config:{key}:v1`, so a key written only before 0.5.201 (on the
    // legacy `config:v1` leaf) has no head yet and opens its leaf with `scores`.
    let renews = head.map(|h| h.attestation_id.as_str());
    let kind = if renews.is_some() {
        attestation_type::SUPERSEDES
    } else {
        attestation_type::SCORES
    };
    let dimension = config_dimension(key);
    let envelope = config_envelope(&node_key_id, &entry, renews);
    // Attester/scrub = the node's #247 DERIVED federation key_id, stamped by
    // `Engine::emit_attestation_self` from the engine's own signer.
    let mut input = EmitAttestationInput::with_envelope(
        kind,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)?,
        CONFIG_COHORT_SCOPE,
    );
    input.attested_key_id = Some(node_key_id.clone());
    input.subject_key_ids = vec![node_key_id.to_owned()];
    input.weight = Some(1.0);
    // Typed cohort_scope — the field persist's admission actually reads (#324).
    input.cohort_scope = CONFIG_COHORT_SCOPE.to_string();
    let attestation_id = engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| anyhow::anyhow!("emit_attestation_self({dimension}, {kind}): {e}"))?;
    invalidate();
    tracing::info!(
        key,
        version,
        updated_by,
        dimension = %dimension,
        kind,
        renews = renews.unwrap_or("-"),
        attestation_id = %attestation_id,
        "wrote config entry (signed, owner-gated at the API layer)"
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
        .expect("readable")
        // A Windows checkout carries CRLF and the body is cut at "\n}\n".
        .replace("\r\n", "\n");
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
