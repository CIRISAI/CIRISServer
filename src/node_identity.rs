//! **The node's own name for itself** (CIRISServer#410) — so a held port can be
//! ASKED who holds it.
//!
//! The incident: an embedded-fold restart found the read-API port already
//! answering, and the operator could not tell "my own node's previous process"
//! from "a foreign CIRIS node" from "a non-CIRIS squatter" — every case
//! surfaced as the same opaque `start read API: Address already in use`.
//! So every health route now serves a `node` block naming the answering
//! process, and [`port_holder_verdict`] is the pure classifier a launcher (or
//! this crate's own bind-failure path in `compose`) applies to a probe of the
//! contested port.
//!
//! The instance identity is minted **lazily on first read**, never at bind
//! time: the client polls `/health` DURING boot, and the id must exist even
//! when compose later fails — that failure IS the incident this diagnoses.
//!
//! `"unresolved"` is a NAMED state, never a missing key: "I can't name myself
//! yet" is a distinct fact from "I have no identity" — the same distinct-zeroes
//! discipline as [`crate::self_identity`].
//!
//! The full home PATH never rides the wire: the read API binds `0.0.0.0` and
//! the path carries the OS username. The wire gets only `home_id`, a
//! domain-separated fingerprint; the path itself is reserved for the
//! in-process [`local_json`] accessor (`ciris_server.node_identity()`), the
//! same channel discipline as [`crate::compose_status`].

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, SecondsFormat, Utc};

/// The stamped half of the self-name — known only once compose has derived the
/// node's ONE key_id from the engine signer.
struct Resolved {
    key_id: String,
    /// The absolute home path — IN-PROCESS ONLY (see the module doc).
    home: PathBuf,
    /// `hex(sha256("ciris-node-home\0" + absolute home))[..16]` — stable
    /// across restarts of the same home, and never a slice of the path.
    home_id: String,
}

/// Per-process identity: (uuid v4, mint time). Minted lazily on FIRST READ so
/// it exists for the health poll that races a failing compose.
static INSTANCE: OnceLock<(String, DateTime<Utc>)> = OnceLock::new();
static RESOLVED: Mutex<Option<Resolved>> = Mutex::new(None);

fn instance() -> &'static (String, DateTime<Utc>) {
    INSTANCE.get_or_init(|| (uuid::Uuid::new_v4().to_string(), Utc::now()))
}

/// This process's instance id — minted on first read, stable until exit. Also
/// stamped on the boot INFO line so a subprocess launcher that owns our stdout
/// can scrape it and later match it against a port probe.
pub fn instance_id() -> &'static str {
    &instance().0
}

/// When this process minted its instance id, RFC3339.
pub fn started_at_rfc3339() -> String {
    instance().1.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Stamp the resolved identity — called by `compose` the moment the one
/// derived key_id exists. Overwrites on a re-serve: the block describes the
/// CURRENT serve, like `compose_status` describes the current boot.
pub fn stamp(key_id: &str, home: &Path) {
    // Touch the instance FIRST so `started_at` can never postdate the stamp.
    let _ = instance();
    let abs = std::path::absolute(home).unwrap_or_else(|_| home.to_path_buf());
    let home_id = home_fingerprint(&abs);
    *RESOLVED.lock().unwrap_or_else(|p| p.into_inner()) = Some(Resolved {
        key_id: key_id.to_string(),
        home: abs,
        home_id,
    });
}

/// The wire-safe home fingerprint: a domain-separated hash, NEVER the path or
/// any substring of it (gate: `tests/health_names_the_node.rs`, the privacy
/// assertion).
fn home_fingerprint(abs: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ciris-node-home\0");
    h.update(abs.to_string_lossy().as_bytes());
    hex::encode(h.finalize())[..16].to_string()
}

/// The wire shape, rendered from one place so [`wire_json`] and [`local_json`]
/// cannot disagree on a shared field (the axis-fusion guard: two readers of
/// one fact must be one renderer).
fn render(resolved: Option<&Resolved>) -> serde_json::Value {
    let (id, started) = instance();
    let started = started.to_rfc3339_opts(SecondsFormat::Millis, true);
    match resolved {
        Some(r) => serde_json::json!({
            "standing": "identified",
            "instance_id": id,
            "started_at": started,
            "key_id": r.key_id,
            "home_id": r.home_id,
        }),
        // "unresolved" with EXPLICIT nulls — a probe must be able to tell "the
        // node cannot name itself yet" from "this listener never answers the
        // question" (a pre-#410 node, or not a CIRIS node at all).
        None => serde_json::json!({
            "standing": "unresolved",
            "instance_id": id,
            "started_at": started,
            "key_id": serde_json::Value::Null,
            "home_id": serde_json::Value::Null,
        }),
    }
}

/// The public `node` block every health route serves (`/health`, `/v1/health`,
/// `/v1/system/health`). Wire-safe: carries `home_id`, never the home path.
pub fn wire_json() -> serde_json::Value {
    let g = RESOLVED.lock().unwrap_or_else(|p| p.into_inner());
    render(g.as_ref())
}

/// The in-process superset for the embedding host
/// (`ciris_server.node_identity()`), NEVER served over HTTP: the wire block
/// plus `pid`, the FULL `home` path and the bound read-API address. The
/// superset is built ON TOP of [`render`], so the shared fields are the wire
/// fields by construction.
pub fn local_json() -> String {
    let g = RESOLVED.lock().unwrap_or_else(|p| p.into_inner());
    let mut v = render(g.as_ref());
    v["pid"] = std::process::id().into();
    v["home"] = match g.as_ref() {
        Some(r) => r.home.display().to_string().into(),
        None => serde_json::Value::Null,
    };
    v["bound_addr"] = match crate::node_control::bound_addr() {
        Some(a) => a.to_string().into(),
        None => serde_json::Value::Null,
    };
    v.to_string()
}

/// Our stamped key_id, if any — the `our_key_id` input the compose-side
/// bind-failure path feeds [`port_holder_verdict`].
pub(crate) fn resolved_key_id() -> Option<String> {
    RESOLVED
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(|r| r.key_id.clone())
}

/// Who holds the port, relative to the asking process — the four-way verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortHolderVerdict {
    /// The probed listener IS this process (same `instance_id`).
    Match,
    /// A DIFFERENT process serving the SAME node identity — the classic stale
    /// prior serve still holding the port across a restart. Remedy:
    /// `shutdown_node()` / stop the old process and retry.
    MismatchSameKey,
    /// A different process serving a DIFFERENT node identity — someone else's
    /// CIRIS node owns the port.
    MismatchForeign,
    /// The holder could not be named: nothing answered, the answer carried no
    /// `node` block, or either side cannot name its key. NEVER collapsed into
    /// [`PortHolderVerdict::Match`] — "cannot answer" is a distinct fact from
    /// any answer, and guessing here is how an operator kills the wrong node.
    Unverifiable,
}

impl PortHolderVerdict {
    /// The wire/log spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            PortHolderVerdict::Match => "match",
            PortHolderVerdict::MismatchSameKey => "mismatch_same_key",
            PortHolderVerdict::MismatchForeign => "mismatch_foreign",
            PortHolderVerdict::Unverifiable => "unverifiable",
        }
    }
}

/// Classify a probed health body against OUR identity. PURE — both sides are
/// explicit inputs, so client code (the desktop launcher) can mirror the truth
/// table verbatim and the table is testable without a process-global state
/// dance.
///
/// `probed_health` is the parsed body of `GET /health` on the contested port;
/// the `node` block is read at top level or under `data` (the `/v1/*` shapes),
/// the same envelope tolerance `folded_health` extends a brain. `None` means
/// the probe got no parseable answer at all.
pub fn port_holder_verdict(
    our_instance_id: &str,
    our_key_id: Option<&str>,
    probed_health: Option<&serde_json::Value>,
) -> PortHolderVerdict {
    let node = probed_health.and_then(|b| {
        b.get("node")
            .or_else(|| b.get("data").and_then(|d| d.get("node")))
    });
    // A missing `node` block is `unverifiable`, never `match`: the listener
    // did not answer the question, which is not the same as answering "you".
    let Some(node) = node else {
        return PortHolderVerdict::Unverifiable;
    };
    let Some(their_instance) = node.get("instance_id").and_then(|v| v.as_str()) else {
        return PortHolderVerdict::Unverifiable;
    };
    if their_instance == our_instance_id {
        return PortHolderVerdict::Match;
    }
    match (our_key_id, node.get("key_id").and_then(|v| v.as_str())) {
        (Some(ours), Some(theirs)) if ours == theirs => PortHolderVerdict::MismatchSameKey,
        (Some(_), Some(_)) => PortHolderVerdict::MismatchForeign,
        // Either side is unresolved: the mismatch is known but the
        // same-key/foreign split is NOT, and inventing it would be exactly the
        // collapse this enum exists to refuse.
        _ => PortHolderVerdict::Unverifiable,
    }
}
