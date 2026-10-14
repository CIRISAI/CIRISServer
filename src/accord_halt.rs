//! **HUMANITY_ACCORD constitutional halt — the latch** (CC 4.2.1.1 as amended by
//! CIRISConstitution#146, rc7; `FSD/CONSTITUTIONAL_HALT.md`).
//!
//! A verified `constitutional` row — **one** seated holder's hybrid signature,
//! the threshold verify's `InvocationKind::required_signatures` names — is an
//! **agent pause with zero data disruption**. When a node honors one it:
//!
//!   1. replicates the row to **all known peers FIRST** (the kill propagates
//!      mesh-wide; see [`crate::accord`]);
//!   2. writes this **latch** to disk ([`latch_halt`]) with the instant IT
//!      received the row; and
//!   3. **keeps running.** Replication, storage, serving, messaging, files and
//!      every consent rule continue; the latch is read by exactly one thing,
//!      the agent's act gate (CC 1.13.6), through `GET /v1/accord/halt-status`.
//!
//! **The fuse.** One holder can stop every agent instantly, because a missed
//! halt is the one unrecoverable failure; one holder MUST NOT keep them stopped
//! alone. A latch **lapses `fuse_secs` after `received_at`** — counted on this
//! node's clock from receipt, never from the signer's `asserted_at` — unless a
//! strict majority of the standing roster **confirms** it
//! (`accord:lifecycle:confirmed`, `confirms_halt_id`) within the fuse. A
//! confirmed halt stands until a majority `accord:lifecycle:active` names it
//! (`resumes_halt_id`). `fuse_secs` is the charter member `halt_fuse_secs`;
//! absent means [`HALT_FUSE_SECS_DEFAULT`] (24 h).
//!
//! **In effect is computed on every read** ([`HaltRecord::standing_at`]), never
//! stored: a lapsed latch stays on disk as history and reads `halted: false`.
//!
//! ## What changed from the 0.5.1xx–0.5.224 model
//!
//! That model terminated the process (`exit 42`) and `check_halt_gate` refused
//! every later boot until a roster majority released it. Under the fire-at-one
//! threshold that would let a single holder take the mesh down for good, which
//! is exactly what rc7's fuse forbids; so the exit and the boot gate are gone
//! together with the 2-of-3 fire. [`load_halt_latch`] replaces the gate: it
//! reads the latch at boot, consumes a presented offline release token
//! ([`crate::accord_release`]) and journals it, and **never refuses to start**.
//!
//! ## Ways to end a halt, all accord-authorized
//!
//! 1. A majority `accord:lifecycle:active` delivered to `/v1/accord/message`
//!    (the node is up now, so the wire path reaches it).
//! 2. **[`crate::accord_release`]** — the offline-verifiable release token
//!    (file drop / USB / QR / paste), still consumed at boot and by the CLI.
//! 3. **[`crate::accord_reactivate`]** — a proof verified against the live
//!    family read from persist.
//!
//! Manually deleting the latch remains a non-conformant operator override.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The halt-latch filename, written under the node `home`.
pub const HALT_LATCH_FILE: &str = "HUMANITY_ACCORD_HALT";

/// CC 4.2.1.1: the fuse a charter that names no `halt_fuse_secs` runs on — 24 h.
/// The final genesis charter (minted 2026-10-04, before the ruling) omits it.
pub const HALT_FUSE_SECS_DEFAULT: u64 = 86_400;

/// The strict-majority confirmation that keeps a one-holder halt past its fuse
/// (`accord:lifecycle:confirmed`, CC 4.2.1.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaltConfirmation {
    /// The confirmation row's `invocation_id`.
    pub invocation_id: String,
    /// The roster members whose cosignatures verified (a strict majority).
    pub signers: Vec<String>,
    /// When THIS node received the confirmation (its own clock).
    pub received_at: String,
}

/// What is recorded in the latch: the invocation that paused the agents
/// (re-verifiable against the cold-start roster), the fuse, any confirmation,
/// and — since CIRISServer#347 — what would lift it.
///
/// Every field added after the first latch shape is `Option` with
/// `serde(default)`, so a latch written by an older build still parses. A
/// pre-rc7 latch (no `received_at`) takes `latched_at` as its receipt and the
/// default fuse, so an upgrade never resurrects a stale halt past 24 h.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaltRecord {
    pub invocation_kind: String,
    pub invocation_id: String,
    /// The registered holder `key_id`s whose signatures verified.
    pub valid_signers: Vec<String>,
    /// verify's `required_signatures` for the kind (1 for `constitutional`).
    pub quorum_threshold: usize,
    /// RFC-3339 instant the latch was written.
    pub latched_at: String,
    /// RFC-3339 instant THIS node received the halt — the fuse clock starts
    /// here (CC 4.2.1.1: "counted from receipt on the node's own clock").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<String>,
    /// The fuse, in seconds, this latch runs on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuse_secs: Option<u64>,
    /// The majority confirmation, once one names this halt within the fuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<HaltConfirmation>,
    /// The federation `key_id` of the node this latch is on (binds a release
    /// token to one node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// `payload_sha256` of the halt invocation that fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_payload_sha256: Option<String>,
    /// A fresh CSPRNG id minted per latch write (makes a token unstockpilable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latch_id: Option<String>,
    /// **Documentation, not authority** — the digest a conformant release token
    /// carries; [`crate::accord_release::verify_release_token`] recomputes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_payload_sha256: Option<String>,
    /// The same, expanded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_binding: Option<serde_json::Value>,
}

/// Whether a latch is in effect at an instant — the ONE predicate the status
/// surface, the boot log and the confirmation door share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "standing", rename_all = "snake_case")]
pub enum HaltStanding {
    /// The agents are paused. `lapses_at` is `None` once confirmed.
    InEffect { lapses_at: Option<String> },
    /// The fuse passed with no confirmation; the latch is history.
    Lapsed { lapsed_at: String },
}

impl HaltRecord {
    /// Build the record the halt path latches, minting the per-latch `latch_id`
    /// and stamping the release binding. `latched_at` doubles as `received_at`
    /// (the caller writes the latch in the same step it receives the row);
    /// [`Self::with_fuse`] sets the fuse.
    #[must_use]
    pub fn new(
        invocation_kind: String,
        invocation_id: String,
        valid_signers: Vec<String>,
        quorum_threshold: usize,
        latched_at: String,
        node_id: Option<String>,
        halt_payload_sha256: Option<String>,
    ) -> Self {
        let latch_id = {
            let mut b = [0u8; 32];
            match ciris_crypto::random::fill(&mut b) {
                Ok(()) => Some(hex::encode(b)),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "CSPRNG unavailable while latching the halt — the latch carries NO \
                         release binding, so the offline release token is unavailable on this \
                         node (fail-secure). `accord reactivate` still applies."
                    );
                    None
                }
            }
        };
        let mut rec = Self {
            invocation_kind,
            invocation_id,
            valid_signers,
            quorum_threshold,
            received_at: Some(latched_at.clone()),
            latched_at,
            fuse_secs: Some(HALT_FUSE_SECS_DEFAULT),
            confirmed: None,
            node_id,
            halt_payload_sha256,
            latch_id,
            release_payload_sha256: None,
            release_binding: None,
        };
        if let Ok(binding) = crate::accord_release::ReleaseBinding::from_halt_record(&rec) {
            rec.release_payload_sha256 = binding.payload_sha256().ok();
            rec.release_binding = Some(binding.to_json());
        }
        rec
    }

    /// The fuse this latch runs on (the charter's `halt_fuse_secs`).
    #[must_use]
    pub fn with_fuse(mut self, fuse_secs: u64) -> Self {
        self.fuse_secs = Some(fuse_secs);
        self
    }

    /// The instant the fuse counts from: `received_at`, or `latched_at` for a
    /// latch written before the field existed.
    #[must_use]
    pub fn received_at(&self) -> chrono::DateTime<chrono::Utc> {
        let s = self.received_at.as_deref().unwrap_or(&self.latched_at);
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&chrono::Utc))
            // An unparseable instant must never read as "fresh forever": a
            // latch whose clock cannot be read lapses at once.
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
    }

    /// The fuse in seconds, defaulting per CC 4.2.1.1.
    #[must_use]
    pub fn fuse_secs(&self) -> u64 {
        self.fuse_secs.unwrap_or(HALT_FUSE_SECS_DEFAULT)
    }

    /// When an unconfirmed latch lapses.
    #[must_use]
    pub fn lapses_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.received_at() + chrono::Duration::seconds(self.fuse_secs().min(i64::MAX as u64) as i64)
    }

    /// Is this latch in effect at `now`? Confirmed → yes until released;
    /// otherwise yes until the fuse lapses.
    #[must_use]
    pub fn standing_at(&self, now: chrono::DateTime<chrono::Utc>) -> HaltStanding {
        if self.confirmed.is_some() {
            return HaltStanding::InEffect { lapses_at: None };
        }
        let lapses_at = self.lapses_at();
        if now < lapses_at {
            HaltStanding::InEffect {
                lapses_at: Some(lapses_at.to_rfc3339()),
            }
        } else {
            HaltStanding::Lapsed {
                lapsed_at: lapses_at.to_rfc3339(),
            }
        }
    }

    /// Convenience: `standing_at(now)` is `InEffect`.
    #[must_use]
    pub fn in_effect_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        matches!(self.standing_at(now), HaltStanding::InEffect { .. })
    }
}

/// Where the latch lives for `home`.
#[must_use]
pub fn halt_latch_path(home: &Path) -> PathBuf {
    home.join(HALT_LATCH_FILE)
}

/// Read the latch under `home`, if any. `None` when absent; an unparseable file
/// is an error (a latch that cannot be read must not silently read as no halt).
pub fn read_halt_latch(home: &Path) -> anyhow::Result<Option<HaltRecord>> {
    let path = halt_latch_path(home);
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("read halt latch {}: {e}", path.display()))?;
    let rec: HaltRecord = serde_json::from_str(&body)
        .map_err(|e| anyhow::anyhow!("parse halt latch {}: {e}", path.display()))?;
    Ok(Some(rec))
}

/// Boot-time: load the latch, consume a presented offline release token, and
/// say what stands. **Never refuses to start** (rc7: a halt pauses agents, it
/// does not stop a node). Returns the latch that stands after any release.
///
/// A token that fails verification clears nothing: the refusal is journaled
/// and WARNed, and the latch stays.
pub fn load_halt_latch(home: &Path) -> anyhow::Result<Option<HaltRecord>> {
    let Some(record) = read_halt_latch(home)? else {
        return Ok(None);
    };
    let path = halt_latch_path(home);
    let token_path = crate::accord_release::release_token_path(home);
    if token_path.exists() {
        let detail = std::fs::read_to_string(&path).unwrap_or_default();
        match crate::accord_release::consume_presented_release_token(home, &detail) {
            Ok(v) => {
                let line = format!(
                    "HUMANITY_ACCORD HALT RELEASED — {valid} of {n} accord seats authorized \
                     accord:lifecycle:active {inv} for latch {latch} on node {node} (authority: \
                     {src}, verified OFFLINE). The latch is cleared; journal: {journal}",
                    valid = v.valid_signers,
                    n = v.roster_size,
                    inv = v.release_invocation_id,
                    latch = v.latch_id,
                    node = v.node_id,
                    src = v.authority_source,
                    journal = crate::accord_release::release_journal_path(home).display(),
                );
                tracing::warn!("{line}");
                eprintln!("✅ {line}");
                return Ok(None);
            }
            Err(e) => {
                tracing::warn!(
                    token = %token_path.display(),
                    latch = %path.display(),
                    error = %format!("{e:#}"),
                    "a release token was presented and REFUSED — the latch is untouched; have \
                     a strict majority of the standing roster cosign a release for THIS \
                     latch's release_binding"
                );
            }
        }
    }
    let now = chrono::Utc::now();
    match record.standing_at(now) {
        HaltStanding::InEffect { lapses_at } => tracing::warn!(
            latch = %path.display(),
            invocation_id = %record.invocation_id,
            confirmed = record.confirmed.is_some(),
            ?lapses_at,
            "HUMANITY_ACCORD HALT IN EFFECT — the agents on this node are PAUSED (CC 4.2.1.1, \
             rc7). The node serves; only the agent act gate reads this. It ends by a majority \
             accord:lifecycle:active naming this halt, an offline release token, or `accord \
             reactivate`; unconfirmed, it lapses at the instant above."
        ),
        HaltStanding::Lapsed { lapsed_at } => tracing::info!(
            latch = %path.display(),
            invocation_id = %record.invocation_id,
            %lapsed_at,
            "a HUMANITY_ACCORD halt latch is present but LAPSED (its fuse passed with no \
             majority confirmation) — history, not a pause"
        ),
    }
    Ok(Some(record))
}

/// Write the latch (idempotent overwrite). Called AFTER the verified halt has
/// been replicated to peers (replicate-before-latch).
pub fn latch_halt(home: &Path, record: &HaltRecord) -> anyhow::Result<PathBuf> {
    let path = halt_latch_path(home);
    let body = serde_json::to_string_pretty(record).unwrap_or_else(|_| format!("{record:?}"));
    std::fs::write(&path, body)
        .map_err(|e| anyhow::anyhow!("write halt latch {}: {e}", path.display()))?;
    Ok(path)
}

/// Record a majority confirmation on the standing latch: the latch no longer
/// lapses. The caller has verified the row and that it names this halt within
/// the fuse.
pub fn confirm_halt(
    home: &Path,
    mut record: HaltRecord,
    confirmation: HaltConfirmation,
) -> anyhow::Result<HaltRecord> {
    record.confirmed = Some(confirmation);
    latch_halt(home, &record)?;
    Ok(record)
}

/// Remove the latch after a verified resumption delivered over the wire
/// (`accord:lifecycle:active` at a strict majority naming this halt), and
/// journal it beside the offline releases so every ending leaves one trace.
pub fn release_halt(
    home: &Path,
    record: &HaltRecord,
    entry: &serde_json::Value,
) -> anyhow::Result<()> {
    crate::accord_release::append_journal_line(home, entry)
        .map_err(|e| anyhow::anyhow!("journal the resumption: {e:#}"))?;
    let path = halt_latch_path(home);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "the resumption VERIFIED but the halt latch {} for {} could not be removed: {e}",
            path.display(),
            record.invocation_id
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(latched_at: &str) -> HaltRecord {
        HaltRecord::new(
            "constitutional".into(),
            "halt-001".into(),
            vec!["accord-holder-a".into()],
            1,
            latched_at.into(),
            Some("node-under-test".into()),
            Some("cd".repeat(32)),
        )
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn a_fresh_latch_is_in_effect_and_lapses_after_the_fuse() {
        let r = rec("2026-06-20T00:00:00.000Z");
        assert_eq!(r.fuse_secs(), HALT_FUSE_SECS_DEFAULT);
        assert!(r.in_effect_at(at("2026-06-20T23:59:59Z")));
        assert_eq!(
            r.standing_at(at("2026-06-21T00:00:00Z")),
            HaltStanding::Lapsed {
                lapsed_at: at("2026-06-21T00:00:00Z").to_rfc3339()
            },
            "exactly fuse_secs after receipt it has lapsed"
        );
    }

    #[test]
    fn a_confirmed_latch_never_lapses_on_its_own() {
        let mut r = rec("2026-06-20T00:00:00.000Z");
        r.confirmed = Some(HaltConfirmation {
            invocation_id: "confirm-001".into(),
            signers: vec!["a".into(), "b".into()],
            received_at: "2026-06-20T01:00:00Z".into(),
        });
        assert_eq!(
            r.standing_at(at("2030-01-01T00:00:00Z")),
            HaltStanding::InEffect { lapses_at: None }
        );
    }

    #[test]
    fn the_fuse_counts_from_receipt_not_the_signers_instant_and_a_charter_fuse_overrides() {
        let r = rec("2026-06-20T00:00:00.000Z").with_fuse(60);
        assert!(r.in_effect_at(at("2026-06-20T00:00:59Z")));
        assert!(!r.in_effect_at(at("2026-06-20T00:01:00Z")));
    }

    #[test]
    fn a_pre_rc7_latch_takes_latched_at_as_receipt_and_the_default_fuse() {
        let old = serde_json::json!({
            "invocation_kind": "CONSTITUTIONAL", "invocation_id": "halt-old",
            "valid_signers": ["A1", "B1"], "quorum_threshold": 2,
            "latched_at": "2026-06-01T00:00:00Z"
        });
        let r: HaltRecord = serde_json::from_value(old).unwrap();
        assert!(
            matches!(
                r.standing_at(at("2026-06-03T00:00:00Z")),
                HaltStanding::Lapsed { .. }
            ),
            "an upgrade never resurrects a stale halt past 24 h"
        );
        assert!(r.in_effect_at(at("2026-06-01T12:00:00Z")));
    }

    #[test]
    fn load_reads_a_present_latch_and_never_refuses() {
        let dir = std::env::temp_dir().join(format!(
            "accord-halt-{}-{}",
            std::process::id(),
            std::sync::atomic::AtomicU64::new(0).fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(halt_latch_path(&dir));
        assert!(load_halt_latch(&dir).unwrap().is_none());
        let r = rec(&chrono::Utc::now().to_rfc3339());
        let path = latch_halt(&dir, &r).unwrap();
        let loaded = load_halt_latch(&dir)
            .unwrap()
            .expect("the latch is read, not refused");
        assert_eq!(loaded.invocation_id, "halt-001");
        assert!(loaded.in_effect_at(chrono::Utc::now()));
        assert!(r.latch_id.is_some(), "every latch mints a fresh latch_id");
        assert_eq!(
            r.release_payload_sha256.as_deref(),
            Some(
                crate::accord_release::ReleaseBinding::from_halt_record(&r)
                    .unwrap()
                    .payload_sha256()
                    .unwrap()
                    .as_str()
            ),
        );
        let confirmed = confirm_halt(
            &dir,
            loaded,
            HaltConfirmation {
                invocation_id: "confirm-001".into(),
                signers: vec!["a".into(), "b".into()],
                received_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .unwrap();
        assert!(read_halt_latch(&dir).unwrap().unwrap().confirmed.is_some());
        release_halt(&dir, &confirmed, &serde_json::json!({"event": "test"})).unwrap();
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_latches_of_the_same_halt_get_distinct_latch_ids() {
        let (a, b) = (
            rec("2026-06-20T00:00:00.000Z"),
            rec("2026-06-20T00:00:00.000Z"),
        );
        assert_ne!(a.latch_id, b.latch_id);
        assert_ne!(a.release_payload_sha256, b.release_payload_sha256);
    }
}
