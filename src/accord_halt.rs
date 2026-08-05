//! **HUMANITY_ACCORD operational halt** (CIRISServer#41, CC 4.2.1 / 4.2.3 / §9.2.1)
//! — the disk-latched *full halt* that makes the 2-of-3 kill-switch enforceable at
//! the fabric-node layer, not merely verifiable.
//!
//! A verified 2-of-3 `CONSTITUTIONAL` invocation is "kill-switch authority; full
//! halt" (CC 4.2.1) and explicitly **"not a recoverable pause"** (CC 4.2.3). When
//! a node honors one it:
//!
//!   1. replicates the halt to **all known peers FIRST** (so the kill propagates
//!      mesh-wide even as nodes go dark — see [`crate::accord`]);
//!   2. writes a **halt latch** file to disk ([`latch_halt`]); and
//!   3. terminates — fail-secure, degrading to *not operating*, never escalating.
//!
//! The latch is the load-bearing mechanic: [`check_halt_gate`] runs at the very
//! top of boot and **refuses to start** while the latch exists. No operator,
//! steward, or Wise Authority restart can override it (CC 4.2 §157); the authority
//! lives outside the federation by design.
//!
//! ## Two ways back, both accord-authorized (CIRISServer#347)
//!
//! 1. **[`crate::accord_reactivate`]** — a `lifecycle:active` proof verified
//!    against the **live** family read from persist (live M-of-N + ≥1 original
//!    seat). Needs the DB and the keystore; handles a rotated/grown family.
//! 2. **[`crate::accord_release`]** — an **offline-verifiable release token**
//!    verified against the **baked** accord genesis. Needs nothing but two files
//!    in `home`, so a dark node can be released by file drop / USB / QR / paste.
//!    [`check_halt_gate`] consumes one if present.
//!
//! The latch itself records **what would lift it** ([`HaltRecord::release_binding`]):
//! a halted node's own disk states the exact payload the accord must sign. That is
//! what removes the O(nodes) physical recovery from a *mistaken* halt — the failure
//! mode far likelier than a real compromise, and the one whose cost previously made
//! operators hesitate to use the safety mechanism at all.
//!
//! Manually deleting the latch remains a non-conformant operator override that the
//! accord does not authorize; the release token is the conformant offline path,
//! and unlike a deletion it leaves an audited, quorum-signed trace.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The halt-latch filename, written under the node `home`. Presence == halted.
pub const HALT_LATCH_FILE: &str = "HUMANITY_ACCORD_HALT";

/// The process exit code a node uses after latching an accord halt (a sentinel an
/// operator / supervisor can recognize as "halted by HUMANITY_ACCORD", distinct
/// from a crash). Non-zero so a naive `restart=on-failure` does NOT silently
/// resurrect it — and the latch gate blocks the restart regardless.
pub const HALT_EXIT_CODE: i32 = 42;

/// What gets recorded in the latch for the operator + audit (the invocation that
/// halted the node, re-verifiable against the cold-start holder roster) **and, since
/// CIRISServer#347, what would lift it**.
///
/// Every `#347` field is `Option` with `serde(default)`: a latch written by an older
/// build still parses, and [`crate::accord_release`] fails **closed** on it (a latch
/// that names no binding is a latch no token can be bound to — such a node takes the
/// `accord reactivate` path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaltRecord {
    pub invocation_kind: String,
    pub invocation_id: String,
    /// The registered holder `key_id`s whose cosignatures met the 2-of-3.
    pub valid_signers: Vec<String>,
    pub quorum_threshold: usize,
    /// RFC-3339 instant the halt was latched.
    pub latched_at: String,

    // ── #347: the release binding — what a token must name to lift THIS latch ──
    /// The federation `key_id` of the node this latch is on. Binds a release
    /// token to one node, so a token is never a mesh-wide skeleton key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// `payload_sha256` of the halt invocation that fired. Binds the release to
    /// this halt's contents, not merely its id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt_payload_sha256: Option<String>,
    /// A fresh CSPRNG id minted per latch write. This is what makes a token
    /// unstockpilable: a release cannot be pre-signed against a halt that has not
    /// happened, and a token for an earlier latch of the *same* halt is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latch_id: Option<String>,
    /// **Documentation, not authority.** The digest a conformant release token
    /// carries in `invocation.payload_sha256`, written here so an operator reading
    /// the latch on a dark machine knows exactly what to have signed.
    /// [`crate::accord_release::verify_release_token`] RECOMPUTES this from the
    /// three fields above and ignores the stored copy — a tampered value here
    /// changes nothing about what is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_payload_sha256: Option<String>,
    /// The same, expanded — the payload the digest is over. Also documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_binding: Option<serde_json::Value>,
}

impl HaltRecord {
    /// Build the record the halt path latches, minting the per-latch `latch_id`
    /// and stamping the release binding.
    ///
    /// `node_id` is the node's federation `key_id`; `None` (a test / no-identity
    /// context) yields a latch with no binding, which fails closed on the release
    /// path exactly like a pre-#347 latch.
    ///
    /// # Panics
    ///
    /// Never — a CSPRNG fault degrades to a `latch_id` of `None` (no binding, so
    /// no release token), which is the fail-secure direction.
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
        // Fail-secure CSPRNG (CIRISServer#283 finding 2): never a predictable
        // latch id — a guessable one would let a token be pre-minted for a halt
        // that has not happened yet.
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
            latched_at,
            node_id,
            halt_payload_sha256,
            latch_id,
            release_payload_sha256: None,
            release_binding: None,
        };
        // Stamp the (advisory) binding so the dark node's own latch states what
        // would lift it. Absent when any binding field is missing.
        if let Ok(binding) = crate::accord_release::ReleaseBinding::from_halt_record(&rec) {
            rec.release_payload_sha256 = binding.payload_sha256().ok();
            rec.release_binding = Some(binding.to_json());
        }
        rec
    }
}

/// The latch path under a node `home`.
#[must_use]
pub fn halt_latch_path(home: &Path) -> PathBuf {
    home.join(HALT_LATCH_FILE)
}

/// **Startup gate** — refuse to boot while the halt latch exists. Fail-secure:
/// presence is the gate (an unreadable-but-present latch still blocks). Returns a
/// loud, actionable error that the boot path propagates (the node does not start).
///
/// # CIRISServer#347 — the offline release
///
/// If a [`crate::accord_release::RELEASE_TOKEN_FILE`] sits beside the latch, the
/// gate verifies it **here, offline** — against the baked accord genesis, with no
/// network, no peer, no live quorum and no database — and on success clears the
/// latch and lets the node boot. That is the whole point: a halted node is not
/// running, so an un-halt can never be *delivered* to it; it has to be *found on
/// disk at boot*.
///
/// A token that fails verification does **not** clear anything: the gate refuses
/// with the reason, and the attempt is journaled.
pub fn check_halt_gate(home: &Path) -> anyhow::Result<()> {
    let path = halt_latch_path(home);
    if !path.exists() {
        return Ok(());
    }
    let detail = std::fs::read_to_string(&path).unwrap_or_default();

    // ── The offline release token, if one has been presented ──────────────────
    let token_path = crate::accord_release::release_token_path(home);
    if token_path.exists() {
        match crate::accord_release::consume_presented_release_token(home, &detail) {
            Ok(v) => {
                // Loud on BOTH channels: the gate runs at the very top of boot and
                // a subscriber may not be installed yet, but a release is a
                // governance act and must be visible however the operator is watching.
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
                return Ok(());
            }
            Err(e) => {
                anyhow::bail!(
                    "HUMANITY_ACCORD HALT IN EFFECT — refusing to start.\n\n\
                     A release token was presented at {token} and was REFUSED:\n\n  {e:#}\n\n\
                     The latch is untouched. Re-read the latch's `release_binding` below and \
                     have >=M accord seats cosign a release for THAT binding; a token minted \
                     for another node, another halt, or an earlier latch of this halt is not \
                     a key to this one.\n\n\
                     Halt latch: {path}\n{detail}\n",
                    token = token_path.display(),
                    path = path.display(),
                );
            }
        }
    }

    anyhow::bail!(
        "HUMANITY_ACCORD HALT IN EFFECT — refusing to start.\n\n\
         A 2-of-3 accord CONSTITUTIONAL halt has been honored by this node \
         (CC 4.2.1: kill-switch authority, full halt). This is NOT a recoverable \
         pause (CC 4.2.3): the node stays down until humanity re-activates the \
         accord (accord:lifecycle:active). No operator, steward, or Wise Authority \
         restart can override it.\n\n\
         Halt latch: {path}\n{detail}\n\n\
         TWO conformant ways back, both authorized by the accord itself:\n\n\
         (a) OFFLINE release token (CIRISServer#347) — no network, no peer, no database. \
         The `release_binding` in the latch above states exactly what the accord must sign; \
         `ciris-server accord release-request --home <home>` prints the invocation and the \
         bytes to cosign. Then either drop the signed token at\n    {token}\n\
         and restart, or run:\n    \
         ciris-server accord release --home <home> --token <token.json>\n\n\
         (b) LIVE-roster reactivation — a verified M-of-N accord:lifecycle:active that \
         includes >=1 of the ORIGINAL (genesis) holders, verified against the family read \
         from persist (use this if the family has rotated past its founders):\n    \
         ciris-server accord reactivate --home <home> --proof <proof.json>\n\n\
         Manually deleting the latch is a NON-conformant operator override the accord does \
         not authorize and is not a supported recovery path; the kill-switch holders, not the \
         operator, bring a node back.\n",
        path = path.display(),
        token = crate::accord_release::release_token_path(home).display(),
    );
}

/// Latch the halt to disk (idempotent overwrite). Called AFTER the verified halt
/// has been replicated to peers (replicate-before-halt). A write failure is
/// returned so the caller can still proceed to terminate (fail-secure).
pub fn latch_halt(home: &Path, record: &HaltRecord) -> anyhow::Result<PathBuf> {
    let path = halt_latch_path(home);
    let body = serde_json::to_string_pretty(record).unwrap_or_else(|_| format!("{record:?}"));
    std::fs::write(&path, body)
        .map_err(|e| anyhow::anyhow!("write halt latch {}: {e}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_passes_when_no_latch_and_blocks_once_latched() {
        let dir = std::env::temp_dir().join(format!("accord-halt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(halt_latch_path(&dir));

        // No latch ⇒ boot allowed.
        assert!(check_halt_gate(&dir).is_ok());

        // Latch ⇒ boot refused, and the error names the manual-removal path.
        let rec = HaltRecord::new(
            "CONSTITUTIONAL".into(),
            "halt-001".into(),
            vec!["accord-holder-a".into(), "accord-holder-b".into()],
            2,
            "2026-06-20T00:00:00.000Z".into(),
            Some("node-under-test".into()),
            Some("cd".repeat(32)),
        );
        let path = latch_halt(&dir, &rec).unwrap();
        assert!(path.exists());
        let err = check_halt_gate(&dir).unwrap_err().to_string();
        assert!(err.contains("HALT IN EFFECT"), "got: {err}");
        assert!(
            err.contains(&path.display().to_string()),
            "must name the latch path"
        );

        // #347: the latch states what would lift it — the operator on a dark
        // machine can read the binding out of the file itself.
        assert!(rec.latch_id.is_some(), "every latch mints a fresh latch_id");
        assert_eq!(
            rec.release_payload_sha256.as_deref(),
            Some(
                crate::accord_release::ReleaseBinding::from_halt_record(&rec)
                    .unwrap()
                    .payload_sha256()
                    .unwrap()
                    .as_str()
            ),
        );
        assert!(
            err.contains("release-request"),
            "the gate must name the offline path: {err}"
        );

        // Manual removal clears the gate.
        std::fs::remove_file(&path).unwrap();
        assert!(check_halt_gate(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_latches_of_the_same_halt_get_distinct_latch_ids() {
        // The anti-stockpile property: a release token binds to the latch INSTANCE,
        // so re-halting after a release invalidates any token held from before.
        let mk = || {
            HaltRecord::new(
                "CONSTITUTIONAL".into(),
                "halt-001".into(),
                vec!["A1".into(), "B1".into()],
                2,
                "2026-06-20T00:00:00.000Z".into(),
                Some("node-x".into()),
                Some("ef".repeat(32)),
            )
        };
        let (a, b) = (mk(), mk());
        assert_ne!(a.latch_id, b.latch_id);
        assert_ne!(a.release_payload_sha256, b.release_payload_sha256);
    }
}
