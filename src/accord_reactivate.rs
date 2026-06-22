//! **`ciris-server accord reactivate`** — the constitutional way back from a
//! HUMANITY_ACCORD halt (CC 4.2.1 §69 / CEG §9.2).
//!
//! A halted node refuses to boot (the disk latch + [`crate::accord_halt::check_halt_gate`]).
//! The **only** thing that clears it is a verified **`accord:lifecycle:active`**
//! invocation carrying ≥M of the N family seats' cosignatures — *"not an operator
//! restart."* The quorum, not the operator, brings the node back. verify v6.11.0's
//! [`InvocationKind::LifecycleActive`] (its own wire- and scope-isolated canonical
//! domain) makes that proof wire-checkable; this runs OFFLINE (the server can't
//! serve while latched), reads the entrenched family roster straight from persist,
//! verifies the quorum, and removes the latch.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ciris_keyring::{HardwareSigner, PqcSigner};
use ciris_persist::federation::cohort::Cohort;
use ciris_persist::prelude::Engine;
use ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
use ciris_verify_core::humanity_accord::{Invocation, InvocationKind};
use ciris_verify_core::threshold::{
    verify_threshold_signatures, QuorumPolicy, ThresholdMember, ThresholdSignature,
};

use crate::accord_halt::halt_latch_path;
use crate::compose::{federation_pqc_signer, federation_signer};
use crate::config::ServerConfig;

/// The reactivation proof an operator presents to `accord reactivate` — a 2/3 (M-of-N)
/// `accord:lifecycle:active` invocation collected from the family seats (each holder
/// signs on their own device, exactly as for a halt).
#[derive(Debug, serde::Deserialize)]
pub struct ReactivationProof {
    /// The `lifecycle:active` invocation (its canonical bytes use the distinct
    /// `LIFECYCLE_DOMAIN_PREFIX`, so a halt signature can never be replayed here).
    pub invocation: Invocation,
    /// ≥M family-seat cosignatures over the invocation's canonical bytes.
    pub signatures: Vec<ThresholdSignature>,
}

/// Verify a 2/3 (M-of-N) `lifecycle:active` proof against the entrenched family and,
/// on success, clear the halt latch so the node may boot again.
pub async fn reactivate_accord(cfg: &ServerConfig, proof: ReactivationProof) -> Result<()> {
    let latch = halt_latch_path(&cfg.home);
    if !latch.exists() {
        bail!(
            "no HUMANITY_ACCORD halt latch at {} — the node is not halted; nothing to reactivate",
            latch.display()
        );
    }
    // The proof MUST be a lifecycle:active invocation — never a halt/notify/drill.
    if proof.invocation.invocation_kind != InvocationKind::LifecycleActive {
        bail!(
            "the reactivation proof must be an accord:lifecycle:active invocation, got {:?}",
            proof.invocation.invocation_kind
        );
    }

    // Open the engine read-side with the SAME hybrid signer the boot path builds (the
    // halt startup gate lives in `serve`, not here) and read the entrenched family.
    cfg.ensure_dirs()?;
    let signer: Arc<dyn HardwareSigner> = Arc::from(federation_signer(cfg)?);
    let pqc: Arc<dyn PqcSigner> = federation_pqc_signer(cfg)?;
    let pqc_key_id = format!("{}-pqc", cfg.keystore_alias);
    let engine =
        Engine::with_hardware_signer_hybrid(signer, Some(pqc), Some(pqc_key_id), &cfg.dsn())
            .await
            .context("open the persist Engine to read the accord family roster")?;

    let family = crate::family::lookup(&engine, HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
        .map_err(|e| anyhow::anyhow!("read accord family: {e}"))?
        .context("no HUMANITY_ACCORD family is entrenched — cannot verify a reactivation")?;
    let roster = crate::family::active_threshold_roster(&engine, HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await
        .map_err(|e| anyhow::anyhow!("resolve accord roster: {e}"))?;
    if roster.is_empty() {
        bail!("the HUMANITY_ACCORD family has no live seats — cannot verify a reactivation");
    }

    // The threshold M comes from the family's own consensus_protocol (`quorum:M/N`),
    // so a reconstituted 3/5 family needs 3 — never a stale hard-coded 2.
    let m = family
        .consensus_protocol
        .strip_prefix("quorum:")
        .and_then(QuorumPolicy::parse)
        .map(|p| p.m)
        .with_context(|| {
            format!(
                "family consensus_protocol {:?} is not a quorum:M/N policy",
                family.consensus_protocol
            )
        })?;

    // (1) The current quorum: ≥M distinct LIVE seats signed THIS lifecycle:active.
    let canonical = proof.invocation.canonical_bytes();
    let valid =
        verify_threshold_signatures(&canonical, &roster, &proof.signatures, m).map_err(|e| {
            anyhow::anyhow!(
                "reactivation quorum NOT met ({m} of {} required): {e}",
                roster.len()
            )
        })?;

    // (2) Original-mesh continuity (the reactivation FLOOR): the proof MUST also carry
    // ≥1 cosignature from an ORIGINAL (genesis, version-1) seat. A halted node is
    // brought back only with a FOUNDING human's authorization — so a fully rotated (or
    // captured) roster cannot resurrect a node the original humanity halted. (If every
    // founder's key is gone, reactivation requires re-establishing the family — by
    // design: the gravest undo demands continuity with who established the accord.)
    let dir = engine.federation_directory();
    let genesis_member_ids: Vec<String> = match dir
        .group_at(Cohort::Family, HUMANITY_ACCORD_FAMILY_KEY_ID, 1)
        .await
        .map_err(|e| anyhow::anyhow!("read genesis (version 1) family: {e}"))?
    {
        Some(v) => v.snapshot["members"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.get("key_id")?.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        // No version-1 record (never superseded) ⇒ the current family IS the original.
        None => family.members.iter().map(|m| m.key_id.clone()).collect(),
    };
    let mut original_roster: Vec<ThresholdMember> = Vec::new();
    for key_id in &genesis_member_ids {
        if let Some(rec) = dir
            .lookup_public_key(key_id)
            .await
            .map_err(|e| anyhow::anyhow!("resolve genesis seat {key_id}: {e}"))?
        {
            original_roster.push(ThresholdMember {
                member_id: rec.key_id,
                ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                role: None,
            });
        }
    }
    verify_threshold_signatures(&canonical, &original_roster, &proof.signatures, 1).map_err(
        |_| {
            anyhow::anyhow!(
                "reactivation needs >=1 signature from an ORIGINAL (genesis) family seat — no \
             founding holder authorized this. The quorum brings the node back, and at least \
             one of the humans who established the accord MUST be among them."
            )
        },
    )?;

    // Authorized — clear the latch. (Idempotent: a second run finds no latch.)
    std::fs::remove_file(&latch)
        .with_context(|| format!("remove halt latch {}", latch.display()))?;
    println!(
        "✅ HUMANITY_ACCORD reactivated — {valid} of {} family seats authorized \
         accord:lifecycle:active. The halt latch is cleared; the node may now start.",
        roster.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle_proof(kind: InvocationKind) -> ReactivationProof {
        ReactivationProof {
            invocation: Invocation {
                invocation_kind: kind,
                invocation_id: "react-001".into(),
                nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                asserted_at: "2026-06-21T00:00:00.000Z".into(),
                valid_until: "2030-01-01T00:00:00.000Z".into(),
                payload_sha256: "0".repeat(64),
            },
            signatures: Vec::new(),
        }
    }

    fn temp_cfg(tag: &str) -> (ServerConfig, std::path::PathBuf) {
        let home = std::env::temp_dir().join(format!("react-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let _ = std::fs::remove_file(halt_latch_path(&home));
        let cfg = ServerConfig::from_home(home.clone(), "test-node".into()).unwrap();
        (cfg, home)
    }

    #[tokio::test]
    async fn errors_when_not_halted() {
        // No latch ⇒ the guard returns before any engine work.
        let (cfg, home) = temp_cfg("nohalt");
        let e = reactivate_accord(&cfg, lifecycle_proof(InvocationKind::LifecycleActive))
            .await
            .unwrap_err();
        assert!(
            e.to_string().contains("not halted") || e.to_string().contains("nothing"),
            "{e}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn rejects_a_non_lifecycle_proof_without_clearing_the_latch() {
        // A latch exists; a CONSTITUTIONAL (halt) proof must be refused BEFORE the
        // engine opens, and the latch must stay put.
        let (cfg, home) = temp_cfg("wrongkind");
        std::fs::write(halt_latch_path(&home), b"{}").unwrap();
        let e = reactivate_accord(&cfg, lifecycle_proof(InvocationKind::Constitutional))
            .await
            .unwrap_err();
        assert!(e.to_string().contains("lifecycle:active"), "{e}");
        assert!(
            halt_latch_path(&home).exists(),
            "the latch must NOT be cleared by a bad proof"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
