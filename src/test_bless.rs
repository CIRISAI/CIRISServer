//! TEST-ANCHOR-ONLY (CIRISServer#258) — auto-bless this node with a **software
//! single-key trust root**, so a self-consistent local mesh (`harness/mesh-repro`)
//! roots and drives a delivery round with **no operator YubiKeys**.
//!
//! Compile-time fenced behind the `test-anchor` Cargo feature — the production
//! wheel MUST NOT carry it (CIRISServer#258; the feature's *absence* is the wall,
//! since the prod container is zero-env). At runtime it additionally requires
//! `CIRIS_TESTING_MODE=true` (CIRISAgent's own QA flag) + a `CIRIS_TEST_TRUST_ROOT_SEED`.
//!
//! It mirrors verify v10.2.0's anchor override, which reads `CIRIS_TEST_TRUST_ROOT`
//! (the test root **pubkey**) and returns it as the 1-of-N accord anchor. Here the
//! **seed** blesses (scrub-signs this node's record) and the **pubkey** anchors —
//! two halves of one throwaway SW root — so the node roots exactly as a production
//! canonical roots under an A1-scrubbed record, but with no hardware holder.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::prelude::Engine;

use crate::config::ServerConfig;

/// Mint the SW hybrid test root from `CIRIS_TEST_TRUST_ROOT_SEED`, keyed as the
/// persist-seeded holder `test-accord-holder-0` so scrubs it signs verify
/// against the (PQC-complete, scrub-verifying — persist#451) seeded row. The
/// ML-DSA seed is derived from the Ed seed (domain-separated SHA-256) so the
/// whole root comes from ONE env. Shared by the boot self-bless below and the
/// harness `test-admit-peer` bless-then-register endpoint.
pub(crate) fn mint_test_root() -> Result<ciris_verify_core::self_at_login::HybridSigningIdentity> {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer};
    use ciris_verify_core::self_at_login::HybridSigningIdentity;

    let seed_b64 = std::env::var("CIRIS_TEST_TRUST_ROOT_SEED")
        .map_err(|_| anyhow!("CIRIS_TEST_TRUST_ROOT_SEED is unset"))?;
    let ed_seed: [u8; 32] = B64
        .decode(seed_b64.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| anyhow!("CIRIS_TEST_TRUST_ROOT_SEED must be base64 of exactly 32 bytes"))?;
    let ml_seed: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(ed_seed);
        h.finalize().into()
    };
    let ed = Ed25519Signer::from_seed(&ed_seed).map_err(|e| anyhow!("test-root ed25519: {e}"))?;
    let mldsa =
        MlDsa65Signer::from_seed(&ml_seed).map_err(|e| anyhow!("test-root ml-dsa-65: {e}"))?;
    let root_pub_b64 = B64.encode(
        ed.public_key()
            .map_err(|e| anyhow!("test-root pubkey: {e}"))?,
    );

    // Sanity: the root we bless WITH must equal the anchor verify checks AGAINST.
    if let Ok(anchor) = std::env::var("CIRIS_TEST_TRUST_ROOT") {
        if anchor.trim() != root_pub_b64 {
            tracing::error!(
                seed_derived_pub = %root_pub_b64,
                anchor = %anchor.trim(),
                "TEST BLESS: CIRIS_TEST_TRUST_ROOT (the anchor) does NOT match the pubkey derived \
                 from CIRIS_TEST_TRUST_ROOT_SEED — records blessed by this key will not root. \
                 Fix the harness env so they correspond."
            );
        }
    }
    Ok(HybridSigningIdentity::new(
        "test-accord-holder-0".to_string(),
        ed,
        mldsa,
    ))
}

/// If `test-anchor` is compiled in AND `CIRIS_TESTING_MODE=true` AND a test-root
/// seed is set: mint the SW test root, scrub-sign THIS node's own key record with
/// it, and adopt the blessed record — so the node roots under the
/// `CIRIS_TEST_TRUST_ROOT` anchor. Loud no-op otherwise. Never engages in prod
/// (the feature is absent there).
pub(crate) async fn maybe_test_bless_self(engine: &Engine, cfg: &ServerConfig) -> Result<()> {
    if std::env::var("CIRIS_TESTING_MODE").ok().as_deref() != Some("true") {
        return Ok(());
    }
    if std::env::var("CIRIS_TEST_TRUST_ROOT_SEED").is_err() {
        tracing::warn!(
            "test-anchor compiled in + CIRIS_TESTING_MODE=true, but CIRIS_TEST_TRUST_ROOT_SEED \
             is unset — skipping self-bless (the node stays self-signed and will not root under \
             the test anchor)"
        );
        return Ok(());
    }

    use ciris_persist::federation::SignedKeyRecord;
    use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};

    let test_root = mint_test_root()?;
    let root_pub_b64 = std::env::var("CIRIS_TEST_TRUST_ROOT").unwrap_or_default();
    let valid_from = chrono::Utc::now().to_rfc3339();

    // This node's own self record → the ScrubTarget the test root scrub-signs.
    // With `CIRIS_TEST_BLESS_CANONICAL=true` (the harness canonical service) the
    // blessed record claims `canonical,node` — the SAME shape as the baked prod
    // canonical genesis (canonical_seed.json). Role conferral goes through the
    // untouched m-of-n add gate (`check_canonical_role_admission`): strict
    // majority of the LIVE roster, which under the test override is the ONE
    // seeded SW holder → 1-of-1, satisfied by this very scrub. A dial hint
    // (`CIRIS_TEST_CANONICAL_DIAL`, e.g. `canonical:4242`) rides in the signed
    // envelope so a peer's `canonical_bootstrap_hints()` (hint-driven) yields
    // this key_id as a delivery target.
    let bless_canonical =
        std::env::var("CIRIS_TEST_BLESS_CANONICAL").ok().as_deref() == Some("true");
    let rec = crate::compose::build_self_key_record(cfg).await?;
    let target = ScrubTarget {
        key_id: rec.key_id.clone(),
        pubkey_ed25519_base64: rec.pubkey_ed25519_base64.clone(),
        pubkey_ml_dsa_65_base64: rec
            .pubkey_ml_dsa_65_base64
            .clone()
            .ok_or_else(|| anyhow!("self record has no ML-DSA-65 pubkey — cannot scrub-sign"))?,
        identity_type: if bless_canonical {
            "canonical,node".to_string()
        } else {
            rec.identity_type.clone()
        },
        roles: Vec::new(),
    };
    let hints: Vec<ciris_verify_core::federation_self_record::TransportHint> = if bless_canonical {
        let dial = std::env::var("CIRIS_TEST_CANONICAL_DIAL")
            .unwrap_or_else(|_| cfg.listen_addr.to_string());
        vec![ciris_verify_core::federation_self_record::TransportHint {
            kind: "ip".to_string(),
            destination: dial,
        }]
    } else {
        Vec::new()
    };
    let scrubbed = produce_scrubbed_key_record(&test_root, target, &valid_from, &hints)
        .await
        .map_err(|e| anyhow!("test-root scrub-sign of {}: {e}", rec.key_id))?;

    // Adopt: upgrade this node's self-signed directory row to the test-root-blessed
    // one — the same `adopt_scrub_upgrade` path the real A1 admit-node uses. The
    // scrub is FULL HYBRID; it verifies against the PQC-complete seeded holder.
    let persist_rec: SignedKeyRecord =
        serde_json::from_value(serde_json::to_value(&scrubbed).context("scrubbed -> value")?)
            .context("scrubbed -> persist SignedKeyRecord")?;
    // IDEMPOTENT on a CONFIGURED-home restart (#264 ask 3 exposed this): boot 2
    // re-blesses the row boot 1 already upgraded and adopt_scrub_upgrade returns
    // a Conflict ("already anchored") — benign; the row IS blessed. Only a
    // non-conflict error is fatal.
    let outcome = match engine.adopt_scrub_upgrade(persist_rec).await {
        Ok(o) => o,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already anc") || msg.contains("onflict") {
                tracing::info!(
                    key_id = %rec.key_id,
                    "TEST-ANCHOR: self record already blessed (configured-home restart) — continuing"
                );
                return Ok(());
            }
            return Err(anyhow!("adopt the test-root-blessed self record: {e}"));
        }
    };

    tracing::warn!(
        key_id = %rec.key_id,
        test_root = %root_pub_b64,
        ?outcome,
        "TEST-ANCHOR SELF-BLESS ACTIVE — this node is blessed by a SOFTWARE test trust root, \
         NOT the humanity-accord anchor (CIRISServer#258; local harness only)."
    );
    Ok(())
}
