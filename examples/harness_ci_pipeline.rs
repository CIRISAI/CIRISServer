//! The mesh harness's stand-in for a CI pipeline (`scenarios/manifest.sh`).
//!
//! A real pipeline holds its own hybrid keypair, is blessed for `infra:attest`
//! by the accord (`POST /v1/accord/ci-key/{propose,cosign}`), and on each
//! release signs a build-manifest Contribution and publishes it beside the
//! manifest bytes. This does the same three things with the harness's SOFTWARE
//! test root standing in for the accord's hardware holders — which is the only
//! thing about it that is not the production shape.
//!
//! It writes two `POST /v1/builds` bodies into `<out>`:
//!
//! - `blessed.json` — a pipeline the test root granted
//!   `delegates_to(root → pipeline, infra:attest)`;
//! - `unblessed.json` — a second pipeline with a real key, a valid signature
//!   over a manifest that matches, and a record nobody blessed.
//!
//! and `facts.json` naming what each one attests, for the ladder to read.
//!
//!   CIRIS_TEST_TRUST_ROOT_SEED=… cargo run --features test-anchor \
//!       --example harness_ci_pipeline -- <out-dir> [version]

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::federation::envelope::EnvelopeCore;
use ciris_persist::federation::{attestation_emit, EmitAttestationInput};
use ciris_registry_core::fold_builds::{contribution_envelope, BuildFacts, SignedContribution};
use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};
use ciris_verify_core::self_at_login::{HybridSigningIdentity, SelfSigner};
use sha2::{Digest, Sha256};

/// The SW test root, derived exactly as `test_bless::mint_test_root` derives
/// it. Duplicated because that module is private to the crate; the anchor
/// check below is what keeps the two from drifting silently.
fn test_root() -> Result<HybridSigningIdentity> {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer};
    let seed_b64 = std::env::var("CIRIS_TEST_TRUST_ROOT_SEED")
        .map_err(|_| anyhow!("CIRIS_TEST_TRUST_ROOT_SEED is unset"))?;
    let ed_seed: [u8; 32] = B64
        .decode(seed_b64.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| anyhow!("CIRIS_TEST_TRUST_ROOT_SEED must be base64 of 32 bytes"))?;
    let ml_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(ed_seed);
        h.finalize().into()
    };
    let ed = Ed25519Signer::from_seed(&ed_seed).map_err(|e| anyhow!("test-root ed25519: {e}"))?;
    let mldsa =
        MlDsa65Signer::from_seed(&ml_seed).map_err(|e| anyhow!("test-root ml-dsa-65: {e}"))?;
    if let Ok(anchor) = std::env::var("CIRIS_TEST_TRUST_ROOT") {
        let derived = B64.encode(
            ed.public_key()
                .map_err(|e| anyhow!("test-root pubkey: {e}"))?,
        );
        if anchor.trim() != derived {
            return Err(anyhow!(
                "CIRIS_TEST_TRUST_ROOT ({}) is not the key CIRIS_TEST_TRUST_ROOT_SEED derives \
                 ({derived}); a pipeline blessed by this root would not root on the mesh",
                anchor.trim()
            ));
        }
    }
    Ok(HybridSigningIdentity::new(
        "test-accord-holder-0".to_string(),
        ed,
        mldsa,
    ))
}

/// `pipeline`'s key record, scrub-signed by `scrubber`. Blessed when the
/// scrubber is the test root and `roles` carries `infra:attest`; a plain
/// self-signed record when the scrubber is the pipeline itself.
async fn key_record(
    scrubber: &HybridSigningIdentity,
    pipeline: &HybridSigningIdentity,
    roles: &[&str],
) -> Result<serde_json::Value> {
    let member = pipeline
        .directory_member()
        .map_err(|e| anyhow!("pipeline member: {e}"))?;
    let record = produce_scrubbed_key_record(
        scrubber,
        ScrubTarget {
            key_id: pipeline.key_id().to_string(),
            pubkey_ed25519_base64: member.ed25519_public_key_base64,
            pubkey_ml_dsa_65_base64: member
                .mldsa65_public_key_base64
                .ok_or_else(|| anyhow!("pipeline key is not hybrid"))?,
            identity_type: "node".to_string(),
            roles: roles.iter().map(|r| (*r).to_string()).collect(),
        },
        &chrono::Utc::now().to_rfc3339(),
        None,
        &[],
    )
    .await
    .map_err(|e| anyhow!("scrub-sign {}: {e}", pipeline.key_id()))?;
    serde_json::to_value(&record).context("key record -> json")
}

/// Stamp the Contribution through persist's emit chokepoint and sign the
/// canonical bytes with the pipeline's key.
async fn contribution(
    pipeline: &HybridSigningIdentity,
    facts: &BuildFacts,
) -> Result<SignedContribution> {
    let core = EnvelopeCore::from_value(contribution_envelope(facts))
        .map_err(|e| anyhow!("contribution envelope: {e}"))?;
    let mut input = EmitAttestationInput::with_envelope("scores", core, "federation");
    input.attested_key_id = Some(pipeline.key_id().to_string());
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, pipeline.key_id(), chrono::Utc::now())
            .map_err(|e| anyhow!("stamp: {e}"))?;
    let (ed, pqc) = pipeline
        .sign_bound(&canonical)
        .await
        .map_err(|e| anyhow!("pipeline sign: {e}"))?;
    Ok(SignedContribution {
        signed_envelope: input.attestation_envelope.to_value(),
        ed25519_signature_base64: ed,
        mldsa65_signature_base64: pqc,
    })
}

/// The bless: `delegates_to(root → pipeline, infra:attest)` at federation,
/// signed by the root. The same row the harness ceremony mints for a canonical,
/// naming a pipeline instead.
async fn grant(
    root: &HybridSigningIdentity,
    pipeline: &HybridSigningIdentity,
) -> Result<SignedContribution> {
    let envelope = ciris_persist::federation::delegates_to_envelope(
        pipeline.key_id(),
        &["infra:attest".to_string()],
        false,
    );
    let core = EnvelopeCore::from_value(envelope).map_err(|e| anyhow!("grant envelope: {e}"))?;
    let mut input = EmitAttestationInput::with_envelope("delegates_to", core, "federation");
    input.attested_key_id = Some(pipeline.key_id().to_string());
    input.subject_key_ids = vec![pipeline.key_id().to_string()];
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, root.key_id(), chrono::Utc::now())
            .map_err(|e| anyhow!("stamp grant: {e}"))?;
    let (ed, pqc) = root
        .sign_bound(&canonical)
        .await
        .map_err(|e| anyhow!("root sign: {e}"))?;
    Ok(SignedContribution {
        signed_envelope: input.attestation_envelope.to_value(),
        ed25519_signature_base64: ed,
        mldsa65_signature_base64: pqc,
    })
}

fn manifest_for(version: &str, label: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "version": version,
        "files": {
            "ciris_engine/__init__.py": hex::encode(Sha256::digest(label.as_bytes())),
            "ciris_engine/constants.py": hex::encode(Sha256::digest(version.as_bytes())),
        },
    }))
    .expect("manifest json")
}

async fn submission(
    pipeline: &HybridSigningIdentity,
    record: serde_json::Value,
    grant: Option<SignedContribution>,
    version: &str,
) -> Result<(serde_json::Value, BuildFacts)> {
    let manifest = manifest_for(version, pipeline.key_id());
    let facts = BuildFacts {
        target: "python-source-tree".to_string(),
        build_id: format!("harness-{}-{version}", pipeline.key_id()),
        binary_hash: hex::encode(Sha256::digest(format!("artifact:{version}").as_bytes())),
        binary_version: version.to_string(),
        manifest_hash: hex::encode(Sha256::digest(&manifest)),
        manifest_size: manifest.len() as u64,
    };
    let body = serde_json::json!({
        "contribution": contribution(pipeline, &facts).await?,
        "manifest_base64": B64.encode(&manifest),
        "pipeline_record": record,
        "pipeline_grant": grant,
    });
    Ok((body, facts))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let out = std::path::PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow!("usage: <out-dir> [version]"))?,
    );
    let version = args.next().unwrap_or_else(|| "9.9.9".to_string());
    std::fs::create_dir_all(&out).with_context(|| format!("create {}", out.display()))?;

    let root = test_root()?;
    let suffix = hex::encode(&Sha256::digest(chrono::Utc::now().to_rfc3339().as_bytes())[..4]);

    let blessed = HybridSigningIdentity::generate(format!("harness-ci-blessed-{suffix}"))
        .map_err(|e| anyhow!("mint blessed pipeline: {e}"))?;
    // The record is scrub-signed by the root so the pipeline's announces root;
    // the GRANT is what blesses it. A role on the record alone does not: the
    // capability walk reads a co-scrubbed record as "this key is a root".
    let blessed_record = key_record(&root, &blessed, &["infra:attest"]).await?;
    let blessed_grant = grant(&root, &blessed).await?;
    let (blessed_body, blessed_facts) =
        submission(&blessed, blessed_record, Some(blessed_grant), &version).await?;

    let unblessed = HybridSigningIdentity::generate(format!("harness-ci-unblessed-{suffix}"))
        .map_err(|e| anyhow!("mint unblessed pipeline: {e}"))?;
    let unblessed_record = key_record(&unblessed, &unblessed, &[]).await?;
    let unblessed_version = format!("{version}-unblessed");
    let (unblessed_body, unblessed_facts) =
        submission(&unblessed, unblessed_record, None, &unblessed_version).await?;

    let write = |name: &str, v: &serde_json::Value| -> Result<()> {
        let path = out.join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(v)?)
            .with_context(|| format!("write {}", path.display()))
    };
    write("blessed.json", &blessed_body)?;
    write("unblessed.json", &unblessed_body)?;
    write(
        "facts.json",
        &serde_json::json!({
            "blessed": { "pipeline_key_id": blessed.key_id(), "facts": blessed_facts },
            "unblessed": { "pipeline_key_id": unblessed.key_id(), "facts": unblessed_facts },
        }),
    )?;
    println!(
        "pipeline {} (blessed for infra:attest by {}) signed {} manifest {}",
        blessed.key_id(),
        root.key_id(),
        blessed_facts.binary_version,
        blessed_facts.manifest_hash
    );
    println!(
        "pipeline {} (blessed by nobody) signed {} manifest {}",
        unblessed.key_id(),
        unblessed_facts.binary_version,
        unblessed_facts.manifest_hash
    );
    Ok(())
}
