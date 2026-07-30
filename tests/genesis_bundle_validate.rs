//! Validate a REAL minted `GenesisBundle` by running stage 1 against it.
//!
//! Point it at a bundle and it answers the only question that matters:
//!
//!     Given a fresh node holding nothing but this bundle, does
//!     `capability_roots_to_trusted_root(node, serve_node, "infra:serve")` resolve?
//!
//!     CIRIS_GENESIS_BUNDLE=~/genesis_2.json cargo test --test genesis_bundle_validate -- --nocapture
//!
//! Skips (loudly) when the env var is unset, so CI stays green without the
//! artifact — a ceremony output is not a repo file.
//!
//! This is `scenarios/genesis_seed.sh` (arm B) in-process: same preconditions,
//! seconds instead of minutes, and no docker. It exists because "the bundle looks
//! right" is a reading of JSON, and every expensive mistake in this arc came from
//! reading a field and inferring behaviour instead of executing the gate. It
//! reports EVERY unmet precondition rather than stopping at the first — they are
//! independent facts, and collapsing them is what let four defects look like one.

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::algorithm;
use ciris_persist::federation::{KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::FederationDirectory;
use ed25519_dalek::SigningKey;

use ciris_server::mesh_genesis::{
    accept_trust_root, charter_root_key_id, install_trust_root_records, verify_bundle,
    verify_bundle_structure, GenesisBundle,
};

const NODE_KEY_ID: &str = "ciris-validator-node-1";

fn bundle_path() -> Option<std::path::PathBuf> {
    let raw = std::env::var("CIRIS_GENESIS_BUNDLE").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // `~` is not expanded by the shell inside an env assignment in every form.
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        std::path::PathBuf::from(std::env::var("HOME").ok()?).join(rest)
    } else {
        std::path::PathBuf::from(raw)
    };
    Some(expanded)
}

async fn fresh_node() -> Arc<Engine> {
    use ciris_keyring::PqcSigner as _;
    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let signing_key_pub = signing_key.verifying_key().to_bytes();
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0x5B; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("validator ML-DSA-65 seed"),
    );
    let mldsa_pub = pqc.public_key().await.expect("validator ML-DSA-65 pubkey");
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    );

    // Production registers the node's own key BEFORE stage 1 (compose.rs:208
    // `register_self_key` precedes `install_baked_trust_root` at :219; the agent
    // path pre-registers its row). Without it `accept_trust_root` fails with
    // "attesting_key_id ... does not exist in federation_keys" — a fixture
    // artifact, not a bundle defect, and reporting it as one would send persist
    // chasing a bug that is not there.
    let node_key_id = engine
        .local_derived_key_id()
        .await
        .expect("node identity resolves");
    let ed_pub = BASE64.encode(signing_key_pub);
    let now = chrono::Utc::now();
    let record = KeyRecord {
        key_id: node_key_id.clone(),
        pubkey_ed25519_base64: ed_pub.clone(),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(&mldsa_pub)),
        algorithm: algorithm::HYBRID.into(),
        identity_type: "node".to_string(),
        identity_ref: node_key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({ "key_id": node_key_id }),
        original_content_hash: "de".repeat(32),
        scrub_signature_classical: ed_pub,
        scrub_signature_pqc: None,
        scrub_key_id: node_key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .sqlite_backend()
        .expect("sqlite backend present")
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the validator node's own key");

    engine
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_bundle_makes_a_fresh_node_serve() {
    let Some(path) = bundle_path() else {
        eprintln!(
            "SKIP: set CIRIS_GENESIS_BUNDLE=<path to a minted bundle> to validate one.\n\
             This test is the in-process form of harness arm B."
        );
        return;
    };

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read bundle {}: {e}", path.display()));

    // ── 1. it parses as persist's type ──────────────────────────────────────
    let bundle: GenesisBundle = serde_json::from_str(&raw).unwrap_or_else(|e| {
        panic!(
            "NOT A BUNDLE — {} does not deserialize as persist's GenesisBundle: {e}\n\
             The seed is a GenesisBundle and that is the only shape.",
            path.display()
        )
    });

    println!("\n═══ bundle: {} ═══", path.display());
    println!("  version            {}", bundle.version);
    println!("  family_key_id      {}", bundle.family_key_id);
    println!("  consensus_protocol {}", bundle.consensus_protocol);
    println!("  holders            {}", bundle.holders.len());
    println!("  serve_nodes        {}", bundle.serve_nodes.len());
    println!("  attestations       {}", bundle.attestations.len());
    println!("  authorizations     {}", bundle.authorizations.len());
    println!("  produced_at        {}", bundle.produced_at);

    let mut failures: Vec<String> = Vec::new();
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("  {} {name}{}", if ok { "✓" } else { "✗" }, {
            if detail.is_empty() {
                String::new()
            } else {
                format!(" — {detail}")
            }
        });
        if !ok {
            failures.push(format!("{name}: {detail}"));
        }
    };

    // ── 2. persist's own verifiers ──────────────────────────────────────────
    println!("\n─── verification ───");
    match verify_bundle_structure(&bundle) {
        Ok(()) => check("structure", true, String::new()),
        Err(e) => check("structure", false, e.to_string()),
    }
    match verify_bundle(&bundle) {
        Ok(()) => check("signatures + quorum", true, String::new()),
        Err(e) => check("signatures + quorum", false, e.to_string()),
    }

    let root = charter_root_key_id(&bundle);
    check(
        "charter root",
        root.is_some(),
        root.clone()
            .unwrap_or_else(|| "NONE — nothing to accept".into()),
    );

    // ── 3. stage 1, for real ────────────────────────────────────────────────
    println!("\n─── stage 1 (install + accept) ───");
    let engine = fresh_node().await;

    let report = install_trust_root_records(engine.federation_directory().as_ref(), &bundle).await;
    match &report {
        Ok(r) => check(
            "install records",
            true,
            format!(
                "holders={} serve_nodes={} attestations={} root={}",
                r.holders_seeded, r.serve_nodes_seeded, r.attestations_seeded, r.trust_root_key_id
            ),
        ),
        Err(e) => check("install records", false, e.to_string()),
    }

    match accept_trust_root(&engine, &bundle).await {
        Ok(Some(r)) => check("accept trust root", true, format!("trust:accepts -> {r}")),
        Ok(None) => check(
            "accept trust root",
            false,
            "no-op — no charter root, or this node IS the root".into(),
        ),
        Err(e) => check("accept trust root", false, e.to_string()),
    }

    // ── 4. the question ─────────────────────────────────────────────────────
    println!("\n─── the serve gate ───");
    let node_key_id = engine
        .local_derived_key_id()
        .await
        .expect("node identity resolves");

    // The PRODUCTION entry point. Note it resolves the accord roster from the
    // BAKED genesis — which does not yet contain this bundle's holders. So the
    // AccordCoScrub plane cannot pass here by construction, and a pass proves the
    // DELEGATION plane (charter -> confers -> this node's trust:accepts) carries
    // it alone. That is the stronger result: delegation is the plane that works
    // before the bake, and therefore the one that makes the bundle bakeable.
    let dir = engine.federation_directory();
    for n in &bundle.serve_nodes {
        let serve_key = &n.record.key_id;
        let resolved = ciris_persist::federation::trust_root::capability_roots_to_trusted_root(
            dir.as_ref(),
            &node_key_id,
            serve_key,
            "infra:serve",
        )
        .await;
        match resolved {
            Ok(Some(r)) => check(
                &format!("infra:serve for {serve_key}"),
                true,
                format!("roots to {r:?}"),
            ),
            Ok(None) => check(
                &format!("infra:serve for {serve_key}"),
                false,
                "capability_roots_to_trusted_root returned None — this node would WITHHOLD \
                 every trace:* row to it"
                    .into(),
            ),
            Err(e) => check(
                &format!("infra:serve for {serve_key}"),
                false,
                e.to_string(),
            ),
        }
    }

    println!();
    assert!(
        failures.is_empty(),
        "\n{} precondition(s) unmet — this bundle does NOT yet make a fresh node serve:\n{}\n\n\
         Each line is an INDEPENDENT fact, not a pipeline. See FSD/GENESIS_TO_SCORE.md.\n",
        failures.len(),
        failures
            .iter()
            .map(|f| format!("  ✗ {f}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );

    println!("═══ VALID — a fresh node holding only this bundle resolves infra:serve ═══\n");
}

/// ISOLATE the blocker: is the delegation plane itself sound?
///
/// The full install aborts on the FIRST holder (persist refuses its
/// `attestation_evidence`), so nothing lands and every downstream check fails
/// for one upstream reason. That is the "four defects that were one" shape, and
/// the honest way to tell them apart is to remove the blocked step and re-ask.
///
/// So: install the serve nodes and the delegation plane ONLY — no holders — and
/// ask the serve gate again. This fabricates nothing. If it resolves, the
/// charter → confers → trust:accepts chain is correct and the holder-evidence
/// refusal is the SOLE blocker; if it does not, the bundle has a second, real
/// problem and persist needs to hear about both.
#[tokio::test(flavor = "multi_thread")]
async fn the_delegation_plane_alone_resolves_the_serve_gate() {
    let Some(path) = bundle_path() else {
        eprintln!("SKIP: set CIRIS_GENESIS_BUNDLE to isolate the blocker.");
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("read bundle");
    let bundle: GenesisBundle = serde_json::from_str(&raw).expect("parse bundle");

    let engine = fresh_node().await;
    let dir = engine.federation_directory();

    for n in &bundle.serve_nodes {
        dir.put_public_key(n.clone())
            .await
            .expect("serve node record installs");
    }
    let mut attestation_errors = Vec::new();
    for a in &bundle.attestations {
        if let Err(e) = dir.put_attestation(a.clone()).await {
            attestation_errors.push(format!("{:?}: {e}", a.attestation.attestation_id));
        }
    }
    assert!(
        attestation_errors.is_empty(),
        "the delegation plane itself does not ingest — a SECOND defect beyond the holder \
         evidence:\n  {}",
        attestation_errors.join("\n  ")
    );

    accept_trust_root(&engine, &bundle)
        .await
        .expect("accept trust root")
        .expect("a charter root to accept");

    let node_key_id = engine.local_derived_key_id().await.expect("node identity");
    for n in &bundle.serve_nodes {
        let serve_key = &n.record.key_id;
        let grant = ciris_persist::federation::trust_root::capability_roots_to_trusted_root(
            dir.as_ref(),
            &node_key_id,
            serve_key,
            "infra:serve",
        )
        .await
        .expect("walk runs");
        println!("  delegation-plane-only: infra:serve for {serve_key} -> {grant:?}");
        assert!(
            grant.is_some(),
            "even WITHOUT the blocked holder records, infra:serve for {serve_key} does not \
             resolve — the charter/confers/accepts chain has its own defect"
        );
    }
    println!("\n  => the holder attestation_evidence refusal is the SOLE blocker.\n");
}

/// THE PRODUCTION ASSERTION — no env var, no external artifact.
///
/// persist v23.1.0 bakes the real ceremony bundle as `canonical_seed.json`, so
/// every wheel now ships it and every fresh node installs it at boot. This runs
/// that exact path — `install_baked_trust_root`, the same call both boot paths
/// make — and asserts the node ends up able to serve.
///
/// This is the test that could not exist until today: before the bake the baked
/// bundle was empty, so stage 1 correctly did nothing and there was no end state
/// to assert. It is now a standing regression gate on the whole of stage 0+1 —
/// if a future substrate bump breaks the seed, the ceremony, or the walk, this
/// goes red in ~1s instead of surfacing as silently withheld traces in the field.
#[tokio::test(flavor = "multi_thread")]
async fn the_baked_seed_makes_every_fresh_node_serve() {
    let engine = fresh_node().await;

    ciris_server::mesh_genesis::install_baked_trust_root(&engine)
        .await
        .expect("stage 1 installs the baked trust root");

    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    assert!(
        !baked.holders.is_empty() && !baked.attestations.is_empty(),
        "the BAKED bundle is empty (holders={}, attestations={}) — stage 1 ran and installed \
         nothing. Every node would withhold every trace:* row.",
        baked.holders.len(),
        baked.attestations.len()
    );

    let node_key_id = engine.local_derived_key_id().await.expect("node identity");
    let dir = engine.federation_directory();

    for n in &baked.serve_nodes {
        let serve_key = &n.record.key_id;
        let grant = ciris_persist::federation::trust_root::capability_roots_to_trusted_root(
            dir.as_ref(),
            &node_key_id,
            serve_key,
            "infra:serve",
        )
        .await
        .expect("walk runs");
        let grant = grant.unwrap_or_else(|| {
            panic!(
                "a fresh node holding the BAKED seed cannot serve {serve_key} — \
                 capability_roots_to_trusted_root returned None"
            )
        });
        assert!(
            grant.verdict.valid,
            "trust_root_valid is false for {serve_key}: {:?}",
            grant.verdict
        );
        println!(
            "  baked seed: infra:serve for {serve_key} -> root {} via {:?} (drill {:?})",
            grant.root_key_id, grant.conferral_plane, grant.verdict.drill_freshness
        );
    }
}
