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

/// **Install stage 1 — or witness that the baked seed predates the ceremony.**
///
/// Returns `true` when the baked bundle installed, `false` when it is the pre-v31
/// artifact this release ships with (having first asserted that persist REFUSES
/// it, which is the whole point).
///
/// # Why the assertion inverts on the artifact instead of being skipped
///
/// persist v31 binds the seven typed columns and the two instants into the signed
/// envelope (CIRISPersist#643/#598). The baked `canonical_seed.json` was signed
/// before those bindings existed, so its `genesis-charter` / `genesis-grant:…` /
/// `genesis-lifecycle` rows are refused at every `put_attestation` — correctly,
/// and that gate must not be weakened to admit a stale artifact: a genesis-shaped
/// carve-out would be a permanent hole in exactly the rows that grant everything.
///
/// So these gates ask persist's own predicate which regime the artifact is in,
/// and assert the REFUSAL while it is pre-v31 and INSTALLATION once it is
/// re-signed. The expectation flips on the seed, not on a hand-edited constant —
/// which means the re-bake turns these witnesses back on by itself and nobody has
/// to remember to. A `#[ignore]` would have gone quiet forever.
async fn install_or_witness_pre_v31(engine: &Arc<Engine>) -> bool {
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let outcome = ciris_server::mesh_genesis::install_baked_trust_root(engine).await;
    match ciris_persist::federation::genesis::bundle_delegation_plane_v31_shaped(baked) {
        Ok(()) => {
            outcome.expect("a v31-shaped baked bundle must install — stage 1 is the boot path");
            true
        }
        Err(why) => {
            let e = outcome.expect_err(&format!(
                "the baked bundle is NOT v31-shaped ({why}), so its delegation rows must be \
                 REFUSED. Stage 1 reporting success here would mean the binding gate had been \
                 weakened for genesis rows — a permanent hole in the rows that grant everything."
            ));
            println!("  baked seed is pre-v31 ({why}); stage 1 refused as it must: {e}");
            false
        }
    }
}

/// The store every check in this file runs against.
///
/// **`sqlite::memory:` unless told otherwise** — and being told otherwise is the
/// entire point (CIRISServer#382). Set `CIRIS_TEST_DSN` to a Postgres URL and
/// every genesis check below re-runs against it unchanged.
///
/// # Why this knob exists
///
/// The genesis validation was sqlite-only, and SQLite is the backend that
/// **cannot** see the class of defect it is supposed to catch. `CIRISServer#381`
/// is the proof: the baked bundle signs symbolic attestation ids
/// (`genesis-charter`, `genesis-grant:…`, `genesis-lifecycle`), Postgres had
/// them in a `uuid`-typed column, and stage 1 aborted at character 0. SQLite has
/// no `uuid` type, so the column is TEXT and the identical bundle stored fine.
///
/// Same binary, same constant, same value; only Postgres refused. Two production
/// agents crash-looped 151 and 223 times while this suite was green — it was
/// green *because* it only ever asked the backend that was immune.
///
/// A validator that runs on one backend does not validate a bundle; it validates
/// a bundle **on that backend**. Those are different claims, and shipping the
/// first while proving the second is what put this in front of operators.
fn dsn() -> String {
    std::env::var("CIRIS_TEST_DSN").unwrap_or_else(|_| "sqlite::memory:".to_string())
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
    let target = dsn();
    let engine = Arc::new(
        Engine::with_signer(signer, &target)
            .await
            .unwrap_or_else(|e| panic!("engine over `{target}`: {e}")),
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
    // FIXED, not `Utc::now()`. Every test in this file calls `fresh_node()`, and
    // on `sqlite::memory:` each got a private database, so a per-call timestamp
    // was invisible. Against one shared Postgres they all write the SAME key id
    // with a DIFFERENT `valid_from`, and persist correctly refuses the second:
    //
    //   Conflict("key_id ciris-validator-node-1-… already exists with
    //            different content")
    //
    // The node identity here is already deterministic (a fixed `0x5A` seed); the
    // clock was the one non-deterministic field in an otherwise fixed record.
    // Pinning it makes re-registration idempotent, which is what "fresh node"
    // has to mean on a backend where the store outlives the test.
    let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("fixed fixture timestamp");
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
    // Through the TRAIT, never a concrete backend accessor. `put_public_key` is
    // a `FederationDirectory` method, so this one line works on every backend —
    // and reaching past the trait for a concrete one is precisely how this
    // fixture pinned itself to the backend that could not fail (`src/backend.rs`
    // documents the thirty other sites that did the same).
    //
    // The needle is deliberately NOT spelled here: `no_concrete_backend_reach`
    // below scans this file, and a comment naming the pattern would satisfy the
    // scan with its own documentation.
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register the validator node's own key");

    engine
}

/// **Reports `ignored`, never `ok`, when it has no bundle to check.**
///
/// It used to `return` early with an eprintln when `CIRIS_GENESIS_BUNDLE` was
/// unset, which made the run print `test result: ok` for a check that examined
/// nothing. On 2026-08-14 that line was read as "the ceremony path is verified"
/// and a two-holder seed ceremony was run on the strength of it; the ceremony
/// then failed on CIRISPersist#683, which this test would have caught had it
/// ever been given a bundle.
///
/// A check that could not run must not be counted as a check that passed — the
/// same distinct-zeroes rule the rest of this suite applies to the substrate,
/// applied to the suite itself. `#[ignore]` says "not run" in the result line,
/// and running it explicitly with no bundle now FAILS rather than no-ops.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a minted bundle: CIRIS_GENESIS_BUNDLE=<path> cargo test --test \
            genesis_bundle_validate -- --ignored"]
async fn a_real_bundle_makes_a_fresh_node_serve() {
    let path = bundle_path().expect(
        "CIRIS_GENESIS_BUNDLE is unset — this test validates a REAL minted bundle and \
         has nothing to validate. It is `#[ignore]`d precisely so an absent bundle is \
         never mistaken for a passing check; if you ran it explicitly, point it at a seed.",
    );

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

    // Engine construction seeds the BAKED genesis (engine.rs -> seed_family_and_canonical),
    // so this node already holds the CURRENTLY-baked canonical record before stage 1
    // runs. A candidate that re-blesses that canonical carries a DIFFERENT record
    // (new roles in the signed envelope), and persist rightly refuses to replace an
    // anchored row — so validating a candidate against a node whose bake is the OLD
    // artifact fails on a conflict that says nothing about the candidate.
    //
    // Drop the stale rows first: after persist bakes THIS bundle, the seeded record
    // IS this record and the install is a no-op match. That post-bake state is what
    // we mean by "a fresh node holding only this bundle".
    for n in &bundle.serve_nodes {
        let _ = engine
            .federation_directory()
            // persist v38.0.0 requires a REASON and the delegation acted under.
            // Peer removal is an accountable act now, and a test is not exempt
            // from saying why — a blank reason here would be the first
            // meaningless entry in an audit trail built to carry meaning.
            // `None` delegation is accurate: this is the harness acting
            // directly, not on anyone's authority.
            .remove_peer_record(
                &n.record.key_id,
                true,
                "genesis_bundle_validate: clearing seeded serve-node rows so the \
                 bundle installs onto a node holding only itself",
                None,
            )
            .await;
    }

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

    // ── 3b. did the quorum survive into the ROWS? (#556) ────────────────────
    println!("\n─── quorum in the graph (#556) ───");
    for sa in &bundle.attestations {
        let at = &sa.attestation;
        let n = at.distinct_scrub_count();
        let who: Vec<String> = at.scrubs().iter().map(|x| x.scrub_key_id.clone()).collect();
        check(
            &format!("scrubs on {}", at.attestation_id),
            n >= 2,
            format!("{n} distinct {who:?}"),
        );
    }

    // ── 3c. is the drill ABOUT THE ROOT? (born Green, not Red) ──────────────
    // The drill leg reads attestations ABOUT the root, and under family rooting
    // the root is the family. A heartbeat naming a holder is a drill about that
    // holder — persist, trust_root.rs ~864. It gates nothing, but a root born
    // reading "never drilled" is a bad birth announcement for a production trust
    // root, and it is free to get right at mint time.
    if let Some(root_id) = &root {
        let hb = bundle
            .attestations
            .iter()
            .map(|a| &a.attestation)
            .find(|a| a.attestation_id == ciris_server::mesh_genesis::LIFECYCLE_ATTESTATION_ID);
        match hb {
            Some(h) => check(
                "heartbeat is about the root",
                &h.attested_key_id == root_id,
                format!("attested {} (root is {root_id})", h.attested_key_id),
            ),
            None => check(
                "heartbeat is about the root",
                false,
                "no genesis-lifecycle row — the root is born with drill_freshness Red".into(),
            ),
        }
    }

    // ── 4. the question ─────────────────────────────────────────────────────
    println!("\n─── the serve gate: EVERY scope, BOTH planes ───");
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
        for scope in ciris_server::mesh_genesis::SERVE_NODE_SCOPES {
            let grant = ciris_persist::federation::trust_root::capability_roots_to_trusted_root(
                dir.as_ref(),
                &node_key_id,
                serve_key,
                scope,
            )
            .await;
            // Read the co-scrub plane off the BUNDLE'S RECORD, not the installed
            // row. The installed row is whatever the engine seeded from the
            // CURRENTLY-baked genesis, and persist refuses to replace an anchored
            // record — so on a node whose bake is the older artifact, the directory
            // keeps the OLD roles no matter how good the candidate is. Measuring
            // that would report the stale bake, not the bundle under test.
            //
            // Post-bake the seeded record IS this record, so the bundle's
            // registration_envelope.roles is exactly what has_accord_conferred_role
            // will read in production. Same surface, read from the artifact.
            let coscrub = ciris_server::mesh_genesis::carries_scope(n, scope);
            match grant {
                Ok(Some(g)) => {
                    check(
                        &format!("{scope:16} delegation"),
                        true,
                        format!(
                            "root {} kind {:?} plane {:?}",
                            g.root_key_id, g.verdict.root_kind, g.conferral_plane
                        ),
                    );
                    // #557 acceptance. A mis-shaped family charter does NOT error —
                    // solo 1-of-1 roots stay valid on purpose — so it yields a
                    // WORKING single-key root. Assert the axis explicitly.
                    check(
                        &format!("{scope:16} root_kind=Family"),
                        g.verdict.root_kind
                            == ciris_persist::federation::trust_root::RootKind::Family,
                        format!("{:?}", g.verdict.root_kind),
                    );
                    check(
                        &format!("{scope:16} plane=FamilyQuorum"),
                        g.conferral_plane
                            == ciris_persist::federation::trust_root::ConferralPlane::FamilyQuorum,
                        format!("{:?}", g.conferral_plane),
                    );
                }
                Ok(None) => check(
                    &format!("{scope:16} delegation"),
                    false,
                    "None — capability does not root to a trusted root".into(),
                ),
                Err(e) => check(&format!("{scope:16} delegation"), false, e.to_string()),
            }
            check(
                &format!("{scope:16} co-scrub"),
                coscrub,
                if coscrub {
                    String::new()
                } else {
                    "absent from registration_envelope.roles".into()
                },
            );
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

    if !install_or_witness_pre_v31(&engine).await {
        return;
    }

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
            "  baked seed: infra:serve for {serve_key} -> root {} via {:?} (drill {:?}, kind {:?})",
            grant.root_key_id,
            grant.conferral_plane,
            grant.verdict.drill_freshness,
            grant.verdict.root_kind,
        );
        // #557 acceptance: the root must be the FAMILY, reached by quorum.
        //
        // Asserted explicitly because a subtly-wrong family shape does NOT error
        // — persist keeps solo 1-of-1 roots valid on purpose, so a mis-shaped
        // charter or a grant with only one seated signer yields a WORKING
        // single-key root pointing at A1. Silent success is the failure mode
        // here, so intent is declared in the test rather than inferred from a
        // green walk.
        assert_eq!(
            grant.verdict.root_kind,
            ciris_persist::federation::trust_root::RootKind::Family,
            "root_kind is {:?}, not Family — the charter is not family-shaped, or the \
             family row was never seeded, so this degraded to a single-seat root at {}",
            grant.verdict.root_kind,
            grant.root_key_id,
        );
        assert_eq!(
            grant.conferral_plane,
            ciris_persist::federation::trust_root::ConferralPlane::FamilyQuorum,
            "conferral_plane is {:?}, not FamilyQuorum — the grant's verified signer set \
             did not reach the family threshold, so it roots to one seat",
            grant.conferral_plane,
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn baked_audit() {
    let engine = fresh_node().await;
    if !install_or_witness_pre_v31(&engine).await {
        return;
    }
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let dir = engine.federation_directory();

    println!(
        "\n── CO-SCRUB plane (has_accord_conferred_role, reads registration_envelope.roles) ──"
    );
    for n in &baked.serve_nodes {
        for scope in ["infra:serve", "infra:attest"] {
            let r = ciris_persist::federation::admission::has_accord_conferred_role(
                dir.as_ref(),
                &n.record.key_id,
                scope,
            )
            .await;
            println!("   {:14} {} -> {:?}", scope, n.record.key_id, r);
        }
    }

    println!("\n── installed attestation rows: tier + cohort ──");
    for a in &baked.attestations {
        let at = &a.attestation;
        println!(
            "   {:44} type={} tier={:?}",
            at.attestation_id, at.attestation_type, at.tier
        );
    }

    println!("\n── holder records: scrub count ──");
    for h in &baked.holders {
        println!(
            "   {:6} identity_type={:20} scrub={} additional={}",
            h.record.key_id,
            h.record.identity_type,
            h.record.scrub_key_id,
            h.record.additional_scrubs.len()
        );
    }
    for n in &baked.serve_nodes {
        println!(
            "   {:6} identity_type={:20} scrub={} additional={} roles={:?}",
            n.record.key_id,
            n.record.identity_type,
            n.record.scrub_key_id,
            n.record.additional_scrubs.len(),
            n.record.capability_roles
        );
    }
}

/// THE GATE THAT WAS MISSING — both planes, every required scope.
///
/// 0.5.141 shipped a baked root whose canonical could `infra:serve` and nothing
/// else: `capability_roots_to_trusted_root(.., "infra:attest")` returned None
/// and `has_accord_conferred_role(.., "infra:attest")` returned false. Nothing
/// caught it because every test in the tree asked for `infra:serve` — edge's
/// gate is hardcoded to SERVE_CAPABILITY, and this file's own validator looped
/// the serve nodes asking for the literal "infra:serve". A suite that asks one
/// question cannot fail the others, and it reads as a general verdict.
///
/// So this asserts the FULL required set on BOTH conferral planes:
///
///   * DELEGATION  — the grant's `scope`, walked by capability_roots_to_trusted_root
///   * CO-SCRUB    — the key record's registration_envelope.roles, read by
///                   has_accord_conferred_role
///
/// Both must carry every scope. A node that resolves a capability on one plane
/// and not the other is the axis split that has cost this project an arc.
#[tokio::test(flavor = "multi_thread")]
async fn the_baked_canonical_holds_every_scope_on_both_planes() {
    let engine = fresh_node().await;
    if !install_or_witness_pre_v31(&engine).await {
        return;
    }
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let node_key_id = engine.local_derived_key_id().await.expect("node identity");
    let dir = engine.federation_directory();

    let required = ciris_server::mesh_genesis::SERVE_NODE_SCOPES;
    let mut missing: Vec<String> = Vec::new();

    for n in &baked.serve_nodes {
        let key = &n.record.key_id;
        for scope in required {
            let delegation =
                ciris_persist::federation::trust_root::capability_roots_to_trusted_root(
                    dir.as_ref(),
                    &node_key_id,
                    key,
                    scope,
                )
                .await
                .expect("walk runs")
                .is_some();
            let coscrub = ciris_persist::federation::admission::has_accord_conferred_role(
                dir.as_ref(),
                key,
                scope,
            )
            .await
            .expect("co-scrub read runs");

            println!(
                "  {key} {scope:18} delegation={} co-scrub={}",
                if delegation { "✓" } else { "✗" },
                if coscrub { "✓" } else { "✗" },
            );
            if !delegation {
                missing.push(format!(
                    "{key}: {scope} does NOT resolve on the DELEGATION plane"
                ));
            }
            if !coscrub {
                missing.push(format!(
                    "{key}: {scope} is NOT conferred on the CO-SCRUB plane"
                ));
            }
        }
    }

    assert!(
        !baked.serve_nodes.is_empty(),
        "the baked bundle has no serve nodes — nothing to check"
    );
    assert!(
        missing.is_empty(),
        "\nthe baked root does not confer every required scope on both planes:\n{}\n\n\
         Required (mesh_genesis::SERVE_NODE_SCOPES): {:?}\n\
         A canonical serves, vouches, stores and relays — see SERVE_NODE_SCOPES for what each is.\n\
         This needs a re-mint: `scope` and `roles` are both inside signed envelopes, and \n\
         `attestation_envelope` is covered by authorization_digest, so it cannot be patched.\n",
        missing
            .iter()
            .map(|m| format!("  ✗ {m}"))
            .collect::<Vec<_>>()
            .join("\n"),
        required,
    );
}

/// Stage 1 must be IDEMPOTENT. Running it twice is the normal case — every boot
/// after the first re-installs a bundle whose rows are already present.
///
/// It was not. Genesis attestation ids are stable (`genesis-charter`,
/// `genesis-grant:<node>`, `genesis-lifecycle`), so the second run hit
/// `UNIQUE constraint failed: federation_attestations.attestation_id`, aborted,
/// and the caller logged "this node has no trust root and will withhold every
/// trace:* row" — while the charter, grant, trust edge and heartbeat were all
/// present and correct. Observed on the production canonical; it sent three
/// people hunting a delivery bug that did not exist.
#[tokio::test(flavor = "multi_thread")]
async fn stage_one_is_idempotent_across_reboots() {
    let engine = fresh_node().await;

    // Idempotence is asserted in BOTH regimes: a pre-v31 seed must refuse the same
    // way every time (a refusal that becomes a success on run 2 would mean the
    // first run left rows behind), and a v31 seed must install the same way.
    let mut installed = false;
    for run in 1..=3 {
        let ok = install_or_witness_pre_v31(&engine).await;
        if run == 1 {
            installed = ok;
        } else {
            assert_eq!(
                ok, installed,
                "stage 1 run {run} reached a DIFFERENT outcome than run 1. It must be idempotent \
                 in both regimes — a refusal that turns into a success means the refused run \
                 left rows behind."
            );
        }
    }
    if !installed {
        return;
    }

    // And the trust root is still good after the repeats, not merely un-errored.
    let baked = ciris_persist::federation::genesis::canonical_genesis_bundle();
    let node_key_id = engine.local_derived_key_id().await.expect("node identity");
    let dir = engine.federation_directory();
    for n in &baked.serve_nodes {
        let grant = ciris_persist::federation::trust_root::capability_roots_to_trusted_root(
            dir.as_ref(),
            &node_key_id,
            &n.record.key_id,
            "infra:serve",
        )
        .await
        .expect("walk runs")
        .expect("infra:serve still resolves after three stage-1 runs");
        assert!(
            grant.verdict.valid,
            "verdict after repeats: {:?}",
            grant.verdict
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The two guards that keep CIRISServer#382 fixed.
//
// Making the fixture backend-parametric is worth nothing on its own: the knob
// defaults to sqlite, so a suite that never sets it is sqlite-only again with
// every test still reporting `ok`. These assert the two ways it can silently
// revert — the fixture reaching past the trait, and CI not running the other
// backend at all.
// ─────────────────────────────────────────────────────────────────────────────

/// **This fixture must not reach for a concrete backend.**
///
/// `tests/backend_parity.rs` walks `src/` only, which is how the reach in this
/// file survived while that gate was green — a gate scoped to one directory
/// making a claim about the crate. (The broader `tests/` sweep is ~20 files and
/// deliberately not attempted here; several are legitimately sqlite-specific.)
#[test]
fn no_concrete_backend_reach() {
    let src = include_str!("genesis_bundle_validate.rs");
    // SPLIT so this predicate cannot match itself, the same discipline persist
    // uses in `attestation_id_is_text_622`.
    let needles = [
        format!("sqlite{}()", "_backend"),
        format!("postgres{}()", "_backend"),
    ];
    let mut offenders = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let l = line.trim_start();
        if l.starts_with("//") || l.starts_with("///") || l.starts_with("//!") {
            continue;
        }
        for n in &needles {
            if line.contains(n.as_str()) {
                offenders.push(format!("  line {}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the genesis validator reaches past `FederationDirectory` for a concrete backend:\n{}\n\n\
         That pins these checks to ONE backend. It is how CIRISServer#381 shipped: the \
         validation ran only on SQLite, which has no `uuid` type and therefore could not \
         see the defect that crash-looped two Postgres agents 151 and 223 times.",
        offenders.join("\n")
    );
}

/// **CI must actually RUN this against Postgres.**
///
/// Compilation coverage is not execution coverage, and a parametric fixture with
/// nobody passing the parameter is sqlite-only with extra steps. So this asserts
/// the workflow leg exists, by the same reasoning as the release ladder's
/// `assert_proven`: the property is "it ran on the other backend", and only
/// `.github/workflows/` can witness that.
#[test]
fn ci_runs_the_genesis_validation_on_postgres() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{} unreadable — this gate cannot run: {e}", dir.display()));

    let mut witness: Option<String> = None;
    for p in entries.flatten().map(|e| e.path()) {
        if !p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            continue;
        }
        let raw = std::fs::read_to_string(&p).unwrap_or_default();
        // Comments stripped BEFORE matching: a note explaining the leg must not
        // be able to stand in for the leg.
        let code: String = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        if code.contains("CIRIS_TEST_DSN") && code.contains("genesis_bundle_validate") {
            witness = Some(p.file_name().unwrap().to_string_lossy().into_owned());
            break;
        }
    }

    assert!(
        witness.is_some(),
        "NO workflow runs `genesis_bundle_validate` with `CIRIS_TEST_DSN` set.\n\n\
         The fixture is backend-parametric, but the parameter defaults to sqlite — so \
         with no CI leg passing a Postgres DSN, every genesis check reports `ok` having \
         asked only the backend that is structurally unable to fail (CIRISServer#382).\n\n\
         That is not a hypothetical: it is the exact state in which CIRISServer#381 \
         reached production."
    );
}
