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
use ciris_persist::federation::types::{attestation_type, cohort_scope};
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

/// The ONE runtime fence both test-anchor entry points gate through — the composed
/// node's [`maybe_test_bless_self`] AND the bare agent's
/// [`maybe_test_bless_delivery_self`]. `test-anchor` being compiled in is the
/// compile-time wall; at runtime the bless/ceremony additionally requires
/// `CIRIS_TESTING_MODE=true` and a `CIRIS_TEST_TRUST_ROOT_SEED`. Returns
/// `Some(root)` (the minted SW test root) when it should proceed, or a loud `None`
/// when a precondition is missing (never an error — a missing seed is a skip, not a
/// boot failure). Single-sourcing this keeps the two entry points from drifting on
/// the fence — the exact "two hand-maintained lists" class we keep closing.
fn test_anchor_root_or_skip(
    context: &str,
) -> Result<Option<ciris_verify_core::self_at_login::HybridSigningIdentity>> {
    if std::env::var("CIRIS_TESTING_MODE").ok().as_deref() != Some("true") {
        return Ok(None);
    }
    if std::env::var("CIRIS_TEST_TRUST_ROOT_SEED").is_err() {
        tracing::warn!(
            context,
            "test-anchor compiled in + CIRIS_TESTING_MODE=true, but CIRIS_TEST_TRUST_ROOT_SEED \
             is unset — skipping (the node stays self-signed and will not root under the test anchor)"
        );
        return Ok(None);
    }
    Ok(Some(mint_test_root()?))
}

/// If `test-anchor` is compiled in AND `CIRIS_TESTING_MODE=true` AND a test-root
/// seed is set: mint the SW test root, scrub-sign THIS node's own key record with
/// it, and adopt the blessed record — so the node roots under the
/// `CIRIS_TEST_TRUST_ROOT` anchor. Loud no-op otherwise. Never engages in prod
/// (the feature is absent there).
///
/// Then performs the miniature trust-root ceremony
/// ([`perform_trust_root_ceremony`]) — **leg B** of the CIRISEdge#386 trace-serve
/// gate. Leg A (above) puts `infra:serve` on the scrubbed KEY RECORD so
/// `has_effective_role` passes; leg B builds the `delegates_to` GRAPH the sender's
/// `capability_roots_to_trusted_root` walk demands (root charter + this node's
/// trust edge + a lifecycle liveness score + — on the canonical — a replicating
/// serve-capability grant). Without it the agent withholds every trace
/// ("recipient's `infra:serve` roots to no root this node trusts").
pub(crate) async fn maybe_test_bless_self(
    engine: &std::sync::Arc<Engine>,
    cfg: &ServerConfig,
) -> Result<()> {
    // Runtime fence, single-sourced with the delivery-path entry
    // ([`test_anchor_root_or_skip`]): a loud no-op unless CIRIS_TESTING_MODE=true +
    // a seed is present. This path (composed node) ADDITIONALLY does leg A below.
    let Some(test_root) = test_anchor_root_or_skip("self-bless")? else {
        return Ok(());
    };

    use ciris_persist::federation::SignedKeyRecord;
    use ciris_verify_core::federation_self_record::{produce_scrubbed_key_record, ScrubTarget};

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
    let rec = crate::compose::build_self_key_record(engine, cfg).await?;
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
        // A canonical IS the accord-conferred consent to serve: identity_type
        // alone is a contradiction the trace-serve gate (leg A, #379/#386)
        // correctly refuses ("a canonical without infra:serve cannot receive
        // traces"). Mirror the baked prod genesis (canonical_seed.json:
        // registration_envelope.roles ⊇ [infra:serve]) so the harness
        // canonical is a REAL canonical — this line was the last predicate of
        // the whole #315 trace-ship arc.
        roles: if bless_canonical {
            vec!["infra:serve".to_string(), "infra:attest".to_string()]
        } else {
            Vec::new()
        },
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
    // non-conflict error is fatal. NB: a benign conflict is NOT an early return —
    // we still fall through to the trust-root ceremony below (its own graph-state
    // existence checks make a re-run a no-op), so the leg-B graph is (re)built
    // even on a boot where the leg-A scrub was already present.
    match engine.adopt_scrub_upgrade(persist_rec).await {
        Ok(outcome) => {
            tracing::warn!(
                key_id = %rec.key_id,
                test_root = %root_pub_b64,
                ?outcome,
                "TEST-ANCHOR SELF-BLESS ACTIVE — this node is blessed by a SOFTWARE test trust root, \
                 NOT the humanity-accord anchor (CIRISServer#258; local harness only)."
            );
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("already anc") || msg.contains("onflict") {
                tracing::info!(
                    key_id = %rec.key_id,
                    "TEST-ANCHOR: self record already blessed (configured-home restart) — continuing to ceremony"
                );
            } else {
                return Err(anyhow!("adopt the test-root-blessed self record: {e}"));
            }
        }
    }

    // ── Leg B (CIRISEdge#386): the miniature trust-root ceremony ──────────────
    perform_trust_root_ceremony(engine, &test_root, bless_canonical).await?;

    Ok(())
}

/// TEST-ANCHOR-ONLY leg-B entry for the **bare embedded agent** (the mesh-repro
/// traceflow agent boots via `ciris_server.start_federation_delivery`, NOT
/// `serve_with_python_adapter` → `serve_with_adapter`, so [`maybe_test_bless_self`]
/// — hooked only into `serve_with_adapter` — never runs on it). Without this the
/// agent's OWN directory holds none of the leg-B graph, so
/// `capability_roots_to_trusted_root(user=agent, subject=canonical, "infra:serve")`
/// finds no root the agent trusts and the agent withholds every trace
/// ("recipient's `infra:serve` roots to no root this node trusts") — the observed
/// NO-CARRIER even after the canonical's ceremony ran.
///
/// It runs the SAME [`perform_trust_root_ceremony`] the composed path runs (NO
/// duplication — team-lead ask 3), through the SAME [`test_anchor_root_or_skip`]
/// runtime fence, so both entry points share the fence AND the ceremony body. The
/// agent needs exactly rows (1) charter, (2) its OWN trust edge
/// `delegates_to(agent → root)` (only the agent can author it — via
/// `emit_attestation_self`, whose attester is the agent's registered
/// `local_derived_key_id()`; `agent_boot.py:409`'s `register_self_federation_key`
/// admits that key BEFORE `start_federation_delivery`, so the mint's
/// `put_attestation` finds the attesting row), and (3) lifecycle — all authored
/// LOCALLY into the agent's directory at `cohort_scope: self`. `bless_canonical` is
/// read from the SAME `CIRIS_TEST_BLESS_CANONICAL` env the composed path reads
/// (unset on the agent ⇒ `false`), so the agent mints NO row (4): the serve
/// capability grant is the recipient/canonical's to author + replicate, never the
/// sender's. Idempotent across restarts and a no-op if a node ever ran both paths
/// (the ceremony's per-row graph-state existence checks). Leg A (scrubbing the
/// node's OWN key record) is intentionally NOT run here: for the forward direction
/// (agent→canonical) leg A is evaluated on the RECIPIENT (canonical) record, not
/// the agent's, and it needs the `ServerConfig` this bare path does not have.
#[cfg(feature = "python")]
pub(crate) async fn maybe_test_bless_delivery_self(engine: &std::sync::Arc<Engine>) -> Result<()> {
    let Some(test_root) = test_anchor_root_or_skip("delivery-path leg-B ceremony")? else {
        return Ok(());
    };
    let bless_canonical =
        std::env::var("CIRIS_TEST_BLESS_CANONICAL").ok().as_deref() == Some("true");
    tracing::warn!(
        bless_canonical,
        "TEST-ANCHOR: bare-agent delivery path — running leg-B trust-root ceremony \
         (CIRISEdge#386; the agent never runs serve_with_adapter, so leg B is minted HERE)"
    );
    perform_trust_root_ceremony(engine, &test_root, bless_canonical).await?;
    // CIRISConstitution#46 / persist v22.0.0 — CONSENT BEFORE SCORING. Minted only
    // on a non-canonical node (the SUBJECT of scoring); a canonical scores others.
    if !bless_canonical {
        grant_analyze_consent_to_canonicals(engine).await?;
    }
    Ok(())
}

/// **CIRISConstitution#46 (persist v22.0.0) — the subject's `analyze` consent.**
///
/// v22 inverts the RC2 default for one family: a federation-tier `capacity:*`
/// claim about subject S by attester P is REFUSED unless a live
/// [`CAPACITY_CONSENT_SCOPE`] consent from S covering P exists in the scoring
/// node's corpus. Persist's words for why: *"were you permitted to compute and
/// publish this about me?"* — and CC 3.4.5 previously let **any** registered key
/// score any third party, which on a deliberately-cheap bootstrap means anyone.
///
/// The claim is the edge `P → S`; the consent is the **REVERSE** edge `S → P` —
/// `attesting_key_id` = S (this node, the subject), `attested_key_id` = P (the
/// canonical that will score us), envelope `dimension` =
/// `consent:state:granted:v1`, envelope `scope` naming `analyze`. Resolved by
/// `resolve_scoped_consent` (one canonical fold, all three backends), so the row
/// must be **federation-tier** (`emit_attestation_self` assembles it as such) and
/// must REPLICATE to the scoring node — hence `cohort_scope: federation`, not
/// `self`. A self-scoped grant would resolve locally and be invisible where it is
/// actually read, which is the "accepted but not projected" class.
///
/// Vocabulary is single-sourced from persist (`paths::DIMENSION`,
/// `consent_dimension::STATE_GRANTED_PREFIX`, `CAPACITY_CONSENT_SCOPE`) — never
/// hand-mirrored, because a mirrored literal compiles and skews the wire.
///
/// **Harness-only, deliberately.** Consenting to be analysed is the subject's
/// decision, so in production this belongs behind an owner-authorized action, not
/// an automatic boot step. It is gated with the rest of the test-anchor path and
/// compiled out of release builds.
///
/// `subject_key_ids` is left EMPTY on purpose: it confers revocation authority
/// (persist rule 2), and this node authored the grant so it can already withdraw
/// it as producer. Naming the canonical there would hand the scorer a say over
/// the consent that authorizes it — the CIRISPersist#528 G2 shape.
async fn grant_analyze_consent_to_canonicals(engine: &std::sync::Arc<Engine>) -> Result<()> {
    use ciris_persist::federation::admission::CAPACITY_CONSENT_SCOPE;
    use ciris_persist::federation::consent::consent_dimension;
    use ciris_persist::federation::envelope::paths;
    use ciris_persist::federation::hard_case::ConsentState;

    let self_key_id = engine
        .local_derived_key_id()
        .await
        .context("analyze-consent: resolve this node's derived federation key_id")?;
    let canonicals = engine
        .list_canonical_servers()
        .await
        .context("analyze-consent: list_canonical_servers")?;
    if canonicals.is_empty() {
        tracing::warn!(
            "TEST-ANCHOR: no canonical servers in the directory yet — no `analyze` consent \
             minted, so any capacity:* score about this node will be REFUSED by CC#46 until \
             one appears"
        );
        return Ok(());
    }
    let dimension = format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX);
    for rec in canonicals {
        let attester = rec.key_id.clone();
        if attester == self_key_id {
            continue; // never grant to ourselves
        }
        // Idempotent: skip when the canonical fold already resolves to a grant.
        match engine
            .federation_directory()
            .resolve_scoped_consent(
                &attester,
                &self_key_id,
                CAPACITY_CONSENT_SCOPE,
                None,
                chrono::Utc::now(),
            )
            .await
        {
            Ok(ConsentState::Granted) => {
                tracing::info!(
                    attester = %attester,
                    "TEST-ANCHOR: `analyze` consent already resolves to Granted — no-op"
                );
                continue;
            }
            _ => {}
        }
        let envelope = serde_json::json!({
            (paths::DIMENSION): dimension,
            "scope": CAPACITY_CONSENT_SCOPE,
        });
        let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
            "consent",
            ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
                .map_err(|e| anyhow!("analyze-consent: EnvelopeCore: {e}"))?,
            // FEDERATION, not self: it is read on the SCORING node, not here.
            cohort_scope::FEDERATION,
        );
        input.attested_key_id = Some(attester.clone());
        engine.emit_attestation_self(input).await.map_err(|e| {
            anyhow!("analyze-consent: emit consent:state:granted for {attester}: {e}")
        })?;
        // Assert the RESOLVED STANCE, not the row — the error we are curing named
        // `resolved stance: Unspecified`, so a row that exists but does not fold to
        // Granted is exactly the silent-false we must not ship (CIRISEdge#425).
        match engine
            .federation_directory()
            .resolve_scoped_consent(
                &attester,
                &self_key_id,
                CAPACITY_CONSENT_SCOPE,
                None,
                chrono::Utc::now(),
            )
            .await
        {
            Ok(ConsentState::Granted) => tracing::warn!(
                subject = %self_key_id,
                attester = %attester,
                scope = CAPACITY_CONSENT_SCOPE,
                "TEST-ANCHOR: `analyze` consent GRANTED and RESOLVED (CIRISConstitution#46) — \
                 the canonical may now author capacity:* about this node"
            ),
            Ok(state) => tracing::error!(
                subject = %self_key_id,
                attester = %attester,
                resolved = ?state,
                "TEST-ANCHOR: `analyze` consent row emitted but the scoped fold does NOT \
                 resolve to Granted — capacity:* will still be refused (CC#46). Check the \
                 envelope `scope` shape and the row's tier/cohort_scope"
            ),
            Err(e) => tracing::error!(
                attester = %attester,
                error = %e,
                "TEST-ANCHOR: `analyze` consent emitted but resolve_scoped_consent FAILED"
            ),
        }
    }
    Ok(())
}

/// **Leg B of the CIRISEdge#386 trace-serve gate — the miniature trust-root
/// ceremony.** A faithful model of the production owner-binding claim flow
/// (`crate::auth::ownership`), scaled to the SW test root.
///
/// The sender withholds a trace unless
/// `capability_roots_to_trusted_root(sender_dir, user=self, subject=peer,
/// "infra:serve")` (CIRISPersist `federation::trust_root`) returns a grant — i.e.
/// the recipient's `infra:serve` roots to a root THE SENDER trusts. Leg A (the
/// scrubbed key record's `roles`) is necessary but NOT sufficient: that predicate
/// is a `delegates_to` GRAPH walk over `trust_root_valid`, and nothing else in the
/// harness builds it. This mints exactly the four rows it demands, ALL at
/// `tier: federation` (mandatory — `counts_in_capability_walk` gates on
/// tier==FEDERATION, and `list_attestations_by/for` only surface federation-tier
/// rows to the walk):
///
/// 1. **Root charter** `delegates_to(root → root)`, scope ⊇ {`infra:serve`,
///    `infra:attest`} + a well-formed `pre_rotation_commitment` (persist REFUSES a
///    charter without it — `check_trust_charter_admission`). Satisfies
///    `root_self_declares` + `charter_has_recovery`.
/// 2. **This node's trust edge** `delegates_to(self → root)` — the sender's own
///    consensual trust declaration. Satisfies `edge_exists`. Node-attested, so it
///    is signed by the engine's OWN key via `emit_attestation_self`.
/// 3. **Lifecycle liveness** — a fresh `accord:lifecycle:v1` `scores` about the
///    root. Satisfies `lifecycle_active`. `accord:*` dimensions require an
///    `accord_holder` attester (`DimensionAdmissionPolicy`); the seeded test root
///    IS `identity_type: accord_holder`, so it self-scores its own liveness.
/// 4. **Capability grant** `delegates_to(root → self, infra:serve)` — CANONICAL
///    ONLY. This is the one `delegates_to(root → node, infra:*)` the production
///    `ownership.rs` claim mints; here the root (not a user) grants it, so it is
///    NOT an owner-binding (no owner-binding dimension/purpose ⇒ the single-owner
///    gate no-ops) and confers only `infra:serve`.
///
/// ## Determinism / replication strategy (deliberate)
///
/// Every blessed node mints (1)–(3) **locally** at `cohort_scope: self`, rather
/// than relying on replication. The sender evaluates `trust_root_valid` from ITS
/// OWN records, so each node needs the charter, its own edge, and a lifecycle row
/// in its OWN directory — and each mints them itself. `self`-scope keeps them
/// structurally invisible (they never cross-replicate, so no per-node duplicate
/// accumulation), while `tier` stays `federation` — the exact
/// `tier=federation`+`cohort=self` shape the production owner-binding uses.
///
/// The charter's signed ENVELOPE is deterministic (no timestamp/id fields; JCS is
/// order-free), so both nodes' test roots — derived from the same seed — produce a
/// byte-identical charter signature; the rows differ only in `attestation_id` /
/// `asserted_at` / `scrub_timestamp`, which are outside the signature and which
/// the `.any()`-over-live-charters predicate does not care about. Idempotency
/// across restarts is therefore a **graph-state existence check** before each mint
/// (skip if the required edge/score already exists), NOT a deterministic
/// `attestation_id`: that is the only strategy that also covers the (2)
/// `emit_attestation_self` edge whose id is generated internally and cannot be
/// pinned, and it tolerates a partial prior boot.
///
/// Only the (4) capability grant is minted ONCE, on the canonical, at
/// `cohort_scope: federation` — because it is the single ceremony fact that
/// inherently must CROSS to the peer: the agent (sender) reads
/// `delegates_to(root → canonical, infra:serve)` from ITS directory, so canonical
/// must replicate it. `federation` is the scope that replicates (`self`/`family`
/// suppress `holds_bytes` and stay local — `cohort_scope::suppresses_holds_bytes`).
async fn perform_trust_root_ceremony(
    engine: &std::sync::Arc<Engine>,
    test_root: &ciris_verify_core::self_at_login::HybridSigningIdentity,
    bless_canonical: bool,
) -> Result<()> {
    use ciris_persist::federation::delegates_to_envelope;
    use ciris_persist::federation::envelope::paths;
    use ciris_persist::federation::trust_root::{
        pre_rotation_commitment, ACCORD_LIFECYCLE_DIMENSION, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
    };

    // The two identities the ceremony binds: the shared SW test root
    // (`test-accord-holder-0`, seeded accord_holder), and THIS node's #247-derived
    // federation key_id — the EXACT attester `emit_attestation_self` stamps, so the
    // trust edge and the walk agree on "self" by construction (CIRISServer#315).
    let root_key_id = test_root.key_id().to_string();
    let self_key_id = engine
        .local_derived_key_id()
        .await
        .map_err(|e| anyhow!("ceremony: local_derived_key_id: {e}"))?;

    let charter_scopes = vec![
        INFRA_SERVE_SCOPE.to_string(),
        INFRA_ATTEST_SCOPE.to_string(),
    ];

    // ── (1) Root charter: delegates_to(root → root), scope ⊇ {serve,attest}. ──
    if !has_live_charter(engine, &root_key_id).await? {
        // v19.0.0 #488 (the KERI lesson): a charter MUST be born recoverable —
        // `check_trust_charter_admission` REFUSES one without a well-formed
        // `pre_rotation_commitment` (64 lowercase hex). We commit to a
        // deterministic placeholder successor set: the harness never runs the
        // recovery ceremony (which would ALSO carry `recovers`/`successor_keys`
        // and bind against this hash), so any well-formed commitment satisfies
        // `charter_has_recovery`; a real ceremony hashes the actual pre-generated
        // successor keyset here. Built via the pinned persist constructor (no
        // hand-rolled JCS).
        let successor = format!("{root_key_id}-successor-v1");
        let commitment = pre_rotation_commitment(std::slice::from_ref(&successor))
            .map_err(|e| anyhow!("ceremony: pre_rotation_commitment: {e}"))?;
        let mut envelope = delegates_to_envelope(&root_key_id, &charter_scopes, false);
        envelope
            .as_object_mut()
            .expect("delegates_to_envelope builds a JSON object")
            .insert(
                paths::PRE_ROTATION_COMMITMENT.to_string(),
                serde_json::json!(commitment),
            );
        put_root_signed_attestation(
            engine,
            test_root,
            attestation_type::DELEGATES_TO,
            &root_key_id,
            envelope,
            vec![root_key_id.clone()],
            cohort_scope::SELF,
        )
        .await?;
        tracing::warn!(
            root_key_id = %root_key_id,
            "TEST-ANCHOR ceremony: minted root charter delegates_to(root→root) [serve,attest]+commitment"
        );
    }

    // ── (3) Lifecycle liveness: a fresh accord:lifecycle:v1 `scores` about root. ─
    if !has_fresh_lifecycle(engine, &root_key_id).await? {
        let envelope = serde_json::json!({
            "kind": "scores",
            (paths::DIMENSION): ACCORD_LIFECYCLE_DIMENSION,
            // Liveness = alive. `trust_root_valid` reads only the dimension +
            // freshness window, never the value, but a `scores` row conventionally
            // carries one.
            "score": 1.0,
        });
        put_root_signed_attestation(
            engine,
            test_root,
            attestation_type::SCORES,
            &root_key_id,
            envelope,
            vec![root_key_id.clone()],
            cohort_scope::SELF,
        )
        .await?;
        tracing::warn!(
            root_key_id = %root_key_id,
            "TEST-ANCHOR ceremony: minted accord:lifecycle:v1 liveness score about root"
        );
    }

    // ── (2) The trust edge: delegates_to(self → root). Node-attested ⇒ signed by
    //         THIS node's engine key via emit_attestation_self (attester ==
    //         local_derived_key_id() == the walk's `user`). ────────────────────
    if !has_trust_edge(engine, &self_key_id, &root_key_id).await? {
        let envelope = delegates_to_envelope(&root_key_id, &charter_scopes, false);
        let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
            attestation_type::DELEGATES_TO,
            ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
                .map_err(|e| anyhow!("ceremony: trust-edge EnvelopeCore: {e}"))?,
            // self-scope: this node's OWN trust declaration, read locally by
            // trust_root_valid(user=self). No peer needs it.
            cohort_scope::SELF,
        );
        input.attested_key_id = Some(root_key_id.clone());
        input.subject_key_ids = vec![root_key_id.clone()];
        engine
            .emit_attestation_self(input)
            .await
            .map_err(|e| anyhow!("ceremony: emit trust edge delegates_to(self→root): {e}"))?;
        tracing::warn!(
            self_key_id = %self_key_id,
            root_key_id = %root_key_id,
            "TEST-ANCHOR ceremony: minted trust edge delegates_to(self→root)"
        );
    }

    // ── (4) Capability grant: delegates_to(root → self, infra:serve). CANONICAL
    //         ONLY, cohort=federation so it REPLICATES to the sending peer. ─────
    if bless_canonical && !has_capability_grant(engine, &root_key_id, &self_key_id).await? {
        let grant_scopes = vec![INFRA_SERVE_SCOPE.to_string()];
        let envelope = delegates_to_envelope(&self_key_id, &grant_scopes, false);
        put_root_signed_attestation(
            engine,
            test_root,
            attestation_type::DELEGATES_TO,
            &self_key_id,
            envelope,
            vec![self_key_id.clone()],
            // federation: the ONE ceremony fact that must cross to the peer — the
            // agent evaluates the serve gate from ITS directory and needs this
            // grant there. self/family would stay structurally invisible.
            cohort_scope::FEDERATION,
        )
        .await?;
        tracing::warn!(
            root_key_id = %root_key_id,
            subject = %self_key_id,
            "TEST-ANCHOR ceremony: minted capability grant delegates_to(root→self, infra:serve) @ federation (replicating)"
        );
    }

    // ── Derivation-trace self-check (CIRISEdge#386 class discipline) ──────────
    // After minting, evaluate the FULLY-LOCAL `trust_root_valid(self → root)` and
    // log all five legs of `TrustRootVerdict`. This is the "log which of the five
    // you satisfied" the leg-B spec demands: on a bless where any conjunct is
    // unexpectedly false, the verdict NAMES the failed leg
    // (edge_exists / root_self_declares / charter_has_recovery / lifecycle_active
    // / halt_latched), turning "the trace plane is dark" into a one-line read
    // instead of the multi-hour investigation the #386 gate's silent `debug!`
    // refusal cost. Deliberately checks only the LOCAL root verdict — NOT
    // `capability_roots_to_trusted_root`: leg 4 (the peer's replicated capability
    // grant) is legitimately absent from the sender's directory until the mesh
    // replicates it, so a `None` there at bless time is expected, not a failure.
    // The four rows minted above must make this verdict green on BOTH nodes now.
    let verdict = ciris_persist::federation::trust_root::trust_root_valid(
        &*engine.federation_directory(),
        &self_key_id,
        &root_key_id,
    )
    .await
    .map_err(|e| anyhow!("ceremony: trust_root_valid self-check: {e}"))?;
    if verdict.valid {
        tracing::warn!(
            ?verdict,
            self_key_id = %self_key_id,
            root_key_id = %root_key_id,
            "TEST-ANCHOR ceremony: trust_root_valid GREEN — leg B built (edge_exists + root_self_declares \
             + charter_has_recovery + lifecycle_active, no halt latched)"
        );
    } else {
        // Loud, not silent: a non-green verdict here means the harness will still
        // withhold every trace. The `?verdict` fields say WHICH leg to fix.
        tracing::error!(
            ?verdict,
            self_key_id = %self_key_id,
            root_key_id = %root_key_id,
            "TEST-ANCHOR ceremony: trust_root_valid NOT green after mint — the trace plane will stay dark; \
             the `false` field(s) in ?verdict name the unsatisfied leg B conjunct(s)"
        );
    }

    Ok(())
}

/// Build + `put_attestation` a federation-tier row **signed by the SW test root**
/// (`test-accord-holder-0`, a [`ciris_verify_core::self_at_login::SelfSigner`]).
///
/// The federation-tier ingest gate (`verify_federation_tier_ingest`, CC
/// 5.3.2.4.3.1) re-canonicalizes the envelope with `ceg_produce_canonicalize`,
/// cross-checks `SHA-256(canonical) == original_content_hash`, and Strict
/// `verify_hybrid`s the `scrub_signature_*` against **`attesting_key_id`**'s
/// REGISTERED pubkeys. So we canonicalize with that SAME function and bound-hybrid
/// sign THOSE exact bytes with the root (`sign_bound` — the identical construction
/// `produce_scrubbed_key_record` already uses for leg A, so the seeded PQC-complete
/// `test-accord-holder-0` row verifies it). `attesting_key_id == scrub_key_id ==
/// root` (a self-attested root row). Mirrors the 20-field
/// `crate::auth::ownership::persist_user_signed_owner_binding` assembly, but the
/// signer is the root, not a user `LocalSigner`.
async fn put_root_signed_attestation(
    engine: &std::sync::Arc<Engine>,
    root: &ciris_verify_core::self_at_login::HybridSigningIdentity,
    attestation_type_str: &str,
    attested_key_id: &str,
    envelope: serde_json::Value,
    subject_key_ids: Vec<String>,
    cohort_scope_str: &str,
) -> Result<String> {
    use ciris_persist::federation::types::{attestation_tier, Attestation, SignedAttestation};
    use ciris_verify_core::self_at_login::SelfSigner as _;
    use sha2::{Digest, Sha256};

    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| anyhow!("ceremony canonicalize: {e}"))?;
    let (ed_sig_b64, pqc_sig_b64) = root
        .sign_bound(&canonical)
        .await
        .map_err(|e| anyhow!("ceremony sign_bound({}): {e}", root.key_id()))?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    let now = chrono::Utc::now();
    let root_key_id = root.key_id().to_string();
    let attestation_id = crate::ids::new_id();
    let attestation = Attestation {
        attestation_id: attestation_id.clone(),
        attesting_key_id: root_key_id.clone(),
        attested_key_id: attested_key_id.to_string(),
        attestation_type: attestation_type_str.to_string(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: ed_sig_b64,
        scrub_signature_pqc: Some(pqc_sig_b64),
        scrub_key_id: root_key_id,
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope_str.to_string(),
        tier: attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
    };
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| anyhow!("ceremony put_attestation({attestation_type_str}): {e}"))?;
    Ok(attestation_id)
}

/// Does `token` appear in the envelope's `scope` field (bare string OR array — the
/// two wire shapes persist's `trust_root::scope_contains` accepts)? Idempotency-read
/// helper; mirrors persist's parse so a mint is skipped iff the walk would see it.
fn envelope_scope_contains(envelope: &serde_json::Value, token: &str) -> bool {
    match envelope.get(ciris_persist::federation::envelope::paths::SCOPE) {
        Some(serde_json::Value::String(s)) => s == token,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(token)),
        _ => false,
    }
}

/// Idempotency: is a root charter `delegates_to(root → root)` carrying a
/// `pre_rotation_commitment` already present in THIS directory? (Federation-tier
/// only — `list_attestations_by` filters to it, exactly as the walk does.)
async fn has_live_charter(engine: &std::sync::Arc<Engine>, root_key_id: &str) -> Result<bool> {
    use ciris_persist::federation::envelope::paths;
    let rows = engine
        .federation_directory()
        .list_attestations_by(root_key_id)
        .await
        .map_err(|e| anyhow!("ceremony has_live_charter: {e}"))?;
    Ok(rows.iter().any(|a| {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attested_key_id == root_key_id
            && a.attestation_envelope
                .get(paths::PRE_ROTATION_COMMITMENT)
                .is_some()
    }))
}

/// Idempotency: is there already a FRESH `accord:lifecycle:v1` `scores` about the
/// root (within the same freshness window `trust_root_valid` uses)? A stale one is
/// treated as absent so a fresh liveness score is (re)minted.
async fn has_fresh_lifecycle(engine: &std::sync::Arc<Engine>, root_key_id: &str) -> Result<bool> {
    use ciris_persist::federation::envelope::paths;
    use ciris_persist::federation::trust_root::{
        ACCORD_LIFECYCLE_DIMENSION, ACCORD_LIFECYCLE_FRESHNESS_DAYS,
    };
    let rows = engine
        .federation_directory()
        .list_attestations_for(root_key_id)
        .await
        .map_err(|e| anyhow!("ceremony has_fresh_lifecycle: {e}"))?;
    let now = chrono::Utc::now();
    let window = chrono::Duration::days(ACCORD_LIFECYCLE_FRESHNESS_DAYS);
    Ok(rows.iter().any(|a| {
        a.attestation_type == attestation_type::SCORES
            && a.attestation_envelope
                .get(paths::DIMENSION)
                .and_then(|v| v.as_str())
                == Some(ACCORD_LIFECYCLE_DIMENSION)
            && now.signed_duration_since(a.asserted_at) <= window
    }))
}

/// Idempotency: does this node's own trust edge `delegates_to(self → root)`
/// already exist? (Authored BY self ⇒ `list_attestations_by(self)`.)
async fn has_trust_edge(
    engine: &std::sync::Arc<Engine>,
    self_key_id: &str,
    root_key_id: &str,
) -> Result<bool> {
    let rows = engine
        .federation_directory()
        .list_attestations_by(self_key_id)
        .await
        .map_err(|e| anyhow!("ceremony has_trust_edge: {e}"))?;
    Ok(rows.iter().any(|a| {
        a.attestation_type == attestation_type::DELEGATES_TO && a.attested_key_id == root_key_id
    }))
}

/// Idempotency: does a serve-capability grant `delegates_to(root → subject,
/// infra:serve)` already exist about `subject`? (About `subject` ⇒
/// `list_attestations_for(subject)`.)
async fn has_capability_grant(
    engine: &std::sync::Arc<Engine>,
    root_key_id: &str,
    subject_key_id: &str,
) -> Result<bool> {
    use ciris_persist::federation::trust_root::INFRA_SERVE_SCOPE;
    let rows = engine
        .federation_directory()
        .list_attestations_for(subject_key_id)
        .await
        .map_err(|e| anyhow!("ceremony has_capability_grant: {e}"))?;
    Ok(rows.iter().any(|a| {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attesting_key_id == root_key_id
            && envelope_scope_contains(&a.attestation_envelope, INFRA_SERVE_SCOPE)
    }))
}
