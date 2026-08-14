//! **CC 4.1.4 `withdraws-arbitrage`** — the arbitrage countermeasure, driven
//! end-to-end against a real substrate (CIRISServer#159).
//!
//! The unit tests in `src/withdraws_arbitrage.rs` pin the *rule* (the
//! precedence-collapsed, add-one-smoothed, windowed ratio). THIS file pins the
//! *gate*: real hybrid-signed structural composers, admitted through persist's
//! own `put_attestation` federation-tier ingest gate (so every row here is one the
//! substrate genuinely accepted — CC 2.4.1.1 MUST-admit, which the countermeasure
//! deliberately does NOT touch), then judged by
//! [`ciris_server::withdraws_arbitrage::enforce`].
//!
//! The adversary (`arbitrage-attester`) is a *misattester*: it emits `scores` rows and then
//! erases the ones that fail to stick. The honest attester does the same volume of
//! work but pays for its errors with `recants`. The test asserts the substrate
//! stores both alike, and the consumer policy separates them.
//!
//! Harness (engine + hybrid signers + key registration) mirrors
//! `tests/peer_replication.rs`.

use std::sync::Arc;

use ed25519_dalek::SigningKey;

use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::types::{attestation_type, cohort_scope, identity_type};
use ciris_persist::prelude::{Engine, LocalSigner};

use ciris_server::attest::{Emit, KeySigner, Spec};
use ciris_server::withdraws_arbitrage::{
    self, ArbitragePolicy, Refusal, DEFAULT_RATIO_THRESHOLD, DEFAULT_WINDOW_DAYS,
};

const NODE_KEY_ID: &str = "ciris-server";

/// The consumer node (us): the corpus in which foreign attesters' behavior is
/// observed and judged.
async fn node() -> Arc<Engine> {
    let signing_key = SigningKey::from_bytes(&[0xA1; 32]);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    let engine = Engine::with_signer(signer, "sqlite::memory:")
        .await
        .expect("Engine::with_signer (sqlite::memory:)");
    Arc::new(engine)
}

async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

/// Register the node's own steward key (the `put_attestation` attested-key FK).
async fn register_self(engine: &Engine) {
    let key_id = node_key_id(engine).await;
    // Through the ONE door (CIRISServer#402): the registration envelope now BINDS
    // ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither the
    // identity type nor either pubkey, and persist v31 refuses it — an envelope
    // that does not name its subject stands for any record it is pasted onto
    // (CIRISPersist#659).
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key");
}

/// A foreign attester with real hybrid keys — the one whose *retraction behavior*
/// the CC 4.1.4 ledger judges.
struct Attester {
    key_id: String,
    /// The hybrid signer, which is also how this attester goes through the emit
    /// door: `LocalSigner::sign_hybrid` IS the bound shape persist's ingest gate
    /// verifies (Ed25519 over canonical, ML-DSA-65 over `canonical ‖ ed_sig`).
    signer: LocalSigner,
}

impl Attester {
    fn new(key_id: &str, seed: u8) -> Self {
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0xFF; 32], format!("{key_id}-pqc"))
                .expect("attester ML-DSA-65 seed"),
        );
        Attester {
            key_id: key_id.to_string(),
            signer: LocalSigner::from_parts(
                SigningKey::from_bytes(&[seed; 32]),
                key_id.to_string(),
                Some(pqc),
                Some(format!("{key_id}-pqc")),
            ),
        }
    }

    async fn register(&self, engine: &Engine) {
        // Through the ONE door (CIRISServer#402): the registration envelope now
        // BINDS ITS SUBJECT. The hand-rolled `{"key_id": …}` shape named neither
        // the identity type nor either pubkey, and persist v31 refuses it — an
        // envelope that does not name its subject stands for any record it is
        // pasted onto (CIRISPersist#659).
        ciris_server::attest::register_key(
            engine,
            KeySigner::Local(&self.signer),
            &self.key_id,
            identity_type::WITNESS,
            serde_json::Value::Null,
        )
        .await
        .expect("register foreign attester key");
    }

    /// A genuinely-signed row of any `attestation_type`, `age_days` old, carrying
    /// `envelope`. Admitted through `put_attestation` — the SAME gate an inbound
    /// replicated row goes through. Returns the minted `attestation_id`.
    async fn put(
        &self,
        engine: &Engine,
        kind: &str,
        subject: &str,
        envelope: serde_json::Value,
        age_days: i64,
    ) -> String {
        let asserted_at = chrono::Utc::now() - chrono::Duration::days(age_days);
        // Through the ONE door (CIRISServer#402), stamped AT `asserted_at`: the age
        // is what puts a row inside or outside CC 4.1.4's rolling window, and the
        // stamp is what makes that instant the SIGNED one. Hand-rolled beside its
        // envelope, this row carried an `asserted_at` no signature covered and no
        // typed-column mirror, both of which persist v31 refuses
        // (CIRISPersist#598/#643).
        //
        // The id is MINTED into the signed bytes now, so a retraction references the
        // id its upstream came back with rather than one the fixture chose — which
        // is also how a real producer builds the chain.
        let row = Emit::stamp_at(
            &self.key_id,
            Spec::new(kind, cohort_scope::FEDERATION, envelope).about(subject),
            asserted_at,
        )
        .unwrap_or_else(|e| panic!("stamp {kind} row: {e}"))
        .sign_and_assemble(KeySigner::Local(&self.signer))
        .await
        .unwrap_or_else(|e| panic!("sign {kind} row: {e}"));
        ciris_server::attest::put(engine, row)
            .await
            .unwrap_or_else(|e| panic!("substrate MUST admit {kind} row: {e}"))
    }

    /// A `scores` claim about `subject` (the row the attester will later erase).
    async fn scores(&self, engine: &Engine, subject: &str, age_days: i64) -> String {
        self.put(
            engine,
            attestation_type::SCORES,
            subject,
            serde_json::json!({
                "dimension": "provenance:asserted:v1",
                "score": 1.0,
                "confidence": 1.0,
                "epistemic_mode": "direct",
                "witness_relation": "external",
                "stake": "reputational",
                "attested_key_id": subject,
            }),
            age_days,
        )
        .await
    }

    /// Producer self-`withdraws` against its own prior row (CC 2.4.1.1 rule 1) —
    /// "I retract this", claiming NOTHING about whether it was false. Free.
    async fn withdraws(&self, engine: &Engine, subject: &str, upstream: &str, age: i64) {
        self.put(
            engine,
            attestation_type::WITHDRAWS,
            subject,
            serde_json::json!({
                "dimension": "provenance:asserted:v1",
                "references_attestation_id": upstream,
                "withdrawal_reason": "no longer asserted",
            }),
            age,
        )
        .await;
    }

    /// Producer `recants` against its own prior row — "it was false at issuance".
    /// The costly primitive: an acknowledged-error chain consumers downweight.
    async fn recants(&self, engine: &Engine, subject: &str, upstream: &str, age: i64) {
        self.put(
            engine,
            attestation_type::RECANTS,
            subject,
            serde_json::json!({
                "dimension": "provenance:asserted:v1",
                "references_attestation_id": upstream,
                "recantation_reason": "the claim was false when I made it",
                "what_was_false": "the score",
            }),
            age,
        )
        .await;
    }
}

fn policy() -> ArbitragePolicy {
    ArbitragePolicy::default()
}

// ─────────────────────────────────────────────────────────────────────────────
// BENIGN — the substrate admits, and the consumer policy admits.
// ─────────────────────────────────────────────────────────────────────────────

/// A legitimate `withdraws` (a stale claim retracted) and a legitimate `recants`
/// (an error owned) from an honest attester are BOTH admitted by the substrate and
/// BOTH cleared by CC 4.1.4. The countermeasure must not tax honest retraction —
/// that would push attesters toward *never* retracting, which is strictly worse.
#[tokio::test]
async fn honest_withdraw_and_honest_recant_are_admitted() {
    let engine = node().await;
    register_self(&engine).await;
    let subject = node_key_id(&engine).await;

    let honest = Attester::new("honest-attester", 0xC0);
    honest.register(&engine).await;

    let s1 = honest.scores(&engine, &subject, 3).await;
    let s2 = honest.scores(&engine, &subject, 3).await;
    // One stale claim retracted (no falsity admitted) …
    honest.withdraws(&engine, &subject, &s1, 2).await;
    // … and one error actually owned.
    honest.recants(&engine, &subject, &s2, 1).await;

    let ledger =
        withdraws_arbitrage::enforce(&engine, &honest.key_id, policy(), chrono::Utc::now())
            .await
            .expect("an honest 1:1 attester MUST be admitted");
    assert_eq!((ledger.withdraws, ledger.recants), (1, 1));
    assert_eq!(ledger.ratio, 1.0);
    assert!(!ledger.is_arbitrage());
    assert_eq!(ledger.trust_multiplier(), 1.0, "no downweight for honesty");
}

/// A first-contact peer (no observed history) is clean — the countermeasure is
/// behavioral, not a presumption of guilt. This is the peering-time path.
#[tokio::test]
async fn unobserved_attester_is_clean() {
    let engine = node().await;
    register_self(&engine).await;
    let stranger = Attester::new("stranger", 0xD0);
    stranger.register(&engine).await;

    let ledger =
        withdraws_arbitrage::enforce(&engine, &stranger.key_id, policy(), chrono::Utc::now())
            .await
            .expect("an attester with no observed retractions is not an arbitrager");
    assert_eq!((ledger.withdraws, ledger.recants), (0, 0));
}

// ─────────────────────────────────────────────────────────────────────────────
// ADVERSARIAL — the substrate still admits every row (CC 2.4.1.1); the consumer
// policy REFUSES.
// ─────────────────────────────────────────────────────────────────────────────

/// **The arbitrage.** A misattester sprays `scores` claims and, when each one
/// fails to stick, emits `withdraws` — the free primitive — where an honest
/// attester would have emitted `recants`. Its `recants` count stays at zero, so the
/// trust penalty an acknowledged-error chain would have cost it never lands.
///
/// It is adversarial in three ways at once:
///
///   1. **Every row is valid.** Genuinely hybrid-signed, producer-self-withdrawn
///      (CC 2.4.1.1 admission rule 1) — the substrate MUST and DOES admit each one
///      (asserted below). There is nothing at the wire tier to reject.
///   2. **It pays a token toll.** It emits a `recants` — enough that a naive "has
///      this attester ever recanted?" check passes, and enough to make the
///      denominator non-zero. It still never approaches paying for the 26 rows it
///      erased for free.
///   3. **It tries to double-count that toll.** Its one substantive `recants`
///      targets a row it ALSO withdrew, so that the single admission of error would
///      score on BOTH sides of the ratio (denominator credit *and* a numerator slot
///      it already had). CEG §6.1 precedence collapses each (attester, upstream)
///      group to its highest-ranked composer, so that row counts as a `recants` and
///      NOT also as a `withdraws` — one retraction act, one tally mark.
#[tokio::test]
async fn spray_and_retract_arbitrage_is_refused() {
    let engine = node().await;
    register_self(&engine).await;
    let subject = node_key_id(&engine).await;

    let bad = Attester::new("arbitrage-attester", 0xE0);
    bad.register(&engine).await;

    // 30 aggressive claims.
    let mut sprayed = Vec::with_capacity(30);
    for _ in 0..30 {
        sprayed.push(bad.scores(&engine, &subject, 20).await);
    }
    // 26 of them erased with the FREE primitive — not one word about falsity.
    for id in sprayed.iter().take(26) {
        bad.withdraws(&engine, &subject, id, 10).await;
    }
    // The token toll: ONE error owned (defeats a naive "ever recanted?" check and
    // gives the ratio a non-zero denominator) …
    bad.recants(&engine, &subject, &sprayed[29], 9).await;
    // … and the double-count attempt: recant a row it ALSO withdrew, hoping that
    // single admission scores in the denominator while keeping its numerator slot.
    // Precedence says otherwise (the first sprayed row collapses to `recants`).
    bad.recants(&engine, &subject, &sprayed[0], 8).await;

    // (1) The SUBSTRATE admitted every row — the countermeasure is NOT a wire
    //     refusal (CC 2.4.1.1 MUST-admit / CC 4.1.2 "no new wire primitives").
    let rows = engine
        .federation_directory()
        .list_attestations_by(&bad.key_id)
        .await
        .expect("read the arbitrager's rows");
    assert_eq!(
        rows.len(),
        30 + 26 + 2,
        "every sprayed claim + every retraction is stored — the audit chain is complete"
    );

    // (2) The CONSUMER POLICY refuses.
    let refusal = withdraws_arbitrage::enforce(&engine, &bad.key_id, policy(), chrono::Utc::now())
        .await
        .expect_err("CC 4.1.4: the withdraws-arbitrage sequence MUST be refused");

    let ledger = match refusal {
        Refusal::Arbitrage(l) => *l,
        other => panic!("expected an Arbitrage refusal, got {other}"),
    };
    // The double-count attempt yielded nothing: the doubly-retracted row collapses
    // to its `recants` winner, so 26 withdraws − 1 collapsed = 25 withdraws against 2 recants
    // (12.5:1). Note which way the collapse cuts: it moved a row OFF the numerator,
    // i.e. it is the attacker-favourable, CEG-faithful count — and 12.5:1 is still
    // more than twice the 5:1 line. Buying the ratio down means actually admitting
    // error on the record, which is the price CC 4.1.4 exists to make it pay.
    assert_eq!(
        (ledger.withdraws, ledger.recants),
        (25, 2),
        "precedence-collapsed counts (a recanted upstream is NOT also a withdraw)"
    );
    assert_eq!(ledger.ratio, 12.5);
    assert!(ledger.ratio > DEFAULT_RATIO_THRESHOLD);
    assert!(ledger.is_arbitrage());
    assert!(
        ledger.trust_multiplier() < 1.0,
        "CC 4.1.4 SHOULD-downweight is graded and strictly below 1.0 for an arbitrager"
    );
}

/// **The pacing dodge.** The arbitrager spreads the SAME spray-and-retract volume
/// over a longer history so that only a few withdraws land inside the rolling
/// window. CC 4.1.4's window is a rolling window by design — behavior is forgiven
/// with age — so an attester that has genuinely slowed to a trickle clears. This
/// test pins the cost of that dodge: to stay clear it must keep its *in-window*
/// rate at or under the threshold, i.e. it must actually stop spraying.
#[tokio::test]
async fn stale_history_ages_out_but_in_window_spray_still_trips() {
    let engine = node().await;
    register_self(&engine).await;
    let subject = node_key_id(&engine).await;

    let paced = Attester::new("paced-attester", 0xF0);
    paced.register(&engine).await;

    // 20 withdraws, all older than the window → forgiven.
    for _ in 0..20 {
        let upstream = paced
            .scores(&engine, &subject, DEFAULT_WINDOW_DAYS + 40)
            .await;
        paced
            .withdraws(&engine, &subject, &upstream, DEFAULT_WINDOW_DAYS + 20)
            .await;
    }
    let cleared =
        withdraws_arbitrage::enforce(&engine, &paced.key_id, policy(), chrono::Utc::now())
            .await
            .expect("a purely historical spray ages out of the rolling window");
    assert_eq!((cleared.withdraws, cleared.recants), (0, 0));

    // It resumes inside the window → trips again on the fresh behavior alone.
    for _ in 0..6 {
        let upstream = paced.scores(&engine, &subject, 3).await;
        paced.withdraws(&engine, &subject, &upstream, 1).await;
    }
    let refusal =
        withdraws_arbitrage::enforce(&engine, &paced.key_id, policy(), chrono::Utc::now())
            .await
            .expect_err("6 in-window withdraws : 0 recants = 6:1 > 5:1 → refused");
    match refusal {
        Refusal::Arbitrage(l) => {
            assert_eq!((l.withdraws, l.recants), (6, 0));
            assert_eq!(l.ratio, 6.0);
        }
        other => panic!("expected an Arbitrage refusal, got {other}"),
    }
}

/// The threshold is CC-configurable ("a configured threshold (default 5:1)"). A
/// stricter consumer policy refuses an attester the default would have cleared —
/// and the refusal message carries the threshold it was judged against, so the
/// audit line is self-explaining.
#[tokio::test]
async fn a_stricter_configured_threshold_refuses_earlier() {
    let engine = node().await;
    register_self(&engine).await;
    let subject = node_key_id(&engine).await;

    let a = Attester::new("borderline-attester", 0xB7);
    a.register(&engine).await;
    for _ in 0..3 {
        let upstream = a.scores(&engine, &subject, 4).await;
        a.withdraws(&engine, &subject, &upstream, 2).await;
    }

    // Default 5:1 → 3:1 is clear.
    withdraws_arbitrage::enforce(&engine, &a.key_id, policy(), chrono::Utc::now())
        .await
        .expect("3 withdraws : 0 recants is under the default 5:1");

    // A consumer that configures 2:1 refuses the same history.
    let strict = ArbitragePolicy {
        ratio_threshold: 2.0,
        ..ArbitragePolicy::default()
    };
    let refusal = withdraws_arbitrage::enforce(&engine, &a.key_id, strict, chrono::Utc::now())
        .await
        .expect_err("3:1 exceeds a configured 2:1 threshold");
    assert!(
        refusal.to_string().contains("2.00:1 threshold"),
        "the refusal names the threshold it judged against: {refusal}"
    );
}
