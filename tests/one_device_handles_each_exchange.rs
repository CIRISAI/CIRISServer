//! **One device handles each exchange** (CC 3.1.3.1, CIRISPersist#782; the
//! maintainer's ruling of 2026-09-30, `FSD/SESSION_CLAIMS.md`).
//!
//! Two occurrences of ONE owner — two real substrates, each with its own
//! hybrid node key, each bound to the same minted fed-ID, each holding the
//! other's key and owner-binding the way claim-remote and replication leave
//! them — and the claim rows carried between them by hand, through each
//! receiver's own admission door, exactly as a round would carry them.
//!
//! What must hold:
//!
//! 1. **With no claim, neither device acts** — not even the one that could.
//! 2. **Only the claiming device acts**; the other, attended or not, defers
//!    and writes no claim of its own (a live claim is never contested).
//! 3. **After the claim lapses and the other device is the attended one, the
//!    other acts**, and the first defers to it.
//! 4. **A claim row authored by a third party is refused at admission** — and
//!    a stranger's claim about ITSELF never makes it a handler of this
//!    person's exchange.
//! 5. `GET /v1/self/sessions` names the SAME handler on both devices.
//! 6. The re-wrap of old self files — a real ACT site — runs only on the
//!    device the fold names.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::session_claim::SESSION_CLAIM_DIMENSION;
use ciris_persist::federation::types::{cohort_scope, identity_type, SignedAttestation};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use ciris_persist::wa_cert::WaRole;
use ciris_server::session_claims::{
    self, Attendance, Occupant, Step, Verdict, SELF_ROOM_MEMBERSHIP_SESSION,
};
use ed25519_dalek::SigningKey;

#[allow(dead_code)] // one fixture, several binaries: each uses a different subset
mod support {
    include!("support/drive_fixture.rs");
}
use support::*;

// ── two devices of one person ──────────────────────────────────────────────

/// The second device's seeds — `other_engine` builds its signer from them and
/// `seed_key` registers the same pubkeys on the first device.
const B_ED: u8 = 0xC1;
const B_PQC: u8 = 0xC2;

async fn other_engine(alias: &str, ed: u8, pqc: u8) -> Arc<Engine> {
    let pqc_signer = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[pqc; 32], format!("{alias}-pqc"))
            .expect("ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[ed; 32]),
        alias.to_string(),
        Some(pqc_signer),
        Some(format!("{alias}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

/// The owner-binding claim-remote records locally for the other device.
async fn record_binding(engine: &Engine, owner: &OwnerIdentity, node: &str) {
    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let binding = ciris_server::auth::ownership::build_signed_owner_binding(
        &owner.signer().await,
        node,
        &scopes,
        cohort_scope::SELF,
    )
    .await
    .expect("build the owner-binding");
    ciris_server::auth::ownership::apply_signed_owner_binding(
        engine,
        node,
        cohort_scope::SELF,
        HybridPolicy::Strict,
        &binding,
    )
    .await
    .expect("record the other device's owner-binding");
}

struct Person {
    owner: OwnerIdentity,
    a: Arc<Engine>,
    a_key: String,
    b: Arc<Engine>,
    b_key: String,
}

impl Person {
    /// Two devices of one owner, each knowing the other the way the claim and
    /// replication leave them: the other's hybrid key and owner-binding.
    async fn two_devices(b_alias: &str) -> Self {
        let owner = OwnerIdentity::mint().await;
        let a = node_engine().await;
        let a_key = register_self(&a).await;
        bind_owner(&a, &owner, &a_key).await;
        let b = other_engine(b_alias, B_ED, B_PQC).await;
        let b_key = register_self(&b).await;
        bind_owner(&b, &owner, &b_key).await;
        seed_key(&a, &b_key, B_ED, B_PQC, identity_type::NODE).await;
        record_binding(&a, &owner, &b_key).await;
        seed_key(&b, &a_key, 0xA1, 0xA2, identity_type::NODE).await;
        record_binding(&b, &owner, &a_key).await;
        Self {
            owner,
            a,
            a_key,
            b,
            b_key,
        }
    }

    fn occupant(&self, key: &str) -> Occupant {
        Occupant {
            owner: self.owner.key_id.clone(),
            occurrence: key.to_owned(),
        }
    }

    fn community(&self) -> String {
        session_claims::self_community(&self.owner.key_id)
    }
}

/// The session-claim rows `from_key` authored on `from` — self-reports.
async fn claims_by(from: &Engine, from_key: &str) -> Vec<SignedAttestation> {
    from.federation_directory()
        .list_attestations_for(from_key)
        .await
        .expect("rows about the occurrence")
        .into_iter()
        .filter(|r| {
            r.attesting_key_id == from_key
                && r.attestation_envelope
                    .get(ciris_persist::federation::envelope::paths::DIMENSION)
                    .and_then(|d| d.as_str())
                    == Some(SESSION_CLAIM_DIMENSION)
        })
        .map(|attestation| SignedAttestation { attestation })
        .collect()
}

/// Carry every claim `from_key` wrote on `from` to `to`, through `to`'s own
/// admission door — what a replication round does with a `self` row.
async fn carry_claims(from: &Engine, from_key: &str, to: &Engine) {
    for row in claims_by(from, from_key).await {
        to.federation_directory()
            .put_attestation(row)
            .await
            .expect("the receiving device admits its sibling's self-reported claim");
    }
}

// ── 1-3: who acts ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_device_acts_the_other_defers_and_takes_over_after_the_claim_lapses() {
    init_tracing();
    let p = Person::two_devices("ciris-sessions-b").await;
    let (att_a, att_b) = (Attendance::new(), Attendance::new());
    let community = p.community();
    let s = SELF_ROOM_MEMBERSHIP_SESSION;
    let t0 = chrono::Utc::now();

    // 1. NOBODY IS HERE: neither acts, neither claims. The lone-device
    //    shortcut ("only I could, so I will") is exactly what CC 3.1.3.1 bans.
    for (e, k, att) in [(&p.a, &p.a_key, &att_a), (&p.b, &p.b_key, &att_b)] {
        let v = session_claims::gate_at(e, att, &p.occupant(k), &community, s, "test", t0).await;
        assert_eq!(v, Verdict::Unclaimed, "no claim: nobody acts ({k})");
        assert!(
            claims_by(e, k).await.is_empty(),
            "an unattended device writes no claim"
        );
    }

    // 2. THE PERSON IS ON A: A takes the exchange on demand and acts.
    att_a.note_presence();
    let v = session_claims::gate_at(
        &p.a,
        &att_a,
        &p.occupant(&p.a_key),
        &community,
        s,
        "test",
        t0,
    )
    .await;
    assert_eq!(
        v,
        Verdict::Act,
        "the attended device claims what nobody holds, and acts"
    );
    carry_claims(&p.a, &p.a_key, &p.b).await;

    // …and B defers — even when the person is on B too. A live claim is never
    // contested, so B writes nothing.
    att_b.note_presence();
    let v = session_claims::gate_at(
        &p.b,
        &att_b,
        &p.occupant(&p.b_key),
        &community,
        s,
        "test",
        t0,
    )
    .await;
    assert_eq!(
        v,
        Verdict::HandledElsewhere {
            occurrence: p.a_key.clone()
        },
        "B sees A's claim and does not act"
    );
    assert!(
        claims_by(&p.b, &p.b_key).await.is_empty(),
        "B wrote no competing claim while A's is live"
    );
    // B's renewal pass agrees: defer, write nothing.
    let lines = session_claims::renew_once_at(&p.b, &att_b, t0).await;
    assert_eq!(
        lines.iter().map(|l| &l.step).collect::<Vec<_>>(),
        vec![&Step::Defer {
            handler: p.a_key.clone()
        }]
    );

    // A's renewal while the person stays: fresh lease → hold; 60 s on → renew.
    let lines = session_claims::renew_once_at(&p.a, &att_a, t0).await;
    assert_eq!(lines[0].step, Step::Hold, "{lines:?}");
    let renew_at = t0 + chrono::Duration::seconds(61);
    let lines = session_claims::renew_once_at(&p.a, &att_a, renew_at).await;
    assert_eq!(lines[0].step, Step::Renew, "{lines:?}");
    assert_eq!(
        claims_by(&p.a, &p.a_key).await.len(),
        2,
        "a successor lease was written"
    );

    // 3. THE PERSON LEAVES A. A lapses — writes nothing more.
    att_a.end_presence();
    let before = claims_by(&p.a, &p.a_key).await.len();
    let lines = session_claims::renew_once_at(&p.a, &att_a, renew_at).await;
    assert_eq!(lines[0].step, Step::Lapse, "{lines:?}");
    assert_eq!(
        claims_by(&p.a, &p.a_key).await.len(),
        before,
        "a lapsing device renews nothing"
    );

    // …while A's newest lease is live, B still defers…
    let v = session_claims::gate_at(
        &p.b,
        &att_b,
        &p.occupant(&p.b_key),
        &community,
        s,
        "test",
        renew_at,
    )
    .await;
    assert!(matches!(v, Verdict::HandledElsewhere { .. }), "{v:?}");

    // …and once every A lease is past the TTL, B (attended) takes it and acts.
    let lapsed = renew_at + chrono::Duration::from_std(session_claims::SESSION_CLAIM_TTL).unwrap();
    let v = session_claims::gate_at(
        &p.b,
        &att_b,
        &p.occupant(&p.b_key),
        &community,
        s,
        "test",
        lapsed,
    )
    .await;
    assert_eq!(v, Verdict::Act, "after A's claim lapsed, B is the handler");
    carry_claims(&p.b, &p.b_key, &p.a).await;
    let v = session_claims::gate_at(
        &p.a,
        &att_a,
        &p.occupant(&p.a_key),
        &community,
        s,
        "test",
        lapsed,
    )
    .await;
    assert_eq!(
        v,
        Verdict::HandledElsewhere {
            occurrence: p.b_key.clone()
        },
        "A, whose person left, now defers to B"
    );

    // 5. BOTH DEVICES NAME THE SAME HANDLER on the surface's body.
    let va = session_claims::sessions_view(&p.a, &att_a, &p.owner.key_id, &p.a_key)
        .await
        .expect("A's view");
    let vb = session_claims::sessions_view(&p.b, &att_b, &p.owner.key_id, &p.b_key)
        .await
        .expect("B's view");
    // (The view reads the real clock, when B's claim — dated `lapsed`, in the
    // future — is live and A's are too: the fold's earliest live claim is A's.
    // Both devices must agree on it, which is the property; which one it is
    // follows from persist's merge.)
    let handler = |v: &serde_json::Value| -> Option<String> {
        v["sessions"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["session_id"] == s))
            .and_then(|x| x["handler_occurrence_key_id"].as_str().map(str::to_owned))
    };
    assert!(handler(&va).is_some(), "A lists the exchange: {va}");
    assert_eq!(
        handler(&va),
        handler(&vb),
        "both devices name ONE handler: {va} / {vb}"
    );
}

// ── 4: a third party cannot claim for the person ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_authored_by_a_third_party_is_refused_at_admission() {
    init_tracing();
    let p = Person::two_devices("ciris-sessions-third").await;
    let stranger_alias = "session-claim-stranger";
    seed_key(&p.a, stranger_alias, 0x7A, 0x7B, identity_type::NODE).await;
    let stranger = LocalSigner::from_parts(
        SigningKey::from_bytes(&[0x7A; 32]),
        stranger_alias.to_string(),
        Some(Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[0x7B; 32], format!("{stranger_alias}-pqc"))
                .expect("pqc"),
        )),
        Some(format!("{stranger_alias}-pqc")),
    );
    let community = p.community();

    // A claim ABOUT the person's device, signed by someone else: refused.
    let env = serde_json::json!({
        (ciris_persist::federation::envelope::paths::DIMENSION): SESSION_CLAIM_DIMENSION,
        "score": 1.0,
        "community_id": community,
        "session_id": SELF_ROOM_MEMBERSHIP_SESSION,
        "claimed_at": session_claims::canonical_instant(chrono::Utc::now()),
    });
    let err = ciris_server::attest::emit(
        &p.a,
        ciris_server::attest::KeySigner::Local(&stranger),
        ciris_server::attest::Spec::new(
            ciris_persist::federation::types::attestation_type::SCORES,
            cohort_scope::SELF,
            env,
        )
        .attested_to(&p.a_key)
        .weighing(Some(1.0)),
    )
    .await
    .expect_err("a third party's session claim must be refused at the door");
    assert!(
        format!("{err}").contains("SELF-REPORT"),
        "refused BY NAME as a self-report violation: {err}"
    );

    // A stranger's claim about ITSELF is admitted (it is a well-formed
    // self-report) — and makes it no handler of this person's exchange: the
    // fold walks the person's own occurrences only.
    session_claims::write_claim(
        &p.a,
        ciris_server::attest::KeySigner::Local(&stranger),
        &community,
        SELF_ROOM_MEMBERSHIP_SESSION,
        chrono::Utc::now(),
        chrono::Utc::now() + chrono::Duration::from_std(session_claims::SESSION_CLAIM_TTL).unwrap(),
    )
    .await
    .expect("a self-report about oneself admits");
    let v = session_claims::gate(
        &p.a,
        &Attendance::new(),
        &p.occupant(&p.a_key),
        &community,
        SELF_ROOM_MEMBERSHIP_SESSION,
        "test",
    )
    .await;
    assert_eq!(
        v,
        Verdict::Unclaimed,
        "an outsider's claim is not one of the person's occurrences — nobody acts"
    );
}

// ── 6: a real ACT site — the re-wrap for a new device ──────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_rewrap_runs_only_on_the_device_the_fold_names() {
    use ciris_persist::federation::blobs::BlobStorage as _;
    init_tracing();
    let p = Person::two_devices("ciris-sessions-rewrap").await;

    // A holds a self file written before B's content occurrence existed.
    let bearer = mint_session(&p.a, "wa-sessions-owner", WaRole::Root).await;
    let base = serve_drive(
        Arc::clone(&p.a),
        node_edge_signer(&p.a).await,
        p.owner.seed_dir.clone(),
    )
    .await;
    let client = reqwest::Client::new();
    let (st, v) = status_json(
        client
            .post(format!("{base}/v1/files"))
            .bearer_auth(&bearer)
            .json(&serde_json::json!({
                "cohort": "self",
                "bytes_base64": BASE64.encode(b"one device re-wraps this"),
                "media_type": "text/plain",
                "filename": "before.txt",
            }))
            .send()
            .await
            .expect("POST /v1/files"),
    )
    .await;
    assert_eq!(st, 200, "self upload: {v}");
    let id = v["attestation_id"].as_str().expect("id").to_owned();
    let (st, meta) = status_json(
        client
            .get(format!("{base}/v1/files/{id}/meta?cohort=self"))
            .bearer_auth(&bearer)
            .send()
            .await
            .expect("meta"),
    )
    .await;
    assert_eq!(st, 200, "{meta}");
    let sha: [u8; 32] = hex::decode(meta["at_rest_sha256"].as_str().expect("sha"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");

    // B provisions its content occurrence; the signed row crosses to A.
    let (occurrence, _) = ciris_server::backend::provision_engine_occurrence(&p.b, &p.owner.key_id)
        .await
        .expect("B provisions its occurrence");
    let row =
        p.b.federation_directory()
            .list_signed_identity_occurrences_for(&p.owner.key_id)
            .await
            .expect("signed occurrences")
            .into_iter()
            .find(|o| o.identity_occurrence.occurrence_key_id == occurrence)
            .expect("the occurrence rides the signed plane");
    p.a.federation_directory()
        .put_identity_occurrence(row)
        .await
        .expect("A admits B's occurrence");
    let granted_to_b = || async {
        p.a.sqlite_backend()
            .expect("sqlite")
            .list_at_rest_grant_recipients(&sha)
            .await
            .expect("recipients")
            .contains(&occurrence)
    };

    // The pen opens on A (what compose registers at boot).
    ciris_server::node_key::set_user_seed_dir(p.owner.seed_dir.clone(), p.owner.alias.clone());
    let community = p.community();
    let session = session_claims::rewrap_session(&occurrence);

    // UNCLAIMED, nobody attended on A: the pen is here, the work is pending,
    // and NOTHING runs.
    let att_a = Attendance::new();
    let r = ciris_server::self_rewrap::rewrap_for_new_devices_with(&p.a, &p.a_key, &att_a).await;
    assert_eq!(r.pending, vec![occurrence.clone()], "{r:?}");
    assert!(!r.no_pen_here, "{r:?}");
    assert_eq!(
        r.not_handled_here,
        vec![(occurrence.clone(), None)],
        "{r:?}"
    );
    assert!(
        r.rewrapped.is_empty(),
        "the server re-wrap did not run here: {r:?}"
    );
    // persist v53 (I397b–d) re-keys a device the moment its occurrence is
    // admitted, so B already holds the old file's key. The server's re-wrap
    // stays as the catch-up for devices admitted BEFORE v53, which persist's
    // walk never saw; what this test pins is that it runs only where the fold
    // names this device.
    assert!(granted_to_b().await, "persist re-keyed B at admission");

    // HANDLED ELSEWHERE: another device of the person holds a live claim on
    // this re-wrap (written there, carried here). A, attended, defers. The
    // claim is dated so it has ~10 s of life left: long enough for this step,
    // short enough to watch it lapse below without waiting out the TTL.
    let ttl = chrono::Duration::from_std(session_claims::SESSION_CLAIM_TTL).unwrap();
    session_claims::write_claim(
        &p.b,
        ciris_server::attest::KeySigner::Engine(&p.b),
        &community,
        &session,
        chrono::Utc::now() - ttl + chrono::Duration::seconds(10),
        // persist v52.0.1 judges the SIGNED lease: it ends ~10 s from now.
        chrono::Utc::now() + chrono::Duration::seconds(10),
    )
    .await
    .expect("B claims");
    carry_claims(&p.b, &p.b_key, &p.a).await;
    att_a.note_presence();
    let r = ciris_server::self_rewrap::rewrap_for_new_devices_with(&p.a, &p.a_key, &att_a).await;
    assert_eq!(
        r.not_handled_here,
        vec![(occurrence.clone(), Some(p.b_key.clone()))],
        "{r:?}"
    );
    assert!(
        r.rewrapped.is_empty(),
        "the server re-wrap did not run here: {r:?}"
    );
    // persist v53 (I397b–d) re-keys a device the moment its occurrence is
    // admitted, so B already holds the old file's key. The server's re-wrap
    // stays as the catch-up for devices admitted BEFORE v53, which persist's
    // walk never saw; what this test pins is that it runs only where the fold
    // names this device.
    assert!(granted_to_b().await, "persist re-keyed B at admission");
    assert!(
        claims_by(&p.a, &p.a_key).await.is_empty(),
        "A did not contest B's live claim"
    );

    // HANDLED HERE: B's claim lapses (nobody renewed it); A, attended, takes
    // the session and the re-wrap RUNS — once.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    let r = ciris_server::self_rewrap::rewrap_for_new_devices_with(&p.a, &p.a_key, &att_a).await;
    assert!(r.not_handled_here.is_empty(), "{r:?}");
    assert_eq!(r.rewrapped.len(), 1, "{r:?}");
    assert!(granted_to_b().await, "the old self file now opens on B");
    assert_eq!(
        claims_by(&p.a, &p.a_key).await.len(),
        1,
        "A claimed the re-wrap on demand before acting"
    );

    // IDEMPOTENT per act: the next pass has nothing pending.
    let again =
        ciris_server::self_rewrap::rewrap_for_new_devices_with(&p.a, &p.a_key, &att_a).await;
    assert!(
        again.pending.is_empty() && again.rewrapped.is_empty(),
        "{again:?}"
    );
}

// ── persist v52.0.1: a renewal keeps claimed_at ────────────────────────────

/// The `claimed_at` every claim row `key` wrote on `engine` carries, oldest row
/// first (by `valid_until`).
async fn claimed_ats(engine: &Engine, key: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = claims_by(engine, key)
        .await
        .into_iter()
        .map(|r| {
            let e = &r.attestation.attestation_envelope;
            (
                e["valid_until"].as_str().unwrap_or_default().to_owned(),
                e["claimed_at"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    v.sort();
    v
}

/// **A renewed claim never moves the handler** (persist v52.0.1,
/// CIRISPersist#946 read side). A claims and renews THREE times; every
/// renewal row keeps A's ORIGINAL `claimed_at` and carries a later signed
/// `valid_until`. B, with each row carried to it, defers to A at every step —
/// including the instant just past the first lease's end, where the pre-v52.0.1
/// fold (`now − claimed_at < ttl`) would have dropped A and let B take over.
/// Then the cap: once a renewal would push `valid_until` past `claimed_at +
/// 1 day`, A writes a FRESH claim dated then, and B still defers (A's older
/// row is live to the cap).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewals_keep_claimed_at_and_the_other_device_never_sees_the_handler_move() {
    init_tracing();
    let p = Person::two_devices("ciris-sessions-renew-b").await;
    let (att_a, att_b) = (Attendance::new(), Attendance::new());
    att_a.note_presence();
    att_b.note_presence();
    let community = p.community();
    let s = SELF_ROOM_MEMBERSHIP_SESSION;
    let ttl = chrono::Duration::from_std(session_claims::SESSION_CLAIM_TTL).unwrap();
    let t0 =
        ciris_persist::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
    let b_defers = |at: chrono::DateTime<chrono::Utc>, why: &'static str| {
        let (p, att_b, community) = (&p, &att_b, community.clone());
        async move {
            let v = session_claims::gate_at(
                &p.b,
                att_b,
                &p.occupant(&p.b_key),
                &community,
                s,
                "test",
                at,
            )
            .await;
            assert_eq!(
                v,
                Verdict::HandledElsewhere {
                    occurrence: p.a_key.clone()
                },
                "{why}"
            );
            assert!(
                claims_by(&p.b, &p.b_key).await.is_empty(),
                "B never wrote a competing claim ({why})"
            );
        }
    };

    let v = session_claims::gate_at(
        &p.a,
        &att_a,
        &p.occupant(&p.a_key),
        &community,
        s,
        "test",
        t0,
    )
    .await;
    assert_eq!(v, Verdict::Act);
    let original = att_a.claimed_at(&community, s).expect("A's claimed_at");
    carry_claims(&p.a, &p.a_key, &p.b).await;
    b_defers(t0, "A just claimed").await;

    // Three renewals, each at the renewal threshold; B checks across each.
    let step = chrono::Duration::from_std(session_claims::SESSION_CLAIM_RENEW_AFTER).unwrap()
        + chrono::Duration::seconds(1);
    let mut now = t0;
    for n in 1..=3 {
        now += step;
        let lines = session_claims::renew_once_at(&p.a, &att_a, now).await;
        assert_eq!(lines[0].step, Step::Renew, "renewal {n}: {lines:?}");
        carry_claims(&p.a, &p.a_key, &p.b).await;
        assert_eq!(
            att_a.claimed_at(&community, s),
            Some(original),
            "renewal {n} keeps the original claimed_at"
        );
        // Just past where the PREVIOUS lease ended — and, from the second
        // renewal on, past t0 + TTL, where the old ttl-from-claimed_at fold
        // dropped A.
        b_defers(now + chrono::Duration::seconds(1), "across a renewal").await;
    }
    assert!(
        now + chrono::Duration::seconds(1) > t0 + ttl,
        "the test crossed the first lease's end"
    );
    let rows = claimed_ats(&p.a, &p.a_key).await;
    assert_eq!(rows.len(), 4, "a claim and three renewals: {rows:?}");
    let original_s = session_claims::canonical_instant(original);
    assert!(
        rows.iter().all(|(_, c)| *c == original_s),
        "every renewal keeps claimed_at {original_s}: {rows:?}"
    );

    // THE CAP: a renewal past claimed_at + 1 day is a fresh claim. The day of
    // renewals is stood in by A's longest admissible lease on the original
    // claim (valid_until = claimed_at + 1 day, persist's bound), so the
    // holder is still A, by that claimed_at, a minute before the cap.
    let cap = original
        + chrono::Duration::seconds(ciris_persist::federation::admission::SESSION_LEASE_MAX_SECS);
    session_claims::write_claim(
        &p.a,
        ciris_server::attest::KeySigner::Engine(&p.a),
        &community,
        s,
        original,
        cap,
    )
    .await
    .expect("persist admits a lease of exactly a day");
    carry_claims(&p.a, &p.a_key, &p.b).await;
    let past_cap = cap - chrono::Duration::seconds(60);
    b_defers(past_cap, "a minute before the cap, on the day-long lease").await;
    let lines = session_claims::renew_once_at(&p.a, &att_a, past_cap).await;
    assert_eq!(lines[0].step, Step::Renew, "{lines:?}");
    let fresh = att_a.claimed_at(&community, s).expect("claimed_at");
    assert_eq!(
        fresh, past_cap,
        "a renewal would pass the cap, so the holder claims afresh, dated now"
    );
    let rows = claimed_ats(&p.a, &p.a_key).await;
    assert_eq!(
        rows.last().map(|(_, c)| c.clone()),
        Some(session_claims::canonical_instant(past_cap)),
        "{rows:?}"
    );
    carry_claims(&p.a, &p.a_key, &p.b).await;
    b_defers(past_cap, "across the cap's fresh claim").await;
}
