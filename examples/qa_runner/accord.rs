//! Reusable QA module — the HUMANITY_ACCORD kill-switch lifecycle over the real
//! HTTP surface, with SOFTWARE holders: register holders → genesis (entrench the
//! family) → roster=seats (spares are not seats) → invocation open/concur → 2/3
//! verify → self-quorum refused → CONSTITUTIONAL halt latched + startup gated.

use ciris_server::accord::AccordHalt;
use ciris_server::accord_halt::{check_halt_gate, halt_latch_path};

use crate::common::{invocation, mint_owner_session, node, serve, Report, SoftId};

async fn jpost(
    client: &reqwest::Client,
    url: String,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> (u16, serde_json::Value) {
    let mut req = client.post(&url).json(&body);
    if let Some(b) = bearer {
        req = req.bearer_auth(b);
    }
    let resp = req.send().await.expect("post");
    let status = resp.status().as_u16();
    let json = resp
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub async fn run(report: &mut Report) {
    println!("\n\x1b[1m▶ ACCORD — kill-switch lifecycle (HTTP, software holders)\x1b[0m");
    let m = "accord";
    let engine = node().await;
    let owner = mint_owner_session(&engine).await;

    let home = std::env::temp_dir().join(format!("qa-accord-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("temp home");
    let _ = std::fs::remove_file(halt_latch_path(&home));
    let base = serve(
        std::sync::Arc::clone(&engine),
        AccordHalt {
            home: Some(home.clone()),
            peers: Vec::new(),
            exit_on_halt: false,
        },
    )
    .await;
    let client = reqwest::Client::new();

    let holders = [
        SoftId::new("qa-holder-a", 0xC1),
        SoftId::new("qa-holder-b", 0xC2),
        SoftId::new("qa-holder-c", 0xC3),
    ];

    // 1. Register the 3 holders (hardware-attested accord_holder records).
    let mut reg_ok = true;
    for h in &holders {
        let (s, _) = jpost(
            &client,
            format!("{base}/v1/accord/holder"),
            Some(&owner),
            serde_json::json!({ "key_record": h.signed_key_record("accord_holder").await }),
        )
        .await;
        reg_ok &= s == 200;
    }
    report.check(m, "register 3 holders", reg_ok, "");

    // 2. Genesis: envelope → 2/3 founder co-sign → assemble (entrench the family).
    let member_ids: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
    let (_s, env) = jpost(
        &client,
        format!("{base}/v1/accord/genesis/envelope"),
        Some(&owner),
        serde_json::json!({ "family_name": "HUMANITY_ACCORD", "member_key_ids": member_ids }),
    )
    .await;
    let envelope = env["envelope"].clone();
    let mut founders = Vec::new();
    for h in &holders {
        founders.push(h.founder_member().await);
    }
    let signatures = vec![
        holders[0].family_cosign(&envelope).await,
        holders[1].family_cosign(&envelope).await,
    ];
    let (s, _aj) = jpost(
        &client,
        format!("{base}/v1/accord/genesis/assemble"),
        Some(&owner),
        serde_json::json!({ "envelope": envelope, "founders": founders, "signatures": signatures }),
    )
    .await;
    report.check(
        m,
        "genesis assemble (2/3 founders) → entrench family",
        s == 200,
        format!("status {s}"),
    );

    // 3. Register a cold SPARE (a registered accord_holder that is NOT a seat).
    let spare = SoftId::new("qa-holder-a-spare", 0xC9);
    let (s, _) = jpost(
        &client,
        format!("{base}/v1/accord/holder"),
        Some(&owner),
        serde_json::json!({ "key_record": spare.signed_key_record("accord_holder").await }),
    )
    .await;
    report.record(m, "register cold spare", s == 200, "");

    // 4. Roster = the 3 SEATS; the spare is registered but not seated.
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    report.check(
        m,
        "roster: 3 seats, 4 registered (spare not a seat)",
        roster["family_established"] == true
            && roster["seat_count"] == 3
            && roster["registered_total"] == 4,
        format!(
            "seats={} registered={}",
            roster["seat_count"], roster["registered_total"]
        ),
    );

    // 5. Invocation concurrence: open (1/3, sub-quorum) → concur (2/3).
    let inv = invocation("drill", "qa-concur", b"qa-concur");
    let (_s, opened) = jpost(
        &client,
        format!("{base}/v1/accord/invocation"),
        None,
        serde_json::json!({ "invocation": inv, "signature": holders[0].cosign_invocation(&inv).await }),
    )
    .await;
    report.check(
        m,
        "open invocation → sub-quorum",
        opened["quorum_met"] == false,
        format!("quorum_met={}", opened["quorum_met"]),
    );
    let (_s, concurred) = jpost(
        &client,
        format!("{base}/v1/accord/invocation/concur"),
        None,
        serde_json::json!({ "invocation_kind": "drill", "invocation_id": "qa-concur", "signature": holders[1].cosign_invocation(&inv).await }),
    )
    .await;
    report.check(
        m,
        "concur → 2/3 quorum met",
        concurred["quorum_met"] == true,
        format!("quorum_met={}", concurred["quorum_met"]),
    );

    // 6. Authoritative 2/3 verify (against the family seats).
    let vinv = invocation("drill", "qa-verify", b"qa-verify");
    let (_s, verdict) = jpost(
        &client,
        format!("{base}/v1/accord/verify-invocation"),
        None,
        serde_json::json!({
            "invocation": vinv,
            "signatures": [holders[0].cosign_invocation(&vinv).await, holders[1].cosign_invocation(&vinv).await],
            "now": "2026-06-21T00:00:01.000Z",
        }),
    )
    .await;
    report.check(
        m,
        "verify-invocation 2/3 → verified",
        verdict["verified"] == true,
        format!("{verdict}"),
    );

    // 7. Self-quorum REFUSED: a seat + that seat-holder's own SPARE is NOT 2-of-3
    //    (the spare is not a seat, so only 1 valid signer — verified=false).
    let sq = invocation("CONSTITUTIONAL", "qa-selfquorum", b"qa-selfquorum");
    let (_s, sqr) = jpost(
        &client,
        format!("{base}/v1/accord/verify-invocation"),
        None,
        serde_json::json!({
            "invocation": sq,
            "signatures": [holders[0].cosign_invocation(&sq).await, spare.cosign_invocation(&sq).await],
            "now": "2026-06-21T00:00:02.000Z",
        }),
    )
    .await;
    report.check(
        m,
        "self-quorum (seat + own spare) NOT verified",
        sqr["verified"] == false,
        format!("{sqr}"),
    );

    // 8. The real kill: open a CONSTITUTIONAL invocation + concur to 2/3 (the concur
    //    itself latches the halt), then deliver the server-produced 2/3 object to
    //    /v1/accord/message → halted; the latch then gates startup.
    let halt = invocation("CONSTITUTIONAL", "qa-halt", b"qa-halt");
    jpost(
        &client,
        format!("{base}/v1/accord/invocation"),
        None,
        serde_json::json!({ "invocation": halt, "signature": holders[0].cosign_invocation(&halt).await }),
    )
    .await;
    let (_s, concurred) = jpost(
        &client,
        format!("{base}/v1/accord/invocation/concur"),
        None,
        serde_json::json!({ "invocation_kind": "CONSTITUTIONAL", "invocation_id": "qa-halt", "signature": holders[1].cosign_invocation(&halt).await }),
    )
    .await;
    report.check(
        m,
        "2/3 CONSTITUTIONAL concur → quorum met",
        concurred["quorum_met"] == true,
        format!("quorum_met={}", concurred["quorum_met"]),
    );
    // The 2/3 object the server produced — deliver it to the inbound message sink.
    let obj = concurred["invocation"].clone();
    let (_s, hr) = jpost(&client, format!("{base}/v1/accord/message"), None, obj).await;
    report.check(
        m,
        "deliver 2/3 CONSTITUTIONAL to /message → halted",
        hr["halted"] == true,
        format!("{hr}"),
    );
    report.check(m, "halt latch written", halt_latch_path(&home).exists(), "");
    report.check(
        m,
        "startup gate refuses boot while latched",
        check_halt_gate(&home).is_err(),
        "",
    );

    let _ = std::fs::remove_dir_all(&home);
}

/// Membership-change lifecycle (supersede / reconstitute) over the 2/3-quorum gate.
pub async fn run_membership(report: &mut Report) {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    println!("\n\x1b[1m▶ ACCORD — membership change (supersede / reconstitute, 2/3)\x1b[0m");
    let m = "membership";
    let engine = node().await;
    let owner = mint_owner_session(&engine).await;
    let base = serve(
        std::sync::Arc::clone(&engine),
        AccordHalt {
            home: None,
            peers: Vec::new(),
            exit_on_halt: false,
        },
    )
    .await;
    let client = reqwest::Client::new();

    // Genesis: a 3-seat family {a,b,c}, quorum:2/3 — plus vaulted spares d,e,f.
    let h = [
        SoftId::new("mc-a", 0xA1),
        SoftId::new("mc-b", 0xA2),
        SoftId::new("mc-c", 0xA3),
    ];
    let spares = [
        SoftId::new("mc-d", 0xA4),
        SoftId::new("mc-e", 0xA5),
        SoftId::new("mc-f", 0xA6),
    ];
    for id in h.iter().chain(spares.iter()) {
        jpost(
            &client,
            format!("{base}/v1/accord/holder"),
            Some(&owner),
            serde_json::json!({ "key_record": id.signed_key_record("accord_holder").await }),
        )
        .await;
    }
    let member_ids: Vec<String> = h.iter().map(|x| x.key_id.clone()).collect();
    let (_s, env) = jpost(
        &client,
        format!("{base}/v1/accord/genesis/envelope"),
        Some(&owner),
        serde_json::json!({ "family_name": "HUMANITY_ACCORD", "member_key_ids": member_ids }),
    )
    .await;
    let envelope = env["envelope"].clone();
    let mut founders = Vec::new();
    for x in &h {
        founders.push(x.founder_member().await);
    }
    let (s, _) = jpost(
        &client,
        format!("{base}/v1/accord/genesis/assemble"),
        Some(&owner),
        serde_json::json!({ "envelope": envelope,
            "founders": founders,
            "signatures": [h[0].family_cosign(&envelope).await, h[1].family_cosign(&envelope).await] }),
    )
    .await;
    report.check(m, "genesis 3-seat family (quorum:2/3)", s == 200, "");

    // Helper: change-envelope → cosign by `signers` → supersede.
    async fn change(
        client: &reqwest::Client,
        base: &str,
        owner: &str,
        new_ids: &[String],
        cp: &str,
        signers: &[&SoftId],
    ) -> (u16, serde_json::Value) {
        let b64 = base64::engine::general_purpose::STANDARD;
        let (_s, env) = jpost(
            client,
            format!("{base}/v1/accord/family/change/envelope"),
            Some(owner),
            serde_json::json!({ "new_member_key_ids": new_ids, "consensus_protocol": cp }),
        )
        .await;
        let change_envelope = env["change_envelope"].clone();
        let bytes = b64
            .decode(env["signing_bytes_base64"].as_str().unwrap_or_default())
            .unwrap_or_default();
        let mut sigs = Vec::new();
        for s in signers {
            sigs.push(s.sign_bytes(&bytes).await);
        }
        jpost(
            client,
            format!("{base}/v1/accord/family/supersede"),
            Some(owner),
            serde_json::json!({ "change_envelope": change_envelope, "signatures": sigs }),
        )
        .await
    }
    let _ = b64; // (decode used inside `change`)

    // SUPERSEDE: replace seat a → spare d (same N=3). Current roster {a,b,c} — b,c
    // cosign (a is the one being replaced). Roster becomes {b,c,d}.
    let new1 = vec![
        h[1].key_id.clone(),
        h[2].key_id.clone(),
        spares[0].key_id.clone(),
    ];
    let (s1, r1) = change(&client, &base, &owner, &new1, "quorum:2/3", &[&h[1], &h[2]]).await;
    report.check(
        m,
        "supersede replace a→d (2/3) ",
        s1 == 200 && r1["superseded"] == true,
        format!("{r1}"),
    );
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let seats: Vec<String> = roster["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["key_id"].as_str().unwrap_or("").to_string())
        .collect();
    report.check(
        m,
        "roster now {b,c,d} (a replaced)",
        roster["seat_count"] == 3
            && seats.contains(&"mc-d".to_string())
            && !seats.contains(&"mc-a".to_string()),
        format!("{seats:?}"),
    );

    // RECONSTITUTE: expand {b,c,d} → {b,c,d,e,f}. Strict majority forces quorum:3/5.
    // Current roster {b,c,d} — b,c cosign (2 of 3).
    let new2 = vec![
        h[1].key_id.clone(),
        h[2].key_id.clone(),
        spares[0].key_id.clone(),
        spares[1].key_id.clone(),
        spares[2].key_id.clone(),
    ];
    let (s2, r2) = change(&client, &base, &owner, &new2, "quorum:3/5", &[&h[1], &h[2]]).await;
    report.check(
        m,
        "reconstitute expand 3→5 (→quorum:3/5)",
        s2 == 200
            && r2["superseded"] == true
            && r2["consensus_protocol"] == "quorum:3/5"
            && r2["member_count"] == 5,
        format!("{r2}"),
    );

    // NEGATIVE: a 1-signature change is rejected by the substrate quorum gate (now
    // quorum:3/5 needs ≥3) — live row untouched.
    let new3 = vec![
        h[1].key_id.clone(),
        h[2].key_id.clone(),
        spares[0].key_id.clone(),
        spares[1].key_id.clone(),
        h[0].key_id.clone(),
    ];
    let (s3, r3) = change(&client, &base, &owner, &new3, "quorum:3/5", &[&h[1]]).await;
    report.check(
        m,
        "1-signature change REJECTED (quorum gate)",
        s3 != 200 && r3["superseded"] != true,
        format!("status {s3}"),
    );

    // HISTORY: the supersede chain is auditable.
    let hist: serde_json::Value = client
        .get(format!("{base}/v1/accord/family/history"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    report.check(
        m,
        "family/history records the supersede chain",
        hist["versions"]
            .as_array()
            .map(|v| v.len() >= 2)
            .unwrap_or(false),
        format!(
            "versions={}",
            hist["versions"].as_array().map(|v| v.len()).unwrap_or(0)
        ),
    );
}

/// The FULL genesis ceremony, software-key: 3 primaries (→ family SEATS) + 3 cold
/// spares (→ vaulted, registered-not-seated) + assemble. The reference flow the
/// guided KMP wizard mirrors (the wizard adds the per-key pkcs11 provisioning the
/// hardware ceremony needs; the registration + genesis orchestration is this).
pub async fn run_ceremony(report: &mut Report) {
    println!("\n\x1b[1m▶ ACCORD — full genesis ceremony (3 humans × {{primary, spare}})\x1b[0m");
    let m = "ceremony";
    let engine = node().await;
    let owner = mint_owner_session(&engine).await;
    let base = serve(
        std::sync::Arc::clone(&engine),
        AccordHalt {
            home: None,
            peers: Vec::new(),
            exit_on_halt: false,
        },
    )
    .await;
    let client = reqwest::Client::new();

    // 3 humans, each a primary (seat) + a cold spare (vault).
    let primaries = [
        SoftId::new("cer-alice-primary", 0x31),
        SoftId::new("cer-bob-primary", 0x32),
        SoftId::new("cer-carol-primary", 0x33),
    ];
    let spares = [
        SoftId::new("cer-alice-spare", 0x34),
        SoftId::new("cer-bob-spare", 0x35),
        SoftId::new("cer-carol-spare", 0x36),
    ];
    // Walk all 6 keys (A1, A2, B1, B2, C1, C2 order), registering each.
    let order = [
        &primaries[0],
        &spares[0],
        &primaries[1],
        &spares[1],
        &primaries[2],
        &spares[2],
    ];
    let mut all_ok = true;
    for (i, id) in order.iter().enumerate() {
        let (s, _) = jpost(
            &client,
            format!("{base}/v1/accord/holder"),
            Some(&owner),
            serde_json::json!({ "key_record": id.signed_key_record("accord_holder").await }),
        )
        .await;
        all_ok &= s == 200;
        report.record(
            m,
            &format!("key {}/6 registered ({})", i + 1, id.key_id),
            s == 200,
            "",
        );
    }
    report.check(m, "all 6 keys registered", all_ok, "");

    // Genesis over the 3 PRIMARIES only (the seats); 2/3 cosign → assemble.
    let member_ids: Vec<String> = primaries.iter().map(|p| p.key_id.clone()).collect();
    let (_s, env) = jpost(
        &client,
        format!("{base}/v1/accord/genesis/envelope"),
        Some(&owner),
        serde_json::json!({ "family_name": "HUMANITY_ACCORD", "member_key_ids": member_ids }),
    )
    .await;
    let envelope = env["envelope"].clone();
    let mut founders = Vec::new();
    for p in &primaries {
        founders.push(p.founder_member().await);
    }
    let (s, asm) = jpost(
        &client,
        format!("{base}/v1/accord/genesis/assemble"),
        Some(&owner),
        serde_json::json!({ "envelope": envelope, "founders": founders,
            "signatures": [primaries[0].family_cosign(&envelope).await, primaries[1].family_cosign(&envelope).await] }),
    )
    .await;
    report.check(
        m,
        "assemble family genesis (2/3 founders)",
        s == 200,
        format!("status {s}"),
    );
    // The signed genesis is the bake artifact (→ CIRISVerify#107).
    report.check(
        m,
        "genesis object emitted (bake artifact for cold-start root)",
        asm.get("genesis").is_some(),
        "",
    );

    // Roster = the 3 SEATS; all 6 registered; the spares are NOT seats.
    let roster: serde_json::Value = client
        .get(format!("{base}/v1/accord-holders"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let seats: Vec<String> = roster["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["key_id"].as_str().unwrap_or("").to_string())
        .collect();
    report.check(
        m,
        "3 seats = the 3 primaries",
        roster["seat_count"] == 3 && seats.iter().all(|s| s.ends_with("-primary")),
        format!("{seats:?}"),
    );
    report.check(
        m,
        "6 registered (3 seats + 3 vaulted spares)",
        roster["registered_total"] == 6,
        format!("registered={}", roster["registered_total"]),
    );
    report.check(
        m,
        "spares registered but NOT seats",
        !seats.iter().any(|s| s.ends_with("-spare")),
        format!("{seats:?}"),
    );
}
