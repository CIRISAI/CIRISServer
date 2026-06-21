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
