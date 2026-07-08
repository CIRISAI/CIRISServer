//! Reusable QA module — the **canonical trace-flow precondition** (CIRISServer#191 /
//! CIRISPersist#390/#392). The agent's directed `consent:community_trust:v1` grant is
//! aimed at the canonical community group; for it to FK-resolve its counterparty the
//! node's `federation_keys` must carry the baked canonical server, and the record must
//! be fully addressable (pubkeys + transport hint). This module boots a fresh node and
//! asserts, over the real HTTP surface, that:
//!   - the baked genesis canonical server `ciris-canonical-1-d7bdeu223k` is present
//!     (was empty until the 2-of-3 genesis bake #390 — the whole point of the seed);
//!   - it is addressable — carries the hybrid pubkeys + an IP transport hint, so a
//!     directed grant can reach it by `key_id`;
//!   - the HUMANITY_ACCORD trust-root family it roots under is entrenched (2-of-3).
//!
//! Guards the regression class of CIRISPersist#392 at the server tier: a wheel/engine
//! that seeds holders but NOT the canonical server leaves this whole flow dark.

use crate::common::{node_seeded, serve, Report};
use ciris_server::accord::AccordHalt;

const CANONICAL_KEY_ID: &str = "ciris-canonical-1-d7bdeu223k";

async fn jget(client: &reqwest::Client, url: String) -> (u16, serde_json::Value) {
    let resp = client.get(&url).send().await.expect("get");
    let status = resp.status().as_u16();
    let json = resp
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub async fn run(report: &mut Report) {
    println!("\n\x1b[1m▶ CANONICAL — trace-flow target resolves (baked genesis, HTTP)\x1b[0m");
    let m = "canonical";
    let engine = node_seeded().await;
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

    // 1. The baked canonical server is present in `federation_keys` — asserted at the
    //    engine (the trace-flow counterparty is an FK row, not an HTTP artifact; this is
    //    exactly the surface CIRISPersist#392 left empty on the wheel ctor).
    let rows = engine
        .list_canonical_servers()
        .await
        .expect("list_canonical_servers");
    let canonical = rows.iter().find(|r| r.key_id == CANONICAL_KEY_ID);
    report.check(
        m,
        "baked canonical server present",
        canonical.is_some(),
        format!(
            "engine.list_canonical_servers() → {} row(s); want {CANONICAL_KEY_ID}",
            rows.len()
        ),
    );

    // 2. It is fully addressable — a directed grant can reach it by key_id.
    let addressable = canonical.is_some_and(|r| {
        !r.pubkey_ed25519_base64.is_empty()
            && r.pubkey_ml_dsa_65_base64
                .as_deref()
                .is_some_and(|s| !s.is_empty())
            && r.registration_envelope
                .get("transport_hints")
                .and_then(|h| h.as_array())
                .is_some_and(|h| !h.is_empty())
    });
    report.check(
        m,
        "canonical target is addressable (pubkeys + transport hint)",
        addressable,
        "the directed consent:community_trust counterparty must carry hybrid pubkeys + a transport hint to FK-resolve".to_string(),
    );

    // 3. The trust-root family the canonical roots under is entrenched (2-of-3).
    let (fstatus, fbody) = jget(&client, format!("{base}/v1/accord/family")).await;
    let entrenched = fstatus == 200
        && fbody["entrenched"].as_bool() == Some(true)
        && fbody["family_name"].as_str() == Some("HUMANITY_ACCORD");
    report.check(
        m,
        "HUMANITY_ACCORD trust root is entrenched",
        entrenched,
        format!(
            "GET /v1/accord/family → {fstatus}, entrenched={:?} name={:?}",
            fbody["entrenched"], fbody["family_name"]
        ),
    );
}
