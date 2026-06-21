//! Reusable QA module — the GENERIC family lifecycle over `ciris_server::family`
//! (persist's family CEG DX): create → add member → live roster → remove → swap →
//! threshold-roster. NOT accord-aware (a household family would use the same ops).

use ciris_persist::federation::types::{Family, FamilyMember, FamilyMembershipRevocation};
use ciris_server::family;

use crate::common::{node, Report, SoftId};

const FAMILY: &str = "qa-family";

fn member(key_id: &str, role: &str) -> FamilyMember {
    FamilyMember {
        key_id: key_id.to_string(),
        joined_at: chrono::Utc::now(),
        role: Some(role.to_string()),
    }
}

fn revocation(removed: &str) -> FamilyMembershipRevocation {
    let now = chrono::Utc::now();
    FamilyMembershipRevocation {
        family_key_id: FAMILY.to_string(),
        removed_identity_key_id: removed.to_string(),
        removed_at: now,
        effective_at: now,
        reason: Some("qa-runner".into()),
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    }
}

/// Sorted live-member key_ids of `FAMILY`.
async fn live(engine: &ciris_persist::prelude::Engine) -> Vec<String> {
    let mut ids: Vec<String> = family::active_members(engine, FAMILY)
        .await
        .expect("active_members")
        .into_iter()
        .map(|m| m.key_id)
        .collect();
    ids.sort();
    ids
}

pub async fn run(report: &mut Report) {
    println!("\n\x1b[1m▶ FAMILY — generic family ops (ciris_server::family)\x1b[0m");
    let m = "family";
    let engine = node().await;

    // Register four software member identities + a ceremonial family anchor key
    // (the federation_families FK). Generic members are plain `user` identities.
    let ids = [
        SoftId::new("qa-alice", 0x10),
        SoftId::new("qa-bob", 0x11),
        SoftId::new("qa-carol", 0x12),
        SoftId::new("qa-dave", 0x13),
    ];
    for id in &ids {
        engine
            .register_federation_key(id.signed_key_record("user").await)
            .await
            .expect("register member");
    }
    let anchor = SoftId::new(FAMILY, 0x20);
    engine
        .register_federation_key(anchor.signed_key_record("family").await)
        .await
        .expect("register family anchor");
    report.record(m, "register 4 members + anchor key", true, "");

    // create → roster is the 2 founding members.
    let fam = Family {
        family_key_id: FAMILY.into(),
        family_name: "QA Family".into(),
        members: vec![member("qa-alice", "founder"), member("qa-bob", "member")],
        founded_at: chrono::Utc::now(),
        consensus_protocol: "founder_only".into(),
        consensus_protocol_entrenched: false,
        persist_row_hash: String::new(),
    };
    match family::create_family(&engine, fam).await {
        Ok(()) => {
            let r = live(&engine).await;
            report.check(
                m,
                "create_family → roster {alice,bob}",
                r == ["qa-alice", "qa-bob"],
                format!("{r:?}"),
            );
        }
        Err(e) => report.record(m, "create_family", false, e.to_string()),
    }

    // add carol → 3 live members.
    family::add_member(&engine, FAMILY, member("qa-carol", "member"))
        .await
        .expect("add");
    let r = live(&engine).await;
    report.check(
        m,
        "add_member(carol) → 3 live",
        r == ["qa-alice", "qa-bob", "qa-carol"],
        format!("{r:?}"),
    );

    // remove bob (revocation) → active read folds it out.
    family::revoke_member(&engine, revocation("qa-bob"))
        .await
        .expect("revoke");
    let r = live(&engine).await;
    report.check(
        m,
        "revoke_member(bob) → {alice,carol}",
        r == ["qa-alice", "qa-carol"],
        format!("{r:?}"),
    );

    // SWAP alice → dave (revoke + add) — roster stays size 2, seat replaced.
    family::swap_member(
        &engine,
        FAMILY,
        revocation("qa-alice"),
        member("qa-dave", "member"),
    )
    .await
    .expect("swap");
    let r = live(&engine).await;
    report.check(
        m,
        "swap_member(alice→dave) → {carol,dave}",
        r == ["qa-carol", "qa-dave"],
        format!("{r:?}"),
    );

    // threshold roster resolves the live members to pinned pubkeys.
    match family::active_threshold_roster(&engine, FAMILY).await {
        Ok(roster) => {
            let ok = roster.len() == 2
                && roster.iter().all(|tm| {
                    !tm.ed25519_public_key_base64.is_empty()
                        && tm.mldsa65_public_key_base64.is_some()
                });
            report.check(
                m,
                "active_threshold_roster → 2 hybrid members",
                ok,
                format!("len={}", roster.len()),
            );
        }
        Err(e) => report.record(m, "active_threshold_roster", false, e.to_string()),
    }
}
