//! Reusable QA module — the GENERIC family lifecycle over `ciris_server::family`
//! (persist's family CEG DX): create → add member → live roster → remove → swap →
//! threshold-roster. NOT accord-aware (a household family would use the same ops).

use ciris_persist::federation::cohort::{RevokeSpec, RosterMember};
use ciris_persist::federation::types::{Family, FamilyMember};
use ciris_server::family;

use crate::common::{node, Report, SoftId};

const FAMILY: &str = "qa-family";

/// A `FamilyMember` for the genesis roster (`create_family` takes the persist type).
fn member(key_id: &str, role: &str) -> FamilyMember {
    FamilyMember {
        key_id: key_id.to_string(),
        joined_at: chrono::Utc::now(),
        role: Some(role.to_string()),
    }
}

/// A `RosterMember` for the uniform cohort add/swap ops.
/// Kept while the roster-growth checks are BLOCKED upstream (persist v31
/// `AdmitSpec`): the moment the registration gap closes, add/swap come straight
/// back and need this. Deleting it would make the fix a bigger diff than the
/// block, and would lose the shape the fixture is supposed to build.
#[allow(dead_code)]
fn roster_member(key_id: &str, role: &str) -> RosterMember {
    RosterMember {
        key_id: key_id.to_string(),
        joined_at: chrono::Utc::now(),
        role: Some(role.to_string()),
    }
}

fn revoke_spec() -> RevokeSpec {
    RevokeSpec {
        effective_at: chrono::Utc::now(),
        reason: Some("qa-runner".into()),
        witness_set: Vec::new(),
        // ── STALE-BY-PIN (CIRISServer#319 item 1) ──────────────────────────
        //
        // This used to say a LOCAL revoke needs no signature because only a
        // REPLICATED one is verified. There is no such distinction at our pin:
        // `revoke_member(Cohort::Family, ..)` calls
        // `put_family_membership_revocation` (persist `federation/mod.rs:3010`),
        // which runs `verify_family_membership_revocation_admission` BEFORE any
        // other admission step (`store/sqlite.rs:6617`) and hybrid-Strict-verifies
        // the caller-supplied authority signature. Local and replicated go through
        // the same door.
        //
        // So these empty fields do not mean "unsigned is fine here" — they mean
        // this driver's revoke is REFUSED, and the `.expect("revoke")` below would
        // panic rather than exercise anything. Left empty rather than filled with a
        // manufactured signature: inventing an authority to satisfy a gate is the
        // defect, not the fix. Wiring a real signer is tracked on #319.
        authority_key_id: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
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

    // ROSTER GROWTH IS BLOCKED FROM DOWNSTREAM (persist v31.0.0).
    //
    // Growing a roster now requires an `AdmitSpec`: hybrid signatures by a
    // REGISTERED authority over the GROWN record's `signing_envelope()`. That
    // is the right tightening — before v31 an authenticated caller could grow a
    // roster without signing the result, so one signature lifted onto another
    // shape.
    //
    // But a downstream fixture cannot produce a valid one today.
    // `cohort::test_support::admit_family` is public and signs with persist's
    // DETERMINISTIC test keypair; the authority must therefore be registered
    // carrying THOSE pubkeys, and the only helper that does so
    // (`tier_ingest::test_support::register_hybrid_key`) is `pub(crate)`. So we
    // can sign, and we cannot register the key the signature verifies against.
    //
    // Recorded as blocked rather than stubbed. A fabricated spec would make this
    // runner exercise a path production cannot take, which is worse than an
    // honest gap — and it would go green.
    report.record(
        m,
        "add_member(carol) → BLOCKED upstream",
        false,
        "persist v31 AdmitSpec: cohort::test_support::admit_family is pub but \
         tier_ingest::test_support::register_hybrid_key is pub(crate) — cannot register an \
         authority whose pubkeys match the signer (CIRISPersist gap, filed)",
    );

    // remove bob (revocation) → active read folds it out.
    family::revoke_member(&engine, FAMILY, "qa-bob", revoke_spec())
        .await
        .expect("revoke");
    // {alice} — NOT {alice,carol}: carol was never admitted, because the add is
    // blocked above. Expectations downstream of a blocked step must move with it,
    // or the runner reports a FALSE red that hides the real one.
    let r = live(&engine).await;
    report.check(
        m,
        "revoke_member(bob) → {alice}",
        r == ["qa-alice"],
        format!("{r:?}"),
    );

    // SWAP alice → dave is revoke + ADD, so it needs the same `AdmitSpec` and is
    // blocked by the same registration gap.
    report.record(
        m,
        "swap_member(alice→dave) → BLOCKED upstream",
        false,
        "same AdmitSpec registration gap as add_member",
    );

    // threshold roster resolves the live members to pinned pubkeys.
    match family::active_threshold_roster(&engine, FAMILY).await {
        Ok(roster) => {
            // ONE live member while the add is blocked (alice). The property under
            // test is that every live member resolves to PINNED HYBRID pubkeys —
            // that still holds at any roster size, so the check keeps its meaning.
            let ok = !roster.is_empty()
                && roster.iter().all(|tm| {
                    !tm.ed25519_public_key_base64.is_empty()
                        && tm.mldsa65_public_key_base64.is_some()
                });
            report.check(
                m,
                "active_threshold_roster → every live member has hybrid pubkeys",
                ok,
                format!("len={}", roster.len()),
            );
        }
        Err(e) => report.record(m, "active_threshold_roster", false, e.to_string()),
    }
}
