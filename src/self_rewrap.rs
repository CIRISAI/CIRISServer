//! **Old self files open on a new device** (CIRISServer#678, item 2).
//!
//! A `self` file is sealed under a fresh per-write DEK wrapped to every active
//! content-KEM occurrence of the owner that the writing node knows at seal time
//! (persist's at-rest cascade). A device claimed LATER — the second device a
//! person approves through `POST /v1/setup/claim-remote` — provisions its own
//! occurrence (`backend::provision_engine_occurrence`, on its self-room tick)
//! and that occurrence reaches the first device by replication. Nothing then
//! wrapped the EXISTING self DEKs to it: persist's
//! `rekey_self_occurrence_add` ran only from `POST /v1/self/occurrence`, so
//! every file written before the claim listed on the new device and never
//! opened.
//!
//! This is the trigger. On each replication reconcile tick (both loops reach
//! it through [`crate::replication_reconcile::reconcile_once`]) it asks: does
//! this node now hold an occurrence of its owner, with encryption pubkeys,
//! belonging to ANOTHER node that owner owns, that it has not re-wrapped for?
//! If so, and only if this node holds the owner's pen, it runs the re-wrap and
//! logs it by name. The persist door is idempotent (a blob already granted to
//! the newcomer is skipped and not counted); the in-process memo keeps the
//! steady-state tick to a directory read.
//!
//! # Whose authority
//!
//! The re-wrap re-grants a person's private content to another key. That is
//! the OWNER's act, so it runs only where the owner's pen opens —
//! [`crate::owner_signer_capsule::for_owned_node`], the owner-binding authority
//! a background loop has (a loop has no bearer). A device without the pen (the
//! second device itself) does nothing here and says so at debug; the device
//! that approved the claim holds the pen and does the work. Never a machine
//! key: `for_owned_node` refuses rather than falling back to one.
//!
//! # One device re-wraps (CC 3.1.3.1, 0.5.218)
//!
//! "The device holding the pen" is not one device once the person's fed-ID
//! is portable: every device they signed in on holds it, every one of them saw
//! the new occurrence arrive, and every one re-wrapped the same blobs and
//! wrote its own key-grant set for one grant. The re-wrap for a new device is
//! therefore an EXCHANGE — `(self room, self_rewrap:<occurrence>)` — and only
//! the device [`crate::session_claims::gate`] names does it. Per occurrence,
//! because the new device can never re-wrap for itself (it holds none of the
//! old DEKs), so it must never be the one the fold names; it is also never
//! pending for itself here, so it never claims. The gate runs AFTER the pen
//! check: a device that cannot do the work must not take the duty. And an
//! unclaimed re-wrap waits — for the person to be on a device that holds the
//! pen — rather than run on whichever device ticks first.

use std::sync::Arc;

use ciris_persist::federation::admission::nodes_owned_by;
use ciris_persist::prelude::Engine;

use crate::session_claims::{self, Attendance, Occupant, Verdict};

/// What one pass did — returned so a test can read it; the log carries the
/// same facts for an operator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RewrapReport {
    /// The owner whose self content was considered (`None` = unowned node).
    pub owner: Option<String>,
    /// Occurrences of another owned node that had not been re-wrapped for yet.
    pub pending: Vec<String>,
    /// `(occurrence, blobs newly granted)` for every re-wrap that RAN.
    pub rewrapped: Vec<(String, usize)>,
    /// `true` when there was something to do and this node does not hold the
    /// owner's pen, so nothing ran here.
    pub no_pen_here: bool,
    /// `(occurrence, handler)` for every pending re-wrap this device did NOT
    /// run because the session gate said so: `Some(device)` = that device
    /// does it, `None` = unclaimed, nobody does it yet (CC 3.1.3.1).
    pub not_handled_here: Vec<(String, Option<String>)>,
}

/// `rewrap \0 owner \0 occurrence \0 x25519` — the ACT's id for the
/// idempotence ledger (`Attendance::record_act`). A new KEM key for the same
/// occurrence is a new wrap target and is re-wrapped again.
fn act_id(owner: &str, occurrence: &str, x25519: &str) -> String {
    format!("rewrap\u{0}{owner}\u{0}{occurrence}\u{0}{x25519}")
}

/// One pass, gated on this process's attendance. Never fails: every error is
/// logged and the pass ends, because the caller is the peer-convergence tick
/// and must not be stopped by this.
pub async fn rewrap_for_new_devices(engine: &Arc<Engine>, node_key_id: &str) -> RewrapReport {
    rewrap_for_new_devices_with(engine, node_key_id, Attendance::global()).await
}

/// [`rewrap_for_new_devices`] against an explicit [`Attendance`] — a test that
/// stands two devices up in one process gives each its own.
pub async fn rewrap_for_new_devices_with(
    engine: &Arc<Engine>,
    node_key_id: &str,
    attendance: &Attendance,
) -> RewrapReport {
    let mut report = RewrapReport::default();
    let own = crate::peer::own_keys_of_this_node(node_key_id);
    let dir = engine.federation_directory();

    // Which of this node's keys is bound, and to whom — the NODE key first
    // (`Occupant::of_node`), the occurrence the session fold knows.
    let Some(who) = Occupant::of_node(engine, node_key_id).await else {
        return report;
    };
    let bound_key = who.occurrence.clone();
    let owner = who.owner.clone();
    report.owner = Some(owner.clone());

    let owned: Vec<String> = match nodes_owned_by(dir.as_ref(), &owner).await {
        Ok(n) => n,
        Err(e) => {
            tracing::debug!(owner = %owner, error = %e, "self re-wrap: nodes_owned_by failed this tick");
            return report;
        }
    };
    let occurrences = match dir.list_identity_occurrences_active(&owner).await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(owner = %owner, error = %e, "self re-wrap: occurrence read failed this tick");
            return report;
        }
    };
    // Cheap first: what is new? The pen is opened only when something is.
    let mut todo: Vec<(String, String)> = Vec::new();
    for o in &occurrences {
        let Some(enc) = o.encryption_pubkeys.as_ref() else {
            continue;
        };
        if own.contains(&o.occurrence_key_id) || !owned.contains(&o.occurrence_key_id) {
            continue;
        }
        let key = act_id(&owner, &o.occurrence_key_id, &enc.x25519_base64);
        if !attendance.already_acted(&key) {
            todo.push((o.occurrence_key_id.clone(), key));
        }
    }
    if todo.is_empty() {
        return report;
    }
    report.pending = todo.iter().map(|(o, _)| o.clone()).collect();

    // THE OWNER'S PEN, by the owner-binding — the authority a loop has.
    if let Err(refusal) = crate::owner_signer_capsule::for_owned_node(engine, &bound_key).await {
        report.no_pen_here = true;
        tracing::debug!(
            owner = %owner,
            pending = ?report.pending,
            %refusal,
            "self re-wrap: another device of this owner is a new wrap target, and the owner's \
             pen is not on this node — the device holding it re-wraps (CIRISServer#678)"
        );
        return report;
    }

    let community = session_claims::self_community(&owner);
    for (occurrence, key) in todo {
        // ONE DEVICE RE-WRAPS for each new device (CC 3.1.3.1) — see the
        // module note. The gate logs its refusal by name.
        match session_claims::gate(
            engine,
            attendance,
            &who,
            &community,
            &session_claims::rewrap_session(&occurrence),
            "self_rewrap",
        )
        .await
        {
            Verdict::Act => {}
            Verdict::HandledElsewhere {
                occurrence: handler,
            } => {
                report.not_handled_here.push((occurrence, Some(handler)));
                continue;
            }
            Verdict::Unclaimed => {
                report.not_handled_here.push((occurrence, None));
                continue;
            }
        }
        match engine
            .rekey_self_occurrence_add(&owner, std::slice::from_ref(&occurrence))
            .await
        {
            Ok(r) => {
                let granted = r
                    .granted
                    .iter()
                    .find(|(k, _)| *k == occurrence)
                    .map_or(0, |(_, n)| *n);
                tracing::info!(
                    owner = %owner,
                    occurrence = %occurrence,
                    blobs_scanned = r.blobs_scanned,
                    granted,
                    key_grant_sets = r.changed_blobs.len(),
                    excluded = ?r.excluded,
                    "self files RE-WRAPPED for a new device of this owner — every self file \
                     written before it was claimed now opens there (CIRISServer#678)"
                );
                attendance.record_act(&key);
                if !r.changed_blobs.is_empty() {
                    crate::compose::kick_replication("self files re-wrapped for a new device");
                }
                report.rewrapped.push((occurrence, granted));
            }
            Err(e) => tracing::warn!(
                owner = %owner,
                occurrence = %occurrence,
                error = %e,
                "self re-wrap for a new device FAILED this tick — retried next tick; until it \
                 runs, self files written before that device was claimed do not open there"
            ),
        }
    }
    report
}
