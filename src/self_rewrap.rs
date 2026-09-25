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

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use ciris_persist::federation::admission::{nodes_owned_by, owner_of};
use ciris_persist::prelude::Engine;

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
}

/// `owner \0 occurrence \0 x25519` — a new KEM key for the same occurrence is
/// a new wrap target and is re-wrapped again.
fn memo() -> &'static Mutex<HashSet<String>> {
    static MEMO: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashSet::new()))
}

fn memo_key(owner: &str, occurrence: &str, x25519: &str) -> String {
    format!("{owner}\u{0}{occurrence}\u{0}{x25519}")
}

/// One pass. Never fails: every error is logged and the pass ends, because
/// the caller is the peer-convergence tick and must not be stopped by this.
pub async fn rewrap_for_new_devices(engine: &Arc<Engine>, node_key_id: &str) -> RewrapReport {
    let mut report = RewrapReport::default();
    let own = crate::peer::own_keys_of_this_node(node_key_id);
    let dir = engine.federation_directory();

    // Which of this node's keys is bound, and to whom.
    let mut bound: Option<(String, String)> = None;
    for k in &own {
        if let Ok(Some(o)) = owner_of(dir.as_ref(), k).await {
            bound = Some((k.clone(), o));
            break;
        }
    }
    let Some((bound_key, owner)) = bound else {
        return report;
    };
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
    {
        let held = memo().lock().expect("self re-wrap memo poisoned");
        for o in &occurrences {
            let Some(enc) = o.encryption_pubkeys.as_ref() else {
                continue;
            };
            if own.contains(&o.occurrence_key_id) || !owned.contains(&o.occurrence_key_id) {
                continue;
            }
            let key = memo_key(&owner, &o.occurrence_key_id, &enc.x25519_base64);
            if !held.contains(&key) {
                todo.push((o.occurrence_key_id.clone(), key));
            }
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

    for (occurrence, key) in todo {
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
                memo()
                    .lock()
                    .expect("self re-wrap memo poisoned")
                    .insert(key);
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
