//! **Where each file is — the custody view** (0.5.218, `FSD/FILE_CUSTODY.md`).
//!
//! The maintainer's ask of 2026-09-30: "for every blob we have access to, there
//! needs to be a view of which devices it is on, the total devices." This
//! module is the VIEW. Copying a file to a device and removing it from one are
//! a later cut (the FSD names their design); nothing here moves a byte.
//!
//! # Three sources, none of which the server read before this cut
//!
//! 1. **The person's devices** — [`owner_devices`]: persist's
//!    `nodes_owned_by(owner)` (the owner-bindings, which fold the owner's
//!    `withdraws`, so a RELEASED node is gone) minus every node whose content
//!    occurrence for that owner is REVOKED (`list_identity_occurrences_for`
//!    names it, `list_identity_occurrences_active` does not). That is the same
//!    projection the self-room driver and the self re-wrap key their rosters
//!    on, so "your devices" here is the set a self file is wrapped to and
//!    replicated to — not a second opinion about who you are. The occurrence
//!    list alone (`GET /v1/self/occurrences`) was NOT used as the roster: it
//!    carries the person's login anchor and, on an agent split, the ACTOR key
//!    beside the node, so it would count one machine twice; it is read only to
//!    subtract revocations. Labels come from `self:device_label:v1`, the rows
//!    `POST /v1/self/occurrence/label` writes, through
//!    [`crate::self_devices::labels_for`].
//! 2. **Custody** — edge's `FileRow::custody` → persist's
//!    `Engine::blob_custody` (v51.1.0, CIRISPersist#942): who can open the
//!    blob per person and through which devices, whether this node holds it,
//!    and the copies that are countable. It is authorized EXACTLY as the bytes
//!    read (`read_any_for_viewer`'s tier gate, then the withdrawn check), and it
//!    is asked as the drive's viewer key — the split-install content occurrence
//!    (`drive::viewer_key`), never `local_derived_key_id()` — so a viewer who
//!    cannot open the bytes learns nothing, not even the access list.
//! 3. **Delivery receipts** — edge's `FileRow::received_by` →
//!    `receipts::received_for` (CIRISEdge#738, CC 5.3.3.6): one
//!    `(node, epoch, K, at)` per device that stored every chunk of a file
//!    under the root the author published. Since edge v38.0.0 / persist v52
//!    (CIRISPersist#953, CIRISEdge#755) EVERY file is a stream: a chunk DAG's
//!    is its `stream_id`, an inline file's (≤ 1 MiB) is persist's one-leaf log
//!    `inline_blob_stream_id(sha)`, and `at` is the instant the author's store
//!    took the receipt (`list_stored_delivery_receipts_for`'s `received_at`). The receiving node signs it on the
//!    pull (`on_dag_pulled`); the author's node admits it on arrival
//!    (`admit_and_count`, in the replication bridge). A receipt is proof of
//!    DELIVERY — it is never retracted by an eviction at this pin — so a device
//!    with a receipt is reported `holds: "received"`, never "here".
//!
//! # The host wiring the receipts need — checked, all present
//!
//! Past defect class ("host hooks left unset"): an optional edge hook the
//! server never set disabled a feature silently for six releases. Receipts
//! touch four places and every one resolves to a store the server already
//! builds, with no receipt-specific hook to set:
//!
//! - PUBLISH: `files::publish` puts the stream's STH through
//!   `GroupContentStore::stream_log()`. The trait default is `None` (a file
//!   published there carries no STH and can never be receipted); the drive's
//!   store is edge's `PersistGroupContentStore` (`drive::store`), whose
//!   `stream_log` is `receipts::stream_log_of(engine)` — `Some` for the SQLite
//!   and Postgres backends.
//! - RECEIVE: `BlobPuller::spawn` takes the engine as a REQUIRED argument
//!   (`backend::spawn_puller_with`), and `on_dag_pulled` signs with it and
//!   names the puller's `local_key_id` (the edge signer, which is also the key
//!   the engine self-attests the receipt row as — admission requires the two
//!   to agree).
//! - ADMIT: the bridge admits a receipt row only when its `engine` is set,
//!   which is `SealedContentWiring::engine` in `compose::start_replication_runtime`
//!   (wired since 0.5.212 for the key-grant door; edge v27 made it
//!   unconstructible without the pull sink).
//! - READ: this module, through the same `PersistGroupContentStore`.
//!
//! # What the view cannot say, and says so
//!
//! Every partial answer carries a `why` entry with a stable id (one
//! [`msg`] call per reason, so the localization guard sees each):
//! `self`/`family` copies elsewhere are unobservable BY DESIGN (CC 5.2 — never
//! announced); a receipt proves delivery, not current holding; receipts are
//! ADMITTED on the author's device, so another
//! device's view holds only its own; and a receipt signed by a key that is not
//! one of the person's listed devices (a family or community member, or an
//! agent-split ACTOR key) is listed separately rather than dropped.
//!
//! **Retired at edge v38.0.0 / persist v52 (0.5.218):** `custody.inline_no_receipt`
//! (an inline file now has a one-leaf log and is receipted like any other —
//! CIRISPersist#953 item 2, CIRISEdge#755) and `custody.receipt_time_unknown`
//! (`Received::at` is the store's `received_at`, never absent — #953 item 3).
//! Both conditions are now false on every path, so neither id is emitted
//! anywhere; they are deleted rather than kept as dead constants, and the
//! localization ratchet's count drops by two.

use std::collections::{BTreeSet, HashSet};

use serde::Serialize;

use ciris_persist::prelude::Engine;

/// One reason the view is partial: a stable id and its English sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Why {
    pub reason_id: &'static str,
    pub detail: &'static str,
}

/// A reason, built in one place per id — named `msg` so the localization guard
/// reads the id from its argument position and the text beside it.
const fn msg(reason_id: &'static str, detail: &'static str) -> Why {
    Why { reason_id, detail }
}

pub const WHY_COPIES_UNOBSERVABLE: Why = msg(
    "custody.copies_unobservable_by_design",
    "Your own and your family's files are never announced to anyone, so copies on other devices cannot be counted; a delivery receipt is the only sign a device received one.",
);
pub const WHY_RECEIPT_IS_DELIVERY: Why = msg(
    "custody.receipt_is_delivery_not_holding",
    "A delivery receipt proves a device received the whole file. It does not prove the device still holds it: removing a copy does not withdraw its receipt yet.",
);
pub const WHY_RECEIPTS_ON_AUTHOR_DEVICE: Why = msg(
    "custody.receipts_admitted_on_author_device",
    "Delivery receipts are collected by the device that wrote the file. This device lists only the receipts it holds; ask the device that wrote it for the full answer.",
);
pub const WHY_RECEIPT_FROM_OTHER_KEY: Why = msg(
    "custody.receipt_signer_not_your_device",
    "Some receipts were signed by devices that are not among your devices (another member of the room, or an agent's own key); they are listed separately.",
);
pub const WHY_RECEIPTS_UNREADABLE: Why = msg(
    "custody.receipts_unreadable",
    "This device could not read its delivery receipts just now; which devices received the file is unknown until it can.",
);
pub const WHY_COMMONS_READABLE: Why = msg(
    "custody.commons_readable_by_holders",
    "This file is public: anyone holding the bytes can read them, so who can open it is not a list.",
);
pub const WHY_NO_COPY_REPORTS_PENDING: Why = msg(
    "custody.no_copy_reports_pending",
    "Your other devices cannot yet report that they hold no copy; those reports arrive with within-cohort custody acknowledgements. Until then a device without a delivery receipt is shown as unknown.",
);
pub const WHY_NO_COPY_HERE: Why = msg(
    "custody.no_copy_here",
    "This device holds no copy of the file, so who can open it and how many copies are announced are answered by a device that holds it.",
);

/// Every custody reason, for the FSD table and the gates.
pub const ALL_WHY: &[Why] = &[
    WHY_COPIES_UNOBSERVABLE,
    WHY_RECEIPT_IS_DELIVERY,
    WHY_RECEIPTS_ON_AUTHOR_DEVICE,
    WHY_RECEIPT_FROM_OTHER_KEY,
    WHY_RECEIPTS_UNREADABLE,
    WHY_COMMONS_READABLE,
    WHY_NO_COPY_REPORTS_PENDING,
    WHY_NO_COPY_HERE,
];

/// `holds` tokens: one word per fact, like the drive's byte states.
///
/// The maintainer's ruling on #704: "no copy here is a receipt (node
/// responsive, no copy)." A device that ANSWERS that it holds nothing has said
/// something about custody, so `none` is a fact, never folded into `unknown`.
/// At this pin only THIS device can say it (`checked_at`); a remote device's
/// signed "no copy" arrives with persist's within-cohort custody
/// acknowledgements (CIRISConstitution#130), and will carry `reported_at`.
pub const HOLDS_HERE: &str = "here";
pub const HOLDS_RECEIVED: &str = "received";
pub const HOLDS_NONE: &str = "none";
pub const HOLDS_UNKNOWN: &str = "unknown";
/// Every `holds` token, in the order a client should rank them.
pub const HOLDS: &[&str] = &[HOLDS_HERE, HOLDS_RECEIVED, HOLDS_NONE, HOLDS_UNKNOWN];

/// One of the person's devices, with every key it answers to.
#[derive(Debug, Clone)]
pub struct Device {
    /// The key the owner-binding names.
    pub node_key_id: String,
    /// Every key that is this device: the node key, and — for THIS node — its
    /// actor, held node signer and wire identity
    /// (`peer::own_keys_of_this_node`), because a split install binds the node
    /// key while its engine signs receipts as the actor.
    pub keys: Vec<String>,
    pub label: Option<String>,
    pub this_device: bool,
}

/// **The person's devices** — see the module doc, source 1. Sorted, this device
/// first. `Err` only when the directory cannot be read.
pub async fn owner_devices(engine: &Engine, owner: &str) -> Result<Vec<Device>, String> {
    use ciris_persist::federation::admission::nodes_owned_by;
    let dir = engine.federation_directory();
    let owned = nodes_owned_by(dir.as_ref(), owner)
        .await
        .map_err(|e| format!("nodes_owned_by({owner}): {e:#}"))?;
    let active: HashSet<String> = dir
        .list_identity_occurrences_active(owner)
        .await
        .map_err(|e| format!("list_identity_occurrences_active({owner}): {e:#}"))?
        .into_iter()
        .map(|o| o.occurrence_key_id)
        .collect();
    let revoked: HashSet<String> = dir
        .list_identity_occurrences_for(owner)
        .await
        .map_err(|e| format!("list_identity_occurrences_for({owner}): {e:#}"))?
        .into_iter()
        .map(|o| o.occurrence_key_id)
        .filter(|k| !active.contains(k))
        .collect();
    let own: Vec<String> = match engine.local_derived_key_id().await {
        Ok(k) => crate::peer::own_keys_of_this_node(&k),
        Err(_) => crate::node_key::wire_identity()
            .map(|w| vec![w.to_owned()])
            .unwrap_or_default(),
    };
    let labels = crate::self_devices::labels_for(engine, owner).await;
    let mut seen = BTreeSet::new();
    let mut out: Vec<Device> = Vec::new();
    for node in owned {
        if node == owner || revoked.contains(&node) || !seen.insert(node.clone()) {
            continue;
        }
        let this_device = own.contains(&node);
        let keys = if this_device {
            let mut k = vec![node.clone()];
            k.extend(own.iter().filter(|o| **o != node).cloned());
            k
        } else {
            vec![node.clone()]
        };
        let label = keys.iter().find_map(|k| labels.get(k).cloned());
        out.push(Device {
            node_key_id: node,
            keys,
            label,
            this_device,
        });
    }
    out.sort_by(|a, b| {
        b.this_device
            .cmp(&a.this_device)
            .then_with(|| a.node_key_id.cmp(&b.node_key_id))
    });
    Ok(out)
}

/// One receipt, as the view reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReceivedView {
    pub epoch: u64,
    pub k: u64,
    /// When the author's store took the receipt (RFC 3339) — persist's
    /// `received_at` (CIRISPersist#953), the store's fact rather than the
    /// receiving device's claim. Always present since persist v52.
    pub at: String,
}

/// A receipt that no listed device answers to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OtherReceipt {
    pub node_key_id: String,
    pub epoch: u64,
    pub k: u64,
    pub at: String,
}

/// One device's row in the view.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceCustody {
    pub node_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub this_device: bool,
    /// A key of this device is a grant recipient in persist's access list;
    /// `null` when the access list is not answerable here (this device holds
    /// no copy — [`WHY_NO_COPY_HERE`]).
    pub can_open: Option<bool>,
    pub received: Option<ReceivedView>,
    /// `here` (this device holds the bytes), `received` (a delivery receipt
    /// names it), `none` (the device answered: it holds no copy — this device
    /// only, until remote reports exist) or `unknown` (nothing says either way).
    pub holds: &'static str,
    /// THIS device's statement time (RFC 3339): `holds` for this device is a
    /// live answer, not an inference. `null` on every other device.
    pub checked_at: Option<String>,
    /// When a remote device reported its `holds` — always `null` until
    /// persist's within-cohort custody acknowledgements carry such reports.
    pub reported_at: Option<String>,
}

/// What the receipt read found. Since edge v38.0.0 every file — inline or
/// chunked — has a receipt stream, so there is no "unsupported" arm: the only
/// partial answer is a read that failed.
pub enum Receipts {
    /// The stream log could not be read.
    Unreadable,
    /// The receipts this node's stream log holds for the file.
    Held(Vec<ciris_edge::receipts::Received>),
}

/// The view's device half, computed without any I/O so it can be pinned.
pub struct DeviceHalf {
    pub devices: Vec<DeviceCustody>,
    pub other_receipts: Vec<OtherReceipt>,
    pub why: Vec<Why>,
}

fn received_view(r: &ciris_edge::receipts::Received) -> ReceivedView {
    ReceivedView {
        epoch: r.epoch,
        k: r.k,
        at: r.at.to_rfc3339(),
    }
}

/// **The per-device answer**: each device against the access list and the
/// receipts, plus the receipts no device answers to, plus why it is partial.
/// `access_devices` is every device key persist's custody names as able to
/// open the blob (`None` when this device holds no copy and persist's custody
/// could not be asked); `held_here` is persist's, `false` on that path;
/// `checked_at` is the moment this device answered.
pub fn device_half(
    devices: &[Device],
    access_devices: Option<&HashSet<String>>,
    held_here: bool,
    receipts: &Receipts,
    this_device_is_author: bool,
    checked_at: &str,
) -> DeviceHalf {
    let mut why = Vec::new();
    let held: &[ciris_edge::receipts::Received] = match receipts {
        Receipts::Held(r) => r,
        Receipts::Unreadable => {
            why.push(WHY_RECEIPTS_UNREADABLE);
            &[]
        }
    };
    let mut matched: HashSet<usize> = HashSet::new();
    let rows = devices
        .iter()
        .map(|d| {
            let received = held.iter().enumerate().find_map(|(i, r)| {
                d.keys.contains(&r.node_key_id).then(|| {
                    matched.insert(i);
                    received_view(r)
                })
            });
            // THIS device answers for itself: it holds the bytes or it does
            // not, and either is a fact. A receipt this device once signed does
            // not outrank its own "no copy" now (an eviction does not retract
            // a receipt at this pin). Other devices: a receipt, or unknown.
            let holds = match (d.this_device, held_here, received.is_some()) {
                (true, true, _) => HOLDS_HERE,
                (true, false, _) => HOLDS_NONE,
                (false, _, true) => HOLDS_RECEIVED,
                (false, _, false) => HOLDS_UNKNOWN,
            };
            DeviceCustody {
                node_key_id: d.node_key_id.clone(),
                label: d.label.clone(),
                this_device: d.this_device,
                can_open: access_devices.map(|a| d.keys.iter().any(|k| a.contains(k))),
                received,
                holds,
                checked_at: d.this_device.then(|| checked_at.to_owned()),
                reported_at: None,
            }
        })
        .collect::<Vec<_>>();
    // Mark every receipt a device answered to — a device may have receipted
    // under two keys (a split install's actor and node), counted once above.
    for (i, r) in held.iter().enumerate() {
        if devices.iter().any(|d| d.keys.contains(&r.node_key_id)) {
            matched.insert(i);
        }
    }
    let other_receipts: Vec<OtherReceipt> = held
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched.contains(i))
        .map(|(_, r)| OtherReceipt {
            node_key_id: r.node_key_id.clone(),
            epoch: r.epoch,
            k: r.k,
            at: r.at.to_rfc3339(),
        })
        .collect();
    if matches!(receipts, Receipts::Held(_)) {
        why.push(WHY_RECEIPT_IS_DELIVERY);
        if !this_device_is_author {
            why.push(WHY_RECEIPTS_ON_AUTHOR_DEVICE);
        }
        if !other_receipts.is_empty() {
            why.push(WHY_RECEIPT_FROM_OTHER_KEY);
        }
    }
    if access_devices.is_none() {
        why.push(WHY_NO_COPY_HERE);
    }
    if rows
        .iter()
        .any(|d| !d.this_device && d.holds == HOLDS_UNKNOWN)
    {
        why.push(WHY_NO_COPY_REPORTS_PENDING);
    }
    DeviceHalf {
        devices: rows,
        other_receipts,
        why,
    }
}

/// The compact per-row summary `GET /v1/drive` carries: the device count and
/// how many of them hold a receipt — `received_on: null` only when the stream
/// log could not be read (unknowable, not zero). An inline file counts like
/// any other since edge v38.0.0.
#[derive(Debug, Clone, Serialize)]
pub struct CompactCustody {
    pub devices_total: usize,
    pub received_on: Option<usize>,
}

/// [`CompactCustody`] from the roster and the receipt read — one list query
/// per CHUNKED row, none for an inline one, and no manifest read.
pub fn compact(devices: &[Device], receipts: &Receipts) -> CompactCustody {
    let received_on = match receipts {
        Receipts::Held(held) => Some(
            devices
                .iter()
                .filter(|d| held.iter().any(|r| d.keys.contains(&r.node_key_id)))
                .count(),
        ),
        Receipts::Unreadable => None,
    };
    CompactCustody {
        devices_total: devices.len(),
        received_on,
    }
}

/// Read a file row's receipts through the drive's store — inline and chunked
/// alike (edge names the stream, `receipts::receipt_stream_id`; this module
/// never decides which files are receiptable).
pub async fn receipts_of(
    file: &ciris_edge::files::FileRow,
    store: &dyn ciris_edge::group_content::GroupContentStore,
) -> Receipts {
    match file.received_by(store).await {
        Ok(r) => Receipts::Held(r),
        Err(e) => {
            tracing::warn!(
                file = %file.attestation_id,
                error = %e,
                "custody: the file's delivery receipts could not be read — reported as unknown"
            );
            Receipts::Unreadable
        }
    }
}

/// The person-by-person access list, flattened to its device keys.
pub fn access_device_keys(
    custody: &ciris_persist::federation::blob_custody::BlobCustody,
) -> HashSet<String> {
    custody
        .access
        .iter()
        .flat_map(|a| a.devices.iter().cloned())
        .collect()
}

/// The substrate's partial-answer reasons, as ids: persist's `why` is a
/// sentence keyed by TIER, so the tier picks the id (a reword upstream cannot
/// move an answer between reasons). Taken from persist's custody when this
/// device holds a copy, from the row's pointer when it does not.
pub fn substrate_why(copies_observable: bool, tier: &str) -> Vec<Why> {
    let mut out = Vec::new();
    if !copies_observable {
        out.push(WHY_COPIES_UNOBSERVABLE);
    }
    if tier == "plaintext" {
        out.push(WHY_COMMONS_READABLE);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(key: &str, this: bool) -> Device {
        Device {
            node_key_id: key.into(),
            keys: vec![key.into()],
            label: None,
            this_device: this,
        }
    }

    fn rec(node: &str) -> ciris_edge::receipts::Received {
        ciris_edge::receipts::Received {
            node_key_id: node.into(),
            epoch: 0,
            k: 25,
            at: "2026-09-30T00:00:00Z".parse().expect("fixture instant"),
        }
    }

    #[test]
    fn a_receipted_second_device_is_received_and_the_author_is_here() {
        let devices = vec![dev("a", true), dev("b", false)];
        let access: HashSet<String> = ["a".into(), "b".into()].into();
        let half = device_half(
            &devices,
            Some(&access),
            true,
            &Receipts::Held(vec![rec("b"), rec("stranger")]),
            true,
            "2026-09-30T00:00:00Z",
        );
        assert_eq!(half.devices[0].holds, HOLDS_HERE);
        assert_eq!(half.devices[1].holds, HOLDS_RECEIVED);
        assert!(half.devices.iter().all(|d| d.can_open == Some(true)));
        assert_eq!(
            half.devices[0].checked_at.as_deref(),
            Some("2026-09-30T00:00:00Z")
        );
        assert_eq!(half.devices[1].checked_at, None);
        assert_eq!(half.other_receipts.len(), 1);
        let ids: Vec<_> = half.why.iter().map(|w| w.reason_id).collect();
        assert!(ids.contains(&"custody.receipt_is_delivery_not_holding"));
        assert!(ids.contains(&"custody.receipt_signer_not_your_device"));
        assert!(!ids.contains(&"custody.receipts_admitted_on_author_device"));
        let c = compact(&devices, &Receipts::Held(vec![rec("b")]));
        assert_eq!((c.devices_total, c.received_on), (2, Some(1)));
    }

    /// Since edge v38.0.0 a receipt always carries the store's `received_at`,
    /// and nothing in the view says the time is unknown.
    #[test]
    fn a_receipt_says_when_and_no_time_reason_is_given() {
        let devices = vec![dev("a", true), dev("b", false)];
        let access = HashSet::new();
        let half = device_half(
            &devices,
            Some(&access),
            true,
            &Receipts::Held(vec![rec("b")]),
            true,
            "t",
        );
        let got = half.devices[1].received.as_ref().expect("b receipted");
        assert_eq!(got.at, "2026-09-30T00:00:00+00:00");
        assert_eq!(half.why, vec![WHY_RECEIPT_IS_DELIVERY]);
        assert_eq!(
            compact(&devices, &Receipts::Unreadable).received_on,
            None,
            "an unreadable log is unknown, not zero"
        );
    }

    /// The maintainer's ruling on #704: a device that holds the row and not the
    /// bytes answers `none` for itself, with the time it answered — never 409.
    #[test]
    fn this_device_without_a_copy_says_none_and_when() {
        let devices = vec![dev("b", true), dev("a", false)];
        let half = device_half(
            &devices,
            None,
            false,
            &Receipts::Held(vec![rec("b")]),
            false,
            "2026-09-30T12:00:00Z",
        );
        assert_eq!(
            half.devices[0].holds, HOLDS_NONE,
            "its own answer outranks its old receipt"
        );
        assert_eq!(
            half.devices[0].checked_at.as_deref(),
            Some("2026-09-30T12:00:00Z")
        );
        assert_eq!(half.devices[0].can_open, None);
        assert_eq!(half.devices[1].holds, HOLDS_UNKNOWN);
        assert_eq!(half.devices[1].reported_at, None);
        let ids: Vec<_> = half.why.iter().map(|w| w.reason_id).collect();
        assert!(ids.contains(&"custody.no_copy_here"), "{ids:?}");
        assert!(ids.contains(&"custody.no_copy_reports_pending"), "{ids:?}");
    }

    #[test]
    fn every_reason_id_is_unique_and_in_the_custody_family() {
        let mut seen = HashSet::new();
        for w in ALL_WHY {
            assert!(w.reason_id.starts_with("custody."), "{}", w.reason_id);
            assert!(seen.insert(w.reason_id), "duplicate {}", w.reason_id);
        }
    }
}
