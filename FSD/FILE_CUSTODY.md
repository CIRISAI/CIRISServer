# FSD — Where each file is: the custody view (0.5.218)

**Ask (maintainer, 2026-09-30):** "For every blob we have access to, there
needs to be a view of which devices it is on, the total devices."

**This cut ships the VIEW.** Copying a file to a device and removing it from
one are a later cut; §5 is their design, and nothing in 0.5.218 moves a byte
because of it.

Code: `src/file_custody.rs` (the sources and the per-device answer),
`src/drive.rs` (`file_custody`, the route; `read_drive`, the compact
summary). Tests: `tests/file_custody.rs`, the unit tests in
`src/file_custody.rs`, and the harness `custody` relation
(`harness/native/topology.py`, `FSD/TOPOLOGY.md` §2.5) asserted in
`harness/native/topologies/selffiles.yaml` and
`harness/native/topologies/csd-107-file-custody.yaml`.

## 1. The surface

### 1.1 `GET /v1/files/{attestation_id}/custody?cohort=self|family|community[&room_id=…]`

Same auth and cohort handling as `GET /v1/files/{id}/meta`, and the same
doors as the BYTES, in the same order: the owner session
(`drive.owner_session_required`), the cohort named and membership-checked
(`drive.unknown_cohort`, `drive.family_id_required`,
`drive.community_id_required`, `drive.not_a_member`), the row found through
edge's gated reader (`drive.not_in_room`), a withdrawn row `410
drive.withdrawn` — then persist's custody door, asked as the drive's viewer
key (the split-install content occurrence, `drive::viewer_key`), which runs
the byte read's tier gate. A viewer who cannot open the bytes gets the byte
read's refusal through the same `refuse_state` (`drive.not_granted`,
`drive.evicted`, …) and learns nothing about who else can open them. No new
refusal id.

**Authorized by the ROW, not the bytes** (maintainer's ruling on #704: "no
copy here is a receipt (node responsive, no copy)"). A device that holds the
row but not the bytes is NOT refused `409 drive.not_fetched` (the byte read
still is): the view answers 200, its own entry is `holds: "none"` with
`checked_at`, `held_here: false`, `copies_known: 0`, and — because persist's
custody reads the blob's head row, which is not there — `access: null`,
`size_bytes: null`, `announced_holders: []`, every device's `can_open: null`,
with `custody.no_copy_here` in `why`. The tier and `copies_observable` come
from the row's pointer.

```jsonc
{
  "attestation_id": "…", "cohort": "self", "room_id": "…",
  "tier": "invisible_encrypted",          // persist's tier token
  "size_bytes": 25168000,                 // the stored (at-rest) length
  "at_rest_sha256": "…",
  "author_device": "<node key>",          // the stream's producer (or the row's attester, inline)
  "checked_at": "2026-09-30T…Z",          // when THIS device answered
  "this_device_is_author": true,
  "devices_total": 2,                     // the person's devices (§2.1)
  "devices": [
    { "node_key_id": "…", "label": "laptop", "this_device": true,
      "can_open": true, "received": null, "holds": "here",
      "checked_at": "2026-09-30T…Z", "reported_at": null },
    { "node_key_id": "…", "this_device": false,
      "can_open": true, "received": { "epoch": 0, "k": 25, "at": null }, "holds": "received",
      "checked_at": null, "reported_at": null }
  ],
  "held_here": true,
  "copies_known": 1,                      // persist: held_here + announced holders elsewhere
  "copies_observable": false,             // false for self/family BY DESIGN (CC 5.2)
  "announced_holders": [],                // community / commons only: [{node_key_id, size_bytes}]
  "access": [ { "person_key_id": "…", "devices": ["…"], "via": "at_rest_grant" } ],
  "receipts_supported": true,             // false for an inline file
  "receipts_unsupported_reason": null,    // "custody.inline_no_receipt" when false
  "receipts_from_other_keys": [],         // receipts no listed device answers to
  "why": [ { "reason_id": "custody.…", "detail": "…" } ]
}
```

`holds` is one word per fact, like the drive's byte states: `here` (this
device, bytes held — persist's `held_here`), `received` (a delivery receipt
names the device), `none` (the device ANSWERED that it holds no copy — at this
pin only this device can, and its entry carries `checked_at`, the moment it
answered; a live statement, not an inference), `unknown` (nothing this node
can see says either way — NOT "absent"). A device's own `none` outranks a
receipt it once signed (an eviction does not retract a receipt, §4.3).
`reported_at` is on every entry and always `null` today: a remote device's
signed "no copy" arrives with persist's within-cohort custody
acknowledgements (CIRISConstitution#130), and will fill `holds: "none"` +
`reported_at` for other devices then. `can_open` is `null` when the access
list is not answerable on this device.

### 1.2 `GET /v1/drive` — `custody: {devices_total, received_on}` per row

Cheap by construction, so it ships: the device roster is read ONCE per page,
and a row costs one receipt-list query when it is a chunk DAG and nothing when
it is inline — no manifest read, no custody door. `received_on` counts the
person's devices this node holds a receipt from; it is `null` for an inline
file (unknowable, not zero) and when the stream log could not be read.
`custody` is `null` on a withdrawn row and when the roster could not be read.

## 2. Sources

### 2.1 The person's devices

`nodes_owned_by(owner)` (persist admission: the owner-bindings, folding the
owner's `withdraws` — a RELEASED node is gone), minus every node whose content
occurrence for the owner is REVOKED (named by
`list_identity_occurrences_for`, absent from
`list_identity_occurrences_active`), minus the owner's own key. This is the
projection the self-room driver and the self re-wrap already key on, so "your
devices" is the set a self file is wrapped and replicated to. The occurrence
list behind `GET /v1/self/occurrences` is NOT the roster: it carries the
person's login anchor and, on an agent split, the ACTOR beside the node, so it
would count one machine twice; it is read only to subtract revocations.

This device's row answers to every key this node is
(`peer::own_keys_of_this_node`: engine key, actor, held node signer, wire
identity), because a split install binds the NODE key while its engine signs
receipts as the actor. Labels are the owner's `self:device_label:v1` rows
(`POST /v1/self/occurrence/label`), matched on any of a device's keys.

### 2.2 Custody — persist `Engine::blob_custody` (v51.1.0, CIRISPersist#942)

Through edge's `FileRow::custody(store, viewer)`, the same
`PersistGroupContentStore` every drive read uses. Access is exact (at-rest
grant recipients for self/family, the epoch's member grants for community),
grouped per person; `held_here`; announced holders and `copies_known` for
community/commons. For self/family, copies elsewhere are unobservable by
design: those bytes are never announced (CC 5.2 structural invisibility), so
persist says `copies_observable: false` rather than a false "1 copy".
`can_open` per device = one of its keys is in the access list.

### 2.3 Delivery receipts — edge `FileRow::received_by` (CIRISEdge#738, CC 5.3.3.6)

`receipts::received_for` over the store's stream log: one `(node, epoch, K)`
per node that stored every chunk of a chunk-DAG file under the root the
author published. Proof of DELIVERY, never of consumption, and — at this pin —
never retracted by an eviction.

### 2.4 The receipt host wiring — checked, nothing unset

The "host hooks left unset" class (an optional edge hook the server never set
kept chat bodies sealed for six releases) was checked for all four places a
receipt is touched. None is a receipt-specific hook; each resolves to a store
the server already builds:

| place | edge | server |
|---|---|---|
| publish | `files::publish` → `GroupContentStore::stream_log()` puts the STH (trait default `None` = no STH, never receiptable) | the drive's store is `PersistGroupContentStore` (`drive::store`), whose `stream_log` is `receipts::stream_log_of(engine)` — `Some` for SQLite and Postgres |
| receive | `blob_swarm::pull` → `receipts::on_dag_pulled(engine, backend, local_key_id, …)` after `promote` | `BlobPuller::spawn` takes the engine as a REQUIRED argument (`backend::spawn_puller_with`); `local_key_id` is the edge signer, the key the engine self-attests the receipt row as (admission requires the two to agree) |
| admit | the bridge's `apply` → `receipts::admit_and_count` when its `engine` is set | `SealedContentWiring::engine` in `compose::start_replication_runtime` (since 0.5.212; edge v27 makes it unconstructible without the pull sink) |
| read | `FileRow::received_by(store)` | `file_custody::receipts_of`, through the drive's store |

## 3. What the view cannot say — every partial answer names its reason

Each rides a 200 in `why[]` as `{reason_id, detail}`. String-literal ids,
one `msg` call each in `src/file_custody.rs`, listed as localization debt in
`tools/check_server_localization.py` (ratchet 139 → 151 across this cut, in
`tests/localization_gate.rs`) for the client bundle (CIRISClient#78):

| id | when | English |
|---|---|---|
| `custody.inline_no_receipt` | the file is inline (≤ 1 MiB) | This file is small enough to be stored in one piece, and a file stored in one piece has no delivery receipt yet: your other devices may hold it, but this device cannot be told so. |
| `custody.copies_unobservable_by_design` | persist `copies_observable: false` (self/family) | Your own and your family's files are never announced to anyone, so copies on other devices cannot be counted; a delivery receipt is the only sign a device received one. |
| `custody.receipt_is_delivery_not_holding` | any receipt read | A delivery receipt proves a device received the whole file. It does not prove the device still holds it: removing a copy does not withdraw its receipt yet. |
| `custody.receipt_time_unknown` | a receipt's `at` is `null` | The time each device received the file is not available yet. |
| `custody.receipts_admitted_on_author_device` | this device did not write the file | Delivery receipts are collected by the device that wrote the file. This device lists only the receipts it holds; ask the device that wrote it for the full answer. |
| `custody.receipt_signer_not_your_device` | a receipt no listed device answers to | Some receipts were signed by devices that are not among your devices (another member of the room, or an agent's own key); they are listed separately. |
| `custody.receipts_unreadable` | the stream log read failed | This device could not read its delivery receipts just now; which devices received the file is unknown until it can. |
| `custody.commons_readable_by_holders` | plaintext (commons) tier | This file is public: anyone holding the bytes can read them, so who can open it is not a list. |
| `custody.no_copy_reports_pending` | another device reads `unknown` | Your other devices cannot yet report that they hold no copy; those reports arrive with within-cohort custody acknowledgements. Until then a device without a delivery receipt is shown as unknown. |
| `custody.no_copy_here` | this device holds the row, not the bytes | This device holds no copy of the file, so who can open it and how many copies are announced are answered by a device that holds it. |

~~Also known, not a `why`: a device that holds the ROW but has not pulled the
bytes answers `409 drive.not_fetched`.~~ Superseded by the #704 ruling (§1.1):
that device answers 200 with its own `holds: "none"`; the author device is
still the complete answer for access and receipts.

## 4. Gaps to file upstream (named here, not filed)

1. **Inline files carry no receipt** — edge adopting persist v52's one-leaf
   stream log over an inline blob (CIRISPersist#953); until then
   `receipts_supported: false` for every file ≤ 1 MiB, the most common size.
2. **A receipt's time** — persist's `list_delivery_receipts_for` does not
   return the `received_at` column it stores, so edge's `Received.at` is
   always `None` (edge `receipts.rs`, `Received::at`).
3. **Eviction does not retract a receipt** — a device that evicts its copy
   (engine `evict_blob` retracts its `holds_bytes` claim, CIRISEdge#669) still
   shows `received`. Needs a receipt-retraction row (a `withdraws` of the
   receipt row by its signer on eviction) and persist honouring it in
   `list_delivery_receipts_for`.
4. **Self/family copies are uncountable** — within-cohort custody
   acknowledgements (CIRISPersist#942 part 2, CIRISConstitution#130, persist
   v52); receipts are the only signal until then.
5. **A remote agent-split device receipts as its ACTOR** — the receipt names
   the engine key; the owner-binding names the node. This device folds its
   own keys; a REMOTE split device's receipt lands in
   `receipts_from_other_keys`. Needs a directory read from an actor key to
   the node that hosts it (persist).
6. **Custody on a device that has not pulled** — `blob_custody` refuses
   `NotHeld` without the blob head. Since the #704 ruling the view answers
   anyway (`holds: "none"` for itself), but `access`, `size_bytes` and
   `can_open` are `null` there; a head-less persist answer (access from the
   row's grants) would fill them (persist).
8. **Remote "no copy" reports** — only THIS device can say `none` today; a
   signed per-device "I hold no copy" from the person's other devices is
   persist's within-cohort custody acknowledgement (CIRISConstitution#130,
   CIRISPersist#942 part 2). The per-device shape is ready: `holds` ∈
   here | received | none | unknown, plus `reported_at` (`why`:
   `custody.no_copy_reports_pending`).
7. **Receipts are admitted only where the STH was published** — a
   non-author device holds only its own receipt (and any whose STH it
   re-put while pulling). Replicating the author's admitted receipt set to
   the person's other devices would make the view device-independent (edge).

### 4.1 Closed at edge v38.0.0 / persist v52.0.0 (0.5.218)

- **Gap 1 closed** — an inline file is a one-leaf stream
  (`inline_blob_stream_id(sha)`, CIRISPersist#953 item 2); edge publishes its
  STH and the puller emits its receipt (`receipts::on_file_pulled`, CIRISEdge#755).
  `receipts_supported` is now `true` for every file and
  `receipts_unsupported_reason` always `null` (both kept on the wire, constant);
  a drive row's `received_on` is a count for inline files too (`0`, not `null`,
  before any device receipts it). `custody.inline_no_receipt` is no longer
  emitted and was deleted from `src/file_custody.rs`.
- **Gap 2 closed** — `list_stored_delivery_receipts_for` returns each receipt's
  `received_at` (#953 item 3); edge's `Received::at` is a `DateTime`, and the
  view's `received.at` / `receipts_from_other_keys[].at` are always an RFC 3339
  string. `custody.receipt_time_unknown` is no longer emitted and was deleted.
- The §3 table above keeps both rows as the record of what 0.5.218's first cut
  said; the localization ratchet drops by the two ids.

## 5. Later cut: copy-to and remove-from a device (design, NOT built)

- **The request is an owner-signed, device-addressed row.** `POST
  /v1/files/{id}/custody/{node}` `{want: "keep" | "drop"}` authors a
  `self`-scoped row (`file_custody_request:v1`, a persist registry row — the
  dimension must be registered with persist before any node emits it)
  signed by the OWNER's pen (consent is authored by the human), naming the
  file row, the blob's at-rest sha, the target device and the ask. It rides
  the self room to the owner's devices like any self row.
- **`keep` = pull now.** The target device's puller treats a live `keep`
  naming itself as an operator-consent `Announce` for that blob even when
  its default disposition would defer, and pulls it; the receipt it emits
  closes the loop in this view.
- **`drop` = a sticky "don't keep here".** The target evicts through the
  ENGINE (`evict_blob`, so its holder claim is retracted first) and the
  puller HONOURS the live `drop` on every later offer — without it the next
  anti-entropy round would pull the bytes straight back. A later `keep`
  supersedes it.
- **The last-copy guard.** A `drop` is REFUSED (`custody.last_copy`) when it
  would remove the only copy of an unwithdrawn file: the guard counts this
  view's `here` + `received` devices, minus the target; with receipts
  unretracted on eviction (§4.3) the count can over-report, so the guard
  must wait on gap 3 (or on persist v52's custody acknowledgements) before it
  can be trusted to say "another copy exists". Withdrawing the file is the
  way to remove the last copy.
- Needs: the persist registry row for the request dimension, gap 3 for an
  honest guard, and an edge puller hook to consult the sticky request.
