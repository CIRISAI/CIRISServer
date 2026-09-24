# Roster and drive CRUD — the 0.5.216 contract

Status: **build contract** for CIRISServer 0.5.216 (edge v31.0.0 / persist v48.0.0 / verify v16.1.0).
Owner: CIRISServer. Consumers: CIRISClient (B3 Files, B4 Just me, B5 Family, communities), CIRISAgent.
Related: `FSD/ROSTERED_GROUP_KEY_OPS.md` (the accord's catalog; this document is its household and
community instantiation), edge `FSD/CONTENT_TRANSFER.md`, edge `FSD/FIRST_CONTACT.md`,
CIRISClient issue #65 (drive/notes message ids), CIRISServer #594 / #616 / #622 / #623 / #627 / #630.

## 0. Why this exists

On 2026-09-24 three read-only surveys (client requirements, server rosters, server files) found:

- **Self devices** are wired (occurrence add / revoke / list, portable, associate, claim, announce) but no
  route releases a node from its owner, and the self room still uses the PAIR-form handshake builders, so a
  second device never opens a file's bytes (selffiles `opened_on_b` red). Edge fixed its half in v30.0.0
  (CIRISEdge#656: `key_package_attestation_in`, `welcome_attestation_in`, `welcome_for`); the server never
  adopted it.
- **Family**: nothing can create a household or add a member (#627). `family::add_member` has zero
  production callers; the replicated door `put_family` has zero callers.
- **Community**: only the two-person pair room exists (`POST /v1/chat`). No invite, add, remove, role,
  leave, dissolve or list (#594). Several reads use the room RECORD's `members`, which v48 never grows
  (widenings are a separate plane), so they go stale the moment a room widens.
- **Files**: create, list, open and notes create/list exist. No update, rename, delete/withdraw, move,
  metadata, pagination, or streaming; a withdrawn file reads as the catch-all `drive.unopened`; the upload
  body is capped by axum's 2 MB default.

The client has no code for family, community or files yet; its requirements are the routes, message ids,
scenarios and nav tree quoted in the survey. This document is the server's answer: every route, its
policy, its refusals, its witness.

## 1. Rules that apply to every route here

1. **Sessions.** Every write needs the owner session (`drive_auth::owner` / `require_owner`: bearer, not
   delegated, SystemAdmin + FullAccess, wire-node owner binding). Reads of a room's contents need the
   owner session AND membership. Delegates never author roster changes or files (`*.delegate_may_not_author`).
2. **The human signs.** Roster rows and file rows are signed with the owner's fed-ID pen
   (`owner_signer_capsule::acquire` / `peer::owner_consent_pen`), never a node or agent key.
   The node co-signs only transport and handshake rows.
3. **Rosters are read through the fold.** Membership = `effective_roster` / `is_active_community_member`
   (record ∪ widenings − revocations, latest event wins, removal wins a tie). No server code reads
   `community.members` or `family.members` raw for a membership decision. A source-scraping gate enforces it.
4. **Governance follows the group's own declared rule.** A family or community carries
   `consensus_protocol` (`founder_only`, `unanimous`, `majority`, `quorum:m/n`). A roster change is
   authorized when the signer set satisfies it, verified by persist's `verify_membership_quorum`.
   `founder_only` (the default for a new household or room) is satisfied by one founder's signature, so the
   common case is one call. Anything stronger uses the two-phase envelope → cosign → assemble flow the
   accord already uses (`/v1/accord/family/change/envelope` pattern), generalised in §3.4.
5. **Leaving is always your own act**, never subject to quorum: any member may remove themselves.
6. **Refusals are stable ids** in `{error, reason_id, detail}` form, each covered by the localization guard
   (no `format!`-built ids). New ids are listed per section.
7. **Every write kicks replication** (`compose::kick_replication`) so the change crosses on a round-trip.
8. **Every list route carries the row's envelope** (subject, attester, cohort_scope, dimension,
   consent:scope — CSD-006, #616) and a `resume` cursor.

## 2. Self devices

| Op | Route | Policy | Notes |
|---|---|---|---|
| List owned nodes | `GET /v1/setup/owned-nodes` (exists, loopback) | loopback | unchanged |
| List device keys | `GET /v1/self/occurrences` (exists) | public binding metadata | add `revoked: bool` + `include_revoked=true` query |
| Add a device key | `POST /v1/self/occurrence` (exists) | signed by the primary | unchanged |
| Revoke a device key | `POST /v1/self/occurrence/revoke` (exists) | signed by a SURVIVING occurrence | unchanged |
| Relabel a device | `POST /v1/self/occurrence/label` `{occurrence_key_id, label}` **new** | owner session | a `supersedes` of the occurrence row with the new label; label is display-only |
| **Release a node** | `POST /v1/self/nodes/{node_key_id}/release` **new** | owner session; the owner of `node_key_id` must be the caller | withdraws the owner-binding (`delegates_to(user → node)`) with a signed `withdraws`; the node drops out of `nodes_owned_by`, the self room removes it on the next drive tick, the node reverts to Clause D fail-closed. Refuses the node you are talking to unless `force_self: true` |
| Self room bytes on a 2nd device | background driver | node-signed handshake | adopt `key_package_attestation_in` / `welcome_attestation_in` / `welcome_for` (#656); selffiles `opened_on_b` becomes REQUIRED |

New ids: `self.not_your_node`, `self.release_self_requires_force`, `self.label_empty`.

## 3. Family (household)

A household is a `Family` whose `family_key_id` is a keyless group identifier (V151), founded by the
caller's fed-ID, `consensus_protocol` default `founder_only`, replicated through `put_family` (the
`SignedFamily` door; `put_family_local` stays accord-only). Closes #627.

| Op | Route | Policy |
|---|---|---|
| Create | `POST /v1/families` `{name, consensus_protocol?}` → `{family_id, name, members, consensus_protocol, founded_at}` | owner session; caller becomes founder |
| List mine | `GET /v1/families` | owner session; families where the caller is an active member (fold) |
| Read | `GET /v1/families/{id}` → record + effective roster + roles | member only; a non-member gets 404 (hidden, not refused — "cannot even find out it is there") |
| Add member | `POST /v1/families/{id}/members` `{key_id, role?}` | `consensus_protocol` satisfied (founder for `founder_only`); target must be a registered identity key; DEK rewraps via `at_rest_cascade::rekey_family_member_add` |
| Remove member | `DELETE /v1/families/{id}/members/{key_id}` | `consensus_protocol` satisfied; `effective_at` now; the removed member's future reads fail closed |
| Leave | `POST /v1/families/{id}/leave` | any member, self only; the last founder may not leave a family with other members (`family.last_founder`) |
| Change role | `POST /v1/families/{id}/members/{key_id}/role` `{role}` | `consensus_protocol` satisfied |
| Dissolve | `DELETE /v1/families/{id}` | `consensus_protocol` satisfied; a terminal `supersede_family_with_quorum` with an empty roster; content stays sealed to nobody |
| Quorum change (non-founder_only) | `POST /v1/families/{id}/changes/envelope` → `…/cosign` → `…/assemble` | the accord's three-step pattern, generalised |

New ids: `family.not_found` (404, also for non-members), `family.not_authorized` (the protocol is not
satisfied; names the protocol), `family.unknown_member_key`, `family.already_member`, `family.not_a_member`,
`family.last_founder`, `family.name_empty`, `family.bad_consensus_protocol`, `family.quorum_pending`.

Files at `cohort: family` then work through §5 unchanged; a family rung joins the chat ladder.

## 4. Community and affiliations

A community room is a `Community` with N members (#594), founded by the caller, `consensus_protocol`
default `founder_only`. Growth is a `CommunityMembershipWidening` (edge `community_roster::widen_community`,
persist v48), removal a `CommunityMembershipRevocation` (`revoke_community_member`); the record is never
rewritten to grow. Pair rooms (`POST /v1/chat`) stay as they are and are listed here too.
`affiliations` is the same machinery at `Cohort::Affiliations`, created with `tier: affiliations`.

| Op | Route | Policy |
|---|---|---|
| Create | `POST /v1/communities` `{name, members?: [key_id], tier?: community\|affiliations, consensus_protocol?}` | owner session; caller is founder; each initial member must be a contact whose grant covers `chat:` (same rule as pair rooms) |
| List mine | `GET /v1/communities` (pair rooms included, `kind: pair\|room`) | owner session; fold |
| Read | `GET /v1/communities/{id}` → record + effective roster + roles + appointed moderators | member only; `community.not_found` for non-members |
| Add member (widen) | `POST /v1/communities/{id}/members` `{key_id, role?}` | protocol satisfied (founder, or an appointed roster-duty holder via `delegates_to`); target must be a contact; **blocked on CIRISPersist#907** for the added member's reads, gated by a RED-EXPECTED rung until it lands |
| Remove member | `DELETE /v1/communities/{id}/members/{key_id}` | protocol satisfied |
| Leave | `POST /v1/communities/{id}/leave` | self only; last founder rule as for families |
| Change role / appoint moderator | `POST /v1/communities/{id}/members/{key_id}/role` `{role}`; moderators keep using duty conferral | protocol satisfied |
| Dissolve | `DELETE /v1/communities/{id}` | protocol satisfied; terminal supersede |
| Quorum change | `…/changes/envelope|cosign|assemble` | as §3 |
| Send / read messages | `POST|GET /v1/chat/{id}/messages` (exists) | now room-keyed builders (`chat_message_attestation_in`), recipients from the fold, not the record |

New ids: `community.not_found`, `community.not_authorized`, `community.not_a_contact`,
`community.already_member`, `community.not_a_member`, `community.last_founder`, `community.name_empty`,
`community.bad_consensus_protocol`, `community.bad_tier`, `community.quorum_pending`.

**Stale-record reads fixed in the same change:** `contacts_chat::start_chat` pair check, `other_member`,
`send_message` recipients, `safety/named.rs` existence verdict and auto-promotion. All go through the fold.

**Security note.** Persist's replicated widening/revocation doors verify the signature, not the signer's
standing in the room (CIRISPersist#908). The server's routes enforce the protocol for rows it authors; rows
a peer authors are admitted by persist alone until #908 lands. Stated in the release notes.

### 4.1 As built (`src/communities.rs`, 0.5.216) — decisions and gaps at these pins

- **Ids added beyond the list above:** `community.pair_room_fixed` (409 — a pair room's roster is its
  derived identity; no add/remove/leave/dissolve), `community.change_stale` (409 — a submitted change
  envelope no longer describes the room), `community.malformed_body` (400), `community.delegate_may_not_author`
  and `community.delegation_denied` (403), `community.author_signer_unavailable` (403),
  `community.store_unavailable` (503), `community.write_failed` (500). `community.not_a_member` is 409.
- **Who may authorize** (`tally`): `founder_only` — one active founder, or, for a plain-member add/remove
  only, an APPOINTED `moderate` duty holder (persist `appointed_moderators_of`: founder-rooted
  `delegates_to` scoped `moderate`; there is no dedicated roster-duty scope in persist v48).
  `unanimous` — every active member except a removal's own target. `majority` — strict majority of the fold.
  `quorum:M/N` — M of the fold, and the change is applied through persist's
  `supersede_{community,affiliations}_with_quorum`, i.e. `verify_membership_quorum` re-verifies it.
- **Gap: `verify_membership_quorum` evaluates `quorum:M/N` only.** Its prior envelope reads the protocol
  off the RECORD and requires `quorum:M/N` with N = the fold's size (verify
  `accord_genesis.rs::quorum_threshold_from_envelope`), so `unanimous`/`majority` cannot be verified by
  persist; the server counts those with verify's `verify_threshold_signatures` over the fold's registered
  hybrid keys.
- **Gap: a quorum room's record must be re-baselined.** Because the protocol lives on the record and a
  widening never rewrites it, a `quorum:2/3` room grown to 4 by a widening alone could never be changed
  again (N ≠ member count). So a quorum room's add/remove/role goes through the persist quorum supersede
  (new roster + strict-majority protocol for the new N) AND writes the widening/revocation row, so peers,
  who hold the old record, still fold the change. Other protocols never rewrite the record.
- **Dissolve** is a revocation of every active member (others first, the signer last), not a terminal
  record supersede: verify refuses an empty membership-change roster (`quorum:M/0`), and a rewritten record
  is a roster fork at every peer. With nobody active, no server route can change the room again.
- **Role change** is a fresh widening row carrying the new role, written through the REPLICATED door
  (`put_community_membership_widening`); the local `add_community_member` no-ops for an already-active member.
- **Roster instants** are strictly increasing per room (the fold breaks ties toward removal, so a re-add in
  the removal's millisecond would silently lose); the revocation door refuses future-dated instants, so the
  server waits for the clock rather than stepping past it.
- **Listing a widened member's rooms:** persist indexes the record's members only, so `GET /v1/communities`
  also walks the widening plane (`list_signed_community_membership_widenings_since`) and then judges every
  candidate by the fold.
- **Affiliations** rooms carry `policy_blob: {"cohort_scope": "affiliations"}` on the signed record and use
  `Cohort::Affiliations` for the change envelope and the quorum supersede. **Gap:** edge v31's chat producer
  has no affiliations placement (`ScopeRoom` has no affiliations variant; `chat_message_attestation_in`
  seals at `community`), so an affiliations room's messages ride the `community` tier.
- **N-member room MLS group:** the creator is the smallest active founder by the fold; it adds every
  active member whose KeyPackage has arrived (a Welcome per joiner via `welcome_attestation_in` + a Commit
  row) and removes members the fold dropped; joiners join via `welcome_for` and apply the creator's commits.
  Unlike a pair room it never gates a send: the body is sealed under the room's DEK to the fold, and the
  group is the CC 5.4 addressing root only. State is in-memory per process, as for pair rooms (#623).
- **In-process witness:** `tests/community_crud.rs` runs three/four `Engine`s with distinct node keys and
  owners over ONE sqlite file — a mesh whose replication has fully converged — so "every member reads every
  message" is exercised through the real send/read routes on each member's own node. The crossing itself
  remains the ladder's (`room3`, `widened_reads`).

## 5. Files and drive

| Op | Route | Policy | Result |
|---|---|---|---|
| Upload | `POST /v1/files` (exists) | owner + membership | body limit raised to the edge DAG cap (64 MiB) for this route only; `multipart/form-data` accepted beside the JSON form |
| List | `GET /v1/drive?cohort=&room_id=&limit=&after=` (exists) | owner + membership | adds `resume` (edge `DrivePage::resume`), clamps `limit` ≤ 500, stops decrypting every file to compute byte state (reads presence, not plaintext), hides withdrawn rows unless `include_withdrawn=true` |
| Metadata | `GET /v1/files/{id}/meta` **new** | owner + membership | row envelope, size, media_type, filename, byte state, `devices_holding` (holder claims count) |
| Open bytes | `GET /v1/files/{id}` (exists) | owner + membership | adds `?raw=1` → the bytes with `Content-Type` and `Content-Disposition`, `Range` support via `read_blob_range_as`; the JSON form stays |
| Replace | `PUT /v1/files/{id}` `{bytes_base64 \| multipart, media_type?, filename?}` **new** | author only | publishes the new row as a `supersedes` of the old, then withdraws the old; returns the new id |
| Rename | `POST /v1/files/{id}/rename` `{filename}` **new** | author only | a new row over the SAME blob (no re-upload) `supersedes` the old; the filename is signed into the row |
| Withdraw (delete) | `DELETE /v1/files/{id}` **new** | author only (subject take-back is §7) | edge `withdraws_attestation`; persist then refuses every read of the bytes (CC 2.3); local copy evicted (`evict_blob`); holders drop it on their next pass |
| Move / share to a circle | `POST /v1/files/{id}/move` `{cohort, room_id?, keep_source?: bool}` **new** | author only; target membership | "going out asks": the route IS the ask. Reseals at the target room's tier and publishes there; unless `keep_source`, withdraws the source. Moving INWARD (to a narrower circle) is the same call |
| Notes | `POST|GET /v1/notes` (exist); `PUT /v1/notes/{id}`, `DELETE /v1/notes/{id}` **new** | owner | same supersede / withdraw machinery |

Byte-state and error mapping: `drive.withdrawn` (410) from persist `BlobError::Withdrawn` and the edge
`UnopenedReason::kind()` (never the `Debug` string); `drive.evicted` (410); `drive.seal_mismatch` (500);
`drive.too_large_for_whole_read` (413, use `raw=1` with `Range`). Also `drive.not_author` (403),
`drive.bad_move_target` (400), `drive.same_room` (409), `drive.filename_empty` (400), `notes.not_found` (404).

The split-install viewer key is resolved once: files are opened as the key the KEM occurrence was
provisioned for (`wire_identity()`), and a gate proves a split node opens its own file.

### 5.1 As built (0.5.216, branch `feat/drive-crud`)

Every route in the table above exists (`src/drive.rs`), with the ids above plus six the build needed:
`drive.delegate_may_not_author` / `notes.delegate_may_not_author` (403 — §1 rule 1, named rather than
folded into "no session"), `drive.bad_body` (400, an unparseable JSON or multipart body),
`drive.bad_cursor` (400, an `after` this drive did not issue), `drive.range_not_satisfiable` (416, with
`Content-Range: bytes */total`) and `drive.withdraw_failed` (500). Refusals answer
`{error, reason_id, detail}`. Witnesses: `tests/drive_crud.rs` (12 in-process tests) and
`tests/drive_split_viewer_key.rs` (its own binary: the wire identity is a process-global).

- **Upload.** `DefaultBodyLimit` on `POST /v1/files` and `PUT /v1/files/{id}` only: the 64 MiB cap
  as base64 plus 1 MiB. The FILE cap is the whole-read cap itself, so the node never accepts bytes it
  cannot hand back whole; `drive.too_large` (413) is now reachable (it was dead: axum's 2 MB default
  refused first, in plain text). `multipart/form-data` is parsed in-house (RFC 7578, no new crate).
- **Byte state without a whole read.** Persist has no public "may this viewer read" door —
  `authorize_viewer_by_tier` is `pub(crate)` (`federation/at_rest_cascade.rs:2024`). The drive
  therefore asks `read_blob_range_as` for a range starting past any end: persist authorizes by tier,
  refuses a withdrawn sha, then answers `RangeNotSatisfiable { size }` — no decryption for an inline
  blob, one manifest open for a chunk DAG. One call yields presence, grant, withdrawal and plaintext size.
- **Error mapping** is typed end to end: persist `BlobError` variants on the range/probe path, edge
  `UnopenedReason::kind()` on the whole-read path. The `Debug`-string match is gone.
- **Viewer key.** `backend::content_occurrence_key_id` is the ONE answer, used by the provisioner and
  by every open: the wire node key on a split install, else `engine.local_derived_key_id()`. Before
  this the provisioner wrapped grants to the wire key while the drive opened as the actor key, so a
  split node read `not_granted` on every file it wrote. The witness uses production's
  `node_key::move_owner_binding_to_node_key` and asserts the control (the actor key does NOT open).

**Gaps at these pins (edge v31.0.0 / persist v48.0.0), each deliberate and named:**

1. **Replace / rename / move are "publish new, withdraw old", not a CEG `supersedes`.** Edge's file
   door (`files::publish`) takes no supersedes input and no existing pointer, and persist's only
   supersedes builder (`crossing::build_widening`) changes `cohort_scope` and nothing else. The old
   row is WITHDRAWN (what retires it); a rename row carries the signed member
   `replaces_attestation_id` for lineage, and every change route answers `replaces`. Upstream ask:
   an edge `files::republish(pointer, ..)` and a body-changing `supersedes` builder.
2. **A rename row is built in the server** (`drive::rename_row`) — edge's row shape over the OLD
   pointer, author and instant (the seal's AAD is `(author, asserted_at, field)` read off the row, so
   a new row with those values opens the same bytes). `rename_keeps_the_blob_and_the_bytes_open`
   fails if the shape drifts from edge's.
3. **§1 rule 2 is not met for files.** `files::publish` authors every file row with
   `Signers::node` (edge `src/files.rs:222`, `:271`); the owner's pen is passed as `actor` and never
   used. So "author only" means "this node wrote it" (a rule-1 `withdraws` is signed with the same
   node key), and a file the owner wrote on ANOTHER device answers `drive.not_author` here.
4. **Withdrawn rows are listed by persist's gated reader.** `list_attestations` ignores
   `AttestationFilter::lifecycle` (sqlite `store/sqlite.rs:22334` builds no lifecycle predicate;
   only `list_scores`, `:11095`, applies it), so edge's `files::in_room` returns withdrawn and
   superseded rows. The drive re-derives each row's withdrawal with persist's own
   `check_withdraws_admission` (the per-row fold, `blob_tombstone::retiring_composer`, is private)
   and hides it unless `include_withdrawn=true`.
5. **Edge drops `BlobError::Withdrawn` into `Substrate`** (`group_content/persist_store.rs` `map_err`
   catch-all; `UnopenedReason` has no withdrawn arm). Every read checks the ROW's withdrawal first,
   so `drive.withdrawn` (410) does not depend on it.
6. **Crossing of the withdrawal.** Edge's `withdraws_attestation` is born at the widest cohort with no
   dimension; whether it reaches the owner's other devices depends on the consent plane covering it.
   Not provable in-process — the chat ladder's `withdrawn` rung is the witness.
7. **`devices_holding`** is the live `holds_bytes` claim count and is reported for community rooms
   only; at `self` / `family` CC 5.2 emits no holder claim, so the field is `null` with
   `holder_claims_recorded: false` rather than a misleading 0.
8. **Split-install authorship.** Files are authored by the router's node signer (the ACTOR key on a
   split). The owner's `self` gate admits them only because `move_owner_binding_to_node_key` adds the
   node-key binding without withdrawing the actor's; a change that retires the actor binding would
   hide a split node's files from its own drive.

## 6. Witnesses

- In-process tests per route family (behavioural, not source-scrapes): `tests/family_crud.rs`,
  `tests/community_crud.rs`, `tests/drive_crud.rs`, `tests/self_node_release.rs`, each covering the happy
  path, every refusal id, and the policy matrix (founder / member / outsider / delegate).
- A source-scraping gate: no raw `.members` read for a membership decision in `src/`.
- Ladders: selffiles `opened_on_b` REQUIRED; chat ladder gains `family`, `family_file_on_b`, `room3`
  (a three-member room), `widened_reads` (RED-EXPECTED until CIRISPersist#907), `withdrawn` (a withdrawn
  file reads 410 on the other node).
- openapi.json lists every route here; the localization guard covers every new id.

## 7. Deliberately later

- **Subject take-back** ("Mira is in the photo, so Mira can take it back") needs a subject field on the
  file row and a persist rule that lets a named subject withdraw someone else's row. Not in 0.5.216; the
  row shape reserves `subjects: [key_id]` so it can land without a migration.
- Folders, quotas, per-circle ordering.
