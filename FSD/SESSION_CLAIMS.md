# Session claims — one device handles each exchange (0.5.218)

**Status:** implemented in 0.5.218 (the maintainer's ruling of 2026-09-30).
**Normative source:** CC 3.1.3.1 (`session:*`), CC 2.1 (`community_id`,
`session_id`, `claimed_at`), CC 2.6.2 (the instant's canonical form).
**Substrate:** persist v51.3.0 `federation::session_claim` (CIRISPersist#782),
`check_session_self_report_admission` (CIRISPersist#814 part 5).
**Code:** `src/session_claims.rs`; the gated sites below; the gate test
`tests/every_act_passes_the_session_gate.rs`; the witness
`tests/one_device_handles_each_exchange.rs`.

## 1. The problem, and the split

A person is one fed-ID plus the N nodes they own — the *occurrences* of their
self. A row addressed to the person reaches EVERY one of those nodes (a fed-ID
has no transport path of its own), so every autonomous reaction this server has
ran on every device the person owns. Two devices committing the same MLS add
at one epoch fork the self room; two devices re-wrapping one blob write two
key-grant sets for one grant.

Persist has carried the routing table since v38.7.0 and the server never used
it (zero hits for `session_claim`, `session:claim`, `handler_for` before this
cut). The split is CC 3.1.3.1's:

| persist owns | the server owns |
|---|---|
| the row (`session:claim:v1`), its projection (`SelfOwn` at `self`, `Cohort` at every commons tier) | **attendance** — "the person is on this device" |
| admission: a SELF-REPORT (attester == attested == the claiming occurrence); a third party is refused at the door | when to claim, renew and let go |
| the merge: earliest `claimed_at`, ties on the lowest occurrence key id | the inventory of ACT sites, and the gate at each |
| the read: `handler_for(directory, owner, community, session, now, ttl)` | the surface `GET /v1/self/sessions` |

The server never re-implements the merge. Every "who handles this?" is
`handler_for`; the surface enumerates which exchanges have claim rows but asks
persist who holds each one.

## 2. The inventory

Every place this server ACTS on something addressed to its person, and the
things that look like one but are not. **Gated** rows call
`session_claims::gate` before the act and act only on `Verdict::Act`;
`tests/every_act_passes_the_session_gate.rs` reads the gated rows of THIS table
(`file`, `fn`, `act`) and fails if the function's body does not call the gate
before the act.

### 2.1 Gated — exactly one device acts

| act | file | fn | act call | gated | community_id | session_id |
|---|---|---|---|---|---|---|
| self room: commit an ADD (and the add half of a Rejoin) | `src/self_room_drive.rs` | `drive_once` | `add_members(` | **gated** | the self room's `content_group_id` (`ciris_edge::self_room::room(owner)`) | `self_room:membership` |
| self room: commit a REMOVE (and the remove half of a Rejoin) | `src/self_room_drive.rs` | `drive_once` | `remove_members(` | **gated** | the self room's `content_group_id` | `self_room:membership` |
| re-wrap old self files for a new device | `src/self_rewrap.rs` | `rewrap_for_new_devices_with` | `rekey_self_occurrence_add(` | **gated** | the self room's `content_group_id` | `self_rewrap:<new occurrence key id>` |

Why these session keys:

- **One membership session for the whole self room**, not one per joiner: an
  MLS group's commits must come from one committer at a time — two devices
  adding two DIFFERENT joiners at the same epoch fork the room exactly as two
  adding the same one do. CC 3.1.3.1 lists "a moderation duty" as an exchange;
  this is that shape. Only a device that HOLDS the group reaches these arms, so
  the joiner (which cannot add itself) never claims the duty.
- **One re-wrap session per new occurrence**: the capability is per occurrence.
  The new device holds none of the old DEKs and can never re-wrap for itself,
  so it must never be the one the fold names; per occurrence it never is (it is
  never pending for itself). The gate runs AFTER the pen check: a device that
  cannot do the work does not take the duty.

Idempotence per act (CC 3.1.3.1: "views transiently disagree"): the re-wrap
records its act id (`rewrap \0 owner \0 occurrence \0 x25519`) in the device's
`Attendance` ledger only on success, and persist's door skips a blob already
granted; the self room's `decide` re-reads the tree after applying the room's
commits, so a joiner already added is never re-added.

### 2.2 Not gated — every device does its own

| act | where | why every device does it |
|---|---|---|
| self room: `Create` | `self_room_drive::create_room` | edge's `decide` already confines creation to the LOWEST node key in the roster, and `Abandon` settles an unsettled directory's two rooms. It is the room's genesis by key order, not an answer to anything addressed to the person; gating it would leave a person with no room until they were on the lowest-keyed device. |
| self room: publish KeyPackage, join on a Welcome, apply remote commits, install/advance addresses, seal, `Abandon` | `self_room_drive` | this device's OWN membership steps. |
| provision this device's content-KEM occurrence | `backend::provision_engine_occurrence` | this device's own occurrence. |
| wrap self DEKs to an occurrence bound ON this device (`auth::occurrence::bind_occurrence_core` → `rekey_self_occurrence_add`) | `POST /v1/self/occurrence`, the portable-occurrence doors, `node_key::register_actor_occurrence` at boot | the device doing its OWN binding, never a reaction to a sibling's row. The gate test pins these as the door's only other caller. |
| consent healer (`peer::ensure_contact_consent_covers`) | `replication_reconcile` | consent is per node: each device's grant names itself. |
| replication kicks, publish-own refresh, peer convergence | `compose`, `replication_reconcile` | transport of rows; fan-out must stay fan-out (persist's module doc: "election does not belong on the transport plane"). |
| storing rows, pulling bytes (`receive_axis::pull_owner_testimony`), showing a chat message, listing notes/files | everywhere | every device SHOWS the person's content; nothing here answers anything. |
| heal the owner's key record, accept the roots as owner (boot) | `node_key::heal_owner_key_record`, `accept_roots_as_owner` | the node's own boot maintenance of ONE convergent row, idempotent (a second device finds it bound/accepted and does nothing). Gating it on attendance would leave the production canonical — headless, never attended — unhealed forever. |

### 2.3 Not gated — the person asked on this device

These are HTTP handlers. The request came to ONE device; there is no fan-out,
and the request itself is the person's attendance (it passes
`resolve_bearer`, which marks it).

| act | where | community_id / session_id it would take if it ever became fan-out |
|---|---|---|
| claim-remote, upgrade-owner, announce | `claim_remote.rs` | — |
| second-device approval: `approve`, `claim`, `token` | `auth/device_grant.rs` | pending grants live IN MEMORY on the node that issued the code (never replicate): one handler by construction. If they ever replicate: (self room, `device_grant:<request attestation id>`). |
| release / announce / label a device | `self_devices.rs` | — |
| households, communities, drive, notes, contacts add/withdraw | `family_api.rs`, `communities.rs`, `drive.rs`, `contacts_chat.rs` | — |

### 2.4 Named, not gated in this cut

| act | where | why not yet, and the key it will take |
|---|---|---|
| a chat room's MLS handshake on the CREATOR side (create, add, Welcome, `reconcile_room_group`) | `contacts_chat::room_key`, `room_key_room`, `reconcile_room_group` | runs INSIDE the person's own request, but reacts to KeyPackages that replicated to every device, and the MLS member is the PERSON's key while the MLS store is per node — so the person opening the same chat on two devices builds two groups. Gating it needs the deferring device to JOIN the handler's group, which edge's chat path does not do for a person's second device today. Key when it lands: (`pair_community_key_id(me, peer)` or the community id, `chat:handshake`). |
| an agent's reply to an inbound message | — | no agent auto-reply exists in `src/` (no `auto_reply` anywhere). When a hosted agent replies for the person it passes the gate with (the room's community id, the inbound message's attestation id). |
| accepting a contact, household or community invitation | — | nothing accepts automatically: the invitee's signed acceptance is the person's act on one device (FSD/MEMBERSHIP_INVITES.md). |

## 3. Attendance

A device is **attended** while the person's own session has touched it within
`PRESENCE_IDLE` (10 min). The one place every such request resolves is
`auth::session::resolve_bearer`; on a verified SystemAdmin (owner) session it
calls `Attendance::global().note_presence()`. A delegated `dgrant:` session
returns before that line — a helper acting for the person is not the person.
A device that merely BOOTED is not attended: a claim derived from boot would
hand the person's exchanges to whichever device came up first, including the
headless ones they never look at.

## 4. Claim, renew, lapse

| const | value | why |
|---|---|---|
| `SESSION_CLAIM_TTL` | 120 s | the horizon every device applies (one binary, one constant — until the horizon is in the row). A 60 s renewal on a 30 s loop always leaves a full loop period of slack; when the person moves device, the other device takes the exchange within two minutes. |
| `SESSION_CLAIM_RENEW_EVERY` | 30 s | the loop period (the node's common period; `loop_cadence`'s separation argument needs multiples of 30 s). Loop name `session_claims`, its own slot. |
| `SESSION_CLAIM_RENEW_AFTER` | 60 s | a holder writes its successor lease at half the TTL: one row a minute per held exchange rather than one per tick. |
| `PRESENCE_IDLE` | 10 min | an open client polls far more often; long enough to span the second-device flow (approve on the first device → the second boots, provisions, publishes its KeyPackage → the first must still be attended to commit the add). |

The decision is pure (`session_claims::step`):

- not attended → **Lapse** (write nothing; the claim goes stale);
- nobody holds it → **Claim**;
- another occurrence holds a live claim → **Defer** (never contested);
- we hold it → **Renew** when our newest lease is ≥ 60 s old (or unknown after
  a restart), else **Hold**.

**Claim on demand.** A site with work calls `gate`; if nobody holds the
exchange and this device is attended and can sign as its occurrence, the gate
writes the claim there and then, kicks replication, and re-reads the fold —
acting only if persist then names it. The loop only renews.

**The row.** `scores`, dimension `session:claim:v1`, `cohort_scope: self`,
attested = attester = the device's NODE key (the occurrence the owner-binding
names: the held node signer on a split install, never the actor key), envelope
`{community_id, session_id, claimed_at}` with `claimed_at` in CC 2.6.2 form,
`expires_at = claimed_at + TTL`. Written through `attest::emit`, so it is
signed and stored through the one authored door, and a `self` row reaches the
person's other devices by persist's `send_set_for`.

**Renewal on persist v51 — a successor lease.** v51's liveness is the
consumer's horizon measured from `claimed_at`, and persist is explicit that a
renewal must not move `claimed_at`. Together they mean a same-instant renewal
cannot extend anything on v51. So a renewal here is a fresh lease row written
only by the device the fold already names; because a non-holder never claims
while a live claim exists, the holder's leases are the only live claims and
the earliest of them keeps naming the holder. Residual: a simultaneous first
claim by two attended devices can hand the session over ONCE (the loser's one
lease outlives the winner's first); the new holder renews and the old one
defers. One handover, never two handlers in one view.

**Persist v52 (CIRISPersist#946) — TODO in `session_claims::write_claim`:** the
signed lease bound `valid_until` (≤ 86 400 s after `claimed_at`) replaces the
consumer TTL as the horizon, and a renewal becomes a `supersedes` that keeps
`claimed_at`. Not invented before the pin moves: v51 has no member for it.

## 5. The surface

`GET /v1/self/sessions` — owner-authenticated (a delegate may read):

```json
{
  "owner_key_id": "…",
  "this_device": "<this node's occurrence key>",
  "attended": true,
  "ttl_seconds": 120,
  "sessions": [{
    "community_id": "…", "session_id": "self_room:membership",
    "handler_occurrence_key_id": "…", "handler_label": "Eric's laptop",
    "claimed_at": "2026-09-30T12:00:00.000Z", "live_until": "2026-09-30T12:02:00.000Z",
    "this_device": false,
    "state_id": "session.state.handled_elsewhere",
    "state": "Another of your devices is answering for you in this exchange."
  }]
}
```

Only exchanges some device is answering are listed: an exchange whose every
claim lapsed has nobody answering, and is absent.

New ids (string literals; on `KNOWN_UNLOCALIZED` in
`tools/check_server_localization.py` until the client bundle carries them;
the ratchet in `tests/localization_gate.rs` 139 → 142):

| id | English |
|---|---|
| `session.state.handled_here` | This device is answering for you in this exchange. |
| `session.state.handled_elsewhere` | Another of your devices is answering for you in this exchange. |
| `self.sessions_unavailable` | The node could not read which of your devices is answering. Try again shortly. |

(`self.owner_session_required` is reused with its existing text.)

## 6. What the substrate should provide

- **persist v52 / #946** — `valid_until` on `session:*` (the signed horizon)
  and the `supersedes` renewal; then the successor-lease workaround and the
  shared-constant TTL go.
- **persist** — exported envelope path constants for `community_id`,
  `session_id`, `claimed_at` (its reader spells them inline; the server names
  them once and round-trips a written envelope through `claim_from_envelope` in
  a unit test so a rename fails loudly).
- **edge** — a person's second device joining a chat room the person already
  holds (so the chat handshake in §2.4 can defer to one device).

## 7. The harness

`harness/native/topology.py` relation `session(person, device)` (FSD/TOPOLOGY.md):
for a person with two online devices, drives the person's activity on `device`,
then asserts that `GET /v1/self/sessions` on EVERY device of the person names
the same handler for every listed exchange. In `topologies/selffiles.yaml`
after the `note` step.
