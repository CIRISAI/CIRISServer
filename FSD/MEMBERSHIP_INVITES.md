# MEMBERSHIP INVITES — nobody joins without their own consent

**Status:** design, 2026-09-30. **Ruling:** the maintainer, 2026-09-30: *adding someone
to a family or community requires their consent*; *reverse quorum is not a membership
rule*. **Normative text:** CIRISConstitution#133. **Substrate enforcement:**
CIRISPersist#955. **Client screens:** CSD-100..103 (to gain an invite inbox).

## 1. What is wrong today

Every roster-growing door adds a member on the EXISTING members' authority alone:

| Door | Today's gate | Asks the new member? |
|---|---|---|
| `POST /v1/families/{id}/members` | `check_addable`: a registered key, not already active | no |
| `POST /v1/communities/{id}/members` | `require_contact`: THIS node's live grant toward them covers `chat:` | no — that is our consent toward them, not theirs |
| `POST …/changes/{envelope,cosign,assemble}` (quorum) | M of N existing members | no |

CC 4.4.3.2.3's admit predicate checks only the current members' signatures under
`consensus_protocol` (geographic alone reads a newcomer-signed row, its
`location_proof`). So a founder can enrol any key they can name, and the
enrolled person's node begins receiving the group's rows and wraps.

## 2. The flow

```
inviter(s)                      invitee K                          group
─────────                       ─────────                          ─────
propose(K, role) ──────────────▶ inbox: pending proposal
  (ONE inviter signs: the founder
   under founder_only, any member
   otherwise)
                                 accept(proposal) — K's pen
                                                    │
  growth record (supersede / widening) under the ◀──┘
  group's consensus_protocol, citing the acceptance:
  founder_only = 1 signature; quorum:M/N = envelope
  → cosign → assemble, as today ──────────────────────────────────▶ member admitted
                                 decline(proposal) — K's pen ────▶ proposal closed
                                 (no act before expiry) ──────────▶ proposal expired
```

- **A proposal is not membership.** It grants nothing: no rows, no wraps, no
  room address. It names the group, K (in `subject_key_ids`; AV-84 keeps a
  targeted row's `attested_key_id` its producer), the offered role, the one
  inviter and an `expires_at` (bounded at 30 days), and persist serves it to K
  through a narrow read arm so K's node can see it.
- **The quorum stays on the growth record, not the invitation** (persist's
  #955 design): one inviter proposes; the supersede / widening that admits K
  carries the protocol's M-of-N exactly as today. One quorum check, not two
  that could drift. So under a quorum protocol K may accept and still not be
  admitted if the quorum never assembles.
- **Expiry is judged on signed instants** — the acceptance's and the growth
  record's `asserted_at` against the proposal's `expires_at` — never on a
  receiver's clock.
- **Acceptance is K's own act,** signed by K's person key through the server-side pen
  (the same authority `release_node` uses — a session bearer suffices). It binds the
  proposal (its attestation id / content hash) and the role; accepting a different role
  than offered is a new proposal, not an acceptance.
- **Only then** is the widening (community) or roster-growing supersede (family)
  written, citing the acceptance. The re-key of existing content to K
  (`rekey_family_member_add`) runs after admission, never before.
- **Decline and expiry are terminal.** A declined or expired proposal can never be
  admitted; inviting again is a new proposal.
- **Every protocol,** founder_only included: no quorum stands in for the joiner.
- **Leave is unchanged:** the member's own forward-only `withdraws`, no quorum.

## 3. Routes (server)

| Route | Who | Does |
|---|---|---|
| `POST /v1/families/{id}/invites`, `POST /v1/communities/{id}/invites` | the founder (founder_only) or any member | writes the proposal, signed by that one inviter |
| `GET /v1/families/{id}/invites`, `GET /v1/communities/{id}/invites` | members | pending / accepted / declined / expired, per invitee |
| `DELETE …/invites/{proposal_id}` | the proposer(s) | withdraws a pending proposal |
| `GET /v1/self/invites` | the invitee | the inbox: every proposal addressed to me, across families and communities |
| `POST /v1/self/invites/{proposal_id}/accept` | the invitee | signs the acceptance; the widening follows |
| `POST /v1/self/invites/{proposal_id}/decline` | the invitee | signs the decline |

`POST …/members` stops adding directly: it becomes an alias for `…/invites` that
answers `202 {state: "invited"}` and names the proposal, so no caller mistakes an
invitation for a membership.

## 4. Where the rule lives

The ADMISSION rule is persist's (every host would otherwise write it; one rule,
one implementation): CIRISPersist#955 asks for
the proposal and acceptance rows and a gate on both the local put and the
replication apply. It is a persist MAJOR (v52).

**Interim (the maintainer's choice, 2026-09-30): refuse, don't hold.** Until v52
the server has no way to deliver a proposal to a non-member or to record an
acceptance (the dimensions are not in the strict registry). So every
roster-growing door refuses with 409 `membership.consent_required`: a direct
add, a quorum envelope that adds, and a founding roster naming anyone besides
the founder. Creating a group, removing members, changing roles, leaving and
dissolving are unaffected. This keeps no server-side copy of the rule, only a
closed door.

**Founding members too** (same ruling): the founding record admits only the
founder; everyone else named in it joins by proposal → acceptance.

## 5. Not in scope

- **Reverse quorum** stays the commons objection brake (`/v1/commons/*`,
  CSD-070); `reverse_quorum:` is refused as a family or community protocol.
- **Subject take-back** (removing oneself from rows already shared) stays deferred.
- **Pair rooms** (1:1 chat) keep their own consent: the contact grant each side authors. Seeing a contact request
  someone else authored is §8.

## 6. Persist's contract, as the maintainer resolved it (CIRISPersist#955, 2026-09-30)

- **Signing the founding record is consent.** A founding member is admitted iff
  they signed it, as the authority or as a cosigner. A listed but unsigned member
  is refused as `membership_founding_member_unsigned`. `POST /v1/families` and
  `POST /v1/communities` sign with the founder alone, and the server has no
  founding-cosign flow, so the interim 409 on a founding roster beyond the
  founder stays correct. If the server gains a founding-cosign flow, co-signing
  founders are admitted.
- **A supersede never adds members.** Every addition is a widening; a quorum
  add is a widening carrying the M-of-N. A roster-growing supersede is refused
  as `membership_supersede_cannot_add`. **At v52 adoption the family quorum
  add (envelope → cosign → assemble, today `supersede_family_with_quorum`
  with a grown roster) must become a quorum-carrying widening.** It is
  refused by our 409 until then.
- **Leave and dissolve replicate** (CIRISPersist#956, in v52): leave is a roster
  supersede removing only its own signer, admitted on that one signature;
  dissolve is a quorum-verified terminal amendment. The ignored test
  `a_quorum_dissolve_replicates_as_an_amendment` (CIRISServer#700) is un-ignored
  at v52.

## 7. As built — persist v52.0.0 / edge v38.0.0 (0.5.218)

The interim 409 is gone; the flow of §2 is live. What shipped, and where it
differs from the design above:

### 7.1 Routes

| Route | Who | Answers |
|---|---|---|
| `POST /v1/{families,communities}/{id}/invites` `{key_id, role?, expires_in_days?}` | a founder under `founder_only`; any active member otherwise | 202 `{state: "invited", proposal_id, group_kind, group_id, invitee_key_id, role, expires_at}` |
| `POST /v1/{families,communities}/{id}/members` | same | the alias above, same 202 |
| `GET /v1/{families,communities}/{id}/invites` | members (a delegate may read) | `{invites: [{proposal_id, invitee_key_id, role, proposer_key_id, proposed_at, expires_at, state, reply_id}], seated_now: [...]}` — `state` ∈ `pending` / `accepted` / `joined` / `declined` / `expired` / `withdrawn` |
| `DELETE /v1/{families,communities}/{id}/invites/{proposal_id}` | the proposer | 200 `{state: "withdrawn", withdrawal_id}` (a `withdraws` of the proposal) |
| `GET /v1/self/invites` | the invitee (a delegate may read) | every live, unanswered, unwithdrawn proposal naming them (edge `membership::pending_proposals_for`), families, rooms and pair rooms |
| `POST /v1/self/invites/{proposal_id}/accept` / `…/decline` | the invitee's own session | 200 `{state: "accepted" \| "declined", reply_id, awaiting}` |

Rows are edge's (`membership::{propose, reply, widen_on_acceptance}`, built on
persist's own builders); the server keeps no copy of the admission rule.
`expires_in_days` is 1..=30 (default 14; persist bounds a proposal at 30 days).
A contact grant is NOT required to invite: an invitation reaches a stranger's
nodes under first contact (CIRISEdge#756). The invitee must be a registered key
for a family (the widening names it).

### 7.2 Who seats the member

- **`founder_only`** — the founder's single-signature widening. Written by
  edge's replication bridge when the acceptance arrives
  (`ReplicationRuntimeConfig::membership_widener`, set in `compose` to the
  owner's PERSON pen, because the roster counts seat keys), or by the server
  when a founder lists `…/invites` (covers a node claimed after its runtime
  started, which has no widener until restart). A household's existing
  content is re-wrapped to a member the LIST seats (`rekey_family_member_add`);
  one the bridge seats is not re-wrapped by the server — a gap (§7.5).
- **Any other protocol** — "accepted, awaiting the group" (persist FSD §4): the
  `add` of `…/changes/{envelope,cosign,assemble}`, now written as a co-signed
  WIDENING (persist Q2: a supersede never adds). Without the joiner's
  acceptance persist refuses it at assemble, `membership.awaiting_acceptance`,
  however many members signed. A family's record never grows; its stored
  `quorum:M/N` is not rescaled by an add.

### 7.3 Founding, leave, dissolve

- A create naming anyone but the founder is `membership.founding_member_unsigned`
  (409) — the server has no founding-cosign flow (persist Q1).
- **Quorum family leave** (CIRISPersist#956): `supersede_family_with_quorum`
  with the record minus the leaver, the envelope from
  `build_membership_change_envelope(remaining)`, signed by the leaver alone; the
  protocol is NOT rescaled ("nothing else may change"). It replicates. A member
  seated by a widening is not on the record; their revocation alone is the leave.
- **Quorum family dissolve** (#956): the change envelope pins `dissolved_at`;
  assemble writes the terminal amendment (every seat unchanged, `dissolved_at`
  set) through `supersede_family_with_quorum`. No removal rows. It replicates
  (`a_quorum_dissolve_replicates_as_an_amendment`, un-ignored). A
  `founder_only` dissolve is unchanged (revocations + the local supersede).

### 7.4 Pair rooms

`POST /v1/chat` no longer writes a two-founder record (persist refuses it):
the opener founds alone and proposes the peer as `founder`
(`chat::open_pair_room`); the peer's own `POST /v1/chat` accepts
(`chat::accept_pair_proposal`); the opener's node widens (bridge, or the
opener's next call with their pen). The answer gains `state` (`open` /
`invited` / `accepted` / `awaiting_invitation`) and `proposal_id`. A pair
room's invitation also appears in `GET /v1/self/invites`.

### 7.5 Reason ids (all 409 unless noted)

persist's rules, one each: `membership.awaiting_acceptance`,
`membership.invite_not_here_yet` (both retryable), `membership.declined`,
`membership.invite_expired` (410), `membership.acceptance_mismatch` (403),
`membership.already_answered`, `membership.founding_member_unsigned`,
`membership.supersede_cannot_add`; and `membership.refused` (any other refusal
of a membership row). The flow's own: `membership.invite_not_found` (404),
`membership.not_the_invitee` (403), `membership.not_the_proposer` (403),
`membership.invite_closed`, `membership.bad_expiry` (400),
`membership.owner_session_required` (401/403),
`membership.delegate_may_not_answer` (403), `membership.signer_unavailable`
(403), `membership.store_unavailable` (503). Queued for the client bundle
(`KNOWN_UNLOCALIZED`, CIRISClient#78).

Gaps named, not built: the bridge-seated member's content re-wrap (above); a
founding-cosign flow; the CSD for the inbox screens (CSD-100..103).

## 8. Contact requests — the one inbox covers people too (0.5.237)

**The gap (Eric × Francesco, 2026-10-24).** A contact is consent each side
authors: a live `consent:replication:v1` grant covering `chat:`. `GET /v1/contacts`
lists the grants the OWNER signed. Nothing listed the grants other people signed
naming the owner, so being added was invisible until the owner happened to add
the person themselves. Both people had to add each other blind.

**What a request is.** A live grant that:
- names the owner's fedID or one of this node's keys;
- is signed by someone else, resolved to a PERSON through edge's contact resolver
  (`contact::resolve`); infrastructure (a canonical) and the owner's own devices
  are never requests;
- covers `chat:`;
- is not withdrawn or recanted by its signer, and not expired;
- is unanswered: the person is not already the owner's contact. "Already a
  contact" is `contacts_chat::contact_persons`, the one rule `GET /v1/contacts`
  uses, so the two lists cannot disagree.

One entry per person, newest grant first. The read is persist's bounded
`AttestationQuery::to(key).dimension("consent:replication:v1")`, not an
every-row scan.

**Routes.**

| Route | Who | Answers |
|---|---|---|
| `GET /v1/contacts/requests` | the owner (a delegate may read) | `{requests: [{kind: "contact", requester_key_id, grant_attestation_id, granted_by_key_id, granted_to_key_id, requested_at, grant, accept}], total}` |
| `GET /v1/self/invites` | the invitee | unchanged `invites` (families/households, communities, affiliations, pair rooms) **plus** `contact_requests`, the same entries |

**Answering.** Accepting is adding the person back: `accept` is
`{method: "POST", path: "/v1/contacts", body: {key_id}}`, the existing route. A
contact has no proposal row, so it is never answered through
`/v1/self/invites/{id}/accept`. The request then leaves both lists by the rule
above; there is no separate "accepted" state to keep in step.

**Witnesses.**
- `tests/contacts_chat.rs::someone_who_added_you_is_a_request_until_you_add_them_back`
  and `a_withdrawn_request_is_not_offered`. Each filter is mutation-checked.
- `tests/community_crud.rs::a_contact_request_reaches_the_other_persons_inbox`:
  two nodes. Alice adds Bob, Bob's own inbox shows her, hers shows nothing, and
  Bob adding back clears it.

**Not yet (named, so nobody assumes them):**
- **Declining a contact.** No signed row answers "no" to someone else's grant.
  The only answer today is not adding back. A dismissal that hides a request
  needs a decision: a node-local note, or a signed `declines` the requester's
  node could read.
- **Requests that need a link.** A grant reaches the owner's node only by
  replication. A transport fault between the two nodes holds it back. CIRISEdge#888
  (two keys claiming one destination) was exactly that.
- **Requests addressed to another device.** A grant naming the owner's OTHER
  device replicates to that device; this node lists the grants naming its own
  keys and the fedID.
- **The pair-room invite.** Only the person who opens the chat sends it (§7.4).
  A Joiner who added back must still wait for the Creator's open. The
  five-platform cross-platform chat stage (CIRISAgent, 2026-10-25) measures this
  and the request visibility above.

