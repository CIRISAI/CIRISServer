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
  (founder_only: 1 signature;
   quorum:M/N: envelope → cosign
   → the proposal is complete
   when M have signed)
                                 accept(proposal) — K's pen ─────▶ widening admitted
                                 decline(proposal) — K's pen ────▶ proposal closed
                                 (no act before expiry) ──────────▶ proposal expired
```

- **A proposal is not membership.** It grants nothing: no rows, no wraps, no
  room address. It names the group, K, the offered role, the proposer(s) and an
  expiry, and it reaches K's node so K can see it.
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
| `POST /v1/families/{id}/invites`, `POST /v1/communities/{id}/invites` | a member with authority under the protocol | writes the proposal (founder_only), or opens the quorum envelope whose completion is the proposal |
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
replication apply. Until it lands the server withholds a new member's widening
until the acceptance row is present — an interim check that is DELETED when
persist's gate lands, never kept beside it.

## 5. Not in scope

- **Reverse quorum** stays the commons objection brake (`/v1/commons/*`,
  CSD-070); `reverse_quorum:` is refused as a family or community protocol.
- **Subject take-back** (removing oneself from rows already shared) stays deferred.
- **Pair rooms** (1:1 chat) keep their own consent: the contact grant each side authors.
