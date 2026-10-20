# CSD/4 — the topology catalogue, locked

**Status:** LOCKED at catalogue version 3 (2026-10-20; version 1 and 2 on 2026-10-18 — 2 when the steward ruled the push waits on exhaustiveness over CC's formally defined states, 3 for the held self-roster ADDITION, `key.membership.proposed_add`). Brought in 2026-10-20 with the multi-device cut (CIRISServer#793, #794), the vocabulary pinned to CIRISConstitution rc9 @ `01b47e75`. **Owner:** CIRISServer (the
catalogue, the model, the builder). **Consumers:** CIRISClient's CSD cards and
`check_csd_v3`, the native harness, CC's `tools/topology_to_cfg.py`.
**Source of the ruling:** the steward on CIRISClient#179 §2: *do not give CSD authors
an open grammar for potential topologies; define the relevant topologies up front as a
catalogue for testing.* `FSD/TOPOLOGY.md` stays the TYPING of a catalogue entry.

## 1. What a CSD/4 card carries

CSD/3, plus three fields:

```yaml
derives: [5a, 5b, 2g]        # the plain-rule ids this surface exists for, or `ops`
topology: T7                 # ONE catalogue id; never a topology block
tests:                       # what the card tests, and AT WHICH STATE
  shutdown_dialogue:
    at: [agent.bound, steward.bonded]     # atoms that hold AT THE SAME INSTANT
```

A card names a catalogue id and atoms from the vocabulary (§3), nothing else. The
server's copy of every card's `topology` and `tests` lives in
`harness/native/topologies/catalog/requirements.yaml` (§6); the client checker
compares the card against it. `check_csd_v3` refuses, by name:

1. a `topology` outside T0–T19;
2. an atom outside the vocabulary of the catalogue version the card names;
3. a test whose atoms no catalogue entry reaches at one instant (`plan` reports it
   `uncovered`);
4. `building` without `derives:` (CIRISClient#179 §2).

`topology:` is a hint. The planner may choose a cheaper entry that reaches the same
states (§6.1) and reports the change as `reselected`.

## 2. The catalogue (version 3)

Twenty entries, each one checked-in yaml file in `harness/native/topologies/catalog/`,
named `T<n>-<slug>.yaml`, carrying `catalog_id`, `catalogue_version`, `title`,
`serves`, `derives`, `promises` (the atoms the entry guarantees to reach, which the
model verifies) and the `topology` block typed by `FSD/TOPOLOGY.md`.

| id | who exists | promises (abridged) | builder today |
|---|---|---|---|
| T0 | one person, one node, no canonical (Just me, offline) | `root.none`, `node.unclaimed` → `node.claimed` | whole |
| T1 | one person, two carried devices, self room | `room.self.keyed`, `note.synced`, `session.unified`, `file.held` → `file.custody_received` → `file.withdrawn` | whole |
| T2 | two people, pair room, one outsider | `contact.reachable`, `room.pair.keyed`, `message.delivered`, `person.outsider` | whole |
| T3 | two people, contact by code, a second device BY APPROVAL | `contact.via_code`, `device.join_requested` → `device.join_approved` → `device.joined`, `roster.visible`, `file.held` | whole |
| T4 | a household: guardian on two devices, one child | `household.formed`, `child.member`, `guardian.bound`, `age.assured` | up to `guardian_bond` |
| T5 | a community, a held quorum change, a moderator duty | `community.member`, `quorum_change.held` → `quorum_change.applied`, `moderator.named` | whole |
| T6 | an affiliation, a licensing authority, a delegation chain | `community.formed` (affiliations tier), `authority.licensing`, `delegation.chain` | up to `authority` |
| T7 | an agent under a steward with a Wise Authority | `agent.bound`, `steward.bonded`, `wa.present` | up to `agent` |
| T8 | an M-of-N infrastructure root: halt, confirm, resume | `pair.rooted`, `root.halted` → `root.halt_confirmed` → `root.resumed` | whole |
| T9 | two roots and a party outside both | `root.two`, `party.outside_roots` | up to the second canonical |
| T10 | a stolen device evicted by the quorum path (three roster keys) | `key.holder.thief`, `key.membership.proposed_evict` → `evicted`, `self.roster_size.three_more` | whole (CIRISServer#794 quorum path; a held third-device approval assented in) |
| T11 | two lost devices, recovery by the lone path | `key.holder.lost`, `key.membership.evicted`, `self.roster_size.one` | up to `evict_lone` (the test-anchor `W_self` seam, CIRISPersist#1111) |
| T12 | a root stalls (a founder resigns) and recovers by a conferred human | `root.standing.Stalled`, `root.liveness.stalled` → `root.liveness.live` | up to `resign` (branch pending) |
| T13 | a witnessed lineage: stale head, node-bearing seat | `root.head.stale`, `seat.identity_type.node_bearing` | up to `lineage_head` (CIRISServer#693) |
| T14 | consent end to end | `consent.state.*`, `consent.decay.*`, `consent.community_trust.*`, `consent.replication.none` | up to `community_trust` (CIRISServer#790) |
| T15 | a community's ceremony (incl. an invitation declined at its window, CIRISServer#796) | `member.stage.*`, `group.moderator.*`, `group.federating.no` | up to `invite` (branch pending) |
| T16 | an agent retired under the Standard | `agent.bond.*`, `agent.retirement.*`, `agent.halt_gate.acting` | up to `agent_bond` (agent process) |
| T17 | a takedown and a steward purge; family and community scope | `row.standing.admitted` → `tombstoned`, `blob.custody.purged`, `row.scope.*` | up to `scoped_file` (branch pending) |
| T18 | delegation ends; a key grant; a guardian bond absent | `delegation.link.*`, `grant.state.held`, `guardian.bond.none` | up to `key_grant` (branch pending) |
| T19 | holders under coercion and censorship; revoked_after | `root.holder_disposition.*`, `key.revocation.*`, `node.announce.announced` | up to `holder` (branch pending) |

T10–T19 were proposed by CIRISConstitution's reverse gate (`tools/catalogue_coverage.py`):
of the 155 states in `formal/STATE_TABLE.tsv`, T0–T9 exercised 47, and 58 states a model
constrains were exercised by none. Version 2 adds one atom per such state and the ten
entries whose promises close them. Coerced and censored holders are STAGINGS (a holder
signing an invocation the standing rule refuses; a holder whose rows are withheld past
the window); CC ruled them the model's own dispositions (`formal/accord_roster`).

`→` marks a TRANSIENT state: a later step of the same entry ends it. A test that
needs one must run inside its window, which is why the runner tests at intermediate
checkpoints and not at the end of the build.

The pre-catalogue declarations (`topologies/csd-091…`, `csd-092…`, `csd-094…`,
`csd-107…`, `selffiles`, `bigfile*`) stay as regression fixtures and are not
catalogue entries. T1, T2 and T3 subsume their states.

## 3. The vocabulary (version 3)

Closed, and **owned by the constitution** (steward decision 2026-10-18). CIRISConstitution
publishes `manifests/topology_vocabulary.json`, which maps each atom to its plane state
predicate (over `formal/STATE_TABLE.tsv`), its CC decimal and its meaning. CC CI gates it
(`tools/check_formal_tables.py`). The model loads a byte copy,
`harness/native/topologies/catalog/topology_vocabulary.json`, pinned by commit and SHA-256 in
`topology_vocabulary.pin`. A test fails when the two disagree, and the model refuses any other
`catalogue_version`. Atoms are DERIVED from an entry's steps by the model (`model.effects`)
and never declared by hand, so an entry cannot claim a state its steps do not produce. The
table below is the manifest's meanings as of the pin.

| atom | holds when |
|---|---|
| `root.none` | no canonical serves a root anywhere in the mesh: the node is offline (Just me) |
| `root.key` | a key root (one holder key) is held by a canonical |
| `root.infrastructure` | an infrastructure root (the accord: seated holders, quorum) is held by a canonical |
| `root.rooted` | a canonical holds a root whose lifecycle verdict is rooted |
| `root.two` | two distinct roots are held, by two canonicals |
| `root.halted` | the accord root's kill switch is latched on every node (CC 4.2.1.1) |
| `root.halt_confirmed` | a strict majority confirmed the standing halt within the fuse (CC 4.2.1.3) |
| `root.resumed` | a strict majority resumed the halt; nothing is latched |
| `node.unclaimed` | a node is booted and nobody owns it yet (first run) |
| `node.claimed` | every node a person owns at this point is claimed |
| `node.announced` | some person node announced its owner-binding (placeable) |
| `node.unannounced` | some person node did not announce (P2P only) |
| `canonical.peered` | every node that dials a canonical holds its record (the owner's peering act) |
| `person.multi_device` | a person owns two or more claimed devices |
| `person.outsider` | a person with no relation to anyone else (the negatives' witness) |
| `party.outside_roots` | a node that accepts none of the roots held in the mesh |
| `device.join_requested` | a new device asked to join an existing ID; the other device has not answered |
| `device.join_approved` | the other device approved; the new device verified it offline and HOLDS it, unapplied |
| `device.joined` | the approval was applied: the new device is claimed under the existing ID |
| `peer.direct` | two person nodes peered directly (production peering both ways) |
| `pair.rooted` | two people hold a valid root in common (edge's pair verdict) |
| `contact.reachable` | a person's node binding is held on another's node at federation scope |
| `contact.added` | a contact was added |
| `contact.via_code` | a contact was added from the person's contact code |
| `room.self.keyed` | every device of a person joined its self room |
| `room.pair.keyed` | a pair room is keyed on both sides |
| `message.delivered` | a message's row and body are on the recipient's node |
| `file.held` | a file written on one device is byte-identical on every other device of the person |
| `file.large` | the file is streamed (chunked), not inline |
| `file.custody_received` | the author's custody names every other device with a delivery receipt |
| `file.withdrawn` | the file was withdrawn; no device serves it |
| `roster.visible` | a contact lists the person's announced devices |
| `note.synced` | a note written on one device reads on the others |
| `session.unified` | every device names the same handler for each exchange |
| `household.formed` | a family exists with its first member |
| `household.member` | an invited person accepted and is a member |
| `guardian.bound` | a guardian bond (CC 3.4.13) stands over a child member |
| `child.member` | a child is a member of the household |
| `age.assured` | an age assurance row stands for the child |
| `community.formed` | a community exists |
| `community.member` | an invited person accepted and is a member |
| `moderator.named` | a member holds the moderator duty |
| `quorum_change.held` | a membership change is proposed and held below quorum |
| `quorum_change.applied` | the held change reached quorum and applied |
| `authority.licensing` | a licensing authority is affiliated |
| `delegation.chain` | a delegation chain of length >= 2 stands |
| `agent.bound` | an agent is hard-bound to a node |
| `steward.bonded` | the agent's steward holds a signed bond |
| `wa.present` | a Wise Authority is reachable for the agent |
| `negatives.held` | every declared negative held |
| `values.ready` | the actor's values.json is written |

### 3.1 Added in version 2

One atom per modelled state no version-1 entry exercised, named `<variable>.<state>` after its `formal/STATE_TABLE.tsv` row. Several also hold in version-1 entries, derived from steps they already take (an owner holds a key from the claim; an accord root on human seats is live; a file is admitted; a withdrawal tombstones).

| atom | plane | CC | meaning |
|---|---|---|---|
| `node.announce.announced` | node | 5.4.6 4.2.1 | node: announce = announced — entered by widening of the owner-binding to federation scope (signer: owner) |
| `root.standing.Stalled` | root | 3.2 T7 T8 | root: standing = Stalled — entered by revocation/withdraws/revoked_after leaves ≤ M active (signer: founders) |
| `root.liveness.live` | root | 3.2 T7 | root: liveness = live — entered by ≥ M+1 active human founders (signer: —) |
| `root.liveness.stalled` | root | 3.2 T7 | root: liveness = stalled — entered by ≤ M active; hard_case:community_liveness_stalled (signer: the admitting substrate) |
| `seat.identity_type.human` | root | 3.4.7.1 3.2 | seat: identity_type = human — entered by key record identity_type (a key is substrate or actor, never both) (signer: key holder) |
| `seat.identity_type.node_bearing` | root | 3.4.7.1 3.2 T8 | seat: identity_type = node_bearing — entered by identity_type ⊇ {node}; never counted as a seat (signer: key holder) |
| `root.head.stale` | root | 3.2 T4a | root: head = stale — entered by newest counted cosignature older than attach_window (signer: —) |
| `root.holder_disposition.honest` | root | 4.2.6 | accord: holder_disposition = honest — entered by — (signer: —) |
| `root.holder_disposition.censored` | root | 4.2.6 | accord: holder_disposition = censored — entered by adversary blocks the channel (signer: adversary) |
| `root.holder_disposition.lost` | root | 4.2.6 | accord: holder_disposition = lost — entered by holder unreachable for good (signer: —) |
| `root.holder_disposition.coerced` | root | 4.2.6 | accord: holder_disposition = coerced — entered by adversary controls the key (signer: adversary) |
| `key.holder.owner` | self | 3.3.6.3 | roster key: holder = owner — entered by — (signer: —) |
| `key.holder.thief` | self | 3.3.6.3 1.13.3 | roster key: holder = thief — entered by device stolen with authentication (signer: adversary) |
| `key.holder.lost` | self | 3.3.6.3 | roster key: holder = lost — entered by device lost (signer: —) |
| `key.membership.proposed_evict` | self | 3.3.6.3 | roster key: membership = proposed_evict — entered by eviction proposal (signer: roster key) |
| `key.membership.evicted` | self | 3.3.6 3.3.6.3 | roster key: membership = evicted — entered by withdraws against the occurrence row lands (signer: roster majority / silence) |
| `self.roster_size.one` | self | 3.3.6.3 | roster: roster_size = one — entered by genesis only; add is unilateral (signer: owner) |
| `self.roster_size.three_more` | self | 3.3.6.3 | roster: roster_size = three_or_more — entered by two paths (signer: —) |
| `key.revocation.none` | self | 2.4.1.1 | key record: revocation = none — entered by — (signer: —) |
| `key.revocation.revoked_after` | self | 2.4.1.1 | key record: revocation = revoked_after — entered by key:revocation:v1 with revoked_after (signer: revoking key) |
| `key.revocation.revoked_all` | self | 2.4.1.1 | key record: revocation = revoked_all — entered by key:revocation:v1 without bound (signer: revoking key) |
| `member.stage.proposed` | membership | 3.1.3.2 | key×group: stage = proposed — entered by membership:proposal (expires_at ≤ 30 d) (signer: inviter) |
| `member.stage.accepted_awaiting_group` | membership | 3.1.3.2 | key×group: stage = accepted_awaiting_group — entered by membership:acceptance by the invitee (signer: invitee) |
| `member.stage.declined` | membership | 3.1.3.2 | key×group: stage = declined — entered by membership:decline (terminal) (signer: invitee) |
| `member.stage.removed` | membership | 3.1.3.2 | key×group: stage = removed — entered by membership:removal cosigned (signer: cosigned group) |
| `member.stage.resigned` | membership | 3.1.3.2 | key×group: stage = resigned — entered by membership:resignation (signer: leaving member) |
| `group.moderator.lapsed` | membership | 4.5.4 4.5.13 | group: moderator = lapsed — entered by withdraws or inactivity (signer: group / substrate) |
| `group.moderator.merit_promoted` | membership | 4.5.4 4.5.13 | group: moderator = merit_promoted — entered by most trusted member promoted in the same step (signer: group / substrate) |
| `group.moderator.fail_secure` | membership | 4.5.4 4.5.13 | group: moderator = fail_secure — entered by no moderator: the community does not federate (signer: group / substrate) |
| `group.federating.no` | membership | 4.5.4 | group: federating = no — entered by fail-secure or restricted by root (signer: root / substrate) |
| `consent.state.granted` | consent | 3.3.1 | subject×scope: state = granted — entered by consent:state:granted (signer: subject) |
| `consent.state.revoked` | consent | 3.3.1 | subject×scope: state = revoked — entered by consent:state:revoked (overrides) (signer: subject) |
| `consent.state.expired` | consent | 3.3.1 | subject×scope: state = expired — entered by consent:state:expired (signer: persist) |
| `consent.decay.identity_severed` | consent | 3.3.1 | agent memory: decay = identity_severed — entered by consent:decay:identity_severed self-report (signer: agent consent module) |
| `consent.decay.patterns_anonymized` | consent | 3.3.1 | agent memory: decay = patterns_anonymized — entered by consent:decay:patterns_anonymized self-report (signer: agent consent module) |
| `consent.decay.complete` | consent | 3.3.1 | agent memory: decay = complete — entered by consent:decay:complete self-report (signer: agent consent module) |
| `consent.community_trust.granted` | consent | 3.3.1 | node×community: community_trust = granted — entered by owner- or node-authored grant (#179) (signer: owner or node) |
| `consent.community_trust.bounded` | consent | 3.3.1 | node×community: community_trust = bounded — entered by a revocation is a boundary; capture resumes on a fresh grant (signer: any withdraws signer) |
| `consent.replication.none` | consent | 3.3.7 | node×peer node: replication = none — entered by — (signer: —) |
| `row.standing.admitted` | content | 2.1 2.6.1.7 | row: standing = admitted — entered by admission gates pass (signer: producer) |
| `row.standing.tombstoned` | content | 4.5.3 3.3.2 | row: standing = tombstoned — entered by cosigned takedown_notice; tombstone by digest (signer: trust-root quorum) |
| `blob.custody.purged` | content | 4.5.3 | blob: custody = purged — entered by bytes-plane tombstone; withheld at every byte door (signer: holder / author / quorum) |
| `row.scope.family` | content | 2.3.3 5.2 | row: scope = family — entered by the producer's cohort_scope (mirrored in the signed row) (signer: producer) |
| `row.scope.community` | content | 2.3.3 5.2 | row: scope = community — entered by the producer's cohort_scope (mirrored in the signed row) (signer: producer) |
| `delegation.link.withdrawn` | authority | 4.4.3.4.3 | delegation link: link = withdrawn — entered by withdraws by the principal; cascade (signer: principal) |
| `delegation.link.expired` | authority | 4.4.3.2.8 | delegation link: link = expired — entered by delegation_valid_until passed (a withdrawal) (signer: principal) |
| `grant.state.held` | authority | 3.3.2 | grant: state = held — entered by key_grant:{axis}:v1 one row per recipient (signer: owner / steward) |
| `guardian.bond.none` | authority | 3.4.13 | guardian: bond = none — entered by — (signer: —) |
| `agent.bond.unbound` | agent | 1.13.2 7.5 | agent: bond = unbound — entered by no live steward bond: the key cannot operate (signer: —) |
| `agent.bond.lapsed` | agent | 1.13.2 | agent: bond = lapsed — entered by bond not renewed; the key stops (signer: —) |
| `agent.retirement.decided` | agent | 7.5.5 | agent: retirement = decided — entered by retirement:decided row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.retirement.frozen` | agent | 7.5.5 | agent: retirement = frozen — entered by retirement:frozen row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.retirement.secrets_destroyed` | agent | 7.5.5 | agent: retirement = secrets_destroyed — entered by retirement:secrets_destroyed row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.retirement.handed_over` | agent | 7.5.5 | agent: retirement = handed_over — entered by retirement:handed_over row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.retirement.notified` | agent | 7.5.5 | agent: retirement = notified — entered by retirement:notified row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.retirement.custodian_minted` | agent | 7.5.5 | agent: retirement = custodian_minted — entered by retirement:custodian_minted row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.retirement.retired` | agent | 7.5.5 | agent: retirement = retired — entered by retirement:retired row (agent self-emits to retired; custodian after) (signer: agent / custodian) |
| `agent.halt_gate.acting` | agent | 4.2.1.1 1.13.6 | agent: halt_gate = acting — entered by no latched halt read by the act gate (signer: —) |


### 3.2 Added in version 3

| atom | plane | CC | meaning |
|---|---|---|---|
| `key.membership.proposed_add` | self | 3.3.6.3 | roster key: membership = proposed_add — entered by an addition proposal from a roster of two or more keys (signer: a live roster key); ends when the addition lands (quorum, or after W_self: the key on the roster, `device.join_approved` on the new device) or the proposal is withdrawn or refused; distinct from `device.join_requested`, which holds before the owner's approval |

## 4. Change control

The catalogue is closed: `evaluate` fails on an entry outside T0–T19 and on any
missing entry. Any of these is a catalogue VERSION bump:

- a new entry;
- a new atom;
- a change to what an existing atom means;
- a change to an entry's `promises`.

A bump needs the steward's ruling on CIRISClient#179 (or its successor) and CC's
review of any root-layer change (CIRISConstitution#131). A new atom, or a change to an
atom's meaning, is a CIRISConstitution PR to `manifests/topology_vocabulary.json` FIRST;
the server then moves the pin. A card pins the version it
was written against, and the model refuses a version it does not implement.

Changes that need no bump:

- what the builder can build (a refusal lifted, a relation built);
- a different node layout that keeps every promise.

The model re-verifies the promises on every change.

## 5. What the builder refuses, by name

`topology.REFUSED_RELATIONS` and `MAX_CANONICALS` are the builder's own statements.
The model reads them; it does not copy them. An entry is built up to its first
refused step. Every test whose states hold before that step still runs, and the
rest are reported `NOT_RUN` with the reason.

| refused | why | the route issue it waits on |
|---|---|---|
| `guardian_bond` (T4) | no route writes the CC 3.4.13 bond; family roles are free words | CSD-119 |
| `age_assurance` (T4) | the route is authorized by the x-ciris-* hybrid request signature; the harness has no signer | a harness hybrid signer |
| `authority` (T6) | a licensing authority affiliation has no route | CSD-120–126 (Registry fold) |
| `delegation` (T6) | `POST /v1/auth/device/delegate` writes owner→actor only; a chain needs the delegate's own act | CC 4.4.3.2.8 |
| `agent`, `steward`, `wise_authority` (T7) | the agent layer is a CIRISAgent process | CSD-111–117 (CIRISAgent) |
| `consent_decay` (T14), `agent_bond`, `agent_act`, `retirement` (T16) | the agent's own ladders: a CIRISAgent process | CIRISAgent |
| `seat_node_bearing` (T13) | needs a successor family head; one family per mesh | harness: per-node root env |
| a second canonical (T9) | one root per mesh: `mint_accord_root` rewrites the mesh's base env | harness: per-node root env |

Version 2 adds two more of the builder's statements, read by the model the same way:

**`topology.AWAITING_ROUTE`**: the PRODUCT has no route yet, so each entry is listed with its open issue.
Every step of such a relation must be marked `known_red: <the same issue>`, and `evaluate`
fails on a mismatch. A plan then reports which states wait on which issue, and the
coverage report agrees.

| relation | open issue |
|---|---|
| `evict_propose` | CIRISServer#794 |
| `evict_cosign` | CIRISServer#794 |
| `evict_lone` | CIRISServer#794 |
| `moderator_lapse` | CIRISServer#795 |
| `merit_promote` | CIRISServer#795 |
| `invite_window` | CIRISServer#796 |
| `consent_grant` | CIRISServer#182 |
| `consent_revoke` | CIRISServer#182 |
| `consent_expire` | CIRISServer#182 |
| `community_trust` | CIRISServer#790 |
| `community_trust_bound` | CIRISServer#790 |
| `lineage_head` | CIRISServer#693 |
| `purge` | CIRISServer#756 |
| `delegation_withdraw` | CIRISServer#751 |
| `delegation_expire` | CIRISServer#751 |

**`topology.PENDING_BUILDER`**: the route EXISTS and the harness branch is not written yet.
This is harness work, not a product defect, so it carries no `known_red`.

| relation | the route a branch will drive |
|---|---|
| `resign` | POST /v1/accord/family/supersede + /cosign (a founder leaves the seated roster); the witness is persist's hard_case:community_liveness_stalled row, not /v1/trust-root's posture string |
| `confer` | POST /v1/accord/family/supersede + /cosign (a conferred human widens the roster: T7 recovery) |
| `holder` | the T8 accord machinery: honest signs, lost never signs, coerced signs an invocation the standing rule refuses, censored signs but its rows are withheld past the window |
| `deadmit` | POST /v1/admin/deadmit (preview/commit; `after` = revoked_after, omitted = revoked_all) |
| `invite` | POST /v1/communities/{id}/invites (a proposal, not yet accepted) |
| `accept` | the invitee's acceptance while the group's quorum is pending |
| `decline` | POST /v1/self/invites/{proposal_id}/decline |
| `remove` | DELETE /v1/communities/{id}/members/{key_id} |
| `leave` | POST /v1/communities/{id}/leave |
| `fail_secure` | POST /v1/safety/moderation with no resolving moderator chain (absence never admits) |
| `scoped_file` | POST /v1/files to a family or community cohort (src/drive.rs) |
| `key_grant` | persist emits key_grant:content:v1 per recipient on a sealed share; no read witnesses it yet |

## 6. The planner and the runner

```
python -m harness.native evaluate [--json]                      # the model; no binary
python -m harness.native plan [--csd CSD-091,CSD-129]           # the choice; no binary
python -m harness.native run --binary <test-anchor ciris-server> [--csd …] [--at-state-cmd '…']
python -m harness.native build --topology T3 --binary …         # one entry, by id
```

### 6.1 Selection

Each requirement is the atom set one test needs at once. For each buildable prefix
of each entry, the model computes the earliest step at which that set holds. The
planner then picks the set of entries that covers every coverable requirement:

- fewest builds first;
- among those, least cost (`10 × nodes + steps`).

The search is exact: the catalogue is closed, so every subset is tried. A test is
assigned to the cheapest chosen entry that reaches it (its hinted entry if chosen),
at that entry's earliest such step. The catalogue is never extended to fit a
requirement; a requirement no entry reaches is `uncovered` and the plan says why:

- the atoms are outside the vocabulary;
- they never hold together;
- they hold only past a step the builder refuses.

### 6.2 Checkpoints

`topology.build(…, checkpoint, stop_before)` calls `checkpoint(step_id, ctx)` after
every step, using the step ids `model.steps` names:

- `canonical:<id>`, `nodes`, `person:<id>`, `announced`, `canonical_peered`;
- `rel[i]:<kind>`, `neg[i]:<check>`, `negatives`, `actor`.

The builder compares each finished step with the model's trace. A mismatch is
`builder/model drift` and fails the build: a checkpoint would otherwise test the
wrong state.

At each checkpoint the runner does three things:

1. **Checks the model against the nodes.** Each atom with a WITNESS (a live read
   that decides it: `node.unclaimed` from `/v1/setup/status`, `root.halted` from
   `/v1/accord/halt-status`, `device.join_*` from `/v1/setup/add-device`) must be
   present exactly when the model says so. A disagreement is `MODEL_DRIFT`, a
   fault of the model, not of the card.
2. **Writes `checkpoints/<step>.json`**: the entry, the step, the atoms, the
   values so far and every node's URL, token and keys. This is the fixture a client
   flow drives at THAT state.
3. **Runs the tests scheduled there**: the declared probe (one HTTP read on the
   actor's node or on the node named by `node:`, never `on:`, which YAML reads as `true`), then `--at-state-cmd`, with
   `CSD`, `TEST`, `STEP`, `ENTRY` and `VALUES` in its environment and substituted
   as `${…}`.

A failed test is recorded and the build goes on. A failed build step ends that
entry and names its layer. The run writes `csd4_report.json`: per entry its verdict,
the steps built and where it stopped; per test its verdict, step, atoms, probe and
command output; and the tests not run, with the reason.

## 7. The model's checks (`evaluate`, `harness/native/test_model.py`)

`evaluate` fails on a contradiction:

- an entry missing, or outside the closed catalogue;
- a file name that disagrees with its `catalog_id`;
- an entry unrealizable under `FSD/TOPOLOGY.md` §3;
- a relation outside the typing;
- a promised atom that the entry's steps never reach, or that is outside the
  vocabulary;
- a vocabulary atom that no entry reaches;
- a requirement that names an unknown entry, or an entry that never reaches its
  atoms;
- a requirement no entry reaches.

What the builder cannot build yet is reported per entry (`buildable_steps`,
`refused_by`), not failed.

The unit tests also hold:

- every relation in the typing is either built (read from the builder's source) or
  refused by name;
- each test is scheduled at the earliest step where its atoms hold;
- every atom appears in this document's §3.

CI runs both on every PR (`ci.yml`, the Python step); they need no binary.
