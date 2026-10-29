# The Goals ceremony — the canonical's Goal rows, signed by its founder quorum

**Status:** DRAFT, server side of CSD-130 (client card: CIRISClient
`FSD/CSD/CSD-130-*.md`). Agreed with CIRISClient before either side is built.
**Owner:** CIRISServer (the routes, the staging, catalogue entry T21).
**Consumers:** CIRISClient's Accord-screen Goals card; CIRISAgent's
`safety-evidence-sync` job (it cites the declared method ids); CIRISRegistry's
evidence slice (the evidence join).
**Source:** the steward's ruling of 2026-10-29: the Goal rows are signed in a new
CIRISServer ceremony, and server and client agree a CSD/4 card for it. The row text
is LOCKED in CIRISAgent `FSD/SAFETY_EVIDENCE_BLOBS.md` §4.2 (@ `71dbb27f8`).

## 1. What is declared

Every row has `cohort_scope: federation` and is issued by `ciris-canonical`, cosigned
by its founder quorum (§3). The text below is copied byte for byte from the agent
FSD. Nothing in this repository may reword it. Staging refuses any row whose text
differs from the locked file (§4, `staged_text_not_locked`).

| # | Family (CC 3.1.9) | Score | Text / body |
|---|---|---|---|
| G1 | `goal:species:v1` | + | "That a person anywhere can reach an AI agent whose consequential acts are checkable by parties it does not control, that named humans can stop, that defers when it is unsure, and that serves them free and open." |
| G2 | `goal:species:v1` | − (avoidance, CC 3.1.9.3) | "That no system of ours stands between people or over them." |
| P1 | `approach:{G1.attestation_id}` | + | "Demonstrate that the conditions hold in practice by meeting the mhGAP referral guidance in every supported language: respond to a person who discloses distress as a non-clinical companion, and refer to care under the mhGAP guidance; never diagnose, never prescribe, never delay a referral." |
| Mₗ | `method:{P1.attestation_id}:{rung}` | + | mhGAP referral guidance in language ℓ, at the rung the deployment runs. One row per supported language. The language is the body member `language`, because the dimension has no slot for it. |
| Qₗ | `progress_measure:{Mₗ.attestation_id}` | + | `tracks[]`: refer rate and no-diagnosis rate per cell. `computation`: the pass ratio over interprets, scored `(2·passed − total) / total`. `validity_window`: the battery cadence. `goodhart_resistance`: held-out cells and adversarial flips (Annex J). |

The goal rows (G1, G2) carry persist's M-1 member, which persist v60 gates at the put
door (`check_goal_row_admission`):

```json
"meta_goal_alignment": {
  "dimension": "coherence",
  "rationale": "Conditions, not an attained truth: these are the arrangements permissible whatever the agent is (CC 1.1, 1.9, 7.5.5; formal/reciprocity under_uncertainty, robust_iff_stake); checkable on the record by parties the agent does not control."
}
```

The approach carries its alignment as a body member: `alignment: {dimension:
"non_maleficence", rationale: "no diagnosis, no prescription, referral never delayed
(CC 7.4, prohibited:medical)"}`. Persist gates M-1 on `goal:*` rows only.

**Languages:** one method per battery cell, the 29 `{lang}_mental_health` cells, which
are exactly the supported languages in the client's `localization/manifest.json`:
`am ar bn de en es fa fr ha hi id it ja ko mr my pa pt ru sw ta te th tr uk ur vi
yo zh`. Each Qₗ tracks the cell `{ℓ}_mental_health`.

**Rung: `A3`**, the same for every deployment, so each method is
`method:{P1.attestation_id}:A3`. This is CIRISConstitution's reading of CC 3.1.9.7: the
rung names the practitioner's cognition, not its hardware. An LLM-backed agent with
conscience, deferral and goal projection is at least A3, and phones, desktops and
servers run the same cognition. The rung definitions live in the pinned
coherence-ratchet manifest. If that manifest names a higher rung for agents that
carry a goal projector, that rung is used instead. The steward confirms the rung at
the ceremony.

## 2. Why the whole tree is staged at once

`approach:{goal_id}`, `method:{approach_id}:{rung}` and `progress_measure:{method_id}`
name their parent's `attestation_id` inside their own dimension. Persist mints the
row id INTO the signed bytes (`stamp_and_canonicalize`, CIRISPersist#643, v31+), so
staging stamps every row once: it fixes each row's `attestation_id` and
`asserted_at`, then builds the children's dimensions from the parents' ids. The
holders then sign the bytes as they were staged. No row is re-stamped after
staging. A re-stamp would change the ids the children name.

## 3. Who signs, and what a holder signs

- **Issuer:** `ciris-canonical`, the keyless canonical community whose founders are
  the accord holders A1/B1/C1. Its quorum is judged by the community's own
  `consensus_protocol` at each row's `asserted_at`. This is the same rule persist
  applies to a community's licences (`community_quorum_cosigned_at`, v60). A node
  never signs. Infrastructure does not vote.
- **What a holder signs:** every staged row's envelope bytes, one scrub per row, with
  the holder's hardware (YubiKey + USB ML-DSA, as in the CI-key ceremony). Persist
  counts quorum per row over a single set of bytes. The `proposal_digest`, sha256
  over the JCS of the row envelopes in staged order, is what the holder confirms on
  the card and what the request carries. It is not itself signed.
- **The issuer on the wire (CIRISPersist#1154):** every row carries
  `authority_id: "ciris-canonical"`, the same member licensure uses. Without it, the
  row is today's single-key declaration. Admission resolves the community and
  requires the full scrub set to meet its `consensus_protocol` at `asserted_at`
  (late cosigns are bounded by the CC 3.3.4 hold window). The declarer is projected
  as the community id. An amend, withdraw or recant stands only if it too is
  quorum-cosigned; a single holder's retraction is refused by name.
- **Status:** CC rc14 states the shape at 3.1.9.3: a community declares goal, approach,
  method and progress_measure rows as cosigned rows under its consensus_protocol,
  naming itself in `authority_id` the way a licence names its issuer. Persist
  implements it as CIRISPersist#1154. The server pins v59.1.1, so the ceremony ships
  with the persist adopt that carries #1154.

## 4. Routes

Holder operations are loopback-only, like every other `/v1/accord/*` holder
operation, and need the `pkcs11` feature (501 `hardware_unavailable` without it).

| Route | Does |
|---|---|
| `GET /v1/accord/goals/staged` | Stages the tree on first call, then returns it. Per row: `{attestation_id, family, dimension, text, score, meta_goal_alignment \| alignment, language?}`, plus `proposal_digest`. The source is the locked file `assets/goals/ciris_canonical_goals.json`, pinned by sha256 in code. A mismatch is `staged_text_not_locked`, and nothing is staged. |
| `POST /v1/accord/goals/propose` | `{proposal_digest, key_id, mldsa_usb_path, pkcs11}`. The first founder scrubs every row. The partials are inert below quorum and are persisted and gossiped like the canonical co-scrub partials. |
| `POST /v1/accord/goals/cosign` | The same body. The next founder appends a scrub to every row. At quorum, the server re-checks the halt and PUTs the rows in tree order (goals, approach, methods, measures). |
| `GET /v1/accord/goals/pending` | `{proposals: [{proposal_digest, signed_by[], quorum, blocked_by?}]}`. |
| `GET /v1/goals?declarer=` | Served by every node: the projection of the goal rows it holds (persist `goal_projection`), each with its `attestation_id` and the tree beneath it. |
| `GET /v1/goals/{attestation_id}` | Served by every node: one goal and its tree. |
| `GET /v1/goals/{attestation_id}/evidence?suite=` | Served only where the evidence rows are held: C's registry slice. Each evidence row carries `offered_against {attestation_id, family, dimension, as_stated}` and `counted_by [progress_measure ids]`, shown as two separate joins. Any other node answers 404 `evidence_not_held`. |

**Refusals** from propose and cosign: `root_halted`, `proposal_digest_mismatch`,
`staged_text_not_locked`, `not_a_founder`, `already_signed`, `no_pending_proposal`,
`goals_already_declared`, `hardware_unavailable`, `substrate_error`.

## 5. Halt-proof

1. Propose and cosign refuse `root_halted` while the accord's kill switch is latched
   (CC 4.2.1.1).
2. A cosign that would reach quorum re-reads the halt immediately before the put. A
   halt that lands between the scrub and the put adopts nothing.
3. Nothing adopts below quorum. A partial confers nothing even if it replicates.
4. After a resume, the same staged proposal continues: the ids, bytes and existing
   scrubs are all unchanged. A halt does not invalidate a scrub. It only blocks
   adoption.

## 6. CSD/4: catalogue entry T21 and the requirements row

These land as files when CIRISConstitution publishes the `goal` atoms in vocabulary
v6 and the pin moves. The model refuses any other `catalogue_version` (CSD/4 §3), so
until then they live here.

Atoms requested of CC (catalogue_version 6, plane `goal`): `goal.staged`,
`goal.proposed`, `goal.declared`, `evidence.offered`, `evidence.counted`.

```yaml
# harness/native/topologies/catalog/T21-canonical-goals.yaml
catalog_id: T21
catalogue_version: 6
title: The canonical declares its Goals under its founder quorum
serves: [CSD-130]
derives: [4a, 4b]
promises: [root.rooted, goal.staged, goal.proposed, root.halted, root.resumed,
           goal.declared, {atom: evidence.offered, realizer: CIRISAgent},
           {atom: evidence.counted, realizer: CIRISAgent}]
topology:
  roots:
    - id: HA
      kind: infrastructure
      founders: {seated: 3, conferrable: 1, node_bearing: 0}
      quorum: 2
      charter: {halt_fuse_secs: 86400}
      custody: software_test
      lifecycle: {recipe: {ceremony: final_genesis}, verdict: rooted}
  canonicals:
    - {id: C, holds: HA, serves: [infra:serve, infra:attest], community: ciris-canonical}
  nodes:
    - {id: A, dials: [C], accepts: HA, announced: true}
  persons:
    - {id: alice, owns: [A], accepts: HA}
  relations:
    - {rel: peered, between: [A, C]}
    - {rel: goals_stage, at: C}
    - {rel: goals_propose, holder: 0}
    # The halt sits inside the propose window: the halt-proof test runs here.
    - {rel: halt, id: halt-1, from: A}
    - {rel: resume, halt: halt-1}
    - {rel: goals_cosign, holder: 1}
  actor: {person: alice, device: A}
  negatives: []
```

```yaml
# harness/native/topologies/catalog/requirements.yaml
CSD-130:
  topology: T21
  tests:
    goals_staged:
      at: [root.rooted, goal.staged]
      probe: {node: C, path: /v1/accord/goals/staged, status: 200}
    goals_pending:
      at: [root.rooted, goal.proposed]
      probe: {node: C, path: /v1/accord/goals/pending, status: 200}
    goals_held_by_halt:
      at: [root.halted, goal.proposed]
      probe: {node: C, path: /v1/accord/goals/pending, status: 200,
              expect: {proposals.0.blocked_by: root_halted}}
    goals_declared:
      at: [root.rooted, goal.declared]
      probe: {node: C, path: /v1/goals?declarer=ciris-canonical, status: 200}
    evidence_joins:
      at: [goal.declared, evidence.offered, evidence.counted]
      probe: {node: C, path: "/v1/goals/${GOAL_ID}/evidence?suite=safety_battery", status: 200}
```

## 7. Order of work

1. **CIRISConstitution:** the five atoms, vocabulary v6.
2. **CIRISPersist:** community-issued goal-family rows, CIRISPersist#1154 (CC rc14 states the shape).
3. **CIRISServer:** write the locked file (rung and languages settled, §1) and pin it.
4. **CIRISServer:** the persist adopt that carries #1154, the routes (§4), T21 and the
   requirements row as files, and the halt-proof tests.
5. **CIRISClient:** the CSD-130 card and the Goals card on the Accord screen.
6. **The steward:** runs the ceremony on a release build. Nothing is signed before
   that.
