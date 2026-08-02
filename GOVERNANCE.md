# Governance

Who decides, how a decision is recorded, and what happens to this project if the
person currently doing all of it stops.

This document exists because **CC 4.5.1 imposes a succession duty on every
principal in the mesh, and the steward is exempt from it in practice** — no
successor named, no handover documented, no dead-man behaviour anywhere.
Filed as [CIRISServer#349](https://github.com/CIRISAI/CIRISServer/issues/349),
where a cold audit ranked it above every attack in the list. The clause text
lives in [`CIRISConstitution`](https://github.com/CIRISAI/CIRISConstitution) and
is cited here, not vendored. This document discharges the duty for the **code**;
§3 covers the separate duty on the accord seats.

The house rule for this file is the same one the FSDs run on: where something is
not true yet, it says so.

---

## 1. Two offices, not one

Conflating them is the commonest error in conversations about this project, and
it produces the wrong remedy every time.

| | **the code office** | **the trust-root seats** |
|---|---|---|
| what it is | maintainership of the repos and the published artifacts | holders of the `humanity-accord` charter and its m-of-n powers |
| what it can do | merge, tag, publish a wheel, change the default pin | confer `infra:*` capability, halt a node, amend the charter |
| how it is held | GitHub org ownership, PyPI project, domain | private keys on hardware, one per seat |
| succession path | **prose only — this document** | **mechanical, in the signed record — §3** |
| if it fails | a fork continues; artifacts stop being published | the domain loses or gains legitimacy; nodes re-root |

A successor to the code office inherits **no** accord authority. A new accord
holder gains **no** ability to publish a wheel. They are seated by different
ceremonies and they fail independently. Someone who takes over the repos cannot
sign a genesis attestation, and someone who holds a seat cannot push a release.

---

## 2. The code office

### 2.1 Who decides today

One person: Eric Moore (`eric@ciris.ai`). Concretely, one person holds the
four Rust repos (`CIRISServer`, `CIRISPersist`, `CIRISEdge`, `CIRISVerify`), the
vendored KMP client, the constitution repo, the release-signing secrets, an
accord seat, the production canonical node, and the operator role on it.

That is stated as a finding, not a boast. The mesh's own claim that no single
party can kill it is **not true today**: one party runs the only canonical node,
holds the publishing rights, and is the sole author of the spec's only
implementation. Closing that gap is what this document and #349 are for.

### 2.2 How a decision is recorded

There is no minutes file and there will not be one. The record is the artefacts
the work already produces, in this order of authority:

1. **The commit message.** This project writes long-form commits that state the
   reasoning, the measurement, and the correction — including corrections to the
   author's own earlier diagnosis (see `8c09ff3`, which retracts a false alarm in
   the same message that fixes the defect). If a decision is not in a commit
   message, it is not a decision, it is a conversation.
2. **`FSD/`.** Design documents supersede one another *by name* and list the
   errors in what they replace. `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` opens by
   naming the two documents it supersedes and enumerating five corrections
   "explicitly so the next reader can check them rather than inherit them". A
   design doc that quietly replaces another is a governance failure here.
3. **`CHANGELOG.md`** for what shipped, and the `version` line in `Cargo.toml`,
   which carries the cut's whole rationale.
4. **Issues** in the relevant repo, cross-repo where the defect crosses one.
5. **`evidence/cc_impl.tsv`**, gated by `tools/check_evidence.py` in CI: which
   constitutional claims this repo actually substantiates, and — as importantly —
   which it does not. Declared gaps are code-generated (`SERVER_DECLARED_GAPS`)
   and carry `open`, because a hand-maintained gap list decays and a stale one
   reads as a considered position while describing a codebase that has moved.

Two classes of decision have a harder gate than a commit message:

- **Wire vocabulary.** A tier-1 vocabulary change is a wire break and takes the
  CC §4.5.1 amendment path. `tests/wire_vocabulary_gate.rs` fails the build
  otherwise.
- **Replication and serve policy.** The manifests are hash-pinned by gate tests
  that fail if policy moves without a deliberate cut.

### 2.3 What a successor actually needs

Ranked by what would be hardest to reconstruct if the steward became unreachable
tomorrow.

| asset | where it lives | recoverable without the steward? |
|---|---|---|
| GitHub org `CIRISAI` | one owner account | **no** — this is the single point of failure |
| PyPI project `ciris-server` | Trusted Publishing, OIDC, bound to owner `CIRISAI` / repo `CIRISServer` / workflow `publish-pypi.yml` / environment `pypi` | **yes, via org ownership** — there is no stored API token to lose |
| release artefact signatures | Sigstore keyless (`cosign sign-blob`) using the workflow's OIDC identity | **yes** — keyless, nothing to hand over |
| GHCR packages (CIRISCache layers) | org-scoped, `packages: write` from workflows | yes, via org ownership |
| build-pipeline signing keypair | repo secrets `CIRIS_BUILD_ED25519_SECRET` / `CIRIS_BUILD_MLDSA_SECRET` | **no** — write-only in GitHub; if the offline copy is lost, the pipeline identity must be re-minted and re-blessed |
| `CIRISAGENT_TOKEN` | repo secret, cross-repo client artefacts | no — re-issuable by an org owner |
| the `ciris.ai` domain | registrar account | **no** |
| the production canonical node | one host, one operator | **no** — see §5 |

The good news is narrower than it looks but real: **publishing rights already
follow org ownership rather than a person's laptop.** Trusted Publishing and
Sigstore keyless signing were chosen partly for this. An org owner can cut a
release with no secret material of the steward's at all, except the build
pipeline's own hybrid keypair.

### 2.4 Succession for the code office — the plain statement

**No successor is named today.** That is the finding, and writing this file does
not change it. What this file fixes is that the *requirements* are now written
down instead of being reconstructible only by one person.

The conditions a successor must satisfy, so that naming one is a decision about a
person rather than a design exercise:

1. **A second GitHub org owner**, with the ability to add and remove owners.
   Without this, every other item is moot.
2. **An offline copy of the build-pipeline secrets**, held by someone other than
   the steward, under whatever custody they can actually maintain. The pipeline
   key is not the trust root; losing it costs a re-mint and a re-bless, not the
   mesh.
3. **A second operator** who has stood up a node from scratch and taken it
   through claim, consent, trust-root check and a trace round, without asking
   anyone. `CONTRIBUTING.md` is the first half of that; the maintenance runbook
   (#346's Maintenance tab, #349 item 5) is the second and is **not written**.
4. **A trigger.** There is no dead-man switch, no scheduled check-in, and no
   documented signal that says "the steward has stopped". Until there is, the
   succession path is "someone notices", which is how every project in
   `FSD/PRIOR_ART.md` §13 got into trouble.

Items 1, 2 and 4 are unpaid rather than hard. Item 3 is real work.

### 2.5 Contributions and disagreement

There is no committee, so the honest description of the current process is: the
steward decides, in public, with the reasoning in the commit. A contributor who
disagrees has three escalating options, all legitimate:

1. Open an issue with the measurement. Measurements win arguments in this repo
   more reliably than arguments do — see `CONTRIBUTING.md` §2.
2. Fork. The licence is AGPL-3.0-or-later; there is nothing to negotiate.
3. Mint your own trust root and run your own mesh. See §4, and note this is not
   a threat or a consolation prize — it is the design.

---

## 3. The trust-root seats

The accord's succession is the half that **is** mechanical, and it is worth
knowing precisely, because it is what a reader will otherwise assume the code
office also has.

The production root is the keyless **family** `humanity-accord`, not a seat:
`consensus_protocol: quorum:2/3` over a three-seat roster (`src/accord.rs`), with
the charter requiring 2-of-2. One holder alone roots only to itself; a quorum
roots to the family. The roster is the *family seats*, not "every
`accord_holder` row" — a vaulted cold spare is a registered identity, not a
seat (`src/accord.rs:295`).

**Charter recovery is in the record or it does not exist.** The charter carries a
KERI-style **pre-rotation commitment** over a pre-committed successor set
(`charter_envelope`, `src/mesh_genesis.rs`), and the successor set is *the other
seated holders* — computed, never a hard-coded pair
(`src/accord_provision.rs`). A single-holder accord is refused outright:

> "a single-holder accord cannot pre-commit a recovery set — charter-key
> compromise would be unrecoverable by construction"

The reason is stated in `FSD/TRUST_ROOT_CAPABILITY_GATE.md`: a self-referential
root has no superior to appeal to, so tombstone-revocation is useless against a
compromised charter key — compromise the key and the attacker owns the
tombstoning pen.

### What is still open on the seats

- **Correlated custody.** The 2-of-3 is currently satisfiable within one
  household. `FSD/TRUST_ROOT_CAPABILITY_GATE.md` already states the rule this
  breaks — the m-of-n must be audited for holder *independence*, not signature
  count (the Ronin lesson: a 5-of-9 that was one organization). This is a people
  problem with a different solution and belongs in its own issue, per #349.
- **Dead-man successor behaviour for root-institution death** is specified as a
  requirement in `FSD/PRIOR_ART.md` §13 and is **not implemented**.
- **The halt has no severance window.** `FSD/TRUST_ROOT_CAPABILITY_GATE.md`
  states the requirement — a mandatory delay between an m-of-n halt signing and
  its landing, during which any node may sever its trust edge and exit.
  `src/accord_halt.rs` implements the latch and `exit(42)`; it implements no
  delay and no expiry. Halt is therefore the least reversible operation in the
  system (`FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §3), and recovery is O(nodes)
  manual physical acts. Until the window exists, "consensual kill switch" is
  rhetorical at the one moment it is tested.

---

## 4. What governance failure costs — and why it is bounded

This is the part a reader should take away, because it changes how much the rest
of this document matters.

**Trust roots here are pluggable and multi-polar by design.** A root is a family
of keys; a node trusts one by holding an attestation and un-trusts it by deleting
one. Schism is a routing change, not an existential fight
(`FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §2). Every federated system in that
document's death list had **one shared trust anchor** — one CA root store, one
chain state, one namespace — which is why every governance dispute in their
histories was terminal.

So: **if this project's governance fails, anyone can mint a root and continue.**

- The code is AGPL-3.0-or-later. A fork needs no permission.
- `cohort_subkind: infrastructure` is a general primitive. Anyone may stand up
  their own canonical group; `ciris-canonical` has no privileged wire status,
  only a default pin (`MISSION.md` §3.2). Every node ships trusting it and MAY
  untrust it.
- The baked genesis bundle (`canonical_seed.json`) is **public by nature** — it
  ships inside every wheel and carries only public keys, signatures, hashes and
  custody attestation certificates. Nothing about it is a secret whose loss
  strands anyone.
- The mint ceremony is in this repo (`src/mesh_genesis.rs`,
  `src/accord_provision.rs`), gated by `tests/genesis_bundle_validate.rs`, and
  it took four attempts to get right — the failures are documented so the fifth
  is cheaper for whoever runs it, including someone running it *against* us.

The precedent is Steem → Hive, catalogued in `FSD/PRIOR_ART.md` §3 as "our whole
playbook run once in production": root captured, users re-rooted cheaply, state
intact, captor's stake excluded. Forkability is the real constitution.

This bounds the cost of everything above. A failed steward, a captured accord and
an ordinary disagreement all have the same remedy, and none of them is fatal to
the model. It does **not** bound the cost of the accord's *decisive* powers
being misused while nodes are still rooted to it — that is what the severance
window in §3 is for, and it is not built.

One thing exit does not fix, stated so it is not over-claimed: **authority is
per-mesh; delivery is not.** A purge, a de-admission or a halt is an append on a
pull-only plane. A holder that is offline, forked or joins later never receives
it. "We emitted it" is not "it happened", and cannot be evidenced as such.

---

## 5. The operator role

Running the production canonical node is currently knowledge that exists in
conversation. `#346`'s Maintenance tab needs an operator; there is no runbook for
one. This is the precondition for every adoption item and it is not written.

Until it is, treat the following as the honest state: **there is one node
operator, and node operations do not survive them.** The mesh survives — every
other node is independent, and a new canonical can be blessed by the accord —
but *this* node's continuity does not.

---

## 6. What is not true yet

Collected in one place so nobody has to infer it:

- No named successor for the code office.
- No second GitHub org owner.
- No dead-man trigger, check-in cadence, or documented "the steward has stopped"
  signal.
- No off-steward custody of the build-pipeline signing secrets.
- No second node operator, and no maintenance runbook to make one.
- No severance window on the halt; no expiry; no locally-verifiable release
  token. Un-halt cannot be delivered to a halted node.
- No implemented dead-man successor behaviour for root-institution death
  (`FSD/PRIOR_ART.md` §13).
- The accord's 2-of-3 is not custody-independent.
- No consensus engine: `consensus_protocol` is a stored label
  (`CIRISServer#111`), so communities can neither vote nor reverse-quorum.

Every one of these is unpaid rather than impossible. That is the whole finding of
`FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §7: the mesh is not threatened by the
unknown, it is threatened by a backlog.

---

## 7. Amending this document

By commit, with the reasoning in the message, like everything else. If a future
version removes a line from §6, the commit must say which artefact makes it
false — a name, a path, a ceremony that happened. Deleting an admission because
it is embarrassing is the failure mode this whole file is written against.
