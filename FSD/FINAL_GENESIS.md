# FINAL GENESIS — the re-mint that is never repeated

**Status:** design, 2026-10-02. **Release:** server 0.5.220 on persist v53 (rev
`c9d070af`, verify v19.0.0, edge `prestage/persist-v53`). **Ruling:** the
maintainer, 2026-10-02: *"The important thing for 220/v53 is the re-genesis —
needs to be the final one, mint the full needful."* Earlier rulings this builds
on (2026-10-01): re-mint the existing root, no new keys, only signatures; all
three holders sign in one room; mint the accord and the `ciris-canonical`
community in one ceremony; no witness directory (`witness_quorum = 0`); the
signed roster record is the lineage head (B-1); v53 has no cross-version
compatibility for new acceptance edges.

**Sources:** CC `v1.0-rc6` (3c3e63f, cited `P<n>:<line>` =
`constitution/part_<n>_*.md`); persist `c9d070af` (cited `G/` =
`src/federation/genesis/`); this repo at `prestage/persist-v53`.

## 1. What "final" means

A later change is fine if it is a **quorum act on an existing anchor**; it is a
**re-mint** if it changes something only a genesis can set. The ceremony must
therefore emit every object whose content cannot be amended later, and emit it
right.

| Fixed at this genesis (getting it wrong = another re-mint) | Source |
|---|---|
| The community's `consensus_protocol` (`quorum:2/3`), `consensus_protocol_entrenched: true`, `admission_quorum_basis: founders`, `cohort_subkind: infrastructure`, `community_key_id` `ciris-canonical` | P3:684, P3:832, P3:725 |
| The community birth itself: a node holding a different birth leaves the new one alone (`HeldDiffers`); there is no re-bake over a held birth | persist G/mod.rs:3257-3302 |
| The founders' three signatures (nothing requires all three again) | P3:691 |
| The charter's successor set / pre-rotation commitment: the ONLY place spares A2/B2/C2 can ever enter; no quorum act seats a spare later | persist G/test_ceremony.rs:263, trust_root.rs:366 |
| The anchor every later head descends from (genesis lineage head(s)); see §4 A | P3:816, P3:820 |
| The anchor that pins the community; see §4 B | P5:530 |
| Every row's `trust:{job}` label; the unlabelled exception ends with this re-mint | P3:810 |

Amendable later by a 2-of-3 act, so not required now: witnesses and witnessed
mode, `attach_window_secs` and witness cadence (charter re-scrub), adding nodes
or founders, pipeline (CI) blessings, accord roster changes, scope widening
(72 h severance) (P3:820, P3:810, P3:691, P4:74, P4:229, P4:76). Halt and
`mesh_config` have nothing to mint (P4:76, P4:70).

## 2. What the ceremony emits

| # | Object | Content | Signed by |
|---|---|---|---|
| 1 | Serve-node key record(s) | `canonical,node` envelope, roles `[infra:serve, infra:attest, infra:store, infra:transport]`; byte-identical to today's canonical-1 record unless a field changes (then strictly newer `valid_from`) | accord co-scrub (A1, B1, C1) |
| 2 | Charter `genesis-charter` | `delegates_to(→ humanity-accord)`, `dimension: trust:charter:v1`, scope `[infra:attest, infra:serve, infra:store, infra:transport]`, `successor_key_ids` + pre-rotation commitment (§5 Q1), `witness_quorum: 0`, `attach_window_secs: 604800`, no `witnesses` | base scrub + co-scrubs to the family's full quorum (persist trust_root.rs:2808) |
| 3 | Grant `genesis-grant:<node>` per serve node | `dimension: trust:confers:v1` | same |
| 4 | Heartbeat `genesis-lifecycle` | `accord:lifecycle:v1` | same |
| 5 | GenesisBundle (`canonical_seed.json`) | `version 2`, `family_key_id`, `holders` (= compiled roster exactly), `serve_nodes`, `consensus_protocol quorum:2/3`, `attestations`, `authorizations` x3, `produced_at` | each holder: Ed25519 over `authorization_digest(bundle)` + ML-DSA-65 over `digest || ed_sig` |
| 6 | Community birth (`canonical_community_seed.json`) | `ciris-canonical`, infrastructure, `admission_quorum_basis: founders`, `quorum:2/3` entrenched, A1/B1/C1 `founder`, serve node(s) `member` (no acceptance; seated on the founders' quorum + the accord's scrub on its key record, P3:192) | authority + 2 cosignatures over `JCS(Community::signing_envelope())` |

Every signed instant is strictly newer than the stored rows (persist's
supersede rule, G/mod.rs:4048) and never more than 300 s ahead of a receiver's
clock (admission.rs:5204). The three delegation attestation ids are kept, so a
node supersedes in place.

Before the ceremony is called complete the server runs persist's
`verify_ceremony_outputs(bundle, community)` (G/ceremony_verify.rs:112) on the
two files and refuses to report success if it fails.

## 3. Server changes

1. **Envelope builders**: label the charter (`trust:charter:v1`, plus
   `witness_quorum: 0`, `attach_window_secs: 604800`) and the grant
   (`trust:confers:v1`).
2. **One ceremony, three holders.** `genesis/propose`, then `genesis/cosign`
   twice; complete only at three authorizations and three co-scrubs on every
   row (the family stays `quorum:2/3`). Persist has no production builder, so
   either the server builds each envelope in persist's minter order (node
   record, three rows, bundle digest, community `signing_envelope()`) or
   persist ships a production assembler (asked).
3. **Community birth** built in the same session and saved beside
   `mesh-genesis.json`; `verify_ceremony_outputs` gates completion.
4. **Acceptance writers** (all four: `accept_trust_root`,
   `accept_trust_root_as_node_key`, `accept_trust_roots_as_owner`,
   `write_node_trust_edge`) build their envelope with
   `Engine::trust_acceptance_envelope`, and re-author once at boot when the
   node holds only an unlabelled edge for the root (idempotent on "a live
   labelled edge for this root exists"; never on head advance).
5. **Un-trust** withdraws every matching edge (node, node key, owner),
   labelled or not.
6. **Import** refuses an unlabelled portable bundle by name.
7. **Posture banner** reads `AbsentReason::BakeNotAdopted{held_root_in_force}`:
   "old root in force, new bake not adopted, retried next boot", not
   NO TRUST ROOT.
8. **`GET /v1/trust-root/bundle`** served by the server: `{bundle, community,
   bundle_fingerprint, charter_root_key_id, served_by}`, no wrapper signature,
   `community: null` when not baked (registry serves the same shape).
9. **test_bless** labels its rows (single key root, no head).
10. Delete `src/quorum.rs` (dead, wrong model); reconcile the two
    `family_quorum_m` fallbacks.
11. Client: the re-mint sheet becomes 3-of-3 over two objects (ask to
    CIRISClient; CSD-067 §3, and CSD-105's "3 of 3 witnesses" corrected to
    none).

**Dry run** before the real ceremony: persist's `mint_test_ceremony` outputs
installed on the native harness (`install_test_ceremony_outputs_json`), one
node whose clock is more than 300 s behind the ceremony (refused, old root in
force, adopts at a later boot), and one real YubiKey signing the serve record:
its scrub signs the full envelope including the ML-DSA public key, the input
size that has broken a YubiKey before (persist bundle.rs:272).

## 4. Conflicts to settle before minting

**A. The lineage head.** CC rc6 still defines a `lineage_head` object
(`ciris.lineage_head.v1`) and says the genesis head of both `humanity-accord`
and `ciris-canonical` is a member of `bundle.attestations`, pinned by
`bundle_fingerprint` (P3:816, P5:534); `attached_head_digest` is defined as
the digest of such a head (P2:41). The maintainer's B-1 ruling (the signed
roster record IS the head) is recorded on CIRISConstitution#136 but not in the
text, and a later comment there calls B "still open". Persist v53 implements
B-1. If the text stands, a bundle without genesis heads leaves every later
head without an anchor. **Needs:** CC to amend the text to B-1, or persist to
emit genesis `lineage_head` objects in the bundle. Minting before one of them
lands is not final.

**B. The community anchor.** CC's bundle schema has no community row and says
names are not anchors (P5:530); persist seeds the community from a separate
compiled asset that nothing in the bundle pins. **Needs:** the bundle to pin
the birth (a digest of `canonical_community_seed.json`, or the community's
genesis head in `attestations`), so `bundle_fingerprint` covers both objects.

**C. Smaller CC ambiguities** (P3:1826 vs P3:81, who signs the grant; whether
`ciris-canonical` needs its own charter; the `authorizations` example shows
two; the stale steward backstop at P4:245). Raised with CC; none blocks the
build.

## 5. Decisions for the maintainer

1. **Successors.** Which keys does the charter commit to as successors (the
   pre-rotation commitment)? This is the only time spares can be named.
   Persist's minter uses `holders[1..]`.
2. **Canonicals named in the bundle.** Only canonical-1 has its own key.
   registry-us and registry-eu share ONE key (`75c29fcc...`, identical Ed25519
   and ML-DSA; registry's report, 2026-10-02) and must not be baked as either
   canonical. Proposal: mint with canonical-1 only; add -2/-3 later by
   canonical admission + re-bake (persist admission.rs:9751; a quorum act,
   not a re-mint) after registry re-keys each host.
3. **Pipeline (CI) keys** in the same sitting: optional and amendable later
   (P4:74); the co-scrub path is the one registry's build door accepts.

## 6. Settled (2026-10-02)

- **§4 A — B-1 is the text.** CC branch `rc7` (b578b59), T6: the head is the
  signed family/community record at a version (digest = row hash;
  `prev_head_digest` empty at genesis; `charter_digest` = the charter in force).
  The separate `ciris.lineage_head.v1` object is removed. CC 2.1
  `attached_head_digest` = the digest of the record version attached on. Every
  roster-affecting row, including a charter re-scrub, produces a new version
  (asked of persist to confirm for v53).
- **§4 B — the bundle carries the births.** T5: the bundle is the only genesis
  artifact. The `humanity-accord` family record and the `ciris-canonical`
  birth record are members of `bundle.attestations`, pinned by
  `bundle_fingerprint`. A community seeded from an asset the bundle does not
  pin has no anchor.
- **Grant signers** (CC 3.4.7): a keyless family confers as it charters —
  `delegates_to(member → subject)`, `trust:confers:v1`, scrubbed to the
  family's quorum. A1's scrub alone is no grant.
- **Three authorizations** are fine (CC's example now reads "A1, B1, ...").
- **Assembler:** persist owns it (`assemble_ceremony(partials) -> bundle`,
  builder emitting each signable item); the server calls it from Rust and
  does not copy the minter.
- **With the maintainer, not blocking a mint with witnessed mode off:**
  whether `ciris-canonical` needs its own charter; the us/eu/apac steward
  backstop in CC 4.2.6 (live quorum; entrenched).
- **Persist v53 (952f6a7a), 2026-10-02:** a charter re-scrub did NOT produce a
  new record version (gap, READ by persist); fixed in v53: the record's
  signing envelope gains `prev_head_digest` and `charter_digest`, the charter
  in force is the one the head record names, and every roster-affecting row
  needs a new version. Both genesis records go inside `bundle.attestations`;
  the boot leg reads the birth from the bundle (no separate asset). The
  assembler requires the family's quorum on the grant; persist is checking
  that admission does too.
- **Instants:** stamped once at propose from the ceremony host's clock and
  passed into persist's builder (never read inside it), so a session across
  several requests stays byte-stable; the propose route refuses to stamp on a
  host whose clock is not NTP-synced. No ceremony window at the 300 s door.
- **Canonicals (maintainer, relayed by the registry session 2026-10-02):**
  canonical-2 and canonical-3 go INTO this genesis on fresh, unique Server
  mints (`--key-id ciris-canonical-2/-3`), never the shared registry seed
  `75c29fcc...`; the server replaces the standalone registry. Each canonical:
  roles `[infra:serve, infra:attest]` (+ store/transport as the charter
  confers), a matching quorum-scrubbed `trust:confers:v1` grant, and a signed
  transport hint. The bundle's `serve_nodes` and grants become three; the
  ceremony needs all three key records before the dry run on real inputs.
  Supersedes §5 Q2's "canonical-1 only".
- **CI pipeline keys** are co-scrubbed in the same sitting (same relay).
  Supersedes §5 Q3.
- **Founders (settled):** the relay's "founders" was the registry session's
  wording, not the maintainer's ("unique keys for 2 and 3, baked in as part of
  the ceremony if we can"). Holders A1/B1/C1 are the signing founders;
  canonical-1/-2/-3 are seated as non-signing members (CC P3:670-722,
  P3:192; nodes have no agency).
- **Steward backstop removed (maintainer; CC 4.2.6 on `rc7` fe459cf,
  CIRISConstitution#139):** firing stays floor-1 over the live set; an accord
  roster change (add/remove/swap) needs `yes` from a strict majority of the
  STANDING roster within W (2 of 3 today), no steward co-sign; H7 restore and
  contest removed (`ciris.accord_contest.v1`, `ciris.accord_restore.v1`
  retired). **New genesis-fixed field:** the charter carries each holder's
  pre-committed RECOVERY-key commitment; a holder who loses a signing key
  rotates by a self-`supersedes` under that recovery key. Server: the
  `/v1/accord/*` tally applies the standing-majority threshold. Verify:
  CIRISVerify#302.
- **Open (maintainer):** which keys are the recovery keys. Proposal: the
  spares A2/B2/C2 already exist and are each holder's own second key — commit
  A2 as A1's recovery key, B2 as B1's, C2 as C1's. That also answers §5 Q1
  (successors) without minting anything new.
- **Persist slice R (plan, 2026-10-02):** charter `recovery_commitments:
  {holder_key_id: hex}`; every standing holder exactly one; no commitment for
  an off-roster key; a recovery key may not be a roster signing key. Recovery
  door: `supersedes(old holder key -> new signing key)` signed by R, no
  quorum, own seat only, emits a new roster version carrying a FRESH
  commitment for the new key; R spent after one use. Roster change = strict
  majority of the standing roster; `steward_signatures` dropped.
  **Server objection (sent to persist and CC):** the commitment must bind the
  recovery key's public material (both hybrid halves), not only its id —
  the spares are unregistered, so an id-only commitment is satisfied by
  whoever registers that id first. Ceremony input per holder is therefore
  `{key_id, ed25519, ml_dsa_65}` of the recovery key.
- **Key-binding fix (persist, READ at 952f6a7a):** the hole was also in T3 —
  `pre_rotation_commitment` hashed only sorted key_id strings and the recovery
  check tested only id membership. v53: each element is JCS `{key_id,
  pubkey_ed25519, pubkey_ml_dsa_65}`; T3 commitment = sha256 of the JCS array
  sorted by key_id; per-holder recovery commitment = same over one element;
  both doors check the presenting record's pubkeys. Awaiting CC's spelling.
- **Commitment bytes (CC `rc7` 5e89627, T3 / 4.2.6 / 2.1):** element = JCS
  `{key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64}` as stored on the
  key record; commitment = lowercase-hex SHA-256 of the JCS array sorted by
  `key_id` (UTF-8 bytes); T3 over the successor set, 4.2.6 over one element;
  charter member `recovery_commitments: {holder_key_id: commitment}` REQUIRED
  on the accord's charter; doors recompute from the presenting record's
  pubkeys. Relayed to persist.
