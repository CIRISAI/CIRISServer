# Evidence registry — the `impl:` tier (CIRISServer#155)

[`cc_impl.tsv`](cc_impl.tsv) is CIRISServer's **spec-map manifest**: it resolves the
`impl:CIRISServer#155` pointers in the Constitution's
[`claims.tsv`](../../CIRISConstitution/constitution/claims.tsv) (CIRISConstitution#17,
CC 1.0-rc2) to the concrete reference-implementation symbol that establishes each
fabric/substrate claim — in CIRISServer itself or the **pinned** substrate crates
(`ciris-persist` / `ciris-verify-core` / `ciris-keyring` / `ciris-crypto` / `ciris-edge`).

It operationalizes the four-artifact view (Constitution ↔ Spec ↔ **Implementation** ↔
Formal): a reviewer — or CI — follows a claim from the Constitution to the code that
backs it, and a moved symbol can never silently rot the pointer.

## Format

Tab-separated, one row per `(claim, symbol)`:

```
decimal_id    claim_id    repo    path#symbol    crate@version
```

- `repo` ∈ `CIRISServer | CIRISPersist | CIRISVerify | CIRISEdge`
- `path#symbol` — repo-relative file path + the load-bearing fn/struct/enum/const/mod
  (the definer/enforcer: an admission gate, a canonicalizer, a wire struct, a verdict enum)
- `crate@version` — the crate the symbol lives in, at the version this workspace pins
  (`ciris-persist@v12.5.0`, `ciris-verify-core@v8.7.0`, `ciris-edge@v8.7.2`, …)
- `repo = —`, `crate@version = open` — the claim has **no** reference-implementation
  symbol at the substrate tier (see *Open findings* below); the row is informational.

## The gate — `tools/check_evidence.py`

Run in CI (the Linux `clippy + test` job, after the build populates the cargo git
checkouts). For every non-`open` row it asserts:

1. the `path#symbol` **resolves** at the pinned crate version — in-repo for
   `CIRISServer`; in the vendored checkout for the pinned git rev otherwise
   (a dead pointer is a **build failure**, i.e. a spec-regression test);
2. the row's `crate@version` **matches** the workspace pin in `Cargo.toml` (drift fails);
3. (locally, when the sibling repo is present) every `impl:CIRISServer#155`-tagged claim
   in the Constitution's `claims.tsv` has a manifest row (coverage).

## [`cc_compliance_map.tsv`](cc_compliance_map.tsv) — the CC 4.5.2.2 vertical/statutory map

CC 4.5.2.2 `compliance-vertical` requires the vertical compliance mapping be published as a
**machine-readable** artifact; it existed as Constitution prose only. `cc_compliance_map.tsv`
is that artifact (CIRISServer#159) — a faithful, row-for-row **transcription** of the two
compliance tables:

- **CC 4.5.2.2** "Vertical compliance mapping (informational)" — regulatory framework →
  CEG wire primitive → how it composes (10 rows: GDPR ×4, HIPAA ×2, FERPA, CCPA, EU AI Act
  Art 50, CIRIS Accord M-1).
- **CC 8.8.5 Annex C** "Regulatory Cross-Walk" §2 — external framework → CIRIS Book/Annex §
  (17 rows: EU AI Act ×9, NIST AI RMF, ISO/IEC 42001 ×2, OSHA, EU HLEG, IEEE EAD, ASEAN,
  *Magnifica Humanitas*).

Columns: `cc_section, framework, provision, ceg_primitive, ciris_mapping,
implementing_evidence, composition, source_status, cc_refs, tracking_issue`.

### The chain: `statute → CIRIS document → SHIPPING SYMBOL + TEST`

Columns 1-5 and 7-9 are pure transcription — **nothing is inferred.** A mapping the
Constitution does not state is the literal token `unmapped`: Annex C names no CEG wire
primitive for any statutory row, so all 17 carry `ceg_primitive = unmapped`. Per CC 8.8.5 §3
the statutory rows are informative engineering correspondences, **not** legal opinions; a row
graduates to "verified" only on qualified legal review, which this repo does not perform.

A Book/Annex reference is a pointer to *prose*, not evidence. **`implementing_evidence` is the
tier that makes a compliance claim defensible** — the concrete shipping artifact (`Repo:path#symbol`
and/or the test that proves it) that actually discharges the obligation. It is the one column
NOT from the Constitution; every token was established by **reading the code**, never inferred
from a filename. `partial:` prefixes a cell whose artifact discharges only part of the
obligation. `unmapped` means **no enforcer ships** — these holes are the point of the artifact,
not evasions.

Every gap names a `tracking_issue` (`CIRISServer#N`, or `CIRISAgent:compliance` for rows Annex C
itself assigns to the agent's cross-walk + the Covenant Books). `untracked` explicitly flags a
gap that still needs an issue filed — an honest gap with a tracker is defensible; a blank is not.

**Standing: 6 rows fully evidenced, 2 partial, 19 unmapped.** The canonical hole is **EU AI Act
Art 14** (human oversight — intervene/interrupt/stop): `oversight_mode` is a wire field with **no
enforcer in any shipping artifact** (CIRISServer#115, re-proven by grep). A dedicated test pins
that hole open.

Loaded by [`src/compliance.rs`](../src/compliance.rs) (`ComplianceMap`, baked in with
`include_str!`); gated by [`tests/compliance_map.rs`](../tests/compliance_map.rs), which asserts
well-formedness, completeness against the source row/framework counts (a dropped **or invented**
row fails), the honesty invariants above, that **every cited `implementing_evidence` path exists
on disk and contains the cited symbol** (a citation can neither rot nor be invented), that Art 14
stays unmapped, that every gap is tracked, and that no `cc_impl.tsv` claim the map leans on has
regressed to `open`.

## Coverage

**99 / 111** claims tagged `impl:CIRISServer#155` resolve to a grep-verified symbol at
the pinned versions. The remaining **12** carry no substrate `impl` symbol — they are
feedback to the Constitution (below), not gaps in this manifest.

## Open findings → close them (implement) or `normative-only`

These 12 claims are tagged `impl:CIRISServer#155` but have no reference-implementation
symbol yet. A claim the Constitution tags `impl:` asserts a reference implementation
*should* exist — so where one is genuinely possible, the disposition is **implement it**
(tracked below), not retag it away. Only claims with no realizable runtime artifact (a
bibliography, a MUST/SHOULD glossary) stay `normative-only`.

**Implement (tracked):**

| decimal | claim | disposition |
|---|---|---|
| 2.2 | CLM-conformance | implement — CIRISServer#159 (declared conformance level + gate) |
| 2.6.4 | CLM-policy-versioning | implement — CIRISServer#159 (version-negotiation policy) |
| 4.1.4 | CLM-withdraws-arbitrage | implement — CIRISServer#159 (arbitrage countermeasure) |
| 4.2.2.1 | CLM-hardware-class-hardware | implement — CIRISServer#159 (attest hardware_class; closes CC 8.3.1 R5) |
| 3.4.9 | CLM-co-stewarded | implement — CIRISPersist#365 (`licensure:*` co-stewarded admission) |
| 4.4.1 | CLM-frickerian | implement — CIRISAgent#911 (consumer tier) |
| 4.5.8.3 | CLM-settled | implement — CIRISAgent#911 (consumer tier) |
| 2.6.1.4 | CLM-worked | add a `test` vector — CIRISConformance#59 (the rule is impl'd via JCS) |

**Genuinely `normative-only`** (no realizable impl artifact):

| decimal | claim | why |
|---|---|---|
| 2.6.5 | CLM-references | normative references (bibliography) |
| 2.6.9 | CLM-conformance-language | MUST/SHOULD/SHALL definitions |
| 4.4 | CLM-composition-policies | policy preamble — the sub-policies A/I/J/L are already implemented |
| 4.5.10.4 | CLM-documents-what-2 | meta "what this documents" |

**Partial note (4.2.6, CLM-accord-livequorum):** resolved here to the live-quorum roster
enforcer (`verify_membership_change_by_live_quorum`), but the specific *"post-W contest on
append-log evidence + mandatory restore"* refinement has no symbol yet — tracked by
CIRISServer#122 (FSD-004 live-quorum Phase 3).
