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

## Coverage

**98 / 111** claims tagged `impl:CIRISServer#155` resolve to a grep-verified symbol at
the pinned versions. The remaining **13** carry no substrate `impl` symbol — they are
feedback to the Constitution (below), not gaps in this manifest.

## Open findings → recommended Constitution retags

These 13 claims are tagged `impl:CIRISServer#155` but have no reference-implementation
symbol in the four pinned substrate repos. Most are **`normative-only`** (a self-contained
rule / documentation / conformance-language section — no runtime artifact is *expected*);
a few are genuine, already-tracked **`open`** gaps; two belong to the **CIRISAgent** consumer
tier, not the substrate.

| decimal | claim | recommended tag | why |
|---|---|---|---|
| 2.2 | CLM-conformance | `normative-only` | conformance levels — definitional |
| 2.6.1.4 | CLM-worked | `normative-only` | worked-attack illustration |
| 2.6.4 | CLM-policy-versioning | `normative-only` | versioning policy (doc) |
| 2.6.5 | CLM-references | `normative-only` | normative references (doc) |
| 2.6.9 | CLM-conformance-language | `normative-only` | MUST/SHOULD language |
| 4.4 | CLM-composition-policies | `normative-only` | composition-policy preamble |
| 4.5.2.2 | CLM-compliance-vertical | `normative-only` | explicitly informational |
| 4.5.10.4 | CLM-documents-what-2 | `normative-only` | meta "what this documents" |
| 4.4.1 | CLM-frickerian | `impl:CIRISAgent#911` | consumer-policy norm (lives in the consumer) |
| 4.5.8.3 | CLM-settled | `impl:CIRISAgent#911` | "settled in CIRISAgent, carried as-is" |
| 3.4.9 | CLM-co-stewarded | `open` | `licensure:*` co-stewarded — not admission-gated (consumer-composition) |
| 4.1.4 | CLM-withdraws-arbitrage | `open` | the arbitrage countermeasure is consumer-policy, un-implemented |
| 4.2.2.1 | CLM-hardware-class-hardware | `open` | hardware-class self-assertion gap — already CC 8.3.1 R5 |

**Partial note (4.2.6, CLM-accord-livequorum):** resolved here to the live-quorum roster
enforcer (`verify_membership_change_by_live_quorum`), but the specific *"post-W contest on
append-log evidence + mandatory restore"* refinement has no symbol yet — tracked by
CIRISServer#122 (FSD-004 live-quorum Phase 3).
