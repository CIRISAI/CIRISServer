# Pre-commit hooks — operator runbook

Lens-core sets the pre-commit pattern for the CIRIS family — neither
persist, edge, nor CIRISConformance ships a `.pre-commit-config.yaml`
yet. This doc covers what the hooks gate, how to install, and how to
debug a hook firing.

## TL;DR — install

```sh
# Once per workstation (Python tool):
pip install pre-commit

# Once per clone:
pre-commit install
# (registers .git/hooks/pre-commit pointing at this config)

# Run against the whole tree (useful right after install):
pre-commit run --all-files
```

After `pre-commit install`, every `git commit` runs the fast tier
locally before the commit lands. Failures abort the commit; you fix
+ re-stage + re-commit.

## What the hooks gate

Five fast Rust gates + four file-shape sanity hooks. All cheap;
total ~10–15 s warm:

| Hook | What it catches | When it fires |
|---|---|---|
| `cargo fmt --check` | rustfmt drift | every `.rs` change |
| `cargo check --no-default-features` | rlib-path build break | every `.rs` change |
| `cargo check --features python` | cohabitation-feature-graph drift (pyo3 + edge/pyo3 + persist/pyo3) | every `.rs` change |
| `cargo bench --no-run` | bench-fixture API drift (BatchEnvelope-schema shift etc.) | every `.rs` change |
| `trailing-whitespace` | the obvious | every text file |
| `end-of-file-fixer` | missing trailing newline | every text file |
| `check-yaml` | yaml syntax | `.yml` / `.yaml` |
| `check-toml` | toml syntax | `.toml` |
| `check-merge-conflict` | `<<<<<<<` markers in commit | every file |
| `check-added-large-files` | accidental binary commit (>512 KB) | every file |

## What the hooks deliberately DON'T gate

The slow tier stays in CI, where the cache amortizes the cost:

- **`cargo clippy --all-targets`** — ~30s cold; CI's
  `Swatinem/rust-cache` makes it cheap there
- **`cargo test --lib`** — ~10s + actual test wallclock; CI runs it
  on every PR
- **`cargo deny check`** — network-dependent (advisory database
  fetch); CI runs it
- **`maturin build`** — wheel-shape verification belongs in CI's
  `pyo3-wheel` matrix

If you want a heavyweight local gate, use `pre-push` hooks instead
(in `.git/hooks/pre-push`) — they fire on `git push`, less often
than commit.

## Real failures the hooks would have caught

### CIRISLensCore 5c33a72 — rustfmt drift

`cargo fmt --check` fires on the multi-line `bench_with_input`
closure rustfmt prefers single-line. Hook fires at commit time;
the commit is rejected; `cargo fmt --all` fixes it; re-commit
lands clean.

### CIRISLensCore 5c33a72 — bench fixture API drift

`cargo bench --no-run` fires because the `BatchEnvelope` JSON
fixture in `benches/canonicalize.rs` no longer matches the typed
schema after persist's `BatchEvent` variant rename. Hook catches
at commit time; the commit is rejected. The bench fixture is
fixed (switched to a `serde_json::Value`-based fixture against
`canonicalize_envelope_for_signing` directly so the bench is
decoupled from typed-schema drift).

Both 5c33a72 failures cost a CI run + a follow-up commit. With
pre-commit they would have cost zero.

## Debugging a hook fire

Hook output prints to stderr. Re-run a single hook against the
staged set:

```sh
pre-commit run cargo-fmt
pre-commit run cargo-bench-no-run
```

…or against the whole tree:

```sh
pre-commit run cargo-fmt --all-files
```

To skip a single hook for one commit (last resort):

```sh
SKIP=cargo-fmt git commit
```

To skip pre-commit entirely (real last resort):

```sh
git commit --no-verify
```

`--no-verify` bypasses every hook. Don't use it routinely — the
hook exists to catch the regression class CI catches at a much
higher cost.

## Sister-repo parity

When persist / edge / CIRISConformance adopt pre-commit (proposed
as the cross-repo pattern lens-core sets here), the hook set should
be the same shape — fast Rust gates that would have caught the
specific class of regression each repo's CI has historically caught
late. The pre-commit pattern is a one-time install per workstation,
permanent per clone; the value compounds across the CIRIS family.

## References

- [pre-commit.com](https://pre-commit.com) — upstream tool
- [`.pre-commit-config.yaml`](../.pre-commit-config.yaml) — the
  source of truth for what gates fire
- [`docs/PYPI_PUBLISH.md`](PYPI_PUBLISH.md) — the per-release
  checklist (pre-commit doesn't gate releases; tag CI does)
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — the
  slow-tier gates that complement what the hooks cover
