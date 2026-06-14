# PyPI publishing — operator runbook

`ciris-lens-core` publishes to PyPI on every `refs/tags/v*` push via
OIDC trusted publishing (no long-lived API token in CI). This doc
covers the one-time setup, the per-release workflow, and the
recovery path when a release ships wrong.

---

## TL;DR — per-release checklist

1. Track CIRISConformance — current cohabitation triple matches
   [the matrix](https://github.com/CIRISAI/CIRISConformance).
2. Bump `Cargo.toml` `[package].version` + the comment block.
3. Bump `pyproject.toml` `dependencies = ["ciris-persist==X.Y.Z"]`
   to whatever the triple says.
4. Update `docs/RELEASE_NOTES.md` with the new section (newest
   first).
5. Verify local: `cargo test --lib --no-default-features` +
   `cargo test --lib --features python` + `cargo clippy
   --all-targets --features python -- -D warnings` + `cargo fmt
   --all -- --check` + `cargo deny check`. All green.
6. Commit with `release: vX.Y.Z — <one-line title>` shape.
7. `git tag -a vX.Y.Z -m "vX.Y.Z — <one-line title> …"`.
8. `git push origin main && git push origin vX.Y.Z`.
9. Watch the tag CI run; `publish-pypi` job fires once the eight
   gating jobs are green.

Total time: ~3 minutes once the triple lands; rest is CI wallclock.

---

## Why OIDC trusted publishing (no API token)

Older PyPI publish flows used long-lived API tokens uploaded as
GitHub repo secrets. Tokens leak; rotation is manual; revocation
is reactive.

PyPI's trusted publishing (PEP 740 / OIDC) replaces that:

- GitHub Actions issues a short-lived JWT identifying the workflow
  run.
- PyPI verifies the JWT against a pre-configured trust policy
  ("only allow uploads from `CIRISAI/CIRISLensCore`'s `ci.yml`
  workflow running in the `pypi` environment").
- No persistent credential stored anywhere.

Plus PEP 740 sigstore attestation — consumers can verify the wheel
ties to this exact GH workflow identity. Same pattern persist + edge
+ verify use.

---

## One-time setup (already done; documented for posterity)

1. **PyPI side** — project `ciris-lens-core` reserved by the org
   maintainer. Trusted publisher configured:
   - **Owner:** `CIRISAI`
   - **Repository:** `CIRISLensCore`
   - **Workflow filename:** `ci.yml`
   - **Environment:** `pypi`
2. **GitHub side** — `pypi` environment exists on the repo with
   `id-token: write` permission scoped to the publish-pypi job.
   No long-lived `PYPI_API_TOKEN` secret.
3. **`.github/workflows/ci.yml`** — `publish-pypi` job is gated on
   `if: startsWith(github.ref, 'refs/tags/v')` and `needs:` every
   quality job (pyo3-wheel × 3, lint, license-audit,
   linux-x86_64-test, darwin-aarch64-test). Presence of a wheel
   alone is NOT a quality gate.

---

## What `publish-pypi` does

```yaml
publish-pypi:
  name: Publish wheels to PyPI (tag-gated)
  needs: [pyo3-wheel, lint, license-audit, linux-x86_64-test, darwin-aarch64-test]
  if: startsWith(github.ref, 'refs/tags/v')
  environment:
    name: pypi
    url: https://pypi.org/project/ciris-lens-core/
  permissions:
    id-token: write
  steps:
    - uses: actions/download-artifact@v4
      with:
        pattern: ciris_lens_core-wheel-*
        merge-multiple: true
        path: dist
    - name: sanity-check wheel shapes
      run: |
        ls -la dist/
        # Reject anything that isn't cp310-abi3 — mixed-mode
        # maturin can silently emit cp31N-cp31N wheels which
        # break consumer install on other minors. Catching at
        # publish time, not after PyPI accepts.
        COUNT=$(ls dist/*.whl | wc -l)
        [ "$COUNT" -lt 3 ] && exit 1
        for wheel in dist/*.whl; do
          [[ "$wheel" =~ -cp310-abi3- ]] || exit 1
        done
    - uses: pypa/gh-action-pypi-publish@release/v1
      with:
        packages-dir: dist
        skip-existing: true       # tag re-runs idempotent
        attestations: true        # PEP 740 sigstore attestation
```

The three core wheels (linux-x86_64, linux-aarch64, darwin-aarch64)
are matrix-built by `pyo3-wheel`, uploaded as artifacts, then
downloaded + sanity-checked + published to PyPI in one shot.

A fourth Windows wheel (windows-x86_64) is built by the
`pyo3-wheel-windows` job (#43.3). It is NON-GATING: if the Windows
build fails, `publish-pypi` still runs with 3 wheels. On success,
the Windows wheel is included in the `ciris_lens_core-wheel-*`
artifact download and goes to PyPI alongside the other three — OIDC
trusted publishing is workflow-scoped so the same publisher covers
the fourth wheel without extra PyPI setup. The Windows wheel ALSO
appears on GitHub Release (see below).

---

## GitHub Release artifacts (v1.0.1 / #43.3)

As of v1.0.1, every `v*` tag CI run also produces a **GitHub Release**
via the `mobile-release` job (tag-gated, non-gating to PyPI). The
release carries:

| Asset | Contents |
|---|---|
| `ciris-lens-core-vX.Y.Z-android-wheels.tar.gz` | Chaquopy abi3 wheels: `arm64_v8a`, `x86_64`, `armeabi_v7a` (cp310-abi3-android_24_*) |
| `ciris-lens-core-vX.Y.Z-android.tar.gz` | jniLibs layout — raw `.so` per ABI, plain (no PyO3) |
| `ciris-lens-core-vX.Y.Z-ios.tar.gz` | `ios-device/ciris_lens_core.abi3.so` + `ios-simulator/ciris_lens_core.abi3.so` |
| `ciris_lens_core-X.Y.Z-cp310-abi3-win_amd64.whl` | Windows x86_64 wheel (also on PyPI when build succeeds) |
| `SHA256SUMS` | SHA-256 hashes of all of the above |

The agent team can pull mobile artifacts via:

```bash
gh release download vX.Y.Z --repo CIRISAI/CIRISLensCore \
  --pattern "ciris-lens-core-vX.Y.Z-android-wheels.tar.gz"
```

`mobile-release` is **additive + non-gating**: a failure here does
NOT block `publish-pypi`. The job depends on the build jobs
(`ios-pyo3-package`, `android-package`, `pyo3-wheel-windows`) plus
`lint` + `license-audit` as quality gates. Pattern mirrors
CIRISEdge v0.7.0+ `mobile-release` + CIRISPersist v2.0.7+
`mobile-release` exactly.

---

## Release-commit shape

Matches persist + edge sister-repo conventions. Per-release commit
title:

```
release: vX.Y.Z — <one-line title>
```

The commit body is the release notes (mirrors what lands in
`docs/RELEASE_NOTES.md`). Example from v0.2.0:

```
release: v0.2.0 — federation cohabitation + CEG §5.5 foundations

Triple bump to the current CIRISConformance matrix
(v3.14.3 / v1.1.10 / v4.8.0) + crate version bump 0.1.1 → 0.2.0.
…
```

Annotated-tag message follows the same shape:

```
git tag -a v0.2.0 -m "v0.2.0 — federation cohabitation + CEG §5.5 foundations

Tracks CIRISConformance matrix: persist v3.14.3 + edge v1.1.10 +
verify v4.8.0. …"
```

The annotated form is required — lightweight tags don't carry the
message GitHub renders on the releases page.

---

## When a release ships wrong

PyPI rejects same-version re-uploads. `skip-existing: true` makes
tag re-runs idempotent on the publish side (the workflow doesn't
fail when PyPI rejects), but the wheel that's on PyPI is the wheel
that's on PyPI — you can't `pip install --force-reinstall` your
way out.

Recovery path:

1. **Never re-tag the same version.** Sister-repo discipline.
2. **Bump patch** — fix the issue, bump `Cargo.toml` +
   `pyproject.toml` to vX.Y.(Z+1), update `docs/RELEASE_NOTES.md`
   with a short "patch: <what was wrong>" section, push commit +
   tag, let the new wheel supersede.
3. **For yanks** — if the release is dangerous (security regression,
   not just a minor bug), yank on PyPI (UI: project page → release
   page → yank). Doesn't remove the wheel; flags it so
   `pip install` skips it unless `==X.Y.Z` is explicit.

---

## Version-bump scheme (pre-1.0)

Lens-core follows semver pre-1.0 conventions:

- **major (0.X.0 → 0.(X+1).0):** new feature surface; pre-1.0
  callers may need source changes
- **minor (0.X.Y → 0.X.(Y+1)):** bug fix, CI fix, doc-only
- **breaking (0.X.* → 0.(X+1).0):** wire-contract changes, removed
  PyO3 functions, persist-pin majors

Post-1.0 will follow strict semver (CIRISLensCore#18 ships the
wire-contract freeze).

Federation-pin bumps that *don't* change lens-core's surface are
typically minor-version (v0.X.Y → v0.X.(Y+1)) — the surface is
stable, just the substrate moved. v0.2.0 is an exception because it
also adds `install_relay`.

---

## Verify a published wheel

```bash
pip install ciris-lens-core==X.Y.Z
python -c "import ciris_lens_core; print(ciris_lens_core.PROJECTION_VERSION)"
# crc-v1
```

The `PROJECTION_VERSION` module constant is a quick smoke test —
proves the wheel loaded, the rlib's compiled, the PyO3 surface is
reachable.

For provenance verification:

```bash
pip install sigstore
sigstore verify identity --bundle ciris_lens_core-X.Y.Z-*.whl.publish.attestation \
    --cert-identity https://github.com/CIRISAI/CIRISLensCore/.github/workflows/ci.yml@refs/tags/vX.Y.Z \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    ciris_lens_core-X.Y.Z-*.whl
```

The attestation ties the wheel to this exact workflow run on this
exact tag. PEP 740 / sigstore standard.

---

## References

- [PyPI project page](https://pypi.org/project/ciris-lens-core/) —
  live release history
- [Trusted publishers PyPI docs](https://docs.pypi.org/trusted-publishers/) —
  PEP 740 / OIDC flow
- [CIRISPersist `docs/PYPI_PUBLISH.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/PYPI_PUBLISH.md) —
  sister-repo runbook with the original OIDC setup writeup
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — the
  `publish-pypi` job source of truth
- [`docs/RELEASE_NOTES.md`](RELEASE_NOTES.md) — versioned release
  history
