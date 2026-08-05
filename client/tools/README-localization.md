# Client localization

The vendored KMP client ships UI strings as per-language JSON bundles. There are
**29 languages** (`en` + 28 others) plus a `manifest.json`, kept in **four
committed runtime bundles that must stay byte-identical** — one per platform
loader:

- `client/shared/src/desktopMain/resources/localization/*.json` — **canonical**
- `client/desktopApp/src/main/resources/localization/*.json` — desktop packaging
- `client/androidApp/src/main/assets/localization/*.json` — Android assets
- `client/iosApp/iosApp/localization/*.json` — iOS bundle

Each platform loader reads its own copy, so any bundle that goes stale ships raw
keys at runtime. The validator enforces that all four are byte-for-byte identical
to canonical.

`en.json` is the **source of truth**. New keys are added to `en.json` first; the
other 28 languages are then translated to match its key set. Missing translations
degrade gracefully (the runtime falls back to English), so cross-language drift is
a warning, not a hard failure.

## Keys must be NESTED, never flat-dotted

`LocalizationManager.resolveKey` always splits a key on `.` and walks nested JSON
objects. It **never** tries an exact top-level match. So this works:

```json
{ "mesh_config": { "ttl": { "expired": "…" } } }     // resolveKey("mesh_config.ttl.expired") -> "…"
```

…and this is **dead at runtime, in every language including English**:

```json
{ "mesh_config.ttl.expired": "…" }                    // resolveKey(…) -> null -> renders the raw id
```

This is not hypothetical: commit `0c728b1` added 53 server-emitted message ids in
the flat form. They were present, byte-identical across all four bundles, and
completely unreachable — and the validator was green throughout, because to a
**key-set comparison a flat key and a nested key are the same key**
(CIRISServer#366; data fixed in `26605b5`). The validator now ports
`resolveKey`'s algorithm and checks reachability, not key sets.

Supported languages (read from `manifest.json`, never hardcoded):

```
am ar bn de en es fa fr ha hi id it ja ko mr my pa pt ru sw ta te th tr uk vi ur yo zh
```

## Validator

`client/tools/check_localization_sync.py` is a stdlib-only guard (no pip deps).

```bash
# From the repo root:
python3 client/tools/check_localization_sync.py             # ERRORs block; drift = warning
python3 client/tools/check_localization_sync.py --strict    # drift also blocks
python3 client/tools/check_localization_sync.py --self-test # prove the guard can fail
```

Six ERROR-level checks (exit 1 if any fail):

1. **json-validity** — every `*.json` in all four bundles parses and is an object.
2. **bundle-mirror** — all four bundles carry identical file sets and every file
   is byte-identical to canonical.
3. **manifest-coverage** — every language the manifest lists has a file, and
   every locale file that ships is listed in the manifest.
4. **reference-coverage** — every `localizedString("…")` / `getString("…")` key
   used in `client/shared/src/commonMain` Kotlin **resolves** in `en.json` under
   `resolveKey` semantics (an unresolvable key renders raw on every platform).
5. **key-resolvability** — every key in every locale file is reachable by the
   ported `resolveKey`, i.e. no flat dotted keys. See the section above.
6. **placeholder-parity** — a translated value carries exactly the placeholders
   of its `en.json` source (`{named}`, `${…}`, `{0}`, `%s`, `%1$s`). A dropped or
   misspelled `{count}` renders literally, so this is corruption, not lag.

…and one WARNING-level check (exit 0 by default, exit 1 under `--strict`):

7. **translation-drift** — each locale carries `en.json`'s full key set, with no
   empty values and no keys `en.json` lacks.

Every check prints **what it examined**, not just what it found — `0 findings
over 86,275 addresses` is evidence; `0 findings` alone is not. A check whose
denominator is zero is reported as an error in its own right.

### The self-test is the point

`--self-test` builds a synthetic bundle in a temp dir, breaks it twenty ways —
flattening a nested key, desyncing each of the three mirrors, corrupting a named
and a printf placeholder, invalid JSON, an unlisted locale file, a zero
denominator — and asserts each check fires **with a message that names the
break**. It also asserts, in code, that flattening a nested key leaves the
flattened key set byte-for-byte identical: the proof that the old key-parity
check could not have caught #366, and the reason the resolvability check exists.

CI runs `--self-test` as a required step **before** the real check
(`.github/workflows/localization.yml`), so the gate demonstrates it can fail on
every run. A gate that has never been shown able to fail is not evidence.

## Filling missing translations — the `localize-ui` Claude workflow

Cross-language drift (warnings above) is fixed by a Claude Code workflow that
fans out one translation subagent per language.

Run it via the **Workflow** tool with name `localize-ui`
(`.claude/workflows/localize-ui.js`):

- Default (no args): translate **all** missing/empty keys in **all 28**
  non-English languages.
- Parameterizable via `args`, e.g.:
  - `{ "languages": ["de", "fr"] }` — only those languages.
  - `{ "keys": ["mobile.setup_2fa_title", "manage_nodes_upgrade_fed_id"] }` —
    only those keys (still only where missing/empty).

The workflow:

1. Scans `en.json` + each language file to compute the missing/empty keys
   (canonical `shared/` dir is authoritative).
2. Translates only the missing/empty keys per language (idempotent / re-runnable),
   preserving placeholders (`${...}`, `{0}`), punctuation, and brand terms that
   are never translated (CIRIS, CIRISVerify, YubiKey, TPM, Fed ID, Secure Enclave).
3. Merges results into the canonical bundle **as nested objects** (never flat
   dotted keys — see above), then mirrors canonical byte-for-byte into all four
   runtime bundles.
4. Re-runs the validator and reports any language still missing keys.
