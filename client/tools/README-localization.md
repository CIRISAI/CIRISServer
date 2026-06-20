# Client localization

The vendored KMP client ships UI strings as per-language JSON bundles. There are
**29 languages** (`en` + 28 others) plus a `manifest.json`, kept in **two
locations that must stay byte-identical**:

- `client/shared/src/desktopMain/resources/localization/*.json` — **canonical**
- `client/desktopApp/src/main/resources/localization/*.json` — packaging mirror

The desktopApp copy has historically gone stale and shadowed the shared copy at
runtime, so the validator enforces that the two dirs are byte-for-byte identical.

`en.json` is the **source of truth**. New keys are added to `en.json` first; the
other 28 languages are then translated to match its key set. Missing translations
degrade gracefully (the runtime falls back to English), so cross-language drift is
a warning, not a hard failure.

Supported languages (read from `manifest.json`, never hardcoded):

```
am ar bn de en es fa fr ha hi id it ja ko mr my pa pt ru sw ta te th tr uk vi ur yo zh
```

## Validator

`client/tools/check_localization_sync.py` is a stdlib-only guard (no pip deps).

```bash
# From the repo root:
python3 client/tools/check_localization_sync.py            # ERRORs block; drift = warning
python3 client/tools/check_localization_sync.py --strict   # untranslated keys also block
```

It runs three ERROR-level checks (exit 1 if any fail):

1. **JSON validity** — every `*.json` in both dirs parses.
2. **Mirror parity** — the two localization dirs carry identical file sets and
   each file is byte-identical across them.
3. **Reference coverage** — every `localizedString("…")` / `getString("…")` key
   used in `client/shared/src/commonMain` Kotlin resolves in `en.json`
   (an undefined key renders raw on every platform).

…and one WARNING-level check (exit 0 by default, exit 1 under `--strict`):

4. **Cross-language parity** — each locale carries `en.json`'s full key set with
   no empty values.

CI runs the default (non-strict) invocation via
`.github/workflows/localization.yml` on every push/PR.

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
3. Merges results into **both** dir copies for each language, keeping them
   identical and valid JSON.
4. Re-runs the validator and reports any language still missing keys.
