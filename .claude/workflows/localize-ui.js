export const meta = {
  name: "localize-ui",
  description:
    "Fan out UI-string translation to all 28 non-English languages of the vendored KMP client. Computes per-language missing/empty keys against en.json (source of truth), translates only those keys (idempotent), and writes the merged results into both byte-identical localization dirs. Parameterizable via args: { languages?: string[], keys?: string[] }.",
  phases: ["scan", "translate", "verify"],
};

// ---------------------------------------------------------------------------
// Static config. These paths are relative to the repo root (the cwd of any
// agent we spawn). en.json is the source of truth; the two dirs below must
// stay byte-identical (shared/ is canonical).
// ---------------------------------------------------------------------------
const SHARED_DIR =
  "client/shared/src/desktopMain/resources/localization";
const DESKTOP_DIR =
  "client/desktopApp/src/main/resources/localization";
const VALIDATOR = "client/tools/check_localization_sync.py";

// 28 non-English languages (code -> name / native name). Source: manifest.json.
const LANGUAGES = {
  am: "Amharic (አማርኛ)",
  ar: "Arabic (العربية)",
  bn: "Bengali (বাংলা)",
  de: "German (Deutsch)",
  es: "Spanish (Español)",
  fa: "Persian (فارسی)",
  fr: "French (Français)",
  ha: "Hausa (Hausa)",
  hi: "Hindi (हिन्दी)",
  id: "Indonesian (Bahasa Indonesia)",
  it: "Italian (Italiano)",
  ja: "Japanese (日本語)",
  ko: "Korean (한국어)",
  mr: "Marathi (मराठी)",
  my: "Burmese (မြန်မာ)",
  pa: "Punjabi (ਪੰਜਾਬੀ)",
  pt: "Portuguese (Português)",
  ru: "Russian (Русский)",
  sw: "Swahili (Kiswahili)",
  ta: "Tamil (தமிழ்)",
  te: "Telugu (తెలుగు)",
  th: "Thai (ไทย)",
  tr: "Turkish (Türkçe)",
  uk: "Ukrainian (Українська)",
  ur: "Urdu (اردو)",
  vi: "Vietnamese (Tiếng Việt)",
  yo: "Yoruba (Yorùbá)",
  zh: "Chinese Simplified (中文)",
};

// Brand / proper nouns that must NEVER be translated.
const DO_NOT_TRANSLATE = [
  "CIRIS",
  "CIRISVerify",
  "YubiKey",
  "TPM",
  "Fed ID",
  "Secure Enclave",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function pickLanguages(a) {
  const requested =
    a && Array.isArray(a.languages) && a.languages.length ? a.languages : null;
  const all = Object.keys(LANGUAGES);
  if (!requested) return all;
  // Keep only known, non-English codes; preserve manifest order.
  return all.filter((code) => requested.includes(code));
}

function keyFilterClause(a) {
  if (a && Array.isArray(a.keys) && a.keys.length) {
    return (
      "ONLY consider these specific keys (ignore all others): " +
      JSON.stringify(a.keys) +
      ". Of those, still only include the ones that are missing or empty in this language file."
    );
  }
  return "Consider ALL keys present in en.json.";
}

// ---------------------------------------------------------------------------
// Workflow body
// ---------------------------------------------------------------------------
const a = typeof args !== "undefined" ? args : undefined;
const targetLangs = pickLanguages(a);
const keyClause = keyFilterClause(a);

log(
  `localize-ui: ${targetLangs.length} target language(s): ${targetLangs.join(", ")}`
);

// --- Phase 1: scan -------------------------------------------------------
phase("scan");

const scanSchema = {
  type: "object",
  properties: {
    languages: {
      type: "object",
      description:
        "Map of language code -> array of {key, english_value} that are missing or empty in that language.",
      additionalProperties: {
        type: "array",
        items: {
          type: "object",
          properties: {
            key: { type: "string" },
            english_value: { type: "string" },
          },
          required: ["key", "english_value"],
          additionalProperties: false,
        },
      },
    },
  },
  required: ["languages"],
  additionalProperties: false,
};

const scan = await agent(
  `You are scanning the CIRIS vendored client localization bundles to find untranslated UI strings.

The source of truth is the canonical file: ${SHARED_DIR}/en.json
Treat the shared/ dir as canonical (the ${DESKTOP_DIR} copy must mirror it).

Steps:
1. Read ${SHARED_DIR}/en.json and flatten it to dotted leaf keys (e.g. "mobile.setup_2fa_title"). IGNORE the top-level "_meta" object entirely. Each leaf is a string value.
2. For EACH of these language codes: ${JSON.stringify(targetLangs)}
   - Read ${SHARED_DIR}/<code>.json (flatten the same way, ignoring "_meta").
   - Compute the set of keys that are present in en.json but MISSING in that language file, OR present but whose value is an empty/whitespace-only string.
   - ${keyClause}
   - Record, for each such key, the key and its english_value (the en.json string).
3. Return a JSON object mapping each language code to its array of {key, english_value}. Include a language code even if its array is empty (so the caller knows it was scanned).

Use the Read tool (and Bash with python3 if helpful for flattening/diffing). Do not write any files in this phase.`,
  { label: "scan-missing-keys", phase: "scan", schema: scanSchema }
);

const missingByLang = (scan && scan.languages) || {};
const langsToDo = targetLangs.filter(
  (code) =>
    Array.isArray(missingByLang[code]) && missingByLang[code].length > 0
);

log(
  `scan complete: ${langsToDo.length} language(s) need translation` +
    (langsToDo.length ? ` (${langsToDo.join(", ")})` : "")
);

if (langsToDo.length === 0) {
  phase("verify");
  const verifyClean = await agent(
    `All target languages are already at key parity. Run the localization validator and report the result verbatim:\n\n  python3 ${VALIDATOR}\n\nUse Bash. Report the exit code and the final summary lines.`,
    { label: "verify-noop", phase: "verify" }
  );
  log("Nothing to translate. Validator output:\n" + verifyClean);
  return;
}

// --- Phase 2: translate (fan out, one agent per language) ----------------
phase("translate");

const transSchema = {
  type: "object",
  properties: {
    translations: {
      type: "object",
      description:
        "Map of dotted key -> translated string. Keys must exactly match the requested keys.",
      additionalProperties: { type: "string" },
    },
  },
  required: ["translations"],
  additionalProperties: false,
};

const translated = await parallel(
  langsToDo.map((code) => async () => {
    const name = LANGUAGES[code];
    const pairs = missingByLang[code];
    const result = await agent(
      `Translate the following CIRIS client UI strings from English into ${name} (language code "${code}").

Rules:
- Produce faithful, natural, app-appropriate UI translations (these are buttons, labels, titles, hints, descriptions in a setup/identity wizard).
- PRESERVE every placeholder EXACTLY as written: \${...}, {0}, {1}, %s, %1$s, and any HTML/markdown.
- PRESERVE leading/trailing punctuation and casing intent.
- DO NOT translate these brand / proper terms (keep verbatim): ${DO_NOT_TRANSLATE.join(", ")}.
- Return one translation per input key; the output keys must match the input keys exactly.

Here are the {key, english_value} pairs to translate (JSON):
${JSON.stringify(pairs, null, 2)}

Return a JSON object: { "translations": { "<key>": "<translated value>", ... } }.`,
      { label: `translate-${code}`, phase: "translate", schema: transSchema }
    );
    const translations = (result && result.translations) || {};
    return { code, translations };
  })
);

// --- Phase 3 (still translate phase): write into both dirs ----------------
// One writer agent per language so file IO is done by agents, not the script.
const written = await parallel(
  translated.map((entry) => async () => {
    if (!entry) return null;
    const { code, translations } = entry;
    if (!translations || Object.keys(translations).length === 0) return null;
    const payload = JSON.stringify(translations);
    const res = await agent(
      `Merge translated UI strings into the CIRIS client localization bundles for language "${code}".

You are given a flat JSON map of dotted-key -> translated value:
${payload}

Do this with a single Python script run via Bash (python3) so it is exact and atomic:
1. Load ${SHARED_DIR}/${code}.json preserving its existing structure and key ordering. Use json.load with an ordered dict (the default dict preserves insertion order in py3.7+).
2. For each dotted key in the payload, set the nested value, CREATING intermediate dicts as needed, but DO NOT remove or reorder existing keys. New keys should be appended within their parent object. Never touch the "_meta" object.
3. Only overwrite a key if it was missing or its current value is an empty/whitespace string (idempotent — do not clobber existing human translations).
4. Write the result back to ${SHARED_DIR}/${code}.json as UTF-8, ensure_ascii=False, indent=2, with a trailing newline, matching the file's existing formatting style.
5. Copy the SAME resulting file to ${DESKTOP_DIR}/${code}.json so the two dirs are byte-identical (e.g. read the bytes you just wrote and write them to the desktopApp path).
6. Verify both files parse as JSON and report how many keys you set.

Report the number of keys written and confirm both files are byte-identical.`,
      { label: `write-${code}`, phase: "translate" }
    );
    return { code, summary: res };
  })
);

const doneCodes = written.filter(Boolean).map((w) => w.code);
log(`translate+write complete for: ${doneCodes.join(", ")}`);

// --- Phase 4: verify ------------------------------------------------------
phase("verify");

const verify = await agent(
  `Run the CIRIS client localization validator and report the result.

  python3 ${VALIDATOR}

Use Bash. Then:
- Report the exit code.
- Quote the ERROR section (mirror parity / JSON validity / reference coverage) verbatim — these MUST be clean.
- List any languages still reported under WARNINGS (translation drift) with their missing counts.
- Conclude with a one-line summary: which of these languages still have missing keys: ${JSON.stringify(doneCodes)}.`,
  { label: "verify-final", phase: "verify" }
);

log("Final validator report:\n" + verify);
return verify;
