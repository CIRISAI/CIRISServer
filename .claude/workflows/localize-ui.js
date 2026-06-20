export const meta = {
  name: "localize-ui",
  description:
    "Fan out UI-string translation to all 28 non-English languages of the vendored KMP client. Chunked + temp-file routed so every agent's I/O stays small (the single-huge-output shape truncated). Computes per-language missing/empty keys vs en.json, translates in chunks (preserving named {param}/printf placeholders), merges per language, then mirrors the canonical bundle byte-for-byte into all four committed runtime bundles. Args: { languages?: string[], keys?: string[], chunk?: number }.",
  phases: ["scan", "translate", "merge", "sync", "verify"],
};

// ---------------------------------------------------------------------------
// Config. Paths relative to repo root (cwd of spawned agents). en.json is the
// source of truth; SHARED_DIR is canonical; all four committed runtime bundles
// must end byte-identical (Codex review, PR #40).
// ---------------------------------------------------------------------------
const SHARED_DIR = "client/shared/src/desktopMain/resources/localization";
const MIRROR_DIRS = [
  "client/desktopApp/src/main/resources/localization",
  "client/androidApp/src/main/assets/localization",
  "client/iosApp/iosApp/localization",
];
const VALIDATOR = "client/tools/check_localization_sync.py";

// Temp scratch (agent Bash writes/reads these; the script never touches fs).
const MISS_DIR = "/tmp/localize-missing"; // scan writes <code>.json = {key: english}
const OUT_DIR = "/tmp/localize-out"; // translate writes <code>.<chunk>.json = {key: translated}

// 28 non-English languages (code -> name / native). Source: manifest.json.
const LANGUAGES = {
  am: "Amharic (አማርኛ)", ar: "Arabic (العربية)", bn: "Bengali (বাংলা)",
  de: "German (Deutsch)", es: "Spanish (Español)", fa: "Persian (فارسی)",
  fr: "French (Français)", ha: "Hausa (Hausa)", hi: "Hindi (हिन्दी)",
  id: "Indonesian (Bahasa Indonesia)", it: "Italian (Italiano)", ja: "Japanese (日本語)",
  ko: "Korean (한국어)", mr: "Marathi (मराठी)", my: "Burmese (မြန်မာ)",
  pa: "Punjabi (ਪੰਜਾਬੀ)", pt: "Portuguese (Português)", ru: "Russian (Русский)",
  sw: "Swahili (Kiswahili)", ta: "Tamil (தமிழ்)", te: "Telugu (తెలుగు)",
  th: "Thai (ไทย)", tr: "Turkish (Türkçe)", uk: "Ukrainian (Українська)",
  ur: "Urdu (اردو)", vi: "Vietnamese (Tiếng Việt)", yo: "Yoruba (Yorùbá)",
  zh: "Chinese Simplified (中文)",
};

const DO_NOT_TRANSLATE = ["CIRIS", "CIRISVerify", "YubiKey", "TPM", "Fed ID", "Secure Enclave"];

const a = typeof args !== "undefined" ? args : undefined;
const allLangs = Object.keys(LANGUAGES);
const targetLangs =
  a && Array.isArray(a.languages) && a.languages.length
    ? allLangs.filter((c) => a.languages.includes(c))
    : allLangs;
const CHUNK = a && Number.isInteger(a.chunk) && a.chunk > 0 ? a.chunk : 45;
const keyClause =
  a && Array.isArray(a.keys) && a.keys.length
    ? `ONLY consider these keys (and only where missing/empty per lang): ${JSON.stringify(a.keys)}.`
    : "Consider ALL keys present in en.json.";

log(`localize-ui: ${targetLangs.length} lang(s), chunk=${CHUNK}: ${targetLangs.join(", ")}`);

// --- Phase 1: scan -> write per-lang missing maps to MISS_DIR --------------
phase("scan");
const scanSchema = {
  type: "object",
  properties: {
    langs: {
      type: "array",
      items: {
        type: "object",
        properties: { code: { type: "string" }, count: { type: "integer" } },
        required: ["code", "count"],
        additionalProperties: false,
      },
    },
  },
  required: ["langs"],
  additionalProperties: false,
};

const scan = await agent(
  `Compute, for each target language, the localization keys that still need translation, and WRITE them to temp files. Do it ALL in one python3 script via Bash (no large output):

Canonical source: ${SHARED_DIR}/en.json   (ignore the top-level "_meta" object)
Target language codes: ${JSON.stringify(targetLangs)}
${keyClause}

A key NEEDS WORK for a language if ANY of: (a) it is MISSING there; (b) its value is empty/whitespace; (c) PLACEHOLDER DRIFT — its value's set of interpolation placeholders differs from the english value's. Placeholders = the regex \`\\$\\{[^}]*\\}|\\{[A-Za-z0-9_]+\\}|%[0-9]*\\$?[sd]\` (named {param}, \${...}, {0}, %s, %1$s); compare as sorted multisets.

Script:
1. Flatten en.json to dotted leaf keys -> english string (skip _meta).
2. mkdir -p ${MISS_DIR}
3. For each target code, flatten ${SHARED_DIR}/<code>.json the same way. Compute the keys that NEED WORK per (a)/(b)/(c) above. Write ${MISS_DIR}/<code>.json = an OBJECT mapping each such dotted key -> its ENGLISH value (UTF-8, ensure_ascii=False). Write the file even if empty ({}).
4. Print one line per code: "<code> <count>" (also print how many were drift vs missing).

Then return {langs:[{code,count}]} for every target code (count = number of missing keys).`,
  { label: "scan", phase: "scan", schema: scanSchema }
);

const counts = {};
for (const e of (scan && scan.langs) || []) counts[e.code] = e.count;
const langsToDo = targetLangs.filter((c) => (counts[c] || 0) > 0);
log(`scan: ${langsToDo.length} lang(s) need work` + (langsToDo.length ? ` (${langsToDo.join(", ")})` : ""));

// --- Phase 2: translate (fan out per (lang, chunk); write to OUT_DIR) -------
if (langsToDo.length > 0) {
  phase("translate");
  const work = [];
  for (const code of langsToDo) {
    const nChunks = Math.ceil(counts[code] / CHUNK);
    for (let i = 0; i < nChunks; i++) work.push({ code, chunk: i, nChunks });
  }
  log(`translate: ${work.length} chunk-task(s) across ${langsToDo.length} lang(s)`);

  await parallel(
    work.map((w) => async () => {
      const name = LANGUAGES[w.code];
      const start = w.chunk * CHUNK;
      const end = start + CHUNK;
      return agent(
        `Translate a CHUNK of CIRIS client UI strings from English into ${name} (code "${w.code}").

Do this exactly, using Read + one python3 Bash script (keep your own output tiny — write the result to a file, don't echo it):
1. Read ${MISS_DIR}/${w.code}.json (a JSON object: dotted_key -> english_value).
2. Take the keys SORTED, then the slice [${start}:${end}] (this chunk). If the slice is empty, write {} and stop.
3. Translate each english value into ${name}. Rules:
   - Natural, app-appropriate UI strings (buttons/labels/titles/hints in a setup/identity wizard).
   - PRESERVE every interpolation placeholder EXACTLY, byte-for-byte: named braces like {count} {provider} {error} {code}, plus \${...}, {0}, {1}, %s, %1$s, and any HTML/markdown. The set of placeholders in each translation MUST equal the set in its english source — same names, same count. Do NOT translate text inside placeholders.
   - Do NOT translate these brand terms (keep verbatim): ${DO_NOT_TRANSLATE.join(", ")}.
4. mkdir -p ${OUT_DIR}; write ${OUT_DIR}/${w.code}.${w.chunk}.json = { dotted_key: translated_value } for EXACTLY the chunk keys (UTF-8, ensure_ascii=False, indent=2).
5. Print only: "<code> chunk ${w.chunk}: <n> translated".

Report one short line. Do not output the translations themselves.`,
        { label: `tx:${w.code}#${w.chunk}`, phase: "translate" }
      );
    })
  );

  // --- Phase 3: merge per-lang chunk outputs into canonical ----------------
  phase("merge");
  await parallel(
    langsToDo.map((code) => async () =>
      agent(
        `Merge the translated chunks for language "${code}" into the canonical localization file, with one python3 Bash script:
1. Read all ${OUT_DIR}/${code}.*.json files; combine into one dict (later chunks override earlier on key collision — there won't be any).
2. Load ${SHARED_DIR}/${code}.json preserving structure + key order (dict keeps insertion order). Never touch "_meta".
3. For each merged dotted key, set the nested value (create intermediate dicts). Set it if the key is currently MISSING, empty/whitespace, OR has PLACEHOLDER DRIFT (its current placeholders differ from en.json's for that key) — the scan only emitted keys that need work, so set every merged key. Do NOT reorder existing keys; append new keys within their parent object. Never touch "_meta".
4. Placeholder guard (MANDATORY): for each value you set, its set of placeholders (named {param}, \${...}, {0}, %s, %1$s) MUST equal the set in the same key's value in ${SHARED_DIR}/en.json. If any differ, FIX the value so it carries the EXACT english placeholders (same names/count), reworded as needed so it still reads naturally. Re-check after fixing; do not write a value that still drifts.
5. Write back ${SHARED_DIR}/${code}.json (UTF-8, ensure_ascii=False, indent=2, trailing newline).
6. Print: "<code>: set <n> keys, <m> placeholder fixes; remaining-missing <r>" (r = en keys still missing after merge).

Report that one line.`,
        { label: `merge:${code}`, phase: "merge" }
      )
    )
  );
}

// --- Phase 4: sync canonical -> all mirror bundles (byte-identical) ---------
phase("sync");
const sync = await agent(
  `Make every committed runtime localization bundle BYTE-IDENTICAL to the canonical bundle, with one python3 Bash script:

CANONICAL: ${SHARED_DIR}
MIRRORS:   ${JSON.stringify(MIRROR_DIRS)}

For each *.json in CANONICAL (en.json, manifest.json, every <lang>.json): copy its raw BYTES into each mirror dir (overwrite; create dir if needed). Then assert every mirror file is byte-identical to its canonical source; report any that differ. Print: total files synced + per-mirror OK/DIFF.`,
  { label: "sync", phase: "sync" }
);
log("sync:\n" + sync);

// --- Phase 5: verify -------------------------------------------------------
phase("verify");
const verify = await agent(
  `Run the CIRIS client localization validator and report the result:

  python3 ${VALIDATOR}

Use Bash. Report: exit code; the ERROR section verbatim (MUST be clean = byte-identical bundles); and any languages still under WARNINGS (missing keys or placeholder drift) with counts. End with a one-line PASS/FAIL.`,
  { label: "verify", phase: "verify" }
);
log("verify:\n" + verify);
return verify;
