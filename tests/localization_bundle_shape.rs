//! **The canonical bundle must be NESTED, because the loader only walks**
//! (CIRISServer#366).
//!
//! `LocalizationManager.resolveKey`
//! (`client/shared/src/commonMain/kotlin/ai/ciris/mobile/shared/localization/LocalizationManager.kt:296`)
//! does exactly one thing with an id:
//!
//! ```text
//! val parts = key.split("."); walk nested JsonObjects; a JsonPrimitive resolves
//! ```
//!
//! It **never** falls back to an exact top-level match. So a bundle entry stored
//! as the flat key `"admin.self.partition"` is unreachable — `resolveKey` splits
//! it into `["admin", "self", "partition"]`, looks for a nested `admin` object,
//! finds none, and returns null. The id then renders RAW, and it renders raw in
//! **every language including English**, because the English fallback is the
//! same lookup against the same shape.
//!
//! That is not hypothetical: 1,484 keys shipped flat and were dead in every
//! language until they were re-nested.
//!
//! # Why a Rust gate when a Python one already exists
//!
//! `client/tools/check_localization_sync.py` owns this invariant in its full
//! form — its `key-resolvability` check tests every leaf address in every locale
//! file, and it mutation-proves itself via `--self-test`. It is the deeper
//! instrument and it stays the authority.
//!
//! It runs in a *different workflow* (`.github/workflows/localization.yml`).
//! This gate is the narrow one, in the main Rust suite, so that a change which
//! flattens the canonical bundle fails in the same run as the server tests
//! rather than only in the localization job. It deliberately checks LESS than
//! the Python check rather than re-deriving it: a second full port of
//! `resolveKey` would be a third answer to one question, which is the defect
//! class this repo has been paying for all week.
//!
//! For the same reason it reads the canonical `en.json` ONLY. The other 28
//! bundles are owned by the `localize-ui` workflow and are written
//! asynchronously; gating them from here would make this suite go red for
//! reasons that have nothing to do with the tree it is testing.

#[path = "support/localization.rs"]
mod localization;

/// **No top-level key in the canonical bundle may contain a `.`**
///
/// The top level is where the defect actually landed, and it is where it is
/// most tempting to reintroduce: a flat `"a.b.c"` entry looks identical to a
/// nested one in a diff, in a key-set comparison, and in any tool that flattens
/// before comparing. It is only different at runtime, where it is dead.
#[test]
fn no_top_level_key_in_the_canonical_bundle_contains_a_dot() {
    let bundle = localization::canonical_bundle();
    let top = bundle
        .as_object()
        .expect("the canonical bundle's root must be a JSON object");

    // A zero finding is only evidence when the denominator is non-zero. A gate
    // that examined nothing and reported nothing wrong is the failure mode this
    // whole cut has been chasing.
    assert!(
        !top.is_empty(),
        "the canonical en.json has NO top-level keys — this gate examined an empty bundle and \
         would have passed over any defect at all"
    );

    let flat: Vec<&str> = top
        .keys()
        .filter(|k| k.contains('.'))
        .map(String::as_str)
        .collect();

    assert!(
        flat.is_empty(),
        "{} of {} top-level keys in the canonical en.json contain a `.`, so they are FLAT keys \
         that `LocalizationManager.resolveKey` can never reach — it always splits on `.` and \
         walks nested objects, and never tries an exact top-level match. Every id below renders \
         RAW in every language, English included. Store them nested \
         (admin: {{ self: {{ partition: \"…\" }} }}), never as a flat dotted key.\nflat keys: {:#?}",
        flat.len(),
        top.len(),
        flat
    );
}

/// The same defect one level down: a dotted key nested *inside* an object is
/// equally unreachable, because the walk that arrives there splits on `.` too.
///
/// Cheap to check while the bundle is already parsed, and it closes the obvious
/// way to reintroduce the bug just below where the gate above is looking.
#[test]
fn no_key_at_any_depth_in_the_canonical_bundle_contains_a_dot() {
    let bundle = localization::canonical_bundle();
    let mut dotted = Vec::new();
    let mut leaves = 0usize;
    collect_dotted_keys(&bundle, &mut String::new(), &mut dotted, &mut leaves);

    assert!(
        leaves > 0,
        "the canonical en.json holds no leaves at all — an empty denominator is not evidence"
    );
    assert!(
        dotted.is_empty(),
        "the canonical en.json carries {} dotted key(s) below the root. A `.` inside a key is a \
         separator to the loader wherever it appears, so these addresses are unreachable and \
         render RAW in every language ({} leaves examined).\ndotted: {:#?}",
        dotted.len(),
        leaves,
        dotted
    );
}

/// Walk the bundle, recording the path of every key that contains a `.` and
/// counting the leaves examined.
fn collect_dotted_keys(
    node: &serde_json::Value,
    path: &mut String,
    dotted: &mut Vec<String>,
    leaves: &mut usize,
) {
    match node {
        serde_json::Value::Object(o) => {
            for (k, v) in o {
                let mark = path.len();
                if !path.is_empty() {
                    path.push('/');
                }
                path.push_str(k);
                if k.contains('.') {
                    dotted.push(path.clone());
                }
                collect_dotted_keys(v, path, dotted, leaves);
                path.truncate(mark);
            }
        }
        _ => *leaves += 1,
    }
}

// ─── the gates' own proof that they can fail ────────────────────────────────
//
// A gate nobody has watched fail is a claim, not a check. These run the same
// predicates over synthetic bundles that carry the defect, so the ability to
// fail is asserted on every CI run rather than in a commit message.
//
// (The real-bundle mutation — flatten one nested key in en.json, watch the two
// gates above go red, restore — was run by hand when they were written. These
// are what keep that true afterwards, since en.json itself is owned by the
// translation workflow and must not be edited to prove a point.)

#[test]
fn the_top_level_predicate_catches_a_flattened_key() {
    let flat = serde_json::json!({ "admin.self.partition": "text", "agent": { "ok": "y" } });
    let found: Vec<&str> = flat
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| k.contains('.'))
        .map(String::as_str)
        .collect();
    assert_eq!(
        found,
        vec!["admin.self.partition"],
        "the top-level predicate did not see a flat dotted key, so the gate built on it is vacuous"
    );

    // …and the flat key really is unreachable by the loader's own traversal,
    // which is WHY the predicate above is the right one. Same shared port every
    // other id gate uses.
    assert_eq!(
        localization::resolve_id(&flat, "admin.self.partition"),
        None,
        "a flat dotted key must be unreachable — if it resolved, this gate would be forbidding \
         something harmless"
    );
    let nested = serde_json::json!({ "admin": { "self": { "partition": "text" } } });
    assert_eq!(
        localization::resolve_id(&nested, "admin.self.partition"),
        Some("text"),
        "the nested form must resolve — otherwise the gate forbids the flat shape while the \
         shape it demands does not work either"
    );
}

#[test]
fn the_any_depth_predicate_catches_a_key_flattened_below_the_root() {
    let mut dotted = Vec::new();
    let mut leaves = 0usize;
    collect_dotted_keys(
        &serde_json::json!({ "admin": { "self.partition": "text", "fine": "y" } }),
        &mut String::new(),
        &mut dotted,
        &mut leaves,
    );
    assert_eq!(
        dotted,
        vec!["admin/self.partition".to_owned()],
        "the any-depth predicate missed a dotted key below the root"
    );
    assert_eq!(leaves, 2, "the leaf denominator must count every leaf");
}
