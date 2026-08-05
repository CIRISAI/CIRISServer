//! **One port of `LocalizationManager.resolveKey`, shared by every suite that
//! gates a server-emitted message id.**
//!
//! ## Why this exists, and why it is shared rather than copied
//!
//! The server hands a UI `{id, text}` pairs and the UI resolves `id` in the
//! reader's language. The Kotlin resolver
//! (`client/shared/src/commonMain/…/localization/LocalizationManager.kt:296`)
//! does exactly one thing:
//!
//! ```text
//! val parts = key.split("."); walk nested JsonObjects; a JsonPrimitive resolves
//! ```
//!
//! **It never falls back to an exact top-level match.** So a bundle entry stored
//! as the flat key `"admin.self.partition"` is unreachable, and the id renders
//! raw in every language including English — CIRISServer#366. Not hypothetical:
//! **1,484 keys shipped flat** and were dead in every language, English
//! included, until they were re-nested. A check here must speak the loader's
//! language, not JSON's.
//!
//! A gate that checks ids with `bundle.get(&id)` does not merely miss that bug:
//! it **requires** it. `tests/mesh_config_consumers.rs` shipped exactly that
//! lookup, went green over the broken shape, and went red the moment the bundle
//! was corrected — the gate was pinning the defect. That is the reason this is
//! one function in one file instead of a snippet each suite retypes: a second
//! copy of a resolver is a second answer, and this class has already cost three
//! incidents in one day.
//!
//! NB: files under `tests/support/` are not auto-compiled as test binaries; each
//! suite pulls this in with an explicit `#[path]` (same shape as
//! `tests/support/log_capture.rs`).

#![allow(dead_code)]

/// The canonical bundle every runtime bundle mirrors.
pub fn canonical_bundle() -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/client/shared/src/desktopMain/resources/localization/en.json"
        ))
        .expect("read the canonical localization bundle"),
    )
    .expect("the canonical bundle is JSON")
}

/// Resolve a dotted id the way the loader does: **nested traversal only**.
///
/// Returns `None` for a flat dotted key, a missing key, or a non-primitive leaf
/// — the three shapes that render raw at runtime.
#[must_use]
pub fn resolve_id<'a>(bundle: &'a serde_json::Value, id: &str) -> Option<&'a str> {
    let mut cur = bundle;
    for part in id.split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    cur.as_str()
}

/// Harvest every `{id, text}` pair out of a response, at any depth.
///
/// The server's localizable strings are these pairs and nothing else, so
/// harvesting them from a REAL response gates what the routes actually emit
/// rather than a hand-listed vocabulary that can fall behind them.
pub fn collect_pairs(v: &serde_json::Value, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::Object(o) => {
            if let (Some(id), Some(text)) = (
                o.get("id").and_then(serde_json::Value::as_str),
                o.get("text").and_then(serde_json::Value::as_str),
            ) {
                if o.len() == 2 {
                    out.push((id.to_owned(), text.to_owned()));
                    return;
                }
            }
            for (_, vv) in o {
                collect_pairs(vv, out);
            }
        }
        serde_json::Value::Array(a) => {
            for vv in a {
                collect_pairs(vv, out);
            }
        }
        _ => {}
    }
}

/// Assert every `{id, text}` pair in `response` resolves in the canonical
/// bundle **with byte-identical English**.
///
/// Both halves matter and they fail differently: a missing id renders raw on
/// every platform, while an id whose English has drifted from the source
/// renders a stale translation of *different content* — which is worse, because
/// it looks right.
pub fn assert_pairs_resolve(bundle: &serde_json::Value, response: &serde_json::Value, what: &str) {
    let mut pairs = Vec::new();
    collect_pairs(response, &mut pairs);
    assert!(
        !pairs.is_empty(),
        "{what}: harvested ZERO {{id, text}} pairs — a gate over an empty denominator is not \
         evidence"
    );
    for (id, text) in pairs {
        match resolve_id(bundle, &id) {
            None => panic!(
                "{what}: `{id}` does not resolve in the canonical en.json by nested traversal, so \
                 it renders RAW in every language. Store it as a nested object \
                 (admin: {{ self: {{ partition: \"…\" }} }}), never as a flat dotted key."
            ),
            Some(bundled) => assert_eq!(
                bundled, text,
                "{what}: `{id}` resolves, but the bundle's English has drifted from the English \
                 this build emits — every translated locale is then a translation of text this \
                 build no longer sends"
            ),
        }
    }
}

// ─── the resolver's own proof that it can fail ──────────────────────────────
//
// A resolver that silently accepted the flat shape would make every gate built
// on it vacuous, which is the exact failure this file exists to end. These run
// in every suite that includes the module.

#[test]
fn the_resolver_refuses_a_flat_dotted_key() {
    let flat = serde_json::json!({ "admin.self.partition": "text" });
    assert_eq!(
        resolve_id(&flat, "admin.self.partition"),
        None,
        "a flat dotted key is unreachable at runtime and must be unreachable here"
    );
    let nested = serde_json::json!({ "admin": { "self": { "partition": "text" } } });
    assert_eq!(resolve_id(&nested, "admin.self.partition"), Some("text"));
}

#[test]
fn the_resolver_refuses_a_non_primitive_leaf() {
    let obj_leaf = serde_json::json!({ "admin": { "self": { "partition": { "a": 1 } } } });
    assert_eq!(resolve_id(&obj_leaf, "admin.self.partition"), None);
    let null_leaf = serde_json::json!({ "admin": { "self": { "partition": null } } });
    assert_eq!(resolve_id(&null_leaf, "admin.self.partition"), None);
}

#[test]
fn the_pair_harvester_finds_pairs_at_every_depth() {
    let mut out = Vec::new();
    collect_pairs(
        &serde_json::json!({
            "message": { "id": "a", "text": "A" },
            "rows": [ { "note": { "id": "b", "text": "B" } } ],
            "not_a_pair": { "id": "c", "text": "C", "extra": 1 },
        }),
        &mut out,
    );
    out.sort();
    assert_eq!(
        out,
        vec![
            ("a".to_owned(), "A".to_owned()),
            ("b".to_owned(), "B".to_owned())
        ],
        "a three-field object is not an {{id, text}} pair and must not be harvested as one"
    );
}
