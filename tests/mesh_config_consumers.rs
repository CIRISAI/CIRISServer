//! **`consumed` must be derived, not declared** (CIRISServer#365).
//!
//! `src/mesh_config_effect.rs` answers, per `mesh_config` key, whether a loop in
//! THIS build reads it. The read surface prints that answer beside `effective`,
//! because `effective: 10` alone is a false statement about a key nothing
//! consumes.
//!
//! An answer like that is worth exactly as much as its coupling to reality. This
//! repo's recurring defect is the restated value that forks from its source — the
//! harness restated the consent prefixes for eight releases while production
//! shipped a different set and moved zero traces; `src/location.rs` carries a
//! whole test whose only job is to prove a bound was READ rather than written
//! down. A hand-maintained `consumed` column would be that defect wearing the
//! costume of its own cure.
//!
//! So the flag is pinned from both sides, and this file is the second side:
//!
//! - **The structural half** (unit-tested inside the module): `EffectiveMeshConfig`
//!   keeps its fold PRIVATE, so the only way any code reads a folded value is a
//!   named accessor. A key with no accessor cannot have a consumer.
//! - **The actual half (here):** every key reported `Wired` names an accessor
//!   that is genuinely CALLED, from non-test code, outside the module that
//!   defines it. An accessor nobody calls is the original defect with extra
//!   steps.
//!
//! And the converse, which matters just as much: a key reported NOT consumed
//! must not be read by anything, or the surface is lying in the other direction.
//! The private fold makes that structural — this file states it as a property so
//! the reason survives a refactor.
//!
//! **Mutation-verified.** Deleting the `trace_plane()` call from
//! `src/ingest_http.rs` turns `every_wired_key_has_a_real_call_site` red with
//! the key that lost its caller named; deleting the `serve_fidelity()` call from
//! `src/compose.rs` does the same for the other.

use std::collections::BTreeSet;

use ciris_persist::federation::MeshConfigKey;
use ciris_server::mesh_config_effect::{consumption, Consumption, MeshConfigEffect};

/// The ONE port of `LocalizationManager.resolveKey`. See the module doc there
/// for why this is shared rather than retyped per suite.
#[path = "support/localization.rs"]
mod localization;

/// Every `.rs` file under `src/`, excluding the module that DEFINES the
/// accessors — a definition is not a call site, and counting it would let a
/// consumer be declared into existence.
fn call_site_sources() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.to_string_lossy().to_string();
            if name.ends_with("mesh_config_effect.rs") {
                continue;
            }
            out.push((
                name,
                std::fs::read_to_string(&path).expect("read source file"),
            ));
        }
    }
    let mut out = Vec::new();
    walk(
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut out,
    );
    assert!(out.len() > 20, "the source walk found almost nothing");
    out
}

/// `code` with every line comment stripped AND everything from the first
/// `#[cfg(test)]` onward dropped — so a scan never trips on prose that
/// legitimately names what the code must (or must not) spell, and a call inside
/// a unit test never counts as production wiring. (A test calling an accessor
/// is exactly the "read it and ignore it" shape this file exists to catch.)
fn production_code(code: &str) -> String {
    let code = match code.find("#[cfg(test)]") {
        Some(i) => &code[..i],
        None => code,
    };
    code.lines()
        .map(|l| match l.find("//") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The bare method name an accessor path names: `EffectiveMeshConfig::foo` → `foo`.
fn method_of(site: &str) -> &str {
    site.rsplit("::").next().expect("a site names a method")
}

#[test]
fn every_wired_key_has_a_real_call_site() {
    let sources = call_site_sources();
    let mut missing: Vec<String> = Vec::new();

    for &key in MeshConfigKey::ALL {
        let Consumption::Wired { site, .. } = consumption(key) else {
            continue;
        };
        // A CALL, with a receiver — `.foo()`. A bare `foo(` would match a
        // function DEFINITION or a similarly-named test fn somewhere else in
        // the tree, and a definition is not a consumer (this exact false
        // positive was found by mutating the gate: `src/peer.rs` has a test
        // named `default_covers_the_trace_plane`, which kept the gate green
        // after the real call site was deleted).
        let needle = format!(".{}()", method_of(site));
        let found: Vec<&str> = sources
            .iter()
            .filter(|(_, body)| production_code(body).contains(&needle))
            .map(|(name, _)| name.as_str())
            .collect();
        if found.is_empty() {
            missing.push(format!(
                "{} claims consumed:true through `{site}` and NOTHING outside \
                 src/mesh_config_effect.rs calls it",
                key.wire_name()
            ));
        }
    }

    assert!(
        missing.is_empty(),
        "the read surface would report `consumed: true` for a key no loop reads — which is \
         exactly the false confirmation CIRISServer#365 exists to remove:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn a_key_reported_unconsumed_is_read_by_nothing() {
    // The converse. `consumed: false` beside a value something quietly honours
    // is a lie in the other direction, and it is the one a reader would never
    // think to check. The private fold makes this structural — the property is
    // written down so the reason outlives the refactor that would break it.
    let accessors: BTreeSet<&str> = MeshConfigKey::ALL
        .iter()
        .filter_map(|k| match consumption(*k) {
            Consumption::Wired { site, .. } => Some(method_of(site)),
            _ => None,
        })
        .collect();

    // Every accessor `EffectiveMeshConfig` exposes is claimed by exactly one
    // key. An accessor no key claims would be a read path with no entry in the
    // registry — a consumer the surface never mentions.
    let unwired = MeshConfigEffect::unwired();
    let readable: BTreeSet<&str> = unwired
        .current()
        .wired_readings()
        .into_iter()
        .map(|(k, _)| match consumption(k) {
            Consumption::Wired { site, .. } => method_of(site),
            _ => unreachable!("wired_readings yields only wired keys"),
        })
        .collect();
    assert_eq!(
        accessors, readable,
        "the accessor set and the declared-wired set must be the same set"
    );

    // And no key outside that set is named by a consumer-shaped read anywhere.
    // `MeshConfigKey::` appears legitimately in the surface (which renders the
    // whole registry) and in the effect module (which declares it); a THIRD
    // module naming a key is a consumer that never registered itself.
    let named_elsewhere: Vec<String> = call_site_sources()
        .into_iter()
        .filter(|(name, body)| {
            !name.ends_with("mesh_config_surface.rs")
                && production_code(body).contains("MeshConfigKey::")
        })
        .map(|(name, _)| name)
        .collect();
    assert!(
        named_elsewhere.is_empty(),
        "a module outside the mesh-config surface and its effect registry names a \
         MeshConfigKey directly — if it reads one, the registry must say so:\n  {}",
        named_elsewhere.join("\n  ")
    );
}

#[test]
fn the_registry_answers_for_every_key_and_names_a_tracker_when_it_cannot() {
    // A "no consumer here" that does not say WHERE the consumer is, or that it
    // has none anywhere, sends an operator looking for a bug in the wrong repo.
    for &key in MeshConfigKey::ALL {
        match consumption(key) {
            Consumption::Wired { site, effect } => {
                assert!(
                    !site.is_empty() && !effect.is_empty(),
                    "{}",
                    key.wire_name()
                );
            }
            Consumption::Elsewhere { owner, tracked_by } => {
                assert!(!owner.is_empty(), "{} names no owner", key.wire_name());
                assert!(
                    tracked_by.contains('#'),
                    "{} names no tracking issue",
                    key.wire_name()
                );
            }
            Consumption::Unreachable {
                owner,
                blocker,
                tracked_by,
            } => {
                assert!(!owner.is_empty(), "{} names no owner", key.wire_name());
                // The arm's whole justification: it claims a consumer EXISTS
                // and cannot be reached. An arm that says that without naming
                // what blocks it is a `false` with no address, which is the
                // shape this registry replaced.
                assert!(
                    blocker.len() > 40,
                    "{} is unreachable but names no blocker an operator could act on",
                    key.wire_name()
                );
                assert!(
                    tracked_by.contains('#'),
                    "{} names no tracking issue",
                    key.wire_name()
                );
            }
            Consumption::Unbuilt { tracked_by } => {
                assert!(
                    tracked_by.contains('#'),
                    "{} names no tracking issue",
                    key.wire_name()
                );
            }
        }
    }
}

#[test]
fn every_consumption_message_resolves_in_the_canonical_bundle() {
    // The surface emits `{id, text}` pairs and a UI resolves the id in the
    // reader's language, falling back to the English source. An id with no entry
    // in the canonical bundle renders RAW on every platform; an entry whose
    // English has drifted from the source renders a *stale translation of
    // different content*, which is worse — it looks right.
    //
    // **This gate used to read `bundle.get(&id)`** — an exact top-level lookup
    // the Kotlin loader never performs. Against a correctly NESTED bundle that
    // returns `None` for every dotted id, so the assertion could only pass while
    // the bundle carried the flat keys #366 exists to forbid: the gate did not
    // miss the defect, it required it. It now goes through the one shared port
    // of the loader's own algorithm, which carries its own proof that it can
    // fail (`the_resolver_refuses_a_flat_dotted_key`).
    let bundle = localization::canonical_bundle();

    for &key in MeshConfigKey::ALL {
        let c = consumption(key);
        let id = c.message_id();
        assert_eq!(
            localization::resolve_id(&bundle, &id),
            Some(c.message_text()),
            "`{id}` must resolve in the canonical en.json BY NESTED TRAVERSAL, with the SAME \
             English the server emits (unresolvable ⇒ the id renders raw in every language; \
             different ⇒ every translated locale is a translation of text this build no longer \
             sends)"
        );
    }
}

#[test]
fn the_four_redundancy_keys_stay_unconsumed_and_say_why() {
    // persist v30.0.0 (CIRISPersist#602) removed the FIRST of #365's two
    // blockers: `redundancy.*` is now four keys on two TYPED axes (`Symbols` /
    // `Holders`), taken from edge's own four-tuple decomposition, so mapping a
    // key onto a knob is no longer an axis choice made on our own authority.
    //
    // The second blocker stands. `FountainSwarmRuntime::start` takes
    // `SwarmRuntimeConfig` by value and offers no setter, so the only place a
    // value could land is `crate::holonomic::install_swarm_runtime`, once, at
    // composition — after which a TTL-expired relief would keep applying until
    // a restart. That is a NEW lie, not the existing gap, so these stay false.
    //
    // Pinned so a later pass cannot flip them on the strength of the axis split
    // alone, which is the half that changed.
    let keys: Vec<MeshConfigKey> = MeshConfigKey::ALL
        .iter()
        .copied()
        .filter(|k| k.wire_name().starts_with("redundancy."))
        .collect();
    assert_eq!(
        keys.len(),
        4,
        "persist's registry carries four redundancy keys after #602's axis split; got {:?}",
        keys.iter().map(|k| k.wire_name()).collect::<Vec<_>>()
    );
    for key in keys {
        match consumption(key) {
            Consumption::Unreachable {
                owner, tracked_by, ..
            } => {
                assert_eq!(owner, "CIRISEdge", "{}", key.wire_name());
                assert_eq!(tracked_by, "CIRISEdge#440", "{}", key.wire_name());
            }
            other => panic!(
                "{} must stay unconsumed while edge's swarm runtime has no setter: got {other:?}",
                key.wire_name()
            ),
        }
    }
}

#[test]
fn the_descent_multiplier_stays_unconsumed_until_there_is_a_descent_operator() {
    // #365 says this one in terms: `descent.pressure_multiplier` is blocked on
    // #239, which has no descent operator to multiply, and a `true` here would
    // be exactly the lie the issue exists to remove. Pinned so a later pass
    // cannot flip it on the strength of having READ the value.
    match consumption(MeshConfigKey::DescentPressureMultiplier) {
        Consumption::Unbuilt { tracked_by } => assert_eq!(tracked_by, "CIRISServer#239"),
        other => panic!(
            "descent.pressure_multiplier must stay unconsumed while #239's operator does not \
             exist; got {other:?}"
        ),
    }
}
