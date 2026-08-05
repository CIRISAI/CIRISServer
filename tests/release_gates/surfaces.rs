//! **The operator-surface rungs** — what a human reads off this node, and the two
//! ways that reading lies.
//!
//! Both failures here are the same shape from opposite ends: a surface that
//! cannot distinguish "we could not ask" from "the answer is none", and a string
//! that reaches the reader as a raw token because the id was written in a form
//! the loader can never resolve.

use crate::ladder::{assert_proven, repo, DISTINCT_ZEROES, LOCALIZATION_REACHABLE};

/// The canonical bundle, and the three runtime copies that must mirror it
/// byte-for-byte. Each platform loader reads a DIFFERENT one of these; any that
/// goes stale ships different strings to that platform's readers only.
const BUNDLE_DIRS: &[&str] = &[
    "client/shared/src/desktopMain/resources/localization", // CANONICAL
    "client/desktopApp/src/main/resources/localization",
    "client/androidApp/src/main/assets/localization",
    "client/iosApp/iosApp/localization",
];

/// Could-not-ask ≠ nothing-there, on every surface that shows a zero.
///
/// Every instance of this class in this repo has been found the same way: the
/// collapsed reading was GREEN and wrong. `not_exercised` folded into `idle` made
/// an untested node read healthy; the federation-identity fallback answered
/// `200 {"peer_count_total": 0}` with confidence it had not earned. A zero that
/// does not name its own cause is not data.
#[test]
fn gate_distinct_zeroes() {
    assert_proven(&DISTINCT_ZEROES);
}

/// Every message id resolves under the loader's REAL semantics.
///
/// `LocalizationManager.resolveKey` splits the key on `.` and walks nested
/// objects — there is no top-level exact-match fallback. So a flat dotted key is
/// dead for every reader in every language, English included, and it is dead
/// identically in all four committed bundles, which is why mirror-parity checks
/// see nothing wrong.
///
/// The bundle checker cannot catch it either: its `flatten()` maps a flat dotted
/// key and a nested path to the SAME string, so a key the loader can never
/// resolve satisfies the guard. That is this cut's defect class stated exactly —
/// a check whose scope does not cover what it claims — which is why the rung
/// anchors on the SHAPE predicate (`no key at any depth contains a dot`) and on
/// that predicate's own two mutation proofs, rather than on the flattened view.
///
/// The rung deliberately does NOT claim every emitted id has a bundle entry.
/// Ids with no entry degrade as designed — the wire carries `{id, text}` and the
/// English source ships in the payload — so absence is a localization-coverage
/// ratchet, not a release blocker. Reachability is the release blocker: a
/// DEFINED-but-unreachable id is worse than an absent one, because every bundle
/// agrees and the lookup still returns null.
#[test]
fn gate_localization_reachable() {
    assert_proven(&LOCALIZATION_REACHABLE);
}

/// **The four runtime bundles are byte-identical — checked HERE, on the tree
/// being tagged.**
///
/// This rung is direct rather than anchored, and that is the whole point of it.
/// `client/tools/check_localization_sync.py` already detects this perfectly and
/// names every offending file; `tests/localization_gate.rs` already runs that
/// guard. Duplicating a check normally forks it. This one is duplicated on
/// purpose, because of HOW the invariant breaks:
///
/// > Byte-identity across four files is a CROSS-FILE invariant, and git merges
/// > PER FILE.
///
/// Observed on this repo, 2026-08-05. Two branches from one base, touching
/// **disjoint** files: `a54bb96` repaired 65 values in the canonical bundle,
/// `b773c1f` synced the three mirrors to the pre-repair text. Both were green
/// alone. Git merged them cleanly with no conflict and produced `09ce708` — a
/// state neither branch was ever in, with the canonical repaired and all three
/// mirrors stale. That is not bad luck; two green branches touching different
/// bundle files merge into a violation every time.
///
/// And the guard could not see it: `localization.yml` is `on: pull_request`, so
/// no job ever inspects a merge RESULT. The instrument was not failing silently —
/// it was never RUN on the tree where the breakage existed, because the breakage
/// is created by an event the trigger does not cover.
///
/// A release gate is the one place that hole closes for free: it runs on whatever
/// tree you are about to tag, however that tree came to be.
///
/// The durable fix is still the TRIGGER (`push: branches: [main]`, or a
/// merge_group), and it is NOT made here. Be precise about why, because the
/// obvious framing is wrong: it is not that adding the trigger *would* turn CI
/// red. `localization.yml` already runs `--strict` on `pull_request`, and
/// `--strict` exits 1 today on 28 translation-drift warnings — so **every PR
/// opened against main already gets a red localization check**, for drift its
/// author did not introduce. The trigger question is about ADDITIONAL coverage of
/// merge results; the red is live on the coverage that already exists.
///
/// The workflow's own comment sets the rule this violates — *"the flag goes in
/// only when the tree passes it"* — so the precondition `--strict` was admitted
/// under is currently false. Clearing it is a retranslation pass (the `localize-ui`
/// workflow), which is content and belongs to whoever owns the locales; this rung
/// is what can be done without waiting on it.
#[test]
fn gate_localization_bundles_are_byte_identical_mirrors() {
    let canonical_dir = repo().join(BUNDLE_DIRS[0]);
    let mut names: Vec<String> = std::fs::read_dir(&canonical_dir)
        .expect("the canonical localization bundle must be readable")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert!(
        names.len() > 20,
        "only {} bundle file(s) under {} — the walker is not seeing the bundle, so a green \
         result here would mean nothing",
        names.len(),
        BUNDLE_DIRS[0],
    );

    let mut drift: Vec<String> = Vec::new();
    let mut compares = 0usize;
    for name in &names {
        let canonical = std::fs::read(canonical_dir.join(name)).expect("canonical bundle file");
        for mirror_dir in &BUNDLE_DIRS[1..] {
            let path = repo().join(mirror_dir).join(name);
            compares += 1;
            match std::fs::read(&path) {
                Err(_) => drift.push(format!("  {mirror_dir}/{name} — ABSENT")),
                Ok(bytes) if bytes != canonical => drift.push(format!(
                    "  {mirror_dir}/{name} — differs from canonical ({} vs {} bytes)",
                    bytes.len(),
                    canonical.len()
                )),
                Ok(_) => {}
            }
        }
    }

    assert!(
        drift.is_empty(),
        "\n\
         🚫 RELEASE GATE [localization-mirrors] — DO NOT TAG.\n\
         \n\
         Unsafe to ship: the four committed runtime bundles are not byte-identical, so the\n\
         platforms reading the stale copies ship DIFFERENT STRINGS from the canonical —\n\
         silently, and only on those platforms. {compares} file comparisons, {} bad:\n\
         \n\
         {}\n\
         \n\
         Before assuming a branch did this: byte-identity across four files is a CROSS-FILE\n\
         invariant and git merges PER FILE, so two green branches touching DIFFERENT bundle\n\
         files merge cleanly into this state — one repairing the canonical, one syncing the\n\
         mirrors, neither ever wrong on its own. It happened here on 2026-08-05 (a54bb96 +\n\
         b773c1f -> 09ce708). `localization.yml` is `on: pull_request` and never inspects a\n\
         merge result, so nothing upstream of this gate can see it.\n\
         \n\
         Fix: copy the canonical files over the mirrors — but VERIFY FIRST that the\n\
         canonical is the newer side. A blind copy in the wrong direction reverts a repair.\n",
        drift.len(),
        drift.join("\n"),
    );
}
