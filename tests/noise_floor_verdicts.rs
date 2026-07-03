//! CC 6.1.2 noise-floor PURE verdict functions — conformance vector tables
//! (CIRISConformance#55, tests #1 + #6).
//!
//! These are the two SHIPPED, side-effect-free decision functions that gate the
//! §19.7 noise-floor descent, driven against the pinned crates
//! (persist v12.2.0 / verify v8.5.0 / edge v8.6.1). No backend, no async — the
//! whole point of the CEG §19.7 design is that the *routing* is a pure fn a fabric
//! node can compute mechanically, and the substrate merely executes it. Here we
//! pin the real boundary/routing tables so a future crate bump that silently
//! moves a threshold fails CIRISServer's build.
//!
//!   #1 classification — persist's `FountainContent::classify` maps a retained
//!      symbol count to a degradation class (Full / Partial / EnvelopeOnly). The
//!      single source of truth for the read-path fidelity boundary
//!      (persist `src/fountain/types.rs`).
//!
//!   #6 ejection routing — verify-core's `ejection_verdict` maps (consent,
//!      pressure) to the canonical §19.7.3 `EjectionVerdict`; persist's
//!      `EjectionAction::from_verdict` then resolves the tier-agnostic verdict
//!      onto a concrete persist eviction action (verify `holonomic/aggregation.rs`,
//!      persist `src/fountain/aggregation.rs`).

use ciris_persist::fountain::{
    EjectionAction, FountainContent, FountainReadClass, FountainTier,
};
use ciris_verify_core::holonomic::{
    eject_aggregated_tier, ejection_verdict, ConsentState, EjectionVerdict,
};

// ---------------------------------------------------------------------------
// #1 — FountainContent::classify boundary table.
//
// REAL semantics (persist src/fountain/types.rs, the doc-commented contract):
//   * `present >= n_source`            ⇒ Full
//   * `min_viable <= present < n_source` ⇒ Partial
//   * `present < min_viable` (incl. 0) ⇒ EnvelopeOnly
//
// Both boundaries are inclusive-below (`>=`): min_viable itself is Partial, and
// n_source itself is Full. Every boundary point is pinned:
//   0, min_viable-1, min_viable, n_source-1, n_source, n_source+1.
// ---------------------------------------------------------------------------

#[test]
fn classify_boundary_table() {
    // A manifest with headroom between the floor and the full-recovery count so
    // every boundary is distinct: min_viable = 3, n_source = 10.
    const N_SOURCE: u32 = 10;
    const MIN_VIABLE: u32 = 3;

    let cases: &[(u32, FountainReadClass, &str)] = &[
        // present < min_viable ⇒ EnvelopeOnly (manifest-only provenance).
        (0, FountainReadClass::EnvelopeOnly, "present=0 ⇒ EnvelopeOnly"),
        (
            MIN_VIABLE - 1, // 2
            FountainReadClass::EnvelopeOnly,
            "present=min_viable-1 ⇒ EnvelopeOnly (below the floor)",
        ),
        // min_viable <= present < n_source ⇒ Partial (floor inclusive).
        (
            MIN_VIABLE, // 3
            FountainReadClass::Partial,
            "present=min_viable ⇒ Partial (floor is inclusive)",
        ),
        (
            (MIN_VIABLE + N_SOURCE) / 2, // 6, a mid-range partial
            FountainReadClass::Partial,
            "min_viable < present < n_source ⇒ Partial",
        ),
        (
            N_SOURCE - 1, // 9
            FountainReadClass::Partial,
            "present=n_source-1 ⇒ Partial (still short of full recovery)",
        ),
        // present >= n_source ⇒ Full (recovery count inclusive).
        (
            N_SOURCE, // 10
            FountainReadClass::Full,
            "present=n_source ⇒ Full (recovery count is inclusive)",
        ),
        (
            N_SOURCE + 1, // 11
            FountainReadClass::Full,
            "present>n_source ⇒ Full (repair headroom)",
        ),
    ];

    for &(present, expected, why) in cases {
        assert_eq!(
            FountainContent::classify(present, N_SOURCE, MIN_VIABLE),
            expected,
            "classify(present={present}, n_source={N_SOURCE}, min_viable={MIN_VIABLE}): {why}",
        );
    }
}

#[test]
fn classify_degenerate_floor_equals_full() {
    // When min_viable == n_source there is NO Partial band: below the count is
    // EnvelopeOnly, at/above it is Full. Pins that `>=` (not `>`) governs both
    // edges so the bands never overlap or leave a gap.
    const N: u32 = 5;
    assert_eq!(
        FountainContent::classify(N - 1, N, N),
        FountainReadClass::EnvelopeOnly,
        "present just below the collapsed floor ⇒ EnvelopeOnly (no Partial band)",
    );
    assert_eq!(
        FountainContent::classify(N, N, N),
        FountainReadClass::Full,
        "present at the collapsed floor ⇒ Full (>= is inclusive)",
    );
}

// ---------------------------------------------------------------------------
// #6 — ejection routing matrix.
//
// REAL routing (verify holonomic/aggregation.rs `ejection_verdict`):
//   Withdrawn, pressure=*        ⇒ EjectHardDelete  (N5: revocation overrides
//                                                     pressure; NEVER a tier-shed)
//   Active,    pressure=true     ⇒ EjectToTier
//   Active,    pressure=false    ⇒ Keep
//   Unknown,   pressure=true     ⇒ EjectToTier      (Unknown routes like Active
//   Unknown,   pressure=false    ⇒ Keep              here — fail-secure rarity is
//                                                     an UPSTREAM sub-decision that
//                                                     only sets `pressure`, it does
//                                                     not force ejection)
//
// NOTE the verify verdict `EjectToTier` is tier-AGNOSTIC; the concrete tier is
// persist's storage decision, resolved by `EjectionAction::from_verdict`.
// ---------------------------------------------------------------------------

#[test]
fn ejection_verdict_routing_matrix() {
    let cases: &[(ConsentState, bool, EjectionVerdict, &str)] = &[
        // Revocation (§19.3 N5) forces hard delete regardless of pressure.
        (
            ConsentState::Withdrawn,
            true,
            EjectionVerdict::EjectHardDelete,
            "Withdrawn + pressure ⇒ EjectHardDelete",
        ),
        (
            ConsentState::Withdrawn,
            false,
            EjectionVerdict::EjectHardDelete,
            "Withdrawn + no pressure ⇒ EjectHardDelete (revocation overrides pressure)",
        ),
        // Active: pressure steps down one tier, otherwise retain.
        (
            ConsentState::Active,
            true,
            EjectionVerdict::EjectToTier,
            "Active + pressure ⇒ EjectToTier (one downward step)",
        ),
        (
            ConsentState::Active,
            false,
            EjectionVerdict::Keep,
            "Active + no pressure ⇒ Keep",
        ),
        // Unknown routes identically to Active in THIS fn (fail-secure rarity is
        // upstream — it only informs whether `under_capacity_pressure` is set).
        (
            ConsentState::Unknown,
            true,
            EjectionVerdict::EjectToTier,
            "Unknown + pressure ⇒ EjectToTier (routes like Active)",
        ),
        (
            ConsentState::Unknown,
            false,
            EjectionVerdict::Keep,
            "Unknown + no pressure ⇒ Keep",
        ),
    ];

    for &(consent, pressure, expected, why) in cases {
        assert_eq!(
            ejection_verdict(consent, pressure),
            expected,
            "ejection_verdict({consent:?}, pressure={pressure}): {why}",
        );
    }

    // Withdrawn is NEVER a tier-shed at any pressure — pin the privacy invariant
    // directly (a revoked item MUST be below the floor at every retained tier).
    for pressure in [true, false] {
        assert_ne!(
            ejection_verdict(ConsentState::Withdrawn, pressure),
            EjectionVerdict::EjectToTier,
            "Withdrawn must never resolve to a recoverable tier-shed",
        );
    }
}

// ---------------------------------------------------------------------------
// #6 (cont.) — persist resolves the tier-agnostic verdict onto a concrete
// eviction action. `EjectionAction::from_verdict(verdict, Option<FountainTier>)`.
// ---------------------------------------------------------------------------

#[test]
fn from_verdict_resolves_concrete_tier() {
    // The Active+pressure verdict is tier-agnostic; supplying a concrete target
    // tier resolves it to that persist action.
    let verdict = ejection_verdict(ConsentState::Active, true);
    assert_eq!(verdict, EjectionVerdict::EjectToTier);

    assert_eq!(
        EjectionAction::from_verdict(verdict, Some(FountainTier::T3)),
        EjectionAction::EjectToTier(FountainTier::T3),
        "EjectToTier + Some(T3) ⇒ EjectToTier(T3)",
    );

    // EjectToTier with no target (or Full — nothing to drop) is a no-op Keep:
    // full fidelity is retained, so there is no descent step.
    assert_eq!(
        EjectionAction::from_verdict(verdict, None),
        EjectionAction::Keep,
        "EjectToTier + None ⇒ Keep (no tier to degrade to)",
    );
    assert_eq!(
        EjectionAction::from_verdict(verdict, Some(FountainTier::Full)),
        EjectionAction::Keep,
        "EjectToTier + Some(Full) ⇒ Keep (Full == retain everything)",
    );
}

#[test]
fn from_verdict_passthrough_and_tier_only_roundtrip() {
    // Keep and EjectHardDelete ignore the target tier entirely.
    assert_eq!(
        EjectionAction::from_verdict(EjectionVerdict::Keep, Some(FountainTier::T2)),
        EjectionAction::Keep,
        "Keep verdict ⇒ Keep action (target tier ignored)",
    );
    let hard = ejection_verdict(ConsentState::Withdrawn, false);
    assert_eq!(hard, EjectionVerdict::EjectHardDelete);
    assert_eq!(
        EjectionAction::from_verdict(hard, Some(FountainTier::T4)),
        EjectionAction::EjectHardDelete,
        "EjectHardDelete verdict ⇒ EjectHardDelete action (target tier ignored)",
    );

    // The tier-granular stratum-shed round-trips its stratum index through
    // from_verdict unchanged, and the carried tier index is irrelevant to the
    // supplied target tier (it is a stratum index, not a fidelity tier).
    for stratum in [0u32, 1, 2, 7] {
        let verdict = eject_aggregated_tier(stratum);
        assert_eq!(
            verdict,
            EjectionVerdict::EjectAggregatedTierOnly { tier: stratum },
            "eject_aggregated_tier constructs the tier-tagged verdict",
        );
        assert_eq!(
            EjectionAction::from_verdict(verdict, Some(FountainTier::T3)),
            EjectionAction::EjectAggregatedTierOnly(stratum),
            "EjectAggregatedTierOnly{{tier={stratum}}} round-trips to \
             EjectAggregatedTierOnly({stratum}) (target tier irrelevant)",
        );
        // Round-trips identically with no target tier supplied.
        assert_eq!(
            EjectionAction::from_verdict(verdict, None),
            EjectionAction::EjectAggregatedTierOnly(stratum),
            "stratum-shed round-trip is independent of any target tier",
        );
    }
}
