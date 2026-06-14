//! Consent-resolution layer — determines whether emission is permitted for
//! a given accord-traces batch, per CIRISAgent#870.
//!
//! # Purpose
//!
//! Post-fold, the source of truth for the accord-traces consent gate is a
//! **CEG consent object on the shared persist Engine**: a `scores`
//! attestation on dimension `consent:community_trust:v1`. During the 2.9.6
//! interim the canonical community key isn't published, so no such object
//! exists and the live path is operator config. This module implements the
//! decided shape: **read the CEG object first, fall back to config when
//! absent — but a withdrawn/recanted grant must NEVER fall back to config**
//! (a recant must stop emission; location/consent cannot outlive a recant).
//!
//! # MISSION boundary
//!
//! Lens-core composes substrate reads, never re-implements persist rules.
//! This module reads attestation rows via `Engine::federation_directory()`
//! and applies the dimension-scoped newest-wins semantics the agent's own
//! consent model uses (`ciris_engine/logic/services/governance/consent/
//! attestation.py`, (occurrence, dimension) upsert key). No attestation
//! logic is re-implemented here; the pure predicate [`resolve_grant`]
//! merely inspects the type of the newest row for the target dimension.
//!
//! # References
//!
//! - CIRISAgent#870 — consent-gate decision + the CEG-first / config-
//!   fallback / recant-hard-stop ladder.
//! - CIRISLensCore#34 — recant cascade: a recant arriving in any relay
//!   hop must propagate and stop emission immediately; this module is the
//!   chokepoint that enforces it.

use chrono::{DateTime, Utc};

// ── Public constants ─────────────────────────────────────────────────────────

/// The CEG dimension string for community-trust consent
/// (`consent:community_trust:v1`). Present as a constant so callers and
/// tests share a single definition — a typo in a string literal would
/// silently make consent perpetually absent.
pub const CONSENT_DIMENSION: &str = "consent:community_trust:v1";

// ── Pure predicate types ─────────────────────────────────────────────────────

/// The result of inspecting the attestation rows for [`CONSENT_DIMENSION`],
/// before the config fallback is considered. Used by [`resolve_grant`] and
/// consumed by [`resolve_consent`].
#[derive(Debug, Clone, PartialEq)]
pub enum GrantState {
    /// A `scores` or `supersedes` row is the newest word on the dimension.
    /// Emission is permitted under CEG authority.
    InForce {
        /// `asserted_at` of the newest granting row.
        asserted_at: DateTime<Utc>,
    },
    /// A `withdraws` or `recants` row is the newest word on the dimension.
    /// Emission MUST stop and MUST NOT fall back to config.
    Withdrawn {
        /// `asserted_at` of the newest withdrawal/recant row.
        at: DateTime<Utc>,
    },
    /// No rows exist for the dimension on this attesting key.
    Absent,
}

// ── Config fallback type ──────────────────────────────────────────────────────

/// Operator/environment-sourced consent, used when no CEG object exists yet
/// (the 2.9.6 interim path). Mirrors the agent's
/// `services.py:613-633` config/env sourcing: `CONSENT_TIMESTAMP` env var
/// or equivalent config key. An empty string is treated as `None` —
/// persist 422s a batch whose `consent_timestamp` is empty or missing
/// (TRACE_WIRE_FORMAT.md §1), so we normalize empty→absent here rather than
/// letting a batch fail downstream with a confusing error.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsentConfig {
    /// RFC-3339 consent timestamp from operator config/env, or `None` when
    /// not set. Empty string is treated as `None` (see struct-level doc).
    pub consent_timestamp: Option<String>,
}

impl ConsentConfig {
    /// Return the consent timestamp iff it is non-empty.
    fn effective_timestamp(&self) -> Option<&str> {
        self.consent_timestamp.as_deref().filter(|s| !s.is_empty())
    }
}

// ── Resolution output ─────────────────────────────────────────────────────────

/// Why emission is or isn't permitted, per CIRISAgent#870.
#[derive(Debug, Clone, PartialEq)]
pub enum ConsentResolution {
    /// CEG grant in force — `asserted_at` is the grant row's timestamp.
    /// Callers should use this as the `consent_timestamp` in the
    /// outbound [`BatchProvenance`](super::batch::BatchProvenance).
    CegGrant {
        /// `asserted_at` of the authoritative `scores`/`supersedes` row.
        asserted_at: DateTime<Utc>,
    },
    /// Config/env-sourced consent (the 2.9.6 interim path). No CEG object
    /// exists yet; the operator timestamp is the gate. Callers use
    /// `consent_timestamp` as the `BatchProvenance.consent_timestamp`.
    ConfigFallback {
        /// Timestamp string from operator config/env (non-empty, validated
        /// non-empty by [`resolve_consent`]).
        consent_timestamp: String,
    },
    /// A CEG `withdraws` or `recants` is the newest word on the dimension.
    /// **Emission MUST stop.** This variant is NEVER downgraded to config
    /// fallback — a withdrawal/recant cannot be overridden by operator
    /// config (CIRISAgent#870, CIRISLensCore#34 recant cascade).
    Withdrawn {
        /// `asserted_at` of the withdrawal/recant row.
        at: DateTime<Utc>,
    },
    /// No CEG object AND no config consent — emission refused.
    NoConsent,
}

// ── Error ────────────────────────────────────────────────────────────────────

/// Error fetching consent state from the persist Engine.
///
/// A directory READ ERROR maps to an error, not silently to
/// [`ConsentResolution::ConfigFallback`] — we fail closed. Consent state is
/// a safety gate; if we can't read the gate we must not emit, not silently
/// degrade to a weaker fallback. (Compare: a network partition cannot be
/// semantically equivalent to "no CEG object exists".)
#[derive(Debug, thiserror::Error)]
pub enum ConsentError {
    /// The federation directory returned an error while listing attestations.
    /// The inner string is the `Display` of the substrate error (matching
    /// the `HandlerError::Persist(e.to_string())` pattern in
    /// `src/role/handler.rs`).
    #[error("federation directory error reading consent attestations: {0}")]
    Directory(String),
}

// ── Pure predicate ────────────────────────────────────────────────────────────

/// Inspect a slice of attestation rows and return the [`GrantState`] for
/// [`CONSENT_DIMENSION`].
///
/// **Semantics (CIRISAgent#870 / `attestation.py` upsert model):**
/// The agent's model uses an (occurrence, dimension) upsert key — one
/// replaceable grant row per dimension — and `withdraws`/`recants` are
/// separate rows carrying the SAME dimension. So:
///
/// 1. Keep only rows whose `attestation_envelope.dimension` equals
///    [`CONSENT_DIMENSION`].
/// 2. Order by `(asserted_at DESC, attestation_id DESC)` — newest-first,
///    `attestation_id` desc as tiebreaker (matching the substrate cursor
///    ordering used by `list_attestations_by`).
/// 3. Inspect the **newest** row's `attestation_type`:
///    - `"scores"` or `"supersedes"` → [`GrantState::InForce`].
///    - `"withdraws"` or `"recants"` → [`GrantState::Withdrawn`].
/// 4. No matching rows → [`GrantState::Absent`].
///
/// Rows for other dimensions are ignored.
pub fn resolve_grant(rows: &[ciris_persist::federation::Attestation]) -> GrantState {
    // Filter to the target dimension.
    let mut matching: Vec<&ciris_persist::federation::Attestation> = rows
        .iter()
        .filter(|a| {
            a.attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
                == Some(CONSENT_DIMENSION)
        })
        .collect();

    if matching.is_empty() {
        return GrantState::Absent;
    }

    // Sort newest-first: (asserted_at DESC, attestation_id DESC).
    // `attestation_id` is a UUID string; lexicographic desc is correct for
    // the tiebreak since the substrate cursor ordering is also
    // (asserted_at DESC, attestation_id DESC) per AttestationCursor.
    matching.sort_by(|a, b| {
        b.asserted_at
            .cmp(&a.asserted_at)
            .then_with(|| b.attestation_id.cmp(&a.attestation_id))
    });

    let newest = matching[0];
    match newest.attestation_type.as_str() {
        "scores" | "supersedes" => GrantState::InForce {
            asserted_at: newest.asserted_at,
        },
        "withdraws" | "recants" => GrantState::Withdrawn {
            at: newest.asserted_at,
        },
        // Unknown type — treat as absent (fail open for forward-compat
        // with new attestation_type tokens; the grant must be explicit).
        _ => GrantState::Absent,
    }
}

// ── Combinator ────────────────────────────────────────────────────────────────

/// Combine a [`GrantState`] with operator [`ConsentConfig`] into a final
/// [`ConsentResolution`], implementing the CIRISAgent#870 ladder:
///
/// | GrantState        | Config present? | Resolution          |
/// |-------------------|-----------------|---------------------|
/// | `InForce`         | any             | `CegGrant`          |
/// | `Withdrawn`       | any             | `Withdrawn` (**NEVER** config) |
/// | `Absent`          | yes (non-empty) | `ConfigFallback`    |
/// | `Absent`          | no / empty      | `NoConsent`         |
///
/// The `Withdrawn→Withdrawn (not config)` row is the privacy-critical
/// invariant: a consent withdrawal/recant issued through the CEG MUST
/// stop emission even when operator config would otherwise permit it.
pub fn resolve_consent(grant: GrantState, config: &ConsentConfig) -> ConsentResolution {
    match grant {
        GrantState::InForce { asserted_at } => ConsentResolution::CegGrant { asserted_at },
        // PRIVACY-CRITICAL: a recant/withdrawal is a hard stop. Operator
        // config cannot revive emission after a CEG withdrawal. A recant
        // arriving via relay must propagate here (CIRISLensCore#34).
        GrantState::Withdrawn { at } => ConsentResolution::Withdrawn { at },
        GrantState::Absent => match config.effective_timestamp() {
            Some(ts) => ConsentResolution::ConfigFallback {
                consent_timestamp: ts.to_owned(),
            },
            None => ConsentResolution::NoConsent,
        },
    }
}

// ── Async Engine wrapper ──────────────────────────────────────────────────────

/// Fetch attestation rows for `attesting_key_id` via the Engine's federation
/// directory, then resolve consent using [`resolve_grant`] +
/// [`resolve_consent`].
///
/// Uses `FederationDirectory::list_attestations_by` (the `by`-issuer API on
/// the `FederationDirectory` trait) with in-memory dimension filtering in
/// [`resolve_grant`], because `list_attestations_by` is available on the
/// object-safe `Arc<dyn FederationDirectory>` returned by
/// `Engine::federation_directory()`, while the filtered
/// `ReadEngine::list_attestations` lives on backend-specific impls and
/// requires matching on `Engine::backend()`. Using the directory API avoids
/// that dispatch and keeps this module free of backend-specific types. The
/// in-memory filter is correct and cheap: the set of consent-dimension rows
/// per key is tiny in practice.
///
/// # Fail closed
///
/// A directory read error returns `Err(ConsentError::Directory(_))`, NOT
/// `Ok(ConsentResolution::ConfigFallback)`. Consent state is a safety gate;
/// inability to read the gate is not semantically equivalent to "no CEG
/// object exists". Callers must treat `Err` as "do not emit".
pub async fn resolve_consent_via_engine(
    engine: &ciris_persist::prelude::Engine,
    attesting_key_id: &str,
    config: &ConsentConfig,
) -> Result<ConsentResolution, ConsentError> {
    let dir = engine.federation_directory();
    let rows = dir
        .list_attestations_by(attesting_key_id)
        .await
        .map_err(|e| ConsentError::Directory(e.to_string()))?;
    let grant = resolve_grant(&rows);
    Ok(resolve_consent(grant, config))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ciris_persist::federation::Attestation;
    use serde_json::json;

    // Helper: build an Attestation row with just the fields resolve_grant
    // inspects. Non-semantic fields are filled with minimal valid strings.
    fn make_attestation(
        attestation_id: &str,
        attestation_type: &str,
        dimension: &str,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        Attestation {
            attestation_id: attestation_id.to_owned(),
            attesting_key_id: "test-key".to_owned(),
            attested_key_id: "test-key".to_owned(),
            attestation_type: attestation_type.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: json!({ "dimension": dimension }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2ln".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: "test-key".to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: "federation".to_owned(),
            promoted_at: None,
        }
    }

    fn ts(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn no_config() -> ConsentConfig {
        ConsentConfig {
            consent_timestamp: None,
        }
    }

    fn config_with(ts_str: &str) -> ConsentConfig {
        ConsentConfig {
            consent_timestamp: Some(ts_str.to_owned()),
        }
    }

    // (a) Single `scores` row → InForce
    #[test]
    fn single_scores_row_is_in_force() {
        let rows = vec![make_attestation("id-1", "scores", CONSENT_DIMENSION, ts(0))];
        assert_eq!(
            resolve_grant(&rows),
            GrantState::InForce { asserted_at: ts(0) }
        );
    }

    // (b) scores then LATER withdraws → Withdrawn (withdraws is newest)
    #[test]
    fn scores_then_later_withdraws_is_withdrawn() {
        let rows = vec![
            make_attestation("id-1", "scores", CONSENT_DIMENSION, ts(0)),
            make_attestation("id-2", "withdraws", CONSENT_DIMENSION, ts(10)),
        ];
        assert_eq!(resolve_grant(&rows), GrantState::Withdrawn { at: ts(10) });
    }

    // (c) withdraws then LATER scores (re-grant after withdrawal) → InForce
    #[test]
    fn re_grant_after_withdrawal_is_in_force() {
        let rows = vec![
            make_attestation("id-1", "withdraws", CONSENT_DIMENSION, ts(0)),
            make_attestation("id-2", "scores", CONSENT_DIMENSION, ts(20)),
        ];
        assert_eq!(
            resolve_grant(&rows),
            GrantState::InForce {
                asserted_at: ts(20)
            }
        );
    }

    // (d) recants newest → Withdrawn
    #[test]
    fn recants_newest_is_withdrawn() {
        let rows = vec![
            make_attestation("id-1", "scores", CONSENT_DIMENSION, ts(0)),
            make_attestation("id-2", "recants", CONSENT_DIMENSION, ts(5)),
        ];
        assert_eq!(resolve_grant(&rows), GrantState::Withdrawn { at: ts(5) });
    }

    // (e) rows on OTHER dimensions are ignored
    #[test]
    fn rows_on_other_dimensions_are_ignored() {
        let rows = vec![
            make_attestation("id-1", "scores", "consent:community_trust:v0", ts(0)),
            make_attestation("id-2", "withdraws", "accord:alignment:v1", ts(10)),
        ];
        // Neither row is for CONSENT_DIMENSION → Absent
        assert_eq!(resolve_grant(&rows), GrantState::Absent);
    }

    // (f) Absent + config timestamp → ConfigFallback
    #[test]
    fn absent_with_config_timestamp_gives_config_fallback() {
        let grant = GrantState::Absent;
        let cfg = config_with("2026-01-01T00:00:00Z");
        assert_eq!(
            resolve_consent(grant, &cfg),
            ConsentResolution::ConfigFallback {
                consent_timestamp: "2026-01-01T00:00:00Z".to_owned()
            }
        );
    }

    // (g) Absent + empty/None config → NoConsent
    #[test]
    fn absent_with_no_config_gives_no_consent() {
        assert_eq!(
            resolve_consent(GrantState::Absent, &no_config()),
            ConsentResolution::NoConsent
        );
        // Empty string is also treated as None (persist 422s empty
        // consent_timestamp).
        let empty_cfg = ConsentConfig {
            consent_timestamp: Some(String::new()),
        };
        assert_eq!(
            resolve_consent(GrantState::Absent, &empty_cfg),
            ConsentResolution::NoConsent
        );
    }

    // (h) Withdrawn + config present → STILL Withdrawn (privacy-critical)
    //
    // This is the load-bearing invariant from CIRISAgent#870 / LensCore#34:
    // a CEG recant/withdrawal CANNOT be overridden by operator config. If a
    // user has withdrawn consent, no config timestamp can revive emission.
    #[test]
    fn withdrawn_plus_config_is_still_withdrawn_never_config_fallback() {
        let grant = GrantState::Withdrawn { at: ts(99) };
        let cfg = config_with("2026-01-01T00:00:00Z");
        // Must remain Withdrawn, not ConfigFallback.
        assert_eq!(
            resolve_consent(grant, &cfg),
            ConsentResolution::Withdrawn { at: ts(99) }
        );
    }

    // (i) `supersedes` newest → InForce with the supersedes row's asserted_at
    #[test]
    fn supersedes_newest_is_in_force() {
        let rows = vec![
            make_attestation("id-1", "scores", CONSENT_DIMENSION, ts(0)),
            make_attestation("id-2", "supersedes", CONSENT_DIMENSION, ts(50)),
        ];
        assert_eq!(
            resolve_grant(&rows),
            GrantState::InForce {
                asserted_at: ts(50)
            }
        );
    }

    // (j) tiebreak: same asserted_at → attestation_id desc (lexicographic)
    #[test]
    fn tiebreak_same_asserted_at_uses_attestation_id_desc() {
        let same_ts = ts(0);
        // "zzz-withdraws" sorts after "aaa-scores" lexicographically, so
        // it should win the DESC tiebreak and make this Withdrawn.
        let rows = vec![
            make_attestation("aaa-scores", "scores", CONSENT_DIMENSION, same_ts),
            make_attestation("zzz-withdraws", "withdraws", CONSENT_DIMENSION, same_ts),
        ];
        assert_eq!(resolve_grant(&rows), GrantState::Withdrawn { at: same_ts });

        // And the reverse: "zzz-scores" wins over "aaa-withdraws" → InForce.
        let rows2 = vec![
            make_attestation("aaa-withdraws", "withdraws", CONSENT_DIMENSION, same_ts),
            make_attestation("zzz-scores", "scores", CONSENT_DIMENSION, same_ts),
        ];
        assert_eq!(
            resolve_grant(&rows2),
            GrantState::InForce {
                asserted_at: same_ts
            }
        );
    }

    // Bonus: combinator: InForce → CegGrant regardless of config
    #[test]
    fn in_force_gives_ceg_grant() {
        let grant = GrantState::InForce { asserted_at: ts(7) };
        let cfg = config_with("2026-01-01T00:00:00Z");
        assert_eq!(
            resolve_consent(grant, &cfg),
            ConsentResolution::CegGrant { asserted_at: ts(7) }
        );
    }
}
