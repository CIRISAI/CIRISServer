//! Declared cohort axes — the agent-asserted 6-tuple from the trace's
//! `deployment_profile` block.
//!
//! # Source of truth
//!
//! Wire spec: CIRISAgent FSD `TRACE_WIRE_FORMAT.md` §3.2. Six fields,
//! all required at `trace_schema_version 2.7.9`:
//!
//! ```text
//! agent_role, agent_template, deployment_domain, deployment_type,
//! deployment_region, deployment_trust_mode
//! ```
//!
//! Persist's `extract` stage walks the envelope and populates
//! [`DeclaredCohortAxes`]; lens-core consumes the typed struct
//! rather than re-parsing the envelope. This module is the
//! `DeclaredCohortAxes → cohort_cell JSON` boundary that signed
//! [`DetectionEvent`][de] rows carry.
//!
//! # Wire-shape vs cohort-cell-shape
//!
//! `DeclaredCohortAxes` uses `Option<String>` for each field (tolerance
//! against pre-2.7.9 traces). The cohort_cell JSON object carries
//! `null` for absent fields rather than omitting them — preserves
//! the 6-key shape across deserializers and lets downstream
//! consumers distinguish "field was declared as null" from "field
//! was missing entirely."
//!
//! # LC-AV-2 use
//!
//! [`is_complete`] flags the "agent declined to declare a cohort
//! identity" edge case. LC-AV-2 mismatch detection short-circuits
//! when declared is incomplete — there's nothing to compare against
//! the inferred cohort, so [`crate::scoring::AssemblyInput::AmbiguousCohort`]
//! is the appropriate fall-through (no LC-AV-2 firing on a trace
//! that didn't claim a cohort identity in the first place).
//!
//! [de]: ciris_persist::prelude::DetectionEvent

use ciris_persist::pipeline::extract::DeclaredCohortAxes;
use serde_json::{json, Value};

/// Pull the agent-declared 6-tuple out of a trace envelope's body.
/// The wire format places these fields under
/// `deployment_profile.{agent_role, agent_template, ...}` per
/// CIRISAgent FSD §3.2.
///
/// Absent fields land as `None` rather than erroring — wire spec
/// §3.2 makes them required at 2.7.9 but pre-2.7.9 traces and
/// development-mode emissions may omit some; the orchestrator
/// routes incomplete-declared traces through
/// [`crate::scoring::AssemblyInput::AmbiguousCohort`].
pub fn parse_from_envelope(body: &Value) -> DeclaredCohortAxes {
    let profile = body.get("deployment_profile");
    let s = |field: &str| -> Option<String> {
        profile
            .and_then(|p| p.get(field))
            .and_then(Value::as_str)
            .map(String::from)
    };
    DeclaredCohortAxes {
        agent_role: s("agent_role"),
        agent_template: s("agent_template"),
        deployment_domain: s("deployment_domain"),
        deployment_type: s("deployment_type"),
        deployment_region: s("deployment_region"),
        deployment_trust_mode: s("deployment_trust_mode"),
    }
}

/// Build the cohort_cell JSON object from a declared 6-tuple. Absent
/// fields render as JSON `null` rather than being omitted, preserving
/// the 6-key shape.
pub fn cohort_cell(axes: &DeclaredCohortAxes) -> Value {
    json!({
        "agent_role":            axes.agent_role,
        "agent_template":        axes.agent_template,
        "deployment_domain":     axes.deployment_domain,
        "deployment_type":       axes.deployment_type,
        "deployment_region":     axes.deployment_region,
        "deployment_trust_mode": axes.deployment_trust_mode,
    })
}

/// True when all six declared axes are present. False when ≥1 axis
/// is `None` — pre-2.7.9 trace, malformed agent emission, or
/// (legitimately) operator hasn't completed configuration.
pub fn is_complete(axes: &DeclaredCohortAxes) -> bool {
    axes.agent_role.is_some()
        && axes.agent_template.is_some()
        && axes.deployment_domain.is_some()
        && axes.deployment_type.is_some()
        && axes.deployment_region.is_some()
        && axes.deployment_trust_mode.is_some()
}

/// Names of any axes that are `None`. Returns empty when
/// [`is_complete`]. Diagnostic / observability surface; not a hot
/// path.
pub fn missing_axes(axes: &DeclaredCohortAxes) -> Vec<&'static str> {
    let mut out = Vec::new();
    if axes.agent_role.is_none() {
        out.push("agent_role");
    }
    if axes.agent_template.is_none() {
        out.push("agent_template");
    }
    if axes.deployment_domain.is_none() {
        out.push("deployment_domain");
    }
    if axes.deployment_type.is_none() {
        out.push("deployment_type");
    }
    if axes.deployment_region.is_none() {
        out.push("deployment_region");
    }
    if axes.deployment_trust_mode.is_none() {
        out.push("deployment_trust_mode");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_axes() -> DeclaredCohortAxes {
        DeclaredCohortAxes {
            agent_role: Some("ally".into()),
            agent_template: Some("ally-v3-default".into()),
            deployment_domain: Some("moderation".into()),
            deployment_type: Some("production".into()),
            deployment_region: Some("US".into()),
            deployment_trust_mode: Some("federated_peer".into()),
        }
    }

    #[test]
    fn full_axes_render_all_six_keys() {
        let cell = cohort_cell(&full_axes());
        assert_eq!(cell["agent_role"], "ally");
        assert_eq!(cell["agent_template"], "ally-v3-default");
        assert_eq!(cell["deployment_domain"], "moderation");
        assert_eq!(cell["deployment_type"], "production");
        assert_eq!(cell["deployment_region"], "US");
        assert_eq!(cell["deployment_trust_mode"], "federated_peer");
    }

    #[test]
    fn cohort_cell_is_object_with_exactly_six_keys() {
        let cell = cohort_cell(&full_axes());
        let obj = cell.as_object().expect("cohort_cell is JSON object");
        assert_eq!(obj.len(), 6, "expected exactly 6 keys, got {}", obj.len());
        for key in [
            "agent_role",
            "agent_template",
            "deployment_domain",
            "deployment_type",
            "deployment_region",
            "deployment_trust_mode",
        ] {
            assert!(obj.contains_key(key), "missing key: {key}");
        }
    }

    #[test]
    fn missing_axes_render_as_null_not_omitted() {
        // Preserves 6-key shape so downstream deserializers can
        // distinguish "null" from "missing entirely". Wire spec §3.2
        // says `deployment_region: null` is a valid "not disclosed"
        // declaration; absence-of-field is malformed.
        let mut axes = full_axes();
        axes.deployment_region = None;
        let cell = cohort_cell(&axes);
        assert!(cell["deployment_region"].is_null());
        assert_eq!(cell.as_object().unwrap().len(), 6);
    }

    #[test]
    fn all_absent_axes_render_six_nulls() {
        let axes = DeclaredCohortAxes::default();
        let cell = cohort_cell(&axes);
        let obj = cell.as_object().unwrap();
        assert_eq!(obj.len(), 6);
        for v in obj.values() {
            assert!(v.is_null());
        }
    }

    #[test]
    fn is_complete_true_for_full_six_tuple() {
        assert!(is_complete(&full_axes()));
    }

    #[test]
    fn is_complete_false_when_any_axis_absent() {
        for unset in 0..6 {
            let mut axes = full_axes();
            match unset {
                0 => axes.agent_role = None,
                1 => axes.agent_template = None,
                2 => axes.deployment_domain = None,
                3 => axes.deployment_type = None,
                4 => axes.deployment_region = None,
                5 => axes.deployment_trust_mode = None,
                _ => unreachable!(),
            }
            assert!(
                !is_complete(&axes),
                "is_complete should be false when axis {unset} is None"
            );
        }
    }

    #[test]
    fn missing_axes_empty_for_full_six_tuple() {
        assert!(missing_axes(&full_axes()).is_empty());
    }

    #[test]
    fn missing_axes_lists_all_absent() {
        let mut axes = full_axes();
        axes.agent_role = None;
        axes.deployment_trust_mode = None;
        let missing = missing_axes(&axes);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"agent_role"));
        assert!(missing.contains(&"deployment_trust_mode"));
    }

    #[test]
    fn missing_axes_returns_all_six_when_all_absent() {
        let missing = missing_axes(&DeclaredCohortAxes::default());
        assert_eq!(missing.len(), 6);
    }

    #[test]
    fn cohort_cell_round_trips_through_deserialize() {
        // Persist stores cohort_cell as JSONB; on read, downstream
        // consumers may deserialize back to DeclaredCohortAxes.
        // Verify the round-trip preserves all six fields including
        // null declarations.
        let mut axes = full_axes();
        axes.deployment_region = None;
        let cell = cohort_cell(&axes);
        let recovered: DeclaredCohortAxes =
            serde_json::from_value(cell).expect("cohort_cell deserializes to DeclaredCohortAxes");
        assert_eq!(recovered.agent_role, axes.agent_role);
        assert_eq!(recovered.deployment_region, None);
        assert_eq!(recovered.deployment_trust_mode, axes.deployment_trust_mode);
    }
}
