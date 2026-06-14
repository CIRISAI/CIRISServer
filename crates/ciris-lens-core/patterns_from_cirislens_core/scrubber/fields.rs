//! Authoritative SCRUB_FIELDS list. Mirrors the consolidated v1 final state
//! plus the IDMA result fields and DMA structured-output fields that the
//! original walker missed.
//!
//! Stored as a HashSet for O(1) lookup. Updates require a code change —
//! intentional, since SCRUB_FIELDS is part of the security boundary.

use lazy_static::lazy_static;
use std::collections::HashSet;

lazy_static! {
    pub static ref SCRUB_FIELDS: HashSet<&'static str> = {
        let mut s = HashSet::new();

        // THOUGHT_START
        s.insert("task_description");
        s.insert("initial_context");
        s.insert("thought_content");

        // SNAPSHOT_AND_CONTEXT
        s.insert("system_snapshot");
        s.insert("gathered_context");
        s.insert("relevant_memories");
        s.insert("conversation_history");
        s.insert("current_thought_summary");

        // DMA_RESULTS
        s.insert("reasoning");
        s.insert("prompt_used");
        s.insert("combined_analysis");
        s.insert("flags");
        s.insert("alignment_check");
        s.insert("conflicts");
        s.insert("stakeholders");

        // ASPDMA_RESULT
        s.insert("action_rationale");
        s.insert("reasoning_summary");
        s.insert("action_parameters");
        s.insert("aspdma_prompt");
        s.insert("questions");
        s.insert("completion_reason");

        // CONSCIENCE_RESULT
        s.insert("conscience_override_reason");
        s.insert("epistemic_data");
        s.insert("updated_status_content");
        s.insert("entropy_reason");
        s.insert("coherence_reason");
        s.insert("optimization_veto_justification");
        s.insert("epistemic_humility_justification");
        s.insert("epistemic_humility_uncertainties");

        // ACTION_RESULT
        s.insert("execution_error");

        // IDMA_RESULT
        s.insert("intervention_recommendation");
        s.insert("next_best_recovery_step");
        s.insert("correlation_factors");
        s.insert("top_correlation_factors");
        s.insert("common_cause_flags");
        s.insert("sources_identified");
        s.insert("source_ids");
        s.insert("source_clusters");
        s.insert("source_types");
        s.insert("source_type_counts");
        s.insert("pairwise_correlation_summary");
        s.insert("reasoning_state");

        s
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_fields_present() {
        assert!(SCRUB_FIELDS.contains("task_description"));
        assert!(SCRUB_FIELDS.contains("flags"));
        assert!(SCRUB_FIELDS.contains("source_ids"));
        assert!(SCRUB_FIELDS.contains("thought_content"));
    }

    #[test]
    fn random_field_absent() {
        assert!(!SCRUB_FIELDS.contains("random_field_name"));
        assert!(!SCRUB_FIELDS.contains("agent_name"));
    }

    #[test]
    fn field_count_sanity() {
        // Ballpark: ~40 fields. If this drops massively, we lost coverage.
        // If it explodes, we may be over-scrubbing. Either is worth a review.
        let n = SCRUB_FIELDS.len();
        assert!(n >= 35, "SCRUB_FIELDS shrunk to {n} — coverage regression?");
        assert!(n <= 60, "SCRUB_FIELDS grew to {n} — review for over-scope?");
    }
}
