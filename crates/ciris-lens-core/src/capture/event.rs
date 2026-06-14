//! Reasoning-event taxonomy — the typed wire contract for the agent's
//! `reasoning_event_stream` (CIRISLensCore#11, client/emit path).
//!
//! # Why this is a closed enum, not a string
//!
//! The agent's legacy `accord_metrics/services.py` carried the event
//! taxonomy as a `str`-keyed `EVENT_TO_COMPONENT` dict + a parallel
//! `parent_event_type` normalization map. That string-keyed shape is
//! exactly what produced the wire-contract drift incidents in
//! CIRISAgent#757 (an event type renamed upstream, the consumer's map
//! not updated, traces silently mis-componented) and CIRISLens#13
//! (a bridge diagnostic cycle chasing a one-character event-name
//! typo). Lens-core's #11 acceptance bar is that those incidents are
//! **structurally prevented — compile-time, not test-time.**
//!
//! A closed Rust enum is that structural prevention: a new event type
//! cannot be emitted without adding a variant here, and the
//! [`component_type`](ReasoningEventType::component_type) mapping is an
//! exhaustive `match` the compiler forces to stay total. The
//! `EVENT_TO_COMPONENT` table can no longer silently lack an entry.
//!
//! # Dual wire forms
//!
//! The agent's stream emits event types in two interchangeable string
//! forms — bare (`"THOUGHT_START"`) and enum-qualified
//! (`"ReasoningEvent.THOUGHT_START"`, the Python `str(enum_member)`
//! form). [`ReasoningEventType::parse`] normalizes both to one variant;
//! [`ReasoningEventType::as_wire_str`] always emits the bare canonical
//! form into the signed trace.

/// A reasoning-event type from the agent's `reasoning_event_stream`.
///
/// Closed enumeration — adding a variant is a deliberate wire-contract
/// change reviewed at compile time. The canonical wire string is the
/// SCREAMING_SNAKE_CASE bare form ([`as_wire_str`](Self::as_wire_str));
/// [`parse`](Self::parse) accepts both that and the `ReasoningEvent.`
/// enum-qualified form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasoningEventType {
    /// `THOUGHT_START` — a thought begins processing. Opens a trace.
    ThoughtStart,
    /// `SNAPSHOT_AND_CONTEXT` — system snapshot + assembled context.
    SnapshotAndContext,
    /// `DMA_RESULTS` — the three baseline DMA results (CSDMA / DSDMA / PDMA).
    DmaResults,
    /// `IDMA_RESULT` — Intuition-DMA fragility check.
    IdmaResult,
    /// `ASPDMA_RESULT` — action-selection PDMA result.
    AspdmaResult,
    /// `TSASPDMA_RESULT` — **DEPRECATED** legacy two-step ASPDMA;
    /// superseded by [`VerbSecondPassResult`](Self::VerbSecondPassResult).
    /// Retained so historical / in-flight streams still parse; new
    /// emissions SHOULD use `VERB_SECOND_PASS_RESULT`.
    TsaspdmaResult,
    /// `VERB_SECOND_PASS_RESULT` — generic verb-specific second pass.
    VerbSecondPassResult,
    /// `CONSCIENCE_RESULT` — conscience evaluation outcome.
    ConscienceResult,
    /// `ACTION_RESULT` — final action + execution outcome + audit data.
    /// **Seals the trace** (see [`seals_trace`](Self::seals_trace)).
    ActionResult,
    /// `LLM_CALL` — per-provider-call sub-pipeline observation.
    LlmCall,
    /// `DEFERRAL_ROUTED` — Commons-Credits: a deferral was routed.
    DeferralRouted,
    /// `DEFERRAL_RECEIVED` — Commons-Credits: a deferral was received.
    DeferralReceived,
    /// `DEFERRAL_RESOLVED` — Commons-Credits: a deferral was resolved.
    DeferralResolved,
    /// `GRATITUDE_SIGNALED` — Commons-Credits: gratitude signal.
    GratitudeSignaled,
    /// `CREDIT_GENERATED` — Commons-Credits: a credit was generated.
    CreditGenerated,
}

/// The trace-component bucket an event type contributes to. Several
/// event types fold into one component (e.g. all four DMA-family events
/// → `rationale`); the wire string is the component's snake_case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentType {
    /// `observation` — what triggered processing.
    Observation,
    /// `context` — system snapshot + assembled context.
    Context,
    /// `rationale` — DMA reasoning analysis (DMA / IDMA / ASPDMA / TSASPDMA).
    Rationale,
    /// `verb_second_pass` — verb-specific second-pass result.
    VerbSecondPass,
    /// `conscience` — conscience evaluation.
    Conscience,
    /// `action` — final action + outcome.
    Action,
    /// `llm_call` — per-provider LLM-call observation.
    LlmCall,
    /// `deferral_routed` — Commons-Credits deferral routing.
    DeferralRouted,
    /// `deferral_received` — Commons-Credits deferral receipt.
    DeferralReceived,
    /// `deferral_resolved` — Commons-Credits deferral resolution.
    DeferralResolved,
    /// `gratitude_signaled` — Commons-Credits gratitude signal.
    GratitudeSignaled,
    /// `credit_generated` — Commons-Credits credit generation.
    CreditGenerated,
}

impl ComponentType {
    /// The snake_case wire string carried in `TraceComponent.component_type`.
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Context => "context",
            Self::Rationale => "rationale",
            Self::VerbSecondPass => "verb_second_pass",
            Self::Conscience => "conscience",
            Self::Action => "action",
            Self::LlmCall => "llm_call",
            Self::DeferralRouted => "deferral_routed",
            Self::DeferralReceived => "deferral_received",
            Self::DeferralResolved => "deferral_resolved",
            Self::GratitudeSignaled => "gratitude_signaled",
            Self::CreditGenerated => "credit_generated",
        }
    }
}

/// Prefix the agent's `str(ReasoningEvent.X)` form carries.
const ENUM_QUALIFIER: &str = "ReasoningEvent.";

impl ReasoningEventType {
    /// Every variant, in declaration order. The closed-enum membership
    /// lock — `ALL.len()` is the wire-stable count of known event types.
    pub const ALL: [ReasoningEventType; 15] = [
        Self::ThoughtStart,
        Self::SnapshotAndContext,
        Self::DmaResults,
        Self::IdmaResult,
        Self::AspdmaResult,
        Self::TsaspdmaResult,
        Self::VerbSecondPassResult,
        Self::ConscienceResult,
        Self::ActionResult,
        Self::LlmCall,
        Self::DeferralRouted,
        Self::DeferralReceived,
        Self::DeferralResolved,
        Self::GratitudeSignaled,
        Self::CreditGenerated,
    ];

    /// The bare canonical SCREAMING_SNAKE_CASE wire string. This is what
    /// lens-core writes into the signed trace, regardless of which form
    /// the inbound stream used.
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::ThoughtStart => "THOUGHT_START",
            Self::SnapshotAndContext => "SNAPSHOT_AND_CONTEXT",
            Self::DmaResults => "DMA_RESULTS",
            Self::IdmaResult => "IDMA_RESULT",
            Self::AspdmaResult => "ASPDMA_RESULT",
            Self::TsaspdmaResult => "TSASPDMA_RESULT",
            Self::VerbSecondPassResult => "VERB_SECOND_PASS_RESULT",
            Self::ConscienceResult => "CONSCIENCE_RESULT",
            Self::ActionResult => "ACTION_RESULT",
            Self::LlmCall => "LLM_CALL",
            Self::DeferralRouted => "DEFERRAL_ROUTED",
            Self::DeferralReceived => "DEFERRAL_RECEIVED",
            Self::DeferralResolved => "DEFERRAL_RESOLVED",
            Self::GratitudeSignaled => "GRATITUDE_SIGNALED",
            Self::CreditGenerated => "CREDIT_GENERATED",
        }
    }

    /// The trace component this event contributes to. Exhaustive `match`
    /// — the compiler guarantees every event type has a component
    /// mapping (the structural fix for the CIRISAgent#757 missing-entry
    /// class).
    pub const fn component_type(self) -> ComponentType {
        match self {
            Self::ThoughtStart => ComponentType::Observation,
            Self::SnapshotAndContext => ComponentType::Context,
            // The DMA family all fold into `rationale`.
            Self::DmaResults | Self::IdmaResult | Self::AspdmaResult | Self::TsaspdmaResult => {
                ComponentType::Rationale
            }
            Self::VerbSecondPassResult => ComponentType::VerbSecondPass,
            Self::ConscienceResult => ComponentType::Conscience,
            Self::ActionResult => ComponentType::Action,
            Self::LlmCall => ComponentType::LlmCall,
            Self::DeferralRouted => ComponentType::DeferralRouted,
            Self::DeferralReceived => ComponentType::DeferralReceived,
            Self::DeferralResolved => ComponentType::DeferralResolved,
            Self::GratitudeSignaled => ComponentType::GratitudeSignaled,
            Self::CreditGenerated => ComponentType::CreditGenerated,
        }
    }

    /// Does this event seal the trace? Only `ACTION_RESULT` does — it
    /// carries the final action + outcome, after which the trace is
    /// canonicalized + signed + persisted.
    pub const fn seals_trace(self) -> bool {
        matches!(self, Self::ActionResult)
    }

    /// Parse an inbound event-type string. Accepts both the bare form
    /// (`"THOUGHT_START"`) and the Python enum-qualified form
    /// (`"ReasoningEvent.THOUGHT_START"`). Returns `None` for an
    /// unknown event type — the caller decides whether an unknown event
    /// is a hard error or a logged-and-dropped event (lens-core's
    /// client treats it as a typed rejection, never a silent
    /// mis-component).
    pub fn parse(raw: &str) -> Option<Self> {
        let bare = raw.strip_prefix(ENUM_QUALIFIER).unwrap_or(raw);
        Self::ALL.into_iter().find(|ev| ev.as_wire_str() == bare)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_has_fifteen_variants() {
        // Closed-enum lock: the known event taxonomy is exactly 15.
        // Adding a 16th requires a variant here + a component mapping +
        // a deliberate bump of this count — the wire-contract change is
        // forced through code review.
        assert_eq!(ReasoningEventType::ALL.len(), 15);
    }

    #[test]
    fn every_variant_round_trips_through_bare_form() {
        for ev in ReasoningEventType::ALL {
            assert_eq!(ReasoningEventType::parse(ev.as_wire_str()), Some(ev));
        }
    }

    #[test]
    fn every_variant_round_trips_through_enum_qualified_form() {
        // The agent's `str(ReasoningEvent.X)` form must normalize to the
        // same variant — this is the parent_event_type normalization the
        // legacy Python did with a parallel dict, now compile-time.
        for ev in ReasoningEventType::ALL {
            let qualified = format!("ReasoningEvent.{}", ev.as_wire_str());
            assert_eq!(ReasoningEventType::parse(&qualified), Some(ev));
        }
    }

    #[test]
    fn unknown_event_type_is_none_not_a_guess() {
        // The CIRISLens#13 class: a typo'd / renamed event type must
        // surface as None (typed rejection), never get silently bucketed.
        assert_eq!(ReasoningEventType::parse("THOUGHT_STRT"), None);
        assert_eq!(ReasoningEventType::parse("ReasoningEvent.NOPE"), None);
        assert_eq!(ReasoningEventType::parse(""), None);
        assert_eq!(ReasoningEventType::parse("ReasoningEvent."), None);
    }

    #[test]
    fn dma_family_all_map_to_rationale() {
        // The four DMA-family events fold into one component. If any
        // drifts, cohort/rationale aggregation downstream silently
        // changes — lock it.
        for ev in [
            ReasoningEventType::DmaResults,
            ReasoningEventType::IdmaResult,
            ReasoningEventType::AspdmaResult,
            ReasoningEventType::TsaspdmaResult,
        ] {
            assert_eq!(ev.component_type(), ComponentType::Rationale);
        }
    }

    #[test]
    fn component_wire_strings_locked() {
        // The EVENT_TO_COMPONENT contract, asserted exactly against the
        // legacy services.py table so the port is wire-identical.
        let cases = [
            (ReasoningEventType::ThoughtStart, "observation"),
            (ReasoningEventType::SnapshotAndContext, "context"),
            (ReasoningEventType::DmaResults, "rationale"),
            (ReasoningEventType::VerbSecondPassResult, "verb_second_pass"),
            (ReasoningEventType::ConscienceResult, "conscience"),
            (ReasoningEventType::ActionResult, "action"),
            (ReasoningEventType::LlmCall, "llm_call"),
            (ReasoningEventType::DeferralRouted, "deferral_routed"),
            (ReasoningEventType::DeferralReceived, "deferral_received"),
            (ReasoningEventType::DeferralResolved, "deferral_resolved"),
            (ReasoningEventType::GratitudeSignaled, "gratitude_signaled"),
            (ReasoningEventType::CreditGenerated, "credit_generated"),
        ];
        for (ev, expected) in cases {
            assert_eq!(ev.component_type().as_wire_str(), expected);
        }
    }

    #[test]
    fn only_action_result_seals() {
        for ev in ReasoningEventType::ALL {
            assert_eq!(ev.seals_trace(), ev == ReasoningEventType::ActionResult);
        }
    }
}
