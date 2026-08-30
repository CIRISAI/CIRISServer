//! **The mesh-config CONSUMERS** (CIRISServer#365) — the loops in this build
//! that actually read persist's [`mesh_config`](ciris_persist::federation::mesh_config)
//! plane and change what they do because of it.
//!
//! # The defect this module exists to remove
//!
//! [`crate::mesh_config_surface`] shipped the plane's read and its two write
//! paths, and every signal an operator had said the setting took effect: the
//! row admitted, the fold ran, the provenance rendered, the TTL ticked. **And
//! nothing read the value.** persist states plainly that it consumes none of
//! the eleven keys — every consumer is a downstream loop, here or in edge — and
//! this repo had a caller for none of them.
//!
//! > An unbuilt plane refuses. **A plane with no consumer confirms.**
//!
//! That is worse than the gap it looks like, because the surface makes the
//! setting *visibly successful*. So this module does two things, and the first
//! one matters even where the second is impossible:
//!
//! 1. **It says which keys have a consumer in THIS build** ([`consumption`]),
//!    so the read surface can print `consumed: false` beside `effective: 10`.
//!    `effective: 10` alone is a false statement about the system;
//!    `effective: 10, consumed: false` is a true one.
//! 2. **It is the only way to read a folded value**, so the flag cannot drift
//!    from the fact — see the next section.
//!
//! # Why `consumed` is not a hand-maintained literal
//!
//! This codebase has been bitten repeatedly by restated values that fork from
//! their source (`src/location.rs` reads persist's resolution bound rather than
//! writing it down; the harness restated the consent prefixes for eight
//! releases while production shipped a different set). A `consumed` column
//! maintained by hand would be exactly that defect wearing the costume of its
//! own cure.
//!
//! So it is derived, structurally, in two steps:
//!
//! - [`EffectiveMeshConfig`] keeps its [`MeshConfigFold`] **private**. The only
//!   way any code in this crate can obtain a folded value is one of the
//!   per-key accessors below. A key with no accessor is unreadable by
//!   construction, so it cannot have a consumer; a key with an accessor can.
//! - `tests/mesh_config_consumers.rs` then proves the *actual* half: every key
//!   this module reports [`Consumption::Wired`] names an accessor that is
//!   **called from outside this module**, in non-test code. Delete the call and
//!   the gate goes red — which is the mutation that was run.
//!
//! Neither half alone is enough. An accessor nobody calls is the original
//! defect; a call site with no accessor cannot exist.
//!
//! # Reading the plane: one fold, one read path
//!
//! The value comes from [`crate::mesh_config_surface::resolve_fold`] — the
//! SAME snapshot-and-fold the operator surface renders, which is persist's own
//! pure [`fold_mesh_config`](ciris_persist::federation::mesh_config::fold_mesh_config)
//! over rows gathered per subscribed trust root. There is no second read path,
//! so what a consumer honours and what the tab prints cannot disagree — the
//! `#541` two-lists-that-differ shape, refused up front.
//!
//! It is re-folded on a cadence ([`REFRESH_INTERVAL`]) rather than per request,
//! for two reasons: the read touches the directory once per subscribed root and
//! belongs nowhere near a hot path, and **the fold is TTL-evaluated at `now`**,
//! so an emergency relief that expires must stop applying without anyone
//! filing anything. A consumer that only read at boot would keep a 72-hour
//! relief forever, which is the same class of lie as not reading it at all.
//!
//! # Three zeroes, and what each one makes a consumer do
//!
//! *"The key is unset"*, *"the key is set to zero"* and *"we could not read the
//! plane"* are three different facts ([`Reading`]).
//!
//! - **Folded, not relieved** — no root moved it; the value IS the owner's own
//!   baseline. The consumer runs it.
//! - **Folded, relieved** — a root moved it. Same code path; the difference is
//!   attribution, which the surface already renders.
//! - **Unreadable** — the consumer applies NOTHING and keeps the behaviour it
//!   had before this module existed. It does *not* treat an unreadable plane as
//!   "no relief is in force", because that is a claim, and the whole point of
//!   this issue is to stop making claims the system cannot support. Every key
//!   wired here has an owner default on the side of *more* flow, so the
//!   unreadable arm is also the arm that never quietly narrows a node on the
//!   strength of a failed read.
//!
//! A **partial** read — some subscribed roots readable, some not — is honoured
//! rather than discarded, and that is safe in one direction only, which is the
//! direction it happens to be: the cross-root fold is most-restrictive, so a
//! root that could not be read can only ever have made the answer *tighter*.
//! Honouring the partial fold therefore under-relieves and never over-relieves,
//! and can never exceed the owner's baseline. The operator surface still calls
//! the plane `unreadable` when any root fails, because a *reading* and a
//! *report* answer different questions.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ciris_persist::federation::{MeshConfigFold, MeshConfigKey};
use ciris_persist::prelude::Engine;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How often the refresh loop re-folds the plane.
///
/// Emergency relief is bounded in hours (persist's `EMERGENCY_MAX_TTL_HOURS`),
/// so a minute is far finer than anything the plane can express — the cadence
/// exists so a relief ARRIVES and EXPIRES without a restart, not to chase
/// sub-minute precision.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

// ═══════════════════════════════════════════════════════════════════════════
//  Which keys this build consumes — the honest interim, and the permanent one
// ═══════════════════════════════════════════════════════════════════════════

/// **Does a loop in THIS build read this key?**
///
/// Four arms, because "nobody reads it" is not one fact. A key whose consumer
/// lives in edge is a wiring gap in a component that exists; a key whose
/// consumer runs HERE but cannot be reached from this plane is a missing setter
/// in a component that ships; a key whose consumer does not exist anywhere is a
/// design gap. An operator deciding whether to file a bug — and against which
/// repo — needs to know which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consumption {
    /// A loop in this build reads the key through `site` and changes what it
    /// does. `site` is the [`EffectiveMeshConfig`] accessor; the gate test
    /// requires it to be CALLED from outside this module in non-test code.
    Wired {
        /// The accessor the consumer reads through.
        site: &'static str,
        /// Where the change lands — the module, for an operator reading a log.
        effect: &'static str,
    },
    /// No loop in this build reads it; the consumer lives in another
    /// component. Setting it here admits a row and changes nothing **on this
    /// node** — it may still change something wherever `owner` runs.
    Elsewhere {
        /// The component that owns the consumer.
        owner: &'static str,
        /// The issue tracking its adoption there.
        tracked_by: &'static str,
    },
    /// v30.0.0 adoption (CIRISPersist#602) — **the consumer runs in THIS
    /// process and this plane still cannot reach it.**
    ///
    /// Distinct from [`Elsewhere`](Self::Elsewhere), which points an operator
    /// at another component's runtime: here the loop is composed by this
    /// binary, so "it may still change something wherever the owner runs" is
    /// false — there is nowhere else for it to take effect. Distinct from
    /// [`Unbuilt`](Self::Unbuilt), which says no consumer exists; one does.
    ///
    /// The arm exists because the two facts an operator needs are different
    /// bugs to file. `blocker` names the thing that must change.
    Unreachable {
        /// The component that owns the knob the consumer reads.
        owner: &'static str,
        /// **Why the value cannot reach it** — one sentence, addressed to
        /// whoever would otherwise wire it.
        blocker: &'static str,
        /// The issue tracking the missing path.
        tracked_by: &'static str,
    },
    /// The consumer does not exist anywhere yet. Setting it admits a row and
    /// changes nothing, in any component.
    Unbuilt {
        /// The issue the missing consumer rides.
        tracked_by: &'static str,
    },
}

impl Consumption {
    /// **The whole point of the field**: is there a consumer here?
    #[must_use]
    pub const fn consumed(self) -> bool {
        matches!(self, Self::Wired { .. })
    }

    /// The stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Wired { .. } => "wired",
            Self::Elsewhere { .. } => "elsewhere",
            Self::Unreachable { .. } => "unreachable",
            Self::Unbuilt { .. } => "unbuilt",
        }
    }

    /// The localizable message id for this arm. DERIVED from the token, so the
    /// id set cannot drift from the arm set.
    #[must_use]
    pub fn message_id(self) -> String {
        format!("mesh_config.consumption.{}", self.as_str())
    }

    /// The English source for [`Self::message_id`].
    #[must_use]
    pub const fn message_text(self) -> &'static str {
        match self {
            Self::Wired { .. } => {
                "A loop in this build reads this key and changes what it does. The effective \
                 value beside it is in force on this node."
            }
            Self::Elsewhere { .. } => {
                "No loop in this build reads this key — its consumer lives in another component. \
                 A row set here is admitted and folded, and changes nothing on this node."
            }
            Self::Unreachable { .. } => {
                "This key's consumer runs in this process, but nothing carries a value from this \
                 plane to it: the component that owns the knob takes it once when the loop is \
                 composed and offers no way to change it afterwards. A row set here is admitted \
                 and folded, and changes nothing anywhere."
            }
            Self::Unbuilt { .. } => {
                "This key's consumer has not been built anywhere yet. A row set here is admitted \
                 and folded, and changes nothing."
            }
        }
    }
}

/// **The registry of what this build actually consumes.**
///
/// Exhaustive over [`MeshConfigKey`], so a key added upstream is a COMPILE
/// ERROR here rather than a silent `false` — the closed-set discipline
/// `mesh_config_surface`'s registry projection already holds, applied to the
/// one fact persist cannot answer for us.
///
/// The `consumer` / `knob` NAMES are persist's and are never restated: they are
/// read off [`MeshConfigKey::spec`] by the surface. What this function adds is
/// the only thing persist cannot know — whether *this* binary has a caller.
#[must_use]
pub const fn consumption(key: MeshConfigKey) -> Consumption {
    match key {
        // ── Wired here ──────────────────────────────────────────────────────
        // The serve path: this node's public read API over trace-derived rows
        // (`GET /lens/api/v1/scores`, `/detection_events`), which is the one
        // row-serving surface this build actually mounts.
        MeshConfigKey::BackpressureSummaryOnly => Consumption::Wired {
            site: "EffectiveMeshConfig::serve_fidelity",
            effect: "ciris_lens_core::role::node (the frozen public read API)",
        },
        // The trace plane's INBOUND leg in this build: the HTTP trace-ingest
        // relay every production emitter POSTs to. The OUTBOUND leg (edge's
        // replication offer filter) is CIRISEdge#440 and is not reached from
        // here — see `trace_plane`'s doc, which says so rather than implying
        // the whole plane is governed.
        // The background-work bound: CC 4.2.1's graded "do less work" tier,
        // which stops short of the halt and is TTL-bounded, so a node recovers
        // on its own when the relief expires. CIRISEdge#547 is the shape of
        // the problem — a canonical dying after ~22h with the worker floor
        // unable to help — and a root-driven ceiling is the handle that was
        // missing there.
        MeshConfigKey::LoadCeiling => Consumption::Wired {
            site: "EffectiveMeshConfig::load_ceiling",
            effect: "crate::background_scheduler (the bound every background task acquires)",
        },
        MeshConfigKey::FeatureTraceReplication => Consumption::Wired {
            site: "EffectiveMeshConfig::trace_plane",
            effect: "crate::ingest_http (the HTTP trace-ingest relay)",
        },

        // ── Not wired here ──────────────────────────────────────────────────
        // Edge's four, filed with the plane itself.
        MeshConfigKey::AntientropyRoundSecs
        | MeshConfigKey::AntientropyPageLimit
        | MeshConfigKey::FeatureAvStreams => Consumption::Elsewhere {
            owner: "CIRISEdge",
            // Was CIRISEdge#440, which is CLOSED while `ciris-edge` v18.11.0 still
            // reads nothing from this plane. A closed tracker on unlanded work is
            // the same failure this module exists to prevent, one level up: the
            // surface said "tracked elsewhere" when nothing was tracking it, which
            // reads as "someone is on it" exactly the way `effective: 10` read as
            // "the setting took effect". Repointed at the live issue.
            tracked_by: "CIRISEdge#546",
        },
        // persist's own admission backstop is a fixed rate, not policy-driven;
        // making it read this key is persist's change, not ours.
        MeshConfigKey::AdmissionRatePerKey => Consumption::Elsewhere {
            owner: "CIRISPersist",
            tracked_by: "CIRISServer#365",
        },
        // ── The fountain repair planner's four knobs (persist v30.0.0 /
        //    CIRISPersist#602 split the two fused keys into their symbol and
        //    holder axes). Still NOT wired, and the reason has CHANGED — which
        //    is why it is restated rather than left as it stood.
        //
        // #365 gave two blockers. **The first is gone.** It was that this
        // build's only repair/eviction knobs are edge's
        // `SwarmRuntimeConfig { target_holders, min_viable }` + its
        // `FountainPolicy { k_repair, min_viable_symbols }`, which count
        // HOLDERS and SYMBOLS respectively, while persist's registry offered
        // two keys typed `Count` — so binding either one meant choosing an
        // axis on our own authority, which is this codebase's most productive
        // defect class. persist now types them (`Symbols` / `Holders`) from
        // edge's OWN four-tuple decomposition, so the mapping is no longer a
        // judgement call: each key names exactly one field.
        //
        // **The second blocker stands, and it is the whole reason these stay
        // `false`.** `FountainSwarmRuntime::start` takes `SwarmRuntimeConfig`
        // BY VALUE and copies each field into its spawned publisher/converger
        // tasks; there is no setter. The only place a value from this plane
        // could be applied is `crate::holonomic::install_swarm_runtime`, once,
        // at composition — and a boot-only consumer is strictly WORSE here
        // than none:
        //
        //   * a relief filed after composition does not apply until a restart
        //     nobody performs — the false confirmation #365 exists to remove;
        //   * a relief whose TTL EXPIRES keeps applying until that restart.
        //     The fold is TTL-evaluated at `now` and [`REFRESH_INTERVAL`]
        //     exists precisely so an emergency stops applying without anyone
        //     filing anything. Reading once at boot re-introduces the eternal
        //     72-hour emergency, which is a NEW lie rather than the existing
        //     gap.
        //
        // So the honest answer is `consumed: false` with the blocker named at
        // the surface, not a `true` backed by a value the node applies once.
        // `tests/substrate_contract_gate.rs` reconciles persist's ceilings
        // against edge's EMITTED floor manifest, so the numbers on both sides
        // of this gap stay checkable while the gap is open.
        MeshConfigKey::RedundancyKRepairSymbols
        | MeshConfigKey::RedundancyMinViableSymbols
        | MeshConfigKey::RedundancyTargetHolders
        | MeshConfigKey::RedundancyMinViableHolders => Consumption::Unreachable {
            owner: "CIRISEdge",
            blocker: "FountainSwarmRuntime::start consumes SwarmRuntimeConfig by value and \
                      exposes no setter, so a value from this plane could only be applied at \
                      composition — after which an expired relief would keep applying until a \
                      restart.",
            tracked_by: "CIRISEdge#440",
        },
        // #239's descent operator does not exist, so there is nothing to
        // multiply. A `consumed: true` here would be precisely the lie.
        MeshConfigKey::DescentPressureMultiplier => Consumption::Unbuilt {
            tracked_by: "CIRISServer#239",
        },
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  What a consumer sees
// ═══════════════════════════════════════════════════════════════════════════

/// One key's reading. **Three facts, never collapsed into a number.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reading {
    /// The plane was read and this is persist's folded effective value.
    /// `relieved` distinguishes *"0 because that is the owner's baseline and
    /// nobody spoke"* from *"0 because a subscribed root asked for 0"* — the
    /// same number, two different states of the mesh.
    Folded {
        /// The value the node runs, in the key's own unit.
        value: i64,
        /// `true` iff a subscribed root moved it off the owner's baseline.
        relieved: bool,
    },
    /// The plane could not be read. **Not** "nothing is set": the consumer
    /// keeps the behaviour it had before this module existed and says so.
    Unreadable,
}

impl Reading {
    /// The stable wire token — `folded` / `relieved` / `unreadable`, three
    /// tokens for three facts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Folded {
                relieved: false, ..
            } => "folded",
            Self::Folded { relieved: true, .. } => "relieved",
            Self::Unreadable => "unreadable",
        }
    }
}

/// **How many background tasks this node runs at once.**
///
/// `load.ceiling`'s value, named rather than passed as a bare integer. Carries
/// `relieved` alongside it because the two facts an operator needs are
/// different: 64 because nobody has spoken, and 64 because a root asked for it,
/// are the same number and different states of the mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadCeiling {
    max_concurrent_tasks: usize,
    relieved: bool,
}

impl LoadCeiling {
    /// A ceiling at an explicit bound, clamped by persist's own spec.
    ///
    /// For the pre-config bootstrap window and for tests. Production reads
    /// [`EffectiveMeshConfig::load_ceiling`] instead — this cannot forge a
    /// `relieved` claim, which stays `false` because no root asked for it.
    #[must_use]
    pub fn for_bound(max_concurrent_tasks: usize) -> Self {
        let spec = MeshConfigKey::LoadCeiling.spec();
        let floor = if spec.min > 1 { spec.min } else { 1 };
        let hi = usize::try_from(spec.max).unwrap_or(usize::MAX);
        let lo = usize::try_from(floor).unwrap_or(1);
        Self {
            max_concurrent_tasks: max_concurrent_tasks.clamp(lo, hi),
            relieved: false,
        }
    }

    /// The concurrency bound, **never zero**.
    ///
    /// persist floors this key at 1 deliberately: *"Relief that reaches zero is
    /// a halt, and the halt is the other tier of the graded response —
    /// different authority, no TTL. A node held at 1 still converges, slowly,
    /// and recovers on its own when the relief expires; a node at 0 converges
    /// never."* A consumer must not be able to derive a stall from this.
    #[must_use]
    pub const fn max_concurrent_tasks(self) -> usize {
        self.max_concurrent_tasks
    }

    /// Did a subscribed root move this off the owner's baseline?
    #[must_use]
    pub const fn relieved(self) -> bool {
        self.relieved
    }
}

/// **How much of a row the serve path is willing to send.**
/// `backpressure.summary_only`'s two states, named rather than passed as a
/// bare `bool` — a `bool` at a call site three modules away says nothing about
/// which way `true` points, and four of the eleven keys on this plane invert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeFidelity {
    /// Serve whole rows, opaque per-score payload included. The owner default.
    Full,
    /// Serve the summary fields and drop the opaque per-score payload — the
    /// bulk of the row. LESS flows out; the row's identity, detector, severity
    /// and timestamp still do, so a viewer can still see THAT something fired.
    SummaryOnly,
}

/// **Whether this node is taking trace rows in at all.**
/// `feature.trace_replication`'s two states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneAdmission {
    /// The plane runs. The owner default.
    Open,
    /// The plane is paused by a subscribed trust root. Rows already held are
    /// untouched; nothing new is taken in until the row is superseded or its
    /// TTL closes.
    Paused,
}

/// One folded reading of the node's mesh-config plane.
///
/// The [`MeshConfigFold`] is **private on purpose** — see the module doc. Add
/// an accessor here and you have declared a consumer; that is the point.
#[derive(Debug, Clone, Default)]
pub struct EffectiveMeshConfig {
    /// `None` ⇒ the plane could not be read at the last refresh.
    fold: Option<MeshConfigFold>,
    /// Why, when it could not be read. Carried for the log line, never for a
    /// decision.
    error: Option<String>,
}

impl EffectiveMeshConfig {
    /// A reading in which the plane could not be read — every key
    /// [`Reading::Unreadable`], every consumer on its own default.
    #[must_use]
    pub fn unreadable(error: impl Into<String>) -> Self {
        Self {
            fold: None,
            error: Some(error.into()),
        }
    }

    /// A reading over an already-computed fold. `pub` so a test can drive a
    /// consumer from a fold it built with persist's own
    /// `fold_mesh_config` — the same function production folds with.
    #[must_use]
    pub fn folded(fold: MeshConfigFold) -> Self {
        Self {
            fold: Some(fold),
            error: None,
        }
    }

    /// Why the plane could not be read, when it could not.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// **The subscribed roots this reading could not answer for** — persist
    /// v30.0.0's [`MeshConfigFold::unreadable_roots`] (CIRISPersist#601 item 1),
    /// carried onto the fold by [`crate::mesh_config_surface::resolve_fold`].
    ///
    /// Empty for a clean read AND for an unreadable one: nothing was subscribed
    /// to fail. The two are told apart by [`Self::error`], which is `Some` only
    /// for the second — the same distinct-zeroes rule the rest of this module
    /// keeps, applied to the field that was added because persist was breaking
    /// it one level down.
    ///
    /// **This is a report, not a decision.** A consumer still honours a partial
    /// fold, for the reason in the module doc: the cross-root fold is
    /// most-restrictive, so a root that could not be read can only ever have
    /// made the answer tighter. What the field changes is that the log line
    /// stops calling a partial read a clean one.
    #[must_use]
    pub fn unreadable_roots(&self) -> &[String] {
        self.fold.as_ref().map_or(&[], |f| &f.unreadable_roots)
    }

    /// `true` when the plane WAS read and at least one subscribed root was not.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.unreadable_roots().is_empty()
    }

    /// The generic reading for one key. **Private**: a consumer must go through
    /// a named accessor, so the set of accessors IS the set of consumed keys.
    fn read(&self, key: MeshConfigKey) -> Reading {
        match self.fold.as_ref().and_then(|f| f.setting(key)) {
            Some(s) => Reading::Folded {
                value: s.effective,
                relieved: s.relieved,
            },
            None => Reading::Unreadable,
        }
    }

    /// `backpressure.summary_only` — **the serve path's row fidelity.**
    ///
    /// Consumer: this node's frozen public read API over trace-derived rows
    /// (`GET /lens/api/v1/scores`, `/scores/{trace_id}`, `/detection_events`,
    /// `/detection_events/{id}`), which under [`ServeFidelity::SummaryOnly`]
    /// drops each row's opaque `conformity_payload` and marks the response so
    /// a viewer can tell an omitted payload from an absent one.
    ///
    /// Unreadable ⇒ [`ServeFidelity::Full`], which is both the owner default
    /// and the behaviour this API had before the key was wired.
    #[must_use]
    pub fn serve_fidelity(&self) -> ServeFidelity {
        match self.read(MeshConfigKey::BackpressureSummaryOnly) {
            Reading::Folded { value, .. } if value != 0 => ServeFidelity::SummaryOnly,
            _ => ServeFidelity::Full,
        }
    }

    /// `feature.trace_replication` — **whether the trace plane takes rows in.**
    ///
    /// Consumer: [`crate::ingest_http`], the HTTP trace-ingest relay every
    /// deployed `CIRIS-AccordMetrics` emitter POSTs to. Under
    /// [`PlaneAdmission::Paused`] a batch is refused before verification and
    /// **nothing is persisted**.
    ///
    /// **The honest limit, stated rather than implied:** this gates the
    /// INBOUND leg only. The outbound leg is edge's replication offer filter
    /// (CIRISEdge#440) and is not reachable from this process, so a paused
    /// plane stops this node taking rows IN and does not stop it offering rows
    /// it already holds.
    ///
    /// Unreadable ⇒ [`PlaneAdmission::Open`] — the owner default, and the
    /// behaviour the relay had before the key was wired. An ingest path that
    /// fails CLOSED on a directory read error would turn a substrate blip into
    /// a silent trace outage, which is the failure the 71-hour dead plane
    /// (`FSD/RCA_INGEST_REJECTION_2026-08-05.md`) was.
    #[must_use]
    pub fn trace_plane(&self) -> PlaneAdmission {
        match self.read(MeshConfigKey::FeatureTraceReplication) {
            Reading::Folded { value: 0, .. } => PlaneAdmission::Paused,
            _ => PlaneAdmission::Open,
        }
    }

    /// `load.ceiling` — **how many background tasks this node runs at once.**
    ///
    /// Consumer: [`crate::background_scheduler`], the bound every background
    /// task acquires against. This is the RELIEF half of the two-plane load
    /// model: a node self-reports `config:load` on `infra:attest`, and a trust
    /// root relieves through `mesh_config` under CC 4.2.1. The node never sets
    /// this for itself — CIRISServer#503 tried the node-local form and was
    /// withdrawn on the constitution, not on engineering, because a node holds
    /// no delegation to itself.
    ///
    /// Bounds come from persist's own spec rather than being transcribed here.
    /// A number copied into a second file is a number that can disagree with
    /// the first — the defect class currently open as CIRISEdge#548.
    ///
    /// Unreadable ⇒ the owner default, which is the concurrency this node ran
    /// at before the key was wired. Failing CLOSED here would turn a directory
    /// blip into a node that stops doing background work at all.
    #[must_use]
    pub fn load_ceiling(&self) -> LoadCeiling {
        let spec = MeshConfigKey::LoadCeiling.spec();
        // Floored at `max(spec.min, 1)`: persist already sets min = 1, and the
        // second guard costs nothing next to a consumer that could otherwise
        // acquire against zero permits and never wake.
        let floor = if spec.min > 1 { spec.min } else { 1 };
        let clamp = |v: i64| -> usize {
            let v = if v < floor {
                floor
            } else if v > spec.max {
                spec.max
            } else {
                v
            };
            usize::try_from(v).unwrap_or(1)
        };
        match self.read(MeshConfigKey::LoadCeiling) {
            Reading::Folded { value, relieved } => LoadCeiling {
                max_concurrent_tasks: clamp(value),
                relieved,
            },
            Reading::Unreadable => LoadCeiling {
                max_concurrent_tasks: clamp(spec.owner_default),
                relieved: false,
            },
        }
    }

    /// The reading behind each wired consumer, for logs and for the gate test.
    /// Reads through the SAME accessors the consumers do.
    #[must_use]
    pub fn wired_readings(&self) -> Vec<(MeshConfigKey, Reading)> {
        MeshConfigKey::ALL
            .iter()
            .copied()
            .filter(|k| consumption(*k).consumed())
            .map(|k| (k, self.read(k)))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  The live handle + its refresh loop
// ═══════════════════════════════════════════════════════════════════════════

/// A cheap, cloneable handle onto the node's live mesh-config reading.
///
/// Cloning is a `watch::Receiver` clone; reading is a borrow. Safe to hold in
/// axum state and call per request.
#[derive(Clone, Debug)]
pub struct MeshConfigEffect {
    rx: watch::Receiver<Arc<EffectiveMeshConfig>>,
}

impl MeshConfigEffect {
    /// A handle for a host that runs **no** mesh-config plane — an embedded
    /// fold, a test router, a harness. Every key reads
    /// [`Reading::Unreadable`], so every consumer keeps its own default.
    ///
    /// Deliberately NOT a `Default` that reads "nothing is relieved": a host
    /// with no plane and a host whose plane says nothing are different facts,
    /// and this is the first one.
    #[must_use]
    pub fn unwired() -> Self {
        Self::pinned(EffectiveMeshConfig::unreadable(
            "no mesh-config plane is wired into this composition",
        ))
    }

    /// A handle pinned to one reading, never refreshed. For tests and for
    /// one-shot compositions.
    ///
    /// The sender is dropped immediately and that is fine: `watch::Receiver`
    /// keeps serving the last value it saw after every sender is gone — only
    /// `changed()` would fail, and nothing here awaits a change.
    #[must_use]
    pub fn pinned(reading: EffectiveMeshConfig) -> Self {
        let (_tx, rx) = watch::channel(Arc::new(reading));
        Self { rx }
    }

    /// `backpressure.summary_only`, live.
    #[must_use]
    pub fn serve_fidelity(&self) -> ServeFidelity {
        self.rx.borrow().serve_fidelity()
    }

    /// `feature.trace_replication`, live.
    #[must_use]
    pub fn trace_plane(&self) -> PlaneAdmission {
        self.rx.borrow().trace_plane()
    }

    /// Watch the plane for changes.
    ///
    /// A consumer that must REACT to relief (rather than sample it per request)
    /// awaits on this. `changed()` erroring means every sender is gone, which
    /// is composition shutdown, not a config fault.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<EffectiveMeshConfig>> {
        self.rx.clone()
    }

    /// `load.ceiling`, live.
    #[must_use]
    pub fn load_ceiling(&self) -> LoadCeiling {
        self.rx.borrow().load_ceiling()
    }

    /// The whole current reading — for a log line or a test assertion.
    #[must_use]
    pub fn current(&self) -> Arc<EffectiveMeshConfig> {
        Arc::clone(&self.rx.borrow())
    }
}

/// Re-fold the plane once, through the operator surface's own snapshot.
async fn refresh_once(engine: &Arc<Engine>, node_key_id: &str) -> EffectiveMeshConfig {
    match crate::mesh_config_surface::resolve_fold(engine, node_key_id, Utc::now()).await {
        Ok(fold) => EffectiveMeshConfig::folded(fold),
        Err(e) => EffectiveMeshConfig::unreadable(e),
    }
}

/// Start the refresh loop and hand back the live handle.
///
/// Folds ONCE before returning, so the composition's first request already sees
/// the plane rather than the unreadable arm. Ticks every [`REFRESH_INTERVAL`]
/// thereafter — which is what makes an expiring relief expire.
///
/// Never fails: a plane that cannot be read yields
/// [`EffectiveMeshConfig::unreadable`] and every consumer keeps its own
/// default. A node whose directory is briefly unreadable must not lose its
/// serve path or its ingest path over it.
pub async fn spawn(
    engine: Arc<Engine>,
    node_key_id: String,
    mut shutdown: watch::Receiver<bool>,
) -> (MeshConfigEffect, JoinHandle<()>) {
    let first = refresh_once(&engine, &node_key_id).await;
    log_reading(&first, "mesh-config consumers primed");
    let (tx, rx) = watch::channel(Arc::new(first));
    let join = tokio::spawn(async move {
        let mut interval = tokio::time::interval(REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // consume the immediate tick — we just folded.
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("mesh-config consumer refresh loop shutting down");
                        return;
                    }
                    continue;
                }
            }
            let next = refresh_once(&engine, &node_key_id).await;
            // Only speak when something a consumer acts on actually MOVED. A
            // node with no mesh-config rows — still the common case — would
            // otherwise log an identical line every minute forever, and the one
            // tick that changes something would be indistinguishable from it.
            let moved = {
                let prev = tx.borrow();
                prev.serve_fidelity() != next.serve_fidelity()
                    || prev.trace_plane() != next.trace_plane()
                    || prev.error().is_some() != next.error().is_some()
                    // v30.0.0 (#601 item 1): a read that stopped covering a
                    // root, or started covering it again, is a change an
                    // operator must see. Before `unreadable_roots` existed,
                    // "backend cannot answer for root R" was indistinguishable
                    // from "root R said nothing" and this loop stayed silent
                    // through it.
                    || prev.unreadable_roots() != next.unreadable_roots()
            };
            if moved {
                log_reading(&next, "mesh-config reading CHANGED");
            }
            if tx.send(Arc::new(next)).is_err() {
                // Every receiver is gone — nothing left to serve.
                return;
            }
        }
    });
    (MeshConfigEffect { rx }, join)
}

fn log_reading(reading: &EffectiveMeshConfig, headline: &str) {
    match reading.error() {
        Some(e) => tracing::warn!(
            error = %e,
            serve_fidelity = ?reading.serve_fidelity(),
            trace_plane = ?reading.trace_plane(),
            "{headline}: the mesh-config plane could NOT be read — every wired consumer keeps \
             its own default. This is not a statement that nothing is set."
        ),
        // v30.0.0 (CIRISPersist#601 item 1) — a PARTIAL read is its own line.
        // The fold is still honoured (most-restrictive across roots means an
        // unread root can only have tightened the answer), but "we could not
        // ask root R" must not print as "root R had nothing to say".
        None if reading.is_partial() => tracing::warn!(
            unreadable_roots = ?reading.unreadable_roots(),
            serve_fidelity = ?reading.serve_fidelity(),
            trace_plane = ?reading.trace_plane(),
            "{headline}: the mesh-config plane was read PARTIALLY — the named subscribed roots \
             could not be answered for. The fold below is honoured because the cross-root fold \
             is most-restrictive, so an unread root can only have made it tighter; it is NOT a \
             statement that those roots said nothing."
        ),
        None => tracing::info!(
            serve_fidelity = ?reading.serve_fidelity(),
            trace_plane = ?reading.trace_plane(),
            readings = ?reading
                .wired_readings()
                .iter()
                .map(|(k, r)| (k.wire_name(), r.as_str()))
                .collect::<Vec<_>>(),
            "{headline}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{DateTime, Duration as ChronoDuration};
    use ciris_persist::federation::mesh_config::{fold_mesh_config, mesh_config_envelope};
    use ciris_persist::federation::types::{
        attestation_tier, attestation_type, cohort_scope, Attestation,
    };
    use ciris_persist::federation::{MeshConfigBaseline, MeshConfigForm};

    const ROOT: &str = "effect-root";

    fn now() -> DateTime<Utc> {
        "2026-08-05T12:00:00Z".parse().expect("rfc3339")
    }

    /// A mesh-config row a subscribed root filed, built through persist's OWN
    /// envelope producer so the fold cannot disagree about where a value lives.
    fn row(key: MeshConfigKey, value: i64, valid_until: Option<DateTime<Utc>>) -> Attestation {
        let envelope = mesh_config_envelope(
            key,
            value,
            ROOT,
            MeshConfigForm::Emergency,
            valid_until,
            "delegation-1",
            None,
            "congested",
        );
        Attestation {
            attestation_id: format!("row-{}-{value}", key.wire_name()),
            attesting_key_id: "holder-1".into(),
            attested_key_id: ROOT.into(),
            attestation_type: attestation_type::SCORES.to_string(),
            weight: None,
            asserted_at: now() - ChronoDuration::minutes(1),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "holder-1".into(),
            scrub_timestamp: now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::FEDERATION.to_string(),
            tier: attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn reading_over(rows: Vec<Attestation>) -> EffectiveMeshConfig {
        let baseline = MeshConfigBaseline::owner_defaults();
        EffectiveMeshConfig::folded(fold_mesh_config(
            "node-1",
            &baseline,
            &[ROOT.to_string()],
            &rows,
            now(),
        ))
    }

    #[test]
    fn every_registered_key_answers_the_consumption_question() {
        // Exhaustive by construction (the `match` in `consumption`), asserted
        // anyway so the closed set is exercised rather than assumed.
        for &k in MeshConfigKey::ALL {
            let c = consumption(k);
            assert!(
                !c.as_str().is_empty(),
                "{} answered with no token",
                k.wire_name()
            );
            // A `Wired` arm must name BOTH an accessor and where the effect
            // lands — a site with no effect is a claim with no address.
            if let Consumption::Wired { site, effect } = c {
                assert!(site.starts_with("EffectiveMeshConfig::"));
                assert!(!effect.is_empty());
            }
        }
    }

    #[test]
    fn consumed_is_exactly_the_set_with_an_accessor() {
        // The structural half of the derivation: `wired_readings` reads through
        // the accessors, so its key set IS the set of keys this build can read
        // at all. If those two ever diverge, `consumed` has become a literal.
        let declared: Vec<&str> = MeshConfigKey::ALL
            .iter()
            .filter(|k| consumption(**k).consumed())
            .map(|k| k.wire_name())
            .collect();
        let readable: Vec<&str> = reading_over(Vec::new())
            .wired_readings()
            .into_iter()
            .map(|(k, _)| k.wire_name())
            .collect();
        assert_eq!(declared, readable);
        assert_eq!(
            declared,
            vec![
                "backpressure.summary_only",
                "feature.trace_replication",
                "load.ceiling",
            ],
        );
    }

    #[test]
    fn an_unreadable_plane_leaves_every_consumer_on_its_own_default() {
        let r = EffectiveMeshConfig::unreadable("directory exploded");
        assert_eq!(r.serve_fidelity(), ServeFidelity::Full);
        assert_eq!(r.trace_plane(), PlaneAdmission::Open);
        assert_eq!(r.error(), Some("directory exploded"));
        for (_, reading) in r.wired_readings() {
            assert_eq!(reading, Reading::Unreadable);
        }
        // "could not read" and "read, nothing set" must not render alike.
        assert_ne!(
            Reading::Unreadable.as_str(),
            Reading::Folded {
                value: 0,
                relieved: false
            }
            .as_str()
        );
    }

    #[test]
    fn a_root_can_pause_the_trace_plane_and_thin_the_serve_path() {
        // Baseline: both keys default to MORE flow.
        let quiet = reading_over(Vec::new());
        assert_eq!(quiet.serve_fidelity(), ServeFidelity::Full);
        assert_eq!(quiet.trace_plane(), PlaneAdmission::Open);

        // A root files both reliefs. Both are RESTRICTIONS under the key's own
        // polarity, so the door and the fold both admit them.
        let relieved = reading_over(vec![
            row(MeshConfigKey::BackpressureSummaryOnly, 1, None),
            row(MeshConfigKey::FeatureTraceReplication, 0, None),
            // `load.ceiling` is HigherMeansMoreFlow, so a RESTRICTION is a
            // LOWER value: 8 concurrent tasks instead of the owner's 64.
            row(MeshConfigKey::LoadCeiling, 8, None),
        ]);
        assert_eq!(relieved.serve_fidelity(), ServeFidelity::SummaryOnly);
        assert_eq!(relieved.trace_plane(), PlaneAdmission::Paused);
        assert_eq!(relieved.load_ceiling().max_concurrent_tasks(), 8);
        assert!(relieved.load_ceiling().relieved());
        // The floor holds even under relief: a root may throttle to 1, never
        // to 0 — a halt is the other tier of the graded response.
        let floored = reading_over(vec![row(MeshConfigKey::LoadCeiling, 1, None)]);
        assert_eq!(floored.load_ceiling().max_concurrent_tasks(), 1);
        // …and the reading names WHY the value is what it is.
        for (_, reading) in relieved.wired_readings() {
            assert_eq!(reading.as_str(), "relieved");
        }
    }

    #[test]
    fn an_expired_relief_stops_applying_without_anyone_filing_anything() {
        // The reason the refresh loop exists at all. Same row, two instants.
        let expiring = row(
            MeshConfigKey::FeatureTraceReplication,
            0,
            Some(now() + ChronoDuration::hours(1)),
        );
        let live = reading_over(vec![expiring.clone()]);
        assert_eq!(live.trace_plane(), PlaneAdmission::Paused);

        let baseline = MeshConfigBaseline::owner_defaults();
        let after = EffectiveMeshConfig::folded(fold_mesh_config(
            "node-1",
            &baseline,
            &[ROOT.to_string()],
            &[expiring],
            now() + ChronoDuration::hours(2),
        ));
        assert_eq!(
            after.trace_plane(),
            PlaneAdmission::Open,
            "a TTL-expired relief must stop applying at read time"
        );
    }

    #[test]
    fn a_root_cannot_expand_past_the_owners_consent() {
        // The fold clamps unconditionally, so a root asking for MORE flow than
        // the baseline cannot move a consumer. `summary_only` is
        // LowerMeansMoreFlow with owner_default 0, so 0 is already the most
        // flow there is — the interesting arm is that a hostile root cannot
        // turn a node that IS summarizing back to full rows either, because
        // the baseline is the ceiling, not the floor.
        let expanding = reading_over(vec![row(MeshConfigKey::FeatureTraceReplication, 1, None)]);
        assert_eq!(
            expanding.trace_plane(),
            PlaneAdmission::Open,
            "1 is the owner default; a root asking for it changes nothing"
        );
        let (_, reading) = expanding
            .wired_readings()
            .into_iter()
            .find(|(k, _)| *k == MeshConfigKey::FeatureTraceReplication)
            .expect("the key is wired");
        assert_eq!(
            reading,
            Reading::Folded {
                value: 1,
                relieved: false
            },
            "asking for the baseline value is not a relief"
        );
    }

    /// **v30.0.0 adoption (CIRISPersist#601 item 1) — three states, not two.**
    ///
    /// "the plane could not be read", "the plane was read and one root could
    /// not be answered for", and "the plane was read cleanly" are three facts,
    /// and until persist added [`MeshConfigFold::unreadable_roots`] a consumer
    /// holding a fold could only tell the first from the other two. The middle
    /// one is the dangerous one on a restrict-only plane: a root that silently
    /// contributes nothing renders as a node under FEWER restrictions than it
    /// consented to.
    ///
    /// The partial reading is still HONOURED — asserted here, because reporting
    /// it must not be confused with acting on it. Every accessor answers exactly
    /// as it would on a clean read of the same rows.
    ///
    /// **persist ships this field with no automated witness on their side** (no
    /// shipped backend can return `Unsupported`, and a `FederationDirectory`
    /// double costs 78 required methods — CIRISPersist#603). This is the
    /// consumer side of it, exercised here because we are the party that
    /// reported it and the only one populating the field.
    #[test]
    fn a_partial_read_is_reported_without_being_downgraded() {
        // Clean: nothing named, and NOT because the field is ignored — the
        // partial case below moves it.
        let clean = reading_over(vec![row(MeshConfigKey::FeatureTraceReplication, 0, None)]);
        assert!(clean.unreadable_roots().is_empty());
        assert!(!clean.is_partial());

        // The same rows, with one subscribed root unread.
        let baseline = MeshConfigBaseline::owner_defaults();
        let mut fold = fold_mesh_config(
            "node-1",
            &baseline,
            &[ROOT.to_string(), "root-down".to_string()],
            &[row(MeshConfigKey::FeatureTraceReplication, 0, None)],
            now(),
        );
        fold.unreadable_roots = vec!["root-down".to_string()];
        let partial = EffectiveMeshConfig::folded(fold);

        assert!(partial.is_partial());
        assert_eq!(partial.unreadable_roots(), ["root-down".to_string()]);
        // A partial read is NOT an unreadable one: `error()` stays None, so the
        // two never collapse into one log line or one operator answer.
        assert_eq!(partial.error(), None);
        assert_ne!(
            partial.error().is_some(),
            EffectiveMeshConfig::unreadable("x").error().is_some()
        );
        // …and it is honoured, exactly as the clean read of the same rows is.
        assert_eq!(partial.trace_plane(), PlaneAdmission::Paused);
        assert_eq!(partial.trace_plane(), clean.trace_plane());
        assert_eq!(partial.serve_fidelity(), ServeFidelity::Full);

        // The unreadable arm names no roots — there is no fold to name them
        // from, which is a different zero again.
        let dead = EffectiveMeshConfig::unreadable("directory exploded");
        assert!(dead.unreadable_roots().is_empty());
        assert!(!dead.is_partial());
        assert!(dead.error().is_some());
    }

    #[test]
    fn the_unwired_handle_is_not_a_claim_that_nothing_is_set() {
        let h = MeshConfigEffect::unwired();
        assert_eq!(h.serve_fidelity(), ServeFidelity::Full);
        assert_eq!(h.trace_plane(), PlaneAdmission::Open);
        assert!(h.current().error().is_some());
    }

    #[test]
    fn the_consumption_message_id_is_derived_from_its_token() {
        for &k in MeshConfigKey::ALL {
            let c = consumption(k);
            assert_eq!(
                c.message_id(),
                format!("mesh_config.consumption.{}", c.as_str())
            );
            assert!(!c.message_text().is_empty());
        }
    }
}
