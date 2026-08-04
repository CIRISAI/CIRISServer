//! **CC 2.2 conformance levels + CC 2.6.4 versioning policy** (CIRISServer#159).
//!
//! Two paired gaps, both of the shape "declare a level/version, then ENFORCE it".
//! Before this module the node declared NEITHER: it had no conformance surface at
//! all (CC 2.2), and it negotiated no CEG wire version with a peer (CC 2.6.4) — it
//! simply proceeded, which is exactly the silent-divergence failure both sections
//! exist to foreclose.
//!
//! ## CC 2.2 — the normative rule implemented here
//!
//! CC 2.2 names THREE conformance profiles and calls them "the minimums" each role
//! must meet:
//!
//!   1. **CCP — CEG-Conforming Producer**: emits well-formed CC 2.1 envelopes,
//!      hybrid-signs them (CC 2.6.5 [hybrid-sig]), respects the CC 3.4 reserved
//!      prefixes, declares `oversight_mode` + `witness_relation`.
//!   2. **CCC — CEG-Conforming Consumer**: verifies hybrid signatures, enforces
//!      reserved-prefix rules **at admission**, implements at least Policy A
//!      (CC 4.4.3.8) with the CC 4.4.2 default aggregation, honors the `null`
//!      placeholder/dev hardware-class rejection (CC 4.2.2).
//!   3. **CCS — CEG-Conforming Substrate**: the CC 5.3.1 / CC 5.3.2 storage +
//!      transport guarantees — idempotent replication, full-SHA blob verification
//!      before consumption, witness-quorum multi-party admission.
//!
//! "Interoperability needs named roles so that *conforming* means the same thing to
//! every peer" (CC 2.2). A declaration nobody honors is decoration, so this module
//! makes the declaration OPERATIONAL: every federation-wire op names the profiles
//! it exercises ([`required_profiles`]), and an op whose profiles the node's
//! DECLARED level does not claim is **REFUSED** ([`require_op`]) — the node will
//! not perform, on the wire, a role it does not claim to conform to.
//!
//! The declaration is a `config:*` CEG object ([`KEY_CONFORMANCE_PROFILES`], the
//! zero-env config-as-graph rule) so it is owner-authored, signed, versioned and
//! replicable like every other node knob — and it is bounded above by
//! [`BUILD_PROFILES`], the profiles THIS BINARY actually implements: an operator
//! may NARROW the node's claim (a read-only consumer node declaring `["CCC"]`), and
//! may never widen it past what the code does.
//!
//! ## CC 2.6.4 — the normative rule implemented here
//!
//! CC 2.6.4 pins CEG to **SemVer 2.0.0** with an explicit wire-compatibility
//! mapping — "the grammar can evolve only if every change announces whether it
//! breaks the wire… so a peer knows **from the version alone** whether it can still
//! interoperate":
//!
//!   - **MAJOR** — wire-INCOMPATIBLE (field removal, semantic change, domain-sep
//!     label change, prefix/reservation break, conformance-language change).
//!   - **MINOR** — wire-COMPATIBLE additions; "existing Conforming Producers and
//!     Consumers continue to interoperate without modification" (an unknown added
//!     field rides the CC 2.1.1 forward-compat rule, already implemented).
//!   - **PATCH** — clarifications / editorial.
//!   - **0.x** — "consumers MUST treat 0.x as unstable until 1.0 publication"; any
//!     0.x → 0.(x+1) bump MAY be wire-breaking.
//!
//! CC 2.6.4 additionally makes the **wire vocabulary a hash-pinned artifact**: every
//! ratifying repo pins `WIRE_VOCABULARY.md`'s SHA-256 at build, and "a hash mismatch
//! at cohabitation is a substrate-tier build failure, **not a warning**"
//! (`tests/wire_vocabulary_gate.rs` is our build-side half; [`negotiate`] is the
//! runtime, peer-facing half).
//!
//! [`negotiate`] is the enforcement of exactly that: a peer announcing a wire
//! version we cannot interoperate with — or a different wire vocabulary — is
//! **REFUSED** at the federation boundary, never silently tolerated.
//!
//! ## Fail-closed (both halves)
//!
//!   - An unreadable / unparseable conformance declaration yields the EMPTY profile
//!     set, not the full one: no claim ⇒ no wire op. A garbled declaration is never
//!     a licence.
//!   - An unparseable peer version, an out-of-range peer version, a malformed or
//!     mismatched peer vocabulary hash → REFUSE.
//!   - The one deliberate default: a peer that OMITS the negotiation fields is
//!     judged against [`PRE_NEGOTIATION_WIRE_VERSION`] — the wire version in force
//!     when the fields were introduced — NOT against "whatever this node happens to
//!     speak today". That is the CC 2.6.4 MINOR rule ("new envelope field with
//!     documented default") and it stays fail-closed across a future break: the next
//!     MAJOR / 0.MINOR bump automatically makes every omitting (i.e. older) peer
//!     incompatible, with no code change here.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use ciris_persist::prelude::Engine;
use serde::{Deserialize, Serialize};

use crate::auth::gate::CapabilityVerb;

// ─── CC 2.2 — the three profiles ─────────────────────────────────────────────

/// A CC 2.2 conformance profile — one of the three normative roles a peer may
/// claim. `Ord` so a declaration folds into a stable, deterministic set (the
/// declaration is served on the wire; its ordering must not wobble).
///
/// Serializes as the WIRE TOKEN (`"CCP"` / `"CCC"` / `"CCS"`), never as the Rust
/// variant name: the token is the CC 2.2 vocabulary every peer reads, and a Rust
/// rename must never be able to change what we publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConformanceProfile {
    /// **CCP** — CEG-Conforming Producer (emits + hybrid-signs CC 2.1 envelopes).
    Producer,
    /// **CCC** — CEG-Conforming Consumer (verifies + admits, reserved-prefix rules).
    Consumer,
    /// **CCS** — CEG-Conforming Substrate (CC 5.3.1 / 5.3.2 storage + transport).
    Substrate,
}

impl ConformanceProfile {
    /// The stable wire token (`CCP` / `CCC` / `CCS`) — what a declaration carries
    /// and what a peer reads off `GET /v1/federation/conformance`.
    pub fn as_str(self) -> &'static str {
        match self {
            ConformanceProfile::Producer => "CCP",
            ConformanceProfile::Consumer => "CCC",
            ConformanceProfile::Substrate => "CCS",
        }
    }

    /// The CC 2.2 long name (for the human reading a refusal).
    pub fn title(self) -> &'static str {
        match self {
            ConformanceProfile::Producer => "CEG-Conforming Producer",
            ConformanceProfile::Consumer => "CEG-Conforming Consumer",
            ConformanceProfile::Substrate => "CEG-Conforming Substrate",
        }
    }

    /// Parse a declaration token. Case-insensitive on the short form only — an
    /// unknown token is `None`, and [`parse_declaration`] treats ANY unknown token
    /// as a declaration-level failure (fail-closed: we do not guess what a peer /
    /// operator meant by a profile name we do not implement).
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_uppercase().as_str() {
            "CCP" => Some(ConformanceProfile::Producer),
            "CCC" => Some(ConformanceProfile::Consumer),
            "CCS" => Some(ConformanceProfile::Substrate),
            _ => None,
        }
    }
}

impl fmt::Display for ConformanceProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ConformanceProfile {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ConformanceProfile {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        // Fail-closed at the serde boundary too: an unknown token is an ERROR, not
        // a silently-dropped element (see `parse_declaration`).
        ConformanceProfile::parse(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown CC 2.2 conformance profile '{raw}'"))
        })
    }
}

/// The profiles THIS BINARY implements — the ceiling on any declaration.
///
/// WHY all three (the CC 2.2 checklist, and where each obligation lives):
///   - **CCP**: `peer::emit_replication_consent` / `emit_attestation_self` build CC
///     2.1 envelopes and hybrid-sign them through `Engine::sign_hybrid`
///     (Ed25519 + ML-DSA-65); reserved-prefix roles are enforced by persist's
///     admission gate on emit; `oversight_mode` / `witness_relation` ride the
///     envelope builders.
///   - **CCC**: `peer::register_peer_key` → `Engine::register_federation_key` is the
///     fail-secure admission gate (hybrid-verify BEFORE store, reserved-prefix +
///     hardware-class rejection); composition runs persist's Policy-A scorer.
///   - **CCS**: the `ReplicationRuntime` + CIRISEdge transport give idempotent
///     replication + full-SHA blob verification before consumption
///     (`replication_reconcile`, `holonomic`), and persist enforces witness-quorum
///     multi-party admission.
///
/// A node may declare a SUBSET of this (see [`declared`]); it may never declare a
/// superset — you cannot claim a profile the code does not implement.
pub const BUILD_PROFILES: [ConformanceProfile; 3] = [
    ConformanceProfile::Producer,
    ConformanceProfile::Consumer,
    ConformanceProfile::Substrate,
];

/// The `config:*` key carrying THIS node's declared conformance level: a list of
/// CC 2.2 profile tokens, e.g. `["CCP","CCC","CCS"]`. ABSENT ⇒ [`BUILD_PROFILES`]
/// (the honest default: this build implements all three, so a node that has said
/// nothing claims what it can actually do). PRESENT ⇒ the declaration governs, and
/// a profile absent from it is a profile this node refuses to act in.
pub const KEY_CONFORMANCE_PROFILES: &str = "node.conformance_profiles";

// ─── CC 2.6.4 — the wire version ─────────────────────────────────────────────

/// The CEG wire version THIS node speaks — the CIRISConstitution version the
/// substrate pins (`CIRISConstitution/VERSION` = `1.0-rc2`), normalized to the
/// SemVer 2.0.0 triple CC 2.6.4 mandates.
///
/// A release candidate is NOT the published 1.0, and CC 2.6.4 binds its
/// MAJOR/MINOR/PATCH rules strictly only "once 1.0 is published" — so an `-rcN`
/// version is treated as UNSTABLE by [`WireVersion::interoperates_with`], exactly
/// like the 0.x series it is the tail of.
pub const CEG_WIRE_VERSION: &str = "1.0.0-rc2";

/// The documented default for a peer that omits the negotiation fields (CC 2.6.4
/// MINOR rule: "new envelope field with documented default"; the omission itself
/// rides the CC 2.1.1 forward-compat rule already implemented on the consumer side).
///
/// It is PINNED at the version in force when negotiation was introduced — NOT
/// aliased to [`CEG_WIRE_VERSION`]. That is what keeps the default fail-closed: the
/// day the wire breaks (a MAJOR, or a 0.MINOR in the unstable series), every peer
/// that still omits the fields — i.e. every peer running pre-break code — becomes
/// automatically INCOMPATIBLE and is refused, without anyone remembering to touch
/// this file.
pub const PRE_NEGOTIATION_WIRE_VERSION: &str = "1.0.0-rc2";

/// A SemVer 2.0.0 version as CC 2.6.4 uses it: the triple plus an optional
/// pre-release tag (build metadata is parsed and DISCARDED — SemVer §10: it is not
/// part of precedence, and it can never be the difference between interoperating
/// and not).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// The `-rc2` / `-alpha.1` tail, if any. Its PRESENCE is what matters here:
    /// a pre-release is not the published version whose rules bind strictly.
    pub pre: Option<String>,
}

impl WireVersion {
    /// Parse `MAJOR.MINOR.PATCH[-pre][+build]`. Strict: a missing component, a
    /// non-numeric component, or an empty pre-release tag is an ERROR, never a
    /// lenient coercion — an unparseable version is a REFUSAL (fail-closed), and a
    /// lenient parse here would be a silent downgrade of the whole negotiation.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty version string".to_string());
        }
        // Strip build metadata (`+…`) first — SemVer §10, ignored for precedence.
        let core_and_pre = s.split('+').next().unwrap_or(s);
        let (core, pre) = match core_and_pre.split_once('-') {
            Some((core, pre)) => {
                if pre.is_empty() {
                    return Err(format!("empty pre-release tag in '{s}'"));
                }
                (core, Some(pre.to_string()))
            }
            None => (core_and_pre, None),
        };
        let mut parts = core.split('.');
        let mut next = |what: &str| -> Result<u64, String> {
            parts
                .next()
                .ok_or_else(|| format!("missing {what} in '{s}'"))?
                .parse::<u64>()
                .map_err(|e| format!("bad {what} in '{s}': {e}"))
        };
        let major = next("major")?;
        let minor = next("minor")?;
        let patch = next("patch")?;
        if parts.next().is_some() {
            return Err(format!("too many dotted components in '{s}'"));
        }
        Ok(WireVersion {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Is this a version whose CC 2.6.4 compatibility rules "bind strictly"? True
    /// only for a PUBLISHED 1.0+ (major ≥ 1, no pre-release tag). The 0.x series is
    /// explicitly "unstable until 1.0 publication", and an `-rcN` is by definition
    /// not yet that publication.
    pub fn is_stable(&self) -> bool {
        self.major >= 1 && self.pre.is_none()
    }

    /// **The CC 2.6.4 compatibility predicate** — "a peer knows from the version
    /// alone whether it can still interoperate":
    ///
    ///   - Differing MAJOR ⇒ NEVER interoperable (MAJOR *is* the wire-break
    ///     announcement).
    ///   - Both STABLE (≥ 1.0.0, no pre-release) and equal MAJOR ⇒ interoperable:
    ///     MINOR is a wire-compatible addition ("existing Conforming Producers and
    ///     Consumers continue to interoperate without modification") and PATCH is
    ///     editorial. A newer peer's added fields ride the CC 2.1.1 forward-compat
    ///     rule (ignore-unknown), which this node already implements.
    ///   - Otherwise (either side 0.x or a pre-release) ⇒ interoperable ONLY on an
    ///     exact MINOR **and** pre-release match: "any 0.x → 0.(x+1) bump MAY include
    ///     wire-breaking changes; consumers MUST treat 0.x as unstable until 1.0
    ///     publication". PATCH may still differ (editorial-only by definition).
    pub fn interoperates_with(&self, peer: &WireVersion) -> bool {
        if self.major != peer.major {
            return false;
        }
        if self.is_stable() && peer.is_stable() {
            return true;
        }
        self.minor == peer.minor && self.pre == peer.pre
    }
}

impl fmt::Display for WireVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// The SHA-256 of the ratified `WIRE_VOCABULARY.md` this build is pinned to, hex.
///
/// CC 2.6.4: "Every ratifying repo **pins the artifact's SHA-256 at build**; a hash
/// mismatch at cohabitation is a substrate-tier build failure, not a warning." The
/// build-time half of that gate is `tests/wire_vocabulary_gate.rs` (edge's exported
/// hash vs the ratified constant); this is the RUNTIME half — the value we publish
/// to peers and compare a peer's announcement against in [`negotiate`].
pub fn wire_vocabulary_sha256() -> String {
    hex::encode(ciris_edge::WIRE_VOCABULARY_HASH)
}

// ─── CC 2.6.4 — the persist-owned CEG contract-hash fingerprint (SRV-2) ──────
//
// CIRISServer#323. `wire_vocabulary_sha256` above is edge's hash of the *message
// TYPE set*. persist v20.0.0 (#495) generalized that same "pin a canonical
// manifest's SHA-256, gate it with a `computed == pinned` witness" discipline to
// the CEG's *field/semantics* contracts, and v21 added two more. Each persist
// contract ships a `pub const` PIN + a `pub fn` that RECOMPUTES the hash over the
// live manifest, with an internal `*_is_pinned` test asserting the two agree.
//
// Two of these carry a doc line in persist that ALREADY asserts server behavior —
// `ENVELOPE_VOCABULARY_SHA256` ("CIRISServer serves the hash on /v1/health,
// consumers assert it") and `TRACE_SUMMARY_EXTRACTION_SHA256` ("served by
// CIRISServer beside `wire_vocabulary_sha256`; asserted by the agent's emitter
// contract test"). Before #323 that claim was FALSE: `/v1/health` served only
// `wire_vocabulary_sha256`. [`contract_hashes`] makes the spec true, and extends
// the surface to the two other PEER-FACING CEG-semantics contracts a consumer
// must agree on to interpret the same wire bytes the same way — the consent
// grammar and the transform algebra — so one health read fingerprints the whole
// wire+semantics contract this build speaks.

/// One persist-owned CEG contract this node fingerprints on `/v1/health`.
struct ContractHash {
    /// The stable snake_case key served under `conformance.contract_hashes`
    /// (the `wire_vocabulary_sha256` naming convention; persist names two of the
    /// consts `*_HASH`, but every one is a SHA-256 hex, so the wire key is `_sha256`).
    key: &'static str,
    /// persist's PINNED hash const — the value this build speaks and serves.
    pinned: &'static str,
    /// persist's recompute-from-live-manifest fn — the RHS of the boot
    /// drift-witness ([`assert_contract_hashes_pinned`]).
    recompute: fn() -> String,
}

/// The persist-owned CEG contracts whose hashes `/v1/health` publishes.
///
/// The replication APPLY-authority hash
/// (`ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH`) is
/// deliberately NOT here: it is the per-`EnvelopeKind` admission/projection policy,
/// already pinned as a cross-repo build gate in `tests/replication_policy_gate.rs`
/// (with edge's `SERVE_ADVERTISE_POLICY_HASH`). It governs how records are ADMITTED,
/// not which wire vocabulary/semantics a bare-node liveness check fingerprints, so
/// it stays on its dedicated gate rather than the public health surface.
const CONTRACT_HASHES: &[ContractHash] = &[
    // v20.0.0 #495 — persist's doc asserts /v1/health serves this. `federation/envelope.rs`.
    ContractHash {
        key: "envelope_vocabulary_sha256",
        pinned: ciris_persist::federation::envelope::ENVELOPE_VOCABULARY_SHA256,
        recompute: ciris_persist::federation::envelope::envelope_vocabulary_sha256,
    },
    // v20.0.0 #495 — persist's doc asserts /v1/health serves this; the Python
    // trace emitter binds the same manifest. `trace_summary_contract.rs`.
    ContractHash {
        key: "trace_summary_extraction_sha256",
        pinned: ciris_persist::trace_summary_contract::TRACE_SUMMARY_EXTRACTION_SHA256,
        recompute: ciris_persist::trace_summary_contract::extraction_manifest_sha256,
    },
    // The consent grammar — how a `consent:*` envelope's directions/audiences/ops
    // are interpreted. A peer that reads it differently diverges on the SAME bytes.
    // `federation/consent_grammar.rs`.
    ContractHash {
        key: "consent_grammar_sha256",
        pinned: ciris_persist::federation::consent_grammar::CONSENT_GRAMMAR_HASH,
        recompute: ciris_persist::federation::consent_grammar::consent_grammar_sha256,
    },
    // The transform algebra — the strictly-total opcode set disclosure transforms
    // compute in. Same-bytes-different-meaning risk as the grammar. `federation/transform.rs`.
    ContractHash {
        key: "transform_algebra_sha256",
        pinned: ciris_persist::federation::transform::TRANSFORM_ALGEBRA_HASH,
        recompute: ciris_persist::federation::transform::transform_algebra_sha256,
    },
];

/// The `conformance.contract_hashes` object served on `/v1/health` beside
/// [`wire_vocabulary_sha256`]: `{ <stable key>: <persist's pinned hash> }` for
/// every [`CONTRACT_HASHES`] entry. A peer or the KMP client fetches this and
/// asserts it against its own substrate; a vocabulary/grammar/algebra change on
/// either side fails loudly on both (the CC 2.6.4 hash-pinned-artifact discipline).
pub fn contract_hashes() -> serde_json::Value {
    serde_json::Value::Object(
        CONTRACT_HASHES
            .iter()
            .map(|c| {
                (
                    c.key.to_string(),
                    serde_json::Value::String(c.pinned.to_string()),
                )
            })
            .collect(),
    )
}

/// **Boot drift-witness** (CIRISServer#323). For every contract hash this node
/// SERVES, persist's PINNED const must equal what persist RECOMPUTES over its live
/// manifest IN THE BINARY WE LINKED. persist's own `*_is_pinned` tests prove this in
/// persist's CI; re-running it at the server's boot proves the persist crate we
/// actually link is self-consistent — so the fingerprint we publish is one the
/// substrate can reproduce, never a stale or hand-patched const. A mismatch is a
/// substrate-tier failure, not a warning (CC 2.6.4), so this PANICS: the node
/// refuses to boot rather than serve a `/v1/health` contract it cannot stand behind.
///
/// This is the RUNTIME half. The cross-repo RATIFIED pin — the deliberate,
/// reviewed re-pin a persist bump that changes a hash must travel with — is the
/// BUILD-TIME half, gated in the `tests/` contract-drift suite alongside
/// `tests/replication_policy_gate.rs` (mirroring that same `assert_eq!` witness).
pub fn assert_contract_hashes_pinned() {
    for c in CONTRACT_HASHES {
        let recomputed = (c.recompute)();
        assert_eq!(
            c.pinned, recomputed,
            "CEG contract-hash drift for `{}`: persist PINS {} but RECOMPUTES {} over its \
             live manifest — the linked persist crate is internally inconsistent. This node \
             will not serve a /v1/health fingerprint it cannot reproduce (CC 2.6.4: a hash \
             mismatch is a substrate-tier failure, not a warning). Re-pin the persist const \
             deliberately and re-adopt the substrate.",
            c.key, c.pinned, recomputed,
        );
    }
}

// ─── The declaration ─────────────────────────────────────────────────────────

/// THIS node's declared conformance + wire identity — the typed surface CC 2.2
/// asks for, served to peers (`GET /v1/federation/conformance`), echoed in every
/// peering response (so the REQUESTER can refuse US — negotiation is symmetric),
/// and summarized on `/v1/health`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeclaredConformance {
    /// The CC 2.2 profiles this node CLAIMS (sorted, deduped). EMPTY on a
    /// fail-closed declaration error — an empty claim refuses every wire op.
    pub profiles: Vec<ConformanceProfile>,
    /// The profiles this BINARY implements ([`BUILD_PROFILES`]) — the ceiling. A
    /// peer can see that a narrow declaration is a POLICY choice, not a capability
    /// gap.
    pub build_profiles: Vec<ConformanceProfile>,
    /// The CEG wire version this node speaks ([`CEG_WIRE_VERSION`]).
    pub ceg_wire_version: String,
    /// The pinned wire-vocabulary SHA-256 ([`wire_vocabulary_sha256`]).
    pub wire_vocabulary_sha256: String,
    /// `true` when the declaration came from a live `config:*` object; `false` when
    /// it is the [`BUILD_PROFILES`] default (nothing declared) — so an operator can
    /// tell "I meant this" from "nobody has said anything".
    pub declared_by_config: bool,
}

impl DeclaredConformance {
    /// Does the node claim `profile`?
    pub fn claims(&self, profile: ConformanceProfile) -> bool {
        self.profiles.contains(&profile)
    }

    /// The profiles `needed` that this declaration does NOT claim (empty ⇒ the op
    /// may proceed).
    pub fn missing(&self, needed: &[ConformanceProfile]) -> Vec<ConformanceProfile> {
        needed
            .iter()
            .copied()
            .filter(|p| !self.claims(*p))
            .collect()
    }
}

/// Parse a raw declaration (the `config:*` list) into the claimed profile set.
///
/// FAIL-CLOSED, deliberately harshly:
///   - An UNKNOWN token (`"CCX"`, a typo, a profile from a future CC) invalidates
///     the WHOLE declaration → `Err` → the caller declares NOTHING. We refuse to
///     silently drop the token and act on the remainder: an operator who wrote a
///     profile we do not understand has not told us what they meant, and the safe
///     reading of "I do not understand your claim" is "you have claimed nothing".
///   - A token naming a profile OUTSIDE [`BUILD_PROFILES`] is likewise an error —
///     a node may never claim a profile its code does not implement.
///   - An EMPTY list is a VALID declaration meaning "I claim nothing" (a pure
///     serve-only / local-tier node) — it is not an error, it is a posture.
pub fn parse_declaration(tokens: &[String]) -> Result<Vec<ConformanceProfile>, String> {
    let mut set: BTreeSet<ConformanceProfile> = BTreeSet::new();
    for tok in tokens {
        let p = ConformanceProfile::parse(tok)
            .ok_or_else(|| format!("unknown CC 2.2 conformance profile token '{tok}'"))?;
        if !BUILD_PROFILES.contains(&p) {
            return Err(format!(
                "this build does not implement {} ({}) — a node may not declare a \
                 profile it cannot perform",
                p.as_str(),
                p.title()
            ));
        }
        set.insert(p);
    }
    Ok(set.into_iter().collect())
}

/// Resolve THIS node's [`DeclaredConformance`] from the CEG.
///
/// Reads [`KEY_CONFORMANCE_PROFILES`]. Three outcomes, all fail-closed except the
/// documented default:
///   - key ABSENT           → [`BUILD_PROFILES`] (`declared_by_config: false`).
///   - key present + valid  → the declared subset (`declared_by_config: true`).
///   - key present + INVALID, or the config read FAILS (store error, unreadable
///     rows) → the EMPTY set. A node that cannot establish what it claims claims
///     NOTHING, and every profile-gated wire op is refused until the operator fixes
///     the declaration. (Loud: the failure is logged at `error`.)
pub async fn declared(engine: &Arc<Engine>) -> DeclaredConformance {
    let build: Vec<ConformanceProfile> = BUILD_PROFILES.to_vec();
    let base = |profiles: Vec<ConformanceProfile>, declared_by_config: bool| DeclaredConformance {
        profiles,
        build_profiles: build.clone(),
        ceg_wire_version: CEG_WIRE_VERSION.to_string(),
        wire_vocabulary_sha256: wire_vocabulary_sha256(),
        declared_by_config,
    };
    match crate::graph_config::get_config(engine, KEY_CONFORMANCE_PROFILES).await {
        Ok(None) => base(build.clone(), false),
        Ok(Some(entry)) => {
            let Some(tokens) = entry.value.as_str_list() else {
                tracing::error!(
                    key = KEY_CONFORMANCE_PROFILES,
                    "CC 2.2: conformance declaration is not a list of profile tokens — \
                     the node declares NOTHING (fail-closed); every federation-wire op \
                     is refused until it is fixed"
                );
                return base(Vec::new(), true);
            };
            match parse_declaration(&tokens) {
                Ok(profiles) => base(profiles, true),
                Err(e) => {
                    tracing::error!(
                        key = KEY_CONFORMANCE_PROFILES,
                        error = %e,
                        "CC 2.2: invalid conformance declaration — the node declares \
                         NOTHING (fail-closed)"
                    );
                    base(Vec::new(), true)
                }
            }
        }
        Err(e) => {
            tracing::error!(
                key = KEY_CONFORMANCE_PROFILES,
                error = %e,
                "CC 2.2: could not read the conformance declaration — the node declares \
                 NOTHING (fail-closed)"
            );
            base(Vec::new(), false)
        }
    }
}

// ─── The op → profile map (the enforcement vocabulary) ───────────────────────

/// **The CC 2.2 enforcement map**: the profiles an owner-gated op EXERCISES on the
/// federation wire. The match is exhaustive on [`CapabilityVerb`] on purpose — a
/// new gated op cannot be added without deciding, at compile time, which
/// conformance profiles it needs (the same fail-closed discipline that makes
/// `CapabilityVerb` non-`Default`).
///
/// An op mapped to `&[]` exercises NO federation-wire role (it is a local-tier /
/// custody op) and is therefore not conformance-gated — it is still, of course,
/// owner/role/delegation-gated by `auth::gate`.
pub fn required_profiles(verb: CapabilityVerb) -> &'static [ConformanceProfile] {
    use ConformanceProfile::{Consumer, Producer, Substrate};
    match verb {
        // Peering is the full federation-wire act: this node EMITS a hybrid-signed
        // `consent:replication:v1` grant (CCP), ADMITS the peer's self-signed key
        // record through the fail-secure admission gate (CCC), and thereafter
        // REPLICATES rows to/from the peer under the CC 5.3.1 / 5.3.2 storage +
        // transport guarantees (CCS). All three profiles, or no peering.
        CapabilityVerb::Peer => &[Producer, Consumer, Substrate],
        // Claiming a REMOTE node emits an owner-binding onto the wire (CCP) and
        // admits the remote's key record (CCC).
        CapabilityVerb::ClaimRemote => &[Producer, Consumer],
        // Announce publishes this node's identity attestation onto the mesh (CCP)
        // and requires the transport substrate to carry it (CCS).
        CapabilityVerb::Announce => &[Producer, Substrate],
        // A relayed control op rides the mesh transport (store-and-forward /
        // idempotent delivery — CC 5.3.1), i.e. the substrate role.
        CapabilityVerb::MeshRelay => &[Substrate],
        // A delegation is a signed `delegates_to` envelope on the wire (CCP).
        CapabilityVerb::Delegate => &[Producer],
        // The accord kill-switch emits a hybrid-signed Invocation (CCP).
        CapabilityVerb::AccordHalt => &[Producer],
        // Local-tier / custody ops — no federation-wire role is exercised, so no
        // CC 2.2 profile is required (they remain owner-gated).
        //
        // CIRISServer#356: the operator surface is a pure READ of state this
        // node already holds — it puts nothing on the wire and admits nothing
        // from it, so it exercises no profile. Conformance-gating a gauge would
        // make a node that cannot declare its profiles also unable to say WHY,
        // which is the failure mode the surface exists to remove.
        CapabilityVerb::ConfigWrite
        | CapabilityVerb::SetAge
        | CapabilityVerb::Wipe
        | CapabilityVerb::ReadNodeState => &[],
    }
}

/// Why an op was refused by the CC 2.2 gate — serialized into the `403` body so the
/// operator sees exactly which profile the node does not claim, and where to fix it.
#[derive(Debug, Clone, Serialize)]
pub struct ConformanceRefusal {
    /// Always `conformance_level` — the stable machine token.
    pub error: &'static str,
    /// The verb that was attempted (`peer`, `announce`, …).
    pub verb: &'static str,
    /// The profiles the op requires.
    pub required: Vec<&'static str>,
    /// The profiles the node DECLARES.
    pub declared: Vec<&'static str>,
    /// The required profiles the declaration does not claim (the reason).
    pub missing: Vec<&'static str>,
    /// Human-readable detail, naming the config key to fix.
    pub detail: String,
}

/// **The CC 2.2 enforcement point.** `None` ⇒ the node's declared level claims every
/// profile the op exercises and it may proceed; `Some(response)` ⇒ the ready `403`
/// to `return` from the handler (`Option`, not `Result`, so the large `Response`
/// isn't a `result_large_err` — same shape as `auth::gate::require_verb`).
///
/// This is the "HONOR it" half of CC 2.2: a node that does not claim a profile does
/// not act in that role on the wire, whatever its role/session authority.
#[must_use]
pub async fn require_op(
    engine: &Arc<Engine>,
    verb: CapabilityVerb,
) -> Option<axum::response::Response> {
    let declared = declared(engine).await;
    refuse_if_unclaimed(&declared, verb).map(refusal_response)
}

/// The pure core of [`require_op`] (unit-testable without an Engine): the refusal,
/// or `None` when the declaration claims everything the verb needs.
pub fn refuse_if_unclaimed(
    declared: &DeclaredConformance,
    verb: CapabilityVerb,
) -> Option<ConformanceRefusal> {
    let required = required_profiles(verb);
    let missing = declared.missing(required);
    if missing.is_empty() {
        return None;
    }
    Some(ConformanceRefusal {
        error: "conformance_level",
        verb: verb.as_str(),
        required: required.iter().map(|p| p.as_str()).collect(),
        declared: declared.profiles.iter().map(|p| p.as_str()).collect(),
        missing: missing.iter().map(|p| p.as_str()).collect(),
        detail: format!(
            "'{}' requires the CC 2.2 conformance profile(s) {} — this node does not declare \
             {}. A node performs on the federation wire only the roles it CLAIMS (CC 2.2). \
             Fix the declaration: PUT /v1/config/{} (e.g. [\"CCP\",\"CCC\",\"CCS\"]).",
            verb.as_str(),
            missing
                .iter()
                .map(|p| format!("{} ({})", p.as_str(), p.title()))
                .collect::<Vec<_>>()
                .join(" + "),
            missing
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            KEY_CONFORMANCE_PROFILES,
        ),
    })
}

/// Render a [`ConformanceRefusal`] as the `403` a caller receives (kept here so
/// every conformance-gated op refuses with the same shape).
pub fn refusal_response(refusal: ConformanceRefusal) -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::FORBIDDEN, axum::Json(refusal)).into_response()
}

// ─── CC 2.6.4 — wire-version negotiation ─────────────────────────────────────

/// What a peer announces about its wire at a federation handshake. BOTH fields are
/// optional-with-documented-default (CC 2.6.4 MINOR rule + CC 2.1.1 forward-compat)
/// — see [`PRE_NEGOTIATION_WIRE_VERSION`] for why the default is pinned rather than
/// aliased to ours.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PeerWireAnnouncement {
    /// The peer's CEG wire version (SemVer 2.0.0, CC 2.6.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceg_wire_version: Option<String>,
    /// The SHA-256 (hex) of the `WIRE_VOCABULARY.md` the peer pinned at build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_vocabulary_sha256: Option<String>,
}

/// Why a peer's wire was REFUSED — serialized into the `409` body.
#[derive(Debug, Clone, Serialize)]
pub struct WireRefusal {
    /// `wire_version_incompatible` | `wire_version_malformed` | `wire_vocabulary_mismatch`.
    pub error: &'static str,
    /// What this node speaks.
    pub local_ceg_wire_version: String,
    /// What the peer announced (or the assumed pre-negotiation default).
    pub peer_ceg_wire_version: String,
    /// This node's pinned wire-vocabulary hash.
    pub local_wire_vocabulary_sha256: String,
    /// The peer's announced hash, when it sent one.
    pub peer_wire_vocabulary_sha256: Option<String>,
    /// Human-readable detail citing the rule.
    pub detail: String,
}

/// **The CC 2.6.4 enforcement point.** Negotiate a peer's wire against ours:
/// `Ok(negotiated)` — the peer's (or defaulted) version, which we have positively
/// established we interoperate with — or `Err(WireRefusal)`, which the caller turns
/// into a `409` and **refuses the federation op**. Never "log and continue": an
/// incompatible wire version silently tolerated is precisely the divergence CC 2.6.4
/// exists to make impossible ("a peer knows from the version alone whether it can
/// still interoperate").
///
/// The refusal is BOXED — it is the cold path, and an unboxed `WireRefusal` (five
/// strings) makes the `Err` variant dominate every `Ok` return (clippy
/// `result_large_err`).
pub fn negotiate(announced: &PeerWireAnnouncement) -> Result<WireVersion, Box<WireRefusal>> {
    let local = WireVersion::parse(CEG_WIRE_VERSION)
        .expect("CEG_WIRE_VERSION is a compile-time constant and MUST parse");
    let local_hash = wire_vocabulary_sha256();
    let refuse = |error: &'static str, peer_v: String, detail: String| {
        Box::new(WireRefusal {
            error,
            local_ceg_wire_version: local.to_string(),
            peer_ceg_wire_version: peer_v,
            local_wire_vocabulary_sha256: local_hash.clone(),
            peer_wire_vocabulary_sha256: announced.wire_vocabulary_sha256.clone(),
            detail,
        })
    };

    // ── The version (omitted ⇒ the PINNED pre-negotiation default, see the const) ─
    let raw = announced
        .ceg_wire_version
        .clone()
        .unwrap_or_else(|| PRE_NEGOTIATION_WIRE_VERSION.to_string());
    let peer = match WireVersion::parse(&raw) {
        Ok(v) => v,
        // Fail-closed: a version we cannot parse is a version we cannot reason
        // about, and CC 2.6.4's whole promise is that the version tells us whether
        // we interoperate. If it doesn't parse, it doesn't tell us. Refuse.
        Err(e) => {
            return Err(refuse(
                "wire_version_malformed",
                raw.clone(),
                format!(
                    "peer announced a CEG wire version that is not SemVer 2.0.0 ({e}) — \
                     CC 2.6.4 requires the version to be machine-legible; refusing rather \
                     than guessing"
                ),
            ))
        }
    };
    if !local.interoperates_with(&peer) {
        let why = if local.major != peer.major {
            "a differing MAJOR is the CC 2.6.4 announcement of a WIRE-INCOMPATIBLE change \
             (field removal / semantic change / domain-separation or prefix break)"
        } else {
            "the CEG spec is pre-1.0-publication (0.x / release-candidate): CC 2.6.4 makes \
             every 0.MINOR (and every distinct pre-release) potentially wire-breaking, so \
             only an EXACT minor + pre-release match interoperates"
        };
        return Err(refuse(
            "wire_version_incompatible",
            peer.to_string(),
            format!(
                "peer speaks CEG {peer}, this node speaks CEG {local} — {why}. Refused: \
                 CC 2.6.4 forbids proceeding on a wire we cannot prove we share."
            ),
        ));
    }

    // ── The wire vocabulary (CC 2.6.4 hash-pinned artifact) ───────────────────
    // "a hash mismatch at cohabitation is a substrate-tier build failure, not a
    // warning" — the build-time half is tests/wire_vocabulary_gate.rs; this is the
    // peer-facing half. Absent ⇒ the peer predates the field and, per the version
    // check above, is on our wire (which pins the same ratified artifact).
    if let Some(peer_hash) = announced.wire_vocabulary_sha256.as_deref() {
        let peer_hash = peer_hash.trim().to_ascii_lowercase();
        // Shape first (CC 2.6.3: lowercase, unpadded, byte-length-exact hex).
        if peer_hash.len() != 64 || !peer_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(refuse(
                "wire_vocabulary_mismatch",
                peer.to_string(),
                "peer announced a malformed wire-vocabulary hash (CC 2.6.3 requires a \
                 lowercase, unpadded, 64-char SHA-256 hex) — refused"
                    .to_string(),
            ));
        }
        if peer_hash != local_hash {
            return Err(refuse(
                "wire_vocabulary_mismatch",
                peer.to_string(),
                format!(
                    "peer pinned WIRE_VOCABULARY.md sha256={peer_hash}, this node pinned \
                     {local_hash} — the peers recognize DIFFERENT message-type sets. CC 2.6.4: \
                     'a hash mismatch at cohabitation is a substrate-tier build failure, not a \
                     warning'. Refused."
                ),
            ));
        }
    }
    Ok(peer)
}

/// Render a [`WireRefusal`] as the `409 Conflict` a peer receives. `409` (not `400`):
/// the request is well-formed, but it CONFLICTS with the state of this node's wire —
/// the peer must upgrade/downgrade, not re-phrase.
pub fn wire_refusal_response(refusal: WireRefusal) -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::CONFLICT, axum::Json(refusal)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(profiles: Vec<ConformanceProfile>) -> DeclaredConformance {
        DeclaredConformance {
            profiles,
            build_profiles: BUILD_PROFILES.to_vec(),
            ceg_wire_version: CEG_WIRE_VERSION.to_string(),
            wire_vocabulary_sha256: wire_vocabulary_sha256(),
            declared_by_config: true,
        }
    }

    #[test]
    fn full_declaration_claims_every_op() {
        let d = decl(BUILD_PROFILES.to_vec());
        for verb in [
            CapabilityVerb::Peer,
            CapabilityVerb::ClaimRemote,
            CapabilityVerb::Announce,
            CapabilityVerb::MeshRelay,
            CapabilityVerb::Delegate,
            CapabilityVerb::AccordHalt,
            CapabilityVerb::ConfigWrite,
        ] {
            assert!(
                refuse_if_unclaimed(&d, verb).is_none(),
                "a full CC 2.2 declaration must claim {}",
                verb.as_str()
            );
        }
    }

    #[test]
    fn consumer_only_node_refuses_peering_and_announce() {
        let d = decl(vec![ConformanceProfile::Consumer]);
        let r =
            refuse_if_unclaimed(&d, CapabilityVerb::Peer).expect("CCC-only must refuse peering");
        assert_eq!(r.error, "conformance_level");
        assert_eq!(r.missing, vec!["CCP", "CCS"]);
        let r =
            refuse_if_unclaimed(&d, CapabilityVerb::Announce).expect("CCC-only refuses announce");
        assert_eq!(r.missing, vec!["CCP", "CCS"]);
        // …but a local-tier op that exercises no wire role is NOT conformance-gated.
        assert!(refuse_if_unclaimed(&d, CapabilityVerb::ConfigWrite).is_none());
    }

    #[test]
    fn empty_declaration_refuses_every_wire_op() {
        let d = decl(Vec::new());
        for verb in [
            CapabilityVerb::Peer,
            CapabilityVerb::ClaimRemote,
            CapabilityVerb::Announce,
            CapabilityVerb::MeshRelay,
            CapabilityVerb::Delegate,
            CapabilityVerb::AccordHalt,
        ] {
            assert!(
                refuse_if_unclaimed(&d, verb).is_some(),
                "a node that claims nothing must refuse {}",
                verb.as_str()
            );
        }
    }

    #[test]
    fn declaration_parse_is_fail_closed() {
        assert_eq!(
            parse_declaration(&["CCP".into(), "ccc".into()]).expect("valid"),
            vec![ConformanceProfile::Producer, ConformanceProfile::Consumer]
        );
        // Deduped + sorted (deterministic on the wire).
        assert_eq!(
            parse_declaration(&["CCS".into(), "CCP".into(), "CCS".into()]).expect("valid"),
            vec![ConformanceProfile::Producer, ConformanceProfile::Substrate]
        );
        // An empty list is a POSTURE ("I claim nothing"), not an error.
        assert_eq!(parse_declaration(&[]).expect("valid"), Vec::new());
        // An unknown token invalidates the WHOLE declaration (never a silent drop).
        assert!(parse_declaration(&["CCP".into(), "CCX".into()]).is_err());
    }

    #[test]
    fn semver_parse_is_strict() {
        let v = WireVersion::parse("1.2.3").expect("triple");
        assert_eq!((v.major, v.minor, v.patch, v.pre.clone()), (1, 2, 3, None));
        let v = WireVersion::parse("1.0.0-rc2+build.7").expect("pre + build meta");
        assert_eq!(v.pre.as_deref(), Some("rc2"));
        assert_eq!(v.to_string(), "1.0.0-rc2", "build metadata is discarded");
        for bad in ["", "1.0", "1.0.0.0", "x.y.z", "1.0.0-", "1.-1.0"] {
            assert!(WireVersion::parse(bad).is_err(), "'{bad}' must not parse");
        }
    }

    #[test]
    fn cc_2_6_4_compatibility_mapping() {
        let one_two_zero = WireVersion::parse("1.2.0").expect("v");
        // Stable, same MAJOR: MINOR/PATCH additions are wire-compatible.
        assert!(one_two_zero.interoperates_with(&WireVersion::parse("1.5.9").expect("v")));
        assert!(one_two_zero.interoperates_with(&WireVersion::parse("1.0.0").expect("v")));
        // Differing MAJOR is THE wire-break announcement.
        assert!(!one_two_zero.interoperates_with(&WireVersion::parse("2.0.0").expect("v")));
        assert!(!one_two_zero.interoperates_with(&WireVersion::parse("0.9.0").expect("v")));
        // 0.x is unstable: MINOR must match exactly.
        let zero_five = WireVersion::parse("0.5.1").expect("v");
        assert!(zero_five.interoperates_with(&WireVersion::parse("0.5.9").expect("v")));
        assert!(!zero_five.interoperates_with(&WireVersion::parse("0.6.0").expect("v")));
        // A pre-release is not the published 1.0 — exact pre-release match only.
        let rc2 = WireVersion::parse("1.0.0-rc2").expect("v");
        assert!(rc2.interoperates_with(&WireVersion::parse("1.0.0-rc2").expect("v")));
        assert!(!rc2.interoperates_with(&WireVersion::parse("1.0.0-rc1").expect("v")));
        assert!(!rc2.interoperates_with(&WireVersion::parse("1.0.0").expect("v")));
    }

    #[test]
    fn negotiate_accepts_our_own_wire_and_the_omitted_default() {
        // A peer announcing exactly our wire (the fleet case).
        let ok = negotiate(&PeerWireAnnouncement {
            ceg_wire_version: Some(CEG_WIRE_VERSION.to_string()),
            wire_vocabulary_sha256: Some(wire_vocabulary_sha256()),
        })
        .expect("our own wire must interoperate with itself");
        assert_eq!(ok.to_string(), CEG_WIRE_VERSION);
        // A pre-negotiation peer (omits both) → the documented default.
        let ok = negotiate(&PeerWireAnnouncement::default()).expect("omitted ⇒ documented default");
        assert_eq!(ok.to_string(), PRE_NEGOTIATION_WIRE_VERSION);
    }

    #[test]
    fn negotiate_refuses_incompatible_and_malformed_wires() {
        // MAJOR break.
        let e = negotiate(&PeerWireAnnouncement {
            ceg_wire_version: Some("2.0.0".into()),
            wire_vocabulary_sha256: None,
        })
        .expect_err("a MAJOR break must be refused");
        assert_eq!(e.error, "wire_version_incompatible");
        // Unparseable ⇒ refuse, never guess.
        let e = negotiate(&PeerWireAnnouncement {
            ceg_wire_version: Some("banana".into()),
            wire_vocabulary_sha256: None,
        })
        .expect_err("a malformed version must be refused");
        assert_eq!(e.error, "wire_version_malformed");
        // A DIFFERENT ratified wire vocabulary ⇒ different message-type sets.
        let e = negotiate(&PeerWireAnnouncement {
            ceg_wire_version: Some(CEG_WIRE_VERSION.into()),
            wire_vocabulary_sha256: Some("00".repeat(32)),
        })
        .expect_err("a vocabulary-hash mismatch must be refused");
        assert_eq!(e.error, "wire_vocabulary_mismatch");
        // A malformed hash ⇒ refuse on shape (CC 2.6.3).
        let e = negotiate(&PeerWireAnnouncement {
            ceg_wire_version: Some(CEG_WIRE_VERSION.into()),
            wire_vocabulary_sha256: Some("NOTHEX".into()),
        })
        .expect_err("a malformed hash must be refused");
        assert_eq!(e.error, "wire_vocabulary_mismatch");
    }
}
