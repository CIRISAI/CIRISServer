//! Directed-consent federation peering (CIRISServer federation Round 2).
//!
//! Node A is a member of the canonical CIRIS infrastructure community; Node B
//! (`ciris-status`) is **out** of that group. Bidirectional replication A<->B is
//! therefore authorized NOT by in-group trust but by **directed consent
//! attestations** at federation scope, plus **mutual key registration** as the
//! admission door. This module owns Node A's side of that contract:
//!
//!   1. [`register_peer_key`] — register B's published hybrid pubkeys in A's
//!      `federation_keys` (identity_type `"witness"`), so B's replicated
//!      `health:liveness:*` attestations are admitted (`put_attestation`
//!      requires the attesting key to exist as a `federation_keys` row).
//!   2. [`emit_replication_consent`] — emit a directed `consent:replication:v1`
//!      `scores` attestation (subject = [B's key_id]) recording "A consents to
//!      replicate `capacity:*` to B." This is the auditable consent object;
//!      revocation rides the CEG withdraws/recants structural primitive later.
//!
//! Both are modeled on `compose::register_self_key` (key registration; benign
//! Conflict) and `scorer.rs` / CIRISStatus `ceg.rs::emit_liveness` (the
//! canonicalize → hybrid-sign → `put_attestation` emit recipe). The shared wire
//! contract (Node B builds the mirror side to the SAME shapes) fixes:
//! `consent:replication:v1`, a directed `scores` attestation, `cohort_scope =
//! "federation"`, FEDERATION tier, hybrid-signed by the granting node's steward
//! key, payload recording the grant intent.

use anyhow::Result;
use sha2::{Digest, Sha256};

use ciris_persist::federation::consent_grammar::RestrictionOp;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::types::{attestation_type, cohort_scope, identity_type};
use ciris_persist::federation::{EmitAttestationInput, Error as FederationError};
use ciris_persist::prelude::Engine;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

use crate::config::PeerB;

/// **CIRISConstitution#46 — the production producer for the `analyze` grant.**
///
/// v22 refuses a `capacity:*` claim about subject S from attester P unless a live
/// `analyze`-scoped consent from S covers P. Before this, the ONLY producer of
/// that row was the test-anchor harness, so **capacity scoring was structurally
/// dead in every real deployment** — the scorer would run, see the traces, and
/// author nothing (CIRISServer#331).
///
/// The claim is the edge `P → S`; the consent is the **REVERSE** edge `S → P`:
/// this node (the subject) attests, naming the attester, with the envelope naming
/// scope `analyze`.
///
/// Four details that are load-bearing, each one a trap the DX doc names:
///
/// 1. **`cohort_scope: federation`, not `self`.** The row is read on the SCORING
///    node, so it must replicate. A self-scoped grant resolves locally, looks
///    right in your own DB, and is invisible where it is actually consulted.
/// 2. **Vocabulary single-sourced from persist** — a hand-mirrored dimension or
///    scope literal compiles and skews the wire.
/// 3. **`subject_key_ids` left EMPTY.** It confers revocation authority, and this
///    node already holds that as producer; naming the attester there would hand
///    the scorer a say over the consent that authorizes it (the #528 G2 shape).
/// 4. **Idempotent on the RESOLVED STANCE, not on row existence** — a row that
///    exists but folds to `Unspecified` is the silent-false this whole arc keeps
///    curing.
///
/// Returns the grant's `attestation_id`, or `Ok(None)` when a live grant already
/// resolves (nothing to do).
pub async fn emit_analyze_consent(
    engine: &Engine,
    subject_key_id: &str,
    attester_key_id: &str,
) -> Result<Option<String>> {
    use ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE;
    use ciris_persist::federation::consent::consent_dimension;
    use ciris_persist::federation::hard_case::ConsentState;

    let now = chrono::Utc::now();
    if matches!(
        engine
            .federation_directory()
            .resolve_scoped_consent(
                attester_key_id,
                subject_key_id,
                ANALYZE_CONSENT_SCOPE,
                None,
                now,
            )
            .await?,
        ConsentState::Granted
    ) {
        return Ok(None);
    }

    let envelope = serde_json::json!({
        (paths::DIMENSION): format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
        "scope": ANALYZE_CONSENT_SCOPE,
    });
    let core = ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)
        .map_err(|e| anyhow::anyhow!("analyze-consent envelope: {e}"))?;
    let mut input = EmitAttestationInput::with_envelope(
        "consent",
        core,
        // See (1): read on the scoring node, so it MUST replicate.
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(attester_key_id.to_string());
    let id = engine.emit_attestation_self(input).await?;

    // Assert the FOLD, not the row (4). A grant that does not resolve is worse
    // than no grant: it reads as consented while the gate still refuses.
    match engine
        .federation_directory()
        .resolve_scoped_consent(
            attester_key_id,
            subject_key_id,
            ANALYZE_CONSENT_SCOPE,
            None,
            chrono::Utc::now(),
        )
        .await
    {
        Ok(ConsentState::Granted) => tracing::info!(
            subject = %subject_key_id,
            attester = %attester_key_id,
            scope = ANALYZE_CONSENT_SCOPE,
            attestation_id = %id,
            "CC#46 `analyze` consent authored and RESOLVED — the attester may now author \
             capacity:* about this node"
        ),
        Ok(other) => tracing::error!(
            subject = %subject_key_id,
            attester = %attester_key_id,
            resolved = ?other,
            "CC#46 `analyze` consent row authored but the scoped fold does NOT resolve to \
             Granted — capacity:* will still be refused. Check the envelope scope shape and \
             the row's tier/cohort_scope"
        ),
        Err(e) => tracing::error!(error = %e, "analyze consent: resolve_scoped_consent failed"),
    }
    Ok(Some(id))
}

/// The directed-consent dimension the A<->B replication grant rides on.
/// **Versioned** (`:v1`) to satisfy persist's
/// `DimensionAdmissionPolicy { require_version_segment: true }`. Open-vocab
/// (`consent:` is NOT a reserved prefix), so a steward-keyed attestation on it
/// is admitted without a reserved-prefix role.
pub const CONSENT_DIMENSION: &str = "consent:replication:v1";

/// What A consents to replicate to B by **default** (boot-env peering, when the
/// caller supplies no explicit set). The grant payload carries these as the JCS
/// array of namespace-prefix strings (trailing ":" significant), **sorted
/// ascending + deduplicated** (see [`normalize_prefixes`]) so consumers agree
/// byte-for-byte.
///
/// # `trace:` is here because it is the whole point of the grant
///
/// This was `["capacity:"]` alone, which had the direction backwards: a node
/// does not author `capacity:*` ABOUT ITSELF — the canonical does, and sends it
/// back. What a node replicates UPSTREAM is its traces. So the default granted
/// the one family that barely flows in this direction and withheld the one that
/// matters.
///
/// The consequence was total and silent. `promote_consented_backlog` only sweeps
/// rows whose dimension a live grant's `attestation_prefixes` COVER, so every
/// `trace:complete:v1` row stayed at `(cohort_scope=self, tier=local)`, the offer
/// filter (which keys on `cohort_scope`) never saw it, and the node reported
/// "converged to 1 consent peers" while shipping nothing. Measured in the field:
/// ZERO trace_events had ever reached the production canonical, from any node.
///
/// It survived because the mesh-repro harness passes its prefixes EXPLICITLY
/// (`author_federation_consent(peer, ["trace:","capacity:"])`, lib.rs) and so
/// never exercised this default — the green traceflow run reports
/// `covered_prefixes: ["capacity:","trace:"]`. A fixture that supplies the value
/// production defaults cannot prove the default; it proved a path production
/// could not take. `default_covers_the_trace_plane` below is the gate.
pub const DEFAULT_GRANT_ATTESTATION_PREFIXES: &[&str] = &["capacity:", "trace:"];

/// **The operator-facing consent disclosure — the copy a setup wizard SHOWS.**
///
/// # Why this ships from the wheel instead of living in the wizard
///
/// Everything a wizard needs to explain the consent choice is already knowable
/// here: which grants exist, which is optional, and exactly what declining the
/// optional one costs. A wizard that writes its own version of that paragraph
/// drifts from the substrate the moment either changes — and every time
/// something in this system was restated rather than read, it forked:
///
///   * the harness restated `["trace:","capacity:"]` and stayed green for eight
///     releases while production shipped `["capacity:"]` and moved zero traces;
///   * a docstring restated the consent route and sent an in-fold wizard to an
///     HTTP path that 404s by construction.
///
/// So the wizard renders this. It does not compose it.
///
/// # Localization
///
/// Every human-readable string is `{"id": …, "text": …}`. `id` is a **stable
/// message key**; `text` is the English source. A wizard resolves `id` against
/// its catalogue and falls back to `text` when there is no translation yet — so
/// a locale that lags a release degrades to English rather than to a blank
/// screen or a stale translation of different content.
///
/// **The ids are wire-stable.** Renaming one silently un-translates that string
/// in every locale, which reads exactly like a missing translation and not at
/// all like a rename. If the MEANING changes, mint a new id (`…:v2`) rather than
/// editing the text under the old one — a catalogue cannot tell that the English
/// moved, and a stale translation asserting the old meaning is worse than
/// English. `tests/fold_consent_surface.rs` pins the id set.
pub fn consent_disclosure_json() -> String {
    use ciris_persist::federation::admission::ANALYZE_CONSENT_SCOPE;
    use ciris_persist::federation::consent::consent_dimension;
    use ciris_persist::federation::envelope::paths;

    /// One localizable string: a stable key plus its English source.
    fn m(id: &str, text: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "text": text })
    }

    serde_json::json!({
        // The locale THIS build's `text` fields are written in. A wizard that
        // resolves every id needs none of them; one that falls back needs to
        // know what it is falling back TO, so it can mark it rather than
        // present English as if it were the user's language.
        "source_locale": "en",
        // The screen is ONE primary action with the detail expandable beneath
        // it. An operator who expands nothing still gave a real consent, so the
        // button's own label has to name the whole bundle rather than the first
        // item in it.
        "primary_action": m(
            "consent.mesh_participation.action",
            "Consent to CIRIS Mesh Participation"
        ),
        "details_expandable": true,
        "grants": [
            {
                "id": "replication",
                "required": true,
                "title": m("consent.grant.replication.title", "Send traces"),
                "permits": m(
                    "consent.grant.replication.permits",
                    "The peer may HOLD your traces."
                ),
                (paths::DIMENSION): "consent:replication:v1",
                "covers": default_attestation_prefixes(),
            },
            {
                "id": "analyze",
                "required": false,
                "title": m("consent.grant.analyze.title", "Be scored"),
                "permits": m(
                    "consent.grant.analyze.permits",
                    "The peer may SCORE your traces — this is what builds reputation."
                ),
                (paths::DIMENSION): format!("{}:v1", consent_dimension::STATE_GRANTED_PREFIX),
                "scope": ANALYZE_CONSENT_SCOPE,
                "parameter": "analyze=True",
            },
        ],
        // Two grants, two edges, opposite directions. Authoring one implies
        // NOTHING about the other — say so, because the natural reading of
        // "share my traces" is that scoring comes with it, and it does not.
        "independent": m(
            "consent.grants.independent",
            "These are separate consents on opposite edges. Granting one does not grant the \
             other, and either can be withdrawn without the other."
        ),
        "declining_analyze": {
            "allowed": true,
            "summary": m(
                "consent.decline_analyze.summary",
                "You may send traces without consenting to be analyzed. Traces will still flow."
            ),
            "costs": [
                m(
                    "consent.decline_analyze.cost.no_reputation",
                    "You build NO reputation — every capacity:* claim about you is refused, so \
                     none can ever exist."
                ),
                m(
                    "consent.decline_analyze.cost.no_capability_services",
                    "You cannot use streams or services that require third-party capability \
                     attestations, because you will not have any."
                ),
                m(
                    "consent.decline_analyze.cost.peers_may_refuse",
                    "Some peers may refuse to interact with you at all."
                ),
            ],
        },
        // ── Location: the H3 cell on the envelope ───────────────────────────
        //
        // ONE representation, used by everything — server, agent, every
        // producer. CEG 0.8 §0.8 makes it a signed `LocationProof` carrying an
        // H3 `cell_id` + `cell_resolution`. There is no second location format
        // anywhere in the system, and a producer that ships raw coordinates
        // instead is non-conformant rather than merely different.
        //
        // **What it is FOR: reporting patterns across regions.** A coarse cell is
        // what lets regional patterns be reported at all, and it is what makes
        // regional community participation possible:
        // `communities_containing(cell_id)` matches the geographic communities
        // (`cohort_subkind = "geographic"`) whose own constraint cell CONTAINS
        // yours, and `member_in_geographic_constraint` admits a member only on an
        // in-force, unexpired contained proof. With no cell there is nothing to
        // compare, so there is no membership.
        //
        // It is ALSO an optional gate on visibility — a geographic community may
        // restrict items destined for IT to members inside its region. That gate
        // is scoped to that community's own traffic; it is not a general
        // restriction on your traces, which the replication consent decides.
        // Saying "location never affects visibility" would be the simpler line
        // and it would be false.
        //
        // §0.8.1 rough-only is enforced by the SUBSTRATE, not by this copy:
        // `validate_location_cell` refuses `cell_resolution > 7` at admission,
        // and resolution-redundancy means a producer cannot assert a coarse
        // resolution while shipping a fine cell. "Rough region only" is a
        // property of the wire format rather than a promise a UI is making on a
        // client's behalf — which is the whole reason it can be trusted.
        "location": {
            "kind": "envelope_field",
            "required": false,
            "title": m("location.title", "Share your approximate region"),
            "permits": m(
                "location.permits",
                "Attaches a coarse H3 cell to your envelope so patterns can be reported across \
                 regions. The substrate refuses anything finer than resolution 7, so it \
                 identifies a rough region — never your specific locality or address."
            ),
            "purpose": m(
                "location.purpose",
                "Regional pattern reporting, and taking part in regional communities. A \
                 community may also use it as an OPTIONAL visibility gate, restricting items \
                 destined for that community to members whose region falls inside it. It is \
                 not a general restriction on your traces — that is decided by the consents \
                 above."
            ),
            "carrier": "location_proof",
            "cell_format": "h3",
            "max_resolution": ciris_persist::federation::location::MAX_LOCATION_PROOF_RESOLUTION,
            "declining": {
                "allowed": true,
                "costs": [
                    m(
                        "location.cost.no_regional_reporting",
                        "Your activity cannot contribute to regional pattern reporting."
                    ),
                    m(
                        "location.cost.no_regional_community",
                        "You cannot take part in any regional community. Membership is decided \
                         by whether your cell falls inside the community's own region, so \
                         without a cell there is nothing to compare."
                    ),
                ],
            },
        },
        // Rule 1. Not a consent choice — the floor for being served at all.
        "announce_requirement": m(
            "mesh.announce_requirement",
            "A node that does not announce gets no service access on the mesh and no agent \
             services. The accord's kill switch is only meaningful against a node it can reach, \
             so an unreachable node is never served in the first place."
        ),
    })
    .to_string()
}

/// `consent:replication` payload `subject_kind` (CEG 1.0-RC29 §4.2.2.3): a
/// payload member (NOT an envelope field) declaring the grant's subject shape.
const SUBJECT_KIND_CONSENT_REPLICATION: &str = "consent_replication";

/// The outcome of [`emit_replication_consent`]: which grant row now exists for
/// the directed (this node → peer) `consent:replication:v1` consent, and whether
/// THIS call wrote it (`freshly_emitted == true`) or found a durable existing
/// grant (idempotent no-op, `freshly_emitted == false`). `attestation_id` /
/// `content_hash` identify the grant either way, so an owner-authority caller can
/// echo the same handle on a repeat POST.
#[derive(Debug, Clone)]
pub struct ConsentGrant {
    /// The grant row's `attestation_id`.
    pub attestation_id: String,
    /// The grant envelope's `original_content_hash` (the integrity anchor).
    pub content_hash: String,
    /// `true` when this call wrote a fresh grant; `false` on an idempotent no-op.
    pub freshly_emitted: bool,
}

/// The owner-chosen policy dimensions of a `consent:replication:v1` grant BEYOND
/// the covered prefixes — the contextual-integrity tuple fields persist's closed
/// consent grammar ([`ciris_persist::federation::consent_grammar::ConsentTransferPolicy`],
/// validated by `parse_grant_payload`) accepts. Boot / default callers use
/// [`ConsentGrantOptions::default`] (audience = `federation`, no expiry, no
/// restrictions); the owner-gated `POST /v1/federation/consent` route fills these
/// from the operator's request so an owner can narrow the recipient cohort, time-box
/// the grant, or attach `strip_field` / `recipient_capability` restrictions
/// (CIRISServer#327 §2 / #510 P2).
#[derive(Debug, Clone, Default)]
pub struct ConsentGrantOptions {
    /// The recipient cohort — one of the 7 closed
    /// [`cohort_scope`](ciris_persist::federation::types::cohort_scope) values.
    /// `None` ⇒ persist's `default_audience()` (`federation`). A supplied value
    /// is validated against the closed set at the producer (fail-closed) so a bad
    /// token never reaches persist admission.
    pub audience: Option<String>,
    /// The grant's payload-declared expiry (distinct from the row's `expires_at`
    /// column). `None` ⇒ no payload-declared expiry.
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Restrictions applied to the covered flow — typed through persist's OWN
    /// closed [`RestrictionOp`] enum, so an unknown `op` cannot be authored (edge
    /// honors these at serve; persist applies `StripField` at promotion).
    pub restrictions: Vec<RestrictionOp>,
    /// Which envelope KINDS the grant covers. `None` ⇒ `["Attestation"]`.
    /// Every entry must name a real `EnvelopeKind` that is `Consentable`;
    /// a structural-plane kind rejects the whole grant at admission.
    pub kinds: Option<Vec<String>>,
    /// Flow direction. `None` ⇒ `egress` (what this node SENDS).
    pub direction: Option<String>,
    /// The Nissenbaum transmission principle. `None` ⇒ `share`.
    pub principle: Option<String>,
    /// Free-text human-readable purpose. Unvalidated, but it is what an operator
    /// reads back when auditing why a flow exists — worth filling in.
    pub purpose: Option<String>,
}

/// A consent grant, stated exhaustively.
///
/// # Why every field is emitted, even at its default
///
/// A consent object is a contextual-integrity tuple: WHAT flows, to WHICH
/// recipient cohort, under WHAT principle, with WHAT restrictions, for HOW LONG.
/// Omitting a member means the answer comes from persist's `#[serde(default)]`
/// instead of from the owner — so the grant records a policy nobody stated, and
/// the recorded policy silently changes if a default ever moves.
///
/// That is not hypothetical here: `attestation_prefixes` defaulted to
/// `["capacity:"]` for eight releases, no consent object said so, and ZERO traces
/// reached the production canonical from any node while every gate stayed green.
///
/// So the producer writes the FULL tuple. Defaults still exist — they are how a
/// caller says "I have no opinion" — but the value they resolve to is written
/// into the object at authoring time, where it can be audited and where a
/// downstream default change cannot rewrite what the owner agreed to.
///
/// # The recipient is a CLASS, not a list of keys
///
/// `audience` is a cohort, not an enumerated peer set — "the federation", not
/// "these three key ids". `subject_key_ids` names the directed counterparty for
/// this row, but the POLICY is the cohort. That is what makes the grant
/// exhaustive: it answers for recipients the owner has never met.
///
/// The second half of "…to canonicals blessed by a trust root I trust" is NOT in
/// this object, and deliberately so. Consent says what may flow and to which
/// cohort; the serve gate independently requires
/// `capability_roots_to_trusted_root(me, recipient, infra:serve)` — the recipient
/// must hold the capability from a root THIS node accepts. Two conditions, both
/// required, neither able to satisfy the other. Folding the trust predicate into
/// the consent payload would let a grant assert a trust relationship it cannot
/// verify.
///
/// The same shape carries any policy of this form — "medical data to providers I
/// trust, and that my providers trust" is `attestation_prefixes: ["medical:"]`
/// with the cohort as audience, the onward-transfer question answered by
/// `principle` + `restrictions`, and the trust predicate answered by the gate.
#[derive(Debug, Clone)]
pub struct ExhaustiveConsent;

/// Normalize a caller-supplied (or default) prefix set into the byte-for-byte
/// form that goes into the grant payload so every consumer (and B's mirror)
/// agrees on the JCS array: trimmed, empty-dropped, **sorted ascending +
/// deduplicated**. The owner (via `POST /v1/federation/peering`) or the boot-env
/// path both flow their prefix set through here so the on-wire shape is identical
/// regardless of who authored the grant.
///
/// **Narrowing note (RC29 §5.6.8.15):** partial narrowing of the prefix set MUST
/// go via a `supersedes` attestation carrying a *narrower* set — never a silent
/// drop. Not implemented here; this helper deliberately does not preclude it.
pub fn normalize_prefixes<S: AsRef<str>>(prefixes: &[S]) -> Vec<String> {
    let mut v: Vec<String> = prefixes
        .iter()
        .map(|s| s.as_ref().trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The default prefix set as owned strings (boot-env peering convenience).
pub fn default_attestation_prefixes() -> Vec<String> {
    normalize_prefixes(DEFAULT_GRANT_ATTESTATION_PREFIXES)
}

/// Register Node B's *self-signed* `SignedKeyRecord` in A's federation directory
/// through the **single canonical admission gate** —
/// `Engine::register_federation_key` (persist v8.8.0, CIRISPersist#234,
/// CEG 1.0-RC29 §5.6.8.15) — the ADMISSION mechanism for directed-consent
/// replication. Until B's key is a verified `federation_keys` row, A's
/// `put_attestation` rejects any B-attested `health:liveness:*` row B replicates
/// in (`InvalidArgument`: attesting_key_id does not exist).
///
/// **v8.8.0 fail-secure shape:** the gate REQUIRES B's *self-signed* record
/// (proof-of-possession) — A can no longer mint B's row from raw pubkeys. A
/// hands B's exported `SignedKeyRecord` ([`PeerB::key_record`], supplied via
/// `CIRIS_PEER_B_KEY_RECORD`) straight to `register_federation_key`, which
/// `verify_key_registration`s B's hybrid signature (Ed25519+ML-DSA-65, Strict,
/// over `ceg_produce_canonicalize(registration_envelope)` against B's own
/// pubkeys, `scrub_key_id == key_id`) BEFORE any store. An unverifiable/forged
/// peer record is rejected and never stored — the security check is the
/// signature, not A's say-so.
///
/// Idempotent: a row that already matches returns `Ok(())`; a `Conflict` (a
/// *differing* row already holds B's key_id) is benign (logged at debug) — we
/// must not fail boot over a directory race, and B's stable published identity
/// should never legitimately conflict.
pub async fn register_peer_key(engine: &Engine, peer: &PeerB) -> Result<()> {
    // Safe-mesh floor (B1): an `accord_holder` identity — a kill-switch SEAT — may be
    // admitted ONLY through the custody-gated `POST /v1/accord/holder` (which mandates
    // a verified FIPS YubiKey custody attestation). This generic peer-key route does
    // NOT verify custody, so it must REFUSE accord_holder records — otherwise an owner
    // could seat a non-FIPS kill-switch holder via the side door.
    if peer.key_record.record.identity_type == identity_type::ACCORD_HOLDER {
        return Err(anyhow::anyhow!(
            "refusing to register an accord_holder key via the peering route — accord holders \
             must be admitted through the custody-gated POST /v1/accord/holder"
        ));
    }
    // CC 4.2.2.1 (CIRISServer#159): the peering route is the classic unchecked-
    // self-report surface — a peer hands us its own record, hardware_class and all.
    // `register_attested_federation_key` proves any hardware-class claim (chain to a
    // pinned root + bound to THIS record's key) before persist's PoP gate stores it.
    match crate::hardware_attestation::register_attested_federation_key(
        engine,
        peer.key_record.clone(),
    )
    .await
    {
        Ok(()) => {
            tracing::info!(
                peer_key_id = %peer.key_id,
                identity_type = %peer.key_record.record.identity_type,
                "registered Node B's self-signed key via register_federation_key \
                 (fail-secure admission gate; directed-consent replication admission)"
            );
            Ok(())
        }
        Err(FederationError::Conflict(msg)) => {
            tracing::debug!(
                peer_key_id = %peer.key_id,
                conflict = %msg,
                "peer-key registration is a benign conflict (key already present) — continuing"
            );
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!(
            "register Node B federation key (fail-secure verify): {e}"
        )),
    }
}

/// Boot / default / test entry (backward-compatible 4-arg form): author the
/// directed `consent:replication:v1` grant with DEFAULT policy
/// ([`ConsentGrantOptions::default`] — audience `federation`, no payload expiry,
/// no restrictions). The full closed-grammar payload and the non-vacuous-prefix
/// guard still apply — those are producer invariants, not owner options. The
/// owner-gated consent route uses [`emit_replication_consent_with_policy`] to
/// carry an owner-chosen policy.
pub async fn emit_replication_consent<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    attestation_prefixes: &[S],
) -> Result<ConsentGrant> {
    emit_replication_consent_with_policy(
        engine,
        node_key_id,
        peer_key_id,
        attestation_prefixes,
        &ConsentGrantOptions::default(),
    )
    .await
}

/// Emit Node A's directed `consent:replication:v1` attestation at Node B:
/// "A consents to replicate `capacity:*` to B." A directed `scores` attestation,
/// `subject_key_ids = [B]`, `cohort_scope = "federation"`, FEDERATION tier,
/// hybrid-signed by A's steward key (`node_key_id`).
///
/// **Idempotent**: if A has already emitted a `consent:replication:v1` row
/// directed at this peer (the grant is durable, not per-boot), this is a no-op
/// returning the existing grant's handle with `freshly_emitted == false` —
/// `scores` rows are NOT collapsed by dimension on the federation tier (each
/// `put_attestation` mints a fresh `attestation_id`), so we guard the emit with a
/// directory lookup rather than blindly re-emitting. Returns a [`ConsentGrant`]
/// with `freshly_emitted == true` when a fresh grant row was written.
///
/// Revocation (not built here, per the contract) rides the CEG
/// withdraws/recants structural primitive targeting this grant's
/// `attestation_id` — the same mechanism CIRISAgent's `build_community_structural`
/// uses for the community-trust grant.
///
/// `attestation_prefixes` is the caller-supplied namespace-prefix set this node
/// consents to replicate to the peer (trailing ":" significant). It is
/// [`normalize_prefixes`]d (trimmed / empty-dropped / sorted-ascending / deduped)
/// before it lands in the grant payload, so the on-wire JCS array is byte-for-byte
/// agreed regardless of caller input order. The boot-env path passes
/// [`default_attestation_prefixes`]; the owner-authority `POST /v1/federation/peering`
/// path passes the operator's set. A **vacuous** (empty-after-normalize) set is
/// REFUSED here — persist's `parse_grant_payload` rejects an empty-STRING entry
/// but NOT an empty ARRAY, and a grant that `covers()` nothing is a governance
/// object that looks authoritative and grants nothing (CIRISServer#327 §2's
/// non-vacuous-prefix guard, the `"scores:"`-token bug class the walk found).
///
/// `opts` carries the rest of the closed #510 consent-transfer payload the
/// producer authors in FULL (grants / audience / attestation_prefixes /
/// valid_until / restrictions) — see [`ConsentGrantOptions`]. The grant is
/// deliberately **NOT** stamped `delivery_mode = "mandatory"`: a grant is not a
/// revocation. `delivery_mode` is a SELECTIVE fail-secure flag (edge v15.0.0's
/// `decide` maps `(Mandatory, no-path) → FailLoudNoPath`), reserved for the
/// withdraws / recants / kill-switch-tier class where a *silent drop* is a
/// security failure. A grant that misses a temporarily-unreachable peer is an
/// ordinary best-effort case that retry converges — stamping it `mandatory`
/// would convert that into a self-inflicted loud outage. Absent ⇒ BestEffort,
/// which is correct here (CIRISServer#327 §2 delivery_mode-is-selective ruling).
///
/// The 4-arg [`emit_replication_consent`] wrapper is the boot / default / test
/// entry (default policy); this `_with_policy` form is the owner-gated
/// `POST /v1/federation/consent` route's entry, carrying the operator's chosen
/// audience / expiry / restrictions.
pub async fn emit_replication_consent_with_policy<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    attestation_prefixes: &[S],
    opts: &ConsentGrantOptions,
) -> Result<ConsentGrant> {
    // Idempotency guard: does A hold a LIVE replication-consent grant to this
    // peer? See [`standing_live_grant`] for why "live" and not "present".
    if let Some(existing) = standing_live_grant(engine, node_key_id, peer_key_id).await? {
        tracing::debug!(
            peer_key_id,
            attestation_id = %existing.attestation_id,
            "live replication-consent grant already present — skipping re-emit (idempotent)"
        );
        return Ok(ConsentGrant {
            attestation_id: existing.attestation_id,
            content_hash: existing.original_content_hash,
            freshly_emitted: false,
        });
    }

    emit_grant_row(engine, node_key_id, peer_key_id, attestation_prefixes, opts).await
}

/// **The standing grant this node holds for `peer_key_id`, or `None`.**
///
/// One predicate, asked the same way by the idempotency guard above and by
/// [`ensure_replication_consent_covers`] — because they are the same question
/// and were briefly answered two different ways.
///
/// # Why `list_live_consent_grants_by` and not `list_attestations_by`
///
/// The guard used to scan `list_attestations_by`, which returns every
/// federation-tier row this node authored and folds NOTHING. A withdrawn grant
/// is still a row, so the guard reported "already present" for consent that had
/// been REVOKED — and returned `freshly_emitted: false` without writing
/// anything. Withdrawing consent therefore poisoned all future re-consent to
/// that peer: re-peering or re-adding them succeeded, silently, with no live
/// grant behind it and nothing replicating.
///
/// That is the same one-name-two-questions defect as the prefix bug next door
/// ("does a row EXIST" answering for "is consent LIVE"), and it is the more
/// serious half: a revocation that costs you the ability to ever re-consent is
/// not a revocation anyone can afford to use, and a right you cannot afford to
/// exercise is not a right. `list_live_consent_grants_by` reads persist's
/// `consent_peer_set` projection, whose `withdraws`/`recants`/`supersedes` fold
/// already ran at write time.
///
/// A backend that cannot answer this ERRORS rather than guessing. Guessing has
/// two shapes and both are wrong: assume-live refuses to re-consent, and
/// assume-absent duplicates a grant that already stands.
///
/// The rows it returns are already filtered to the consent dimension, and a
/// structural composer can never appear among them (the projection early-returns
/// for composers, so nothing sources a `consent_peer_set` row from one) — which
/// is why the old scan's `attestation_type` / `dimension` predicates are gone
/// rather than merely relocated. Ordered `asserted_at DESC` by both SQL
/// backends, so the first match is the most recent.
async fn standing_live_grant(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
) -> Result<Option<ciris_persist::federation::types::Attestation>> {
    Ok(engine
        .federation_directory()
        .list_live_consent_grants_by(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list_live_consent_grants_by({node_key_id}): {e}"))?
        .into_iter()
        .find(|a| a.subject_key_ids.iter().any(|s| s == peer_key_id)))
}

/// **The grant EMIT half, with no idempotency guard.**
///
/// Split out of [`emit_replication_consent_with_policy`] because there are now
/// TWO conditions under which a grant must be written, and only one of them is
/// "no grant exists". The other is [`ensure_replication_consent_covers`]:
/// a standing grant whose prefix set is too NARROW is superseded by a wider
/// one, and that emit must not consult the guard it is deliberately stepping
/// past. Keeping the recipe here means the two callers cannot author two
/// different shapes of the same object.
///
/// Every caller is responsible for its own precondition; this function only
/// authors and stores.
async fn emit_grant_row<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    attestation_prefixes: &[S],
    opts: &ConsentGrantOptions,
) -> Result<ConsentGrant> {
    // ── The RC29 LOCKED consent:replication grant (CEG §5.6.8.15, resolves
    //    CIRISRegistry#98). A bare `scores` Attestation. ──────────────────────
    //
    // ENVELOPE level (envelope fields per §4.2.2.x):
    //   - attesting_key_id = A; dimension = consent:replication:v1
    //   - score > 0 (positive — magnitude NOT load-bearing)
    //   - subject_key_ids = [B] (the SINGLE recipient peer)
    //   - cohort_scope = "federation"
    //   - witness_relation = "self" (REQUIRED — G attests its own replication
    //     intent; forecloses third-party forgery of a consent grant)
    //   - topical_relation = "bilateral_pair" (SHOULD — lets a consumer pair
    //     A→B with B→A)
    //   - delivery_mode: deliberately UNSET (⇒ BestEffort). A grant is not a
    //     revocation; `mandatory` is reserved for the withdraws/recants/
    //     kill-switch class where a silent drop is a security failure. See the
    //     `_with_policy` doc comment for the full rationale.
    //
    // PAYLOAD level (a payload member under subject_kind, §4.2.2.3 — NOT envelope
    // fields): the FULL closed #510 consent-transfer grammar
    // (`consent_grammar::ConsentTransferPolicy`, validated at admission by
    // `parse_grant_payload`), authored complete rather than leaning on persist's
    // field defaults (CIRISServer#327 §2 / #510 P2):
    //   - subject_kind = "consent_replication"
    //   - grants = "replication" (the legacy-compat token; parse accepts it)
    //   - audience = the owner-chosen recipient cohort (default `federation`)
    //   - attestation_prefixes = the JCS array of namespace-prefix strings A
    //     replicates (trailing ":" significant), sorted ascending + deduped so
    //     consumers agree byte-for-byte — NON-VACUOUS (guarded below)
    //   - valid_until = optional payload-declared expiry
    //   - restrictions = strip_field / recipient_capability ops (persist's OWN
    //     closed RestrictionOp enum — an unknown op is unrepresentable)
    let prefixes = normalize_prefixes(attestation_prefixes);
    if prefixes.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing to author a consent:replication grant with an empty (vacuous) \
             attestation-prefix set — persist admits an empty array but the grant would \
             cover nothing (CIRISServer#327 §2 non-vacuous-prefix guard)"
        ));
    }
    let audience = opts
        .audience
        .clone()
        .unwrap_or_else(|| cohort_scope::FEDERATION.to_string());
    if !cohort_scope::is_valid(&audience) {
        return Err(anyhow::anyhow!(
            "consent audience {audience:?} is not one of the closed cohort_scope values \
             (self/family/community/affiliations/species/biosphere/federation)"
        ));
    }
    // THE EXHAUSTIVE TUPLE. Every member is written, at its resolved value,
    // including the ones a caller left to default — see [`ExhaustiveConsent`].
    // A default that lives only in persist is a policy nobody stated and that a
    // downstream change can silently rewrite; `attestation_prefixes` defaulting
    // to ["capacity:"] for eight releases, with no consent object recording it,
    // is exactly how zero traces reached production while every gate was green.
    let kinds = opts
        .kinds
        .clone()
        .unwrap_or_else(|| vec!["Attestation".to_string()]);
    let direction = opts
        .direction
        .clone()
        .unwrap_or_else(|| "egress".to_string());
    let principle = opts
        .principle
        .clone()
        .unwrap_or_else(|| "share".to_string());
    let mut payload = serde_json::json!({
        // "replication" is the legacy spelling persist still accepts alongside
        // "transfer"; kept so an in-flight grant does not change shape mid-cut.
        "grants": "replication",
        "direction": direction,
        "kinds": kinds,
        "attestation_prefixes": prefixes,
        "principle": principle,
        "audience": audience,
        "restrictions": opts.restrictions,
    });
    if let Some(purpose) = opts.purpose.as_deref() {
        payload["purpose"] = serde_json::json!(purpose);
    }
    if let Some(valid_until) = opts.valid_until {
        payload["valid_until"] = serde_json::json!(valid_until);
    }
    // Fail at the PRODUCER, not at admission: parse our own payload through
    // persist's one strict parser before signing it. `deny_unknown_fields` means
    // a member we spell wrong — or one persist later removes — is caught here,
    // with the field named, instead of surfacing as a refused row on a peer.
    {
        let probe = serde_json::json!({ "payload": payload });
        ciris_persist::federation::consent_grammar::parse_grant_payload(&probe).map_err(|e| {
            anyhow::anyhow!(
                "refusing to author a consent grant persist would reject: {e}. Payload: {}",
                serde_json::to_string(&payload).unwrap_or_default()
            )
        })?;
    }
    let envelope = serde_json::json!({
        (paths::DIMENSION): CONSENT_DIMENSION,
        "attesting_key_id": node_key_id,
        "subject_key_ids": [peer_key_id],
        "score": 1.0,
        "cohort_scope": cohort_scope::FEDERATION,
        "witness_relation": "self",
        "topical_relation": "bilateral_pair",
        // NO `asserted_at` HERE (CIRISServer#402 / CIRISPersist#598). The stamp
        // writes it — once, truncated to the substrate's resolution — and
        // `assemble` reads the row column back out of it. A producer that sets it
        // is honoured and NOT truncated, so a hand-written `Utc::now()` lands with
        // nanoseconds postgres cannot store and the put is refused. It made every
        // write on this path fail on v31.
        // §4.2.2.3 payload member (subject_kind + its payload), NOT envelope fields.
        "subject_kind": SUBJECT_KIND_CONSENT_REPLICATION,
        "payload": payload,
    });
    // NOTE: `delivery_mode` is intentionally NOT set (⇒ persist/edge treat its
    // absence as BestEffort). See the fn doc comment: a grant is the ordinary
    // class, not the withdraws/recants/kill-switch mandatory-delivery class, so it
    // must never fail loud on an unreachable peer.

    // ── Emit (CIRISPersist#253 collapse) ─────────────────────────────────────
    // The hand-rolled canonicalize→hash→hybrid-sign→assemble→put recipe is now
    // `Engine::emit_attestation_self` (signs with the engine's OWN composed
    // hardware-hybrid signer; attester/scrub = the node's #247 DERIVED federation
    // key_id == `node_key_id` here — wire-preserving). `weight = Some(1.0)`
    // matches the trust model's `unwrap_or(1.0)` default (preserved explicitly).
    //
    // `content_hash` (the integrity anchor surfaced to the operator via the
    // peering admin response) is the SAME JCS canonical hash emit computes
    // internally — derived here for the ConsentGrant return without a read-back.
    let canonical = ceg_produce_canonicalize(&envelope).map_err(|e| {
        anyhow::anyhow!("ceg_produce_canonicalize replication-consent envelope: {e}")
    })?;
    let content_hash = hex::encode(Sha256::digest(&canonical));

    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)?,
        // consent:replication:v1 is federation-scope MANDATORY (the grant must
        // be readable by the peer it names, and by the CCS leg).
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(peer_key_id.to_owned());
    input.subject_key_ids = vec![peer_key_id.to_owned()];
    input.weight = Some(1.0);
    let attestation_id = engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| anyhow::anyhow!("emit_attestation_self(consent:replication:v1): {e}"))?;

    tracing::info!(
        peer_key_id,
        dimension = CONSENT_DIMENSION,
        attestation_id = %attestation_id,
        "emitted directed replication-consent grant (this node consents to replicate to peer)"
    );
    Ok(ConsentGrant {
        attestation_id,
        content_hash,
        freshly_emitted: true,
    })
}

/// The prefix set a live grant covers, or `None` when its payload does not parse.
///
/// `None` and `Some(vec![])` are DIFFERENT facts and both are honest: a grant
/// whose payload fails the closed grammar covers nothing AND cannot be reasoned
/// about, while an empty set would claim it was read and found bare. Callers
/// treat `None` as "covers nothing" — the same verdict `promote_consented_backlog`
/// reaches when it warns and skips.
fn grant_prefixes(grant: &ciris_persist::federation::types::Attestation) -> Option<Vec<String>> {
    ciris_persist::federation::consent_grammar::parse_grant_payload(&grant.attestation_envelope)
        .ok()
        .map(|policy| normalize_prefixes(&policy.attestation_prefixes))
}

/// **What this node's LIVE grant to `peer_key_id` actually covers.**
///
/// The sibling of [`standing_live_grant`] on the same revocation-folded read —
/// deliberately not a second predicate, because "is there a live grant" and
/// "what does it cover" are two questions about ONE row, and answering them
/// through two lookups is how they drift apart.
///
/// `Ok(None)` = no live grant at all (never granted, or withdrawn).
/// `Ok(Some(prefixes))` = a live grant covering exactly these.
pub async fn live_grant_prefixes(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
) -> Result<Option<Vec<String>>> {
    Ok(standing_live_grant(engine, node_key_id, peer_key_id)
        .await?
        .map(|g| grant_prefixes(&g).unwrap_or_default()))
}

/// Every peer this node holds a LIVE grant for, paired with what that grant
/// covers — the list form of [`live_grant_prefixes`], reading the folded set
/// ONCE rather than per peer.
///
/// This is what a caller wants when "is X a peer" is not the question: a
/// contacts list needs to know which peers it can actually MESSAGE, and a peer
/// federated under the default `capacity:`/`trace:` grant is not one of them.
pub async fn live_consent_grants(
    engine: &Engine,
    node_key_id: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    let grants = engine
        .federation_directory()
        .list_live_consent_grants_by(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list_live_consent_grants_by({node_key_id}): {e}"))?;
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for grant in &grants {
        let prefixes = grant_prefixes(grant).unwrap_or_default();
        for peer in &grant.subject_key_ids {
            // Rows come back `asserted_at DESC`, so the FIRST grant naming a peer
            // is the most recent — keep it and ignore any older row that also
            // names them.
            if !out.iter().any(|(p, _)| p == peer) {
                out.push((peer.clone(), prefixes.clone()));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// The outcome of [`ensure_replication_consent_covers`] — what is LIVE after
/// the call, and what it cost.
#[derive(Debug, Clone)]
pub struct ConsentCoverage {
    /// The `attestation_id` of the grant that is live for this peer AFTER the
    /// call. `list_live_consent_grants_by` returns this row and no other for
    /// the peer.
    pub attestation_id: String,
    /// That grant's `original_content_hash`.
    pub content_hash: String,
    /// `true` iff a grant row was written — either the first grant for this
    /// peer, or a widening one. `false` is the true no-op: the standing grant
    /// already covered every required prefix.
    pub freshly_emitted: bool,
    /// The standing grant this call superseded, when it widened one. `None`
    /// when nothing was superseded (first grant, or no-op).
    pub superseded_attestation_id: Option<String>,
    /// The effective covered prefix set after the call (normalized).
    pub prefixes: Vec<String>,
}

/// **Ensure this node's live grant to `peer_key_id` COVERS `required_prefixes`,
/// widening a too-narrow standing grant by superseding it.**
///
/// # The defect this exists for (CIRISServer PR #464 P1)
///
/// [`emit_replication_consent_with_policy`]'s idempotency guard matches on
/// `(subject, dimension)` and **never compares prefixes**, so once any grant
/// exists for a peer, every later call with a wider prefix set is a silent
/// no-op. After ordinary federation peering a key already holds a grant
/// covering `capacity:` / `trace:` only — so adding that peer as a CONTACT
/// appeared to succeed while `chat:` rows stayed ineligible for promotion,
/// **precisely for the contacts who peered first**. The narrower the existing
/// relationship, the more correct the outcome looked; that is what kept it
/// invisible.
///
/// # Why widening is a SUPERSEDES and not a second grant
///
/// It could have been a second grant: `promote_consented_backlog` unions the
/// prefixes of every ACTIVE grant, so an additional narrow grant would also
/// have made `chat:` eligible. It is a supersedes because persist's
/// `consent_peer_set` projection is keyed `(node_key_id, peer_key_id)` and
/// `INSERT OR REPLACE`s — so writing a second grant already silently unlinks
/// the first (`list_live_consent_grants_by` selects on
/// `EXISTS source_attestation_id = attestation_id`). The old grant would stop
/// being live either way; the only question is whether the corpus SAYS so. A
/// `supersedes` is that sentence, and it is what an auditor reading the chain
/// needs in order to see one widened relationship rather than two grants of
/// unexplained differing scope.
///
/// Which also fixes the union: because the old grant does stop being live, the
/// new one must carry `standing ∪ required`, not just the new prefixes.
///
/// # Order is load bearing
///
/// The widened grant is written FIRST, the `supersedes` second. The projection
/// runs its revocation fold as a `DELETE … WHERE source_attestation_id = <old>`
/// and its grant upsert as an `INSERT OR REPLACE` on `(node, peer)`; writing
/// the grant first means that row already points at the NEW grant by the time
/// the delete runs, so the delete is a no-op and consent is never momentarily
/// absent. The reverse order converges to the same state through a window in
/// which this node consents to nothing.
///
/// # The standing policy is PRESERVED, not reset
///
/// Only the prefix axis widens. `audience` / `valid_until` / `restrictions` /
/// `kinds` / `direction` / `principle` / `purpose` are read off the standing
/// grant and re-authored verbatim, so an owner who narrowed the recipient
/// cohort or time-boxed the grant through `POST /v1/federation/consent` does
/// not have those choices silently reverted by someone adding a contact. A
/// standing grant whose payload does not parse is the one exception: it covers
/// NOTHING today (`promote_consented_backlog` warns and skips it), so it is
/// superseded by a well-formed grant carrying the required prefixes under
/// default policy — stated here because it is the only path that discards a
/// recorded choice, and it discards one that was already inert.
pub async fn ensure_replication_consent_covers<S: AsRef<str>>(
    engine: &Engine,
    node_key_id: &str,
    peer_key_id: &str,
    required_prefixes: &[S],
) -> Result<ConsentCoverage> {
    use ciris_persist::federation::consent_grammar::parse_grant_payload;

    let required = normalize_prefixes(required_prefixes);
    if required.is_empty() {
        return Err(anyhow::anyhow!(
            "refusing to ensure coverage for an empty (vacuous) attestation-prefix set \
             — see the non-vacuous-prefix guard on emit_grant_row"
        ));
    }
    // The revocation-FOLDED standing grant — one predicate, shared with the
    // idempotency guard (see [`standing_live_grant`]).
    let Some(standing) = standing_live_grant(engine, node_key_id, peer_key_id).await? else {
        // No live grant: the ordinary first-grant path, guard and all.
        let grant = emit_replication_consent_with_policy(
            engine,
            node_key_id,
            peer_key_id,
            &required,
            &ConsentGrantOptions::default(),
        )
        .await?;
        return Ok(ConsentCoverage {
            attestation_id: grant.attestation_id,
            content_hash: grant.content_hash,
            freshly_emitted: grant.freshly_emitted,
            superseded_attestation_id: None,
            prefixes: required,
        });
    };

    // What does it actually cover, and under what policy?
    let (covered, opts) = match parse_grant_payload(&standing.attestation_envelope) {
        // `grant_prefixes` reads the same field through the same parser; the
        // policy axes below need the whole parsed struct, so this arm keeps it.
        Ok(policy) => {
            let opts = ConsentGrantOptions {
                audience: Some(policy.audience.clone()),
                valid_until: policy.valid_until,
                restrictions: policy.restrictions.clone(),
                kinds: Some(policy.kinds.clone()),
                direction: enum_token(&policy.direction),
                principle: enum_token(&policy.principle),
                purpose: policy.purpose.clone(),
            };
            (normalize_prefixes(&policy.attestation_prefixes), opts)
        }
        Err(e) => {
            tracing::warn!(
                peer_key_id,
                attestation_id = %standing.attestation_id,
                error = %e,
                "the standing consent grant's payload does not parse, so it covers nothing \
                 (promote_consented_backlog skips it) — superseding it with a well-formed \
                 grant under DEFAULT policy"
            );
            (Vec::new(), ConsentGrantOptions::default())
        }
    };
    if required.iter().all(|p| covered.contains(p)) {
        tracing::debug!(
            peer_key_id,
            attestation_id = %standing.attestation_id,
            "standing consent grant already covers every required prefix — no-op"
        );
        return Ok(ConsentCoverage {
            attestation_id: standing.attestation_id,
            content_hash: standing.original_content_hash,
            freshly_emitted: false,
            superseded_attestation_id: None,
            prefixes: covered,
        });
    }

    // Widen. `normalize_prefixes` sorts + dedups, so the union is byte-stable
    // regardless of which side contributed which entry.
    let union: Vec<String> = normalize_prefixes(
        &covered
            .iter()
            .chain(required.iter())
            .cloned()
            .collect::<Vec<String>>(),
    );
    let grant = emit_grant_row(engine, node_key_id, peer_key_id, &union, &opts).await?;
    emit_grant_supersedes(engine, node_key_id, &standing.attestation_id).await?;
    tracing::info!(
        peer_key_id,
        superseded = %standing.attestation_id,
        attestation_id = %grant.attestation_id,
        prefixes = ?union,
        "widened this node's replication-consent grant (superseded the narrower standing grant)"
    );
    Ok(ConsentCoverage {
        attestation_id: grant.attestation_id,
        content_hash: grant.content_hash,
        freshly_emitted: true,
        superseded_attestation_id: Some(standing.attestation_id),
        prefixes: union,
    })
}

/// The wire token for one of persist's lowercase-renamed consent enums
/// (`Direction`, `TransmissionPrinciple`). Read through serde rather than a
/// hand-written match, so a variant persist adds cannot be silently re-spelled
/// here — [`ConsentGrantOptions`] carries these as `Option<String>` because
/// that is the shape [`emit_grant_row`] writes into the payload.
fn enum_token<T: serde::Serialize>(value: &T) -> Option<String> {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
}

/// The CEG `supersedes` composer that RETIRES a prior consent grant: "this row
/// replaces a prior attestation by the same attester" (CC 2.4.1 / FSD-002
/// §2.2.2). Authored by the node's own engine signer, exactly like the grant it
/// retires.
///
/// # It carries NO `dimension`, and that is persist's rule, not a shortcut
///
/// The obvious shape — stamp `dimension = consent:replication:v1` so an
/// operator can see which plane was superseded — is REFUSED at the put door.
/// `validate_grant_admission` fires on the dimension ALONE, not on the
/// attestation type, so a composer wearing the grant dimension is parsed as a
/// grant and rejected for carrying no `payload`. Persist states the rule in
/// that gate's own comment ("a `withdraws`/`recants` referencing a grant
/// carries its OWN dimension, never GRANT_DIMENSION, so it never reaches this
/// check") and its `consent_peer_set` fixture composer carries no dimension at
/// all. This matches the fixture: `references_attestation_id` and nothing more.
///
/// Legibility is not lost by it — `references_attestation_id` names the grant,
/// and the grant names the peer, which is the same link the projection's
/// revocation fold walks.
///
/// `subject_key_ids` is likewise EMPTY (again matching the fixture): naming the
/// peer there would hand the peer revocation authority over this node's own
/// retirement of its own grant (§4.2.6 — subjects are who may revoke).
async fn emit_grant_supersedes(
    engine: &Engine,
    node_key_id: &str,
    superseded_attestation_id: &str,
) -> Result<String> {
    // No `asserted_at` (CIRISServer#402 / CIRISPersist#598): the emit door
    // stamps it once, into the bytes it signs.
    let envelope = serde_json::json!({
        (paths::REFERENCES_ATTESTATION_ID): superseded_attestation_id,
        "attesting_key_id": node_key_id,
        "cohort_scope": cohort_scope::FEDERATION,
    });
    let input = EmitAttestationInput::with_envelope(
        attestation_type::SUPERSEDES,
        ciris_persist::federation::envelope::EnvelopeCore::from_value(envelope)?,
        cohort_scope::FEDERATION.to_owned(),
    );
    engine
        .emit_attestation_self(input)
        .await
        .map_err(|e| anyhow::anyhow!("emit_attestation_self(supersedes consent grant): {e}"))
}

/// Read this node's **desired replication topology back out of the corpus**: the
/// set of peer `key_id`s this node has authored a `consent:replication:v1` grant
/// for. This is the CEG-driven reconciler's source of truth — the consent objects
/// in the corpus ARE the desired Initiator/Responder set
/// ([`crate::replication_reconcile`]).
///
/// A `consent:replication` grant is the EXACT row [`emit_replication_consent`]
/// writes: a `scores` attestation authored by `node_key_id` whose
/// `attestation_envelope["dimension"] == CONSENT_DIMENSION`. The peers are the
/// `subject_key_ids` carried on those rows (each grant is directed at a single
/// peer, but the set unions across all grant rows). The returned set is **sorted
/// + deduped** so callers (and the reconciler's set-difference) are deterministic.
///
/// **Revocation is folded in (persist v21.0.0, CIRISPersist#502 E7).** This now
/// delegates to persist's [`list_consent_peers`](ciris_persist::federation::FederationDirectory::list_consent_peers),
/// which projects the consent peer set from the corpus with the CEG
/// `withdraws`/`supersedes` structural modifiers applied — a grant whose
/// `attestation_id` has been withdrawn is dropped before the subjects are
/// unioned (RC29 §5.6.8.15). This closes the former `presence == active`
/// classical edge: a revoked peer stops being replicated to on the next
/// reconcile tick, which is the nuclear-un-trust property the doctrine depends
/// on. The hand-rolled `list_attestations_by` + dimension filter it replaced
/// had no such filter, so a withdrawn grant kept replicating forever.
pub async fn replication_peers_from_consent(
    engine: &std::sync::Arc<Engine>,
    node_key_id: &str,
) -> Result<Vec<String>> {
    // persist returns the revocation-folded peer set already sorted + deduped
    // (a projection maintained by the Registry-of-Record), so this is a direct
    // read — no client-side filtering that could re-introduce the drift.
    engine
        .federation_directory()
        .list_consent_peers(node_key_id)
        .await
        .map_err(|e| anyhow::anyhow!("list consent peers for {node_key_id}: {e}"))
}

#[cfg(test)]
mod default_prefix_gate {
    use super::*;

    /// The DEFAULT grant must cover the trace plane — the thing a node actually
    /// replicates upstream.
    ///
    /// Asserted against persist's own `covers` (the same matcher
    /// `promote_consented_backlog` uses to decide which rows to sweep), not
    /// against the literal, so this cannot pass on a string that merely looks
    /// right. The trailing colon is significant: `trace:` does not cover
    /// `trace_summary:v1`.
    ///
    /// This exists because the default was `["capacity:"]` and nothing caught
    /// it: the mesh-repro harness supplies its prefixes EXPLICITLY, so the green
    /// end-to-end run proved a path production could not take. Zero traces had
    /// ever reached the production canonical, from any node, while the harness
    /// was green.
    #[test]
    fn default_covers_the_trace_plane() {
        let prefixes = default_attestation_prefixes();
        for dimension in ["trace:complete:v1", "capacity:sustained_coherence:v1"] {
            assert!(
                ciris_persist::federation::consent_grammar::covers(&prefixes, dimension),
                "the default replication grant does not cover {dimension} — \
                 promote_consented_backlog will skip every such row, leaving it at \
                 (cohort_scope=self, tier=local) and never offered. Default is {prefixes:?}"
            );
        }
    }

    /// The harness must not be able to drift from the default it is meant to
    /// exercise: whatever the default covers, a harness-authored grant with the
    /// SAME set covers too. Cheap, but it pins the two together so the next
    /// person changing one sees the other.
    #[test]
    fn default_is_normalized_and_stable() {
        let p = default_attestation_prefixes();
        let mut sorted = p.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            p, sorted,
            "default prefixes must be sorted + deduped (JCS byte-agreement)"
        );
        assert!(
            p.iter().all(|s| s.ends_with(':')),
            "every prefix needs its trailing colon — `trace` would cover trace_summary:v1 too"
        );
    }
}
