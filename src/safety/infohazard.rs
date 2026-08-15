//! Infohazard consent-gate — the protective **reveal gate** (CC 4.5.13; the
//! CC 4.5.5 `content_class` gate × the CC 3.3.1 consent primitive).
//!
//! ## The gap this closes (CIRISServer#161)
//!
//! The *decision* — "may viewer V reveal flagged subject S?" — is a
//! **composition** (the consumer / policy tier, CC 4.4), which is exactly what
//! CIRISServer (the absorbed LensCore) is for. persist is correct to have no
//! engine byte-gate on it. This module is that composition; NO persist change,
//! NO new wire shape. `consent:state:granted` + `consent:scope:view` emit
//! cleanly from the viewer's own key — a real, admittable wire shape.
//!
//! ## The write door does NOT protect the flag — WE do (CIRISServer#363)
//!
//! This module used to say, here and on [`emit_content_flag`], that
//! `content_class:` was a **substrate-reserved** prefix which persist's
//! `default_reserved_prefix_rules` admitted only from an
//! `identity_type = substrate_persist` emitter, so a viewer/agent trying to
//! self-clear the flag was refused `federation_reserved_prefix_emitter_mismatch`.
//!
//! **That sentence is false at the pinned `ciris-persist v30.2.0`, and it was
//! load-bearing.** CC 3.3.12 opens its table with *"All four families are open
//! vocabulary"* and reserves exactly one of them (`age_assurance:`); persist's
//! rc3 re-vendor (CIRISPersist#571) therefore dropped the CEG-sourced emitter
//! gates on `content_rating:` / `content_class:` / `cw_class:`. At v30.2.0
//! `content_class:` carries no `ReservedPrefixRule`, is absent from
//! `HARD_CODED_RESERVED_STEMS`, and `MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN` is
//! empty because the three *"are no longer governed at all"*. persist said what
//! that costs a consumer in as many words: *"If you relied on persist's write
//! gate to keep these families trustworthy, that enforcement is gone by design.
//! **Discriminate on read.**"*
//!
//! We relied on it and did not discriminate: [`subject_flag`] folded every
//! inbound `content_class:*` row latest-wins on `asserted_at` with **no emitter
//! predicate at all**, and the fold is clearable — so an ordinary admitted key
//! could author `content_class:infohazard:v1 {"withdrawn": true}` naming a
//! subject and clear a child-safety flag it did not set. That is now closed by
//! [`FlagAuthority`]: the read door, on this side, where CC puts it.
//!
//! ## What ships
//!
//! 1. **the pure gate** — [`infohazard_reveal_decision`] decides visibility from
//!    `(flag, has_consent)`. The default is PROTECTIVE: a flagged subject with
//!    absent/unknown consent ⇒ [`RevealDecision::Interstitial`], never a passive
//!    `Allow`. Mirrors [`super::age::gate_content_for`].
//! 2. **flag resolution** — [`subject_flag`] reads the `content_class:*` flag on
//!    the subject, under the [`FlagAuthority`] read predicate.
//! 3. **consent resolution** — persist's `resolve_scoped_consent` (v16.1.1,
//!    CIRISPersist#389) folds the viewer's `consent:state:*` rows latest-wins over
//!    those naming `scope:view` + the flagged `content_class`. We used to hand-roll
//!    this; that duplicate is DELETED (CIRISServer#243, the DRY-audit H2 finding).
//!    A scope-less BLANKET revoke still re-closes the gate — the substrate fold is
//!    asymmetric on stance, so it is a strict superset of the fold we removed.
//! 4. **the decision endpoint** — `POST /v1/safety/reveal` (decision-only; it
//!    NEVER emits the consent — the app emits it via the existing attestation
//!    surface, then re-calls).
//!
//! ## The loop (no new emit path)
//!
//! app calls `/reveal` → `403 interstitial` → user clicks "I consent" → app emits
//! `consent:state:granted {scope:"view", content_class:"infohazard"}` via the
//! **existing** attestation surface (the viewer's own signed act) → app re-calls
//! `/reveal` → `200 allow` → renders. Passive exposure is structurally
//! impossible: the fabric never returns `allow` for a flagged item until the
//! viewer's signed consent is on the graph.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use ciris_persist::federation::consent::consent_dimension;
use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::hard_case::ConsentState;
use ciris_persist::federation::types::{attestation_type, cohort_scope};
use ciris_persist::federation::{EmitAttestationInput, FederationDirectory};
use ciris_persist::prelude::{Engine, HybridPolicy, LocalSigner};
use serde::{Deserialize, Serialize};

use super::moderation::{admit_moderation_action, Duty};
use crate::auth::verify::{self, VerifyError};

/// The `content_class:infohazard` flag prefix. **Open vocabulary at the write
/// door** (CC 3.3.12) — any admitted key may author a row here, so who is
/// believed is decided on READ by [`FlagAuthority`], not by persist.
pub const CONTENT_CLASS_INFOHAZARD_PREFIX: &str = "content_class:infohazard";
/// The `content_class:reported` flag prefix. Same open write door, same
/// [`FlagAuthority`] read predicate as [`CONTENT_CLASS_INFOHAZARD_PREFIX`].
pub const CONTENT_CLASS_REPORTED_PREFIX: &str = "content_class:reported";
/// The `consent:scope:view` scope the interstitial requires.
pub const CONSENT_SCOPE_VIEW: &str = "consent:scope:view";
/// The bare scope token persist's `resolve_scoped_consent` matches on — the
/// envelope's `"scope"` member carries `"view"`, NOT the `consent:scope:view`
/// dimension limb (that is the dimension spelling, a different string).
const VIEW_SCOPE: &str = "view";

/// The producer-declared content flag (CC 3.3.12). **Open vocabulary** — the
/// substrate reserves only `age_assurance:` of that table, so who may author one
/// is [`FlagAuthority`]'s call on read. Ordered
/// by protective precedence: [`ContentFlag::Infohazard`] outranks
/// [`ContentFlag::Reported`] when both are present and the caller did not
/// disambiguate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentFlag {
    /// Flagged as a potential infohazard (the more severe class).
    Infohazard,
    /// Flagged as reported.
    Reported,
}

impl ContentFlag {
    /// The `content_class` token tail (`"infohazard"` / `"reported"`).
    pub fn as_str(self) -> &'static str {
        match self {
            ContentFlag::Infohazard => "infohazard",
            ContentFlag::Reported => "reported",
        }
    }

    /// Parse from a `content_class` token (`"infohazard"` / `"reported"`).
    pub fn from_token(s: &str) -> Option<ContentFlag> {
        match s {
            "infohazard" => Some(ContentFlag::Infohazard),
            "reported" => Some(ContentFlag::Reported),
            _ => None,
        }
    }

    /// The `content_class:*` dimension prefix for this flag.
    pub fn dimension_prefix(self) -> &'static str {
        match self {
            ContentFlag::Infohazard => CONTENT_CLASS_INFOHAZARD_PREFIX,
            ContentFlag::Reported => CONTENT_CLASS_REPORTED_PREFIX,
        }
    }

    /// The interstitial prompt the viewer affirms to unlock a reveal.
    pub fn prompt(self) -> &'static str {
        match self {
            ContentFlag::Infohazard => {
                "I consent to view this material reported as a potential infohazard."
            }
            ContentFlag::Reported => "I consent to view this material that has been reported.",
        }
    }
}

/// The consent an interstitial requires the viewer to emit — the wire shape the
/// app publishes via the *existing* attestation surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequiredConsent {
    /// `consent:state:granted`.
    pub state: &'static str,
    /// `consent:scope:view`.
    pub scope: &'static str,
    /// The flagged class the consent must name (`"infohazard"` / `"reported"`).
    pub content_class: String,
}

/// The reveal decision — the whole gate output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealDecision {
    /// Not flagged, or flagged-AND-consented — the app may render the content.
    Allow,
    /// Flagged, no matching live consent — the app MUST show the interstitial and
    /// WITHHOLD the content until a consent-to-view is emitted.
    Interstitial {
        /// Which class the subject is flagged as.
        flag: ContentFlag,
        /// The consent the viewer must emit to unlock the reveal.
        required: RequiredConsent,
    },
}

/// **The pure reveal gate** — CC 4.5.5 `content_class` × CC 3.3.1 consent. No
/// I/O; unit-testable. Mirrors the protective default of
/// [`super::age::gate_content_for`]:
///
/// - `flag == None` → `Allow` (unflagged content is universally visible).
/// - `flag == Some(_) && has_consent` → `Allow` (the viewer consented).
/// - `flag == Some(f) && !has_consent` → `Interstitial { .. }` — the PROTECTIVE
///   default: absent/unknown consent NEVER passively allows.
pub fn infohazard_reveal_decision(flag: Option<ContentFlag>, has_consent: bool) -> RevealDecision {
    match flag {
        None => RevealDecision::Allow,
        Some(_) if has_consent => RevealDecision::Allow,
        Some(flag) => RevealDecision::Interstitial {
            flag,
            required: RequiredConsent {
                state: consent_dimension::STATE_GRANTED_PREFIX,
                scope: CONSENT_SCOPE_VIEW,
                content_class: flag.as_str().to_owned(),
            },
        },
    }
}

// ─── Resolution helpers (I/O-free cores, wired to the substrate above) ───────

/// True if `dimension`/`expires_at` describe a LIVE `content_class:*` flag at
/// `now` (not expired). Pure — the liveness rule, factored for testing.
fn flag_row_is_live(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    expires_at.is_none_or(|exp| exp > now)
}

/// **The read-side emitter predicate** (CIRISServer#363): whose
/// `content_class:*` **withdrawal** this node believes.
///
/// # Why `attesting_key_id`, and why an explicit allowlist
///
/// A row's emitter is its `attesting_key_id`, and that field is
/// **cryptographically bound**: persist's `verify_federation_tier_ingest`
/// resolves the REGISTERED pubkeys of `attesting_key_id` via `lookup_public_key`
/// and verifies the row's signature against those — *"never against pubkeys
/// carried on the row"*. So writing someone else's key_id into the field does
/// not forge their authorship; you must hold their private half. An exact-match
/// allowlist on that field is therefore a real predicate over key CUSTODY, not a
/// test on a string the author chose.
///
/// # The three things this is deliberately NOT
///
/// 1. **NOT an `identity_type` check.** `identity_type = substrate_persist` is
///    SELF-ASSERTED at v30.2.0: `types::identity_type::conferral_mode` declares
///    it `DerivedFromVerifiedState`, and
///    `check_privileged_identity_type_admission_over_roster` enforces only
///    claims whose mode is `AccordCoScrubbed` — a set that is EMPTY at this
///    version. persist's own note justifies that mode *only* while nothing
///    consumes such rows "as authority over a third party", and names the
///    retirement condition in as many words: *"If a `system:*` row ever becomes
///    an input to a decision ABOUT ANOTHER PARTY, this must move to
///    AccordCoScrubbed."* A `content_class:` flag NAMING A SUBJECT is a decision
///    about another party. Gating on `identity_type` would have moved the attack
///    from "register as `agent`" to "register as `substrate_persist`" and closed
///    nothing.
/// 2. **NOT `lookup_trusted_publisher_chain`.** persist points consumers there
///    for these families, but it is shape-wrong for this one: it is scoped to
///    `content_rating:*` dimensions AND keyed by a hex `content_sha256` in
///    `evidence_refs`. Our rows are `content_class:*` keyed on the SUBJECT. It
///    cannot see them at all.
/// 3. **NOT (yet) a federated delegation walk.** The sound federated primitive
///    IS `trust_root::capability_roots_to_trusted_root` — v30.2.0
///    (CIRISPersist#607) minted three delegation scopes for exactly this shape,
///    assertions *about third parties*: `infra:attest_assurance`,
///    `infra:record_hard_case`, `infra:detect`. **None names content
///    classification**, and persist refuses scope reuse on principle
///    (`INFRA_ATTEST_ASSURANCE`: *"One name, two authorities is the fusion class
///    this repo keeps closing"*). Borrowing one of those tokens would let e.g. a
///    detector silently gain the power to clear a child-safety flag. So the
///    federated arm waits on an upstream scope token rather than being invented
///    here; until it lands, [`Self::none`] is the honest answer for a node with
///    no local flag producer, and it fails CLOSED.
///
/// # Fail-closed by construction
///
/// [`Default`] / [`Self::none`] is the EMPTY authority, and empty means **no
/// emitter may clear** — never "no gate". A node with no `substrate_persist`
/// signer wired therefore cannot have a flag cleared by anyone, which is the
/// protective direction for a CC 4.5.13 gate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlagAuthority {
    /// The `attesting_key_id`s whose withdrawals this node honours.
    emitters: std::collections::BTreeSet<String>,
}

impl FlagAuthority {
    /// The EMPTY authority: no emitter may clear a flag. The fail-closed
    /// default, and the honest answer on a node with no flag producer wired.
    pub fn none() -> Self {
        Self::default()
    }

    /// The node's own `substrate_persist` flag signer — the identity
    /// [`emit_content_flag`] signs with, reached only through the §11.10
    /// `Duty::Moderate` gate on `POST /v1/safety/flag`. Keyed on
    /// `derived_key_id()` because that is what `Engine::emit_attestation`
    /// stamps into `attesting_key_id`.
    pub fn of_substrate_signer(signer: &LocalSigner) -> Self {
        Self::from_key_ids([signer.derived_key_id()])
    }

    /// An explicit allowlist of authorised emitter `key_id`s.
    pub fn from_key_ids<I, S>(key_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            emitters: key_ids.into_iter().map(Into::into).collect(),
        }
    }

    /// True when NO emitter is authorised — i.e. no withdrawal can ever be
    /// honoured. Not an error: it is this gate's safe resting state.
    pub fn is_empty(&self) -> bool {
        self.emitters.is_empty()
    }

    /// The pure membership half, factored out so the allowlist is testable
    /// without a substrate.
    fn lists(&self, attesting_key_id: &str) -> bool {
        self.emitters.contains(attesting_key_id)
    }

    /// **May `attesting_key_id`'s withdrawal enter the fold at `now`?** The I/O
    /// half — reads the emitter's revocation state and defers the decision to
    /// [`clear_verdict`]. An error is passed through as `Err`, never swallowed
    /// into an empty list (an unreadable directory would otherwise read as "no
    /// revocations", i.e. as permission).
    async fn admits_clear(
        &self,
        directory: &dyn FederationDirectory,
        attesting_key_id: &str,
        now: DateTime<Utc>,
    ) -> ClearAdmission {
        let revocations = directory.revocations_for(attesting_key_id).await;
        clear_verdict(
            self.lists(attesting_key_id),
            revocations.as_deref().map_err(|_| ()),
            now,
        )
    }
}

/// **The clear-admission rule, pure.** Factored out of
/// [`FlagAuthority::admits_clear`] for the same reason [`flag_row_is_live`] is
/// factored: the fail-closed branch needs a witness that does not require a
/// fault-injecting substrate.
///
/// - not on the allowlist → [`ClearAdmission::NotAuthorized`] (the #363 attack);
/// - on it, but the revocation read FAILED → [`ClearAdmission::Unevaluable`].
///   "We could not check" is not "it is fine" — an unreadable directory must
///   never read as permission;
/// - on it, and a revocation is effective at `now` → `NotAuthorized`. A
///   rotated-out substrate key must not keep clearing child-safety flags;
/// - on it, live, readable → [`ClearAdmission::Admitted`]. The ONLY way through.
fn clear_verdict(
    listed: bool,
    revocations: Result<&[ciris_persist::federation::types::Revocation], ()>,
    now: DateTime<Utc>,
) -> ClearAdmission {
    if !listed {
        return ClearAdmission::NotAuthorized;
    }
    match revocations {
        Err(()) => ClearAdmission::Unevaluable,
        Ok(rows) if rows.iter().any(|r| r.effective_at <= now) => ClearAdmission::NotAuthorized,
        Ok(_) => ClearAdmission::Admitted,
    }
}

/// Why a `content_class:*` **withdrawal** row was or was not admitted into
/// [`subject_flag`]'s fold. Named rather than boolean because the two refusals
/// are different facts and a refusal that cannot say which branch it took is how
/// this defect survived: only [`Self::Admitted`] clears.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClearAdmission {
    /// The emitter is on this node's [`FlagAuthority`] and its key is live.
    Admitted,
    /// The emitter was evaluated and is NOT authorised — the CIRISServer#363
    /// attack shape (an ordinary admitted key withdrawing a flag it did not set).
    NotAuthorized,
    /// The emitter could NOT be evaluated (the revocation read failed). Fails
    /// CLOSED: the withdrawal is dropped and the subject stays flagged.
    Unevaluable,
}

/// **Resolve the flag on the subject.** Reads the subject's inbound
/// `content_class:*` attestations; a live `content_class:infohazard` /
/// `content_class:reported` row ⇒ flagged. When `requested` is `Some`, only that
/// class counts (the caller disambiguating). Otherwise the more severe
/// [`ContentFlag::Infohazard`] wins over [`ContentFlag::Reported`].
///
/// **The clear fold (latest-wins per class).** A moderator can CLEAR a flag
/// (retain→unflag, CC 4.5.13) — [`emit_content_flag`] with `withdrawn = true`
/// emits a superseding `content_class:{class}:v1` row carrying
/// `"withdrawn": true`. Per class, the row with the newest `asserted_at`
/// decides: a live flag row ⇒ flagged; a newer *admitted* withdrawal ⇒ cleared;
/// a still-newer re-flag ⇒ flagged again. This mirrors the latest-wins fold
/// persist already uses for consent, so a producer→gate flag and its later clear
/// compose without a separate `withdraws`-discovery read.
///
/// # The asymmetry, and why it is the fix (CIRISServer#363)
///
/// `content_class:` is open vocabulary at the write door (CC 3.3.12), so the
/// emitter predicate is ours and it is applied **per direction**:
///
/// - **A withdrawal enters the fold ONLY from an emitter `authority` admits**
///   ([`FlagAuthority::admits_clear`]). Anything else — an `agent`-typed
///   stranger, a key that merely *calls itself* `substrate_persist`, an emitter
///   whose revocation state will not read — is DROPPED before the fold and can
///   never clear the flag. This is the hole #363 reported and the reason this
///   function takes an `authority` at all.
/// - **A flag enters the fold from any emitter.** Deliberate, and strictly
///   weaker than the withdrawal rule, which is the required ordering: a forged
///   *set* over-withholds (a censorship nuisance the local duty-holder can undo,
///   since their clear IS admitted and wins latest-wins), while a forged *clear*
///   reveals material someone flagged. Dropping unauthorised sets would also
///   discard peer-replicated protective flags — this node runs a live
///   replication runtime — and at v30.2.0 there is no sound way to tell a peer's
///   genuine flag from a stranger's (see [`FlagAuthority`] note 3, the missing
///   upstream scope token). Between over-withholding and under-withholding on a
///   CC 4.5.13 child-safety gate, this gate over-withholds.
///
/// The residual is therefore named, not silent: **any admitted key can impose an
/// interstitial; only an authorised emitter can lift one.**
///
/// Returns `Ok(None)` when the subject carries no live, un-withdrawn flag. A
/// directory read that fails returns `Err` — which the route renders as 500,
/// never as `allow`.
pub async fn subject_flag(
    engine: &Engine,
    subject_key_id: &str,
    requested: Option<ContentFlag>,
    authority: &FlagAuthority,
) -> Result<Option<ContentFlag>, String> {
    let directory = engine.federation_directory();
    let rows = directory
        .list_attestations_for(subject_key_id)
        .await
        .map_err(|e| format!("list flags for subject: {e}"))?;
    let now = Utc::now();
    // Per class: the newest ADMITTED `content_class:*` row's
    // `(asserted_at, withdrawn)`.
    let mut infohazard: Option<(DateTime<Utc>, bool)> = None;
    let mut reported: Option<(DateTime<Utc>, bool)> = None;
    // Emitter verdicts are memoised per call: a subject carrying many rows from
    // one emitter costs ONE revocation read, and every row of that emitter gets
    // the SAME answer — a fold that changed its mind mid-scan would be its own
    // defect.
    let mut verdicts: std::collections::HashMap<String, ClearAdmission> =
        std::collections::HashMap::new();
    for row in rows {
        if !flag_row_is_live(row.expires_at, now) {
            continue;
        }
        let Some(dimension) = row
            .attestation_envelope
            .get(paths::DIMENSION)
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        let is_infohazard = dimension.starts_with(CONTENT_CLASS_INFOHAZARD_PREFIX);
        let is_reported = dimension.starts_with(CONTENT_CLASS_REPORTED_PREFIX);
        if !is_infohazard && !is_reported {
            continue;
        }
        let withdrawn = row
            .attestation_envelope
            .get("withdrawn")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        // THE READ-SIDE DISCRIMINATION (CIRISServer#363). A withdrawal is the
        // only direction that can OPEN this gate, so it is the only direction
        // that has to earn it.
        if withdrawn {
            let verdict = match verdicts.get(&row.attesting_key_id) {
                Some(v) => *v,
                None => {
                    let v = authority
                        .admits_clear(directory.as_ref(), &row.attesting_key_id, now)
                        .await;
                    verdicts.insert(row.attesting_key_id.clone(), v);
                    v
                }
            };
            if verdict != ClearAdmission::Admitted {
                // Loud, not silent: this is a refused attempt to lift a
                // child-safety flag, and the branch it took is the fact worth
                // having when one shows up in a log.
                tracing::warn!(
                    subject_key_id,
                    attesting_key_id = %row.attesting_key_id,
                    dimension,
                    verdict = ?verdict,
                    "REFUSED a content_class withdrawal from an unauthorised or \
                     unevaluable emitter — the subject stays flagged (CIRISServer#363)"
                );
                continue;
            }
        }
        let slot = if is_infohazard {
            &mut infohazard
        } else {
            &mut reported
        };
        // Latest-wins: keep only the newest ADMITTED row for this class.
        if slot.is_none_or(|(ts, _)| row.asserted_at >= ts) {
            *slot = Some((row.asserted_at, withdrawn));
        }
    }
    // Present iff the newest row for the class is a (non-withdrawn) flag.
    let present = |f: ContentFlag| {
        matches!(
            match f {
                ContentFlag::Infohazard => infohazard,
                ContentFlag::Reported => reported,
            },
            Some((_, false))
        )
    };
    Ok(match requested {
        // Caller disambiguated: only that class counts.
        Some(f) => present(f).then_some(f),
        // Undisambiguated: the more severe class wins.
        None if present(ContentFlag::Infohazard) => Some(ContentFlag::Infohazard),
        None if present(ContentFlag::Reported) => Some(ContentFlag::Reported),
        None => None,
    })
}

/// **Resolve the whole gate against the substrate.** Reads the subject's flag
/// (under `authority` — see [`subject_flag`]) + the viewer's live consent, then
/// applies [`infohazard_reveal_decision`].
pub async fn reveal_decision(
    engine: &Engine,
    viewer_key_id: &str,
    subject_key_id: &str,
    requested: Option<ContentFlag>,
    authority: &FlagAuthority,
) -> Result<RevealDecision, String> {
    let flag = subject_flag(engine, subject_key_id, requested, authority).await?;
    let has_consent = match flag {
        None => false, // unflagged: consent is moot (Allow regardless).
        Some(f) => {
            // CIRISServer#243 / CIRISPersist#389 — the ONE canonical scoped fold.
            //
            // We used to hand-roll this (`resolve_view_consent` + a `ConsentRow`
            // projection). That duplicate is now DELETED: persist v16.1.1's
            // `resolve_scoped_consent` folds `consent:state:*` rows latest-wins over
            // exactly the rows that name `scope:view` + this `content_class`.
            //
            // The adoption was HELD until v16.1.1 because v16.1.0's fold dropped
            // scope-less rows before the latest-wins step — which would have silently
            // deleted a tested safety property of THIS gate: a viewer who issues a
            // BLANKET `consent:state:revoked` (no scope named) would have kept the
            // infohazard gate OPEN, because an older scoped grant still won. On a CC
            // 4.5.13 child-safety gate that is not an acceptable regression.
            //
            // v16.1.1's `matches_scoped_query` fixes it with the right asymmetry, and
            // is now a strict superset of the fold we deleted:
            //   * a row NAMING this scope       → matches (on content_class);
            //   * a row naming ANOTHER scope    → unrelated, never re-closes us;
            //   * a scope-LESS non-grant        → BLANKET withdrawal, re-closes us;
            //   * a scope-LESS grant            → matches NOTHING (`granted` is the
            //     only fail-OPEN stance, so it must name its scope exactly — you can
            //     never back into a view-consent with a bare `consent:state:granted`).
            //
            // Only `Granted` opens the gate: `Revoked` / `Expired` / `Unspecified` all
            // fail closed, which is the protective default this gate has always had.
            let state = engine
                .federation_directory()
                .resolve_scoped_consent(
                    subject_key_id, // target: whose content is flagged
                    viewer_key_id,  // subject: who asserted the consent
                    VIEW_SCOPE,
                    Some(f.as_str()), // the content_class qualifier
                    chrono::Utc::now(),
                )
                .await
                .map_err(|e| format!("resolve_scoped_consent: {e}"))?;
            matches!(state, ConsentState::Granted)
        }
    };
    Ok(infohazard_reveal_decision(flag, has_consent))
}

// ─── The producer (CIRISServer#181) — substrate-signed flag emit ─────────────

/// **Emit the `content_class:{class}:v1` flag on `subject`** (CC 4.5.13 producer
/// hook). This is the row [`subject_flag`] reads and the `/v1/safety/reveal`
/// gate keys off — WITHOUT it the gate is inert (every read `allow`s).
///
/// ## Why a `substrate_persist` signer, not the node / duty-holder
///
/// **The reason changed in CIRISServer#363; the signer did not.** This doc used
/// to say `content_class:` was a substrate-reserved prefix that persist's
/// `default_reserved_prefix_rules` admitted only from an
/// `identity_type = substrate_persist` emitter, so emitting with the node or
/// duty-holder key would be refused `federation_reserved_prefix_emitter_mismatch`.
/// At the pinned v30.2.0 that is **false**: the family is open vocabulary at the
/// write door (CC 3.3.12), every one of those keys would be admitted, and
/// nothing about signing here is enforced by the substrate.
///
/// What makes this signer load-bearing now is the READ side: its
/// `derived_key_id()` is precisely this node's [`FlagAuthority`], the one
/// emitter whose `withdrawn: true` row [`subject_flag`] will honour. So the
/// split is unchanged in shape — the duty-HOLDER authorizes (the §11.10 gate at
/// the HTTP layer) and the SUBSTRATE signs — but it is now OUR read predicate
/// that gives it force, not persist's write gate.
///
/// `substrate_signer` is the node-scoped `substrate_persist` identity minted +
/// registered at boot (`compose::substrate_persist_signer` /
/// `compose::register_substrate_key`). [`Engine::emit_attestation`] derives the
/// attester/scrub key_id from that signer, so the row's `attesting_key_id` is
/// the substrate identity — never the node or the moderator — and
/// `verify_federation_tier_ingest` binds that field to the signer's registered
/// pubkeys, which is what makes the read-side allowlist unforgeable.
///
/// `withdrawn = false` FLAGS; `withdrawn = true` CLEARS (retain→unflag) — a
/// superseding row [`subject_flag`]'s latest-wins fold reads as "no live flag",
/// **and only because this signer is on the reader's [`FlagAuthority`]**. The
/// same bytes from any other key are dropped before that fold.
/// Returns the emitted attestation id.
pub async fn emit_content_flag(
    engine: &Engine,
    substrate_signer: &LocalSigner,
    subject_key_id: &str,
    flag: ContentFlag,
    withdrawn: bool,
) -> Result<String, String> {
    let class = flag.as_str();
    // The exact shape `subject_flag` reads + the test harness emits: a `scores`
    // row on `content_class:{class}:v1`, envelope `{dimension, content_class}`
    // (plus `withdrawn: true` on a clear). SCORES is the family's attestation
    // type per CC 3.3.12 — it is no longer a gate input (v30.2.0 gates nothing
    // on `content_class:`), it is the shape reader and writer agree on.
    let dimension = format!("content_class:{class}:v1");
    let mut envelope = serde_json::json!({ (paths::DIMENSION): dimension, "content_class": class });
    if withdrawn {
        envelope["withdrawn"] = serde_json::Value::Bool(true);
    }
    let input = EmitAttestationInput {
        attestation_type: attestation_type::SCORES.to_owned(),
        attested_key_id: Some(subject_key_id.to_owned()),
        attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
            envelope,
        )
        .map_err(|e| e.to_string())?,
        subject_key_ids: vec![subject_key_id.to_owned()],
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        expires_at: None,
        weight: None,
    };
    engine
        .emit_attestation(substrate_signer, input)
        .await
        .map_err(|e| format!("emit content_class:{class} flag (substrate-signed): {e}"))
}

// ─── HTTP surface ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct RevealState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
    /// Whose `content_class:*` withdrawal this node believes (CIRISServer#363).
    /// Empty on a node with no substrate flag signer — which means no flag can
    /// be cleared at all, not that clearing is ungated.
    authority: FlagAuthority,
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

#[derive(Debug, Deserialize)]
struct RevealRequest {
    /// The CEG subject a detection / moderation flow may have flagged.
    subject_key_id: String,
    /// Optional disambiguation when both classes are present.
    #[serde(default)]
    content_class: Option<ContentFlag>,
}

/// `POST /v1/safety/reveal` — decide whether the (signed) viewer may reveal a
/// flagged subject. Decision-only: it NEVER emits the consent (the app does, via
/// the existing attestation surface, then re-calls). Every view is attributable —
/// the viewer's signature is required (missing/invalid ⇒ 401).
///
/// - `200 { "decision": "allow" }` — unflagged, or flagged-and-consented.
/// - `403 { "decision": "interstitial", "flag": .., "prompt": .., "required": .. }`
///   — flagged, no live consent (the enforcement).
async fn reveal(State(st): State<RevealState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(StatusCode::UNAUTHORIZED, format!("signature: {e}"))
        }
    };
    let req: RevealRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    match reveal_decision(
        &st.engine,
        &caller.key_id,
        &req.subject_key_id,
        req.content_class,
        &st.authority,
    )
    .await
    {
        Ok(RevealDecision::Allow) => (
            StatusCode::OK,
            Json(serde_json::json!({ "decision": "allow" })),
        )
            .into_response(),
        Ok(RevealDecision::Interstitial { flag, required }) => (
            // 403: the enforcement. The content is WITHHELD until the viewer's
            // consent lands and the app re-calls.
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "decision": "interstitial",
                "flag": flag.as_str(),
                "prompt": flag.prompt(),
                "required": required,
            })),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

// ─── The producer endpoint (CIRISServer#181) — POST /v1/safety/flag ──────────

#[derive(Clone)]
struct FlagState {
    engine: Arc<Engine>,
    policy: HybridPolicy,
    /// The node-scoped `substrate_persist` signer that authors the reserved
    /// `content_class:*` flag. `None` on a node with no substrate identity
    /// wired (the flag endpoint then 503s — the gate stays honestly inert
    /// rather than emitting with the wrong identity).
    substrate_signer: Option<Arc<LocalSigner>>,
}

/// Flag vs. clear (retain→unflag). Defaults to [`FlagAction::Flag`].
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FlagAction {
    /// Emit the `content_class:{class}` flag on the subject.
    #[default]
    Flag,
    /// Clear a prior flag (emit a superseding withdrawal — the latest-wins fold).
    Clear,
}

#[derive(Debug, Deserialize)]
struct FlagRequest {
    /// The acting key (the moderator delegate or the duty-holder itself).
    signer_key_id: String,
    /// The community the moderation action is scoped to (the §11.10 duty gate).
    community_key_id: String,
    /// The CEG subject to flag / clear.
    subject_key_id: String,
    /// Which class (`infohazard` / `reported`).
    content_class: ContentFlag,
    /// `flag` (default) or `clear`.
    #[serde(default)]
    action: FlagAction,
}

#[derive(Debug, Serialize)]
struct FlagResponse {
    /// The emitted `content_class` attestation id.
    attestation_id: String,
    /// The class flagged / cleared.
    content_class: &'static str,
    /// `flag` or `clear`.
    action: &'static str,
    /// The `substrate_persist` identity that SIGNED the reserved flag (never the
    /// duty-holder). It is this key — not the authorizing moderator — that the
    /// reveal gate's [`FlagAuthority`] allowlists, so it is what makes the
    /// emitted row believable on read.
    emitter_key_id: String,
}

/// `POST /v1/safety/flag` — a **duty-gated producer** (CC 4.5.13): a moderator
/// flags a subject and the NODE's `substrate_persist` identity emits the
/// `content_class:{class}` flag, which makes
/// `/v1/safety/reveal` withhold the subject from non-consented viewers.
///
/// Auth mirrors [`super::moderation`] exactly: `verify_request` → caller;
/// `signer_acts_for`; then the §11.10 `Duty::Moderate` admit-iff gate is the
/// authority (a held/delegated `moderate` duty stands in for "a live-majority
/// favors moderation" in today's model — the FSD-004 live-quorum vote is a
/// future upgrade). A non-duty caller is REFUSED (403).
///
/// The duty-HOLDER authorizes; the SUBSTRATE signs (see [`emit_content_flag`]).
async fn flag(State(st): State<FlagState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match verify::verify_request(&st.engine, &headers, &body, st.policy).await {
        Ok(c) => c,
        Err(VerifyError::MissingHeader(h)) => {
            return err(StatusCode::UNAUTHORIZED, format!("missing {h}"))
        }
        Err(VerifyError::NoDirectory) => {
            return err(StatusCode::SERVICE_UNAVAILABLE, "no federation directory")
        }
        Err(VerifyError::SignatureInvalid(e)) => {
            return err(StatusCode::UNAUTHORIZED, format!("signature: {e}"))
        }
    };
    let req: FlagRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("bad request: {e}")),
    };
    // The HTTP signer must act for the declared acting key (self or an admitted
    // occurrence) — then the §11.10 duty gate decides authority.
    if !verify::signer_acts_for(&st.engine, &caller.key_id, &req.signer_key_id).await {
        return err(
            StatusCode::FORBIDDEN,
            "signer is neither the acting key nor an admitted occurrence of it",
        );
    }
    // COMPOSE the §11.10 admit-iff gate — a `moderate` duty is required.
    match admit_moderation_action(
        &st.engine,
        &req.signer_key_id,
        &req.community_key_id,
        Duty::Moderate,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return err(
                StatusCode::FORBIDDEN,
                "not authorized to flag: the moderate duty is held or delegated, never assumed \
                 (CEG §11.10 — no named-moderator authority and no live delegated chain)",
            )
        }
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
    // The duty-holder authorized; the SUBSTRATE identity signs the reserved flag.
    let Some(substrate_signer) = st.substrate_signer.as_ref() else {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no substrate_persist signer wired on this node — cannot author the reserved \
             content_class flag (compose::substrate_persist_signer)",
        );
    };
    let withdrawn = req.action == FlagAction::Clear;
    match emit_content_flag(
        &st.engine,
        substrate_signer,
        &req.subject_key_id,
        req.content_class,
        withdrawn,
    )
    .await
    {
        Ok(attestation_id) => (
            StatusCode::OK,
            Json(FlagResponse {
                attestation_id,
                content_class: req.content_class.as_str(),
                action: if withdrawn { "clear" } else { "flag" },
                emitter_key_id: substrate_signer.derived_key_id(),
            }),
        )
            .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

/// The infohazard reveal-gate + producer router. Default [`HybridPolicy::Strict`].
///
/// `substrate_signer` is the node-scoped `substrate_persist` identity that
/// authors the `content_class:*` flag. It is now load-bearing on BOTH sides: it
/// signs the flag on the producer route, and its `derived_key_id()` IS this
/// node's [`FlagAuthority`] — the only emitter whose withdrawal the reveal gate
/// believes. `None` leaves `/v1/safety/flag` 503-inert AND leaves the authority
/// EMPTY, so no flag on this node can be cleared by anyone (fail-closed; see
/// [`FlagAuthority::none`]).
pub fn router(
    engine: Arc<Engine>,
    policy: HybridPolicy,
    substrate_signer: Option<Arc<LocalSigner>>,
) -> Router {
    let authority = substrate_signer
        .as_ref()
        .map_or_else(FlagAuthority::none, |s| {
            FlagAuthority::of_substrate_signer(s)
        });
    Router::new()
        .route("/v1/safety/reveal", axum::routing::post(reveal))
        .with_state(RevealState {
            engine: Arc::clone(&engine),
            policy,
            authority,
        })
        .merge(
            Router::new()
                .route("/v1/safety/flag", axum::routing::post(flag))
                .with_state(FlagState {
                    engine,
                    policy,
                    substrate_signer,
                }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── flag liveness ───────────────────────────────────────────────────────

    #[test]
    fn flag_liveness_folds_expiry() {
        let now = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        assert!(flag_row_is_live(None, now), "no expiry ⇒ live");
        assert!(
            flag_row_is_live(DateTime::<Utc>::from_timestamp(2_000, 0), now),
            "future expiry ⇒ live"
        );
        assert!(
            !flag_row_is_live(DateTime::<Utc>::from_timestamp(500, 0), now),
            "past expiry ⇒ not live"
        );
    }

    // ─── the read-side emitter predicate (CIRISServer#363) ───────────────────

    #[test]
    fn an_empty_flag_authority_lists_nobody() {
        // The fail-closed resting state: `none()` / `Default` must mean "no
        // emitter may clear", never "no gate". If this ever flips to true for
        // an arbitrary key, every withdrawal in the fold is honoured again.
        let empty = FlagAuthority::none();
        assert!(empty.is_empty());
        assert!(!empty.lists("anyone-at-all"));
        assert_eq!(empty, FlagAuthority::default());
    }

    #[test]
    fn flag_authority_lists_only_its_own_emitters() {
        let a = FlagAuthority::from_key_ids(["substrate-a"]);
        assert!(a.lists("substrate-a"));
        assert!(
            !a.lists("substrate-b"),
            "a neighbouring key is NOT authorised"
        );
        assert!(
            !a.lists("Substrate-A"),
            "key_ids are exact, never case-folded"
        );
        assert!(!a.is_empty());
    }

    #[test]
    fn clear_verdict_fails_closed_when_the_emitter_cannot_be_evaluated() {
        let now = DateTime::<Utc>::from_timestamp(1_000, 0).unwrap();
        // Listed, readable, no revocations — the ONLY way through.
        assert_eq!(
            clear_verdict(true, Ok(&[]), now),
            ClearAdmission::Admitted,
            "a listed, live, readable emitter clears"
        );
        // Not listed — the CIRISServer#363 attack shape.
        assert_eq!(
            clear_verdict(false, Ok(&[]), now),
            ClearAdmission::NotAuthorized,
            "an emitter this node never authorised must not clear"
        );
        // THE FAIL-CLOSED BRANCH: listed, but the revocation state would not
        // read. An unreadable directory must never read as permission.
        assert_eq!(
            clear_verdict(true, Err(()), now),
            ClearAdmission::Unevaluable,
            "an unreadable emitter must NOT be admitted — 'we could not check' \
             is not 'it is fine'"
        );
        // Belt and braces: whatever the branch is called, it is not `Admitted`,
        // and only `Admitted` reaches the fold.
        assert_ne!(clear_verdict(true, Err(()), now), ClearAdmission::Admitted);
    }

    #[test]
    fn only_admitted_clears_and_the_other_two_branches_are_distinct() {
        // The whole point of naming the branches: `NotAuthorized` (evaluated,
        // refused) and `Unevaluable` (could not evaluate) are different facts
        // that reach the SAME protective outcome — neither is `Admitted`.
        assert_ne!(ClearAdmission::NotAuthorized, ClearAdmission::Admitted);
        assert_ne!(ClearAdmission::Unevaluable, ClearAdmission::Admitted);
        assert_ne!(ClearAdmission::Unevaluable, ClearAdmission::NotAuthorized);
    }

    #[test]
    fn content_flag_token_roundtrip() {
        for f in [ContentFlag::Infohazard, ContentFlag::Reported] {
            assert_eq!(ContentFlag::from_token(f.as_str()), Some(f));
        }
        assert_eq!(ContentFlag::from_token("bogus"), None);
    }

    // ─── HTTP: 401 without a signed request (returns before engine use) ───────

    #[tokio::test]
    async fn reveal_requires_a_signature() {
        use axum::body::Body;
        use axum::http::Request;
        use ciris_persist::prelude::LocalSigner;
        use ed25519_dalek::SigningKey;
        use tower::ServiceExt;

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x11; 32]),
            "reveal-test-node".to_string(),
            None,
            None,
        ));
        let engine = Arc::new(
            Engine::with_signer(signer, "sqlite::memory:")
                .await
                .expect("engine"),
        );
        let app = router(engine, HybridPolicy::Strict, None);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/safety/reveal")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "subject_key_id": "some-subject" }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
