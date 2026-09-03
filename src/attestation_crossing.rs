//! The v39 tier crossing, in ONE place.
//!
//! ## What replaced `attestation_promote`
//!
//! Persist v39.0.0 (CIRISPersist#799) deleted `attestation_promote`, which did
//! two different things under one name: it flipped a row's TIER *and* rewrote
//! its `cohort_scope` inside the signed envelope, re-signing the result with
//! THIS node's key and clearing the actor's scrub. The fabric became the author
//! of a claim it was only carrying, and any row attested by a key other than
//! the node's was refused at every peer while promotion still returned `Ok`.
//!
//! The two things are now two verbs, and this module is the one place that
//! composes them:
//!
//! | verb | what moves | who signs |
//! |---|---|---|
//! | [`Engine::enter_mesh`] | tier `local` → `federation`, SAME bytes | actor's signature stays the base scrub; the node may only APPEND a co-scrub |
//! | [`Engine::widen_audience`] | a NEW row at a strictly wider audience | the ACTOR — there is no delegated widening |
//!
//! ## Why every caller here needs both
//!
//! A local row is written at `cohort_scope: self` — persist requires it
//! ("local-tier rows MUST be `self`"). So the old single call to
//! `attestation_promote(id, FEDERATION)` was always doing a crossing AND a
//! widening at once. Faithfully migrating it therefore means both verbs, in
//! that order, and it leaves **two rows**: the `(federation, self)` original and
//! the `supersedes` at the wider audience. That is the design, not a bug — the
//! narrow row is what the actor signed, and the widening is a separate claim the
//! actor also signs.
//!
//! ## The outcome is not a boolean any more
//!
//! `attestation_promote` returned `bool`. It could afford to, because the node
//! re-signed everything and therefore always succeeded — which is exactly the
//! defect. Now a row attested by another key, with no signer in hand, returns
//! [`MeshCrossingOutcome::AwaitingActor`]: it is neither an error nor a success,
//! it WAITS for that actor. Callers must say which happened rather than
//! flattening it, so this returns the outcome.

use ciris_persist::federation::envelope::paths;
use ciris_persist::federation::{
    crossing, Attestation, Audience, CrossingBasis, Error, MeshCrossingOutcome,
};
use ciris_persist::signing::LocalSigner;
use ciris_persist::Engine;

/// Cross a local row into the mesh and place it at `target`.
///
/// `actor` is the signer of the row's attester when the caller holds it; `None`
/// when this node is the attester (the engine's own composed signer stands in)
/// or when the caller genuinely does not hold it — in which case an unsigned row
/// by another key comes back as [`MeshCrossingOutcome::AwaitingActor`] instead
/// of being forged into the node's name.
///
/// Returns the outcome of the LAST verb that ran: the widening when one was
/// needed, otherwise the crossing. A widening is skipped when the row already
/// sits at `target` — `enter_mesh` alone is then the whole motion.
pub async fn enter_mesh_at(
    engine: &Engine,
    attestation_id: &str,
    target: &Audience,
    basis: &CrossingBasis,
    actor: Option<&LocalSigner>,
) -> Result<MeshCrossingOutcome, Error> {
    let dir = engine.federation_directory();
    let row = dir.get_attestation(attestation_id).await?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "enter_mesh_at: row {attestation_id} does not exist"
        ))
    })?;

    // The crossing is over the row AS IT STANDS — its own audience, not the
    // target. `enter_mesh` cross-checks all nine axes against the row and
    // refuses by axis name, so describing it at the target audience here would
    // be refused (`recipient_see`), and rightly: the tier flip must not smuggle
    // a scope change into the signed envelope. That smuggling is the whole
    // reason `attestation_promote` is gone.
    let placed = Audience::of_row(&row)?;
    let ci = crossing::describe(&row, placed.clone(), basis.clone())?;
    let crossed = engine.enter_mesh(attestation_id, &ci, actor).await?;

    // A row that is waiting on its actor has not crossed, so there is nothing to
    // widen; returning here keeps the caller's report honest.
    if matches!(crossed, MeshCrossingOutcome::AwaitingActor { .. })
        || placed.cohort_scope() == target.cohort_scope()
    {
        return Ok(crossed);
    }

    // Re-read: the crossing rewrote the row's tier (and, on a node co-scrub, its
    // `additional_scrubs`), and the widening is built FROM the prior row. Using
    // the pre-crossing copy would describe a row that no longer exists.
    let prior = dir.get_attestation(attestation_id).await?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "enter_mesh_at: row {attestation_id} vanished between crossing and widening"
        ))
    })?;
    let ci = crossing::describe(&prior, target.clone(), basis.clone())?;
    // `strip` is empty: these callers widen the row they just wrote, with
    // nothing withheld. A consent `StripField` restriction is the sweep's
    // business (`promote_consented_backlog`), which carries the grant's
    // restrictions as `differs_in` members.
    engine.widen_audience(attestation_id, &ci, actor, &[]).await
}

/// Did the motion place the row at its target audience?
///
/// The compact reading for callers that reported a `bool` before. `AwaitingActor`
/// is FALSE — it has not been placed — but a caller that can distinguish should
/// match the outcome instead, because "waiting for its actor" and "refused" are
/// different things to tell an operator.
#[must_use]
pub fn is_placed(outcome: &MeshCrossingOutcome) -> bool {
    matches!(
        outcome,
        MeshCrossingOutcome::Crossed(_)
            | MeshCrossingOutcome::AlreadyInMesh { .. }
            | MeshCrossingOutcome::AlreadyWidened { .. }
    )
}

/// The id of the row that is actually ON the wire at the target audience.
///
/// **Not always the id you passed in.** `enter_mesh` keeps the row's id, but
/// `widen_audience` writes a NEW `supersedes` row and that row is the one the
/// wider audience can see — so a caller that reports or re-reads the original id
/// after a widening is naming the narrow row, which the audience cannot read.
/// `None` means nothing was placed (the row waits on its actor).
#[must_use]
pub fn placed_id(outcome: &MeshCrossingOutcome) -> Option<&str> {
    match outcome {
        MeshCrossingOutcome::Crossed(c) => Some(&c.attestation_id),
        MeshCrossingOutcome::AlreadyInMesh { attestation_id } => Some(attestation_id),
        // `AlreadyWidened` names the PRIOR row, not the widening that already
        // exists — the put door deduplicated and wrote nothing, so the new row's
        // id is not in the outcome. Returning the prior would hand back the
        // narrow row under the name of the wide one, which is the precise
        // mistake this function exists to prevent. A caller that needs the
        // placed row must re-read the chain.
        MeshCrossingOutcome::AlreadyWidened { .. } | MeshCrossingOutcome::AwaitingActor { .. } => {
            None
        }
    }
}

/// Is this row a `supersedes` written to PLACE a claim at a wider audience,
/// rather than to replace or retract it?
///
/// Asked of `widened_at`, which persist v40.0.0 (#801) added for exactly this
/// and which `crossing::check_widening` REQUIRES on every widening — it refuses
/// one without it, saying why: *"a widening carries the claim's instant in
/// `asserted_at` and its OWN in `widened_at`, so a reader can tell when the
/// claim was made from when it was placed"*. So on a v40 mesh the member is
/// present on every widening that got through the put door, and absent
/// everywhere else (it is `skip_serializing_if = "Option::is_none"`).
///
/// **Every consumer that folds `supersedes` needs this.** A widened claim leaves
/// TWO rows, and the second supersedes the first as a matter of mechanism. A
/// reader that cannot tell the two apart reports a message as retracted by its
/// own arrival, or a detector counts one claim as two and calls the pair a
/// revision. Both happened here before this existed.
///
/// This keyed on `differs_in ∋ cohort_scope` through the v39 adoption, to keep
/// recognising widenings a v39 peer might already have placed. v39 never
/// shipped — persist tagged it and we never did, and the ladder that refused
/// our tag is the reason — so there is no such row to recognise, and inferring
/// the shape from `differs_in` when the substrate states it outright is a second
/// spelling of persist's own definition.
#[must_use]
pub fn is_placement_widening(row: &Attestation) -> bool {
    is_placement_widening_envelope(&row.attestation_envelope)
}

/// [`is_placement_widening`] over the envelope alone, for callers that hold the
/// signed body without the row around it (`attest::claim_view`).
#[must_use]
pub fn is_placement_widening_envelope(envelope: &serde_json::Value) -> bool {
    envelope
        .get(paths::WIDENED_AT)
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.is_empty())
}
