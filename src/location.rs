//! **Location-proof minting** (CIRISServer#341) — the producer half of CEG 0.8 §0.8.
//!
//! # Why this lives in the wheel
//!
//! `Engine` could already READ location proofs (`list_signed_location_proofs_since`,
//! persist v21.0.0) and nothing anywhere could produce one. An agent that wanted
//! to take part in regional community matching had no way to.
//!
//! It cannot fill the gap itself, for a concrete reason: minting an H3 cell in
//! Python needs the `h3` package, which publishes **no Android wheel** and is a
//! C extension rather than pure Python. Chaquopy requires a wheel per ABI, so
//! `h3` cannot be a dependency of an agent that ships to mobile. `ciris-server`
//! already publishes `android_24_{arm64_v8a,armeabi_v7a,x86_64}`.
//!
//! There is a second reason, and this codebase has paid for it repeatedly: a
//! producer that mints its own cell is restating a rule the substrate owns.
//! Every time something here was restated rather than read, it forked — a
//! harness restated the consent prefixes and hid a dead trace plane for eight
//! releases; a docstring restated the consent route and 404'd a wizard two
//! releases after the code was fixed. So the resolution bound is never written
//! down here. It is read from persist, and persist's own
//! `validate_location_cell` is the gate every minted cell passes through before
//! it is signed.
//!
//! # What a proof is for
//!
//! Reporting patterns across regions, and regional community membership:
//! `communities_containing(cell_id)` matches the geographic communities whose
//! constraint cell CONTAINS yours, and `member_in_geographic_constraint` admits
//! a member only on an in-force, unexpired contained proof. A community may also
//! use it as an optional gate on items destined for it. It is not a general
//! restriction on your traces — the replication consents decide that.

use anyhow::{Context, Result};
use ciris_persist::federation::location::MAX_LOCATION_PROOF_RESOLUTION;
use ciris_persist::federation::types::{LocationProof, SignedLocationProof};
use ciris_persist::prelude::Engine;

/// How long a minted proof stays in force.
///
/// A location proof is a claim about where you are, and people move. Long
/// enough that a settled user is not re-minting constantly; short enough that a
/// stale cell stops matching communities rather than silently persisting as
/// truth. Re-minting refreshes it.
const LOCATION_PROOF_VALIDITY_DAYS: i64 = 30;

/// Assertion instants are floored to a day.
///
/// Same discipline as the capacity scorer, for the same reason: a raw `now()`
/// inside a signed envelope makes every re-mint a distinct object with a
/// distinct content hash, so an agent that re-mints on each app launch would
/// accumulate permanent, replicating rows that all say the same thing. A daily
/// bucket is the right coarseness here — the underlying claim is "roughly where
/// I am", which does not change by the minute, and it means a re-mint from the
/// same cell on the same day is recognisably the SAME assertion.
///
/// Floor, never ceiling. `asserted_at` is a lower bound, so rounding up could
/// assert a position past the real `now()`.
const LOCATION_COALESCE_SECS: i64 = 86_400;

/// Mint, sign, and store a `SignedLocationProof` for THIS node at
/// `(latitude, longitude)`, returning it as JSON.
///
/// `resolution` omitted ⇒ this build's default, which is persist's
/// [`MAX_LOCATION_PROOF_RESOLUTION`] — the coarsest-bounded cell CEG 0.8 §0.8.1
/// permits, and therefore the most useful one that is still "rough". A caller
/// wanting to share LESS may pass a smaller number; a caller passing a larger
/// one is refused by persist, not by a bound restated here.
pub async fn mint_location_proof(
    engine: &Engine,
    latitude: f64,
    longitude: f64,
    resolution: Option<u8>,
) -> Result<String> {
    let resolution = resolution.unwrap_or(MAX_LOCATION_PROOF_RESOLUTION);

    // ── lat/lng → H3 cell ───────────────────────────────────────────────────
    let res = h3o::Resolution::try_from(resolution).map_err(|e| {
        anyhow::anyhow!(
            "mint_location_proof: resolution {resolution} is not a valid H3 resolution: {e}"
        )
    })?;
    let cell = h3o::LatLng::new(latitude, longitude)
        .map_err(|e| anyhow::anyhow!("mint_location_proof: ({latitude}, {longitude}): {e}"))?
        .to_cell(res);
    // Canonical wire form is LOWERCASE hex — persist rejects uppercase up front
    // so two encodings of one cell cannot both admit.
    let cell_id = cell.to_string().to_lowercase();

    // Persist's OWN gate, before we sign anything. This is the §0.8.1 rough-only
    // bound plus resolution-redundancy (the asserted resolution must equal the
    // cell's own encoded one, so a producer cannot claim coarseness it did not
    // use). Calling it here means a refusal surfaces as a clear error at mint
    // time rather than as a rejected write after a signature.
    ciris_persist::federation::location::validate_location_cell(&cell_id, resolution)
        .map_err(|e| anyhow::anyhow!("mint_location_proof: {e}"))?;

    let subject_key_id = engine
        .local_derived_key_id()
        .await
        .context("mint_location_proof: resolve this node's derived federation key_id")?;

    let asserted_at = ciris_persist::federation::freshness::coalesce_touch_ts(
        chrono::Utc::now(),
        chrono::Duration::seconds(LOCATION_COALESCE_SECS),
    );

    let proof = LocationProof {
        subject_key_id: subject_key_id.clone(),
        cell_id,
        cell_resolution: resolution,
        asserted_at,
        valid_until: Some(asserted_at + chrono::Duration::days(LOCATION_PROOF_VALIDITY_DAYS)),
        attestation_evidence: None,
        withdrawn_at: None,
        persist_row_hash: String::new(),
    };

    // Sign the canonical signing envelope (persist strips `persist_row_hash`,
    // which it computes itself). `sign_hybrid` produces the bound signature —
    // ML-DSA over `canonical ‖ ed25519_sig` — which is what the hybrid-Strict
    // verify in `verify_location_proof_admission` requires.
    let canonical =
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&proof.signing_envelope())
            .map_err(|e| anyhow::anyhow!("mint_location_proof: canonicalize: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| anyhow::anyhow!("mint_location_proof: sign_hybrid: {e}"))?;

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let signed = SignedLocationProof {
        location_proof: proof,
        // The subject asserting its own position. persist deliberately does not
        // require authority == subject (that is a broader policy layer), but a
        // self-minted proof is exactly the subject case.
        authority_key_id: subject_key_id,
        scrub_signature_classical: b64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(b64.encode(&sig.pqc.signature)),
    };

    engine
        .federation_directory()
        .put_location_proof(signed.clone())
        .await
        .map_err(|e| anyhow::anyhow!("mint_location_proof: put_location_proof: {e}"))?;

    tracing::info!(
        subject = %signed.location_proof.subject_key_id,
        cell_id = %signed.location_proof.cell_id,
        resolution,
        "location proof minted (H3, rough-only bound enforced by persist)"
    );
    serde_json::to_string(&signed).context("mint_location_proof: serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default must be READ from persist, never written down here.
    ///
    /// A restated bound is a bound that outlives the substrate changing it, and
    /// it fails in the direction that matters: the copy in `consent_disclosure()`
    /// tells an operator "resolution 7 or coarser is enforced", so a local
    /// constant drifting finer would make that sentence false while everything
    /// stayed green.
    #[test]
    fn the_default_resolution_is_persists_bound_not_a_local_literal() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/location.rs"),
        )
        .expect("readable");
        // Scan the CODE only. Including the test module makes this gate match
        // its own error message — a check that fails because of the words it
        // uses to describe failing is not measuring the code.
        let code = src.split("#[cfg(test)]").next().expect("code section");
        assert!(
            code.contains("resolution.unwrap_or(MAX_LOCATION_PROOF_RESOLUTION)"),
            "the omitted-resolution default must come from persist's own constant"
        );
        for literal in ["cell_resolution: 7", "unwrap_or(7)", "= 7;"] {
            assert!(
                !code.contains(literal),
                "found a hand-written resolution literal ({literal:?}). The bound belongs to \
                 CEG 0.8 §0.8.1 and is enforced by validate_location_cell — restating it here \
                 creates a second copy that can silently disagree."
            );
        }
    }

    /// Minted cells must be canonical for persist: lowercase hex, and carrying
    /// the resolution they claim.
    #[test]
    fn minted_cells_are_canonical_and_within_the_rough_only_bound() {
        for (lat, lng) in [(37.7749, -122.4194), (-33.8688, 151.2093), (0.0, 0.0)] {
            let res = h3o::Resolution::try_from(MAX_LOCATION_PROOF_RESOLUTION).unwrap();
            let cell_id = h3o::LatLng::new(lat, lng)
                .unwrap()
                .to_cell(res)
                .to_string()
                .to_lowercase();
            assert!(
                !cell_id.chars().any(|c| c.is_ascii_uppercase()),
                "({lat},{lng}) minted {cell_id} — persist rejects uppercase so two encodings of \
                 one cell cannot both admit"
            );
            ciris_persist::federation::location::validate_location_cell(
                &cell_id,
                MAX_LOCATION_PROOF_RESOLUTION,
            )
            .unwrap_or_else(|e| {
                panic!("({lat},{lng}) minted a cell persist refuses: {e}");
            });
        }
    }

    /// Finer than the bound must be refused by persist — not by a check here.
    #[test]
    fn a_finer_cell_is_refused_by_the_substrate() {
        let finer = MAX_LOCATION_PROOF_RESOLUTION + 1;
        let cell_id = h3o::LatLng::new(37.7749, -122.4194)
            .unwrap()
            .to_cell(h3o::Resolution::try_from(finer).unwrap())
            .to_string()
            .to_lowercase();
        assert!(
            ciris_persist::federation::location::validate_location_cell(&cell_id, finer).is_err(),
            "resolution {finer} must be refused. The substrate is the second line of defence \
             after client UI gating — a producer must not be able to over-share precise location \
             even when the client fails."
        );
    }
}
