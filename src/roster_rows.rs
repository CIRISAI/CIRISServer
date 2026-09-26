//! **Co-signed roster rows** (persist v49.0.0, CIRISPersist#908/#910, FSD
//! `ROOM_ROSTER_AUTHORITY.md` §3) — the signature shape both roster flows use.
//!
//! A multi-signature room or household changes its roster through ROWS (a
//! widening, a revocation), and persist admits each row by the group's
//! `consensus_protocol` over the row's OWN signatures: the primary plus
//! `cosignatures`, each a hybrid scrub over the same `signing_envelope()`. So
//! a signer of a change signs two things: the change envelope (what the
//! threshold tally and persist's quorum doors count) and every row the change
//! writes (what the roster doors count). [`ChangeSignature`] carries both,
//! flattened over the threshold signature, so a client that passes the
//! `signature` objects from `…/cosign` straight to `…/assemble` carries the
//! row signatures without knowing they exist.
//!
//! One module, because the community flow (`communities.rs`) and the family
//! flow (`family_api.rs`) are the same idea on two planes; a copy in each would
//! be the mirrored rule this repo keeps paying for.

use std::collections::BTreeSet;

use ciris_verify_core::threshold::ThresholdSignature;
use serde::{Deserialize, Serialize};

/// One signer's signature over one ROW a change writes (persist v49.0.0,
/// CIRISPersist#908, `ROOM_ROSTER_AUTHORITY.md` §3). A multi-signature room's
/// widening or revocation is admitted by the room's `consensus_protocol` over
/// the row's OWN signatures — the primary plus `cosignatures`, each a hybrid
/// scrub over the same `signing_envelope()` — so the envelope's signatures
/// alone no longer carry a change: every signer also signs the exact rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RowSignature {
    /// `"widening"` or `"revocation"`.
    pub(crate) kind: String,
    /// Whom the row is about.
    pub(crate) member_key_id: String,
    pub(crate) authority_key_id: String,
    pub(crate) scrub_signature_classical: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scrub_signature_pqc: Option<String>,
}

/// A signature on a change: the signer's threshold signature over the change
/// envelope (what `tally` and persist's quorum doors count), plus the same
/// signer's signatures over the rows the change writes (what the roster doors
/// count). Flattened, so a client that passes `signature` objects from
/// `…/cosign` straight to `…/assemble` carries both without knowing either.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ChangeSignature {
    #[serde(flatten)]
    pub(crate) threshold: ThresholdSignature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) row_signatures: Vec<RowSignature>,
}

pub(crate) fn thresholds(sigs: &[ChangeSignature]) -> Vec<ThresholdSignature> {
    sigs.iter().map(|s| s.threshold.clone()).collect()
}

/// The co-signatures for one row: every OTHER signer's scrub over it, one per
/// signer. The door verifies each and refuses a duplicate or the primary, so
/// both are left out here rather than sent to be refused.
pub(crate) fn cosignatures_for(
    sigs: &[ChangeSignature],
    primary: &str,
    kind: &str,
    member: &str,
) -> Vec<ciris_persist::federation::types::RosterCosignature> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for s in sigs {
        for r in &s.row_signatures {
            if r.kind == kind
                && r.member_key_id == member
                && r.authority_key_id != primary
                && seen.insert(r.authority_key_id.clone())
            {
                out.push(ciris_persist::federation::types::RosterCosignature {
                    authority_key_id: r.authority_key_id.clone(),
                    scrub_signature_classical: r.scrub_signature_classical.clone(),
                    scrub_signature_pqc: r.scrub_signature_pqc.clone(),
                });
            }
        }
    }
    out
}
