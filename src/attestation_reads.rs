//! **Every row by / to one key** — the two whole-key reads this server made
//! through persist's `list_attestations_by` / `list_attestations_for`, which
//! persist v56 (CIRISPersist#1001) demoted to test builds and replaced with the
//! typed bounded read, [`AttestationQuery`].
//!
//! These are the same loop persist ran inside those two methods — every page of
//! `AttestationQuery::by` / `::to` at [`FOLD_PAGE`] — so the adoption of persist
//! v59 changes no caller's answer. The loop is written once here; narrowing
//! each caller to the dimension and types it actually reads (persist's intent:
//! no "every row" form) is the follow-up, site by site.
//!
//! [`AttestationQuery`]: ciris_persist::federation::attestation_query::AttestationQuery
//! [`FOLD_PAGE`]: ciris_persist::federation::attestation_query::FOLD_PAGE

use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
use ciris_persist::federation::{Attestation, Error, FederationDirectory};

/// The whole-key reads, on any federation directory (`dir.attestations_by_all(k)`).
#[async_trait::async_trait]
pub trait AllAttestations {
    /// Every row `attesting_key_id` authored, newest first.
    async fn attestations_by_all(&self, attesting_key_id: &str) -> Result<Vec<Attestation>, Error>;
    /// Every row attested to `attested_key_id`, newest first.
    async fn attestations_to_all(&self, attested_key_id: &str) -> Result<Vec<Attestation>, Error>;
}

#[async_trait::async_trait]
impl<D: FederationDirectory + ?Sized> AllAttestations for D {
    async fn attestations_by_all(&self, attesting_key_id: &str) -> Result<Vec<Attestation>, Error> {
        let mut out = Vec::new();
        let mut pages = AttestationQuery::by(attesting_key_id, FOLD_PAGE).pages();
        while let Some(rows) = pages.next(self).await? {
            out.extend(rows);
        }
        Ok(out)
    }

    async fn attestations_to_all(&self, attested_key_id: &str) -> Result<Vec<Attestation>, Error> {
        let mut out = Vec::new();
        let mut pages = AttestationQuery::to(attested_key_id, FOLD_PAGE).pages();
        while let Some(rows) = pages.next(self).await? {
            out.extend(rows);
        }
        Ok(out)
    }
}
