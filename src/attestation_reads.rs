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
/// Per call site: `(calls, rows, wall µs)` since boot. Whole-key reads are the
/// server's widest reads (a key the canonical vouches for has thousands of
/// rows), and persist's per-door counters cannot say WHICH caller pays: the
/// call site can (steward 2026-11-01: "we need the hot paths clear").
type SiteCounts =
    std::collections::HashMap<&'static std::panic::Location<'static>, (u64, u64, u64)>;
static SITES: std::sync::Mutex<Option<SiteCounts>> = std::sync::Mutex::new(None);

fn record(site: &'static std::panic::Location<'static>, rows: usize, micros: u64) {
    let Ok(mut g) = SITES.lock() else {
        return;
    };
    let e = g
        .get_or_insert_with(Default::default)
        .entry(site)
        .or_default();
    e.0 += 1;
    e.1 += rows as u64;
    e.2 += micros;
}

/// `file:line -> (calls, rows, wall µs)`, cumulative since boot.
#[must_use]
pub fn whole_key_read_sites() -> Vec<(String, u64, u64, u64)> {
    let Ok(g) = SITES.lock() else {
        return Vec::new();
    };
    g.as_ref()
        .map(|m| {
            m.iter()
                .map(|(l, &(c, r, us))| (format!("{}:{}", l.file(), l.line()), c, r, us))
                .collect()
        })
        .unwrap_or_default()
}

type Rows<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Vec<Attestation>, Error>> + Send + 'a>,
>;

/// The whole-key reads, on any federation directory (`dir.attestations_by_all(k)`).
/// Each call is attributed to its caller's `file:line` ([`whole_key_read_sites`]).
pub trait AllAttestations {
    /// Every row `attesting_key_id` authored, newest first.
    #[track_caller]
    fn attestations_by_all<'a>(&'a self, attesting_key_id: &'a str) -> Rows<'a>;
    /// Every row attested to `attested_key_id`, newest first.
    #[track_caller]
    fn attestations_to_all<'a>(&'a self, attested_key_id: &'a str) -> Rows<'a>;
}

impl<D: FederationDirectory + ?Sized + Sync> AllAttestations for D {
    #[track_caller]
    fn attestations_by_all<'a>(&'a self, attesting_key_id: &'a str) -> Rows<'a> {
        let site = std::panic::Location::caller();
        Box::pin(async move {
            let t = std::time::Instant::now();
            let mut out = Vec::new();
            let mut pages = AttestationQuery::by(attesting_key_id, FOLD_PAGE).pages();
            while let Some(rows) = pages.next(self).await? {
                out.extend(rows);
            }
            record(site, out.len(), t.elapsed().as_micros() as u64);
            Ok(out)
        })
    }
    #[track_caller]
    fn attestations_to_all<'a>(&'a self, attested_key_id: &'a str) -> Rows<'a> {
        let site = std::panic::Location::caller();
        Box::pin(async move {
            let t = std::time::Instant::now();
            let mut out = Vec::new();
            let mut pages = AttestationQuery::to(attested_key_id, FOLD_PAGE).pages();
            while let Some(rows) = pages.next(self).await? {
                out.extend(rows);
            }
            record(site, out.len(), t.elapsed().as_micros() as u64);
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each call names its own call site, not this module.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_whole_key_read_is_attributed_to_its_caller() {
        let engine = ciris_persist::prelude::Engine::with_signer(
            std::sync::Arc::new(ciris_persist::prelude::LocalSigner::from_parts(
                ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
                "site-probe".into(),
                None,
                None,
            )),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        let dir = engine.federation_directory();
        let line = line!() + 1;
        let _ = dir.attestations_to_all("nobody").await.expect("read");
        let here = format!("{}:{line}", file!());
        let sites = whole_key_read_sites();
        let hit = sites.iter().find(|s| s.0 == here);
        assert!(hit.is_some_and(|s| s.1 >= 1), "{here} not in {sites:?}");
    }
}
