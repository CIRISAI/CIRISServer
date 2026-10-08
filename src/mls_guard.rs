//! Panic isolation for adding a peer's KeyPackage to an MLS group, until edge
//! isolates it itself (CIRISEdge#823, v40.0.9).
//!
//! openmls (through libcrux-kem, RUSTSEC-2026-0330 / -0331) can panic on a
//! peer-signed KeyPackage with a short X-Wing init key, at decode or at
//! `add_member`. Every server call site already runs in a spawned task, so the
//! process survives, but the daemons that add members (the self-room drive and
//! the pair-room driver) read the SAME persisted package on every tick: a
//! panic caught and retried would panic again every tick and block the room
//! for good.
//!
//! [`add_member_guarded`] therefore catches the panic for one member, records
//! that exact package (by digest) as poisoned for the life of the process, and
//! reports the member as skipped. The other members of the tick proceed. A new
//! KeyPackage from the same device has different bytes and is tried fresh.

use std::collections::HashSet;
use std::sync::Mutex;

use ciris_edge::mls::cohort_group::{key_package_from_bytes, CohortCommit, CohortGroup};
use futures_util::FutureExt as _;
use sha2::{Digest, Sha256};

/// Bound on remembered poisoned packages; past it the oldest guard is the
/// panic itself, which is still caught.
const MAX_POISONED: usize = 1024;

static POISONED: Mutex<Option<HashSet<[u8; 32]>>> = Mutex::new(None);

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Was this exact package already seen to panic?
#[must_use]
pub fn is_poisoned(kp_bytes: &[u8]) -> bool {
    let d = digest(kp_bytes);
    POISONED
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.contains(&d)))
        .unwrap_or(false)
}

fn poison(kp_bytes: &[u8]) {
    if let Ok(mut g) = POISONED.lock() {
        let set = g.get_or_insert_with(HashSet::new);
        if set.len() < MAX_POISONED {
            set.insert(digest(kp_bytes));
        }
    }
}

/// How an add came out.
pub enum GuardedAdd {
    /// The commit; the caller places its Welcome as before.
    Added(CohortCommit),
    /// Skipped: this package panicked now or on an earlier tick. Not an error
    /// for the tick: the member waits for a fresh KeyPackage.
    Poisoned,
}

/// Decode `kp_bytes` and add `member` to `group`, with any panic in either step
/// caught and the package poisoned. Ordinary failures are returned as `Err`,
/// exactly as before.
///
/// # Errors
/// The decode or the add failed without panicking.
pub async fn add_member_guarded(
    group: &CohortGroup,
    member: &str,
    kp_bytes: &[u8],
) -> Result<GuardedAdd, String> {
    if is_poisoned(kp_bytes) {
        return Ok(GuardedAdd::Poisoned);
    }
    let attempt = std::panic::AssertUnwindSafe(async {
        let kp = key_package_from_bytes(kp_bytes).map_err(|e| format!("KeyPackage: {e}"))?;
        group
            .add_member(member, kp)
            .await
            .map_err(|e| format!("add_member({member}): {e}"))
    })
    .catch_unwind()
    .await;
    match attempt {
        Ok(Ok(commit)) => Ok(GuardedAdd::Added(commit)),
        Ok(Err(e)) => Err(e),
        Err(_panic) => {
            poison(kp_bytes);
            tracing::error!(
                member,
                "MLS: adding this KeyPackage PANICKED (openmls/libcrux, RUSTSEC-2026-0330/0331) \
                 — the package is poisoned for this process and the member skipped until it \
                 publishes a fresh one (CIRISEdge#823)"
            );
            Ok(GuardedAdd::Poisoned)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_poisoned_package_is_remembered_by_its_exact_bytes() {
        let bad = b"mls-guard-test: a package that panicked".to_vec();
        let fresh = b"mls-guard-test: the same device's next package".to_vec();
        assert!(!is_poisoned(&bad));
        poison(&bad);
        assert!(is_poisoned(&bad), "the same bytes are skipped next tick");
        assert!(!is_poisoned(&fresh), "a fresh package is tried again");
    }
}
