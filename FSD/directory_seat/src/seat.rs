//! The seat. Its whole state is `held`; nothing else survives a call. Guarded: every fn carries `@tla`.

use std::collections::BTreeMap;

use crate::{KeyId, Refusal, Registration, Verifier};

#[derive(Default)]
pub struct Seat {
    /// Per key, the registrations that verified. No first-come residency, no hint, no score, no counter.
    held: BTreeMap<KeyId, Vec<Registration>>,
}

pub enum LookupReply<'a> {
    Route(&'a Registration),
    /// The seat holds the key, but its route is not a forwarder's to serve (CC 5.4.6).
    KeyOnly(&'a crate::KeyRecord),
    Unknown,
}

impl Seat {
    /// @tla Valid
    pub fn verify_registration(v: &dyn Verifier, r: &Registration, now_ms: u64) -> Result<(), Refusal> {
        if v.key_id_of(&r.record.composite_pubkey) != r.record.key_id {
            return Err(Refusal::KeyIdMismatch);
        }
        if !v.verify(&r.record, &v.record_bytes(&r.record), &r.record.signature) {
            return Err(Refusal::BadRecordSignature);
        }
        if r.record.valid_until_ms <= now_ms {
            return Err(Refusal::RecordExpired);
        }
        if r.binding.key_id != r.record.key_id {
            return Err(Refusal::BindingNamesAnotherKey);
        }
        if !v.verify(&r.record, &v.binding_bytes(&r.binding), &r.binding.signature) {
            return Err(Refusal::BadBindingSignature);
        }
        if let Some(a) = &r.announce {
            if !v.announces(a, &r.record.key_id, now_ms) {
                return Err(Refusal::BadAnnounce);
            }
        }
        Ok(())
    }

    /// @tla Admissible
    /// Deliberately reads nothing from `self`: what the seat heard before cannot make a genuine row inadmissible.
    pub fn admissible(&self, v: &dyn Verifier, r: &Registration, now_ms: u64) -> Result<(), Refusal> {
        Self::verify_registration(v, r, now_ms)
    }

    /// @tla Servable
    pub fn servable(r: &Registration) -> bool {
        let owned = r.announce.is_some();
        !owned || r.binding.relay_offered
    }

    /// @tla Answer
    /// A function of `held` alone: the newest binding by its own signed instant, ties broken by transport bytes.
    pub fn answer_lookup(&self, key: &KeyId) -> Option<&Registration> {
        let newest = self
            .held
            .get(key)?
            .iter()
            .max_by_key(|r| (r.binding.asserted_at_ms, r.binding.transport))?;
        Self::servable(newest).then_some(newest)
    }

    /// @tla Admit
    pub fn admit_registration(&mut self, v: &dyn Verifier, r: Registration, now_ms: u64) -> Result<bool, Refusal> {
        self.admissible(v, &r, now_ms)?;
        let rows = self.held.entry(r.record.key_id).or_default();
        if rows.contains(&r) {
            return Ok(false);
        }
        rows.push(r);
        Ok(true)
    }

    /// @tla Sync
    /// A replica is a source of rows, never of trust: each one is admitted exactly as if a node had sent it.
    pub fn sync_from_replica(&mut self, v: &dyn Verifier, rows: impl IntoIterator<Item = Registration>, now_ms: u64) -> usize {
        rows.into_iter()
            .filter(|r| matches!(self.admit_registration(v, r.clone(), now_ms), Ok(true)))
            .count()
    }

    /// @tla Lookup
    pub fn serve_lookup(&self, key: &KeyId) -> LookupReply<'_> {
        match self.answer_lookup(key) {
            Some(r) => LookupReply::Route(r),
            None => match self.held.get(key).and_then(|rows| rows.first()) {
                Some(r) => LookupReply::KeyOnly(&r.record),
                None => LookupReply::Unknown,
            },
        }
    }

    /// @tla-none: a selection among `answer_lookup` results for relay-offering keys; each element is covered by
    /// Inv_NeverSwapped and Inv_OwnedRouteUnserved. Order is by transport bytes (no score, CC 5.4.3).
    pub fn serve_referrals(&self, max: usize) -> Vec<&Registration> {
        self.held
            .keys()
            .filter_map(|k| self.answer_lookup(k))
            .filter(|r| r.announce.is_some() && r.binding.relay_offered)
            .take(max)
            .collect()
    }

    /// @tla-none: fixed bytes compiled into the release; authority is the node's anchor check (FetchBundle,
    /// client::accept_bundle), never this route (CC 5.3.4 "no response_signature").
    pub fn serve_bundle(&self) -> &'static [u8] {
        todo!("the ceg-genesis-bundle/2 bytes this release carries")
    }
}

#[cfg(test)]
mod tests {
    // Each test names the TLA+ property it witnesses in code. Bodies are skeletons.

    /// @tla-inv Inv_NeverSwapped
    #[test]
    fn a_record_under_another_keys_name_is_refused() { /* key_id != H(pub) -> KeyIdMismatch */ }

    /// @tla-inv Inv_NoAuthority
    #[test]
    fn the_seat_has_no_door_that_writes_a_row_it_did_not_receive() { /* Seat has no pub fn taking a KeyId and a TransportId */ }

    /// @tla-inv Inv_NoLockout
    #[test]
    fn a_second_transport_at_the_same_instant_is_admitted() { /* admit(A), admit(B same key) -> both Ok(true) */ }

    /// @tla-inv Inv_OwnedRouteUnserved
    #[test]
    fn an_announced_node_without_relay_offer_answers_key_only() { /* serve_lookup -> KeyOnly */ }

    /// @tla-inv Prop_Registered
    /// @tla-inv Prop_Discoverable
    #[test]
    fn admitted_then_answered_with_the_newest_binding() { /* admit(v0 on A), admit(v1 on B) -> Route(B) in any order */ }
}
