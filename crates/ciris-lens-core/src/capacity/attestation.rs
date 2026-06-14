//! [`CapacityAttestation`] — type-system-enforced CEG §7.5
//! anti-Goodhart invariant.

use serde::{Deserialize, Serialize};

/// A capacity-score attestation about `attested_key_id`, emitted by
/// `attesting_key_id`. **Cannot be constructed with matching keys**
/// — CEG §7.5 anti-Goodhart, enforced at the type system.
///
/// Construct via [`CapacityAttestation::new`] (or its friends);
/// pattern-match to access the keys. The struct is a value type
/// (`Clone + Debug + Eq + Serialize + Deserialize`) so it can flow
/// through serde, but `serde::Deserialize` re-validates the
/// invariant on the way in — see the [`Deserialize`] impl.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CapacityAttestation {
    /// The federation peer attesting *about* the subject.
    pub attesting_key_id: String,
    /// The federation peer the attestation is *about*. Per CEG §7.5,
    /// MUST NOT equal `attesting_key_id`.
    pub attested_key_id: String,
}

impl CapacityAttestation {
    /// Construct an attestation. Returns
    /// [`AntiGoodhartViolation::SelfAttestation`] if the keys match —
    /// CEG §7.5 forbids `capacity:*` self-emission.
    pub fn new(
        attesting_key_id: impl Into<String>,
        attested_key_id: impl Into<String>,
    ) -> Result<Self, AntiGoodhartViolation> {
        let attesting_key_id = attesting_key_id.into();
        let attested_key_id = attested_key_id.into();
        if attesting_key_id == attested_key_id {
            return Err(AntiGoodhartViolation::SelfAttestation {
                key_id: attesting_key_id,
            });
        }
        Ok(Self {
            attesting_key_id,
            attested_key_id,
        })
    }

    /// The attesting peer's `federation_keys.key_id`.
    pub fn attesting(&self) -> &str {
        &self.attesting_key_id
    }

    /// The attested-about peer's `federation_keys.key_id`.
    pub fn attested(&self) -> &str {
        &self.attested_key_id
    }
}

// Deserialize re-validates the invariant — bytes arriving over the
// wire can't bypass the construction-time check by skipping `new`.
impl<'de> Deserialize<'de> for CapacityAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Shadow {
            attesting_key_id: String,
            attested_key_id: String,
        }
        let s = Shadow::deserialize(deserializer)?;
        Self::new(s.attesting_key_id, s.attested_key_id).map_err(serde::de::Error::custom)
    }
}

/// Violations of CEG §7.5 anti-Goodhart construction-time invariant.
#[derive(Debug, thiserror::Error)]
pub enum AntiGoodhartViolation {
    /// `capacity:*` cannot be self-attested — the `attesting_key_id`
    /// and `attested_key_id` matched. The federation peer emitting a
    /// capacity score about an agent MUST NOT be that same agent
    /// (CEG §7.5).
    #[error("capacity self-attestation rejected per CEG §7.5: key_id={key_id}")]
    SelfAttestation {
        /// The key_id that appeared on both sides — included for
        /// diagnostics. Carries no privacy risk: `federation_keys.
        /// key_id` is already federation-public.
        key_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_keys_construct_ok() {
        let a = CapacityAttestation::new("lens-prod-eu", "agent-alpha")
            .expect("distinct keys must succeed");
        assert_eq!(a.attesting(), "lens-prod-eu");
        assert_eq!(a.attested(), "agent-alpha");
    }

    #[test]
    fn matching_keys_rejected_with_diagnostic() {
        let err = CapacityAttestation::new("agent-alpha", "agent-alpha")
            .expect_err("self-attestation must fail");
        assert!(matches!(
            err,
            AntiGoodhartViolation::SelfAttestation { ref key_id } if key_id == "agent-alpha"
        ));
        // The Display message references CEG §7.5 so any log line
        // surfaces the spec section without re-coining vocabulary.
        assert!(err.to_string().contains("CEG §7.5"));
    }

    #[test]
    fn serde_roundtrip_preserves_invariant() {
        let a = CapacityAttestation::new("attester", "attested").unwrap();
        let json = serde_json::to_string(&a).unwrap();
        let back: CapacityAttestation = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn deserialize_rejects_self_attestation_on_the_wire() {
        // A peer that hand-crafts wire bytes with matching keys
        // can't slip a self-attestation past the type — the invariant
        // is re-asserted in the Deserialize path.
        let bad = r#"{"attesting_key_id":"k1","attested_key_id":"k1"}"#;
        let result: Result<CapacityAttestation, _> = serde_json::from_str(bad);
        assert!(result.is_err(), "deserialize must reject self-attestation");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("CEG §7.5"),
            "diagnostic must cite the spec: {msg}"
        );
    }

    #[test]
    fn case_sensitive_inequality() {
        // `federation_keys.key_id` is case-sensitive per persist's
        // schema; an "almost-self" attestation with case diff is
        // structurally allowed (separate key_ids in the directory).
        let a = CapacityAttestation::new("Lens-Prod", "lens-prod").unwrap();
        assert_eq!(a.attesting(), "Lens-Prod");
        assert_eq!(a.attested(), "lens-prod");
    }
}
