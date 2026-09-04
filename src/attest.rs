//! **One author per row** — the single door every attestation this server
//! produces goes through (CIRISServer#402).
//!
//! # The class
//!
//! An [`Attestation`] is two things that must agree: a set of typed COLUMNS the
//! store orders and joins on, and a signed ENVELOPE the whole mesh verifies. For
//! most of this repo's life those two were built by different code, a few lines
//! (or a few hundred kilometres) apart, and their agreement was a property
//! nobody wrote down and nothing checked.
//!
//! persist v31 checks it — at every door, on every backend — and in one sitting
//! it found FOUR ways the owner-binding path got it wrong:
//!
//! | gate | what diverged |
//! |------|---------------|
//! | CIRISPersist#659 | the key-registration envelope did not name its subject at all |
//! | CIRISPersist#598 | the `asserted_at` COLUMN was a second clock read, ~2 ms after the signed one |
//! | CIRISPersist#598 | that instant carried nanoseconds, which postgres cannot store |
//! | CIRISPersist#643 | the envelope carried no signed mirror of the seven typed columns |
//!
//! Each arrived as a 500 on a live first-run claim, and each looked like its own
//! small bug. They are one bug: **two authors for one fact**. Fixing them one at
//! a time is whack-a-mole with a fifth mole guaranteed — persist has three more
//! bindings on its roadmap and every one of them lands as a fresh 500 on
//! whichever hand-rolled row happens to run first.
//!
//! # The cure
//!
//! There is exactly one way to mint a row here, and it delegates the parts that
//! must agree to persist's OWN producer chokepoint:
//!
//! - [`attestation_emit::stamp_and_canonicalize`] mints the `attestation_id`,
//!   truncates and stamps `asserted_at`/`expires_at`, and writes the seven-member
//!   [`RowMirror`](ciris_persist::federation::envelope::RowMirror) — all BEFORE
//!   the bytes exist, so the signature covers them.
//! - [`attestation_emit::assemble`] reads every one of those back OUT of the
//!   signed envelope to build the columns, and re-checks the binding at the mint.
//!
//! The projection "which columns does this envelope imply" therefore has ONE
//! definition, and it is the same one `check_row_column_binding` compares against
//! at admission. Two definitions of that projection would be two definitions of
//! the binding, which is the class again one layer up.
//!
//! # What this module is NOT
//!
//! It is not a validation layer. [`Emit::adopt`] rebuilds a row from an envelope
//! that arrived on the wire, and the binding check on that row is TAUTOLOGICAL —
//! the columns were derived from the mirror, so of course they match it. The
//! defence for a received row is elsewhere and must stay there:
//!
//! 1. the caller verifies the hybrid signature over [`Emit::canonical`] BEFORE
//!    adopting (tampering with any mirrored field breaks that signature), and
//! 2. the caller checks the row's claims against facts it holds INDEPENDENTLY —
//!    this node's key id, the cohort the operator claimed under, the purpose it
//!    expects. [`apply_signed_owner_binding`](crate::auth::ownership::apply_signed_owner_binding)
//!    does both, and the second is what stops a validly-signed binding for a
//!    DIFFERENT node from being adopted here.
//!
//! Saying so plainly matters, because a gate whose denominator is its own
//! numerator reads exactly like a gate that works.
//!
//! # The exemption
//!
//! One site legitimately builds an `Attestation` literal outside this module:
//! the read-only PROBE in `admin_ops::read_admission_standing`, which is never
//! signed, never stored, and exists only to ask a persist predicate a question.
//! It is named in `tests/one_author_per_row.rs` so the exemption is a decision on
//! the record rather than a hole in a grep.

use ciris_persist::federation::envelope::EnvelopeCore;
use ciris_persist::federation::types::{Attestation, SignedAttestation};
use ciris_persist::federation::{attestation_emit, EmitAttestationInput};
use ciris_persist::prelude::{Engine, LocalSigner};

/// Who signs — the node's own engine identity, or a `LocalSigner` held for some
/// other party.
///
/// ONE abstraction across BOTH planes (attestations and key registrations),
/// because two would be how the binding comes to be applied on one path and not
/// the other — which is the shape this module exists to retire.
#[derive(Clone, Copy)]
pub enum KeySigner<'a> {
    /// This node's own federation identity.
    Engine(&'a Engine),
    /// A keypair held directly (a user's fed-ID, a test party).
    Local(&'a LocalSigner),
}

impl KeySigner<'_> {
    /// The attester id this signer authors under.
    ///
    /// For the engine it is the DERIVED federation key_id (#247) — the same one
    /// `emit_attestation_self` stamps. For a `LocalSigner` it is `key_id()`
    /// verbatim: the owner-binding wire contract keys on the registered id end to
    /// end, and deriving again would produce `<id>-<fp>-<fp>` and break the
    /// `federation_keys` foreign key.
    pub async fn key_id(&self) -> Result<String, Error> {
        match self {
            Self::Engine(e) => e
                .local_derived_key_id()
                .await
                .map_err(|e| Error::Sign(e.to_string())),
            Self::Local(s) => Ok(s.key_id().to_owned()),
        }
    }

    async fn sign_hybrid(&self, bytes: &[u8]) -> Result<ciris_crypto::HybridSignature, Error> {
        match self {
            Self::Engine(e) => e
                .sign_hybrid(bytes)
                .await
                .map_err(|e| Error::Sign(e.to_string())),
            Self::Local(s) => s
                .sign_hybrid(bytes)
                .await
                .map_err(|e| Error::Sign(e.to_string())),
        }
    }
}

/// What a caller wants said, as columns. Everything a producer decides; nothing
/// a producer may derive.
///
/// Note what is ABSENT: `attestation_id`, `asserted_at`, `original_content_hash`
/// and the `scrub_*` fields. Those are not inputs — they are consequences of
/// signing, and a caller that could set them is a caller that could set them
/// wrong. `tier` is absent for the same reason (the substrate mints
/// `federation`, and a `local`-tier row is a different primitive).
#[derive(Debug, Clone)]
pub struct Spec {
    /// The verb (`delegates_to`, `scores`, `withdraws`, …).
    pub attestation_type: String,
    /// Who the claim is ABOUT. `None` ⇒ a self-attestation; the substrate
    /// stamps the attester's own id into both the column and the mirror.
    pub attested_key_id: Option<String>,
    /// Whose consent governs the row — this is what grants revocation authority,
    /// which is why it is signed rather than stamped by whoever stores the row.
    pub subject_key_ids: Vec<String>,
    /// The recipient axis. VALIDATED, never defaulted (CIRISPersist#527): an
    /// empty scope must not be laundered into a federation-wide broadcast.
    pub cohort_scope: String,
    /// The absolute expiry, or `None` for a row that never lapses.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The weighted-claim value, or `None` for a NULL column.
    pub weight: Option<f64>,
    /// The dimension-specific body. The stamp adds the bound fields to it; it is
    /// otherwise carried through untouched.
    pub envelope: serde_json::Value,
}

impl Spec {
    /// A claim with no expiry and no weight — the common shape.
    pub fn new(
        attestation_type: impl Into<String>,
        cohort_scope: impl Into<String>,
        envelope: serde_json::Value,
    ) -> Self {
        Self {
            attestation_type: attestation_type.into(),
            attested_key_id: None,
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope.into(),
            expires_at: None,
            weight: None,
            envelope,
        }
    }

    /// Name the subject of the claim: `attested_key_id` AND `subject_key_ids`,
    /// which for every claim this server makes are the same key.
    ///
    /// They are set together because setting only one is a real defect with no
    /// symptom: `attested_key_id` is what the delegation walk joins on, and
    /// `subject_key_ids` is what lets that subject later revoke. A row with the
    /// first and not the second confers authority nobody can withdraw.
    #[must_use]
    pub fn about(mut self, subject_key_id: &str) -> Self {
        self.attested_key_id = Some(subject_key_id.to_owned());
        self.subject_key_ids = vec![subject_key_id.to_owned()];
        self
    }

    /// Name who the claim is ABOUT without naming a subject.
    ///
    /// Distinct from [`Self::about`], and the distinction is load bearing:
    /// `subject_key_ids` grants revocation authority, so a `scores` row that
    /// listed its subject would let the scored party revoke the score
    /// (CIRISPersist#519 exhibit G2). A claim about someone is not a claim
    /// theirs to withdraw.
    #[must_use]
    pub fn attested_to(mut self, attested_key_id: &str) -> Self {
        self.attested_key_id = Some(attested_key_id.to_owned());
        self
    }

    /// Set the absolute expiry (CC 2.4.1.2 `delegation_valid_until`).
    #[must_use]
    pub fn expiring(mut self, at: Option<chrono::DateTime<chrono::Utc>>) -> Self {
        self.expires_at = at;
        self
    }

    /// Set the weighted-claim value.
    #[must_use]
    pub fn weighing(mut self, weight: Option<f64>) -> Self {
        self.weight = weight;
        self
    }
}

/// Everything that can go wrong between a [`Spec`] and a stored row.
///
/// Distinct variants because they are distinct operator situations: a
/// [`Self::Substrate`] means the row is malformed and no retry helps, while a
/// [`Self::Persist`] means the row was fine and the store was not.
#[derive(Debug)]
pub enum Error {
    /// The envelope is not a JSON object, or does not parse as an envelope.
    Envelope(String),
    /// persist refused to stamp, canonicalize or assemble the row.
    Substrate(String),
    /// A signature half is not valid base64, or is the wrong length.
    Signature(String),
    /// Signing failed (no key, locked keyring, FFI error).
    Sign(String),
    /// The store refused or was unavailable.
    Persist(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(e) => write!(f, "attestation envelope: {e}"),
            Self::Substrate(e) => write!(f, "attestation assembly refused: {e}"),
            Self::Signature(e) => write!(f, "attestation signature: {e}"),
            Self::Sign(e) => write!(f, "attestation signing: {e}"),
            Self::Persist(e) => write!(f, "attestation store: {e}"),
        }
    }
}

impl std::error::Error for Error {}

/// A stamped, canonicalized, NOT-YET-SIGNED row.
///
/// Holding the bytes and the stamped input together in one value is the point:
/// the only way to get [`Self::canonical`] is to have gone through the stamp, and
/// the only way to reach [`Self::assemble`] is to hold the same value the stamp
/// produced. A caller cannot sign one envelope and assemble another.
pub struct Emit {
    attesting_key_id: String,
    input: EmitAttestationInput,
    canonical: Vec<u8>,
}

impl Emit {
    /// **Stage 1 — stamp.** Bind every column persist requires into the envelope,
    /// then canonicalize. `attesting_key_id` is the key that will sign, and it is
    /// needed HERE because it goes into the signed mirror: stamping for one
    /// signer and assembling with another is refused at the mint.
    pub fn stamp(attesting_key_id: &str, spec: Spec) -> Result<Self, Error> {
        Self::stamp_at(attesting_key_id, spec, chrono::Utc::now())
    }

    /// [`Self::stamp`] with the instant supplied — for tests that need a fixed
    /// clock. The instant is truncated to the substrate's resolution by the
    /// stamp, so a caller cannot introduce sub-microsecond precision here.
    pub fn stamp_at(
        attesting_key_id: &str,
        spec: Spec,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, Error> {
        let core =
            EnvelopeCore::from_value(spec.envelope).map_err(|e| Error::Envelope(e.to_string()))?;
        let mut input =
            EmitAttestationInput::with_envelope(spec.attestation_type, core, spec.cohort_scope);
        input.attested_key_id = spec.attested_key_id;
        input.subject_key_ids = spec.subject_key_ids;
        input.expires_at = spec.expires_at;
        input.weight = spec.weight;

        let canonical = attestation_emit::stamp_and_canonicalize(&mut input, attesting_key_id, now)
            .map_err(|e| Error::Substrate(e.to_string()))?;
        Ok(Self {
            attesting_key_id: attesting_key_id.to_owned(),
            input,
            canonical,
        })
    }

    /// **Re-open a row that arrived already signed.** The envelope carries the
    /// stamp (id, instant, mirror) the producer signed; the columns are derived
    /// back out of it rather than re-decided here.
    ///
    /// The mirror is NOT re-stamped: a fresh stamp would mint a new
    /// `attestation_id` into bytes the producer's signature no longer covers.
    ///
    /// **The caller must verify the signature over [`Self::canonical`] and check
    /// the row's claims against independently-held facts** — see this module's
    /// header. Adoption transports a claim; it does not test one.
    pub fn adopt(envelope: &serde_json::Value) -> Result<Self, Error> {
        let core = EnvelopeCore::from_value(envelope.clone())
            .map_err(|e| Error::Envelope(e.to_string()))?;
        let mirror = core.row.clone().ok_or_else(|| {
            Error::Envelope(
                "the envelope carries no signed `row` mirror, so it names no columns to adopt. Its \
                 producer did not build it through an emit chokepoint, and persist v31 refuses \
                 such a row at every door (CIRISPersist#643)"
                    .to_owned(),
            )
        })?;
        let expires_at = match core.expires_at.as_deref() {
            Some(raw) => Some(
                chrono::DateTime::parse_from_rfc3339(raw)
                    .map(|t| t.with_timezone(&chrono::Utc))
                    .map_err(|e| Error::Envelope(format!("envelope `expires_at`: {e}")))?,
            ),
            None => None,
        };
        let attesting_key_id = mirror.attesting_key_id.clone();
        let mut input = EmitAttestationInput::with_envelope(
            mirror.attestation_type.clone(),
            core,
            mirror.cohort_scope.clone(),
        );
        input.attested_key_id = Some(mirror.attested_key_id.clone());
        input.subject_key_ids = mirror.subject_key_ids.clone();
        input.expires_at = expires_at;
        input.weight = mirror.weight.as_ref().and_then(serde_json::Number::as_f64);

        // Canonicalize WITHOUT re-stamping — these must be the producer's bytes,
        // because they are the bytes the caller verified the signature over.
        let canonical = attestation_emit::canonicalize(&input.attestation_envelope.to_value())
            .map_err(|e| Error::Substrate(e.to_string()))?;
        Ok(Self {
            attesting_key_id,
            input,
            canonical,
        })
    }

    /// **Replace the minted row id with a SYMBOLIC one, before signing.**
    ///
    /// The trust-root ceremony's three rows are found by name — `genesis-charter`,
    /// `genesis-grant:<serve>`, `genesis-lifecycle` — on both sides of the wire.
    /// persist's `verify_delegation_plane_seeded` looks each up by the id the
    /// BAKED bundle carries, and this server's `charter_of` matches the charter by
    /// id because a self-loop stopped identifying it once the charter went
    /// family-shaped. So these ids are data, not decoration, and a fresh v4 uuid
    /// per ceremony would leave both lookups searching for rows that exist under
    /// another name.
    ///
    /// This is a narrow hatch, and it lives INSIDE the door on purpose. It edits
    /// the typed mirror — the same `RowMirror` the stamp wrote — and then
    /// re-canonicalizes through persist's own `canonicalize`, so the property that
    /// matters is preserved: one author for the row and its envelope. Calling it
    /// after the bytes are signed is impossible, because signing consumes `self`.
    ///
    /// Do not reach for this to make ordinary rows predictable. A row id that a
    /// producer can choose is a row id an attacker can choose; the ceremony rows
    /// earn the exception by being verified against a baked, signed artifact.
    pub fn with_row_id(mut self, attestation_id: &str) -> Result<Self, Error> {
        let mirror = self
            .input
            .attestation_envelope
            .row
            .as_mut()
            .ok_or_else(|| Error::Substrate("the stamp did not write a row mirror".to_owned()))?;
        mirror.attestation_id = attestation_id.to_owned();
        self.canonical =
            attestation_emit::canonicalize(&self.input.attestation_envelope.to_value())
                .map_err(|e| Error::Substrate(e.to_string()))?;
        Ok(self)
    }

    /// The exact bytes to sign — and, for an adopted row, the exact bytes whose
    /// signature must be verified before [`Self::assemble_from_b64`].
    #[must_use]
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    /// The stamped envelope, as it will be stored and as it goes on the wire.
    #[must_use]
    pub fn envelope(&self) -> serde_json::Value {
        self.input.attestation_envelope.to_value()
    }

    /// The key the mirror names as attester — for an adopted row, the producer.
    #[must_use]
    pub fn attesting_key_id(&self) -> &str {
        &self.attesting_key_id
    }

    /// The row id minted into the signed bytes.
    #[must_use]
    pub fn attestation_id(&self) -> Option<&str> {
        self.input
            .attestation_envelope
            .row
            .as_ref()
            .map(|m| m.attestation_id.as_str())
    }

    /// Who the claim is about, as the assembled row will carry it (a
    /// self-attestation resolves to the attester).
    #[must_use]
    pub fn attested_key_id(&self) -> &str {
        self.input
            .attested_key_id
            .as_deref()
            .unwrap_or(&self.attesting_key_id)
    }

    /// The verb.
    #[must_use]
    pub fn attestation_type(&self) -> &str {
        &self.input.attestation_type
    }

    /// The recipient axis the row will carry.
    #[must_use]
    pub fn cohort_scope(&self) -> &str {
        &self.input.cohort_scope
    }

    /// Whose consent governs the row — what grants revocation authority.
    #[must_use]
    pub fn subject_key_ids(&self) -> &[String] {
        &self.input.subject_key_ids
    }

    /// **Stage 2 — assemble** from a hybrid signature produced over
    /// [`Self::canonical`]. Every mirrored column is read back out of the signed
    /// envelope by the substrate, and the binding is re-checked at the mint.
    pub fn assemble(self, sig: ciris_crypto::HybridSignature) -> Result<Attestation, Error> {
        let (row, _) =
            attestation_emit::assemble(self.attesting_key_id, &self.canonical, sig, self.input)
                .map_err(|e| Error::Substrate(e.to_string()))?;
        Ok(row)
    }

    /// **Stage 2′ — assemble** from base64 signature halves produced elsewhere:
    /// the claim path (the owner signs on their own node) and the co-signed
    /// conferral path (a holder signs out of hardware custody).
    ///
    /// No public keys, because the row has no column for one. A verifier resolves
    /// the scrub key's pubkeys from `federation_keys` by `scrub_key_id` — which is
    /// the point of registering them — so threading pubkeys through here would put
    /// a second copy of a fact the directory already holds next to a signature that
    /// would then be checked against it. **This function does not verify and cannot:
    /// it never sees a policy.** The caller verifies first.
    pub fn assemble_from_b64(
        self,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: &str,
    ) -> Result<Attestation, Error> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;

        let d = |what: &str, s: &str| -> Result<Vec<u8>, Error> {
            B64.decode(s)
                .map_err(|e| Error::Signature(format!("{what} is not base64: {e}")))
        };
        let sig = ciris_crypto::HybridSignature {
            crypto_kind: ciris_crypto::CRYPTO_KIND_CIRIS_V1,
            classical: ciris_crypto::TaggedClassicalSignature {
                algorithm: ciris_crypto::ClassicalAlgorithm::Ed25519,
                signature: d("ed25519 signature", ed25519_sig_b64)?,
                public_key: Vec::new(),
            },
            pqc: ciris_crypto::TaggedPqcSignature {
                algorithm: ciris_crypto::PqcAlgorithm::MlDsa65,
                signature: d("ml-dsa-65 signature", ml_dsa_65_sig_b64)?,
                public_key: Vec::new(),
            },
            mode: ciris_crypto::SignatureMode::HybridRequired,
        };
        self.assemble(sig)
    }

    /// **Stage 2″ — sign here, then assemble.** For the sites that hold the
    /// signer themselves.
    pub async fn sign_and_assemble(self, signer: KeySigner<'_>) -> Result<Attestation, Error> {
        let sig = signer.sign_hybrid(&self.canonical).await?;
        self.assemble(sig)
    }
}

/// Store an assembled row through the ordinary door.
pub async fn put(engine: &Engine, row: Attestation) -> Result<String, Error> {
    let id = row.attestation_id.clone();
    engine
        .federation_directory()
        .put_attestation(SignedAttestation { attestation: row })
        .await
        .map_err(|e| Error::Persist(e.to_string()))?;
    Ok(id)
}

/// **The whole recipe** — stamp, sign with `signer`, assemble, store. Returns the
/// stored `attestation_id`.
///
/// The attester comes from [`KeySigner::key_id`], which is derived for the engine
/// and verbatim for a `LocalSigner` — see that method for why the difference is
/// load bearing.
pub async fn emit(engine: &Engine, signer: KeySigner<'_>, spec: Spec) -> Result<String, Error> {
    let key_id = signer.key_id().await?;
    let row = Emit::stamp(&key_id, spec)?
        .sign_and_assemble(signer)
        .await?;
    put(engine, row).await
}

/// The envelope keys that are **per-row bookkeeping, not part of the claim**.
///
/// persist v31 binds the row's own identity and instants INTO the signed
/// envelope (CIRISPersist#643/#598) so a relay cannot rewrite them. That is
/// right, and it broke this module in two directions at once, because both of
/// its comparisons treated "the envelope" and "the claim" as the same thing:
///
/// - `row.attestation_id` is unique per row, so EVERY pair of envelopes differs
///   on `row` — the evidence started naming `row` as a field two claims
///   "disagree on", which is noise that appears in every proof.
/// - `original_content_hash` covers those bytes, so two IDENTICAL claims can
///   never hash equal any more. Duplicate detection — the arm that keeps an
///   honest restatement or a replicated copy from being called a contradiction —
///   stopped firing at all.
///
/// Read from persist's own path constants rather than re-spelled: a rename
/// upstream must break this build, not silently shrink what counts as the claim.
///
/// TWO consumers now, which is why it lives here rather than in either of them:
/// [`crate::equivocation`] asks "do these two claims differ", and
/// [`crate::commons_surface`] asks "is this echoed envelope a stamp of the one I
/// would have built". Two spellings of "what is the claim" would be two answers.
/// persist v40.0.0 (#801) added a fourth: `widened_at`, the instant a WIDENING
/// was placed. It is per-placement bookkeeping by the same argument as the other
/// three — two identical claims republished at different moments are still the
/// same claim, and without this the duplicate arm stops firing on any widened
/// row exactly the way `original_content_hash` broke it in v31.
pub const ROW_BOOKKEEPING: [&str; 4] = [
    ciris_persist::federation::envelope::paths::ROW,
    ciris_persist::federation::envelope::paths::ASSERTED_AT,
    ciris_persist::federation::envelope::paths::EXPIRES_AT,
    ciris_persist::federation::envelope::paths::WIDENED_AT,
];

/// The members that describe a WIDENING's placement rather than its claim.
/// Removed only when the envelope IS a placement widening — see [`claim_view`].
pub const WIDENING_BOOKKEEPING: [&str; 2] = [
    ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID,
    ciris_persist::federation::envelope::paths::DIFFERS_IN,
];

/// The envelope with [`ROW_BOOKKEEPING`] removed — **what the attester actually
/// claimed**, as opposed to which row carried it.
///
/// `asserted_at` is excluded from the CONTENT comparison and is still the
/// coordinate the pair is keyed on (see the module note): two claims at the same
/// signed instant is the precondition, and what they say at it is this.
pub fn claim_view(envelope: &serde_json::Value) -> serde_json::Value {
    let Some(obj) = envelope.as_object() else {
        return envelope.clone();
    };
    let mut out = obj.clone();
    for k in ROW_BOOKKEEPING {
        out.remove(k);
    }
    // A PLACEMENT WIDENING'S CLAIM IS THE PRIOR'S BODY. persist v39.0.0 made a
    // claim reach a wider audience by writing a `supersedes` that carries the
    // prior's body verbatim plus three members describing the PLACEMENT: which
    // row it republishes, what differs, and (since v40.0.0) when it was placed.
    //
    // Those three are bookkeeping here for the same reason `row` is. Two
    // identical claims each get their own local row and therefore their own
    // widening, referencing different priors — so without this, two byte-identical
    // statements never hash equal and the duplicate arm silently stops firing.
    // That is the v31 `original_content_hash` breakage returning by another door,
    // and it is why this is stripped rather than the pair being called distinct.
    //
    // Conditional, and that matters: on a REAL `supersedes` or `withdraws`,
    // `references_attestation_id` is the claim — it names what is being retracted
    // — and stripping it there would make every composer look alike.
    if crate::attestation_crossing::is_placement_widening_envelope(envelope) {
        for k in WIDENING_BOOKKEEPING {
            out.remove(k);
        }
    }
    serde_json::Value::Object(out)
}

// ─── The KEY plane: the registration envelope and its columns ───────────────

/// **Register a key this node holds the signer for**, with a registration
/// envelope that BINDS ITS SUBJECT (CIRISPersist#659).
///
/// # The same class, one table over
///
/// A [`KeyRecord`] is the row/envelope pair again: typed columns (`key_id`,
/// `identity_type`, both pubkeys) beside a signed `registration_envelope`, and
/// for most of this repo's life the envelope was `{"key_id": …}` — naming one of
/// the four and vouching for none of the rest. persist v31 refuses that, and its
/// refusal says why better than a summary could: *"every signature over this row
/// is verified over those bytes ONLY, so an envelope that does not name its
/// subject stands for ANY record it is pasted onto."*
///
/// # Why the pubkeys are read off a probe signature
///
/// They must be in the envelope BEFORE it is canonicalized, and they must be the
/// keys that actually sign — not keys re-derived from a seed that might have
/// diverged. One throwaway signature answers both: it is produced by the same
/// signer, so its public halves are authoritative by construction. (This is the
/// move `EngineSelfSigner` already makes for the node's own record; the reason it
/// exists in two places is that they take different signer types, not different
/// facts.)
///
/// `extra` is merged into the envelope before binding — `roles` for the co-scrub
/// plane, `transport_hints` for a dialable canonical. Pass `Value::Null` for none.
pub async fn register_key(
    engine: &Engine,
    signer: KeySigner<'_>,
    key_id: &str,
    identity_type: &str,
    extra: serde_json::Value,
) -> Result<(), Error> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
    use sha2::{Digest, Sha256};

    let probe = signer
        .sign_hybrid(b"ciris:registration:pubkey-probe:v1")
        .await?;
    let ed_pub = B64.encode(&probe.classical.public_key);
    let pqc_pub = B64.encode(&probe.pqc.public_key);

    let mut envelope = serde_json::json!({ "key_id": key_id });
    if let (Some(dst), Some(src)) = (envelope.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        key_id,
        identity_type,
        &ed_pub,
        Some(&pqc_pub),
        None,
    )
    .map_err(Error::Envelope)?;

    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| Error::Substrate(e.to_string()))?;
    let sig = signer.sign_hybrid(&canonical).await?;
    let now = chrono::Utc::now();

    engine
        .register_federation_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: ed_pub,
                pubkey_ml_dsa_65_base64: Some(pqc_pub),
                algorithm: algorithm::HYBRID.into(),
                identity_type: identity_type.to_owned(),
                identity_ref: key_id.to_owned(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(Sha256::digest(&canonical)),
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: key_id.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .map_err(|e| Error::Persist(e.to_string()))
}
