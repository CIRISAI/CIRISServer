//! [`FederationKeyId`] — the **`derive_key_id` namespace**, made a type.
//!
//! ## The incident this exists to make impossible
//!
//! On 2026-08-02 a producer began signing federation trace batches with
//! `agent-55fe8d181727`. That is a well-formed key id — of the **agent-credits**
//! namespace (`CIRISAgent/ciris_engine/logic/audit/signing_protocol.py:127`,
//! `f"agent-{sha256(pubkey).hexdigest()[:12]}"`). The federation plane knows only
//! the *other* derivation:
//!
//! ```text
//! ciris-agent-bootstrap-25uzoxtlro     ← fedcode::derive_key_id(<alias>, <ed25519 pubkey>)
//! agent-55fe8d181727                   ← agent-credits: "agent-" + sha256(pk)[:12] hex
//! ```
//!
//! Two derivations, two namespaces, **one `String` field**. Every layer accepted
//! the value because at every layer it is a string that looks like a key id. It
//! failed at the one place that could tell — a `federation_keys` directory lookup
//! — 8,631 times a day for 71 hours, in a different process on a different
//! machine, and the trace plane was dead for two days
//! (`FSD/RCA_INGEST_REJECTION_2026-08-05.md`, CIRISServer#371).
//!
//! This is the **tenth** instance of the house defect class `CONTRIBUTING.md` §1
//! tabulates — *one name, two axes*. The argument for a type rather than more
//! care is in that table's last line: each of the first nine was found by a
//! different method, and none by review of the code containing it.
//!
//! ## What this type is, precisely
//!
//! A `FederationKeyId` is a value **minted by [`fedcode::derive_key_id`]** — the
//! id a `federation_keys` row is registered under, and the only id
//! `verify_hybrid_via_directory` will ever resolve. It is *not* "a key id"; it
//! is one namespace of at least four in this mesh (see [`KeyIdNamespace`] and
//! the "cannot be applied" list below).
//!
//! ## The derivation is verify's, called and never copied
//!
//! [`FederationKeyId::derive`] calls [`fedcode::derive_key_id`]; there is no
//! second implementation of the rule here, because a second implementation of an
//! identity rule is the drift shape CIRISServer#283 finding 3 retired.
//!
//! [`FederationKeyId::parse`] necessarily inspects **shape** rather than
//! re-deriving (a parser has no pubkey to derive from), so it is scoped to
//! exactly one question — *which namespace minted this?* — and is pinned to the
//! real derivation by [`tests::every_derived_id_parses`], which round-trips
//! `derive_key_id` output back through `parse` across a label corpus. If verify
//! changes the derivation, that test goes red rather than this file going
//! quietly wrong.
//!
//! [`fedcode::derive_key_id`]: ciris_verify_core::fedcode::derive_key_id
//!
//! ## The wire is unchanged
//!
//! [`Serialize`] is `#[serde(transparent)]` — a `FederationKeyId` is the same
//! JSON string it always was. This is a type-system change, not a wire change,
//! and [`tests::the_wire_is_one_plain_string`] pins that.
//!
//! ## Construction from an arbitrary `String` is explicit and rare
//!
//! There is deliberately **no** `From<String>`, no `From<&str>`, no
//! `Deref<Target = str>`: a newtype with a free conversion buys nothing. Three
//! ways in, in descending order of trust:
//!
//! | | when | can it fail |
//! |---|---|---|
//! | [`derive`](FederationKeyId::derive) | you hold the label + pubkey | no — correct by construction |
//! | [`of_local_signer`](FederationKeyId::of_local_signer) | you hold the signer | no — persist derives it |
//! | [`of_engine`](FederationKeyId::of_engine) | you hold the `Engine` | only if the signer cannot read its own key |
//! | [`parse`](FederationKeyId::parse) | the value came from outside | **yes**, and the error names the namespace |
//!
//! ## Where this type CANNOT be applied — the honest list
//!
//! Stated rather than implied, because these are where the class can still bite:
//!
//! - **Accord seat ids** (`A1`, `B1`, `C1`) and the canonical-seed family ids.
//!   They live in the same `accord_public_keys` directory as derived ids — the
//!   RCA's own diagnostic sample shows all four side by side — but they are a
//!   **third namespace**, minted by the seed ceremony, not by `derive_key_id`.
//!   [`FederationKeyId::parse`] refuses them, correctly and inconveniently.
//! - **The keystore alias** (`LocalSigner::key_id()`, `HardwareSigner::
//!   current_alias()`) — the derive_key_id *input*, e.g. `ciris-client`. A
//!   fourth namespace, and the one that caused CIRISServer#118. It is
//!   `String`-shaped here too; the cure is that every seal-stamp site now takes
//!   `&FederationKeyId`, so an alias cannot reach the stamp without going
//!   through [`derive`](FederationKeyId::derive).
//! - **`pqc_key_id`.** The ML-DSA-65 label persist stores verbatim and the
//!   hybrid verify does not consult. It is a fifth axis on the same word, and
//!   typing it as a federation id would assert an equivalence nothing checks.
//! - **Row columns read back out of persist** (`Attestation::attesting_key_id`,
//!   `Revocation::revoked_key_id`, every `key_id` on a persist struct). These
//!   are `String` on persist's types, which this repo does not own; converting
//!   at each read would be `.as_str()` churn buying nothing, because the value
//!   was not *chosen* there — it was stored, and the directory already vouched
//!   for it.

use std::fmt;

use ciris_verify_core::fedcode::{self, KEY_ID_FINGERPRINT_LEN};
use serde::{Deserialize, Deserializer, Serialize};

/// The lowercase RFC-4648 base32 alphabet a derived fingerprint is drawn from.
///
/// Not a second copy of a rule: `derive_key_id` lowercases the standard base32
/// output, so this is the *recognizable* character set of a value verify minted.
/// The link is pinned by [`tests::every_derived_id_parses`].
const FINGERPRINT_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";

/// The agent-credits prefix — `agent-{sha256(pubkey).hexdigest()[:12]}`.
const CREDITS_PREFIX: &str = "agent-";

/// The hex-digit count in an agent-credits id (`hexdigest()[:12]`).
const CREDITS_HEX_LEN: usize = 12;

/// Which derivation minted a key-id-shaped string.
///
/// Three states, not two: "is a federation id" and "is not" collapses the one
/// distinction the producer needs to fix their configuration. The RCA's fix 6
/// asks for exactly this — *the 401 body should name the namespace mismatch, not
/// just `verify_unknown_key`* — because the producer is the party who can act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdNamespace {
    /// `fedcode::derive_key_id(<alias>, <ed25519 pubkey>)` — the federation
    /// plane's only namespace. `ciris-agent-bootstrap-25uzoxtlro`.
    Federation,
    /// CIRISAgent's agent-credits id — `agent-` + 12 hex chars.
    /// `agent-55fe8d181727`. **This is the 2026-08-05 incident.**
    AgentCredits,
    /// Neither shape. A keystore alias (`ciris-client`), an accord seat (`A1`),
    /// a family id, or something else entirely. Named `Unrecognized` and not
    /// `Invalid` on purpose: this node cannot prove the value is meaningless,
    /// only that it is not a derived federation id.
    Unrecognized,
}

impl KeyIdNamespace {
    /// A stable machine token for logs and error bodies (closed set — never a
    /// formatted string, never the value itself).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KeyIdNamespace::Federation => "federation_derive_key_id",
            KeyIdNamespace::AgentCredits => "agent_credits",
            KeyIdNamespace::Unrecognized => "unrecognized",
        }
    }
}

/// Classify a key-id-shaped string by the derivation that could have minted it.
///
/// Total and allocation-free — every string lands in exactly one
/// [`KeyIdNamespace`]. This is the diagnostic half of [`FederationKeyId::parse`]
/// and it is what a refusal path reports.
#[must_use]
pub fn classify(value: &str) -> KeyIdNamespace {
    if is_derived_shape(value) {
        return KeyIdNamespace::Federation;
    }
    if is_agent_credits_shape(value) {
        return KeyIdNamespace::AgentCredits;
    }
    KeyIdNamespace::Unrecognized
}

fn is_agent_credits_shape(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(CREDITS_PREFIX) else {
        return false;
    };
    hex.len() == CREDITS_HEX_LEN && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Does `value` have the shape `derive_key_id` produces — `<label>-<fp>`, where
/// `fp` is [`KEY_ID_FINGERPRINT_LEN`] lowercase base32 chars and `label` is the
/// sanitized form (ascii-lowercase-alphanumeric groups joined by single dashes,
/// no leading or trailing dash)?
fn is_derived_shape(value: &str) -> bool {
    let Some((label, fp)) = value.rsplit_once('-') else {
        return false;
    };
    if fp.chars().count() != KEY_ID_FINGERPRINT_LEN
        || !fp.chars().all(|c| FINGERPRINT_ALPHABET.contains(c))
    {
        return false;
    }
    is_sanitized_label(label)
}

/// The post-`sanitize_label` form: non-empty, `[a-z0-9]` runs joined by single
/// `-`, no leading/trailing `-`, no `--`.
///
/// `derive_key_id` emits the literal label `id` when the caller's label
/// sanitizes to empty, so `id-<fp>` is a legitimate derived id and passes here
/// like any other.
fn is_sanitized_label(label: &str) -> bool {
    if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    let mut last_dash = false;
    for c in label.chars() {
        if c == '-' {
            if last_dash {
                return false;
            }
            last_dash = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            last_dash = false;
        } else {
            return false;
        }
    }
    true
}

/// An Ed25519 public key is exactly 32 bytes — the only input
/// [`fedcode::derive_key_id`] produces a *resolvable* id from.
const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// The derivation was handed something that is not an Ed25519 public key.
///
/// A fifth way to get the wrong namespace, and the quietest: `derive_key_id`
/// hashes whatever bytes it is given, so a 65-byte ECDSA P-256 key or an
/// ML-DSA-65 key yields a *perfectly well-formed* `<label>-<10 base32>` that no
/// `federation_keys` row can ever match. persist hardened its own accessor
/// against exactly this (`Engine::local_derived_key_id`, CIRISPersist#275 third
/// surface); [`FederationKeyId::try_derive`] is the same guard for the two sites
/// in this repo that derive from a runtime `Vec<u8>` rather than a `[u8; 32]`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "federation key id derivation needs a 32-byte Ed25519 public key, got {len} bytes — a \
     non-Ed25519 signer has no federation identity, and deriving over its key would mint a \
     well-formed id that no federation_keys row can match"
)]
pub struct NotEd25519 {
    /// The length actually supplied.
    pub len: usize,
}

/// Why an arbitrary string is not a federation key id.
///
/// Carries the namespace it *is*, so a refusal can tell the producer which
/// derivation they used — the difference between "unknown key" and "you signed
/// with your credits identity".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyIdNamespaceError {
    /// The value is an agent-credits id. **The 2026-08-05 incident.**
    #[error(
        "key id is the agent-credits namespace (agent-<12 hex>), not the federation \
         namespace (fedcode::derive_key_id output, <label>-<10 base32>)"
    )]
    AgentCredits,
    /// The value matches no derivation this node knows: a keystore alias, an
    /// accord seat id, a family id, or a typo.
    #[error(
        "key id is not fedcode::derive_key_id output (expected <label>-<10 base32 \
         chars>); it may be a keystore alias, an accord seat id, or a family id"
    )]
    Unrecognized,
}

impl KeyIdNamespaceError {
    /// The namespace the refused value actually belongs to.
    #[must_use]
    pub fn namespace(&self) -> KeyIdNamespace {
        match self {
            KeyIdNamespaceError::AgentCredits => KeyIdNamespace::AgentCredits,
            KeyIdNamespaceError::Unrecognized => KeyIdNamespace::Unrecognized,
        }
    }

    /// A stable machine token for an error body (never the offending value —
    /// AV-15; the value goes to the log, not the response).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            KeyIdNamespaceError::AgentCredits => "key_id_namespace_agent_credits",
            KeyIdNamespaceError::Unrecognized => "key_id_namespace_unrecognized",
        }
    }
}

/// A federation key id — a value minted by
/// [`fedcode::derive_key_id`](ciris_verify_core::fedcode::derive_key_id), and
/// the only id the federation directory resolves.
///
/// One `String` on the wire (`#[serde(transparent)]`); a distinct type in Rust.
///
/// ```
/// use ciris_lens_core::key_id::FederationKeyId;
///
/// let id = FederationKeyId::derive("ciris-agent-bootstrap", &[7u8; 32]);
/// assert!(FederationKeyId::parse(id.as_str()).is_ok());
/// assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{}\"", id.as_str()));
/// ```
///
/// A credits-namespace id cannot be one:
///
/// ```
/// use ciris_lens_core::key_id::{FederationKeyId, KeyIdNamespaceError};
///
/// assert_eq!(
///     FederationKeyId::parse("agent-55fe8d181727"),
///     Err(KeyIdNamespaceError::AgentCredits),
/// );
/// ```
///
/// …and it cannot be *silently* one — there is no `From<String>`, so the
/// incident is a compile error at the site that chooses the value:
///
/// ```compile_fail
/// use ciris_lens_core::key_id::FederationKeyId;
///
/// // The 2026-08-05 producer's mistake, in Rust. `signature_key_id` was a
/// // `String`, so this was a runtime 401 in another process two days later.
/// let id: FederationKeyId = "agent-55fe8d181727".to_string().into();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FederationKeyId(String);

impl FederationKeyId {
    /// Mint the federation key id for `(label, ed25519_pubkey)` — verify's
    /// derivation, called, never re-implemented.
    ///
    /// This is the correct-by-construction path and the one every signing site
    /// should reach for: given the two inputs the derivation takes, the wrong
    /// namespace is not expressible.
    #[must_use]
    pub fn derive(label: &str, ed25519_pubkey: &[u8]) -> Self {
        Self(fedcode::derive_key_id(label, ed25519_pubkey))
    }

    /// [`derive`](Self::derive) for a pubkey whose length is not known at
    /// compile time — a `Vec<u8>` off a `HardwareSigner` or a base64 decode.
    ///
    /// Every other caller holds a `[u8; 32]` (`VerifyingKey::as_bytes`,
    /// `LocalSigner::ed25519_public_key_bytes`) and cannot get this wrong, which
    /// is why [`derive`](Self::derive) stays infallible. These two can, and
    /// silently: see [`NotEd25519`].
    ///
    /// # Errors
    /// [`NotEd25519`] when `ed25519_pubkey` is not exactly 32 bytes.
    pub fn try_derive(label: &str, ed25519_pubkey: &[u8]) -> Result<Self, NotEd25519> {
        if ed25519_pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(NotEd25519 {
                len: ed25519_pubkey.len(),
            });
        }
        Ok(Self::derive(label, ed25519_pubkey))
    }

    /// The federation key id of a persist [`LocalSigner`] — persist's own
    /// `derived_key_id()`, not a re-derivation here.
    ///
    /// persist documents the distinction on that method: `LocalSigner::key_id()`
    /// is the raw keystore **alias** (the `derive_key_id` *input*), and *"any
    /// value that must FK to `federation_keys` … MUST use this, not
    /// `key_id`"* (CIRISPersist#247). Stamping the alias is CIRISServer#118.
    ///
    /// [`LocalSigner`]: ciris_persist::prelude::LocalSigner
    #[must_use]
    pub fn of_local_signer(signer: &ciris_persist::prelude::LocalSigner) -> Self {
        Self(signer.derived_key_id())
    }

    /// This node's own federation key id — persist's
    /// [`Engine::local_derived_key_id`], not a re-derivation here.
    ///
    /// The async sibling of [`Self::of_local_signer`], for the paths that hold
    /// an `Engine` rather than a `LocalSigner` (hardware custody keeps the
    /// public key behind an async read, which is why persist's own accessor is
    /// async).
    ///
    /// # Errors
    /// Propagates persist's [`SignError`] verbatim — a signer that cannot read
    /// its own public key has no federation identity, and inventing one here
    /// would be the fail-open shape.
    ///
    /// [`Engine::local_derived_key_id`]: ciris_persist::prelude::Engine::local_derived_key_id
    /// [`SignError`]: ciris_persist::engine::SignError
    pub async fn of_engine(
        engine: &ciris_persist::prelude::Engine,
    ) -> Result<Self, ciris_persist::engine::SignError> {
        Ok(Self(engine.local_derived_key_id().await?))
    }

    /// Accept a value that came from outside this process — **the only path
    /// from an arbitrary string, and it can fail.**
    ///
    /// # Errors
    /// [`KeyIdNamespaceError::AgentCredits`] when the value is an agent-credits
    /// id (the 2026-08-05 incident); [`KeyIdNamespaceError::Unrecognized`] for
    /// any other shape — a keystore alias, an accord seat id, a family id.
    pub fn parse(value: &str) -> Result<Self, KeyIdNamespaceError> {
        match classify(value) {
            KeyIdNamespace::Federation => Ok(Self(value.to_owned())),
            KeyIdNamespace::AgentCredits => Err(KeyIdNamespaceError::AgentCredits),
            KeyIdNamespace::Unrecognized => Err(KeyIdNamespaceError::Unrecognized),
        }
    }

    /// The wire value — one plain `String`, unchanged.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the wire `String` (for a persist/edge API that takes one).
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for FederationKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Deserialization goes through [`FederationKeyId::parse`], so a wrong-namespace
/// value cannot enter a typed field by riding a JSON string. The *shape* on the
/// wire is unchanged (a bare string); only the acceptance is narrowed.
impl<'de> Deserialize<'de> for FederationKeyId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        FederationKeyId::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin against derivation drift: whatever verify's `derive_key_id`
    /// emits, `parse` must accept. If verify changes the fingerprint length or
    /// alphabet, this goes red — rather than `is_derived_shape` going quietly
    /// wrong and refusing every honest producer.
    #[test]
    fn every_derived_id_parses() {
        let labels = [
            "ciris-agent-bootstrap",
            "ciris-client",
            "A1",                  // uppercase → sanitized to `a1`
            "Eric Moore's Node!!", // punctuation + spaces → dash-joined
            "",                    // empty → the `id-<fp>` form
            "----",                // all-separator → also the `id-<fp>` form
            "node9",
            "ünïcödé",
        ];
        for (i, label) in labels.iter().enumerate() {
            let pk = [i as u8; 32];
            let derived = fedcode::derive_key_id(label, &pk);
            assert_eq!(
                classify(&derived),
                KeyIdNamespace::Federation,
                "derive_key_id({label:?}) = {derived:?} must classify as the federation \
                 namespace — if this fails, verify's derivation moved and this module \
                 is now refusing honest producers"
            );
            assert_eq!(
                FederationKeyId::parse(&derived).map(FederationKeyId::into_string),
                Ok(derived.clone()),
                "parse must round-trip {derived:?} byte-for-byte"
            );
            assert_eq!(FederationKeyId::derive(label, &pk).as_str(), derived);
        }
    }

    /// The incident, as data.
    #[test]
    fn the_two_incident_ids_are_the_credits_namespace() {
        for id in ["agent-55fe8d181727", "agent-1ee871dcf31b"] {
            assert_eq!(classify(id), KeyIdNamespace::AgentCredits);
            assert_eq!(
                FederationKeyId::parse(id),
                Err(KeyIdNamespaceError::AgentCredits),
                "the RCA's rejected producer id must be refused BY NAMESPACE, not \
                 merely refused — the producer is the party who can fix it"
            );
        }
        // …and the id the federation plane actually knows, from the same
        // diagnostic, is accepted.
        assert!(FederationKeyId::parse("ciris-agent-bootstrap-25uzoxtlro").is_ok());
    }

    /// The other namespaces that share this word. Each is refused, and refused
    /// as `Unrecognized` rather than mislabelled — a wrong *name* in a refusal
    /// is how a producer chases the wrong fix.
    #[test]
    fn the_neighbouring_namespaces_are_refused_without_being_misnamed() {
        // Accord seat ids — they sit in `accord_public_keys` beside derived ids
        // (the RCA sample is literally ["A1","B1","C1","ciris-agent-bootstrap-…"]).
        for seat in ["A1", "B1", "C1"] {
            assert_eq!(classify(seat), KeyIdNamespace::Unrecognized);
        }
        // Keystore aliases — the derive_key_id INPUT (CIRISServer#118).
        for alias in ["ciris-client", "ciris-agent-bootstrap", "agent-unified-key"] {
            assert_eq!(
                classify(alias),
                KeyIdNamespace::Unrecognized,
                "{alias} is the derivation's input, not its output"
            );
        }
        // The other agent-credits form, `agent-{agent_id}` — not the hex form,
        // so it lands in Unrecognized. Naming it AgentCredits would be a guess.
        assert_eq!(classify("agent-datum"), KeyIdNamespace::Unrecognized);
    }

    /// Mutation-verification for the length discriminator: a 12-char hex tail is
    /// the credits shape and a 10-char base32 tail is the federation shape, and
    /// the check that separates them is the tail LENGTH, not the alphabet
    /// (`abcdef2345` is legal in both alphabets).
    #[test]
    fn the_discriminator_is_the_fingerprint_length() {
        // 10 base32 chars → a derived fingerprint.
        assert_eq!(classify("agent-abcdef2345"), KeyIdNamespace::Federation);
        // 12 hex chars → the credits shape.
        assert_eq!(classify("agent-abcdef234567"), KeyIdNamespace::AgentCredits);
        // 11 → neither namespace mints that length.
        assert_eq!(classify("agent-abcdef23456"), KeyIdNamespace::Unrecognized);
        // Base32 excludes 0/1/8/9, so a tail carrying them is not a fingerprint
        // however long it is.
        assert_eq!(classify("node-0189abcdef"), KeyIdNamespace::Unrecognized);
    }

    /// Labels that `sanitize_label` could never emit are refused, so a
    /// hand-typed near-miss does not pass as derived.
    #[test]
    fn a_malformed_label_is_not_a_derived_id() {
        for bad in [
            "",
            "abcdefghij",        // no dash at all
            "-abcdefghij",       // empty label
            "node--abcdefghij",  // double dash
            "NODE-abcdefghij",   // uppercase label
            "no de-abcdefghij",  // space
            "node_x-abcdefghij", // underscore
            "node-abcdefghij-",  // trailing dash → empty fingerprint
            "node-abcdefghi",    // 9 chars
            "node-abcdefghijk",  // 11 chars
            "node-abcdefghi1",   // `1` is not in the base32 alphabet
        ] {
            assert_eq!(
                classify(bad),
                KeyIdNamespace::Unrecognized,
                "{bad:?} must not read as a derived federation id"
            );
        }
    }

    /// The type-system change must not be a wire change: one plain JSON string,
    /// byte-identical to what a bare `String` field emitted.
    #[test]
    fn the_wire_is_one_plain_string() {
        let id = FederationKeyId::derive("ciris-agent-bootstrap", &[3u8; 32]);
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(
            json,
            serde_json::to_string(id.as_str()).expect("serialize str")
        );
        assert!(json.starts_with('"') && json.ends_with('"'));

        // Round-trip, and a wrong-namespace string cannot ride in.
        let back: FederationKeyId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
        assert!(serde_json::from_str::<FederationKeyId>("\"agent-55fe8d181727\"").is_err());

        // Nested in a struct, the field is indistinguishable from a String field.
        #[derive(Serialize)]
        struct Envelope<'a> {
            signature_key_id: &'a FederationKeyId,
        }
        assert_eq!(
            serde_json::to_string(&Envelope {
                signature_key_id: &id
            })
            .expect("serialize"),
            format!(r#"{{"signature_key_id":"{}"}}"#, id.as_str())
        );
    }

    /// A non-Ed25519 key derives to something that LOOKS right and can never
    /// resolve — the quietest way left to mint the wrong namespace.
    #[test]
    fn a_non_ed25519_pubkey_cannot_mint_a_federation_id() {
        // 65 bytes: an uncompressed SEC1 ECDSA P-256 key, the keystore fallback
        // persist#275 hardened against.
        let p256 = [4u8; 65];
        assert_eq!(
            FederationKeyId::try_derive("ciris-client", &p256),
            Err(NotEd25519 { len: 65 })
        );
        // And it would have been accepted: the shape check cannot catch this,
        // which is exactly why the LENGTH has to be checked at the derivation.
        assert_eq!(
            classify(&fedcode::derive_key_id("ciris-client", &p256)),
            KeyIdNamespace::Federation,
            "a P-256 key derives to a well-formed federation id — the defect is \
             invisible downstream, so it must be refused here"
        );

        assert_eq!(
            FederationKeyId::try_derive("ciris-client", &[]),
            Err(NotEd25519 { len: 0 })
        );
        assert_eq!(
            FederationKeyId::try_derive("ciris-client", &[7u8; 32]),
            Ok(FederationKeyId::derive("ciris-client", &[7u8; 32])),
            "try_derive must agree with derive on a real Ed25519 key"
        );
    }

    #[test]
    fn the_namespace_tokens_are_a_closed_stable_set() {
        assert_eq!(
            KeyIdNamespace::Federation.as_str(),
            "federation_derive_key_id"
        );
        assert_eq!(KeyIdNamespace::AgentCredits.as_str(), "agent_credits");
        assert_eq!(KeyIdNamespace::Unrecognized.as_str(), "unrecognized");
        assert_eq!(
            KeyIdNamespaceError::AgentCredits.namespace(),
            KeyIdNamespace::AgentCredits
        );
        assert_eq!(
            KeyIdNamespaceError::AgentCredits.kind(),
            "key_id_namespace_agent_credits"
        );
    }
}
