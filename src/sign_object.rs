//! **Generic object signing** — a hybrid signature over any caller-supplied
//! artifact, for research harnesses and anything else that produces a file the
//! mesh does not carry.
//!
//! # Why this exists
//!
//! Every signing surface in this crate is tied to a CEG object: a consent grant,
//! a capacity score, a location proof. Each canonicalizes a *known* envelope
//! shape and lands a row on a *known* plane. That is right for the graph and
//! useless for an artifact the graph does not hold.
//!
//! The research harness is the motivating case. `tools/qa_runner/server.py`
//! writes the full trace — components, prompts, the reasoning under test — to
//! `trace_{task}_{hash}.json`, and that file is **deliberately not a CEG trace**:
//! the CEG carries the structural summary, the dump carries the material a
//! reviewer needs and a subject may not want federated. So the dump is exactly
//! the class of thing that must be *attestable without being replicated*.
//!
//! Unsigned, a dump proves nothing after the fact. A reviewer cannot tell the
//! file from an edited copy, and neither can the person who produced it — which
//! matters most for a campaign whose own rules say a reading is void if the
//! instrument cannot be shown clean. TORQUE (RATCHET#16) requires its hidden
//! arms be *"verified by trace audit, not by intention"*; an audit over
//! unsigned artifacts is an audit of whatever is on disk today.
//!
//! # What this signs, and what it does not claim
//!
//! It signs **bytes**, and says only: *this node's key saw exactly these bytes
//! at this instant.* It does not assert the artifact is true, complete,
//! conformant, or produced by any particular process. Provenance, not warrant.
//!
//! Nothing is written to the graph. No row, no dimension, no replication, no
//! consent implication — a signed dump is a detached fact the holder may show or
//! discard. That is deliberate: the moment signing an artifact created a CEG
//! row, signing a research dump would publish its existence, which is the
//! disclosure the dump/CEG split exists to avoid.
//!
//! # The hybrid binding
//!
//! `local_sign_hybrid` produces the bound pair — ML-DSA over `message ‖
//! ed25519_sig` — through persist's single implementation, pinned upstream
//! against the rlib path. This crate composes no preimage of its own; the last
//! site that did was retired in #283 finding 3, and a second correct copy is
//! still a copy that can only drift.

use anyhow::{Context, Result};
use ciris_persist::prelude::Engine;

/// The manifest a signature is computed over, and which travels beside the
/// artifact.
///
/// Signing the raw bytes alone would leave the signature ambiguous about WHAT
/// was signed — a detached blob and its signature can be paired with any story
/// about their origin. The manifest binds the digest to the claim, so the
/// signature covers `{what, how big, which algorithm, when, by whom}` and not
/// merely a byte string.
///
/// `label` is caller-supplied and uninterpreted: the harness puts the run id or
/// arm name there. It is inside the signed envelope, so a dump cannot later be
/// relabelled as belonging to a different arm — which for a campaign with
/// hidden and visible arms is the property that matters most.
fn manifest(
    digest_hex: &str,
    byte_len: usize,
    label: &str,
    signer_key_id: &str,
    signed_at: chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "ciris:signed-object:v1",
        "sha256": digest_hex,
        "byte_len": byte_len,
        "label": label,
        "signer_key_id": signer_key_id,
        "signed_at": signed_at.to_rfc3339(),
    })
}

/// Sign arbitrary bytes with this node's hybrid key. Returns the detached
/// signature document as JSON.
///
/// The returned document carries the manifest and both signature halves, so a
/// verifier needs the artifact and this document and nothing else — no network,
/// no graph read, no live node.
pub async fn sign_object_bytes(
    engine: &Engine,
    bytes: &[u8],
    label: &str,
) -> Result<serde_json::Value> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let digest_hex = hex::encode(Sha256::digest(bytes));
    let signer_key_id = engine
        .local_derived_key_id()
        .await
        .context("sign_object: resolve this node's derived federation key_id")?;

    let manifest = manifest(
        &digest_hex,
        bytes.len(),
        label,
        &signer_key_id,
        chrono::Utc::now(),
    );

    // Canonicalize the MANIFEST, not the artifact. The artifact is covered by
    // its digest inside the manifest, so arbitrary bytes — a JSON dump, a
    // tarball, a PNG — never have to satisfy a canonicalization rule they were
    // not written for. Only the manifest does, and we control its shape.
    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(&manifest)
        .map_err(|e| anyhow::anyhow!("sign_object: canonicalize manifest: {e}"))?;
    let sig = engine
        .sign_hybrid(&canonical)
        .await
        .map_err(|e| anyhow::anyhow!("sign_object: sign_hybrid: {e}"))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(serde_json::json!({
        "manifest": manifest,
        "scrub_signature_classical": b64.encode(&sig.classical.signature),
        "scrub_signature_pqc": b64.encode(&sig.pqc.signature),
    }))
}

/// Verify a signature document against bytes: does the digest match, and does
/// the signature verify against the named key's REGISTERED pubkeys?
///
/// Returns `Ok(false)` for an honest mismatch and `Err` only when the check
/// could not be performed — a verifier that cannot tell "this is forged" from
/// "I could not look" is the shape that admits both.
pub async fn verify_object_bytes(
    engine: &Engine,
    bytes: &[u8],
    signature_doc: &serde_json::Value,
) -> Result<bool> {
    use sha2::{Digest, Sha256};

    let manifest = signature_doc
        .get("manifest")
        .context("verify_object: signature document has no manifest")?;

    // Digest first: a mismatch here means the artifact changed, and there is no
    // point verifying a signature over a manifest describing different bytes.
    let claimed = manifest
        .get("sha256")
        .and_then(|v| v.as_str())
        .context("verify_object: manifest has no sha256")?;
    if hex::encode(Sha256::digest(bytes)) != claimed {
        return Ok(false);
    }

    let key_id = manifest
        .get("signer_key_id")
        .and_then(|v| v.as_str())
        .context("verify_object: manifest has no signer_key_id")?;
    let record = engine
        .federation_directory()
        .lookup_public_key(key_id)
        .await
        .map_err(|e| anyhow::anyhow!("verify_object: lookup_public_key({key_id}): {e}"))?
        .with_context(|| format!("verify_object: signer {key_id} is not a registered key"))?;

    let classical = signature_doc
        .get("scrub_signature_classical")
        .and_then(|v| v.as_str())
        .context("verify_object: no classical signature")?;
    let pqc = signature_doc
        .get("scrub_signature_pqc")
        .and_then(|v| v.as_str())
        .context("verify_object: no pqc signature")?;

    let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(manifest)
        .map_err(|e| anyhow::anyhow!("verify_object: canonicalize manifest: {e}"))?;

    // HybridPolicy::Strict: both halves must verify. A detached artifact has no
    // migration story and no legacy rows, so there is no case for accepting the
    // classical half alone — the reason Strict is refused elsewhere (pre-PQC
    // rows exist on the wire) simply does not arise here.
    let outcome = ciris_persist::verify::hybrid::verify_hybrid(
        &canonical,
        classical,
        Some(pqc),
        &record.pubkey_ed25519_base64,
        record.pubkey_ml_dsa_65_base64.as_deref(),
        ciris_persist::verify::hybrid::HybridPolicy::Strict,
        None,
    );
    // ONLY HybridVerified counts. The other two outcomes are honest results for
    // wire rows — a pre-PQC row pending its hybrid half, or an explicit fallback
    // policy — and neither is acceptable for a detached artifact signed today by
    // a key that has both halves. Accepting them would make the strict policy
    // above decorative.
    Ok(matches!(
        outcome,
        Ok(ciris_persist::verify::hybrid::VerifyOutcome::HybridVerified)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_binds_what_was_signed_not_just_the_bytes() {
        let m = manifest(
            "abc123",
            42,
            "torque/arm-d/hidden/run-7",
            "node-1",
            chrono::Utc::now(),
        );
        for field in ["sha256", "byte_len", "label", "signer_key_id", "signed_at"] {
            assert!(
                m.get(field).is_some(),
                "the manifest must carry `{field}`. Signing the raw bytes alone leaves the \
                 signature ambiguous about WHAT was signed — a detached blob and its signature \
                 can be paired with any story about their origin."
            );
        }
        assert_eq!(
            m["label"], "torque/arm-d/hidden/run-7",
            "the label is INSIDE the signed envelope, so a dump cannot be relabelled as \
             belonging to a different arm after the fact — the property that matters most for a \
             campaign with hidden and visible arms"
        );
    }

    /// The artifact is covered by its digest; only the manifest is
    /// canonicalized. So a dump containing bytes no canonicalizer would accept —
    /// a tarball, a PNG, invalid UTF-8 — is still signable.
    #[test]
    fn arbitrary_bytes_never_have_to_satisfy_a_canonicalization_rule() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sign_object.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        assert!(
            code.contains("ceg_produce_canonicalize(&manifest)"),
            "the MANIFEST is canonicalized, never the artifact"
        );
        assert!(
            !code.contains("ceg_produce_canonicalize(bytes)")
                && !code.contains("canonicalize_value(bytes)"),
            "canonicalizing the artifact would restrict signing to values that already satisfy \
             a CEG shape — which excludes exactly the research dumps this exists for"
        );
    }

    /// Signing an artifact must not create a graph row. A signed research dump
    /// that published its own existence would leak the disclosure the dump/CEG
    /// split exists to avoid.
    #[test]
    fn signing_an_object_writes_nothing_to_the_graph() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sign_object.rs"),
        )
        .expect("readable");
        let code = src.split("#[cfg(test)]").next().expect("code");
        for w in ["emit_attestation", "put_attestation", "put_location_proof"] {
            assert!(
                !code.contains(w),
                "`{w}` would land a row. A signed dump is a DETACHED fact the holder may show or \
                 discard; the moment signing publishes existence, signing a research dump \
                 discloses that the research happened."
            );
        }
    }
}
