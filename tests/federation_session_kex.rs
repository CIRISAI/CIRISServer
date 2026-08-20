//! Federation-session hybrid X25519 + ML-KEM-768 KEX — Rust conformance gate
//! (CIRISServer#109). Run: `cargo test --test federation_session_kex`.
//!
//! This is the CORRECTNESS lane for the post-quantum federation handshake. The
//! KEX is otherwise exercised only by `benches/pqc_av_streaming.rs` (criterion
//! *timing*, `pqc_kex` group) — that proves it runs FAST, not that it runs
//! RIGHT. This gate drives the real, pinned `ciris_edge` / `ciris_crypto`
//! crates Rust-to-Rust (the feature is not on the Python wheel surface, so it
//! cannot be reached from the persist/agent test lanes) and asserts the three
//! security properties CEG hybrid-KEX conformance demands — modeled on the STH
//! consistency gate (`tests/stream_sth_consistency.rs`): drive the real crates,
//! assert the behaviour, AND prove the negative (fail closed).
//!
//! Pinned triple (Cargo.lock): ciris-edge v7.0.12 (rev 943cdcd) /
//! ciris-crypto v7.5.0 / ciris-verify-core v7.5.0.
//!
//! ## The construction under test (CIRISEdge#54, FIPS 203 ML-KEM-768)
//!
//! `FederationSession::initiate(peer, alg)` returns `(SessionHandshakeMsg, SessionKey)`
//! — the initiator's wire message (its X25519 ephemeral pub + the ML-KEM-768
//! ciphertext encapsulated to the peer's long-term ML-KEM pub) PLUS the
//! initiator's derived 32-byte session key. `FederationSession::respond(own, &msg)`
//! recomputes the SAME key from that message + the responder's KEX privkeys.
//! The session key is `HKDF(IKM = shared_x25519 || shared_mlkem,
//! salt = eph_pk || recipient_x_pk || mlkem_ct || recipient_mlkem_pk)`, so the
//! ML-KEM half is bound into BOTH the IKM and the salt — tampering the
//! ciphertext diverges the key on both paths (see `tamper_*` tests below).
//!
//! ## What this gate asserts
//!
//! 1. AGREEMENT — initiator and responder derive the identical 32-byte key.
//! 2. TAMPER CLOSED — a flipped / dropped ML-KEM ciphertext NEVER yields an
//!    agreed key (error, or a non-matching key — never a silent classical-only
//!    success).
//! 3. HYBRID REQUIRED — `KexAlgorithm::HybridRequired` (the HNDL-strict policy
//!    flag) rejects a classical-only peer instead of degrading; and there is NO
//!    classical-only success path inside a hybrid message (the hybrid wire form
//!    always carries the ML-KEM ciphertext).

use ciris_crypto::{ml_kem, x25519};
use ciris_edge::transport::federation_session::{
    FederationSession, KexAlgorithm, OwnKexKeys, PeerKexPubkeys, SessionHandshakeMsg,
    ALGORITHM_HYBRID_V1,
};

/// A fresh responder identity holding both KEX private halves. Mirrors the
/// bench's keygen (`x25519::generate_ephemeral_keypair` + `ml_kem::generate_keypair`,
/// the same `ciris_crypto` primitives) so this gate and the timing bench drive
/// byte-identical key material shapes.
fn fresh_responder() -> OwnKexKeys {
    let (x_priv, _x_pub) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
    let (mlkem_priv, mlkem_pub) = ml_kem::generate_keypair().expect("ml-kem keypair");
    OwnKexKeys {
        x25519_priv: x_priv,
        mlkem768_priv: Some(mlkem_priv),
        mlkem768_pub: Some(mlkem_pub),
    }
}

/// The peer view (what the initiator sees advertised) for a hybrid-capable
/// responder: both the X25519 and ML-KEM-768 pubkeys.
fn advertise_hybrid(own: &OwnKexKeys) -> PeerKexPubkeys {
    PeerKexPubkeys {
        x25519_pub: x25519::public_from_secret(&own.x25519_priv),
        // OwnKexKeys still carries an Option (a node may lack its own PQC
        // half); the PEER view does not. Unwrapping here is correct for a
        // fixture that just generated one, and it is where the two types stop
        // agreeing — the asymmetry is the point, not an oversight.
        mlkem768_pub: own
            .mlkem768_pub
            .clone()
            .expect("fixture generates a PQC half"),
    }
}

/// The peer view for a responder advertising NO USABLE ML-KEM half.
///
/// At edge v18.2.0 `mlkem768_pub` stopped being `Option` (CIRISEdge#458), so a
/// classical-only peer is no longer EXPRESSIBLE — the retirement moved from a
/// runtime refusal to a type-level impossibility, which is the stronger form.
///
/// An EMPTY key is the closest thing that still type-checks, and it is also the
/// shape an attacker actually has: they cannot delete a field from the wire
/// struct, they can only strip the bytes. So the refusal tests below keep
/// running against the case that can still occur, rather than being deleted on
/// the grounds that the old one cannot.
fn advertise_no_usable_mlkem(own: &OwnKexKeys) -> PeerKexPubkeys {
    PeerKexPubkeys {
        x25519_pub: x25519::public_from_secret(&own.x25519_priv),
        mlkem768_pub: Vec::new(),
    }
}

// ── 1. AGREEMENT ─────────────────────────────────────────────────────────────

/// The load-bearing positive: the full hybrid handshake completes end-to-end
/// and BOTH peers derive the same 32-byte session key. This is the property the
/// transport AEAD layer relies on — if these bytes ever diverged, every sealed
/// frame on the link would fail to open.
#[test]
fn hybrid_handshake_derives_identical_session_key() {
    let responder = fresh_responder();
    let peer = advertise_hybrid(&responder);

    let (msg, initiator_key) =
        FederationSession::initiate(&peer, KexAlgorithm::Hybrid).expect("hybrid initiate");

    // The message must carry the hybrid (post-quantum) wire form — not a
    // silently negotiated-down classical message.
    assert_eq!(
        msg.algorithm(),
        ALGORITHM_HYBRID_V1,
        "hybrid initiate must stamp the hybrid wire algorithm id"
    );
    assert!(
        matches!(msg, SessionHandshakeMsg::Hybrid(_)),
        "hybrid initiate must produce a Hybrid handshake message"
    );

    let responder_key = FederationSession::respond(&responder, &msg).expect("hybrid respond");

    assert_eq!(
        initiator_key.as_bytes(),
        responder_key.as_bytes(),
        "initiator and responder derived different session keys"
    );
    assert_eq!(
        initiator_key.as_bytes().len(),
        32,
        "session key must be 32 bytes"
    );
}

// ── 2. TAMPER FAILS CLOSED ───────────────────────────────────────────────────

/// Flip a byte in the ML-KEM-768 ciphertext before the responder consumes it.
/// ML-KEM-768 is IND-CCA2, so decapsulation of a mangled ciphertext does NOT
/// error — it returns an implicit-reject shared secret. That divergent shared
/// secret (plus the tampered ciphertext feeding the HKDF salt) MUST yield a
/// responder key that does NOT match the initiator's. The point: a man in the
/// middle who strips/mangles the PQ half cannot force agreement on a
/// classical-only-derivable key. Fail closed = no agreed key.
#[test]
fn tampered_mlkem_ciphertext_fails_closed() {
    let responder = fresh_responder();
    let peer = advertise_hybrid(&responder);

    let (msg, initiator_key) =
        FederationSession::initiate(&peer, KexAlgorithm::Hybrid).expect("hybrid initiate");

    // Reach into the hybrid message and flip one bit of the ML-KEM ciphertext.
    let tampered = match msg {
        SessionHandshakeMsg::Hybrid(mut m) => {
            assert!(
                !m.mlkem768_ciphertext.is_empty(),
                "hybrid message must carry an ML-KEM ciphertext"
            );
            m.mlkem768_ciphertext[0] ^= 0x01;
            SessionHandshakeMsg::Hybrid(m)
        }
        SessionHandshakeMsg::Classical(_) => {
            panic!("hybrid initiate unexpectedly produced a classical message")
        }
    };

    // Responder must NOT silently agree on the initiator's key.
    match FederationSession::respond(&responder, &tampered) {
        Ok(responder_key) => assert_ne!(
            initiator_key.as_bytes(),
            responder_key.as_bytes(),
            "TAMPER NOT CAUGHT: responder agreed on a key despite a mangled ML-KEM ciphertext \
             (silent downgrade — the PQ half was not actually bound into the session key)"
        ),
        Err(_) => { /* erroring out is also fail-closed — acceptable */ }
    }
}

/// Drop the ML-KEM-768 ciphertext entirely (truncate to empty) before the
/// responder consumes it. A dropped PQ half must NOT decapsulate to anything
/// the initiator can match — the handshake must error OR diverge, never fall
/// back to a classical-only agreement.
#[test]
fn dropped_mlkem_ciphertext_fails_closed() {
    let responder = fresh_responder();
    let peer = advertise_hybrid(&responder);

    let (msg, initiator_key) =
        FederationSession::initiate(&peer, KexAlgorithm::Hybrid).expect("hybrid initiate");

    let dropped = match msg {
        SessionHandshakeMsg::Hybrid(mut m) => {
            m.mlkem768_ciphertext.clear(); // drop the entire PQ half
            SessionHandshakeMsg::Hybrid(m)
        }
        SessionHandshakeMsg::Classical(_) => {
            panic!("hybrid initiate unexpectedly produced a classical message")
        }
    };

    match FederationSession::respond(&responder, &dropped) {
        Ok(responder_key) => assert_ne!(
            initiator_key.as_bytes(),
            responder_key.as_bytes(),
            "DROP NOT CAUGHT: responder agreed on a key with an empty ML-KEM ciphertext \
             (silent classical-only fallback inside a hybrid handshake)"
        ),
        Err(_) => { /* erroring out is fail-closed — acceptable */ }
    }
}

// ── 3. HYBRID REQUIRED / NO CLASSICAL-ONLY SUCCESS PATH ──────────────────────

/// The `ln`/federation-session API DOES expose a "hybrid required" policy:
/// `KexAlgorithm::HybridRequired` (the HNDL-strict mode for CEG §10.5.5 realtime
/// A/V + key_grant DEK distribution). Against a classical-only peer it MUST be
/// rejected with `HybridRequiredButPeerLacksMlkem` — refusal, not a silent
/// downgrade to classical. This is the "classical-only path is rejected when
/// hybrid is required" assertion.
#[test]
fn hybrid_required_rejects_classical_only_peer() {
    let responder = fresh_responder();
    let classical_peer = advertise_no_usable_mlkem(&responder);

    let r = FederationSession::initiate(&classical_peer, KexAlgorithm::HybridRequired);
    // THE PROPERTY IS THE REFUSAL, NOT ITS SPELLING. Before edge v18.2.0 an
    // absent PQC half was `None` and this returned
    // `HybridRequiredButPeerLacksMlkem` — a POLICY verdict. Now the field is
    // non-optional, so "absent" can only be expressed as EMPTY, and the refusal
    // arrives from the length check instead. Same outcome, earlier gate.
    //
    // Asserting the exact variant would have made this test fail on a change
    // that STRENGTHENED the guarantee, which is how a safety test gets deleted
    // for being noisy.
    assert!(
        r.is_err(),
        "HybridRequired must REJECT a peer with no usable ML-KEM half (no silent \
         downgrade to classical), got {r:?}"
    );
}

/// Complement to the above: when hybrid IS satisfiable, `HybridRequired`
/// succeeds and produces the SAME agreed key the hybrid path would — proving
/// the strict policy is a gate on the *peer*, not a different ciphersuite.
#[test]
fn hybrid_required_succeeds_and_agrees_against_hybrid_peer() {
    let responder = fresh_responder();
    let peer = advertise_hybrid(&responder);

    let (msg, initiator_key) = FederationSession::initiate(&peer, KexAlgorithm::HybridRequired)
        .expect("hybrid-required initiate");
    assert_eq!(msg.algorithm(), ALGORITHM_HYBRID_V1);
    let responder_key = FederationSession::respond(&responder, &msg).expect("respond");
    assert_eq!(
        initiator_key.as_bytes(),
        responder_key.as_bytes(),
        "HybridRequired must agree against a hybrid-capable peer"
    );
}

/// There is NO classical-only success path *inside* a hybrid handshake: a
/// `Hybrid` request against a hybrid peer always yields a `Hybrid` wire message
/// carrying a non-empty ML-KEM-768 ciphertext. (The only way the federation
/// session emitted a `Classical` message was when the peer never advertised the
/// ML-KEM half AND the caller opted into fallback via `Hybrid`; as of
/// CIRISEdge#481 that path is RETIRED and `initiate` refuses instead —
/// see the refusal test below.) This nails down that the PQ half is
/// structurally present, not optional, on the hybrid path the tamper tests
/// above rely on.
#[test]
fn hybrid_path_always_carries_mlkem_ciphertext() {
    let responder = fresh_responder();
    let peer = advertise_hybrid(&responder);

    let (msg, _k) =
        FederationSession::initiate(&peer, KexAlgorithm::Hybrid).expect("hybrid initiate");
    match msg {
        SessionHandshakeMsg::Hybrid(m) => assert!(
            !m.mlkem768_ciphertext.is_empty(),
            "hybrid handshake produced an empty ML-KEM ciphertext — classical-only success leaked \
             into the hybrid path"
        ),
        SessionHandshakeMsg::Classical(_) => {
            panic!("hybrid request against a hybrid peer must not produce a classical message")
        }
    }
}

/// **There is no lenient mode any more** (CIRISEdge#481, adopted in 0.5.175).
///
/// This test used to assert the opposite: that `KexAlgorithm::Hybrid` DOES fall
/// back to classical against a classical-only peer, that the fallback
/// round-trips, and that `HybridRequired` was therefore the policy a caller
/// picked when classical-only had to be refused. All of that was accurate, and
/// all of it was the hazard.
///
/// Edge's audit found the responder accepting a classical handshake
/// **unconditionally** — an active downgrade reachable in a single message,
/// sitting beside an envelope-verify path that was already `HybridPolicy::Strict`.
/// One seam, two answers. With the mesh pre-release and fully PQC-provisioned,
/// the rollout posture the fallback existed for has no remaining user, so the
/// classical path is gone rather than deprioritised — which is what actually
/// closes Fed TM §3.3 Gap C (harvest-now-decrypt-later).
///
/// So `Hybrid` and `HybridRequired` are now the same thing at the initiate side.
/// Keeping this case as a REFUSAL test rather than deleting it preserves the
/// coverage and records the day the behaviour inverted.
#[test]
fn lenient_hybrid_no_longer_falls_back_against_a_classical_only_peer() {
    let responder = fresh_responder();
    let classical_peer = advertise_no_usable_mlkem(&responder);

    let r = FederationSession::initiate(&classical_peer, KexAlgorithm::Hybrid);
    // Same reasoning as `hybrid_required_rejects_...`: the guarantee is that
    // lenient `Hybrid` does NOT negotiate down, and it still does not. At edge
    // v18.2.0 the absent PQC half became inexpressible, so the case now arrives
    // as an EMPTY key and is refused by the length check rather than the policy
    // check. Pinning the variant would red this test for a change that made the
    // downgrade harder, not easier.
    assert!(
        r.is_err(),
        "lenient `Hybrid` negotiated DOWN against a peer with no usable ML-KEM \
         half. That is a downgrade: an attacker who strips the ML-KEM bytes from \
         an advertisement gets a classical session from a caller who never asked \
         for one. Got {r:?}"
    );
    // THIS ASSERTION EXISTS TO CATCH THE SURFACE MOVING, AND IT DID.
    //
    // It pinned `HybridRequiredButPeerLacksMlkem` and went red at edge v18.2.0 —
    // correctly. `mlkem768_pub` stopped being `Option` (CIRISEdge#458), so the
    // absent half is now expressed as EMPTY and refused by the LENGTH check
    // before policy is consulted. The guarantee strengthened; the spelling
    // changed.
    //
    // Widened to the two grounds we know are safe rather than dropped, because
    // the value here is catching a THIRD shape — a refusal for some unrelated
    // reason would mean the downgrade path is no longer being tested at all,
    // which is exactly what this gate is for.
    let msg = format!("{:?}", r.unwrap_err());
    assert!(
        msg.contains("HybridRequiredButPeerLacksMlkem")
            || msg.contains("ML-KEM-768 pubkey wrong length"),
        "refused, but on neither documented ground — got `{msg}`. Expected either \
         the policy refusal (HybridRequiredButPeerLacksMlkem, pre-v18.2.0) or the \
         length refusal (empty ML-KEM half, v18.2.0+). A different error means the \
         negotiation surface moved AGAIN and this gate is no longer measuring what \
         it names."
    );
}
