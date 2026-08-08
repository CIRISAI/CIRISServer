//! **One federation identity per node, hybrid on both halves** — checked at boot,
//! refused if not (CIRISServer#380).
//!
//! # Why this is a boot error and not a warning
//!
//! Everything downstream assumes the persist Engine's signer and this process's
//! federation signer ARE the same key. On the standalone binary that is true by
//! construction — `build_engine` is handed the same `signer`. In the **embedded
//! fold** the Engine arrives from the host process, and until this gate nothing
//! ever checked it.
//!
//! When they differ the node boots, looks healthy, and cannot federate:
//! `cfg.key_id` names the ENGINE's identity (CIRISServer#315) while
//! `publish_self_identity_occurrence` signs with the COMPOSE seed. The occurrence
//! fails its own scrub-signature, never publishes, so no peer can seal to this
//! node, KEX never becomes authoritative, and every announce is admitted as
//! advisory routing-hint only. Traces are produced perfectly and delivered
//! nowhere.
//!
//! The upstream signature of this is the part worth internalising: **zero arrivals
//! and zero rejections.** Nothing is refused because nothing is ever attributable.
//! There is no error to grep for on either side — which is why it cost 71 hours as
//! CIRISAgent#1009 and a second full investigation as CIRISServer#380, both ending
//! at the same sentence: *a second identity was minted locally alongside the one
//! the fabric verifies against.*
//!
//! A node with two identities is misconfigured. There is no reading under which
//! continuing is better than a boot error that names both seeds.
//!
//! # Why public keys, not key_ids
//!
//! The derived `key_id` is `derive_key_id(alias, ed25519_pubkey)` — it folds in the
//! keystore alias. Two *names* for one key would read as a fork and this gate would
//! block a correct node. Two *keys* is the defect; two labels is not. So the
//! comparison is on raw public-key bytes.

use std::path::Path;

/// The four public keys a node must reconcile at boot, plus where the canonical
/// pair lives so a failure can name the fix instead of the symptom.
pub(crate) struct IdentityFacts<'a> {
    /// Ed25519 public key the persist Engine signs with.
    pub engine_ed: &'a [u8],
    /// Ed25519 public key this process's federation signer signs with.
    pub compose_ed: &'a [u8],
    /// ML-DSA-65 public key the Engine actually produced a signature under.
    /// `None` when `sign_hybrid` yielded no post-quantum half at all.
    pub engine_pqc: Option<&'a [u8]>,
    /// ML-DSA-65 public key this process's federation PQC signer holds.
    pub compose_pqc: &'a [u8],
    /// The derived key_id every wire surface will carry.
    pub key_id: &'a str,
    /// `<identity_dir>/ed25519.seed` — the one classical seed.
    pub seed_path: &'a Path,
    /// `<identity_dir>/ml_dsa_65.seed` — the one post-quantum seed.
    pub pqc_seed_path: &'a Path,
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The copy-pasteable remedy. Consumers hit this at 2am; a paragraph of prose
/// about identity models is worth less to them than the four lines to change.
fn remedy(f: &IdentityFacts<'_>) -> String {
    format!(
        "  THE FIX — point the Engine at the node's ONE identity:\n\
         \n\
             Engine(\n\
                 dsn,\n\
                 signing_key_id,\n\
                 local_key_id      = signing_key_id,\n\
                 local_key_path    = \"{}\",\n\
                 local_pqc_key_id  = signing_key_id,\n\
                 local_pqc_key_path= \"{}\",\n\
             )\n\
         \n\
           and DELETE any locally-minted pair (`local_signing.seed` /\n\
           `local_pqc_signing.seed` under the data dir). This removes key paths;\n\
           it does not add one.\n\
         \n\
           There is no ordering problem to solve. The derived key_id is\n\
           `derive_key_id(alias, ed25519_pubkey)` — a pure function of the seed.\n\
           You pass the SEED; the id falls out. That is why the same seed in two\n\
           processes yields the same id, and why two seeds yielded two ids.",
        f.seed_path.display(),
        f.pqc_seed_path.display(),
    )
}

/// `Ok(())` iff this node holds exactly one federation identity and can sign
/// hybrid with it. Every error names both keys and the remedy.
pub(crate) fn check(f: &IdentityFacts<'_>) -> anyhow::Result<()> {
    if f.engine_ed != f.compose_ed {
        anyhow::bail!(
            "TWO FEDERATION IDENTITIES IN ONE NODE — refusing to start (CIRISServer#380).\n\
             \n\
             The persist Engine and this process sign as DIFFERENT keys:\n\
             \n\
               engine  ed25519 pubkey  {}\n\
               compose ed25519 pubkey  {}\n\
             \n\
             This node would derive key_id={} from the ENGINE, then sign its self\n\
             identity-occurrence with the COMPOSE seed. The occurrence fails its own\n\
             scrub-signature and never publishes, so no peer can seal to this node and\n\
             KEX never becomes authoritative. Traces would be produced and delivered\n\
             nowhere, and upstream would record ZERO arrivals and ZERO 401s — nothing\n\
             refused, because nothing was ever attributable.\n\
             \n\
             {}",
            b64(f.engine_ed),
            b64(f.compose_ed),
            f.key_id,
            remedy(f),
        );
    }

    // ALWAYS HYBRID, END TO END. Hybrid-mandatory admission refuses the rest, and
    // that refusal lands on somebody else's node — far from the cause.
    let Some(engine_pqc) = f.engine_pqc else {
        anyhow::bail!(
            "ENGINE SIGNS CLASSICAL-ONLY — refusing to start (CIRISServer#380).\n\
             \n\
             `sign_hybrid` produced no ML-DSA-65 half, so this node cannot author a\n\
             federation-tier row any peer will admit. Signing is hybrid end to end or it\n\
             is not federation signing.\n\
             \n\
             {}",
            remedy(f),
        );
    };

    // The classical halves matching is NOT enough: the identity is the PAIR, and
    // #380 forked on the post-quantum side specifically. A gate that stopped at
    // Ed25519 would have waved that node through to the same silent stall.
    if engine_pqc != f.compose_pqc {
        anyhow::bail!(
            "TWO POST-QUANTUM IDENTITIES IN ONE NODE — refusing to start \
             (CIRISServer#380).\n\
             \n\
             The classical halves agree, so this is the PQC half alone — the exact shape\n\
             CIRISServer#380 hit: persist loaded its own ML-DSA-65 seed while compose\n\
             adopted the federation one.\n\
             \n\
               engine  ml-dsa-65 pubkey  {}\n\
               compose ml-dsa-65 pubkey  {}\n\
             \n\
             The self identity-occurrence would be signed under one and verified under\n\
             the other: SignatureInvalid, nothing published, no peer able to seal here.\n\
             \n\
             {}",
            b64(engine_pqc),
            b64(f.compose_pqc),
            remedy(f),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn facts<'a>(
        engine_ed: &'a [u8],
        compose_ed: &'a [u8],
        engine_pqc: Option<&'a [u8]>,
        compose_pqc: &'a [u8],
        seed: &'a Path,
        pqc_seed: &'a Path,
    ) -> IdentityFacts<'a> {
        IdentityFacts {
            engine_ed,
            compose_ed,
            engine_pqc,
            compose_pqc,
            key_id: "ciris-agent-bootstrap-ecyk3eihcj",
            seed_path: seed,
            pqc_seed_path: pqc_seed,
        }
    }

    fn paths() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("/var/lib/ciris/identity/ed25519.seed"),
            PathBuf::from("/var/lib/ciris/identity/ml_dsa_65.seed"),
        )
    }

    /// The standalone binary: Engine built FROM the compose signer, so both halves
    /// are the same key. This must pass, or the gate bricks every healthy node.
    #[test]
    fn one_identity_hybrid_passes() {
        let (s, p) = paths();
        let f = facts(b"ED-A", b"ED-A", Some(b"PQ-A"), b"PQ-A", &s, &p);
        assert!(check(&f).is_ok(), "a correctly composed node must boot");
    }

    /// The classical fork.
    #[test]
    fn forked_ed25519_is_refused() {
        let (s, p) = paths();
        let f = facts(b"ED-A", b"ED-B", Some(b"PQ-A"), b"PQ-A", &s, &p);
        let e = check(&f).unwrap_err().to_string();
        assert!(e.contains("TWO FEDERATION IDENTITIES"), "{e}");
        assert!(
            e.contains("ZERO arrivals and ZERO 401s"),
            "names the symptom: {e}"
        );
    }

    /// THE #380 CASE. Classical halves agree; only the PQC seed forked. A gate
    /// that stopped at Ed25519 would pass this — and this is the one that shipped.
    #[test]
    fn forked_pqc_alone_is_refused() {
        let (s, p) = paths();
        let f = facts(b"ED-A", b"ED-A", Some(b"PQ-A"), b"PQ-B", &s, &p);
        let e = check(&f).unwrap_err().to_string();
        assert!(e.contains("TWO POST-QUANTUM IDENTITIES"), "{e}");
    }

    /// Always hybrid, end to end.
    #[test]
    fn classical_only_is_refused() {
        let (s, p) = paths();
        let f = facts(b"ED-A", b"ED-A", None, b"PQ-A", &s, &p);
        let e = check(&f).unwrap_err().to_string();
        assert!(e.contains("CLASSICAL-ONLY"), "{e}");
    }

    /// Every refusal must carry the copy-pasteable fix AND both canonical seed
    /// paths. An error that only diagnoses leaves the reader where it found them —
    /// and this one has already been reached twice by people who had correctly
    /// diagnosed it and still could not act.
    #[test]
    fn every_refusal_names_the_fix_and_both_seeds() {
        let (s, p) = paths();
        let cases: Vec<IdentityFacts<'_>> = vec![
            facts(b"ED-A", b"ED-B", Some(b"PQ-A"), b"PQ-A", &s, &p),
            facts(b"ED-A", b"ED-A", Some(b"PQ-A"), b"PQ-B", &s, &p),
            facts(b"ED-A", b"ED-A", None, b"PQ-A", &s, &p),
        ];
        assert_eq!(cases.len(), 3, "all three refusal paths are covered");
        for (i, f) in cases.iter().enumerate() {
            let e = check(f).unwrap_err().to_string();
            assert!(e.contains("THE FIX"), "case {i} must state the remedy: {e}");
            assert!(
                e.contains("ed25519.seed"),
                "case {i} must name the classical seed"
            );
            assert!(
                e.contains("ml_dsa_65.seed"),
                "case {i} must name the PQC seed"
            );
            assert!(
                e.contains("local_pqc_key_path"),
                "case {i} must show the actual constructor kwarg to change"
            );
            assert!(
                e.contains("CIRISServer#380"),
                "case {i} must be traceable to the investigation"
            );
        }
    }
}
