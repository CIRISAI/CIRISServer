//! Throwaway probe: what digest does THIS pin compute for a given seed, and do
//! the holder authorizations verify against it? Run explicitly.
//!
//! CIRIS_GENESIS_BUNDLE=<seed> cargo test --test seed_digest_probe -- --ignored --nocapture

use ciris_server::mesh_genesis::{authorization_digest, verify_bundle, GenesisBundle};

#[test]
#[ignore = "probe: needs CIRIS_GENESIS_BUNDLE"]
fn what_does_this_pin_compute() {
    let path = std::env::var("CIRIS_GENESIS_BUNDLE").expect("set CIRIS_GENESIS_BUNDLE");
    let b: GenesisBundle =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("parse");

    let d = authorization_digest(&b).expect("digest");
    println!("\nseed            {path}");
    println!("persist pin     {}", env!("CARGO_PKG_VERSION"));
    println!("digest len      {}", d.len());
    println!(
        "digest          {}",
        d.iter().map(|x| format!("{x:02x}")).collect::<String>()
    );

    for a in &b.authorizations {
        let h = b
            .holders
            .iter()
            .find(|h| h.record.key_id == a.holder_key_id)
            .expect("holder carried");
        let r = ciris_persist::verify::verify_hybrid(
            &d,
            &a.signature_classical,
            Some(&a.signature_pqc),
            &h.record.pubkey_ed25519_base64,
            h.record.pubkey_ml_dsa_65_base64.as_deref(),
            ciris_persist::verify::HybridPolicy::Strict,
            None,
        );
        println!(
            "auth {:<4}       {}",
            a.holder_key_id,
            match &r {
                Ok(o) => format!("VERIFIES ({o:?})"),
                Err(e) => format!("FAILS: {e}"),
            }
        );
    }
    println!(
        "verify_bundle   {}\n",
        match verify_bundle(&b) {
            Ok(()) => "VALID".to_string(),
            Err(e) => format!("INVALID: {e}"),
        }
    );
}
