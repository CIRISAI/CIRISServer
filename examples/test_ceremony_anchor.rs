//! Print the three-holder test anchor the final-genesis dry run signs under,
//! as JSON: `{"env": {VAR: value}, "holders": [{"key_id", "seed_b64"}],
//! "recovery_keys": {holder_key_id: CommittedKey}}`.
//! The native harness (`python -m harness.native final_genesis`) arms every
//! node with `env` and signs through `POST /v1/accord/final-genesis/sign`
//! with each holder's seed. Same seeds as `tests/final_genesis_dry_run.rs`.
//!
//! `cargo run --features test-anchor --example test_ceremony_anchor`
use base64::Engine as _;

fn main() {
    let seeds: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];
    let block = ciris_persist::federation::genesis::mint_test_anchor_block(&seeds)
        .expect("mint the three-holder test anchor block");
    let env: serde_json::Map<String, serde_json::Value> = block
        .env_pairs()
        .into_iter()
        .map(|(k, v)| (k.to_owned(), serde_json::Value::String(v)))
        .collect();
    let holders: Vec<serde_json::Value> = block
        .holders
        .iter()
        .zip(&seeds)
        .map(|(h, s)| {
            serde_json::json!({
                "key_id": h.key_id,
                "seed_b64": base64::engine::general_purpose::STANDARD.encode(s),
            })
        })
        .collect();
    // Each holder's software recovery key (CC 4.2.6), as persist's minter
    // commits it — the plan needs them, since the test roster is not the
    // production one the recorded spares belong to.
    let recovery_keys: serde_json::Map<String, serde_json::Value> = block
        .holders
        .iter()
        .zip(&seeds)
        .map(|(h, s)| {
            let k = ciris_persist::federation::genesis::test_ceremony_recovery_key(&h.key_id, s)
                .expect("derive the holder's recovery key");
            (
                h.key_id.clone(),
                serde_json::to_value(k).expect("CommittedKey JSON"),
            )
        })
        .collect();
    println!(
        "{}",
        serde_json::json!({ "env": env, "holders": holders, "recovery_keys": recovery_keys })
    );
}
