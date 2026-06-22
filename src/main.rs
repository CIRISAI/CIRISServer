//! CIRISServer binary — the headless fabric node entry point.
//!
//! Thin shell: all composition lives in the `ciris_server` library
//! (src/lib.rs), which is ALSO built as a PyO3 abi3 wheel that CIRISAgent
//! consumes. `agent = fabric node + brain` — one cohabitation composition, two
//! shapes (MISSION.md §1.2/§6). See lib.rs and MISSION.md.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    ciris_server::init_tracing();
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        // `ciris-server import-traces <dump-dir>` — one-shot legacy-trace import
        // (CIRISLens TimescaleDB dump → persist corpus as CEG objects).
        Some("import-traces") => {
            let dump_dir = args
                .next()
                .ok_or_else(|| anyhow::anyhow!("usage: ciris-server import-traces <dump-dir>"))?;
            ciris_server::import_traces(&dump_dir).await
        }
        // `ciris-server scoreboard [--criterion-dir <dir>]` — print the holonomic
        // federation scoreboard (CIRISServer#12/#13) as JSON and exit. With
        // `--criterion-dir` the substrate tier is promoted to MEASURED from real
        // criterion bench output; without it the board stays all-modeled/gated.
        Some("scoreboard") => {
            let mut criterion_dir: Option<String> = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--criterion-dir" => {
                        criterion_dir = Some(args.next().ok_or_else(|| {
                            anyhow::anyhow!("usage: scoreboard --criterion-dir <dir>")
                        })?);
                    }
                    other if other.starts_with("--criterion-dir=") => {
                        criterion_dir = Some(other["--criterion-dir=".len()..].to_string());
                    }
                    other => return Err(anyhow::anyhow!("unknown scoreboard arg: {other}")),
                }
            }
            match criterion_dir {
                Some(dir) => println!("{}", ciris_server::scoreboard_json_with_criterion(&dir)),
                None => println!("{}", ciris_server::scoreboard_json()),
            }
            Ok(())
        }
        // `ciris-server identity create [--backend pkcs11|platform-sealed|software]
        //  [--label ...] [--piv-slot 9c] [--seed-dir ...]` — MINT a hardware-rooted
        // USER federation identity (CIRISServer#21). THIS is what the founder runs
        // to mint their YubiKey-backed federation ID. Prints the fedcode + key_id.
        Some("identity") => match args.next().as_deref() {
            Some("create") => run_identity_create(args).await,
            other => Err(anyhow::anyhow!(
                "usage: ciris-server identity create [--backend pkcs11|platform-sealed|software] \
                 [--label <name>] [--piv-slot 9c] [--seed-dir <dir>] (got {:?})",
                other
            )),
        },
        // `ciris-server accord reactivate --home <path> [--key-id <name>] --proof <file>`
        // — the constitutional way back from a HUMANITY_ACCORD halt (CC 4.2.1 §69): a
        // verified 2/3 `accord:lifecycle:active` proof clears the disk latch so the
        // node may boot. NOT an operator restart — the quorum brings it back.
        Some("accord") => match args.next().as_deref() {
            Some("reactivate") => run_accord_reactivate(args).await,
            other => Err(anyhow::anyhow!(
                "usage: ciris-server accord reactivate --home <path> [--key-id <name>] \
                 --proof <file.json> (got {:?})",
                other
            )),
        },
        // `ciris-server identity create ...` consumed the first arg already; the
        // default arm boots the fabric node. The default-serve path takes the ONLY
        // two bootstrap inputs (Server 0.5 zero-env): `--home <path>` (the data
        // root; default DEFAULT_CIRIS_HOME) and `--key-id <name>` (the federation
        // key label; default DEFAULT_KEY_ID — the status-node deploy passes
        // `--key-id ciris-status`). Everything else is baked constants or config:*
        // CEG resolved at boot.
        first => {
            // `first` is the already-consumed first token (Some for the default
            // serve path with a leading flag, None for a bare `ciris-server`).
            let leading = first.map(|s| s.to_string());
            let (home, key_id) = ciris_server::parse_serve_flags(leading, args)?;
            ciris_server::run(home, key_id).await
        }
    }
}

/// Parse `accord reactivate` flags + clear the halt latch on a verified 2/3 proof.
async fn run_accord_reactivate(mut args: impl Iterator<Item = String>) -> Result<()> {
    use ciris_server::config::{ServerConfig, DEFAULT_CIRIS_HOME, DEFAULT_KEY_ID};

    let mut home: Option<String> = None;
    let mut key_id = DEFAULT_KEY_ID.to_string();
    let mut proof_path: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--home" => home = Some(args.next().context("--home needs a path")?),
            "--key-id" => key_id = args.next().context("--key-id needs a name")?,
            "--proof" => proof_path = Some(args.next().context("--proof needs a file")?),
            other => return Err(anyhow::anyhow!("unknown accord-reactivate arg: {other}")),
        }
    }
    let home = home.unwrap_or_else(|| DEFAULT_CIRIS_HOME.to_string());
    let proof_path = proof_path
        .ok_or_else(|| anyhow::anyhow!("accord reactivate requires --proof <file.json>"))?;

    let cfg = ServerConfig::from_home(std::path::PathBuf::from(home), key_id)?;
    let proof_bytes = std::fs::read(&proof_path)
        .with_context(|| format!("read reactivation proof {proof_path}"))?;
    let proof: ciris_server::accord_reactivate::ReactivationProof =
        serde_json::from_slice(&proof_bytes).context("parse reactivation proof JSON")?;

    ciris_server::accord_reactivate::reactivate_accord(&cfg, proof).await
}

use anyhow::Context as _;

/// Parse the `identity create` flags and mint the USER federation identity.
async fn run_identity_create(mut args: impl Iterator<Item = String>) -> Result<()> {
    use ciris_server::identity::{Pkcs11Options, UserIdentityBackend};

    let mut backend_name = "software".to_string();
    let mut label: Option<String> = None;
    let mut piv_slot = ciris_server::identity::DEFAULT_PIV_SLOT.to_string();
    let mut seed_dir: Option<String> = None;
    let mut pkcs11_module: Option<String> = None;
    let mut provision = false;
    let mut home: Option<String> = None;
    let mut key_id: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--home" => {
                home = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--home needs a value"))?,
                );
            }
            "--key-id" => {
                key_id = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--key-id needs a value"))?,
                );
            }
            "--backend" => {
                backend_name = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--backend needs a value"))?;
            }
            "--label" => {
                label = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--label needs a value"))?,
                );
            }
            "--piv-slot" => {
                piv_slot = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--piv-slot needs a value"))?;
            }
            "--seed-dir" => {
                seed_dir = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--seed-dir needs a value"))?,
                );
            }
            "--pkcs11-module" => {
                pkcs11_module = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--pkcs11-module needs a value"))?,
                );
            }
            "--provision" => provision = true,
            other => return Err(anyhow::anyhow!("unknown identity-create arg: {other}")),
        }
    }

    let backend = match backend_name.as_str() {
        "software" => UserIdentityBackend::Software,
        "platform-sealed" | "platform_sealed" => UserIdentityBackend::PlatformSealed,
        "pkcs11" | "yubikey" => {
            let mut opts = Pkcs11Options {
                piv_slot: piv_slot.clone(),
                provision,
                ..Pkcs11Options::default()
            };
            if let Some(m) = pkcs11_module {
                opts.module_path = m.into();
            }
            UserIdentityBackend::Pkcs11(opts)
        }
        other => {
            return Err(anyhow::anyhow!(
                "unknown --backend {other:?} — use pkcs11 | platform-sealed | software"
            ))
        }
    };

    // Build the node config from the conventions + flags (Server 0.5 zero-env).
    let cfg = ciris_server::ServerConfig::from_home(
        std::path::PathBuf::from(
            home.unwrap_or_else(|| ciris_server::config::DEFAULT_CIRIS_HOME.to_string()),
        ),
        key_id.unwrap_or_else(|| ciris_server::config::DEFAULT_KEY_ID.to_string()),
    )?;
    let seed_dir_override = seed_dir.map(std::path::PathBuf::from);
    let minted =
        ciris_server::provision_user_identity(&cfg, backend, label, seed_dir_override).await?;

    println!("✅ Your YubiKey-backed federation USER identity is minted.");
    println!();
    println!("  identity_type : {}", minted.identity_type);
    println!("  key_id        : {}", minted.key_id);
    println!("  fedcode       : {}", minted.fedcode);
    println!("                  (this is your usercode — share it / drop it into a node");
    println!("                   config to claim ownership)");
    println!("  hardware      : {}", minted.hardware_type);
    println!("  ed25519 pub   : {}", minted.pubkey_ed25519_base64);
    println!("  ml-dsa-65 pub : {}", minted.pubkey_ml_dsa_65_base64);
    println!();
    println!("  The ML-DSA-65 PQC half is sealed at rest under your CIRIS keys dir.");
    println!("  This local node now holds your USER identity — POST /v1/setup/claim-remote");
    println!("  will sign owner-bindings with this key.");
    Ok(())
}
