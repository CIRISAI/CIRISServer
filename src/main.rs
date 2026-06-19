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
        // Default: boot the fabric node.
        _ => ciris_server::run().await,
    }
}

/// Parse the `identity create` flags and mint the USER federation identity.
async fn run_identity_create(mut args: impl Iterator<Item = String>) -> Result<()> {
    use ciris_server::identity::{Pkcs11Options, UserIdentityBackend};

    let mut backend_name = "software".to_string();
    let mut label: Option<String> = None;
    let mut piv_slot = ciris_server::identity::DEFAULT_PIV_SLOT.to_string();
    let mut seed_dir: Option<String> = None;
    let mut pkcs11_module: Option<String> = None;
    let mut provision = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
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

    // `--seed-dir` overrides the per-user seed location for this run.
    if let Some(dir) = &seed_dir {
        std::env::set_var("CIRIS_USER_SEED_DIR", dir);
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

    let minted = ciris_server::provision_user_identity(backend, label).await?;

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
