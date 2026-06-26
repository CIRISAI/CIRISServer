//! CIRISServer binary — the headless fabric node entry point.
//!
//! Thin shell: all composition lives in the `ciris_server` library
//! (src/lib.rs), which is ALSO built as a PyO3 abi3 wheel that CIRISAgent
//! consumes. `agent = fabric node + brain` — one cohabitation composition, two
//! shapes (MISSION.md §1.2/§6). See lib.rs and MISSION.md.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // File logging to <home>/logs (resolved from --home, else the default data
    // root) so a node logs reliably to disk; stdout stays on for CLI subcommands.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    ciris_server::init_tracing_with(Some(&ciris_server::log_dir_from_args(&argv)));
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
        // `ciris-server bench-results [--criterion-dir <dir>] [--erasure-sidecar <file>]
        //  [--commit <sha>] [--date <YYYY-MM-DD>] [--out <file>]` — emit the unified
        // `bench_results.json` (schema v2). EVERY entry is measured-or-gated: substrate
        // metrics from real criterion medians, the empirical erasure curve from the
        // erasure_survival bench sidecar (gated if absent), and LIVE in-process mesh
        // measurements (cohort propagation + isolation + A↔B replication) over the real
        // FountainSwarmRuntime. This is the source of truth for the public bench page.
        Some("bench-results") => {
            let mut criterion_dir = String::from("target/criterion");
            let mut erasure_sidecar = String::from("target/erasure_survival.json");
            let mut commit = std::env::var("GITHUB_SHA").unwrap_or_else(|_| "unknown".into());
            let mut date = current_utc_date();
            let mut out: Option<String> = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--criterion-dir" => {
                        criterion_dir = args.next().ok_or_else(|| {
                            anyhow::anyhow!("usage: bench-results --criterion-dir <dir>")
                        })?;
                    }
                    "--erasure-sidecar" => {
                        erasure_sidecar = args.next().ok_or_else(|| {
                            anyhow::anyhow!("usage: bench-results --erasure-sidecar <file>")
                        })?;
                    }
                    "--commit" => {
                        commit = args.next().ok_or_else(|| {
                            anyhow::anyhow!("usage: bench-results --commit <sha>")
                        })?;
                    }
                    "--date" => {
                        date = args.next().ok_or_else(|| {
                            anyhow::anyhow!("usage: bench-results --date <YYYY-MM-DD>")
                        })?;
                    }
                    "--out" => {
                        out =
                            Some(args.next().ok_or_else(|| {
                                anyhow::anyhow!("usage: bench-results --out <file>")
                            })?);
                    }
                    other => {
                        return Err(anyhow::anyhow!("unknown bench-results arg: {other}"));
                    }
                }
            }
            let json =
                ciris_server::bench_results_json(&commit, &date, &criterion_dir, &erasure_sidecar);
            match out {
                Some(path) => {
                    std::fs::write(&path, &json)?;
                    eprintln!("wrote {path}");
                }
                None => println!("{json}"),
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
        // `ciris-server claim --home <path> --key-id <alias> --backend platform-sealed \
        //  --node-code <CIRIS-V1-...> --claim-pin <PIN> --target-url <node read-API URL> \
        //  [--cohort-scope self] [--owner-password ...] [--owner-username ...]`
        // — claim ROOT ownership of a REMOTE node FOR your fed-ID. Opens your local
        // user fed-ID (TPM-sealed / YubiKey / software), builds + hybrid-signs the
        // owner-binding, and POSTs the 1-phase claim to the target's /v1/setup/root
        // (v0.5.37: that route is PIN + signed-binding gated, no loopback — so this
        // works against a remote node's public read-API). The "local client" that
        // claims a node with just its NodeCode + PIN.
        Some("claim") => run_claim(args).await,
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

/// `ciris-server claim ...` — claim ROOT ownership of a REMOTE node FOR your local
/// user fed-ID. Opens your fed-ID signer (the SAME alias/path the node resolves:
/// `<keystore_alias>-user` at the conventional user-seed dir), builds + hybrid-signs
/// the `delegates_to(you → node, infra:*)` owner-binding, and POSTs the 1-phase
/// claim to the target's `/v1/setup/root` (gated by PIN + the signed binding;
/// network-reachable since v0.5.37). The "local client that claims a node with just
/// its NodeCode + PIN."
async fn run_claim(mut args: impl Iterator<Item = String>) -> Result<()> {
    use ciris_server::identity::{Pkcs11Options, UserIdentityBackend};

    let mut backend_name = "platform-sealed".to_string();
    let mut home: Option<String> = None;
    let mut key_id: Option<String> = None;
    let mut piv_slot = ciris_server::identity::DEFAULT_PIV_SLOT.to_string();
    let mut pkcs11_module: Option<String> = None;
    let mut node_code: Option<String> = None;
    let mut claim_pin: Option<String> = None;
    let mut cohort_scope = "self".to_string();
    let mut target_url: Option<String> = None;
    let mut owner_password: Option<String> = None;
    let mut owner_username: Option<String> = None;

    while let Some(arg) = args.next() {
        let need = |a: &mut dyn Iterator<Item = String>, f: &str| -> Result<String> {
            a.next().ok_or_else(|| anyhow::anyhow!("{f} needs a value"))
        };
        match arg.as_str() {
            "--home" => home = Some(need(&mut args, "--home")?),
            "--key-id" => key_id = Some(need(&mut args, "--key-id")?),
            "--backend" => backend_name = need(&mut args, "--backend")?,
            "--piv-slot" => piv_slot = need(&mut args, "--piv-slot")?,
            "--pkcs11-module" => pkcs11_module = Some(need(&mut args, "--pkcs11-module")?),
            "--node-code" => node_code = Some(need(&mut args, "--node-code")?),
            "--claim-pin" => claim_pin = Some(need(&mut args, "--claim-pin")?),
            "--cohort-scope" => cohort_scope = need(&mut args, "--cohort-scope")?,
            "--target-url" => target_url = Some(need(&mut args, "--target-url")?),
            "--owner-password" => owner_password = Some(need(&mut args, "--owner-password")?),
            "--owner-username" => owner_username = Some(need(&mut args, "--owner-username")?),
            other => return Err(anyhow::anyhow!("unknown claim arg: {other}")),
        }
    }

    let backend = match backend_name.as_str() {
        "software" => UserIdentityBackend::Software,
        "platform-sealed" | "platform_sealed" | "tpm" => UserIdentityBackend::PlatformSealed,
        "pkcs11" | "yubikey" => {
            let mut opts = Pkcs11Options {
                piv_slot: piv_slot.clone(),
                ..Pkcs11Options::default()
            };
            if let Some(m) = pkcs11_module {
                opts.module_path = m.into();
            }
            UserIdentityBackend::Pkcs11(opts)
        }
        other => {
            return Err(anyhow::anyhow!(
                "unknown --backend {other:?} — use tpm | yubikey | software"
            ))
        }
    };

    let node_code = node_code
        .ok_or_else(|| anyhow::anyhow!("--node-code required (the target's CIRIS-V1-... code)"))?;
    let claim_pin = claim_pin
        .ok_or_else(|| anyhow::anyhow!("--claim-pin required (the target's one-time PIN)"))?;
    let target_url = target_url.ok_or_else(|| {
        anyhow::anyhow!("--target-url required (the target read-API URL, e.g. http://1.2.3.4:4243)")
    })?;

    // Open YOUR local user fed-ID exactly as the node resolves it: alias
    // `<keystore_alias>-user` at the conventional user-seed path.
    let cfg = ciris_server::ServerConfig::from_home(
        std::path::PathBuf::from(
            home.unwrap_or_else(|| ciris_server::config::DEFAULT_CIRIS_HOME.to_string()),
        ),
        key_id.unwrap_or_else(|| ciris_server::config::DEFAULT_KEY_ID.to_string()),
    )?;
    let user_key_id = format!("{}-user", cfg.keystore_alias);
    let seed_dir = ciris_server::user_seed_dir(&cfg);
    eprintln!("opening user fed-ID {user_key_id} ({backend_name}) — touch your token if prompted…");
    let signer =
        ciris_server::identity::hardware_user_local_signer(backend, &user_key_id, seed_dir).await?;

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let result = ciris_server::claim_remote::claim_remote(
        &http,
        &signer,
        &node_code,
        &claim_pin,
        &cohort_scope,
        Some(target_url.as_str()),
        owner_password.as_deref(),
        owner_username.as_deref(),
    )
    .await?;
    println!("✅ claim accepted by {target_url}");
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// Today's date in UTC as `YYYY-MM-DD` (the default `--date` for `bench-results`,
/// overridable so a CI run can stamp the exact build date).
fn current_utc_date() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}
