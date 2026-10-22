//! CIRISServer#807 — the import-time tier pin guesses the home (`CIRIS_HOME`,
//! else `~/ciris`). A node served from a different `--home` must decide its own
//! tier, not inherit a software-tier pin made against the guess. One test in its
//! own binary: it rewrites this process's environment.

use ciris_server::key_tier::{
    pin_process_tier, pin_process_tier_at_import, HomeTier, TPM_PLUGIN_DISABLED,
};

#[test]
fn the_served_home_decides_its_own_tier() {
    let root = std::env::temp_dir().join(format!("ciris-807-{}", std::process::id()));
    let user_home = root.join("user");
    let keys = user_home.join("ciris").join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(keys.join("legacy.master.key"), b"x").unwrap();
    let served = root.join("served");
    std::fs::create_dir_all(&served).unwrap();

    // SAFETY: the only test in this binary; nothing else reads the environment.
    unsafe {
        std::env::remove_var("CIRIS_HOME");
        std::env::remove_var("CIRIS_TPM_PLUGIN");
        std::env::set_var("HOME", &user_home);
    }

    pin_process_tier_at_import();
    assert_eq!(
        std::env::var("CIRIS_TPM_PLUGIN").ok().as_deref(),
        Some(TPM_PLUGIN_DISABLED),
        "~/ciris holds software-tier keys, so the import pin disables the plugin"
    );

    assert_eq!(pin_process_tier(&served), HomeTier::Fresh);
    assert_eq!(
        std::env::var("CIRIS_TPM_PLUGIN").ok(),
        None,
        "a fresh --home keeps TPM custody: the import pin made for ~/ciris is undone"
    );

    assert_eq!(
        pin_process_tier(&user_home.join("ciris")),
        HomeTier::PinnedSoftware,
        "serving ~/ciris itself still pins it"
    );
    let _ = std::fs::remove_dir_all(&root);
}
