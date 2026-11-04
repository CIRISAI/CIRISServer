//! `ciris_server.upgrade` is standard-library Python, tested by
//! tests/python/test_upgrade.py. This runs it under `cargo test`, so it gates
//! CI on every platform with a Python, Windows included.

#[test]
fn the_upgrade_helper_passes_its_tests() {
    let python = if cfg!(windows) { "python" } else { "python3" };
    let out = match std::process::Command::new(python)
        .args(["-I", "tests/python/test_upgrade.py"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("no {python} here ({e}); skipped");
            return;
        }
    };
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
