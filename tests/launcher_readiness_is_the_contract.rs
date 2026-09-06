//! The wheel launcher's readiness predicate IS the boot contract, not a
//! mirrored vocabulary (CIRISServer#548).
//!
//! `python/ciris_server/cli.py::_wait_for_node_health` used to accept
//! `body["status"] in ("ok", "starting", "degraded")` — a status vocabulary
//! the node never had: the plain `/health` route serves a constant `"ok"`, the
//! only derived word lives on `/v1/health` and is `"ok" | "degraded"`, and no
//! producer anywhere emits `"starting"`. An agent-side reader found the tuple,
//! read it as the node's own readiness helper "expecting to see `starting`",
//! and nearly told the client to key on a state that cannot occur. That is the
//! mirrored-rule failure: one rule (200 ⇒ serving, because the listener binds
//! after every boot phase that matters), two implementations, and the copy
//! drifted from a vocabulary the original does not have.
//!
//! This gate scrapes both sides so the copy cannot come back: the launcher
//! must not name `"starting"` as a status, and the node must not grow one
//! without this file being the place that says the launcher may accept it.

use std::fs;
use std::path::Path;

fn read(rel: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn the_launcher_keys_on_200_not_on_a_status_word() {
    let cli = read("python/ciris_server/cli.py");
    let start = cli
        .find("def _wait_for_node_health(")
        .expect("cli.py still defines _wait_for_node_health");
    let end = cli[start..]
        .find("\ndef ")
        .map(|i| start + i)
        .unwrap_or(cli.len());
    let body = &cli[start..end];
    assert!(
        !body.contains("\"starting\""),
        "_wait_for_node_health names a \"starting\" status again — the node has no such \
         value (plain /health is a constant \"ok\"; /v1/health is \"ok\" | \"degraded\"). \
         200 is the contract (#548)."
    );
    assert!(
        !body.contains("body.get(\"status\""),
        "_wait_for_node_health decides readiness from the status word again; the listener \
         binds after every boot phase that matters, so `resp.status == 200` is the whole \
         predicate (#548)."
    );
    assert!(
        body.contains("resp.status == 200"),
        "_wait_for_node_health must still test the HTTP status — that IS the contract"
    );
}

#[test]
fn the_node_has_no_starting_status() {
    // The vocabulary the launcher was mirroring. If a producer ever grows a
    // "starting" word, this is the file to update — deliberately, with the
    // launcher in the same change.
    for rel in ["src/health.rs", "src/degradation.rs"] {
        let s = read(rel);
        for (n, line) in s.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("\"starting\""),
                "{rel}:{} emits a \"starting\" status the launcher contract (#548) says cannot occur",
                n + 1
            );
        }
    }
}
