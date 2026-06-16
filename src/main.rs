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
        // `ciris-server scoreboard` — print the holonomic federation scoreboard
        // (modeled capacity/survival; CIRISServer#12/#13) as JSON and exit.
        Some("scoreboard") => {
            println!("{}", ciris_server::scoreboard_json());
            Ok(())
        }
        // Default: boot the fabric node.
        _ => ciris_server::run().await,
    }
}
