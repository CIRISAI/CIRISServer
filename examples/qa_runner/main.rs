//! **Desktop QA runner** — boots an in-process ciris-server (SOFTWARE hybrid
//! signer) and exercises the FULL family + accord lifecycle end-to-end with
//! software keys, so the whole flow is proven before real YubiKeys are plugged in.
//!
//! Two reusable modules mirroring the production decoupling:
//!   - [`family`] — the generic CEWP family ops (`ciris_server::family`);
//!   - [`accord`] — the HUMANITY_ACCORD kill-switch specialization (HTTP surface).
//!
//! Run:  cargo run --example qa_runner
//! Exit: 0 if every step is green, 1 otherwise.

mod accord;
mod common;
mod family;

use common::Report;

#[tokio::main]
async fn main() {
    println!("\x1b[1mCIRISServer QA runner — software-key end-to-end (family + accord)\x1b[0m");
    let mut report = Report::new();

    family::run(&mut report).await;
    accord::run(&mut report).await;
    accord::run_membership(&mut report).await;

    let ok = report.print_and_status();
    std::process::exit(i32::from(!ok));
}
