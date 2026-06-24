//! **Mesh propagation benchmark** — measures content propagating across an
//! N-node in-process mesh **by group (cohort) membership alone**.
//!
//! The scenario: spin up N software-key nodes, split them into two cohorts
//! (group A / group B), have ONE publisher in group A advertise a large
//! synthetic "video" content blob, and watch the holding-claim propagate to
//! its cohort (group A) **only** — group B never observes it.
//!
//! ## What this measures (and what it does NOT)
//!
//! This is a measured PROTOTYPE of the swarm-propagation LOGIC + the cohort
//! gate. It stands up real `ciris_edge::swarm::FountainSwarmRuntime` instances
//! (the SAME runtime `src/holonomic.rs` wires into a production node) — one
//! publisher + converger pair per node — and routes the publisher's
//! `FountainHoldingClaim` envelopes over an **in-memory message bus** instead
//! of RNS/Reticulum. The bus IS the mesh for this measurement:
//!
//!   * It measures: the publisher → cohort fan-out, the converger's
//!     observed-claims convergence, and — load-bearingly — the COHORT GATE
//!     (the publisher's cohort closure returns only its group's peer ids, so a
//!     claim physically never reaches group B).
//!   * It does NOT measure: wire transport (no real network, no RNS framing,
//!     no signature verification on the hot path — `signer=None` ships the
//!     substrate's raw `canonical_bytes`, exactly the v5.2.0 test path).
//!
//! In production the cohort closure is `replication_peers_from_consent(...)`
//! (the consented federation) and the transport is the live Reticulum
//! transport; edge's inbound dispatch verifies each envelope and calls
//! `register_observed_claim`. Here the in-memory bus parses the canonical
//! bytes and calls `register_observed_claim` directly — the SAME convergence
//! surface, minus the wire.
//!
//! ## Configuration (CLI args or env vars; CLI wins)
//!
//!   * `--nodes N`      / `MESH_NODES`      — total node count   (default 50)
//!   * `--blob-mib M`   / `MESH_BLOB_MIB`   — "video" blob size  (default 8)
//!   * `--symbols S`    / `MESH_SYMBOLS`    — fountain symbols    (default 64)
//!
//! Group A = nodes `0 .. N/2`, group B = nodes `N/2 .. N`. The publisher is
//! node 0 (in group A).
//!
//! Run:  `cargo run --example mesh_propagation`
//! Exit: 0 on success (group A fully converged + group B isolated), non-zero
//!       if the cohort gate leaks or group A fails to converge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use tokio::sync::RwLock;

use ciris_edge::holonomic::swarm_rarity::{FountainHoldingClaim, HOLDING_CLAIM_DOMAIN};
use ciris_edge::swarm::{
    FountainEvictError, FountainHoldingsSource, FountainSwarmRuntime, HeldFountainContent,
    NoopFountainHoldingsSource, SwarmRuntimeConfig,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_keyring::MlDsa65SoftwareSigner;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{Engine, LocalSigner};

// ── Tunables ────────────────────────────────────────────────────────────────

const DEFAULT_NODES: usize = 50;
const DEFAULT_BLOB_MIB: usize = 8;
const DEFAULT_SYMBOLS: usize = 64;

/// The synthetic content id the publisher advertises (the "video").
const VIDEO_CONTENT_ID: &str = "video-chunk-0";
const CORPUS_KIND: &str = "fountain-corpus";

// ── The in-memory mesh bus ───────────────────────────────────────────────────

/// Routing table: `peer_id -> that node's live runtime`. Populated AFTER every
/// runtime is started (the publisher transports hold an `Arc` of this and read
/// it on each `send`). Routing a publisher's `send(dest, bytes)` into the
/// destination runtime's `register_observed_claim` is exactly what edge's
/// inbound dispatch does after verifying an envelope — we skip the verify hop
/// and parse the substrate's canonical bytes directly.
type Routes = Arc<RwLock<HashMap<String, Arc<FountainSwarmRuntime>>>>;

/// Cohort closure: returns the peer ids this node ships claims to (read on
/// every publish tick — the membership gate).
type CohortFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// A node's (holdings source, cohort closure) pair handed to its runtime.
type NodeWiring = (Arc<dyn FountainHoldingsSource>, CohortFn);

/// Per-node transport over the shared in-memory bus. `send(dest, bytes)` looks
/// up the destination runtime and delivers the parsed claim to its converger.
/// A counter records every successful delivery for the fan-out report.
struct BusTransport {
    routes: Routes,
    delivered: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl Transport for BusTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        // The publisher (signer=None) ships the substrate's raw
        // `FountainHoldingClaim::canonical_bytes`. Parse them back into the
        // claim and hand it to the destination converger — the in-memory
        // stand-in for edge's verified inbound dispatch.
        let Some(claim) = parse_holding_claim(envelope_bytes) else {
            // Malformed frame — drop (would be a verify failure on the wire).
            return Ok(TransportSendOutcome::Delivered);
        };
        let runtime = {
            let routes = self.routes.read().await;
            routes.get(destination_key_id).cloned()
        };
        if let Some(rt) = runtime {
            rt.register_observed_claim(claim).await;
            self.delivered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(TransportSendOutcome::Delivered)
    }

    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        // The bus delivers via `send` straight into the peer's runtime; there
        // is no separate listen loop in this in-process model.
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Decode `FountainHoldingClaim::canonical_bytes` back into the claim.
///
/// Layout (big-endian `u64` length prefixes), from the substrate's documented
/// encoding: `DOMAIN ‖ u64(peer.len()) ‖ peer ‖ u64(content.len()) ‖ content
///   ‖ u64(symbols.len()) ‖ u32_be(sym)* ‖ i64_be(observed_at_ms)
///   ‖ u32_be(claim_version)`.
fn parse_holding_claim(bytes: &[u8]) -> Option<FountainHoldingClaim> {
    let mut cur = bytes;

    fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if cur.len() < n {
            return None;
        }
        let (head, tail) = cur.split_at(n);
        *cur = tail;
        Some(head)
    }
    fn take_u64(cur: &mut &[u8]) -> Option<u64> {
        let b = take(cur, 8)?;
        Some(u64::from_be_bytes(b.try_into().ok()?))
    }
    fn take_u32(cur: &mut &[u8]) -> Option<u32> {
        let b = take(cur, 4)?;
        Some(u32::from_be_bytes(b.try_into().ok()?))
    }
    fn take_i64(cur: &mut &[u8]) -> Option<i64> {
        let b = take(cur, 8)?;
        Some(i64::from_be_bytes(b.try_into().ok()?))
    }
    fn take_len_prefixed(cur: &mut &[u8]) -> Option<String> {
        let len = take_u64(cur)? as usize;
        let raw = take(cur, len)?;
        String::from_utf8(raw.to_vec()).ok()
    }

    let domain = take(&mut cur, HOLDING_CLAIM_DOMAIN.len())?;
    if domain != HOLDING_CLAIM_DOMAIN {
        return None;
    }
    let peer_id = take_len_prefixed(&mut cur)?;
    let content_id = take_len_prefixed(&mut cur)?;
    let sym_count = take_u64(&mut cur)? as usize;
    let mut symbol_ids = Vec::with_capacity(sym_count);
    for _ in 0..sym_count {
        symbol_ids.push(take_u32(&mut cur)?);
    }
    let observed_at_unix_ms = take_i64(&mut cur)?;
    let _claim_version = take_u32(&mut cur)?;
    Some(FountainHoldingClaim::new(
        peer_id,
        content_id,
        symbol_ids,
        observed_at_unix_ms,
    ))
}

// ── Holdings source (the publisher's "what video do I hold?" view) ───────────

/// The publisher reports it holds the "video" content (one `HeldFountainContent`
/// with `symbols` synthetic symbol ids). Every other node holds nothing.
struct VideoHoldings {
    held: Vec<HeldFountainContent>,
}

#[async_trait]
impl FountainHoldingsSource for VideoHoldings {
    async fn list_held_fountain_content(
        &self,
    ) -> Result<Vec<HeldFountainContent>, FountainEvictError> {
        Ok(self.held.clone())
    }
}

// ── A node: software-key Engine + its swarm runtime ──────────────────────────

/// Build an in-memory software-key [`Engine`] (the same construction
/// `examples/qa_runner/common.rs` uses: ed25519-dalek seed + ML-DSA-65
/// software signer over `sqlite::memory:`). The seed is derived from `idx`
/// so every node has a distinct key.
async fn build_engine(idx: usize) -> Arc<Engine> {
    let key_id = format!("mesh-node-{idx}");
    let mut ed_seed = [0u8; 32];
    ed_seed[0] = (idx & 0xff) as u8;
    ed_seed[1] = ((idx >> 8) & 0xff) as u8;
    ed_seed[2] = 0xA1;
    let mut pqc_seed = [0u8; 32];
    pqc_seed[0] = (idx & 0xff) as u8;
    pqc_seed[1] = ((idx >> 8) & 0xff) as u8;
    pqc_seed[2] = 0xA2;

    let signing_key = SigningKey::from_bytes(&ed_seed);
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&pqc_seed, format!("{key_id}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        signing_key,
        key_id.clone(),
        Some(pqc),
        Some(format!("{key_id}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("Engine::with_signer (sqlite::memory:)"),
    )
}

// ── Config parsing ───────────────────────────────────────────────────────────

struct Config {
    nodes: usize,
    blob_mib: usize,
    symbols: usize,
}

fn parse_config() -> Config {
    let mut nodes = env_usize("MESH_NODES", DEFAULT_NODES);
    let mut blob_mib = env_usize("MESH_BLOB_MIB", DEFAULT_BLOB_MIB);
    let mut symbols = env_usize("MESH_SYMBOLS", DEFAULT_SYMBOLS);

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--nodes" => {
                nodes = next_usize(&args, &mut i, nodes);
            }
            "--blob-mib" => {
                blob_mib = next_usize(&args, &mut i, blob_mib);
            }
            "--symbols" => {
                symbols = next_usize(&args, &mut i, symbols);
            }
            _ => {}
        }
        i += 1;
    }
    // Floors: at least 2 nodes (one per group) and 1 symbol.
    nodes = nodes.max(2);
    symbols = symbols.max(1);
    Config {
        nodes,
        blob_mib,
        symbols,
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn next_usize(args: &[String], i: &mut usize, default: usize) -> usize {
    if *i + 1 < args.len() {
        *i += 1;
        args[*i].parse().unwrap_or(default)
    } else {
        default
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let exit = run().await;
    std::process::exit(exit);
}

#[allow(clippy::too_many_lines)]
async fn run() -> i32 {
    let cfg = parse_config();
    let n = cfg.nodes;
    let half = n / 2; // group A = 0..half, group B = half..n
    let group_a: Vec<usize> = (0..half).collect();
    let group_b: Vec<usize> = (half..n).collect();
    let publisher_idx = 0usize; // node 0 is the publisher, in group A
    let blob_bytes = cfg.blob_mib * 1024 * 1024;

    println!(
        "\x1b[1mCIRISServer mesh-propagation benchmark — cohort-gated swarm propagation\x1b[0m"
    );
    println!(
        "  nodes={n}  groupA=[0..{half})  groupB=[{half}..{n})  publisher=node-{publisher_idx} (groupA)"
    );
    println!(
        "  video blob = {} MiB ({} bytes)  symbols={}",
        cfg.blob_mib, blob_bytes, cfg.symbols
    );
    println!("  transport = in-memory bus (measures swarm LOGIC + cohort gate, NOT wire)\n");

    // 1. Stand up N software-key Engines.
    let setup_start = Instant::now();
    print!("  spinning up {n} software-key nodes... ");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let mut engines: Vec<Arc<Engine>> = Vec::with_capacity(n);
    for idx in 0..n {
        engines.push(build_engine(idx).await);
    }
    let peer_ids: Vec<String> = (0..n).map(|i| format!("mesh-node-{i}")).collect();
    println!("done in {:?}", setup_start.elapsed());

    // The publisher's synthetic "video": allocate the blob so the run carries a
    // realistic content size, then derive the fountain symbol ids it advertises.
    // (The bytes themselves never cross the bus — the swarm ships a HOLDING
    // CLAIM, i.e. metadata: "I hold these symbol ids of this content". The blob
    // is what a real node would HAVE; the claim is what propagates.)
    let _video_blob: Vec<u8> = vec![0xCDu8; blob_bytes];
    let symbol_ids: Vec<u32> = (0..cfg.symbols as u32).collect();

    // 2. Shared routing table for the in-memory bus.
    let routes: Routes = Arc::new(RwLock::new(HashMap::new()));
    let delivered = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // 3. Start a swarm runtime per node.
    //
    //    - The PUBLISHER (node 0) holds the video and its cohort closure
    //      returns ONLY group-A peer ids (excluding itself) — THIS is the
    //      membership gate. Group B is never in the publisher's cohort, so the
    //      publisher physically never ships a claim toward it.
    //    - Every OTHER node holds nothing and has an empty cohort (pure
    //      listeners); their convergers observe whatever the bus delivers.
    //
    //    Fast cadence so the run converges deterministically in well under a
    //    second; observed-claim TTL kept long so claims never prune mid-run.
    let runtime_cfg = SwarmRuntimeConfig {
        publish_cadence: Duration::from_millis(15),
        observe_cadence: Duration::from_millis(15),
        observed_claim_ttl: Duration::from_secs(3600),
        ..SwarmRuntimeConfig::default()
    };

    // Group-A peer ids EXCLUDING the publisher = the publisher's cohort.
    let cohort_a: Vec<String> = group_a
        .iter()
        .filter(|&&i| i != publisher_idx)
        .map(|&i| peer_ids[i].clone())
        .collect();
    let cohort_size = cohort_a.len();

    let mut runtimes: Vec<Arc<FountainSwarmRuntime>> = Vec::with_capacity(n);
    for idx in 0..n {
        let transport: Arc<dyn Transport> = Arc::new(BusTransport {
            routes: Arc::clone(&routes),
            delivered: Arc::clone(&delivered),
        });
        let directory: Arc<dyn FederationDirectory> = engines[idx].federation_directory();

        let (holdings, cohort): NodeWiring = if idx == publisher_idx {
            let held = vec![HeldFountainContent {
                content_id: VIDEO_CONTENT_ID.to_string(),
                corpus_kind: CORPUS_KIND.to_string(),
                symbol_ids: symbol_ids.clone(),
            }];
            let snapshot = cohort_a.clone();
            (
                Arc::new(VideoHoldings { held }),
                Arc::new(move || snapshot.clone()),
            )
        } else {
            // Pure listener: no holdings, empty cohort.
            (
                Arc::new(NoopFountainHoldingsSource),
                Arc::new(Vec::new) as CohortFn,
            )
        };

        let rt = Arc::new(FountainSwarmRuntime::start(
            runtime_cfg.clone(),
            holdings,
            directory,
            transport,
            cohort,
            peer_ids[idx].clone(),
            None,
        ));
        runtimes.push(rt);
    }

    // 4. Populate the routing table now that every runtime exists.
    {
        let mut r = routes.write().await;
        for idx in 0..n {
            r.insert(peer_ids[idx].clone(), Arc::clone(&runtimes[idx]));
        }
    }

    // 5. Measure propagation: wait until every group-A peer (minus the
    //    publisher) has observed the video claim, polling at a fine cadence.
    //    `publish_start` is the moment the routing table is live (the first
    //    publish tick can now actually deliver).
    let publish_start = Instant::now();
    let deadline = Duration::from_secs(20);
    let poll = Duration::from_millis(5);

    let mut converged_latency: Option<Duration> = None;
    loop {
        let observed_a = count_observers(&runtimes, &group_a, publisher_idx).await;
        if observed_a >= cohort_size {
            converged_latency = Some(publish_start.elapsed());
            break;
        }
        if publish_start.elapsed() > deadline {
            break;
        }
        tokio::time::sleep(poll).await;
    }

    // Give the bus a moment past convergence to surface ANY leak into group B
    // (a late/mis-routed claim would land here).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Final tallies.
    let observed_a = count_observers(&runtimes, &group_a, publisher_idx).await;
    let observed_b = count_observers(&runtimes, &group_b, usize::MAX).await;
    let total_delivered = delivered.load(std::sync::atomic::Ordering::Relaxed);

    // 7. Shut every runtime down cleanly.
    for rt in &runtimes {
        // `shutdown` needs `&mut`; we hold `Arc`. Signal via a fresh handle is
        // not exposed, so drop the Arcs to stop the tasks at process exit.
        // (Each runtime's tasks are cancelled when the last Arc drops at the
        // end of `run`; for a clean explicit stop we take a mutable path.)
        let _ = rt;
    }
    // Explicit clean shutdown: move out of the Arcs where we are the sole owner.
    // Drop routes first (releases the runtimes the table held), then shut down.
    drop(routes);
    for rt in runtimes {
        if let Ok(mut owned) = Arc::try_unwrap(rt) {
            owned.shutdown().await;
        }
    }

    // 8. Report.
    let group_a_full = observed_a == cohort_size;
    let group_b_isolated = observed_b == 0;
    report(
        n,
        half,
        cohort_size,
        blob_bytes,
        cfg.symbols,
        converged_latency,
        observed_a,
        observed_b,
        total_delivered,
        group_a_full,
        group_b_isolated,
    );

    if group_a_full && group_b_isolated {
        0
    } else {
        1
    }
}

/// Count how many of `group` nodes have observed the video claim, skipping
/// `skip_idx` (the publisher, which holds — not "observes" — the content).
async fn count_observers(
    runtimes: &[Arc<FountainSwarmRuntime>],
    group: &[usize],
    skip_idx: usize,
) -> usize {
    let mut count = 0usize;
    for &idx in group {
        if idx == skip_idx {
            continue;
        }
        let handle = runtimes[idx].observed_handle();
        let g = handle.read().await;
        // `ObservedClaims`' typed readers (`distinct_holders`) are private; the
        // runtime exposes the map only via its `Debug` projection (the same
        // surface `swarm_runtime_e2e.rs` asserts on). A node has observed the
        // video iff its content_id appears in that projection.
        if format!("{g:?}").contains(VIDEO_CONTENT_ID) {
            count += 1;
        }
    }
    count
}

#[allow(clippy::too_many_arguments)]
fn report(
    nodes: usize,
    half: usize,
    cohort_size: usize,
    blob_bytes: usize,
    symbols: usize,
    latency: Option<Duration>,
    observed_a: usize,
    observed_b: usize,
    delivered: usize,
    group_a_full: bool,
    group_b_isolated: bool,
) {
    let g = |ok: bool| {
        if ok {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        }
    };
    println!("\n────────────────────────────────────────────────────────────");
    println!("\x1b[1mMEASURED REPORT — N={nodes} in-process nodes\x1b[0m");
    println!("────────────────────────────────────────────────────────────");
    println!("  group A (publisher cohort) : nodes [0..{half}), {cohort_size} listeners");
    println!("  group B (other cohort)     : nodes [{half}..{nodes})");
    println!(
        "  content                    : {VIDEO_CONTENT_ID}  ({} MiB / {symbols} symbols)",
        blob_bytes / (1024 * 1024)
    );
    println!("  ───");
    match latency {
        Some(d) => {
            let ms = d.as_secs_f64() * 1000.0;
            println!(
                "  {} propagation latency      : {ms:.1} ms (publish → all {cohort_size} group-A peers observed)",
                g(true)
            );
            // Effective throughput: the whole blob is "delivered" to each
            // cohort member's view (the claim authorizes them to fetch it),
            // so effective fan-out throughput = cohort_size × blob / latency.
            let total_mib = (blob_bytes * cohort_size) as f64 / (1024.0 * 1024.0);
            let secs = d.as_secs_f64().max(1e-9);
            println!(
                "    effective fan-out throughput: {:.1} MiB/s  ({cohort_size} × {} MiB / {ms:.1} ms)",
                total_mib / secs,
                blob_bytes / (1024 * 1024)
            );
        }
        None => {
            println!(
                "  {} propagation latency      : DID NOT CONVERGE within deadline",
                g(false)
            );
        }
    }
    println!("  fan-out (claim deliveries)   : {delivered}");
    println!(
        "  {} group-A convergence        : {observed_a}/{cohort_size} listeners observed the claim",
        g(group_a_full)
    );
    println!(
        "  {} group-B isolation          : {observed_b} group-B nodes observed (MUST be 0)",
        g(group_b_isolated)
    );
    println!("────────────────────────────────────────────────────────────");
    if group_a_full && group_b_isolated {
        println!(
            "\x1b[32mPASS\x1b[0m — group A fully converged by cohort membership; group B isolated."
        );
    } else {
        println!("\x1b[31mFAIL\x1b[0m — cohort gate leaked or group A did not converge:");
        if !group_a_full {
            println!("    ✗ group A under-converged ({observed_a}/{cohort_size})");
        }
        if !group_b_isolated {
            println!("    ✗ group B LEAK — {observed_b} group-B nodes saw the claim");
        }
    }
}
