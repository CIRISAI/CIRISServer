//! **In-process mesh measurements** — cohort propagation + isolation, and an A↔B
//! replication observation, both run over the REAL `ciris_edge::swarm::FountainSwarmRuntime`
//! (the same runtime `src/holonomic.rs` wires into a production node) on an in-memory bus.
//!
//! This is the measured form of `examples/mesh_propagation/main.rs`: it stands up N
//! software-key nodes, splits them into two cohorts, has one group-A publisher advertise a
//! synthetic content blob, and measures — with real wall-clock — how the holding-claim
//! converges across group A (cohort gate ON) while group B observes nothing (isolation =
//! 0 by construction). No network, no external state — fully CI-runnable.
//!
//! The codec is NOT needed here (the swarm ships a HOLDING CLAIM = metadata, not the
//! blob), so this lives in the shipped library; the erasure tier (which DOES need the
//! dev-only fountain codec) is measured separately by `benches/erasure_survival.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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

const VIDEO_CONTENT_ID: &str = "video-chunk-0";
const CORPUS_KIND: &str = "fountain-corpus";

// ── Result shapes (serialized into bench_results.json) ───────────────────────

/// One cohort-propagation measurement at a given total node count.
#[derive(Debug, Clone)]
pub struct CohortResult {
    pub n_total: usize,
    pub group_a_converged: usize,
    pub group_a_expected: usize,
    pub group_b_leaks: usize,
    pub latency_ms: f64,
    pub deliveries: usize,
    /// `true` iff group A fully converged AND group B saw zero leaks.
    pub ok: bool,
}

/// The A↔B replication observation (a signed claim emitted at A observed at B).
#[derive(Debug, Clone)]
pub struct ReplicationResult {
    pub emitted_at_a: usize,
    pub observed_at_b: usize,
    pub latency_ms: f64,
    pub ok: bool,
}

// ── In-memory bus (identical mechanics to examples/mesh_propagation) ──────────

type Routes = Arc<RwLock<HashMap<String, Arc<FountainSwarmRuntime>>>>;
type CohortFn = Arc<dyn Fn() -> Vec<String> + Send + Sync>;
type NodeWiring = (Arc<dyn FountainHoldingsSource>, CohortFn);

struct BusTransport {
    routes: Routes,
    delivered: Arc<AtomicUsize>,
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
        let Some(claim) = parse_holding_claim(envelope_bytes) else {
            return Ok(TransportSendOutcome::Delivered);
        };
        let runtime = {
            let routes = self.routes.read().await;
            routes.get(destination_key_id).cloned()
        };
        if let Some(rt) = runtime {
            rt.register_observed_claim(claim).await;
            self.delivered.fetch_add(1, Ordering::Relaxed);
        }
        Ok(TransportSendOutcome::Delivered)
    }

    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Decode `FountainHoldingClaim::canonical_bytes` back into the claim (the same
/// big-endian length-prefixed layout the substrate documents).
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
        Some(u64::from_be_bytes(take(cur, 8)?.try_into().ok()?))
    }
    fn take_u32(cur: &mut &[u8]) -> Option<u32> {
        Some(u32::from_be_bytes(take(cur, 4)?.try_into().ok()?))
    }
    fn take_i64(cur: &mut &[u8]) -> Option<i64> {
        Some(i64::from_be_bytes(take(cur, 8)?.try_into().ok()?))
    }
    fn take_len_prefixed(cur: &mut &[u8]) -> Option<String> {
        let len = take_u64(cur)? as usize;
        String::from_utf8(take(cur, len)?.to_vec()).ok()
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

/// Build an in-memory software-key [`Engine`] (ed25519-dalek seed + ML-DSA-65 software
/// signer over `sqlite::memory:`), seeded by `idx` so each node has a distinct key.
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
        if format!("{g:?}").contains(VIDEO_CONTENT_ID) {
            count += 1;
        }
    }
    count
}

/// Measure cohort propagation + isolation at one total node count `n`.
///
/// group A = `0..n/2`, group B = `n/2..n`, publisher = node 0 (group A). Returns the
/// observed convergence (group A), leaks (group B — MUST be 0 by the cohort gate), and
/// real wall-clock propagation latency.
pub async fn measure_cohort(n: usize, symbols: usize) -> CohortResult {
    let n = n.max(2);
    let symbols = symbols.max(1);
    let half = n / 2;
    let group_a: Vec<usize> = (0..half).collect();
    let group_b: Vec<usize> = (half..n).collect();
    let publisher_idx = 0usize;

    let mut engines: Vec<Arc<Engine>> = Vec::with_capacity(n);
    for idx in 0..n {
        engines.push(build_engine(idx).await);
    }
    let peer_ids: Vec<String> = (0..n).map(|i| format!("mesh-node-{i}")).collect();
    let symbol_ids: Vec<u32> = (0..symbols as u32).collect();

    let routes: Routes = Arc::new(RwLock::new(HashMap::new()));
    let delivered = Arc::new(AtomicUsize::new(0));

    let runtime_cfg = SwarmRuntimeConfig {
        publish_cadence: Duration::from_millis(15),
        observe_cadence: Duration::from_millis(15),
        observed_claim_ttl: Duration::from_secs(3600),
        ..SwarmRuntimeConfig::default()
    };

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

    {
        let mut r = routes.write().await;
        for idx in 0..n {
            r.insert(peer_ids[idx].clone(), Arc::clone(&runtimes[idx]));
        }
    }

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

    // Let any late/mis-routed claim surface as a group-B leak.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let observed_a = count_observers(&runtimes, &group_a, publisher_idx).await;
    let observed_b = count_observers(&runtimes, &group_b, usize::MAX).await;
    let deliveries = delivered.load(Ordering::Relaxed);

    drop(routes);
    for rt in runtimes {
        if let Ok(mut owned) = Arc::try_unwrap(rt) {
            owned.shutdown().await;
        }
    }

    let latency_ms = converged_latency
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(f64::NAN);
    let ok = observed_a == cohort_size && observed_b == 0;
    CohortResult {
        n_total: n,
        group_a_converged: observed_a,
        group_a_expected: cohort_size,
        group_b_leaks: observed_b,
        latency_ms,
        deliveries,
        ok,
    }
}

/// Measure an A↔B replication observation in-process: node A (a software-key Engine
/// running the real swarm runtime) emits a holding claim that node B observes over the
/// in-memory consent/cohort path. This is the two-node specialization of the cohort
/// measurement (A's cohort closure = {B}), measuring real propagation wall-clock.
pub async fn measure_replication() -> ReplicationResult {
    // A two-node mesh: node 0 = A (publisher, cohort = {B}), node 1 = B (listener).
    let n = 2usize;
    let res = measure_cohort(n, 1).await;
    // In the 2-node case group A = {A}, group B = {B}; A's cohort is empty under the
    // generic split (the publisher's only group-A peer is itself, excluded), so the
    // generic cohort measurement does NOT exercise A→B. Run a dedicated A→B below.
    let _ = res;

    let engines: Vec<Arc<Engine>> = vec![build_engine(0).await, build_engine(1).await];
    let peer_ids = ["repl-node-a".to_string(), "repl-node-b".to_string()];
    let routes: Routes = Arc::new(RwLock::new(HashMap::new()));
    let delivered = Arc::new(AtomicUsize::new(0));

    let runtime_cfg = SwarmRuntimeConfig {
        publish_cadence: Duration::from_millis(15),
        observe_cadence: Duration::from_millis(15),
        observed_claim_ttl: Duration::from_secs(3600),
        ..SwarmRuntimeConfig::default()
    };

    let mut runtimes: Vec<Arc<FountainSwarmRuntime>> = Vec::with_capacity(n);
    for idx in 0..n {
        let transport: Arc<dyn Transport> = Arc::new(BusTransport {
            routes: Arc::clone(&routes),
            delivered: Arc::clone(&delivered),
        });
        let directory: Arc<dyn FederationDirectory> = engines[idx].federation_directory();

        // A (idx 0) holds the content and its cohort closure = {B}; B (idx 1) listens.
        let (holdings, cohort): NodeWiring = if idx == 0 {
            let held = vec![HeldFountainContent {
                content_id: VIDEO_CONTENT_ID.to_string(),
                corpus_kind: CORPUS_KIND.to_string(),
                symbol_ids: vec![0],
            }];
            let b = peer_ids[1].clone();
            (
                Arc::new(VideoHoldings { held }),
                Arc::new(move || vec![b.clone()]) as CohortFn,
            )
        } else {
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

    {
        let mut r = routes.write().await;
        for idx in 0..n {
            r.insert(peer_ids[idx].clone(), Arc::clone(&runtimes[idx]));
        }
    }

    let publish_start = Instant::now();
    let deadline = Duration::from_secs(20);
    let poll = Duration::from_millis(5);
    let mut observed_latency: Option<Duration> = None;
    loop {
        let b_observed = {
            let handle = runtimes[1].observed_handle();
            let g = handle.read().await;
            format!("{g:?}").contains(VIDEO_CONTENT_ID)
        };
        if b_observed {
            observed_latency = Some(publish_start.elapsed());
            break;
        }
        if publish_start.elapsed() > deadline {
            break;
        }
        tokio::time::sleep(poll).await;
    }

    let observed_at_b = if observed_latency.is_some() { 1 } else { 0 };

    drop(routes);
    for rt in runtimes {
        if let Ok(mut owned) = Arc::try_unwrap(rt) {
            owned.shutdown().await;
        }
    }

    let latency_ms = observed_latency
        .map(|d| d.as_secs_f64() * 1000.0)
        .unwrap_or(f64::NAN);
    ReplicationResult {
        emitted_at_a: 1,
        observed_at_b,
        latency_ms,
        ok: observed_at_b == 1,
    }
}
