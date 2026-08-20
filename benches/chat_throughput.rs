//! **Chat throughput + memory pressure** — the four-phase bench behind
//! `.github/workflows/chat-bench.yml`. Run:
//!
//! ```text
//! cargo bench --bench chat_throughput
//! ```
//!
//! Modelled directly on CIRISAgent's `memory-benchmark.yml` discipline: it does
//! not ask "is this fast", it asks **what does RSS do as the transcript grows**,
//! and it samples that at four phase boundaries — cold start, a 100-message warm
//! set, a burst out to 1000, and a 30-second idle tail. The agent's benchmark
//! exists because a leak shows up as a *shape* across phases, never as a single
//! number, and the same is true here.
//!
//! # What it drives
//!
//! The REAL router. [`ciris_server::contacts_chat::router`] is served on a bound
//! ephemeral TCP listener against an in-memory substrate, and every message goes
//! over HTTP through `reqwest` — the same way `tests/contacts_chat.rs` drives it.
//! Nothing under measurement is stubbed: each `POST /v1/chat/{id}/messages`
//! performs the owner gate, the membership check, an `attestation_upsert_local`,
//! a hybrid-signed `attestation_promote(community)`, and the read-back
//! projection. Each `GET` re-reads and re-folds the whole transcript.
//!
//! # The fixture is a COPY, and that is a hazard worth naming
//!
//! The seeding path below is lifted from `tests/contacts_chat.rs` — a bench
//! cannot `use` an integration test (its `#[tokio::test]` items need the test
//! harness), and neither `src/` nor `tests/` is this file's to restructure.
//!
//! A correct re-implementation sitting beside its original is precisely how
//! CIRISServer#454 stayed invisible for months: the test built its own envelope,
//! that copy was right, the producer was wrong, and everything was green. So this
//! copy does not merely run — it **asserts its own preconditions** at the first
//! message and at each list: the round-trip must carry `attestation_id`,
//! `cohort_scope: community`, `attesting_key_id == OWNER_USER_KEY_ID`, and the
//! transcript total must equal the number of messages actually emitted. A fixture
//! that has drifted out from under this file fails the bench instead of quietly
//! measuring a shape that no longer matches production.
//!
//! # Honesty
//!
//! Every phase emits exactly one JSON object on stdout (jsonl). A phase that
//! could not run emits `{"phase": …, "ran": false, "reason": …}` and the process
//! exits non-zero. Silence is never coverage — a missing line is a bug in this
//! file, not a passing phase. RSS is read from `/proc/self/status`; where that
//! file does not exist the samples are `null` with a stated reason rather than a
//! plausible-looking zero.
//!
//! **This iteration RECORDS. It does not gate.** The summary derives a
//! `suggested_rss_ceiling_kb_per_1000` from the growth measured *in this very
//! run* — never an invented constant — and marks it `"gating": false`. A
//! threshold is worth asserting once a baseline series exists; asserting one
//! before that is how a bench starts failing for reasons unrelated to the code.
//!
//! # Knobs
//!
//! | env | default | meaning |
//! |---|---|---|
//! | `CHAT_BENCH_WARM` | `100` | messages emitted in the warm phase |
//! | `CHAT_BENCH_BURST` | `900` | ADDITIONAL messages in the burst phase (→ 1000 total) |
//! | `CHAT_BENCH_IDLE_SECS` | `30` | idle tail length |
//! | `CHAT_BENCH_LIST_SAMPLES` | `5` | `GET` samples per latency measurement |

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner as _};
use ciris_persist::federation::types::{
    algorithm, cohort_scope, identity_type, IdentityOccurrence, KeyRecord, SignedKeyRecord,
};
use ciris_persist::prelude::{Engine, LocalSigner};
use ciris_persist::verify::canonical::ceg_produce_canonicalize;
use ciris_persist::wa_cert::{TokenType, WaCert, WaRole};

use ciris_server::auth::store;
use ciris_server::contacts_chat;

// ─── Fixture constants (mirrors tests/contacts_chat.rs) ─────────────────────

const NODE_KEY_ID: &str = "ciris-server";
const OWNER_USER_KEY_ID: &str = "ciris-owner-user";
const OWNER_ED_SEED: [u8; 32] = [0xF1; 32];
const OWNER_PQC_SEED: [u8; 32] = [0xF2; 32];
const CONTACT_KEY_ID: &str = "bob-v1";
const CONTACT_OCCURRENCE_KEY_ID: &str = "bob-v1-phone";

// ─── Config ─────────────────────────────────────────────────────────────────

struct Cfg {
    warm: usize,
    burst: usize,
    idle_secs: u64,
    list_samples: usize,
}

impl Cfg {
    fn from_env() -> Self {
        fn num<T: std::str::FromStr>(key: &str, default: T) -> T {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        Cfg {
            warm: num("CHAT_BENCH_WARM", 100),
            burst: num("CHAT_BENCH_BURST", 900),
            idle_secs: num("CHAT_BENCH_IDLE_SECS", 30),
            list_samples: num("CHAT_BENCH_LIST_SAMPLES", 5),
        }
    }
}

// ─── RSS ────────────────────────────────────────────────────────────────────

/// `VmRSS` / `VmHWM` in kB, read from `/proc/self/status`.
///
/// Returns `Err(reason)` off Linux (or wherever procfs is absent) so the caller
/// can emit `null` WITH a stated reason. A zero here would read as "no memory
/// used", which is the one answer that is never true.
fn read_rss() -> Result<(u64, u64), String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
        format!("/proc/self/status unreadable ({e}) — RSS not sampled on this host")
    })?;
    let field = |name: &str| -> Option<u64> {
        status
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
    };
    match (field("VmRSS:"), field("VmHWM:")) {
        (Some(rss), Some(hwm)) => Ok((rss, hwm)),
        _ => Err("/proc/self/status carried no VmRSS/VmHWM lines".to_string()),
    }
}

/// The RSS pair as JSON members, or explicit `null`s plus the reason.
fn rss_json() -> serde_json::Value {
    match read_rss() {
        Ok((rss, hwm)) => serde_json::json!({ "rss_kb": rss, "peak_rss_kb": hwm }),
        Err(reason) => {
            serde_json::json!({ "rss_kb": null, "peak_rss_kb": null, "rss_reason": reason })
        }
    }
}

fn rss_kb() -> Option<u64> {
    read_rss().ok().map(|(rss, _)| rss)
}

// ─── jsonl emit ─────────────────────────────────────────────────────────────

/// One JSON object per line, flushed immediately.
///
/// Rust's `Stdout` is line-buffered even when piped, so `println!` already
/// yields a usable stream — but the explicit flush is deliberate. The agent's
/// 13m22s run that produced ZERO captured lines (run 25033091098) died with its
/// output still in a block buffer, and the point of a phase-by-phase bench is
/// that a run cancelled in phase 3 still tells you phases 1 and 2.
fn emit(v: serde_json::Value) {
    println!("{v}");
    let _ = std::io::stdout().flush();
}

// ─── Latency helpers ────────────────────────────────────────────────────────

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_ms.len() as f64 - 1.0) * p).round() as usize;
    sorted_ms[idx]
}

fn latency_json(mut ms: Vec<f64>) -> serde_json::Value {
    ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    serde_json::json!({
        "samples": ms.len(),
        "min_ms":  round3(ms.first().copied().unwrap_or(0.0)),
        "p50_ms":  round3(percentile(&ms, 0.50)),
        "p95_ms":  round3(percentile(&ms, 0.95)),
        "max_ms":  round3(ms.last().copied().unwrap_or(0.0)),
    })
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

// ─── Fixture (copied from tests/contacts_chat.rs — see the module docs) ─────

async fn node() -> Arc<Engine> {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[0xA2; 32], format!("{NODE_KEY_ID}-pqc"))
            .expect("node ML-DSA-65 seed"),
    );
    let signer = Arc::new(LocalSigner::from_parts(
        SigningKey::from_bytes(&[0xA1; 32]),
        NODE_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{NODE_KEY_ID}-pqc")),
    ));
    Arc::new(
        Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("in-memory engine"),
    )
}

async fn node_key_id(engine: &Engine) -> String {
    engine
        .local_derived_key_id()
        .await
        .expect("derive node federation key_id")
}

async fn register_self(engine: &Engine) {
    let key_id = node_key_id(engine).await;
    ciris_server::attest::register_key(
        engine,
        ciris_server::attest::KeySigner::Engine(engine),
        &key_id,
        identity_type::STEWARD,
        serde_json::Value::Null,
    )
    .await
    .expect("register node steward key via admission gate");
}

async fn seed_user_key(engine: &Engine, key_id: &str, ed_seed: u8, pqc_seed: u8) {
    let ed = SigningKey::from_bytes(&[ed_seed; 32]);
    let mldsa = MlDsa65SoftwareSigner::from_seed_bytes(&[pqc_seed; 32], format!("{key_id}-pqc"))
        .expect("ML-DSA-65 seed");
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize registration");
    let record = KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: BASE64.encode(ed.verifying_key().to_bytes()),
        pubkey_ml_dsa_65_base64: Some(BASE64.encode(mldsa.public_key().await.expect("ml-dsa pk"))),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: key_id.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .unwrap_or_else(|e| panic!("seed user key {key_id}: {e}"));
}

fn owner_user_signer() -> LocalSigner {
    let pqc = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&OWNER_PQC_SEED, format!("{OWNER_USER_KEY_ID}-pqc"))
            .expect("owner ML-DSA-65 seed"),
    );
    LocalSigner::from_parts(
        SigningKey::from_bytes(&OWNER_ED_SEED),
        OWNER_USER_KEY_ID.to_string(),
        Some(pqc),
        Some(format!("{OWNER_USER_KEY_ID}-pqc")),
    )
}

async fn bind_owner(engine: &Engine) {
    let owner_ed_pub = BASE64.encode(
        SigningKey::from_bytes(&OWNER_ED_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let owner_mldsa_pub = {
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(
            &OWNER_PQC_SEED,
            format!("{OWNER_USER_KEY_ID}-pqc"),
        )
        .expect("owner ML-DSA-65 seed");
        BASE64.encode(pqc.public_key().await.expect("owner ML-DSA-65 pubkey"))
    };
    let now = chrono::Utc::now();
    let envelope = serde_json::json!({ "key_id": OWNER_USER_KEY_ID });
    let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize owner envelope");
    let record = KeyRecord {
        key_id: OWNER_USER_KEY_ID.to_string(),
        pubkey_ed25519_base64: owner_ed_pub,
        pubkey_ml_dsa_65_base64: Some(owner_mldsa_pub),
        algorithm: algorithm::HYBRID.into(),
        identity_type: identity_type::USER.into(),
        identity_ref: OWNER_USER_KEY_ID.to_string(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(Sha256::digest(&canonical)),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: OWNER_USER_KEY_ID.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };
    engine
        .federation_directory()
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("register responsible-party user key");

    let scopes: Vec<String> = ciris_server::auth::ownership::OWNER_BINDING_INFRA_SCOPES
        .iter()
        .map(|s| s.to_string())
        .collect();
    let node = node_key_id(engine).await;
    ciris_server::auth::ownership::emit_steward_binding(
        engine,
        &owner_user_signer(),
        &node,
        &scopes,
    )
    .await
    .expect("emit owner-binding delegates_to(user -> node, infra:*)");
}

async fn seed_contact_occurrence(engine: &Engine) {
    seed_user_key(engine, CONTACT_OCCURRENCE_KEY_ID, 0xB2, 0xB3).await;
    engine
        .federation_directory()
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: CONTACT_KEY_ID.to_string(),
            occurrence_key_id: CONTACT_OCCURRENCE_KEY_ID.to_string(),
            device_class: "phone".to_string(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind the contact's phone occurrence");
}

async fn mint_session(engine: &Engine, wa_id: &str, role: WaRole) -> String {
    let now = chrono::Utc::now();
    let cert = WaCert {
        wa_id: wa_id.to_string(),
        name: wa_id.to_string(),
        role,
        pubkey: BASE64.encode([0u8; 32]),
        jwt_kid: format!("kid-{wa_id}"),
        password_hash: None,
        api_key_hash: None,
        oauth_provider: None,
        oauth_external_id: None,
        oauth_links: None,
        veilid_id: None,
        auto_minted: false,
        parent_wa_id: None,
        parent_signature: None,
        scopes: serde_json::json!([]),
        custom_permissions: None,
        adapter_id: None,
        adapter_name: None,
        adapter_metadata: None,
        token_type: TokenType::Session,
        created: now,
        last_login: None,
        active: true,
    };
    store::upsert(engine, cert).await.expect("mint wa_cert");
    ciris_server::auth::session::test_support_issue_session_token(wa_id)
}

async fn serve(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<()>) {
    let app = contacts_chat::router(engine);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

/// The whole fixture, plus the open chat the message phases write into.
struct Bed {
    _engine: Arc<Engine>,
    base: String,
    owner: String,
    community_id: String,
    _serve: tokio::task::JoinHandle<()>,
}

async fn build_bed(client: &reqwest::Client) -> Result<Bed, String> {
    let engine = node().await;
    register_self(&engine).await;
    bind_owner(&engine).await;
    seed_user_key(&engine, CONTACT_KEY_ID, 0xB0, 0xB1).await;
    seed_contact_occurrence(&engine).await;
    let owner = mint_session(&engine, "wa-owner", WaRole::Root).await;
    let (base, handle) = serve(Arc::clone(&engine)).await;

    let resp = client
        .post(format!("{base}/v1/contacts"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .map_err(|e| format!("POST /v1/contacts: {e}"))?;
    if resp.status() != 200 {
        return Err(format!(
            "POST /v1/contacts returned {} — the fixture no longer stands up",
            resp.status()
        ));
    }
    let resp = client
        .post(format!("{base}/v1/chat"))
        .bearer_auth(&owner)
        .json(&serde_json::json!({ "key_id": CONTACT_KEY_ID }))
        .send()
        .await
        .map_err(|e| format!("POST /v1/chat: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("POST /v1/chat returned {}", resp.status()));
    }
    let json: serde_json::Value = resp.json().await.map_err(|e| format!("chat json: {e}"))?;
    let community_id = json["community_id"]
        .as_str()
        .ok_or("POST /v1/chat carried no community_id")?
        .to_string();
    // The convergence property the whole room depends on — recomputed here, so a
    // fixture that stopped deriving the pair id fails loudly rather than
    // benchmarking a room only this process can find.
    if community_id != contacts_chat::pair_community_key_id(OWNER_USER_KEY_ID, CONTACT_KEY_ID) {
        return Err(format!(
            "community_id {community_id} is not the derived pair id — fixture drift"
        ));
    }

    Ok(Bed {
        _engine: engine,
        base,
        owner,
        community_id,
        _serve: handle,
    })
}

// ─── The measured legs ──────────────────────────────────────────────────────

/// Emit `n` messages, returning per-message latencies in ms.
///
/// `verify_first` checks the round-trip shape once — the fixture's own gate. It
/// runs on the first message of the warm phase only; repeating it 1000 times
/// would measure `serde_json` rather than the router.
async fn emit_messages(
    client: &reqwest::Client,
    bed: &Bed,
    n: usize,
    tag: &str,
    verify_first: bool,
) -> Result<Vec<f64>, String> {
    let url = format!("{}/v1/chat/{}/messages", bed.base, bed.community_id);
    let mut lat = Vec::with_capacity(n);
    for i in 0..n {
        let body = format!("{tag} message {i} — chat throughput bench, in-process router");
        let t = Instant::now();
        let resp = client
            .post(&url)
            .bearer_auth(&bed.owner)
            .json(&serde_json::json!({ "body": body }))
            .send()
            .await
            .map_err(|e| format!("POST message {i}: {e}"))?;
        let status = resp.status();
        if status != 200 {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("POST message {i} returned {status}: {text}"));
        }
        if verify_first && i == 0 {
            let json: serde_json::Value =
                resp.json().await.map_err(|e| format!("send json: {e}"))?;
            if !json["attestation_id"].is_string() {
                return Err(format!("send carried no attestation_id: {json}"));
            }
            if json["cohort_scope"] != cohort_scope::COMMUNITY {
                return Err(format!(
                    "send placed the row at {:?}, not the community tier",
                    json["cohort_scope"]
                ));
            }
            if json["message"]["attesting_key_id"] != OWNER_USER_KEY_ID {
                return Err(format!(
                    "the read-back message is not attested by the owner: {json}"
                ));
            }
        } else {
            // Drain the body — an undrained response leaves bytes in the socket
            // and the next request pays for them, which would land in the NEXT
            // message's latency rather than this one's.
            let _ = resp.bytes().await;
        }
        lat.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(lat)
}

/// `GET` the transcript `samples` times; returns (latencies_ms, reported total).
async fn list_messages(
    client: &reqwest::Client,
    bed: &Bed,
    samples: usize,
    expect_total: usize,
) -> Result<(Vec<f64>, usize), String> {
    let url = format!("{}/v1/chat/{}/messages", bed.base, bed.community_id);
    let mut lat = Vec::with_capacity(samples);
    let mut total = 0usize;
    for i in 0..samples {
        let t = Instant::now();
        let resp = client
            .get(&url)
            .bearer_auth(&bed.owner)
            .send()
            .await
            .map_err(|e| format!("GET messages: {e}"))?;
        if resp.status() != 200 {
            return Err(format!("GET messages returned {}", resp.status()));
        }
        let json: serde_json::Value = resp.json().await.map_err(|e| format!("list json: {e}"))?;
        lat.push(t.elapsed().as_secs_f64() * 1000.0);
        total = json["total"].as_u64().unwrap_or(0) as usize;
        if i == 0 && total != expect_total {
            return Err(format!(
                "transcript holds {total} messages, {expect_total} were emitted — \
                 the read is not returning what the writes put in"
            ));
        }
    }
    Ok((lat, total))
}

// ─── main ───────────────────────────────────────────────────────────────────

fn main() {
    let cfg = Cfg::from_env();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run(cfg));
    std::process::exit(code);
}

/// Emit `ran:false` for a phase that never got to run, with the reason.
fn skipped(phase: &str, reason: &str) {
    emit(serde_json::json!({
        "phase": phase,
        "ran": false,
        "reason": reason,
    }));
}

async fn run(cfg: Cfg) -> i32 {
    emit(serde_json::json!({
        "phase": "config",
        "ran": true,
        "warm_messages": cfg.warm,
        "burst_messages": cfg.burst,
        "transcript_after_burst": cfg.warm + cfg.burst,
        "idle_secs": cfg.idle_secs,
        "list_samples": cfg.list_samples,
        "note": "RECORD-ONLY: no threshold is asserted; see the summary's gating:false",
    }));

    let rss_process_start = rss_kb();
    let client = reqwest::Client::new();

    // ── Phase 1: cold start ────────────────────────────────────────────────
    let t = Instant::now();
    let bed = match build_bed(&client).await {
        Ok(b) => b,
        Err(reason) => {
            emit(serde_json::json!({
                "phase": "cold_start", "ran": false, "reason": reason,
            }));
            for p in ["warm", "burst", "idle", "summary"] {
                skipped(p, "cold_start did not stand up the fixture");
            }
            return 1;
        }
    };
    let cold_ms = t.elapsed().as_secs_f64() * 1000.0;
    let rss_cold = rss_kb();
    let mut obj = serde_json::json!({
        "phase": "cold_start",
        "ran": true,
        "elapsed_ms": round3(cold_ms),
        "rss_at_process_start_kb": rss_process_start,
        "community_id": bed.community_id,
        "what": "engine + fixture seed + router served + contact added + chat opened",
    });
    merge(&mut obj, rss_json());
    emit(obj);

    // ── Phase 2: warm (100 messages) ───────────────────────────────────────
    let t = Instant::now();
    let warm_lat = match emit_messages(&client, &bed, cfg.warm, "warm", true).await {
        Ok(l) => l,
        Err(reason) => {
            emit(serde_json::json!({ "phase": "warm", "ran": false, "reason": reason }));
            for p in ["burst", "idle", "summary"] {
                skipped(p, "the warm phase could not emit");
            }
            return 1;
        }
    };
    let warm_secs = t.elapsed().as_secs_f64();
    let warm_list = match list_messages(&client, &bed, cfg.list_samples, cfg.warm).await {
        Ok(r) => r,
        Err(reason) => {
            emit(serde_json::json!({ "phase": "warm", "ran": false, "reason": reason }));
            for p in ["burst", "idle", "summary"] {
                skipped(p, "the warm phase could not read back");
            }
            return 1;
        }
    };
    let rss_warm = rss_kb();
    let mut obj = serde_json::json!({
        "phase": "warm",
        "ran": true,
        "messages_emitted": cfg.warm,
        "transcript_total": warm_list.1,
        "emit_seconds": round3(warm_secs),
        "emit_messages_per_sec": round3(cfg.warm as f64 / warm_secs.max(f64::MIN_POSITIVE)),
        "emit_latency": latency_json(warm_lat),
        "list_latency": latency_json(warm_list.0),
    });
    merge(&mut obj, rss_json());
    emit(obj);

    // ── Phase 3: burst (out to 1000) ───────────────────────────────────────
    let total_after_burst = cfg.warm + cfg.burst;
    let t = Instant::now();
    let burst_lat = match emit_messages(&client, &bed, cfg.burst, "burst", false).await {
        Ok(l) => l,
        Err(reason) => {
            emit(serde_json::json!({ "phase": "burst", "ran": false, "reason": reason }));
            for p in ["idle", "summary"] {
                skipped(p, "the burst phase could not emit");
            }
            return 1;
        }
    };
    let burst_secs = t.elapsed().as_secs_f64();
    let burst_list = match list_messages(&client, &bed, cfg.list_samples, total_after_burst).await {
        Ok(r) => r,
        Err(reason) => {
            emit(serde_json::json!({ "phase": "burst", "ran": false, "reason": reason }));
            for p in ["idle", "summary"] {
                skipped(p, "the burst phase could not read back");
            }
            return 1;
        }
    };
    let rss_burst = rss_kb();
    let mut obj = serde_json::json!({
        "phase": "burst",
        "ran": true,
        "messages_emitted": cfg.burst,
        "transcript_total": burst_list.1,
        "emit_seconds": round3(burst_secs),
        "emit_messages_per_sec": round3(cfg.burst as f64 / burst_secs.max(f64::MIN_POSITIVE)),
        "emit_latency": latency_json(burst_lat),
        "list_latency": latency_json(burst_list.0),
    });
    merge(&mut obj, rss_json());
    emit(obj);

    // ── Phase 4: idle tail ─────────────────────────────────────────────────
    //
    // No traffic. What RSS does here separates "the transcript is resident"
    // (flat) from "something is still accruing" (a climb with nothing driving
    // it) — the distinction a single post-burst number cannot make.
    let mut idle_samples: Vec<serde_json::Value> = Vec::new();
    let idle_t = Instant::now();
    let step = Duration::from_secs(5);
    while idle_t.elapsed().as_secs() < cfg.idle_secs {
        tokio::time::sleep(step).await;
        idle_samples.push(serde_json::json!({
            "at_secs": idle_t.elapsed().as_secs(),
            "rss_kb": rss_kb(),
        }));
    }
    let rss_idle = rss_kb();
    let mut obj = serde_json::json!({
        "phase": "idle",
        "ran": true,
        "idle_secs": cfg.idle_secs,
        "samples": idle_samples,
    });
    merge(&mut obj, rss_json());
    emit(obj);

    // ── Summary: the DELTAS, and a ceiling derived from THIS run ───────────
    let delta = |a: Option<u64>, b: Option<u64>| -> Option<i64> {
        match (a, b) {
            (Some(a), Some(b)) => Some(b as i64 - a as i64),
            _ => None,
        }
    };
    let burst_growth = delta(rss_warm, rss_burst);
    let per_1000 = burst_growth.map(|g| {
        let per_msg = g as f64 / cfg.burst.max(1) as f64;
        round3(per_msg * 1000.0)
    });
    emit(serde_json::json!({
        "phase": "summary",
        "ran": true,
        "rss_kb": {
            "process_start": rss_process_start,
            "cold":  rss_cold,
            "warm":  rss_warm,
            "burst": rss_burst,
            "idle":  rss_idle,
        },
        "rss_delta_kb": {
            "cold_to_warm":  delta(rss_cold, rss_warm),
            "warm_to_burst": burst_growth,
            "burst_to_idle": delta(rss_burst, rss_idle),
            "cold_to_idle":  delta(rss_cold, rss_idle),
        },
        "rss_growth_kb_per_1000_messages": per_1000,
        // DERIVED FROM THIS RUN, not from a constant someone picked. 2x the
        // measured growth is a starting point for a ceiling once a baseline
        // series exists; nothing here compares against it.
        "suggested_rss_ceiling_kb_per_1000": per_1000.map(|v| round3(v * 2.0)),
        "gating": false,
        "gating_note": "first iteration RECORDS. Gate only after a weekly baseline series exists.",
    }));
    0
}

/// Fold `src`'s members into `dst` (both must be objects).
fn merge(dst: &mut serde_json::Value, src: serde_json::Value) {
    if let (Some(d), Some(s)) = (dst.as_object_mut(), src.as_object()) {
        for (k, v) in s {
            d.insert(k.clone(), v.clone());
        }
    }
}
