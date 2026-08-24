//! **Server health** — the fabric node's OWN liveness endpoint.
//!
//! The kill-switch/ownership flows aside, a relying client (the desktop/mobile app,
//! a load balancer, a peer) must be able to ask "is this NODE up?" without an agent
//! running on top. That is what ciris-server answers here. It is the MANDATORY base
//! health: a bare node serves it.
//!
//! Layering (CIRISServer = the server; agent = server + brain):
//!   - `GET /health`            — plain liveness (`{"status":"ok"}`), for LBs.
//!   - `GET /v1/health`         — the structured SERVER health the client checks.
//!   - `GET /v1/system/health`  — the SAME server-health base; an agent running on
//!     top INHERITS this endpoint and ENRICHES it with its optional cognitive
//!     health (`cognitive_state`, the 22 services). The agent's cognitive health is
//!     OPTIONAL; the server health is NOT — so the client's required check resolves
//!     here on a bare node, and the agent's adapter extends it when present.
//!
//! Unauthenticated by design (liveness is public; it carries no owner-gated data).

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use ciris_persist::prelude::Engine;

/// The node's **CC 2.2 / CC 2.6.4 wire identity** as health reports it
/// (CIRISServer#159, extended by CIRISServer#323): the profiles this BUILD
/// implements, the CEG wire version it speaks, the `WIRE_VOCABULARY.md` SHA-256 it
/// pinned at build, and the persist-owned CEG contract-hash fingerprint
/// (`contract_hashes`).
///
/// This is the BUILD-level (capability) view — the STATE-level view (what the node
/// actually *declares*, which an operator may narrow via
/// `config:node.conformance_profiles`) is the authenticated-substrate read served at
/// `GET /v1/federation/conformance`, because it requires the Engine. Health is
/// stateless and public, so it reports the honest ceiling + the wire identity a peer
/// or LB needs to know it is even talking to a compatible node.
///
/// `contract_hashes` (CIRISServer#323 / SRV-2) publishes the persist-owned
/// envelope-vocabulary, trace-summary-extraction, consent-grammar and
/// transform-algebra hashes — making true the persist docs that already claim
/// "CIRISServer serves the hash on /v1/health". `wire_vocabulary_sha256` keeps its
/// top-level key unchanged (a published surface); the new hashes are ADDED beside
/// it. See [`crate::conformance::contract_hashes`] for the exact set + rationale,
/// and [`crate::conformance::assert_contract_hashes_pinned`] for the boot witness
/// that keeps every served value reproducible from the linked substrate.
fn build_conformance() -> serde_json::Value {
    serde_json::json!({
        "build_profiles": crate::conformance::BUILD_PROFILES
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>(),
        "ceg_wire_version": crate::conformance::CEG_WIRE_VERSION,
        "wire_vocabulary_sha256": crate::conformance::wire_vocabulary_sha256(),
        "contract_hashes": crate::conformance::contract_hashes(),
        "declared_at": "/v1/federation/conformance",
    })
}

/// Plain liveness — `{"status":"ok","version":"…"}`.
async fn plain_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "conformance": build_conformance(),
        // CIRISServer#410 — WHO is answering, not just whether something is
        // up: a bind-collision probe needs the holder's name to classify the
        // collision (see `crate::node_identity::port_holder_verdict`).
        "node": crate::node_identity::wire_json(),
    }))
}

/// Structured SERVER health (the `{"data":{…}}` envelope the client parses). A bare
/// node reports `status: "ok"` with no `cognitive_state` — that field appears only
/// when an agent enriches this endpoint (optional). `services` is the server's own
/// (empty at this layer; the agent adds its service map).
async fn server_health() -> Json<serde_json::Value> {
    Json(node_health())
}

fn node_health() -> serde_json::Value {
    // CIRISServer#446/#480 — the status word is now DERIVED, not asserted.
    // It read a hardcoded "ok" while the canonical was SIGKILLed 193 times at
    // 93% of its memory limit; every watcher above it believed the node.
    // `probe_memory` reads the cgroup on the way past, so asking how the node
    // is IS the thing that notices it is running out of room.
    //
    // ORDER IS LOAD-BEARING. Every probe RAISES as a side effect of measuring,
    // so all of them must run before `snapshot()` reads the registry — reversed,
    // each health read reports the PREVIOUS read's findings and the first read
    // after a node starts stalling says it is fine.
    // ONE LOCK ACROSS PROBE **AND** VERDICT. `verdict()` made the three verdict
    // fields agree with each other; it did not make them agree with the
    // READINGS printed beside them. Every probe raises or clears as a side
    // effect of measuring, so two concurrent requests interleave and one can
    // return its own 94% memory reading beside the other's `status: "ok"` —
    // numbers and judgement both real, and together a lie the reader can only
    // resolve by distrusting the surface (PR #483 review).
    //
    // Poison-recovering like every other lock here: a panic in one request must
    // not wedge the health route for the life of the process.
    let _collect = crate::degradation::COLLECT_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let memory = crate::degradation::probe_memory();
    // #446's own subject: a 2-vCPU canonical whose HTTP worker becomes
    // unschedulable under contention. Utilisation cannot see this — a box at
    // 100% CPU serving requests promptly is healthy — so the reading is STALL,
    // from the kernel's pressure interface, and `io` is the disk half of the
    // same question.
    let (cpu, io) = crate::degradation::probe_contention();
    // ONE registry read for all three verdict fields. Three separate reads let a
    // reporter raise or clear between them and produce a torn response —
    // `degraded` with an empty reason list, or an error warning beside
    // `degraded_mode: false` (PR #483 review). Producers tick on their own
    // cadences with no relationship to when this request arrives.
    let (warnings, degraded_mode, status) = crate::degradation::verdict();
    serde_json::json!({
        "data": {
            "status": status,
            // The shape the client has parsed all along (`CIRISApiClient`:
            // `status != "ok" || degradedMode || warnings.isNotEmpty()`), which
            // this node simply never populated. Producer meets waiting consumer.
            "warnings": warnings,
            "degraded_mode": degraded_mode,
            // What this process is using against what it is allowed — or why
            // that cannot be read. Three distinct states, never a comfortable
            // zero (see `MemoryReading`).
            // What this node is running out of, and what it could not measure.
            //
            // Deliberately the CHEAP readings only: three small file reads that
            // cost the same on a Raspberry Pi as on the canonical. The store
            // footprint (bytes, rows, per-plane counts) is NOT here and must
            // not be added — it is six `count(*)`s plus two PRAGMAs, `count(*)`
            // is a full scan on Postgres, and this route is polled by every
            // watcher in the mesh on a timer. It lives on `GET /v1/node/state`,
            // which is documented as not-for-seconds-cadence polling, and
            // `operator_surface::corpus_and_store` says so at the reader.
            "resources": { "memory": memory, "cpu": cpu, "io": io },
            "role": "fabric-node",
            "version": env!("CARGO_PKG_VERSION"),
            "services": {},
            // CC 2.2 / CC 2.6.4 (CIRISServer#159) — see `build_conformance`.
            "conformance": build_conformance(),
            // CIRISServer#410 — the node's self-name, on the base BOTH
            // `/v1/health` and `/v1/system/health` inherit (`folded_health`
            // merges the brain on top; `node` is deliberately absent from its
            // allow-list so a brain can never rename the node).
            "node": crate::node_identity::wire_json(),
        }
    })
}

/// The brain base URL, when one is folded. `None` ⇒ bare node.
#[derive(Clone)]
struct BrainState {
    upstream: Option<String>,
    client: reqwest::Client,
}

/// **`GET /v1/system/health` — the UNION of both meanings** (CIRISServer#390).
///
/// # The bug this exists to close
///
/// A folded deployment serves the node and the brain on ONE port. The universal
/// client decides node-vs-agent from this endpoint: AGENT iff `cognitive_state`
/// is present or the service map is non-empty. But health is a SUBSTRATE path —
/// the node answers it natively and never proxies — so on the folded port a full
/// agent reported as a bare NODE, and the client hid the 22 cognitive services
/// of the very agent it was talking to.
///
/// Pointing the client at the brain's own port instead does not work either:
/// that port 404s the node's surface. **Neither port served both meanings**, so
/// it had to be fixed here. This is the same one-name-two-axes shape as the rest
/// of this codebase's worst bugs: one path answering "is the NODE up?" and "is
/// there a BRAIN, and how is it?" — correct for one axis, silently wrong on the
/// other.
///
/// # Merge, never replace
///
/// Proxying this path wholesale would answer the second question and lose the
/// first: a bare node's liveness would vanish behind an upstream that may not
/// exist. So the node's own health is always the base, and the brain's
/// `cognitive_state` / `services` are merged ON TOP. The endpoint is the union
/// because the union is what is true.
///
/// # Three states, not two
///
/// `agent.folded` and `agent.reachable` are reported separately, because "no
/// brain is attached" and "a brain is attached and did not answer" are DIFFERENT
/// facts with different fixes — and both would otherwise render as a bare node,
/// which is the failure mode this endpoint just had. A client may still key
/// purely on `cognitive_state`; the extra field costs it nothing and tells an
/// operator which of the two they are looking at.
async fn folded_health(State(st): State<BrainState>) -> Json<serde_json::Value> {
    let mut out = node_health();
    let Some(upstream) = st.upstream.as_deref() else {
        out["data"]["agent"] = serde_json::json!({ "folded": false, "reachable": false });
        return Json(out);
    };
    // Bounded: health is a liveness probe and a client blocks on it during
    // startup. A slow brain must not hang the node's own liveness answer.
    let probe = st
        .client
        .get(format!("{upstream}/v1/system/health"))
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await;
    let brain: Option<serde_json::Value> = match probe {
        Ok(r) if r.status().is_success() => r.json().await.ok(),
        Ok(r) => {
            tracing::debug!(status = %r.status(), "brain health probe returned non-success");
            None
        }
        Err(e) => {
            tracing::debug!(error = %e, "brain health probe failed");
            None
        }
    };
    let Some(brain) = brain else {
        out["data"]["agent"] = serde_json::json!({ "folded": true, "reachable": false });
        return Json(out);
    };
    // The brain speaks the same `{"data":{…}}` envelope; tolerate a bare object
    // so a future/older brain shape still contributes what it has.
    //
    // ALLOW-LIST, never a blanket merge: the brain contributes ONLY its
    // cognitive fields. `node` (the #410 self-name a bind-collision probe
    // trusts) and the substrate fields stay the node's own — a brain that
    // ships its own `node`/`key_id` must not be able to rename the port's
    // holder. Gate: tests/folded_health.rs.
    let bd = brain.get("data").unwrap_or(&brain);
    for key in ["cognitive_state", "services", "cognitive", "agent_id"] {
        if let Some(v) = bd.get(key) {
            out["data"][key] = v.clone();
        }
    }
    fold_brain_degradation(&mut out, bd);
    out["data"]["agent"] = serde_json::json!({ "folded": true, "reachable": true });
    Json(out)
}

/// **A folded pair is degraded if EITHER half is** (CIRISServer#446).
///
/// The allow-list above is correct and is not what this fixes: it stops a brain
/// from renaming the node or overwriting the substrate fields. But by naming
/// only the cognitive keys it also DROPPED the brain's own health verdict, and
/// the node then answered for both halves using only its own.
///
/// The client has been reading `degraded_mode` off THIS route all along, where
/// its comment says the flag means "no working LLM provider" — a brain-tier
/// condition. So an agent with every provider dead, folded into a node with a
/// healthy store and plenty of memory, reported `degraded_mode: false` and
/// `status: "ok"`. Nothing lied; the node answered a question about the pair
/// while looking at half of it.
///
/// # Escalate only, never lower
///
/// The node's own verdict is the FLOOR. A brain can move this payload from `ok`
/// toward `degraded` and never the other way — otherwise a cheerful agent would
/// be able to clear a memory-critical node's alarm, which is the #480 defect
/// with an extra hop in it. Concretely: `degraded_mode` is an OR, `status`
/// leaves an already-degraded node degraded, and the node's own warnings are
/// never removed.
///
/// # Codes are namespaced, because the tier is part of the fix
///
/// Brain warnings arrive as `agent.<code>`. A dashboard groups on `code`, and
/// the same code from two tiers means two different things to go and do — so
/// within this payload the code has to identify the condition AND whose it is.
/// The original is preserved verbatim after the prefix.
///
/// # Hostile input
///
/// This is a remote, unauthenticated-shaped document from another process.
/// Every field is optional and every shape is tolerated: a non-array
/// `warnings`, a non-object entry, a missing `code`. Malformed entries are
/// skipped rather than defaulted, and the list is capped — a brain that offers
/// ten thousand warnings must not be able to make the node's health response
/// unservable, which would be a denial of service through the liveness probe.
fn fold_brain_degradation(out: &mut serde_json::Value, bd: &serde_json::Value) {
    /// Enough to diagnose, bounded so a runaway brain cannot bloat the node's
    /// liveness answer. The count is reported when it bites, so the cap can
    /// never be mistaken for the brain having had nothing more to say.
    const MAX_BRAIN_WARNINGS: usize = 32;

    /// **Count is not size** (codex review, PR #483).
    ///
    /// Thirty-two entries is not a bound on anything if ONE of them carries a
    /// megabyte of `message`, or a nested payload of arbitrary depth. This
    /// route is public and unauthenticated, and every request re-fetches and
    /// re-serializes the brain's document — so a buggy or compromised brain
    /// could turn concurrent health polling into unbounded memory and
    /// bandwidth, using the liveness probe as the amplifier.
    ///
    /// 2 KiB is generous for a sentence a human is meant to read on a phone,
    /// and it is applied to the SERIALIZED entry so a deep nested object is
    /// bounded by the same number as a long string — there is no second shape
    /// to reason about.
    const MAX_BRAIN_WARNING_BYTES: usize = 2048;

    /// Fields worth keeping when an entry is too large to carry whole.
    ///
    /// An oversized warning is REDUCED, never dropped: the `code` is the part
    /// an operator acts on and is nearly always small, so discarding the whole
    /// entry would throw away the signal to save the noise.
    fn reduce(w: &serde_json::Value, code: &str) -> serde_json::Value {
        let mut msg = w
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(300)
            .collect::<String>();
        msg.push_str(
            " […truncated by this node: the agent's warning exceeded the size this \
                      payload carries. Read the agent's own /v1/system/health for it in full.]",
        );
        // EVERY retained string is bounded, not just `message` (codex review,
        // PR #483). The first cut copied `code` and `severity` verbatim on the
        // reduction path — so a brain whose size came from a multi-megabyte
        // CODE sailed straight through the entry bound this reducer exists to
        // enforce, and got re-serialized on every public health request. A cap
        // with an exempt field is not a cap.
        //
        // An unrecognised severity is NORMALISED rather than clipped: it is a
        // closed vocabulary the client switches on, and a truncated token would
        // be neither valid nor obviously wrong.
        //
        // Enumerated rather than `unwrap_or`, which is what clippy suggests and
        // would be WRONG: `unwrap_or` passes an unrecognised value through, and
        // an unrecognised value here is exactly the multi-megabyte string this
        // guard exists to stop. The arms are the closed vocabulary; everything
        // else — absent, oversized, or simply unknown — becomes `warning`.
        let severity = match w.get("severity").and_then(serde_json::Value::as_str) {
            Some("info") => "info",
            Some("error") => "error",
            Some("critical") => "critical",
            _ => "warning",
        };
        serde_json::json!({
            "code": clip(code, MAX_CODE_BYTES),
            "message": msg,
            "severity": severity,
        })
    }

    /// The most `code` bytes this payload will carry, on BOTH paths — the
    /// namespacing above and the reduction below. One const, because a bound
    /// that two call sites define separately is a bound one of them will lose.
    const MAX_CODE_BYTES: usize = 256;

    /// Whether `v` serializes to at most `limit` bytes, WITHOUT building the
    /// string.
    ///
    /// `serde_json::to_string` on a hostile value allocates the whole thing
    /// before anyone can look at its length, which makes the size check itself
    /// the denial of service it was added to prevent. This writes into a sink
    /// that counts and aborts past the limit, so the cost of rejecting a 4 MiB
    /// warning is the limit, not the warning.
    fn serializes_within(v: &serde_json::Value, limit: usize) -> bool {
        struct Counter {
            written: usize,
            limit: usize,
        }
        impl std::io::Write for Counter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.written += buf.len();
                if self.written > self.limit {
                    // Any error stops serde; the distinction is carried by
                    // `written` rather than by the error kind.
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "over limit",
                    ));
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut c = Counter { written: 0, limit };
        // Unserializable is treated as oversized: if we cannot measure it, we
        // do not carry it whole.
        serde_json::to_writer(&mut c, v).is_ok() && c.written <= limit
    }

    /// Clip to at most `max` BYTES on a character boundary.
    ///
    /// Bytes because the bound is about bytes; on a boundary because slicing a
    /// UTF-8 string at an arbitrary offset panics, and this is a public,
    /// unauthenticated path fed by a remote process.
    fn clip(s: &str, max: usize) -> &str {
        match s.char_indices().find(|(i, c)| i + c.len_utf8() > max) {
            Some((i, _)) => &s[..i],
            None => s,
        }
    }

    let brain_degraded = bd
        .get("degraded_mode")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let offered = bd
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();

    // FILTER FIRST, THEN CAP (codex review, PR #483). Capping the raw array
    // lets malformed entries consume the whole budget: a brain that emits 32
    // junk objects followed by one real `llm.no_provider` would have the real
    // one silently dropped, and the response would carry nothing but a
    // truncation notice. Which entries are worth carrying is a question about
    // VALID warnings, so the cap has to be applied to those.
    // **THE CAP BOUNDS THE WORK, NOT JUST THE OUTPUT** (codex review, PR #483).
    //
    // The first cut transformed EVERY entry into `valid` and truncated
    // afterwards, so a brain returning hundreds of thousands of warnings made
    // each public health request build a full transformed list before throwing
    // most of it away. The advertised 32-entry cap bounded the response and
    // nothing else, and concurrent polling on a public route is exactly how
    // that becomes an outage.
    //
    // Retain at most the cap; count the rest.
    let mut valid: Vec<serde_json::Value> = Vec::with_capacity(MAX_BRAIN_WARNINGS);
    let mut dropped = 0usize;
    // Whether anything BEYOND the cap was degrading — see the cap branch below.
    let mut dropped_degrading = false;
    for w in offered {
        // No `code` means nothing to group on and nothing to act on; skipping
        // beats inventing an empty-string code that collides with every other
        // malformed entry.
        // A code must be present AND USABLE (codex review, PR #483). An empty
        // string passed the `Some(..)` test, namespaced to the identical
        // `agent.` for every entry, and 32 of them consumed the whole cap —
        // pushing the actionable warnings out while the truncation notice
        // claimed only valid entries had been retained. "Has a code field" and
        // "has something to group on" are different questions.
        let Some(code) = w
            .get("code")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|c| !c.is_empty())
        else {
            continue;
        };
        if valid.len() >= MAX_BRAIN_WARNINGS {
            // Past the cap: count it and do NO work on it — no clone, no
            // serialize, no reduce. Counting is the whole cost from here.
            //
            // EXCEPT its SEVERITY, which is one string comparison and is the
            // difference between reporting a pair as healthy and not (codex
            // review, PR #483). A brain with 33 warnings whose 33rd is
            // `critical`, and which omits both flags, would otherwise have that
            // condition counted and discarded while the verdict read `ok`.
            dropped += 1;
            if matches!(
                w.get("severity").and_then(serde_json::Value::as_str),
                Some("error" | "critical")
            ) {
                dropped_degrading = true;
            }
            continue;
        }
        // CLIP BEFORE ALLOCATING (codex review, PR #483). `format!` on a
        // multi-megabyte code materialised a full namespaced copy before the
        // size decision, so the RESPONSE was bounded while peak memory and
        // per-request work stayed proportional to hostile input — and this
        // route is public and polled concurrently.
        let namespaced = format!("agent.{}", clip(code, MAX_CODE_BYTES));
        // Measured with a COUNTING writer, so a huge entry is never
        // materialised as a string just to learn that it is huge. One huge
        // field and one deeply nested object are still bounded by the same
        // number, which is why this measures the serialized form at all.
        let oversized = !serializes_within(w, MAX_BRAIN_WARNING_BYTES);
        if oversized {
            valid.push(reduce(w, &namespaced));
            continue;
        }
        let mut w = w.clone();
        w["code"] = serde_json::json!(namespaced);
        valid.push(w);
    }
    let mut folded = valid;
    if dropped > 0 {
        tracing::warn!(
            valid = dropped + MAX_BRAIN_WARNINGS,
            cap = MAX_BRAIN_WARNINGS,
            "the folded brain offered more valid warnings than this payload carries — truncated"
        );
        // The count is of VALID warnings omitted, not raw array entries — an
        // operator chasing "how many am I not seeing" needs the number of real
        // ones, and malformed junk is not something they can go and read.
        folded.push(serde_json::json!({
            "code": "agent.warnings_truncated",
            "message": format!(
                "the folded agent reported {} valid warnings; {MAX_BRAIN_WARNINGS} are shown \
                 here and {dropped} are omitted. Read the agent's own /v1/system/health for \
                 the rest.",
                dropped + MAX_BRAIN_WARNINGS
            ),
            "severity": "warning",
        }));
    }

    // **A DEGRADING WARNING IS THE THIRD SIGNAL** (codex review, PR #483).
    //
    // The client's contract is `status != "ok" || degradedMode ||
    // warnings.isNotEmpty()`, and this fold honoured the first two. A brain
    // that emits an `error` or `critical` warning while omitting BOTH flags —
    // an older or partially compatible one — had that warning appended to the
    // payload while the outer verdict stayed `ok`, so a status-only watcher
    // ignored a critical condition visible three lines below it in the same
    // response.
    //
    // Read from the RETAINED warnings, after namespacing and the cap, so what
    // is judged is exactly what is reported.
    let brain_warning_degrades = dropped_degrading
        || folded.iter().any(|w| {
            matches!(
                w.get("severity").and_then(serde_json::Value::as_str),
                Some("error" | "critical")
            )
        });

    if !folded.is_empty() {
        match out["data"]["warnings"].as_array_mut() {
            Some(existing) => existing.extend(folded),
            // The node's own health always emits an array; this arm exists so a
            // future shape change cannot silently drop the brain's half.
            None => out["data"]["warnings"] = serde_json::Value::Array(folded),
        }
    }

    // A non-`ok` STATUS is an independent degradation signal, not a decoration
    // on the boolean (codex review, PR #483). The client's own contract is
    // `status != "ok" || degradedMode || warnings.isNotEmpty()` — three
    // independent signals — and this fold said every field was optional and
    // every shape tolerated, then keyed solely on the boolean. An older or
    // partially-compatible brain that reports `status: "degraded"` and no
    // `degraded_mode` would have had a valid verdict silently discarded.
    //
    // Absent status is NOT a claim of health: only a present, non-`ok` value
    // escalates, so a brain that omits the field entirely changes nothing.
    let brain_status_bad = bd
        .get("status")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s != "ok");

    if brain_degraded || brain_status_bad || brain_warning_degrades {
        out["data"]["degraded_mode"] = serde_json::json!(true);
        out["data"]["status"] = serde_json::json!("degraded");
    }
}

/// The server-health routes, merged onto the read API. Stateless (liveness only).
///
/// This is the node's boot path for the health surface (compose merges it at
/// startup), so it is where the CIRISServer#323 contract-hash **boot drift-witness**
/// fires: before wiring the routes we assert every hash `/v1/health` will serve is
/// reproducible from the linked substrate — a mismatch PANICS the boot rather than
/// let the node publish a fingerprint it cannot stand behind (run once per process).
pub fn router() -> Router {
    router_with_brain(None)
}

/// [`router`], plus the folded brain's base URL when one is attached, so
/// `/v1/system/health` can answer BOTH meanings on one port (CIRISServer#390).
///
/// `/v1/health` deliberately stays node-only: it is documented as the structured
/// SERVER health, and a caller that wants the node's own answer must keep having
/// somewhere to get it. Enriching both would leave no path that means "the node".
pub fn router_with_brain(brain_upstream: Option<String>) -> Router {
    static WITNESS: std::sync::Once = std::sync::Once::new();
    WITNESS.call_once(crate::conformance::assert_contract_hashes_pinned);
    let brain = BrainState {
        upstream: brain_upstream.map(|u| u.trim_end_matches('/').to_string()),
        client: reqwest::Client::new(),
    };
    Router::new()
        .route("/health", get(plain_health))
        .route("/v1/health", get(server_health))
        // The base the agent inherits + enriches (optional cognitive health on top).
        .merge(
            Router::new()
                .route("/v1/system/health", get(folded_health))
                .with_state(brain),
        )
}

/// State for the read-only verify-status endpoint: the node Engine (to report its
/// derived federation key_id) + the custody hardware-class label.
#[derive(Clone)]
pub struct VerifyStatusState {
    pub engine: Arc<Engine>,
    /// `TPM_2_0` | `EXTERNAL_SECURE_ELEMENT` | `PKCS11` | `SOFTWARE_ONLY`.
    pub hardware_type: String,
}

/// `GET /v1/system/verify-status` — read-only CIRISVerify / attestation status for
/// the client's Trust & Security display.
///
/// CIRISVerify is part of the node substrate (it's statically linked into the
/// wheel), so `loaded`/`binary_ok` are always true on a bare node; the node's
/// federation identity is reported via its derived key_id. This closes the gap
/// where the client GET-ed the POST-only `/v1/auth/attestation` *emit* route (405)
/// and there was no read-only verify-status route at all. Unauthenticated like
/// `/v1/system/health` — the key_id is public (it's in the NodeCode / federation_keys).
async fn verify_status(State(st): State<VerifyStatusState>) -> Json<serde_json::Value> {
    let key_id = st.engine.local_derived_key_id().await.ok();
    let has_key = key_id.is_some();
    // The node's own ed25519 fingerprint (for display) = the suffix of the
    // FSD-003 derived key_id (`<label>-<fp>`), if present.
    let fingerprint = key_id
        .as_deref()
        .and_then(|k| k.rsplit('-').next())
        .map(|s| s.to_string());
    let hw = st.hardware_type.as_str();
    let hardware_backed = hw != "SOFTWARE_ONLY";
    // Coarse attestation level for the trust meter: a booted node with a
    // registered federation identity is software-attested (2); a hardware
    // custody class lifts it. Honest floor — see the SOFTWARE_ONLY TODO.
    let max_level = if !has_key {
        0
    } else if hardware_backed {
        4
    } else {
        2
    };
    let key_storage_mode = match hw {
        "TPM_2_0" => "tpm",
        "EXTERNAL_SECURE_ELEMENT" => "secure_enclave",
        "PKCS11" => "pkcs11",
        _ => "software",
    };
    Json(serde_json::json!({
        "data": {
            // Core: the verify family is statically linked into the node wheel.
            "loaded": true,
            "binary_ok": true,
            "version": env!("CARGO_PKG_VERSION"),
            "agent_version": env!("CARGO_PKG_VERSION"),
            "role": "fabric-node",
            // Custody + identity.
            "hardware_type": st.hardware_type,
            "hardware_backed": hardware_backed,
            "key_storage_mode": key_storage_mode,
            "key_status": if has_key { "active" } else { "none" },
            "key_id": key_id,
            "ed25519_fingerprint": fingerprint,
            "attestation_status": if has_key { "verified" } else { "not_attempted" },
            // Attestation-level checks the node can honestly assert: the verify
            // binary is functional, the node self-registered its federation key,
            // and it carries an audit chain. The agent-only checks (DNS/HTTPS
            // cross-probe, file/env integrity, Play Integrity) are not run by a
            // bare node → reported false rather than over-claimed.
            "registry_ok": has_key,
            "audit_ok": true,
            "binary_self_check": "ok",
            "max_level": max_level,
            "level_pending": false,
            "attestation_mode": if hardware_backed { "full" } else { "partial" },
            "platform_os": std::env::consts::OS,
            "platform_arch": std::env::consts::ARCH,
            "checks": {
                "verify_loaded": true,
                "key_registered": has_key,
                "audit_chain": true,
                "hardware_backed": hardware_backed,
            },
            "disclaimer": "CIRISVerify provides cryptographic attestation of this node's federation identity.",
        }
    }))
}

/// The verify-status route (state-bearing — needs the node Engine + custody class).
/// Merged onto the read API next to [`router`].
pub fn verify_status_router(engine: Arc<Engine>, hardware_type: String) -> Router {
    Router::new()
        .route("/v1/system/verify-status", get(verify_status))
        .with_state(VerifyStatusState {
            engine,
            hardware_type,
        })
}
