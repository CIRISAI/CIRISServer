# Realtime A/V + holonomic federation — methodology & capacity model

> Methodology behind the capability page (<https://cirisai.github.io/CIRISServer/>).
> Three provenance classes, badged on the page and here:
> **MEASURED** (criterion microbench, this repo) · **MODEL** (bandwidth arithmetic
> over the scaling toys) · **FRONTIER** (wire/substrate ships; production piece does not yet).
> Substrate floor: persist v8.2.0 / edge v4.2.0 / verify v5.9.0, CEG 1.0-RC12.
> Scaling sources: CIRISEdge `FEDERATION_SCALING_MODEL.md` + CIRISNodeCore
> `examples/scale_model.rs` (scale_model v0.7 fountain).

## 1. MEASURED — the crypto path (`benches/pqc_av_streaming.rs`, `replication_ingest.rs`)

Two-layer seal: inner AES-256-GCM under a per-`(stream,epoch)` DEK (end-to-end —
relays never hold it) ‖ outer AES-256-GCM under a per-Link transit key from a
hybrid X25519+ML-KEM-768 KEX. Single-core, in-memory, host-relative.

- **Per-frame PQC cost is structurally zero** — bulk is AES-256-GCM; the only PQ
  cost is the KEM, paid **once per peer-link** (~80–90 µs ML-KEM tax, matching
  PQ-TLS deployments). Frame e2e ≈ 2.2 GiB/s asymptote.
- **Fan-out** (`seal_av_inner` once + `seal_av_outer` per Link, CIRISEdge#122):
  ~2× sender-CPU win at N=50.
- **Membership rekey** SHIPPED in edge v4.2.0 (`realtime_av_session.rs`,
  `AvSession::advance_epoch`, MLS/openmls X-Wing) — join/leave epoch-DEK rotation
  with forward secrecy + batch cold-join. *Caveat:* the joiner-side bootstrap
  `AvSession::process_welcome` is still a documented stub (`JoinerSurfaceUnwired`)
  pending the L3 federation-directory KeyPackage publish/fetch — see §6.
- **Store spine**: hybrid trace ingest (`VerifyMode::Full` verifies both halves,
  rejects classical-only — CIRISPersist#225); replay is verify-bound by design.

**Honesty:** these are AEAD-bound in-memory microbenches. Over the wire,
deployment is NIC/kernel/Reticulum-bound — crypto is *not* the bottleneck anywhere.

## 2. MODEL — bitrate anchors & room scale

Anchors (edge `FEDERATION_SCALING_MODEL.md`; NodeCore `scale_model.rs`):

| stream | bitrate | per-30fps-frame |
|---|---|---|
| blinking-dot blob (`{0,0,0}` base layer) | ~50 kbps | ~208 B |
| 720p30 AV1-SVC (full) | 2.5 Mbps | ~10 KiB |
| 1080p30 | 4–5 Mbps | |
| 8K30 (publisher top layer) | ~80 Mbps | |

Per relay core: **~150 Mbps egress** (kernel-TX-bound) → **~3,000 blob** or **~60
full-720p** forwards/core. Home uplink ~30 Mbps → flat-mesh cap ≈ **13** at 720p30.

**Room scale — downlink to render *everyone* as a blob (`N × 50 kbps`):**

| room N | see-all-as-blobs (your downlink) | flat-mesh full-720p uplink/publisher | topology |
|---|---|---|---|
| 49 | 2.4 Mbps ✓ | 120 Mbps ✕ | ALM tree |
| 200 | 10 Mbps ✓ | 498 Mbps ✕ | ALM tree |
| 500 | 25 Mbps ✓ | 1.25 Gbps ✕ | ALM tree |
| 1000 | 50 Mbps ✓ | 2.5 Gbps ✕ | ALM tree |
| **2000** | **100 Mbps ✓** | 5 Gbps ✕ | ALM tree |

**"2,000 four-pixel blobs from 2,000 8K streams?"** Yes: subscribe to each
publisher's base SVC layer (~50 kbps) → 2,000 × 50 kbps ≈ 100 Mbps down (home
gigabit). The 8K is each publisher's *top* layer, uploaded once and forwarded only
to whoever zooms in. RaptorQ-per-layer makes each blob reconstruct from any
sufficient fragment subset (lossy mesh, no jitter-buffer stalls). **The bitrate win
is SVC/MDC layering; RaptorQ buys loss-resilience + the holographic property.**

## 3. MODEL — the ALM relay tree (why large rooms work)

No node fans out to N. Each publisher emits **one** sealed copy into a tree of
peer-relays, per-node fan-out `f` bounded by measured uplink. Depth =
`ceil(log_f N)`:

| fan-out f | tiers for N=2000 | tier sizes (2000 → root) |
|---|---|---|
| 12 | **4** | 2000 → 167 → 14 → 2 → root |
| 13 | **3** | 2000 → 154 → 12 → root |
| 45 | 2 | 2000 → 45 → root |

At blob bitrate even a 30 Mbps home uplink could fan out to ~600; `f` is capped
(~12–15) for latency/balance, giving the **3–4 tiers** a 2,000-room needs. Capacity
ads are hybrid-PQC-signed + capped; topology is a deterministic pure function of
witnessed state (no leader, no node lies its way to the center). CEG RC12 §19.

## 4. Scale / chaos — multi-tier chain (SHIPPED) + 2,000-stream harness (design)

**The multi-tier relay chain is built.** edge v4.2.0 shipped the relay outer-open
primitive `open_av_outer` (CIRISEdge#149): a relay opens an upstream hop's per-link
outer AEAD and re-seals downstream **without touching the epoch DEK**, so the inner
E2E ciphertext survives arbitrary relay→relay hops. Now proven + measured:

- **`tests/alm_chain.rs`** (CI-gated): inner E2E plaintext recovered **byte-identical**
  at the viewer after **1–5 relay→relay hops**; a wrong inbound key fails closed.
- **`tests/chaos_mesh.rs`** (CI-gated): **stream path-redundancy** — a chunk delivered
  over disjoint relay paths (ALM primary + 2 backups) decodes identically from any
  *surviving* path (kill all but one → the stream continues); and the **survival
  floor**, now a **real encode→drop→decode against edge v4.2.0's own fountain codec**
  (`fountain_encode`/`fountain_decode`, `codec-fountain` L1-A): content is coded into
  H=30 holders (N=20 source), a third are killed, and the survivors reconstruct it
  **byte-identical**. Measured reception overhead (`report_fountain_overhead`):
  **20/30 (33% loss) → 99.6%**, **21/30 (30%) → 100% (2000/2000)**, 19/30 below the
  floor → never. This replaces the old `(H−k) ≥ N` tautology; the q-availability
  survival *curve* in §scoreboard stays MODEL (the swarm-availability assumption, not
  the codec). The codec is dev-enabled for the test; the fabric node relays symbols
  opaquely, so the shipped wheel stays codec-free.
- **`benches/alm_chain.rs`**: **~437 ns / relay hop** (blob) · 3.18 µs (full 720p);
  end-to-end through 4 tiers ~2.7 µs (~0.44 µs/added tier). So a 2,000-room (3–4-tier
  tree) is ~10% of one core of relay forwarding — bandwidth, not CPU, is the limit.

**The 2,000-stream / 5-viewer chaos harness (CIRISConformance#16) is the remaining
design** — the in-process federation that fans 2,000 streams through 3–4 tiers to 5
viewers each viewing all 2,000, asserting correctness at depth in GH CI (4 vCPU,
<3 min). The publisher-seal slice is now **MEASURED** (no longer arithmetic):

**Sustained multi-stream seal throughput (`benches/stream_fanout.rs`, MEASURED).**
Sealing all N blob streams for one 30 fps frame-tick in a real loop (release,
single core, host-relative):

| N streams | seal time / 30fps tick | × 30 fps = core-fraction |
|---|---|---|
| 500 | ~127 µs | ~0.4% of a core |
| 1,000 | ~268 µs | ~0.8% of a core |
| **2,000** | **~528 µs** | **~1.6% of a core** |

So **2,000 blob publishers seal in ~1.6% of one core** — measured ~0.26 µs/seal,
*better* than the ~1 µs arithmetic estimate (the old "~6–10%" was conservative).
The "50 streams/core × 40 workers" instinct is ~3,000× off.

**CPU budget for the full 2,000 × 4-tier × 5-viewer blob sim @30fps** (publisher
seal MEASURED; the rest still MODEL-arithmetic from the per-op costs):
- publishers: **~1.6% of a core** (MEASURED, `stream_fanout`)
- viewer-facing fan (5 viewers × 2000 streams): 10,000 outer-seals × 30 × ~0.7 µs ≈ **~21% of a core** (MODEL); interior tiers similar order
- viewers: 5 × 2000 × 30 × ~0.26 µs ≈ **~8% of a core** (MODEL, scaled to the measured per-seal)
- **Total ≈ well under 1 core for seals** → fits GH CI's 4 vCPU with headroom, well under 3 min.

**The harness's value is correctness-at-depth, not a CPU limit** (in-memory has no
egress — the real-world limit is donated bandwidth, §2–§3). The chain primitive that
backbone rests on is already *proven* above; the harness extends it to the full
2,000-stream / 5-viewer fan-out.

## 5. Provenance & honesty
- **MEASURED**: §1 (crypto path, AEAD-bound; wire is NIC/kernel-bound); the multi-tier
  relay chain (`benches/alm_chain.rs`, `tests/alm_chain.rs`); **stream path-redundancy
  + the fountain survival floor** via real encode→drop→decode against **edge's own
  `codec-fountain`** (`tests/chaos_mesh.rs` — 99.6% @ 20/30, 100% @ 21/30); and
  **sustained multi-stream seal throughput** (`benches/stream_fanout.rs` — 2,000
  streams ≈ 1.6% of a core).
- **MODEL**: §2–§3 bandwidth/probability arithmetic (room scale, supply ledger, tier
  depth, the q-availability survival curve) — not a live N-node test.
- **SHIPPED in edge v4.2.0** (substrate provides it; integration is the remaining work):
  the fountain codec (`codec-fountain`), AV1 + Opus codecs, the ALM tree primitives
  (`realtime_av_alm` — `SignedRelayCapacity`, `AlmJoinPlanner` primary+backup parent
  selection, `heal`), the per-subscriber relay fan-out with layer-drop
  (`realtime_av_relay`), and MLS membership rekey (`realtime_av_session`).
- **FRONTIER / integration gaps** (what's NOT yet end-to-end): the **Layer-2 wire
  dispatcher** (`RelayNode::forward` returns sealed chunks; enqueuing them onto each
  subscriber's RNS Link is deferred to "Layer 2 / T8"), the **joiner bootstrap**
  (`AvSession::process_welcome` stub → `JoinerSurfaceUnwired`, pending L3 directory
  KeyPackage publish/fetch), and **multi-tier tree orchestration** (ALM-B selects
  parents; assembling N participants into the full O(log_f N) tree is application/
  directory scope). Symmetric M>2 MDC video stays FRONTIER (NeuralMDC-class codec
  doesn't exist; M=2 default). The full 2,000-stream chaos harness
  (CIRISConformance#16) is the remaining design.
