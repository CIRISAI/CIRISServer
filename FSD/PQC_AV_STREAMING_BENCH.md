# Realtime A/V + holonomic federation — methodology & capacity model

> Methodology behind the capability page (<https://cirisai.github.io/CIRISServer/>).
> Three provenance classes, badged on the page and here:
> **MEASURED** (criterion microbench, this repo) · **MODEL** (bandwidth arithmetic
> over the scaling toys) · **FRONTIER** (wire/substrate ships; production piece does not yet).
> Substrate floor: persist v8.1.0 / edge v4.1.x / verify v5.8.0, CEG 1.0-RC12.
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
- **Membership rekey** PROJECTED from the real hybrid-KEM (CIRISEdge#129 not yet
  implemented): flat O(N) vs tree O(log N) per join/leave.
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

## 4. Scale / chaos CI test — design & math (gated on CIRISEdge#149)

Goal (CIRISConformance#16): a synthetic in-process federation — **2,000 streams →
3–4 ALM relay tiers → 5 viewers each viewing all 2,000** — asserting correctness at
depth and fitting GH CI (4 vCPU, <3 min).

**How many streams can one core create (GH CI, in-memory)?** Seal is
nonce-derivation-dominated:

| op | per-frame | streams/core @30fps (theory · CI-throttled) |
|---|---|---|
| `seal_av_inner` blob (~208 B) | ~1 µs | ~33,000 · ~20,000 |
| `seal_av_inner` full 720p (~10 KiB) | ~3 µs | ~11,000 · ~7,000 |
| `open_av_chunk` blob (viewer) | ~1 µs | ~33,000 · ~20,000 |

So **2,000 blob streams is ~6–10% of one core** — the "50 streams/core × 40
workers" instinct is ~400× conservative. Realistic CI layout: all 2,000 publishers
on **1–2 cores** (or 500/core × 4); the tree + viewers on the rest.

**CPU budget for the full 2,000 × 4-tier × 5-viewer blob sim @30fps:**
- publishers: 2000 × 30 × 1 µs ≈ **6% of a core**
- viewer-facing fan (5 viewers × 2000 streams): 10,000 outer-seals × 30 × ~0.7 µs ≈ **~21% of a core**; interior tiers similar order
- viewers: 5 × 2000 × 30 × 1 µs ≈ **~30% of a core** (6% each)
- **Total ≈ 1–2 cores** → fits GH CI's 4 vCPU with headroom, well under 3 min.

**The point of the test is correctness, not a CPU limit** (in-memory has no
egress): inner ciphertext **byte-identical** publisher→tier1→…→viewer (E2E
preserved across N outer hops), tree assembly, and all 2,000 streams decode at all
5 viewers.

**Blocked on CIRISEdge#149:** a true wire chain needs the relay **outer-open**
(`SealedAvChunk → InnerSealed`, never touching the `EpochDek`) so a relay can
forward an *upstream relay's* chunk. Shipped APIs wire only a depth-1 tree
(`RelayNode::forward` takes an `InnerSealed`). When #149 lands, the chain test is a
`benches/alm_chain.rs` over the real primitives.

## 5. Provenance & honesty
- **MEASURED**: §1 — in-memory criterion, AEAD-bound; wire is NIC/kernel-bound.
- **MODEL**: §2–§4 — bandwidth arithmetic over the scaling toys, not a live N-node test.
- **FRONTIER**: the blob path ships via AV1 SVC base layers; symmetric M>2 MDC video
  is the design ceiling (NeuralMDC-class codec does not exist yet; M=2 is the
  production default). Membership rekey is projected (CIRISEdge#129). The multi-tier
  chain test is gated (CIRISEdge#149).
