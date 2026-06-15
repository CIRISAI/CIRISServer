# PQC realtime A/V streaming — E2E benchmark results

> The cost a CIRIS fabric node pays to carry **group video/voice** over the edge
> realtime-A/V mesh profile (CIRISEdge#62, CEG 0.13 §10.5.8) under its
> **two-layer hybrid-PQC crypto**. Bench: [`benches/pqc_av_streaming.rs`](../benches/pqc_av_streaming.rs)
> (`cargo bench --bench pqc_av_streaming`). Numbers below: release build, single
> host, criterion 0.5, 100 samples/case, on the frozen triple (persist v6.8.1 /
> edge v3.5.0 / verify v5.4.0). The realtime_av crypto path is byte-identical in
> edge v3.5.0/v3.5.1 (3.5.1 only added the replication-routing hooks).

## The path under test

```text
wire = OuterAEAD( transit_key, OuterNonce,
          InnerAEAD( epoch_dek, InnerNonce, frame_plaintext ) )
```

- **Inner** — AES-256-GCM under the per-`(stream,epoch)` DEK. End-to-end: relays /
  SFUs never see plaintext. The inner nonce is deterministic in
  `(stream_id, epoch, chunk_seq)`, so the inner ciphertext is **identical across
  the whole mesh** for a given frame.
- **Outer** — AES-256-GCM under the per-Link transit key. Hop authenticity +
  replay binding (nonce derived from `link_id || link_seq`). The transit key is
  the output of the **hybrid X25519 + ML-KEM-768 KEX** (`federation_session`,
  CIRISEdge#54) — that handshake is the post-quantum half.

Absolute numbers are host-relative; the **ratios and the conclusion are not.**

## 1. Per-frame end-to-end (seal → wire codec → open, one link)

| Frame | size | time | throughput |
|---|---|---|---|
| Opus voice (~20 ms @128 kbps) | 320 B | 0.99 µs | 308 MiB/s |
| 720p inter-frame (low motion) | 4 KiB | 2.49 µs | 1.53 GiB/s |
| 720p inter-frame (typical) | 16 KiB | 7.37 µs | 2.07 GiB/s |
| 1080p inter / 720p keyframe | 64 KiB | 27.8 µs | 2.21 GiB/s |
| 1080p keyframe | 256 KiB | 105 µs | 2.33 GiB/s |

Sender/receiver split @ 64 KiB: **seal 12.8 µs**, **open 12.4 µs** — symmetric,
as expected for a double-AEAD round-trip. (The fixed ~1 µs of SHA-256 nonce
derivation + 48-byte header codec is why small frames show lower MiB/s and large
frames asymptote to the raw AES-256-GCM ceiling ~2.3 GiB/s.)

## 2. The post-quantum half — hybrid vs classical KEX (per-link, one-time)

| | initiate | respond | full handshake |
|---|---|---|---|
| **Hybrid (X25519 + ML-KEM-768)** | 71.1 µs | 99.0 µs | **~170 µs** |
| Classical (X25519 only) | 40.7 µs | 40.5 µs | ~81 µs |

ML-KEM-768 adds **~89 µs once per peer-link** at session setup — the *entire*
post-quantum tax. It is never paid per frame.

## 3. Mesh fan-out per frame (16 KiB, sender CPU for a room of N)

| room N | naive (current `seal_av_chunk` ×N) | shared-inner (inner ×1, outer ×N) | speedup |
|---|---|---|---|
| 2 | 6.63 µs | 4.96 µs | 1.34× |
| 8 | 27.9 µs | 15.5 µs | 1.80× |
| 50 | 173 µs | 87.5 µs | **1.98×** |

Fan-out planner (`RealtimeFanout::plan`, entitled∧reachable, 50 peers): 16.4 µs.

The current `seal_av_chunk` re-runs **both** AEAD layers per participant. Because
the inner (E2E) ciphertext is identical across the mesh, an inner-once / outer-N
path nearly **halves sender CPU at room scale** (and the win grows with N as the
shared inner seal amortizes). Filed as **CIRISEdge#122** for the Phase-1.x
SFU/large-room surface.

## 4. What it means

**Crypto is nowhere near the bottleneck for interactive group video.**

- A single core driving a **50-person mesh** at 30 fps / 16 KiB frames spends
  `30 × 173 µs ≈ 5.2 ms per wall-second` — **~0.5 % of one core**, naive; ~0.26 %
  with the shared-inner path. Headroom to ~9,600 participant-links/core before the
  AES path saturates. Bandwidth and the network give out long before the crypto.
- The PQ-safe handshake is a **sub-200 µs one-time** cost per link; re-establishing
  an entire 50-link room is ~8.5 ms, once.
- Steady-state, the frame path **is** AES-256-GCM at 2–2.3 GiB/s. The two-layer
  design pays for post-quantum confidentiality entirely at session setup.

**Net: PQC group video is effectively free.** The realtime-A/V mesh profile can
carry interactive video on commodity nodes with the post-quantum guarantee intact.

## 5. Methodology notes / honesty

- This benches the **crypto + wire-codec spine** (`seal_av_chunk` / `open_av_chunk`
  / `SealedAvChunk` codec / `FederationSession` KEX / `RealtimeFanout::plan`) — the
  CPU cost CIRISServer owns. It does **not** include the RNS Link send/recv network
  path (that lives in `transport/reticulum.rs` and is bandwidth/RTT-bound, covered
  by edge's own transport benches) nor codec encode/decode (the app's job).
- Single-threaded, single-host, warm cache. Real deployments fan out across cores;
  these are per-operation lower bounds, not a system throughput model.
- Frame sizes are representative codec outputs, not captured from a live encoder.
