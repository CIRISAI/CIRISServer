# PQC realtime A/V streaming — E2E benchmark results

> The cost a CIRIS fabric node pays to carry **group video/voice** over the edge
> realtime-A/V mesh profile (CIRISEdge#62, CEG §10.5.8) under its **two-layer
> hybrid-PQC crypto** — the "stream" axis of the CEWP crux use case (*stream and
> store at massive scale*). Bench: [`benches/pqc_av_streaming.rs`](../benches/pqc_av_streaming.rs)
> (`cargo bench --bench pqc_av_streaming`); the live, auto-generated page is at
> <https://cirisai.github.io/CIRISServer/>. Numbers below: release build, single
> host, criterion 0.5, on the shipped triple (**persist v8.1.0 / edge v4.1.0 /
> verify v5.8.0**, CEG 1.0-RC11). **Absolute µs are host-relative; the ratios and
> the conclusion are not.**

## The path under test

```text
wire = OuterAEAD( transit_key, OuterNonce,
          InnerAEAD( epoch_dek, InnerNonce, frame_plaintext ) )
```

- **Inner** — AES-256-GCM under the per-`(stream,epoch)` DEK. End-to-end: relays /
  SFUs never see plaintext. The inner nonce is deterministic in
  `(stream_id, epoch, chunk_seq)`, so the inner ciphertext is **identical across
  the whole mesh** for a given frame (the basis of the fan-out win, §3).
- **Outer** — AES-256-GCM under the per-Link transit key. Hop authenticity +
  replay binding (nonce from `link_id || link_seq`). The transit key is the output
  of the **hybrid X25519 + ML-KEM-768 KEX** (`federation_session`, CIRISEdge#54),
  run **one-shot per session** — the post-quantum half.

The load-bearing insight: **bulk frames are AES-256-GCM, which is already
quantum-fine** (Grover only halves a 256-bit key — still 128-bit). So the
post-quantum cost *can only* live in the KEM, and the design pushes it to setup.
**Per-frame PQC cost is structurally zero, not just small.**

## 1. Per-frame end-to-end (seal → wire codec → open, one link)

| Frame | size | e2e | seal (send) | open (recv) | throughput |
|---|---|---|---|---|---|
| Opus voice (~20 ms @128 kbps) | 320 B | 0.95 µs | 0.52 µs | 0.45 µs | ~330 MiB/s |
| 720p inter-frame (low motion) | 4 KiB | 2.37 µs | 1.21 µs | 1.12 µs | 1.6 GiB/s |
| 720p inter-frame (typical) | 16 KiB | 7.05 µs | 3.25 µs | 3.08 µs | 2.1 GiB/s |
| 1080p inter / 720p keyframe | 64 KiB | 27.3 µs | 12.8 µs | 12.8 µs | 2.2 GiB/s |
| 1080p keyframe | 256 KiB | 112 µs | 56.7 µs | 49.0 µs | 2.2 GiB/s |

Seal (sender) and open (receiver) are measured **per size** — because honest mesh
accounting charges a **receiver open-only** (it never re-seals what it receives).

## 2. The post-quantum half — hybrid vs classical KEX (per-link, one-time)

| | initiate | respond | full handshake |
|---|---|---|---|
| **Hybrid (X25519 + ML-KEM-768)** | 68.1 µs | 93.7 µs | **~162 µs** |
| Classical (X25519 only) | 39.6 µs | 39.2 µs | ~79 µs |

ML-KEM-768 adds **~83 µs once per peer-link** at session setup — the *entire*
post-quantum tax for the stream path. Never paid per frame. (The responder eats
most of it — decapsulation-side.)

## 3. Mesh fan-out per frame (16 KiB, sender CPU for a room of N)

| room N | naive (`seal_av_chunk` ×N) | shared-inner (`seal_av_inner` ×1 + `seal_av_outer` ×N) | speedup |
|---|---|---|---|
| 2 | 6.51 µs | 4.79 µs | 1.36× |
| 8 | 26.0 µs | 14.0 µs | 1.85× |
| 50 | 163 µs | 78.6 µs | **2.07×** |

Fan-out planner (`RealtimeFanout::plan`, entitled∧reachable, 50 peers): ~15 µs.

The inner (E2E) ciphertext is identical across the mesh, so sealing it **once** and
applying only the per-Link outer seal per recipient roughly **halves sender CPU at
room scale**. As of **edge v3.7.0 this is the real shipped API** (`seal_av_inner` /
`seal_av_outer`, CIRISEdge#122) — wire bytes byte-identical to N×`seal_av_chunk`;
the bench drives the real functions (it previously hand-rolled the equivalent
against v3.5.0).

## 4. Membership-change rekey — the churn path (⚠ projected, not implemented)

On a join/leave the stream owner advances the epoch and rewraps the fresh inner DEK
to the member-set via a hybrid-KEM `key_grant` wrap (the same encapsulation §2
measures). **edge v3.7.1 does not implement this yet** — `EpochDek` has no ratchet
primitive and epoch rotation / DEK distribution are owned out-of-module
(**CIRISEdge#129** files the unicast-mesh baseline). These numbers **project** the
intended cost from the real primitive:

| room N | flat O(N) / delta | tree O(log N) / delta | tree win |
|---|---|---|---|
| 2 | 0.135 ms | 0.068 ms | 2.0× |
| 8 | 0.543 ms | 0.203 ms | 2.7× |
| 50 | **3.41 ms** | **0.41 ms** | 8.3× |

`flat` = O(N) wraps (the unicast-mesh baseline, #129); `tree` = O(log N) (the
TreeKEM optimization, needs multicast, CIRISEdge#66). The outer per-Link key is
**not** re-KEX'd on churn (KEX is one-shot per session) — churn cost is the inner
DEK rewrap only. A 50-room paying the flat baseline spends ~3.4 ms per membership
delta — ~10 % of a single 33 ms frame, or ~0.34 % of a core at one join/leave per
second. Affordable even unoptimized; the tree removes it as a concern.

## 5. What it means

**Crypto is nowhere near the bottleneck for interactive group video.**

- A 50-person mesh at 30 fps costs, on one core, **~0.5 % to receive** (open-only,
  under a stated 720p / GOP-30 model: 1×64 KiB keyframe + 29×16 KiB inter per
  second × 49 inbound streams), range ~0.17 % (low-motion 4 KiB) to ~0.45 %
  (typical 16 KiB). Publishing one stream to the room is ~0.24 %. Headroom is
  ~10,000+ inbound 30 fps streams/core before the AES path saturates. Bandwidth and
  the network give out long before the crypto.
- The PQ-safe handshake is a **sub-200 µs one-time** cost per link.
- Steady-state, the frame path **is** AES-256-GCM at ~2.2 GiB/s; post-quantum
  confidentiality is paid entirely at session setup.

**Net: PQC group video is effectively free — at steady state.** The one cost that
is *not* yet zero is the **membership-change rekey** (§4): real, affordable, but
**unimplemented** (CIRISEdge#129). Until it lands, "effectively free" is a
steady-state claim, not a churn claim — stated plainly so it doesn't over-travel.

## 6. Methodology notes / honesty

- Benches the **crypto + wire-codec spine** (`seal_av_chunk`/`seal_av_inner`/
  `seal_av_outer`/`open_av_chunk` / `SealedAvChunk` codec / `FederationSession` KEX
  / `RealtimeFanout::plan`) — the CPU cost CIRISServer owns. Excludes the RNS Link
  send/recv network path (bandwidth/RTT-bound; edge's transport benches) and codec
  encode/decode (the app's job).
- **Receivers are charged open-only.** A node never re-seals frames it receives, so
  mesh receive cost uses the per-size `open` half, not the e2e round-trip. (An
  earlier page charged receivers the full e2e — that inflated the per-room figure;
  fixed here.)
- **Blended figures state their model inline.** The GOP/fps assumption is named
  wherever a single "% of a core" number appears; per-size rows are shown so the
  range is visible, not one cherry-picked frame.
- **Rekey is projected, not measured-as-shipped** (§4) — flagged everywhere.
- Single-threaded, single-host, warm cache. Real deployments fan out across cores;
  these are per-operation lower bounds, not a system throughput model.
- Frame sizes are representative codec outputs, not captured from a live encoder.
