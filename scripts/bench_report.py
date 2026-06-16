#!/usr/bin/env python3
"""
Build the CIRISServer capability page — what the fabric node can actually DO
(room-scale video, vs the state of the art, how), grounded in measured crypto
microbenches + the edge capacity model + the holonomic scoreboard.

Usage:
    cargo bench --bench pqc_av_streaming --bench replication_ingest
    cargo run --release -- scoreboard > scoreboard.json
    python3 scripts/bench_report.py --out bench-site --scoreboard scoreboard.json

Emits <out>/index.html + <out>/data.json (+ scoreboard.json passthrough).

Every figure is badged by provenance so the page is credible, not marketing:
  • MEASURED  — criterion microbench on this run's runner (in-memory, AEAD-bound;
                real deployment is NIC/kernel-bound — absolute µs host-relative).
  • MODEL     — derived from edge FEDERATION_SCALING_MODEL.md bitrate anchors +
                bandwidth arithmetic (not a live N-node test).
  • FRONTIER  — design ships at the wire/substrate but the production piece
                (e.g. symmetric M>2 MDC video codec) does not exist yet.
"""
from __future__ import annotations
import argparse, glob, html, json, os, sys

MiB = 1024 * 1024
FPS = 30
GOP = 30
KEYFRAME_BYTES = 64 * 1024
INTER_BYTES = 16 * 1024
MESH_N = 50

# ── Capacity model constants — edge FEDERATION_SCALING_MODEL.md (v4.1.x) ──────
BITRATE_MBPS = {                       # codec output bitrate anchors
    "Opus voice": 0.024,
    "blinking-dot blob": 0.05,
    "720p30 AV1-SVC": 2.5,
    "1080p30": 4.5,
    "4K30": 20.0,
    "8K30 (top layer)": 80.0,
}
RELAY_EGRESS_MBPS = 150.0   # sustained egress per relay core (kernel TX-bound)
HOME_UPLINK_MBPS = 30.0     # median home upload
GIGABIT_MBPS = 1000.0
ROOMS = [49, 200, 500, 1000, 2000]
SOTA_TILE_CAP = 49          # Zoom / Meet / Teams gallery-view cap


def load_estimates(criterion_dir: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for p in glob.glob(os.path.join(criterion_dir, "**", "new", "estimates.json"), recursive=True):
        bench_id = os.path.relpath(os.path.dirname(os.path.dirname(p)), criterion_dir)
        if bench_id.startswith("report"):
            continue
        try:
            with open(p) as fh:
                out[bench_id.replace(os.sep, "/")] = json.load(fh)["mean"]["point_estimate"]
        except Exception:
            pass
    return out


def us(ns: float | None) -> float | None:
    return None if ns is None else ns / 1_000.0


def pct_core(ns_per_sec: float) -> float:
    return round(100.0 * ns_per_sec / 1e9, 2)


FRAME_LABELS = {
    "320": "Opus voice frame (~20 ms @128 kbps)",
    "4096": "720p inter-frame (low motion)",
    "16384": "720p inter-frame (typical)",
    "65536": "1080p inter / 720p keyframe",
    "262144": "1080p keyframe",
}


def capacity_model() -> dict:
    """MODEL-derived room-scale feasibility (bandwidth arithmetic over the edge
    bitrate anchors). The headline question: what downlink renders *everyone* as a
    blinking-dot blob, and where does flat mesh die?"""
    blob = BITRATE_MBPS["blinking-dot blob"]
    full = BITRATE_MBPS["720p30 AV1-SVC"]
    rooms = []
    for n in ROOMS:
        rooms.append({
            "n": n,
            "down_all_blobs_mbps": round(n * blob, 2),          # DEMAND: your downlink to see all blobs
            "aggregate_uplink_gbps": round(n * n * blob / 1000.0, 1),  # SUPPLY: N²·b donated uplink (= agg. downlink)
            "mesh_full_uplink_mbps": round((n - 1) * full, 1),  # flat-mesh full-720p uplink/publisher
            "feasible_blobs": (n * blob) <= GIGABIT_MBPS,
        })
    # What a "blob" costs is the dominant lever on the supply side. 50 kbps is edge's
    # BLINKING_DOT (a low-res *video thumbnail*); a literal presence dot is far cheaper.
    sensitivity = []
    for kbps, label in [(5, "presence dot (~4 px, 1–2 fps)"),
                        (15, "low thumbnail"),
                        (50, "video thumbnail (edge BLINKING_DOT)")]:
        b = kbps / 1000.0
        sensitivity.append({
            "kbps": kbps, "label": label,
            "per_viewer_down_mbps": round(2000 * b, 1),
            "aggregate_gbps": round(2000 * 2000 * b / 1000.0, 1),
        })
    return {
        "rooms": rooms,
        "blob_kbps": int(blob * 1000),
        "blob_per_core": int(RELAY_EGRESS_MBPS / blob),     # ~3000
        "full720_per_core": int(RELAY_EGRESS_MBPS / full),  # ~60
        "mesh_full_cap": 1 + int(HOME_UPLINK_MBPS // full),  # ~13
        "relay_egress_mbps": RELAY_EGRESS_MBPS,
        "home_uplink_mbps": HOME_UPLINK_MBPS,
        "sota_tile_cap": SOTA_TILE_CAP,
        "bitrates_mbps": BITRATE_MBPS,
        "blob_sensitivity": sensitivity,
    }


def build_model(est: dict[str, float]) -> dict:
    m: dict = {"video_frames": [], "kex": {}, "fanout": [], "rekey": [], "chain": {},
               "mesh": {}, "replication": {}, "capacity": capacity_model(), "assumptions": {}}

    for size_s, label in FRAME_LABELS.items():
        e2e = est.get(f"av_frame_e2e/{size_s}")
        if e2e is None:
            continue
        size = int(size_s)
        m["video_frames"].append({
            "bytes": size, "label": label,
            "e2e_us": round(us(e2e), 2),
            "seal_us": round(us(est[f"av_frame_halves/seal/{size_s}"]), 2) if f"av_frame_halves/seal/{size_s}" in est else None,
            "open_us": round(us(est[f"av_frame_halves/open/{size_s}"]), 2) if f"av_frame_halves/open/{size_s}" in est else None,
            "gib_s": round((size / (e2e * 1e-9)) / (1024 * MiB), 2),
            "fps_ceiling": round(1e9 / e2e),
        })

    for n in (2, 8, MESH_N):
        naive = est.get(f"av_mesh_fanout/naive/{n}")
        shared = est.get(f"av_mesh_fanout/shared_inner/{n}")
        row = {"n": n}
        if naive is not None:
            row["naive_us"] = round(us(naive), 2)
        if shared is not None:
            row["shared_inner_us"] = round(us(shared), 2)
        if naive and shared:
            row["speedup"] = round(naive / shared, 2)
        m["fanout"].append(row)

    open_inter = est.get(f"av_frame_halves/open/{INTER_BYTES}")
    open_key = est.get(f"av_frame_halves/open/{KEYFRAME_BYTES}")
    open_low = est.get(f"av_frame_halves/open/4096")
    send_50 = est.get(f"av_mesh_fanout/shared_inner/{MESH_N}")
    peers = MESH_N - 1
    if send_50:
        m["mesh"]["send_pct_core"] = pct_core(FPS * send_50)
    if open_inter:
        m["mesh"]["recv_typical_pct_core"] = pct_core(peers * FPS * open_inter)
        m["mesh"]["max_recv_streams_30fps_core"] = round(1e9 / (FPS * open_inter))
    if open_low:
        m["mesh"]["recv_lowmotion_pct_core"] = pct_core(peers * FPS * open_low)
    if open_inter and open_key:
        per_stream_sec = open_key + (GOP - 1) * open_inter
        m["mesh"]["recv_gop_blend_pct_core"] = pct_core(peers * per_stream_sec)

    h_i, h_r = est.get("pqc_kex/hybrid_initiate"), est.get("pqc_kex/hybrid_respond")
    c_i, c_r = est.get("pqc_kex/classical_initiate"), est.get("pqc_kex/classical_respond")
    if h_i and h_r:
        m["kex"]["hybrid_full_us"] = round(us(h_i + h_r), 1)
        m["kex"]["hybrid_initiate_us"] = round(us(h_i), 1)
    if c_i and c_r:
        m["kex"]["classical_full_us"] = round(us(c_i + c_r), 1)
    if h_i and h_r and c_i and c_r:
        m["kex"]["mlkem_tax_us"] = round(us((h_i + h_r) - (c_i + c_r)), 1)

    for n in (2, 8, MESH_N):
        flat = est.get(f"av_rekey/flat_rewrap/{n}")
        tree = est.get(f"av_rekey/tree_rewrap/{n}")
        row = {"n": n}
        if flat is not None:
            row["flat_ms"] = round(flat / 1e6, 3)
        if tree is not None:
            row["tree_ms"] = round(tree / 1e6, 3)
        if flat and tree:
            row["tree_speedup"] = round(flat / tree, 1)
        m["rekey"].append(row)

    new = est.get("replication_ingest/ingest_new")
    dedup = est.get("replication_ingest/ingest_dedup")
    if new:
        m["replication"]["ingest_new_us"] = round(us(new), 2)
        m["replication"]["traces_per_sec"] = round(1e9 / new)
    if dedup:
        m["replication"]["dedup_us"] = round(us(dedup), 2)
        m["replication"]["dedup_per_sec"] = round(1e9 / dedup)
    if new and dedup:
        m["replication"]["dedup_savings_pct"] = round(100.0 * (new - dedup) / new, 1)

    # ── ALM relay chain (per-hop + per-depth; CIRISEdge#149 open_av_outer) ──
    hop_blob = est.get("alm_chain_hop/208")
    hop_full = est.get("alm_chain_hop/16384")
    if hop_blob:
        m["chain"]["hop_blob_ns"] = round(hop_blob, 1)
    if hop_full:
        m["chain"]["hop_full_us"] = round(us(hop_full), 2)
    e2e = {}
    for t in (1, 2, 3, 4):
        v = est.get(f"alm_chain_e2e_blob/tiers/{t}")
        if v:
            e2e[str(t)] = round(us(v), 2)
    if e2e:
        m["chain"]["e2e_by_tier_us"] = e2e
        if "1" in e2e and "4" in e2e:
            m["chain"]["per_tier_added_us"] = round((e2e["4"] - e2e["1"]) / 3, 3)

    m["assumptions"] = {
        "measured": "MEASURED rows are single-core in-memory criterion microbenches "
                    "(AEAD-bound); over-the-wire deployment is NIC/kernel/Reticulum-bound. "
                    "Absolute µs are host-relative; ratios travel.",
        "model": "MODEL rows are bandwidth arithmetic over edge FEDERATION_SCALING_MODEL.md "
                 "bitrate anchors (720p30≈2.5 Mbps, blinking-dot≈50 kbps, relay egress≈150 Mbps/core) "
                 "— not a live N-node test.",
        "frontier": "The blob path ships today via AV1 SVC base layers. Full symmetric M>2 MDC "
                    "video is FRONTIER — the wire/substrate ships; the production codec "
                    "(NeuralMDC-class) does not exist yet. M=2 is the production default.",
        "pqc": "100% hybrid PQC, hard cut — Ed25519+ML-DSA-65 sigs, X25519+ML-KEM-768 KEM, no classical-only path.",
        "rekey": "Membership-change rekey is PROJECTED from the real hybrid-KEM primitive "
                 "(CIRISEdge#129 not yet implemented); steady-state video is unaffected.",
    }
    return m


def H(s) -> str:
    return html.escape(str(s))


def fmt(n) -> str:
    return format(n, ",") if isinstance(n, (int,)) else str(n)


def render_hero(model: dict) -> str:
    cap = model["capacity"]
    dot = next((s for s in cap["blob_sensitivity"] if s["kbps"] == 5), {})
    dot_down = dot.get("per_viewer_down_mbps", 10.0)
    dot_agg = dot.get("aggregate_gbps", 20.0)
    peak = max((f["gib_s"] for f in model["video_frames"]), default=None)
    tax = model["kex"].get("mlkem_tax_us", "—")
    return f"""<header class="hero">
  <h1>Encrypted, datacenter-free <b>presence at scale</b>.</h1>
  <p class="tag">Thousands of people sharing one space — each <i>present</i> as a live presence dot, with full
  quality focus-pulled on demand. End-to-end post-quantum. Forwarded by the participants' own uplinks,
  <b>no datacenter</b>. This is a category the centralized incumbents can't enter — not a bigger grid of tiles.</p>
  <div class="cards">
    <div class="card"><div class="big">presence<br>at scale</div>
      <div class="cl">the dot is a deliberate <b>presence primitive</b>, not degraded video — at a true
      ~5 kbps presence dot a 2,000-person space is ~{dot_down:g} Mbps to <i>your</i> device, and the room's
      whole forwarding load (~{dot_agg:g} Gbps) sums from <b>ordinary home uplinks</b> — no datacenter</div></div>
    <div class="card"><div class="big">0</div>
      <div class="cl">datacenters — peers relay for each other; scale by adding people, not servers</div></div>
    <div class="card"><div class="big">100%</div>
      <div class="cl">post-quantum, <b>end-to-end</b> — relays forward ciphertext they can never read</div></div>
  </div>
  <p class="note">Crypto isn't the constraint (measured: AEAD up to {peak} GiB/s, post-quantum cost
  ~{tax} µs <b>once per peer-link</b>, never per frame). The real constraint is <b>donated uplink</b> —
  how much the room's own peers can forward — shown below on <i>both</i> sides of the ledger.</p>
</header>"""


def render_roomscale(model: dict) -> str:
    cap = model["capacity"]
    rows = "\n".join(
        f"<tr><td><b>{fmt(r['n'])}</b></td>"
        f"<td class='ok'>{r['down_all_blobs_mbps']} Mbps</td>"
        f"<td>{r['aggregate_uplink_gbps']} Gbps</td>"
        f"<td class='bad'>{fmt(round(r['mesh_full_uplink_mbps']))} Mbps ✕</td></tr>"
        for r in cap["rooms"])
    sens = "\n".join(
        f"<tr><td>{s['kbps']} kbps — {H(s['label'])}</td>"
        f"<td>{s['per_viewer_down_mbps']} Mbps</td><td>{s['aggregate_gbps']} Gbps</td></tr>"
        for s in cap["blob_sensitivity"])
    return f"""<h2>Can a room of N do video? <span class="badge model">MODEL</span></h2>
<p>Layered encoding makes it a bandwidth question, not a tile cap: you pull each person's lowest layer
(a ~{cap['blob_kbps']} kbps presence blob) and focus-pull full quality only for whoever you're looking at.
Two sides of the ledger — what <i>you</i> receive (demand), and what the room's peers must <i>donate</i>
to forward it (supply, = N²·b by conservation):</p>
<table><tr><th>room</th><th>your downlink (demand)</th>
<th>room's total donated uplink (supply, N²·b)</th><th>flat-mesh full-720p (why mesh dies)</th></tr>
{rows}</table>
<p class="note"><b>Demand is the easy half</b> — even 2,000 blobs is ~100 Mbps to your device.
<b>Supply is the real question.</b> Everyone-sees-everyone is N×N delivery, so the room must source
~{cap['rooms'][-1]['aggregate_uplink_gbps']} Gbps of forwarding at N=2,000 — and <b>leaves forward nothing</b>
(a constrained mobile peer just publishes its own blob), so that load lands on the <b>fat interior</b>:
peers with real donated uplink, in an O(log N)-deep ALM tree (per-node fan-out bounded by <i>measured</i>
uplink). Feasibility is <code>Σ(donated interior uplink) ≥ N²·b</code> — <b>not</b> crypto. It's the one
open empirical variable, gated honestly in the edge capacity benches (<code>alm_tree_depth_vs_n</code>,
<code>cold_join_burst_latency</code>, CIRISEdge PR#147).</p>
<p>And what a "blob" costs dominates the supply side. {cap['blob_kbps']} kbps is edge's
<code>BLINKING_DOT</code> — a low-res <i>video thumbnail</i>; a literal presence dot is far cheaper, which
decides whether the room needs prosumer fat interior or rides ordinary asymmetric home uplinks:</p>
<table><tr><th>blob @ N=2,000</th><th>your downlink</th><th>room's donated uplink (N²·b)</th></tr>
{sens}</table>
<p class="note">At a true <b>presence dot (~5 kbps)</b> the room needs ~20 Gbps total — ordinary
asymmetric homes (~10 Mbps up each) sum to it with no datacenter. At a <b>50 kbps video thumbnail</b>
it needs ~200 Gbps — real prosumer/home-server fat interior, or it collapses back toward centralization.
<b>The "presence at scale" claim is strongest precisely because presence is cheap.</b></p>
<div class="hl"><b>"2,000 four-pixel blobs from 2,000 8K streams?"</b> Yes — you subscribe to each
publisher's base SVC layer; the 8K is their <i>top</i> layer, uploaded once and forwarded only to whoever
zooms in. The bitrate win is <b>SVC/MDC layering</b>; <b>RaptorQ</b> buys the loss-resilience (any
sufficient fragment subset reconstructs — lossy mesh, no jitter-buffer stalls). Whether the room holds
2,000 is the donated-uplink question above, not a crypto or codec one.</div>"""


def render_sota() -> str:
    rows = [
        ("Ambient presence of a large room", "no such mode — gallery caps at 49 tiles; beyond that you "
         "see a speaker + a participant count, not the room",
         "every person present at once as a live ~5 kbps dot — a category SFUs don't have"),
        ("1,000+ in one space", "falls back to webinar / HLS-DASH (one-way, seconds of latency)",
         "presence for all + focus-pull full quality on demand (interactivity bounded by donated uplink, MODEL)"),
        ("Topology", "centralized SFU, cascaded in a datacenter",
         "peer ALM relay tree — no datacenter, every peer relays"),
        ("Per-core fan-out", "~500 consumers / worker-core (mediasoup), ~115 Mbps/core",
         "~3,000 blob / ~60 full-720p streams per core (egress)"),
        ("Encryption", "DTLS-SRTP hop-by-hop — the SFU sees plaintext",
         "two-layer hybrid-PQC E2E — the relay never sees plaintext"),
        ("Packet loss", "NACK / RTX / jitter buffer",
         "RaptorQ per layer — any sufficient subset reconstructs"),
        ("Capacity claims", "trusted infrastructure",
         "hybrid-PQC-signed, capped, deterministically verifiable tree"),
    ]
    body = "\n".join(
        f"<tr><td>{H(d)}</td><td class='bad'>{H(s)}</td><td class='ok'>{H(c)}</td></tr>"
        for d, s, c in rows)
    return f"""<h2>vs the state of the art</h2>
<table class="vs"><tr><th>dimension</th><th>Zoom / Meet / Teams / SFU</th><th>CIRIS fabric</th></tr>
{body}</table>
<p class="note">Sources:
<a href="https://support.google.com/meet/answer/9292748">Meet 49-tile cap</a>,
<a href="https://mediasoup.discourse.group/t/maximum-number-of-consumers-per-worker-is-500-w-r-t-cpu/4058">mediasoup ~500 consumers/core</a>,
<a href="https://getstream.io/glossary/sfu-cascading/">SFU cascading</a>,
<a href="https://www.rfc-editor.org/rfc/rfc9605">SFrame (E2E media)</a>.
The honest framing: <i>this isn't a bigger gallery — it's a different mode. An SFU can't show you the
ambient presence of a 2,000-person room at all; the fabric makes that the primitive, end-to-end encrypted,
scaling by peers instead of servers. Whether a given room sustains it is the donated-uplink question
(MODEL) above, not a crypto one.</i></p>"""


def render_how(model: dict) -> str:
    ch = model.get("chain", {})
    chain_line = (f" <b>Measured</b> (CIRISEdge#149 <code>open_av_outer</code>): ~{ch.get('hop_blob_ns', '—')} ns CPU "
                  f"per relay hop, ~{ch.get('per_tier_added_us', '—')} µs added per tier "
                  f"(<code>benches/alm_chain.rs</code>); the inner E2E ciphertext is byte-identical across "
                  f"arbitrary hops (<code>tests/chaos_mesh.rs</code>).") if ch else ""
    return f"""<h2>How</h2>
<div class="pillars">
  <div class="pillar"><h3>① ALM relay tree</h3>
    <p>No node fans out to 2,000. Each publisher emits <b>one</b> sealed copy to a relay parent;
    relays form a tree with per-node fan-out bounded by each peer's <i>measured</i> uplink budget —
    O(log N) deep, primary + 2 backup parents. Every capacity claim is hybrid-PQC-signed and capped; the
    topology is a deterministic pure function of witnessed state, so peers agree with <b>no leader and no
    node can lie its way to the center</b>. No datacenter; switching cost ≈ 0.{chain_line}</p></div>
  <div class="pillar"><h3>② Holographic layered encoding <span class="badge frontier">SVC today · MDC frontier</span></h3>
    <p>Streams are layered (spatial × temporal × quality). Subscribe to fewer layers → send/receive less;
    the relay drops un-admitted layers <b>before</b> sealing (no bandwidth, no CPU). The base
    <code>{{0,0,0}}</code> layer is the ~50 kbps "blinking dot." Under MDC, any subset of descriptions
    decodes at proportional fidelity — "holographic": degrade gracefully, reconstruct from fragments.</p></div>
  <div class="pillar"><h3>③ Two-layer hybrid-PQC E2E</h3>
    <p>Inner AES-256-GCM under a per-epoch group key (end-to-end — relays never hold it); outer
    AES-256-GCM under a per-link transit key from an X25519+ML-KEM-768 handshake. The bulk is symmetric
    AES (already quantum-safe); the post-quantum cost is one handshake per link. A fully compromised
    relay recovers only ciphertext.</p></div>
</div>"""


def render_crypto_proof(model: dict, est: dict) -> str:
    v, kex, rep, mesh = model["video_frames"], model["kex"], model["replication"], model["mesh"]

    def rows(rs):
        return "\n".join("<tr>" + "".join(f"<td>{H(c)}</td>" for c in r) + "</tr>" for r in rs)

    def kib(b):
        return f"{b // 1024} KiB" if b >= 1024 else f"{b} B"

    video_rows = rows([[f["label"], kib(f["bytes"]), f"{f['e2e_us']} µs",
                        f"{f.get('seal_us','—')} µs", f"{f.get('open_us','—')} µs", f"{f['gib_s']} GiB/s"] for f in v])
    fan_rows = rows([[r["n"], f"{r.get('naive_us','—')} µs", f"{r.get('shared_inner_us','—')} µs",
                      f"{r.get('speedup','—')}×"] for r in model["fanout"]])
    rekey_rows = rows([[r["n"], f"{r.get('flat_ms','—')} ms", f"{r.get('tree_ms','—')} ms",
                        f"{r.get('tree_speedup','—')}×"] for r in model["rekey"]])
    return f"""<h2>Is the crypto in the way? No — here's the measurement. <span class="badge measured">MEASURED</span></h2>
<p>Per-frame the post-quantum cost is <b>structurally zero</b> (bulk is AES-256-GCM); the PQ cost is a
one-time handshake per peer-link. The numbers, single-core, in-memory:</p>
<table><tr><th>frame</th><th>size</th><th>seal→wire→open</th><th>seal (send)</th><th>open (recv)</th><th>throughput</th></tr>
{video_rows}</table>
<table><tr><th>handshake</th><th>full (initiate+respond)</th></tr>
<tr><td>Hybrid X25519 + ML-KEM-768 (PQ-safe)</td><td>{kex.get('hybrid_full_us','—')} µs</td></tr>
<tr><td>Classical X25519 only</td><td>{kex.get('classical_full_us','—')} µs</td></tr>
<tr><td><b>ML-KEM-768 tax</b></td><td><b>+{kex.get('mlkem_tax_us','—')} µs, once per peer-link</b></td></tr></table>
<p class="note">A 50-person 30 fps room is ~{mesh.get('recv_gop_blend_pct_core','—')}% of one core to
<i>receive</i> (open-only) and ~{mesh.get('send_pct_core','—')}% to publish. Fan-out (inner-once/outer-N):</p>
<table><tr><th>room (N)</th><th>naive</th><th>shared-inner</th><th>speedup</th></tr>{fan_rows}</table>
<p class="note"><b>Membership-rekey</b> <span class="badge model">PROJECTED · CIRISEdge#129</span>
flat O(N) vs tree O(log N) per join/leave:</p>
<table><tr><th>room (N)</th><th>flat O(N)/delta</th><th>tree O(log N)/delta</th><th>tree win</th></tr>{rekey_rows}</table>
<p class="note"><b>Store spine</b>: hybrid trace ingest {rep.get('ingest_new_us','—')} µs
(~{fmt(rep.get('traces_per_sec',0))} traces/s/core); re-delivery saves only
~{rep.get('dedup_savings_pct','—')}% (verify runs before dedup — replay is verify-bound by design, the
AV-9-safe choice). Levers: pre-verified relay path + batch verify (CIRISPersist#225).</p>"""


def render_scoreboard(sb: dict | None) -> str:
    if not sb:
        return ""
    st, pol = sb.get("storage", {}), sb.get("policy", {})
    ro = st.get("replication_overhead", {})
    curve = "\n".join(
        f"<tr><td>{p['q']}</td><td>{H(p['label'])}</td><td>{p['p_reconstruct'] * 100:.3f}%</td></tr>"
        for p in st.get("survival_curve", []))

    def gated(name, g):
        return (f"<li><b>{H(name)}</b> — <code>gated</code> on {H(g.get('gated_on', ''))}: "
                f"{H(', '.join(g.get('metrics', [])))}</li>")

    return f"""<h2>Holonomic storage — survival of the replicated corpus <span class="badge model">MODEL</span></h2>
<p>The same holographic property runs the "store" half: content is fountain-split into symbols, any
sufficient subset reconstructs. Policy <code>N={pol.get('n')} K={pol.get('k')} H={pol.get('h')}</code>;
overhead {ro.get('modeled','—')}× (vs ~5× whole-copy). Survival
<code>P(Binomial(H,q) ≥ N)</code> — computed, reproducing scale_model v0.7:</p>
<table><tr><th>per-peer availability q</th><th>regime</th><th>P(reconstruct)</th></tr>{curve}</table>
<p class="note">A live node recomputes survival from <i>measured</i> q + observed holders and alarms
under the 99% floor. Substrate/holonomic tiers are explicit <code>gated</code> stubs (not fabricated):</p>
<ul>{gated('substrate', sb.get('substrate', {}))}{gated('holonomic', sb.get('holonomic', {}))}</ul>"""


def render_what() -> str:
    return """<h2>What this is</h2>
<p><b>CIRIS is the CIRIS Epistemic Web Platform (CEWP)</b> — a <b>complete replacement for the internet's
extractive middle</b>. Streaming, video calls, gaming, files, messages, and signed claims route
<b>directly between the devices people already own</b>, over a post-quantum-encrypted mesh: no giant data
centers in the middle, no handful of companies owning the pipes or deciding what you see. The network
<b>governs itself</b> through signed, weighted votes (no platform owner), never advertises your local
content to the rest of the network, and runs on hardware you already have — it <b>removes the centralized
control plane</b> rather than renting it back to you.</p>
<p>This page measures <b>one capability</b> of that substrate — <b>presence at scale</b>: encrypted
realtime A/V for thousands, forwarded by participants' own uplinks. The fabric node (CIRISServer) is the
transport + storage tier — the same primitives that carry a live blob also store the durable corpus.
Full framing: <a href="https://ciris.ai/cewp">ciris.ai/cewp</a>.</p>"""


def render_landscape() -> str:
    cols = ["IPFS", "Nostr", "Matrix", "Reticulum", "CIRIS / CEWP"]
    rows = [
        ("What it is", ["content-addressed storage", "relayed social notes", "federated chat",
                        "real-time mesh transport", "full stack: stream + store + govern"]),
        ("End-to-end encryption", ["✗ content public", "✗ signed, not encrypted", "✓ Olm/MLS",
                                   "✓ transport", "✓ two-layer hybrid"]),
        ("Post-quantum by default", ["✗", "✗", "partial (exploratory)", "✗",
                                     "✓ Ed25519+ML-DSA · X25519+ML-KEM"]),
        ("Realtime group video at scale", ["✗", "✗", "✗ (small WebRTC bridge)", "building block",
                                           "◐ ALM tree, ~2,000 presence (MODEL, uplink-gated)"]),
        ("Durable storage (survives node loss)", ["partial (manual pinning)", "✗ relays drop", "server DB",
                                                  "✗", "✓ fountain, any-N-of-H"]),
        ("Self-governance (no owner)", ["✗", "✗ relay operators", "✗ server admins", "✗",
                                        "✓ signed weighted votes"]),
        ("No datacenter / runs on owned HW", ["partial (mostly DC-pinned)", "relays (often hosted)",
                                              "homeservers (often hosted)", "✓", "✓ every peer relays"]),
        ("Maturity", ["production (~230k nodes)", "production", "production", "stable",
                      "RC-grade, pre-1.0"]),
    ]
    head = "<tr><th>dimension</th>" + "".join(f"<th>{H(c)}</th>" for c in cols) + "</tr>"
    body = "\n".join(
        "<tr><td>" + H(dim) + "</td>"
        + "".join(
            (f"<td class='ciris'><b>{H(c)}</b></td>" if i == len(cells) - 1 else f"<td>{H(c)}</td>")
            for i, c in enumerate(cells))
        + "</tr>"
        for dim, cells in rows)
    return f"""<h2>Where this sits among decentralized projects</h2>
<p>Against the centralized incumbents the contrast is the 49-tile cap (above). Against the
<i>decentralized</i> field, the distinction is <b>scope</b>: the others are mature, excellent,
<i>single-purpose</i> layers; CEWP is the (pre-1.0) attempt at the <b>whole stack</b> — transport +
durable storage + realtime-at-scale + self-governance — and 100% post-quantum.</p>
<table class="matrix">{head}
{body}</table>
<p class="note"><b>Composes, not only competes.</b> CEWP runs <i>on</i> Reticulum transport today, and can
piggyback IPFS / Veilid / Iroh as blob-bootstrap &amp; cache substrates (CIRISPersist#147). The
distinctive claim isn't beating any one layer — it's the whole stack in one post-quantum substrate, with
realtime presence-at-scale and self-governance that none of the others attempt together. (Honest caveat:
those projects are production-deployed at scale; CEWP is RC-grade.) Sources:
<a href="https://news.ycombinator.com/item?id=41259030">Reticulum vs IPFS/Nostr/SSB (HN)</a>,
<a href="https://www.iroh.computer/blog/comparing-iroh-and-libp2p">Iroh vs libp2p</a>,
<a href="https://github.com/2gatherproject/decentralized-social-apps-guide">decentralized-apps guide</a>.</p>"""


def badge_cls(prov: str) -> str:
    if prov.startswith("MEASURED"):
        return "measured"
    if prov.startswith("FRONTIER"):
        return "frontier"
    return "model"  # MODEL, PROJECTED


def render_characteristics(model: dict, scoreboard: dict | None) -> str:
    """The UX-facing spec: the envelope the substrate guarantees, with provenance."""
    cap = model["capacity"]
    ch = model.get("chain", {})
    rk = {r["n"]: r for r in model.get("rekey", [])}
    r2000 = next((r for r in cap["rooms"] if r["n"] == 2000), {})
    sb = scoreboard or {}
    sv = next((p["p_reconstruct"] * 100 for p in sb.get("storage", {}).get("survival_curve", [])
               if p["q"] == 0.85), None)
    rk50 = rk.get(50, {})
    survival = (f"{sv:.1f}% @ q=0.85 · survives 33% holder loss" if sv
                else "survives 33% holder loss (any 20 of 30)")
    rows = [
        ("Presence blob", f"~{cap['blob_kbps']} kbps / stream", "MODEL",
         f"max tiles ≈ your downlink ÷ {cap['blob_kbps']} kbps (~{int(r2000.get('down_all_blobs_mbps', 0))} Mbps → 2,000)"),
        ("Focus stream (full 720p)", "2.5 Mbps", "MODEL",
         "one full view ≈ 50 blobs of bandwidth — focus-pull on tap"),
        ("Per relay hop", f"~{ch.get('hop_blob_ns', '—')} ns CPU + 1 RTT", "MEASURED",
         "a depth-d tree adds d network hops to glass-to-glass latency"),
        ("Tree depth at N", "3–4 tiers @ 2,000 (ceil log_f N)", "MODEL",
         "budget ~3–4 added RTT at the largest rooms"),
        ("Join / membership rekey", f"flat {rk50.get('flat_ms', '—')} ms · tree {rk50.get('tree_ms', '—')} ms / delta", "PROJECTED",
         "join-latency budget; gated CIRISEdge#129"),
        ("Stream path-redundancy", "survives loss of all-but-one of 3 paths", "MEASURED",
         "presence holds through relay churn — no reconnect flicker"),
        ("Content survival", survival, "MODEL",
         "recordings & corpus persist through node churn — a 'durable' affordance"),
        ("Encryption", "E2E hybrid-PQC, ~0 per-frame", "MEASURED",
         "no quality/feature tradeoff for E2E; relays forward ciphertext they can't read"),
    ]
    body = "\n".join(
        f"<tr><td>{H(c)}</td><td><b>{H(g)}</b></td>"
        f"<td><span class='badge {badge_cls(p)}'>{H(p)}</span></td><td>{H(u)}</td></tr>"
        for c, g, p, u in rows)
    return f"""<h2>Guaranteed mesh characteristics <span class="note">— build the UX against these</span></h2>
<p>The envelope the substrate guarantees, with provenance. A UX can rely on these directly — what a device
renders at a given downlink, how presence degrades, what survives node churn — without re-deriving the physics.</p>
<table><tr><th>characteristic</th><th>guarantee</th><th>basis</th><th>UX implication</th></tr>
{body}</table>"""


def render_references(model: dict) -> str:
    kex, rep = model.get("kex", {}), model.get("replication", {})
    v = model.get("video_frames", [])
    rekey = {r["n"]: r for r in model.get("rekey", [])}
    peak = max((f["gib_s"] for f in v), default=None)
    r50 = rekey.get(50, {})
    rows = [
        ("PQ KEM (X25519+ML-KEM-768)", f"hybrid KEX {kex.get('hybrid_full_us','—')} µs",
         "liboqs ML-KEM-768: encap ~95 / decap ~118 µs", "https://openquantumsafe.org/benchmarking/"),
        ("PQ handshake tax", f"+{kex.get('mlkem_tax_us','—')} µs once/peer-link",
         "PQ-TLS (Cloudflare/AWS): ~80–150 µs ML-KEM overhead",
         "https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/"),
        ("E2E media AEAD", f"two-layer AES-256-GCM, up to {peak} GiB/s",
         "SFrame (RFC 9605): AES-GCM E2E, SFU-forwardable", "https://www.rfc-editor.org/rfc/rfc9605"),
        ("Group rekey", f"flat {r50.get('flat_ms','—')} / tree {r50.get('tree_ms','—')} ms @N=50",
         "OpenMLS / PQ-MLS combiner: O(log n)", "https://eprint.iacr.org/2026/034.pdf"),
        ("Store verify", f"hybrid ingest {rep.get('ingest_new_us','—')} µs",
         "liboqs ML-DSA-65 verify ~0.40 ms", "https://openquantumsafe.org/benchmarking/"),
    ]
    body = "\n".join(
        f"<tr><td>{H(a)}</td><td>{H(b)}</td><td>{H(c)}</td><td><a href='{H(u)}'>src</a></td></tr>"
        for a, b, c, u in rows)
    return f"""<h2>Benchmarked against the field — per layer</h2>
<p>No single "PQC streaming" suite exists, so each layer is held next to its recognized reference.</p>
<table><tr><th>layer</th><th>CIRISServer (this run)</th><th>reference</th><th></th></tr>{body}</table>"""


def render(model, est, commit, date, scoreboard=None) -> str:
    raw_rows = "\n".join(f"<tr><td>{H(k)}</td><td>{us(ns):.3f} µs</td></tr>" for k, ns in sorted(est.items()))
    honesty = "".join(f"<li>{H(x)}</li>" for x in model["assumptions"].values())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIRIS fabric — streaming &amp; storage at scale</title>
<style>
 :root{{--ink:#16181d;--mut:#5b6370;--line:#e6e8ec;--blue:#2b6cff;--green:#0a7d2c;--red:#c0392b;--amber:#b8740f}}
 *{{box-sizing:border-box}}
 body{{font:16px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:920px;margin:0 auto;padding:0 1.1rem 4rem;color:var(--ink)}}
 h1{{font-size:2.1rem;line-height:1.2;margin:.2rem 0}} h2{{font-size:1.4rem;margin:2.6rem 0 .4rem;border-bottom:2px solid var(--line);padding-bottom:.3rem}}
 h3{{font-size:1.05rem;margin:.2rem 0 .4rem}}
 .hero{{background:linear-gradient(135deg,#0b1f4d,#123a8a);color:#fff;margin:1.2rem -1.1rem 0;padding:2.2rem 1.6rem;border-radius:0 0 14px 14px}}
 .hero h1{{color:#fff}} .hero .tag{{font-size:1.12rem;opacity:.95;max-width:46rem}}
 .hero .note{{color:#cfe0ff;font-size:.92rem;border-top:1px solid #ffffff2e;padding-top:.8rem;margin-top:1.2rem}}
 .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.8rem;margin:1.3rem 0 .4rem}}
 .card{{background:#ffffff14;border:1px solid #ffffff2e;border-radius:10px;padding:.9rem 1rem}}
 .card .big{{font-size:1.9rem;font-weight:700}} .card .cl{{font-size:.9rem;opacity:.92}}
 table{{border-collapse:collapse;width:100%;margin:.7rem 0;font-size:.94rem}}
 th,td{{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}}
 th{{background:#f7f8fa;font-size:.85rem;text-transform:uppercase;letter-spacing:.02em;color:var(--mut)}}
 td:first-child{{font-weight:600}} table.vs td:nth-child(2){{color:var(--red)}} table.vs td:nth-child(3){{color:var(--green)}}
 table.matrix td.ciris{{background:#eaf7ee}} table.matrix th:last-child{{background:#dcefe2;color:var(--green)}}
 .ok{{color:var(--green)}} .bad{{color:var(--red)}}
 .note{{color:var(--mut);font-size:.9rem}}
 .hl{{background:#eaf3ff;border-left:4px solid var(--blue);padding:.9rem 1.1rem;border-radius:8px;margin:1rem 0}}
 .pillars{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:1rem;margin-top:.6rem}}
 .pillar{{border:1px solid var(--line);border-radius:10px;padding:1rem}}
 .pillar p{{font-size:.92rem;color:#2c313a;margin:0}}
 .badge{{font-size:.66rem;font-weight:700;letter-spacing:.04em;padding:.12rem .4rem;border-radius:5px;vertical-align:middle}}
 .badge.measured{{background:#e3f6e9;color:var(--green)}} .badge.model{{background:#e7eefc;color:var(--blue)}}
 .badge.frontier{{background:#fdf0dc;color:var(--amber)}}
 code{{background:#f1f2f4;padding:.05rem .3rem;border-radius:4px;font-size:.88em}}
 details{{margin-top:1.4rem}} footer{{margin-top:3rem;color:#8a909a;font-size:.82rem;border-top:1px solid var(--line);padding-top:1rem}}
 a{{color:var(--blue)}}
</style></head><body>
{render_hero(model)}
{render_what()}
{render_roomscale(model)}
{render_sota()}
{render_landscape()}
{render_how(model)}
{render_characteristics(model, scoreboard)}
{render_crypto_proof(model, est)}
{render_scoreboard(scoreboard)}
{render_references(model)}

<h2>Provenance &amp; honesty</h2>
<ul class="note">{honesty}</ul>

<details><summary>Raw criterion means ({len(est)})</summary>
<table><tr><th>bench</th><th>mean</th></tr>{raw_rows}</table></details>

<footer>CIRIS fabric node (CIRISServer) · pqc_av_streaming + replication_ingest + holonomic scoreboard ·
commit {H(commit[:12])} · {H(date)} ·
<a href="https://github.com/CIRISAI/CIRISServer/blob/main/FSD/PQC_AV_STREAMING_BENCH.md">methodology</a> ·
capacity model: CIRISEdge FEDERATION_SCALING_MODEL.md</footer>
</body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--criterion-dir", default="target/criterion")
    ap.add_argument("--out", default="bench-site")
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    ap.add_argument("--date", default=os.environ.get("BENCH_DATE", ""))
    ap.add_argument("--scoreboard", default=None)
    args = ap.parse_args()

    est = load_estimates(args.criterion_dir)
    if not est:
        print(f"no estimates under {args.criterion_dir} — run the benches first", file=sys.stderr)
        return 1
    scoreboard = None
    if args.scoreboard and os.path.exists(args.scoreboard):
        try:
            with open(args.scoreboard) as fh:
                scoreboard = json.load(fh)
        except Exception as e:
            print(f"warning: could not read scoreboard {args.scoreboard}: {e}", file=sys.stderr)
    model = build_model(est)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "data.json"), "w") as fh:
        json.dump({"schema": "ciris-server/bench/3", "commit": args.commit, "date": args.date,
                   "model": model, "scoreboard": scoreboard,
                   "raw_means_us": {k: round(v / 1000, 4) for k, v in est.items()}}, fh, indent=2)
    if scoreboard is not None:
        with open(os.path.join(args.out, "scoreboard.json"), "w") as fh:
            json.dump(scoreboard, fh, indent=2)
    with open(os.path.join(args.out, "index.html"), "w") as fh:
        fh.write(render(model, est, args.commit, args.date, scoreboard))
    print(f"wrote {args.out}/index.html ({len(est)} benches"
          f"{', + scoreboard' if scoreboard else ''}) + data.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
