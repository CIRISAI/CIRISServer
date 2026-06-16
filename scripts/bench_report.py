#!/usr/bin/env python3
"""
Turn criterion's raw `target/criterion/**/estimates.json` into an INTERPRETED
benchmark page for CIRISServer — what the numbers MEAN (video throughput under
*stated* assumptions, membership-rekey cost, replication speed, post-quantum
overhead), not just ns.

Usage:
    cargo bench --bench pqc_av_streaming --bench replication_ingest
    python3 scripts/bench_report.py --out bench-site [--commit SHA --date ISO]

Emits  <out>/index.html  (the page) + <out>/data.json  (machine-readable).
Self-contained HTML, no external assets. Host-relative numbers — the ratios and
conclusions are what travel, not the absolute µs (stamped with the runner).

Honesty discipline (CEWP crux use case = stream AND store at massive scale):
  - Receivers are charged OPEN-ONLY (they don't re-seal what they receive).
  - Any blended "% of a core" figure names its GOP/fps model inline; per-size
    rows are shown so the reader sees the range, not one cherry-picked frame.
  - Membership-rekey is labelled PROJECTED (the substrate doesn't implement it
    yet — CIRISEdge#129); steady-state and churn costs are kept distinct.
"""
from __future__ import annotations
import argparse, glob, html, json, math, os, sys

MiB = 1024 * 1024
FPS = 30  # reference frame rate for all per-second utilisation figures

# Pinned video-encoding model (stated, not cherry-picked): 720p @30fps, GOP=30
# (one keyframe per second). Inter = 16 KiB "typical" (av_frame), keyframe = 64 KiB.
GOP = 30
KEYFRAME_BYTES = 64 * 1024
INTER_BYTES = 16 * 1024
MESH_N = 50  # the realtime mesh cap before the SFU/relay crossover (CIRISEdge#66)


def load_estimates(criterion_dir: str) -> dict[str, float]:
    """Map criterion bench id -> mean estimate in nanoseconds."""
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
    """ns of CPU spent per wall-second -> % of one core."""
    return round(100.0 * ns_per_sec / 1e9, 2)


FRAME_LABELS = {
    "320": "Opus voice frame (~20 ms @128 kbps)",
    "4096": "720p inter-frame (low motion)",
    "16384": "720p inter-frame (typical)",
    "65536": "1080p inter / 720p keyframe",
    "262144": "1080p keyframe",
}


def build_model(est: dict[str, float]) -> dict:
    """Compute the interpreted metrics from raw means."""
    m: dict = {"video_frames": [], "kex": {}, "fanout": [], "rekey": [],
               "mesh": {}, "replication": {}, "assumptions": {}}

    # ── Video: per-frame end-to-end + the seal/open split (sender/receiver) ──
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

    # ── Mesh fan-out (sender, 16 KiB) — realized inner-once/outer-N win ─────
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

    # ── HONEST 50-room cost @30fps — send (seal/fan-out) vs receive (open) ──
    open_inter = est.get(f"av_frame_halves/open/{INTER_BYTES}")
    open_key = est.get(f"av_frame_halves/open/{KEYFRAME_BYTES}")
    open_low = est.get(f"av_frame_halves/open/4096")
    send_50 = est.get(f"av_mesh_fanout/shared_inner/{MESH_N}")
    peers = MESH_N - 1
    if send_50:
        # publish one stream to 49 peers, every frame, 30 fps (16 KiB frame)
        m["mesh"]["send_pct_core"] = pct_core(FPS * send_50)
    if open_inter:
        # receive 49 inbound 16 KiB streams @30fps (open-only — the honest charge)
        m["mesh"]["recv_typical_pct_core"] = pct_core(peers * FPS * open_inter)
        m["mesh"]["max_recv_streams_30fps_core"] = round(1e9 / (FPS * open_inter))
    if open_low:
        m["mesh"]["recv_lowmotion_pct_core"] = pct_core(peers * FPS * open_low)
    if open_inter and open_key:
        # stated-GOP blend: 1 keyframe + (GOP-1) inter per second, ×49 receivers
        per_stream_sec = open_key + (GOP - 1) * open_inter
        m["mesh"]["recv_gop_blend_pct_core"] = pct_core(peers * per_stream_sec)
        m["mesh"]["gop_model"] = f"720p, {FPS} fps, GOP={GOP} (1×64 KiB keyframe + {GOP-1}×16 KiB inter per second), receiver opens {peers} streams"

    # ── Post-quantum KEX overhead (per peer-link, one-time) ────────────────
    h_i, h_r = est.get("pqc_kex/hybrid_initiate"), est.get("pqc_kex/hybrid_respond")
    c_i, c_r = est.get("pqc_kex/classical_initiate"), est.get("pqc_kex/classical_respond")
    if h_i and h_r:
        m["kex"]["hybrid_full_us"] = round(us(h_i + h_r), 1)
        m["kex"]["hybrid_initiate_us"] = round(us(h_i), 1)
    if c_i and c_r:
        m["kex"]["classical_full_us"] = round(us(c_i + c_r), 1)
    if h_i and h_r and c_i and c_r:
        m["kex"]["mlkem_tax_us"] = round(us((h_i + h_r) - (c_i + c_r)), 1)

    # ── Membership-change rekey (PROJECTED — CIRISEdge#129 unimplemented) ───
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
    # churn budget: a 50-room paying flat O(N) per delta, as % of a core per delta/s
    flat50 = est.get(f"av_rekey/flat_rewrap/{MESH_N}")
    if flat50:
        m["rekey_note"] = {
            "flat50_ms": round(flat50 / 1e6, 2),
            "pct_core_per_delta_per_sec": pct_core(flat50),  # one join/leave per second
            "frame_budget_pct": round(100.0 * flat50 / (1e9 / FPS), 1),  # vs one 33 ms frame
        }

    # ── Replication / corpus ingest (CEG-RC5 receive spine) ────────────────
    new = est.get("replication_ingest/ingest_new")
    dedup = est.get("replication_ingest/ingest_dedup")
    if new:
        m["replication"]["ingest_new_us"] = round(us(new), 2)
        m["replication"]["traces_per_sec"] = round(1e9 / new)
    if dedup:
        m["replication"]["dedup_us"] = round(us(dedup), 2)
        m["replication"]["dedup_per_sec"] = round(1e9 / dedup)
    if new and dedup:
        # the finding: re-delivery saves almost nothing because verify runs first
        m["replication"]["dedup_savings_pct"] = round(100.0 * (new - dedup) / new, 1)

    m["assumptions"] = {
        "cores": "single thread, one core; real deployments fan out across cores",
        "frames": "frame sizes are representative codec outputs, not a live encoder; "
                  "the GOP blend states its model inline",
        "receiver": "receivers are charged OPEN-ONLY — a node never re-seals frames it receives",
        "fps": f"{FPS} fps reference for all per-second / % -of-core figures",
        "rekey": "membership-change rekey is PROJECTED from the real hybrid-KEM primitive — "
                 "the substrate does not implement it yet (CIRISEdge#129); steady-state cost is unaffected",
        "scope": "crypto + wire-codec + persist spine (CIRISServer-owned); excludes the "
                 "RNS network hop (bandwidth/RTT-bound) and codec encode/decode",
        "pqc": "100% hybrid PQC, hard cut — Ed25519+ML-DSA-65 sigs, X25519+ML-KEM-768 KEM, no classical-only path",
    }
    return m


def H(s) -> str:
    return html.escape(str(s))


def render_references(model: dict) -> str:
    """Per-layer comparison to the recognized reference for each subsystem — the
    honest replacement for cross-tier 'SOTA' toy numbers. No single PQC-streaming
    suite exists; each layer is held next to its field reference."""
    kex = model.get("kex", {})
    rep = model.get("replication", {})
    v = model.get("video_frames", [])
    rekey = {r["n"]: r for r in model.get("rekey", [])}
    peak = max((f["gib_s"] for f in v), default=None)
    open16 = next((f.get("open_us") for f in v if f["bytes"] == 16384), None)
    r50 = rekey.get(50, {})
    rows = [
        ("PQ KEM primitive (X25519+ML-KEM-768)",
         f"hybrid KEX {kex.get('hybrid_full_us', '—')} µs (init {kex.get('hybrid_initiate_us', '—')} µs)",
         "liboqs ML-KEM-768: encap ~95 µs / decap ~118 µs",
         "https://openquantumsafe.org/benchmarking/"),
        ("PQ handshake tax (vs classical)",
         f"+{kex.get('mlkem_tax_us', '—')} µs once per peer-link",
         "PQ-TLS (Cloudflare/AWS): ~80–150 µs ML-KEM compute overhead",
         "https://aws.amazon.com/blogs/security/ml-kem-post-quantum-tls-now-supported-in-aws-kms-acm-and-secrets-manager/"),
        ("E2E media AEAD",
         (f"two-layer AES-256-GCM, up to {peak} GiB/s (open {open16} µs/16 KiB)" if peak else "—"),
         "SFrame (RFC 9605): AES-GCM E2E media, SFU-forwardable",
         "https://www.rfc-editor.org/rfc/rfc9605"),
        ("Group rekey on membership change",
         f"flat O(N) {r50.get('flat_ms', '—')} ms vs tree O(log N) {r50.get('tree_ms', '—')} ms @ N=50",
         "OpenMLS / PQ-MLS combiner: update sub-linear O(log n)",
         "https://eprint.iacr.org/2026/034.pdf"),
        ("Store-path signature verify",
         f"hybrid trace ingest {rep.get('ingest_new_us', '—')} µs (~{format(rep.get('traces_per_sec', 0), ',')}/s/core)",
         "liboqs ML-DSA-65 verify ~0.40 ms",
         "https://openquantumsafe.org/benchmarking/"),
    ]
    body = "\n".join(
        f"<tr><td>{H(layer)}</td><td>{H(ours)}</td><td>{H(ref)}</td><td><a href='{H(url)}'>src</a></td></tr>"
        for layer, ours, ref, url in rows)
    return f"""<h2>Benchmarked against the field — per layer</h2>
<p>There is no single "PQC streaming platform" suite to compare against, so each layer is held
next to its recognized reference. Absolute µs are host-relative; the ratios and the parity claim travel.</p>
<table><tr><th>layer</th><th>CIRISServer (this run)</th><th>reference</th><th></th></tr>
{body}</table>"""


def render_scoreboard(sb: dict | None) -> str:
    """Render the holonomic federation scoreboard (from `ciris-server scoreboard`)."""
    if not sb:
        return ""
    st = sb.get("storage", {})
    pol = sb.get("policy", {})
    ro = st.get("replication_overhead", {})
    curve = "\n".join(
        f"<tr><td>{p['q']}</td><td>{H(p['label'])}</td><td>{p['p_reconstruct'] * 100:.3f}%</td></tr>"
        for p in st.get("survival_curve", []))
    tiers = "\n".join(
        f"<tr><td>{H(t['tier'])}</td><td>{t['holders']}</td><td>{t['overhead_multiplier']}×</td></tr>"
        for t in st.get("degradation_tiers", []))

    def gated(name: str, g: dict) -> str:
        return (f"<li><b>{H(name)}</b> — <code>gated</code> on {H(g.get('gated_on', ''))}: "
                f"{H(', '.join(g.get('metrics', [])))}</li>")

    return f"""<h2>Holonomic federation scoreboard <span class="note">(CIRISServer#12/#13)</span></h2>
<p>Measured-vs-modeled capacity &amp; survival for the fountain-replicated corpus. Policy
<code>N={pol.get('n')} K={pol.get('k')} H={pol.get('h')}</code>. The survival curve is
<b>computed</b> (<code>P(Binomial(H,q) ≥ N)</code>) — it reproduces the scale_model v0.7 targets,
which is what makes "measured vs modeled" trustworthy.</p>
<table><tr><th>metric</th><th>modeled</th><th>alarm</th></tr>
<tr><td>replication overhead (H/N)</td><td>{ro.get('modeled', '—')}×</td><td>&gt;{ro.get('alarm_high', '—')}× / &lt;{ro.get('alarm_low', '—')}×</td></tr>
<tr><td>per-peer load (1/N)</td><td>{st.get('per_peer_load_frac', '—')}</td><td>&gt;0.10</td></tr>
<tr><td>active-eject threshold</td><td>{st.get('eject_threshold_holders', '—')} holders</td><td>H×1.15</td></tr>
<tr><td>survival floor / target @ q={st.get('design_q', '—')}</td><td>{st.get('survival_floor', '—')} / {st.get('survival_target', '—')}</td><td>&lt; floor</td></tr></table>
<p class="note"><b>Survival curve</b> — P(reconstruct) by per-peer availability q:</p>
<table><tr><th>q</th><th>regime</th><th>P(reconstruct)</th></tr>{curve}</table>
<p class="note"><b>Holographic degradation tiers</b> — capacity grows under pressure (sheds toward min_viable=5):</p>
<table><tr><th>tier</th><th>holders</th><th>overhead</th></tr>{tiers}</table>
<p class="note">Tiers not yet grounded — emitted as explicit stubs (the deliberate anti-toy-numbers posture), not fabricated:</p>
<ul>{gated('substrate', sb.get('substrate', {}))}{gated('holonomic', sb.get('holonomic', {}))}</ul>"""


def render(model: dict, est: dict, commit: str, date: str, scoreboard: dict | None = None) -> str:
    v = model["video_frames"]
    kex = model["kex"]
    rep = model["replication"]
    mesh = model["mesh"]
    refs_html = render_references(model)
    scoreboard_html = render_scoreboard(scoreboard)

    def rows(cells_list):
        return "\n".join("<tr>" + "".join(f"<td>{H(c)}</td>" for c in r) + "</tr>" for r in cells_list)

    def kib(b):
        return f"{b // 1024} KiB" if b >= 1024 else f"{b} B"

    video_rows = rows([[f["label"], kib(f["bytes"]), f"{f['e2e_us']} µs",
                        f"{f.get('seal_us','—')} µs", f"{f.get('open_us','—')} µs",
                        f"{f['gib_s']} GiB/s"] for f in v])
    fan_rows = rows([[f"{r['n']}", f"{r.get('naive_us','—')} µs", f"{r.get('shared_inner_us','—')} µs",
                      f"{r.get('speedup','—')}×"] for r in model["fanout"]])
    rekey_rows = rows([[f"{r['n']}", f"{r.get('flat_ms','—')} ms", f"{r.get('tree_ms','—')} ms",
                        f"{r.get('tree_speedup','—')}×"] for r in model["rekey"]])
    raw_rows = rows([[k, f"{us(ns):.3f} µs"] for k, ns in sorted(est.items())])

    # headline
    sub = []
    if v:
        peak = max(f["gib_s"] for f in v)
        sub.append(f"the steady-state frame path runs at up to {peak:.1f} GiB/s (AES-256-GCM — quantum-irrelevant at 256-bit)")
    if kex.get("mlkem_tax_us") is not None:
        sub.append(f"the post-quantum tax is ~{kex['mlkem_tax_us']:.0f} µs <b>once per peer-link</b>, never per frame")
    sub_html = "; ".join(sub) + "." if sub else ""

    rk = model.get("rekey_note", {})
    gop_line = ""
    if mesh.get("recv_gop_blend_pct_core") is not None:
        gop_line = (f"<p class='big'>A 50-person room costs ~{mesh['recv_gop_blend_pct_core']}% of one core to receive</p>"
                    f"<p class='note'>…under a <b>stated</b> model: {H(mesh.get('gop_model',''))}. "
                    f"Range across motion: ~{mesh.get('recv_lowmotion_pct_core','—')}% (low-motion 4 KiB) "
                    f"to ~{mesh.get('recv_typical_pct_core','—')}% (typical 16 KiB), receive-only. "
                    f"Publishing one stream to the room is ~{mesh.get('send_pct_core','—')}% of a core. "
                    f"Crypto is nowhere near the bottleneck — bandwidth and the network are.</p>")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIRISServer — benchmarks, interpreted</title>
<style>
 body{{font:16px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:880px;margin:2.2rem auto;padding:0 1.1rem;color:#1a1a1a}}
 h1{{font-size:1.7rem;margin:.2rem 0}} h2{{margin-top:2.2rem;border-bottom:2px solid #eee;padding-bottom:.3rem}}
 .lead{{font-size:1.15rem;background:#f0f7ff;border-left:4px solid #2b7cff;padding:.8rem 1rem;border-radius:6px}}
 table{{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.95rem}}
 th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee}} th{{background:#fafafa}}
 td:nth-child(n+2){{font-variant-numeric:tabular-nums}}
 .note{{color:#555;font-size:.9rem}} .big{{font-size:1.35rem;font-weight:600;color:#0a7d2c}}
 .warn{{background:#fff7e6;border-left:4px solid #e69500;padding:.6rem .9rem;border-radius:6px;font-size:.95rem}}
 code{{background:#f4f4f4;padding:.05rem .3rem;border-radius:3px}}
 details{{margin-top:1rem}} footer{{margin-top:2.5rem;color:#888;font-size:.85rem;border-top:1px solid #eee;padding-top:.8rem}}
</style></head><body>
<h1>CIRISServer — benchmarks, interpreted</h1>
<p class="note">The CEWP crux use case — <b>stream and store at massive scale</b> — measured and
interpreted. Receivers are charged open-only; every blended figure names its model. Raw criterion
numbers at the bottom. Absolute µs are host-relative (this run's runner); the ratios and ceilings travel.</p>
<p class="lead"><b>PQC group video is effectively free at steady state.</b> {sub_html}</p>

<h2>Video throughput — realtime A/V mesh (two-layer hybrid-PQC)</h2>
<p>Per frame: inner AES-256-GCM (E2E epoch DEK) → wire codec → outer AES-256-GCM (per-Link transit
key). <code>seal</code> is the sender's cost; <code>open</code> is the receiver's (it never re-seals).</p>
<table><tr><th>Frame</th><th>size</th><th>seal→wire→open</th><th>seal (send)</th><th>open (recv)</th><th>throughput</th></tr>
{video_rows}</table>
{gop_line}

<h2>Post-quantum overhead — the hybrid handshake (per peer-link, one-time)</h2>
<p>The only place the post-quantum cost can live: bulk frames are AES-256-GCM (already quantum-fine),
so the PQ cost is structurally confined to the KEM at session setup. Per-frame PQC cost is zero.</p>
<table><tr><th>handshake</th><th>full (initiate+respond)</th></tr>
<tr><td>Hybrid X25519 + ML-KEM-768 (PQ-safe)</td><td>{kex.get('hybrid_full_us','—')} µs</td></tr>
<tr><td>Classical X25519 only</td><td>{kex.get('classical_full_us','—')} µs</td></tr>
<tr><td><b>ML-KEM-768 tax</b></td><td><b>+{kex.get('mlkem_tax_us','—')} µs, once per peer-link</b></td></tr></table>

<h2>Mesh fan-out — sender cost per frame (16 KiB)</h2>
<p><code>naive</code> = N× full <code>seal_av_chunk</code>. <code>shared_inner</code> = v3.7.0's
<code>seal_av_inner</code> once + <code>seal_av_outer</code> per Link (CIRISEdge#122) — wire-identical,
inner AEAD done once.</p>
<table><tr><th>room (N)</th><th>naive</th><th>shared-inner</th><th>speedup</th></tr>
{fan_rows}</table>

<h2>Membership-change rekey — the churn path <span class="note">(projected)</span></h2>
<div class="warn">⚠ <b>Projected, not implemented.</b> The substrate does not yet rekey on join/leave
(CIRISEdge#129 — <code>EpochDek</code> has no ratchet; epoch rotation is owned out-of-module). These
numbers project the <i>intended</i> cost from the real hybrid-KEM <code>key_grant</code> wrap. They
are the answer to "is rekey-on-membership-change affordable?" — not a measurement of shipped code.</div>
<p>Each join/leave rewraps the fresh epoch DEK to the member-set. <code>flat</code> = O(N) (the
unicast-mesh baseline, #129). <code>tree</code> = O(log N) (the TreeKEM optimization, needs multicast,
#66). The outer per-Link key is <b>not</b> re-KEX'd on churn (KEX is one-shot per session).</p>
<table><tr><th>room (N)</th><th>flat O(N) / delta</th><th>tree O(log N) / delta</th><th>tree win</th></tr>
{rekey_rows}</table>
{f'''<p class="note">A 50-room paying the flat baseline spends ~{rk.get('flat50_ms')} ms per membership
delta — ~{rk.get('frame_budget_pct')}% of a single {int(1000/FPS)} ms frame, or ~{rk.get('pct_core_per_delta_per_sec')}%
of a core at one join/leave per second. Affordable even unoptimized; the tree (#66) removes it as a concern.
Steady-state video is untouched by churn.</p>''' if rk else ""}

<h2>Replication speed — CEG-RC5 corpus ingest (the "store" spine)</h2>
<p>What a node pays per replicated trace: Ed25519 verify → decompose → persist (5-tuple
<code>ON CONFLICT DO NOTHING</code> dedup — not a content-hash lookup).</p>
<table><tr><th>path</th><th>per trace</th><th>throughput</th></tr>
<tr><td>new trace (insert — replication intake)</td><td>{rep.get('ingest_new_us','—')} µs</td><td>{format(rep.get('traces_per_sec',0),',')} traces/s/core</td></tr>
<tr><td>re-delivery (dedup — anti gossip-loop)</td><td>{rep.get('dedup_us','—')} µs</td><td>{format(rep.get('dedup_per_sec',0),',')} /s/core</td></tr></table>
<p class="note"><b>The finding:</b> re-delivery saves only ~{rep.get('dedup_savings_pct','—')}% over a fresh
insert — because <b>verify runs before dedup</b>, a duplicate still pays full Ed25519 verification. So a
replay / gossip flood is bounded by verify throughput, not a cheap reject. This is <b>deliberate</b>
(verify-before-mutation; reordering dedup ahead of verify is an AV-9 suppression oracle — the dedup key
is attacker-controllable). The scale levers are the pre-verified relay path
(<code>VerifyMode::TrustPreVerified</code> gated on an Edge <code>verify_outcome</code>) and batch
verification (CIRISPersist#225) — not dedup-first.</p>

{refs_html}

{scoreboard_html}

<h2>Assumptions</h2>
<ul>{''.join(f'<li>{H(x)}</li>' for x in model['assumptions'].values())}</ul>

<details><summary>Raw criterion means ({len(est)})</summary>
<table><tr><th>bench</th><th>mean</th></tr>{raw_rows}</table></details>

<footer>CIRISServer · benches/pqc_av_streaming.rs + replication_ingest.rs ·
commit {H(commit[:12])} · {H(date)} ·
<a href="https://github.com/CIRISAI/CIRISServer/blob/main/FSD/PQC_AV_STREAMING_BENCH.md">methodology</a></footer>
</body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--criterion-dir", default="target/criterion")
    ap.add_argument("--out", default="bench-site")
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    ap.add_argument("--date", default=os.environ.get("BENCH_DATE", ""))
    ap.add_argument("--scoreboard", default=None,
                    help="path to `ciris-server scoreboard` JSON (holonomic federation scoreboard)")
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
        json.dump({"schema": "ciris-server/bench/2", "commit": args.commit,
                   "date": args.date, "model": model, "scoreboard": scoreboard,
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
