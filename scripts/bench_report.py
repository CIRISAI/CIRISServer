#!/usr/bin/env python3
"""
Turn criterion's raw `target/criterion/**/estimates.json` into an INTERPRETED
benchmark page for CIRISServer — what the numbers MEAN (video throughput under
stated assumptions, replication speed, post-quantum overhead), not just ns.

Usage:
    cargo bench --bench pqc_av_streaming --bench replication_ingest
    python3 scripts/bench_report.py --out bench-site [--commit SHA --date ISO]

Emits  <out>/index.html  (the page) + <out>/data.json  (machine-readable).
Self-contained HTML, no external assets. Host-relative numbers — the ratios and
conclusions are what travel, not the absolute µs (stamped with the runner).
"""
from __future__ import annotations
import argparse, glob, html, json, os, sys

MiB = 1024 * 1024


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


FRAME_LABELS = {
    "320": "Opus voice frame (~20 ms @128 kbps)",
    "4096": "720p inter-frame (low motion)",
    "16384": "720p inter-frame (typical)",
    "65536": "1080p inter / 720p keyframe",
    "262144": "1080p keyframe",
}


def build_model(est: dict[str, float]) -> dict:
    """Compute the interpreted metrics from raw means."""
    m: dict = {"video_frames": [], "kex": {}, "fanout": [], "replication": {}, "assumptions": {}}

    # ── Video: per-frame end-to-end seal->wire->open ───────────────────────
    for size_s, label in FRAME_LABELS.items():
        ns = est.get(f"av_frame_e2e/{size_s}")
        if ns is None:
            continue
        size = int(size_s)
        gibs = (size / (ns * 1e-9)) / (1024 * MiB)
        m["video_frames"].append({
            "bytes": size, "label": label,
            "us": round(us(ns), 2),
            "gib_s": round(gibs, 2),
            "fps_ceiling": round(1e9 / ns),  # one core, one stream
        })

    # ── Mesh fan-out (16 KiB) + derived sustainable-participants @30fps ────
    for n in (2, 8, 50):
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
    # Sustainable participant-links @30fps on one core (naive seal, from N=50).
    n50 = est.get("av_mesh_fanout/naive/50")
    if n50:
        per_link_ns = n50 / 50.0
        m["max_links_30fps_core"] = round(1e9 / (30.0 * per_link_ns))
        # utilization for a 50-person mesh @30fps
        m["mesh50_30fps_core_pct"] = round(100.0 * 30.0 * n50 / 1e9, 2)

    # ── Post-quantum KEX overhead (per peer-link, one-time) ────────────────
    h_i, h_r = est.get("pqc_kex/hybrid_initiate"), est.get("pqc_kex/hybrid_respond")
    c_i, c_r = est.get("pqc_kex/classical_initiate"), est.get("pqc_kex/classical_respond")
    if h_i and h_r:
        m["kex"]["hybrid_full_us"] = round(us(h_i + h_r), 1)
    if c_i and c_r:
        m["kex"]["classical_full_us"] = round(us(c_i + c_r), 1)
    if h_i and h_r and c_i and c_r:
        m["kex"]["mlkem_tax_us"] = round(us((h_i + h_r) - (c_i + c_r)), 1)

    # ── Replication / corpus ingest (the CEG-RC5 receive spine) ────────────
    new = est.get("replication_ingest/ingest_new")
    dedup = est.get("replication_ingest/ingest_dedup")
    if new:
        m["replication"]["ingest_new_us"] = round(us(new), 2)
        m["replication"]["traces_per_sec"] = round(1e9 / new)
    if dedup:
        m["replication"]["dedup_us"] = round(us(dedup), 2)
        m["replication"]["dedup_per_sec"] = round(1e9 / dedup)

    m["assumptions"] = {
        "cores": "single thread, one core; real deployments fan out across cores",
        "frames": "frame sizes are representative codec outputs, not a live encoder",
        "cache": "warm cache, steady state",
        "scope": "crypto + wire-codec + persist spine (CIRISServer-owned); excludes the "
                 "RNS network hop (bandwidth/RTT-bound) and codec encode/decode",
        "fps": "30 fps reference for the mesh-utilization figures",
    }
    return m


def H(s) -> str:
    return html.escape(str(s))


def render(model: dict, est: dict, commit: str, date: str) -> str:
    v = model["video_frames"]
    kex = model["kex"]
    rep = model["replication"]
    # headline derived figures (guarded)
    mesh50 = model.get("mesh50_30fps_core_pct")
    maxlinks = model.get("max_links_30fps_core")

    def rows(cells_list):
        return "\n".join("<tr>" + "".join(f"<td>{H(c)}</td>" for c in r) + "</tr>" for r in cells_list)

    video_rows = rows([[f["label"], f"{f['bytes']//1024 or '<1'} KiB" if f['bytes'] >= 1024 else f"{f['bytes']} B",
                        f"{f['us']} µs", f"{f['gib_s']} GiB/s", f"{f['fps_ceiling']:,} fps"] for f in v])
    fan_rows = rows([[f"{r['n']}", f"{r.get('naive_us','—')} µs", f"{r.get('shared_inner_us','—')} µs",
                      f"{r.get('speedup','—')}×"] for r in model["fanout"]])
    raw_rows = rows([[k, f"{us(ns):.3f} µs"] for k, ns in sorted(est.items())])

    headline = "PQC group video is effectively free."
    sub = []
    if v:
        peak = max(f["gib_s"] for f in v)
        sub.append(f"steady-state frame path runs at up to {peak:.1f} GiB/s (AES-256-GCM)")
    if kex.get("mlkem_tax_us") is not None:
        sub.append(f"the post-quantum tax is ~{kex['mlkem_tax_us']:.0f} µs <b>once per peer-link</b>, never per frame")
    if mesh50 is not None:
        sub.append(f"a 50-person 30&nbsp;fps mesh costs ~{mesh50:.1f}% of one core")
    sub_html = "; ".join(sub) + "." if sub else ""

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
 code{{background:#f4f4f4;padding:.05rem .3rem;border-radius:3px}}
 details{{margin-top:1rem}} footer{{margin-top:2.5rem;color:#888;font-size:.85rem;border-top:1px solid #eee;padding-top:.8rem}}
</style></head><body>
<h1>CIRISServer — benchmarks, interpreted</h1>
<p class="note">The fabric node's hot paths, in terms that mean something. Raw criterion
numbers at the bottom. Absolute µs are host-relative (this run's runner); the ratios and
ceilings are what travel.</p>
<p class="lead"><b>{headline}</b> {sub_html}</p>

<h2>Video throughput — realtime A/V mesh (two-layer hybrid-PQC)</h2>
<p>Per frame, end-to-end: inner AES-256-GCM (E2E epoch DEK) → wire codec → outer AES-256-GCM
(per-Link transit key). One core, one participant link.</p>
<table><tr><th>Frame</th><th>size</th><th>seal→wire→open</th><th>throughput</th><th>fps ceiling / stream</th></tr>
{video_rows}</table>
{"<p class='big'>A single core sustains ~" + format(maxlinks, ',') + " participant-links at 30 fps</p>" if maxlinks else ""}
<p class="note">…so a 50-person 30&nbsp;fps mesh is ~{mesh50}% of one core. Crypto is not the
bottleneck — bandwidth and the network are. The post-quantum cost is paid at session setup, not per frame.</p>

<h2>Post-quantum overhead — the hybrid handshake (per peer-link, one-time)</h2>
<table><tr><th>handshake</th><th>full (initiate+respond)</th></tr>
<tr><td>Hybrid X25519 + ML-KEM-768 (PQ-safe)</td><td>{kex.get('hybrid_full_us','—')} µs</td></tr>
<tr><td>Classical X25519 only</td><td>{kex.get('classical_full_us','—')} µs</td></tr>
<tr><td><b>ML-KEM-768 tax</b></td><td><b>+{kex.get('mlkem_tax_us','—')} µs, once per peer-link</b></td></tr></table>

<h2>Mesh fan-out — sender cost per frame (16 KiB)</h2>
<p><code>naive</code> = the current API (full two-layer seal × N). <code>shared_inner</code> =
inner-seal once (shared E2E ciphertext), outer-seal per Link — the SFU/large-room optimization.</p>
<table><tr><th>room (N)</th><th>naive</th><th>shared-inner</th><th>speedup</th></tr>
{fan_rows}</table>

<h2>Replication speed — CEG-RC5 corpus ingest (receive spine)</h2>
<p>What a node pays per replicated trace: Ed25519 verify + persist + content-addressed dedup.</p>
<table><tr><th>path</th><th>per trace</th><th>throughput</th></tr>
<tr><td>new trace (insert — replication intake)</td><td>{rep.get('ingest_new_us','—')} µs</td><td>{format(rep.get('traces_per_sec',0),',')} traces/s/core</td></tr>
<tr><td>re-delivery (dedup — anti gossip-loop)</td><td>{rep.get('dedup_us','—')} µs</td><td>{format(rep.get('dedup_per_sec',0),',')} /s/core</td></tr></table>

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
    args = ap.parse_args()

    est = load_estimates(args.criterion_dir)
    if not est:
        print(f"no estimates under {args.criterion_dir} — run the benches first", file=sys.stderr)
        return 1
    model = build_model(est)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "data.json"), "w") as fh:
        json.dump({"schema": "ciris-server/bench/1", "commit": args.commit,
                   "date": args.date, "model": model,
                   "raw_means_us": {k: round(v / 1000, 4) for k, v in est.items()}}, fh, indent=2)
    with open(os.path.join(args.out, "index.html"), "w") as fh:
        fh.write(render(model, est, args.commit, args.date))
    print(f"wrote {args.out}/index.html ({len(est)} benches) + data.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
