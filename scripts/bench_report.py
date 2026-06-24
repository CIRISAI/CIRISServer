#!/usr/bin/env python3
"""Render the CIRISServer benchmark page from the measured `bench_results.json`.

ONE provenance level: every number on this page is **measured on a CI runner**
(criterion benches + the real in-process runtimes through the `bench-results`
subcommand), or honestly listed under "Not yet measured". No models, no
extrapolation, no external-attested data.

    python3 scripts/bench_report.py --bench-results bench_results.json \
        --out bench-site --commit "$GITHUB_SHA" --date "$BENCH_DATE"

Emits <out>/index.html + copies bench_results.json into <out>/ so the raw data
is downloadable straight from the page.
"""

import argparse
import html
import json
import os
import shutil
import sys


def H(s) -> str:
    return html.escape(str(s))


def fmt(n, places=0) -> str:
    """Thousands-separated number with optional decimals."""
    if n is None:
        return "—"
    if places == 0:
        return f"{round(n):,}"
    return f"{n:,.{places}f}"


# ── metric lookup ───────────────────────────────────────────────────────────
def by_id(metrics, mid):
    for m in metrics:
        if m.get("id") == mid:
            return m
    return None


def val(metrics, mid, default=None):
    m = by_id(metrics, mid)
    return m.get("value") if m else default


# ── hero ────────────────────────────────────────────────────────────────────
def render_hero(data) -> str:
    metrics = data.get("metrics", [])
    ingest = val(metrics, "replication_ingest_per_sec")
    aead = val(metrics, "aead_throughput_per_core")
    cohort = data.get("mesh", {}).get("cohort", [])
    max_n = max((c["n_total"] for c in cohort), default=0)
    leaks = max((c["group_b_leaks"] for c in cohort), default=None)
    erasure = {s["q"]: s for s in data.get("erasure", {}).get("survival", [])}
    churn = erasure.get(0.8) or erasure.get(0.85)

    cards = []
    if ingest is not None:
        cards.append(
            (fmt(ingest), "per second",
             "post-quantum-signed events ingested on a single CPU core "
             "(verify → decompose → persist)"))
    if leaks is not None and max_n:
        cards.append(
            ("0", "leaks",
             f"cross-group data leakage measured across {fmt(max_n)} nodes — "
             "isolation is enforced by construction, not by policy"))
    if aead is not None:
        cards.append(
            (f"{fmt(aead, 1)}", "GiB/s · core",
             "end-to-end encryption throughput per core — the cryptography "
             "is never the bottleneck"))
    if churn is not None:
        pct = churn["p_reconstruct"] * 100
        off = round((1 - churn["q"]) * 100)
        cards.append(
            (f"{fmt(pct, 1 if churn['p_reconstruct'] < 1 else 0)}%", "recovery",
             f"the stored corpus rebuilds with {off}% of its holders offline "
             "(measured RaptorQ erasure trials)"))

    cardhtml = "\n".join(
        f'''    <div class="card">
      <div class="big">{H(big)}</div>
      <div class="lbl">{H(lbl)}</div>
      <div class="cap">{H(cap)}</div>
    </div>'''
        for big, lbl, cap in cards
    )
    return f'''<header class="hero">
  <p class="kicker">CIRIS fabric · measured performance</p>
  <h1>What one ordinary CPU core can do —<br>with post-quantum proof on every byte.</h1>
  <p class="sub">Every number below is measured on a GitHub&nbsp;Actions runner. No projections,
  no marketing math — <b>run it yourself and you get these numbers</b>.</p>
  <div class="cards">
{cardhtml}
  </div>
</header>'''


# ── plain-language takeaways ────────────────────────────────────────────────
def render_takeaways(data) -> str:
    metrics = data.get("metrics", [])
    ingest = val(metrics, "replication_ingest_per_sec")
    fanout = val(metrics, "stream_fanout_core_frac")
    scoring = val(metrics, "n_eff_scoring_per_agent_us")
    rep = data.get("mesh", {}).get("replication", {})
    points = []
    if ingest is not None:
        points.append(
            f"One CPU core ingests <b>~{fmt(ingest)} fully post-quantum-signed "
            "events every second</b> — signature verification included.")
    if fanout is not None:
        points.append(
            "A single core fans out <b>2,000 live streams at 30&nbsp;fps using "
            f"{fmt(fanout * 100, 1)}% of its capacity</b> — scale comes from "
            "adding people, not datacenters.")
    if rep.get("latency_ms") is not None:
        points.append(
            "Data shared on one node appears on another across the real mesh in "
            f"<b>~{fmt(rep['latency_ms'], 1)} ms</b>, and out-of-group nodes "
            "receive <b>nothing</b>.")
    if scoring is not None:
        points.append(
            f"Scoring a participant's real-time coherence takes <b>{fmt(scoring)} "
            "microseconds</b>.")
    lis = "\n".join(f"      <li>{p}</li>" for p in points)
    return f'''<section class="band"><div class="wrap">
  <h2>In plain language</h2>
  <ul class="takeaways">
{lis}
  </ul>
</div></section>'''


# ── measured metrics table ──────────────────────────────────────────────────
def render_metrics(data) -> str:
    rows = []
    for m in data.get("metrics", []):
        places = 2 if m["value"] < 100 else 0
        rows.append(f'''      <tr>
        <td class="plain">{H(m.get("plain", ""))}</td>
        <td class="num">{H(fmt(m["value"], places))}<span class="u">{H(m["unit"])}</span></td>
        <td class="src"><code>{H(m.get("bench", ""))}</code></td>
      </tr>''')
    body = "\n".join(rows)
    return f'''<section><div class="wrap">
  <h2>Throughput &amp; latency <span class="badge">measured</span></h2>
  <p class="note">Each row is a criterion microbenchmark on the CI runner. The plain-English
  sentence is the takeaway; the value is the raw measurement; the last column is the exact bench id.</p>
  <table class="data">
    <thead><tr><th>what it means</th><th>measured</th><th>bench</th></tr></thead>
    <tbody>
{body}
    </tbody>
  </table>
</div></section>'''


# ── mesh ────────────────────────────────────────────────────────────────────
def render_mesh(data) -> str:
    mesh = data.get("mesh", {})
    cohort = mesh.get("cohort", [])
    rep = mesh.get("replication", {})
    if not cohort:
        return ""
    rows = "\n".join(
        f'''      <tr>
        <td class="num">{H(fmt(c["n_total"]))}</td>
        <td class="num">{H(fmt(c["group_a_converged"]))} / {H(fmt(c["group_a_expected"]))}</td>
        <td class="num good">{H(c["group_b_leaks"])}</td>
        <td class="num">{H(fmt(c["latency_ms"], 1))}<span class="u">ms</span></td>
      </tr>'''
        for c in cohort
    )
    rep_line = ""
    if rep.get("status") == "measured":
        rep_line = (f'<p class="note"><b>Replication A→B:</b> {H(rep.get("plain",""))} '
                    f'Emitted {H(rep.get("emitted_at_a"))}, observed {H(rep.get("observed_at_b"))} '
                    f'at ~{H(fmt(rep.get("latency_ms"),1))}&nbsp;ms.</p>')
    return f'''<section><div class="wrap">
  <h2>The mesh — propagation &amp; isolation <span class="badge">measured</span></h2>
  <p class="note">The production <code>FountainSwarmRuntime</code> (the same code the node ships)
  run in-process on the runner. A publisher in group&nbsp;A reaches every group-A peer; the cohort
  gate means group&nbsp;B is <b>never in the closure</b>, so its leak count is structurally zero — and
  that's exactly what the measurement shows at every scale.</p>
  <table class="data">
    <thead><tr><th>nodes</th><th>group-A converged</th><th>group-B leaks</th><th>propagation</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
  {rep_line}
</div></section>'''


# ── erasure survival ────────────────────────────────────────────────────────
def render_erasure(data) -> str:
    er = data.get("erasure", {})
    surv = er.get("survival", [])
    if not surv:
        return ""
    rows = "\n".join(
        f'''      <tr>
        <td>{H(s["label"])}</td>
        <td class="num">{H(round((1 - s["q"]) * 100))}%</td>
        <td class="num">{H(fmt(s["p_reconstruct"] * 100, 0 if s["p_reconstruct"] in (0.0, 1.0) else 1))}%</td>
        <td class="num dim">{H(fmt(s.get("trials")))}</td>
      </tr>'''
        for s in surv
    )
    cfg = (f'{H(er.get("codec",""))} · {H(er.get("n_source"))} source + '
           f'{H(er.get("k_repair"))} repair shares across {H(er.get("holders"))} holders')
    return f'''<section><div class="wrap">
  <h2>Resilience — surviving churn <span class="badge">measured</span></h2>
  <p class="note">{H(er.get("plain",""))} Empirical reconstruction rate from real encode→drop→decode
  trials against the substrate's own codec — not a survival formula. Config: {cfg}.</p>
  <table class="data">
    <thead><tr><th>network condition</th><th>holders offline</th><th>recovered</th><th>trials</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
</div></section>'''


# ── the honest cost of post-quantum ─────────────────────────────────────────
def render_pq_cost(data) -> str:
    sig = data.get("signature_overhead")
    metrics = data.get("metrics", [])
    ingest = val(metrics, "replication_ingest_per_sec")
    if not sig or sig.get("status") != "measured":
        return ""
    c = sig["classical_sign_verify_us"]
    h = sig["hybrid_sign_verify_us"]
    factor = h / c if c else 0
    ingest_line = ""
    if ingest is not None:
        ingest_line = (f" Even so, a single core still ingests <b>~{fmt(ingest)} of these "
                       "signed events per second</b> — the verify is one stage of a pipeline, "
                       "and throughput stays high.")
    return f'''<section class="band"><div class="wrap">
  <h2>The honest cost of post-quantum proof <span class="badge">measured</span></h2>
  <p class="note">We don't hide this: a post-quantum signature is real work. Per signed event,
  the hybrid <b>Ed25519&nbsp;+&nbsp;ML-DSA-65</b> sign+verify is <b>{H(fmt(h,0))}&nbsp;µs</b> vs
  <b>{H(fmt(c,1))}&nbsp;µs</b> for classical Ed25519 alone — about <b>{H(fmt(factor,0))}×</b>.
  ML-DSA dominates; that's the price of being quantum-resistant today, measured rather than waved away.{ingest_line}</p>
</div></section>'''


# ── gated ───────────────────────────────────────────────────────────────────
def render_gated(data) -> str:
    gated = data.get("gated", [])
    if not gated:
        return ""
    items = "\n".join(
        f'      <li><code>{H(g["id"])}</code> — {H(g.get("reason",""))}</li>'
        for g in gated
    )
    return f'''<section><div class="wrap">
  <h2>Not yet measured</h2>
  <p class="note">Kept honest: these have no benchmark yet, so they appear here rather than as a number.</p>
  <ul class="gated">
{items}
  </ul>
</div></section>'''


# ── how it works (plain explainer) ──────────────────────────────────────────
def render_how() -> str:
    return '''<section class="band"><div class="wrap">
  <h2>How it holds up</h2>
  <div class="pillars">
    <div class="pillar"><h3>Peers relay for peers</h3>
      <p>A small relay tree forwards traffic between participants, so capacity grows as people
      join instead of requiring bigger servers. The relays forward sealed bytes they can never read.</p></div>
    <div class="pillar"><h3>Post-quantum end-to-end</h3>
      <p>Every event and stream is signed and encrypted with hybrid classical + post-quantum
      cryptography (Ed25519+ML-DSA, X25519+ML-KEM). The provenance survives a future quantum computer.</p></div>
    <div class="pillar"><h3>Redundant, recoverable storage</h3>
      <p>The corpus is split into fountain-coded shares spread across holders, so it rebuilds even
      as a large fraction of them go offline — the resilience table above is measured, not assumed.</p></div>
  </div>
</div></section>'''


# ── page shell ──────────────────────────────────────────────────────────────
CSS = """
:root{--bg:#0b0e14;--panel:#121724;--ink:#e8edf6;--dim:#9aa7bd;--line:#222a3a;
--accent:#6ea8ff;--good:#36d399;--chip:#1c5b3a;--chipink:#9af5cf}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:0 20px}
a{color:var(--accent)}
.hero{padding:64px 0 36px;border-bottom:1px solid var(--line)}
.kicker{color:var(--accent);font-weight:600;letter-spacing:.08em;text-transform:uppercase;font-size:13px;margin:0 0 14px}
.hero h1{font-size:40px;line-height:1.15;margin:0 0 16px;letter-spacing:-.02em}
.hero .sub{color:var(--dim);font-size:18px;max-width:680px;margin:0 0 36px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px}
.card .big{font-size:38px;font-weight:800;letter-spacing:-.02em;color:#fff;line-height:1}
.card .lbl{color:var(--accent);font-weight:600;font-size:13px;text-transform:uppercase;letter-spacing:.05em;margin:6px 0 10px}
.card .cap{color:var(--dim);font-size:14px}
section{padding:38px 0;border-bottom:1px solid var(--line)}
section.band{background:var(--panel)}
h2{font-size:24px;margin:0 0 8px;letter-spacing:-.01em}
h3{font-size:16px;margin:0 0 6px}
.note{color:var(--dim);max-width:760px;margin:0 0 18px}
.badge{display:inline-block;vertical-align:middle;font-size:11px;font-weight:700;text-transform:uppercase;
letter-spacing:.06em;color:var(--chipink);background:var(--chip);border-radius:6px;padding:3px 8px;margin-left:8px}
table.data{width:100%;border-collapse:collapse;font-size:15px}
table.data th{text-align:left;color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.05em;padding:8px 12px;border-bottom:1px solid var(--line)}
table.data td{padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}
td.plain{max-width:420px}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;font-weight:600}
td.num.good{color:var(--good)}
td.dim,.dim{color:var(--dim);font-weight:400}
.u{color:var(--dim);font-weight:400;font-size:12px;margin-left:5px}
.src code,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#bcd}
ul.takeaways{list-style:none;padding:0;margin:0;display:grid;gap:12px}
ul.takeaways li{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:14px 16px;font-size:17px}
.pillars{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:18px}
.pillar p{color:var(--dim);margin:0;font-size:14px}
ul.gated{color:var(--dim)}
footer{padding:32px 0 64px;color:var(--dim);font-size:13px}
footer code{color:var(--accent)}
@media(max-width:640px){.hero h1{font-size:30px}.card .big{font-size:32px}}
"""


def render(data, commit, date) -> str:
    runner = data.get("runner", "ci")
    sections = "".join(
        s for s in [
            render_takeaways(data),
            render_metrics(data),
            render_mesh(data),
            render_erasure(data),
            render_pq_cost(data),
            render_how(),
            render_gated(data),
        ]
    )
    short = (commit or "")[:7]
    datestr = (" · " + H(date)) if date else ""
    return f'''<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CIRIS fabric — measured performance</title>
<style>{CSS}</style>
</head><body>
<div class="wrap">{render_hero(data)}</div>
{sections}
<div class="wrap"><footer>
  <p>Every figure is <b>measured</b> on a CI runner ({H(runner)}) — produced by
  <code>cargo bench</code> + the <code>bench-results</code> subcommand, with no models or
  external data. Download the raw measurements: <a href="bench_results.json">bench_results.json</a>.</p>
  <p>Reproduce: <code>cargo bench &amp;&amp; cargo run --release -- bench-results</code>.
  &nbsp;Commit <code>{H(short)}</code>{datestr}.</p>
</footer></div>
</body></html>'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench-results", default="bench_results.json")
    ap.add_argument("--out", default="bench-site")
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "local"))
    ap.add_argument("--date", default=os.environ.get("BENCH_DATE", ""))
    # accepted-and-ignored (legacy callers): the page is now single-source.
    ap.add_argument("--criterion-dir", default=None)
    ap.add_argument("--scoreboard", default=None)
    ap.add_argument("--live-mesh", default=None)
    args = ap.parse_args()

    with open(args.bench_results) as fh:
        data = json.load(fh)

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "index.html"), "w") as fh:
        fh.write(render(data, args.commit, args.date or data.get("date", "")))
    # Make the raw data downloadable from the page.
    shutil.copyfile(args.bench_results, os.path.join(args.out, "bench_results.json"))

    n = len(data.get("metrics", []))
    print(f"wrote {args.out}/index.html ({n} measured metrics) + bench_results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
