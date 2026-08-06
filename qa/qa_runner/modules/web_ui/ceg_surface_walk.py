"""CEG operator-surface walk — SystemScreen / ModerationScreen / NetworkOpsScreen.

These screens shipped with 46 `testable()` tags between them and zero QA cases.
They exist to keep *distinctions* alive, so every case here asserts a distinction
rather than a happy path, and every case reports **what the surface actually
said** — the band token, the standing, the counts — not just pass/fail. A walk
that only says PASS cannot tell you the trace plane is dark.

Driven entirely through testTags (see :mod:`surface_driver` for why).

Run
---
    cd client && CIRIS_TEST_MODE=true ./gradlew :desktopApp:run   # port 9091

    python3 qa/qa_runner/modules/web_ui/ceg_surface_walk.py lint    # no app needed
    python3 qa/qa_runner/modules/web_ui/ceg_surface_walk.py walk
    python3 qa/qa_runner/modules/web_ui/ceg_surface_walk.py walk --json

Exit code is non-zero when any case FAILS. BLOCKED never fails the run — it
means the case could not be exercised, which is a fact to report, not a defect.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import httpx

try:
    from .surface_driver import Snapshot, SurfaceDriver
except ImportError:  # run as a plain script
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from surface_driver import Snapshot, SurfaceDriver  # type: ignore

PORT = int(os.environ.get("CIRIS_TEST_PORT", "9091"))
NODE_API = os.environ.get("CIRIS_API_URL", "http://127.0.0.1:4243")
QA_USER = os.environ.get("CIRIS_QA_USER", "qaadmin")
QA_PASSWORD = os.environ.get("CIRIS_QA_PASSWORD", "qa_test_password_12345")


# ─────────────────────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────────────────────
class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    #: Could not be *exercised* — a precondition outside the UI was absent.
    #: Deliberately not PASS: an unexercised case is not a passing one. Also
    #: deliberately not FAIL: the UI is not wrong because the node had nothing
    #: to say. This distinction is the same one the surfaces themselves make.
    BLOCKED = "BLOCKED"


@dataclass
class CaseResult:
    name: str
    status: Status
    detail: str = ""
    #: The RICH part: what the surface actually reported. Kept on every status,
    #: including BLOCKED, so the run explains itself.
    observed: Dict[str, Any] = field(default_factory=dict)
    screenshot: Optional[str] = None

    def line(self) -> str:
        s = f"[{self.status.value:7s}] {self.name}\n           {self.detail}"
        for k, v in self.observed.items():
            s += f"\n             · {k}: {v}"
        return s


@dataclass
class WalkReport:
    cases: List[CaseResult] = field(default_factory=list)

    def add(self, r: CaseResult) -> CaseResult:
        self.cases.append(r)
        print(r.line(), flush=True)
        return r

    @property
    def failed(self) -> List[CaseResult]:
        return [c for c in self.cases if c.status is Status.FAIL]

    @property
    def blocked(self) -> List[CaseResult]:
        return [c for c in self.cases if c.status is Status.BLOCKED]

    def summary(self) -> str:
        p = sum(1 for c in self.cases if c.status is Status.PASS)
        out = [
            "", "=" * 74,
            f"{p} passed / {len(self.failed)} failed / {len(self.blocked)} blocked"
            f"   (of {len(self.cases)})",
        ]
        if self.blocked:
            out.append("")
            out.append("NOT EXERCISED (and why):")
            out += [f"  · {c.name}\n      {c.detail}" for c in self.blocked]
        out.append("=" * 74)
        return "\n".join(out)

    def to_json(self) -> str:
        return json.dumps(
            [{"name": c.name, "status": c.status.value, "detail": c.detail,
              "observed": c.observed, "screenshot": c.screenshot}
             for c in self.cases], indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Node route probe — "is it mounted", never "will it answer"
# ─────────────────────────────────────────────────────────────────────────────
SURFACE_ROUTES = {
    "system.node_state": ("GET", "/v1/node/state"),
    "networkops.tier_s": ("GET", "/v1/admin/self"),
    # POST-only; a GET answers 405, which still proves the route is mounted.
    "networkops.tier_r": ("POST", "/v1/admin/reader/fold"),
    "moderation.ladder": ("POST", "/v1/admin/preview"),
    "meshconfig": ("GET", "/v1/mesh-config"),
    "commons": ("GET", "/v1/commons/standing"),
    # Agent-side route; a fabric node does not mount it. Probed so the walk can
    # tell a real mode reading from a ViewModel default.
    "agent_mode": ("GET", "/v1/system/agent-mode"),
}

ABSENT, MOUNTED, UNREACHABLE = "absent", "mounted", "unreachable"


async def probe_routes() -> Dict[str, str]:
    """This probe is UNAUTHENTICATED, so it answers exactly one question: does
    the running build mount the route. It cannot say whether the signed-in app
    gets a body — conflating those is how an earlier version of this module
    predicted `not_offered` for a surface the app was in fact rendering."""
    out: Dict[str, str] = {}
    async with httpx.AsyncClient(base_url=NODE_API, timeout=8.0) as c:
        for name, (method, path) in SURFACE_ROUTES.items():
            try:
                r = await c.request(method, path,
                                    json={} if method == "POST" else None)
                out[name] = ABSENT if r.status_code == 404 else MOUNTED
            except Exception:
                out[name] = UNREACHABLE
    return out


Case = Callable[[SurfaceDriver, WalkReport, Dict[str, str]], Any]


# ═════════════════════════════════════════════════════════════════════════════
# SURFACE 1 — SystemScreen: the node-state operator band (#356 / #369 / #370)
# ═════════════════════════════════════════════════════════════════════════════
#: The six mutually-exclusive arms. Exactly one may render: "we are still
#: asking", "we could not reach it", "it refused", "this build does not offer
#: it", "we could not parse it" and "here is a reading" are six different facts,
#: and collapsing any two of them is the failure this surface exists to prevent.
NODE_STATE_ARMS = [
    "node_state_loading",
    "node_state_unreachable",
    "node_state_refused",
    "node_state_not_offered",
    "node_state_malformed",
    "node_state_headline",  # the Present arm
]

#: What each trace-plane standing is entitled to put on screen.
TRACE_STANDING_RULES: Dict[str, Dict[str, List[str]]] = {
    # the corpus could not be asked — an instant or a count would be invented
    "unreadable": {"require": [], "forbid": ["trace_last_admitted", "trace_rows"]},
    # the corpus WAS read and holds nothing — say so, AND show the checkable zero
    "never_admitted": {"require": ["trace_rows"], "forbid": ["trace_last_admitted"]},
    # these have a real arrival instant, so it and its age must be shown
    "live": {"require": ["trace_last_admitted", "trace_age"], "forbid": []},
    "quiet": {"require": ["trace_last_admitted", "trace_age"], "forbid": []},
    "dark": {"require": ["trace_last_admitted", "trace_age"], "forbid": []},
    # producer-clock skew: the instant IS shown, flagged rather than banded
    "future_dated": {"require": ["trace_last_admitted"], "forbid": []},
}


async def _open_system(d: SurfaceDriver) -> bool:
    return await d.goto("system", "System", group_id="node")


async def case_system_one_arm(d: SurfaceDriver, rep: WalkReport,
                              probe: Dict[str, str]):
    name = "system/node_state · exactly one arm renders"
    if not await _open_system(d):
        rep.add(CaseResult(name, Status.FAIL, "could not reach the System screen"))
        return
    snap = await d.snapshot()
    arms = [a for a in NODE_STATE_ARMS if a in snap]
    shot = await d.screenshot("system_node_state")
    if len(arms) == 1:
        rep.add(CaseResult(
            name, Status.PASS, f"one arm: {arms[0]}",
            observed={"arm": arms[0], "route": probe.get("system.node_state")},
            screenshot=shot))
    else:
        rep.add(CaseResult(
            name, Status.FAIL,
            f"expected exactly one arm, got {len(arms)}",
            observed={"arms": arms}, screenshot=shot))


async def case_system_absent_route_not_offered(d: SurfaceDriver, rep: WalkReport,
                                               probe: Dict[str, str]):
    """A route this build does not mount renders `not_offered` — not a band, and
    not `refused` (which means a node answered and said no)."""
    name = "system/node_state · an unmounted route reads not_offered, not a band"
    snap = await d.snapshot()
    arms = [a for a in NODE_STATE_ARMS if a in snap]
    if not arms:
        rep.add(CaseResult(name, Status.FAIL, "no node-state arm rendered at all"))
        return
    arm, route = arms[0], probe.get("system.node_state", UNREACHABLE)
    if route == ABSENT:
        ok = arm == "node_state_not_offered"
        rep.add(CaseResult(
            name, Status.PASS if ok else Status.FAIL,
            f"route absent → {arm}" if ok
            else f"route absent but rendered {arm}",
            observed={"arm": arm, "route": route}))
    elif arm == "node_state_not_offered":
        rep.add(CaseResult(
            name, Status.FAIL,
            "route IS mounted yet the screen claims the build does not offer it",
            observed={"arm": arm, "route": route}))
    else:
        rep.add(CaseResult(name, Status.PASS, f"route mounted → {arm}",
                           observed={"arm": arm, "route": route}))


async def case_system_trace_standing(d: SurfaceDriver, rep: WalkReport,
                                     probe: Dict[str, str]):
    """The trace plane shows exactly what its standing entitles it to show."""
    name = "system/trace_plane · the standing shows only what it may"
    snap = await d.snapshot()
    if "node_state_trace_plane" not in snap:
        rep.add(CaseResult(
            name, Status.BLOCKED, "no trace-plane card rendered",
            observed={"route": probe.get("system.node_state"),
                      "arms": [a for a in NODE_STATE_ARMS if a in snap]}))
        return
    standing = snap.token("node_state_trace_standing")
    if not standing:
        rep.add(CaseResult(
            name, Status.FAIL,
            "the standing pill publishes no token, so a walk cannot tell which "
            "of the distinct zeroes rendered"))
        return
    rules = TRACE_STANDING_RULES.get(standing)
    obs = {"standing": standing,
           "traces_held": snap.text("trace_rows"),
           "last_admitted": snap.text("trace_last_admitted"),
           "age": snap.text("trace_age")}
    if rules is None:
        rep.add(CaseResult(name, Status.BLOCKED,
                           f"no rendering rule pinned for standing {standing!r}",
                           observed=obs))
        return
    missing = [t for t in rules["require"] if t not in snap]
    invented = [t for t in rules["forbid"] if t in snap]
    shot = await d.screenshot(f"system_trace_{standing}")
    if not missing and not invented:
        rep.add(CaseResult(name, Status.PASS,
                           f"{standing}: rendering matches its rule",
                           observed=obs, screenshot=shot))
    else:
        rep.add(CaseResult(
            name, Status.FAIL,
            f"{standing}: missing={missing} invented={invented}",
            observed={**obs, "missing": missing, "invented": invented},
            screenshot=shot))


async def case_system_uncomputed_named(d: SurfaceDriver, rep: WalkReport,
                                       probe: Dict[str, str]):
    """An UNKNOWN roll-up must name its uncomputed signals.

    A red roll-up outranks an unknown, so without the explicit list an
    uncomputed signal disappears behind the headline — an untested zero read as
    a healthy one, which is the 2026-08-05 failure exactly.
    """
    name = "system/node_state · uncomputed signals are named, not swallowed"
    snap = await d.snapshot()
    if "node_state_headline" not in snap:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "no live reading present to roll up"))
        return
    band = snap.token("node_state_band")
    listed = "node_state_unknown_list" in snap
    obs = {"headline_band": band, "unknown_list_rendered": listed}
    if band == "unknown" and not listed:
        rep.add(CaseResult(
            name, Status.FAIL,
            "headline band is UNKNOWN but no uncomputed-signal list rendered",
            observed=obs))
    else:
        rep.add(CaseResult(name, Status.PASS,
                           f"band={band or '(none)'}, list={'yes' if listed else 'n/a'}",
                           observed=obs))


async def case_system_edge_halves(d: SurfaceDriver, rep: WalkReport,
                                  probe: Dict[str, str]):
    """Carriage and receive are two halves and read separately."""
    name = "system/edge · carriage and receive report independently"
    snap = await d.snapshot()
    if "node_state_headline" not in snap:
        rep.add(CaseResult(name, Status.BLOCKED, "no live reading present"))
        return
    obs = {"carriage": snap.token("node_state_carriage_standing") or "(absent)",
           "receive": snap.token("node_state_receive_standing") or "(absent)",
           "ingest": snap.token("node_state_ingest_standing") or "(absent)"}
    both = "node_state_carriage" in snap and "node_state_receive" in snap
    rep.add(CaseResult(
        name, Status.PASS if both else Status.BLOCKED,
        "both halves rendered" if both
        else "one or both edge halves absent from this reading",
        observed=obs))


# ═════════════════════════════════════════════════════════════════════════════
# SURFACE 2 — ModerationScreen: the graded enforcement ladder (#346)
# ═════════════════════════════════════════════════════════════════════════════
LADDER_RUNGS = ["annotate", "throttle", "un_throttle", "quarantine",
                "un_quarantine", "descend", "deadmit", "re_admit",
                "refuse_writes", "accept_writes"]


async def _open_moderation(d: SurfaceDriver) -> bool:
    return await d.goto("moderation", "Moderation", group_id="safety")


async def case_moderation_rungs_distinct(d: SurfaceDriver, rep: WalkReport,
                                         probe: Dict[str, str]):
    """Ten rungs, ten chips. A ladder that folds `throttle` into `quarantine`
    is one an operator cannot climb deliberately."""
    name = "moderation/ladder · every rung is its own chip"
    if not await _open_moderation(d):
        rep.add(CaseResult(name, Status.FAIL, "could not reach Moderation"))
        return
    snap = await d.snapshot()
    want = {f"chip_ladder_{r}" for r in LADDER_RUNGS}
    missing = sorted(want - snap.tags)
    shot = await d.screenshot("moderation_ladder")
    rep.add(CaseResult(
        name, Status.PASS if not missing else Status.FAIL,
        f"{len(want) - len(missing)}/{len(want)} rungs present",
        observed={"missing": missing or "none",
                  "present": snap.with_prefix("chip_ladder_")},
        screenshot=shot))


async def case_moderation_no_preview_no_commit(d: SurfaceDriver, rep: WalkReport,
                                               probe: Dict[str, str]):
    """The ladder commits the hash its preview returned, so with no preview
    there must be nothing to commit."""
    name = "moderation/ladder · no preview ⇒ no commit"
    snap = await d.snapshot()
    if "txt_ladder_preview_none" not in snap and "block_ladder_preview" in snap:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "a preview is already loaded; case assumes a fresh screen"))
        return
    dispatchable = await d.exists("btn_ladder_commit", timeout_ms=900)
    rep.add(CaseResult(
        name, Status.FAIL if dispatchable else Status.PASS,
        "commit is dispatchable with no preview taken" if dispatchable
        else "commit unreachable before a preview",
        observed={"preview_state": "none" if "txt_ladder_preview_none" in snap
                  else "unknown"}))


async def case_moderation_descend_typed_ack(d: SurfaceDriver, rep: WalkReport,
                                            probe: Dict[str, str]):
    """`descend` — and only `descend` — takes a typed acknowledgement.

    Needs a preview, which needs the ladder route; without one the confirmation
    sheet cannot be opened at all.
    """
    name = "moderation/ladder · descend requires a typed acknowledgement"
    route = probe.get("moderation.ladder")
    if route != MOUNTED:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            f"POST /v1/admin/preview is {route}; no preview can be taken, so the "
            "descend confirmation sheet cannot be opened",
            observed={"route": route}))
        return
    snap = await d.snapshot()
    if "chip_ladder_descend" not in snap:
        rep.add(CaseResult(name, Status.BLOCKED, "descend rung not on screen"))
        return
    await d.act("chip_ladder_descend", wait_ms=1200)
    if not await d.exists("btn_ladder_preview", timeout_ms=1500):
        rep.add(CaseResult(name, Status.BLOCKED,
                           "preview control unavailable for descend"))
        return
    await d.act("btn_ladder_preview", wait_ms=3000)
    if not await d.exists("sheet_ladder_confirm", timeout_ms=2500):
        rep.add(CaseResult(
            name, Status.BLOCKED,
            "confirmation sheet did not open after preview — no rows to act on, "
            "or the preview was refused"))
        return
    ack = await d.exists("input_ladder_descend_ack", timeout_ms=1500)
    rep.add(CaseResult(
        name, Status.PASS if ack else Status.FAIL,
        "typed acknowledgement present on descend" if ack
        else "descend offered NO typed acknowledgement — an irreversible rung "
             "commits on the same single tap as annotate",
        screenshot=await d.screenshot("moderation_descend_sheet")))


# ═════════════════════════════════════════════════════════════════════════════
# SURFACE 3 — NetworkOpsScreen: tier S and tier R (#345)
# ═════════════════════════════════════════════════════════════════════════════
#: The three self-directed axes as the surface actually names them. Verified
#: live against 0.5.155 — `legal_compulsion`, not `compelled`.
TIER_S_AXES = ["load_shed", "accepting", "legal_compulsion"]


async def _open_networkops(d: SurfaceDriver) -> bool:
    return await d.goto("network_ops", "NetworkOps", group_id="manage")


async def case_networkops_renders(d: SurfaceDriver, rep: WalkReport,
                                  probe: Dict[str, str]):
    name = "networkops · screen renders"
    ok = await _open_networkops(d)
    snap = await d.snapshot() if ok else None
    rep.add(CaseResult(
        name, Status.PASS if ok else Status.FAIL,
        "rendered" if ok else "could not reach NetworkOps",
        observed={"signer_key": snap.text("row_netops_signer_key") if snap else None,
                  "mode": snap.text("row_netops_mode") if snap else None} if snap else {},
        screenshot=await d.screenshot("networkops") if ok else None))


async def case_networkops_mode_is_read_not_defaulted(d: SurfaceDriver,
                                                     rep: WalkReport,
                                                     probe: Dict[str, str]):
    """The agent mode on screen is a READING, not a default.

    `NetworkViewModel` initialises `_mode = MutableStateFlow(AgentMode.PROXY)`
    and `loadAgentMode()` overwrites it only on success. `GET
    /v1/system/agent-mode` is not mounted by ciris-server (it is an agent-side
    route), so on a fabric node the call 404s, the default survives, and the
    Network surface renders `Current  PROXY` — a value no one read, presented
    exactly like one that was.

    That is the defect the whole node-state surface exists to prevent, on the
    screen next door: an untested value rendered as a healthy reading. The fix
    is client-side — carry "not read" as its own state and render it as such,
    the way `SystemScreen` renders `not_offered` rather than a band.
    """
    name = "networkops/mode · the agent mode shown was actually read"
    snap = await d.snapshot()
    mode = snap.text("row_netops_mode")
    reachable = probe.get("agent_mode", ABSENT)
    obs = {"rendered_mode": mode, "agent_mode_route": reachable}
    if reachable == MOUNTED:
        rep.add(CaseResult(name, Status.PASS,
                           "route mounted; the rendered mode is a real read",
                           observed=obs))
        return
    if mode is None:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            "the mode row publishes no text, so what it renders cannot be "
            "checked from a walk (add the value to its testable() call)",
            observed=obs))
        return
    rep.add(CaseResult(
        name, Status.FAIL,
        f"GET /v1/system/agent-mode is {reachable} on this node, yet the surface "
        f"renders {mode!r} — a ViewModel default presented as a reading",
        observed=obs))


async def case_networkops_tier_s_axes(d: SurfaceDriver, rep: WalkReport,
                                      probe: Dict[str, str]):
    """Tier S is THREE standings, never one switch — a node can shed load while
    still accepting new work, and an operator must move them independently."""
    name = "networkops/tier_S · three axes render as three standings"
    snap = await d.snapshot()
    cards = snap.with_prefix("card_self_axis_")
    obs = {"axis_cards": cards, "route": probe.get("networkops.tier_s")}
    if not cards:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            "no axis cards rendered — the tier-S read produced no standings",
            observed=obs))
        return
    if len(cards) == 3:
        rep.add(CaseResult(name, Status.PASS, f"three standings: {cards}",
                           observed=obs))
    else:
        rep.add(CaseResult(name, Status.FAIL,
                           f"expected 3 axis cards, got {len(cards)}",
                           observed=obs))


async def case_networkops_refusal_not_invented(d: SurfaceDriver, rep: WalkReport,
                                               probe: Dict[str, str]):
    """A tier-S read that failed must render *unknown*, never three clean
    standings. This is the arm that actually runs on a node without the route,
    and the one that catches a screen inventing a healthy answer."""
    name = "networkops/tier_S · a refused read is not a clear one"
    snap = await d.snapshot()
    cards = snap.with_prefix("card_self_axis_")
    refused = "block_self_refusal" in snap or "text_self_refusal" in snap
    obs = {"axis_cards": cards, "refusal_block": refused,
           "route": probe.get("networkops.tier_s")}
    if cards:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "the read succeeded; nothing is being refused",
                           observed=obs))
        return
    rep.add(CaseResult(name, Status.PASS,
                       "no standings invented where the read produced none",
                       observed=obs))


async def case_networkops_decline_is_peer_of_honour(d: SurfaceDriver,
                                                    rep: WalkReport,
                                                    probe: Dict[str, str]):
    """Tier R's `decline` sits beside `honour` as a normal action.

    Two readers with different policies reaching different, both-valid states
    from one judgement is the design working — so declining must never be
    rendered as an error.
    """
    name = "networkops/tier_R · decline is a first-class peer of honour"
    snap = await d.snapshot()
    honour = snap.with_prefix("btn_reader_honour_")
    decline = snap.with_prefix("btn_reader_decline_")
    obs = {"honour": len(honour), "decline": len(decline),
           "route": probe.get("networkops.tier_r")}
    if not decline and not honour:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            "the reader fold is empty — no judgement row exists to inspect",
            observed=obs))
        return
    rep.add(CaseResult(
        name, Status.PASS if len(honour) == len(decline) else Status.FAIL,
        f"{len(decline)} decline / {len(honour)} honour controls",
        observed=obs))


# ═════════════════════════════════════════════════════════════════════════════
# CONSENT — the two grants are NOT the same thing
# ═════════════════════════════════════════════════════════════════════════════
async def case_consent_hold_vs_analyze(d: SurfaceDriver, rep: WalkReport,
                                       probe: Dict[str, str]):
    """`consent:replication:v1` lets a peer HOLD traces; `consent:state:granted:v1`
    scope `analyze` lets one SCORE them. Different dimensions, opposite edge
    directions. Sending traces without the analyze grant is allowed but costs
    reputation and capability-gated services, and some peers refuse outright — so
    a surface offering one control for "traces" while implying the other came
    with it is a real defect.
    """
    name = "consent · HOLD (replication) and SCORE (analyze) are separate grants"
    if not await d.goto("manage_consent", "ManageConsent", group_id="manage"):
        rep.add(CaseResult(name, Status.BLOCKED,
                           "could not reach the Manage Consent surface"))
        return
    snap = await d.snapshot()
    # HOLD — `consent:replication:v1`, driven by POST /v1/federation/peering.
    hold = sorted(t for t in snap.tags
                  if "peering" in t or "replication" in t)
    # SCORE — `consent:state:granted:v1` scope `analyze`.
    analyze = sorted(t for t in snap.tags if "analyze" in t)
    shot = await d.screenshot("consent")
    obs = {"hold_controls": hold or "none",
           "analyze_controls": analyze or "none",
           "surface_tags": sorted(snap.tags - {t for t in snap.tags
                                               if t.startswith("nav_")
                                               or t.startswith("btn_brightness")
                                               or t.startswith("img_")})}
    if hold and analyze:
        rep.add(CaseResult(name, Status.PASS,
                           "both grants separately addressable",
                           observed=obs, screenshot=shot))
        return
    which = []
    if not hold:
        which.append("HOLD (consent:replication:v1)")
    if not analyze:
        which.append("SCORE (consent:state:granted:v1 scope analyze)")
    rep.add(CaseResult(
        name, Status.FAIL,
        "no control for " + " and ".join(which) + " — a peer HOLDING traces and "
        "a peer SCORING them are different dimensions with opposite edge "
        "directions, so one control cannot stand for both, and an operator who "
        "grants replication must not be left assuming analyze came with it",
        observed=obs, screenshot=shot))


# ═════════════════════════════════════════════════════════════════════════════
# LOCALIZATION GATE — pure file check, no app required
# ═════════════════════════════════════════════════════════════════════════════
REPO = Path(__file__).resolve().parents[4]
COMMITTED_BUNDLES = {
    "desktopApp": "client/desktopApp/src/main/resources/localization/en.json",
    "shared/desktopMain": "client/shared/src/desktopMain/resources/localization/en.json",
    "androidApp": "client/androidApp/src/main/assets/localization/en.json",
    "iosApp": "client/iosApp/iosApp/localization/en.json",
}


def case_localization_bundles_mirror(rep: WalkReport) -> CaseResult:
    """The four committed runtime bundles carry the same namespaces.

    `LocalizationManager.getString` returns the KEY when it cannot resolve one.
    That is deliberate — it is how a server-supplied `{id, text}` pair degrades
    to its English `text`. But a screen's OWN static strings have no such
    fallback, so a namespace that reaches only some bundles renders as literal
    dotted ids in the shipped app and nothing in the build says a word. This run
    found exactly that: `operator_ui` (42 ids), `moderation` (89) and `surfaces`
    (122) were present only in `shared/desktopMain`, so SystemScreen printed
    `operator_ui.title` and the whole enforcement ladder printed its key names.

    A pure file check on purpose: it needs no running app and is the cheapest
    possible gate on the defect that cost this walk two entire screens.
    """
    name = "localization · committed bundles carry identical namespaces"
    loaded: Dict[str, Dict[str, Any]] = {}
    for label, rel in COMMITTED_BUNDLES.items():
        p = REPO / rel
        if not p.exists():
            return rep.add(CaseResult(name, Status.BLOCKED, f"bundle absent: {rel}"))
        loaded[label] = json.loads(p.read_text())

    everywhere = set.intersection(*(set(d) for d in loaded.values()))
    anywhere = set.union(*(set(d) for d in loaded.values()))
    divergent = sorted(anywhere - everywhere)
    if not divergent:
        return rep.add(CaseResult(
            name, Status.PASS,
            f"all {len(everywhere)} namespaces present in all {len(loaded)} bundles"))
    detail = {
        ns: sorted(l for l, d in loaded.items() if ns not in d)
        for ns in divergent
    }
    return rep.add(CaseResult(
        name, Status.FAIL,
        f"{len(divergent)} namespace(s) would render as raw dotted ids",
        observed={"missing_from": detail}))


# ═════════════════════════════════════════════════════════════════════════════
# Runner
# ═════════════════════════════════════════════════════════════════════════════
SYSTEM_CASES: Sequence[Case] = (
    case_system_one_arm,
    case_system_absent_route_not_offered,
    case_system_trace_standing,
    case_system_uncomputed_named,
    case_system_edge_halves,
)
MODERATION_CASES: Sequence[Case] = (
    case_moderation_rungs_distinct,
    case_moderation_no_preview_no_commit,
    case_moderation_descend_typed_ack,
)
NETWORKOPS_CASES: Sequence[Case] = (
    case_networkops_renders,
    case_networkops_mode_is_read_not_defaulted,
    case_networkops_tier_s_axes,
    case_networkops_refusal_not_invented,
    case_networkops_decline_is_peer_of_honour,
)
CONSENT_CASES: Sequence[Case] = (case_consent_hold_vs_analyze,)

SUITES: Dict[str, Sequence[Case]] = {
    "system": SYSTEM_CASES,
    "moderation": MODERATION_CASES,
    "networkops": NETWORKOPS_CASES,
    "consent": CONSENT_CASES,
}


async def run_walk(suites: Sequence[str], shot_dir: Optional[str]) -> WalkReport:
    rep = WalkReport()
    case_localization_bundles_mirror(rep)

    async with SurfaceDriver(PORT, Path(shot_dir) if shot_dir else None) as d:
        if not await d.healthy():
            rep.add(CaseResult(
                "driver · test server reachable", Status.FAIL,
                f"http://localhost:{PORT}/health did not answer with testMode=true — "
                "start the app with CIRIS_TEST_MODE=true"))
            return rep
        rep.add(CaseResult("driver · test server reachable", Status.PASS,
                           f"port {PORT}"))

        probe = await probe_routes()
        rep.add(CaseResult("node · surface routes", Status.PASS,
                           "route mount status (unauthenticated probe)",
                           observed=probe))

        if not await d.login(QA_USER, QA_PASSWORD):
            rep.add(CaseResult("driver · signed in", Status.FAIL,
                               f"login as {QA_USER} did not leave the Login screen"))
            return rep
        rep.add(CaseResult("driver · signed in", Status.PASS, f"as {QA_USER}"))

        # Before trusting a single PASS, prove /click actually moves the app.
        fault = await d.verify_click_dispatch("nav_group_node")
        if fault:
            rep.add(CaseResult("driver · programmatic click dispatches", Status.FAIL,
                               fault))
            return rep
        rep.add(CaseResult("driver · programmatic click dispatches", Status.PASS,
                           "a tag click changes the tree"))

        for suite in suites:
            for case in SUITES[suite]:
                try:
                    await case(d, rep, probe)
                except Exception as e:
                    rep.add(CaseResult(getattr(case, "__name__", "case"),
                                       Status.FAIL, f"raised {e!r}"))
    return rep


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", nargs="?", default="walk",
                    choices=["walk", "lint"])
    ap.add_argument("--suites", default="system,moderation,networkops,consent")
    ap.add_argument("--shots", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.mode == "lint":
        rep = WalkReport()
        case_localization_bundles_mirror(rep)
    else:
        suites = [s.strip() for s in a.suites.split(",") if s.strip() in SUITES]
        rep = asyncio.run(run_walk(suites, a.shots))

    print(rep.summary())
    if a.json:
        print(rep.to_json())
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
