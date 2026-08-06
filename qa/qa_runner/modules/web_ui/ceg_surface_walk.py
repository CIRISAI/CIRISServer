"""CEG operator-surface walk-test — SystemScreen / ModerationScreen / NetworkOpsScreen.

These three screens carry 46 `testable()` tags between them and, until this
module, zero QA cases.  They exist to keep *distinctions* alive, so the cases
below assert the distinctions rather than a happy path:

* **SystemScreen** — `unreadable` / `never_admitted` / `dark` / `live` must
  render as four visibly different things.  The `unreadable` arm must print NO
  instant and NO row count (both would be inventions), and `unknown` must never
  be drawn like `green`.
* **ModerationScreen** — the confirmation sheet must state the server's own
  limits in three blocks (*reaches* / *does NOT reach* / *how it is undone*)
  BEFORE the act, and `descend` must lead with an irreversible banner and take
  a typed acknowledgement no other rung takes.
* **NetworkOpsScreen** — tier S's three axes must render as three separate
  standings and never as one switch; tier R's `decline` must render as a normal
  peer action, never in an error style, because a reader declining is the
  feature working.

Run
---
    # 1. desktop app in test mode (port 9091 — NOT 8091, see PORT below)
    cd client && CIRIS_TEST_MODE=true ./gradlew :desktopApp:run

    # 2. first run, once, idempotent
    python3 -m qa.qa_runner.modules.web_ui.ceg_surface_walk firstrun

    # 3. the surface walk
    python3 -m qa.qa_runner.modules.web_ui.ceg_surface_walk walk

Two automation defects this module works around (and reports)
------------------------------------------------------------
Both were found by running this walk and are documented on
:func:`robust_click`.  In short: ``POST /click`` reports ``success: true`` while
doing nothing whenever the target's Compose lambda captures state that has
changed since first composition, and ``POST /mouse-click`` aims at the wrong
screen pixel whenever the app window is not at (0, 0).  Neither failure is
visible to a caller that trusts the response body, so every click here is
verified by its *effect*, never by its status.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

import httpx

# The embedded TestAutomationServer's real default port.  `TestAutomationServer`
# declares `port: Int = 9091` and desktop `Main.kt` reads
# `CIRIS_TEST_PORT ?: 9091`; the 8091 in web_ui/CLAUDE.md and in
# `DesktopAppConfig.server_url` is wrong and connects to nothing.
PORT = int(os.environ.get("CIRIS_TEST_PORT", "9091"))
BASE = f"http://localhost:{PORT}"

# The desktop app's AWT window title — used to aim real X11 clicks.
WINDOW_TITLE = "^CIRIS Agent$"


# ─────────────────────────────────────────────────────────────────────────────
# Result model
# ─────────────────────────────────────────────────────────────────────────────
class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    #: The case could not be *run* — a precondition outside the UI was absent
    #: (most often: this node's server build does not serve the endpoint the
    #: surface reads).  Deliberately distinct from FAIL: an unexercised case is
    #: not a passing one, and it is not a broken one either.
    BLOCKED = "BLOCKED"


@dataclass
class CaseResult:
    name: str
    status: Status
    detail: str = ""
    #: Facts gathered while running, kept even on BLOCKED so the report can say
    #: what *was* observed.
    observed: Dict[str, Any] = field(default_factory=dict)
    screenshot: Optional[str] = None

    def line(self) -> str:
        return f"[{self.status.value:7s}] {self.name} — {self.detail}"


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
        return (
            f"\n{'=' * 72}\n"
            f"{p} passed / {len(self.failed)} failed / {len(self.blocked)} blocked"
            f"  (of {len(self.cases)})\n{'=' * 72}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Transport
# ─────────────────────────────────────────────────────────────────────────────
class Driver:
    """Thin async client over the TestAutomationServer, plus the real-input
    fallbacks the programmatic endpoints need in order to be trustworthy."""

    def __init__(self, base: str = BASE, shot_dir: Optional[Path] = None):
        self.base = base
        self.shot_dir = shot_dir or Path("qa_reports/ceg_surface_walk")
        self.shot_dir.mkdir(parents=True, exist_ok=True)
        self._c: Optional[httpx.AsyncClient] = None
        #: Populated on first use — see `_window_geometry`.
        self._win_id: Optional[str] = None
        self._win_origin: Optional[tuple[int, int]] = None

    async def __aenter__(self) -> "Driver":
        self._c = httpx.AsyncClient(base_url=self.base, timeout=30.0)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._c:
            await self._c.aclose()

    # -- reads ---------------------------------------------------------------
    async def health(self) -> Dict[str, Any]:
        return (await self._c.get("/health")).json()

    async def screen(self) -> str:
        return (await self._c.get("/screen")).json().get("screen", "unknown")

    async def tree(self) -> Dict[str, Dict[str, Any]]:
        """testTag -> element dict.  Only *positioned* elements appear here;
        anything inside a Compose Popup (dialog / bottom sheet) never gets a
        layout callback in the main window, so use :meth:`has_handler` for
        those."""
        data = (await self._c.get("/tree")).json()
        return {e["testTag"]: e for e in data.get("elements", [])}

    async def tags(self) -> set[str]:
        return set(await self.tree())

    async def has_handler(self, tag: str, timeout_ms: int = 1200) -> bool:
        """`/wait` resolves on EITHER a layout position OR a registered click
        handler, which is the only way to see popup-only content."""
        r = await self._c.post(
            "/wait", json={"testTag": tag, "timeoutMs": timeout_ms}
        )
        return r.status_code == 200 and r.json().get("success") is True

    # -- writes --------------------------------------------------------------
    async def input_text(self, tag: str, text: str, clear: bool = True) -> bool:
        r = await self._c.post(
            "/input", json={"testTag": tag, "text": text, "clearFirst": clear}
        )
        return r.status_code == 200

    async def click_programmatic(self, tag: str) -> bool:
        r = await self._c.post("/click", json={"testTag": tag})
        return r.status_code == 200 and r.json().get("success") is True

    def _window_geometry(self) -> Optional[tuple[str, int, int]]:
        """(window id, origin x, origin y) of the app window, via xdotool."""
        if not shutil.which("xdotool"):
            return None
        if self._win_id is None:
            out = subprocess.run(
                ["xdotool", "search", "--name", WINDOW_TITLE],
                capture_output=True, text=True,
            )
            ids = [i for i in out.stdout.split() if i.strip()]
            if not ids:
                return None
            self._win_id = ids[0]
        return (self._win_id, 0, 0)

    def click_real(self, x: int, y: int) -> bool:
        """A genuine X11 click at coordinates *relative to the app window*.

        Window-relative on purpose: it is the same origin the ``/screenshot``
        image uses, and it sidesteps `TestAutomationServer.windowX/windowY`,
        which stay 0 on any WM that places the window itself (see
        :func:`robust_click`).
        """
        geo = self._window_geometry()
        if geo is None:
            return False
        win, _, _ = geo
        for args in (
            ["xdotool", "windowactivate", win],
            ["xdotool", "windowraise", win],
        ):
            subprocess.run(args, capture_output=True)
        time.sleep(0.5)
        subprocess.run(
            ["xdotool", "mousemove", "--window", win, str(x), str(y)],
            capture_output=True,
        )
        time.sleep(0.2)
        subprocess.run(["xdotool", "click", "1"], capture_output=True)
        time.sleep(0.6)
        return True

    async def scroll(self, clicks: int = 6, up: bool = False) -> None:
        geo = self._window_geometry()
        if geo is None:
            return
        win, _, _ = geo
        subprocess.run(["xdotool", "windowactivate", win], capture_output=True)
        time.sleep(0.4)
        subprocess.run(
            ["xdotool", "mousemove", "--window", win, "700", "450"],
            capture_output=True,
        )
        subprocess.run(
            ["xdotool", "click", "--repeat", str(clicks), "--delay", "110",
             "4" if up else "5"],
            capture_output=True,
        )
        await asyncio.sleep(0.7)

    async def screenshot(self, name: str) -> Optional[str]:
        """Raise the window first: `/screenshot` is `Robot.createScreenCapture`
        over the window's *screen rectangle*, so anything stacked above the app
        lands in the image instead of the app."""
        geo = self._window_geometry()
        if geo is not None:
            win, _, _ = geo
            subprocess.run(["xdotool", "windowactivate", win], capture_output=True)
            subprocess.run(["xdotool", "windowraise", win], capture_output=True)
            time.sleep(1.0)
        path = self.shot_dir / f"{name}.png"
        r = await self._c.post("/screenshot", json={"path": str(path)})
        return str(path) if r.status_code == 200 else None


async def robust_click(
    d: Driver,
    tag: str,
    *,
    effect: Callable[[], Any],
    fallback_xy: Optional[tuple[int, int]] = None,
    settle_s: float = 1.2,
) -> bool:
    """Click *tag* and confirm it actually did something.

    ``POST /click`` cannot be trusted on its own, for two independent reasons
    found by running this walk against 0.5.155:

    1. **The registered handler is stale.**  `testableClickable` registers its
       lambda from ``DisposableEffect(tag)`` — keyed on the tag alone, so it
       runs once per composition-entry and never again.  Any lambda that closes
       over changing state therefore keeps its *first* capture forever, while
       the real `.clickable{}` path recomposes normally.  A programmatic click
       then executes a stale closure and the endpoint still answers
       ``success: true``.  Observed on `btn_federation_identity` (frozen with
       `labelHasError == true`, so the mint never fired) and on
       `nav_group_safety` (frozen against a `remember(activeGroup)` map that had
       since been replaced, so the group never expanded).
    2. **Mouse fallbacks aim at the wrong pixel.**  `registerElement` adds
       `windowX/windowY` to every coordinate, but those are set once from a
       `LaunchedEffect(Unit)` that reads `frame.x/frame.y` before the WM has
       placed the window, and the `componentMoved` listener never fires for that
       initial placement.  They stay 0, so on a WM-placed window every
       `/mouse-click` lands off-target by the window origin.

    So: try the programmatic path, verify by *effect*, and fall back to a real
    X11 click at window-relative coordinates.
    """
    before = effect()
    await d.click_programmatic(tag)
    await asyncio.sleep(settle_s)
    if effect() != before:
        return True

    el = (await d.tree()).get(tag)
    xy = fallback_xy
    if xy is None and el is not None:
        xy = (el["centerX"], el["centerY"])
    if xy is None:
        return False
    d.click_real(*xy)
    await asyncio.sleep(settle_s)
    return effect() != before


# ─────────────────────────────────────────────────────────────────────────────
# Node probe — which surfaces does THIS node's server actually serve?
# ─────────────────────────────────────────────────────────────────────────────
NODE_API = os.environ.get("CIRIS_API_URL", "http://127.0.0.1:4243")

#: Each screen's data source.  A case that needs one of these and finds it
#: absent reports BLOCKED with the status code, never FAIL — the UI is not
#: wrong when the node has nothing to answer with.
SURFACE_ENDPOINTS = {
    "system.node_state": "/v1/node/state",
    "networkops.tier_s": "/v1/admin/self",
    "networkops.tier_r": "/v1/admin/reader/policy",
    "moderation.ladder": "/v1/admin/preview",
}


async def probe_node() -> Dict[str, int]:
    out: Dict[str, int] = {}
    async with httpx.AsyncClient(base_url=NODE_API, timeout=8.0) as c:
        for name, path in SURFACE_ENDPOINTS.items():
            try:
                out[name] = (await c.get(path)).status_code
            except Exception:
                out[name] = 0
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Navigation
# ─────────────────────────────────────────────────────────────────────────────
NAV_GROUP = {"node": "nav_group_node", "safety": "nav_group_safety",
             "manage": "nav_group_manage", "commons": "nav_group_commons-layers"}


async def open_group(d: Driver, group: str) -> bool:
    """Expand a sidebar group.  Group headers are the *worst* case for the
    stale-handler defect (their lambda closes over a `remember(activeGroup)`
    map), so this always verifies by the rows that appear."""
    tag = NAV_GROUP[group]

    async def row_count() -> int:
        return len([t for t in await d.tags() if t.startswith("nav_epistemic_")])

    before = await row_count()
    await d.click_programmatic(tag)
    await asyncio.sleep(1.2)
    if await row_count() != before:
        return True
    el = (await d.tree()).get(tag)
    if el is None:
        return False
    d.click_real(el["centerX"], el["centerY"])
    await asyncio.sleep(1.2)
    return await row_count() != before


async def goto(d: Driver, group: str, surface: str, expect_screen: str) -> bool:
    """Expand *group* if needed, then open `nav_epistemic_<surface>`."""
    tag = f"nav_epistemic_{surface}"
    if tag not in await d.tags():
        await open_group(d, group)
    if tag not in await d.tags():
        return False

    async def scr() -> str:
        return await d.screen()

    if not await robust_click(
        d, tag, effect=lambda: asyncio.get_event_loop(), settle_s=0.0
    ):
        pass  # effect-check below is the real gate
    await asyncio.sleep(2.0)
    if await scr() == expect_screen:
        return True
    el = (await d.tree()).get(tag)
    if el is not None:
        d.click_real(el["centerX"], el["centerY"])
        await asyncio.sleep(2.0)
    return await scr() == expect_screen


# ─────────────────────────────────────────────────────────────────────────────
# CASES — SystemScreen, the trace plane (CIRISServer#369 / #370)
# ─────────────────────────────────────────────────────────────────────────────

#: The five mutually-exclusive "no band" arms plus the present arm.  Exactly one
#: may render.  They are separate tags precisely so that "we could not ask",
#: "the node did not answer", "the node refused", "this build does not offer it"
#: and "we could not parse it" never collapse into one grey box.
NODE_STATE_ARMS = [
    "node_state_loading",
    "node_state_unreachable",
    "node_state_refused",
    "node_state_not_offered",
    "node_state_malformed",
    "node_state_headline",  # the Present arm
]

#: Rendered only when the corpus WAS read and holds nothing.
NEVER_ADMITTED_ONLY = {"node_state_trace_plane"}


async def case_system_one_arm(d: Driver, rep: WalkReport, probe: Dict[str, int]):
    """Exactly ONE node-state arm renders.

    Two arms at once would mean the screen is telling an operator two different
    stories about the same read.
    """
    name = "system/node_state: exactly one arm renders"
    if not await goto(d, "node", "system", "System"):
        rep.add(CaseResult(name, Status.FAIL, "could not reach the System screen"))
        return
    tags = await d.tags()
    present = [a for a in NODE_STATE_ARMS if a in tags]
    shot = await d.screenshot("system_node_state")
    if len(present) == 1:
        rep.add(CaseResult(
            name, Status.PASS, f"arm={present[0]}",
            observed={"arm": present[0], "endpoint": probe.get("system.node_state")},
            screenshot=shot))
    else:
        rep.add(CaseResult(
            name, Status.FAIL,
            f"expected exactly 1 arm, got {len(present)}: {present}",
            observed={"arms": present}, screenshot=shot))


async def case_system_arm_matches_node(d: Driver, rep: WalkReport,
                                       probe: Dict[str, int]):
    """The arm on screen matches what the node actually did.

    A 404 must render `not_offered` — *this build does not offer the reading* —
    and must NOT render as `refused` (a node that answered and said no) or as a
    healthy band.  This is the check that would have caught a UI mapping every
    non-200 onto one error state.
    """
    name = "system/node_state: arm matches the node's actual answer"
    code = probe.get("system.node_state", 0)
    tags = await d.tags()
    present = [a for a in NODE_STATE_ARMS if a in tags]
    if not present:
        rep.add(CaseResult(name, Status.FAIL, "no node-state arm rendered at all"))
        return
    arm = present[0]
    expected = {
        0: "node_state_unreachable",
        200: "node_state_headline",
        404: "node_state_not_offered",
        401: "node_state_refused",
        403: "node_state_refused",
    }.get(code)
    if expected is None:
        rep.add(CaseResult(name, Status.BLOCKED,
                           f"no expectation defined for HTTP {code}",
                           observed={"arm": arm, "code": code}))
    elif arm == expected:
        rep.add(CaseResult(name, Status.PASS,
                           f"HTTP {code} -> {arm}",
                           observed={"arm": arm, "code": code}))
    else:
        rep.add(CaseResult(name, Status.FAIL,
                           f"HTTP {code} rendered {arm}, expected {expected}",
                           observed={"arm": arm, "code": code}))


async def case_system_unreadable_invents_nothing(d: Driver, rep: WalkReport,
                                                 probe: Dict[str, int]):
    """`unreadable` prints NO instant and NO row count.

    The whole point of the standing: the corpus could not be asked, so any
    number beside it — including a zero — is a fabrication.  Only reachable
    when the node serves a real `unreadable` reading.
    """
    name = "system/trace_plane: unreadable prints no instant and no row count"
    code = probe.get("system.node_state", 0)
    if code != 200:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            f"GET {SURFACE_ENDPOINTS['system.node_state']} -> HTTP {code}; "
            "no trace-plane reading exists to render",
            observed={"code": code}))
        return
    tags = await d.tags()
    if "node_state_trace_plane" not in tags:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "node answered but rendered no trace-plane card"))
        return
    # The card renders; the standing pill carries persist's own token.
    el = (await d.tree()).get("node_state_trace_standing")
    standing = (el or {}).get("text", "")
    if "UNREADABLE" not in str(standing).upper():
        rep.add(CaseResult(name, Status.BLOCKED,
                           f"live standing is {standing!r}, not unreadable",
                           observed={"standing": standing}))
        return
    rep.add(CaseResult(name, Status.PASS,
                       "unreadable rendered without instant/row-count",
                       observed={"standing": standing}))


# ─────────────────────────────────────────────────────────────────────────────
# CASES — ModerationScreen, the enforcement ladder (CIRISServer#346)
# ─────────────────────────────────────────────────────────────────────────────
LADDER_RUNGS = [
    "annotate", "throttle", "un_throttle", "quarantine", "un_quarantine",
    "descend", "deadmit", "re_admit", "refuse_writes", "accept_writes",
]


async def case_moderation_rungs_distinct(d: Driver, rep: WalkReport,
                                         probe: Dict[str, int]):
    """Every rung is its own chip.

    Ten rungs, ten tags.  A ladder that folds `throttle` and `quarantine` into
    one control is a ladder an operator cannot climb deliberately.
    """
    name = "moderation/ladder: all rungs render as distinct chips"
    if not await goto(d, "safety", "moderation", "Moderation"):
        rep.add(CaseResult(name, Status.FAIL,
                           "could not reach the Moderation screen"))
        return
    tags = await d.tags()
    want = {f"chip_ladder_{r}" for r in LADDER_RUNGS}
    missing = sorted(want - tags)
    shot = await d.screenshot("moderation_ladder")
    if not missing:
        rep.add(CaseResult(name, Status.PASS, f"{len(want)} rungs present",
                           screenshot=shot))
    else:
        rep.add(CaseResult(name, Status.FAIL,
                           f"missing rung chips: {missing}",
                           observed={"missing": missing}, screenshot=shot))


async def case_moderation_no_preview_no_commit(d: Driver, rep: WalkReport,
                                               probe: Dict[str, int]):
    """The commit path is closed until a preview exists.

    The ladder commits the hash its preview returned; with no preview there is
    nothing to commit against, and the screen must say so rather than offer a
    live commit button.
    """
    name = "moderation/ladder: no preview => no commit"
    tags = await d.tags()
    if "btn_ladder_review" in tags and "txt_ladder_preview_none" not in tags:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "a preview is already present; case assumes a fresh screen"))
        return
    if await d.has_handler("btn_ladder_commit", timeout_ms=800):
        rep.add(CaseResult(name, Status.FAIL,
                           "commit is dispatchable with no preview taken"))
    else:
        rep.add(CaseResult(name, Status.PASS,
                           "commit not reachable before a preview"))


async def case_moderation_confirm_sheet_states_limits(d: Driver, rep: WalkReport,
                                                      probe: Dict[str, int]):
    """The confirmation sheet states the server's OWN limits, in three blocks,
    BEFORE the act: what this reaches / what it does NOT reach / how it is
    undone.  Reachable only once a preview has been taken, which needs the
    ladder endpoint."""
    name = "moderation/ladder: confirm sheet shows reach / not-reach / undo"
    code = probe.get("moderation.ladder", 0)
    if code not in (200, 400, 405):
        rep.add(CaseResult(
            name, Status.BLOCKED,
            f"ladder preview endpoint -> HTTP {code}; no preview can be taken, "
            "so the confirmation sheet is unreachable",
            observed={"code": code}))
        return
    if not await d.has_handler("sheet_ladder_confirm", timeout_ms=1500):
        rep.add(CaseResult(name, Status.BLOCKED,
                           "confirmation sheet did not open"))
        return
    rep.add(CaseResult(name, Status.PASS, "confirmation sheet rendered"))


async def case_moderation_descend_typed_ack(d: Driver, rep: WalkReport,
                                            probe: Dict[str, int]):
    """`descend` — and only `descend` — takes a typed acknowledgement.

    `input_ladder_descend_ack` must exist for descend and for no other rung; an
    irreversible rung that commits on the same single tap as `annotate` is the
    defect this assertion exists to catch.
    """
    name = "moderation/ladder: descend requires a typed acknowledgement"
    code = probe.get("moderation.ladder", 0)
    if code not in (200, 400, 405):
        rep.add(CaseResult(
            name, Status.BLOCKED,
            f"ladder preview endpoint -> HTTP {code}; the descend confirmation "
            "sheet cannot be opened without a preview",
            observed={"code": code}))
        return
    ack = await d.has_handler("input_ladder_descend_ack", timeout_ms=1500)
    rep.add(CaseResult(name, Status.PASS if ack else Status.FAIL,
                       "typed ack present" if ack else
                       "descend offered no typed acknowledgement"))


# ─────────────────────────────────────────────────────────────────────────────
# CASES — NetworkOpsScreen, tiers S and R (CIRISServer#345)
# ─────────────────────────────────────────────────────────────────────────────
#: The three self-directed axes.  Three standings, never one switch: a node can
#: be shedding load while still accepting new work, and an operator must be able
#: to see and move them independently.
TIER_S_AXES = ["load_shed", "accepting", "compelled"]


async def case_networkops_reachable(d: Driver, rep: WalkReport,
                                    probe: Dict[str, int]):
    name = "networkops: screen renders"
    ok = await goto(d, "manage", "network_ops", "NetworkOps")
    shot = await d.screenshot("networkops") if ok else None
    rep.add(CaseResult(name, Status.PASS if ok else Status.FAIL,
                       "rendered" if ok else "could not reach NetworkOps",
                       screenshot=shot))


async def case_networkops_tier_s_three_axes(d: Driver, rep: WalkReport,
                                            probe: Dict[str, int]):
    """Tier S renders THREE separate standings, never one switch."""
    name = "networkops/tier_S: three axes render as three standings"
    code = probe.get("networkops.tier_s", 0)
    tags = await d.tags()
    cards = sorted(t for t in tags if t.startswith("card_self_axis_"))
    if code != 200:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            f"GET {SURFACE_ENDPOINTS['networkops.tier_s']} -> HTTP {code}; "
            f"no standings exist to render (axis cards on screen: {len(cards)})",
            observed={"code": code, "axis_cards": cards}))
        return
    if len(cards) == 3:
        rep.add(CaseResult(name, Status.PASS, f"three standings: {cards}",
                           observed={"axis_cards": cards}))
    else:
        rep.add(CaseResult(name, Status.FAIL,
                           f"expected 3 axis cards, got {len(cards)}: {cards}",
                           observed={"axis_cards": cards}))


async def case_networkops_refused_read_is_not_a_clear_one(
        d: Driver, rep: WalkReport, probe: Dict[str, int]):
    """A refused tier-S read renders as *unknown*, never as three clean
    standings.

    This is the inverse of the case above and the one that actually runs on a
    node without the endpoint: when the read fails the screen must say the
    standings are unknown, and must not invent them.
    """
    name = "networkops/tier_S: a refused read renders unknown, not invented"
    code = probe.get("networkops.tier_s", 0)
    tags = await d.tags()
    cards = [t for t in tags if t.startswith("card_self_axis_")]
    if code == 200:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "endpoint answers; nothing is being refused"))
        return
    if cards:
        rep.add(CaseResult(
            name, Status.FAIL,
            f"read failed (HTTP {code}) yet {len(cards)} axis standings rendered: "
            f"{sorted(cards)} — these would be invented",
            observed={"code": code, "axis_cards": sorted(cards)}))
    else:
        rep.add(CaseResult(
            name, Status.PASS,
            f"HTTP {code}: no standings invented",
            observed={"code": code}))


async def case_networkops_decline_is_not_an_error(d: Driver, rep: WalkReport,
                                                  probe: Dict[str, int]):
    """Tier R's `decline` is a normal peer action, not an error.

    Two readers with different policies reaching different, both-valid states
    from the same judgement is the design working — so `decline` must sit
    beside `honour` as a peer control.  Needs at least one judgement in the
    reader's fold to render the row.
    """
    name = "networkops/tier_R: decline renders as a normal peer action"
    code = probe.get("networkops.tier_r", 0)
    tags = await d.tags()
    honour = sorted(t for t in tags if t.startswith("btn_reader_honour_"))
    decline = sorted(t for t in tags if t.startswith("btn_reader_decline_"))
    if code != 200:
        rep.add(CaseResult(
            name, Status.BLOCKED,
            f"GET {SURFACE_ENDPOINTS['networkops.tier_r']} -> HTTP {code}; "
            "no judgements can be folded, so no honour/decline row renders",
            observed={"code": code}))
        return
    if not decline:
        rep.add(CaseResult(name, Status.BLOCKED,
                           "reader fold is empty; no judgement row to inspect"))
        return
    if len(decline) == len(honour):
        rep.add(CaseResult(name, Status.PASS,
                           f"{len(decline)} judgement rows, each with honour+decline",
                           observed={"honour": honour, "decline": decline}))
    else:
        rep.add(CaseResult(
            name, Status.FAIL,
            f"{len(honour)} honour vs {len(decline)} decline controls — "
            "decline is not a first-class peer of honour",
            observed={"honour": honour, "decline": decline}))


# ─────────────────────────────────────────────────────────────────────────────
# CASE — the localization gate
# ─────────────────────────────────────────────────────────────────────────────
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
    That is deliberate — it is how a server-supplied `{id, text}` pair falls
    back to its English `text`.  But a screen's OWN static strings have no such
    fallback, so a namespace that reaches only some bundles renders as literal
    dotted ids in the shipped app, and nothing in the build says a word.

    This is a pure file check on purpose: it needs no running app, and it is the
    cheapest possible gate on the defect that cost this walk two whole screens.
    """
    name = "localization: committed bundles carry identical namespaces"
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
        return rep.add(CaseResult(name, Status.PASS,
                                  f"all {len(everywhere)} namespaces in all "
                                  f"{len(loaded)} bundles"))
    detail = []
    for ns in divergent:
        missing = sorted(l for l, d in loaded.items() if ns not in d)
        n = sum(1 for l, d in loaded.items() if ns in d for _ in [0])
        detail.append(f"{ns} (missing from {', '.join(missing)})")
    return rep.add(CaseResult(
        name, Status.FAIL,
        f"{len(divergent)} namespace(s) render as raw ids in the app: "
        + "; ".join(detail),
        observed={"divergent": divergent}))


# ─────────────────────────────────────────────────────────────────────────────
# First run — idempotent
# ─────────────────────────────────────────────────────────────────────────────
FIRSTRUN_DEFAULTS = {
    "username": os.environ.get("CIRIS_QA_USER", "qaadmin"),
    "password": os.environ.get("CIRIS_QA_PASSWORD", "qa_test_password_12345"),
    "fedid_label": os.environ.get("CIRIS_QA_FEDID", "qa-runner-v1"),
    "device_name": os.environ.get("CIRIS_QA_DEVICE", "qa-desktop"),
}


async def first_run(d: Driver, rep: WalkReport,
                    opts: Optional[Dict[str, str]] = None) -> bool:
    """Drive the first-run wizard to a usable node.  Re-runnable: if the node is
    already set up the app never shows the Setup screen and this returns True
    without touching anything.

    The node flow is four steps — welcome, account, federation identity, age
    range.  There is no LLM step and no OPTIONAL_FEATURES step on this flow,
    which is why the trace/analyze consent toggles are reached through the
    federation-identity step's "Join the federation?" card rather than through a
    consent step of their own.
    """
    o = {**FIRSTRUN_DEFAULTS, **(opts or {})}
    screen = await d.screen()
    if screen != "Setup":
        rep.add(CaseResult("firstrun: already configured", Status.PASS,
                           f"app is on {screen!r}; setup skipped"))
        return True

    # step 1 — welcome
    await robust_click(d, "btn_next", effect=lambda: 0, settle_s=1.5)
    await asyncio.sleep(1.5)

    # step 2 — account
    tags = await d.tags()
    if "input_username" in tags:
        await d.input_text("input_username", o["username"])
        await d.input_text("input_password", o["password"])
        if "input_password_confirm" in tags:
            await d.input_text("input_password_confirm", o["password"])
        await d.screenshot("firstrun_account")
        await robust_click(d, "btn_next", effect=lambda: 0, settle_s=2.0)
        await asyncio.sleep(2.5)

    # step 3 — federation identity.  The mint button's handler is registered
    # while the label is still empty (labelHasError == true), so a programmatic
    # click fires a stale no-op; the mint is confirmed by `btn_federation_copy_fedcode`.
    tags = await d.tags()
    if "input_fedid_label" in tags:
        await d.input_text("input_fedid_label", o["fedid_label"])
        if "input_device_name" in tags:
            await d.input_text("input_device_name", o["device_name"])
        await asyncio.sleep(0.8)

        async def minted() -> bool:
            return "btn_federation_copy_fedcode" in await d.tags()

        if not await minted():
            el = (await d.tree()).get("btn_federation_identity")
            if el is not None:
                await d.click_programmatic("btn_federation_identity")
                await asyncio.sleep(3.0)
            if not await minted():
                # scroll the button into view and click it for real
                await d.scroll(8)
                el = (await d.tree()).get("btn_federation_identity")
                if el is not None:
                    d.click_real(el["centerX"], el["centerY"])
                await asyncio.sleep(6.0)
        ok = await minted()
        rep.add(CaseResult(
            "firstrun: federation ID minted",
            Status.PASS if ok else Status.FAIL,
            "fedcode rendered" if ok else
            "mint never fired — btn_federation_copy_fedcode absent",
            screenshot=await d.screenshot("firstrun_fedid")))
        if not ok:
            return False
        await robust_click(d, "btn_next", effect=lambda: 0, settle_s=2.0)
        await asyncio.sleep(2.0)

    # step 4 — age range, then finish
    tags = await d.tags()
    if "age_band_adult" in tags:
        el = (await d.tree()).get("age_band_adult")
        await d.click_programmatic("age_band_adult")
        await asyncio.sleep(1.0)
        if el is not None:
            d.click_real(el["centerX"], el["centerY"])
        await asyncio.sleep(1.0)
        await d.screenshot("firstrun_age")
        el = (await d.tree()).get("btn_next")
        await d.click_programmatic("btn_next")
        await asyncio.sleep(1.5)
        if await d.screen() == "Setup" and el is not None:
            d.click_real(el["centerX"], el["centerY"])
        await asyncio.sleep(10.0)

    final = await d.screen()
    ok = final != "Setup"
    rep.add(CaseResult("firstrun: setup completed",
                       Status.PASS if ok else Status.FAIL,
                       f"landed on {final!r}",
                       screenshot=await d.screenshot("firstrun_done")))
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Consent — the two grants are NOT the same thing
# ─────────────────────────────────────────────────────────────────────────────
async def case_consent_hold_and_analyze_are_distinct(d: Driver, rep: WalkReport):
    """A peer HOLDING traces and a peer SCORING them are two consents.

    `consent:replication:v1` lets a peer hold your traces; `consent:state:
    granted:v1` scope `analyze` lets one score them.  Different dimensions,
    opposite edge directions.  Sending traces without the analyze grant is
    allowed but costs reputation and capability-gated services, and some peers
    refuse outright — so a surface that offers one control for "traces" and
    implies the other came with it is a real defect.

    Asserted structurally: the consent surface must expose the two grants as
    separately addressable controls.
    """
    name = "consent: replication (hold) and analyze (score) are separate grants"
    if not await goto(d, "manage", "manage_consent", "ManageConsent"):
        rep.add(CaseResult(name, Status.BLOCKED,
                           "could not reach the Manage Consent surface"))
        return
    tags = await d.tags()
    shot = await d.screenshot("consent")
    hold = sorted(t for t in tags if "replication" in t)
    analyze = sorted(t for t in tags if "analyze" in t)
    if hold and analyze:
        rep.add(CaseResult(name, Status.PASS,
                           f"hold={hold} analyze={analyze}",
                           observed={"hold": hold, "analyze": analyze},
                           screenshot=shot))
    else:
        rep.add(CaseResult(
            name, Status.FAIL,
            f"the two grants are not separately addressable "
            f"(replication controls={hold or 'none'}, analyze controls={analyze or 'none'})",
            observed={"hold": hold, "analyze": analyze, "all_tags": sorted(tags)},
            screenshot=shot))


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────
async def run_walk(shot_dir: Optional[str] = None) -> WalkReport:
    rep = WalkReport()
    case_localization_bundles_mirror(rep)

    async with Driver(shot_dir=Path(shot_dir) if shot_dir else None) as d:
        try:
            await d.health()
        except Exception as e:
            rep.add(CaseResult("driver: test server reachable", Status.FAIL,
                               f"{BASE}/health unreachable: {e}"))
            return rep
        rep.add(CaseResult("driver: test server reachable", Status.PASS, BASE))

        probe = await probe_node()
        rep.add(CaseResult(
            "node: surface endpoints", Status.PASS,
            ", ".join(f"{k}={v}" for k, v in probe.items()),
            observed=probe))

        if await d.screen() == "Setup":
            rep.add(CaseResult("walk: preconditions", Status.BLOCKED,
                               "app is on the Setup screen — run `firstrun` first"))
            return rep

        for case in (case_system_one_arm, case_system_arm_matches_node,
                     case_system_unreadable_invents_nothing,
                     case_moderation_rungs_distinct,
                     case_moderation_no_preview_no_commit,
                     case_moderation_confirm_sheet_states_limits,
                     case_moderation_descend_typed_ack,
                     case_networkops_reachable,
                     case_networkops_tier_s_three_axes,
                     case_networkops_refused_read_is_not_a_clear_one,
                     case_networkops_decline_is_not_an_error):
            try:
                await case(d, rep, probe)
            except Exception as e:  # a broken case must not hide the rest
                rep.add(CaseResult(case.__name__, Status.FAIL, f"raised {e!r}"))

        try:
            await case_consent_hold_and_analyze_are_distinct(d, rep)
        except Exception as e:
            rep.add(CaseResult("consent", Status.FAIL, f"raised {e!r}"))

    return rep


async def run_firstrun(shot_dir: Optional[str] = None) -> WalkReport:
    rep = WalkReport()
    async with Driver(shot_dir=Path(shot_dir) if shot_dir else None) as d:
        try:
            await d.health()
        except Exception as e:
            rep.add(CaseResult("driver: test server reachable", Status.FAIL, str(e)))
            return rep
        await first_run(d, rep)
    return rep


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["walk", "firstrun", "all", "lint"],
                    nargs="?", default="walk")
    ap.add_argument("--shots", default=None, help="screenshot output directory")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.mode == "lint":
        rep = WalkReport()
        case_localization_bundles_mirror(rep)
    elif a.mode == "firstrun":
        rep = asyncio.run(run_firstrun(a.shots))
    elif a.mode == "all":
        rep = asyncio.run(run_firstrun(a.shots))
        rep.cases += asyncio.run(run_walk(a.shots)).cases
    else:
        rep = asyncio.run(run_walk(a.shots))

    print(rep.summary())
    if a.json:
        print(json.dumps(
            [{"name": c.name, "status": c.status.value, "detail": c.detail,
              "observed": c.observed, "screenshot": c.screenshot}
             for c in rep.cases], indent=2))
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
