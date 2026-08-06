"""Pure-testTag driver for the CIRIS desktop TestAutomationServer.

**Everything here goes through a testTag.** No synthetic mouse events, no window
manager tooling, no screen coordinates. That is a deliberate constraint, not a
convenience:

* A coordinate-driven click is aimed by the harness, so it can miss — and it
  misses *silently*, reporting success while landing on whatever pixel it
  computed. That is what `TestAutomationServer.windowX/windowY` did on every
  WM-placed window until it was fixed: an actuator acting on the wrong
  coordinates is worse than a check that reports the wrong answer, because
  nothing downstream can tell.
* A testTag-driven click is aimed by the *app*. It either dispatches to a
  registered handler or it does not exist, and both are honest outcomes.

The endpoints used here are exactly the shared ones (`/health`, `/screen`,
`/tree`, `/element/{tag}`, `/act`, `/click`, `/input`, `/wait`) plus
`/screenshot`, which raises the window itself.

Two harness defects this driver assumes FIXED (they are, in this tree):

1. `testableClickable` registered its lambda from `DisposableEffect(tag)`, so a
   handler that closed over changing state kept its first capture forever and a
   programmatic click executed a stale closure while `/click` still answered
   `success: true`. Now indirected through `rememberUpdatedState`.
2. `/screenshot` captured a screen rectangle without raising the window, so it
   could return a perfect picture of some other window. Now raises first.

If you are running against an older build, `verify_click_dispatch()` below will
tell you rather than letting the walk report green.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

DEFAULT_PORT = 9091


@dataclass
class Element:
    """One registered UI element. `text` is present only when the composable
    passed it to `testable(tag, text)` — which the surfaces do for values whose
    CONTENT is the assertion (band tokens, standings, counts)."""

    test_tag: str
    x: int
    y: int
    width: int
    height: int
    center_x: int
    center_y: int
    text: Optional[str] = None

    @classmethod
    def parse(cls, d: Dict[str, Any]) -> "Element":
        return cls(
            test_tag=d["testTag"], x=d.get("x", 0), y=d.get("y", 0),
            width=d.get("width", 0), height=d.get("height", 0),
            center_x=d.get("centerX", 0), center_y=d.get("centerY", 0),
            text=d.get("text"),
        )


@dataclass
class Snapshot:
    """What the app looked like at one instant: the screen plus every element
    it published. Cases assert against this rather than against pixels."""

    screen: str
    elements: Dict[str, Element] = field(default_factory=dict)

    def __contains__(self, tag: str) -> bool:
        return tag in self.elements

    @property
    def tags(self) -> Set[str]:
        return set(self.elements)

    def text(self, tag: str) -> Optional[str]:
        el = self.elements.get(tag)
        return el.text if el else None

    def token(self, tag: str) -> str:
        """The wire token a pill/standing published, normalised for comparison.
        Empty string when the element is absent OR published no text — the
        caller must treat those as different from a token it recognises."""
        return (self.text(tag) or "").strip().lower().replace(" ", "_")

    def with_prefix(self, prefix: str) -> List[str]:
        return sorted(t for t in self.elements if t.startswith(prefix))


class SurfaceDriver:
    """Async, testTag-only client."""

    def __init__(self, port: int = DEFAULT_PORT, shot_dir: Optional[Path] = None):
        self.base = f"http://localhost:{port}"
        self.shot_dir = shot_dir or Path("qa_reports/ceg_surface_walk")
        self.shot_dir.mkdir(parents=True, exist_ok=True)
        self._c: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SurfaceDriver":
        self._c = httpx.AsyncClient(base_url=self.base, timeout=40.0)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._c:
            await self._c.aclose()

    # ── reads ───────────────────────────────────────────────────────────────
    async def healthy(self) -> bool:
        try:
            r = await self._c.get("/health")
            return r.status_code == 200 and r.json().get("testMode") is True
        except Exception:
            return False

    async def screen(self) -> str:
        return (await self._c.get("/screen")).json().get("screen", "unknown")

    async def snapshot(self) -> Snapshot:
        d = (await self._c.get("/tree")).json()
        return Snapshot(
            screen=d.get("screen", "unknown"),
            elements={e["testTag"]: Element.parse(e) for e in d.get("elements", [])},
        )

    async def exists(self, tag: str, timeout_ms: int = 1500) -> bool:
        """True when the tag has a layout position OR a registered click
        handler. The handler arm matters: anything inside a Compose Popup
        (AlertDialog, ModalBottomSheet) never reports a layout position to the
        main window, so `/tree` alone cannot see dialog content at all."""
        r = await self._c.post("/wait", json={"testTag": tag, "timeoutMs": timeout_ms})
        return r.status_code == 200 and r.json().get("success") is True

    # ── writes ──────────────────────────────────────────────────────────────
    async def type_into(self, tag: str, text: str, clear: bool = True) -> bool:
        r = await self._c.post(
            "/input", json={"testTag": tag, "text": text, "clearFirst": clear}
        )
        return r.status_code == 200 and r.json().get("success") is True

    async def act(self, tag: str, wait_ms: int = 1200,
                  filter_tags: Optional[List[str]] = None) -> Snapshot:
        """Click and read back in one call. The returned snapshot is the app's
        answer — always assert on THAT, never on the click's own status."""
        body: Dict[str, Any] = {"testTag": tag, "action": "click", "waitMs": wait_ms}
        if filter_tags:
            body["filterTags"] = filter_tags
        r = await self._c.post("/act", json=body)
        d = r.json()
        return Snapshot(
            screen=d.get("screen", "unknown"),
            elements={e["testTag"]: Element.parse(e)
                      for e in d.get("elements", [])},
        )

    async def click(self, tag: str, settle_s: float = 1.0) -> bool:
        r = await self._c.post("/click", json={"testTag": tag})
        ok = r.status_code == 200 and r.json().get("success") is True
        await asyncio.sleep(settle_s)
        return ok

    async def screenshot(self, name: str) -> Optional[str]:
        path = self.shot_dir / f"{name}.png"
        r = await self._c.post("/screenshot", json={"path": str(path)})
        return str(path) if r.status_code == 200 else None

    # ── harness self-check ──────────────────────────────────────────────────
    async def verify_click_dispatch(self, toggle_tag: str) -> Optional[str]:
        """Confirm a programmatic click actually MOVES the app.

        Clicking a collapsible nav group is the sharpest available probe,
        because its handler closes over a `remember(...)` map that is replaced
        whenever the active surface changes — precisely the shape that the old
        `DisposableEffect(tag)` registration froze. If the tree does not change,
        this build's `/click` is dispatching stale closures and every downstream
        'PASS' would be meaningless.

        Returns None when dispatch is healthy, else a description of the fault.
        """
        before = (await self.snapshot()).tags
        await self.click(toggle_tag, settle_s=1.4)
        after = (await self.snapshot()).tags
        if before == after:
            return (
                f"programmatic /click on {toggle_tag!r} changed nothing — this "
                "build still registers click handlers from DisposableEffect(tag), "
                "so /click dispatches the lambda captured at first composition "
                "and reports success anyway"
            )
        # put it back
        await self.click(toggle_tag, settle_s=1.0)
        return None

    # ── navigation, entirely by tag ─────────────────────────────────────────
    async def open_group(self, group_id: str) -> bool:
        """Expand a sidebar group, verified by the nav rows that appear."""
        tag = f"nav_group_{group_id}"
        before = len((await self.snapshot()).with_prefix("nav_epistemic_"))
        await self.act(tag, wait_ms=1400)
        after = len((await self.snapshot()).with_prefix("nav_epistemic_"))
        return after != before

    async def goto(self, surface_id: str, expect_screen: str,
                   group_id: Optional[str] = None,
                   timeout_s: float = 12.0) -> bool:
        """Open `nav_epistemic_<surface_id>`, expanding its group if needed."""
        tag = f"nav_epistemic_{surface_id.replace('-', '_')}"
        snap = await self.snapshot()
        if tag not in snap and group_id:
            await self.open_group(group_id)
        if not await self.exists(tag, timeout_ms=2500):
            return False
        await self.act(tag, wait_ms=2500)
        deadline = asyncio.get_event_loop().time() + timeout_s
        while asyncio.get_event_loop().time() < deadline:
            if await self.screen() == expect_screen:
                return True
            await asyncio.sleep(0.6)
        return False

    async def login(self, username: str, password: str,
                    timeout_s: float = 25.0) -> bool:
        if await self.screen() != "Login":
            return True
        await self.type_into("input_username", username)
        await self.type_into("input_password", password)
        await self.act("btn_login_submit", wait_ms=4000)
        deadline = asyncio.get_event_loop().time() + timeout_s
        while asyncio.get_event_loop().time() < deadline:
            if await self.screen() not in ("Login", "unknown"):
                return True
            await asyncio.sleep(0.8)
        return False
