"""Desktop Google-OAuth end-to-end — the CIRISServer#384 loop, closed.

Drives a REAL node (the installed wheel, not a test harness) through the whole
owner-session path and asserts the thing the operator actually feels: *an owner
who signed in with Google, and therefore has no password, can still get back
into the node they just claimed.*

Why this exists
---------------
#384 was invisible from every instrument. The claim returned ``success``, the
wizard advanced, and the **age band — a safety input — was silently skipped**,
because the claim rotates the setup bearer and an OAuth owner had no credential
to re-authenticate with. Nothing logged a refusal; there was simply no session.
So this file asserts on *state*, not on the absence of errors.

The password question
---------------------
Nothing here types a password. The flow reuses an EXISTING signed-in Chrome
profile, so Google's consent is an account-chooser click. Point ``--profile`` at
a copy of a real profile (copy it — Chrome holds a lock on the live one, and
Playwright will fail to launch against a locked ``user-data-dir``).

Usage
-----
    python3 desktop_oauth_e2e.py --node http://127.0.0.1:4243 \
        --profile /path/to/profile-copy --account eric@ciris.ai

    # everything except the browser leg (no display / no profile needed):
    python3 desktop_oauth_e2e.py --node http://127.0.0.1:4243 --headless-checks-only
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Result plumbing ─────────────────────────────────────────────────────────


@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Run:
    steps: List[Step] = field(default_factory=list)

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.steps.append(Step(name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
        return ok

    @property
    def failed(self) -> int:
        return sum(1 for s in self.steps if not s.ok)


def _get(url: str, timeout: int = 10) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # noqa: PERF203 - the status IS the result
        return e.code, e.read().decode("utf-8", "replace")


def _get_no_redirect(url: str, timeout: int = 10) -> tuple[int, Dict[str, str]]:
    """Fetch WITHOUT following redirects — the Location header is the assertion."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_a: Any, **_kw: Any) -> None:
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(urllib.request.Request(url), timeout=timeout) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


# ── The checks that need no browser ─────────────────────────────────────────


def check_provider_configured(run: Run, node: str) -> Optional[str]:
    """Google must be usable with NO operator step.

    The store shipped empty, so `/v1/auth/oauth/google/login` had no client and
    sign-in required POSTing credentials to `/v1/auth/oauth/providers` FIRST —
    unreachable, since sign-in is itself a first-run step.
    """
    status, body = _get(f"{node}/v1/auth/oauth/providers")
    if status != 200:
        run.record("google configured at boot", False, f"status={status}")
        return None
    provs = {p.get("provider"): p.get("client_id") for p in json.loads(body).get("providers", [])}
    cid = provs.get("google")
    run.record(
        "google configured at boot",
        bool(cid and cid.endswith(".apps.googleusercontent.com")),
        f"client_id={cid}",
    )
    return cid


def check_authorize_url(run: Run, node: str, expect_client_id: Optional[str]) -> None:
    """The authorize redirect must carry PKCE and point back at THIS node.

    Two independent regressions live here. The callback base defaulted to the
    Python brain's `:8080` while this router is mounted on the node's `:4243` —
    a correct sign-in redirected the browser to a dead port, failing in the
    BROWSER with nothing in the node's log. And PKCE is what actually binds the
    code to this client, since a desktop client's secret ships in the wheel.
    """
    status, headers = _get_no_redirect(f"{node}/v1/auth/oauth/google/login")
    loc = headers.get("location") or headers.get("Location") or ""
    run.record("login issues a provider redirect", status in (302, 307) and bool(loc), f"status={status}")
    if not loc:
        return
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    redirect_uri = (q.get("redirect_uri") or [""])[0]
    node_host = urllib.parse.urlparse(node).netloc

    run.record(
        "redirect_uri points at THIS node, not the brain",
        node_host in redirect_uri and redirect_uri.endswith("/v1/auth/oauth/google/callback"),
        redirect_uri,
    )
    run.record(
        "PKCE S256 on the authorize URL",
        bool((q.get("code_challenge") or [""])[0]) and (q.get("code_challenge_method") or [""])[0] == "S256",
        f"method={(q.get('code_challenge_method') or ['<none>'])[0]}",
    )
    if expect_client_id:
        run.record(
            "authorize URL uses the configured desktop client",
            (q.get("client_id") or [""])[0] == expect_client_id,
            "",
        )


def check_owner_binding(run: Run, node: str, db: Optional[Path]) -> None:
    """The ROOT cert must CARRY the OAuth identity — the #384 fix itself.

    `create_oauth_user` resolves `get_by_oauth` BEFORE minting, so a ROOT cert
    holding `(provider, subject)` is simply found and returned, and
    `WaRole::Root` maps to SystemAdmin. Written as `oauth_provider: None`, the
    owner's sign-in missed it and minted a fresh unprivileged row instead.
    """
    status, body = _get(f"{node}/v1/auth/owner-hint")
    hint = json.loads(body).get("owner_hint", {}) if status == 200 else {}
    run.record(
        "owner-hint reports the OAuth provider",
        hint.get("oauth_provider") == "google",
        f"owner_hint={hint}",
    )

    if not db or not db.exists():
        run.record("ROOT cert carries (provider, subject)", False, "no node db supplied — pass --db")
        return

    con = sqlite3.connect(str(db))
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    tbl = next((t for t in tables if "wa_cert" in t.lower()), None)
    if not tbl:
        run.record("ROOT cert carries (provider, subject)", False, "no wa_cert table")
        return
    rows = con.execute(
        f"select wa_id, role, oauth_provider, oauth_external_id, password_hash is not null from {tbl} where role='root'"  # noqa: S608
    ).fetchall()
    if not rows:
        run.record("ROOT cert carries (provider, subject)", False, "no ROOT row — node unclaimed?")
        return
    wa_id, role, prov, ext, has_pw = rows[0]
    run.record(
        "ROOT cert carries (provider, subject)",
        prov == "google" and bool(ext),
        f"wa_id={wa_id} role={role} oauth=({prov}, {ext})",
    )
    # The condition that MADE #384: an owner with no password. If a password is
    # present the OAuth path is untested — the owner had a fallback all along.
    run.record(
        "the owner genuinely has NO password (the #384 condition)",
        not has_pw,
        "has_password=False" if not has_pw else "has_password=True — this run proves nothing about OAuth",
    )


# ── The browser leg ─────────────────────────────────────────────────────────


async def run_browser_leg(run: Run, node: str, profile: Path, account: str, headed: bool) -> None:
    """Complete Google consent from an ALREADY-SIGNED-IN profile.

    No password is typed: the profile carries the session, so this is an
    account-chooser click. Chrome locks a live profile, so `profile` must be a
    COPY.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        run.record("browser leg", False, "playwright not installed")
        return

    async with async_playwright() as pw:
        ctx = await pw.chromium.launch_persistent_context(
            str(profile),
            channel="chrome",
            headless=not headed,
            args=["--no-first-run", "--no-default-browser-check"],
        )
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        try:
            await page.goto(f"{node}/v1/auth/oauth/google/login", wait_until="domcontentloaded", timeout=45000)

            # Account chooser, when Google offers one.
            try:
                chooser = page.get_by_text(account, exact=False).first
                await chooser.wait_for(timeout=12000)
                await chooser.click()
            except Exception:
                pass  # already-consented profiles land straight on the callback

            # Consent screen, when this client has not been approved before.
            for label in ("Continue", "Allow", "Weiter"):
                try:
                    btn = page.get_by_role("button", name=label).first
                    await btn.wait_for(timeout=6000)
                    await btn.click()
                    break
                except Exception:
                    continue

            await page.wait_for_url(lambda u: "/v1/auth/oauth/google/callback" in u or "127.0.0.1" in u, timeout=45000)
            final = page.url
            body = await page.content()
            # A password prompt means the profile was NOT signed in — stop
            # rather than fall back to typing one.
            if "signin/challenge/pwd" in final or "Enter your password" in body:
                run.record(
                    "browser leg",
                    False,
                    "profile is not signed in — Google asked for a password; sign the profile in and re-run",
                )
                return
            run.record("callback returned to the node", "/v1/auth/oauth/google/callback" in final or "127.0.0.1" in final, final[:160])
            run.record(
                "callback did not error",
                "audience mismatch" not in body and "not configured" not in body and "error" not in body[:400].lower(),
                "",
            )
        finally:
            await ctx.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--node", default="http://127.0.0.1:4243")
    ap.add_argument("--profile", type=Path, help="COPY of a signed-in Chrome profile (Chrome locks the live one)")
    ap.add_argument("--account", default="eric@ciris.ai")
    ap.add_argument("--db", type=Path, help="node sqlite db, for the ROOT-cert assertion")
    ap.add_argument("--headed", action="store_true", help="show the browser (needs a display)")
    ap.add_argument("--headless-checks-only", action="store_true", help="skip the browser leg")
    args = ap.parse_args()

    run = Run()
    print("── checks that need no browser ──")
    cid = check_provider_configured(run, args.node)
    check_authorize_url(run, args.node, cid)
    check_owner_binding(run, args.node, args.db)

    if not args.headless_checks_only:
        if not args.profile:
            run.record("browser leg", False, "--profile required (or pass --headless-checks-only)")
        else:
            print("── browser leg (account chooser; no password typed) ──")
            asyncio.run(run_browser_leg(run, args.node, args.profile, args.account, args.headed))

    print()
    total = len(run.steps)
    print(f"  {total - run.failed} passed / {run.failed} failed  (of {total})")
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(main())
