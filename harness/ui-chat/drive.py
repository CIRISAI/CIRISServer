#!/usr/bin/env python3
"""Drive the CIRIS desktop UI through a two-node chat, entirely via the UI.

The claim under test is the one the HTTP `chat` scenario cannot make: that a
person, using the surface a person uses, can add a contact, consent to them, and
have their typed message arrive in the other person's transcript. Every step
below is a real click or keystroke through the app's TestAutomationServer
(java.awt.Robot at screen coordinates); nothing here calls the node's API to
make a step succeed.

Read-only HTTP is used for EVIDENCE only — to learn a node's own key id, which
the UI has no reason to display, and to say what a node believes when the UI
disagrees. It is never used to perform a step.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

# The wizard has more steps than any one deployment shows: age band, federation
# identity, consent toggles, and whichever the node's capabilities enable. So the
# driver fills what it FINDS rather than assuming a fixed sequence — a harness
# that hardcodes step 3 breaks the first time a step is added, and reports it as
# a chat failure.
WIZARD_TEXT_FIELDS = {
    "input_username": "username",
    "input_password": "password",
    "input_password_confirm": "password",
    "input_device_name": "device_name",
    "input_fedid_label": "username",
}
WIZARD_CHOICES = ("age_band_adult",)

# THE OPT-IN THAT MAKES A FED-ID DISCOVERABLE IS ALREADY ON. DO NOT CLICK IT.
#
# `net.announce_ownership` defaults FALSE on the SERVER, and while it is false
# "the transport still brings up + announces its raw destination hash, but with
# NO identity attestation -> rooting peers drop it (fail-honest) -> the node is
# not federation-identity-discoverable". That is the state that makes a peer's
# fed-id never arrive, so `add_contact` refuses `contacts.unknown_fed_id`.
#
# But the WIZARD opts in for you: `SetupState.announceOwnership` defaults TRUE,
# and completing setup performs the promote. An earlier revision of this driver
# clicked `toggle_announce_ownership` to "opt in" and thereby turned it OFF —
# the tree reports element positions, not checked state, so a click is a
# TOGGLE and never an assertion. The run then failed four minutes later, in a
# different stage, for a reason that looked like a replication problem.
#
# Nothing to press. Listed here so the next person does not add it back.
WIZARD_TOGGLES_ONCE: tuple[str, ...] = ()


START = time.time()


def log(scope: str, msg: str) -> None:
    """One line per thing that happened, stamped with elapsed time.

    Every failure in this harness so far was diagnosed from a state dump taken
    AFTER the fact — which screen, which tags, which directory rows. Printing
    that as it happens is the difference between "the contacts button never
    appeared" and "we were on ManageNodes because the previous stage navigated
    away". The log IS the diagnosis; the exception is only where it stopped.
    """
    print(f"  [{time.time() - START:6.1f}s] {scope:<14} {msg}", flush=True)


def directory_of(read_api_port: int) -> list[str]:
    """Key ids this node's federation directory holds — the precondition every
    contact stage depends on and none of them could previously show."""
    try:
        url = f"http://127.0.0.1:{read_api_port}/v1/federation/peers"
        with urllib.request.urlopen(url, timeout=8) as r:
            return [p.get("key_id") for p in json.loads(r.read().decode()).get("peers", [])]
    except Exception as exc:  # noqa: BLE001 — diagnosis must never mask the real failure
        return [f"<unreadable: {exc}>"]


class UiError(RuntimeError):
    pass


class Ui:
    """One app instance, addressed through its TestAutomationServer."""

    def __init__(self, name: str, port: int, timeout: float = 10.0, api_port: int | None = None):
        self.name = name
        self.base = f"http://127.0.0.1:{port}"
        self.timeout = timeout
        # The node behind this UI, for showing preconditions. Never used to
        # PERFORM a step — only to say why one could not.
        self.api_port = api_port

    # ── transport ────────────────────────────────────────────────────────────
    def _get(self, path: str):
        with urllib.request.urlopen(f"{self.base}{path}", timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    def _post(self, path: str, body: dict):
        req = urllib.request.Request(
            f"{self.base}{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read().decode())

    # ── reading ──────────────────────────────────────────────────────────────
    def screen(self) -> str:
        return self._get("/screen").get("screen", "?")

    def tree(self) -> dict:
        return self._get("/tree")

    def tags(self) -> list[str]:
        return [e.get("testTag") for e in self.tree().get("elements", [])]

    def wait_ready(self, secs: int = 180) -> None:
        """Up AND rendering. The port answering is not the app being alive: on
        Android the automation server came up 200ms before the process died, and
        a check that stops at the port reports green on a corpse."""
        deadline = time.time() + secs
        while time.time() < deadline:
            try:
                if self.tree().get("count", 0) > 0:
                    return
            except (urllib.error.URLError, OSError, json.JSONDecodeError):
                pass
            time.sleep(2)
        raise UiError(f"{self.name}: no rendered UI within {secs}s")

    def wait_for_tag(self, tag: str, secs: int = 90) -> None:
        deadline = time.time() + secs
        seen: list[str] = []
        while time.time() < deadline:
            seen = self.tags()
            if tag in seen:
                return
            time.sleep(2)
        raise UiError(
            f"{self.name}: {tag!r} never appeared within {secs}s "
            f"(screen={self.screen()!r}, present={sorted(t for t in seen if t)})"
        )

    # ── acting ───────────────────────────────────────────────────────────────
    def click(self, tag: str) -> dict:
        log(self.name, f"click {tag}")
        res = self._post("/click", {"testTag": tag})
        if not res.get("success"):
            raise UiError(f"{self.name}: click {tag!r} failed: {res}")
        return res

    def type_into(self, tag: str, text: str) -> dict:
        shown = text if "password" not in tag else "*" * len(text)
        log(self.name, f"type  {tag} = {shown!r}")
        res = self._post("/input", {"testTag": tag, "text": text})
        if not res.get("success"):
            raise UiError(f"{self.name}: input {tag!r} failed: {res}")
        return res

    def click_if_present(self, tag: str) -> bool:
        if tag in self.tags():
            self.click(tag)
            return True
        return False


def node_code(read_api_port: int) -> str:
    """One side's node code — the identifier a person hands over out of band.

    Read over HTTP here, which is what a person does by reading it off their own
    screen. The out-of-band part is not the transport; it is that the OTHER side
    learns it from the person rather than from the federation. That distinction
    is the design, and CIRISServer#524 §6.3 rules it:

        "Stranger contact is meant to start from a nodecode, not a directory
         lookup. You hand out an identifier out-of-band, the peer dials that
         specific node (which serves its own record), and consent follows.
         Building 'search the federation for a person' on top of `discover` will
         work only for people you already have a consented relationship with —
         that is the boundary, not a gap to route around."

    An earlier revision of this driver waited for discovery to deliver the peer's
    fed-id and called that wait a blocked stage. It was not blocked: it asked the
    substrate for an address-book lookup it refuses by design, because answering
    a third-party probe "would make a body-holding server an address-book oracle
    for records it never advertised" (§6.1).
    """
    url = f"http://127.0.0.1:{read_api_port}/v1/federation/node-code"
    with urllib.request.urlopen(url, timeout=10) as r:
        payload = json.loads(r.read().decode())
    code = payload.get("code") or ""
    if not code:
        raise UiError(f"no node code at :{read_api_port} — payload keys {sorted(payload)}")
    return code


def add_peer_by_code(ui: Ui, code: str) -> None:
    """Admit a peer from the code they handed you — the stranger-contact entry.

    This is what makes the peer's own record fetchable: you dial THAT node and it
    serves its own record. Everything downstream — learning the owner behind it,
    adding the contact, consent — hangs off having done this first.
    """
    ui.click_if_present("nav_epistemic_network_ops")
    ui.wait_for_tag("btn_add_peer", secs=90)
    ui.click("btn_add_peer")
    ui.wait_for_tag("input_add_peer_code", secs=30)
    ui.type_into("input_add_peer_code", code)
    ui.click("btn_add_peer_submit")
    time.sleep(8)
    if "text_add_peer_error" in ui.tags():
        raise UiError(f"{ui.name}: peer add refused (see text_add_peer_error)")
    log(ui.name, "peer admitted from the handed-over code")


def wait_for_key(ui: Ui, api_port: int, key_id: str, secs: int = 240) -> None:
    """Wait for a peer's FED-ID to reach this node's federation directory.

    It arrives on the Reticulum announce, but only once the owner has opted in:
    `net.announce_ownership` defaults FALSE, and while it is false the transport
    "announces its raw destination hash, but with NO identity attestation ->
    rooting peers drop it (fail-honest)". The wizard's
    `toggle_announce_ownership` is that opt-in, and the setting is
    boot-structural — it takes effect on the restart the wizard performs when it
    completes, which is also why the app asks you to sign in again.

    So this is a real wait on a real cadence (15s announces in the harness), not
    a sleep hiding a race.
    """
    deadline = time.time() + secs
    last = 0
    while time.time() < deadline:
        held = directory_of(api_port)
        if key_id in held:
            log(ui.name, f"directory now holds {key_id} ({len(held)} keys)")
            return
        if len(held) != last:
            log(ui.name, f"directory has {len(held)} keys, still no {key_id}")
            last = len(held)
        time.sleep(8)
    raise UiError(
        f"{ui.name}: {key_id!r} never reached the federation directory in {secs}s. "
        f"Holding: {directory_of(api_port)}. A fed-id is only discoverable when its "
        f"owner opted in (net.announce_ownership) AND the node has restarted since."
    )


def goto(ui: Ui, nav_tag: str, expect_screen: str, secs: int = 60) -> None:
    """Navigate and CONFIRM the landing.

    Every stage assumes a starting screen, and a stage that reads its own
    prerequisites as failures is the least useful kind: `owner_fed_id` left the
    UI on ManageNodes once, and the next stage reported "the contacts button
    never appeared" — true, and pointing at the wrong thing entirely.
    """
    if ui.screen() == expect_screen:
        return
    log(ui.name, f"nav   {ui.screen()} -> {expect_screen} via {nav_tag}")
    ui.click_if_present(nav_tag)
    deadline = time.time() + secs
    while time.time() < deadline:
        if ui.screen() == expect_screen:
            log(ui.name, f"nav   arrived at {expect_screen}")
            return
        time.sleep(2)
    raise UiError(
        f"{ui.name}: {nav_tag} did not reach {expect_screen!r} "
        f"(still on {ui.screen()!r})"
    )


def owner_fed_id(ui: Ui, secs: int = 90) -> str:
    """This node's OWNER fed-id, read off the UI's own node graph.

    A contact is a PERSON, not a node. `contacts_chat::add_contact` takes a
    federation key id and `peer::bound_nodes_of` resolves it through
    `nodes_stewarded_by`, filtering to `identity_type == "node"` — because "only
    NODE-role keys are what edge's consent send-set matches links against".
    Typing a node key into the contact form skips that resolution entirely and
    asks the wire to route to a person, which is the unroutable-subject defect
    that function exists to avoid.

    Read from the UI rather than an API on purpose: it is the value a person
    would copy from their own screen, and it keeps the harness honest about what
    is reachable through the interface.
    """
    ui.click_if_present("nav_epistemic_nodes")
    deadline = time.time() + secs
    while time.time() < deadline:
        for tag in ui.tags():
            if tag and tag.startswith("node_graph_node_qaowner"):
                fed = tag.replace("node_graph_node_", "")
                print(f"  [{ui.name}] owner fed-id: {fed}")
                goto(ui, "nav_epistemic_contacts", "Contacts")
                return fed
        time.sleep(3)
    raise UiError(
        f"{ui.name}: no owner fed-id on the node graph within {secs}s "
        f"(screen={ui.screen()!r}) — the wizard may not have minted one"
    )


def node_key_id(read_api_port: int) -> str:
    """A node's own key id, for the contact the OTHER side must type."""
    url = f"http://127.0.0.1:{read_api_port}/v1/identity"
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())["key_id"]


def first_run(ui: Ui, username: str, password: str, device_name: str) -> None:
    """Log in locally and walk the wizard to completion.

    The claim itself is NOT performed here. The node writes its one-time PIN to
    `<home>/claim_pin` (0600, never over HTTP) and the app reads it from the path
    the NODE declares — local-FS access to the node's home being operator-level
    access already. So the wizard claims the node on its own, and the driver's
    job is only to answer the questions it asks.
    """
    ui.wait_ready()
    values = {"username": username, "password": password, "device_name": device_name}
    pressed: set[str] = set()

    if "btn_local_login" in ui.tags():
        ui.click("btn_local_login")
        time.sleep(3)

    # Walk forward until the wizard hands over. Bounded, so a wizard that loops
    # on a validation error fails as a wizard failure rather than hanging.
    for step in range(1, 13):
        screen = ui.screen()
        if screen != "Setup":
            print(f"  [{ui.name}] wizard complete at step {step} (screen={screen})")
            return
        tags = set(ui.tags())
        log(ui.name, f"wizard step {step}: {len(tags)} elements on {screen}")
        for tag, key in WIZARD_TEXT_FIELDS.items():
            if tag in tags:
                ui.type_into(tag, values[key])
        for tag in WIZARD_CHOICES:
            if tag in tags:
                ui.click(tag)
        for tag in WIZARD_TOGGLES_ONCE:
            if tag in tags and tag not in pressed:
                ui.click(tag)
                pressed.add(tag)
                log(ui.name, f"opted in: {tag}")
        if "btn_next" not in tags:
            raise UiError(
                f"{ui.name}: wizard step {step} has no btn_next "
                f"(screen={screen}, tags={sorted(tags)})"
            )
        ui.click("btn_next")
        time.sleep(6)

    raise UiError(f"{ui.name}: wizard did not finish in 12 steps (screen={ui.screen()})")


def login(ui: Ui, username: str, password: str) -> None:
    """Sign in after setup.

    The wizard does NOT leave you signed in: it completes, returns to Login, and
    says so with `banner_setup_complete_relogin`. Skipping this step lands every
    later stage on the Login screen and reports "the contacts button never
    appeared", which is true and useless — the button is on a screen you were
    never going to reach.
    """
    ui.wait_for_tag("btn_local_login", secs=90)
    ui.click("btn_local_login")
    ui.wait_for_tag("input_username", secs=30)
    ui.type_into("input_username", username)
    ui.type_into("input_password", password)
    ui.click("btn_login_submit")
    # Sign-in lands on Contacts directly.
    deadline = time.time() + 90
    while time.time() < deadline:
        if ui.screen() != "Login":
            print(f"  [{ui.name}] signed in (screen={ui.screen()})")
            return
        time.sleep(3)
    raise UiError(f"{ui.name}: still on Login 90s after submit (tags={sorted(t for t in ui.tags() if t)})")


def add_contact(ui: Ui, key_id: str) -> None:
    """Add the peer as a contact — through the form, not the API."""
    goto(ui, "nav_epistemic_contacts", "Contacts")
    log(ui.name, f"adding contact {key_id}")
    if ui.api_port:
        held = directory_of(ui.api_port)
        present = key_id in held
        log(ui.name, f"directory holds {len(held)} keys; contact present={present}")
        if not present:
            log(ui.name, f"  directory: {held}")
            log(ui.name, "  NOTE: add_contact refuses contacts.unknown_fed_id for a key "
                         "the directory does not hold — the peer must be ADMITTED first "
                         "(POST /v1/federation/peering with the peer's blessed self record). "
                         "Discovery admits NODE keys; owner fed-ids are self-plane "
                         "(Projection::SelfOwn) and are advertised by nobody.")
    ui.wait_for_tag("btn_contacts_add_open", secs=120)
    ui.click("btn_contacts_add_open")
    ui.wait_for_tag("input_contacts_add_key")
    ui.type_into("input_contacts_add_key", key_id)
    ui.click("btn_contacts_add_submit")
    time.sleep(6)
    # A refusal is a RESULT, not an exception: reporting it with its own text is
    # the difference between "consent was refused" and "the harness broke".
    if "contacts_add_refusal" in ui.tags():
        raise UiError(f"{ui.name}: contact add refused (see contacts_add_refusal)")

    # AND THE CONTACT MUST APPEAR. The first version of this stopped at the line
    # above and reported PASS while `listContacts` said "0 contact(s) of 0" — it
    # asserted the absence of a complaint, which is not the presence of a
    # contact, and every later stage then failed somewhere unrelated.
    deadline = time.time() + 90
    while time.time() < deadline:
        ui.click_if_present("btn_contacts_refresh")
        blob = json.dumps(ui.tree())
        if key_id in blob or "contacts_list" in blob:
            print(f"  [{ui.name}] contact {key_id} is listed")
            return
        time.sleep(5)
    raise UiError(
        f"{ui.name}: contact {key_id!r} never appeared in the list. The node "
        f"admits a contact only if the key is already in its federation "
        f"directory (contacts.unknown_fed_id otherwise) — check that discovery "
        f"put the peer there."
    )


def consent(ui: Ui) -> None:
    """Grant the replication consent the contact rides on."""
    for tag in ("btn_consent_peering", "btn_consent"):
        if ui.click_if_present(tag):
            time.sleep(5)
            return
    print(f"  [{ui.name}] no explicit consent control — contact add carried it")


def send_chat(ui: Ui, text: str) -> None:
    ui.click_if_present("btn_contacts_add_open_chat")
    ui.wait_for_tag("input_chat_body", secs=90)
    ui.type_into("input_chat_body", text)
    ui.click("btn_chat_send")
    time.sleep(5)
    if "chat_refusal" in ui.tags():
        raise UiError(f"{ui.name}: send refused (see chat_refusal)")


def transcript_has(ui: Ui, text: str, secs: int = 180) -> bool:
    """Poll node B's ON-SCREEN transcript for the message.

    Keyed on the sender's exact text, which B could not produce for itself. The
    HTTP scenario keys on the sender's attestation_id for the same reason: a
    green transcript that B derived locally would prove nothing about delivery.
    """
    deadline = time.time() + secs
    while time.time() < deadline:
        ui.click_if_present("btn_chat_refresh")
        try:
            blob = json.dumps(ui.tree())
        except (urllib.error.URLError, OSError):
            blob = ""
        if text in blob:
            return True
        time.sleep(6)
    return False


def restart_nodes(compose_dir: str = ".", services: tuple[str, ...] = ("node-a", "node-b")) -> None:
    """Restart the node containers so a boot-structural opt-in takes effect."""
    log("restart", f"restarting {', '.join(services)} to apply net.announce_ownership")
    res = subprocess.run(
        ["docker", "compose", "restart", *services],
        cwd=compose_dir, capture_output=True, text=True, timeout=300,
    )
    if res.returncode != 0:
        raise UiError(f"restart failed: {res.stderr.strip()[:300]}")
    # Wait for the UI to come back, not for the command to return: the container
    # is up long before the app is rendering, and every stage after this one
    # assumes a live UI.
    for ui, port in (("node-a", 9101), ("node-b", 9102)):
        probe = Ui(ui, port)
        probe.wait_ready(secs=240)
        log("restart", f"{ui} UI back up")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a-ui", type=int, default=9101)
    ap.add_argument("--b-ui", type=int, default=9102)
    ap.add_argument("--a-api", type=int, default=14243)
    ap.add_argument("--b-api", type=int, default=24243)
    ap.add_argument("--message", default="ui-chat harness: A to B, typed by hand")
    args = ap.parse_args()

    a = Ui("node-a", args.a_ui, api_port=args.a_api)
    b = Ui("node-b", args.b_ui, api_port=args.b_api)
    stages: list[tuple[str, bool, str]] = []

    def stage(name, fn):
        log("stage", f"BEGIN {name}")
        try:
            fn()
            stages.append((name, True, ""))
            print(f"  ✓ {name}")
        except Exception as exc:  # noqa: BLE001 — every stage reports, none aborts silently
            stages.append((name, False, str(exc)))
            print(f"  ✗ {name}: {exc}")
            raise

    try:
        print("── first run, both nodes (the wizard claims each node itself) ──")
        stage("first_run:a", lambda: first_run(a, "qaowner-a", "QaHarness!2026", "node-a-desktop"))
        stage("first_run:b", lambda: first_run(b, "qaowner-b", "QaHarness!2026", "node-b-desktop"))

        # THE RESTART THE WIZARD WOULD HAVE DONE ITSELF.
        #
        # `net.announce_ownership` is boot-structural: the opt-in is written by
        # the wizard, and the node wires its federation signer into the announce
        # on the NEXT boot. On a desktop install the app OWNS the node process
        # (`PythonRuntime` launches it and reads its stdout), so completing setup
        # restarts it and the operator simply signs in again.
        #
        # This harness starts the node from the container entrypoint instead, so
        # the app has nothing to restart and the opt-in would never take effect —
        # the fed-id stays undiscoverable and every later stage fails at the
        # contact. Restarting here is not a workaround for a product bug; it is
        # the harness standing in for the lifecycle a real install already has.
        stage("restart:for_announce_optin", restart_nodes)

        print("── sign in (the wizard returns to Login on purpose) ──")
        stage("login:a", lambda: login(a, "qaowner-a", "QaHarness!2026"))
        stage("login:b", lambda: login(b, "qaowner-b", "QaHarness!2026"))

        print("── identities ──")
        a_owner, b_owner = owner_fed_id(a), owner_fed_id(b)
        a_node, b_node = node_key_id(args.a_api), node_key_id(args.b_api)
        log("identity", f"A owner={a_owner} node={a_node}")
        log("identity", f"B owner={b_owner} node={b_node}")

        # THE CONTACT IS THE FED-ID. Not the node key.
        #
        # A contact is a PERSON. `peer::bound_nodes_of` resolves that fed-id
        # through `nodes_stewarded_by` and filters to `identity_type == "node"`,
        # because "only NODE-role keys are what edge's consent send-set matches
        # links against" — so the person is what you name and their nodes are
        # what the wire routes to. Both the fed-id AND its bound nodes have to be
        # in the directory: the first to name the contact, the second to route to
        # them, and the owner-binding between them to validate the relationship.
        #
        # An earlier revision fell back to the peer's node key when the fed-id
        # was missing. That made the stage pass while testing something else
        # entirely — node-to-node delivery wearing a person-to-person label. The
        # fed-id being absent is the DEFECT, so it is waited for and then
        # reported, never substituted.
        # THE OUT-OF-BAND HAND-OFF. Each side gets the other's node code the way a
        # person would — handed over, not discovered. The harness carrying the
        # string between the two UIs IS the out-of-band channel.
        print("── exchange node codes (the stranger-contact entry) ──")
        a_code, b_code = node_code(args.a_api), node_code(args.b_api)
        log("handoff", f"A code {a_code[:24]}…   B code {b_code[:24]}…")
        stage("peer:a_admits_b", lambda: add_peer_by_code(a, b_code))
        stage("peer:b_admits_a", lambda: add_peer_by_code(b, a_code))

        # Only now is the peer's record reachable — and only now can the by-name
        # Pull that CIRISEdge#556 widened fetch the owner behind it.
        print("── the owner behind each admitted node ──")
        stage("resolve:a_sees_b_fedid", lambda: wait_for_key(a, args.a_api, b_owner))
        stage("resolve:b_sees_a_fedid", lambda: wait_for_key(b, args.b_api, a_owner))
        a_types, b_types = b_owner, a_owner

        print("── contact + consent, through the UI ──")
        stage("contact:a_adds_b", lambda: add_contact(a, a_types))
        stage("consent:a", lambda: consent(a))
        stage("contact:b_adds_a", lambda: add_contact(b, b_types))
        stage("consent:b", lambda: consent(b))

        print("── send from A, read on B ──")
        stage("send:a", lambda: send_chat(a, args.message))
        arrived = transcript_has(b, args.message)
        stages.append(("arrived:b", arrived, "" if arrived else "message never appeared in B's transcript"))
        print(("  ✓ " if arrived else "  ✗ ") + "arrived:b")
    except Exception:
        pass

    print("\n── verdict ──")
    for name, ok, why in stages:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{('  — ' + why) if why else ''}")
    failed = [s for s in stages if not s[1]]
    return 1 if failed or not stages else 0


if __name__ == "__main__":
    sys.exit(main())
