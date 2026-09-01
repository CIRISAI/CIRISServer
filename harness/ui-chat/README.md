# ui-chat — a chat driven through the interface a person actually uses

Three containers: a canonical and two nodes, each node running a real
`ciris-server` **and** the real Compose Desktop client, driven through the app's
`TestAutomationServer` (`/click`, `/input`, `/tree` — `java.awt.Robot` at screen
coordinates). No step is performed over the node's HTTP API; HTTP is read-only
and used for evidence, never to make a stage succeed.

`harness/mesh-repro/scenarios/chat.sh` proves the same delivery over HTTP. This
proves it through the surface a person uses: the contact is added in the UI,
consent is given in the UI, the message is typed and sent in the UI, and the
assertion reads node B's on-screen transcript.

```
./run.sh              # build what is missing, run, tear down
KEEP=1 ./run.sh       # leave the containers up
SKIP_BUILD=1 ./run.sh # reuse the image
```

## Why a container per node

The client resolves federation-crypto calls to
`CIRISApiClient.LOCAL_NODE_URL`, a hardcoded `http://127.0.0.1:4243`
(CIRISClient#26). Three nodes on one host would make those calls target whichever
node answers 4243 — a different node — and mint the owner's identity in the wrong
place. A container per node gives each its own netns, so its node genuinely *is*
`127.0.0.1:4243` and the constant is correct rather than merely tolerated. Nothing
needs patching and no node moves off the default ports, which is also how a real
install looks.

## Status: BLOCKED at `discover:a_sees_b_fedid`

Passing: `first_run` ×2 (wizard, auto-claim from `<home>/claim_pin`),
`restart:for_announce_optin`, `login` ×2.

Blocked: both nodes discover each other's **node** keys and the canonical;
neither ever obtains the other owner's **fed-id**, so `add_contact` refuses
`contacts.unknown_fed_id`. The canonical's own directory shows both node keys and
neither owner.

That is CIRISEdge#552's cell: `Key` already serves `public` on the advertise axis
but the RECEIVE axis was `subject_pull:data_subject; subject-only`, which made it
*"un-addressable, not undisclosed"* — `Pull` is the only by-name read, and a node
cannot compute the hash of a record it has never held. CIRISEdge#556 widens it to
`data_subject+any_attributed`. **This harness is waiting on an edge release
carrying that** (CIRISServer#522, the `SERVE_ADVERTISE_POLICY_HASH` re-pin).

## What it found on the way

Each of these cost a run, and each is now prevented rather than remembered:

1. **`default-jre-headless` has no X11/AWT.** Dies `HeadlessException: No X11
   DISPLAY variable was set` — reads as a missing display, is a missing toolkit.
2. **The TestAutomationServer binds loopback only.** Answers `docker exec curl`
   perfectly and the host not at all; needs the `socat` forwarder in
   `entrypoint.sh`. Any containerised UI platform hits this.
3. **All five trust-root vars are required.** The classical two boot a node that
   roots, arms its gates, then dies `PQC signature without pubkey`.
4. **`tmpfs` home + a restart = a wiped node.** The wizard's opt-in is
   boot-structural, so the harness restarts to apply it — and a tmpfs home makes
   that restart destroy the identity the restart existed to apply.
5. **A stale `/tmp/.X99-lock` survives a restart.** Second boot only, so it reads
   like a flake.
6. **A click is a toggle, never an assertion.** The driver clicked
   `toggle_announce_ownership` to "opt in" and turned it OFF —
   `SetupState.announceOwnership` already defaults `true`. The run then failed
   four minutes later in an unrelated stage.

Two more in the driver's own assertions, both the same shape — a check that
cannot fail:

- `contact:a_adds_b` passed on the ABSENCE of a refusal banner while
  `listContacts` said `0 contact(s) of 0`. It now requires the contact to appear.
- A navigation stage left the UI on `ManageNodes` and the next stage reported
  "the contacts button never appeared" — true, and pointing at the wrong thing.
  `goto()` now confirms the landing screen.

## Design notes

- **Readiness is `/tree` returning elements, never the port answering.** On
  Android the automation server came up 200 ms before the process died
  (CIRISClient#25); a port check calls that green.
- **The arrival assertion keys on the sender's exact typed text**, which B cannot
  produce for itself — the same reasoning `chat.sh` uses when it keys on the
  sender's `attestation_id`.
- **The contact is a fed-id, never a node key.** `peer::bound_nodes_of` resolves
  the person through `nodes_stewarded_by` and filters to `identity_type == "node"`,
  because *"only NODE-role keys are what edge's consent send-set matches links
  against"*. An earlier revision fell back to the peer's node key when the fed-id
  was missing, which made the stage pass while testing node-to-node delivery
  wearing a person-to-person label. The fed-id being absent is the DEFECT.
- **The canonical runs no UI**, so a transcript can only come from a node someone
  actually drove.

## Not yet aligned with CIRISServer#520

#520 rules that identity promotion is opt-out, that opting out means the agent
does not run, and that it is recorded as a `consent_state: granted` row with
specific wizard copy. The driver currently just walks the wizard's defaults. When
#520 lands, the first-run stage should assert that shape rather than accept
whatever the wizard does.
