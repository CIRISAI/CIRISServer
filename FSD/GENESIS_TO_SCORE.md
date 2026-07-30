# Genesis to score — the happy path

The one sequence a trace follows from an unminted mesh to a capacity score, and
the one the harness must walk. Substrate: persist **v23.0.0**, edge **v15.5.0**.

Vocabulary is in `NAMING_THE_TRUST_ROOT.md`; this document is the sequence.

---

## Stage 0 — GENESIS (once, on hardware, with the accord keys)

Accord holders **A1 / B1 / C1** run the ceremony. It emits **one artifact**: a
`GenesisBundle`.

| the bundle carries | signed by |
|---|---|
| holders — A1 / B1 / C1 key records | the accord ceremony |
| serve_nodes — `canonical-server-1`, `registration_envelope.roles: [infra:serve]` | m-of-n co-scrub |
| `trust:charter:v1` — the root declares itself, with a pre-rotation commitment | the charter key |
| `trust:confers:v1` — the root grants `canonical-server-1` `infra:serve` | the charter key |
| accord heartbeat — the drill signal | an `accord_holder` |
| `authorizations` — m-of-n over the bundle digest | the seated holders |

**Re-bless is not a second path.** It gathers the same inputs — A1/B1/C1 and
`canonical-server-1` — and calls the same mint. One implementation.

The bundle is then baked by persist as `canonical_seed.json`. Every node ships
with it.

> The bundle is **durable**: valid until revoked, withdrawn or superseded. Nothing
> in it expires. The heartbeat ages into a yellow/red drill band, which is a
> displayed signal and never a gate.

---

## Stage 1 — NODE BOOT (every node, automatic)

1. **Install the bundle's records** — holders and serve nodes enter the directory,
   the charter and conferral enter the graph.
2. **Accept the trust root** — the node writes its own `trust:accepts:v1` to the
   bundle's charter root.

Step 2 is the node's *own signed act* and cannot be shipped in the bundle: it
requires the node's key, which does not exist when the seed is baked. It is
**default trust** — the constitution already says a fresh node trusts
`ciris-canonical` — not a consent decision, so it happens at boot without asking.

**It is also the un-trust lever.** Delete that one row and everything downstream
fails closed on its own: the walk returns `None`, the serve gate withholds, agent
capabilities gate off, manifests stop. No symptom is hard-coded.

After stage 1, `trust_root_valid` holds:

```
edge_exists ✓   root_self_declares ✓   charter_has_recovery ✓   !halt_latched ✓
```

---

## Stage 2 — PEERING (owner-authorized, once per peer)

Consent is **directional**, and two different grants are needed:

| grant | author | names | why |
|---|---|---|---|
| `consent:replication:v1` | node | canonical | the node's send-set — without it the node ships nothing |
| `consent:replication:v1` | canonical | node | the canonical's send-set — without it *it* ships nothing back |
| `consent:state:granted:v1` scope `analyze` | **node** | canonical | CC#46 — the canonical may not score a node that has not consented to be analysed |

The `analyze` grant rides the same owner-gated `POST /v1/federation/consent`
(`"analyze": true`), authored atomically with the replication grant. One owner
action, complete set.

Assert the **resolved stance**, never the presence of a row.

---

## Stage 3 — TRACE (per trace)

1. Agent seals a trace → a `trace:complete:v1` carrier row.
2. The **serve gate** asks: may this recipient receive `trace:*`?
   - the recipient's `infra:serve` resolves via `AccordCoScrub` **or** `Delegation`
   - **and** this node holds `trust:accepts` to that root
3. Anti-entropy round ships it; the canonical admits and materializes it.
4. The scorer summarizes and — given the `analyze` consent — authors
   `capacity:sustained_coherence:v1` **about the agent, by the canonical**.

A distinct sovereign identity does the scoring. That is not incidental: the
constitution refuses self-attestation, so arrival is necessary and never
sufficient.

---

## The whole path, one line each

```
0  ceremony (A1/B1/C1)     → GenesisBundle → baked as the seed
1  node boot               → install records → accept trust root      [trust_root_valid ✓]
2  owner consents          → replication (both ways) + analyze
3  seal → serve gate → round → admit → materialize → summarize → SCORE
```

---

## What remains

All four stages have an implementation as of 0.5.140. One input is missing, and
it is not code.

**The baked seed is bundle-shaped but empty** — `holders 0, attestations 0,
authorizations 0`. The container ships; the ceremony has not yet filled it. So
stage 1 runs and installs nothing, and stage 0 is the only step still done by
hand, once, on hardware.

That is the honest state, and the harness is built to say so:

| arm | scenario | what it proves |
|---|---|---|
| A | `traceflow` | the **carrier** — seal → serve gate → round → admit → score |
| B | `genesis_seed` | the **seed** — a node holding *only* the baked bundle |

Arm A keeps the test-anchor fixture, which mints a trust root **locally on every
node**. That substitutes for stage 0+1 and is deliberately not the happy path: it
simulates a world where the seed is already filled. Arm B sets
`CIRIS_TEST_NO_CEREMONY=true`, removes the fixture entirely, and audits each
precondition **independently** (`VERDICT_MODE=audit`) — reporting every unmet one
rather than stopping at the first, because these are separate facts and reporting
only the first zero is what once let four distinct defects look like one problem.

Arm B is red until a real bundle is minted and baked. When it goes green, the
portable trust root is operable and the scenario becomes a regression gate.

**Known, unfiled:** `Attestation` carries one `scrub_key_id` and no
`additional_scrubs`, so a 3-key ceremony degrades to 1-of-n once its rows land in
the graph. The bundle's `authorizations` retain the m-of-n; the materialized rows
do not.
