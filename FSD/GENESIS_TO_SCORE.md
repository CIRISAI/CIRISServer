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

## What is not yet automatic

Stage 0 is ready: the ceremony mints the full bundle and persist bakes a bundle
shape. Stages 2 and 3 are proven end to end.

**Stage 1 has no implementation.** Nothing installs a baked bundle at boot, and
nothing writes `trust:accepts`. Today the only writer is `write_node_trust_edge`,
on the *minting* node; `install_trust_root_records` deliberately refuses. So a
node that did not mint has no trust edge and `edge_exists` is false.

That is why the harness fixture mints a trust root **locally on every node** — it
substitutes for stage 1. Useful for exercising stages 2-3 in isolation, and it is
not the happy path: it simulates a world where stage 1 already works.

Until stage 1 lands, `harness/mesh-repro/scenarios/genesis_seed.sh` is the honest
measure — a node holding only the baked seed, auditing every precondition and
reporting each unmet one rather than stopping at the first.
