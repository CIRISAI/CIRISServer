# RCA — the trace plane stopped, and the instrument said nothing

**2026-08-05, canonical-server-1, ciris-server 0.5.153.**

Traces stopped arriving on **2026-08-03T23:30**. Nothing alerted. The condition
was found by a routine soak check two days later, and only after the first
attempt to look **returned a false clean**.

---

## The one-line finding

> A producer signed with an identity from the **wrong derivation namespace**, the
> server refused it correctly 8,631 times a day, and **no instrument anywhere
> turned "the trace plane is dead" into a signal.** The refusal was visible only
> as log volume nobody was reading.

---

## Timeline

| when | what |
|---|---|
| 2026-08-02 14:23 | first `verify_unknown_key` rejection |
| 2026-08-03 23:30 | **last trace ever admitted** |
| 2026-08-05 13:55 | still rejecting, ~6/min, unbroken for 71 hours |

Both conditions ran **concurrently for 33 hours** before the plane went fully
silent. That overlap is the missed detection window: a producer was being
refused while another was still succeeding, and nothing compared the two.

---

## Root cause: two key-id namespaces, one field

Registered federation identities look like:

```
ciris-agent-bootstrap-25uzoxtlro      (derive_key_id — the federation namespace)
```

The rejected producers present:

```
agent-55fe8d181727                    4,317 rejections / 24h
agent-1ee871dcf31b                    4,314 rejections / 24h
```

`agent-{hash[:12]}` is the **agent-credits** key id
(`CIRISAgent/ciris_engine/schemas/services/agent_credits.py:64`), a *different
identity namespace* from the federation key id. Neither key exists in
`federation_keys` — persist's own diagnostic says so precisely, and it is a good
diagnostic:

```
verify_unknown_key — lookup miss
  envelope_signer_id=agent-55fe8d181727
  looked_up_id_byte_len=18
  accord_public_keys_size=Some(346)
  accord_public_keys_sample=Some(["A1","B1","C1","ciris-agent-bootstrap-…"])
```

**The server is right and the producer is wrong.** A 401 on an unregistered
signer is the admission gate working exactly as designed.

This is the house defect class again — *one name, two axes*. `signing_key_id` is
one field carrying identities minted by two different derivations, and nothing
in either type system says which namespace a given value belongs to. The
producer picked the wrong one and every layer accepted the string.

---

## The instrument failures — the expensive half

Three, and each is worse than the last.

**1. Nothing measures trace-plane liveness.** The node has a scorer that reports
`n_summaries`, a retention loop, an operator surface with distinct zeroes across
four axes — and **nothing that says "no trace has been admitted in 48 hours."**
Arrival is the one thing this node exists to do, and it is the one thing
unwatched. Compare `drill_freshness`, which bands exactly this shape for the
trust root.

**2. A sustained 401 flood is not a signal.** 8,631 rejections a day, 71 hours
unbroken, two stable identities: that is not noise, it is a *stuck producer*.
Every individual refusal is correct, which is precisely why the aggregate needs
a separate reading — a rate of correct refusals is a fault report about someone
else.

**3. My own first check returned a false clean.** I grepped

```
grep -oE '(WARN|ERROR)[^:]*: [a-z_ ]{10,60}'
```

and got **zero matches**, then nearly reported the node healthy. The real count
was **25,927**. The pattern was wrong; the absence of output read as absence of
problems.

That is the RCA discipline this project already wrote down — *a zero is not
evidence unless the instrument can fail* — and I violated it while running a
health check. What caught it was asking the meta-question: `wc -l` on the whole
log (28,924 lines) made "zero WARNs" obviously false. **The instrument must be
shown able to fail, in the same session it is trusted.**

---

## What was NOT wrong

- **Coalescing works, verified in production.** Capacity rows: 900/day (Aug 1,
  pre-fix) → 641 (Aug 2, mid-deploy) → **21, 19, 7**. A 45× reduction, holding.
- **No attestation flood.** 2,611 attestations, 284 distinct authors, shapes
  consistent with honest use. `consent:replication:v1` is 253 rows from 253
  distinct keys — one apiece, exactly right.
- **No storage pressure.** 101 MB DB (49 MB traces, 28 MB attestations), zero
  free-list pages, 25 GB free on the volume.
- **No adversary.** Two stable identities, constant rate, no growth, no
  variation. This is a misconfigured client in a retry loop, not an attack — and
  it is worth saying plainly, because a 6/min unauthenticated POST flood *looks*
  like one until you read the key ids.

---

## Fixes

**Detection, and this is the important half:**

1. **Trace-plane liveness as a banded signal** on the operator surface —
   `last_admitted_at` with green/yellow/red, the shape `drill_freshness` already
   uses. A plane that has admitted nothing for two days must be *red*, not
   *absent from the display*.
2. **Refusal-rate as its own reading.** A sustained rate of *correct* refusals
   from a *stable* identity set is a distinct condition from "no refusals" and
   from "varied refusals" — three states, not one counter.
3. **Distinguish "refusing" from "idle" on the receive plane.** The operator
   surface already does this for edge's withhold ledger; the HTTP ingest path
   has no equivalent.

**Cause:**

4. **The producer must sign with the federation key id.** Agent-side; the
   credits namespace is not a federation identity.
5. **Namespace the type, not the string.** A `FederationKeyId` newtype would
   have made this a compile error rather than a 71-hour outage. This is the
   general cure for the axis-fusion class and it is worth more than the specific
   fix.
6. **The 401 body should name the namespace mismatch**, not just
   `verify_unknown_key`. persist's *log* diagnostic is excellent; the response
   the producer actually receives is one token, and the producer is the party
   who can fix it.

---

## The lesson worth keeping

Every layer behaved correctly. The producer signed, the server verified, the
gate refused, persist logged a precise diagnostic naming the exact byte length
and a sample of what it looked in.

**And the mesh was dead for two days.**

Correct refusal is not the same as handled failure. A system composed entirely
of components that are individually right can still have no one whose job it is
to notice that nothing is happening — and "nothing is happening" is the hardest
condition to detect, because it has no positive signal to match on.
