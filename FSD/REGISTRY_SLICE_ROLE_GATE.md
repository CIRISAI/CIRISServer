# FSD — The registry slice is conferred, not configured

**Status:** Phase 1 IMPLEMENTED (the gate). Phases 2–4 are the surface work.
**Companion:** [`REGISTRY_FOLD_DERISK.md`](REGISTRY_FOLD_DERISK.md) (what the fold needs),
[`TRUST_ROOT_CAPABILITY_GATE.md`](TRUST_ROOT_CAPABILITY_GATE.md) (the capability model this
applies), [`MESH_SEED_RUNBOOK_POST_DELEGATION.md`](MESH_SEED_RUNBOOK_POST_DELEGATION.md)
(the ceremony that confers it).
**Upstream:** CIRISRegistry#76 (co-bump, **done** — registry-core now resolves on
persist v32.3.0 / edge v17.4.1 / verify v13.3.1, matching this repo's pins exactly),
CIRISRegistry#62 (the three-siblings umbrella), CIRISServer#441 (the admission quorum).

---

## 1. The ordering constraint this exists to enforce

> **No server converts to a canonical node until CIRISServer can serve registry
> capabilities under the granted role.**

Convert first and you turn three working registries into three blessed nodes that
cannot do registry work. The gate is what makes "can serve registry capabilities"
a property the node *evaluates*, rather than a claim the operator makes.

## 2. Why a boolean was the wrong shape

Today the slice is selected by config:

```rust
pub struct Slices { pub lens: bool, pub registry: bool, pub node: bool }
// default: registry: false
```

```rust
if cfg.slices.registry {
    compose_registry(&edge, &engine, &cfg).await?;   // todo!()
}
```

An operator setting a boolean is exactly the self-assertion the accord-scrub model
exists to remove. A node is canonical because **the trust root signed off**, and the
same must be true of the authority slice it runs: the accord confers `infra:attest`
and `infra:serve`, and the node serves the registry surface *because* it holds them.

**The verbs already exist.** This was the open question and the answer is favourable:
the baked `genesis-charter` declares
`[infra:attest, infra:serve, infra:store, infra:transport]`, and
`genesis-grant:ciris-canonical-1-d7bdeu223k` carries **all four**. Registry's work —
identity, license, revocation, build provenance — is attestation-shaped, so it rides
`infra:attest` + `infra:serve`, both of which a canonical node holds the moment it is
blessed. **No new capability verb, and therefore no charter amendment** — which
matters, because the scopes live in the signed bytes, so amending the charter is an
m-of-n re-scrub by the holder roster, not an edit.

## 3. Where the gate can and cannot live

The lens slice is already capability-gated rather than config-gated, in the same
dispatch block:

```rust
if caps.lens_store { LensCore::attach_handler(...).await?; }
```

but that is **not** the pattern to copy wholesale, and the reason is load-bearing.
`Capabilities::detect` runs **before the Engine is open** — it is a pre-corpus
structural gate (free disk), which is precisely why `DEFAULT_LENS_STORE_MIN_GIB` is a
baked constant and not a `config:*` CEG object: there is no corpus to read it from yet.

The registry gate is the opposite kind of question. "Does this node hold `infra:attest`
from a root it accepts?" is a **delegation-graph walk over the federation directory** —
it *requires* the corpus. So it cannot join `Capabilities`, and must be evaluated at
slice-composition time, after the Engine exists. It is a **post-corpus** gate.

## 4. The check

persist supplies the walk:

```rust
capability_roots_to_trusted_root(
    directory,
    user_key_id,     // who accepts the root  — this node
    subject_key_id,  // who holds the capability — this node
    scope,           // "infra:attest"
) -> Result<Option<TrustedGrant>, Error>
```

Both ids are this node's own `key_id`: we are asking *"do I hold this capability, from
a root I myself accept?"* Both halves matter. The `trust:accepts` edge is the operator's
un-trust lever — delete that one row and the walk returns `None`, the slice goes dark on
its own, and nothing special-cased it.

`None` is not an error. A node that has never been blessed is in a legitimate steady
state; it simply does not serve the authority slice.

## 5. Fail-secure composition, and the boot-panic trap

There is a trap here that must be named, because the obvious implementation is a
production outage.

`compose_registry()` is currently `todo!()`. It is unreachable today only because
`slices.registry` defaults to `false`. **Naively swapping the boolean for the grant
check would make canonical-1 — which holds all four verbs — evaluate the gate to
`true` and panic at boot.** The gate cannot land before the slice it gates has a
non-panicking body.

So the increment is ordered:

1. **The grant is the authority, and it lives inside the slice.** `compose_registry`
   performs its own gate check and refuses when the grant is absent. Authority checks
   belong with the thing they authorise, not at the call site.
2. **Config may only decline, never confer.** `slices.registry` is retained as an
   operator *opt-out*; it can keep a blessed node from serving, and can never make an
   unblessed node serve. Default stays `false`, so no deployed node changes behaviour.
3. **The body is honest about what it does not do yet.** Until the surfaces land, a
   conferred node logs that it is blessed and that the slice is not yet composed. It
   does not panic, and it does not silently pretend to serve.

```
grant absent  → refuse, log the reason, slice off        (fail-secure)
grant present → proceed  (Phase 1: log-only; Phases 2-4: compose the surfaces)
config off    → decline before either                    (operator opt-out)
```

## 6. What the slice will actually compose (Phases 2–4)

Not a port. `ciris-registry-core` is 21,689 lines of which **12,153 touch `sqlx`** and
**14,400 touch `tonic`**; only 3,604 touch neither. That mass does not fold — it
dissolves. Registry's tables become the shared corpus and the gRPC surface stops
existing rather than being re-hosted in axum.

The impedance is *not* Postgres-versus-SQLite — this repo runs full Postgres via
persist's `postgres` feature on the Linux target. It is **raw sqlx versus the persist
`Engine`**: hand-written SQL bypasses the signing, scrub and quorum-merge machinery
that makes a row federate. That is what the rewrite buys, and why the tables cannot
come along unchanged.

What survives is the residual with live consumers — surfaces this repo does not have:

| Surface | Consumer | Phase |
|---|---|---|
| `/v1/builds`, `/v1/builds/{version}`, `/hash/{h}` | CIRISVerify | 2 |
| `/v1/verify/{binary,build,function}-manifest*` | CIRISVerify | 2 |
| `/v1/verify/key/{fingerprint}` | CIRISVerify | 2 |
| `/v1/revocation/{target_id}` | CIRISVerify | 2 |
| `/v1/transparency/sth/cosign`, `/witnesses` | transparency log | 3 |
| `/v1/integrity/*` (1,480 LOC — Play Integrity + iOS App Attest) | mobile attestation | 3 |
| Portal's organizations / users / key custody | **the KMP client, as cards** | 4 |
| `/v1/steward-key` | — | **retires** |

Portal's gRPC service is not rebuilt as an API. Its UI comes in as cards alongside the
existing `AccordScreen`, `IdentityManagementScreen`, `DelegationsScreen`,
`BillingScreen` and `AuditScreen` — which is what lets the RPC layer go away instead of
being re-hosted.

### `/v1/steward-key` retires rather than being carried

Worth recording why, because it looks like a surface with consumers. It is not: three
mutually incompatible schemas exist and **no two agree**. Registry serves
`{stewards[], verification_policy, …}`; verify's actual HTTP client
(`ciris-verify-core/src/https.rs`) expects single-steward `{classical{}, pqc{}, …}`
whose non-`Option` fields are absent from that response, so it fails to deserialize
outright; and verify's spec-conformant parser (`steward_key.rs`) expects
`{stewards[], threshold_policy, response_signature}` and is never reached by the HTTP
path. The live response also declares `signature_mode: "HYBRID_REQUIRED"` while
carrying no signature field at all, and asserts `hardware_class: HSM_PROD` under
`self_attested: true`.

There is no working contract to preserve. The replacement is the **public broadcast of
the persist-baked `GenesisBundle`**, which is self-authenticating — it carries its own
hybrid `authorizations` from two accord holders over the charter — and therefore
satisfies CIRISRegistry#133 by construction rather than by patch. Note this is genuinely
net-new: `GET /v1/trust-root` today is loopback-gated, an operator surface, not a
federation broadcast.

## 7. Only then, the conversion

With the slice served under a conferred role, registry-us and registry-eu convert via
the existing ceremony — `add-canonical` from the Trust Root card, A1's YubiKey plus the
USB-wrapped ML-DSA cosign, persist refusing the `canonical` role on any record that is
not anchor-scrubbed (`CanonicalRoleNotAccordConferred`). Identities carry byte-identically
per `REGISTRY_FOLD_DERISK.md` §2 — no re-key, same addresses. Then `canonical_seed.json`
is re-baked with three `serve_nodes` and tagged, so the portable root carries all three.

**Decide the admission quorum first (CIRISServer#441).** `add-canonical` is classed
`Operational` and resolves to 1-of-3 today, while the baked founding record is 2-of-3
(A1 + B1) because CIRISPersist#390 judged a single-anchor founding record a first-strike
weakness. These two admissions double the canonical set; they should not inherit 1-of-3
by default.
