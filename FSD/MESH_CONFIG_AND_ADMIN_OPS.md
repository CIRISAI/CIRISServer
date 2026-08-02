# Mesh configuration + admin ops — the 0.5.154 design

Companion to `FSD/ADMIN_OPS_TAXONOMY.md` (the failure taxonomy this is checked
against). Scope: the trust-root card's four tabs, the mesh-config plane, the
graded admin ops, and the substrate asks that fall out.

---

## 0. Principles, restated as walls

Every design decision below is forced by the intersection of restrictions that
already exist. Stated once:

- **W1 — markers, not commands.** A mesh-native admin op is a signed,
  attributable, subscribable marker (`withdraws` / `HardCaseEvent` /
  `delegates_to`), never a destructive global command. Derived from the Usenet
  cancel wars; every durable system re-derived it (NoCeM, Matrix policy rooms,
  fediverse limits, Tor flags, CT graded distrust).
- **W2 — exit is real.** Multi-trust-root is an acceptable and intended state.
  Anyone can mint a root with six YubiKeys and run the mesh their way. Every
  authority below is therefore scoped to *the cohort that trusts this root* —
  power that overreaches evacuates the mesh rather than corrupting it, and that
  threat is what keeps tier-3 ops honest.
- **W3 — node config is SELF.** `config:*` is `cohort_scope=SELF` by ratified
  design (#324): a node's configuration is not federation-visible. Mesh-wide
  config is therefore a NEW plane, not a widening of the old one. Conflating
  them would undo #324.
- **W4 — no consent is implied.** A node honours a root's mesh config *because
  it trusts that root* — the trust edge is the subscription. Un-trusting the
  root (delete one attestation) unsubscribes from its configuration, and the
  capability cascade fails closed on its own.
- **W5 — the emergency path must not become the government.** Single-holder
  speed and quorum legitimacy pull apart. The resolution (below) is that
  emergency changes are temporary BY CONSTRUCTION.

---

## 1. The trust-root card — four tabs

```
┌─ Trust Root ────────────────────────────────────────────────────┐
│ [Genesis Ops] [Maintenance] [Operations] [Mesh Configuration]   │
└─────────────────────────────────────────────────────────────────┘
```

### Tab 1 — Genesis Ops (current material, organized)
- Trust root state: `root_kind`, `conferral_plane`, drill band, charter
- Humanity-accord roster: the 3 seats, custody tiers, heartbeat
- Canonical servers: CRUD (bless via co-scrub, withdraw via `retired_at`)
- CI runner blesses: `/v1/accord/ci-key/{propose,cosign}` (#290)

### Tab 2 — Maintenance (new)
- Mesh state view: nodes/keys/corpora **selected by filter** (the same
  `AttestationFilter` push-down of #343 — the UI filter IS the query filter)
- The graded ops (taxonomy tiers 0–4): annotate · throttle · quarantine ·
  force-descent · de-admit
- **Preview before commit** as a gate, not a convenience: exact row set, count,
  blast radius, rendered from a dry-run — the same selection the commit will
  use, not a re-computation (left-pad rule)
- Hard-case ledger: every admin action's tombstone, filterable by kind /
  authority / subject
- Every commit carries: the authorizing `delegates_to` attestation id + a
  mandatory reason string → into `HardCaseEvent.detail`

### Tab 3 — Operations (current material)
- Halt (kill switch, quorum-gated) · reactivate
- Drill (freshness band drives the trust card)
- Announce (single-holder notify)

### Tab 4 — Mesh Configuration (new)
- The mesh-config plane (§2): current effective values, provenance
  (which accord action set each), TTLs counting down
- Emergency relief actions (§3): pre-declared knobs with graded authority
- History: every past change with its signed carrier

---

## 2. The mesh-config plane

**A new dimension family: `mesh_config:{key}:v1`** (name subject to persist's
vocabulary registry — see asks).

| property | node config (`config:v1`) | mesh config (`mesh_config:*`) |
|---|---|---|
| cohort_scope | SELF (#324) | FEDERATION |
| author | the node itself | an accord holder (or quorum, §3) |
| audience | this node | every node that trusts this root |
| subscription | n/a | the trust edge itself (W4) |
| conflict rule | last-write-wins per key | last-write-wins per key **per root** |

A node resolves a mesh-config key by folding: rows authored by holders of a
root it trusts, newest-first, TTL-unexpired. **Multi-root nodes fold per root
and take the most restrictive value** — restrictions compose safely; grants do
not (fail-closed under plural authority).

The knobs are a **closed registry, not free-form** — every key names its
consumer processor or it cannot be set (the #333 lesson: a scope conferred with
no processor gating on it is decoration). Initial registry:

| key | consumer | relieves |
|---|---|---|
| `redundancy.k_repair_target` | fountain repair planner | storage pressure (20 copies → 10) |
| `redundancy.min_viable_floor` | fountain eviction | do-not-descend-below floor |
| `antientropy.round_secs` | edge reconcile cadence | network congestion |
| `antientropy.page_limit` | replication page size | memory/network pressure |
| `backpressure.summary_only` | trace serving | serve summaries, not raw traces |
| `feature.av_streams` | ALM admission | disable A/V under congestion |
| `feature.trace_replication` | replication offer filter | pause the heaviest plane |
| `descent.pressure_multiplier` | #239 retirement operator | accelerate aging mesh-wide |
| `admission.rate_per_key` | tier-1 throttle default | flood response |

### The safety floor

`mesh_config` may **relieve** pressure and **restrict** activity. It may not:
- override the kill switch or drill machinery (constitutional plane, CC 4.2)
- alter consent semantics — no key may cause a node to share MORE than its
  owner consented to (a mesh-config key can narrow serving, never widen it)
- touch `min_viable` below the safety floor the manifest pins (a root that
  wants data loss must say so with a tier-3 op, not a config knob)

The invariant, checkable per key: **every mesh-config action must be a
restriction or relief, never an expansion of what flows.** That is what makes
W4's "trust = subscription" safe — the worst a hostile root can do to a
subscriber via config is slow it down, which is also exactly the multi-root
most-restrictive fold rule.

---

## 3. The emergency channel (W5)

The announce machinery already exists (`POST /v1/accord/announce`,
`InvocationKind::Notify`, threshold 1, verified + gossiped). The emergency
config change rides the same carrier with a new invocation kind:

```
InvocationKind::ConfigRelief {
    changes:    [{ key, value }],        // registry keys only
    ttl_secs:   u32,                     // MANDATORY, bounded (e.g. ≤ 72h)
    reason:     String,                  // MANDATORY
}
```

**The wall-derived resolution of speed vs legitimacy:**

| authority | effect | duration |
|---|---|---|
| ONE holder (threshold 1, announce-fast) | any registry key | **expires automatically**; TTL ≤ 72h; not renewable by the same single holder back-to-back |
| accord quorum (kill-switch M) | any registry key | durable until changed |

A single holder can relieve congestion *now* — and cannot govern, because the
change dies on its own unless quorum ratifies it. Ratification is an ordinary
quorum action referencing the emergency's `payload_sha256`, so the ledger shows
"emergency by A1 at T, ratified by quorum at T+6h" as two linked objects.
Auto-expiry is the W5 wall: the emergency path is useful precisely because it
cannot become the government.

Every change (emergency or durable) lands as a signed attestation → tombstone
trail for free; the Mesh Configuration tab's history is just a filtered read.

---

## 4. The graded admin ops (from the taxonomy) — route sketch

All owner-gated, all requiring a `delegates_to` chain with the named scope, all
recording `{delegation_id, reason}` in a `HardCaseEvent`:

```
POST /v1/admin/annotate     tier 0  scope: review      → hard_case marker only
POST /v1/admin/throttle     tier 1  scope: moderate    → admission.rate_per_key for a key
POST /v1/admin/quarantine   tier 2  scope: moderate    → withhold-from-serving marker, rows retained
POST /v1/admin/descend      tier 3  scope: slash (NEW) → CC 6.1.2 forced descent, blur + tombstone
POST /v1/admin/deadmit      tier 4  scope: slash (NEW) → key may no longer write (re-admittable)
POST /v1/admin/preview      any     (read-only)        → exact row set + counts for a proposed op
```

`preview` returns a **selection hash**; the commit call must present the same
hash, so what was previewed is what executes (TOCTOU-closed, left-pad rule).
Tier 3 takes an optional `after: timestamp` — the time-bounded judgement family
2b needs (key compromise: "everything after T", not "everything").

---

## 5. Substrate asks (thread 1, derived)

### CIRISPersist
1. **`mesh_config` vocabulary + fold** — the family, the closed key registry
   shape, the per-root most-restrictive fold, TTL expiry at read time.
   (Vocabulary is persist's; we will not hand-mirror it — SRV-1.)
2. **`slash` delegation scope** — the tier-3/4 duty scope. The four existing
   scopes are all emit-authorities; this is the first remove-authority, and it
   must be persist's constant.
3. **Admin-action `hard_case` kind** with REQUIRED `{delegation_id, reason}`
   in `detail` — refused at admission if absent (an unattributed admin action
   is indistinguishable from an unauthorized one).
4. **Time-bounded de-admission**: `revoked_after: timestamp` on the key plane,
   so compromise response does not destroy the key's honest history.
5. **Quarantine marker** the serve path consults (withhold-from-serving without
   row deletion) — tier 2's carrier.

### CIRISEdge
6. **Consume `antientropy.*` + `feature.*` mesh-config keys** — reconcile
   cadence, page size, per-plane pause, ALM admission toggle.
7. **`ConfigRelief` invocation kind** on the accord announce carrier —
   verify, gossip, surface; same machinery as Notify.
8. **Honour quarantine markers in the offer filter** (do not serve quarantined
   rows to peers; keep them locally).

### CIRISServer (us, 0.5.154)
9. The four-tab card + routes above; the preview engine over
   `AttestationFilter` (#343's push-down IS the selection engine).
10. Wire `erase_agent_traces` (tier 3's GDPR-shaped sibling, built + unreachable).
11. First caller for `DELEGATION_SCOPE_CONSENT_REVOCATION` (proxy revocation,
    currently unused).

---

## 6. What this deliberately does not do

- No global delete. Tier 3 leaves the blur and the tombstone (CC 6.1.2).
- No cross-root authority. A root configures its own cohort; W2.
- No free-form config keys. Registry-only, each key naming its processor.
- No silent ops. Every tier ≥ 1 action is itself a replicated, signed object.
