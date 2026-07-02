# FSD — Delegation Constraints & Enforcement (constrained act-on-behalf grants)

**Status:** MVP **IMPLEMENTED** in 0.5.72 (this spec's Phase-1 scope: action allow/deny +
goal + server never-list + tighten-only approve + graph-persisted constraints + full
transparency). Supersedes/formalizes `FSD/DELEGATION_EXPANSION.md` (the exploratory
proposal). Not law.

**Shipped in 0.5.72 (delta from the spec below):**
- `DelegationConstraints { actions_allow: Option<Vec>, actions_deny: Vec, goal }` (`src/auth/session.rs`)
  — the tri-state allow-list (`None`=all / `[]`=read-only / subset), rides in the signed
  `delegates_to` envelope (`with_constraints`, `src/auth/device_grant.rs`) AND caches on the grant.
- `authorize_delegated(caller, verb) -> Result<(), DenyReason>` + `require_verb` + the
  `CapabilityVerb` enum & `never_delegatable()` floor (delegate/wipe/accord_halt) in
  `src/auth/gate.rs`; wired after `require_owner` in claim-remote / announce / peering / set-age.
- `/delegate` carries `constraints`; `/approve` folds them **tighten-only**
  (`DelegationConstraints::tightened_with` — allow=∩, deny=∪, never widens).
- Duration: `emit_signed_attestation` gained `expires_at` (= CC 2.4.1.2 `delegation_valid_until`),
  so delegation edges self-expire.
- Transparency: `x-ciris-delegation` response header on every dgrant use (global middleware,
  `src/delegation_transparency.rs`) + a `delegation` object in `/claim`+`/token` bodies.
- Client UX localized to 28 languages (DelegationsScreen constraints editor + "what this permits").
- Deferred (still spec-only below): resources & tasks axes, per-request metering, and reading
  constraints back **from the graph edge** in `resolve_bearer` (today enforced from the in-memory
  grant — consistent, since the bearer is ephemeral; the envelope copy is the durable/audit record).

**Constitution baseline:** CC 3.2 / CC 1.13.5 (responsible-party model) + CC 4.4.3.5
(scope split). Capability-security layered ON TOP of the existing CEG authority model —
no new trust root.
**Subsystem:** `src/auth/` (device-grant delegation + session bearer resolution).
**Companion specs:** `FSD/DELEGATION_EXPANSION.md` (the high-level five-axis proposal this
document turns into a build), `FSD/SAFE_MESH.md` (owner-binding invariants),
`FSD/MESH_SEED_RUNBOOK_POST_DELEGATION.md`.
**Primary files:** `src/auth/device_grant.rs`, `src/auth/session.rs`, `src/auth/ownership.rs`,
plus the eight `require_owner` call-sites enumerated in §7.

---

## 1. Summary & goals / non-goals

### 1.1 Thesis

Today, when the owner authorizes an agent to "act on my behalf" (the RFC-8628-shaped
device grant in `src/auth/device_grant.rs`), the delegate receives the owner's **entire
authority** — `SystemAdmin` role + `FullAccess` permission — for a fixed **1 hour**
(`DELEGATED_TTL_SECS = 3_600`, `device_grant.rs:65`) under a single fixed scope string
(`DEFAULT_SCOPE = "owner:act-on-behalf"`, `device_grant.rs:68`). The delegate passes every
owner-gated gate identically to the owner (`session.rs:335-341` mints a caller wielding
`grant.owner_role` + `permissions_for(grant.owner_role)`); the only thing distinguishing it
is `SessionCaller.actor: Some(client_id)` (`session.rs:166`), which today is inspected in
exactly two places to forbid re-delegation (`device_grant.rs:716`, `accord.rs:387`).

This spec makes the owner able to **constrain** a grant along five axes — **duration,
resources, actions, goal, tasks** — each with an allow form and (where sensible) a deny
form, PLUS a server-side **NEVER-list** that holds regardless of any allow-list. The
constraints ride INSIDE the signed `delegates_to` CEG envelope (tamper-evident, replicable,
revocable exactly like the grant itself) and are enforced by a single guard,
`authorize_delegated`, folded into every `require_owner` so no call-site can forget it.

### 1.2 Goals

- G1. Least-privilege delegation: the owner constrains what a delegate may do, to what, for
  how long, toward what stated goal, and (optionally) exactly which tasks how many times.
- G2. Deny wins: an owner deny-list and a server NEVER-list override any allow-list.
- G3. CEG-native: constraints are a member of the signed `delegates_to` envelope — no new
  persist primitive, no parallel authority store. The bearer stays an ephemeral session
  credential re-checked against the graph on every request (`session.rs:294-341`).
- G4. Enforcement cannot be forgotten: the guard is threaded through the shared owner gate so
  adding an owner-gated route without a verb fails to compile.
- G5. Full backward compatibility: an absent `constraints` == today's unconstrained grant.
- G6. Tighten-only: an approver may narrow a client-requested grant, never widen it.

### 1.3 Non-goals

- N1. Not a policy engine / OPA. Verbs are coarse route-groups; the resource matcher is a
  simple glob/exact matcher. No expression language.
- N2. Goal is NOT machine-enforced intent (inherent limit of capability security, §11).
- N3. No cross-restart hard metering guarantee in MVP (counts are in-memory; §9).
- N4. No change to the owner's own power. A real owner session has `actor == None` and the
  guard short-circuits to `Ok(())` (§6.2) — this document only ever constrains **delegates**.
- N5. No new token format. `dgrant:<rand>` (`session.rs:214`) is unchanged; only the
  registry entry behind it gets richer.

---

## 2. Current state (precise data model, with citations)

### 2.1 The grant is a single scope string + full owner authority

| Concern | Where | Value / shape |
|---|---|---|
| Default scope | `device_grant.rs:68` | `const DEFAULT_SCOPE: &str = "owner:act-on-behalf"` |
| Handshake TTL | `device_grant.rs:60` | `GRANT_TTL_SECS = 600` (RFC-8628 `expires_in`) |
| Bearer TTL | `device_grant.rs:63-65` | `DELEGATED_TTL_SECS = 3_600` (1h, FIXED) |
| Graph-walk depth | `device_grant.rs:71`, `session.rs:209` | `DELEGATION_DEPTH = 4`, `DELEGATION_REACHABILITY_DEPTH = 4` |
| Ephemeral handshake | `device_grant.rs:94-106` | `struct DeviceGrant { user_code, client_id, scope: String, expires_at, status }` |
| `/code` request DTO | `device_grant.rs:209-214` | `DeviceCodeRequest { client_id, scope: Option<String> }` |
| `/delegate` request DTO | `device_grant.rs:309-322` | `DelegateRequest { mode, label, existing_key_id, scope: Option<Vec<String>> }` — only `scope.first()` is kept (`device_grant.rs:420-423`) |
| `/approve` request DTO | `device_grant.rs:733-736` | `DecisionRequest { user_code }` |

### 2.2 The durable authority is a signed `delegates_to` CEG attestation

On owner one-shot mint (`delegate`, `device_grant.rs:401`) or client-flow approve
(`approve`, `device_grant.rs:747`), the node resolves the owner's federation signer
(`resolve_owner_signer`, `device_grant.rs:132`) and emits a signed `delegates_to(owner →
actor, [scope])`:

- envelope built by `ciris_persist::federation::delegates_to_envelope(&client_id, &[scope],
  false)` — `device_grant.rs:535-539` (delegate) / `792-796` (approve). Per
  `DELEGATION_EXPANSION.md`, the persist helper's fixed shape is
  `{kind, dimension, delegate_key_id, scope, sub_delegation}`.
- persisted via `crate::auth::ownership::emit_signed_attestation(...)` —
  `device_grant.rs:540-557` / `797-814`. That function **canonicalizes the envelope verbatim**
  (`ceg_produce_canonicalize`, `ownership.rs:820`), hashes it
  (`original_content_hash = SHA-256(canonical)`, `ownership.rs:822`), hybrid-signs the canonical
  bytes (`ownership.rs:823-826`), and stores the envelope UNMODIFIED in
  `attestation_envelope` (`ownership.rs:836`). It hardcodes `expires_at: None`
  (`ownership.rs:835`) and `cohort_scope: FEDERATION` / `tier: FEDERATION`
  (`ownership.rs:846-847`).

**Key finding for storage (§5):** `emit_signed_attestation` accepts an arbitrary
`serde_json::Value` envelope and canonicalizes+signs+stores it verbatim. Adding a
`constraints` member is therefore tamper-evident for free (it is inside the signed bytes)
and requires NO persist change. The target is AGENT-role (`register_minted_agent_key` sets
`identity_type::AGENT`, `device_grant.rs:368`), so the CC 1.13.5 node-agency admission gate
(which rejects non-`infra:*` scopes only for NODE-role targets) does not apply.

### 2.3 The bearer is re-checked against the graph on every request

`claim` (`device_grant.rs:603`) and `token` (`device_grant.rs:888`) both re-verify the edge
is live before minting: `engine.reachable_under_scope(&owner_key_id, &client_id, &scope,
DELEGATION_DEPTH)` — `device_grant.rs:659-667` / `949-957`. They register a `dgrant:<rand>`
bearer: `register_delegated_grant(DelegatedGrant { owner_wa_id, owner_role, owner_key_id,
client_id, scope, expires_at })` — `device_grant.rs:669-676` / `963-970`; struct at
`session.rs:187-204`.

On EVERY request `resolve_bearer` (`session.rs:285`) sees the `dgrant:` prefix
(`session.rs:294`), re-runs `reachable_under_scope` (`session.rs:305-327`), and returns a
`SessionCaller` wielding the owner's full role (`session.rs:335-341`), distinguished only by
`actor: Some(client_id)`. So a `withdraws` on the edge kills the bearer immediately.

### 2.4 Where authorization is enforced today (the gap)

Every owner-gated route calls a local `require_owner` that checks ONLY
`role == SystemAdmin && permissions.contains(FullAccess)`; NONE check per-action/-resource/
-duration constraints (they do not exist). See §7 for the full grep. A delegated caller
passes all of them identically to the owner. This is the crux this spec closes.

---

## 3. Data model — `DelegationConstraints`

New module `src/auth/delegation_guard.rs`. Every field optional; an all-default value is the
sentinel for "explicitly read-only" (see §8 back-compat for the `Option`-vs-`default`
distinction that preserves the literal legacy grant).

```rust
use serde::{Deserialize, Serialize};

/// Owner-authored bounds on ONE act-on-behalf delegation. Serialized INTO the signed
/// `delegates_to` envelope (tamper-evident) AND snapshotted onto `DelegatedGrant`
/// (session.rs) for cheap per-request checks. All fields optional (§8 back-compat).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DelegationConstraints {
    // ── AXIS 1: DURATION ────────────────────────────────────────────────────
    /// Requested bearer lifetime (s). Clamped to `max_ttl_secs` and the server ceiling
    /// `MAX_DELEGATED_TTL_SECS`. Absent ⇒ `DELEGATED_TTL_SECS` (3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Owner-tolerated ceiling; a renewal may not exceed it. Absent ⇒ server ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    /// Absolute wall-clock expiry (unix s). The grant dies here regardless of renewals;
    /// plumbed into the edge's `expires_at` so the graph denies a lapsed delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_expiry_unix: Option<u64>,
    /// May the delegate re-mint a bearer against a still-live edge (re-`claim`/`token`)
    /// without a fresh owner approval? Default false.
    #[serde(default)]
    pub renewable: bool,

    // ── AXIS 2: RESOURCES (allow + deny) ────────────────────────────────────
    /// If non-empty, the delegate may touch ONLY matching resources; empty ⇒ all
    /// (subject to deny). Grammar = `ResourceRef` string forms (§3.2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources_allow: Vec<String>,
    /// Always-forbidden resources (evaluated AFTER allow; deny wins).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources_deny: Vec<String>,

    // ── AXIS 3: ACTIONS (allow + deny) ──────────────────────────────────────
    /// Capability verbs the delegate may perform (`CapabilityVerb` wire strings, §3.1).
    /// Empty ⇒ `["read"]` (fail-safe: read-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions_allow: Vec<String>,
    /// Verbs ALWAYS forbidden (deny wins). The server NEVER-list (§6.3) is unioned in
    /// unconditionally regardless of this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions_deny: Vec<String>,

    // ── AXIS 4: GOAL ────────────────────────────────────────────────────────
    /// Human-readable intent this grant is scoped to. Advisory to the enforcer (logged
    /// on every action; surfaced in listing) but load-bearing for the human approver +
    /// audit. Capped at `MAX_GOAL_LEN` (512) chars at admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,

    // ── AXIS 5: TASKS ───────────────────────────────────────────────────────
    /// Explicit allow-list of concrete tasks. Empty ⇒ not task-gated (fall back to
    /// action/resource). When non-empty it is AUTHORITATIVE-AND-ADDITIVE: the request's
    /// task id must be present AND action/resource must still pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks_allow: Vec<TaskGrant>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskGrant {
    /// Stable task id, e.g. `config.set:net.bootstrap_peers`, `federation.announce`.
    pub task: String,
    /// Optional cap on invocations ("at most N times"). Metered per-bearer (§9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
}
```

### 3.1 `CapabilityVerb`

A closed enum with stable wire strings. The verb is passed by each route (§7). Keeping it an
enum (not a bare `&str`) is what makes G4 compile-time-safe — a new owner-gated route must
name a verb.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityVerb {
    Read,          // "read"          — any GET / read-only owner-gated route
    ConfigWrite,   // "config:write"  — POST/PUT /v1/config, /v1/config/{key}
    ConfigDelete,  // "config:delete" — DELETE /v1/config/{key}
    Announce,      // "announce"      — POST /v1/federation/announce
    Peering,       // "peering"       — POST /v1/federation/peering
    ClaimRemote,   // "claim-remote"  — POST /v1/setup/claim-remote
    IdentitySelf,  // "identity:self" — POST /v1/self/identity, /v1/self/age
    Occurrence,    // "occurrence"    — POST /v1/self/occurrence/portable, /v1/self/associate
    // ── NEVER verbs (never grantable to a delegate; §6.3) ──
    Delegate,      // "delegate"      — device-grant delegate/approve/deny/revoke
    UpgradeOwner,  // "owner:upgrade" — POST /v1/self/upgrade-owner
    Wipe,          // "wipe"          — /v1/system/data/{reset-account,wipe-signing-key}
    Accord,        // "accord"        — every /v1/accord/* owner-gated op
}

impl CapabilityVerb {
    pub fn wire(self) -> &'static str { /* the string in each comment above */ }
    /// The hard floor — true for verbs a delegate may NEVER hold (§6.3).
    pub fn is_never(self) -> bool {
        matches!(self, Self::Delegate | Self::UpgradeOwner | Self::Wipe | Self::Accord)
    }
}
```

### 3.2 `ResourceRef`

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ResourceRef {
    /// A node key_id (`node:<key_id>`). Exact match.
    Node(String),
    /// A config key or dotted prefix (`config:<key>` / `config:<prefix>*`). Glob on `*`.
    Config(String),
    /// A CEG object type (`ceg:<object_type>`, e.g. `ceg:consent:*`). Glob on `*`.
    CegType(String),
    /// The route names no specific resource (a self/identity op). Matches allow-all only.
    None,
}
```

Match rule (used by the guard, §6): `resources_allow` empty ⇒ allow-all; else the request's
`ResourceRef` must match ≥1 allow pattern; then it must match NO `resources_deny` pattern
(deny wins). `Config`/`CegType` glob on a single trailing (or embedded) `*`; `Node` is exact.
`ResourceRef::None` only satisfies an empty allow-list (an unscoped op can't be resource-gated
positively — the owner constrains it via the action verb instead).

### 3.3 Exact JSON (serialized inside the envelope; camelCase not used — snake per serde)

```jsonc
{
  "ttl_secs": 900,
  "max_ttl_secs": 3600,
  "hard_expiry_unix": 1750000000,
  "renewable": false,
  "resources_allow": ["config:net.*", "node:ciris-client-kdcinpxuio"],
  "resources_deny": ["config:net.bootstrap_peers"],
  "actions_allow": ["read", "config:write"],
  "actions_deny": [],
  "goal": "keep the peer list fresh while I travel",
  "tasks_allow": [
    { "task": "config.set:net.relay_hint", "max_invocations": 5 }
  ]
}
```

An absent field is omitted (`skip_serializing_if`); an all-default value serializes to `{}`
(and, critically, is distinct on the wire from a MISSING `constraints` member — §8).

---

## 4. In-memory cache changes

- `DeviceGrant` (`device_grant.rs:94-106`) gains `constraints: DelegationConstraints` — carried
  from `/code` or `/delegate` through approve to claim/token.
- `DelegatedGrant` (`session.rs:187-204`) gains:
  - `constraints: DelegationConstraints` (snapshot for per-request checks), and
  - `invocation_counts: Arc<Mutex<HashMap<String, u32>>>` (per-bearer metering, §9).
- `SessionCaller` (`session.rs:151-167`) gains `delegation: Option<DelegationConstraints>`,
  populated ONLY on the delegated branch (`session.rs:335`); `None` for a normal owner/user
  session (`session.rs:354-360`) so owner power is untouched.

---

## 5. Storage — CEG-native, no new persist primitive

**Decision: constraints ride INSIDE the signed `delegates_to` envelope.** Verified against
`ownership.rs`: `emit_signed_attestation` (`ownership.rs:810-856`) takes the envelope as an
arbitrary `serde_json::Value`, runs `ceg_produce_canonicalize` over it (`ownership.rs:820`),
stores it verbatim in `attestation_envelope` (`ownership.rs:836`), and signs the canonical
bytes (`ownership.rs:823-826`, `original_content_hash` at `822`). Therefore an added
`constraints` member is inside the tamper-evident, hash-bound, hybrid-signed payload — and is
replicated + revoked (via `withdraws`) exactly like the grant. **No new persist primitive.**

### 5.1 Envelope shape

Because the persist helper `delegates_to_envelope` has a fixed shape, build the envelope
locally at the two emit sites (`device_grant.rs:535`, `792`) and add the member:

```jsonc
{
  "kind": "delegates_to",
  "dimension": "<the helper's DIMENSION_DELEGATES_TO>",
  "delegate_key_id": "<actor key_id>",
  "scope": ["owner:act-on-behalf"],   // UNCHANGED — reachable_under_scope / edge_scope key on this
  "sub_delegation": false,
  "constraints": { /* DelegationConstraints, only when non-empty */ }
}
```

`scope` stays the coarse string: `reachable_under_scope` (`session.rs:305`,
`device_grant.rs:661`, `949`) and `edge_scope`/`live_delegations` (`device_grant.rs:163-173`,
`1000-1026`) all key on it; changing it would ripple through liveness + listing.
`constraints` is a NEW additive member the guard reads back from the same signed envelope.
Omit the member entirely when the owner supplied none (preserves the legacy canonical bytes,
§8).

### 5.2 Duration is the one axis that also touches the edge row

The attestation's own `expires_at` is hardcoded `None` (`ownership.rs:835`). To make the graph
itself deny a lapsed delegation (not only the volatile in-memory TTL), plumb an
`Option<DateTime<Utc>>` through `emit_signed_attestation` and set it from
`constraints.hard_expiry_unix`. This is a signature change to `emit_signed_attestation`
(add a trailing `expires_at: Option<chrono::DateTime<chrono::Utc>>`); all existing callers pass
`None`. `reachable_under_scope` then naturally rejects an expired edge. (Confirm
`put_attestation` honors `expires_at` in liveness; `emit_steward_binding` and the owner-binding
path both set `expires_at: None` today, so this is the first non-`None` use — flagged as a test
item, §10.)

### 5.3 Admissibility check (do before impl)

`DELEGATION_EXPANSION.md` §7.2 flagged persist strictness on `delegates_to`. The node-agency
admission gate (`check_node_agency_admission`) rejects non-`infra:*` scope only for NODE-role
**targets**; our target is AGENT-role (`device_grant.rs:362-368`) and `scope` is unchanged, so
the gate is not triggered. The only remaining risk is a persist schema that rejects UNKNOWN
envelope members — but `emit_signed_attestation` already round-trips arbitrary CEG envelopes
through `ceg_produce_canonicalize` + `put_attestation` for every attestation type, so an extra
object member is admissible. **Fallback (if a future persist admission ever rejects unknown
members):** emit a SIBLING attestation `attestation_type = "delegation_constraints"` whose
envelope is `{ "delegates_to_id": <edge id>, "constraints": {...} }`, signed by the same owner
signer in the same call, and have the guard resolve it by the edge id. This is strictly a
fallback; the primary design is the single-envelope member.

---

## 6. Enforcement — one guard, folded into `require_owner`

### 6.1 Signature

New in `src/auth/delegation_guard.rs`:

```rust
/// The single delegated-authorization guard. Called by EVERY owner-gated route (via the
/// shared owner gate, §6.4). A real owner (`caller.delegation.is_none()`) short-circuits
/// to Ok(()). A delegate is checked against its constraints in the fixed order §6.2.
pub fn authorize_delegated(
    caller: &SessionCaller,
    verb: CapabilityVerb,
    resource: &ResourceRef,
) -> Result<(), DenyReason>;

/// Structured denial (rendered to the 403 body, §6.5).
#[derive(Debug, Clone)]
pub struct DenyReason {
    pub denied_by: DeniedBy,      // NeverList | ActionDeny | ActionAllow | ResourceDeny |
                                  // ResourceAllow | TaskNotAllowed | MeterExhausted | Expired
    pub verb: CapabilityVerb,
    pub resource: ResourceRef,
    pub goal: Option<String>,     // echoed from the grant for the human-readable explanation
    pub detail: String,
}
```

Metering (`TaskGrant.max_invocations`) mutates the per-bearer counter, so the guard also needs
the counter handle. Two shapes are acceptable; pick one at impl time:
(a) pass `&DelegatedGrant` instead of `&SessionCaller` to the guard (richer, but every route
would need the grant), or **(b, preferred)** carry an `Arc<Mutex<HashMap<String,u32>>>` on
`SessionCaller.delegation` alongside the constraints (populated at `session.rs:335`), so the
guard reads/increments through the caller. (b) keeps the route signature to
`(caller, verb, resource)`.

### 6.2 Ordering of checks (deny-biased; FIRST failure wins)

```
authorize_delegated(caller, verb, resource):
  let Some(c) = caller.delegation else { return Ok(()) }   // real owner → unconstrained
  1. NEVER-LIST   : if verb.is_never()                        → Deny(NeverList)
  2. ACTION DENY  : if verb.wire() ∈ c.actions_deny           → Deny(ActionDeny)
  3. ACTION ALLOW : let allow = if c.actions_allow.is_empty() {["read"]} else {c.actions_allow};
                    if verb.wire() ∉ allow                    → Deny(ActionAllow)
  4. RESOURCE DENY: if resource matches any c.resources_deny  → Deny(ResourceDeny)
  5. RESOURCE ALLOW: if !c.resources_allow.is_empty()
                     && resource matches none                 → Deny(ResourceAllow)
  6. TASKS        : if !c.tasks_allow.is_empty():
                      let t = task_id_for(verb, resource);
                      let Some(tg) = c.tasks_allow.find(t)    else Deny(TaskNotAllowed)
                      if let Some(max)=tg.max_invocations:
                        if counter[t] >= max                  → Deny(MeterExhausted)
                        else counter[t] += 1                  // meter on PASS (§9)
  7. Ok(())
```

Duration/expiry (axis 1) is enforced at TWO earlier points, not inside this guard:
`resolve_bearer` rejects an expired bearer TTL (`lookup_delegated_grant`, `session.rs:244-252`)
and an expired edge (`reachable_under_scope`, `session.rs:305`, backed by §5.2's edge
`expires_at`). So by the time the guard runs, duration already passed; the guard covers axes
2-5 + the never-list. (A belt-and-suspenders `hard_expiry_unix` recheck inside the guard is
cheap and recommended — the `Expired` `DeniedBy` variant exists for it.)

### 6.3 The server NEVER-list (hard floor)

Independent of any `actions_allow`, verbs `Delegate`, `UpgradeOwner`, `Wipe`, `Accord` are
refused (`CapabilityVerb::is_never`, step 1). This holds even if an owner fat-fingers them into
`actions_allow`. Two of these are ALREADY partially floored today and MUST stay:
`device_grant.rs:716` (`caller.actor.is_none()` blocks a delegate approving/re-delegating) and
`accord.rs:387` (blocks a delegate reactivating the accord). The never-list generalizes those
two ad-hoc `actor` checks into one rule.

### 6.4 Folding into the shared owner gate (so it cannot be forgotten — G4)

Today each of the eight `require_owner` variants is a per-file copy that checks only
role+permission. Refactor them to a **single shared** gate that TAKES the verb+resource and
runs `authorize_delegated` internally. Proposed home: extend `src/auth/gate.rs` (already the
owner-gate module, hosting `require_owner_bound`, `gate.rs:64`):

```rust
// src/auth/gate.rs
pub async fn require_owner_verb(
    engine: &Engine,
    headers: &HeaderMap,
    verb: CapabilityVerb,
    resource: ResourceRef,
) -> Result<SessionCaller, Response> {
    let caller = /* existing role+FullAccess check, from the current require_owner bodies */;
    delegation_guard::authorize_delegated(&caller, verb, &resource)
        .map_err(deny_response)?;   // 403 structured body, §6.5
    Ok(caller)
}
```

Each existing local `require_owner` becomes a thin wrapper (or is replaced at the call-site) that
supplies its route's verb+resource. Because `verb: CapabilityVerb` is a required non-defaultable
argument, a NEW owner-gated route physically cannot call the gate without choosing a verb — the
compile-time seam that satisfies G4. The `actor.is_none()` sub-clause currently in
`device_grant.rs:716` is subsumed by the `Delegate` never-verb.

### 6.5 Failure response shape

```
403 Forbidden
{
  "error": "delegation_forbidden",
  "denied_by": "resource_allow",
  "verb": "config:write",
  "resource": "config:secrets.root",
  "goal": "keep the peer list fresh while I travel",
  "detail": "resource config:secrets.root not in the grant's allow-list [config:net.*]"
}
```

Duration failures keep the existing shapes: `410 Gone {"error":"expired_token"}` at claim/token
(`device_grant.rs:627`, `916`), and `Ok(None)` → the route's own `401/UNAUTHORIZED` when
`resolve_bearer` drops an expired/lapsed bearer (`session.rs:247-252`, `315-322`). A
guard-level hard-expiry recheck returns `403 {"error":"delegation_expired"}`.

---

## 7. Verb & endpoint catalog (from the `require_owner` grep)

Every owner-gated route, its file:line, the `CapabilityVerb` it passes, and the `ResourceRef`.
NEVER rows are refused for any delegate (§6.3).

| Route | Handler / gate site | Verb | Resource | Delegate? |
|---|---|---|---|---|
| `POST /v1/config` | `config_api.rs:116` set_config; gate `:126` | `ConfigWrite` | `Config(req.key)` | if allowed |
| `GET /v1/config` | `config_api.rs` list_config; gate `:182` | `Read` | `Config(prefix?)` | if allowed |
| `GET /v1/config/{key}` | get_config; gate `:204` | `Read` | `Config(key)` | if allowed |
| `PUT /v1/config/{key}` | update_config; gate `:239` | `ConfigWrite` | `Config(key)` | if allowed |
| `DELETE /v1/config/{key}` | delete_config; gate `:287` | `ConfigDelete` | `Config(key)` | if allowed |
| `POST /v1/federation/peering` | `federation_admin.rs:185` (handler) / gate `:80` | `Peering` | `None` | if allowed |
| `POST /v1/setup/claim-remote` | `claim_remote.rs:344` gate; handler `claim_remote_handler` | `ClaimRemote` | `Node(target)` | if allowed |
| `POST /v1/self/upgrade-owner` | `claim_remote.rs:450` gate | `UpgradeOwner` | `None` | **NEVER** |
| `POST /v1/self/age` | `claim_remote.rs:565` gate; `set_age_self` | `IdentitySelf` | `None` | if allowed |
| `POST /v1/federation/announce` | `claim_remote.rs:660` gate; `announce_self_handler` | `Announce` | `Node(self)` | if allowed |
| `POST /v1/self/identity` | `identity.rs:1005` gate; `self_identity_handler` | `IdentitySelf` | `None` | if allowed |
| `POST /v1/self/occurrence/portable` | `portable_occurrence.rs:197` gate | `Occurrence` | `None` | if allowed |
| `POST /v1/self/associate` | `portable_occurrence.rs:346` gate | `Occurrence` | `None` | if allowed |
| `POST /v1/system/data/reset-account` | `system_data.rs:126` gate | `Wipe` | `None` | **NEVER** |
| `POST /v1/system/data/wipe-signing-key` | `system_data.rs:212` gate | `Wipe` | `None` | **NEVER** |
| `POST /v1/accord/*` (holder/genesis/family/invocation) | `accord.rs` gate `:373`, sites `:425,798,841,1475,1590` | `Accord` | `None` | **NEVER** |
| `POST /v1/auth/device/delegate` | `device_grant.rs:407` gate | `Delegate` | `None` | **NEVER** |
| `POST /v1/auth/device/approve` | `device_grant.rs:753` gate | `Delegate` | `None` | **NEVER** |
| `POST /v1/auth/device/deny` | `device_grant.rs:851` gate | `Delegate` | `None` | **NEVER** |
| `GET /v1/auth/device/grants` | `device_grant.rs:1032` gate | `Read` | `None` | if allowed |
| `POST /v1/auth/device/revoke` | `device_grant.rs:1072` gate | `Delegate` | `None` | **NEVER** |

Notes:
- `device_grant.rs`'s local `require_owner` (`:699`) additionally checks `caller.actor.is_none()`
  (`:716`) — the delegate-can't-re-delegate rule, now generalized to the `Delegate` never-verb.
  Keep the local gate for delegate/approve/deny/revoke; those verbs are NEVER anyway.
- `require_owner_bound` (`gate.rs:64`, `config_api.rs:91`, `federation_admin.rs:174`) is the
  serve-only-floor gate (node must be owned at all). It is ORTHOGONAL to delegation and unchanged.
- `GET /v1/my-data/lens-identifier` (`system_data.rs`) and `GET /v1/federation/self-key-record`
  (`federation_admin.rs:116`) are NOT owner-gated (no `require_owner`) — out of scope.

---

## 8. Migration / back-compat

The critical distinction is **`constraints` absent** vs **`constraints` present but default**:

| Wire state | Meaning | Guard behavior |
|---|---|---|
| member MISSING (legacy client, or `None`) | unconstrained (today's coarse grant) | `SessionCaller.delegation = None` → `authorize_delegated` short-circuits `Ok(())` |
| member PRESENT `{}` (`Some(default)`) | explicitly least-privilege | `actions_allow` empty ⇒ `["read"]`; delegate is read-only |
| member PRESENT with fields | owner-constrained | full §6.2 evaluation |

- On the wire this is `constraints: Option<DelegationConstraints>` in the DTOs. `None`
  (absent) ⇒ omit the envelope member ⇒ legacy canonical bytes preserved ⇒ legacy behavior.
- `resolve_bearer` populates `SessionCaller.delegation` by reading the envelope's `constraints`
  member back off the live edge (it already has the edge from `reachable_under_scope`; add one
  `list_attestations_for`/lookup to fetch the envelope, or thread the constraints through the
  `DelegatedGrant` snapshot set at mint — the latter avoids the extra read and is preferred). If
  the member is absent → `None` (legacy). If present → `Some(parsed)`.
- `DELEGATED_TOKEN_PREFIX` / `dgrant:` format unchanged (`session.rs:214`).
- Client DTOs (`models/federation/Delegation.kt`) gain an optional `constraints`; kotlinx
  `ignoreUnknownKeys` means old clients ignore it.
- **Deprecation path (owner directive needed):** for one release, absent == unconstrained with
  a `tracing::warn!("legacy unconstrained delegation")`. A later release MAY flip absent →
  read-only. Tracked as OQ-1 (§12).

### 8.1 Wire/API changes (exact)

- `DeviceCodeRequest` (`device_grant.rs:209-214`): `+ constraints: Option<DelegationConstraints>`
  (client proposes; owner tightens at approve).
- `DelegateRequest` (`device_grant.rs:309-322`): `+ constraints: Option<DelegationConstraints>`
  (owner authors directly — these ARE the consented bounds). Response
  (`device_grant.rs:582-592`) echoes `constraints` so the client shows what was minted.
- `DecisionRequest` (`device_grant.rs:733-736`): `+ constraints: Option<DelegationConstraints>`.
  When present at approve it REPLACES the client-proposed value — subject to the tighten-only
  rule below. The owner-supplied value is what gets written into the signed edge.
- **Tighten-only rule (G6):** at `approve`, the owner's constraints may only NARROW the
  client's proposal. Implement `DelegationConstraints::is_tightening_of(&self, proposed) ->
  bool`: every allow-list ⊆ proposed's (or proposed empty=all), every deny-list ⊇ proposed's,
  `ttl_secs`/`max_ttl_secs`/`hard_expiry_unix` ≤ proposed, `renewable` ⇒ proposed.renewable,
  each `TaskGrant.max_invocations` ≤ proposed's. On violation → `400
  {"error":"constraints_widen_request"}`. When the owner sends nothing at approve, the client
  proposal stands (it was the owner's to approve or deny wholesale).

---

## 9. Metering & TTL

- **TTL clamp at mint** (`device_grant.rs:669` claim / `963` token / inline in `delegate`):
  `ttl = min(c.ttl_secs.unwrap_or(DELEGATED_TTL_SECS), c.max_ttl_secs.unwrap_or(CEIL), CEIL)`
  where `CEIL = MAX_DELEGATED_TTL_SECS` (new const, e.g. 24h). `expires_at = min(now + ttl,
  c.hard_expiry_unix.unwrap_or(u64::MAX))`. The same `hard_expiry_unix` is written to the edge
  `expires_at` (§5.2).
- **renewable:** only if `c.renewable` may a second `claim`/`token` mint a fresh bearer against
  a still-live edge. The handshake is single-use (`device_grant.rs:640-645`, `929-934`), so
  "renew" means re-run the poll; a non-renewable grant simply cannot (its handshake is consumed
  and a new one needs a new owner approval). Enforced at the mint sites.
- **max_invocations:** per-bearer counter `DelegatedGrant.invocation_counts`
  (`Arc<Mutex<HashMap<task_id,u32>>>`). Incremented on a PASSING guard check (§6.2 step 6).
  Task id derived by `task_id_for(verb, resource)` (e.g. `config.set:net.relay_hint`).
- **RESTART RISK (call it out explicitly):** `DELEGATED_GRANTS` is in-process
  (`session.rs:216-217`, LazyLock Mutex HashMap) and a node restart drops all bearers AND their
  counters (memory note: "a node restart drops outstanding delegations", `session.rs:175`).
  Consequences: (1) a non-renewable grant effectively dies at restart (acceptable — fail-safe);
  (2) a renewable grant survives via re-claim against the still-live edge, but its
  `max_invocations` counter RESETS to zero — weakening the cap. MVP ACCEPTS this and documents
  it. To make caps hard across restart, persist the counter as a CEG counter object keyed by
  (edge_id, task) — expensive, deferred to Full (OQ-6, §12). The edge `expires_at` (§5.2) is the
  ONE duration signal that DOES survive restart, which is why hard expiry is plumbed to the edge.

---

## 10. Test plan

Unit (`src/auth/delegation_guard.rs` `#[cfg(test)]`):
- `owner_unconstrained_passes`: `caller.delegation = None` → `Ok(())` for every verb incl. NEVER.
- `read_default_when_actions_empty`: default constraints → `Read` ok, `ConfigWrite` denied
  (`ActionAllow`).
- `action_allow_passes / action_deny_blocks`: allow `["config:write"]` passes ConfigWrite; add
  it to `actions_deny` → `ActionDeny` (deny wins over allow).
- `never_list_overrides_allow`: `actions_allow = ["wipe","accord","delegate","owner:upgrade"]`
  → each still `Deny(NeverList)`.
- `resource_allow / resource_deny`: `Config("net.bootstrap_peers")` vs allow `["config:net.*"]`
  passes; add `config:net.bootstrap_peers` to deny → `ResourceDeny`.
- `resource_glob`: `config:net.*` matches `net.relay_hint`, not `secrets.x`.
- `task_gating`: non-empty `tasks_allow` with a matching task passes; unknown task →
  `TaskNotAllowed`; `max_invocations=2` passes twice then `MeterExhausted`.
- `tighten_only`: `is_tightening_of` accepts narrower, rejects wider (each axis).
- serde round-trip: `DelegationConstraints` ⇄ the §3.3 JSON; empty ⇒ `{}`; absent member ⇒
  `None`.

Integration (mirror the existing device-grant tests + `tests/`):
- `legacy_grant_still_full_power`: `/delegate` with no `constraints` → the delegate can
  `POST /v1/config` (back-compat).
- `constrained_blocks_write`: `/delegate` with `actions_allow=["read"]` → delegate GET
  `/v1/config` 200, POST `/v1/config` 403 `delegation_forbidden`.
- `never_wipe`: any grant → delegate `POST /v1/system/data/reset-account` 403 `NeverList`.
- `duration_clamp`: `ttl_secs` beyond `max_ttl_secs`/CEIL is clamped; bearer expires early.
- `edge_hard_expiry`: `hard_expiry_unix` in the past → `reachable_under_scope` denies →
  bearer rejected even before TTL (validates §5.2 edge `expires_at` plumbing).
- `tighten_only_at_approve`: client proposes `ttl=3600,actions=[read,config:write]`; owner
  approves with `ttl=600,actions=[read]` → minted grant is the tightened one; owner approving
  with `actions=[read,config:write,peering]` → 400 `constraints_widen_request`.
- `restart_drops_meter` (documented-weakness test): assert counter resets (guards the §9 note).

---

## 11. Phasing

### MVP (biggest risk reduction per line)

Axes: **Duration** (`ttl_secs`, `max_ttl_secs`, `hard_expiry_unix`, `renewable`) +
**Actions** allow-list (coarse verbs) + **Goal** (logged/displayed) + the server **NEVER-list**
(mostly already present as the two ad-hoc `actor` checks). This alone converts "full owner
power for 1h" into "read-only for a bounded window unless the owner ticks specific write verbs."

MVP file-by-file touch list:
1. **NEW** `src/auth/delegation_guard.rs` — `DelegationConstraints`, `TaskGrant`,
   `CapabilityVerb`, `ResourceRef`, `DenyReason`, `authorize_delegated`, `deny_response`.
2. `src/auth/session.rs` — `DelegatedGrant` (`:187`) + `SessionCaller` (`:151`) gain
   `delegation`; `resolve_bearer` delegated branch (`:335-341`) populates it; keep the
   in-memory registry.
3. `src/auth/gate.rs` — add `require_owner_verb(engine, headers, verb, resource)` wrapping the
   role check + `authorize_delegated`.
4. `src/auth/ownership.rs` — `emit_signed_attestation` (`:810`) gains a trailing
   `expires_at: Option<DateTime<Utc>>`; all callers pass `None` except the two device-grant
   emits.
5. `src/auth/device_grant.rs` — DTOs (`:209,309,733`) gain `constraints`; `DeviceGrant`
   (`:94`) carries it; build the envelope locally + add the member at the emit sites
   (`:535,792`); clamp TTL + set edge `expires_at` at mint (`:669,963` + inline delegate);
   echo `constraints` in the `/delegate` response (`:582`); tighten-only check at `approve`.
6. Owner-gated routes adopt `require_owner_verb` with their verb+resource: `config_api.rs`
   (`:126,182,204,239,287`), `federation_admin.rs` (`:185`), `claim_remote.rs`
   (`:344,450,565,660`), `identity.rs` (`:1005`), `system_data.rs` (`:126,212`),
   `portable_occurrence.rs` (`:197,346`), `accord.rs` (`:425,798,841,1475,1590`). NEVER routes
   just pass their NEVER verb (guard refuses delegates; owners pass).
7. Client (KMP): `models/federation/Delegation.kt` (+ optional `constraints`),
   `viewmodels/DelegationsViewModel.kt`, `api/CIRISApiClient.kt` (currently hardcodes scope),
   `ui/screens/DelegationsScreen.kt` OfferPane (Duration + Actions checkboxes + Goal field).

### Full

Resources allow/deny (glob matcher), Tasks allow-list with `max_invocations` metering,
action/resource deny-lists surfaced in UI, `renewable` UX, per-grant metering, optional
route→verb middleware refactor, and persisted counters (OQ-6). Client gains chip editors + an
Advanced task pane.

---

## 12. Open questions / risks

- **OQ-1 Deny-by-default vs preserve-legacy.** Absent `constraints`: full owner power (today)
  or read-only? Proposal: legacy `None` = unconstrained for one release with a deprecation log,
  then flip. **Needs owner directive.** (§8)
- **OQ-2 Edge `expires_at` liveness.** First non-`None` `expires_at` through
  `emit_signed_attestation`/`put_attestation`; confirm `reachable_under_scope` treats an
  expired edge as unreachable. Test `edge_hard_expiry` guards this. (§5.2)
- **OQ-3 Persist unknown-member admissibility.** Primary design adds a `constraints` member to
  the signed envelope; if a future persist admission rejects unknown members, use the sibling
  `delegation_constraints` attestation fallback. Verify against the running substrate before
  impl. (§5.3)
- **OQ-4 Verb granularity.** Coarse verbs can't say "config:write but only net.*" without the
  resource axis; MVP relies on Actions, Full adds Resources. Acceptable?
- **OQ-5 Bearer-TTL vs edge-expiry drift.** Duration enforced twice (in-memory TTL + edge
  `expires_at`); a restart drops the bearer but the edge persists — a renewable grant survives
  via re-claim, a non-renewable one dies at restart. Confirm this is desired. (§9)
- **OQ-6 max_invocations across restart.** Counters are in-memory; a restart resets them,
  weakening caps. Hard caps need CEG counters (expensive) — deferred to Full; MVP documents the
  weakness. (§9)
- **OQ-7 Goal enforceability.** Goal is advisory; an agent can act within its verbs/resources
  but outside the stated intent. Inherent to capability security; mitigations are audit + tight
  action/resource lists, not the goal string.
- **RISK Enforcement completeness.** A delegate silently retains full power on any owner-gated
  route that skips the guard. Mitigated by G4: the shared `require_owner_verb` takes a
  non-defaultable `CapabilityVerb`, so a new route cannot gate without choosing one. A grep test
  (assert no residual local `require_owner` bypasses the shared gate) is recommended.
