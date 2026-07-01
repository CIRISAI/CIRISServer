# FSD — Delegation Expansion (constrained device-grant delegation)

**Status:** design proposal (no code). **Author:** exploratory.
**Scope:** enrich the owner→agent "act-on-behalf" device grant
(`src/auth/device_grant.rs`) from a single coarse scope string into an owner-authored
**constraint envelope** along five axes (duration, resources, actions, goal, tasks)
plus symmetric deny-lists, while keeping the CEG-native "authority IS the graph"
model intact.

---

## 1. Current state (precise, with citations)

### 1.1 The grant is a single scope string + full owner authority

Today a delegation carries exactly one lever: a scope **string**, defaulted to a
constant:

- `const DEFAULT_SCOPE: &str = "owner:act-on-behalf";` — `src/auth/device_grant.rs:68`
- Handshake TTL `GRANT_TTL_SECS = 600` (`device_grant.rs:60`); minted-bearer TTL
  `DELEGATED_TTL_SECS = 3_600` (1h) — `device_grant.rs:63-65`.
- Graph-walk depth `DELEGATION_DEPTH = 4` — `device_grant.rs:71`.

The ephemeral handshake object stores just that scalar scope:

```
struct DeviceGrant { user_code, client_id, scope: String, expires_at, status }
```
— `src/auth/device_grant.rs:94-106`.

The request DTOs surface only an optional scope:

- `DeviceCodeRequest { client_id, scope: Option<String> }` — `device_grant.rs:209-214`.
- `DelegateRequest { mode, label, existing_key_id, scope: Option<Vec<String>> }`
  — `device_grant.rs:309-322`. Even though `scope` is a `Vec`, only the FIRST
  element is kept: `let scope = scope_vec.first()...` — `device_grant.rs:419-423`.

### 1.2 The durable authority is a signed `delegates_to` CEG attestation

On approve (`approve`, `device_grant.rs:747`) or one-shot owner mint (`delegate`,
`device_grant.rs:401`), the node resolves the owner's federation signer
(`resolve_owner_signer`, `device_grant.rs:132`) and emits a signed
`delegates_to(owner → actor, [scope])` attestation:

- envelope built by `ciris_persist::federation::delegates_to_envelope(delegate_key_id,
  scopes, sub_delegation)` — `device_grant.rs:535-539` / `792-796`. The persist
  helper's fixed shape is `{kind, dimension, delegate_key_id, scope, sub_delegation}`
  — `cirispersist .../src/federation/self_at_login.rs:148-160`.
- persisted via `crate::auth::ownership::emit_signed_attestation(...)` —
  `device_grant.rs:540-557` / `797-814`; the function stores the envelope **verbatim**
  in `attestation_envelope` and signs its canonicalization — `src/auth/ownership.rs:810`+.
  NOTE: it hardcodes `expires_at: None` on the `Attestation` (the edge itself never
  expires; only the in-memory bearer TTL bounds a session).

### 1.3 The bearer is a session credential; authority is re-checked on every request

`claim` (`device_grant.rs:603`) and the RFC-8628 `token` poll (`device_grant.rs:888`)
both, before minting, re-verify the edge is live:

```
engine.reachable_under_scope(&owner_key_id, &client_id, &scope, DELEGATION_DEPTH)
```
— `device_grant.rs:659-667` (claim), `device_grant.rs:949-957` (token).

Then they register an opaque `dgrant:<rand>` bearer:

```
register_delegated_grant(DelegatedGrant { owner_wa_id, owner_role, owner_key_id,
    client_id, scope, expires_at })
```
— `device_grant.rs:669-676` / `963-970`; struct at `src/auth/session.rs:187-204`.

On EVERY request, `resolve_bearer` (`src/auth/session.rs:285`) sees the `dgrant:`
prefix (`session.rs:294`), re-runs `reachable_under_scope` (`session.rs:305-327`,
depth const `DELEGATION_REACHABILITY_DEPTH = 4` at `session.rs:209`), and if live
returns a `SessionCaller` that wields the **owner's full role**:

```
SessionCaller { wa_id: owner_wa_id, name: client_id, role: owner_role,
    permissions: permissions_for(owner_role), actor: Some(client_id) }
```
— `session.rs:335-341`. So the delegate acts with the owner's `SystemAdmin` +
`FullAccess`, distinguished only by `actor: Some(..)` (`SessionCaller.actor`,
`session.rs:166`).

### 1.4 Where authorization is enforced today

Owner-gated endpoints each call a local `require_owner` that only checks
role+permission (NOT the constraints, which don't exist):

- `src/auth/device_grant.rs:699` (also rejects delegated self-amplification via
  `caller.actor.is_none()`, `device_grant.rs:716`).
- `src/config_api.rs:58` (+ `require_owner_bound` serve-only floor, `config_api.rs:91`;
  `set_config` calls both, `config_api.rs` `set_config`).
- `src/federation_admin.rs:80`, `src/claim_remote.rs:274`, `src/identity.rs:916`,
  `src/system_data.rs:44`, `src/accord.rs:373` (also `actor.is_none()`,
  `accord.rs:387`), `src/auth/portable_occurrence.rs:76`.

Pattern: `resolve_bearer` → check `role == SystemAdmin && permissions.contains(FullAccess)`.
A delegated caller passes every one of these gates identically to the owner —
**there is no per-action, per-resource, or duration constraint anywhere in the
request path.** The `actor` field is inspected in only two places
(`device_grant.rs:716`, `accord.rs:387`), both merely to forbid a delegate from
re-delegating/reactivating. This is the crux the expansion addresses.

### 1.5 Listing / revoking

`live_delegations` (`device_grant.rs:1000`) reads the graph via
`list_attestations_by(owner_fed_id)`, filters `DELEGATES_TO`, pulls the scope with
`edge_scope` (`device_grant.rs:163-173`), skips `infra:*` owner-bindings, and
confirms liveness. `GET /v1/auth/device/grants` (`device_grant.rs:1031`) and
`revoke` (`device_grant.rs:1067`, emits signed `withdraws`) are the CRUD surface.

### 1.6 Client surface (KMP)

- `DelegationsScreen.kt` OfferPane collects only `label`, `mode` (create/existing),
  `existingKeyId` — `DelegationsScreen.kt:337-496`, `onCreate` at line 260.
- `DelegationsViewModel.createDelegation(label, mode, existingKeyId)` —
  `DelegationsViewModel.kt:78`.
- `CIRISApiClient.createDelegation(...)` hardcodes `scope = listOf("owner:act-on-behalf")`
  — `CIRISApiClient.kt:1807-1815`.
- DTOs: `DelegationDto { clientId, scope, expiresAt? }`, `CreateDelegationResponse
  { claimUrl, pin, clientId, scope, expiresIn }` — `models/federation/Delegation.kt:12,39`.

---

## 2. Proposed data model — `DelegationConstraints`

The five axes plus deny-lists become one owner-authored struct that (a) travels in
the request body, (b) is embedded in the SIGNED `delegates_to` envelope (so it is
tamper-evident, replicable, and revocable like any CEG object — consistent with
"everything is a CEG object in persist"), and (c) is snapshotted onto the in-memory
`DelegatedGrant` for cheap per-request checks.

```rust
/// Owner-authored bounds on a single act-on-behalf delegation. Serialized into the
/// signed `delegates_to` envelope (tamper-evident) AND cached on `DelegatedGrant`.
/// EVERY field is optional; an all-`None` value == today's coarse grant (§4.4 back-compat).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationConstraints {
    // ── AXIS 1: DURATION ────────────────────────────────────────────────
    /// Requested bearer lifetime in seconds. Clamped to `max_ttl_secs` and to the
    /// server ceiling. Absent ⇒ DELEGATED_TTL_SECS (3600).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Hard ceiling the owner will tolerate; a renewal may not exceed it. Absent ⇒
    /// server default ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    /// Absolute wall-clock expiry (unix secs). Overrides TTL when sooner. The grant
    /// dies here regardless of renewals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_expiry_unix: Option<u64>,
    /// May the delegate re-mint a fresh bearer against the still-live edge without a
    /// new owner approval? Default false.
    #[serde(default)]
    pub renewable: bool,

    // ── AXIS 2: RESOURCES (allow + deny) ────────────────────────────────
    /// If non-empty, the delegate may touch ONLY these resources; empty ⇒ all
    /// (subject to deny). Grammar: `node:<key_id>`, `config:<key-or-prefix*>`,
    /// `ceg:<object_type>` (e.g. `ceg:consent:*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources_allow: Vec<String>,
    /// Always-forbidden resources (evaluated AFTER allow; deny wins).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources_deny: Vec<String>,

    // ── AXIS 3: ACTIONS (allow + deny) ──────────────────────────────────
    /// Capability verbs the delegate may perform. Verbs are coarse and map to route
    /// groups (§3.2): `read`, `config:write`, `announce`, `peering`, `claim-remote`,
    /// `delegate`, `wipe`, `accord`. Empty ⇒ `["read"]` (fail-safe: read-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions_allow: Vec<String>,
    /// Verbs that are ALWAYS forbidden (deny wins over allow). Seeds the never-list:
    /// `delegate`, `wipe`, `accord` are implicitly appended server-side (§3.4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions_deny: Vec<String>,

    // ── AXIS 4: GOAL ────────────────────────────────────────────────────
    /// Human-readable statement of intent this grant is scoped to. Advisory to the
    /// enforcer (logged on every action) but load-bearing for the human approver and
    /// for audit. Length-capped (e.g. 512 chars).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,

    // ── AXIS 5: TASKS ───────────────────────────────────────────────────
    /// Explicit allow-list of concrete named tasks the delegate is authorized to
    /// run. Empty ⇒ not task-gated (fall back to action/resource checks). Each task
    /// is a stable id the enforcer recognizes (§3.3), optionally with a bound count.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks_allow: Vec<TaskGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskGrant {
    /// Stable task id, e.g. `config.set:net.bootstrap_peers`, `federation.announce`.
    pub task: String,
    /// Optional cap on invocations (owner: "you may do this at most N times").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
}
```

### 2.1 Serialization & storage — CEG-native

The constraints ride INSIDE the signed `delegates_to` envelope so they inherit the
attestation's tamper-evidence, replication, and `withdraws`-based revocation. Rather
than hand-extending the persist helper's fixed shape
(`self_at_login.rs:148-160`), we build the envelope locally and add a `constraints`
member (the envelope passed to `emit_signed_attestation` is arbitrary
`serde_json::Value` and stored verbatim — `ownership.rs:810`+):

```jsonc
{
  "kind": "delegates_to",
  "dimension": "<DIMENSION_DELEGATES_TO>",
  "delegate_key_id": "<actor key_id>",
  "scope": ["owner:act-on-behalf"],      // UNCHANGED — reachable_under_scope key
  "sub_delegation": false,
  "constraints": { /* DelegationConstraints, camel/snake per serde */ }
}
```

Rationale for keeping `scope` as-is: `reachable_under_scope`
(`session.rs:305`, `device_grant.rs:661`) and `live_delegations`/`edge_scope`
(`device_grant.rs:163,1011`) all key on the scope string. Changing it would ripple
through liveness and listing. The constraints are a NEW, additive member the enforcer
reads back from the same signed envelope. **No new persist primitive** — it is the
existing `Attestation.attestation_envelope`, i.e. a CEG object, exactly per the
project principle.

Duration is the one axis that also needs the attestation's own `expires_at` (today
hardcoded `None`, `ownership.rs`): plumb `hard_expiry_unix` into
`emit_signed_attestation` so the EDGE carries the wall-clock ceiling and
`reachable_under_scope` naturally denies a stale delegation without relying on the
volatile in-memory TTL.

### 2.2 In-memory caches gain the constraints

- `DeviceGrant` (`device_grant.rs:94`) gains `constraints: DelegationConstraints`.
- `DelegatedGrant` (`session.rs:187`) gains `constraints: DelegationConstraints` and
  a per-grant `invocation_counts: Arc<Mutex<HashMap<String,u32>>>` for `max_invocations`.
- `SessionCaller` (`session.rs:151`) gains
  `delegation: Option<DelegationConstraints>` (populated ONLY on the delegated path,
  `session.rs:335`; `None` for a real owner session so owner power is unaffected).

---

## 3. Enforcement — exactly where each constraint is checked

Two enforcement points, because constraints split into "bind at mint" vs
"check per request".

### 3.1 Duration — at mint, in `claim`/`token`, and in `resolve_bearer`

- At mint (`device_grant.rs:669` / `963`): compute
  `ttl = min(constraints.ttl_secs.unwrap_or(DELEGATED_TTL_SECS), constraints.max_ttl_secs.unwrap_or(CEILING), CEILING)`
  and `expires_at = min(now + ttl, constraints.hard_expiry_unix.unwrap_or(u64::MAX))`.
- The signed edge carries `expires_at = hard_expiry_unix` (§2.1), so `reachable_under_scope`
  in `resolve_bearer` (`session.rs:305`) fails a lapsed delegation graph-side too.
- Renewal (`renewable`): only if true may a re-`claim`/`token` mint a fresh bearer;
  otherwise second redemption returns `410 expired_token` (the handshake is already
  single-use — `device_grant.rs:640,929` — so renewal specifically means "re-run the
  poll against the live edge").
- **Failure:** `410 Gone {"error":"expired_token"}` (existing shape) or
  `403 {"error":"delegation_expired"}` on a bearer past `hard_expiry`.

### 3.2 Actions — a new gate helper called from every owner-gated route

Introduce `authorize_delegated(caller: &SessionCaller, verb: &str, resource: &Resource)
-> Result<(), Response>` in a new `src/auth/delegation_guard.rs`:

- If `caller.delegation.is_none()` (a real owner) ⇒ `Ok(())` (unchanged behavior).
- Else evaluate against `caller.delegation`:
  1. `verb` must be in `actions_allow` (default `["read"]`) AND not in the effective
     `actions_deny` (owner deny-list ∪ server never-list).
  2. resource must satisfy §3.3.
  3. task/goal per §3.3.
- Each existing `require_owner` variant (the eight sites in §1.4) calls
  `authorize_delegated` with the verb+resource for that route AFTER its role check.
  E.g. `config_api::set_config` → `verb = "config:write"`, `resource =
  Resource::Config(req.key)`; `federation_admin` peering → `verb = "peering"`;
  `claim_remote` → `verb = "claim-remote"`. Read-only GETs pass `verb = "read"`.
- **Failure:** `403 {"error":"delegation_forbidden","denied_by":"action","verb":"config:write",
  "goal":"<grant goal>"}` — structured so the client can explain WHICH constraint blocked it.

Alternative (considered, not chosen for MVP): an axum middleware layer keyed on
`method`+`path`→verb. Cleaner but needs a route→verb table maintained separately from
the handlers; per-handler calls keep the verb next to the resource it names. Revisit
for Full phase.

### 3.3 Resources / Tasks / Goal

- Resource matching: `resources_allow` empty ⇒ allow-all; else the request's
  `Resource` must match at least one pattern (glob on `config:` prefixes, exact on
  `node:`/`ceg:`), and match NO `resources_deny` pattern (deny wins). Enforced inside
  `authorize_delegated` (§3.2), so it is one code path.
- Tasks: if `tasks_allow` non-empty, the route maps to a task id; that id must be
  present, and `max_invocations` (if set) not yet exhausted for THIS bearer
  (`DelegatedGrant.invocation_counts`, incremented on success). Task-gating is stricter
  than action-gating and, when present, is authoritative; action/resource still apply.
- Goal: never blocks; it is logged on every delegated action (extend the existing
  `tracing::info!(actor=.., on_behalf_of=..)` at `session.rs:330`) and surfaced in
  listing so the owner/audit sees intent. It is the human contract.

### 3.4 Server-imposed never-list (the hard floor)

Regardless of `actions_allow`, a delegate is NEVER permitted to: `delegate` (already
blocked by `actor.is_none()`, `device_grant.rs:716`), `accord` reactivate (already
blocked, `accord.rs:387`), or `wipe`/`reset-account`/`wipe-signing-key`
(`src/system_data.rs`). `authorize_delegated` appends these to `actions_deny`
unconditionally so the floor holds even if an owner fat-fingers an allow-list.

---

## 4. Wire / API changes

### 4.1 `POST /v1/auth/device/code` (client-initiated)

Request gains an optional `constraints` object:
```jsonc
{ "client_id": "...", "scope": "owner:act-on-behalf",
  "constraints": { "ttl_secs": 900, "actions_allow": ["read","config:write"],
                   "resources_allow": ["config:net.*"], "goal": "keep peers fresh" } }
```
`DeviceCodeRequest` (`device_grant.rs:209`) gains `constraints: Option<DelegationConstraints>`.
Response unchanged (the owner sees/edits constraints at approve time; see §5).

### 4.2 `POST /v1/auth/device/delegate` (owner one-shot)

`DelegateRequest` (`device_grant.rs:309`) gains `constraints: Option<DelegationConstraints>`.
Because the owner authors this call directly, the constraints they send ARE the
consented bounds (no separate approve step). Response
(`CreateDelegationResponse`) gains an echoed `constraints` object so the client can
show the owner exactly what was minted.

### 4.3 `POST /v1/auth/device/approve`

To let the owner TIGHTEN a client-requested grant at approval, `DecisionRequest`
(`device_grant.rs:733`) gains `constraints: Option<DelegationConstraints>` that,
when present, **replaces** (never widens beyond) what the client asked for. The
owner-supplied value is the one written into the signed edge.

### 4.4 Backward compatibility

- `constraints` absent everywhere ⇒ `DelegationConstraints::default()` ⇒
  all-`None`/empty ⇒ enforcement short-circuits to today's behavior EXCEPT one
  deliberate hardening choice: `actions_allow` empty defaults to `["read"]`
  (read-only). To preserve the LITERAL current coarse grant (full owner power) for
  legacy callers, treat `constraints == None` as the sentinel "unconstrained
  (legacy)" and `constraints == Some(default)` as "explicitly read-only". This keeps
  old clients working while new clients opt into least-privilege. (Owner directive
  needed on whether to flip the default to deny-by-default; see §7.)
- `GET /v1/auth/device/grants` / `DelegationDto` gain optional `constraints`,
  `goal`, `expiresAt` (already nullable). Old clients ignore unknown fields
  (kotlinx `ignoreUnknownKeys`, already used per `CIRISApiClient.kt` json config).
- `dgrant:` token format unchanged; only the registry entry is richer.

---

## 5. Client UX (KMP)

`DelegationsScreen.OfferPane` (`DelegationsScreen.kt:337`) gains a collapsible
"Constraints (optional)" section BELOW the label/mode controls, mapping 1:1 to the
five axes + deny-lists:

1. **Duration** — a duration picker (`ttl_secs`) + "Never valid past" date
   (`hard_expiry_unix`) + a "renewable" switch.
2. **Resources** — a chip editor for allow patterns (`config:net.*`, `node:<id>`),
   with a separate "Never touch" deny chip row. A "Choose config keys" helper can
   reuse the Config screen's key list.
3. **Actions** — a checkbox group of coarse verbs (Read-only / Change config /
   Announce / Peering / Claim remote), rendered from a fixed list; owner-only floor
   verbs (delegate/wipe/accord) are shown greyed as "never allowed".
4. **Goal** — a single-line text field ("What is this delegation for?"), required
   when any write action is enabled (nudges least-privilege + auditability).
5. **Tasks** — an optional explicit task allow-list (advanced): add task id + optional
   max-count. Hidden behind an "Advanced" expander for MVP.

`DelegationsViewModel.createDelegation` (`DelegationsViewModel.kt:78`) and
`CIRISApiClient.createDelegation` (`CIRISApiClient.kt:1807`, currently hardcoding
scope) gain a `constraints: DelegationConstraints?` parameter serialized into the
request body. The created-offer card (`DelegationsScreen.kt:439`) and the Manage
list rows (`DelegationsScreen.kt:628`) render the `goal` + a one-line constraint
summary ("read + config:net.* · 15 min") so the owner can audit at a glance.

New KMP model: `DelegationConstraints` in `models/federation/Delegation.kt` mirroring
the Rust struct; `DelegationDto`/`CreateDelegationResponse` gain the optional field.

---

## 6. Phasing

**MVP (smallest useful least-privilege):**
- Axes: **Duration** (`ttl_secs`, `max_ttl_secs`, `hard_expiry_unix`) + **Actions**
  allow-list (coarse verbs) + **Goal** string (logged, displayed).
- Server never-list (§3.4) — free, mostly already there.
- Enforcement: `authorize_delegated` wired into `config_api`, `federation_admin`,
  `claim_remote`, `system_data`, `identity` require_owner sites; duration plumbed
  into the edge `expires_at` + bearer TTL.
- Wire: `constraints` on `/delegate` (+ echo) and `/approve`; client OfferPane gets
  Duration + Actions + Goal.
- This alone converts "full owner power for 1h" into "read-only for 15 min unless the
  owner ticks specific write verbs" — the biggest risk reduction per line of code.

**Full:**
- **Resources** allow/deny (glob grammar + matcher), **Tasks** allow-list with
  `max_invocations`, **deny-lists** for actions/resources, `renewable` semantics,
  the route→verb middleware refactor (§3.2 alternative), and per-grant invocation
  metering. Client gains the chip editors + Advanced task pane.

---

## 7. Open questions / risks

1. **Deny-by-default vs preserve-legacy (§4.4).** Should an ABSENT `constraints`
   mean "full owner power (today)" or "read-only"? Least-privilege argues deny-by-
   default, but that silently breaks any existing agent relying on the coarse grant.
   Proposal: legacy `None` = unconstrained for one release with a deprecation log,
   then flip. **Needs owner directive.**
2. **Constraint tamper-evidence vs persist admissibility.** The plan embeds
   `constraints` as an extra member of the `delegates_to` envelope. persist v11.5.0
   is strict about `delegates_to` shape (the USER-role refusal noted in memory); must
   confirm `put_attestation` canonicalizes+stores unknown envelope members without
   rejecting them, else constraints need a sibling attestation type
   (`delegation_constraints`) referencing the edge id. Verify against
   `ceg_produce_canonicalize` (`ownership.rs`) + persist admission rules before impl.
3. **Enforcement completeness.** `authorize_delegated` must be called from EVERY
   owner-gated route or a delegate silently retains full power on the missed one. A
   compile-time seam (e.g. requiring a `verb` argument to a shared `require_owner`)
   is safer than remembering to add a call. Consider making `require_owner` itself
   take the verb+resource so the check cannot be forgotten.
4. **Route→verb granularity.** Coarse verbs (read/config:write/announce/…) are easy
   but blunt; a single "config:write" verb can't say "only net.* keys" without the
   resource axis. MVP relies on Actions; Resources (Full) refines. Acceptable?
5. **Bearer-TTL vs edge-expiry drift.** Duration is enforced twice (in-memory TTL +
   edge `expires_at`); a node restart drops the in-memory grant (memory notes this)
   but the edge persists — a renewable grant survives restart via re-claim, a
   non-renewable one effectively dies at restart. Confirm this is the desired
   semantics or persist the bearer.
6. **max_invocations across restart.** Invocation counts are in-memory; a restart
   resets them, weakening the cap. If hard caps matter, they must be CEG counters
   (expensive) — defer to Full, document the weakness.
7. **Goal enforceability.** Goal is advisory only; an agent can act within its
   verbs/resources but outside the stated intent. This is inherent to capability
   security; mitigations are audit + tight action/resource lists, not the goal string.

---

## 8. Touch-list (files an implementation would change)

- `src/auth/device_grant.rs` — DTOs (`209,309,733`), `DeviceGrant` (`94`), mint
  sites (`669,963`), envelope build (`535,792`), listing (`1000`).
- `src/auth/session.rs` — `DelegatedGrant` (`187`), `SessionCaller` (`151`),
  `resolve_bearer` delegated branch (`294-341`).
- `src/auth/ownership.rs` — `emit_signed_attestation` (`810`) to accept `expires_at`.
- **NEW** `src/auth/delegation_guard.rs` — `DelegationConstraints`, `authorize_delegated`.
- `src/config_api.rs` (`58`), `src/federation_admin.rs` (`80`), `src/claim_remote.rs`
  (`274`), `src/identity.rs` (`916`), `src/system_data.rs` (`44`), `src/accord.rs`
  (`373`), `src/auth/portable_occurrence.rs` (`76`) — call `authorize_delegated`.
- Client: `models/federation/Delegation.kt`, `viewmodels/DelegationsViewModel.kt`,
  `api/CIRISApiClient.kt:1807`, `ui/screens/DelegationsScreen.kt:337`.
</content>
</invoke>
