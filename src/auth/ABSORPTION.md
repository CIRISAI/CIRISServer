# Auth Absorption Map — CIRISServer#9

**The no-conflicts artifact.** Every CIRISAgent auth route/capability mapped to the
substrate call(s) it rides and the fabric Rust home that re-expresses it. The agent's
Python auth *already* rides the persist substrate (the `wa_cert` table is the
**eleventh and final** substrate absorption — CIRISPersist#59/#11 — that ended the
agent's direct libsqlite access to `ciris_engine.db`). So this is a **Python → Rust
port over the same substrate**, not a redesign: the agent's `wa_cert` table *is* the
substrate's `WaCertService`.

## The key finding (why no conflicts)

The agent's entire user/WA/OAuth/api-key/service-token surface lives in **one persist
table**, `wa_cert` (24 cols, mirrors CIRISAgent v2.8.13 verbatim), reachable in Rust as
`WaCertService` — plus a sibling `revoked_service_tokens` table as
`ServiceTokenRevocationService`. The agent's "auth_service" `_users` / `_oauth_users` /
`_api_keys` dicts are an **in-memory cache over `wa_cert`** (loaded via `list_was()`).
The fabric becomes the authority by owning the same `wa_cert` rows directly. When the
agent adopts the wheel it **drops its own auth_service storage** and delegates to the
fabric's routes — no schema fork, because both sides were always the same table.

Access pattern (the absorption recipe):
`engine.sqlite_backend()? .conn_handle()` → `Arc<Mutex<Connection>>` →
`SqliteWaCertBackend::new(conn)` (impls `WaCertService`) /
`SqliteServiceTokenRevocationBackend::new(conn)` (impls `ServiceTokenRevocationService`).
This is the same `conn_handle()` sibling-module pattern persist documents for cohabiting
sub-services. Engine itself exposes no wa_cert wrapper — you reach it via the backend.

## Substrate calls used (file:line in the checked-out source)

cirispersist tag v8.4.0 = `~/.cargo/git/checkouts/cirispersist-*/01ae6d1/`:

- `wa_cert/service.rs:31-88` — `WaCertService` 7 methods: `upsert_wa_cert`, `get_wa_cert`,
  `get_by_kid`, `get_by_oauth(provider, external_id)`, `list_by_role(role, limit)`,
  `set_active(wa_id, active)`, `update_last_login(wa_id, t)`.
- `wa_cert/types.rs:108-180` — `WaCert` (24 cols incl. `password_hash`, `api_key_hash`,
  `oauth_provider`, `oauth_external_id`, `oauth_links`, `scopes`, `custom_permissions`,
  `token_type`, `auto_minted`, `parent_wa_id`, `active`, `last_login`),
  `WaRole {Root,Authority,Observer}` (`:26`), `TokenType {Standard,Session,ApiKey,Oauth,Service}` (`:69`).
- `wa_cert/sqlite.rs:47-55` — `SqliteWaCertBackend::new(Arc<Mutex<Connection>>)`.
- `store/sqlite.rs:117` — `SqliteBackend::conn_handle() -> Arc<Mutex<Connection>>`.
- `service_token_revocation/service.rs` — `ServiceTokenRevocationService`:
  `record_revocation`, `list_revocations`, `check_revocation(token_hash)`.
- `service_token_revocation/types.rs:16` — `RevokedServiceToken {token_hash, revoked_at, revoked_by, reason}`.
- `service_token_revocation/sqlite.rs:36` — `SqliteServiceTokenRevocationBackend::new(conn)`.
- `engine.rs` — `Engine::self_at_login(SelfAtLoginInput) -> SelfAtLoginOutcome` (login ceremony);
  `Engine::sign_hybrid(&[u8]) -> ciris_crypto::HybridSignature` (`:847`);
  `Engine::attestation_promote(id) -> bool` (`:870`, self-contained canonicalize→hybrid-sign→promote);
  `Engine::evict_actor(attesting_key_id, now) -> EvictActorReport` (`:1322`, GDPR Art.17 erasure —
  deletes the actor's `federation_blobs` AND emits §10.1.2 `withdraws`, fail-honest);
  `Engine::sqlite_backend() -> Option<&Arc<SqliteBackend>>`.

  **CORRECTION (verified against the built v8.4.0 checkout `7b40aae`):** the mission's
  `Engine::evict_fountain_content_hard_delete(content_id, corpus_kind)` is **NOT present** in
  persist v8.4.0. The shipped erasure primitive is `Engine::evict_actor` (CIRISPersist#125),
  which is in fact stronger — it bundles the `withdraws` emission with the hard delete, which a
  per-content call would have left to the caller. `erasure.rs` uses `evict_actor`.

  **Build note:** `wa_cert` / `service_token_revocation` are behind persist cargo features
  `cirislens_wa_cert` + `cirislens_service_token_revocation` — both now enabled in `Cargo.toml`.
- `federation/mod.rs:235` — `FederationDirectory::attestation_upsert_local(LocalAttestationInput) -> String`;
  `:225` `put_attestation`; `:804` `list_identity_occurrences_active`.
- `federation/types.rs:443` — `LocalAttestationInput {attesting_key_id, attested_key_id?,
  attestation_type, weight?, expires_at?, attestation_envelope (MUST carry "dimension"),
  subject_key_ids, cohort_scope (local MUST = "self")}`.
- `verify/canonical.rs:216` — `ceg_produce_canonicalize(&Value) -> Vec<u8>` (produce-side JCS).
- `verify/hybrid.rs` — `verify_hybrid_via_directory(...)`, `HybridPolicy {Strict, SoftFreshness, Ed25519Fallback}`.

## The map

| Agent route / capability | Substrate call(s) it rides | Fabric Rust home | Status | Conflict |
|---|---|---|---|---|
| `POST /auth/login` (user+pass) | `wa_cert get_by_kid`/scan + verify `password_hash` + mint session | `session.rs` (`/v1/auth/login`) | **ported** | none — was `_users` cache over `wa_cert`; now direct |
| `POST /auth/logout` | revoke session / `set_active` | `session.rs` (`/v1/auth/logout`) | **ported** | none |
| `GET /auth/me` | `get_wa_cert` + role→perms | `session.rs` (`/v1/auth/me`) + `roles.rs` | **ported** | none |
| `POST /auth/refresh` | re-issue session token | `session.rs` (`/v1/auth/refresh`) | **ported** | none — fabric is single token issuer |
| `GET /auth/owner-hint` | scan `wa_cert` for earliest SYSTEM_ADMIN, mask email | `session.rs` (`/v1/auth/owner-hint`) | **ported** | none |
| `GET /auth/oauth/providers` | file I/O (`oauth.json`) | `oauth.rs` (`/v1/auth/oauth/providers`) | **ported** | none — providers config store moved to fabric path |
| `POST /auth/oauth/providers` | file I/O write (0600) | `oauth.rs` | **ported** | none |
| `GET /auth/oauth/{provider}/login` | CSRF state (in-mem TTL) + redirect-uri validate + provider authz URL | `oauth.rs` (`/v1/auth/oauth/{p}/login`) | **ported** | none |
| `GET /auth/oauth/{provider}/callback` | code→token exchange, userinfo, `wa_cert get_by_oauth`+`upsert_wa_cert` (create_oauth_user), mint session, self-at-login bind | `oauth.rs` callback → `self_login.rs` | **ported** (real provider HTTP in `HttpProviderClient`: google/github/discord token→userinfo) | none |
| `POST /auth/native/google` | google tokeninfo verify, `upsert_wa_cert`, mint session | `oauth.rs` (`/v1/auth/native/google`) | **ported** (`HttpProviderClient::verify_google_native`: tokeninfo + aud/iss/exp/sub) | none |
| `POST /auth/native/apple` | Apple JWKS RS256 verify, `upsert_wa_cert`, mint session | `oauth.rs` (`/v1/auth/native/apple`) | **ported** (`HttpProviderClient::verify_apple_native`: JWKS RS256 + aud/iss/exp/sub via jsonwebtoken) | none |
| `POST /api-keys` | `upsert_wa_cert` (TokenType::ApiKey, `api_key_hash`) | `api_keys.rs` (`/v1/auth/api-keys`) | **ported** | none |
| `GET /api-keys` | `list_by_role` / scan filter TokenType::ApiKey | `api_keys.rs` | **ported** | none |
| `DELETE /api-keys/{id}` | `set_active(false)` (revoke = mark inactive) | `api_keys.rs` | **ported** | none — matches agent `revoke_api_key` semantics |
| `POST /service-token/revoke` | `ServiceTokenRevocationService::record_revocation` | `api_keys.rs` (`/v1/auth/service-token/revoke`) | **ported** | none — exact persist absorption (CIRISPersist#64) |
| `POST /auth/attestation` | `attestation_upsert_local` (local) → `attestation_promote` (federation) | `attestation.rs` (`/v1/auth/attestation`) | **ported** | none |
| `create_oauth_user` (svc) | `get_by_oauth` + `upsert_wa_cert` (TokenType::Oauth, oauth_links) | `oauth.rs::create_oauth_user` | **ported** | none |
| `verify_user_password` (svc) | `get_wa_cert` + hash compare | `session.rs::verify_password` | **ported** (BYTE-COMPAT PBKDF2-HMAC-SHA256(100k); verified against an agent-produced hash vector) | none |
| `create_user` (svc) | `upsert_wa_cert` (+ password_hash) | `session.rs::create_user` helper | **ported** | none |
| `revoke_api_key` (svc) | `set_active(false)` | `api_keys.rs` | **ported** | none |
| `revoke_service_token` (svc) | `record_revocation` + audit | `api_keys.rs` | **ported** | none |
| `verify_root_signature` (svc) | Ed25519 verify vs `root_pub.json` | `roles.rs::verify_root_signature` | **ported** (Ed25519 over `MINT_WA:…` w/ 60-min ISO window + no-ts fallback; verified against agent ed25519 vectors; `RootPubKey::load`) | none |
| `mint_wise_authority` (svc) | `upsert_wa_cert` role=Root + parent | `roles.rs` (WaRole helpers) | **scaffolded** | none |
| `oauth_security` (state/PKCE/validate) | in-mem state TTL, picture-URL allowlist | `oauth.rs::security` | **ported** | none |
| `dependencies/auth.py` (enforce) | validate api_key / service-token / password / bearer | `verify.rs` (hybrid) + `session.rs` token-check | **ported** (hybrid-sig contract; bearer→session bridge `session.rs::resolve_bearer`, wired into `/v1/auth/me`) | none |
| `UserRole` hierarchy + `Permission` + `ROLE_PERMISSIONS` | — (pure model) | `roles.rs` (`UserRole`, `Permission`, `permissions_for`) | **ported** | none — client-compat preserved |
| `setup/connect-node` | Portal HTTP device-authorize + attestation | `device_auth.rs` | **ported** (Portal `POST /api/device/authorize` over reqwest + SSRF allowlist + session-file persist) | none |
| `setup/connect-node/status` | Portal device-token + self-custody key register | `device_auth.rs` | **ported** (Portal `POST /api/device/token`: 428/403/200 + session clear; self-custody key POST is a keyring-signer follow-on, see note 4) | none |
| `setup/reset-device-auth` | clear session file | `device_auth.rs` | **ported** | none |
| `setup/download-package` | download+checksum+unzip | `device_auth.rs` | **scaffolded** (out of auth core; left as setup-tier TODO — not an auth gap) | none |
| Consent (CEG-native) | `attestation_upsert_local`+`attestation_promote` OR `put_attestation` (federation) | `consent.rs` | **ported** | none |
| Erasure (GDPR Art.17, §19.7) | `Engine::evict_actor` (deletes blobs + emits §10.1.2 withdraws) | `erasure.rs` | **ported** | none — see correction note (the cited `evict_fountain_content_hard_delete` is absent in v8.4.0) |
| `/v1/self/login` (login ceremony) | `Engine::self_at_login` | `self_login.rs` (pre-existing) | **ported** | none |

## Coverage summary

- **Total auth capabilities mapped:** 33
- **Ported (compiling Rust over the substrate):** 31
- **Scaffolded (clear TODO, substrate call identified):** 2
  (`mint_wise_authority` helper — the `upsert_wa_cert` write is trivial once a
  mint route is added; `setup/download-package` — a setup-tier download, not an
  auth gap.)
- **N/A:** 0
- **Conflicts found:** 0

## Notes / honest gaps

1. **Password hashing — CLOSED (byte-compat).** persist stores `password_hash` opaque
   (caller-side, confirmed NOT FOUND in substrate). The agent's `_hash_password` /
   `_verify_password` use **PBKDF2-HMAC-SHA256, length=32, iterations=100000, salt=32
   random bytes**, stored as `base64(salt || key)` (STANDARD base64, not url-safe).
   `session.rs::{hash_password,verify_password}` reproduce this exactly (pbkdf2+hmac+sha2,
   constant-time compare via `subtle`). Verified by
   `verify_password_matches_agent_pbkdf2_vector` against a hash produced by the agent's
   own `cryptography.PBKDF2HMAC`. (Api-keys use bcrypt(rounds=12) — already handled in
   `api_keys.rs`; the password path was the byte-compat gap and is now closed.)
2. **Native google/apple token verification — CLOSED.** `HttpProviderClient::verify_native`
   over reqwest+rustls. Google: GET `oauth2.googleapis.com/tokeninfo`, validate aud (when
   audiences configured; skipped in on-device mode like the agent), iss ∈
   {accounts.google.com, https://accounts.google.com}, exp, require sub. Apple: fetch
   `appleid.apple.com/auth/keys` JWKS, select RS256 key by `kid`, RS256-verify with
   `jsonwebtoken` (aud ∈ configured, iss = appleid.apple.com, require sub/aud/iss/exp).
   Audiences read from provider config matching the agent's
   `_get_allowed_{,apple_}audiences_from_config`.
3. **OAuth code→token exchange — CLOSED.** `HttpProviderClient::exchange_code` does the
   real google/github/discord token→userinfo flow (endpoints + redirect_uri +
   private-email fallback for github) matching `_handle_*_oauth`; post-exchange
   `create_oauth_user` → `upsert_wa_cert` was already ported.
4. **Device-auth / Portal — CLOSED.** `device_auth.rs` does the Portal device-grant over
   reqwest: `POST /api/device/authorize` (connect-node), `POST /api/device/token` poll
   (428 pending / 403 denied / 200 complete), reset clears the session file. SSRF
   allowlist + URL reconstruction (scheme+host only) ported verbatim from
   `_validate_portal_url`; redirect-following disabled. **Remaining:** the FSD-002
   self-custody public-key registration POST (`/api/device/register-key`) is a follow-on
   once the keyring federation signer is threaded into this route — the device-grant
   itself (the gap) is complete; `download-package` is setup-tier, not auth.
5. **`verify_root_signature` — CLOSED.** `roles.rs::verify_root_signature` Ed25519-verifies
   `MINT_WA:{user_id}:{wa_role}:{timestamp}` over the agent's 60-minute whole-minute ISO
   window (reproducing CPython `datetime.isoformat()` exactly, incl. the micros-omitted
   case) plus the no-timestamp fallback, accepting both standard and url-safe base64
   signatures. `RootPubKey::load` reads a `root_pub.json`-shaped file (the agent's `pubkey`
   base64url field). Verified against agent-produced ed25519 vectors (both paths).
6. **Bearer→session bridge — CLOSED.** `session.rs::resolve_bearer` resolves a fabric
   session token (`sess:<wa_id>:<rand>`) to an active `wa_cert` row (revoked/inactive ⇒
   fail-closed), returning the role + permission set; non-session tokens return
   `Ok(None)` so other auth modes (api-key/service/password) still dispatch as the
   agent's chain did. Wired into `/v1/auth/me`.
7. **Sessions are not a persist primitive** (confirmed NOT FOUND). persist offers
   `TokenType::Session` rows + `set_active`/`last_login` but no per-session revocation API.
   The fabric session issuer is therefore fabric-owned logic over `wa_cert` rows
   (`token_type = session`, revoke = `set_active(false)`), exactly as the agent did it.
