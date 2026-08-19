//! The auth store accessor — the absorption seam (CIRISServer#9).
//!
//! The agent's whole user/WA/OAuth/api-key surface lived in ONE persist table,
//! `wa_cert` (the eleventh + final substrate absorption, CIRISPersist#59/#11,
//! which ended the agent's direct libsqlite access to `ciris_engine.db`). The
//! agent's `auth_service` `_users` / `_oauth_users` / `_api_keys` dicts were an
//! **in-memory cache over `wa_cert`** loaded via `list_was()`. The fabric becomes
//! the single auth authority by owning those same `wa_cert` rows DIRECTLY.
//!
//! This module is the one place that reaches the substrate sub-services off the
//! shared [`Engine`], and it dispatches on the backend the Engine actually has:
//!
//! ```text
//! sqlite:   engine.sqlite_backend()?.conn_handle() -> SqliteWaCertBackend
//! postgres: engine.postgres_backend()?            -> PostgresBackend
//! ```
//!
//! # PostgreSQL agents could not start a node (CIRISServer#397)
//!
//! Both accessors used to reach for `sqlite_backend()` UNCONDITIONALLY, so the
//! auth substrate — WA certs and service-token revocation — was SQLite-only while
//! the rest of the Engine is backend-agnostic. On a postgres node every auth call
//! returned `NoSqliteBackend` and the process could not compose: no federation, no
//! `/v1/self`, no accord, no auth. PostgreSQL is a supported deployment, so that
//! is a total outage for it, not a degraded mode.
//!
//! Nothing upstream was missing. persist has shipped `impl WaCertService for
//! PostgresBackend` and `impl ServiceTokenRevocationService for PostgresBackend`
//! all along, and `Engine::postgres_backend()` to reach them — this module simply
//! never asked. The absorption note below describes the SQLite path because that
//! is the backend the absorption was done against; it was never a statement that
//! auth is SQLite-only.
//!
//! # Why an enum and not `dyn`
//!
//! `WaCertService` uses `-> impl Future`, so it is not dyn-compatible.
//! [`AuthCertBackend`] is a two-arm enum that implements the trait by delegating,
//! which keeps every call site unchanged and makes a THIRD backend a compile
//! error here rather than a runtime `NoSqliteBackend` in production.
//!
//! # The cutover did not cause this
//!
//! The constraint predates the agent's auth cutover. What changed is that auth now
//! genuinely depends on the node — before, postgres agents ran their own auth
//! implementation that never consulted it, which is exactly the duplication
//! CIRISAgent#1028 set out to remove. Deleting that Python exposed a real gap
//! rather than creating one.
//!
//! When the agent adopts the wheel it DROPS its own `auth_service` storage and
//! delegates to the fabric routes — no schema fork, because both sides were
//! always the same table.

use ciris_persist::prelude::Engine;
use ciris_persist::service_token_revocation::sqlite::SqliteServiceTokenRevocationBackend;
use ciris_persist::wa_cert::sqlite::SqliteWaCertBackend;
use ciris_persist::wa_cert::{Error as WaCertBackendError, WaCert, WaCertService, WaRole};
// Only the postgres arms hold an `Arc<PostgresBackend>`, and those exist on
// Linux alone — so the import is unused elsewhere and `-D warnings` fails.
#[cfg(target_os = "linux")]
use std::sync::Arc;

/// Why an auth-store access failed.
#[derive(Debug)]
pub enum StoreError {
    /// The Engine has NO backend this auth store can use — neither SQLite nor
    /// PostgreSQL (CIRISServer#397).
    ///
    /// Named for the limitation rather than the storage detail. The old
    /// `NoSqliteBackend` / "engine is not SQLite-backed" told an operator on a
    /// perfectly healthy postgres node that the wrong database was missing, which
    /// points debugging at the storage layer instead of at auth support.
    NoAuthBackend,
    /// A substrate `wa_cert` call failed.
    WaCert(ciris_persist::wa_cert::Error),
    /// A substrate `revoked_service_tokens` call failed.
    Revocation(ciris_persist::service_token_revocation::Error),
    /// **More than one LIVE cert claims one provider identity** (#397). Not a
    /// lookup failure — a broken invariant. Answering it by picking a cert is
    /// how a human gets signed in with the wrong rights and no error.
    AmbiguousOauthIdentity { provider: String, holders: usize },
    /// **More than one active cert answers to one human NAME** (CIRISAgent#1029).
    ///
    /// Same defect as [`Self::AmbiguousOauthIdentity`], on the identifier humans
    /// actually type. The name scan used to resolve this by PICKING — "the
    /// most-recent active match wins" — which meant a node holding two certs
    /// named `jeff` silently decided which `jeff` you are.
    ///
    /// The failure it produced is worse than a refusal and reads as nothing like
    /// one: login resolves cert A, the password belongs to cert B, and the node
    /// reports `password mismatch` forever while the credential is perfectly
    /// correct. CIRISAgent hit exactly this — their setup writes
    /// `system_admin_password` onto the admin WA and `admin_password` onto the
    /// user WA, and when both carry the same `name` the two sides resolve
    /// different certs.
    ///
    /// Picking is never the right answer here. On the login path, ambiguity means
    /// signing in as the WRONG PERSON — the same reasoning that keeps name
    /// matching exact rather than accepting a first name.
    AmbiguousLoginName { name: String, holders: Vec<String> },
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoAuthBackend => write!(
                f,
                "this node's engine has no auth-capable backend (expected SQLite or PostgreSQL) \
                 — WA certs and service-token revocation cannot be read or written, so login, \
                 /v1/self, accord and federation are all unavailable on this node"
            ),
            StoreError::WaCert(e) => write!(f, "wa_cert: {e}"),
            StoreError::Revocation(e) => write!(f, "service-token revocation: {e}"),
            StoreError::AmbiguousOauthIdentity { provider, holders } => write!(
                f,
                "{holders} live certificates claim the same {provider} identity — refusing to \
                 choose between them"
            ),
            StoreError::AmbiguousLoginName { name, holders } => write!(
                f,
                "{} active certificates answer to the name {name:?} ({}) — refusing to choose \
                 between them. Sign in with the wa_id instead, or give these certs distinct \
                 names; picking one would silently authenticate you as whichever the node \
                 happened to order first.",
                holders.len(),
                holders.join(", ")
            ),
        }
    }
}
impl std::error::Error for StoreError {}

impl From<ciris_persist::wa_cert::Error> for StoreError {
    fn from(e: ciris_persist::wa_cert::Error) -> Self {
        StoreError::WaCert(e)
    }
}
impl From<ciris_persist::service_token_revocation::Error> for StoreError {
    fn from(e: ciris_persist::service_token_revocation::Error) -> Self {
        StoreError::Revocation(e)
    }
}

/// The `wa_cert` backend for whichever store this Engine actually has.
///
/// Implements [`WaCertService`] by delegating, so every call site is unchanged.
/// Adding a third backend is a COMPILE error here — which is the point: the
/// SQLite-only version failed at runtime, in production, on a supported
/// deployment (CIRISServer#397).
pub enum AuthCertBackend {
    Sqlite(SqliteWaCertBackend),
    // persist's `postgres` feature is enabled ONLY on Linux (see Cargo.toml
    // `[target.'cfg(target_os = "linux")'.dependencies]`), so `PostgresBackend`
    // and `Engine::postgres_backend()` do not exist elsewhere. Gating the
    // VARIANT rather than just its construction keeps the exhaustive match a
    // compile-time proof on every platform.
    #[cfg(target_os = "linux")]
    Postgres(Arc<ciris_persist::store::PostgresBackend>),
}

impl WaCertService for AuthCertBackend {
    async fn upsert_wa_cert(&self, cert: WaCert) -> Result<(), WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.upsert_wa_cert(cert).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.upsert_wa_cert(cert).await,
        }
    }
    async fn get_wa_cert(&self, wa_id: &str) -> Result<Option<WaCert>, WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.get_wa_cert(wa_id).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.get_wa_cert(wa_id).await,
        }
    }
    async fn get_by_kid(&self, jwt_kid: &str) -> Result<Option<WaCert>, WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.get_by_kid(jwt_kid).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.get_by_kid(jwt_kid).await,
        }
    }
    async fn get_by_oauth(
        &self,
        provider: &str,
        external_id: &str,
    ) -> Result<Option<WaCert>, WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.get_by_oauth(provider, external_id).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.get_by_oauth(provider, external_id).await,
        }
    }
    async fn list_by_role(
        &self,
        role: WaRole,
        limit: i64,
    ) -> Result<Vec<WaCert>, WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.list_by_role(role, limit).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.list_by_role(role, limit).await,
        }
    }
    async fn set_active(&self, wa_id: &str, active: bool) -> Result<bool, WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.set_active(wa_id, active).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.set_active(wa_id, active).await,
        }
    }
    async fn update_last_login(
        &self,
        wa_id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, WaCertBackendError> {
        match self {
            Self::Sqlite(b) => b.update_last_login(wa_id, at).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.update_last_login(wa_id, at).await,
        }
    }
}

/// Open the `wa_cert` backend for this Engine — SQLite or PostgreSQL.
///
/// SQLite is tried first only because it is the co-located default; neither is
/// privileged. An Engine with neither is [`StoreError::NoAuthBackend`].
pub fn wa_cert_backend(engine: &Engine) -> Result<AuthCertBackend, StoreError> {
    if let Some(sqlite) = engine.sqlite_backend() {
        return Ok(AuthCertBackend::Sqlite(SqliteWaCertBackend::new(
            sqlite.conn_handle(),
        )));
    }
    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return Ok(AuthCertBackend::Postgres(Arc::clone(pg)));
    }
    Err(StoreError::NoAuthBackend)
}

/// The `revoked_service_tokens` backend for this Engine — SQLite or PostgreSQL.
pub enum AuthRevocationBackend {
    Sqlite(SqliteServiceTokenRevocationBackend),
    // persist's `postgres` feature is enabled ONLY on Linux (see Cargo.toml
    // `[target.'cfg(target_os = "linux")'.dependencies]`), so `PostgresBackend`
    // and `Engine::postgres_backend()` do not exist elsewhere. Gating the
    // VARIANT rather than just its construction keeps the exhaustive match a
    // compile-time proof on every platform.
    #[cfg(target_os = "linux")]
    Postgres(Arc<ciris_persist::store::PostgresBackend>),
}

impl ciris_persist::service_token_revocation::ServiceTokenRevocationService
    for AuthRevocationBackend
{
    async fn record_revocation(
        &self,
        revocation: ciris_persist::service_token_revocation::RevokedServiceToken,
    ) -> Result<(), ciris_persist::service_token_revocation::Error> {
        match self {
            Self::Sqlite(b) => b.record_revocation(revocation).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.record_revocation(revocation).await,
        }
    }
    async fn list_revocations(
        &self,
    ) -> Result<
        Vec<ciris_persist::service_token_revocation::RevokedServiceToken>,
        ciris_persist::service_token_revocation::Error,
    > {
        match self {
            Self::Sqlite(b) => b.list_revocations().await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.list_revocations().await,
        }
    }
    async fn check_revocation(
        &self,
        token_hash: &str,
    ) -> Result<
        Option<ciris_persist::service_token_revocation::RevokedServiceToken>,
        ciris_persist::service_token_revocation::Error,
    > {
        match self {
            Self::Sqlite(b) => b.check_revocation(token_hash).await,
            #[cfg(target_os = "linux")]
            Self::Postgres(b) => b.check_revocation(token_hash).await,
        }
    }
}

pub fn revocation_backend(engine: &Engine) -> Result<AuthRevocationBackend, StoreError> {
    if let Some(sqlite) = engine.sqlite_backend() {
        return Ok(AuthRevocationBackend::Sqlite(
            SqliteServiceTokenRevocationBackend::new(sqlite.conn_handle()),
        ));
    }
    #[cfg(target_os = "linux")]
    if let Some(pg) = engine.postgres_backend() {
        return Ok(AuthRevocationBackend::Postgres(Arc::clone(pg)));
    }
    Err(StoreError::NoAuthBackend)
}

/// Look up a WA cert by its OAuth `(provider, external_id)` — the OAuth login
/// path (hits the partial `wa_cert_oauth` index). `None` if no linked cert.
/// Every LIVE cert claiming `(provider, external_id)`.
///
/// Separate from [`get_by_oauth`] because two callers want DIFFERENT things from
/// the same scan, and conflating them broke the claim (found in review by Codex
/// on the 0.5.168 PR):
///
/// - **Sign-in** wants one answer and must REFUSE when there are several —
///   picking one is how a human gets signed in with the wrong rights.
/// - **The claim's cleanup** wants exactly the multi-holder case, because
///   PRODUCING it is what it exists to resolve: the claim has just stamped the
///   owner's pair onto the owner, so the pre-claim OAuth cert and the owner BOTH
///   hold it. Routing that cleanup through the fail-closed resolver made it take
///   the `Err` arm and retire nothing — leaving sign-in permanently ambiguous,
///   which is worse than the duplicate it was meant to remove.
///
/// A fail-closed READER and a REPAIR path cannot share an entry point: the
/// repair exists precisely for the state the reader refuses.
pub async fn live_oauth_holders(
    engine: &Engine,
    provider: &str,
    external_id: &str,
) -> Result<Vec<WaCert>, StoreError> {
    let mut live: Vec<WaCert> = Vec::new();
    for role in [WaRole::Root, WaRole::Authority, WaRole::Observer] {
        live.extend(
            list_by_role(engine, role, 128)
                .await?
                .into_iter()
                .filter(|c| {
                    c.active
                        && c.oauth_provider.as_deref() == Some(provider)
                        && c.oauth_external_id.as_deref() == Some(external_id)
                }),
        );
    }
    Ok(live)
}

/// Find an ACTIVE cert an owner PRE-PROVISIONED for this email address
/// (CIRISServer#448).
///
/// # The case this exists for
///
/// An owner adds a colleague in Users. They know that person's ADDRESS; they do
/// not know, and cannot look up, their Google `sub`. Until this existed the node
/// matched only `(provider, external_id)`, so a deliberately provisioned human
/// was refused on the node they had been added to — the node ignoring its own
/// operator.
///
/// # The line this does NOT cross
///
/// `oauth.rs` warns that "a stranger who can reach the port should get NOTHING
/// for proving they control some unrelated email", and that remains exactly
/// true. This matches an email an OWNER WROTE onto a cert, never an email a
/// caller asserts about themselves: an unprovisioned address matches no row and
/// is refused as before. Provisioning is the authorisation; the OAuth
/// verification only proves the presenter is who the provider says.
///
/// Matching is case-insensitive on the whole address. That is deliberately
/// coarser than the RFC (a local-part may be case-sensitive) because the input
/// is a human typing a colleague's address into a form, and refusing
/// `Guest@Example.org` for a cert provisioned as `guest@example.org` would be a
/// correctness argument that costs an operator an afternoon.
///
/// Returns `None` when more than one cert claims the address, rather than
/// picking: two certs provisioned for one human is a state an operator must
/// resolve, and choosing silently would bind the identity to whichever row the
/// index happened to return.
pub async fn find_preprovisioned_by_email(
    engine: &Engine,
    email: &str,
) -> Result<Option<WaCert>, StoreError> {
    let want = email.trim().to_ascii_lowercase();
    if want.is_empty() {
        return Ok(None);
    }
    let mut hits: Vec<WaCert> = Vec::new();
    for role in [WaRole::Root, WaRole::Authority, WaRole::Observer] {
        for c in list_by_role(engine, role, 512).await? {
            if !c.active {
                continue;
            }
            // Only a cert with NO oauth pair yet is a provisioning slot. One
            // that already carries a pair belongs to a different identity, and
            // matching it on email would REBIND a live account by address.
            if c.oauth_external_id.is_some() {
                continue;
            }
            let provisioned = c
                .oauth_links
                .as_ref()
                .and_then(|v| v.get("email"))
                .and_then(|v| v.as_str())
                .map(|e| e.trim().to_ascii_lowercase());
            if provisioned.as_deref() == Some(want.as_str()) {
                hits.push(c);
            }
        }
    }
    match hits.len() {
        0 => Ok(None),
        1 => Ok(hits.pop()),
        n => {
            tracing::warn!(
                matches = n,
                "oauth sign-in: {n} active certs are pre-provisioned for the same email — \
                 refusing to choose. An operator must retire the duplicates; binding to \
                 whichever row the index returned would be arbitrary."
            );
            Ok(None)
        }
    }
}

/// Resolve a provider pair to its WA cert. **RETIRED CERTS DO NOT ANSWER**
/// (CIRISServer#395).
///
/// The substrate's lookup is a plain index read and returns a row whatever its
/// `active` flag says. That is right for the store and wrong for a sign-in: a
/// deactivated cert has been RETIRED, and a retired identity answering "who is
/// this human?" is the same class of mistake as a revoked key still verifying.
///
/// It shipped exactly that way. The claim carries the owner's sign-in pair onto
/// the owner cert and deactivates the duplicate — and the very next Google
/// sign-in still resolved to the deactivated one, minting a session for a
/// retired observer account. The retirement was correct and simply had no effect
/// on the question anyone was asking.
///
/// Filtering here rather than at each call site because there is one right
/// answer to "which cert is this provider identity" and it must not depend on
/// which caller is asking.
pub async fn get_by_oauth(
    engine: &Engine,
    provider: &str,
    external_id: &str,
) -> Result<Option<WaCert>, StoreError> {
    // The backend's index answers with ONE row and does not care whether it is
    // active. Filtering that to `None` is not enough — `create_oauth_user`
    // derives a DETERMINISTIC `wa_id` from the pair, so a "not found" makes the
    // next sign-in UPSERT the very row that was retired, reactivating it. The
    // retirement then survives exactly until the next login.
    //
    // So: prefer the indexed row when it is live, and otherwise look for the
    // ACTIVE cert that holds this pair — which after a claim is the OWNER, since
    // the claim stamps the pair onto it. One provider identity, one live answer,
    // wherever that cert happens to live.
    // NO INDEX FAST-PATH. An early return on the indexed row skips the ambiguity
    // check entirely — which is what the first version of this did, and it meant
    // the refusal below could never fire while the very state it guards existed.
    // The scan IS the answer; the index is only consulted when the scan finds
    // nothing (a cert in a role the scan does not enumerate).
    // AMBIGUITY FAILS CLOSED (CIRISServer#397). Collect every LIVE holder before
    // answering, rather than returning the first match found.
    //
    // Picking one is what shipped, and it picked wrong: with the owner and a
    // leftover observer both holding the pair, sign-in silently resolved to the
    // OBSERVER. The human was authenticated, saw no error, and held the wrong
    // rights on their own node — which only surfaces at the first owner-gated
    // act, far from its cause.
    //
    // "Two certs claim this identity" is not a question with a best answer; it
    // is a broken invariant. Refusing says so at the door, as one line in a log,
    // instead of a 403 three screens later.
    let mut live = live_oauth_holders(engine, provider, external_id).await?;
    match live.len() {
        0 => {
            // Nothing live in the scanned roles — let the index answer, still
            // requiring `active`, so a role we do not enumerate is not silently
            // invisible.
            Ok(wa_cert_backend(engine)?
                .get_by_oauth(provider, external_id)
                .await?
                .filter(|c| c.active))
        }
        1 => Ok(live.pop()),
        n => {
            let ids: Vec<&str> = live.iter().map(|c| c.wa_id.as_str()).collect();
            tracing::error!(
                provider = %provider, holders = n, wa_ids = ?ids,
                "AMBIGUOUS provider identity — multiple live certs claim this account. Refusing \
                 to choose: picking one silently signs the human in with whichever rights that \
                 cert happens to carry. Retire all but the intended holder."
            );
            Err(StoreError::AmbiguousOauthIdentity {
                provider: provider.to_string(),
                holders: n,
            })
        }
    }
}

/// Resolve a login identifier to its WA cert — the fabric port of the agent's
/// multi-key `_users` cache (`auth_service.py`: one user is keyed under its
/// `wa_id`, its OAuth `"<provider>:<external_id>"` primary key, AND every OAuth
/// link key). The fabric keys `wa_cert` by `wa_id` ONLY, so the other identifiers
/// resolve through the typed backend lookups + a human-`name` scan:
///
///   1. `wa_id` — the canonical key (`get`).
///   2. OAuth `"<provider>:<external_id>"` — `get_by_oauth` (the agent's OAuth
///      primary key).
///   3. human `name` — the friendly username the wizard stamps on the owner ROOT
///      (`eric`), so the operator logs in with it, not the derived `wa_id`.
///
/// Returns the FIRST match in that precedence. The caller still issues the session
/// against the resolved `cert.wa_id` (the canonical identity), so the friendly
/// alias never leaks into the token.
/// How [`resolve_login`] found the cert — carried so the login path can SAY
/// which key matched instead of leaving an operator to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginMatch {
    /// The identifier was a `wa_id`.
    WaId,
    /// The identifier was `"<provider>:<external_id>"`.
    Oauth,
    /// The identifier equalled a cert's human `name`.
    Name,
}

impl LoginMatch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WaId => "wa_id",
            Self::Oauth => "oauth_pair",
            Self::Name => "name",
        }
    }
}

/// What the name scan actually looked at, for the miss path.
///
/// A bare "no cert resolved" cannot distinguish an EMPTY store (the node is
/// reading a different database than whatever created the account) from a
/// NAME MISMATCH (the certs are right there and none is called that). Those
/// have opposite fixes, so the miss report carries the count and — at DEBUG
/// only — the names themselves. Reported by CIRISAgent as CIRISServer#389:
/// without this, a failed login is a guess between two unrelated causes.
#[derive(Debug, Default)]
pub struct LoginMiss {
    /// How many certs the name scan examined across all roles.
    pub scanned: usize,
    /// The names it saw. DEBUG-only in the log — a human name is the user's.
    pub names: Vec<String>,
}

/// **Every ACTIVE cert answering to `ident` as a human name**, across the login
/// roles, in role order.
///
/// Split out because both resolvers need it and a second copy is how they would
/// come to disagree about which cert a name means — which is the whole defect.
/// Returns them ALL: deciding is the caller's job, and the only correct decision
/// on more than one is to refuse.
async fn certs_named(engine: &Engine, ident: &str) -> Result<Vec<WaCert>, StoreError> {
    let mut out = Vec::new();
    for role in [WaRole::Root, WaRole::Authority, WaRole::Observer] {
        for c in list_by_role(engine, role, 128).await? {
            if c.name == ident {
                out.push(c);
            }
        }
    }
    Ok(out)
}

/// Refuse rather than choose. Logs both `wa_id`s so the operator can see the
/// collision instead of inferring it from a password that "stopped working".
fn one_named(ident: &str, mut found: Vec<WaCert>) -> Result<Option<WaCert>, StoreError> {
    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found.remove(0))),
        _ => {
            let holders: Vec<String> = found.iter().map(|c| c.wa_id.clone()).collect();
            tracing::error!(
                name = %ident, holders = ?holders,
                "AMBIGUOUS LOGIN NAME — multiple active certs answer to this name. Refusing to \
                 choose (CIRISAgent#1029): resolving one of them silently authenticates the \
                 caller as whichever the node ordered first, and presents as an eternal \
                 `password mismatch` when the password belongs to the other."
            );
            Err(StoreError::AmbiguousLoginName {
                name: ident.to_string(),
                holders,
            })
        }
    }
}

/// [`resolve_login`], but reporting HOW it matched or WHAT it scanned.
pub async fn resolve_login_detailed(
    engine: &Engine,
    ident: &str,
) -> Result<Result<(WaCert, LoginMatch), LoginMiss>, StoreError> {
    if let Some(c) = get(engine, ident).await? {
        return Ok(Ok((c, LoginMatch::WaId)));
    }
    if let Some((provider, external_id)) = ident.split_once(':') {
        if !provider.is_empty() && !external_id.is_empty() {
            if let Some(c) = get_by_oauth(engine, provider, external_id).await? {
                return Ok(Ok((c, LoginMatch::Oauth)));
            }
        }
    }
    if let Some(c) = one_named(ident, certs_named(engine, ident).await?)? {
        return Ok(Ok((c, LoginMatch::Name)));
    }
    // Only NOW build the miss report — it exists to separate "this node reads a
    // different database" (scanned=0) from "the certs are here and none is named
    // that" (scanned>0), and neither is true until the name scan has come back
    // empty.
    let mut miss = LoginMiss::default();
    for role in [WaRole::Root, WaRole::Authority, WaRole::Observer] {
        for c in list_by_role(engine, role, 128).await? {
            miss.scanned += 1;
            miss.names.push(c.name);
        }
    }
    Ok(Err(miss))
}

pub async fn resolve_login(engine: &Engine, ident: &str) -> Result<Option<WaCert>, StoreError> {
    if let Some(c) = get(engine, ident).await? {
        return Ok(Some(c));
    }
    if let Some((provider, external_id)) = ident.split_once(':') {
        if !provider.is_empty() && !external_id.is_empty() {
            if let Some(c) = get_by_oauth(engine, provider, external_id).await? {
                return Ok(Some(c));
            }
        }
    }
    // Human-name scan across the active roles (the owner is a ROOT). Names are NOT
    // unique, and this used to resolve that by picking the first match in role
    // order — which decides which `jeff` you are, silently. It refuses now
    // (CIRISAgent#1029); see [`one_named`].
    one_named(ident, certs_named(engine, ident).await?)
}

/// Point lookup by `wa_id`.
pub async fn get(engine: &Engine, wa_id: &str) -> Result<Option<WaCert>, StoreError> {
    Ok(wa_cert_backend(engine)?.get_wa_cert(wa_id).await?)
}

/// Idempotent upsert of a WA cert (create or update).
pub async fn upsert(engine: &Engine, cert: WaCert) -> Result<(), StoreError> {
    Ok(wa_cert_backend(engine)?.upsert_wa_cert(cert).await?)
}

/// Activity toggle. `false` = revoke (the agent's `revoke_api_key` / logout
/// semantics: mark inactive, do not delete — preserve the audit trail).
pub async fn set_active(engine: &Engine, wa_id: &str, active: bool) -> Result<bool, StoreError> {
    Ok(wa_cert_backend(engine)?.set_active(wa_id, active).await?)
}

/// Stamp `last_login` (login bookkeeping).
/// Stamp a verified provider pair onto a PRE-PROVISIONED cert
/// (CIRISServer#448).
///
/// Called once, on the first successful sign-in of a human an owner added by
/// email. After this the cert carries the pair, so `get_by_oauth` resolves them
/// directly and the email path is never consulted for this person again —
/// which matters, because email is the WEAKER handle and should stop being
/// load-bearing the moment a verified subject id exists.
///
/// Refuses to overwrite an existing pair. A cert that already names an identity
/// belongs to that human, and rebinding it by address is precisely the takeover
/// this whole path must not enable.
pub async fn bind_oauth_identity(
    engine: &Engine,
    wa_id: &str,
    provider: &str,
    external_id: &str,
) -> Result<bool, StoreError> {
    let Some(mut cert) = get(engine, wa_id).await? else {
        return Ok(false);
    };
    if cert.oauth_external_id.is_some() {
        tracing::warn!(
            wa_id = %wa_id,
            "refusing to rebind a cert that already carries an oauth identity"
        );
        return Ok(false);
    }
    cert.oauth_provider = Some(provider.to_string());
    cert.oauth_external_id = Some(external_id.to_string());
    upsert(engine, cert).await?;
    Ok(true)
}

pub async fn touch_login(engine: &Engine, wa_id: &str) -> Result<bool, StoreError> {
    Ok(wa_cert_backend(engine)?
        .update_last_login(wa_id, chrono::Utc::now())
        .await?)
}

/// List active certs of a role (the `list_observers` / `list_authorities` path).
pub async fn list_by_role(
    engine: &Engine,
    role: WaRole,
    limit: i64,
) -> Result<Vec<WaCert>, StoreError> {
    Ok(wa_cert_backend(engine)?.list_by_role(role, limit).await?)
}
