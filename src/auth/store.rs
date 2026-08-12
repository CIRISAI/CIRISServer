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
//! shared [`Engine`] — the `conn_handle()` sibling-module pattern persist
//! documents for cohabiting backends:
//!
//! ```text
//! engine.sqlite_backend()? .conn_handle() -> Arc<Mutex<Connection>>
//!     -> SqliteWaCertBackend::new(conn)                 (impls WaCertService)
//!     -> SqliteServiceTokenRevocationBackend::new(conn) (impls ServiceTokenRevocationService)
//! ```
//!
//! When the agent adopts the wheel it DROPS its own `auth_service` storage and
//! delegates to the fabric routes — no schema fork, because both sides were
//! always the same table.

use ciris_persist::prelude::Engine;
use ciris_persist::service_token_revocation::sqlite::SqliteServiceTokenRevocationBackend;
use ciris_persist::wa_cert::sqlite::SqliteWaCertBackend;
use ciris_persist::wa_cert::{WaCert, WaCertService, WaRole};

/// Why an auth-store access failed.
#[derive(Debug)]
pub enum StoreError {
    /// The Engine is not SQLite-backed (no `conn_handle`); the auth store needs
    /// the directory-bearing SQLite backend.
    NoSqliteBackend,
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
            StoreError::NoSqliteBackend => write!(f, "engine is not SQLite-backed"),
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

/// Open the `wa_cert` substrate backend over the Engine's shared SQLite
/// connection. The returned backend impls [`WaCertService`].
pub fn wa_cert_backend(engine: &Engine) -> Result<SqliteWaCertBackend, StoreError> {
    let sqlite = engine.sqlite_backend().ok_or(StoreError::NoSqliteBackend)?;
    Ok(SqliteWaCertBackend::new(sqlite.conn_handle()))
}

/// Open the `revoked_service_tokens` substrate backend over the Engine's shared
/// SQLite connection. The returned backend impls [`ServiceTokenRevocationService`].
pub fn revocation_backend(
    engine: &Engine,
) -> Result<SqliteServiceTokenRevocationBackend, StoreError> {
    let sqlite = engine.sqlite_backend().ok_or(StoreError::NoSqliteBackend)?;
    Ok(SqliteServiceTokenRevocationBackend::new(
        sqlite.conn_handle(),
    ))
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
