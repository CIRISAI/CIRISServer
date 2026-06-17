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
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoSqliteBackend => write!(f, "engine is not SQLite-backed"),
            StoreError::WaCert(e) => write!(f, "wa_cert: {e}"),
            StoreError::Revocation(e) => write!(f, "service-token revocation: {e}"),
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
pub async fn get_by_oauth(
    engine: &Engine,
    provider: &str,
    external_id: &str,
) -> Result<Option<WaCert>, StoreError> {
    Ok(wa_cert_backend(engine)?
        .get_by_oauth(provider, external_id)
        .await?)
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
