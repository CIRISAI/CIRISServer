//! `LensAudit` PyO3 class — typed audit methods (CIRISLensCore#12 v0.3).
//!
//! # PyO3 surface
//!
//! ```python
//! import ciris_lens_core as cl
//!
//! engine = ciris_persist.Engine(...)
//! audit = cl.LensAudit(engine=engine, tenant_id="agent-tenant-01")
//!
//! audit.log_action(
//!     action_type="speak",
//!     thought_id="th_abc",
//!     handler="speak_handler",
//!     success=True,
//!     duration_ms=42,
//!     rationale="user asked",
//! )
//! audit.log_consent_event(
//!     event_type="grant",
//!     stream_id="ch_99",
//!     duration_days=30,
//!     consent_role="datum",
//! )
//! audit.log_wbd(
//!     deferral_reason="capability_uncertain",
//!     deferred_to="human_oversight",
//!     deferral_window_seconds=86400,
//! )
//! audit.log_identity_change(
//!     field="agent_role",
//!     old="datum",
//!     new="ally",
//!     operator_signature="...",
//! )
//! ```
//!
//! # Engine handshake (matches LensClient exactly)
//!
//! `LensAudit` follows the same cohabitation pattern as `LensClient`
//! (CIRISLensCore#11 Cut 5 / #43.1 P0 fix):
//!
//! - `engine=` (Python `ciris_persist.Engine`) is required for the
//!   cohabitation path (two-wheel deployment).
//! - `engine=None` falls back to `current_rust_engine()` for the
//!   single-wheel path.
//!
//! Python methods called on the engine object (cross-wheel-safe by
//! dispatch-through-Python, same as `LensClient`):
//!
//! - `engine.local_key_id()` → str
//! - `engine.audit_canonicalize_for_hash(entry_json: str)` → bytes
//! - `engine.audit_canonicalize_for_signing(entry_json: str)` → bytes
//! - `engine.local_sign(canonical_bytes: bytes)` → 64-byte Ed25519 sig
//! - `engine.audit_record_entry(entry_json: str)` → None
//!
//! # Cross-wheel note (CIRISConformance)
//!
//! The full canonicalize→sign→record path is a
//! `CIRISConformance requires_audit_engine` cell — it requires two
//! separately-built wheels and cannot be tested in-repo. The pure
//! Rust helpers (`build_entry_draft`, `stamp_entry_hash`,
//! `stamp_signature`) are tested in `crate::audit::delegate`. The
//! Python dispatch is the proven #11 pattern.

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use chrono::Utc;
use uuid::Uuid;

use crate::audit::api::{
    AuditedAction, ConsentEvent, ConsentEventType, IdentityChange, TypedAuditEvent,
    WisdomBasedDeferral,
};
use crate::audit::delegate::{build_entry_draft, stamp_entry_hash, stamp_signature};

// ── Internal engine holder — mirrors LensClientInner ────────────────

enum AuditEngineInner {
    /// Single-wheel path: Arc<ciris_persist::Engine>.
    Sovereign(Arc<ciris_persist::Engine>),
    /// Cohabitation path: the Python engine object.
    Cohabitation { py_engine: Py<PyAny> },
}

/// Typed audit log client — wraps the persist audit-log delegation path.
///
/// Constructs one `AuditEntry` per `log_*` call, drives the three-step
/// canonical+sign+record flow through the host Engine's Python methods,
/// and appends the entry to persist's hash-chained audit log.
#[pyclass(name = "LensAudit")]
pub struct PyLensAudit {
    inner: AuditEngineInner,
    /// `tenant_id` scopes the audit chain. Required by persist's AV-51.
    tenant_id: String,
}

#[pymethods]
impl PyLensAudit {
    /// Construct a `LensAudit`.
    ///
    /// # Parameters
    ///
    /// - `tenant_id` — the audit chain tenant ID (AV-51: required).
    ///   Typically the agent's `key_id` or a stable deployment identifier.
    /// - `engine` — the host `ciris_persist.Engine` Python object (cohabitation
    ///   path). Pass `None` for the single-wheel / sovereign path.
    ///
    /// # Errors
    ///
    /// - `RuntimeError` if `engine=None` and no process `ciris_persist.Engine`
    ///   has been constructed (sovereign path only).
    #[new]
    #[pyo3(signature = (tenant_id, engine = None))]
    fn new(
        _py: Python<'_>,
        tenant_id: String,
        engine: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        if let Some(host_engine) = engine {
            return Ok(Self {
                inner: AuditEngineInner::Cohabitation {
                    py_engine: host_engine.clone().unbind(),
                },
                tenant_id,
            });
        }
        // Sovereign path — same fallback as LensClient.
        let rust_engine = ciris_persist::ffi::pyo3::current_rust_engine().ok_or_else(|| {
            PyRuntimeError::new_err(
                "no process Engine — host must construct ciris_persist.Engine first. \
                 For pip cohabitation (two-wheel deployment) pass engine=<host_engine> \
                 to LensAudit to fix CIRISLensCore#43.1.",
            )
        })?;
        Ok(Self {
            inner: AuditEngineInner::Sovereign(rust_engine),
            tenant_id,
        })
    }

    /// Record a handler action to the audit log.
    ///
    /// Maps to `AuditEntry.action_type = "handler_action_<action_type>"`.
    ///
    /// # Parameters
    ///
    /// - `action_type` — handler vocabulary string
    ///   (e.g. `"speak"`, `"memorize"`, `"defer"`, `"reject"`, `"tool"`,
    ///   `"ponder"`, `"observe"`, `"task_complete"`, `"recall"`, `"forget"`)
    /// - `thought_id` — the thought being handled (trace anchor)
    /// - `handler` — handler class name (e.g. `"speak_handler"`)
    /// - `success` — whether the action completed without error
    /// - `duration_ms` — wall-clock time in milliseconds
    /// - `rationale` — optional reasoning summary (may be `None`)
    ///
    /// # Returns
    ///
    /// `{"entry_id": "<uuid>", "action_type": "handler_action_<type>"}` on success.
    ///
    /// # Errors
    ///
    /// `RuntimeError` if the engine sign/persist step fails.
    #[pyo3(signature = (action_type, thought_id, handler, success, duration_ms, rationale=None))]
    #[allow(clippy::too_many_arguments)]
    fn log_action<'py>(
        &self,
        py: Python<'py>,
        action_type: String,
        thought_id: String,
        handler: String,
        success: bool,
        duration_ms: u64,
        rationale: Option<String>,
    ) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        if action_type.is_empty() {
            return Err(PyValueError::new_err("action_type must not be empty"));
        }
        if thought_id.is_empty() {
            return Err(PyValueError::new_err("thought_id must not be empty"));
        }
        let now = Utc::now();
        let ev = TypedAuditEvent::Action(AuditedAction {
            action_type: action_type.clone(),
            thought_id,
            rationale,
            handler,
            success,
            duration_ms,
            recorded_at: now,
        });
        let entry_id = Uuid::new_v4().to_string();
        let action_type_str = ev.action_type_str();
        self.record_event(py, ev, &entry_id)?;
        let result = pyo3::types::PyDict::new(py);
        result.set_item("entry_id", entry_id)?;
        result.set_item("action_type", action_type_str)?;
        Ok(result)
    }

    /// Record a user-consent lifecycle event to the audit log.
    ///
    /// Maps to `AuditEntry.action_type = "consent_event"`.
    ///
    /// # Parameters
    ///
    /// - `event_type` — `"grant"` | `"revoke"` | `"expire"`
    /// - `stream_id` — the stream or channel this consent applies to
    /// - `consent_role` — principal role (e.g. `"datum"`, `"ally"`)
    /// - `duration_days` — grant horizon in days (`None` for revoke/expire)
    ///
    /// # Returns
    ///
    /// `{"entry_id": "<uuid>", "action_type": "consent_event"}` on success.
    #[pyo3(signature = (event_type, stream_id, consent_role, duration_days=None))]
    fn log_consent_event<'py>(
        &self,
        py: Python<'py>,
        event_type: String,
        stream_id: String,
        consent_role: String,
        duration_days: Option<u32>,
    ) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let et = match event_type.as_str() {
            "grant" => ConsentEventType::Grant,
            "revoke" => ConsentEventType::Revoke,
            "expire" => ConsentEventType::Expire,
            other => {
                return Err(PyValueError::new_err(format!(
                    "event_type must be one of: grant, revoke, expire — got {other:?}"
                )))
            }
        };
        let now = Utc::now();
        let ev = TypedAuditEvent::ConsentEvent(ConsentEvent {
            event_type: et,
            stream_id,
            duration_days,
            consent_role,
            recorded_at: now,
        });
        let entry_id = Uuid::new_v4().to_string();
        self.record_event(py, ev, &entry_id)?;
        let result = pyo3::types::PyDict::new(py);
        result.set_item("entry_id", entry_id)?;
        result.set_item("action_type", "consent_event")?;
        Ok(result)
    }

    /// Record a wisdom-based deferral event to the audit log.
    ///
    /// Maps to `AuditEntry.action_type = "wisdom_based_deferral"`.
    ///
    /// # Parameters
    ///
    /// - `deferral_reason` — capability assessment
    ///   (e.g. `"capability_uncertain"`, `"ethical_boundary"`)
    /// - `deferred_to` — oversight target
    ///   (e.g. `"human_oversight"`, `"wa_authority"`)
    /// - `deferral_window_seconds` — deferral timeout in seconds
    ///
    /// # Returns
    ///
    /// `{"entry_id": "<uuid>", "action_type": "wisdom_based_deferral"}` on success.
    #[pyo3(signature = (deferral_reason, deferred_to, deferral_window_seconds))]
    fn log_wbd<'py>(
        &self,
        py: Python<'py>,
        deferral_reason: String,
        deferred_to: String,
        deferral_window_seconds: u64,
    ) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let now = Utc::now();
        let ev = TypedAuditEvent::WisdomBasedDeferral(WisdomBasedDeferral {
            deferral_reason,
            deferred_to,
            deferral_window_seconds,
            recorded_at: now,
        });
        let entry_id = Uuid::new_v4().to_string();
        self.record_event(py, ev, &entry_id)?;
        let result = pyo3::types::PyDict::new(py);
        result.set_item("entry_id", entry_id)?;
        result.set_item("action_type", "wisdom_based_deferral")?;
        Ok(result)
    }

    /// Record an agent identity change event to the audit log.
    ///
    /// Maps to `AuditEntry.action_type = "identity_change"`.
    ///
    /// # Parameters
    ///
    /// - `field` — identity dimension changed (e.g. `"agent_role"`)
    /// - `old` — previous value
    /// - `new` — new value
    /// - `operator_signature` — Ed25519 sig from the operator authorizing
    ///   the change; URL-safe base64, no pad. Pass `""` if not signed.
    ///
    /// # Returns
    ///
    /// `{"entry_id": "<uuid>", "action_type": "identity_change"}` on success.
    #[pyo3(signature = (field, old, new, operator_signature))]
    fn log_identity_change<'py>(
        &self,
        py: Python<'py>,
        field: String,
        old: String,
        new: String,
        operator_signature: String,
    ) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
        let now = Utc::now();
        let ev = TypedAuditEvent::IdentityChange(IdentityChange {
            field,
            old,
            new,
            operator_signature,
            recorded_at: now,
        });
        let entry_id = Uuid::new_v4().to_string();
        self.record_event(py, ev, &entry_id)?;
        let result = pyo3::types::PyDict::new(py);
        result.set_item("entry_id", entry_id)?;
        result.set_item("action_type", "identity_change")?;
        Ok(result)
    }
}

// ── Delegation core ──────────────────────────────────────────────────

impl PyLensAudit {
    /// Drive the canonical+sign+record flow for one typed audit event.
    ///
    /// This is the three-step delegation path described in the module doc:
    ///
    /// 1. `build_entry_draft` (pure Rust) → initial JSON
    /// 2. `engine.audit_canonicalize_for_hash(json)` → hash bytes
    ///    → sha256 → stamp `entry_hash`
    /// 3. `engine.audit_canonicalize_for_signing(json+hash)` → sign bytes
    ///    → `engine.local_sign(sign_bytes)` → 64-byte sig
    ///    → stamp `signature`
    /// 4. `engine.audit_record_entry(final_json)` → persist write
    ///
    /// All Python dispatch is cross-wheel-safe (method calls on the
    /// Python engine object, not on a per-wheel Rust static).
    fn record_event(&self, py: Python<'_>, event: TypedAuditEvent, entry_id: &str) -> PyResult<()> {
        match &self.inner {
            AuditEngineInner::Sovereign(_rust_engine) => {
                // Sovereign path: we have Arc<Engine> but audit_record_entry
                // needs the JSON-in/JSON-out canonicalize calls. For v0.3 we
                // delegate via the Rust engine's AuditService directly.
                // This path is used when lens-core IS the host wheel (the
                // process singleton is populated). In practice for post-fold
                // agent deployments the cohabitation path is the norm.
                //
                // To avoid duplicating the canonicalize logic we call the
                // same Python methods on the process-singleton Engine by
                // obtaining its Python object via the PyO3 GIL. This is the
                // same technique persist's own sovereign tests use.
                //
                // For now: this path is unsupported at v0.3 (no sovereign
                // AuditService test harness without a live DB). Surface a
                // clear error rather than silently failing.
                Err(PyRuntimeError::new_err(
                    "LensAudit sovereign path not available at v0.3 — \
                     pass engine=<host_engine> to use the cohabitation path. \
                     Sovereign audit requires a DB-backed Engine and is a follow-up.",
                ))
            }

            AuditEngineInner::Cohabitation { py_engine } => {
                let engine = py_engine.bind(py);

                // 1. Get actor_id (the signing key's public-key / key_id).
                let actor_id: String = engine
                    .call_method0("local_key_id")
                    .map_err(|e| PyRuntimeError::new_err(format!("engine.local_key_id(): {e}")))?
                    .extract()?;

                // 2. Build the initial draft (pure Rust — no I/O).
                let now = event.recorded_at();
                let draft = build_entry_draft(&event, &self.tenant_id, &actor_id, entry_id, now);
                let draft_json_str = draft
                    .to_json_str()
                    .map_err(|e| PyRuntimeError::new_err(format!("serialize audit draft: {e}")))?;

                // 3. Canonicalize for hash → stamp entry_hash.
                let hash_canon_bytes_obj = engine
                    .call_method1("audit_canonicalize_for_hash", (draft_json_str,))
                    .map_err(|e| {
                        PyRuntimeError::new_err(format!("engine.audit_canonicalize_for_hash: {e}"))
                    })?;
                let hash_canon_bytes: Vec<u8> =
                    hash_canon_bytes_obj.cast::<PyBytes>()?.as_bytes().to_vec();
                let entry_with_hash = stamp_entry_hash(draft.json, &hash_canon_bytes);

                // 4. Canonicalize for signing → sign → stamp signature.
                let entry_with_hash_str = serde_json::to_string(&entry_with_hash)
                    .map_err(|e| PyRuntimeError::new_err(format!("serialize entry+hash: {e}")))?;
                let sign_canon_bytes_obj = engine
                    .call_method1("audit_canonicalize_for_signing", (entry_with_hash_str,))
                    .map_err(|e| {
                        PyRuntimeError::new_err(format!(
                            "engine.audit_canonicalize_for_signing: {e}"
                        ))
                    })?;
                let sign_canon_bytes: Vec<u8> =
                    sign_canon_bytes_obj.cast::<PyBytes>()?.as_bytes().to_vec();

                let sign_py_bytes = PyBytes::new(py, &sign_canon_bytes);
                let sig_obj = engine
                    .call_method1("local_sign", (sign_py_bytes,))
                    .map_err(|e| PyRuntimeError::new_err(format!("engine.local_sign: {e}")))?;
                let sig_bytes: Vec<u8> = sig_obj.cast::<PyBytes>()?.as_bytes().to_vec();
                if sig_bytes.len() != 64 {
                    return Err(PyRuntimeError::new_err(format!(
                        "engine.local_sign returned {} bytes, expected 64",
                        sig_bytes.len()
                    )));
                }

                let final_entry = stamp_signature(entry_with_hash, &sig_bytes);

                // 5. Persist via engine.audit_record_entry(json).
                let final_json_str = serde_json::to_string(&final_entry)
                    .map_err(|e| PyRuntimeError::new_err(format!("serialize final entry: {e}")))?;
                engine
                    .call_method1("audit_record_entry", (final_json_str,))
                    .map_err(|e| {
                        PyRuntimeError::new_err(format!("engine.audit_record_entry: {e}"))
                    })?;

                tracing::debug!(
                    entry_id = entry_id,
                    action_type = %event.action_type_str(),
                    tenant_id = %self.tenant_id,
                    "LensAudit: audit entry recorded",
                );
                Ok(())
            }
        }
    }
}
