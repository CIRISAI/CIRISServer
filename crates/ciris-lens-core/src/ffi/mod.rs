//! FFI surface — PyO3 cdylib for the lens-deployed-product cutover
//! window. Gated behind the `python` Cargo feature.
//!
//! See [`pyo3`] for the v0.1.0 swap contract.

#[cfg(feature = "python")]
pub mod pyo3;
