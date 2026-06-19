//! A single id helper shared across the attestation builders.
//!
//! The `attestation_id` (and similar) is **cosmetic** — the content hash is the
//! integrity anchor, not this id. This replaces the ~4 hand-rolled
//! counter+nanos `new_uuid_v4` copies (scorer / peer / graph_config / ownership)
//! with one direct `uuid::Uuid::new_v4()` call.

/// A fresh random v4 UUID as a lowercase hyphenated string.
#[must_use]
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
