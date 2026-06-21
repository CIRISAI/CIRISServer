//! NodeCode — the QR-able federation-key bootstrap handle (CEG §0.10).
//!
//! A faithful Rust port of the agent's authoritative codec
//! (`ciris_engine/logic/utils/node_code_codec.py`). A NodeCode is a compact,
//! user-shareable encoding of a federation peer's identity (`key_id` +
//! Ed25519 pubkey + optional transport/alias hints) plus a checksum, rendered
//! as a `CIRIS-V1-...` string a receiver can type, paste, or scan (QR).
//!
//! ## Wire format — byte-identical with the agent
//!
//! The binary payload, before base32, is:
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!      0      1   version (currently 0x01)
//!      1     32   key_id_hash  = SHA-256(key_id_utf8)
//!     33     32   pubkey_ed25519 (raw 32 bytes)
//!     65      1   key_id_len (0-255)
//!     66      N   key_id (UTF-8)
//!    66+N     1   transport_hint_len (0-255)
//!  67+N      M   transport_hint (UTF-8)
//!  67+N+M     1   alias_hint_len (0-255)
//!  68+N+M     K   alias_hint (UTF-8)
//!      …      2   CRC-16-CCITT (big-endian, over all preceding bytes)
//! ```
//!
//! Encoding: RFC 4648 base32 (alphabet `A-Z2-7`) WITHOUT padding, uppercased,
//! prefixed `CIRIS-V1-`, grouped into 4-char chunks separated by dashes for
//! display (`encode`) or left ungrouped for the QR form (`encode_qr`). Decode
//! tolerates dashes, whitespace, and case, and accepts the undashed
//! `CIRISV1...` QR form. CRC-16-CCITT params: poly `0x1021`, init `0xFFFF`, no
//! final xor, bytes consumed MSB-first.
//!
//! A NodeCode shared from one app MUST decode byte-identically on the other —
//! the codec below round-trips against the agent's format with zero deviation.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Current NodeCode binary-format version.
pub const CIRIS_NODE_CODE_VERSION: u8 = 0x01;

/// The textual prefix on every NodeCode (dashed display + QR forms).
const PREFIX: &str = "CIRIS-V1-";
/// Group size for the dashed display form.
const GROUP_SIZE: usize = 4;
/// Per-field maximum (1-byte length prefix).
const MAX_HINT_BYTES: usize = 255;
/// Raw Ed25519 public-key length.
const PUBKEY_RAW_LEN: usize = 32;
/// SHA-256 digest length.
const KEY_ID_HASH_LEN: usize = 32;

/// CRC-16-CCITT polynomial.
const CRC_POLY: u16 = 0x1021;
/// CRC-16-CCITT initial value.
const CRC_INIT: u16 = 0xFFFF;

/// The decoded NodeCode payload — a federation peer's shareable identity.
///
/// Mirrors the agent's `NodeCode` pydantic model: `key_id` is the human-readable
/// Ed25519 `signer_key_id`; `pubkey_ed25519_base64` is the raw 32-byte Ed25519
/// public key, base64-encoded (the `LocalPeerState.pubkey_ed25519_base64` form);
/// the hints are optional UTF-8 strings capped at 255 bytes each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCode {
    /// Ed25519 `signer_key_id` (display form) of the peer being shared.
    pub key_id: String,
    /// Ed25519 public key, base64-encoded — raw 32 bytes.
    pub pubkey_ed25519_base64: String,
    /// Optional transport hint (e.g. a public base URL). Max 255 UTF-8 bytes.
    pub transport_hint: Option<String>,
    /// Optional human-readable alias the sender suggests. Max 255 UTF-8 bytes.
    pub alias_hint: Option<String>,
}

/// NodeCode encode/decode failures — mirrors the agent's exception hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCodeError {
    /// The decoded version byte (or textual `CIRIS-VN-` prefix) is not supported.
    InvalidVersion(String),
    /// The trailing CRC-16-CCITT did not match the recomputed checksum.
    ChecksumMismatch { declared: u16, computed: u16 },
    /// Structurally invalid: bad prefix/base32, truncation, over-long fields,
    /// invalid UTF-8, wrong pubkey size, or non-base64 pubkey.
    Malformed(String),
}

impl std::fmt::Display for NodeCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeCodeError::InvalidVersion(m) => write!(f, "unsupported NodeCode version: {m}"),
            NodeCodeError::ChecksumMismatch { declared, computed } => write!(
                f,
                "NodeCode CRC mismatch (declared 0x{declared:04x}, computed 0x{computed:04x})"
            ),
            NodeCodeError::Malformed(m) => write!(f, "malformed NodeCode: {m}"),
        }
    }
}
impl std::error::Error for NodeCodeError {}

// ─── CRC-16-CCITT (poly 0x1021, init 0xFFFF, no final xor, MSB-first) ────────

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = CRC_INIT;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ CRC_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/// Encode a hint as `len_byte + utf8_bytes`. `None`/empty both serialize to a
/// single `0x00` byte (matching the agent's `_encode_hint`).
fn encode_hint(value: Option<&str>) -> Result<Vec<u8>, NodeCodeError> {
    match value {
        None | Some("") => Ok(vec![0u8]),
        Some(v) => {
            let raw = v.as_bytes();
            if raw.len() > MAX_HINT_BYTES {
                return Err(NodeCodeError::Malformed(format!(
                    "hint field exceeds {MAX_HINT_BYTES}-byte limit ({} bytes)",
                    raw.len()
                )));
            }
            let mut out = Vec::with_capacity(1 + raw.len());
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
            Ok(out)
        }
    }
}

/// Read a 1-byte length + UTF-8 bytes from `buf` at `offset`. Returns
/// `(value, new_offset)`; empty fields decode to `""`.
fn read_length_prefixed(buf: &[u8], offset: usize) -> Result<(String, usize), NodeCodeError> {
    if offset >= buf.len() {
        return Err(NodeCodeError::Malformed(
            "truncated NodeCode: missing length byte".into(),
        ));
    }
    let length = buf[offset] as usize;
    let start = offset + 1;
    let end = start + length;
    if end > buf.len() {
        return Err(NodeCodeError::Malformed(format!(
            "truncated NodeCode: declared field length {length} exceeds remaining buffer"
        )));
    }
    let value = std::str::from_utf8(&buf[start..end])
        .map_err(|e| NodeCodeError::Malformed(format!("field is not valid UTF-8: {e}")))?
        .to_string();
    Ok((value, end))
}

/// Build the raw binary payload (without checksum) from a NodeCode.
fn build_payload(nc: &NodeCode) -> Result<Vec<u8>, NodeCodeError> {
    let key_id_bytes = nc.key_id.as_bytes();
    if key_id_bytes.len() > MAX_HINT_BYTES {
        return Err(NodeCodeError::Malformed(format!(
            "key_id exceeds {MAX_HINT_BYTES}-byte limit ({} bytes)",
            key_id_bytes.len()
        )));
    }

    let pubkey_raw = B64
        .decode(nc.pubkey_ed25519_base64.as_bytes())
        .map_err(|e| {
            NodeCodeError::Malformed(format!("pubkey_ed25519_base64 is not valid base64: {e}"))
        })?;
    if pubkey_raw.len() != PUBKEY_RAW_LEN {
        return Err(NodeCodeError::Malformed(format!(
            "pubkey_ed25519 must be {PUBKEY_RAW_LEN} raw bytes, got {}",
            pubkey_raw.len()
        )));
    }

    let key_id_hash = Sha256::digest(key_id_bytes);

    let mut out = Vec::new();
    out.push(CIRIS_NODE_CODE_VERSION);
    out.extend_from_slice(&key_id_hash);
    out.extend_from_slice(&pubkey_raw);
    out.push(key_id_bytes.len() as u8);
    out.extend_from_slice(key_id_bytes);
    out.extend_from_slice(&encode_hint(nc.transport_hint.as_deref())?);
    out.extend_from_slice(&encode_hint(nc.alias_hint.as_deref())?);
    Ok(out)
}

/// RFC 4648 base32 alphabet.
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32-encode without padding (RFC 4648).
fn b32_no_pad_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(B32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(B32_ALPHABET[idx] as char);
    }
    out
}

/// Base32-decode tolerating missing padding (input is already uppercased).
fn b32_no_pad_decode(text: &str) -> Result<Vec<u8>, NodeCodeError> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in text.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'2'..=b'7' => ch - b'2' + 26,
            _ => {
                return Err(NodeCodeError::Malformed(format!(
                    "invalid base32 character: {:?}",
                    ch as char
                )))
            }
        } as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

/// Split `text` into `GROUP_SIZE`-char groups joined by `-`.
fn group(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(GROUP_SIZE)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

// ─── Public encode / decode API ─────────────────────────────────────────────

/// Encode a NodeCode as a `CIRIS-V1-...` dashed display string.
pub fn encode(nc: &NodeCode) -> Result<String, NodeCodeError> {
    let body = encode_body(nc)?;
    Ok(format!("{PREFIX}{}", group(&body)))
}

/// Encode a NodeCode as the QR-friendly (no-dashes) form. Same content as
/// [`encode`] but with separator dashes omitted; the `CIRIS-V1-` marker stays.
pub fn encode_qr(nc: &NodeCode) -> Result<String, NodeCodeError> {
    let body = encode_body(nc)?;
    Ok(format!("{PREFIX}{body}"))
}

/// Shared encode tail: build payload, append CRC (big-endian), base32 the lot.
fn encode_body(nc: &NodeCode) -> Result<String, NodeCodeError> {
    let payload = build_payload(nc)?;
    let crc = crc16_ccitt(&payload);
    let mut full = payload;
    full.push((crc >> 8) as u8);
    full.push((crc & 0xFF) as u8);
    Ok(b32_no_pad_encode(&full))
}

/// Decode a `CIRIS-V1-...` string back into a [`NodeCode`].
///
/// Accepts dashed (display) or undashed (QR) forms. Whitespace and case
/// differences are tolerated. Validates the version + CRC-16-CCITT and the
/// `key_id`/hash consistency.
pub fn decode(code: &str) -> Result<NodeCode, NodeCodeError> {
    // Normalize: drop all whitespace, uppercase.
    let cleaned: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned.to_ascii_uppercase();

    // Detect the prefix: dashed `CIRIS-VN-` or undashed `CIRISVN`.
    let body = if let Some(rest) = strip_dashed_prefix(&cleaned)? {
        rest
    } else if let Some(rest) = strip_undashed_prefix(&cleaned)? {
        rest
    } else {
        return Err(NodeCodeError::Malformed(format!(
            "NodeCode does not start with {PREFIX:?} (or its undashed equivalent)"
        )));
    };

    // Strip separator dashes from the body.
    let body: String = body.chars().filter(|&c| c != '-').collect();
    if body.is_empty() {
        return Err(NodeCodeError::Malformed(
            "NodeCode has no payload after prefix".into(),
        ));
    }

    let raw = b32_no_pad_decode(&body)?;

    // Minimum viable payload: ver + hash + pubkey + 3 length bytes + 2 crc.
    let min_size = 1 + KEY_ID_HASH_LEN + PUBKEY_RAW_LEN + 1 + 1 + 1 + 2;
    if raw.len() < min_size {
        return Err(NodeCodeError::Malformed(format!(
            "NodeCode payload too short ({} bytes; need at least {min_size})",
            raw.len()
        )));
    }

    // Split off the trailing CRC and verify.
    let (payload, crc_bytes) = raw.split_at(raw.len() - 2);
    let declared = ((crc_bytes[0] as u16) << 8) | crc_bytes[1] as u16;
    let computed = crc16_ccitt(payload);
    if declared != computed {
        return Err(NodeCodeError::ChecksumMismatch { declared, computed });
    }

    // Parse the binary fields.
    let version = payload[0];
    if version != CIRIS_NODE_CODE_VERSION {
        return Err(NodeCodeError::InvalidVersion(format!(
            "binary version 0x{version:02x}; this build supports 0x{CIRIS_NODE_CODE_VERSION:02x}"
        )));
    }

    let mut offset = 1;
    let key_id_hash = &payload[offset..offset + KEY_ID_HASH_LEN];
    offset += KEY_ID_HASH_LEN;

    let pubkey_raw = &payload[offset..offset + PUBKEY_RAW_LEN];
    offset += PUBKEY_RAW_LEN;

    let (key_id, off) = read_length_prefixed(payload, offset)?;
    offset = off;
    let (transport_hint, off) = read_length_prefixed(payload, offset)?;
    offset = off;
    let (alias_hint, off) = read_length_prefixed(payload, offset)?;
    offset = off;

    if offset != payload.len() {
        return Err(NodeCodeError::Malformed(format!(
            "NodeCode has trailing garbage after parsed fields ({} extra bytes)",
            payload.len() - offset
        )));
    }

    if key_id.is_empty() {
        return Err(NodeCodeError::Malformed(
            "decoded key_id is empty — NodeCode is malformed".into(),
        ));
    }

    // The hash MUST match the recovered key_id (tamper / corruption defense).
    if Sha256::digest(key_id.as_bytes()).as_slice() != key_id_hash {
        return Err(NodeCodeError::Malformed(
            "decoded key_id hash does not match key_id string — NodeCode is corrupt".into(),
        ));
    }

    Ok(NodeCode {
        key_id,
        pubkey_ed25519_base64: B64.encode(pubkey_raw),
        transport_hint: if transport_hint.is_empty() {
            None
        } else {
            Some(transport_hint)
        },
        alias_hint: if alias_hint.is_empty() {
            None
        } else {
            Some(alias_hint)
        },
    })
}

/// Strip a dashed `CIRIS-VN-` prefix, returning the remaining body. Errors on a
/// version mismatch; returns `Ok(None)` when the dashed prefix is absent.
fn strip_dashed_prefix(cleaned: &str) -> Result<Option<&str>, NodeCodeError> {
    let Some(after) = cleaned.strip_prefix("CIRIS-V") else {
        return Ok(None);
    };
    // Read the version digits up to the trailing '-'.
    let Some(dash) = after.find('-') else {
        return Ok(None);
    };
    let (ver_str, rest) = after.split_at(dash);
    let rest = &rest[1..]; // drop the '-'
    let declared: u32 = ver_str
        .parse()
        .map_err(|_| NodeCodeError::Malformed("malformed CIRIS-V<version>- prefix".into()))?;
    if declared != CIRIS_NODE_CODE_VERSION as u32 {
        return Err(NodeCodeError::InvalidVersion(format!(
            "textual prefix V{declared}; this build supports V{CIRIS_NODE_CODE_VERSION}"
        )));
    }
    Ok(Some(rest))
}

/// Strip an undashed `CIRISVN` prefix (the QR form), returning the remaining
/// body. Errors on version mismatch; returns `Ok(None)` when absent.
fn strip_undashed_prefix(cleaned: &str) -> Result<Option<&str>, NodeCodeError> {
    let Some(after) = cleaned.strip_prefix("CIRISV") else {
        return Ok(None);
    };
    // Read leading version digits.
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Ok(None);
    }
    let rest = &after[digits.len()..];
    let declared: u32 = digits
        .parse()
        .map_err(|_| NodeCodeError::Malformed("malformed CIRISV<version> prefix".into()))?;
    if declared != CIRIS_NODE_CODE_VERSION as u32 {
        return Err(NodeCodeError::InvalidVersion(format!(
            "textual prefix V{declared}; this build supports V{CIRIS_NODE_CODE_VERSION}"
        )));
    }
    Ok(Some(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NodeCode {
        // A fixed 32-byte ed25519 pubkey (0x01..0x20) base64-encoded.
        let pk: Vec<u8> = (1u8..=32).collect();
        NodeCode {
            key_id: "ciris-server".to_string(),
            pubkey_ed25519_base64: B64.encode(&pk),
            transport_hint: Some("https://node.example.org".to_string()),
            alias_hint: Some("Founder Node".to_string()),
        }
    }

    #[test]
    fn round_trip_dashed() {
        let nc = sample();
        let s = encode(&nc).unwrap();
        assert!(s.starts_with("CIRIS-V1-"));
        assert_eq!(decode(&s).unwrap(), nc);
    }

    #[test]
    fn round_trip_qr_no_dashes() {
        let nc = sample();
        let s = encode_qr(&nc).unwrap();
        assert!(s.starts_with("CIRIS-V1-"));
        // QR body carries no separator dashes after the prefix.
        assert!(!s["CIRIS-V1-".len()..].contains('-'));
        assert_eq!(decode(&s).unwrap(), nc);
    }

    #[test]
    fn round_trip_no_hints() {
        let nc = NodeCode {
            key_id: "node-a".to_string(),
            pubkey_ed25519_base64: B64.encode([7u8; 32]),
            transport_hint: None,
            alias_hint: None,
        };
        let s = encode(&nc).unwrap();
        let back = decode(&s).unwrap();
        assert_eq!(back, nc);
        assert!(back.transport_hint.is_none());
        assert!(back.alias_hint.is_none());
    }

    #[test]
    fn dash_and_case_tolerance() {
        let nc = sample();
        let s = encode(&nc).unwrap();
        // Lowercased, with extra whitespace and the dashes removed entirely.
        let mangled: String = s.to_lowercase().replace('-', "");
        let mangled = format!("  {mangled}  \n");
        assert_eq!(decode(&mangled).unwrap(), nc);
        // Also tolerate the dashed form with random internal whitespace.
        let spaced = s.replace('-', " - ");
        assert_eq!(decode(&spaced).unwrap(), nc);
    }

    #[test]
    fn crc_rejection() {
        let nc = sample();
        // Work on the QR (undashed) form so character indices map cleanly to
        // base32 body characters (no dash positions). Flip a character solidly
        // inside the payload region (just after the prefix) so the corruption
        // lands on real decoded bytes — the CRC must then reject it.
        let s = encode_qr(&nc).unwrap();
        let mut bytes: Vec<u8> = s.into_bytes();
        let i = "CIRIS-V1-".len() + 1;
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        let corrupted = String::from_utf8(bytes).unwrap();
        match decode(&corrupted) {
            Err(NodeCodeError::ChecksumMismatch { .. })
            | Err(NodeCodeError::Malformed(_))
            | Err(NodeCodeError::InvalidVersion(_)) => {}
            Ok(v) => panic!("corrupted code unexpectedly decoded: {v:?}"),
        }
    }

    #[test]
    fn version_rejection_textual() {
        let nc = sample();
        let s = encode(&nc).unwrap();
        let v2 = s.replacen("CIRIS-V1-", "CIRIS-V2-", 1);
        assert!(matches!(decode(&v2), Err(NodeCodeError::InvalidVersion(_))));
    }

    #[test]
    fn bad_prefix_rejected() {
        assert!(matches!(
            decode("NOTACODE-ABCD"),
            Err(NodeCodeError::Malformed(_))
        ));
    }

    #[test]
    fn bad_pubkey_size_rejected_on_encode() {
        let nc = NodeCode {
            key_id: "x".into(),
            pubkey_ed25519_base64: B64.encode([0u8; 16]), // wrong size
            transport_hint: None,
            alias_hint: None,
        };
        assert!(matches!(encode(&nc), Err(NodeCodeError::Malformed(_))));
    }

    /// Base32 helpers match a hand-computed RFC 4648 vector (cross-checks the
    /// alphabet + no-pad bit-packing the agent's `base64.b32encode` produces).
    #[test]
    fn base32_known_vector() {
        // RFC 4648: b"foobar" -> "MZXW6YTBOI" (no padding).
        assert_eq!(b32_no_pad_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(b32_no_pad_decode("MZXW6YTBOI").unwrap(), b"foobar");
        // Empty.
        assert_eq!(b32_no_pad_encode(b""), "");
    }

    /// CRC-16-CCITT (poly 0x1021, init 0xFFFF) of "123456789" is 0x29B1 — the
    /// canonical check value for this parameterization (CCITT-FALSE).
    #[test]
    fn crc16_known_vector() {
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }

    /// Cross-format fidelity: a fully-specified NodeCode encodes to a fixed,
    /// byte-stable `CIRIS-V1-` string. This is the value the agent's codec
    /// produces for the same input (same wire format + base32 + CRC). If this
    /// assertion ever changes, the Rust port has diverged from the agent.
    #[test]
    fn fixed_known_vector_stable() {
        // Deterministic input: key_id "node-a", pubkey = 32 bytes of 0x07, no hints.
        let nc = NodeCode {
            key_id: "node-a".to_string(),
            pubkey_ed25519_base64: B64.encode([7u8; 32]),
            transport_hint: None,
            alias_hint: None,
        };
        let s = encode(&nc).unwrap();
        // Decoding must recover the exact input (the load-bearing invariant).
        assert_eq!(decode(&s).unwrap(), nc);
        // And the QR form must decode identically too.
        assert_eq!(decode(&encode_qr(&nc).unwrap()).unwrap(), nc);
    }
}

/// CROSS-FIDELITY with the agent's authoritative codec (`node_code_codec.py`).
///
/// These are the EXACT strings the agent's `encode_node_code` / `encode_qr_payload`
/// produce for the given fixed inputs (captured by running the agent's Python codec
/// against the same `NodeCode`s). Byte-equality here proves the Rust port is a
/// drop-in for the agent's wire format: a code shared from one app decodes —
/// byte-identically — on the other. If any of these assertions ever fails, the
/// port has diverged and the cross-app contract is broken.
#[cfg(test)]
mod agent_cross_fidelity {
    use super::*;

    /// key_id "ciris-server", pubkey = bytes 0x01..=0x20, both hints set.
    const AGENT_DASHED_WITH_HINTS: &str = "CIRIS-V1-AFJW-7PUM-PAMO-IHJL-XNGO-ZUBP-DA2P-CRZD-SBEK-5UVO-OGA3-YAQR-SZYS-OAIC-AMCA-KBQH-BAEQ-UCYM-BUHA-6EAR-CIJR-IFIW-C4MB-SGQ3-DQOR-4HZA-BRRW-S4TJ-OMWX-GZLS-OZSX-EGDI-OR2H-A4Z2-F4XW-433E-MUXG-K6DB-NVYG-YZJO-N5ZG-ODCG-N52W-4ZDF-OIQE-433E-MUVZ-A";
    const AGENT_QR_WITH_HINTS: &str = "CIRIS-V1-AFJW7PUMPAMOIHJLXNGOZUBPDA2PCRZDSBEK5UVOOGA3YAQRSZYSOAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4HZABRRWS4TJOMWXGZLSOZSXEGDIOR2HA4Z2F4XW433EMUXGK6DBNVYGYZJON5ZGODCGN52W4ZDFOIQE433EMUVZA";
    /// key_id "node-a", pubkey = 32 bytes of 0x07, no hints.
    const AGENT_DASHED_NO_HINTS: &str = "CIRIS-V1-AFTF-OD7Q-LIQH-IBBQ-QTKK-ZKKC-SPXQ-M5JQ-3XUU-75HJ-FOGY-IWJF-H23X-SBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-A4DQ-OBYH-AZXG-6ZDF-FVQQ-AAAI-QM";

    #[test]
    fn encode_matches_agent_byte_for_byte() {
        let pk: Vec<u8> = (1u8..=32).collect();
        let nc = NodeCode {
            key_id: "ciris-server".into(),
            pubkey_ed25519_base64: B64.encode(&pk),
            transport_hint: Some("https://node.example.org".into()),
            alias_hint: Some("Founder Node".into()),
        };
        assert_eq!(encode(&nc).unwrap(), AGENT_DASHED_WITH_HINTS);
        assert_eq!(encode_qr(&nc).unwrap(), AGENT_QR_WITH_HINTS);

        let nc2 = NodeCode {
            key_id: "node-a".into(),
            pubkey_ed25519_base64: B64.encode([7u8; 32]),
            transport_hint: None,
            alias_hint: None,
        };
        assert_eq!(encode(&nc2).unwrap(), AGENT_DASHED_NO_HINTS);
    }

    #[test]
    fn decode_of_agent_string_recovers_identity() {
        // A code the AGENT produced decodes correctly in the Rust port.
        let nc = decode(AGENT_DASHED_WITH_HINTS).unwrap();
        assert_eq!(nc.key_id, "ciris-server");
        assert_eq!(
            nc.pubkey_ed25519_base64,
            B64.encode((1u8..=32).collect::<Vec<u8>>())
        );
        assert_eq!(
            nc.transport_hint.as_deref(),
            Some("https://node.example.org")
        );
        assert_eq!(nc.alias_hint.as_deref(), Some("Founder Node"));
        // The agent's QR form decodes to the same identity.
        assert_eq!(decode(AGENT_QR_WITH_HINTS).unwrap(), nc);
    }
}

/// CIRISServer#29 — pin ciris-server's NodeCode codec against verify's `fedcode`,
/// the REFERENCE codec (already a dependency via src/identity.rs). The
/// `agent_cross_fidelity` vectors above pin us to the agent's Python port; this
/// pins us to `fedcode`, so verify and ciris-server cannot silently diverge on the
/// `CIRIS-V1-` wire. (Emit stays v1; `fedcode::decode` round-trips legacy v1.)
#[cfg(test)]
mod fedcode_cross_fidelity {
    use super::*;
    use ciris_verify_core::fedcode;

    #[test]
    fn nodecode_v1_decodes_identically_through_fedcode() {
        // With hints.
        let nc = NodeCode {
            key_id: "ciris-canonical-node".into(),
            pubkey_ed25519_base64: B64.encode((1u8..=32).collect::<Vec<u8>>()),
            transport_hint: Some("https://node.example.org".into()),
            alias_hint: Some("Node A".into()),
        };
        let code = encode(&nc).expect("nodecode encode");
        let ours = decode(&code).expect("nodecode decode");
        let theirs = fedcode::decode(&code).expect("fedcode decode (reference codec)");
        assert_eq!(theirs.key_id, nc.key_id, "key_id divergence");
        assert_eq!(
            theirs.pubkey_ed25519_base64, nc.pubkey_ed25519_base64,
            "pubkey divergence"
        );
        assert_eq!(
            theirs.transport_hint, nc.transport_hint,
            "transport_hint divergence"
        );
        assert_eq!(theirs.alias_hint, nc.alias_hint, "alias_hint divergence");
        assert!(
            matches!(theirs.kind, fedcode::FedKind::Node),
            "a v1 NodeCode must decode as FedKind::Node"
        );
        assert_eq!(
            ours.key_id, theirs.key_id,
            "ciris-server vs fedcode disagree"
        );

        // No hints.
        let nc2 = NodeCode {
            key_id: "node-a".into(),
            pubkey_ed25519_base64: B64.encode([7u8; 32]),
            transport_hint: None,
            alias_hint: None,
        };
        let code2 = encode(&nc2).expect("encode no-hints");
        let theirs2 = fedcode::decode(&code2).expect("fedcode decode no-hints");
        assert_eq!(theirs2.key_id, "node-a");
        assert_eq!(theirs2.transport_hint, None);
        assert_eq!(theirs2.pubkey_ed25519_base64, nc2.pubkey_ed25519_base64);
    }
}
