//! The drive's write gate and media policy (CIRISServer#642 / #643; CC 3.3.13,
//! CC 5.3.2.6; the client's `FSD/MEDIA_EDGE.md` §3).
//!
//! **The node is the first consumer of an uploaded file's bytes.** Every peer
//! and every device downstream inherits the row's `media_type` and `filename`,
//! so a lie told here is told everywhere. Before 0.5.217 `POST /v1/files`
//! stored both exactly as sent: no RFC 6838 check, no sniff, no RFC 6266
//! cleanup — a name like `invoice\u{202E}txt.exe` replicated as written.
//!
//! This module is pure functions over a string and the leading bytes. No
//! decoder runs here: decoding, re-encoding and renditions are the ingest
//! pipeline (#614). The gate only refuses a file that says it is one thing
//! and is another, and names what it found.
//!
//! The sniff table is the client's (`RenderTier.kt`: masked prefix + `ftyp`
//! brand, sniffed == declared) so the node refuses at write exactly what a
//! client would refuse to render. The same table is CIRISEdge#638 item 1's.

/// Why a declared media type was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeRefusal {
    /// Not an RFC 6838 `type/subtype` essence.
    BadEssence(String),
    /// The leading bytes are a different format than the declared one.
    Mismatch {
        /// The declared essence (normalised).
        declared: String,
        /// What the bytes are, or `"unrecognised"` when the declared type is
        /// one this table can recognise and the bytes are not it.
        sniffed: String,
    },
}

/// RFC 6838 §4.2 top-level types this node admits.
const TOP_LEVEL: &[&str] = &[
    "application",
    "audio",
    "font",
    "haptics",
    "image",
    "message",
    "model",
    "multipart",
    "text",
    "video",
];

fn restricted_name(s: &str) -> bool {
    // RFC 6838 §4.2 restricted-name: 1*127 of ALPHA / DIGIT / ! # $ & - ^ _ . +
    // and it must start with ALPHA / DIGIT.
    !s.is_empty()
        && s.len() <= 127
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
}

/// Parse a declared media type to its RFC 6838 essence: lower-cased
/// `type/subtype`, parameters dropped (a `codecs` parameter is the ingest
/// pipeline's business, not this gate's).
pub fn parse_essence(declared: &str) -> Result<String, TypeRefusal> {
    let bare = declared.split(';').next().unwrap_or("").trim();
    let Some((ty, sub)) = bare.split_once('/') else {
        return Err(TypeRefusal::BadEssence(declared.to_owned()));
    };
    let (ty, sub) = (ty.to_ascii_lowercase(), sub.to_ascii_lowercase());
    if !TOP_LEVEL.contains(&ty.as_str()) || !restricted_name(&ty) || !restricted_name(&sub) {
        return Err(TypeRefusal::BadEssence(declared.to_owned()));
    }
    Ok(format!("{ty}/{sub}"))
}

/// What the leading bytes are, when this table knows. Reads at most the first
/// 2 KiB — a prefix, never a decode.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    let b = &bytes[..bytes.len().min(2048)];
    let starts = |p: &[u8]| b.starts_with(p);
    if starts(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if starts(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if starts(b"GIF87a") || starts(b"GIF89a") {
        return Some("image/gif");
    }
    if b.len() >= 12 && &b[..4] == b"RIFF" {
        match &b[8..12] {
            b"WEBP" => return Some("image/webp"),
            b"WAVE" => return Some("audio/wav"),
            b"AVI " => return Some("video/x-msvideo"),
            _ => {}
        }
    }
    if b.len() >= 12 && &b[4..8] == b"ftyp" {
        let brand = &b[8..12];
        return Some(match brand {
            b"heic" | b"heix" | b"hevc" | b"hevx" => "image/heic",
            b"mif1" | b"msf1" => "image/heif",
            b"avif" | b"avis" => "image/avif",
            b"qt  " => "video/quicktime",
            b"M4A " | b"M4B " => "audio/mp4",
            _ => "video/mp4",
        });
    }
    if starts(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return Some("video/webm");
    }
    if starts(b"OggS") {
        return Some("audio/ogg");
    }
    if starts(b"fLaC") {
        return Some("audio/flac");
    }
    if starts(b"ID3") || (b.len() >= 2 && b[0] == 0xFF && (b[1] & 0xE6) == 0xE2) {
        return Some("audio/mpeg");
    }
    if starts(b"%PDF-") {
        return Some("application/pdf");
    }
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") {
        return Some("application/zip");
    }
    if starts(&[0x1F, 0x8B]) {
        return Some("application/gzip");
    }
    if starts(b"BM") && b.len() >= 14 {
        return Some("image/bmp");
    }
    if starts(b"II*\0") || starts(b"MM\0*") {
        return Some("image/tiff");
    }
    if starts(&[0x00, 0x00, 0x01, 0x00]) {
        return Some("image/x-icon");
    }
    if starts(b"MZ") {
        return Some("application/vnd.microsoft.portable-executable");
    }
    if starts(&[0x7F, b'E', b'L', b'F']) {
        return Some("application/x-elf");
    }
    None
}

/// Declared essences a sniffed family legitimately covers — one container,
/// several honest names (an Office document IS a zip; an audio-only MP4 is
/// still `ftyp`).
fn compatible(declared: &str, sniffed: &str) -> bool {
    if declared == sniffed {
        return true;
    }
    match sniffed {
        "application/zip" => {
            declared.ends_with("+zip")
                || declared.starts_with("application/vnd.openxmlformats-officedocument.")
                || declared.starts_with("application/vnd.oasis.opendocument.")
                || matches!(
                    declared,
                    "application/epub+zip"
                        | "application/java-archive"
                        | "application/x-zip-compressed"
                )
        }
        "video/mp4" => matches!(
            declared,
            "audio/mp4" | "video/3gpp" | "video/x-m4v" | "audio/x-m4a"
        ),
        "audio/mp4" => matches!(declared, "video/mp4" | "audio/x-m4a"),
        "image/heif" => declared == "image/heic",
        "image/heic" => declared == "image/heif",
        "video/webm" => matches!(
            declared,
            "audio/webm" | "video/x-matroska" | "audio/x-matroska"
        ),
        "audio/wav" => matches!(declared, "audio/x-wav" | "audio/wave" | "audio/vnd.wave"),
        "audio/ogg" => matches!(declared, "video/ogg" | "application/ogg"),
        "audio/flac" => declared == "audio/x-flac",
        "application/gzip" => declared == "application/x-gzip",
        "image/x-icon" => declared == "image/vnd.microsoft.icon",
        _ => false,
    }
}

/// The honesty check: parse the declared type and require the bytes to be
/// what it says. `application/octet-stream` is an honest "I don't know" and
/// is accepted for bytes this table does not recognise, never for bytes it
/// does (a JPEG declared as octet-stream is re-declared by the caller, not
/// smuggled). `text/*` must be valid UTF-8 with no NUL.
///
/// Returns the normalised essence to store.
pub fn check_format(declared: &str, bytes: &[u8]) -> Result<String, TypeRefusal> {
    let essence = parse_essence(declared)?;
    let sniffed = sniff(bytes);
    if let Some(s) = sniffed {
        if !compatible(&essence, s) {
            return Err(TypeRefusal::Mismatch {
                declared: essence,
                sniffed: s.to_owned(),
            });
        }
        return Ok(essence);
    }
    // Nothing recognised. A declared type this table CAN recognise is a lie.
    if RECOGNISABLE.contains(&essence.as_str()) {
        return Err(TypeRefusal::Mismatch {
            declared: essence,
            sniffed: "unrecognised".to_owned(),
        });
    }
    if essence.starts_with("text/") {
        let head = &bytes[..bytes.len().min(64 * 1024)];
        // A multi-byte sequence cut at the 64 KiB boundary is not a lie.
        let valid = match std::str::from_utf8(head) {
            Ok(_) => true,
            Err(e) => e.error_len().is_none() && head.len() == 64 * 1024,
        };
        if !valid || head.contains(&0) {
            return Err(TypeRefusal::Mismatch {
                declared: essence,
                sniffed: "binary".to_owned(),
            });
        }
    }
    Ok(essence)
}

/// Every essence [`sniff`] can name — declaring one of these for bytes it does
/// not recognise is a mismatch, not an unknown.
const RECOGNISABLE: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/heic",
    "image/heif",
    "image/avif",
    "image/bmp",
    "image/tiff",
    "audio/wav",
    "audio/mp4",
    "audio/mpeg",
    "audio/ogg",
    "audio/flac",
    "video/mp4",
    "video/quicktime",
    "video/webm",
    "application/pdf",
    "application/zip",
    "application/gzip",
];

/// Characters that change how a name READS without changing what it is:
/// C0/C1 controls, bidi embeddings / overrides / isolates / marks, and
/// zero-width formatting. CC 3.3.13: `name` is display-only.
fn is_hostile(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// RFC 6266 §4.3 cleanup of a display filename: keep only the last path
/// component, drop hostile characters, trim, and cap at 255 bytes on a char
/// boundary. Returns `None` when nothing displayable is left (the caller
/// refuses with `drive.bad_filename`), and whether anything changed.
pub fn sanitize_filename(name: &str) -> Option<(String, bool)> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut out: String = last.chars().filter(|c| !is_hostile(*c)).collect();
    out = out.trim().trim_matches('.').trim().to_owned();
    if out.len() > 255 {
        let mut cut = 255;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    if out.is_empty() {
        return None;
    }
    let changed = out != name;
    Some((out, changed))
}

/// `GET /v1/media/policy` — this node's render policy, published ahead of the
/// ingest pipeline (#643). The table is the client's `FSD/MEDIA_EDGE.md` §3
/// (CC 5.3.2.6's recommended set); an operator narrowing is a later knob.
/// `renditions: false` says no rendition will come, so a client can say "no
/// preview on this node" instead of waiting.
pub fn policy() -> serde_json::Value {
    const MB: u64 = 1_000_000;
    serde_json::json!({
        "policy_version": 1,
        "source": "CC 5.3.2.6 recommended set, as tabulated in CIRISClient FSD/MEDIA_EDGE.md §3",
        "tier_a": {
            "image/jpeg": {"max_bytes": 16 * MB, "max_pixels": 33_000_000},
            "image/png": {"max_bytes": 16 * MB, "max_pixels": 33_000_000, "reject_trailing_after_iend": true},
            "image/webp": {"max_bytes": 10 * MB, "conditional": "webpsan + re-encode on ingest (#614)"},
            "image/gif": {"max_bytes": 25 * MB, "max_pixels": 921_600},
            "text/plain": {"max_bytes": MB, "utf8_only": true, "bidi_rendered_visibly": true},
            "video/mp4": {"max_bytes": 100 * MB, "max_width": 3840, "max_height": 2160,
                          "codecs": ["avc1 (<= L4.1)", "mp4a.40.2"], "conditional": "mp4san on ingest (#614)"},
            "audio/mp4": {"max_bytes": 16 * MB},
            "audio/mpeg": {"conditional": "ID3v2 ignored; APIC never decoded"},
        },
        "tier_b_convert_at_sender": [
            "image/avif", "image/heic", "image/heif", "image/jxl",
            "video/webm", "video/quicktime", "video/x-matroska",
            "audio/ogg", "audio/flac", "audio/wav", "audio/aac",
        ],
        "tier_b_rasterise_on_node": ["image/svg+xml"],
        "tier_c_download": ["application/pdf", "model/gltf-binary", "model/vnd.usdz+zip"],
        "tier_c_refuse": "everything else: a generic file card, and a dangerous-extension block on save",
        "write_gate": {
            "declared_type": "RFC 6838 essence required (drive.bad_media_type)",
            "sniff": "leading bytes must be the declared format (drive.format_mismatch {declared, sniffed})",
            "filename": "RFC 6266 §4.3: last path component, controls/bidi/zero-width removed (drive.bad_filename when nothing is left)",
        },
        "inline_max_bytes": 1024 * 1024,
        "whole_read_max_bytes": crate::drive::WHOLE_READ_CAP,
        "renditions": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn essence_parses_and_normalises() {
        assert_eq!(parse_essence("Image/JPEG; q=1").unwrap(), "image/jpeg");
        assert!(parse_essence("jpeg").is_err());
        assert!(parse_essence("image/").is_err());
        assert!(parse_essence("bogus/type").is_err());
        assert!(parse_essence("image/j peg").is_err());
    }

    #[test]
    fn sniff_equals_declared_or_refuses() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0];
        assert_eq!(check_format("image/jpeg", &jpeg).unwrap(), "image/jpeg");
        assert_eq!(
            check_format("image/png", &jpeg),
            Err(TypeRefusal::Mismatch {
                declared: "image/png".into(),
                sniffed: "image/jpeg".into()
            })
        );
        // A recognisable type declared over unrecognised bytes is a lie.
        assert!(matches!(
            check_format("image/png", b"hello"),
            Err(TypeRefusal::Mismatch { .. })
        ));
        // An executable declared as a document.
        assert!(matches!(
            check_format("application/pdf", b"MZ\x90\x00"),
            Err(TypeRefusal::Mismatch { .. })
        ));
        // Office is a zip; audio-only MP4 is ftyp.
        assert!(check_format(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            b"PK\x03\x04rest"
        )
        .is_ok());
        let mut m4a = vec![0, 0, 0, 0x20];
        m4a.extend_from_slice(b"ftypM4A ");
        assert_eq!(check_format("audio/mp4", &m4a).unwrap(), "audio/mp4");
        // Text must be text.
        assert!(check_format("text/plain", "hello, world".as_bytes()).is_ok());
        assert!(check_format("text/plain", b"hi\0there").is_err());
        // Honest unknown.
        assert!(check_format("application/octet-stream", b"\x01\x02").is_ok());
        assert!(check_format("application/octet-stream", &jpeg).is_err());
    }

    #[test]
    fn filenames_lose_paths_controls_and_bidi() {
        let (n, changed) = sanitize_filename("invoice\u{202E}txt.exe").unwrap();
        assert_eq!(n, "invoicetxt.exe");
        assert!(changed);
        assert_eq!(sanitize_filename("../../etc/passwd").unwrap().0, "passwd");
        assert_eq!(
            sanitize_filename("C:\\Users\\me\\a.jpg").unwrap().0,
            "a.jpg"
        );
        assert_eq!(
            sanitize_filename("a\u{0000}b\u{200B}.png").unwrap().0,
            "ab.png"
        );
        assert_eq!(
            sanitize_filename("photo.jpg").unwrap(),
            ("photo.jpg".into(), false)
        );
        assert!(sanitize_filename("\u{202E}").is_none());
        assert!(sanitize_filename("..").is_none());
        let long = "é".repeat(200);
        assert!(sanitize_filename(&long).unwrap().0.len() <= 255);
    }
}
