//! **The call frames socket, version 1** (CIRISServer#859, 0.5.246).
//!
//! `WS /v1/chat/{room}/call/frames` carries one frame per WebSocket binary
//! message, integers big-endian. The layout was agreed with the client
//! (CIRISClient `FSD/CSD/CSD-134-calls.md`, PR #287) and edge, and is pinned by
//! golden vectors both sides test: `tests/vectors/call_frames_v1.json`.
//!
//! ```text
//! client → node: ver u8 (=1) | codec_id u8 | spatial u8 | temporal u8 | quality u8 | payload…
//! node → client: ver u8 (=1) | codec_id u8 | spatial u8 | temporal u8 | quality u8
//!                | pub_len u16 | publisher[pub_len] (UTF-8 key_id) | stream_id[32]
//!                | epoch u64 | chunk_seq u64 | source_ts_ms u64
//!                | flags u8 | frame_seq u32 | payload…
//! ```
//!
//! `source_ts_ms` is the publisher's signed capture time (edge v45), for lip
//! sync. `frame_seq` is the publisher's per-codec-class frame counter, present
//! on video and other non-audio frames (`flags` bit 0; `frame_seq` is 0 when
//! absent), so a client tells a lost video frame from lost audio. Fixed width,
//! so a wrapping counter never collides with a sentinel. Other `flags` bits are
//! reserved and written 0.
//!
//! Audio is `codec_id 0xFF` (edge's `CODEC_OPAQUE`) at layer (0,0,0) carrying one
//! Opus packet: 48 kHz, mono, 20 ms. Video passes `codec_id` through unchanged;
//! which video codec is open with Eric and the CC, so this layer pins no video
//! rule. A leading version byte means a v2 is refused by name, not misparsed.

/// The only version this module reads or writes.
pub const VERSION: u8 = 1;
/// Edge's codec-opaque id: audio in v1.
pub const CODEC_OPAQUE: u8 = 0xFF;
/// The longest publisher key id a frame may name.
pub const MAX_PUBLISHER: usize = 256;

const HEADER: usize = 5;

/// A frame the client sends to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub codec_id: u8,
    pub layer: (u8, u8, u8),
    pub payload: Vec<u8>,
}

/// A frame the node hands the client: whose stream it is, and where in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub codec_id: u8,
    pub layer: (u8, u8, u8),
    pub publisher: String,
    pub stream_id: [u8; 32],
    pub epoch: u64,
    pub chunk_seq: u64,
    /// The publisher's signed capture time, ms since the Unix epoch.
    pub source_ts_ms: u64,
    /// The publisher's per-codec-class frame counter; `None` on audio.
    pub frame_seq: Option<u32>,
    pub payload: Vec<u8>,
}

/// `flags` bit 0: `frame_seq` is present.
const FLAG_FRAME_SEQ: u8 = 0b1;

/// Why a frame was refused. The token is what the socket reports in its
/// `publish_refused` text event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    UnsupportedVersion,
    Truncated,
    OpaqueLayerNotBase,
    PublisherTooLong,
    PublisherNotUtf8,
}

impl FrameError {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::Truncated => "truncated",
            Self::OpaqueLayerNotBase => "opaque_layer_not_base",
            Self::PublisherTooLong => "publisher_too_long",
            Self::PublisherNotUtf8 => "publisher_not_utf8",
        }
    }
}

fn header(buf: &[u8]) -> Result<(u8, (u8, u8, u8)), FrameError> {
    if buf.len() < HEADER {
        return Err(FrameError::Truncated);
    }
    if buf[0] != VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    let layer = (buf[2], buf[3], buf[4]);
    if buf[1] == CODEC_OPAQUE && layer != (0, 0, 0) {
        return Err(FrameError::OpaqueLayerNotBase);
    }
    Ok((buf[1], layer))
}

/// Read a client → node frame.
///
/// # Errors
/// [`FrameError`] naming what is wrong with it.
pub fn decode_outgoing(buf: &[u8]) -> Result<Outgoing, FrameError> {
    let (codec_id, layer) = header(buf)?;
    Ok(Outgoing {
        codec_id,
        layer,
        payload: buf[HEADER..].to_vec(),
    })
}

/// Write a client → node frame (the client's half; the node never sends one).
#[must_use]
pub fn encode_outgoing(f: &Outgoing) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + f.payload.len());
    out.extend_from_slice(&[VERSION, f.codec_id, f.layer.0, f.layer.1, f.layer.2]);
    out.extend_from_slice(&f.payload);
    out
}

/// Write a node → client frame.
///
/// # Errors
/// [`FrameError::PublisherTooLong`] past [`MAX_PUBLISHER`] bytes.
pub fn encode_incoming(f: &Incoming) -> Result<Vec<u8>, FrameError> {
    let pub_bytes = f.publisher.as_bytes();
    if pub_bytes.len() > MAX_PUBLISHER {
        return Err(FrameError::PublisherTooLong);
    }
    let len = u16::try_from(pub_bytes.len()).map_err(|_| FrameError::PublisherTooLong)?;
    let mut out = Vec::with_capacity(HEADER + 2 + pub_bytes.len() + 32 + 29 + f.payload.len());
    out.extend_from_slice(&[VERSION, f.codec_id, f.layer.0, f.layer.1, f.layer.2]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pub_bytes);
    out.extend_from_slice(&f.stream_id);
    out.extend_from_slice(&f.epoch.to_be_bytes());
    out.extend_from_slice(&f.chunk_seq.to_be_bytes());
    out.extend_from_slice(&f.source_ts_ms.to_be_bytes());
    out.push(if f.frame_seq.is_some() {
        FLAG_FRAME_SEQ
    } else {
        0
    });
    out.extend_from_slice(&f.frame_seq.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&f.payload);
    Ok(out)
}

/// Read a node → client frame (the client's half; the node's tests use it to
/// check its own writes).
///
/// # Errors
/// [`FrameError`] naming what is wrong with it.
pub fn decode_incoming(buf: &[u8]) -> Result<Incoming, FrameError> {
    let (codec_id, layer) = header(buf)?;
    let mut at = HEADER;
    let take = |at: &mut usize, n: usize| -> Result<&[u8], FrameError> {
        let end = at.checked_add(n).ok_or(FrameError::Truncated)?;
        let s = buf.get(*at..end).ok_or(FrameError::Truncated)?;
        *at = end;
        Ok(s)
    };
    let len = usize::from(u16::from_be_bytes(
        take(&mut at, 2)?
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
    ));
    if len > MAX_PUBLISHER {
        return Err(FrameError::PublisherTooLong);
    }
    let publisher = std::str::from_utf8(take(&mut at, len)?)
        .map_err(|_| FrameError::PublisherNotUtf8)?
        .to_owned();
    let stream_id: [u8; 32] = take(&mut at, 32)?
        .try_into()
        .map_err(|_| FrameError::Truncated)?;
    let epoch = u64::from_be_bytes(
        take(&mut at, 8)?
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
    );
    let chunk_seq = u64::from_be_bytes(
        take(&mut at, 8)?
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
    );
    let source_ts_ms = u64::from_be_bytes(
        take(&mut at, 8)?
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
    );
    let flags = take(&mut at, 1)?[0];
    let seq = u32::from_be_bytes(
        take(&mut at, 4)?
            .try_into()
            .map_err(|_| FrameError::Truncated)?,
    );
    Ok(Incoming {
        codec_id,
        layer,
        publisher,
        stream_id,
        epoch,
        chunk_seq,
        source_ts_ms,
        frame_seq: (flags & FLAG_FRAME_SEQ != 0).then_some(seq),
        payload: buf[at..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/call_frames_v1.json"
        ))
        .expect("the golden vectors");
        serde_json::from_str(&raw).expect("vectors are JSON")
    }

    fn hex_of(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap_or_default()).expect("hex")
    }

    fn layer_of(v: &serde_json::Value) -> (u8, u8, u8) {
        let l: Vec<u8> = v["layer"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as u8)
            .collect();
        (l[0], l[1], l[2])
    }

    /// The bytes both sides pin: every valid vector decodes to its fields and
    /// re-encodes to the same bytes, and every invalid one is refused by name.
    #[test]
    fn the_golden_vectors_hold_both_ways() {
        let v = vectors();
        assert_eq!(v["audio_payload"], "opus/48000/1/20ms");
        for c in v["client_to_node"].as_array().unwrap() {
            let bytes = hex_of(c, "hex");
            let f = decode_outgoing(&bytes).unwrap_or_else(|e| panic!("{}: {e:?}", c["name"]));
            assert_eq!(u64::from(f.codec_id), c["codec_id"].as_u64().unwrap());
            assert_eq!(f.layer, layer_of(c));
            assert_eq!(f.payload, hex_of(c, "payload_hex"));
            assert_eq!(encode_outgoing(&f), bytes, "{}", c["name"]);
        }
        for c in v["client_to_node_invalid"].as_array().unwrap() {
            let err = decode_outgoing(&hex_of(c, "hex")).unwrap_err();
            assert_eq!(err.token(), c["error"].as_str().unwrap(), "{}", c["name"]);
        }
        for c in v["node_to_client"].as_array().unwrap() {
            let bytes = hex_of(c, "hex");
            let f = decode_incoming(&bytes).unwrap_or_else(|e| panic!("{}: {e:?}", c["name"]));
            assert_eq!(f.publisher, c["publisher"].as_str().unwrap());
            assert_eq!(f.stream_id.to_vec(), hex_of(c, "stream_id_hex"));
            assert_eq!(f.epoch, c["epoch"].as_u64().unwrap());
            assert_eq!(f.chunk_seq, c["chunk_seq"].as_u64().unwrap());
            assert_eq!(f.source_ts_ms, c["source_ts_ms"].as_u64().unwrap());
            assert_eq!(
                f.frame_seq.map(u64::from),
                c["frame_seq"].as_u64(),
                "{}",
                c["name"]
            );
            assert_eq!(f.layer, layer_of(c));
            assert_eq!(f.payload, hex_of(c, "payload_hex"));
            assert_eq!(encode_incoming(&f).unwrap(), bytes, "{}", c["name"]);
        }
        for c in v["node_to_client_invalid"].as_array().unwrap() {
            let err = decode_incoming(&hex_of(c, "hex")).unwrap_err();
            assert_eq!(err.token(), c["error"].as_str().unwrap(), "{}", c["name"]);
        }
    }

    /// The audio vector is a real Opus packet: one 20 ms frame, mono.
    #[test]
    fn the_audio_vector_is_one_twenty_ms_mono_opus_packet() {
        let v = vectors();
        let payload = hex_of(&v["client_to_node"][0], "payload_hex");
        let toc = payload[0];
        // RFC 6716 §3.1: config 12..=15 is hybrid; 15 is FB 20 ms. s = 0 mono. c = 0 one frame.
        assert_eq!(toc >> 3, 15, "hybrid full-band 20 ms");
        assert_eq!((toc >> 2) & 1, 0, "mono");
        assert_eq!(toc & 0b11, 0, "one frame");
    }

    #[test]
    fn an_over_long_publisher_is_never_written() {
        let f = Incoming {
            codec_id: CODEC_OPAQUE,
            layer: (0, 0, 0),
            publisher: "a".repeat(MAX_PUBLISHER + 1),
            stream_id: [0; 32],
            epoch: 0,
            chunk_seq: 0,
            source_ts_ms: 0,
            frame_seq: None,
            payload: vec![],
        };
        assert_eq!(encode_incoming(&f), Err(FrameError::PublisherTooLong));
    }
}
