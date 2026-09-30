//! **A streaming `multipart/form-data` reader (RFC 7578) — the upload form,
//! read one frame at a time** (0.5.218).
//!
//! Before 0.5.218 the drive buffered the WHOLE request body and sliced parts
//! out of it, which is what capped an upload at persist's 64 MiB whole-read
//! cap: the node could only take what it was willing to hold. Edge v36.1.0's
//! `files::publish_stream` (CIRISEdge#744) seals from a READER, chunk by chunk,
//! so the only thing standing between a phone's 1 GiB video and the drive was
//! this parser. This one never holds more than one body frame plus a
//! delimiter's worth of look-behind.
//!
//! # The shape it accepts, and why the file comes LAST
//!
//! Form fields (`cohort`, `room_id`, `media_type`, `filename`, `size`) are
//! read whole — each is bounded by [`FIELD_CAP`] — and the file part is NOT:
//! its bytes are handed to the seal as they arrive. Once they are, the
//! handler has committed to a room, a type and a length, so every field it
//! needs must already be in hand. A field AFTER the file would arrive after
//! the decision it was meant to inform, so it is refused by name
//! ([`Failure::FieldAfterFile`]) rather than ignored — and refused BEFORE the
//! file's reader reports end-of-file, which is before edge seals the stream
//! (it seals only on the reader's EOF), so the refusal leaves no row.
//! A browser's `FormData` sends parts in insertion order, so "append the file
//! last" is the whole client-side rule.
//!
//! # The delimiter trick
//!
//! RFC 2046 §5.1.1 defines every delimiter as `CRLF "--" boundary`, the CRLF
//! belonging to the delimiter, not the part before it. The FIRST delimiter
//! may have no preceding CRLF (it may open the body), so the reader seeds its
//! buffer with one: every delimiter, first included, is then the same needle,
//! and a CRLF inside a part's bytes can never end it — only CRLF followed by
//! `--boundary` does.
//!
//! # Look-behind
//!
//! A frame boundary may split the delimiter. Bytes are released to the caller
//! only once no delimiter can START among them: while no match is found, the
//! last `delimiter.len() - 1` bytes of the buffer are held back until the next
//! frame decides them.

use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Bytes;
use futures_util::Stream;

/// The body, as frames. Errors are the transport's, rendered.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>>;

/// The largest form FIELD (not the file) this reader will hold. Every field
/// the drive reads is an id, a token, a media type or a filename — 16 KiB is
/// far above any honest one and far below anything that could be used to
/// make the node buffer a file under a field's name.
pub const FIELD_CAP: usize = 16 * 1024;

/// The largest part-header block. Same reasoning as [`FIELD_CAP`].
const HEADER_CAP: usize = 16 * 1024;

/// Why the body could not be read as the upload form. Each arm has a
/// different remedy, so the handler maps each to its own refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The body passed the route's ceiling (`limit` bytes).
    TooLarge {
        /// The ceiling that was passed.
        limit: u64,
    },
    /// A part followed the file part. See the module doc.
    FieldAfterFile,
    /// The body ended before its closing delimiter — a client that stopped
    /// sending, or a connection that dropped.
    Truncated,
    /// Not the multipart shape: a missing boundary, a header block without
    /// its terminator, a field above [`FIELD_CAP`].
    Malformed(String),
    /// The transport failed while the body was being read.
    Transport(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "the body passed this route's {limit}-byte ceiling")
            }
            Self::FieldAfterFile => f.write_str(
                "a form part follows the `file` part — every field must precede the file, which \
                 is streamed to the seal as it arrives",
            ),
            Self::Truncated => f.write_str("the body ended before its closing multipart delimiter"),
            Self::Malformed(d) => write!(f, "malformed multipart body: {d}"),
            Self::Transport(d) => write!(f, "reading the request body failed: {d}"),
        }
    }
}

/// One part's headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartHead {
    /// `Content-Disposition` `name`.
    pub name: String,
    /// `Content-Disposition` `filename`, when the part is a file.
    pub filename: Option<String>,
    /// The part's own `Content-Type`.
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Before the first delimiter (a preamble, if any, is discarded).
    Preamble,
    /// Just past a delimiter: `--` closes the body, CRLF opens a part.
    AfterDelimiter,
    /// Inside a part's bytes.
    InPart,
    /// Past the closing delimiter. Anything after it is epilogue, never read.
    Closed,
}

/// The reader. See the module doc.
pub struct Multipart {
    stream: ByteStream,
    buf: Vec<u8>,
    /// Consumed prefix of `buf`.
    pos: usize,
    /// `CRLF -- boundary`.
    delim: Vec<u8>,
    /// Absolute index in `buf` below which no delimiter starts (a search
    /// cache, so small reads do not rescan the same bytes).
    clean_until: usize,
    read: u64,
    limit: u64,
    ended: bool,
    state: State,
    failure: Option<Failure>,
}

/// The `boundary` parameter of a `multipart/form-data` content type.
pub fn boundary(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (k, v) = param.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim().trim_matches('"');
            (!v.is_empty()).then(|| v.to_owned())
        } else {
            None
        }
    })
}

/// A `Content-Disposition` parameter, quotes stripped.
fn disposition_param(value: &str, key: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|param| {
        let (k, v) = param.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().trim_matches('"').to_owned())
    })
}

/// First index `>= from` where `needle` starts in `hay`. A first-byte scan,
/// then a compare — the needle starts with CR, which is rare in most bytes.
fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let first = *needle.first()?;
    let mut at = from;
    while at + needle.len() <= hay.len() {
        let rel = hay[at..=hay.len() - needle.len()]
            .iter()
            .position(|&b| b == first)?;
        let i = at + rel;
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        at = i + 1;
    }
    None
}

impl Multipart {
    /// A reader over `stream`, refusing past `limit` body bytes.
    pub fn new(stream: ByteStream, boundary: &str, limit: u64) -> Self {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary.as_bytes());
        Self {
            stream,
            // The seeded CRLF: see "The delimiter trick".
            buf: b"\r\n".to_vec(),
            pos: 0,
            delim,
            clean_until: 0,
            read: 0,
            limit,
            ended: false,
            state: State::Preamble,
            failure: None,
        }
    }

    /// Why reading stopped, when it did. The handler reads this after a
    /// failed seal: edge renders a reader error as prose inside
    /// `FileError::Read`, and the typed cause is here.
    pub fn failure(&self) -> Option<&Failure> {
        self.failure.as_ref()
    }

    fn fail(&mut self, f: Failure) -> Failure {
        self.failure.get_or_insert(f).clone()
    }

    /// One more frame into the buffer. `Ok(false)` at the end of the body.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Failure>> {
        if let Some(f) = &self.failure {
            return Poll::Ready(Err(f.clone()));
        }
        if self.ended {
            return Poll::Ready(Ok(false));
        }
        match self.stream.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(Ok(false))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(self.fail(Failure::Transport(e)))),
            Poll::Ready(Some(Ok(frame))) => {
                self.read = self.read.saturating_add(frame.len() as u64);
                if self.read > self.limit {
                    return Poll::Ready(Err(self.fail(Failure::TooLarge { limit: self.limit })));
                }
                // Compact before growing: the consumed prefix is dead.
                if self.pos > 0 {
                    self.buf.drain(..self.pos);
                    self.clean_until = self.clean_until.saturating_sub(self.pos);
                    self.pos = 0;
                }
                self.buf.extend_from_slice(&frame);
                Poll::Ready(Ok(true))
            }
        }
    }

    async fn fill(&mut self) -> Result<bool, Failure> {
        std::future::poll_fn(|cx| self.poll_fill(cx)).await
    }

    /// Where the next delimiter starts, searching only bytes not already
    /// known clean.
    fn next_delim(&mut self) -> Option<usize> {
        let from = self.clean_until.max(self.pos);
        match find(&self.buf, &self.delim, from) {
            Some(i) => {
                self.clean_until = i;
                Some(i)
            }
            None => {
                self.clean_until = self
                    .buf
                    .len()
                    .saturating_sub(self.delim.len() - 1)
                    .max(self.pos);
                None
            }
        }
    }

    /// The next part's headers, or `None` past the closing delimiter.
    ///
    /// Must not be called while a part's bytes are unread except for a part
    /// this reader was told to skip; the drive reads every field whole, and
    /// the file is always the last part.
    pub async fn next_part(&mut self) -> Result<Option<PartHead>, Failure> {
        loop {
            match self.state {
                State::Closed => return Ok(None),
                State::Preamble | State::InPart => {
                    // Skip to the next delimiter (the preamble, or an unread
                    // part the caller chose not to read).
                    if let Some(i) = self.next_delim() {
                        self.pos = i + self.delim.len();
                        self.state = State::AfterDelimiter;
                        continue;
                    }
                    self.pos = self.clean_until;
                    if !self.fill().await? {
                        return Err(self.fail(if self.state == State::Preamble {
                            Failure::Malformed("the body does not contain its boundary".into())
                        } else {
                            Failure::Truncated
                        }));
                    }
                }
                State::AfterDelimiter => {
                    if self.buf.len() - self.pos < 2 {
                        if !self.fill().await? {
                            return Err(self.fail(Failure::Truncated));
                        }
                        continue;
                    }
                    if self.buf[self.pos..].starts_with(b"--") {
                        self.state = State::Closed;
                        return Ok(None);
                    }
                    return self.part_headers().await.map(Some);
                }
            }
        }
    }

    /// Past `CRLF`, the header block up to the blank line.
    async fn part_headers(&mut self) -> Result<PartHead, Failure> {
        // RFC 2046 permits transport padding (LWSP) before the CRLF.
        let head_end = loop {
            let start = self.pos;
            let lwsp = self.buf[start..]
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            if self.buf.len() >= start + lwsp + 2 {
                if &self.buf[start + lwsp..start + lwsp + 2] != b"\r\n" {
                    return Err(self.fail(Failure::Malformed("malformed delimiter line".into())));
                }
                // Search from the delimiter line's own CRLF, so a part with NO
                // headers (CRLF CRLF straight away) is found too.
                if let Some(i) = find(&self.buf, b"\r\n\r\n", start + lwsp) {
                    break (start + lwsp + 2, i);
                }
            }
            if self.buf.len() - start > HEADER_CAP {
                return Err(self.fail(Failure::Malformed("part headers too long".into())));
            }
            if !self.fill().await? {
                return Err(self.fail(Failure::Truncated));
            }
        };
        let (from, to) = head_end;
        let text = std::str::from_utf8(&self.buf[from.min(to)..to])
            .map_err(|_| Failure::Malformed("part headers are not UTF-8".into()));
        let text = match text {
            Ok(t) => t.to_owned(),
            Err(e) => return Err(self.fail(e)),
        };
        let mut head = PartHead::default();
        let mut named = false;
        for line in text.split("\r\n") {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            if k.trim().eq_ignore_ascii_case("content-disposition") {
                if let Some(n) = disposition_param(v, "name") {
                    head.name = n;
                    named = true;
                }
                head.filename = disposition_param(v, "filename");
            } else if k.trim().eq_ignore_ascii_case("content-type") {
                head.content_type = Some(v.trim().to_owned());
            }
        }
        if !named {
            return Err(self.fail(Failure::Malformed("a part has no `name`".into())));
        }
        self.pos = to + 4;
        self.clean_until = self.pos;
        self.state = State::InPart;
        Ok(head)
    }

    /// Copy the current part's next bytes into `out`. `Ok(0)` at the part's
    /// end, with the reader then just past the delimiter.
    fn poll_part_data(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<Result<usize, Failure>> {
        if self.state != State::InPart {
            return Poll::Ready(Ok(0));
        }
        loop {
            let (avail, at_end) = match self.next_delim() {
                Some(i) => (i - self.pos, i == self.pos),
                None => (self.clean_until - self.pos, false),
            };
            if at_end {
                self.pos += self.delim.len();
                self.clean_until = self.pos;
                self.state = State::AfterDelimiter;
                return Poll::Ready(Ok(0));
            }
            if avail > 0 {
                let n = avail.min(out.len());
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Poll::Ready(Ok(n));
            }
            match self.poll_fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => return Poll::Ready(Err(self.fail(Failure::Truncated))),
            }
        }
    }

    /// The current part's bytes, whole, refused above `cap`. For FIELDS (and
    /// for a file whose uploader declared no `size` — bounded by the caller's
    /// cap, which is the whole-read cap).
    pub async fn read_part(&mut self, cap: usize) -> Result<Vec<u8>, ReadPartError> {
        let mut out = Vec::new();
        let mut scratch = vec![0u8; 64 * 1024];
        loop {
            let n = std::future::poll_fn(|cx| self.poll_part_data(cx, &mut scratch))
                .await
                .map_err(ReadPartError::Failed)?;
            if n == 0 {
                return Ok(out);
            }
            if out.len() + n > cap {
                return Err(ReadPartError::AboveCap);
            }
            out.extend_from_slice(&scratch[..n]);
        }
    }

    /// **The file part's leading bytes, WITHOUT consuming them** — the
    /// write gate's peek. Returns up to `n` bytes (fewer only when the part
    /// is shorter); the reader then yields them again from the first byte.
    /// This is "peek, then chain" with no second buffer: the peeked bytes are
    /// simply not released from this reader's own buffer until the seal
    /// reads them.
    pub async fn peek(&mut self, n: usize) -> Result<&[u8], Failure> {
        loop {
            if self.state != State::InPart {
                return Ok(&[]);
            }
            let found = find(&self.buf, &self.delim, self.pos);
            if let Some(i) = found {
                let end = i.min(self.pos + n);
                return Ok(&self.buf[self.pos..end]);
            }
            if self.buf.len() - self.pos >= n + self.delim.len() - 1 {
                return Ok(&self.buf[self.pos..self.pos + n]);
            }
            if !self.fill().await? {
                return Err(self.fail(Failure::Truncated));
            }
        }
    }

    /// The FILE part's reader step: its bytes, then — before reporting the
    /// end — proof that the body closes here (see "why the file comes
    /// LAST"). `Ok(0)` only after the closing delimiter is seen.
    fn poll_file(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<Result<usize, Failure>> {
        match self.state {
            State::Closed => return Poll::Ready(Ok(0)),
            State::InPart => match self.poll_part_data(cx, out) {
                Poll::Ready(Ok(0)) => {}
                other => return other,
            },
            State::AfterDelimiter => {}
            State::Preamble => {
                return Poll::Ready(Err(self.fail(Failure::Malformed("no part is open".into()))))
            }
        }
        loop {
            if self.buf.len() - self.pos >= 2 {
                if self.buf[self.pos..].starts_with(b"--") {
                    self.state = State::Closed;
                    return Poll::Ready(Ok(0));
                }
                return Poll::Ready(Err(self.fail(Failure::FieldAfterFile)));
            }
            match self.poll_fill(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => return Poll::Ready(Err(self.fail(Failure::Truncated))),
            }
        }
    }
}

/// [`Multipart::read_part`]'s refusal.
#[derive(Debug)]
pub enum ReadPartError {
    /// The part is longer than the caller's cap.
    AboveCap,
    /// The body could not be read.
    Failed(Failure),
}

/// The FILE part as a reader, for `files::publish_stream`. Every error is
/// also kept on the [`Multipart`] ([`Multipart::failure`]) so the handler can
/// answer the typed cause rather than edge's rendering of it.
impl tokio::io::AsyncRead for Multipart {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let out = buf.initialize_unfilled();
        match this.poll_file(cx, out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(f)) => Poll::Ready(Err(std::io::Error::other(f.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

    /// `body` cut into frames of `frame` bytes — so every delimiter, header
    /// terminator and field straddles frame boundaries somewhere.
    fn framed(body: &[u8], frame: usize) -> ByteStream {
        let frames: Vec<Result<Bytes, String>> = body
            .chunks(frame)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        Box::pin(futures_util::stream::iter(frames))
    }

    fn form(fields: &[(&str, &str)], file: &[u8], trailing: Option<(&str, &str)>) -> Vec<u8> {
        let mut b = b"preamble to ignore\r\n".to_vec();
        for (k, v) in fields {
            b.extend_from_slice(
                format!("--XyZ\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n")
                    .as_bytes(),
            );
        }
        b.extend_from_slice(
            b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"boat.jpg\"\r\n\
Content-Type: image/jpeg\r\n\r\n",
        );
        b.extend_from_slice(file);
        if let Some((k, v)) = trailing {
            b.extend_from_slice(
                format!("\r\n--XyZ\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}")
                    .as_bytes(),
            );
        }
        b.extend_from_slice(b"\r\n--XyZ--\r\nepilogue");
        b
    }

    #[test]
    fn the_boundary_parameter_is_read_quoted_or_not() {
        assert_eq!(
            boundary("multipart/form-data; boundary=XyZ").as_deref(),
            Some("XyZ")
        );
        assert_eq!(
            boundary("multipart/form-data; boundary=\"XyZ\"").as_deref(),
            Some("XyZ")
        );
        assert_eq!(boundary("multipart/form-data"), None);
    }

    /// Fields then a file, at every frame size from 1 byte up: the fields
    /// read whole, the peek sees the head without consuming it, and the file
    /// reads back exactly — a CRLF and a near-delimiter INSIDE the bytes
    /// included.
    #[tokio::test]
    async fn fields_then_a_streamed_file_at_every_frame_size() {
        let mut file = b"\xFF\xD8\xFF\x00\x01\r\n\x02\r\n--Xy not the end\r\n-".to_vec();
        file.extend((0..5000u32).map(|i| (i % 251) as u8));
        let body = form(&[("cohort", "self"), ("size", "5031")], &file, None);
        for frame in [1, 2, 3, 7, 64, 1000, body.len()] {
            let mut mp = Multipart::new(framed(&body, frame), "XyZ", 1 << 20);
            let h = mp.next_part().await.expect("part").expect("cohort");
            assert_eq!(h.name, "cohort");
            assert_eq!(mp.read_part(FIELD_CAP).await.expect("field"), b"self");
            let h = mp.next_part().await.expect("part").expect("size");
            assert_eq!(h.name, "size");
            assert_eq!(mp.read_part(FIELD_CAP).await.expect("field"), b"5031");
            let h = mp.next_part().await.expect("part").expect("file");
            assert_eq!(h.name, "file");
            assert_eq!(h.filename.as_deref(), Some("boat.jpg"));
            assert_eq!(h.content_type.as_deref(), Some("image/jpeg"));
            assert_eq!(mp.peek(3).await.expect("peek"), b"\xFF\xD8\xFF");
            let mut got = Vec::new();
            mp.read_to_end(&mut got).await.expect("file");
            assert_eq!(got, file, "frame {frame}");
            assert!(mp.next_part().await.expect("closed").is_none());
        }
    }

    #[tokio::test]
    async fn a_field_after_the_file_is_refused_before_the_end_of_file() {
        let body = form(
            &[("cohort", "self")],
            b"abc",
            Some(("filename", "late.txt")),
        );
        let mut mp = Multipart::new(framed(&body, 5), "XyZ", 1 << 20);
        mp.next_part().await.unwrap();
        mp.read_part(FIELD_CAP).await.unwrap();
        mp.next_part().await.unwrap();
        let mut got = Vec::new();
        assert!(mp.read_to_end(&mut got).await.is_err());
        assert_eq!(got, b"abc", "the bytes arrive; the END is what is refused");
        assert_eq!(mp.failure(), Some(&Failure::FieldAfterFile));
    }

    #[tokio::test]
    async fn a_body_that_stops_mid_file_is_truncated_and_a_long_one_too_large() {
        let body = form(&[("cohort", "self")], b"abcdef", None);
        let cut = &body[..body.len() - 20];
        let mut mp = Multipart::new(framed(cut, 4), "XyZ", 1 << 20);
        mp.next_part().await.unwrap();
        mp.read_part(FIELD_CAP).await.unwrap();
        mp.next_part().await.unwrap();
        let mut got = Vec::new();
        assert!(mp.read_to_end(&mut got).await.is_err());
        assert_eq!(mp.failure(), Some(&Failure::Truncated));

        let mut mp = Multipart::new(framed(&body, 4), "XyZ", 40);
        let err = async {
            mp.next_part().await?;
            mp.read_part(FIELD_CAP).await.map_err(|e| match e {
                ReadPartError::Failed(f) => f,
                ReadPartError::AboveCap => Failure::Malformed("cap".into()),
            })?;
            mp.next_part().await
        }
        .await;
        assert_eq!(err.unwrap_err(), Failure::TooLarge { limit: 40 });
    }

    #[tokio::test]
    async fn no_boundary_is_malformed() {
        let mut mp = Multipart::new(framed(b"no boundary here", 3), "XyZ", 1 << 20);
        assert!(matches!(mp.next_part().await, Err(Failure::Malformed(_))));
    }
}
