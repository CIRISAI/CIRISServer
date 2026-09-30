//! **Reading a file without holding it** (0.5.218, edge v36.1.0
//! CIRISEdge#737 / #744) — the drive's side of edge's two streaming read
//! doors, `FileRow::chunks()` and `FileRow::open_range`, and the reader that
//! feeds one file's chunks into another seal (`move`).
//!
//! # Why a task and a channel, not a borrowed stream
//!
//! `FileRow::chunks()` borrows the row, the content store and the viewer key
//! for its whole walk, and an HTTP body must be `'static` — it outlives the
//! handler that built it. A self-referential struct would square that; a
//! producer task that OWNS all three and hands chunks through a bounded
//! channel squares it with nothing clever. The bound is the memory claim:
//! [`IN_FLIGHT`] chunks queued plus the one in the producer's hand plus the
//! one hyper is writing — each at most persist's 1 MiB inline cap (edge:
//! "every `Ok` item is at most persist's inline cap long"), so a 2 GiB file
//! costs a few MiB to serve. A client that disconnects drops the receiver;
//! the producer's next `send` fails and the walk stops there, so an abandoned
//! download does not keep decrypting.
//!
//! # The first item is awaited BEFORE the status line
//!
//! Once headers are sent, a refusal can only be a torn connection. So the
//! handler awaits the first item itself ([`first_item`]) and maps a refusal on
//! it to a status (`not_granted`, `range_not_satisfiable`, …) — the byte-state
//! probe has already vouched for the rest, and a failure after the first
//! chunk is a substrate fault mid-transfer, which a torn body reports
//! honestly (a client comparing `Content-Length` sees the short read).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use ciris_edge::files::{self, FileError, FileRow};
use ciris_persist::prelude::Engine;
use tokio::sync::mpsc;

/// How many chunks may be queued ahead of the writer — the whole of this
/// module's buffering. Two keeps the decrypt one step ahead of the socket
/// without letting it run away from a slow client.
pub const IN_FLIGHT: usize = 2;

/// The window a RANGE is walked in: edge's [`files::STREAM_WINDOW_BYTES`]
/// (persist's 1 MiB inline cap), a multiple of edge's 256 KiB producer
/// chunk, so windows aligned to it open whole chunks and never the same
/// chunk twice. The first window runs from the range's start to the next
/// multiple, every later one is aligned.
pub const RANGE_WINDOW: u64 = files::STREAM_WINDOW_BYTES;

type Item = Result<Vec<u8>, FileError>;

fn store(engine: &Arc<Engine>) -> ciris_edge::group_content::PersistGroupContentStore {
    ciris_edge::group_content::PersistGroupContentStore::new(
        (**engine).clone(),
        engine.federation_directory(),
    )
}

/// The whole file, one chunk per item, through `FileRow::chunks()`.
pub fn spawn_chunks(engine: Arc<Engine>, file: FileRow, viewer: String) -> mpsc::Receiver<Item> {
    let (tx, rx) = mpsc::channel(IN_FLIGHT);
    tokio::spawn(async move {
        let content = store(&engine);
        let mut chunks = file.chunks(&content, &viewer);
        while let Some(item) = chunks.next().await {
            let stop = item.is_err();
            if tx.send(item).await.is_err() || stop {
                return;
            }
        }
    });
    rx
}

/// `[start, end]` inclusive, in [`RANGE_WINDOW`] windows through
/// `FileRow::open_range` — no cap on the range's length, because no window
/// is longer than one.
///
/// Edge's `open_range` refuses a window above the 64 MiB whole-read cap
/// (`AboveWholeReadCap`, "the bound on what one call materializes"); that is
/// a bound on ONE CALL, and this walk never makes a call anywhere near it.
pub fn spawn_range(
    engine: Arc<Engine>,
    file: FileRow,
    viewer: String,
    start: u64,
    end: u64,
) -> mpsc::Receiver<Item> {
    let (tx, rx) = mpsc::channel(IN_FLIGHT);
    tokio::spawn(async move {
        let content = store(&engine);
        let mut at = start;
        while at <= end {
            let window_end = ((at / RANGE_WINDOW) + 1) * RANGE_WINDOW - 1;
            let last = window_end.min(end);
            let item = file.open_range(&content, &viewer, at, last - at + 1).await;
            let stop = item.is_err();
            if tx.send(item).await.is_err() || stop {
                return;
            }
            at = last + 1;
        }
    });
    rx
}

/// The first item, or `None` for a file that yielded nothing.
pub async fn first_item(rx: &mut mpsc::Receiver<Item>) -> Option<Item> {
    rx.recv().await
}

/// The rest of the walk as a response body, `first` in front. If `expect`
/// is given (the size a `Content-Length` promised) a walk that ends at any
/// other count is an ERROR on the body, never a clean short end: the same
/// "row and bytes disagree" the whole read refuses as `seal_mismatch`,
/// surfaced the only way it can be once the status line is out.
pub fn body(first: Vec<u8>, rx: mpsc::Receiver<Item>, expect: Option<u64>) -> Body {
    struct Walk {
        first: Option<Vec<u8>>,
        rx: mpsc::Receiver<Item>,
        sent: u64,
        expect: Option<u64>,
    }
    let walk = Walk {
        sent: 0,
        first: Some(first),
        rx,
        expect,
    };
    let stream = futures_util::stream::unfold(walk, |mut w| async move {
        let item = match w.first.take() {
            Some(b) => Some(Ok(b)),
            None => w.rx.recv().await,
        };
        match item {
            Some(Ok(b)) => {
                w.sent += b.len() as u64;
                if w.expect.is_some_and(|n| w.sent > n) {
                    let e = std::io::Error::other("the file yielded more bytes than its size");
                    return Some((Err(e), w));
                }
                Some((Ok(Bytes::from(b)), w))
            }
            Some(Err(e)) => {
                tracing::warn!(error = %e, "drive: a streamed read failed mid-transfer");
                // After an Err the producer has stopped; end after this.
                w.expect = None;
                Some((Err(std::io::Error::other(e.to_string())), w))
            }
            None => match w.expect.take() {
                Some(n) if n != w.sent => Some((
                    Err(std::io::Error::other(format!(
                        "the file yielded {} bytes and its row declares {n}",
                        w.sent
                    ))),
                    w,
                )),
                _ => None,
            },
        }
    });
    Body::from_stream(stream)
}

/// One file's chunks as an `AsyncRead` — `move`'s source for
/// `files::publish_stream` above the whole-read cap: the walk of the source
/// room's seal feeding the seal of the target room, one chunk in hand.
///
/// [`Self::peek`] fills the write gate's head window without consuming it;
/// a walk refusal is kept ([`Self::failure`]) so the handler answers the
/// typed read refusal rather than edge's `FileError::Read` prose.
pub struct ChunkReader {
    rx: mpsc::Receiver<Item>,
    pending: Vec<u8>,
    at: usize,
    done: bool,
    failure: Option<FileError>,
}

impl ChunkReader {
    /// Over a walk from [`spawn_chunks`].
    pub fn new(rx: mpsc::Receiver<Item>) -> Self {
        Self {
            rx,
            pending: Vec::new(),
            at: 0,
            done: false,
            failure: None,
        }
    }

    /// The walk's refusal, if it stopped on one.
    pub fn failure(&self) -> Option<&FileError> {
        self.failure.as_ref()
    }

    /// Up to `n` leading bytes, not consumed — fewer only for a shorter
    /// file. At most `n` plus one chunk is held.
    pub async fn peek(&mut self, n: usize) -> Result<&[u8], FileError> {
        while self.pending.len() - self.at < n && !self.done {
            match self.rx.recv().await {
                Some(Ok(b)) => {
                    self.pending.drain(..self.at);
                    self.at = 0;
                    self.pending.extend_from_slice(&b);
                }
                Some(Err(e)) => {
                    self.done = true;
                    self.failure = Some(e.clone());
                    return Err(e);
                }
                None => self.done = true,
            }
        }
        let end = (self.at + n).min(self.pending.len());
        Ok(&self.pending[self.at..end])
    }
}

impl tokio::io::AsyncRead for ChunkReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.at < this.pending.len() {
                let n = (this.pending.len() - this.at).min(buf.remaining());
                buf.put_slice(&this.pending[this.at..this.at + n]);
                this.at += n;
                return Poll::Ready(Ok(()));
            }
            if let Some(e) = &this.failure {
                return Poll::Ready(Err(std::io::Error::other(e.to_string())));
            }
            if this.done {
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => this.done = true,
                Poll::Ready(Some(Ok(b))) => {
                    this.pending = b;
                    this.at = 0;
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    this.failure = Some(e);
                }
            }
        }
    }
}
