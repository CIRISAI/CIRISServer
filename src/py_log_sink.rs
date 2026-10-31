//! **One log file: the node's lines go to the host's Python `logging`**
//! (steward 2026-10-31: "having 2 log files is killing us, and that would unify
//! our log rotation/disk management").
//!
//! An embedded node (the agent, the manager client) used to write its own
//! `<home>/logs/ciris-server.log.<date>` beside the host's `latest.log`, with its
//! own retention. Two files meant two rotations, two caps, and a support request
//! that always got the wrong one (Eric↔Francesco, 2026-10-31: the agent log
//! arrived, the node's lines were in the other file).
//!
//! With `init_tracing(python_logging=True)` the file sink is replaced by this
//! one: each event becomes one `logging` record on the logger
//! `ciris_node.<crate>` (`ciris_node.ciris_edge`, `ciris_node.ciris_server`, …),
//! so the host's handlers write it, rotate it and cap it with everything else.
//!
//! **The node never waits on Python.** A tracing event can fire on any thread,
//! including one that holds a lock Python code is waiting on, so emitting
//! under the GIL inline could deadlock. Events go onto a bounded queue; one
//! drain thread takes the GIL and emits in batches. When the queue is full a
//! line is dropped and counted, and the count is reported as one warning record
//! when the drain catches up — the node slows nothing to log.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::OnceLock;

use pyo3::prelude::*;

/// Lines held between the node and the drain before new ones are dropped.
const QUEUE: usize = 20_000;
/// Records emitted per GIL acquisition.
const BATCH: usize = 512;
/// The logger namespace the node's records use; the crate root follows.
pub const LOGGER_PREFIX: &str = "ciris_node";

struct Line {
    level: tracing::Level,
    logger: String,
    msg: String,
}

static TX: OnceLock<SyncSender<Line>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Python's numeric level for a tracing level (TRACE folds into DEBUG).
fn levelno(level: tracing::Level) -> u32 {
    match level {
        tracing::Level::ERROR => 40,
        tracing::Level::WARN => 30,
        tracing::Level::INFO => 20,
        _ => 10,
    }
}

/// `ciris_node.<crate>` for a tracing target (`ciris_edge::replication::bridge`
/// → `ciris_node.ciris_edge`).
pub(crate) fn logger_for(target: &str) -> String {
    let root = target.split("::").next().unwrap_or(target);
    format!("{LOGGER_PREFIX}.{root}")
}

/// Start the drain once per process and hand back the queue's sender.
fn sender() -> SyncSender<Line> {
    TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<Line>(QUEUE);
        let _ = std::thread::Builder::new()
            .name("ciris-log-drain".into())
            .spawn(move || drain(rx));
        tx
    })
    .clone()
}

fn drain(rx: Receiver<Line>) {
    while let Ok(first) = rx.recv() {
        let mut batch = Vec::with_capacity(BATCH);
        batch.push(first);
        while batch.len() < BATCH {
            match rx.try_recv() {
                Ok(l) => batch.push(l),
                Err(_) => break,
            }
        }
        let dropped = DROPPED.swap(0, Ordering::Relaxed);
        // A finalizing interpreter cannot take records; the lines are lost
        // either way, and a panic here would take the drain with them.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Python::attach(|py| -> PyResult<()> {
                let logging = py.import("logging")?;
                if dropped > 0 {
                    logging
                        .call_method1("getLogger", (format!("{LOGGER_PREFIX}.log_sink"),))?
                        .call_method1(
                            "log",
                            (
                                30u32,
                                format!(
                                    "{dropped} node log line(s) were DROPPED: the queue to \
                                     Python logging was full"
                                ),
                            ),
                        )?;
                }
                for line in &batch {
                    logging
                        .call_method1("getLogger", (line.logger.as_str(),))?
                        .call_method1("log", (levelno(line.level), line.msg.as_str()))?;
                }
                Ok(())
            })
        }));
    }
}

/// The `fmt` writer for one event: buffers the formatted line and queues it on
/// drop. Never blocks.
pub(crate) struct LineWriter {
    level: tracing::Level,
    logger: String,
    buf: Vec<u8>,
    tx: SyncSender<Line>,
}

impl Write for LineWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let msg = String::from_utf8_lossy(&self.buf).trim_end().to_owned();
        if msg.is_empty() {
            return;
        }
        let line = Line {
            level: self.level,
            logger: std::mem::take(&mut self.logger),
            msg,
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = self.tx.try_send(line) {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `MakeWriter` that routes each event to the Python sink, by its own level
/// and target.
pub(crate) struct PySinkMakeWriter;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for PySinkMakeWriter {
    type Writer = LineWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LineWriter {
            level: tracing::Level::INFO,
            logger: format!("{LOGGER_PREFIX}.ciris_server"),
            buf: Vec::new(),
            tx: sender(),
        }
    }
    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        LineWriter {
            level: *meta.level(),
            logger: logger_for(meta.target()),
            buf: Vec::new(),
            tx: sender(),
        }
    }
}

/// The layer `init_tracing(python_logging=True)` installs in the file slot:
/// the host's formatter adds the time, level and logger name, so this one
/// writes the target and the event only.
pub(crate) fn layer<S>() -> impl tracing_subscriber::Layer<S> + Send + Sync
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .without_time()
        .with_level(false)
        .with_writer(PySinkMakeWriter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_maps_to_its_crate_logger() {
        assert_eq!(
            logger_for("ciris_edge::replication::bridge"),
            "ciris_node.ciris_edge"
        );
        assert_eq!(logger_for("ciris_server"), "ciris_node.ciris_server");
        assert_eq!(levelno(tracing::Level::WARN), 30);
        assert_eq!(levelno(tracing::Level::TRACE), 10);
    }
}
