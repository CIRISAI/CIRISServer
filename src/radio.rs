//! Serial-attached **RNode LoRa radio** driver for the edge packet-radio
//! transport (the N2 multi-medium plug, CIRISEdge#53).
//!
//! This module drives a serial-attached [RNode-firmware] LoRa modem directly,
//! implementing the edge
//! [`PacketRadioDriver`](ciris_edge::transport::packet_radio::driver::PacketRadioDriver)
//! trait so the federation can carry envelopes over an RF medium that an
//! IP-infrastructure attacker (BGP hijack, DNS takeover, ISP filtering) cannot
//! also control. The medium-specific wire format is RNode's KISS superset —
//! the same framing the Reticulum `RNodeInterface` speaks.
//!
//! ## Hardware-validation status
//!
//! The KISS framing + the RNode `CMD_*` command bytes here are ported from the
//! validated Leviculum reference implementation
//! (`reticulum-core/src/rnode.rs` + `reticulum-core/src/framing/kiss.rs`),
//! which is interop-tested against the Python Reticulum `RNodeInterface`. The
//! constants + the encode/decode state machine match that reference
//! byte-for-byte. Nonetheless the END-TO-END path through a *physical* RNode
//! radio (the serial open parameters, the on-boot config handshake ordering,
//! and real-modem timing) has NOT been exercised on hardware in this crate —
//! see the `TODO(hardware-validate)` markers. Treat the radio path as
//! "wire-correct, hardware-unvalidated" until run against a real RNode.
//!
//! ## Desktop-only
//!
//! The `serialport` crate is not built for the android/ios wheels, so the
//! entire module is gated off the mobile targets (mirrored by the cfg-gated
//! `pub mod radio;` declaration in `lib.rs`).
//!
//! [RNode-firmware]: https://github.com/markqvist/RNode_Firmware

// Self-gate the whole module so it is safe to include unconditionally: the
// `serialport` dependency only exists on desktop targets.
#![cfg(not(any(target_os = "android", target_os = "ios")))]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ciris_edge::transport::packet_radio::driver::{DriverError, PacketRadioDriver};
use ciris_edge::transport::packet_radio::{PacketRadioResolver, PacketRadioTransport};
use ciris_edge::transport::TransportId;
use ciris_persist::prelude::Engine;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// RNode / KISS wire constants
//
// TODO(hardware-validate): confirm these RNode CMD_* constants + the KISS
// framing against a physical RNode radio. Source of truth used here:
// Leviculum `reticulum-core/src/rnode.rs` + `.../framing/kiss.rs` (interop-
// tested vs the Python Reticulum RNodeInterface).
// ---------------------------------------------------------------------------

/// KISS frame delimiter.
const FEND: u8 = 0xC0;
/// KISS escape byte.
const FESC: u8 = 0xDB;
/// Transposed FEND (follows FESC in an escaped payload).
const TFEND: u8 = 0xDC;
/// Transposed FESC (follows FESC in an escaped payload).
const TFESC: u8 = 0xDD;

/// Data packet (standard KISS CMD_DATA).
const CMD_DATA: u8 = 0x00;
/// Set operating frequency (4-byte big-endian Hz payload).
const CMD_FREQUENCY: u8 = 0x01;
/// Set channel bandwidth (4-byte big-endian Hz payload).
const CMD_BANDWIDTH: u8 = 0x02;
/// Set TX power (1-byte dBm payload).
const CMD_TXPOWER: u8 = 0x03;
/// Set spreading factor (1-byte payload).
const CMD_SF: u8 = 0x04;
/// Set coding rate (1-byte payload).
const CMD_CR: u8 = 0x05;
/// Set radio state on/off (1-byte payload: 0x00 off, 0x01 on).
const CMD_RADIO_STATE: u8 = 0x06;
/// Radio configuration lock (1-byte payload). Reserved here for completeness;
/// not driven by the default open sequence.
#[allow(dead_code)]
const CMD_RADIO_LOCK: u8 = 0x07;

/// `CMD_RADIO_STATE` payload — radio off.
#[allow(dead_code)]
const RADIO_STATE_OFF: u8 = 0x00;
/// `CMD_RADIO_STATE` payload — radio on.
const RADIO_STATE_ON: u8 = 0x01;

/// Hardware MTU for all RNode variants (bytes). Matches the RNode firmware +
/// the Python Reticulum RNodeInterface deframer cap.
const RNODE_HW_MTU: usize = 508;

/// Serial line rate the RNode firmware speaks (8N1).
const RNODE_BAUD: u32 = 115_200;

/// Serial read timeout per poll. Short so `recv_frame` can interleave with
/// `send_frame` and remain responsive; the driver loops across timeouts until a
/// complete DATA frame arrives.
const SERIAL_READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Idle backoff between empty serial reads inside `recv_frame`, so we yield the
/// blocking worker thread back to the runtime between polls.
const RECV_IDLE_BACKOFF: Duration = Duration::from_millis(5);

// ---------------------------------------------------------------------------
// Radio parameters
// ---------------------------------------------------------------------------

/// LoRa PHY + serial parameters for a serial-attached RNode radio.
#[derive(Debug, Clone)]
pub struct RadioParams {
    /// OS serial device path the RNode is attached to (e.g. `/dev/ttyUSB0`,
    /// `/dev/ttyACM0`, or `COM3` on Windows).
    pub serial_port: String,
    /// Operating frequency in Hz (e.g. `915_000_000` for the US 915 MHz band).
    pub frequency_hz: u32,
    /// Channel bandwidth in Hz (e.g. `125_000`).
    pub bandwidth_hz: u32,
    /// LoRa spreading factor (7..=12).
    pub spreading_factor: u8,
    /// LoRa coding rate denominator (5..=8 ⇒ 4/5..4/8).
    pub coding_rate: u8,
    /// TX power in dBm.
    pub tx_power_dbm: u8,
}

// ---------------------------------------------------------------------------
// KISS encode / decode
// ---------------------------------------------------------------------------

/// KISS-encode one frame: `FEND, command, escaped(payload)..., FEND`.
///
/// Escaping: `0xC0 -> FESC TFEND`, `0xDB -> FESC TFESC`.
fn kiss_encode(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + payload.len() * 2);
    out.push(FEND);
    out.push(command);
    for &byte in payload {
        match byte {
            FEND => {
                out.push(FESC);
                out.push(TFEND);
            }
            FESC => {
                out.push(FESC);
                out.push(TFESC);
            }
            _ => out.push(byte),
        }
    }
    out.push(FEND);
    out
}

/// Incremental KISS deframer (a faithful port of the Leviculum
/// `KissDeframer` state machine). Holds partial-frame state across reads so a
/// frame split over multiple serial reads is reassembled correctly.
struct KissDecoder {
    in_frame: bool,
    escape_next: bool,
    command: Option<u8>,
    buffer: Vec<u8>,
    max_payload: usize,
}

impl KissDecoder {
    fn new(max_payload: usize) -> Self {
        Self {
            in_frame: false,
            escape_next: false,
            command: None,
            buffer: Vec::with_capacity(max_payload),
            max_payload,
        }
    }

    /// Feed raw serial bytes; append any completed `(command, payload)` frames
    /// to `out`.
    fn push(&mut self, data: &[u8], out: &mut Vec<(u8, Vec<u8>)>) {
        for &byte in data {
            if let Some(frame) = self.push_byte(byte) {
                out.push(frame);
            }
        }
    }

    fn push_byte(&mut self, byte: u8) -> Option<(u8, Vec<u8>)> {
        if byte == FEND {
            if self.in_frame && self.command.is_some() {
                // Closing FEND of a complete frame. FEND also opens the next.
                let command = self.command.take().unwrap_or(0);
                let payload = std::mem::take(&mut self.buffer);
                self.in_frame = true;
                self.escape_next = false;
                return Some((command, payload));
            }
            // Start of frame (or back-to-back FEND delimiters).
            self.in_frame = true;
            self.command = None;
            self.buffer.clear();
            self.escape_next = false;
        } else if self.in_frame {
            if self.command.is_none() {
                self.command = Some(byte);
            } else if self.escape_next {
                let resolved = match byte {
                    TFEND => FEND,
                    TFESC => FESC,
                    other => other,
                };
                self.escape_next = false;
                if self.buffer.len() < self.max_payload {
                    self.buffer.push(resolved);
                }
            } else if byte == FESC {
                self.escape_next = true;
            } else if self.buffer.len() < self.max_payload {
                self.buffer.push(byte);
            }
        }
        // Bytes outside a frame are silently ignored.
        None
    }
}

// ---------------------------------------------------------------------------
// Serial RNode driver
// ---------------------------------------------------------------------------

/// Shared serial state. The port, the persistent KISS decoder, and the queue
/// of decoded-but-not-yet-returned DATA payloads all live behind one mutex so
/// that `send_frame` and `recv_frame` can share the single serial line, and so
/// the decoder state survives `recv_frame` cancellation.
struct SerialInner {
    port: Box<dyn serialport::SerialPort>,
    decoder: KissDecoder,
    /// Decoded DATA payloads awaiting delivery (a single serial read can yield
    /// more than one frame).
    pending: VecDeque<Vec<u8>>,
}

impl SerialInner {
    /// Write a complete KISS frame to the port and flush.
    fn write_kiss(&mut self, command: u8, payload: &[u8]) -> Result<(), DriverError> {
        use std::io::Write as _;
        let framed = kiss_encode(command, payload);
        self.port
            .write_all(&framed)
            .map_err(|e| DriverError::Hardware(format!("serial write: {e}")))?;
        self.port
            .flush()
            .map_err(|e| DriverError::Hardware(format!("serial flush: {e}")))
    }

    /// Do one blocking serial read and feed the decoder. Returns `true` if at
    /// least one DATA frame became available in `pending`. Non-DATA frames are
    /// decoded and discarded. A read timeout (no bytes) returns `false`.
    fn read_once(&mut self) -> Result<bool, DriverError> {
        use std::io::Read as _;
        let mut buf = [0u8; 1024];
        let n = match self.port.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return Ok(false),
            // Some serialport backends surface a timeout as WouldBlock.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(DriverError::Hardware(format!("serial read: {e}"))),
        };
        if n == 0 {
            return Ok(false);
        }
        let mut frames = Vec::new();
        self.decoder.push(&buf[..n], &mut frames);
        let mut got_data = false;
        for (command, payload) in frames {
            if command == CMD_DATA {
                self.pending.push_back(payload);
                got_data = true;
            }
            // Non-DATA frames (stats, ready, errors, …) are ignored.
        }
        Ok(got_data)
    }
}

/// A [`PacketRadioDriver`] over a serial-attached RNode LoRa modem.
///
/// Open with [`SerialRNodeDriver::open`]; the constructor configures the radio
/// (frequency/bandwidth/SF/CR/TX-power) and turns it on before returning.
pub struct SerialRNodeDriver {
    /// The serial line + decoder + pending queue. `tokio::sync::Mutex` because
    /// it is held across the `block_in_place` blocking I/O sections.
    inner: Arc<Mutex<SerialInner>>,
    /// Enforces the trait's "single listener" contract: a `try_lock` failure
    /// in `recv_frame` surfaces [`DriverError::ConcurrentReceive`].
    rx_lock: Mutex<()>,
}

impl SerialRNodeDriver {
    /// Open the serial port (115200 8N1), push the RNode KISS configuration
    /// commands (frequency, bandwidth, TX power, SF, CR) and turn the radio ON,
    /// then return a ready driver.
    ///
    /// TODO(hardware-validate): the open parameters + the config-command
    /// ordering below are wire-correct vs the RNode reference but unvalidated
    /// against a physical radio.
    pub fn open(params: &RadioParams) -> Result<Self, DriverError> {
        let port = serialport::new(&params.serial_port, RNODE_BAUD)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(SERIAL_READ_TIMEOUT)
            .open()
            .map_err(|e| {
                DriverError::Hardware(format!("open serial port {}: {e}", params.serial_port))
            })?;

        let mut inner = SerialInner {
            port,
            decoder: KissDecoder::new(RNODE_HW_MTU),
            pending: VecDeque::new(),
        };

        // Configure the radio, then bring it up. Frequency + bandwidth are
        // 4-byte big-endian; sf/cr/tx_power/state are single bytes.
        inner.write_kiss(CMD_FREQUENCY, &params.frequency_hz.to_be_bytes())?;
        inner.write_kiss(CMD_BANDWIDTH, &params.bandwidth_hz.to_be_bytes())?;
        inner.write_kiss(CMD_TXPOWER, &[params.tx_power_dbm])?;
        inner.write_kiss(CMD_SF, &[params.spreading_factor])?;
        inner.write_kiss(CMD_CR, &[params.coding_rate])?;
        inner.write_kiss(CMD_RADIO_STATE, &[RADIO_STATE_ON])?;

        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            rx_lock: Mutex::new(()),
        })
    }
}

#[async_trait]
impl PacketRadioDriver for SerialRNodeDriver {
    fn medium_id(&self) -> &'static str {
        "lora-rnode"
    }

    async fn send_frame(&self, bytes: &[u8]) -> Result<(), DriverError> {
        if bytes.len() > RNODE_HW_MTU {
            return Err(DriverError::FrameOverMtu {
                got: bytes.len(),
                limit: RNODE_HW_MTU,
            });
        }
        let mut guard = self.inner.lock().await;
        // The serial write is blocking; run it inside block_in_place so the
        // async worker isn't parked. Not a cancellation point — the closure
        // runs to completion before any await can drop this future.
        tokio::task::block_in_place(|| guard.write_kiss(CMD_DATA, bytes))
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, DriverError> {
        // Enforce the single-listener contract. The guard is held for the whole
        // call so a second concurrent caller gets ConcurrentReceive.
        let _rx = self
            .rx_lock
            .try_lock()
            .map_err(|_| DriverError::ConcurrentReceive)?;

        loop {
            // Cancellation can only occur at the awaits below (lock + sleep),
            // i.e. when we hold NO decoder state — so a cancelled recv_frame
            // never corrupts the persistent KISS decoder or the pending queue.
            let decoded = {
                let mut guard = self.inner.lock().await;
                if let Some(frame) = guard.pending.pop_front() {
                    return Ok(frame);
                }
                // Blocking serial read under block_in_place (runs to completion;
                // mutates decoder/pending only here, never across an await).
                tokio::task::block_in_place(|| guard.read_once())?
            };
            if decoded {
                // A DATA frame landed in `pending`; loop to pop it.
                continue;
            }
            // Nothing this poll — yield, then poll again.
            tokio::time::sleep(RECV_IDLE_BACKOFF).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Directory-backed resolver
// ---------------------------------------------------------------------------

/// A [`PacketRadioResolver`] backed by the persist federation directory.
///
/// `resolve(key_id)` returns the peer's ed25519 public-key bytes (32B), looked
/// up from the same `federation_keys` directory the other transports use.
pub struct DirectoryResolver {
    engine: Arc<Engine>,
}

impl DirectoryResolver {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }
}

impl PacketRadioResolver for DirectoryResolver {
    fn resolve(&self, key_id: &str) -> Option<Vec<u8>> {
        // `resolve` is sync but the directory lookup is async. Bridge by running
        // the lookup on the current runtime from a blocking section.
        // `block_in_place` requires the multi-thread runtime (we use it).
        let engine = Arc::clone(&self.engine);
        let key_id = key_id.to_string();
        let record = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                engine
                    .federation_directory()
                    .lookup_public_key(&key_id)
                    .await
            })
        });
        let record = record.ok().flatten()?;
        // Stored as base64-standard of the 32 raw ed25519 bytes.
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(record.pubkey_ed25519_base64.as_bytes())
            .ok()
    }
}

// ---------------------------------------------------------------------------
// Transport builder
// ---------------------------------------------------------------------------

/// Open a serial RNode radio and assemble the edge packet-radio transport over
/// it, bound to the LoRa [`TransportId`].
///
/// Returns a typed [`DriverError`] (the only fallible step is opening +
/// configuring the radio) so the caller can log the hardware failure.
pub fn build_packet_radio_transport(
    params: &RadioParams,
    engine: Arc<Engine>,
) -> Result<Arc<PacketRadioTransport>, DriverError> {
    let driver = SerialRNodeDriver::open(params)?;
    let resolver = DirectoryResolver::new(engine);
    Ok(Arc::new(PacketRadioTransport::new(
        Arc::new(driver),
        Arc::new(resolver),
        TransportId::LORA,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kiss_encode_simple_frame() {
        // FEND, CMD_DATA, "Hi", FEND
        assert_eq!(
            kiss_encode(CMD_DATA, b"Hi"),
            vec![FEND, CMD_DATA, b'H', b'i', FEND]
        );
    }

    #[test]
    fn kiss_encode_escapes_fend_and_fesc() {
        assert_eq!(
            kiss_encode(CMD_DATA, &[FEND]),
            vec![FEND, CMD_DATA, FESC, TFEND, FEND]
        );
        assert_eq!(
            kiss_encode(CMD_DATA, &[FESC]),
            vec![FEND, CMD_DATA, FESC, TFESC, FEND]
        );
    }

    #[test]
    fn decoder_round_trips_a_data_frame() {
        let framed = kiss_encode(CMD_DATA, &[0x01, FEND, 0x02, FESC, 0x03]);
        let mut dec = KissDecoder::new(RNODE_HW_MTU);
        let mut out = Vec::new();
        dec.push(&framed, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, CMD_DATA);
        assert_eq!(out[0].1, vec![0x01, FEND, 0x02, FESC, 0x03]);
    }

    #[test]
    fn decoder_reassembles_split_reads() {
        let framed = kiss_encode(CMD_DATA, b"abcdef");
        let mut dec = KissDecoder::new(RNODE_HW_MTU);
        let mut out = Vec::new();
        // Feed the frame byte-by-byte.
        for chunk in framed.chunks(1) {
            dec.push(chunk, &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, b"abcdef");
    }

    #[test]
    fn decoder_ignores_non_data_command() {
        let framed = kiss_encode(CMD_STAT_PLACEHOLDER, b"xyz");
        let mut dec = KissDecoder::new(RNODE_HW_MTU);
        let mut out = Vec::new();
        dec.push(&framed, &mut out);
        // Decoded, but the caller (read_once) only queues CMD_DATA payloads.
        assert_eq!(out.len(), 1);
        assert_ne!(out[0].0, CMD_DATA);
    }

    // A non-DATA command byte for the ignore test.
    const CMD_STAT_PLACEHOLDER: u8 = 0x23;
}
