// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nv — host tty session-open transport pipeline (SERIAL).
//!
//! The serial-link sibling of [`crate::link_pipeline`] (TCP) /
//! [`crate::udp_pipeline`] (UDP). It is the 2nd layer of the R311nt
//! 2-layer SERIAL split: the transport-agnostic framing / handshake /
//! locator LOGIC lives in [`wz_session_core::serial_link`] (no I/O, so the
//! MCU UART HAL can reuse it); THIS module is the host-only tty BACKEND
//! that drives that logic over real async byte I/O ([`tokio_serial`]).
//! Mirrors zenoh-pico's `_z_open_serial_*` / `_z_connect_serial` /
//! `_z_read_serial` (`src/link/transport/upper/serial_protocol.c`), the
//! posix tty side of which is the `tokio-serial` `SerialStream` here.
//!
//! ## Two phases
//!
//! A serial link has its OWN link-level handshake BEFORE the zenoh
//! transport handshake (unlike TCP/UDP, which connect and immediately
//! carry zenoh INIT bytes). So the pipeline is two-phase:
//!
//! 1. **Link handshake** — [`dial_serial`] (Initiator) / [`accept_serial`]
//!    (Responder) open the tty and drive [`drive_serial_handshake`] to
//!    Connected over the WHOLE stream (INIT / INIT|ACK exchange). The
//!    handshake reader consumes byte-by-byte and stops exactly at the
//!    handshake frame's `0x00` EOP, so no zenoh data byte is over-read
//!    before the split.
//! 2. **Steady state** — [`wire_serial_stream`] splits the now-connected
//!    stream into the cooperating `(SerialReadDriver, Arc<SerialWriteDriver>,
//!    writer-task)` triple the session FSM consumes, exactly as
//!    [`crate::link_pipeline::wire_tcp_stream`] does for TCP. Data frames
//!    carry the zenoh transport bytes as the serial payload with header
//!    `0x00` (the receiver ignores the header on the data path —
//!    serial_protocol.c:282-285).
//!
//! ## Framing vs TCP
//!
//! TCP length-prefixes each frame (`StreamEnvelope`, 2-byte LE). SERIAL
//! instead COBS-frames each payload with a `0x00` EOP delimiter
//! ([`encode_frame`] / [`SerialFrameReader`]); [`serial_writer_task`]
//! encodes on the way out and [`SerialReadDriver`] re-frames on the way in.
//! The wire shape is the R311ns codec catalog
//! (`serial_envelope` / `cobs` / `crc32`), routed through the R311nt
//! `serial_link` logic — a single source of truth, not a hand-rolled strip.
//!
//! ## Split shape
//!
//! [`SerialStream`] is `AsyncRead + AsyncWrite` but NOT owned-half
//! splittable the way [`tokio::net::TcpStream::into_split`] is, so
//! [`tokio::io::split`] is used (a `BiLock` shared between the halves —
//! each `poll_read` / `poll_write` is non-blocking on the tty `AsyncFd`, so
//! the lock contention is negligible). The split is the same TCP shape: an
//! inbound `&mut LinkDriver` read half + an outbound
//! `Arc<dyn BoxedLinkDriver>` write half drained by a [`serial_writer_task`].

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_serial::SerialStream;

use wz_runtime_core::Runtime;

use crate::link_interfaces::addressless_link_subject;
use crate::runtime_impl::{TokioJoinHandle, TokioRuntime};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::{InterceptorLink, LinkSubject};
use wz_session_core::locator::{SerialEndpoint, SerialTarget};
use wz_session_core::serial_link::{
    encode_frame, DecodedFrame, HandshakeStep, SerialFrameReader, SerialHandshake, SerialRole,
    SERIAL_MAX_COBS_BUF, SERIAL_MTU,
};

/// Steady-state data-frame header — no handshake flag set. The receiver
/// ignores the header on the data path (`_z_read_serial`,
/// serial_protocol.c:282-285); it is the control byte ONLY during the
/// link handshake (INIT / INIT|ACK / RESET).
const SERIAL_DATA_HEADER: u8 = 0x00;

/// Initiator back-off between INIT retries when the peer answers RESET
/// (`SERIAL_CONNECT_THROTTLE_TIME_MS`, serial_protocol.c:37).
const SERIAL_CONNECT_THROTTLE: Duration = Duration::from_millis(250);

/// Open the host tty for a [`SerialEndpoint`] — the raw serial-device
/// open primitive (no handshake yet). Only [`SerialTarget::Device`] paths
/// are openable by the host tty backend; a [`SerialTarget::Pins`] target is
/// an MCU UART HAL endpoint with no host device node, so it surfaces a
/// typed `Unsupported` rather than a misleading "no such file".
fn open_serial_device(endpoint: &SerialEndpoint) -> io::Result<SerialStream> {
    let path = match &endpoint.target {
        SerialTarget::Device(path) => path,
        SerialTarget::Pins { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host tty backend cannot open a GPIO TX/RX pin pair; \
                 pins are an MCU UART HAL target",
            ));
        }
    };
    let builder = tokio_serial::new(path, endpoint.baudrate);
    // tokio_serial::Error impls std::error::Error -> io::Error::other carries
    // it without lossy stringly-typed remapping.
    SerialStream::open(&builder).map_err(io::Error::other)
}

/// Dial a serial endpoint as the link Initiator: open the tty and drive
/// the serial-link handshake (send INIT, await INIT|ACK) to Connected — the
/// serial analogue of [`crate::link_pipeline::dial_tcp`] PLUS the link
/// handshake `_z_connect_serial` runs before the zenoh transport. The
/// `dial_locator` serial arm (R311nv) routes a `serial/...` endpoint here.
///
/// No internal handshake timeout — like `dial_tcp`, bounding the wait is
/// the caller's concern (compose a [`tokio::time::timeout`]); a peer that
/// never answers INIT|ACK would otherwise retry on RESET indefinitely, as
/// `_z_connect_serial` does (serial_protocol.c:255-280).
pub async fn dial_serial(endpoint: &SerialEndpoint) -> io::Result<SerialStream> {
    let mut stream = open_serial_device(endpoint)?;
    drive_serial_handshake(&mut stream, SerialRole::Initiator).await?;
    Ok(stream)
}

/// Open a serial endpoint as the link Responder: open the tty and drive the
/// handshake (await INIT, reply INIT|ACK) to Connected. The point-to-point
/// peer of [`dial_serial`] — pico's listen side has no responder (the
/// remote zenoh router serves it), so this models the wz<->wz dual.
pub async fn accept_serial(endpoint: &SerialEndpoint) -> io::Result<SerialStream> {
    let mut stream = open_serial_device(endpoint)?;
    drive_serial_handshake(&mut stream, SerialRole::Responder).await?;
    Ok(stream)
}

/// Drive the serial-link handshake over an already-open transport to
/// Connected, then return — leaving the stream positioned exactly at the
/// first post-handshake byte. Public so the PTY-loopback e2e (which gets
/// its two ends from [`SerialStream::pair`], not [`dial_serial`]) can drive
/// each end's role before wiring the steady state.
///
/// Reads ONE byte at a time into a private [`SerialFrameReader`] so the loop
/// stops at the handshake frame's `0x00` EOP and never over-reads into the
/// zenoh transport bytes that follow (those must reach the split read half
/// intact). This mirrors `_z_read_serial_internal`'s byte-by-byte
/// read-until-`0x00` (serial_protocol.c:145-177).
///
/// - Initiator: writes INIT, then INIT|ACK -> Ok; RESET -> back off
///   ([`SERIAL_CONNECT_THROTTLE`]) and re-send INIT; anything else -> error.
/// - Responder: awaits INIT, writes INIT|ACK -> Ok; anything else -> error.
pub async fn drive_serial_handshake<S>(stream: &mut S, role: SerialRole) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let handshake = match role {
        SerialRole::Initiator => SerialHandshake::initiator(),
        SerialRole::Responder => SerialHandshake::responder(),
    };
    // Initiator emits the opening INIT; the responder is silent until it
    // observes one (open() -> None).
    if let Some(init) = handshake.open() {
        stream.write_all(&init).await?;
        stream.flush().await?;
    }

    let mut framer = SerialFrameReader::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "serial peer closed during link handshake",
            ));
        }
        let frame = match framer.push(byte[0]) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue, // mid-frame
            Err(_) => continue,   // framing noise; the reader resynced past it
        };
        match handshake.on_header(frame.header) {
            HandshakeStep::Connected => return Ok(()),
            HandshakeStep::EmitAndConnect(reply) => {
                stream.write_all(&reply).await?;
                stream.flush().await?;
                return Ok(());
            }
            HandshakeStep::Throttle => {
                // Peer not ready (RESET). Back off and re-drive INIT, as
                // `_z_connect_serial` loops (serial_protocol.c:266-271).
                tokio::time::sleep(SERIAL_CONNECT_THROTTLE).await;
                if let Some(init) = handshake.open() {
                    stream.write_all(&init).await?;
                    stream.flush().await?;
                }
            }
            HandshakeStep::Failed => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "serial link handshake failed: unexpected control header",
                ));
            }
        }
    }
}

/// Split a handshaked [`SerialStream`] into the cooperating drivers the
/// session FSM consumes: an inbound [`SerialReadDriver`] (`&mut LinkDriver`
/// for the poll loop), an outbound `Arc<`[`SerialWriteDriver`]`>`
/// (`BoxedLinkDriver` for `send_blocking`), and the [`serial_writer_task`]
/// join handle.
///
/// The stream MUST already be past its link handshake (via [`dial_serial`]
/// / [`accept_serial`] / [`drive_serial_handshake`]) — this wires only the
/// steady-state data path. Uses [`tokio::io::split`] (not owned halves;
/// `SerialStream` has none) so the read half and the writer task hold
/// `BiLock`-guarded references to the one tty fd. The handle is awaited at
/// teardown so a tail frame the FSM enqueues during its final transition
/// still drains to the peer before the tty drops.
pub fn wire_serial_stream(
    stream: SerialStream,
) -> (
    SerialReadDriver,
    Arc<SerialWriteDriver>,
    TokioJoinHandle<()>,
) {
    let (reader, writer) = split(stream);
    let inbound = SerialReadDriver::new(reader);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = TokioRuntime.spawn(serial_writer_task(writer, rx));
    let outbound = Arc::new(SerialWriteDriver::new(
        tx,
        addressless_link_subject(InterceptorLink::Serial),
    ));
    (inbound, outbound, writer_handle)
}

/// Inbound read half of the split — owns the [`ReadHalf`] and a
/// [`SerialFrameReader`], and impls [`LinkDriver`] with `poll_event`
/// yielding one decoded frame's payload as an [`RxFrame`]. The send / open /
/// close methods mirror [`crate::link_pipeline::TcpReadDriver`]: open is a
/// no-op (handshaked already), close is a no-op (dropping the half releases
/// its `BiLock` share), and send fails loud (outbound is the sibling
/// [`SerialWriteDriver`]).
pub struct SerialReadDriver {
    reader: ReadHalf<SerialStream>,
    /// Byte accumulator detecting `0x00`-EOP frame boundaries across reads.
    framer: SerialFrameReader,
    /// Frames decoded from a single `read` that returned more than one
    /// complete frame — drained one per `poll_event` call before the next
    /// read, so each call yields exactly one [`LinkEvent`].
    pending: VecDeque<DecodedFrame>,
}

impl SerialReadDriver {
    fn new(reader: ReadHalf<SerialStream>) -> Self {
        Self {
            reader,
            framer: SerialFrameReader::new(),
            pending: VecDeque::new(),
        }
    }
}

impl LinkDriver for SerialReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // The link is already handshaked + connected; open is a no-op,
        // mirroring TcpReadDriver / UdpReadDriver.
        Ok(())
    }

    async fn send(&mut self, _frame: &TxFrame<'_>, _reliability: Reliability) -> io::Result<()> {
        // The read half never sends — outbound goes via SerialWriteDriver.
        // Surface NotConnected so an accidental call fails loud rather than
        // silently dropping the frame.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "SerialReadDriver does not send; outbound goes via SerialWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // The read half drops independently; the writer task shuts the tty
        // when its channel closes. No explicit teardown here.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        // One decoded serial frame == one wire message. A single `read` may
        // return several COBS frames (or a partial one); `pending` carries
        // the surplus so each call yields exactly one event. Cancel-safe:
        // the only `.await` is the single `read`, whose partial state lives
        // in `framer` / the kernel tty buffer (a dropped `read` consumes no
        // bytes), so a `tokio::select!` cancellation loses nothing.
        loop {
            if let Some(frame) = self.pending.pop_front() {
                // Data frames carry header 0x00; the header is ignored on
                // the data path (serial_protocol.c:282-285), so deliver the
                // payload regardless of which control bits it carries.
                return LinkEvent::Rx(RxFrame::new(frame.payload));
            }
            let mut buf = [0u8; SERIAL_MAX_COBS_BUF];
            match self.reader.read(&mut buf).await {
                Ok(0) => {
                    return LinkEvent::Lost {
                        cause: LostCause::PeerClosed,
                    }
                }
                Ok(n) => {
                    for &b in &buf[..n] {
                        match self.framer.push(b) {
                            Ok(Some(frame)) => self.pending.push_back(frame),
                            Ok(None) => {}
                            Err(e) => {
                                // A corrupt frame is discarded + resynced
                                // (pico parity, serial.c:114); a single bad
                                // frame must not tear down an otherwise live
                                // link, so log and keep reading.
                                log::warn!(
                                    "wz-runtime-tokio: serial frame discarded ({e:?}); resyncing"
                                );
                            }
                        }
                    }
                    // Loop: a frame queued above returns at the top; an empty
                    // pass (only partial bytes) reads again.
                }
                Err(_) => {
                    return LinkEvent::Lost {
                        cause: LostCause::OsError,
                    }
                }
            }
        }
    }
}

/// Outbound write half of the split — holds an
/// `mpsc::UnboundedSender<Vec<u8>>` whose receiver the [`serial_writer_task`]
/// owns. Impls [`BoxedLinkDriver`] with a NON-blocking enqueue, the same
/// sync-action / async-runtime decoupling
/// [`crate::link_pipeline::TcpWriteDriver`] uses (a nested `block_on` from a
/// sync FSM action handler would trip the runtime-reentrancy check). The
/// channel carries the RAW payload; the writer task does the serial framing.
pub struct SerialWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// R311y453 — the §5.16 link-derived subject, resolved once at open.
    subject: LinkSubject,
}

impl SerialWriteDriver {
    fn new(tx: mpsc::UnboundedSender<Vec<u8>>, subject: LinkSubject) -> Self {
        Self { tx, subject }
    }
}

impl BoxedLinkDriver for SerialWriteDriver {
    // R311y453 — the §5.16 subject resolved at open. A field read, not a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        // A single serial frame carries at most SERIAL_MTU payload bytes
        // (encode_frame rejects past it). The transport TX path now caps
        // its fragment budget to THIS link's MTU — [`Self::link_mtu`]
        // feeds `SessionLinkActions::negotiated_batch_mtu`, which mins it
        // against the negotiated batch (R311nw) — so a well-formed session
        // fragments an oversize message to <= SERIAL_MTU chunks before it
        // ever reaches this seam. The guard stays as a loud defensive
        // backstop: a caller that bypassed the negotiated budget drops
        // here rather than enqueue a frame the writer can only fail to
        // encode.
        if bytes.len() > SERIAL_MTU {
            log::warn!(
                "wz-runtime-tokio: outbound serial frame {} bytes > {SERIAL_MTU}; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound serial channel closed; dropping frame ({e})");
        }
    }

    fn open_blocking(&self) {
        // The tty is already open + handshaked; open is a no-op on this shape.
    }

    fn close_blocking(&self) {
        // The writer task exits when every sender clone drops (the owning
        // scope releases the Arc). Letting the receiver-drop signal terminate
        // the task is the textbook channel idiom (mirrors TcpWriteDriver).
    }

    fn link_mtu(&self) -> usize {
        // The serial link's fixed frame cap — zenoh-pico's
        // `_z_get_link_mtu_serial` returns `_Z_SERIAL_MTU_SIZE`
        // (`src/link/unicast/serial.c:62`), the same 1500. The transport
        // reads this through `negotiated_batch_mtu` to bound its TX
        // fragment budget (`min(link mtu, negotiated batch)`,
        // transport/unicast/transport.c:47), so a >MTU message splits into
        // emittable frames instead of tripping the `send_blocking` drop
        // guard. TCP / UDP inherit the unbounded `DEFAULT_LINK_MTU`.
        SERIAL_MTU
    }
}

/// Async writer task. Owns the [`WriteHalf`] and drains the outbound channel
/// one payload at a time, COBS-framing each through [`encode_frame`] (header
/// [`SERIAL_DATA_HEADER`] + len + payload + crc32 -> COBS -> `0x00` EOP) and
/// writing + flushing. Exits when every [`SerialWriteDriver`] clone has
/// dropped (receiver returns `None`) or a write fails (logged + bail),
/// shutting the write half so the peer observes EOF.
pub async fn serial_writer_task(
    mut writer: WriteHalf<SerialStream>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        // Defensive: send_blocking already rejects oversize, but a future
        // caller could bypass it. encode_frame rejects > SERIAL_MTU.
        let wire = match encode_frame(SERIAL_DATA_HEADER, &payload) {
            Ok(wire) => wire,
            Err(e) => {
                log::warn!(
                    "wz-runtime-tokio: serial_writer_task encode failed for {} bytes ({e:?}); dropping",
                    payload.len()
                );
                continue;
            }
        };
        if let Err(e) = writer.write_all(&wire).await {
            log::warn!("wz-runtime-tokio: serial_writer_task write failed: {e}; closing");
            return;
        }
        if let Err(e) = writer.flush().await {
            log::warn!("wz-runtime-tokio: serial_writer_task flush failed: {e}; closing");
            return;
        }
    }
    // Channel closed -> shut the write half cleanly (peer sees EOF).
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The serial write driver reports the serial link MTU (not the
    /// unbounded `DEFAULT_LINK_MTU` a stream link inherits), so the
    /// transport's `negotiated_batch_mtu` mins its TX fragment budget down
    /// to a frame the serial link can actually emit. This is the link-side
    /// half of the >MTU fragmentation wiring; the end-to-end split is
    /// proved in `serial_pty_e2e`.
    #[test]
    fn serial_write_driver_reports_serial_link_mtu() {
        // Static invariant: the serial cap must bind BELOW the unbounded
        // stream default, else the `negotiated_batch_mtu` min term would be
        // inert and serial would never fragment. A const assertion so a
        // constant regression fails the build, not a runtime check.
        const _: () = assert!(SERIAL_MTU < wz_session_core::link::DEFAULT_LINK_MTU);

        let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let driver = SerialWriteDriver::new(tx, LinkSubject::UNKNOWN);
        assert_eq!(driver.link_mtu(), SERIAL_MTU);
    }

    /// A PTY pair handshakes end to end: the Initiator end sends INIT, the
    /// Responder end replies INIT|ACK, both `drive_serial_handshake` futures
    /// resolve Ok. Bounded by a `timeout` so a handshake regression fails
    /// fast instead of hanging.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pty_pair_completes_handshake_both_roles() {
        let (mut a, mut b) = SerialStream::pair().expect("openpty pair");
        let init = drive_serial_handshake(&mut a, SerialRole::Initiator);
        let resp = drive_serial_handshake(&mut b, SerialRole::Responder);
        let bounded =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(init, resp) });
        let (ia, rb) = bounded.await.expect("handshake completes within 5s");
        ia.expect("initiator reaches Connected");
        rb.expect("responder reaches Connected");
    }

    /// After the handshake, the wired drivers carry a data frame byte-exact:
    /// `send_blocking` enqueues a raw payload, the writer task COBS-frames it
    /// with header 0x00, and the peer's read driver re-frames + delivers the
    /// payload unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wired_pty_pair_round_trips_one_data_frame() {
        let (mut a, mut b) = SerialStream::pair().expect("openpty pair");
        let bounded = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                drive_serial_handshake(&mut a, SerialRole::Initiator),
                drive_serial_handshake(&mut b, SerialRole::Responder),
            )
        });
        let (ia, rb) = bounded.await.expect("handshake completes");
        ia.expect("initiator connected");
        rb.expect("responder connected");

        let (_a_in, a_out, a_writer) = wire_serial_stream(a);
        let (mut b_in, _b_out, _b_writer) = wire_serial_stream(b);

        let payload = b"hello-serial-frame";
        a_out.send_blocking(payload, Reliability::Reliable);

        let event = tokio::time::timeout(Duration::from_secs(5), b_in.poll_event())
            .await
            .expect("frame arrives within 5s");
        match event {
            LinkEvent::Rx(frame) => assert_eq!(frame.bytes, payload),
            other => panic!("expected Rx, got {other:?}"),
        }

        drop(a_out);
        let _ = a_writer.await;
    }
}
