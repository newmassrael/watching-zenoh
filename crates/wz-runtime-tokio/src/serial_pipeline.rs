// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_serial::SerialStream;

use crate::link_interfaces::{addressless_link_endpoints, addressless_link_subject};
use crate::writer_queue::{OutboundQueue, WriterHandle};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::{InterceptorLink, LinkEndpoints, LinkSubject};
use wz_session_core::link::{LinkDropCause, LinkSendOutcome};
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

/// R2722 — "a link is live on this tty", shared between the listener that
/// accepted it and the link itself.
///
/// ⛔ THIS IS THE STRUCTURE WZ DID NOT HAVE, and every serial listener defect
/// above it was a consequence. A tty is point-to-point, so at most one link may
/// hold the device — but "one at a time" and "one ever" are different rules, and
/// without feedback from the link a listener cannot tell them apart. wz's
/// listener carried a one-shot `armed: bool` and parked on both, which made it
/// unable to serve a second peer and left `release_on_close` with nothing to
/// express, since that key's entire observable effect is on a re-accept.
///
/// Upstream is the same shape and is where this one is read from: an
/// `is_connected: Arc<AtomicBool>` its accept task spins on before re-opening
/// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs`
/// @ `while is_connected.load(Ordering::Acquire) {`), stored `true` once a link
/// is accepted (@ `is_connected.store(true, Ordering::Release);`) and cleared by
/// the LINK's own close (@ `self.is_connected.store(false, Ordering::Release);`).
///
/// wz clears it from [`SerialLinkGuard`]'s `Drop` rather than from a `close`
/// method, because wz's accepted link has no close call of its own — it is torn
/// down by being dropped, and a teardown path that must be REMEMBERED is the
/// class this workspace files against itself.
#[derive(Clone, Debug, Default)]
pub struct SerialLiveness(Arc<AtomicBool>);

impl SerialLiveness {
    /// Whether a link accepted off this device is still alive.
    pub fn is_live(&self) -> bool {
        self.0.load(AtomicOrdering::Acquire)
    }

    /// Mark the device taken and hand back the guard that releases it.
    ///
    /// Returning the guard rather than setting a flag and trusting the caller is
    /// what makes the release unforgettable: the only way to claim is to hold
    /// something whose `Drop` un-claims.
    pub fn claim(&self) -> SerialLinkGuard {
        self.0.store(true, AtomicOrdering::Release);
        SerialLinkGuard(self.clone())
    }
}

/// The half of [`SerialLiveness`] the LINK holds: dropping it tells the listener
/// the device is free.
///
/// It is deliberately opaque and has no methods. A guard that could be asked
/// questions would invite a caller to branch on it, and the only correct use of
/// this value is to hold it for exactly as long as the link lives.
#[derive(Debug)]
pub struct SerialLinkGuard(SerialLiveness);

impl Drop for SerialLinkGuard {
    fn drop(&mut self) {
        self.0 .0.store(false, AtomicOrdering::Release);
    }
}

/// An open tty plus, when a LISTENER handed it out, the guard that tells that
/// listener when the link is gone.
///
/// A newtype rather than a second enum field, so `DialedLink::Serial`'s `stream`
/// keeps its name and every construction and match site reads as it did. The
/// guard is `Option` because the two ways to get a serial link are genuinely
/// different: a DIAL owns the device outright and has no listener to report to,
/// while an ACCEPT borrows it from a listener that will hand it out again.
///
/// ⚠ The guard is held and never read, which is the whole contract — its `Drop`
/// is the observable. It is not `_`-prefixed and not `#[allow]`-ed: it is READ,
/// once, by [`Self::into_parts`], because the wiring seam has to move it onto
/// whatever outlives the split. A guard silently dropped at the split would mark
/// the device free while the link was still running, which is the same defect as
/// having no guard at all and harder to see.
pub struct SerialPort {
    stream: SerialStream,
    guard: Option<SerialLinkGuard>,
}

impl std::fmt::Debug for SerialPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerialPort")
            .field("accepted", &self.guard.is_some())
            .finish()
    }
}

impl SerialPort {
    /// A device this process opened for itself — no listener is waiting on it.
    pub fn dialled(stream: SerialStream) -> Self {
        Self {
            stream,
            guard: None,
        }
    }

    /// A device a listener handed out, carrying the guard that frees it.
    pub fn accepted(stream: SerialStream, guard: SerialLinkGuard) -> Self {
        Self {
            stream,
            guard: Some(guard),
        }
    }

    /// The stream, mutably — the serial-link handshake runs over the WHOLE
    /// device before the split, exactly as it did when this was a bare stream.
    pub fn stream_mut(&mut self) -> &mut SerialStream {
        &mut self.stream
    }

    /// Split into the two things the wiring seam needs to keep apart: the stream
    /// it consumes, and the guard it must keep alive past the consumption.
    pub fn into_parts(self) -> (SerialStream, Option<SerialLinkGuard>) {
        (self.stream, self.guard)
    }
}

/// Open the host tty for a [`SerialEndpoint`] — the raw serial-device
/// open primitive (no handshake yet). Only [`SerialTarget::Device`] paths
/// are openable by the host tty backend; a [`SerialTarget::Pins`] target is
/// an MCU UART HAL endpoint with no host device node, so it surfaces a
/// typed `Unsupported` rather than a misleading "no such file".
///
/// Public since R311y805 because the ACCEPT seam needs the two halves of
/// [`accept_serial`] separately: `BoundListener::Serial::accept_raw` runs
/// this (cheap, local, unblocked) and DEFERS the peer-controlled
/// [`drive_serial_handshake`] to `AcceptedLink::handshake`, exactly as the
/// tls/quic acceptors defer their crypto off the accept path. A caller that
/// wants both halves in one call still uses [`accept_serial`].
pub fn open_serial_device(endpoint: &SerialEndpoint) -> io::Result<SerialStream> {
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
    // R2704 — `tout` is deliberately NOT applied to the builder here, and the
    // reason is measured rather than assumed: tokio-serial's `SerialStream`
    // implements `SerialPort::timeout` as `Duration::from_secs(0)` whatever the
    // builder said, because a blocking read timeout is meaningless for an async
    // `AsyncFd` stream. Setting it would have been a line that reads as
    // honouring the key while changing nothing. Upstream spends `tout` on
    // `port.connect(Some(Duration::from_micros(tout)))` -- the serial-link
    // HANDSHAKE -- so wz spends it there too; see [`dial_serial`].
    let builder = tokio_serial::new(path, endpoint.baudrate);
    // tokio_serial::Error impls std::error::Error -> io::Error::other carries
    // it without lossy stringly-typed remapping.
    let mut stream = SerialStream::open(&builder).map_err(io::Error::other)?;
    // `exclusive` is stated in BOTH directions rather than only when false.
    // tokio-serial opens exclusive by default, so wz already matched upstream's
    // default -- what was missing was the CHOICE, and a call that only fired on
    // one value would leave the other resting on a library default that is
    // nobody's stated intent.
    stream
        .set_exclusive(endpoint.options.exclusive)
        .map_err(io::Error::other)?;
    Ok(stream)
}

/// R2704 — the `interfaces` an ACL can narrow a serial link by: THIS link's
/// device name, without the path.
///
/// ## Why not upstream's list
///
/// Upstream answers with every serial port on the host
/// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `match z_serial::get_available_port_names()`),
/// and its own comment states the INTENT as the singular — "for serial port
/// `/dev/ttyUSB0` interface name will be `ttyUSB0`". Those two disagree the
/// moment a host has two ports: a rule naming `ttyUSB1` then governs a link
/// running on `ttyUSB0`, because `ttyUSB1` merely EXISTS. wz answers the
/// intent. That is a strict subset of upstream's answer, it always contains the
/// name that identifies this link, and it differs only where upstream would
/// govern a link by an unrelated device's presence — which this atom's own
/// `SerialTarget::Pins` clause already settled as the criterion: refusing where
/// refusing is right is not a gap.
///
/// ## And a second reason not to enumerate
///
/// wz takes `tokio-serial` with `default-features = false` to avoid a libudev
/// system-lib build dep (see its Cargo.toml entry). The enumeration that
/// remains on Linux without libudev scans `/sys/class/tty` and does so through
/// an `.expect(..)` — so on a host without that directory, enumerating would
/// PANIC rather than return the `Err` upstream's arm handles. Answering from
/// the endpoint reaches no filesystem at all and cannot fail.
///
/// Pins yield NO name: there is no device file, and the host tty backend
/// refuses that target anyway.
pub(crate) fn serial_interface_names(endpoint: &SerialEndpoint) -> Vec<String> {
    match &endpoint.target {
        SerialTarget::Device(path) => {
            let name = path.rsplit('/').next().unwrap_or(path);
            if name.is_empty() {
                Vec::new()
            } else {
                vec![name.to_string()]
            }
        }
        SerialTarget::Pins { .. } => Vec::new(),
    }
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
    drive_serial_handshake_within(
        &mut stream,
        SerialRole::Initiator,
        endpoint.options.timeout_us,
    )
    .await?;
    Ok(stream)
}

/// R2704 — [`drive_serial_handshake`] bounded by the locator's `tout`, in
/// MICROSECONDS.
///
/// This is where upstream spends that key: its dial calls
/// `io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `port.connect(Some(Duration::from_micros(tout))).await?;`,
/// so the window bounds the INIT / INIT|ACK exchange rather than each read. wz
/// had no handshake timeout at all and said so in [`dial_serial`]'s own docs --
/// "bounding the wait is the caller's concern" -- which was a defensible
/// position for a seam with no configured window and is simply wrong now that
/// the locator carries one. Upstream's default is 50 ms.
///
/// ⚠ DIAL ONLY, matching upstream: its ACCEPT path takes no `tout` and instead
/// retries `accept()` behind a throttle, which is what [`accept_serial`] does.
/// A listener that timed out would be refusing a peer that has not spoken YET,
/// which is the normal state of a listener.
pub async fn drive_serial_handshake_within<S>(
    stream: &mut S,
    role: SerialRole,
    timeout_us: u64,
) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    match tokio::time::timeout(
        Duration::from_micros(timeout_us),
        drive_serial_handshake(stream, role),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "serial link handshake did not complete within {timeout_us}us \
                 (the locator's `tout`); the peer never answered"
            ),
        )),
    }
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
/// `endpoint` is the tty this stream was opened from — carried in only so the
/// driver can report its adminspace `{src,dst}` pair (R311y474). A serial link's
/// address is not readable off the stream the way a socket's is, so the ONE object
/// that knows it is the endpoint the caller dialled.
pub fn wire_serial_stream(
    port: SerialPort,
    endpoint: &SerialEndpoint,
) -> (SerialReadDriver, Arc<SerialWriteDriver>, WriterHandle) {
    // R2722 — the guard moves onto the READ driver, which is the half of the
    // split that lives exactly as long as the link does: the session holds it
    // for the link's whole life and drops it at teardown. Dropping the guard
    // here instead would tell the listener the tty was free the moment the link
    // started running.
    let (stream, guard) = port.into_parts();
    let (reader, writer) = split(stream);
    let inbound = SerialReadDriver::new(reader, guard);
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = WriterHandle::spawn(rx, |queue| serial_writer_task(writer, queue));
    // R311y474 — the adminspace `{src,dst}` pair. BOTH ends are this tty's own
    // locator, which is upstream's DIAL-side behaviour verbatim: zenoh passes its
    // one `path` as both `src_path` and `dst_path`
    // (`io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {`).
    // For a point-to-point tty that
    // is the honest answer — the device IS the link, and dialling that locator
    // from this host reaches this link.
    //
    // The one upstream behaviour deliberately NOT reproduced is its LISTENER side,
    // which puts a random UUIDv4 in `dst` (`unicast.rs:329-333`). That string is
    // not a locator anything can dial, which violates the contract on
    // `BoxedLinkDriver::link_endpoints`; and wz has no wired serial acceptor to
    // apply it to anyway (`session_open.rs:2048` — a serial accept is a tty open,
    // not a listen bind).
    let locator = endpoint.locator_address_with_config();
    let outbound = Arc::new(SerialWriteDriver::new(
        tx,
        // R2704 — this link's OWN device name, which closes the R2548 residual.
        // An ACL narrowed by `interfaces` can now target a serial link here as
        // it can upstream. See [`serial_interface_names`] for why this is the
        // link's device rather than the whole system's port list.
        addressless_link_subject(InterceptorLink::Serial, serial_interface_names(endpoint)),
        Some(addressless_link_endpoints(
            InterceptorLink::Serial,
            &locator,
            &locator,
        )),
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
    /// R2722 — present only on an ACCEPTED link: the listener's claim on this
    /// tty, released when this driver drops.
    ///
    /// Held and never read, deliberately. Its `Drop` is the whole contract, and
    /// this driver is where it belongs because this is the half of the split
    /// whose lifetime IS the link's: the session owns it from wiring to
    /// teardown. [`SerialReadDriver::device_is_claimed`] exists so the property
    /// is observable to a test rather than only to the listener it reports to —
    /// an invariant nothing can look at is one nothing can witness.
    liveness: Option<SerialLinkGuard>,
}

impl SerialReadDriver {
    fn new(reader: ReadHalf<SerialStream>, liveness: Option<SerialLinkGuard>) -> Self {
        Self {
            reader,
            framer: SerialFrameReader::new(),
            pending: VecDeque::new(),
            liveness,
        }
    }

    /// Whether this link holds a listener's claim on its device.
    ///
    /// `false` for a DIALLED link, which owns its tty outright and reports to
    /// nobody. This is the read that keeps [`Self::liveness`] an invariant
    /// rather than a field nothing can see.
    pub fn device_is_claimed(&self) -> bool {
        self.liveness.is_some()
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
    /// R311y474 — the adminspace `{src,dst}` locator pair, resolved once at open.
    endpoints: Option<LinkEndpoints>,
}

impl SerialWriteDriver {
    fn new(
        tx: mpsc::UnboundedSender<Vec<u8>>,
        subject: LinkSubject,
        endpoints: Option<LinkEndpoints>,
    ) -> Self {
        Self {
            tx,
            subject,
            endpoints,
        }
    }
}

impl BoxedLinkDriver for SerialWriteDriver {
    // R311y453 — the §5.16 subject resolved at open. A field read, not a syscall.
    fn link_subject(&self) -> Option<&LinkSubject> {
        Some(&self.subject)
    }

    // R311y474 — the adminspace `{src,dst}` pair resolved at open. A field read.
    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        self.endpoints.as_ref()
    }

    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
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
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-runtime-tokio: outbound serial channel closed; dropping frame ({e})");
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        }
        LinkSendOutcome::Sent
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
/// writing + flushing. Exits when the queue is SEALED and drained, when every
/// [`SerialWriteDriver`] clone has dropped, or when a write fails / stalls past
/// [`WRITER_STALL_MS`](crate::writer_queue::WRITER_STALL_MS) on a sealed queue
/// (logged + bail) — see [`crate::writer_queue`] for why the seal, and not
/// sender liveness alone, is the teardown signal. The first two shut the write
/// half so the peer observes EOF.
pub async fn serial_writer_task(mut writer: WriteHalf<SerialStream>, mut queue: OutboundQueue) {
    while let Some(payload) = queue.next().await {
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
        let write = async {
            writer.write_all(&wire).await?;
            writer.flush().await
        };
        match queue.guarded(write).await {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                log::warn!("wz-runtime-tokio: serial_writer_task write failed: {e}; closing");
                return;
            }
            None => {
                log::warn!(
                    "wz-runtime-tokio: serial_writer_task stalled past {} ms draining a \
                     sealed queue; closing with frames undelivered",
                    crate::writer_queue::WRITER_STALL_MS
                );
                return;
            }
        }
    }
    // Queue finished -> shut the write half cleanly (peer sees EOF).
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::locator::SerialOptions;

    /// R2704 — the locator's `tout` bounds the handshake, as upstream's does.
    ///
    /// The peer end is opened and then NEVER written to, which is the case
    /// upstream's `port.connect(Some(..))` exists for. Before this round the
    /// initiator would re-send INIT on every RESET forever, so the only bound
    /// was whatever the caller happened to compose.
    #[tokio::test]
    async fn a_handshake_is_bounded_by_the_locators_tout() {
        let (mut a, _b) = SerialStream::pair().expect("openpty serial pair");
        // A short window so the test costs nothing; the VALUE is the point, not
        // the duration -- it is read from the endpoint, not hard-coded in the
        // seam.
        // ⚠ BOUNDED BY THE TEST TOO, and that is not belt-and-braces: without
        // the seam's own bound this call never returns, so the control for this
        // witness would HANG rather than red -- and a hang is not a failure, it
        // is a suite that never finishes. The outer bound turns "the seam did
        // not bound it" into an assertion with a message.
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            drive_serial_handshake_within(&mut a, SerialRole::Initiator, 20_000),
        )
        .await
        .expect(
            "the seam's own `tout` must fire far inside this test's 5s bound; \
             reaching this means the handshake is unbounded",
        )
        .expect_err("a peer that never answers must not be waited on forever");
        assert_eq!(
            err.kind(),
            io::ErrorKind::TimedOut,
            "the handshake bound must report a timeout, not some other failure: {err}"
        );
    }

    /// The ANTI-VACUITY half: the bound must not be so eager that it refuses a
    /// handshake that DOES complete. Without this, a `drive_serial_handshake_within`
    /// that returned `TimedOut` unconditionally would satisfy the test above.
    #[tokio::test]
    async fn a_bounded_handshake_still_completes_against_a_peer_that_answers() {
        let (mut a, mut b) = SerialStream::pair().expect("openpty serial pair");
        let responder =
            tokio::spawn(
                async move { drive_serial_handshake(&mut b, SerialRole::Responder).await },
            );
        drive_serial_handshake_within(&mut a, SerialRole::Initiator, 5_000_000)
            .await
            .expect("a peer that answers completes inside the window");
        responder
            .await
            .expect("responder task")
            .expect("the responder half completes too");
    }

    /// The endpoint a PTY-pair test stands in for. `SerialStream::pair()` opens an
    /// `openpty` pair and exposes NEITHER end's device name, so a wired PTY link
    /// has no readable address — the endpoint is supplied, exactly as the real dial
    /// path supplies the one it parsed from the locator.
    fn pty_endpoint() -> SerialEndpoint {
        SerialEndpoint {
            target: SerialTarget::Device("/dev/wz-test-pty".to_string()),
            baudrate: 115_200,
            options: SerialOptions::default(),
        }
    }

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
        let driver = SerialWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
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

        let (_a_in, a_out, a_writer) = wire_serial_stream(SerialPort::dialled(a), &pty_endpoint());
        let (mut b_in, _b_out, _b_writer) =
            wire_serial_stream(SerialPort::dialled(b), &pty_endpoint());

        let payload = b"hello-serial-frame";
        assert_eq!(
            a_out.send_blocking(payload, Reliability::Reliable),
            LinkSendOutcome::Sent
        );

        let event = tokio::time::timeout(Duration::from_secs(5), b_in.poll_event())
            .await
            .expect("frame arrives within 5s");
        match event {
            LinkEvent::Rx(frame) => assert_eq!(frame.bytes, payload),
            other => panic!("expected Rx, got {other:?}"),
        }

        drop(a_out);
        let _ = a_writer.into_join().await;
    }
}
