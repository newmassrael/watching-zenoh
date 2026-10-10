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
//! ## The accept's flush (open-debt 795)
//!
//! An accepting side discards what the device holds when the accept happens,
//! because upstream does (`z-serial-0.3.1` @ `pub async fn accept(&mut self)` clears
//! before it waits for `INIT`) and because a re-used device still carries the previous
//! peer's tail. That flush is a CONTRACT with three parts, and each is held by tests:
//!
//! 1. **An `INIT` that reached the device before the flush survives it.** An
//!    initiator writes its `INIT` once and re-sends only after a `RESET`, which a
//!    responder never sends, so an `INIT` discarded here is not late, it is gone,
//!    and both ends then wait for ever. The accept therefore reads what the device
//!    holds, keeps the last `INIT` among it, and the deferred handshake answers that
//!    `INIT` before it reads the device again.
//! 2. **Every other byte received before the flush is discarded, and none received
//!    after it is.** Data frames, frames that fail their CRC and an unterminated tail
//!    are stale and are not handed to the handshake (which would fail on a data
//!    frame); the flush is the instant the device is first read, so a byte arriving
//!    later is the new peer's and is read normally. Nothing is cleared on the input
//!    side with `tcflush`: that call cannot tell an `INIT` from a stale byte, and a
//!    byte landing between a read and a `tcflush` would be lost with them.
//!
//! 3. **A stale fragment no `0x00` closed does not hide the `INIT` behind it.** A
//!    frame on the wire is `COBS(body) 0x00`: only its END is marked, and pico and
//!    upstream read up to the `0x00` and drop the whole span when its CRC fails. So
//!    an unterminated fragment and the `INIT` after it are one span that neither
//!    peer recovers. The flush looks for the `INIT` inside such a span from every
//!    start offset ([`wz_session_core::serial_link::pending_init_header`] states what
//!    an offset must pass and the false-accept bound, below 2^-32 per offset).
//!    Nothing is sent for this: the wire is unchanged, with no `RESET` from the
//!    responder, which upstream does not send either. The steady-state reader is
//!    untouched and still drops such a span. The search is `O(n * frame limit)` at
//!    worst in the `n` bytes held, which `SERIAL_FLUSH_LIMIT` caps at 1 MiB.
//!
//! What is still not recovered is stated rather than hidden, and each case is held
//! by a test: an `INIT` whose body reached the device but whose `0x00` has not (the
//! unterminated tail is never searched: its end is unknown, and what arrives after
//! the flush completes it); an `INIT` the line corrupted, which fails its CRC at every
//! offset. The dial side keeps the full clear: an initiator wants nothing that was
//! on the wire before it spoke.
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
//! The stream the link runs over is a `BoxedSerialStream` (R2995, open-debt
//! 852): a tty's `SerialStream` when there is a device, or an in-memory
//! duplex where there is none, so the framing, handshake, MTU cap, liveness claim
//! and retained device are exercised on every host rather than only on one with
//! an `openpty` pair. [`SerialStream`] is `AsyncRead + AsyncWrite` but NOT owned-half
//! splittable the way [`tokio::net::TcpStream::into_split`] is, so
//! [`tokio::io::split`] is used (a `BiLock` shared between the halves —
//! each `poll_read` / `poll_write` is non-blocking on the tty `AsyncFd`, so
//! the lock contention is negligible). The split is the same TCP shape: an
//! inbound `&mut LinkDriver` read half + an outbound
//! `Arc<dyn BoxedLinkDriver>` write half drained by a [`serial_writer_task`].

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf,
    WriteHalf,
};
use tokio_serial::SerialStream;

use crate::link_interfaces::{addressless_link_endpoints, addressless_link_subject};
use crate::sync::Mutex;
use crate::writer_queue::{OutboundQueue, WriterHandle};
use crate::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::{LinkDropCause, LinkSendOutcome};
use wz_session_core::link::{LinkEndpoints, LinkKind, LinkSubject};
use wz_session_core::locator::{SerialEndpoint, SerialTarget};
use wz_session_core::serial_link::{
    encode_frame_into, pending_init_header, DecodedFrame, HandshakeStep, SerialFrameReader,
    SerialHandshake, SerialRole, SERIAL_MAX_COBS_BUF, SERIAL_MTU,
};

/// Steady-state data-frame header — no handshake flag set. The receiver
/// ignores the header on the data path (`_z_read_serial`,
/// serial_protocol.c:282-285); it is the control byte ONLY during the
/// link handshake (INIT / INIT|ACK / RESET).
const SERIAL_DATA_HEADER: u8 = 0x00;

/// Initiator back-off between INIT retries when the peer answers RESET
/// (`SERIAL_CONNECT_THROTTLE_TIME_MS`, serial_protocol.c:37).
const SERIAL_CONNECT_THROTTLE: Duration = Duration::from_millis(250);

/// R2995 (open-debt 852) -- what the serial link needs of the byte stream it
/// runs over: a duplex of bytes it can move between tasks, and a way to discard
/// what the OS is still holding for it.
///
/// ⛔ THE STRUCTURE THIS ADDS is the boundary between the link and the device. The
/// handshake, the COBS framing, the MTU cap, the liveness claim and the retained
/// device never depended on a tty -- they read and write bytes -- but every type
/// that carried the stream was spelled `SerialStream`, so the only way to run any
/// of it was to own a tty, and the only tty pair there is (`SerialStream::pair`,
/// an `openpty` pair) exists on a Unix alone. A Windows runner therefore compiled
/// the link and executed none of it. The trait is what lets a test hand the same
/// machinery an in-memory duplex on EVERY host, and leaves the real-device arms
/// (open, exclusive, clear) to the tests that need a real device.
///
/// The two methods are what an accept's flush needs of a device (open-debt 795, see
/// the module docs): a read that takes what is already there and never waits, and a
/// way to drop what is queued for sending. They are separate because the input side
/// must be READ, not flushed -- an `INIT` in it has to survive -- while the output
/// side has nothing worth keeping. They are required rather than defaulted: a default
/// that polled would be exact for an in-memory pipe and silently wrong for a tty,
/// whose readiness is only known after the reactor has turned.
pub trait SerialByteStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    /// Take the bytes this device has already received, without waiting for more.
    /// An empty vector means the line is quiet, which is the normal answer.
    fn take_received(&mut self) -> io::Result<Vec<u8>>;

    /// Discard what this device holds queued for SENDING. A stream with no device
    /// queues has nothing to discard.
    fn clear_unsent(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Upper bound on the bytes one accept's flush will take off the device.
///
/// A line cannot hold more than a few kernel buffers of stale bytes, so reaching
/// this means the peer is still writing faster than the flush reads -- a virtual
/// line with a peer in a tight loop. Failing the accept by name is the honest answer;
/// reading on would hold the accept for as long as the peer cared to write.
const SERIAL_FLUSH_LIMIT: usize = 1 << 20;

/// Add one read's bytes to what the flush has taken, refusing past the bound.
fn append_flushed(taken: &mut Vec<u8>, chunk: &[u8]) -> io::Result<()> {
    if taken.len() + chunk.len() > SERIAL_FLUSH_LIMIT {
        return Err(io::Error::other(format!(
            "serial line did not go quiet: more than {SERIAL_FLUSH_LIMIT} bytes arrived \
             while the accept was discarding what the device held"
        )));
    }
    taken.extend_from_slice(chunk);
    Ok(())
}

/// A waker that does nothing: the flush polls a read once and moves on, so there is
/// nothing to wake.
struct NoWake;

impl Wake for NoWake {
    fn wake(self: Arc<Self>) {}
}

/// [`SerialByteStream::take_received`] for a stream whose readiness is decided in
/// memory, by one poll of its read side.
///
/// Exact for an in-memory pipe, whose `poll_read` answers from its own buffer with no
/// reactor in between. NOT usable for a tty, which is why [`SerialStream`] reads the
/// fd directly instead.
///
/// The polling runs under [`tokio::task::unconstrained`]: a tokio read inside a task
/// spends a cooperative-scheduling budget and answers `Pending` once it is spent
/// (128 reads), even with bytes queued, and a flush that took that for "the line is
/// quiet" would keep a stale tail.
fn take_received_by_polling<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let waker = Waker::from(Arc::new(NoWake));
    let mut cx = Context::from_waker(&waker);
    let mut chunk = [0u8; 512];
    let mut taken = Vec::new();
    let mut take = tokio::task::unconstrained(std::future::poll_fn(|cx| loop {
        let mut buf = ReadBuf::new(&mut chunk);
        match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) if buf.filled().is_empty() => break Poll::Ready(Ok(())), // closed
            Poll::Ready(Ok(())) => {
                if let Err(e) = append_flushed(&mut taken, buf.filled()) {
                    break Poll::Ready(Err(e));
                }
            }
            Poll::Ready(Err(e)) => break Poll::Ready(Err(e)),
            Poll::Pending => break Poll::Ready(Ok(())),
        }
    }));
    match Pin::new(&mut take).poll(&mut cx) {
        Poll::Ready(Ok(())) => Ok(taken),
        Poll::Ready(Err(e)) => Err(e),
        // The closure above never answers `Pending`; this arm keeps that claim
        // checked rather than assumed.
        Poll::Pending => Err(io::Error::other("the serial flush future did not complete")),
    }
}

impl SerialByteStream for SerialStream {
    /// Reads the fd directly (`SerialStream::try_read`), not through the async read:
    /// a freshly opened tty has had no readiness recorded by the reactor yet, so the
    /// async read answers `Pending` for bytes that are already queued, and a flush
    /// that took that for "the line is quiet" would leave the stale bytes in the
    /// queue for the handshake to read.
    fn take_received(&mut self) -> io::Result<Vec<u8>> {
        let mut taken = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match self.try_read(&mut chunk) {
                Ok(0) => return Ok(taken),
                Ok(n) => append_flushed(&mut taken, &chunk[..n])?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(taken),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn clear_unsent(&self) -> io::Result<()> {
        tokio_serial::SerialPort::clear(self, tokio_serial::ClearBuffer::Output)
            .map_err(io::Error::other)
    }
}

/// The in-memory stream: a serial link with no device under it. It exists so the
/// link's logic has a witness that runs on a host with no tty pair (open-debt 852).
impl SerialByteStream for DuplexStream {
    fn take_received(&mut self) -> io::Result<Vec<u8>> {
        take_received_by_polling(self)
    }
}

/// The accept-side flush (open-debt 795): take what the device holds, drop what it
/// has queued to send, and report the `INIT` that must survive.
///
/// The returned header is the one frame the handshake is given back; everything else
/// taken here is dropped. See the module docs for the two-sided contract.
pub(crate) fn flush_for_accept<S>(stream: &mut S) -> io::Result<Option<u8>>
where
    S: SerialByteStream + ?Sized,
{
    let received = stream.take_received()?;
    stream.clear_unsent()?;
    Ok(pending_init_header(&received))
}

/// A serial stream with its concrete type erased -- what a [`SerialPort`] and a
/// listener's retained device carry, so one `DialedLink::Serial` can hold either a
/// tty or an in-memory stream. The cost is one vtable hop per poll on a link whose
/// line rate is a few hundred kilobits at most.
pub type BoxedSerialStream = Box<dyn SerialByteStream>;

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
///
/// R2727 — it also carries the way BACK for the two halves of a link that has
/// died, which is what makes `release_on_close=false` expressible: see
/// `SerialRetainSlot` (a code span and not a link, because it is private and
/// this type is not).
#[derive(Clone, Debug)]
pub struct SerialLiveness(Arc<SerialLivenessInner>);

/// The state a [`SerialLiveness`] shares between a listener and the one link it
/// handed the device to.
#[derive(Debug)]
struct SerialLivenessInner {
    /// Whether a link accepted off this device is still alive.
    live: AtomicBool,
    /// Whether the device is RETAINED past its link instead of re-opened per
    /// accept — i.e. `release_on_close == false`. Stored inverted from the
    /// locator key on purpose: the key names what CLOSING does, this names what
    /// the listener HOLDS, and the listener is the thing this value belongs to.
    /// Upstream makes the same choice by branching on the key at both ends
    /// rather than storing it as a mood
    /// (`io/zenoh-links/zenoh-link-serial/src/unicast.rs`
    /// @ `if self.release_on_close {` in `close`, @ `if release_on_close {` in
    /// its accept task).
    retain_device: bool,
    /// The halves on their way home, and the re-assembled device once both have
    /// arrived.
    returned: Mutex<SerialRetainSlot>,
}

/// R2727 — where a dying link's two halves meet so the device can outlive it.
///
/// ⛔ THE HALVES LIVE IN DIFFERENT PLACES, which is the whole reason this is a
/// shared slot rather than a field on either of them: the READ half sits in
/// [`SerialReadDriver`] (dropped by the session at teardown) and the WRITE half
/// is owned by [`serial_writer_task`] (a spawned task whose contract is
/// `Output = ()` across ten pipelines). The one object both can already reach is
/// the [`SerialLiveness`] the listener shares with the link, so the slot goes
/// there.
///
/// A half arriving alone is NOT a retained device — [`tokio::io::split`]'s
/// `unsplit` needs both, and panics if handed halves that are not a pair. That
/// gives the rule this round runs on: **both halves back ⇒ retain; one or none
/// ⇒ the next accept re-opens the device.** It is not a compromise. The one
/// teardown path that loses a half is [`WriterHandle::abort`](crate::writer_queue::WriterHandle::abort),
/// whose own docs name its use — "callers tearing down a session whose link is
/// already gone" — and a tty whose writer was cancelled mid-frame is in an
/// unknown state, so re-opening it is the RIGHT answer there rather than a
/// fallback.
///
/// ⚠ This is where wz DIVERGES from upstream and the divergence is stated, not
/// hidden: upstream's port lives inside the link object and its accept task
/// co-owns that object, so it keeps the port however the link died. wz re-opens
/// on the abort path, which makes `release_on_close=false` a **best-effort
/// retain** here.
#[derive(Default)]
struct SerialRetainSlot {
    reader: Option<ReadHalf<BoxedSerialStream>>,
    writer: Option<WriteHalf<BoxedSerialStream>>,
    /// Both halves, re-assembled — the device the next accept reuses.
    port: Option<BoxedSerialStream>,
}

impl std::fmt::Debug for SerialRetainSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Presence only: the halves are live tty handles, and the same reason
        // `SerialPort`'s `Debug` prints a bool rather than its stream.
        f.debug_struct("SerialRetainSlot")
            .field("reader", &self.reader.is_some())
            .field("writer", &self.writer.is_some())
            .field("port", &self.port.is_some())
            .finish()
    }
}

impl SerialRetainSlot {
    /// Re-assemble once BOTH halves are home.
    ///
    /// A port already sitting here is STALE and is dropped (closing its fd): it
    /// can only be one a previous link handed back after the next accept had
    /// already given up waiting and re-opened the device, so the pair that just
    /// arrived is the newer one.
    fn settle(&mut self) {
        if self.reader.is_some() && self.writer.is_some() {
            let reader = self.reader.take().expect("checked immediately above");
            let writer = self.writer.take().expect("checked immediately above");
            self.port = Some(reader.unsplit(writer));
        }
    }
}

impl SerialLiveness {
    /// A listener's liveness channel for one bound tty.
    ///
    /// `retain_device` is `!release_on_close`: `true` keeps the open device past
    /// its link for the next accept to reuse, `false` (the locator default) lets
    /// it close so the next accept re-opens it, which is upstream's
    /// `unset_port()` on close.
    pub fn new(retain_device: bool) -> Self {
        Self(Arc::new(SerialLivenessInner {
            live: AtomicBool::new(false),
            retain_device,
            returned: Mutex::new(SerialRetainSlot::default()),
        }))
    }

    /// Whether a link accepted off this device is still alive.
    pub fn is_live(&self) -> bool {
        self.0.live.load(AtomicOrdering::Acquire)
    }

    /// Mark the device taken and hand back the guard that releases it.
    ///
    /// Returning the guard rather than setting a flag and trusting the caller is
    /// what makes the release unforgettable: the only way to claim is to hold
    /// something whose `Drop` un-claims.
    pub fn claim(&self) -> SerialLinkGuard {
        self.0.live.store(true, AtomicOrdering::Release);
        SerialLinkGuard(self.clone())
    }

    /// R2727 — whether an OPEN device is being held for the next accept.
    ///
    /// The observable for `release_on_close`. Retention is otherwise visible
    /// only to the accept that consumes it, and an invariant nothing can look at
    /// is one nothing can witness — the same reason
    /// [`SerialReadDriver::device_is_claimed`] exists.
    pub fn retains_device(&self) -> bool {
        self.lock_returned().port.is_some()
    }

    /// Hand the READ half home. Called from [`SerialReadDriver`]'s `Drop`.
    fn return_reader(&self, reader: ReadHalf<BoxedSerialStream>) {
        if !self.0.retain_device {
            return; // `release_on_close=true`: let the half close.
        }
        let mut slot = self.lock_returned();
        slot.reader = Some(reader);
        slot.settle();
    }

    /// Hand the WRITE half home. Called when [`serial_writer_task`] returns.
    fn return_writer(&self, writer: WriteHalf<BoxedSerialStream>) {
        if !self.0.retain_device {
            return; // `release_on_close=true`: let the half close.
        }
        let mut slot = self.lock_returned();
        slot.writer = Some(writer);
        slot.settle();
    }

    /// Take the retained device, if one is being held. The accept seam's read.
    pub(crate) fn take_retained(&self) -> Option<BoxedSerialStream> {
        self.lock_returned().port.take()
    }

    /// The slot, past a poisoned lock.
    ///
    /// A panic while holding this lock can only have come from `unsplit`'s
    /// pair check, and poisoning would then make every later accept on this
    /// listener panic too — turning one bad teardown into a dead listener. The
    /// slot's own invariant does not depend on the panicking section having
    /// finished (each field is independently `Option`), so the guard is taken
    /// either way.
    fn lock_returned(&self) -> std::sync::MutexGuard<'_, SerialRetainSlot> {
        self.0
            .returned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The half of [`SerialLiveness`] the LINK holds: dropping it tells the listener
/// the device is free.
///
/// R2727 — it answers exactly ONE question, `Self::liveness`, and that is not
/// the branch this doc used to refuse. The refusal was of a guard a caller could
/// INTERROGATE — "is the device free?", "am I still the holder?" — because the
/// only correct use of this value is to hold it for as long as the link lives,
/// and a readable state invites a caller to act on it instead. Naming the
/// channel it reports to is a different thing: it hands the WRITE half, which
/// lives in a spawned task rather than behind this guard, the same way home.
#[derive(Debug)]
pub struct SerialLinkGuard(SerialLiveness);

impl SerialLinkGuard {
    /// The listener channel this guard reports to — for handing a half back.
    fn liveness(&self) -> SerialLiveness {
        self.0.clone()
    }
}

impl Drop for SerialLinkGuard {
    fn drop(&mut self) {
        self.0 .0.live.store(false, AtomicOrdering::Release);
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
///
/// R2995 (open-debt 852) -- the stream is a [`BoxedSerialStream`], not a
/// [`SerialStream`]: a tty is the usual provider of the bytes and no longer the
/// only one, which is what lets the link's logic run where no tty pair exists.
pub struct SerialPort {
    stream: BoxedSerialStream,
    guard: Option<SerialLinkGuard>,
    /// The header of an `INIT` the accept's flush took off the device and kept
    /// (open-debt 795). The handshake consumes it before it reads the device, so it
    /// is `None` on a dialled port, on an accept that found the line quiet, and once
    /// the handshake has run.
    early_init: Option<u8>,
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
    pub fn dialled(stream: impl SerialByteStream) -> Self {
        Self {
            stream: Box::new(stream),
            guard: None,
            early_init: None,
        }
    }

    /// A device a listener handed out, carrying the guard that frees it.
    pub fn accepted(stream: impl SerialByteStream, guard: SerialLinkGuard) -> Self {
        Self::accepted_boxed(Box::new(stream), guard)
    }

    /// [`Self::accepted`] for a stream that is already erased -- the device a
    /// listener RETAINED, which comes back out of its slot as a
    /// [`BoxedSerialStream`] and must not be boxed a second time.
    pub(crate) fn accepted_boxed(stream: BoxedSerialStream, guard: SerialLinkGuard) -> Self {
        Self {
            stream,
            guard: Some(guard),
            early_init: None,
        }
    }

    /// Hand this port the `INIT` its accept's flush kept, for the handshake to answer.
    pub(crate) fn with_early_init(mut self, early_init: Option<u8>) -> Self {
        self.early_init = early_init;
        self
    }

    /// Take the kept `INIT`, leaving none: it is answered once.
    pub(crate) fn take_early_init(&mut self) -> Option<u8> {
        self.early_init.take()
    }

    /// The stream, mutably — the serial-link handshake runs over the WHOLE
    /// device before the split, exactly as it did when this was a bare stream.
    pub fn stream_mut(&mut self) -> &mut BoxedSerialStream {
        &mut self.stream
    }

    /// Split into the two things the wiring seam needs to keep apart: the stream
    /// it consumes, and the guard it must keep alive past the consumption.
    pub fn into_parts(self) -> (BoxedSerialStream, Option<SerialLinkGuard>) {
        (self.stream, self.guard)
    }
}

/// Open the host tty for a [`SerialEndpoint`] — the raw serial-device
/// open primitive (no handshake yet). Only [`SerialTarget::Device`] paths
/// are openable by the host tty backend; a [`SerialTarget::Pins`] target is
/// an MCU UART HAL endpoint with no host device node, so it surfaces a
/// typed `Unsupported` rather than a misleading "no such file".
///
/// The dial side's open: it ends in the full buffer clear. The ACCEPT seam needs
/// the two halves of [`accept_serial`] separately (R311y805):
/// `BoundListener::Serial::accept_raw` opens the tty (cheap, local, unblocked) and
/// flushes it, and DEFERS the peer-controlled handshake to
/// `AcceptedLink::handshake`, exactly as the tls/quic acceptors defer their crypto
/// off the accept path. It opens through `open_tty` and not through this function,
/// because this one's clear would discard an `INIT` already on the wire (open-debt
/// 795). A caller that wants both halves in one call uses [`accept_serial`].
pub fn open_serial_device(endpoint: &SerialEndpoint) -> io::Result<SerialStream> {
    let stream = open_tty(endpoint)?;
    // R2727 — a freshly opened tty carries whatever the kernel buffered for the
    // device before this process reached it, and upstream's open clears it:
    // `z-serial-0.3.1` @ `pub fn new(port: String, baud_rate: u32, exclusive: bool)`
    // runs `serial.clear(ClearBuffer::All)?` right after its own `set_exclusive`.
    // The DIAL side inherits that whole: an initiator wants nothing that was on the
    // wire before it spoke. The ACCEPT side does not -- it opens through
    // [`open_tty`] and flushes through [`flush_for_accept`], which keeps an `INIT`
    // (open-debt 795).
    clear_serial_buffers(&stream)?;
    Ok(stream)
}

/// Open the tty for a [`SerialEndpoint`] and leave its buffers as the kernel has them
/// -- [`open_serial_device`] without its clear, for the accept side, whose flush must
/// not discard an `INIT` the peer already wrote (open-debt 795).
pub(crate) fn open_tty(endpoint: &SerialEndpoint) -> io::Result<SerialStream> {
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
    let stream = SerialStream::open(&builder).map_err(io::Error::other)?;
    // `exclusive` is stated in BOTH directions rather than only when false.
    // tokio-serial opens exclusive by default, so wz already matched upstream's
    // default -- what was missing was the CHOICE, and a call that only fired on
    // one value would leave the other resting on a library default that is
    // nobody's stated intent.
    //
    // R2973 — on a Unix only, which is where the call exists: tokio-serial
    // declares `set_exclusive` under `#[cfg(unix)]`, and a Windows COM handle is
    // exclusive by the OS's own rule. Upstream's open is gated the same way
    // (`z-serial-0.3.1` @ `pub fn new(port: String, baud_rate: u32, exclusive: bool)`
    // spells it `#[cfg(unix)] serial.set_exclusive(exclusive)?;`). Ungated, the
    // serial link did not compile on Windows at all -- a host upstream serves it
    // on, and one no lane had ever built it for.
    #[cfg(unix)]
    let stream = {
        let mut stream = stream;
        stream
            .set_exclusive(endpoint.options.exclusive)
            .map_err(io::Error::other)?;
        stream
    };
    Ok(stream)
}

/// R2727 — discard whatever is buffered on a tty, in BOTH directions.
///
/// Upstream clears at two distinct moments and wz needs both: on OPEN
/// (`z-serial-0.3.1` @ `pub fn new(port: String, baud_rate: u32, exclusive: bool)`,
/// mirrored in [`open_serial_device`]) and on every ACCEPT, unconditionally
/// (`z-serial-0.3.1` @ `pub async fn accept(&mut self)`, whose first act past the
/// status check is `// Clear all buffers` / `self.clear()?`). The accept-side
/// clear is the one that MATTERS once a device can be retained: a retained fd
/// re-used for the next peer still holds whatever the previous peer wrote after
/// its last frame, and those bytes would be read as the first bytes of the next
/// link handshake. The symptom is intermittent and the framer resyncs past
/// SOME of it, which is worse than a clean failure.
///
/// `ClearBuffer::All` rather than `Input` alone, matching upstream's `clear()`:
/// an outbound tail the previous link never managed to transmit is no more
/// wanted by the next peer than an inbound one.
///
/// Open-debt 795 -- this full clear is now the DIAL side's. Upstream's accept clears
/// as above, but its initiator writes `INIT` once and its responder never sends the
/// `RESET` that would make it write again, so the same clear at an ACCEPT can end a
/// link before it starts. wz's accept therefore discards by `flush_for_accept`
/// instead, which differs from upstream in exactly one frame.
pub fn clear_serial_buffers(stream: &SerialStream) -> io::Result<()> {
    tokio_serial::SerialPort::clear(stream, tokio_serial::ClearBuffer::All)
        .map_err(io::Error::other)
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
    let mut stream = open_tty(endpoint)?;
    let early_init = flush_for_accept(&mut stream)?;
    drive_serial_handshake_from(&mut stream, SerialRole::Responder, early_init).await?;
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
    drive_serial_handshake_from(stream, role, None).await
}

/// [`drive_serial_handshake`] for a side that has ALREADY read one handshake frame:
/// `early_header` is fed to the handshake as if it had just arrived, before the
/// stream is read. It is the accept's kept `INIT` (open-debt 795) -- the peer wrote
/// it once, before the accept, and will not write it again.
pub(crate) async fn drive_serial_handshake_from<S>(
    stream: &mut S,
    role: SerialRole,
    early_header: Option<u8>,
) -> io::Result<()>
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
    let mut early_header = early_header;
    loop {
        let header = match early_header.take() {
            Some(header) => header,
            None => {
                if stream.read(&mut byte).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "serial peer closed during link handshake",
                    ));
                }
                match framer.push(byte[0]) {
                    Ok(Some(frame)) => frame.header,
                    Ok(None) => continue, // mid-frame
                    Err(_) => continue,   // framing noise; the reader resynced past it
                }
            }
        };
        match handshake.on_header(header) {
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
    // R2727 — the WRITE half's way back to the listener, so a device the locator
    // asked to retain can be re-accepted. `None` on a DIALLED link: there is no
    // listener waiting for that tty, so its halves have nowhere to go and should
    // simply close.
    let retain = guard.as_ref().map(SerialLinkGuard::liveness);
    let (reader, writer) = split(stream);
    let inbound = SerialReadDriver::new(reader, guard);
    let (tx, rx) = serial_outbound_channel();
    let writer_handle =
        WriterHandle::spawn(rx, move |queue| serial_writer_task(writer, queue, retain));
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
        addressless_link_subject(LinkKind::Serial, serial_interface_names(endpoint)),
        Some(addressless_link_endpoints(
            LinkKind::Serial,
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
    /// `Option` ONLY so `Drop` can move the half out and hand it back to the
    /// listener (R2727); it is `Some` for this driver's whole usable life, and
    /// `None` is reachable only from inside `Drop`, after which nothing can call
    /// [`Self::poll_event`] again.
    reader: Option<ReadHalf<BoxedSerialStream>>,
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
    fn new(reader: ReadHalf<BoxedSerialStream>, liveness: Option<SerialLinkGuard>) -> Self {
        Self {
            reader: Some(reader),
            framer: SerialFrameReader::new(),
            pending: VecDeque::new(),
            liveness,
        }
    }

    /// Whether this link holds a listener's claim on its device.
    ///
    /// `false` for a DIALLED link, which owns its tty outright and reports to
    /// nobody. This is the read that keeps `liveness` an invariant
    /// rather than a field nothing can see.
    pub fn device_is_claimed(&self) -> bool {
        self.liveness.is_some()
    }
}

/// R2727 — the READ half goes home BEFORE the guard below it clears liveness,
/// because clearing liveness is what unparks the next accept: reversing the two
/// would let that accept look for a retained device the instant before it
/// arrives, and fall back to re-opening for no reason.
///
/// The ordering is structural rather than written down twice — the `liveness`
/// guard is a FIELD of this struct, so the compiler drops it immediately after
/// this body returns.
impl Drop for SerialReadDriver {
    fn drop(&mut self) {
        if let (Some(reader), Some(guard)) = (self.reader.take(), self.liveness.as_ref()) {
            guard.liveness().return_reader(reader);
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
            // The read is bound before the match so the half's borrow ends here
            // rather than spanning the arms, which re-borrow `self` for the
            // framer.
            let read = self
                .reader
                .as_mut()
                .expect("the read half is taken only by `Drop`, past every poll")
                .read(&mut buf)
                .await;
            match read {
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
/// `OutboundTx` (R2919: priority lanes) whose receiver the [`serial_writer_task`]
/// owns. Impls [`BoxedLinkDriver`] with a NON-blocking enqueue, the same
/// sync-action / async-runtime decoupling
/// [`crate::link_pipeline::TcpWriteDriver`] uses (a nested `block_on` from a
/// sync FSM action handler would trip the runtime-reentrancy check).
///
/// R3250 — the channel carries the FRAMED wire: this driver COBS-frames each
/// payload as it enqueues it ([`encode_frame_into`]), and the writer writes the
/// bytes as they are. It used to carry the raw payload and leave the framing to
/// the writer, which cost a copy of the payload into a vector of its own and
/// two more vectors in the encoder for every frame. Under `runtime-zero-copy`
/// the frame is encoded straight into a slot of the link's transmit pool
/// ([`serial_outbound_channel`]), back to back with the frames queued before it
/// (COBS frames end at their `0x00`, so the concatenation is the wire), and a
/// frame costs no allocation; otherwise it is one vector.
pub struct SerialWriteDriver {
    tx: crate::writer_queue::OutboundTx,
    /// R311y453 — the §5.16 link-derived subject, resolved once at open.
    subject: LinkSubject,
    /// R311y474 — the adminspace `{src,dst}` locator pair, resolved once at open.
    endpoints: Option<LinkEndpoints>,
}

/// R3250 — the outbound queue a serial link's write half and its
/// [`serial_writer_task`] share: under `runtime-zero-copy` one that owns the
/// link's transmit pool (`crate::writer_queue::outbound_channel_pooled`), so a
/// frame lies in a pool slot from its encode to the end of its write; without
/// it, the heap queue.
pub fn serial_outbound_channel() -> (
    crate::writer_queue::OutboundTx,
    crate::writer_queue::OutboundRx,
) {
    #[cfg(feature = "runtime-zero-copy")]
    {
        crate::writer_queue::outbound_channel_pooled()
    }
    #[cfg(not(feature = "runtime-zero-copy"))]
    {
        crate::writer_queue::outbound_channel()
    }
}

impl SerialWriteDriver {
    /// A write half over `tx`, the sending side of the queue its
    /// [`serial_writer_task`] drains (built by [`serial_outbound_channel`]).
    pub fn new(
        tx: crate::writer_queue::OutboundTx,
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

    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        self.send_prioritized(bytes, reliability, wz_session_core::qos::Priority::DEFAULT)
    }

    fn wait_for_room(
        &self,
        priority: wz_session_core::qos::Priority,
        wait: wz_session_core::link::RoomWait,
    ) -> wz_session_core::link::RoomAnswer {
        self.tx.link_room(priority, wait)
    }

    fn shape_tx_queue(&self, shape: wz_session_core::link::TxQueueShape) {
        self.tx.reshape(shape)
    }

    // R2952 — the block-first slot lives on this link's outbound queue.
    fn block_first_acquire(&self, priority: wz_session_core::qos::Priority, wait_us: u64) -> bool {
        self.tx.block_first_acquire(priority, wait_us)
    }

    fn block_first_release(&self, priority: wz_session_core::qos::Priority) {
        self.tx.block_first_release(priority)
    }

    fn send_prioritized(
        &self,
        bytes: &[u8],
        _reliability: Reliability,
        priority: wz_session_core::qos::Priority,
    ) -> LinkSendOutcome {
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
        // R3250 — framed here, into the queue's own storage: a slot of the
        // link's transmit pool on a pooled queue, a vector of its own otherwise.
        #[cfg(feature = "runtime-zero-copy")]
        {
            use crate::writer_queue::PooledSendError;
            match self.tx.send_encoded(priority, SERIAL_MAX_COBS_BUF, |dst| {
                encode_frame_into(SERIAL_DATA_HEADER, bytes, dst).ok()
            }) {
                Ok(()) => LinkSendOutcome::Sent,
                Err(PooledSendError::Closed) => {
                    log::warn!("wz-runtime-tokio: outbound serial channel closed; dropping frame");
                    LinkSendOutcome::Dropped(LinkDropCause::WriterGone)
                }
                Err(e) => {
                    log::warn!(
                        "wz-runtime-tokio: outbound serial frame of {} bytes not framed ({e}); dropping",
                        bytes.len()
                    );
                    LinkSendOutcome::Dropped(LinkDropCause::Oversize)
                }
            }
        }
        #[cfg(not(feature = "runtime-zero-copy"))]
        {
            let mut wire = vec![0u8; SERIAL_MAX_COBS_BUF];
            match encode_frame_into(SERIAL_DATA_HEADER, bytes, &mut wire) {
                Ok(len) => wire.truncate(len),
                Err(e) => {
                    log::warn!(
                        "wz-runtime-tokio: outbound serial frame of {} bytes not framed ({e:?}); dropping",
                        bytes.len()
                    );
                    return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
                }
            }
            if let Err(e) = self.tx.send(priority, wire) {
                log::warn!(
                    "wz-runtime-tokio: outbound serial channel closed; dropping frame ({e})"
                );
                return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
            }
            LinkSendOutcome::Sent
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

/// Async writer task. Owns the [`WriteHalf`] and drains the outbound channel,
/// writing + flushing the frames as they are: [`SerialWriteDriver`] has already
/// COBS-framed each one through [`encode_frame_into`] (header
/// [`SERIAL_DATA_HEADER`] + len + payload + crc32 -> COBS -> `0x00` EOP) when it
/// enqueued it (R3250). Exits when the queue is SEALED and drained, when every
/// [`SerialWriteDriver`] clone has dropped, or when a write fails / stalls past
/// [`WRITER_STALL_MS`](crate::writer_queue::WRITER_STALL_MS) on a sealed queue
/// (logged + bail) — see [`crate::writer_queue`] for why the seal, and not
/// sender liveness alone, is the teardown signal. The first two shut the write
/// half so the peer observes EOF.
/// R2727 — `retain` is the listener channel the WRITE half goes home through so
/// a retained device can be re-accepted (`None` on a dialled link, and a no-op
/// when the locator left `release_on_close` at its default). It is handed the
/// half on EVERY path this task can leave by, which is why the draining loop
/// moved into `drain_serial_writes`: a `return` in the middle of that loop is
/// how a half gets silently forgotten, and there is now exactly one place to
/// forget it from.
///
/// The one exit that does NOT come back through here is
/// [`WriterHandle::abort`](crate::writer_queue::WriterHandle::abort), which
/// cancels this future where it stands; see `SerialRetainSlot` for why
/// re-opening is right in that case.
pub async fn serial_writer_task(
    writer: WriteHalf<BoxedSerialStream>,
    queue: OutboundQueue,
    retain: Option<SerialLiveness>,
) {
    let writer = drain_serial_writes(writer, queue).await;
    if let Some(liveness) = retain {
        liveness.return_writer(writer);
    }
}

/// The draining loop of [`serial_writer_task`], returning the half it was given
/// on every path out.
async fn drain_serial_writes(
    mut writer: WriteHalf<BoxedSerialStream>,
    mut queue: OutboundQueue,
) -> WriteHalf<BoxedSerialStream> {
    // R3250 — what the queue holds is the FRAMED wire (the write half encodes it
    // as it enqueues), so the bytes are written as they are. On a pooled queue a
    // run of frames is one slot of the link's transmit pool: started here, and
    // home through the completion edge when the write has ended.
    while let Some(mut wire) = queue.next_wire().await {
        wire.begin_write();
        let write = async {
            writer.write_all(&wire).await?;
            writer.flush().await
        };
        match queue.guarded(write).await {
            Some(Ok(())) => queue.recycle_wire(wire),
            Some(Err(e)) => {
                log::warn!("wz-runtime-tokio: serial_writer_task write failed: {e}; closing");
                return writer;
            }
            None => {
                log::warn!(
                    "wz-runtime-tokio: serial_writer_task stalled past {} ms draining a \
                     sealed queue; closing with frames undelivered",
                    crate::writer_queue::WRITER_STALL_MS
                );
                return writer;
            }
        }
    }
    // Queue finished -> shut the write half cleanly (peer sees EOF).
    //
    // R2727 — this stays where it was and does NOT conflict with retaining the
    // device, which was checked rather than assumed: tokio-serial's unix
    // `AsyncWrite for SerialStream` implements
    // `poll_shutdown` as a `poll_flush` and `Ok(())`
    // (`tokio-serial-5.4.5/src/lib.rs` @ `let _ = self.poll_flush(cx)?;`), so it
    // never closes the fd. A tty has no half-close to perform.
    let _ = writer.shutdown().await;
    writer
}

// R2995 (open-debt 852) -- the link's LOGIC is witnessed here over an in-memory
// duplex on EVERY host, and over an `openpty` pair as well where there is one.
// R2973 had to fence these tests `#[cfg(unix)]` because the only pair they knew
// how to open was `SerialStream::pair`, `#[cfg(unix)]` inside tokio-serial, so a
// Windows runner built the link and ran none of it. The handshake, the framing,
// the MTU cap, the liveness claim and the retained device read and write bytes
// and never needed a tty, so each body below is generic over the stream and is
// instantiated twice: the duplex is what a host with no tty pair runs, and the
// pty is what keeps the real device underneath the same logic witnessed on a Unix.
#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::serial_link::encode_frame;

    /// R3250 — the write half frames the payload as it enqueues it: what the
    /// queue holds is the codec's frame, byte for byte, in a pool slot under
    /// `runtime-zero-copy`, and frames enqueued together pack into one run.
    #[tokio::test]
    async fn the_write_half_enqueues_the_framed_wire() {
        let (tx, mut rx) = serial_outbound_channel();
        let driver = SerialWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        assert_eq!(
            driver.send_blocking(b"one", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            driver.send_blocking(b"two", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        let mut want = encode_frame(SERIAL_DATA_HEADER, b"one").expect("frame");
        want.extend(encode_frame(SERIAL_DATA_HEADER, b"two").expect("frame"));
        let first = rx.recv_wire().await.expect("a frame");
        // Pooled: both frames are one run in one slot. Heap: a vector each.
        assert_eq!(first.is_pooled(), cfg!(feature = "runtime-zero-copy"));
        let mut got = first.into_vec();
        while got.len() < want.len() {
            got.extend(rx.recv_wire().await.expect("the next frame").into_vec());
        }
        assert_eq!(got, want);
        assert_eq!(
            driver.send_blocking(&[0u8; SERIAL_MTU + 1], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
    }

    /// Two connected ends of an in-memory serial link: what a host with no tty
    /// pair runs these witnesses over.
    fn memory_pair() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    /// R2704 — the locator's `tout` bounds the handshake, as upstream's does.
    ///
    /// The peer end is opened and then NEVER written to, which is the case
    /// upstream's `port.connect(Some(..))` exists for. Before this round the
    /// initiator would re-send INIT on every RESET forever, so the only bound
    /// was whatever the caller happened to compose.
    async fn assert_a_handshake_is_bounded(
        mut a: impl SerialByteStream,
        _b: impl SerialByteStream,
    ) {
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

    #[tokio::test]
    async fn a_handshake_over_memory_is_bounded_by_the_locators_tout() {
        let (a, b) = memory_pair();
        assert_a_handshake_is_bounded(a, b).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_handshake_is_bounded_by_the_locators_tout() {
        let (a, b) = SerialStream::pair().expect("openpty serial pair");
        assert_a_handshake_is_bounded(a, b).await;
    }

    /// The ANTI-VACUITY half: the bound must not be so eager that it refuses a
    /// handshake that DOES complete. Without this, a `drive_serial_handshake_within`
    /// that returned `TimedOut` unconditionally would satisfy the test above.
    async fn assert_a_bounded_handshake_completes_against_a_peer_that_answers(
        mut a: impl SerialByteStream,
        mut b: impl SerialByteStream,
    ) {
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

    #[tokio::test]
    async fn a_bounded_handshake_over_memory_still_completes_against_a_peer_that_answers() {
        let (a, b) = memory_pair();
        assert_a_bounded_handshake_completes_against_a_peer_that_answers(a, b).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_bounded_handshake_still_completes_against_a_peer_that_answers() {
        let (a, b) = SerialStream::pair().expect("openpty serial pair");
        assert_a_bounded_handshake_completes_against_a_peer_that_answers(a, b).await;
    }

    /// The endpoint a wired test link stands in for. Neither a pty pair nor a
    /// memory pair has a device name to read back, so a wired test link has no
    /// readable address -- the endpoint is supplied, exactly as the real dial path
    /// supplies the one it parsed from the locator.
    fn link_endpoint() -> SerialEndpoint {
        use wz_session_core::locator::SerialOptions;
        SerialEndpoint {
            target: SerialTarget::Device("/dev/wz-test-link".to_string()),
            baudrate: 115_200,
            options: SerialOptions::default(),
            qos: None,
        }
    }

    /// The serial write driver reports the serial link MTU (not the
    /// unbounded `DEFAULT_LINK_MTU` a stream link inherits), so the
    /// transport's `negotiated_batch_mtu` mins its TX fragment budget down
    /// to a frame the serial link can actually emit. This is the link-side
    /// half of the >MTU fragmentation wiring; the end-to-end split is
    /// proved in `serial_link_e2e`.
    #[test]
    fn serial_write_driver_reports_serial_link_mtu() {
        // Static invariant: the serial cap must bind BELOW the unbounded
        // stream default, else the `negotiated_batch_mtu` min term would be
        // inert and serial would never fragment. A const assertion so a
        // constant regression fails the build, not a runtime check.
        const _: () = assert!(SERIAL_MTU < wz_session_core::link::DEFAULT_LINK_MTU);

        let (tx, _rx) = crate::writer_queue::outbound_channel();
        let driver = SerialWriteDriver::new(tx, LinkSubject::UNKNOWN, None);
        assert_eq!(driver.link_mtu(), SERIAL_MTU);
    }

    /// A pair handshakes end to end: the Initiator end sends INIT, the
    /// Responder end replies INIT|ACK, both `drive_serial_handshake` futures
    /// resolve Ok. Bounded by a `timeout` so a handshake regression fails
    /// fast instead of hanging.
    async fn assert_a_pair_completes_the_handshake_in_both_roles(
        mut a: impl SerialByteStream,
        mut b: impl SerialByteStream,
    ) {
        let init = drive_serial_handshake(&mut a, SerialRole::Initiator);
        let resp = drive_serial_handshake(&mut b, SerialRole::Responder);
        let bounded =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(init, resp) });
        let (ia, rb) = bounded.await.expect("handshake completes within 5s");
        ia.expect("initiator reaches Connected");
        rb.expect("responder reaches Connected");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn memory_pair_completes_handshake_both_roles() {
        let (a, b) = memory_pair();
        assert_a_pair_completes_the_handshake_in_both_roles(a, b).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pty_pair_completes_handshake_both_roles() {
        let (a, b) = SerialStream::pair().expect("openpty pair");
        assert_a_pair_completes_the_handshake_in_both_roles(a, b).await;
    }

    /// After the handshake, the wired drivers carry a data frame byte-exact:
    /// `send_blocking` enqueues a raw payload, the writer task COBS-frames it
    /// with header 0x00, and the peer's read driver re-frames + delivers the
    /// payload unchanged.
    async fn assert_wired_drivers_round_trip_one_data_frame(
        mut a: impl SerialByteStream,
        mut b: impl SerialByteStream,
    ) {
        let bounded = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                drive_serial_handshake(&mut a, SerialRole::Initiator),
                drive_serial_handshake(&mut b, SerialRole::Responder),
            )
        });
        let (ia, rb) = bounded.await.expect("handshake completes");
        ia.expect("initiator connected");
        rb.expect("responder connected");

        let (_a_in, a_out, a_writer) = wire_serial_stream(SerialPort::dialled(a), &link_endpoint());
        let (mut b_in, _b_out, _b_writer) =
            wire_serial_stream(SerialPort::dialled(b), &link_endpoint());

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wired_memory_pair_round_trips_one_data_frame() {
        let (a, b) = memory_pair();
        assert_wired_drivers_round_trip_one_data_frame(a, b).await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wired_pty_pair_round_trips_one_data_frame() {
        let (a, b) = SerialStream::pair().expect("openpty pair");
        assert_wired_drivers_round_trip_one_data_frame(a, b).await;
    }

    /// Wire an ACCEPTED link off `liveness` the way the accept seam does, and tear
    /// it down the way a CLEAN session teardown does: drop the read driver, release
    /// the last sender, and drain the writer task to completion. Returns the far
    /// end, still open.
    ///
    /// ⛔ THE WIRING IS NOT INCIDENTAL. A `SerialPort` that is merely dropped never
    /// reaches [`wire_serial_stream`], so its stream is never split and neither half
    /// has anywhere to come back FROM -- a retain witness built on that path would be
    /// green for a listener that retains nothing.
    async fn accept_wire_and_tear_down(liveness: &SerialLiveness) -> DuplexStream {
        let (mut device, mut peer) = memory_pair();
        let bounded = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                drive_serial_handshake(&mut peer, SerialRole::Initiator),
                drive_serial_handshake(&mut device, SerialRole::Responder),
            )
        });
        let (ip, rd) = bounded.await.expect("handshake completes");
        ip.expect("peer initiator connected");
        rd.expect("device responder connected");

        let port = SerialPort::accepted(device, liveness.claim());
        assert!(
            liveness.is_live(),
            "claiming the device marks it taken for as long as the link holds the guard"
        );
        let (inbound, outbound, handle) = wire_serial_stream(port, &link_endpoint());
        assert!(
            inbound.device_is_claimed(),
            "an accepted link carries its listener's claim on the read driver"
        );
        drop(inbound); // the read half goes home; the guard frees the device
        drop(outbound); // the last sender goes, which seals the outbound queue
        handle.drain().await; // the writer task ends, and its half goes home
        assert!(
            !liveness.is_live(),
            "tearing the link down must free the device for the next accept"
        );
        peer
    }

    /// `release_on_close=false` keeps the OPEN device past the link that used it,
    /// and the accept that follows TAKES it rather than leaving a copy behind.
    ///
    /// ANTI-VACUITY: a retained object that was not the live device would satisfy
    /// `retains_device()` and nothing else, so the retained stream is READ: a byte
    /// the far end writes must arrive on it. (Only the read direction is asserted,
    /// and that is a fact about this stream type and not a hole in the witness: the
    /// writer task's clean teardown shuts the write half, which closes a duplex's
    /// direction where a tty has no half-close to perform. The pty-backed
    /// listener witnesses in `serial_link_e2e` carry a SECOND LINK over the
    /// retained tty, which is the full property.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retained_device_comes_home_and_is_taken_once() {
        let liveness = SerialLiveness::new(true);
        assert!(
            !liveness.retains_device(),
            "nothing is retained before a link has lived on the device"
        );

        let mut peer = accept_wire_and_tear_down(&liveness).await;
        assert!(
            liveness.retains_device(),
            "both halves home must re-assemble the device: that is the key's whole \
             observable effect"
        );

        let mut retained = liveness
            .take_retained()
            .expect("a retained device is handed to the next accept");
        assert!(
            !liveness.retains_device(),
            "the accept must CONSUME the retained device"
        );

        peer.write_all(b"x").await.expect("the far end writes");
        peer.flush().await.expect("the byte reaches the wire");
        let mut byte = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), retained.read_exact(&mut byte))
            .await
            .expect("the retained device delivers within 5s")
            .expect("the retained device is readable");
        assert_eq!(&byte, b"x", "what came back is the device the link ran on");
    }

    /// THE CONTROL for its sibling above: under the DEFAULT `release_on_close=true`
    /// the same teardown retains NOTHING.
    ///
    /// Without this arm a slot that retained UNCONDITIONALLY would pass the sibling,
    /// and unconditional retention is the wrong behaviour rather than a harmless
    /// surplus: upstream drops the port on close in exactly this case, and a device
    /// held by a listener nobody is using is a tty no other process can open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_released_device_is_not_kept() {
        let liveness = SerialLiveness::new(false);
        let _peer = accept_wire_and_tear_down(&liveness).await;
        assert!(
            !liveness.retains_device(),
            "the default key RELEASES the device on close"
        );
        assert!(
            liveness.take_retained().is_none(),
            "a released device leaves nothing for the next accept to take"
        );
    }

    /// The in-memory stream has no kernel queues, so dropping its unsent bytes is a
    /// no-op that must SUCCEED: the accept seam flushes whatever it retained, and an
    /// error here would make every memory-backed accept fail.
    #[test]
    fn a_stream_with_no_device_queues_clears_cleanly() {
        let (a, _b) = memory_pair();
        a.clear_unsent()
            .expect("a duplex has no device buffers to fail to clear");
    }

    async fn write_all_to(peer: &mut DuplexStream, bytes: &[u8]) {
        peer.write_all(bytes).await.expect("the peer writes");
        peer.flush().await.expect("the bytes reach the wire");
    }

    /// `take_received` takes what is queued, reports a quiet line as empty rather than
    /// waiting, and leaves later bytes for later: the three properties the accept's
    /// flush is built on (open-debt 795, rule 2 of the module's flush contract).
    #[tokio::test]
    async fn take_received_takes_what_is_queued_and_never_waits() {
        let (mut a, mut b) = memory_pair();
        assert!(
            a.take_received().expect("a quiet line reads").is_empty(),
            "a quiet line answers empty at once instead of waiting for a byte"
        );
        write_all_to(&mut b, b"abc").await;
        assert_eq!(a.take_received().expect("queued bytes read"), b"abc");
        assert!(
            a.take_received().expect("a drained line reads").is_empty(),
            "what was taken is gone"
        );
        write_all_to(&mut b, b"de").await;
        assert_eq!(
            a.take_received().expect("later bytes read"),
            b"de",
            "bytes that arrive after a take belong to the next take"
        );
    }

    /// The flush keeps the INIT and nothing else that came before it, and keeps
    /// everything that comes after it (open-debt 795, both rules of the contract).
    #[tokio::test]
    async fn the_accept_flush_keeps_the_init_and_discards_stale_bytes() {
        let (mut a, mut b) = memory_pair();
        let data = encode_frame(SERIAL_DATA_HEADER, b"stale").expect("data frame");
        let init =
            encode_frame(wz_session_core::serial_link::SERIAL_FLAG_INIT, b"").expect("INIT frame");
        write_all_to(&mut b, &data).await;
        write_all_to(&mut b, b"\x11\x22\x33-mangled\x00").await;
        write_all_to(&mut b, &init).await;
        write_all_to(&mut b, &data).await;

        let kept = flush_for_accept(&mut a).expect("the flush reads the line");
        assert_eq!(
            kept,
            Some(wz_session_core::serial_link::SERIAL_FLAG_INIT),
            "rule 1: the INIT that was on the wire survives the flush"
        );
        assert!(
            a.take_received().expect("the line reads").is_empty(),
            "rule 2: nothing stale is left for the handshake to read"
        );

        write_all_to(&mut b, &data).await;
        assert_eq!(
            a.take_received().expect("the line reads"),
            data,
            "rule 2: a byte received after the flush is not discarded"
        );
    }

    /// A flush of a line with no INIT on it keeps nothing, however much stale there is.
    #[tokio::test]
    async fn the_accept_flush_of_a_line_with_no_init_keeps_nothing() {
        let (mut a, mut b) = memory_pair();
        assert_eq!(flush_for_accept(&mut a).expect("a quiet line"), None);
        let data = encode_frame(SERIAL_DATA_HEADER, b"stale").expect("data frame");
        write_all_to(&mut b, &data).await;
        assert_eq!(flush_for_accept(&mut a).expect("a stale line"), None);
    }

    /// An INIT written right behind a stale fragment no `0x00` closed is kept, and
    /// the link comes up on it: the two are one span on the wire, which pico and
    /// upstream would drop on its CRC, and which an initiator that writes `INIT`
    /// once never repeats. The handshake below runs on a silent peer, so the kept
    /// header is the only thing that can complete it (open-debt 795, part 3).
    #[tokio::test]
    async fn the_accept_flush_keeps_an_init_glued_to_an_unterminated_fragment() {
        let (mut a, mut b) = memory_pair();
        let init =
            encode_frame(wz_session_core::serial_link::SERIAL_FLAG_INIT, b"").expect("INIT frame");
        write_all_to(&mut b, b"\x09\x22\x33\x44").await;
        write_all_to(&mut b, &init).await;

        let kept = flush_for_accept(&mut a).expect("the flush reads the line");
        assert_eq!(
            kept,
            Some(wz_session_core::serial_link::SERIAL_FLAG_INIT),
            "the INIT behind the fragment survives the flush"
        );
        assert!(
            a.take_received().expect("the line reads").is_empty(),
            "the fragment is discarded with the rest of the stale bytes"
        );

        tokio::time::timeout(
            Duration::from_secs(5),
            drive_serial_handshake_from(&mut a, SerialRole::Responder, kept),
        )
        .await
        .expect("a responder holding the kept INIT must not wait for another")
        .expect("the handshake completes");
        let want = encode_frame(
            wz_session_core::serial_link::SERIAL_FLAG_INIT
                | wz_session_core::serial_link::SERIAL_FLAG_ACK,
            b"",
        )
        .expect("INIT|ACK frame");
        let mut got = vec![0u8; want.len()];
        b.read_exact(&mut got)
            .await
            .expect("the peer hears INIT|ACK");
        assert_eq!(got, want);
    }

    /// Fragment, data frame, fragment, INIT: the last INIT wins as before, and the
    /// stale data frame and fragments are discarded (open-debt 795, parts 2 and 3).
    #[tokio::test]
    async fn the_accept_flush_keeps_the_last_init_behind_fragments_and_data_frames() {
        let (mut a, mut b) = memory_pair();
        let data = encode_frame(SERIAL_DATA_HEADER, b"stale").expect("data frame");
        let first =
            encode_frame(wz_session_core::serial_link::SERIAL_FLAG_INIT, b"").expect("INIT frame");
        let second = encode_frame(
            wz_session_core::serial_link::SERIAL_FLAG_INIT
                | wz_session_core::serial_link::SERIAL_FLAG_RESET,
            b"",
        )
        .expect("second INIT frame");
        for chunk in [
            &b"\x07\x11"[..],
            &data,
            &b"\x07\x11"[..],
            &first,
            &b"\x05\x22"[..],
            &second,
            &b"\x07\x11"[..],
            &data,
        ] {
            write_all_to(&mut b, chunk).await;
        }

        assert_eq!(
            flush_for_accept(&mut a).expect("the flush reads the line"),
            Some(
                wz_session_core::serial_link::SERIAL_FLAG_INIT
                    | wz_session_core::serial_link::SERIAL_FLAG_RESET
            ),
            "the last INIT on the wire is the one kept"
        );
        assert!(
            a.take_received().expect("the line reads").is_empty(),
            "nothing stale is left for the handshake to read"
        );
    }

    /// Bytes with no INIT in them keep nothing however they are cut, and the search
    /// does not invent one: a fragment with no `0x00`, a fragment glued to a data
    /// frame, and runs of valid-looking codes.
    #[tokio::test]
    async fn the_accept_flush_of_unterminated_garbage_keeps_nothing() {
        let (mut a, mut b) = memory_pair();
        let data = encode_frame(SERIAL_DATA_HEADER, b"stale").expect("data frame");
        write_all_to(&mut b, b"\x09\x22\x33\x44").await;
        assert_eq!(flush_for_accept(&mut a).expect("a fragment"), None);
        write_all_to(&mut b, b"\x09\x22\x33\x44").await;
        write_all_to(&mut b, &data).await;
        assert_eq!(
            flush_for_accept(&mut a).expect("a fragment and a frame"),
            None
        );
        write_all_to(&mut b, &[0x01; 300]).await;
        write_all_to(&mut b, &[0x00]).await;
        assert_eq!(flush_for_accept(&mut a).expect("valid-looking codes"), None);
        assert!(a.take_received().expect("the line reads").is_empty());
    }

    /// The case the search cannot recover, pinned so it is not mistaken for one it
    /// can: an INIT whose body reached the device but whose `0x00` has not. The
    /// flush cannot know that tail is not stale, so it keeps nothing, and the `0x00`
    /// that arrives afterwards is the new line's and is read normally.
    #[tokio::test]
    async fn an_init_whose_end_marker_has_not_arrived_is_not_kept() {
        let (mut a, mut b) = memory_pair();
        let init =
            encode_frame(wz_session_core::serial_link::SERIAL_FLAG_INIT, b"").expect("INIT frame");
        write_all_to(&mut b, b"\x09\x22\x33\x44").await;
        write_all_to(&mut b, &init[..init.len() - 1]).await;
        assert_eq!(flush_for_accept(&mut a).expect("an unfinished INIT"), None);

        write_all_to(&mut b, &init[init.len() - 1..]).await;
        assert_eq!(
            a.take_received().expect("the line reads"),
            [0x00],
            "the end marker arrives after the flush and is not discarded"
        );
    }

    /// The kept INIT is answered WITHOUT reading the device: the peer wrote it once,
    /// so a responder that waited for another would wait for ever. The peer end stays
    /// silent here, which is what makes the early header the only thing that can
    /// complete the handshake.
    #[tokio::test]
    async fn a_kept_init_is_answered_without_reading_the_device() {
        let (mut a, mut b) = memory_pair();
        tokio::time::timeout(
            Duration::from_secs(5),
            drive_serial_handshake_from(
                &mut a,
                SerialRole::Responder,
                Some(wz_session_core::serial_link::SERIAL_FLAG_INIT),
            ),
        )
        .await
        .expect("a responder holding the peer's INIT must not wait for another")
        .expect("the handshake completes");

        let want = encode_frame(
            wz_session_core::serial_link::SERIAL_FLAG_INIT
                | wz_session_core::serial_link::SERIAL_FLAG_ACK,
            b"",
        )
        .expect("INIT|ACK frame");
        let mut got = vec![0u8; want.len()];
        b.read_exact(&mut got)
            .await
            .expect("the peer hears INIT|ACK");
        assert_eq!(got, want);
    }

    /// Past the bound the flush refuses by name instead of reading for as long as the
    /// peer writes.
    #[tokio::test]
    async fn the_accept_flush_refuses_a_line_that_never_goes_quiet() {
        let (mut a, mut b) = tokio::io::duplex(SERIAL_FLUSH_LIMIT + 1024);
        write_all_to(&mut b, &vec![0x55u8; SERIAL_FLUSH_LIMIT + 1]).await;
        let err = flush_for_accept(&mut a).expect_err("more than the bound is refused");
        assert!(
            err.to_string().contains("did not go quiet"),
            "the refusal names the cause: {err}"
        );
    }
}
