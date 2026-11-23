// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Links over a transport the program supplies, on the cooperative engine.
//!
//! The transport is the engine-neutral [`AppTransport`] of `wz-session-core`. This module makes
//! the cooperative engine's link seams of it: a [`StreamSocket`] and a [`DatagramSocket`] over a
//! link's handle, a [`StreamDial`] that opens streams through the program, a [`GroupTransport`]
//! over a group the program joins, and [`AppLinks`], the session shell's [`SessionLinks`] over all
//! of them, so a session of this engine opens no socket of the system's when a transport is given.
//!
//! # Listening
//!
//! A listener carries nothing itself: the program accepts on it each stream, or each source that
//! sends datagrams to it, and the table holds each as a link of its own
//! (`wz_session_core::app_link_table`). A `tcp/` listener yields a stream link for each accepted
//! stream, a `udp/` one a datagram link for each accepted source, and each is the link of a
//! session run as the acceptor, as a connection taken off a socket's port is. The program has told
//! the sources apart, so a datagram link it accepted is one source's alone: each of its datagrams
//! is read as that source's, whatever the program names with it.
//!
//! # The remainder
//!
//! This engine's stream seam takes every byte or fails ([`StreamSocket::send_parts`]), where the
//! program may take part of them or none (would-block). What the program did not take is held in
//! the transport's table ([`AppLinkTable::hold_remainder`](wz_session_core::app_link_table::AppLinkTable::hold_remainder)),
//! behind anything held before, and offered to the program again at the start of every send and
//! every turn of the link's loop (each read and wait), so the stream's bytes leave in order once
//! the program is writable. The remainder is bounded by the link's queue bound, the
//! `APP_LINK_QUEUE_BYTES` of the session that opened it ([`SessionTransport`]); past it the send
//! fails, as a socket whose peer stopped reading does. Only this engine copies a remainder:
//! the tokio engine's writer keeps its own offset.
//!
//! # Waiting
//!
//! A wait for input, and an open the program finishes later, are made on the host by parking the
//! thread with a waker the program's calls wake (`host-lock`, the host build). An image has no
//! thread to park: there a wait looks at the table for a bounded number of turns and returns, and
//! the engine's loop comes back to it.
//!
//! On the host a link also gives the thread that steps its session a wait for its input
//! ([`SessionDatagramLink::readiness`](crate::session_drive::SessionDatagramLink::readiness)),
//! which that thread makes with nothing of the session held, and the links of
//! [`AppLinks::waited_by_owner`] leave their waiting to it: their loop reads what is queued and
//! does not wait. A link that waits in its own loop waits a tick at a time inside the step, under
//! the session's lock, so a thread that takes the session for a call (a get, a declaration) finds
//! it held nearly always, and the read task, which takes it again at once, keeps it.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use core::ffi::c_int;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use wz_session_core::app_link_table::{
    kind_for_locator, AcceptRead, AppLinkKind, DatagramRead, LinkHandle, OpenProgress, SendGate,
    SendStep, StreamRead, DATAGRAM_MAX,
};
use wz_session_core::app_transport::{AppTransport, SessionTransport};

use crate::group_transport::{GroupSend, GroupTransport};
use crate::ip_stack::{heap_link, HeapLink};
use crate::link_storage::{heap_link_buffers, LinkTables, RxBuffer, TxBuffer};
use crate::session_drive::{
    Dialled, LinkListener, LinkOpenError, LinkProto, LinkReadiness, LinkWritability, Locator,
    OpenedLink, PendingDial, SessionLinks,
};
use crate::stream_link::{
    StreamDial, StreamDriver, StreamListen, StreamSocket, STREAM_RX_CAPACITY,
};
use crate::udp_link::{DatagramSocket, Received, UdpDriver, UDP_RX_CAPACITY};

/// The longest an open waits for the program to report the link up, in milliseconds: the
/// connect timeout of a zenoh-pico session, which this engine's dial is held to as a whole.
const OPEN_WAIT_MS: u64 = 10_000;

/// Why a call on a link over the program's transport failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppLinkError {
    /// The link is closed.
    Closed,
    /// The program's send failed, or took part of a datagram.
    Failed,
    /// The program could not take a datagram now; it was not sent.
    WouldBlock,
    /// The remainder held for the program would pass the transport's queue bound.
    Full,
    /// A socket of this kind is opened through [`AppLinks`], never bound on its own.
    NotCarried,
}

/// Waiting on a link: parking the waiting thread until the link's wake comes (`wait_parked`),
/// or looking for a bounded number of turns on an image (`wait_turns`). The build names one of
/// them `wait`.
#[cfg(feature = "host-lock")]
use wait_parked as wait;
#[cfg(not(feature = "host-lock"))]
use wait_turns as wait;

/// The wait of a host: each link owns one wake, made with the link, and every wait on it hands the
/// program's calls that wake's one waker. A wait therefore allocates nothing, however often a
/// session's read waits on its link (once a turn), and every thread that waits on the link (its
/// read, a publisher waiting for room) is woken and looks again. The lock and the condition
/// variable are `std`'s, or the host's own calls' in a library without `std` (`host-lock-sys`).
#[cfg(feature = "host-lock")]
mod wait_parked {
    #[cfg(not(feature = "host-lock-sys"))]
    extern crate std;

    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::task::{Context, Waker};
    use core::time::Duration;

    #[cfg(not(feature = "host-lock-sys"))]
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    #[cfg(feature = "host-lock-sys")]
    use wz_host_sync::{Condvar, Mutex, MutexGuard};

    /// The count of the wakes a link has had, and the condition variable its waiters wait on.
    struct LinkWake {
        wakes: Mutex<u64>,
        changed: Condvar,
    }

    impl Wake for LinkWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let mut wakes = lock(&self.wakes);
            *wakes = wakes.wrapping_add(1);
            drop(wakes);
            self.changed.notify_all();
        }
    }

    /// The lock, a poisoned one taken as it is: a count has no state a panic can leave half made.
    fn lock(wakes: &Mutex<u64>) -> MutexGuard<'_, u64> {
        #[cfg(not(feature = "host-lock-sys"))]
        {
            wakes.lock().unwrap_or_else(PoisonError::into_inner)
        }
        #[cfg(feature = "host-lock-sys")]
        {
            wakes.lock()
        }
    }

    /// Wait, with `guard` held, until the count is no longer `seen`, or `left` has passed when
    /// it is given.
    fn wait_past(changed: &Condvar, guard: MutexGuard<'_, u64>, seen: u64, left: Option<Duration>) {
        #[cfg(not(feature = "host-lock-sys"))]
        {
            match left {
                Some(left) => drop(
                    changed
                        .wait_timeout_while(guard, left, |wakes| *wakes == seen)
                        .unwrap_or_else(PoisonError::into_inner),
                ),
                None => drop(
                    changed
                        .wait_while(guard, |wakes| *wakes == seen)
                        .unwrap_or_else(PoisonError::into_inner),
                ),
            }
        }
        #[cfg(feature = "host-lock-sys")]
        {
            match left {
                Some(left) => drop(changed.wait_timeout_while(guard, left, |wakes| *wakes == seen)),
                None => {
                    let mut guard = guard;
                    while *guard == seen {
                        guard = changed.wait(guard);
                    }
                }
            }
        }
    }

    /// When a wait of `timeout_ms` ends, on the host's monotonic clock: `std`'s `Instant`, or the
    /// host's own reading of it.
    struct Deadline {
        #[cfg(not(feature = "host-lock-sys"))]
        at: Option<std::time::Instant>,
        #[cfg(feature = "host-lock-sys")]
        at_ns: u64,
    }

    impl Deadline {
        fn after_ms(timeout_ms: u64) -> Self {
            #[cfg(not(feature = "host-lock-sys"))]
            {
                Self {
                    at: std::time::Instant::now().checked_add(Duration::from_millis(timeout_ms)),
                }
            }
            #[cfg(feature = "host-lock-sys")]
            {
                Self {
                    at_ns: wz_host_sync::monotonic_ns()
                        .saturating_add(timeout_ms.saturating_mul(1_000_000)),
                }
            }
        }

        /// What is left of the wait, `None` once it has passed. A deadline past what the clock
        /// counts leaves the longest wait there is.
        fn left(&self) -> Option<Duration> {
            #[cfg(not(feature = "host-lock-sys"))]
            {
                let left = match self.at {
                    Some(at) => at.checked_duration_since(std::time::Instant::now()),
                    None => Some(Duration::MAX),
                };
                left.filter(|left| !left.is_zero())
            }
            #[cfg(feature = "host-lock-sys")]
            {
                let now = wz_host_sync::monotonic_ns();
                (now < self.at_ns).then(|| Duration::from_nanos(self.at_ns - now))
            }
        }
    }

    /// The waits of one link: its wake and the waker made of it, once, when the link is opened.
    /// A clone is a second reference to the same wake, for a wait on the link made from outside
    /// the loop that owns it.
    #[derive(Clone)]
    pub(super) struct Waits {
        wake: Arc<LinkWake>,
        waker: Waker,
    }

    impl Waits {
        /// The waits of a new link, sharing one wake.
        pub(super) fn new() -> Self {
            let wake = Arc::new(LinkWake {
                wakes: Mutex::new(0),
                changed: Condvar::new(),
            });
            let waker = Waker::from(Arc::clone(&wake));
            Self { wake, waker }
        }
    }

    impl Waits {
        /// How many wakes the link has had: read before `pending` is asked, so a wake that comes
        /// between the answer and the wait ends the wait at once.
        fn seen(&self) -> u64 {
            *lock(&self.wake.wakes)
        }

        /// Wait up to `timeout_ms` while `pending` answers `true`, handing it the waker the
        /// program's calls wake the link's waiters by.
        pub(super) fn wait_while(
            &self,
            timeout_ms: u64,
            mut pending: impl FnMut(Option<&Waker>) -> bool,
        ) {
            let deadline = Deadline::after_ms(timeout_ms);
            loop {
                let seen = self.seen();
                if !pending(Some(&self.waker)) {
                    return;
                }
                let Some(left) = deadline.left() else {
                    return;
                };
                wait_past(&self.wake.changed, lock(&self.wake.wakes), seen, Some(left));
            }
        }

        /// Wait while `pending` answers `true` and `bound`, a sleep of the session's clock, has
        /// not ended: the program's calls and the clock's move both wake the link's waker, and the
        /// wall clock bounds nothing.
        pub(super) fn wait_while_bound(
            &self,
            mut bound: super::BoundSleep,
            mut pending: impl FnMut(Option<&Waker>) -> bool,
        ) {
            let mut cx = Context::from_waker(&self.waker);
            loop {
                let seen = self.seen();
                if !pending(Some(&self.waker)) {
                    return;
                }
                if bound.as_mut().poll(&mut cx).is_ready() {
                    return;
                }
                wait_past(&self.wake.changed, lock(&self.wake.wakes), seen, None);
            }
        }
    }
}

#[cfg(not(feature = "host-lock"))]
mod wait_turns {
    use core::task::Waker;

    /// How many times a wait looks at the table before it returns to the engine's loop.
    const TURNS: u32 = 1 << 12;

    /// The waits of one link on an image, which has no thread to park: nothing to hold.
    #[derive(Clone)]
    pub(super) struct Waits;

    impl Waits {
        /// The waits of a new link: nothing to make.
        pub(super) const fn new() -> Self {
            Self
        }

        /// Look while `pending` answers `true`, for a bounded number of turns: an image's loop
        /// comes back.
        pub(super) fn wait_while(
            &self,
            _timeout_ms: u64,
            mut pending: impl FnMut(Option<&Waker>) -> bool,
        ) {
            for _ in 0..TURNS {
                if !pending(None) {
                    return;
                }
                core::hint::spin_loop();
            }
        }

        /// [`Self::wait_while`] whatever the clock: the turns bound an image's look, and the
        /// open's own deadline on the session's clock is the engine's.
        pub(super) fn wait_while_bound(
            &self,
            bound: super::BoundSleep,
            pending: impl FnMut(Option<&Waker>) -> bool,
        ) {
            drop(bound);
            self.wait_while(0, pending);
        }
    }
}

/// A sleep of the session's clock: what an [`OpenBound`] makes.
pub type BoundSleep = core::pin::Pin<Box<dyn core::future::Future<Output = ()> + Send>>;

/// How a session's clock bounds an open over the program's transport: a sleep of that many
/// milliseconds of it. Given for a clock the program moves (a time base it supplies), whose
/// sleeps end when the program says its time has passed them and not when the wall clock's do
/// ([`AppLinks::with_open_bound`]).
pub type OpenBound = Arc<dyn Fn(u64) -> BoundSleep + Send + Sync>;

/// The socket address a locator names, or the unspecified address when it names none.
fn socket_of(locator: &str) -> SocketAddr {
    let address = locator
        .split_once('#')
        .map_or(locator, |(address, _)| address);
    let address = address
        .split_once('/')
        .map_or(address, |(_, address)| address);
    address
        .parse()
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
}

/// Open a link of `kind` for `locator`, held to the session's queue bound, and wait until the
/// program says it is up: for [`OPEN_WAIT_MS`] of the wall clock, or of the session's clock when
/// `bound` gives a sleep of it.
fn open_link(
    session: &SessionTransport,
    kind: AppLinkKind,
    locator: &str,
    bound: Option<&OpenBound>,
) -> Result<Held, LinkOpenError> {
    let transport = &session.transport;
    let handle = session.begin_open(kind, locator);
    // The link's waits are made with it, so the open's wait and every one after share its wake.
    let waits = wait::Waits::new();
    let mut progress = OpenProgress::Opening;
    let opening = |waker: Option<&core::task::Waker>| {
        progress = transport.with(|table| table.poll_open(handle, waker));
        progress == OpenProgress::Opening
    };
    match bound {
        Some(bound) => waits.wait_while_bound(bound(OPEN_WAIT_MS), opening),
        None => waits.wait_while(OPEN_WAIT_MS, opening),
    }
    match progress {
        OpenProgress::Open => Ok(Held {
            transport: Arc::clone(transport),
            handle,
            waits,
        }),
        // Not up in time, or refused: the link is let go, and the dial is one the other end did
        // not take, which the engine tries again later.
        OpenProgress::Opening | OpenProgress::Closed => {
            transport.release(handle);
            Err(LinkOpenError::Refused)
        }
    }
}

/// One link of the program's transport as this engine's seams hold it: released when it drops.
struct Held {
    transport: Arc<AppTransport>,
    handle: LinkHandle,
    /// The link's wake, which every wait on it hands the program's calls.
    waits: wait::Waits,
}

impl Held {
    /// A link the program opened on its own (a stream or a source it accepted on a listener),
    /// held with a wake of its own.
    fn accepted(transport: &Arc<AppTransport>, handle: LinkHandle) -> Self {
        Self {
            transport: Arc::clone(transport),
            handle,
            waits: wait::Waits::new(),
        }
    }

    /// Offer the program `bytes` once, as far as it takes them now: how many it took, 0 when it
    /// would block (or the link is not writable yet).
    fn send_once(&self, bytes: &[u8]) -> Result<usize, AppLinkError> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            let gate = self
                .transport
                .with(|table| table.begin_send(self.handle, None));
            let ticket = match gate {
                SendGate::Go(ticket) => ticket,
                SendGate::Blocked | SendGate::Opening | SendGate::Busy => return Ok(0),
                SendGate::Closed => return Err(AppLinkError::Closed),
            };
            let answer = self.transport.port().send(self.handle, bytes);
            let (step, effects) = self
                .transport
                .with(|table| table.send_answered(ticket, bytes.len(), answer));
            self.transport.perform(effects);
            match step {
                SendStep::Retry => {}
                SendStep::Wrote(taken) => return Ok(taken),
                SendStep::Blocked => return Ok(0),
                SendStep::Closed => return Err(AppLinkError::Closed),
                SendStep::Failed => return Err(AppLinkError::Failed),
            }
        }
    }

    /// Offer the program what is held for it, until it would block or has taken all of it: each
    /// run lent in place by the transport ([`AppTransport::offer_remainder`]) and offered with no
    /// lock held, nothing copied. Another writer offering the link's remainder now offers it for
    /// this one.
    fn flush(&self) -> Result<(), AppLinkError> {
        loop {
            let mut sent = Ok(0);
            let Some((taken, offered)) = self.transport.offer_remainder(self.handle, |bytes| {
                sent = self.send_once(bytes);
                sent.as_ref().map_or(0, |taken| *taken)
            }) else {
                return Ok(());
            };
            sent?;
            if taken < offered {
                return Ok(());
            }
        }
    }

    /// Send `parts` in order behind what is held: what the program does not take now is held
    /// for it.
    fn send_all(&self, parts: &[&[u8]]) -> Result<(), AppLinkError> {
        self.flush()?;
        for part in parts {
            let held = self
                .transport
                .with(|table| table.holds_remainder(self.handle));
            let taken = if held { 0 } else { self.send_once(part)? };
            if taken < part.len() {
                self.transport
                    .with(|table| table.hold_remainder(self.handle, &part[taken..]))
                    .map_err(|_| AppLinkError::Full)?;
            }
        }
        Ok(())
    }

    /// Wait up to `timeout_ms` for input, offering what is held on the way.
    fn wait_readable(&self, timeout_ms: c_int) {
        let _ = self.flush();
        let timeout_ms = u64::try_from(timeout_ms).unwrap_or(0);
        self.waits.wait_while(timeout_ms, |waker| {
            !self
                .transport
                .with(|table| table.poll_readable(self.handle, waker))
        });
    }

    /// Wait up to `timeout_ms` for the program to take bytes again, offering what is held on the
    /// way: `true` once the link is open and holds nothing for the program (or has ended, which
    /// the send that follows reports).
    fn wait_writable(&self, timeout_ms: u64) -> bool {
        until_writable(
            &self.transport,
            self.handle,
            &self.waits,
            timeout_ms,
            || {
                let _ = self.flush();
            },
        )
    }

    /// The wait for this link's input that the link's owner makes ([`LinkInput`]).
    fn input(&self) -> LinkInput {
        LinkInput {
            transport: Arc::clone(&self.transport),
            handle: self.handle,
            waits: self.waits.clone(),
        }
    }

    /// What a read just made let the program know of: the links it refused that are read down.
    fn tell_drained(&self) {
        let drained = self.transport.with(|table| table.take_drained());
        self.transport.perform(drained);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.transport.release(self.handle);
    }
}

/// Wait up to `timeout_ms` for the program to take bytes on `handle` again, calling `offer` before
/// each look: `true` once the table answers the link writable (open and holding nothing for the
/// program, or ended, which the send that follows reports).
fn until_writable(
    transport: &AppTransport,
    handle: LinkHandle,
    waits: &wait::Waits,
    timeout_ms: u64,
    mut offer: impl FnMut(),
) -> bool {
    let mut writable = false;
    waits.wait_while(timeout_ms, |waker| {
        offer();
        writable = transport.with(|table| table.poll_writable(handle, waker));
        !writable
    });
    writable
}

/// A group link's wait for room, asked by a thread other than the one that sends on it: the
/// table's writable answer for the link, as the link's own wait reads it. It names the link and
/// holds nothing of it, so a wait made after the link was released answers at once.
struct GroupRoom {
    transport: Arc<AppTransport>,
    handle: LinkHandle,
    waits: wait::Waits,
}

impl LinkWritability for GroupRoom {
    fn wait_writable(&self, timeout_us: u64) -> bool {
        until_writable(
            &self.transport,
            self.handle,
            &self.waits,
            timeout_us.div_ceil(1_000),
            || {},
        )
    }
}

/// A link's wait for its next input, made by a thread other than the one that reads it (the
/// owner's, with nothing of the session held): the table's readable answer for the link, which
/// the program's handing in of bytes or a datagram, its accept of a stream on a listener and the
/// link's end wake. It names the link and holds nothing of it, so a wait made after the link was
/// released answers at once. It shares the link's wake, so the waker the table keeps for the link
/// is the one every wait on it hands over.
struct LinkInput {
    transport: Arc<AppTransport>,
    handle: LinkHandle,
    waits: wait::Waits,
}

impl LinkInput {
    /// Whether a step of the link has something to do: input to read, or bytes the link holds for
    /// a program that takes bytes now (it took part of a write), which a step offers again and no
    /// call of the program's announces. A program that would block wakes the wait when it says the
    /// link is writable.
    fn ready(&self, waker: Option<&core::task::Waker>) -> bool {
        self.transport.with(|table| {
            table.poll_readable(self.handle, waker)
                || (table.state(self.handle) == Some(wz_session_core::app_link::AppLinkState::Open)
                    && table.holds_remainder(self.handle))
        })
    }
}

impl LinkReadiness for LinkInput {
    fn wait_readable(&self, timeout_ms: u32) {
        self.waits
            .wait_while(u64::from(timeout_ms), |waker| !self.ready(waker));
    }
}

/// A byte stream over the program's transport: this engine's [`StreamSocket`] over a link.
pub struct AppStreamSocket {
    held: Held,
    local: SocketAddr,
    peer: SocketAddr,
}

impl StreamSocket for AppStreamSocket {
    type Error = AppLinkError;

    type Link<
        B: crate::link_storage::RxStore + 'static,
        X: crate::link_storage::TxStore + 'static,
    >
        = crate::stream_link::StreamDriver<Self, B, X>
    where
        Self: 'static;

    fn local(&self) -> SocketAddr {
        self.local
    }

    fn peer(&self) -> SocketAddr {
        self.peer
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), AppLinkError> {
        self.held.send_all(parts)
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        self.held.wait_readable(timeout_ms);
    }

    // The program's would-block is the stream's full buffer: a link that holds bytes for the
    // program takes no more until the program says it is writable.
    fn wait_writable(&self, timeout_us: u64) -> bool {
        self.held.wait_writable(timeout_us.div_ceil(1_000))
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, AppLinkError> {
        // A turn of the link's loop: what is held for the program is offered again.
        self.held.flush()?;
        let handle = self.held.handle;
        let read = self
            .held
            .transport
            .with(|table| table.read_stream(handle, buf, None));
        self.held.tell_drained();
        Ok(match read {
            StreamRead::Bytes(n) => Some(n),
            StreamRead::Empty => None,
            StreamRead::End => Some(0),
        })
    }

    fn shutdown(&self) {
        self.held.transport.release(self.held.handle);
    }

    // A host parks the owner's thread until the program's calls wake it; an image has no thread to
    // park, and its link waits in its loop.
    #[cfg(feature = "host-lock")]
    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        Some(Box::new(self.held.input()))
    }
}

/// How this engine opens streams over the program's transport: its [`StreamDial`].
#[derive(Clone)]
pub struct AppStreamDial {
    transport: SessionTransport,
    /// What an open waits on, when it is a clock of the session's ([`AppLinks::with_open_bound`]).
    open_bound: Option<OpenBound>,
}

impl StreamDial for AppStreamDial {
    type Stream = AppStreamSocket;

    fn dial(&self, to: SocketAddr) -> Result<AppStreamSocket, LinkOpenError> {
        let locator = Locator::tcp(to).to_string();
        let held = open_link(
            &self.transport,
            AppLinkKind::StreamDial,
            &locator,
            self.open_bound.as_ref(),
        )?;
        Ok(AppStreamSocket {
            held,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            peer: to,
        })
    }

    fn listen(
        &self,
        at: SocketAddr,
    ) -> Result<Box<dyn StreamListen<Stream = AppStreamSocket>>, LinkOpenError> {
        let locator = Locator::tcp(at).to_string();
        let held = open_link(
            &self.transport,
            AppLinkKind::StreamListen,
            &locator,
            self.open_bound.as_ref(),
        )?;
        Ok(Box::new(AppStreamListener { held, at }))
    }
}

/// A dial of [`AppLinks`] ([`SessionLinks::begin_initiator`]): a link made when it was begun, or
/// one the program was asked to open and has not reported up.
pub struct AppDial(AppDialing);

/// Where an [`AppDial`] stands.
// Held by value in its face's link, as `ip_stack::IpDial` is: a link being made is not boxed.
#[allow(clippy::large_enum_variant)]
enum AppDialing {
    Made(Dialled<HeapLink>),
    Pending(PendingAppLink),
}

impl PendingDial<HeapLink> for AppDial {
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink>, LinkOpenError>> {
        match &mut self.0 {
            AppDialing::Made(made) => made.poll(),
            AppDialing::Pending(pending) => pending.poll(),
        }
    }
}

impl From<OpenedLink<HeapLink>> for AppDial {
    fn from(opened: OpenedLink<HeapLink>) -> Self {
        Self(AppDialing::Made(Dialled::new(opened)))
    }
}

/// A link the program was asked to open and has not reported up ([`AppLinks`]'s begun dial):
/// asked without waiting whether it is up. Dropped before it is, it releases the link, which the
/// program is told to close.
struct PendingAppLink {
    held: Option<Held>,
    buffers: Option<(RxBuffer, TxBuffer)>,
    to: SocketAddr,
    /// A `udp/` link once up, else a `tcp/` one.
    datagram: bool,
    /// Whether the link is waited on by its owner once it is up, as its links' are.
    owner_waits: OwnerWaits,
}

impl PendingDial<HeapLink> for PendingAppLink {
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink>, LinkOpenError>> {
        let held = self.held.as_ref()?;
        let handle = held.handle;
        match held.transport.with(|table| table.poll_open(handle, None)) {
            OpenProgress::Opening => None,
            // Refused by the program, or closed before it was up: as a waiting open that ends so.
            OpenProgress::Closed => {
                self.held = None;
                self.buffers = None;
                Some(Err(LinkOpenError::Refused))
            }
            OpenProgress::Open => {
                let held = self.held.take()?;
                let (rx, tx) = self.buffers.take()?;
                Some(Ok(if self.datagram {
                    heap_link(self.owner_waits.datagram(UdpDriver::initiator_in(
                        AppDatagramSocket {
                            held,
                            peer: self.to,
                            reads_sources: true,
                        },
                        self.to,
                        rx,
                        tx,
                    )))
                } else {
                    heap_link(self.owner_waits.stream(StreamDriver::over(
                        AppStreamSocket {
                            held,
                            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                            peer: self.to,
                        },
                        rx,
                        tx,
                    )))
                }))
            }
        }
    }
}

/// A stream listener over the program's transport: the streams the program accepts on it.
pub struct AppStreamListener {
    held: Held,
    at: SocketAddr,
}

impl StreamListen for AppStreamListener {
    type Stream = AppStreamSocket;

    fn local(&self) -> SocketAddr {
        self.at
    }

    fn accept(&self) -> Result<Option<AppStreamSocket>, LinkOpenError> {
        let next = self.held.transport.with(|table| {
            table.next_accepted(self.held.handle, None, |handle, remote| {
                (handle, socket_of(remote))
            })
        });
        match next {
            AcceptRead::Accepted((handle, peer)) => Ok(Some(AppStreamSocket {
                held: Held::accepted(&self.held.transport, handle),
                local: self.at,
                peer,
            })),
            AcceptRead::Empty => Ok(None),
            AcceptRead::End => Err(LinkOpenError::Unsupported),
        }
    }

    // Ready when the program has accepted a stream on the listener, which wakes it.
    #[cfg(feature = "host-lock")]
    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        Some(Box::new(self.held.input()))
    }
}

/// A datagram link over the program's transport: this engine's [`DatagramSocket`] over a link.
pub struct AppDatagramSocket {
    held: Held,
    /// Where each datagram is said to come from when the program names no source.
    peer: SocketAddr,
    /// Whether the source the program names with a datagram is read. A link the session dialled
    /// reads it; a source the program accepted on a listener is one link alone, so each of its
    /// datagrams is `peer`'s whatever the program names.
    reads_sources: bool,
}

impl AppDatagramSocket {
    /// Open a datagram link to `to` over `transport`, held to the session's queue bound.
    pub fn dial(transport: &SessionTransport, to: SocketAddr) -> Result<Self, LinkOpenError> {
        Self::dial_bounded(transport, to, None)
    }

    /// [`Self::dial`] whose open waits on `bound`, a sleep of the session's clock, when there is
    /// one ([`AppLinks::with_open_bound`]).
    pub fn dial_bounded(
        transport: &SessionTransport,
        to: SocketAddr,
        bound: Option<&OpenBound>,
    ) -> Result<Self, LinkOpenError> {
        let locator = Locator::udp(to).to_string();
        let held = open_link(transport, AppLinkKind::Datagram, &locator, bound)?;
        Ok(Self {
            held,
            peer: to,
            reads_sources: true,
        })
    }

    /// The datagram link of the source the program accepted on a datagram listener as `handle`,
    /// at `peer`, the address of the locator the program named for it.
    fn accepted(transport: &Arc<AppTransport>, handle: LinkHandle, peer: SocketAddr) -> Self {
        Self {
            held: Held::accepted(transport, handle),
            peer,
            reads_sources: false,
        }
    }

    /// Take the next datagram into `buf`: its length (cut to `buf`) and source.
    fn take(&self, buf: &mut [u8]) -> Result<Option<Received>, AppLinkError> {
        let handle = self.held.handle;
        let read = self.held.transport.with(|table| {
            table.read_datagram(handle, None, |datagram| {
                let source = match datagram.source() {
                    Some(named) if self.reads_sources => socket_of(named),
                    _ => self.peer,
                };
                (datagram.copy_to(buf), source)
            })
        });
        self.held.tell_drained();
        match read {
            DatagramRead::Datagram(taken) => Ok(Some(taken)),
            DatagramRead::Empty => Ok(None),
            DatagramRead::End => Err(AppLinkError::Closed),
        }
    }
}

impl DatagramSocket for AppDatagramSocket {
    type Error = AppLinkError;

    fn bind(_at: SocketAddr) -> Result<Self, AppLinkError> {
        Err(AppLinkError::NotCarried)
    }

    fn local(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }

    fn send_to(&self, _to: SocketAddr, bytes: &[u8]) -> Result<(), AppLinkError> {
        // A datagram goes whole or not at all: one the program cannot take now is dropped, as a
        // socket whose buffer is full drops it.
        match self.held.send_once(bytes)? {
            taken if taken == bytes.len() => Ok(()),
            0 => Err(AppLinkError::WouldBlock),
            _ => Err(AppLinkError::Failed),
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        self.held.wait_readable(timeout_ms);
    }

    fn times_out(&self) -> bool {
        false
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, AppLinkError> {
        self.take(buf)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, AppLinkError> {
        self.take(buf)
    }

    #[cfg(feature = "host-lock")]
    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        Some(Box::new(self.held.input()))
    }
}

/// A group the program joins over its transport: this engine's [`GroupTransport`]. Leaving the
/// group is closing the link.
pub struct AppGroupTransport {
    held: Option<Held>,
    /// The datagram the last receive lent, which the transport keeps until its next receive so
    /// that a datagram asked to be kept is lent again whole. Its storage is taken when the group
    /// is joined, room for the widest datagram, and each receive copies into it.
    lent: alloc::vec::Vec<u8>,
    /// The source of the datagram in `lent`, `None` while it holds none.
    lent_from: Option<SocketAddr>,
    /// Whether the next receive lends `lent` again ([`GroupTransport::keep`]).
    kept: bool,
}

impl AppGroupTransport {
    /// Join the group `locator` names (a `udp/` locator with `#iface=`) over `transport`, the
    /// group's link held to the session's queue bound.
    pub fn join(transport: &SessionTransport, locator: &str) -> Result<Self, LinkOpenError> {
        Self::join_bounded(transport, locator, None)
    }

    /// [`Self::join`] whose open waits on `bound`, a sleep of the session's clock, when there is
    /// one ([`AppLinks::with_open_bound`]).
    pub fn join_bounded(
        transport: &SessionTransport,
        locator: &str,
        bound: Option<&OpenBound>,
    ) -> Result<Self, LinkOpenError> {
        Ok(Self {
            held: Some(open_link(transport, AppLinkKind::Group, locator, bound)?),
            lent: alloc::vec::Vec::with_capacity(DATAGRAM_MAX),
            lent_from: None,
            kept: false,
        })
    }
}

impl GroupTransport for AppGroupTransport {
    fn open(&mut self) -> bool {
        self.held.as_ref().is_some_and(|held| {
            held.transport
                .with(|table| table.state(held.handle))
                .is_some_and(|state| {
                    matches!(
                        state,
                        wz_session_core::app_link::AppLinkState::Open
                            | wz_session_core::app_link::AppLinkState::Blocked
                    )
                })
        })
    }

    fn close(&mut self) {
        // Dropping the link closes it on the program, which is the leave.
        self.held = None;
        self.lent_from = None;
        self.kept = false;
    }

    fn service(&self) {}

    fn carrier_up(&self) -> bool {
        self.held.as_ref().is_some_and(|held| {
            held.transport
                .with(|table| table.state(held.handle))
                .is_some_and(|state| {
                    !matches!(
                        state,
                        wz_session_core::app_link::AppLinkState::Closing
                            | wz_session_core::app_link::AppLinkState::Closed
                    )
                })
        })
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        // Best-effort, as a multicast send is: what the program cannot take now is not sent.
        if let Some(held) = &self.held {
            let _ = held.send_once(datagram);
        }
    }

    // The program's would-block is the group socket's full buffer: the datagram was not sent,
    // and the link takes no more until the program says it is writable. A datagram goes whole
    // or not at all, so one the program took part of is lost.
    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        let Some(held) = &self.held else {
            return GroupSend::Failed;
        };
        match held.send_once(datagram) {
            Ok(taken) if taken == datagram.len() => GroupSend::Sent,
            Ok(0) => GroupSend::Full,
            Ok(_) | Err(_) => GroupSend::Failed,
        }
    }

    // The table's writable answer for the link; a group that was left answers at once, and the
    // send that follows fails.
    fn wait_for_room(&self, timeout_us: u64) -> bool {
        match &self.held {
            Some(held) => held.wait_writable(timeout_us.div_ceil(1_000)),
            None => true,
        }
    }

    fn writability(&self) -> Option<Box<dyn LinkWritability>> {
        let held = self.held.as_ref()?;
        Some(Box::new(GroupRoom {
            transport: Arc::clone(&held.transport),
            handle: held.handle,
            waits: held.waits.clone(),
        }))
    }

    // The table's readable answer for the link, waited on from outside the group's loop; a group
    // that was left gives none.
    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        Some(Box::new(self.held.as_ref()?.input()))
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        // A datagram kept is lent again before the program's next one is read.
        if core::mem::take(&mut self.kept) {
            if let Some(source) = self.lent_from {
                f(self.lent.as_slice(), source);
                return true;
            }
        }
        let Some(held) = &self.held else {
            return false;
        };
        let lent = &mut self.lent;
        let read = held.transport.with(|table| {
            table.read_datagram(held.handle, None, |datagram| {
                lent.resize(datagram.len(), 0);
                datagram.copy_to(lent);
                // The table holds a group's datagrams only with their source.
                datagram.source().map_or(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    socket_of,
                )
            })
        });
        held.tell_drained();
        match read {
            DatagramRead::Datagram(source) => {
                self.lent_from = Some(source);
                f(self.lent.as_slice(), source);
                true
            }
            DatagramRead::Empty | DatagramRead::End => false,
        }
    }

    // The datagram the table handed over is the transport's until the next receive.
    fn keeps_input(&self) -> bool {
        true
    }

    fn keep(&mut self) {
        self.kept = self.lent_from.is_some();
    }
}

/// The session shell's links over the program's transport: a `tcp/` dial and listen open
/// streams through the program, a `udp/` dial a datagram link, a `udp/` listen a datagram
/// listener and a `udp/` listen naming an interface a group the program joins, and nothing is a
/// socket of the system's. A `tls/` locator is not carried. Each link is held to the queue bound
/// of the session the links are made for.
pub struct AppLinks {
    transport: SessionTransport,
    dial: AppStreamDial,
    datagram_rx: usize,
    open_bound: Option<OpenBound>,
    /// The tables of the session the links serve, when it lent some
    /// ([`SessionLinks::lend_buffers`]): every link claims its buffers there, and none allocates.
    lent: Option<LinkTables>,
    /// Whether each link is waited on by its owner ([`Self::waited_by_owner`]).
    owner_waits: OwnerWaits,
}

/// Whether the links of an [`AppLinks`] are waited on by their owner
/// ([`AppLinks::waited_by_owner`]), carried to the links a begun dial and a listener make later.
#[derive(Debug, Clone, Copy)]
struct OwnerWaits(bool);

impl OwnerWaits {
    /// A stream link as the links open it.
    fn stream(
        self,
        link: StreamDriver<AppStreamSocket, RxBuffer, TxBuffer>,
    ) -> StreamDriver<AppStreamSocket, RxBuffer, TxBuffer> {
        if self.0 {
            link.waited_by_owner()
        } else {
            link
        }
    }

    /// A datagram link as the links open it.
    fn datagram(
        self,
        link: UdpDriver<AppDatagramSocket, RxBuffer, TxBuffer>,
    ) -> UdpDriver<AppDatagramSocket, RxBuffer, TxBuffer> {
        if self.0 {
            link.waited_by_owner()
        } else {
            link
        }
    }
}

impl AppLinks {
    /// Links over `transport`, as the session whose bound it carries opens them.
    pub fn new(transport: SessionTransport) -> Self {
        Self {
            dial: AppStreamDial {
                transport: transport.clone(),
                open_bound: None,
            },
            transport,
            datagram_rx: UDP_RX_CAPACITY,
            open_bound: None,
            lent: None,
            owner_waits: OwnerWaits(false),
        }
    }

    /// Links whose owner waits for their input, as
    /// [`IpLinks::waited_by_owner`](crate::ip_stack::IpLinks::waited_by_owner) opens a host's:
    /// what steps a session behind a lock and waits for its links outside the lock. On a host
    /// each link's loop then reads what is queued and does not wait, and the program's calls wake
    /// the owner's wait; an image's links give no such wait and still wait in their loop.
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.owner_waits = OwnerWaits(true);
        self
    }

    /// Links whose datagram links receive into buffers of `bytes` each, as
    /// [`IpLinks::with_rx_capacity`](crate::ip_stack::IpLinks::with_rx_capacity) states it.
    #[must_use]
    pub fn with_rx_capacity(mut self, bytes: usize) -> Self {
        self.datagram_rx = bytes.clamp(1, UDP_RX_CAPACITY);
        self
    }

    /// Links whose opens wait for the program to report a link up for `OPEN_WAIT_MS` of the
    /// session's clock, which `bound` sleeps on, in place of the wall clock's: the clock of a
    /// session timed by a time base the program supplies.
    #[must_use]
    pub fn with_open_bound(mut self, bound: OpenBound) -> Self {
        self.dial.open_bound = Some(Arc::clone(&bound));
        self.open_bound = Some(bound);
        self
    }
}

impl SessionLinks for AppLinks {
    type Pump = HeapLink;

    type Dial = AppDial;

    fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // A datagram port that takes whoever sends first is a socket of the system's; the
        // program's transport accepts streams and datagram sources on listeners
        // (`open_listener`).
        Err(LinkOpenError::Unsupported)
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The buffers are claimed before the program is asked for a link, so a session whose
        // tables are full asks it for none.
        match to.proto {
            LinkProto::Udp => {
                let (rx, tx) = heap_link_buffers(self.lent.as_ref(), self.datagram_rx, 0, 0)?;
                Ok(heap_link(self.owner_waits.datagram(
                    UdpDriver::initiator_in(
                        AppDatagramSocket::dial_bounded(
                            &self.transport,
                            to.at,
                            self.open_bound.as_ref(),
                        )?,
                        to.at,
                        rx,
                        tx,
                    ),
                )))
            }
            LinkProto::Tcp => {
                let (rx, tx) = heap_link_buffers(self.lent.as_ref(), STREAM_RX_CAPACITY, 0, 0)?;
                Ok(heap_link(self.owner_waits.stream(StreamDriver::over(
                    self.dial.dial(to.at)?,
                    rx,
                    tx,
                ))))
            }
            LinkProto::Tls => Err(LinkOpenError::Unsupported),
        }
    }

    /// The program is asked for the link and the dial returned before it reports the link up
    /// (`PendingAppLink`), so an open the program finishes late does not hold whoever holds the
    /// session: the engine asks between its steps and gives the open up at its own open deadline,
    /// on the session's clock, in place of the `OPEN_WAIT_MS` a waiting open is held to. The
    /// buffers are claimed before the program is asked, as a waiting open's are, and go back with
    /// an open that is refused or given up.
    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        let (kind, rx, datagram) = match to.proto {
            LinkProto::Udp => (AppLinkKind::Datagram, self.datagram_rx, true),
            LinkProto::Tcp => (AppLinkKind::StreamDial, STREAM_RX_CAPACITY, false),
            LinkProto::Tls => return Err(LinkOpenError::Unsupported),
        };
        let buffers = heap_link_buffers(self.lent.as_ref(), rx, 0, 0)?;
        let handle = self.transport.begin_open(kind, &to.to_string());
        Ok(AppDial(AppDialing::Pending(PendingAppLink {
            held: Some(Held {
                transport: Arc::clone(&self.transport.transport),
                handle,
                waits: wait::Waits::new(),
            }),
            buffers: Some(buffers),
            to: to.at,
            datagram,
            owner_waits: self.owner_waits,
        })))
    }

    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<Self::Pump>>, LinkOpenError> {
        match at.proto {
            LinkProto::Tcp => Ok(Box::new(AppLinkListener {
                listener: self.dial.listen(at.at)?,
                lent: self.lent,
                owner_waits: self.owner_waits,
            })),
            LinkProto::Udp => {
                let locator = Locator::udp(at.at).to_string();
                let held = open_link(
                    &self.transport,
                    AppLinkKind::DatagramListen,
                    &locator,
                    self.open_bound.as_ref(),
                )?;
                Ok(Box::new(AppDatagramListener {
                    held,
                    at: at.at,
                    datagram_rx: self.datagram_rx,
                    lent: self.lent,
                    owner_waits: self.owner_waits,
                }))
            }
            LinkProto::Tls => Err(LinkOpenError::Unsupported),
        }
    }

    /// The group the program joins for `endpoint`: a `udp/` listen locator naming an interface,
    /// which is what the table opens as a group. Any other endpoint is no group the program's
    /// transport carries, and is refused before the program is asked.
    /// Every link opened from now on, and every one a listener opened after this takes, claims its
    /// buffers from `tables`, and its row of the program's transport is taken now, one for each
    /// link the tables hold.
    fn lend_buffers(&mut self, tables: LinkTables) {
        self.transport.provision(tables.links());
        self.lent = Some(tables);
    }

    fn open_group(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        if kind_for_locator(endpoint, true) != Some(AppLinkKind::Group) {
            return Err(LinkOpenError::Unsupported);
        }
        Ok(Box::new(AppGroupTransport::join_bounded(
            &self.transport,
            endpoint,
            self.open_bound.as_ref(),
        )?))
    }

    /// A link of these is shared already: the pump is the handle the sink is a clone of.
    fn share_pump(
        pump: Self::Pump,
    ) -> crate::link_cells::CellRc<dyn crate::session_drive::SessionDatagramLink> {
        pump
    }
}

/// A `udp/` listener of [`AppLinks`]: each source the program accepts on it is a datagram link.
struct AppDatagramListener {
    held: Held,
    at: SocketAddr,
    /// The receive buffer each accepted link reads into, as [`AppLinks::with_rx_capacity`] set it.
    datagram_rx: usize,
    /// The session's tables, which each accepted link claims its buffers from ([`AppLinks`]).
    lent: Option<LinkTables>,
    /// Whether each accepted link is waited on by its owner, as its links' are.
    owner_waits: OwnerWaits,
}

impl LinkListener<HeapLink> for AppDatagramListener {
    fn local(&self) -> Locator {
        Locator::udp(self.at)
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink>>, LinkOpenError> {
        let next = self.held.transport.with(|table| {
            table.next_accepted(self.held.handle, None, |handle, remote| {
                (handle, socket_of(remote))
            })
        });
        let socket = match next {
            AcceptRead::Accepted((handle, peer)) => {
                AppDatagramSocket::accepted(&self.held.transport, handle, peer)
            }
            AcceptRead::Empty => return Ok(None),
            AcceptRead::End => return Err(LinkOpenError::Unsupported),
        };
        // The program told this source apart from the others, so the link's remote end is known
        // from the start, as a dialled link's is; the session over it still runs as the acceptor.
        let peer = socket.peer;
        // Claimed once the source is taken, as an IP listener claims: one the session's tables
        // have no buffers left for is let go of, not left waiting.
        let (rx, tx) = heap_link_buffers(self.lent.as_ref(), self.datagram_rx, 0, 0)?;
        Ok(Some(heap_link(
            self.owner_waits
                .datagram(UdpDriver::initiator_in(socket, peer, rx, tx)),
        )))
    }

    // Ready when the program has accepted a source on the listener, which wakes it.
    #[cfg(feature = "host-lock")]
    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        Some(Box::new(self.held.input()))
    }
}

/// A `tcp/` listener of [`AppLinks`]: each stream the program accepts is a link.
struct AppLinkListener {
    listener: Box<dyn StreamListen<Stream = AppStreamSocket>>,
    /// The session's tables, which each accepted link claims its buffers from ([`AppLinks`]).
    lent: Option<LinkTables>,
    /// Whether each accepted link is waited on by its owner, as its links' are.
    owner_waits: OwnerWaits,
}

impl LinkListener<HeapLink> for AppLinkListener {
    fn local(&self) -> Locator {
        Locator::tcp(self.listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink>>, LinkOpenError> {
        let Some(stream) = self.listener.accept()? else {
            return Ok(None);
        };
        let (rx, tx) = heap_link_buffers(self.lent.as_ref(), STREAM_RX_CAPACITY, 0, 0)?;
        Ok(Some(heap_link(
            self.owner_waits.stream(StreamDriver::over(stream, rx, tx)),
        )))
    }

    fn readiness(&self) -> Option<Box<dyn LinkReadiness>> {
        self.listener.readiness()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec::Vec;

    /// What `link` holds for the program, read through the offer a writer makes, with nothing
    /// taken: the front run, which is all of it while it has not wrapped.
    fn held(transport: &AppTransport, link: LinkHandle) -> Vec<u8> {
        let mut seen = Vec::new();
        let _ = transport.offer_remainder(link, |bytes| {
            seen = bytes.to_vec();
            0
        });
        seen
    }
    use alloc::string::String;
    use alloc::vec;
    use std::sync::Mutex;
    use wz_session_core::app_link_table::{AppLinkTable, ProgramEvent, ProgramOpen, ProgramSend};
    use wz_session_core::app_transport::{AppPort, TableLock};

    struct HostLock(Mutex<AppLinkTable>);

    impl TableLock for HostLock {
        fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable)) {
            f(&mut self.0.lock().unwrap());
        }
    }

    #[derive(Default)]
    struct Script {
        opens: Mutex<Vec<(LinkHandle, AppLinkKind, String)>>,
        sent: Mutex<Vec<u8>>,
        closes: Mutex<Vec<LinkHandle>>,
        answers: Mutex<Vec<ProgramSend>>,
    }

    struct Port(Arc<Script>);

    impl AppPort for Port {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            self.0
                .opens
                .lock()
                .unwrap()
                .push((link, kind, String::from(locator)));
            ProgramOpen::Up
        }

        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            let mut answers = self.0.answers.lock().unwrap();
            let answer = if answers.is_empty() {
                ProgramSend::Wrote(bytes.len())
            } else {
                answers.remove(0)
            };
            if let ProgramSend::Wrote(n) = answer {
                self.0
                    .sent
                    .lock()
                    .unwrap()
                    .extend_from_slice(&bytes[..n.min(bytes.len())]);
            }
            answer
        }

        fn close(&self, link: LinkHandle) {
            self.0.closes.lock().unwrap().push(link);
        }
    }

    fn transport() -> (Arc<Script>, Arc<AppTransport>) {
        let script = Arc::new(Script::default());
        let transport = Arc::new(AppTransport::new(
            Box::new(HostLock(Mutex::new(AppLinkTable::new()))),
            Box::new(Port(Arc::clone(&script))),
        ));
        (script, transport)
    }

    /// `transport` as a session whose links queue at most `bound` bytes opens links over it.
    fn session(transport: &Arc<AppTransport>, bound: usize) -> SessionTransport {
        SessionTransport {
            transport: Arc::clone(transport),
            queue: wz_session_core::limit_binding::Quota::at_most(bound),
        }
    }

    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 7447);

    #[test]
    fn a_dial_opens_a_stream_through_the_program_named_by_its_locator() {
        let (script, transport) = transport();
        let stream = AppStreamDial {
            transport: session(&transport, 64),
            open_bound: None,
        }
        .dial(PEER)
        .expect("the program answers up");
        assert_eq!(
            script.opens.lock().unwrap()[0],
            (
                stream.held.handle,
                AppLinkKind::StreamDial,
                String::from("tcp/192.0.2.9:7447")
            )
        );
        assert_eq!(stream.peer(), PEER);
        drop(stream);
        assert_eq!(
            script.closes.lock().unwrap().len(),
            1,
            "dropping the socket closes it"
        );
    }

    #[test]
    fn what_the_program_does_not_take_is_held_and_leaves_in_order_once_writable() {
        let (script, transport) = transport();
        *script.answers.lock().unwrap() = vec![ProgramSend::Wrote(2), ProgramSend::WouldBlock];
        let stream = AppStreamDial {
            transport: session(&transport, 64),
            open_bound: None,
        }
        .dial(PEER)
        .unwrap();
        // The seam takes every byte: two leave, the rest is held.
        stream
            .send_parts(&[b"ab", b"cd", b"ef"])
            .expect("held, not failed");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"ab");
        assert_eq!(held(&transport, stream.held.handle), b"cdef");
        // A later send queues behind the remainder rather than overtaking it.
        stream.send_parts(&[b"gh"]).unwrap();
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"ab");
        transport
            .event(stream.held.handle, ProgramEvent::Writable)
            .unwrap();
        // The next turn of the loop offers it again.
        let mut buf = [0u8; 4];
        assert_eq!(stream.try_read(&mut buf), Ok(None));
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"abcdefgh");
        assert!(!transport.with(|table| table.holds_remainder(stream.held.handle)));
    }

    #[test]
    fn a_remainder_past_the_bound_fails_the_send() {
        let (script, transport) = transport();
        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock];
        let stream = AppStreamDial {
            transport: session(&transport, 4),
            open_bound: None,
        }
        .dial(PEER)
        .unwrap();
        assert_eq!(stream.send_parts(&[b"abcdef"]), Err(AppLinkError::Full));
    }

    #[test]
    fn a_stream_reads_what_the_program_hands_in_and_ends_when_it_closes() {
        let (_script, transport) = transport();
        let stream = AppStreamDial {
            transport: session(&transport, 64),
            open_bound: None,
        }
        .dial(PEER)
        .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(stream.try_read(&mut buf), Ok(None));
        transport.received(stream.held.handle, b"hi", None).unwrap();
        assert_eq!(stream.try_read(&mut buf), Ok(Some(2)));
        assert_eq!(&buf[..2], b"hi");
        transport
            .event(stream.held.handle, ProgramEvent::Closed)
            .unwrap();
        assert_eq!(
            stream.try_read(&mut buf),
            Ok(Some(0)),
            "the end of the stream"
        );
    }

    #[test]
    fn a_datagram_goes_whole_or_is_dropped() {
        let (script, transport) = transport();
        let socket = AppDatagramSocket::dial(&session(&transport, 64), PEER).unwrap();
        socket.send_to(PEER, b"whole").unwrap();
        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock, ProgramSend::Wrote(1)];
        assert_eq!(
            socket.send_to(PEER, b"later"),
            Err(AppLinkError::WouldBlock)
        );
        // Blocked until the program says writable: nothing is offered meanwhile.
        assert_eq!(socket.send_to(PEER, b"wait"), Err(AppLinkError::WouldBlock));
        transport
            .event(socket.held.handle, ProgramEvent::Writable)
            .unwrap();
        assert_eq!(socket.send_to(PEER, b"cut"), Err(AppLinkError::Failed));
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"wholec");
        transport
            .received(socket.held.handle, b"in", Some("udp/192.0.2.10:7000"))
            .unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            socket.try_recv(&mut buf),
            Ok(Some((2, SocketAddr::from(([192, 0, 2, 10], 7000)))))
        );
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
    }

    #[test]
    fn a_group_is_joined_read_by_member_and_left_on_close() {
        let (script, transport) = transport();
        let mut group =
            AppGroupTransport::join(&session(&transport, 64), "udp/239.7.7.7:7447#iface=lan7")
                .expect("joined");
        assert!(group.open());
        assert!(group.carrier_up());
        let handle = group.held.as_ref().unwrap().handle;
        group.send_to_group(b"join");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"join");
        transport
            .received(handle, b"member", Some("udp/198.51.100.20:7447"))
            .unwrap();
        let mut seen = Vec::new();
        assert!(group.recv_with(&mut |bytes, src| seen.push((bytes.to_vec(), src))));
        assert_eq!(
            seen,
            [(
                b"member".to_vec(),
                SocketAddr::from(([198, 51, 100, 20], 7447))
            )]
        );
        assert!(!group.recv_with(&mut |_, _| {}));
        group.close();
        assert_eq!(
            script.closes.lock().unwrap().as_slice(),
            [handle],
            "the leave"
        );
        assert!(!group.open(), "a group left is not opened again");
    }

    /// A datagram the group asks to keep is lent again, whole and from its member, before the
    /// program's next one; one not kept is not, and a group that was left keeps nothing.
    #[test]
    fn a_kept_group_datagram_is_lent_again_before_the_next() {
        let (_script, transport) = transport();
        let mut group =
            AppGroupTransport::join(&session(&transport, 64), "udp/239.7.7.7:7447#iface=lan7")
                .expect("joined");
        assert!(group.keeps_input());
        let handle = group.held.as_ref().unwrap().handle;
        for bytes in [b"one".as_slice(), b"two".as_slice()] {
            transport
                .received(handle, bytes, Some("udp/198.51.100.20:7447"))
                .unwrap();
        }
        let member = SocketAddr::from(([198, 51, 100, 20], 7447));
        let mut seen = Vec::new();
        assert!(group.recv_with(&mut |bytes, src| seen.push((bytes.to_vec(), src))));
        group.keep();
        assert!(group.recv_with(&mut |bytes, src| seen.push((bytes.to_vec(), src))));
        assert!(group.recv_with(&mut |bytes, src| seen.push((bytes.to_vec(), src))));
        assert_eq!(
            seen,
            [
                (b"one".to_vec(), member),
                (b"one".to_vec(), member),
                (b"two".to_vec(), member)
            ],
            "the kept datagram once more, then the next, and the next is not lent twice"
        );
        assert!(!group.recv_with(&mut |_, _| {}));
        group.keep();
        group.close();
        assert!(
            !group.recv_with(&mut |_, _| {}),
            "a group that was left lends nothing it kept"
        );
    }

    /// A group's datagram the program cannot take now is full and not sent, and the link has no
    /// room until the program says it is writable, whether the group's loop asks or a thread
    /// outside it does; one the program took part of is lost, and a group that was left fails its
    /// send and has room at once.
    #[test]
    fn a_group_datagram_the_program_cannot_take_is_full_until_it_is_writable() {
        let (script, transport) = transport();
        let mut group =
            AppGroupTransport::join(&session(&transport, 64), "udp/239.7.7.7:7447#iface=lan7")
                .expect("joined");
        let handle = group.held.as_ref().unwrap().handle;
        let outside = group.writability().expect("a wait from outside the loop");
        assert_eq!(group.try_send_to_group(b"sent"), GroupSend::Sent);
        assert!(
            group.wait_for_room(0),
            "CONTROL: a link that took the datagram"
        );

        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock];
        assert_eq!(group.try_send_to_group(b"full"), GroupSend::Full);
        assert!(
            !group.wait_for_room(0),
            "no room until the program is writable"
        );
        assert!(!outside.wait_writable(0), "nor asked from outside");
        assert_eq!(
            group.try_send_to_group(b"held"),
            GroupSend::Full,
            "nothing is offered meanwhile"
        );
        transport.event(handle, ProgramEvent::Writable).unwrap();
        assert!(group.wait_for_room(0));
        assert!(outside.wait_writable(0));

        *script.answers.lock().unwrap() = vec![ProgramSend::Wrote(1)];
        assert_eq!(group.try_send_to_group(b"part"), GroupSend::Failed);
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"sentp");

        group.close();
        assert_eq!(group.try_send_to_group(b"left"), GroupSend::Failed);
        assert!(group.wait_for_room(0));
        assert!(
            outside.wait_writable(0),
            "a wait made after the leave answers at once"
        );
    }

    /// A group's wait for input, made from outside the group's loop through the box the links
    /// hand the group out in: it is waited out while nothing is queued, returns once the program
    /// hands in a datagram from another thread, and returns at once while one is queued and once
    /// the group was left. A group that was left gives no wait.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_groups_wait_for_input_returns_when_the_program_hands_in_a_datagram() {
        use std::time::{Duration, Instant};
        let (_script, transport) = transport();
        let joined =
            AppGroupTransport::join(&session(&transport, 64), "udp/239.7.7.7:7447#iface=lan7")
                .expect("joined");
        let handle = joined.held.as_ref().unwrap().handle;
        let mut group: Box<dyn GroupTransport> = Box::new(joined);
        let ready = group.readiness().expect("a wait from outside the loop");
        let started = Instant::now();
        ready.wait_readable(50);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "nothing queued: the wait is waited out"
        );

        let handing = {
            let transport = Arc::clone(&transport);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                transport
                    .received(handle, b"member", Some("udp/198.51.100.20:7447"))
                    .unwrap();
            })
        };
        let started = Instant::now();
        ready.wait_readable(10_000);
        let waited = started.elapsed();
        handing.join().expect("the program's thread");
        assert!(
            waited < Duration::from_secs(5),
            "woken by the datagram, not the end of the wait: {waited:?}"
        );
        let started = Instant::now();
        ready.wait_readable(10_000);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a datagram is queued"
        );

        group.close();
        assert!(group.readiness().is_none(), "a group left gives no wait");
        let started = Instant::now();
        ready.wait_readable(10_000);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a wait made after the leave answers at once"
        );
    }

    #[test]
    fn the_links_open_a_stream_and_a_datagram_link_and_refuse_tls() {
        let (_script, transport) = transport();
        let links = AppLinks::new(session(&transport, 64));
        let tcp = links.open_initiator(Locator::tcp(PEER)).expect("a stream");
        assert!(wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*tcp.sink));
        let udp = links
            .open_initiator(Locator::udp(PEER))
            .expect("a datagram link");
        assert!(!wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*udp.sink));
        assert!(matches!(
            links.open_initiator(Locator::tls(PEER)),
            Err(LinkOpenError::Unsupported)
        ));
        assert!(matches!(
            links.open_acceptor(7447),
            Err(LinkOpenError::Unsupported)
        ));
    }

    /// A program whose opens stay under way until the test reports them, recording each open and
    /// each close as [`Script`] does.
    struct Deferred(Arc<Script>);

    impl AppPort for Deferred {
        fn open(&self, link: LinkHandle, kind: AppLinkKind, locator: &str) -> ProgramOpen {
            self.0
                .opens
                .lock()
                .unwrap()
                .push((link, kind, String::from(locator)));
            ProgramOpen::Pending
        }

        fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
            ProgramSend::Wrote(bytes.len())
        }

        fn close(&self, link: LinkHandle) {
            self.0.closes.lock().unwrap().push(link);
        }
    }

    fn deferred() -> (Arc<Script>, Arc<AppTransport>) {
        let script = Arc::new(Script::default());
        let transport = Arc::new(AppTransport::new(
            Box::new(HostLock(Mutex::new(AppLinkTable::new()))),
            Box::new(Deferred(Arc::clone(&script))),
        ));
        (script, transport)
    }

    /// A begun dial asks the program for its link and waits for nothing: asked while the program
    /// has not reported the link up it answers nothing, however often, and once the program
    /// reports it up it answers the link, once.
    #[test]
    fn a_begun_dial_waits_for_no_open_and_is_made_once_the_program_reports_it_up() {
        let (script, transport) = deferred();
        let links = AppLinks::new(session(&transport, 64));
        let mut pending = links
            .begin_initiator(Locator::tcp(PEER))
            .expect("the program is asked");
        let (handle, kind, locator) = script.opens.lock().unwrap()[0].clone();
        assert_eq!(
            (kind, locator.as_str()),
            (AppLinkKind::StreamDial, "tcp/192.0.2.9:7447")
        );
        for _ in 0..3 {
            assert!(pending.poll().is_none(), "not reported up yet");
        }
        transport.event(handle, ProgramEvent::Connected).unwrap();
        let opened = pending
            .poll()
            .expect("the dial answered")
            .expect("the link is up");
        assert!(wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*opened.sink));
        assert!(pending.poll().is_none(), "a dial answers once");
        assert!(script.closes.lock().unwrap().is_empty());
    }

    /// A begun datagram dial the program closes before it is up is refused; one the session gives
    /// up while it is under way is released, and the program is told to close it; a `tls/` dial
    /// is not the program's to open.
    #[test]
    fn a_begun_dial_the_program_closes_is_refused_and_one_given_up_is_closed() {
        let (script, transport) = deferred();
        let links = AppLinks::new(session(&transport, 64));
        let mut refused = links
            .begin_initiator(Locator::udp(PEER))
            .expect("the program is asked");
        let (first, kind, _) = script.opens.lock().unwrap()[0].clone();
        assert_eq!(kind, AppLinkKind::Datagram);
        transport.event(first, ProgramEvent::Closed).unwrap();
        assert!(matches!(refused.poll(), Some(Err(LinkOpenError::Refused))));

        let given_up = links
            .begin_initiator(Locator::tcp(PEER))
            .expect("the program is asked");
        let second = script.opens.lock().unwrap()[1].0;
        drop(given_up);
        assert!(
            script.closes.lock().unwrap().contains(&second),
            "the program is told to close the link the session gave up"
        );

        assert!(matches!(
            links.begin_initiator(Locator::tls(PEER)),
            Err(LinkOpenError::Unsupported)
        ));
        assert_eq!(
            script.opens.lock().unwrap().len(),
            2,
            "a tls/ dial asks the program for nothing"
        );
    }

    #[test]
    fn a_listener_hands_out_the_streams_the_program_accepts() {
        let (_script, transport) = transport();
        let links = AppLinks::new(session(&transport, 64));
        let listener = links.open_listener(Locator::tcp(PEER)).expect("listening");
        assert!(matches!(listener.accept(), Ok(None)));
        let listening = transport.with(|table| {
            (1..=8)
                .find(|handle| table.kind(*handle) == Some(AppLinkKind::StreamListen))
                .expect("the listener's link")
        });
        transport
            .accepted(listening, "tcp/198.51.100.3:50000")
            .unwrap();
        assert!(matches!(listener.accept(), Ok(Some(_))));
    }

    /// The handle the program was asked to open as a datagram listener, and the locator it was
    /// asked for.
    fn datagram_listener_of(script: &Script) -> (LinkHandle, String) {
        script
            .opens
            .lock()
            .unwrap()
            .iter()
            .find(|(_, kind, _)| *kind == AppLinkKind::DatagramListen)
            .map(|(handle, _, locator)| (*handle, locator.clone()))
            .expect("the program was asked to listen for datagrams")
    }

    #[test]
    fn a_datagram_listener_hands_out_each_source_the_program_accepts_as_a_datagram_link() {
        let (script, transport) = transport();
        let links = AppLinks::new(session(&transport, 64));
        let listener = links
            .open_listener(Locator::udp(PEER))
            .expect("a udp/ listen is carried");
        assert_eq!(listener.local(), Locator::udp(PEER));
        let (listening, locator) = datagram_listener_of(&script);
        assert_eq!(locator, "udp/192.0.2.9:7447");
        assert!(matches!(listener.accept(), Ok(None)), "no source yet");
        transport
            .accepted(listening, "udp/198.51.100.3:50000")
            .expect("a datagram listener accepts");
        let opened = listener
            .accept()
            .expect("the listener stands")
            .expect("the accepted source is a link");
        assert!(
            !wz_session_core::link::BoxedLinkDriver::batch_length_prefixed(&*opened.sink),
            "an accepted source carries datagrams, each a batch"
        );
        assert!(matches!(listener.accept(), Ok(None)), "one link per source");
        // A listener the program closed is broken for good, and the engine lets it go.
        transport.event(listening, ProgramEvent::Closed).unwrap();
        assert!(matches!(listener.accept(), Err(LinkOpenError::Unsupported)));
    }

    #[test]
    fn an_accepted_source_reads_every_datagram_as_its_own() {
        let (script, transport) = transport();
        let links = AppLinks::new(session(&transport, 64));
        let _listener = links.open_listener(Locator::udp(PEER)).unwrap();
        let (listening, _) = datagram_listener_of(&script);
        transport
            .accepted(listening, "udp/198.51.100.3:50000")
            .unwrap();
        let AcceptRead::Accepted((handle, peer)) = transport.with(|table| {
            table.next_accepted(listening, None, |handle, remote| {
                (handle, socket_of(remote))
            })
        }) else {
            panic!("the accepted source waits on the listener");
        };
        let socket = AppDatagramSocket::accepted(&transport, handle, peer);
        // The program names another source, and then none: both are the accepted source's.
        transport
            .received(handle, b"one", Some("udp/203.0.113.7:9"))
            .unwrap();
        transport.received(handle, b"two", None).unwrap();
        let source = SocketAddr::from(([198, 51, 100, 3], 50000));
        let mut buf = [0u8; 8];
        assert_eq!(socket.try_recv(&mut buf), Ok(Some((3, source))));
        assert_eq!(socket.try_recv(&mut buf), Ok(Some((3, source))));
        assert_eq!(socket.try_recv(&mut buf), Ok(None));
        // A dialled link reads the source the program names.
        let dialled = AppDatagramSocket::dial(&session(&transport, 64), PEER).unwrap();
        transport
            .received(dialled.held.handle, b"in", Some("udp/203.0.113.7:9"))
            .unwrap();
        assert_eq!(
            dialled.try_recv(&mut buf),
            Ok(Some((2, SocketAddr::from(([203, 0, 113, 7], 9)))))
        );
    }

    #[test]
    fn the_links_join_a_group_through_the_program_and_refuse_what_names_none() {
        let (script, transport) = transport();
        let links = AppLinks::new(session(&transport, 64));
        // Neither a datagram listen nor another scheme names a group: refused, with nothing asked
        // of the program.
        for endpoint in ["udp/192.0.2.9:7447", "tcp/239.7.7.7:7447#iface=lan7"] {
            assert!(
                matches!(links.open_group(endpoint), Err(LinkOpenError::Unsupported)),
                "{endpoint}"
            );
        }
        assert!(script.opens.lock().unwrap().is_empty());
        let mut group = links
            .open_group("udp/239.7.7.7:7447#iface=lan7")
            .expect("a group the program joins");
        let (handle, kind, locator) = script.opens.lock().unwrap()[0].clone();
        assert_eq!(
            (kind, locator.as_str()),
            (AppLinkKind::Group, "udp/239.7.7.7:7447#iface=lan7"),
            "the program is asked to join the group the endpoint names"
        );
        // The boxed transport is the group's: taken as the session's link, sent to, read by
        // member, left.
        assert!(group.open());
        assert!(group.carrier_up());
        group.send_to_group(b"beacon");
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"beacon");
        transport
            .received(handle, b"member", Some("udp/198.51.100.20:7447"))
            .unwrap();
        let mut seen = Vec::new();
        assert!(group.recv_with(&mut |bytes, src| seen.push((bytes.to_vec(), src))));
        assert_eq!(
            seen,
            [(
                b"member".to_vec(),
                SocketAddr::from(([198, 51, 100, 20], 7447))
            )]
        );
        group.close();
        assert_eq!(
            script.closes.lock().unwrap().as_slice(),
            [handle],
            "the leave"
        );
    }

    /// A program whose opens stay under way: it never reports a link up.
    #[cfg(feature = "host-lock")]
    struct Unanswered;

    #[cfg(feature = "host-lock")]
    impl AppPort for Unanswered {
        fn open(&self, _link: LinkHandle, _kind: AppLinkKind, _locator: &str) -> ProgramOpen {
            ProgramOpen::Pending
        }

        fn send(&self, _link: LinkHandle, _bytes: &[u8]) -> ProgramSend {
            ProgramSend::WouldBlock
        }

        fn close(&self, _link: LinkHandle) {}
    }

    /// A sleep of a clock the test moves: it ends once the test says the clock passed it, and
    /// wakes whoever waits on it then.
    #[cfg(feature = "host-lock")]
    struct Until {
        passed: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<Mutex<Option<core::task::Waker>>>,
    }

    #[cfg(feature = "host-lock")]
    impl core::future::Future for Until {
        type Output = ();

        fn poll(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<()> {
            let passed = || self.passed.load(std::sync::atomic::Ordering::SeqCst);
            if passed() {
                return core::task::Poll::Ready(());
            }
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            if passed() {
                core::task::Poll::Ready(())
            } else {
                core::task::Poll::Pending
            }
        }
    }

    /// An open bounded by the session's clock is given up when that clock passes the bound, long
    /// before the wall clock's ten seconds; while it has not, the open is still waiting.
    #[cfg(feature = "host-lock")]
    #[test]
    fn an_open_bounded_on_the_sessions_clock_is_given_up_when_that_clock_passes() {
        let transport = Arc::new(AppTransport::new(
            Box::new(HostLock(Mutex::new(AppLinkTable::new()))),
            Box::new(Unanswered),
        ));
        let passed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None::<core::task::Waker>));
        let bound: OpenBound = {
            let (passed, waker) = (Arc::clone(&passed), Arc::clone(&waker));
            Arc::new(move |_ms| {
                Box::pin(Until {
                    passed: Arc::clone(&passed),
                    waker: Arc::clone(&waker),
                }) as BoundSleep
            })
        };
        let opening = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let opened =
                AppDatagramSocket::dial_bounded(&session(&transport, 64), PEER, Some(&bound));
            (opened.is_err(), started.elapsed())
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !opening.is_finished(),
            "the open ended while the session's clock stood still"
        );
        passed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        let (refused, took) = opening.join().expect("the opening thread");
        assert!(refused, "an open the program never reported up is refused");
        assert!(
            took < std::time::Duration::from_secs(5),
            "the open waited out the wall clock's bound, not the session clock's ({took:?})"
        );
    }

    /// A group's join and a datagram listen of links bounded on the session's clock wait on that
    /// clock as a dial does: still waiting while it stands still, given up once it passes the
    /// bound, long before the wall clock's ten seconds.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_group_join_and_a_datagram_listen_are_bounded_on_the_sessions_clock() {
        for listen in [false, true] {
            let transport = Arc::new(AppTransport::new(
                Box::new(HostLock(Mutex::new(AppLinkTable::new()))),
                Box::new(Unanswered),
            ));
            let passed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let waker = Arc::new(Mutex::new(None::<core::task::Waker>));
            let bound: OpenBound = {
                let (passed, waker) = (Arc::clone(&passed), Arc::clone(&waker));
                Arc::new(move |_ms| {
                    Box::pin(Until {
                        passed: Arc::clone(&passed),
                        waker: Arc::clone(&waker),
                    }) as BoundSleep
                })
            };
            // The links stay on the thread that opens them, as a session's links stay behind its
            // engine's lock: the buffers a session lends them are not `Send`. The clock is moved
            // from another thread, as a program's time base moves it.
            let links = AppLinks::new(session(&transport, 64)).with_open_bound(bound);
            let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let clock = {
                let (passed, waker, ended) =
                    (Arc::clone(&passed), Arc::clone(&waker), Arc::clone(&ended));
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    let ended_early = ended.load(std::sync::atomic::Ordering::SeqCst);
                    passed.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Some(waker) = waker.lock().unwrap().take() {
                        waker.wake();
                    }
                    ended_early
                })
            };
            let started = std::time::Instant::now();
            let refused = if listen {
                links.open_listener(Locator::udp(PEER)).is_err()
            } else {
                links.open_group("udp/239.7.7.7:7447#iface=lan7").is_err()
            };
            let took = started.elapsed();
            ended.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(
                !clock.join().expect("the clock's thread"),
                "listen={listen}: the open ended while the session's clock stood still"
            );
            assert!(
                refused,
                "listen={listen}: an open never reported up is refused"
            );
            assert!(
                took < std::time::Duration::from_secs(5),
                "listen={listen}: the open waited out the wall clock's bound ({took:?})"
            );
        }
    }

    /// One wake of a link's waits ends every wait on the link, its read's and a publisher's for
    /// room alike: the waits share the one wake the link was opened with, and the waker the table
    /// holds is that wake's, whichever wait handed it over.
    #[cfg(feature = "host-lock")]
    #[test]
    fn one_wake_of_a_link_ends_every_wait_on_it() {
        use core::task::Waker;
        use std::sync::atomic::{AtomicBool, Ordering};

        let waits = wait::Waits::new();
        let ready = AtomicBool::new(false);
        let held: Mutex<Option<Waker>> = Mutex::new(None);
        let started = std::time::Instant::now();
        std::thread::scope(|scope| {
            let wait_on_link = || {
                waits.wait_while(10_000, |waker| {
                    if let Some(waker) = waker {
                        *held.lock().unwrap() = Some(waker.clone());
                    }
                    !ready.load(Ordering::SeqCst)
                });
            };
            // The read's wait and a publisher's wait for room, on two threads.
            let read = scope.spawn(wait_on_link);
            let room = scope.spawn(wait_on_link);
            std::thread::sleep(std::time::Duration::from_millis(100));
            ready.store(true, Ordering::SeqCst);
            let waker = held
                .lock()
                .unwrap()
                .take()
                .expect("a wait handed its waker over");
            waker.wake();
            read.join().expect("the read's wait ran");
            room.join().expect("the wait for room ran");
        });
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a wait on the link outlived the wake ({:?})",
            started.elapsed()
        );
    }

    /// The owner's wait on a stream link: waited out while nothing is queued, ended by bytes the
    /// program hands in from another thread, at once while bytes are queued, and at once while the
    /// link holds bytes for a program that takes bytes (it took part of a write), which the step
    /// after the wait offers again; while the program would block the wait is for its word that
    /// the link is writable.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_streams_wait_for_its_owner_ends_on_input_and_on_bytes_owed_to_the_program() {
        use std::time::{Duration, Instant};
        let (script, transport) = transport();
        let stream = AppStreamDial {
            transport: session(&transport, 64),
            open_bound: None,
        }
        .dial(PEER)
        .expect("the program answers up");
        let handle = stream.held.handle;
        let ready = stream.readiness().expect("a wait for the owner");
        let started = Instant::now();
        ready.wait_readable(50);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "nothing queued: the wait is waited out"
        );

        let handing = {
            let transport = Arc::clone(&transport);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                transport.received(handle, b"in", None).unwrap();
            })
        };
        let started = Instant::now();
        ready.wait_readable(10_000);
        let waited = started.elapsed();
        handing.join().expect("the program's thread");
        assert!(
            waited < Duration::from_secs(5),
            "woken by the bytes, not the end of the wait: {waited:?}"
        );
        let started = Instant::now();
        ready.wait_readable(10_000);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bytes are queued"
        );
        let mut buf = [0u8; 8];
        assert_eq!(stream.try_read(&mut buf), Ok(Some(2)));

        // The program takes two bytes of six: the rest is held, and the wait ends at once.
        *script.answers.lock().unwrap() = vec![ProgramSend::Wrote(2)];
        stream.send_parts(&[b"abcdef"]).expect("held, not failed");
        let started = Instant::now();
        ready.wait_readable(10_000);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bytes owed to a program that takes bytes end the wait"
        );
        // The step's offer finds the program blocked: the wait is waited out until it says
        // writable, and then ends, and the next offer leaves the rest.
        *script.answers.lock().unwrap() = vec![ProgramSend::WouldBlock];
        assert_eq!(stream.try_read(&mut buf), Ok(None));
        assert_eq!(held(&transport, handle), b"cdef");
        let started = Instant::now();
        ready.wait_readable(50);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "a program that would block is waited on"
        );
        transport.event(handle, ProgramEvent::Writable).unwrap();
        let started = Instant::now();
        ready.wait_readable(10_000);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "writable: the rest is offered"
        );
        assert_eq!(stream.try_read(&mut buf), Ok(None));
        assert_eq!(script.sent.lock().unwrap().as_slice(), b"abcdef");
    }

    /// The owner's wait on a listener ends when the program accepts a stream on it, and on a
    /// datagram link when the program hands in a datagram.
    #[cfg(feature = "host-lock")]
    #[test]
    fn a_listeners_wait_ends_on_an_accept_and_a_datagram_links_on_a_datagram() {
        use std::time::{Duration, Instant};
        let (_script, transport) = transport();
        let links = AppLinks::new(session(&transport, 64)).waited_by_owner();
        let listener = links.open_listener(Locator::tcp(PEER)).expect("listening");
        let listening = transport.with(|table| {
            (1..=8)
                .find(|handle| table.kind(*handle) == Some(AppLinkKind::StreamListen))
                .expect("the listener's link")
        });
        let ready = listener.readiness().expect("a wait for the owner");
        let started = Instant::now();
        ready.wait_readable(50);
        assert!(
            started.elapsed() >= Duration::from_millis(40),
            "nothing accepted: the wait is waited out"
        );
        let accepting = {
            let transport = Arc::clone(&transport);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                transport
                    .accepted(listening, "tcp/198.51.100.3:50000")
                    .unwrap();
            })
        };
        let started = Instant::now();
        ready.wait_readable(10_000);
        let waited = started.elapsed();
        accepting.join().expect("the program's thread");
        assert!(
            waited < Duration::from_secs(5),
            "woken by the accept, not the end of the wait: {waited:?}"
        );
        assert!(matches!(listener.accept(), Ok(Some(_))));

        let socket = AppDatagramSocket::dial(&session(&transport, 64), PEER).unwrap();
        let handle = socket.held.handle;
        let ready = socket.readiness().expect("a wait for the owner");
        let handing = {
            let transport = Arc::clone(&transport);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                transport
                    .received(handle, b"d", Some("udp/198.51.100.3:50000"))
                    .unwrap();
            })
        };
        let started = Instant::now();
        ready.wait_readable(10_000);
        let waited = started.elapsed();
        handing.join().expect("the program's thread");
        assert!(
            waited < Duration::from_secs(5),
            "woken by the datagram, not the end of the wait: {waited:?}"
        );
    }

    /// Links opened to be waited on by their owner give the owner a wait for each link and do not
    /// wait in the link's loop: the thread that steps the session never sleeps there with the
    /// session held, and a hundred turns of the loop take no tick each. That holds of a dialled
    /// stream and datagram link, of a stream a listener accepted and of a begun dial once the
    /// program reports it up. The CONTROL is the same links of links not opened so: no wait for the
    /// owner, and each turn of a stream's loop waits its tick for input.
    #[cfg(feature = "host-lock")]
    #[test]
    fn links_waited_by_their_owner_give_a_wait_and_do_not_wait_in_their_loop() {
        use crate::session_drive::SessionDatagramLink;
        use std::time::{Duration, Instant};

        /// The links a session over `transport` holds: two dialled, one accepted, one begun.
        fn opened(transport: &Arc<AppTransport>, links: &AppLinks) -> Vec<OpenedLink<HeapLink>> {
            let mut opened = vec![
                links.open_initiator(Locator::tcp(PEER)).expect("a stream"),
                links
                    .open_initiator(Locator::udp(PEER))
                    .expect("a datagram link"),
            ];
            let listener = links.open_listener(Locator::tcp(PEER)).expect("listening");
            let listening = transport.with(|table| {
                (1..=16)
                    .find(|handle| table.kind(*handle) == Some(AppLinkKind::StreamListen))
                    .expect("the listener's link")
            });
            transport
                .accepted(listening, "tcp/198.51.100.3:50000")
                .unwrap();
            opened.push(
                listener
                    .accept()
                    .expect("the listener stands")
                    .expect("the accepted stream is a link"),
            );
            let mut begun = links
                .begin_initiator(Locator::tcp(PEER))
                .expect("the program is asked");
            opened.push(
                begun
                    .poll()
                    .expect("the program answered up at once")
                    .expect("the link is up"),
            );
            opened
        }

        let (_script, own_transport) = transport();
        let own_loop = AppLinks::new(session(&own_transport, 64));
        for (at, link) in opened(&own_transport, &own_loop).iter().enumerate() {
            assert!(
                link.pump.readiness().is_none(),
                "CONTROL: link {at} gives its owner no wait"
            );
        }
        let stream = own_loop
            .open_initiator(Locator::tcp(PEER))
            .expect("a stream");
        let started = Instant::now();
        for _ in 0..20 {
            stream.pump.service();
        }
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "CONTROL: each turn waits its tick in the loop ({:?})",
            started.elapsed()
        );

        let (_script, transport) = transport();
        let owner = AppLinks::new(session(&transport, 64)).waited_by_owner();
        for (at, link) in opened(&transport, &owner).iter().enumerate() {
            assert!(
                link.pump.readiness().is_some(),
                "link {at} gives its owner a wait"
            );
            let started = Instant::now();
            for _ in 0..100 {
                link.pump.service();
            }
            assert!(
                started.elapsed() < Duration::from_millis(50),
                "link {at}: a turn of the loop waited ({:?} for 100)",
                started.elapsed()
            );
        }
    }
}
