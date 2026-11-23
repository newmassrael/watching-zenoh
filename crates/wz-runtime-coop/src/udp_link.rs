// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's link over UDP datagrams, written once for every stack that has BSD-style
//! sockets under a cooperative loop.
//!
//! A platform supplies a [`DatagramSocket`]: bind, send, and the three ways of taking a datagram
//! (wait for one, take one that is queued, wait and take in one call). Everything above the socket
//! is the same on every platform and is here: [`UdpDriver`] is the session's outbound
//! [`BoxedLinkDriver`] and the drive loop's [`SessionDatagramLink`] over one socket, and
//! [`UdpStack`] is the stack the slot profile's session host is given, opening a driver for each
//! dial.
//!
//! Zephyr's sockets (`wz-runtime-zephyr`) and the host's (`wz-runtime-posix`) are the two sockets
//! that exist. They were one copy of this code each until the host needed it: a stack brings a
//! socket, not a link, because a second copy of a 400-line piece that decides is the shape the
//! session host rejects: it is written once, over the stack's driver and pump link.
//!
//! The receive buffer and the buffer outbound frames are encoded into are the driver's type
//! parameters: a `Vec<u8>` and `HeapTx` on the heap profile, claims on the image's byte tables on
//! the fixed one ([`FixedUdpDriver`]), where the driver is a few words in the session's slot and a
//! datagram costs no allocation either way.

use core::cell::{Cell, OnceCell, RefCell};
use core::ffi::c_int;
use core::fmt::Debug;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// The heap profile's forms (`Vec`, `HeapTx`) exist only in the heap profile: under `session-slot`
// the crate does not link `alloc` at all, which `lib.rs` keeps so that a use creeping back into the
// slot profile is a compile error and not a silent allocation.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use alloc::collections::VecDeque;
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use alloc::rc::Rc;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

#[cfg(feature = "session-slot")]
use core::marker::PhantomData;

use wz_session_core::byte_cells::ByteBuf;
#[cfg(feature = "session-slot")]
use wz_session_core::byte_cells::ByteSource;
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use wz_session_core::datagram_peer::is_init_syn;
use wz_session_core::datagram_peer::{ForeignCounts, PeerBinding};
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEndpoints, LinkSendOutcome, TxSlot, TxSlotGrant,
    DEFAULT_LINK_MTU,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::HeapTx;
use crate::link_storage::{TxLender, TxStore};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::LinkReadiness;
#[cfg(feature = "session-slot")]
use crate::session_drive::{Bind, DriverPump, LinkOpenError, SlotStack};
use crate::session_drive::{LinkProto, Locator, SessionDatagramLink};

/// The largest UDP payload the session receives in one datagram: the transport's own ceiling, so a
/// whole batch always fits.
pub const UDP_RX_CAPACITY: usize = 65_535;

/// How long one pass of the drive loop waits for its link's socket to have a datagram. It bounds
/// the loop's timers (the lease, the keep-alive, the retransmissions), which are looked at once
/// per pass, so it is as long as the loop has always slept between passes: a quiet link costs the
/// same, a datagram costs none of it. A socket bounds its blocking reads by it
/// ([`DatagramSocket::times_out`]).
pub const SERVICE_WAIT_MS: c_int = 1;

/// A datagram a socket took into the caller's buffer: how many bytes it wrote there, and the
/// address and port it came from.
pub type Received = (usize, SocketAddr);

/// One UDP socket of a platform's network stack, IPv4 or IPv6 as the address it is bound to is,
/// bound to an explicit local address (the one the link's locator names). Only the one thread
/// that drives the link touches it.
///
/// The family is the address's, as zenoh-pico opens a socket of the family its locator resolved
/// to (`vendor/zenoh-pico/src/link/transport/udp/udp_zephyr.c` @
/// `socket(endpoint._iptcp->ai_family`): a socket bound to an IPv6 address sends to and receives
/// from IPv6 addresses, and a stack without the family refuses the bind.
pub trait DatagramSocket: Sized {
    /// Why a call failed, as the platform reports it. `Copy`, because the driver keeps the last
    /// receive failure for the deploy to report.
    type Error: Copy + Debug;

    /// Open a socket of `at`'s family and bind it to `at`; port 0 has the stack choose one, as a
    /// dialling link needs, and [`Self::local`] then names the port it chose, never the 0.
    fn bind(at: SocketAddr) -> Result<Self, Self::Error>;

    /// The address and port this socket is bound to.
    fn local(&self) -> SocketAddr;

    /// Send one datagram to `to`, an address of the socket's family. A short or refused send is
    /// an error: UDP either takes the whole datagram or none of it.
    fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Block until a datagram is queued or `timeout_ms` has passed, and return at once when one
    /// already is. A failed wait is the same as a quiet socket here: the receive that follows
    /// reads and reports the error.
    fn wait_readable(&self, timeout_ms: c_int);

    /// Whether [`Self::recv_waiting`] can wait: a blocking read of this socket gives up after
    /// [`SERVICE_WAIT_MS`].
    fn times_out(&self) -> bool;

    /// Whether [`Self::set_receive_timeout`] can take a value. A constant, so that a link over a
    /// socket that cannot compiles the loop's deadline arithmetic out
    /// ([`SessionDatagramLink::uses_wake_budget`]) and an image over it is the image it was.
    const CAN_SET_RECEIVE_TIMEOUT: bool = false;

    /// Bound every blocking read of this socket by `ms` milliseconds from now on, in place of the
    /// [`SERVICE_WAIT_MS`] it was opened with. `true` when the socket took it.
    ///
    /// The provided form takes none, so a socket that cannot is waited on for the one tick it
    /// always was. A socket that can lets the link sleep until the session's next deadline
    /// ([`SessionDatagramLink::service_within`]) instead of waking every tick.
    fn set_receive_timeout(&self, ms: c_int) -> bool {
        let _ = ms;
        false
    }

    /// Wait up to the socket's receive timeout for a datagram and take it into `buf` in the same
    /// call: `Ok(None)` when the timeout ran out, else its length and source. Only for a socket
    /// whose [`Self::times_out`] is true: without the timeout the read would block for ever.
    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error>;

    /// Take one queued datagram into `buf` without blocking: `Ok(None)` when nothing is queued,
    /// else its length and source.
    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error>;

    /// A wait for this socket that a thread other than the link's can make
    /// ([`SessionDatagramLink::readiness`]); `None` when the platform gives none, and then a link
    /// over the socket waits in its own loop whatever it was asked.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        None
    }

    /// Whether a datagram for this socket's link was taken off the stack already, by another
    /// reader of a socket the link shares (a listener's, `PortPeer`), and waits to be read: the
    /// link's owner then steps it at once, where a wait on the stack would not end for it. The
    /// provided answer is no, for a socket that is its link's alone.
    fn holds_datagram(&self) -> bool {
        false
    }

    /// Whether the platform opens datagram sockets at all. A stack asks before it claims any
    /// buffer, so a `udp/` locator on a stack with none is `LinkOpenError::Unsupported`
    /// (permanent) and never `LinkOpenError::Exhausted` (retried): the stream twin is
    /// `StreamDial::CARRIED`.
    const CARRIED: bool = true;

    /// Whether the platform opens IPv6 sockets: `false` on a stack built without IPv6, whose bind
    /// of an IPv6 address is refused for its family ([`Self::refuses_address`]). A constant, so
    /// that a stack of these sockets says so where an endpoint is read (`Bind::IPV6`,
    /// `SessionLinks::IPV6`) and an image of one carries no reader of IPv6 text.
    const IPV6: bool = true;

    /// Whether `error`, from a [`Self::bind`], says the stack can never open a socket for the
    /// address (the stack has no such family, as an IPv6 address on a stack without IPv6, or the
    /// stack cannot name it): a dial that meets it is `LinkOpenError::Unsupported` and not
    /// retried, where any other failed bind is a socket the stack had none of now. The provided
    /// answer is that it never says so, for a platform whose error does not tell.
    fn refuses_address(error: &Self::Error) -> bool {
        let _ = error;
        false
    }
}

/// A failed [`DatagramSocket::bind`] as the stack's refusal to open the link: permanent for an
/// address the socket can never have ([`DatagramSocket::refuses_address`]), retried otherwise.
pub fn bind_refused<S: DatagramSocket>(error: S::Error) -> crate::session_drive::LinkOpenError {
    if S::refuses_address(&error) {
        crate::session_drive::LinkOpenError::Unsupported
    } else {
        crate::session_drive::LinkOpenError::Exhausted
    }
}

/// The datagram socket of a stack that carries none: an image whose links are all streams names it
/// for the `U` of `IpStack`, and every `udp/` dial is `LinkOpenError::Unsupported`. There is no
/// value of it, as there is none of `NoStream`.
#[derive(Debug, Clone, Copy)]
pub enum NoDatagram {}

impl DatagramSocket for NoDatagram {
    type Error = ();

    const CARRIED: bool = false;

    // A socket that opens nothing opens no IPv6 address either.
    const IPV6: bool = false;

    fn bind(_at: SocketAddr) -> Result<Self, ()> {
        Err(())
    }

    fn local(&self) -> SocketAddr {
        match *self {}
    }

    fn send_to(&self, _to: SocketAddr, _bytes: &[u8]) -> Result<(), ()> {
        match *self {}
    }

    fn wait_readable(&self, _timeout_ms: c_int) {
        match *self {}
    }

    fn times_out(&self) -> bool {
        match *self {}
    }

    fn recv_waiting(&self, _buf: &mut [u8]) -> Result<Option<Received>, ()> {
        match *self {}
    }

    fn try_recv(&self, _buf: &mut [u8]) -> Result<Option<Received>, ()> {
        match *self {}
    }
}

/// The unspecified address of `ip`'s family: `0.0.0.0` or `::`.
pub const fn unspecified_like(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// What a socket that dials `peer` is bound to, on a node whose own address is `local`: `local`
/// when it is of the peer's family, else the unspecified address of the peer's family, and port
/// 0 either way, so the stack chooses the port and, for the unspecified address, the source too.
/// A node bound to one family still dials the other where its stack carries it, as zenoh-pico's
/// Zephyr link binds nothing before it sends and its stack picks the source of the peer's family
/// (`vendor/zenoh-pico/src/link/transport/udp/udp_zephyr.c` @ `_z_udp_zephyr_open`).
pub const fn dial_bind(local: IpAddr, peer: SocketAddr) -> SocketAddr {
    let ip = match (local, peer.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => local,
        (_, other) => unspecified_like(other),
    };
    SocketAddr::new(ip, 0)
}

/// The two ends of a link of `proto` from `local` to `peer`, each zenoh's locator text
/// ([`Locator::text`]); an end whose text is longer than the build's locator bound reads blank,
/// which is how [`LinkEndpoints`] names an end it cannot hold.
pub fn link_endpoints(proto: LinkProto, local: SocketAddr, peer: SocketAddr) -> LinkEndpoints {
    let (src, dst) = (
        Locator { proto, at: local }.text(),
        Locator { proto, at: peer }.text(),
    );
    LinkEndpoints::new(src.finish().unwrap_or(""), dst.finish().unwrap_or(""))
}

/// The session's link over one socket `S`, with its receive buffer in `B` and its outbound frames
/// built in `T`: a `Vec<u8>` and `HeapTx` on the heap profile, claims on the image's byte
/// tables on the fixed one ([`FixedUdpDriver`]).
///
/// The link has one peer, fixed once known ([`PeerBinding`]): an initiator's from its dial, an
/// acceptor's from the first `InitSyn` it takes. Every send goes to it, and the session reads its
/// datagrams only; what anyone else sends is discarded and counted ([`Self::foreign`]). UDP is
/// connectionless, so `open_blocking` / `close_blocking` are no-ops: the zenoh handshake and Close
/// frame are the session's open and close.
pub struct UdpDriver<S: DatagramSocket, B: AsMut<[u8]>, T: TxStore> {
    socket: S,
    binding: PeerBinding<SocketAddr>,
    /// The link's two ends, `udp/<ip>:<port>` each, written the first time they are asked for
    /// once the peer is known. Not at the binding: a node that never reads them (no admin space,
    /// no link statistics) then carries no code that writes a locator's text.
    endpoints: OnceCell<LinkEndpoints>,
    rx_buf: RefCell<B>,
    /// The length of `rx_buf`, the largest datagram the link receives whole.
    rx_len: usize,
    /// The memory the session encodes its frames into, and which of it is out.
    tx: TxLender<T>,
    /// The length of a datagram [`SessionDatagramLink::service`] already read into `rx_buf` while
    /// it waited and the binding admitted, for the next receive to hand out without another call
    /// into the stack. Judged when it is read, so only its length is held and not its source: a
    /// datagram the binding does not admit is discarded there and holds nothing.
    stash: Cell<Option<usize>>,
    /// The length of the datagram at the front of `rx_buf` that its session asked the link to keep
    /// ([`SessionDatagramLink::keep`]), lent again whole by the next receive before any other.
    kept: Cell<Option<usize>>,
    /// Whether the session asked, while a datagram is lent, to keep it.
    keeping: Cell<bool>,
    /// The last receive failure, kept for the deploy to report: the loop's
    /// seam returns a frame or nothing, and a socket that fails must not
    /// read as a quiet one.
    rx_error: Cell<Option<S::Error>>,
    /// The longest this link may wait for a datagram when its session has nothing due sooner, in
    /// milliseconds. [`SERVICE_WAIT_MS`] (the default) is the tick the loop has always slept:
    /// the image raises it ([`Self::with_idle_wait_ms`]) only when this link is the one thing its
    /// loop waits on, because another session's socket is not looked at while this one blocks.
    idle_wait_ms: u32,
    /// The receive timeout the socket is armed with now, in milliseconds.
    armed_wait_ms: Cell<c_int>,
    /// Whether the link's owner waits on its socket ([`Self::waited_by_owner`]), so its loop does
    /// not.
    owner_waits: bool,
}

/// The fixed-memory profile's driver: its receive buffer and the buffer its frames are built in
/// are each lent by a table the image declares
/// ([`ByteCells`](wz_session_core::byte_cells::ByteCells)), the first as long as the batch the
/// session advertises and the second as long as the largest frame the link carries. A datagram
/// longer than the receive buffer is truncated by the stack, which the session reads as a bad
/// frame.
pub type FixedUdpDriver<S> = UdpDriver<S, ByteBuf, ByteBuf>;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<S: DatagramSocket> UdpDriver<S, Vec<u8>, HeapTx> {
    /// An acceptor's link: no peer until the first `InitSyn` it takes names one.
    pub fn acceptor(socket: S) -> Self {
        Self::acceptor_with_capacity(socket, UDP_RX_CAPACITY)
    }

    /// An initiator's link: replies and first sends go to `peer`.
    pub fn initiator(socket: S, peer: SocketAddr) -> Self {
        Self::initiator_with_capacity(socket, peer, UDP_RX_CAPACITY)
    }

    /// [`Self::acceptor_with_capacity`] that also lends the session the slots of `tx` to encode its
    /// frames into.
    pub fn acceptor_with_buffers(socket: S, rx_capacity: usize, tx: HeapTx) -> Self {
        Self::acceptor_in(socket, vec![0u8; rx_capacity], tx)
    }

    /// [`Self::initiator_with_capacity`] that also lends the session the slots of `tx` to encode
    /// its frames into.
    pub fn initiator_with_buffers(
        socket: S,
        peer: SocketAddr,
        rx_capacity: usize,
        tx: HeapTx,
    ) -> Self {
        Self::initiator_in(socket, peer, vec![0u8; rx_capacity], tx)
    }

    /// An acceptor's link whose receive buffer holds `rx_capacity` bytes: what a
    /// node that runs several links at once sizes to the batch it negotiates,
    /// rather than to the largest datagram UDP can carry ([`UDP_RX_CAPACITY`]).
    /// A datagram longer than that is truncated by the stack, which the session
    /// reads as a bad frame.
    pub fn acceptor_with_capacity(socket: S, rx_capacity: usize) -> Self {
        Self::acceptor_in(socket, vec![0u8; rx_capacity], HeapTx::new(0, 0))
    }

    /// [`Self::initiator`] with a receive buffer of `rx_capacity` bytes.
    pub fn initiator_with_capacity(socket: S, peer: SocketAddr, rx_capacity: usize) -> Self {
        Self::initiator_in(socket, peer, vec![0u8; rx_capacity], HeapTx::new(0, 0))
    }
}

impl<S: DatagramSocket, B: AsMut<[u8]>, T: TxStore> UdpDriver<S, B, T> {
    /// An acceptor's link over the receive buffer `rx_buf`, building its frames in `tx`: no peer
    /// until the first `InitSyn` it takes names one.
    pub fn acceptor_in(socket: S, rx_buf: B, tx: T) -> Self {
        Self::with_peer(socket, None, rx_buf, tx)
    }

    /// An initiator's link over the receive buffer `rx_buf`, building its frames in `tx`: replies
    /// and first sends go to `peer`.
    pub fn initiator_in(socket: S, peer: SocketAddr, rx_buf: B, tx: T) -> Self {
        Self::with_peer(socket, Some(peer), rx_buf, tx)
    }

    fn with_peer(socket: S, peer: Option<SocketAddr>, mut rx_buf: B, tx: T) -> Self {
        let rx_len = rx_buf.as_mut().len();
        Self {
            socket,
            binding: match peer {
                Some(peer) => PeerBinding::dialled(peer),
                None => PeerBinding::accepting(),
            },
            endpoints: OnceCell::new(),
            rx_buf: RefCell::new(rx_buf),
            rx_len,
            tx: TxLender::new(tx),
            stash: Cell::new(None),
            kept: Cell::new(None),
            keeping: Cell::new(false),
            rx_error: Cell::new(None),
            idle_wait_ms: SERVICE_WAIT_MS as u32,
            armed_wait_ms: Cell::new(SERVICE_WAIT_MS),
            owner_waits: false,
        }
    }

    /// The same link, waited on by its owner when its socket can be
    /// ([`SessionDatagramLink::readiness`]): its loop then reads what is queued and does not
    /// wait, and its owner waits on the socket with nothing of the session held. A socket that
    /// gives no such wait keeps the link waiting in its loop.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.owner_waits = self.socket.readiness().is_some();
        self
    }

    /// Let this link wait up to `ms` milliseconds for a datagram when its session has nothing due
    /// sooner (see [`SessionDatagramLink::service_within`]). Said by the image, and only when this
    /// link is the one thing its loop waits on: a loop that serves several sessions would not look
    /// at the others' sockets for that long. A value below the tick is the tick.
    #[must_use]
    pub fn with_idle_wait_ms(mut self, ms: u32) -> Self {
        // Half of `c_int`'s range, so that rounding down to a power of two stays inside it.
        self.idle_wait_ms = ms.clamp(SERVICE_WAIT_MS as u32, (c_int::MAX / 2) as u32);
        self
    }

    /// Arm the socket's receive timeout at `ms` if it is not already. `false` when the socket
    /// cannot be armed at that value.
    fn arm(&self, ms: c_int) -> bool {
        if self.armed_wait_ms.get() == ms {
            return true;
        }
        let took = self.socket.set_receive_timeout(ms);
        if took {
            self.armed_wait_ms.set(ms);
        }
        took
    }

    /// Whether the session reads `datagram`, taken from `from`. What the binding does not admit (a
    /// stranger's datagram, another source's `InitSyn`, anything before an accepting link's first
    /// `InitSyn`) is counted ([`Self::foreign`]) and the caller discards it; the socket is this
    /// link's alone, so nothing it discards is anyone else's.
    fn admit(&self, from: SocketAddr, datagram: &[u8]) -> bool {
        self.binding.admit(from, datagram).is_taken()
    }

    /// The next datagram the session reads, in `buf`: the one `service` already read and admitted,
    /// if it did, else the next one the stack has queued that the binding admits. Its length, or
    /// `Ok(None)` when nothing the session reads is queued.
    fn next_admitted(&self, buf: &mut [u8]) -> Result<Option<usize>, S::Error> {
        if let Some(len) = self.stash.take() {
            return Ok(Some(len));
        }
        loop {
            let Some((len, from)) = self.socket.try_recv(buf)? else {
                return Ok(None);
            };
            if self.admit(from, datagram_of(buf, len)) {
                return Ok(Some(len));
            }
        }
    }

    /// The peer every send goes to, once one is known.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.binding.peer()
    }

    /// The datagrams this link has discarded for not being its peer's.
    pub fn foreign(&self) -> ForeignCounts {
        self.binding.foreign()
    }

    /// The most recent receive failure, if the socket has failed.
    pub fn rx_error(&self) -> Option<S::Error> {
        self.rx_error.get()
    }
}

impl<S: DatagramSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static>
    UdpDriver<S, B, T>
{
    /// Wait on the socket for a datagram, for as long as it is armed to wait.
    ///
    /// On a socket whose reads time out, the wait is the read: the datagram is taken into
    /// `rx_buf` in the same call that waited for it and held for the receive that follows, so
    /// a datagram crosses the stack once, as it does for zenoh-pico. Otherwise `poll` waits and
    /// the receive reads.
    fn wait_for_datagram(&self) {
        if !self.socket.times_out() {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        }
        if self.stash.get().is_some() {
            return;
        }
        // The buffer is lent out while a receive callback runs; a wait asked for from inside one
        // (the loop does not) falls back to `poll`, which needs no buffer.
        let Ok(mut buf) = self.rx_buf.try_borrow_mut() else {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        };
        let bytes: &mut [u8] = buf.as_mut();
        match self.socket.recv_waiting(bytes) {
            Ok(Some((len, from))) => {
                if self.admit(from, datagram_of(bytes, len)) {
                    self.stash.set(Some(len));
                }
            }
            Ok(None) => {}
            Err(e) => self.rx_error.set(Some(e)),
        }
    }

    /// The socket's send of `bytes` to the peer, as the outcome the session counts: a send with no
    /// peer yet, or one the stack refuses, is REPORTED (R2371's rule for the lwIP driver), not
    /// swallowed.
    fn send_datagram(&self, bytes: &[u8]) -> LinkSendOutcome {
        let Some(peer) = self.binding.peer() else {
            return LinkSendOutcome::Dropped(LinkDropCause::WriterGone);
        };
        match self.socket.send_to(peer, bytes) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }
}

impl<S: DatagramSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static> BoxedLinkDriver
    for UdpDriver<S, B, T>
{
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
        // UDP is unreliable; the session's reliable channel recovers a drop.
        self.send_datagram(bytes)
    }

    // The session encodes a frame straight into the driver's own storage, and the socket reads it
    // from there: the frame is written once and no buffer is allocated for it. The socket takes a
    // datagram whole and synchronously, so a slot is back at its send; a session that batches
    // holds one open beside the message it encodes next, which is why there can be two. An ask
    // with every slot out is refused, which the lend-only profile counts rather than answering
    // from the heap.
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        // The socket writes the datagram's own headers, so the frame starts at the slot's front.
        self.tx.acquire(0)
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.tx.storage(slot)
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        match self.tx.take(slot, start, len) {
            Some(frame) => self.send_datagram(frame),
            None => LinkSendOutcome::Dropped(LinkDropCause::Oversize),
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    // None until the peer is known: a dialled link's from its construction, an accepting one's
    // from the `InitSyn` that binds it. The peer never changes after, and the socket's own end is
    // its bind's, so the text written at the first ask is the text of every later one.
    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        let peer = self.binding.peer()?;
        Some(
            self.endpoints
                .get_or_init(|| link_endpoints(LinkProto::Udp, self.socket.local(), peer)),
        )
    }

    // A driver whose buffers are declared is bounded by them: the frame it sends is at most the
    // storage it lends, and the batch it advertises is at most the datagram it receives whole, as
    // lwIP's session socket declares its slot (`link_mtu` bounds the session's send budget, so a
    // message past it fragments instead of being encoded into a slot too short for it).
    fn link_mtu(&self) -> usize {
        if self.tx.lends() {
            self.tx.slot_len()
        } else {
            DEFAULT_LINK_MTU
        }
    }

    // The batch it advertises is bounded by its receive buffer whether or not it lends frame
    // storage: a buffer sized below the largest datagram (`IpLinks::with_rx_capacity`) must not
    // invite a peer's batch it would cut short.
    fn link_rx_capacity(&self) -> usize {
        self.rx_len
    }
}

impl<S: DatagramSocket + 'static, B: AsMut<[u8]> + 'static, T: TxStore + 'static>
    SessionDatagramLink for UdpDriver<S, B, T>
{
    fn service(&self) {
        // A link its owner waits on reads what is queued and does not wait here.
        if self.owner_waits {
            return;
        }
        // The loop's thread owes the network stack the CPU while it has nothing to do. It gives
        // it by waiting for the socket, so a datagram is taken the moment it is queued, and a
        // quiet socket costs one millisecond, which is what bounds the loop's timers.
        //
        // A longer wait armed by `service_within` is put back to the tick first: whoever asks for
        // `service` asks for the tick.
        if !self.arm(SERVICE_WAIT_MS) {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        }
        self.wait_for_datagram();
    }

    fn uses_wake_budget(&self) -> bool {
        // A socket that cannot be armed waits the tick whatever the budget says, and an image
        // that has not raised the idle wait asked for the tick.
        S::CAN_SET_RECEIVE_TIMEOUT && self.idle_wait_ms > SERVICE_WAIT_MS as u32
    }

    fn service_within(&self, max_wait_ms: u64) {
        // Something is due now (a deadline, a query left for the application's layer): a wait
        // of the tick would be the whole of what the thing costs. The receive that follows reads
        // what is queued without waiting. A link its owner waits on never waits here.
        if max_wait_ms == 0 || self.owner_waits {
            return;
        }
        // The most this link may wait: what its session has due, and what its image allows. At
        // or below the tick it is the tick, which is every link that has not been given more.
        let want = max_wait_ms.min(u64::from(self.idle_wait_ms));
        if want <= SERVICE_WAIT_MS as u64 || !self.socket.times_out() {
            self.service();
            return;
        }
        // The timeout is armed at the largest power of two not above `want`, so a wait never ends
        // after the deadline it was computed from, and re-arming (a system call) happens only
        // when the deadline moves to another power of two: a link whose deadlines are seconds
        // away arms once, and the approach to a deadline costs one wake per halving, not one per
        // tick.
        let armed = power_of_two_within(want);
        // `idle_wait_ms` is at most half of `c_int`'s range, so the power of two is inside it.
        if !self.arm(armed as c_int) {
            self.service();
            return;
        }
        self.wait_for_datagram();
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        let mut buf = self.rx_buf.borrow_mut();
        let bytes: &mut [u8] = buf.as_mut();
        if let Some(len) = self.kept.take() {
            return Some(RxFrame::new(datagram_of(bytes, len).to_vec()));
        }
        match self.next_admitted(bytes) {
            Ok(Some(len)) => Some(RxFrame::new(datagram_of(bytes, len).to_vec())),
            Ok(None) => None,
            Err(e) => {
                self.rx_error.set(Some(e));
                None
            }
        }
    }

    fn holds_input(&self) -> bool {
        self.stash.get().is_some() || self.kept.get().is_some() || self.socket.holds_datagram()
    }

    // The datagram lies in the link's own receive buffer, which nothing writes until the link
    // reads the next one: a datagram kept is lent from where it lies, and costs no copy.
    fn keeps_input(&self) -> bool {
        true
    }

    fn keep(&self) {
        self.keeping.set(true);
    }

    // The receive buffer is written by a receive (`recv_with`, `try_recv`) and by the wait of a
    // service (`wait_for_datagram`) alone, so what a receive lent lies there until the link is next
    // asked for either.
    fn lends_until_next_receive(&self) -> bool {
        true
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        if self.owner_waits {
            self.socket.readiness()
        } else {
            None
        }
    }

    // The datagram is lent out of the link's own receive buffer, which the
    // stack has just written: no heap copy of it. The buffer stays borrowed
    // while `f` runs; the session's sends go through the socket, not through
    // it, and a receive from inside `f` would be refused by the `RefCell`.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        let mut buf = self.rx_buf.borrow_mut();
        let bytes: &mut [u8] = buf.as_mut();
        let len = match self.kept.take() {
            Some(len) => len,
            None => match self.next_admitted(bytes) {
                Ok(Some(len)) => len,
                Ok(None) => return false,
                Err(e) => {
                    self.rx_error.set(Some(e));
                    return false;
                }
            },
        };
        self.keeping.set(false);
        f(datagram_of(bytes, len));
        if self.keeping.replace(false) {
            self.kept.set(Some(len));
        }
        true
    }
}

/// How many datagrams one peer of a listener may have waiting for its link to read them: past it
/// a datagram is dropped and counted ([`UdpPort::overflows`]), as a socket whose receive buffer
/// is full drops one, so a peer that sends faster than its session reads cannot take the
/// listener's memory.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub const PORT_PEER_BACKLOG: usize = 64;

/// The one socket a `udp/` listener is bound to, shared by the link of every peer it took.
///
/// UDP has no connections: every peer that opens a session sends its `InitSyn` to the one port,
/// so the node reads them all from one socket and tells the peers apart by the address each
/// datagram came from, as upstream's UDP listener keeps a link per source address
/// (`io/zenoh-links/zenoh-link-udp/src/unicast.rs` @ `A new peers has sent data to this socket`)
/// and as the lwIP listener of the slot profile does (`wz_session_lwip::listener`). Whoever reads
/// first (the listener looking for a new peer, or any peer's link) takes everything the socket
/// holds and sorts it: a datagram from a peer that has a link waits for that link
/// ([`PortPeer`]); an `InitSyn` from a source with none opens one, which the listener hands out
/// ([`UdpPort::take_fresh`]); anything else is a stray, dropped and counted, which costs no link.
/// A link that is let go of frees its source, whose next `InitSyn` opens a new link.
///
/// Every link of the port is driven by the one thread that drives the session, so the port is
/// shared by `Rc` and its tables are cells.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct UdpPort<S: DatagramSocket> {
    socket: S,
    /// The peers that have a link, each with the datagrams taken for it and not yet read.
    peers: RefCell<Vec<PeerInbox>>,
    /// The sources whose `InitSyn` opened a link the listener has not handed out yet.
    fresh: RefCell<VecDeque<SocketAddr>>,
    /// What one datagram is read into before it is sorted.
    buf: RefCell<Vec<u8>>,
    strays: Cell<u32>,
    overflows: Cell<u32>,
}

/// One peer of a [`UdpPort`] and what was taken for it.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
struct PeerInbox {
    peer: SocketAddr,
    datagrams: VecDeque<Vec<u8>>,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket> UdpPort<S> {
    /// The port of `socket`, which reads each datagram into `rx_capacity` bytes before it sorts
    /// it: the largest datagram a link of the port receives whole.
    pub fn new(socket: S, rx_capacity: usize) -> Self {
        Self {
            socket,
            peers: RefCell::new(Vec::new()),
            fresh: RefCell::new(VecDeque::new()),
            buf: RefCell::new(vec![0u8; rx_capacity]),
            strays: Cell::new(0),
            overflows: Cell::new(0),
        }
    }

    /// The address and port the socket is bound to.
    pub fn local(&self) -> SocketAddr {
        self.socket.local()
    }

    /// A wait for the socket that another thread can make, when the platform gives one.
    pub fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        self.socket.readiness()
    }

    /// Datagrams from a source with no link that were not an `InitSyn`.
    pub fn strays(&self) -> u32 {
        self.strays.get()
    }

    /// Datagrams dropped because their peer had [`PORT_PEER_BACKLOG`] waiting already.
    pub fn overflows(&self) -> u32 {
        self.overflows.get()
    }

    /// The share of the port of the next source whose `InitSyn` opened a link, after the socket
    /// was read: what a listener takes. `Ok(None)` when no new source waits; the socket's error
    /// when the read failed and no new source waits either.
    pub fn take_fresh(port: &Rc<Self>) -> Result<Option<PortPeer<S>>, S::Error> {
        let pumped = port.pump();
        let next = port.fresh.borrow_mut().pop_front();
        match next {
            Some(peer) => Ok(Some(PortPeer {
                port: Rc::clone(port),
                peer,
            })),
            None => pumped.map(|()| None),
        }
    }

    /// Take everything the socket holds and sort it. A read that is already sorting (a link read
    /// from inside another's receive) leaves the socket to it.
    fn pump(&self) -> Result<(), S::Error> {
        let Ok(mut buf) = self.buf.try_borrow_mut() else {
            return Ok(());
        };
        while let Some((len, from)) = self.socket.try_recv(&mut buf)? {
            self.sort(from, datagram_of(&buf, len));
        }
        Ok(())
    }

    /// Hand `datagram`, taken from `from`, to the link of its peer, open a link for the source of
    /// an `InitSyn` that has none, and drop and count anything else.
    fn sort(&self, from: SocketAddr, datagram: &[u8]) {
        let mut peers = self.peers.borrow_mut();
        if let Some(inbox) = peers.iter_mut().find(|inbox| inbox.peer == from) {
            if inbox.datagrams.len() < PORT_PEER_BACKLOG {
                inbox.datagrams.push_back(datagram.to_vec());
            } else {
                self.overflows.set(self.overflows.get().saturating_add(1));
            }
            return;
        }
        if !is_init_syn(datagram) {
            self.strays.set(self.strays.get().saturating_add(1));
            return;
        }
        let mut datagrams = VecDeque::new();
        datagrams.push_back(datagram.to_vec());
        peers.push(PeerInbox {
            peer: from,
            datagrams,
        });
        self.fresh.borrow_mut().push_back(from);
    }

    /// The next datagram taken for `peer`.
    fn take_for(&self, peer: SocketAddr) -> Option<Vec<u8>> {
        self.peers
            .borrow_mut()
            .iter_mut()
            .find(|inbox| inbox.peer == peer)
            .and_then(|inbox| inbox.datagrams.pop_front())
    }

    /// Whether a datagram taken for `peer` waits to be read.
    fn holds_for(&self, peer: SocketAddr) -> bool {
        self.peers
            .borrow()
            .iter()
            .any(|inbox| inbox.peer == peer && !inbox.datagrams.is_empty())
    }

    /// `peer`'s link is gone: what was taken for it goes, and its next `InitSyn` opens a link.
    fn forget(&self, peer: SocketAddr) {
        self.peers.borrow_mut().retain(|inbox| inbox.peer != peer);
        self.fresh.borrow_mut().retain(|fresh| *fresh != peer);
    }
}

/// Why a [`PortPeer`] failed: the port's socket said so, or the share was asked to bind, which
/// only a port does.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPeerError<E> {
    /// The port's socket failed.
    Socket(E),
    /// A share of a port is made by its listener and never bound.
    Unbound,
}

/// One peer's share of a [`UdpPort`]: the socket of the link a listener took for that peer. It
/// reads the datagrams that peer sent, whoever took them off the socket, and sends through the
/// port's socket; dropping it frees the peer's source on the port.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct PortPeer<S: DatagramSocket> {
    port: Rc<UdpPort<S>>,
    peer: SocketAddr,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket> PortPeer<S> {
    /// The peer this share reads and sends for.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket> Drop for PortPeer<S> {
    fn drop(&mut self) {
        self.port.forget(self.peer);
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket> DatagramSocket for PortPeer<S> {
    type Error = PortPeerError<S::Error>;

    const CARRIED: bool = S::CARRIED;

    const IPV6: bool = S::IPV6;

    fn bind(_at: SocketAddr) -> Result<Self, Self::Error> {
        Err(PortPeerError::Unbound)
    }

    fn local(&self) -> SocketAddr {
        self.port.local()
    }

    fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), Self::Error> {
        self.port
            .socket
            .send_to(to, bytes)
            .map_err(PortPeerError::Socket)
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        if !self.holds_datagram() {
            self.port.socket.wait_readable(timeout_ms);
        }
    }

    // A blocking read would take another peer's datagram as well as this one's: the link waits
    // and then reads what was sorted for it.
    fn times_out(&self) -> bool {
        false
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        self.try_recv(buf)
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        let pumped = self.port.pump();
        if let Some(datagram) = self.port.take_for(self.peer) {
            // Cut to the buffer, as the stack cuts a datagram longer than the read.
            let len = datagram.len().min(buf.len());
            if let (Some(to), Some(from)) = (buf.get_mut(..len), datagram.get(..len)) {
                to.copy_from_slice(from);
            }
            return Ok(Some((len, self.peer)));
        }
        pumped.map(|()| None).map_err(PortPeerError::Socket)
    }

    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        self.port.readiness()
    }

    fn holds_datagram(&self) -> bool {
        self.port.holds_for(self.peer)
    }
}

/// A platform's sockets as a stack of the slot profile's session host: the driver in the
/// session's slot is a [`FixedUdpDriver`] over the socket `S`, and the drive loop pumps it through
/// the driver itself ([`DriverPump`]), because the platform has no input path of its own for the
/// loop to advance (the kernel's threads, or the host's, run the network stack). Each session's
/// driver claims its receive buffer (as long as the batch the session advertises) and the buffer
/// its frames are encoded into (the largest frame it sends) from two tables the image declares, so
/// a dial moves a few words and no bytes, and the lengths are the tables' and not the type's.
///
/// Nothing is kept for a listener (`Lane` is `()`): the client node dials, and a node that accepts
/// would bring a lane of its own. The sockets are the platform's descriptors, so no pool of them
/// is declared here; a descriptor the platform cannot give is the dial's
/// [`LinkOpenError::Exhausted`], and the session host's tables bound how many are open at once.
#[cfg(feature = "session-slot")]
pub struct UdpStack<S> {
    local: IpAddr,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    /// What each driver this stack opens is allowed to wait for a datagram when its session has
    /// nothing due sooner ([`UdpDriver::with_idle_wait_ms`]).
    idle_wait_ms: u32,
    socket: PhantomData<fn() -> S>,
}

// Not derived: a derive would ask `S: Clone`, and the stack holds no socket, only the knowledge of
// which type opens them.
#[cfg(feature = "session-slot")]
impl<S> Clone for UdpStack<S> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "session-slot")]
impl<S> Copy for UdpStack<S> {}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> UdpStack<S> {
    /// The stack of a node whose own address is `local`, as its interface holds it, whose links
    /// take their receive buffers from `rx` and their frame buffers from `tx`. A dial to a peer of
    /// the other family binds the unspecified address of the peer's ([`dial_bind`]).
    pub const fn new(
        local: IpAddr,
        rx: &'static dyn ByteSource,
        tx: &'static dyn ByteSource,
    ) -> Self {
        Self {
            local,
            rx,
            tx,
            idle_wait_ms: SERVICE_WAIT_MS as u32,
            socket: PhantomData,
        }
    }

    /// Let the drivers of this stack wait up to `ms` milliseconds for a datagram when their
    /// session has nothing due sooner. The image says so when it has ONE session and nothing else
    /// its loop waits on: with several, a link that blocks for long would leave the others'
    /// sockets unread for as long. The default is the tick, which is what every image had.
    #[must_use]
    pub const fn with_idle_wait_ms(mut self, ms: u32) -> Self {
        self.idle_wait_ms = ms;
        self
    }

    /// The link of a dial to `peer`: a socket on a port the stack picks, with replies and first
    /// sends going to `peer`. What the session host's `dial` is given to open its socket. A table
    /// with no buffer free, like a platform with no descriptor, is [`LinkOpenError::Exhausted`],
    /// and whatever was claimed before the refusal goes back with it.
    pub fn bind_initiator(&self, peer: SocketAddr) -> Result<FixedUdpDriver<S>, LinkOpenError> {
        let rx = self.rx.claim().ok_or(LinkOpenError::Exhausted)?;
        let tx = self.tx.claim().ok_or(LinkOpenError::Exhausted)?;
        let socket = S::bind(dial_bind(self.local, peer)).map_err(bind_refused::<S>)?;
        Ok(UdpDriver::initiator_in(socket, peer, rx, tx).with_idle_wait_ms(self.idle_wait_ms))
    }
}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> Bind<FixedUdpDriver<S>> for UdpStack<S> {
    const IPV6: bool = S::IPV6;

    fn bind(&mut self, to: Locator) -> Result<FixedUdpDriver<S>, LinkOpenError> {
        match to.proto {
            LinkProto::Udp => self.bind_initiator(to.at),
            // A stack of datagram sockets has no stream to give; one that has both is
            // `ip_stack`'s `IpStack`.
            LinkProto::Tcp | LinkProto::Tls => Err(LinkOpenError::Unsupported),
        }
    }
}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> SlotStack for UdpStack<S> {
    type Driver = FixedUdpDriver<S>;
    type Pump = DriverPump<FixedUdpDriver<S>>;
    type Lane = ();

    fn pump(
        &self,
        driver: wz_session_core::session_slot::SlotDriver<FixedUdpDriver<S>>,
        _lane: Option<()>,
    ) -> Self::Pump {
        DriverPump(driver)
    }
}

/// The first `len` bytes of `buf`, as a socket reports a datagram it read into it: a length past
/// the buffer reads as the whole buffer, as the stack cuts a datagram longer than the read.
fn datagram_of(buf: &[u8], len: usize) -> &[u8] {
    buf.get(..len).unwrap_or(buf)
}

/// The largest power of two not above `want`, and `1` for `0`: a wait armed at it never ends
/// after the deadline it was computed from.
fn power_of_two_within(want: u64) -> u64 {
    want.checked_ilog2().map_or(1, |exp| 1 << exp)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// A datagram is the bytes the socket reported, cut to the buffer it was read into.
    #[test]
    fn a_datagram_is_cut_to_the_buffer_it_was_read_into() {
        assert_eq!(datagram_of(&[1, 2, 3], 2), &[1, 2][..]);
        assert_eq!(datagram_of(&[1, 2, 3], 3), &[1, 2, 3][..]);
        assert_eq!(datagram_of(&[1, 2, 3], 5), &[1, 2, 3][..]);
    }

    /// A wait is armed at the largest power of two not above it, and at `1` for none.
    #[test]
    fn a_wait_is_armed_at_the_largest_power_of_two_within_it() {
        assert_eq!(power_of_two_within(0), 1);
        assert_eq!(power_of_two_within(1), 1);
        assert_eq!(power_of_two_within(5), 4);
        assert_eq!(power_of_two_within(1024), 1024);
        assert_eq!(power_of_two_within(u64::MAX), 1 << 63);
    }

    /// The text a link names its ends by is zenoh's locator, the `Display` of the address behind
    /// the scheme, on either family; the longest IPv6 one still fits the default bound.
    #[test]
    fn a_locator_is_what_zenoh_prints_for_it() {
        use core::net::SocketAddrV6;
        for at in [
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::from(([10, 0, 0, 1], 7447)),
            SocketAddr::from(([255, 255, 255, 255], 65535)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)),
            SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 7446)),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                ),
                65535,
                0,
                u32::MAX,
            )),
        ] {
            for proto in [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls] {
                let locator = Locator { proto, at };
                let printed = std::format!("{}/{at}", proto.scheme());
                assert_eq!(locator.text().finish(), Ok(printed.as_str()));
                assert_eq!(std::format!("{locator}"), printed);
            }
        }
        let ends = link_endpoints(
            LinkProto::Udp,
            SocketAddr::from((Ipv6Addr::LOCALHOST, 4000)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)),
        );
        assert_eq!(ends.src.as_str(), "udp/[::1]:4000");
        assert_eq!(ends.dst.as_str(), "udp/[::1]:7447");
    }

    /// The floor the locator bound is held to (at compile time, beside [`Locator::text`]) is the
    /// text of the widest IPv4 end, and the longest IP locator is the widest IPv6 end with a
    /// scope, for every scheme; so every IPv4 end is named whole.
    #[test]
    fn the_locator_floor_is_the_widest_ipv4_end_and_every_ipv4_end_fits() {
        use crate::session_drive::{LONGEST_IPV4_LOCATOR_LEN, LONGEST_IP_LOCATOR_LEN};
        use core::net::SocketAddrV6;
        let widest_v4 = SocketAddr::from(([255, 255, 255, 255], 65535));
        let widest_v6 = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            65535,
            0,
            u32::MAX,
        ));
        for proto in [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls] {
            let v4 = std::format!(
                "{}",
                Locator {
                    proto,
                    at: widest_v4
                }
            );
            let v6 = std::format!(
                "{}",
                Locator {
                    proto,
                    at: widest_v6
                }
            );
            assert_eq!(v4.len(), LONGEST_IPV4_LOCATOR_LEN, "{v4}");
            assert_eq!(v6.len(), LONGEST_IP_LOCATOR_LEN, "{v6}");
            assert_eq!(
                Locator {
                    proto,
                    at: widest_v4
                }
                .text()
                .finish(),
                Ok(v4.as_str())
            );
        }
        let ends = link_endpoints(LinkProto::Udp, widest_v4, widest_v4);
        assert_eq!(ends.dst.as_str(), "udp/255.255.255.255:65535");
    }

    /// A dial binds the node's own address when the peer is of its family, and the unspecified
    /// address of the peer's family when it is not, on a port the stack picks either way.
    #[test]
    fn a_dial_binds_the_nodes_address_of_the_peers_family_or_the_unspecified_one() {
        let v4_node = IpAddr::from([10, 0, 0, 2]);
        let v6_node = IpAddr::from(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2));
        let v4_peer = SocketAddr::from(([10, 0, 0, 1], 7447));
        let v6_peer = SocketAddr::from((Ipv6Addr::LOCALHOST, 7447));
        assert_eq!(dial_bind(v4_node, v4_peer), SocketAddr::new(v4_node, 0));
        assert_eq!(dial_bind(v6_node, v6_peer), SocketAddr::new(v6_node, 0));
        assert_eq!(
            dial_bind(v4_node, v6_peer),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        );
        assert_eq!(
            dial_bind(v6_node, v4_peer),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        );
    }

    /// A datagram the test queues for the driver to receive: its bytes and its source.
    type Datagram = (Vec<u8>, SocketAddr);
    /// A datagram the driver sent: where it went and its bytes.
    type Sent = (SocketAddr, Vec<u8>);

    /// A socket that is two queues: what the test queues for the driver to receive, and what the
    /// driver sent. The datagram a `recv_waiting` takes is the same one `try_recv` would, so the
    /// driver's two receive paths are told apart by which method was called.
    #[derive(Default)]
    struct Loop {
        inbound: core::cell::RefCell<VecDeque<Datagram>>,
        sent: core::cell::RefCell<Vec<Sent>>,
        waits: Cell<u32>,
        waiting_reads: Cell<u32>,
        timeouts: bool,
        /// Whether `set_receive_timeout` takes a value, and the values it was asked to take.
        can_arm: bool,
        arms: core::cell::RefCell<Vec<c_int>>,
        /// The address the socket names as its own; `None` is [`LOCAL`].
        local: Option<SocketAddr>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Refused;

    impl Loop {
        fn take(&self, buf: &mut [u8]) -> Option<Received> {
            let (bytes, from) = self.inbound.borrow_mut().pop_front()?;
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            Some((n, from))
        }
    }

    impl DatagramSocket for Loop {
        type Error = Refused;

        fn bind(_at: SocketAddr) -> Result<Self, Refused> {
            Ok(Loop::default())
        }

        fn local(&self) -> SocketAddr {
            self.local.unwrap_or(LOCAL)
        }

        fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), Refused> {
            self.sent.borrow_mut().push((to, bytes.to_vec()));
            Ok(())
        }

        fn wait_readable(&self, _timeout_ms: c_int) {
            self.waits.set(self.waits.get() + 1);
        }

        fn times_out(&self) -> bool {
            self.timeouts
        }

        const CAN_SET_RECEIVE_TIMEOUT: bool = true;

        fn set_receive_timeout(&self, ms: c_int) -> bool {
            self.arms.borrow_mut().push(ms);
            self.can_arm
        }

        fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, Refused> {
            self.waiting_reads.set(self.waiting_reads.get() + 1);
            Ok(self.take(buf))
        }

        fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, Refused> {
            Ok(self.take(buf))
        }
    }

    const fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    /// The address the test socket names as its own.
    const LOCAL: SocketAddr = v4(10, 0, 0, 2, 4000);

    const PEER: SocketAddr = v4(10, 0, 0, 1, 7447);

    /// Another end than [`PEER`], on the peer's port.
    const STRANGER: SocketAddr = v4(10, 0, 0, 9, 7447);

    /// An `InitSyn` header and a byte of body: what binds an accepting link. Only its first byte
    /// is read, by the binding.
    const SYN: &[u8] = &[0x01, 0x09];

    fn queued(socket: &Loop, bytes: &[u8]) {
        queued_from(socket, bytes, Sender::Peer);
    }

    /// Who a datagram the test queues comes from.
    enum Sender {
        Peer,
        Stranger,
    }

    fn queued_from(socket: &Loop, bytes: &[u8], from: Sender) {
        let from = match from {
            Sender::Peer => PEER,
            Sender::Stranger => STRANGER,
        };
        queued_at(socket, bytes, from);
    }

    fn queued_at(socket: &Loop, bytes: &[u8], from: SocketAddr) {
        socket
            .inbound
            .borrow_mut()
            .push_back((bytes.to_vec(), from));
    }

    /// The driver the tests of the wait and of the link's behaviour are made over, a link that
    /// dialled [`PEER`]: the heap profile's, with two outbound slots...
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn driver(socket: Loop) -> UdpDriver<Loop, Vec<u8>, HeapTx> {
        UdpDriver::initiator_with_buffers(socket, PEER, 64, HeapTx::new(2, 32))
    }

    /// ...or the slot profile's, whose two buffers are claimed from tables the test declares
    /// (more cells than tests run at once) and go back when the driver is dropped.
    #[cfg(feature = "session-slot")]
    fn driver(socket: Loop) -> UdpDriver<Loop, ByteBuf, ByteBuf> {
        let (rx, tx) = slot_buffers();
        UdpDriver::initiator_in(socket, PEER, rx, tx)
    }

    /// An accepting link, of the heap profile...
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn acceptor(socket: Loop) -> UdpDriver<Loop, Vec<u8>, HeapTx> {
        UdpDriver::acceptor_with_buffers(socket, 64, HeapTx::new(2, 32))
    }

    /// ...or of the slot profile.
    #[cfg(feature = "session-slot")]
    fn acceptor(socket: Loop) -> UdpDriver<Loop, ByteBuf, ByteBuf> {
        let (rx, tx) = slot_buffers();
        UdpDriver::acceptor_in(socket, rx, tx)
    }

    #[cfg(feature = "session-slot")]
    fn slot_buffers() -> (ByteBuf, ByteBuf) {
        use wz_session_core::byte_cells::ByteCells;
        static RX: ByteCells<64, 64> = ByteCells::new();
        static TX: ByteCells<32, 64> = ByteCells::new();
        (
            RX.claim().expect("a receive buffer"),
            TX.claim().expect("a frame buffer"),
        )
    }

    /// What `recv_with` hands the session, or `None` when it hands nothing.
    fn received<L: SessionDatagramLink>(link: &L) -> Option<Vec<u8>> {
        let mut got = None;
        link.recv_with(&mut |bytes| got = Some(bytes.to_vec()));
        got
    }

    #[test]
    fn the_test_syn_is_an_init_syn() {
        assert!(wz_session_core::datagram_peer::is_init_syn(SYN));
    }

    #[test]
    fn an_acceptor_is_bound_by_the_first_init_syn_and_answers_its_source() {
        let link = acceptor(Loop::default());
        assert_eq!(link.peer(), None);
        assert!(link.link_endpoints().is_none());
        assert_eq!(
            link.send_blocking(b"early", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
            "a send with no peer is reported, not swallowed"
        );

        // Before a session opens, what opens none is not the session's and binds nothing.
        queued_from(&link.socket, b"hello", Sender::Stranger);
        assert_eq!(received(&link), None);
        assert_eq!(link.peer(), None);
        assert!(link.link_endpoints().is_none());

        queued(&link.socket, SYN);
        assert_eq!(received(&link).as_deref(), Some(SYN));
        assert_eq!(link.peer(), Some(PEER));
        let ends = link
            .link_endpoints()
            .expect("endpoints once the peer is known");
        assert_eq!(ends.src.as_str(), "udp/10.0.0.2:4000");
        assert_eq!(ends.dst.as_str(), "udp/10.0.0.1:7447");

        assert_eq!(
            link.send_blocking(b"reply", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            link.socket.sent.borrow().as_slice(),
            &[(PEER, b"reply".to_vec())]
        );
        assert_eq!(
            link.foreign(),
            ForeignCounts {
                strays: 1,
                refused: 0
            }
        );
    }

    /// The same binding over IPv6: an accepting link is bound by the first `InitSyn` from an IPv6
    /// end, names both ends in zenoh's bracketed text, answers that end, and passes over an IPv6
    /// stranger on the same port as it passes over an IPv4 one.
    #[test]
    fn an_ipv6_acceptor_is_bound_by_its_first_init_syn_and_names_its_ends_in_brackets() {
        let peer = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 7447));
        let stranger = SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9), 7447));
        let link = acceptor(Loop {
            local: Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 4000))),
            ..Loop::default()
        });
        queued_at(&link.socket, SYN, peer);
        assert_eq!(received(&link).as_deref(), Some(SYN));
        assert_eq!(link.peer(), Some(peer));
        let ends = link
            .link_endpoints()
            .expect("endpoints once the peer is known");
        assert_eq!(ends.src.as_str(), "udp/[::1]:4000");
        assert_eq!(ends.dst.as_str(), "udp/[fd00::1]:7447");

        queued_at(&link.socket, b"stray", stranger);
        queued_at(&link.socket, b"peer", peer);
        assert_eq!(received(&link).as_deref(), Some(&b"peer"[..]));
        assert_eq!(
            link.send_blocking(b"reply", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            link.socket.sent.borrow().as_slice(),
            &[(peer, b"reply".to_vec())]
        );
        assert_eq!(link.foreign().strays, 1);
    }

    /// The defect this rule exists for: one datagram from another address used to point the
    /// session's replies and keep-alives at that address until the peer next spoke. Now the
    /// session never sees it, on either receive, and every send still goes to the peer.
    #[test]
    fn a_strangers_datagram_reaches_no_session_and_moves_no_reply() {
        for accepted in [false, true] {
            let link = if accepted {
                let link = acceptor(Loop::default());
                queued(&link.socket, SYN);
                assert_eq!(received(&link).as_deref(), Some(SYN));
                link
            } else {
                driver(Loop::default())
            };
            queued_from(&link.socket, b"stray", Sender::Stranger);
            queued_from(&link.socket, SYN, Sender::Stranger);
            queued(&link.socket, b"peer");
            assert_eq!(
                received(&link).as_deref(),
                Some(&b"peer"[..]),
                "what the stranger sent is passed over, not handed to the session"
            );
            #[cfg(feature = "alloc")]
            {
                queued_from(&link.socket, b"stray", Sender::Stranger);
                assert!(link.try_recv().is_none(), "the copying receive too");
            }
            assert_eq!(link.peer(), Some(PEER));
            assert_eq!(
                link.send_blocking(b"keep-alive", Reliability::Reliable),
                LinkSendOutcome::Sent
            );
            assert_eq!(
                link.socket.sent.borrow().last().map(|sent| sent.0),
                Some(PEER),
                "the reply goes to the peer, accepted={accepted}"
            );
            let strays = if cfg!(feature = "alloc") { 2 } else { 1 };
            assert_eq!(
                link.foreign(),
                ForeignCounts { strays, refused: 1 },
                "accepted={accepted}"
            );
        }
    }

    /// A datagram the wait already took into the buffer is judged as one the receive takes.
    #[test]
    fn a_strangers_datagram_the_wait_took_is_passed_over_too() {
        let socket = Loop {
            timeouts: true,
            ..Loop::default()
        };
        let link = driver(socket);
        queued_from(&link.socket, b"stray", Sender::Stranger);
        link.service();
        assert_eq!(link.socket.waiting_reads.get(), 1, "the wait read it");
        assert_eq!(received(&link), None);
        assert_eq!(link.foreign().strays, 1);
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn an_initiator_sends_to_its_peer_before_it_has_heard_from_it() {
        let link = UdpDriver::initiator_with_capacity(Loop::default(), PEER, 64);
        assert_eq!(link.peer(), Some(PEER));
        assert_eq!(
            link.send_blocking(b"init", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn the_session_encodes_into_a_lent_slot_and_the_slot_returns_at_the_send() {
        let link = UdpDriver::initiator_with_buffers(Loop::default(), PEER, 64, HeapTx::new(2, 32));
        assert_eq!(
            link.link_mtu(),
            32,
            "the bound is the slot the driver lends"
        );
        assert_eq!(link.link_rx_capacity(), 64);

        let first = link
            .tx_slot_acquire(10, Priority::Data)
            .expect("a first slot");
        let second = link
            .tx_slot_acquire(10, Priority::Data)
            .expect("a second slot");
        assert_ne!(first.slot.0, second.slot.0);
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_none(),
            "every slot out is a refusal"
        );

        let (base, capacity) = link.tx_slot_storage(first.slot);
        assert_eq!(capacity, 32);
        // SAFETY: the slot was granted to this test alone and is 32 bytes long.
        unsafe { core::slice::from_raw_parts_mut(base, 3) }.copy_from_slice(b"abc");
        assert_eq!(
            link.tx_slot_send(first.slot, 0, 3, Reliability::Reliable, Priority::Data),
            LinkSendOutcome::Sent
        );
        assert_eq!(link.socket.sent.borrow()[0].1, b"abc");
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_some(),
            "the slot is back once it is sent"
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_send_past_the_slot_is_dropped_oversize_and_gives_the_slot_back() {
        let link = UdpDriver::initiator_with_buffers(Loop::default(), PEER, 64, HeapTx::new(1, 8));
        let grant = link.tx_slot_acquire(4, Priority::Data).expect("a slot");
        assert_eq!(
            link.tx_slot_send(grant.slot, 4, 5, Reliability::Reliable, Priority::Data),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        assert!(link.socket.sent.borrow().is_empty());
        assert!(link.tx_slot_acquire(4, Priority::Data).is_some());
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_driver_with_no_storage_lends_nothing_and_receives_what_its_buffer_holds() {
        let link = UdpDriver::acceptor_with_capacity(Loop::default(), 64);
        assert!(link.tx_slot_acquire(10, Priority::Data).is_none());
        assert_eq!(link.link_mtu(), DEFAULT_LINK_MTU);
        assert_eq!(
            link.link_rx_capacity(),
            64,
            "the advertised batch is held to the receive buffer, lent storage or not"
        );
    }

    #[test]
    fn a_socket_whose_reads_time_out_is_read_once_by_the_wait_and_not_again_by_the_receive() {
        let socket = Loop {
            timeouts: true,
            ..Loop::default()
        };
        let link = driver(socket);
        queued(&link.socket, b"one");
        link.service();
        assert_eq!(link.socket.waiting_reads.get(), 1);
        assert_eq!(link.socket.waits.get(), 0, "the read is the wait");

        let mut got = Vec::new();
        assert!(link.recv_with(&mut |bytes| got.extend_from_slice(bytes)));
        assert_eq!(got, b"one");
        assert!(
            link.socket.inbound.borrow().is_empty(),
            "one datagram, taken once"
        );

        // A held datagram is not read over by the next pass.
        queued(&link.socket, b"two");
        link.service();
        link.service();
        assert_eq!(link.socket.waiting_reads.get(), 2);
    }

    #[test]
    fn a_socket_with_no_timeout_waits_and_the_receive_reads() {
        let link = driver(Loop::default());
        queued(&link.socket, b"one");
        link.service();
        assert_eq!(link.socket.waits.get(), 1);
        assert_eq!(link.socket.waiting_reads.get(), 0);
        let mut got = Vec::new();
        assert!(link.recv_with(&mut |bytes| got.extend_from_slice(bytes)));
        assert_eq!(got, b"one");
        assert!(!link.recv_with(&mut |_| unreachable!("nothing is queued")));
    }

    fn arming_socket() -> Loop {
        Loop {
            timeouts: true,
            can_arm: true,
            ..Loop::default()
        }
    }

    #[test]
    fn a_link_waits_in_the_largest_power_of_two_not_above_what_is_due_and_arms_once_per_step() {
        let link = driver(arming_socket()).with_idle_wait_ms(1000);
        for (due, armed) in [
            (5000u64, 512),
            (1000, 512),
            (700, 512),
            (511, 256),
            (100, 64),
            (3, 2),
        ] {
            link.service_within(due);
            assert_eq!(link.armed_wait_ms.get(), armed, "due in {due} ms");
        }
        // A deadline at the tick puts the tick back.
        link.service_within(1);
        assert_eq!(link.armed_wait_ms.get(), SERVICE_WAIT_MS);
        // Each power of two was asked of the socket once, in the order the deadline came in: 700
        // and 1000 found 512 already armed.
        assert_eq!(*link.socket.arms.borrow(), [512, 256, 64, 2, 1]);
        assert_eq!(
            link.socket.waiting_reads.get(),
            7,
            "every pass waited once, in the read"
        );
    }

    #[test]
    fn a_wait_never_ends_after_the_deadline_it_came_from_and_is_more_than_half_of_it() {
        for due in 2..=1000u64 {
            let link = driver(arming_socket()).with_idle_wait_ms(1000);
            link.service_within(due);
            let armed = link.armed_wait_ms.get() as u64;
            assert!(
                armed <= due,
                "armed {armed} ms for a deadline {due} ms away"
            );
            assert!(
                armed * 2 > due,
                "armed {armed} ms for a deadline {due} ms away"
            );
        }
    }

    #[test]
    fn the_image_caps_the_wait_and_without_its_leave_a_link_waits_the_tick() {
        let capped = driver(arming_socket()).with_idle_wait_ms(100);
        capped.service_within(60_000);
        assert_eq!(capped.armed_wait_ms.get(), 64, "capped at 100 ms, so 64");

        // The default is the tick: a deadline an hour away does not make this link wait.
        let default = driver(arming_socket());
        default.service_within(3_600_000);
        assert!(default.socket.arms.borrow().is_empty(), "no re-arming");
        assert_eq!(default.armed_wait_ms.get(), SERVICE_WAIT_MS);
        assert_eq!(default.socket.waiting_reads.get(), 1, "one tick's read");
    }

    #[test]
    fn a_budget_of_nothing_waits_for_nothing_and_the_receive_reads_what_is_queued() {
        let link = driver(arming_socket()).with_idle_wait_ms(1000);
        queued(&link.socket, b"queued");
        link.service_within(0);
        assert_eq!(link.socket.waiting_reads.get(), 0, "no read to wait on");
        assert_eq!(link.socket.waits.get(), 0, "no poll either");
        assert!(link.socket.arms.borrow().is_empty(), "and nothing armed");

        let mut got = Vec::new();
        assert!(link.recv_with(&mut |bytes| got.extend_from_slice(bytes)));
        assert_eq!(got, b"queued", "what was queued is still read");
        // The control: a budget of one tick or more does wait.
        link.service_within(5);
        assert_eq!(link.socket.waiting_reads.get(), 1);
    }

    #[test]
    fn a_service_asked_for_after_a_long_wait_puts_the_tick_back() {
        let link = driver(arming_socket()).with_idle_wait_ms(1000);
        link.service_within(1000);
        assert_eq!(link.armed_wait_ms.get(), 512);
        link.service();
        assert_eq!(link.armed_wait_ms.get(), SERVICE_WAIT_MS);
        assert_eq!(*link.socket.arms.borrow(), [512, 1]);
    }

    #[test]
    fn a_socket_that_cannot_be_armed_is_waited_on_for_the_tick() {
        let socket = Loop {
            timeouts: true,
            can_arm: false,
            ..Loop::default()
        };
        let link = driver(socket).with_idle_wait_ms(1000);
        link.service_within(1000);
        assert_eq!(
            link.armed_wait_ms.get(),
            SERVICE_WAIT_MS,
            "nothing was armed"
        );
        assert_eq!(link.socket.waiting_reads.get(), 1, "the tick's read, once");
    }

    #[test]
    fn a_socket_with_no_read_timeout_is_polled_for_the_tick_whatever_is_due() {
        let link = driver(Loop::default()).with_idle_wait_ms(1000);
        link.service_within(1000);
        assert_eq!(link.socket.waits.get(), 1);
        assert!(link.socket.arms.borrow().is_empty());
    }

    #[test]
    fn a_link_asks_the_loop_for_the_deadline_only_when_its_image_let_it_wait_longer() {
        assert!(
            !driver(arming_socket()).uses_wake_budget(),
            "the default is the tick"
        );
        assert!(!driver(arming_socket())
            .with_idle_wait_ms(1)
            .uses_wake_budget());
        assert!(driver(arming_socket())
            .with_idle_wait_ms(1000)
            .uses_wake_budget());
    }

    #[test]
    fn a_wait_asked_for_from_inside_a_receive_falls_back_to_the_socket_wait() {
        let socket = Loop {
            timeouts: true,
            ..Loop::default()
        };
        let link = driver(socket);
        queued(&link.socket, b"one");
        assert!(link.recv_with(&mut |_| link.service()));
        assert_eq!(link.socket.waits.get(), 1);
        assert_eq!(link.socket.waiting_reads.get(), 0);
    }

    #[cfg(feature = "session-slot")]
    mod stack {
        use super::*;
        use wz_session_core::byte_cells::ByteCells;

        static RX: ByteCells<64, 1> = ByteCells::new();
        static TX: ByteCells<32, 1> = ByteCells::new();

        const TO_PEER: SocketAddr = PEER;

        const NODE: IpAddr = LOCAL.ip();

        #[test]
        fn a_dial_claims_both_buffers_and_a_table_with_none_free_refuses() {
            let mut stack = UdpStack::<Loop>::new(NODE, &RX, &TX);
            let link = stack.bind(Locator::udp(TO_PEER)).expect("the first dial");
            assert_eq!(link.peer(), Some(PEER));
            assert_eq!(link.link_mtu(), 32);
            assert_eq!(link.link_rx_capacity(), 64);
            assert!(matches!(
                stack.bind(Locator::udp(TO_PEER)),
                Err(LinkOpenError::Exhausted)
            ));
            drop(link);
            assert!(
                stack.bind(Locator::udp(TO_PEER)).is_ok(),
                "the buffers go back with the driver"
            );
        }

        static TCP_RX: ByteCells<64, 1> = ByteCells::new();
        static TCP_TX: ByteCells<32, 1> = ByteCells::new();

        #[test]
        fn a_stack_of_datagram_sockets_refuses_a_stream_and_claims_nothing() {
            let mut stack = UdpStack::<Loop>::new(NODE, &TCP_RX, &TCP_TX);
            assert!(matches!(
                stack.bind(Locator::tcp(TO_PEER)),
                Err(LinkOpenError::Unsupported)
            ));
            assert!(
                stack.bind(Locator::udp(TO_PEER)).is_ok(),
                "both buffers still free"
            );
        }

        static LEND_RX: ByteCells<64, 1> = ByteCells::new();
        static LEND_TX: ByteCells<32, 1> = ByteCells::new();

        #[test]
        fn the_fixed_driver_lends_its_one_slot_and_takes_it_back_at_the_send() {
            let mut stack = UdpStack::<Loop>::new(NODE, &LEND_RX, &LEND_TX);
            let link = stack.bind(Locator::udp(TO_PEER)).expect("a dial");
            let grant = link
                .tx_slot_acquire(10, Priority::Data)
                .expect("the one slot");
            assert!(
                link.tx_slot_acquire(10, Priority::Data).is_none(),
                "a byte buffer is one slot, and it is out"
            );
            let (base, capacity) = link.tx_slot_storage(grant.slot);
            assert_eq!(capacity, 32);
            // SAFETY: the slot was granted to this test alone and is 32 bytes long.
            unsafe { core::slice::from_raw_parts_mut(base, 3) }.copy_from_slice(b"abc");
            assert_eq!(
                link.tx_slot_send(grant.slot, 0, 3, Reliability::Reliable, Priority::Data),
                LinkSendOutcome::Sent
            );
            assert_eq!(link.socket.sent.borrow()[0].1, b"abc");

            let again = link
                .tx_slot_acquire(10, Priority::Data)
                .expect("the slot is back once it is sent");
            assert_eq!(
                link.tx_slot_send(again.slot, 30, 5, Reliability::Reliable, Priority::Data),
                LinkSendOutcome::Dropped(LinkDropCause::Oversize),
                "a frame past the slot is refused, not truncated"
            );
            assert_eq!(link.socket.sent.borrow().len(), 1, "and nothing was sent");
            assert!(link.tx_slot_acquire(10, Priority::Data).is_some());
        }
    }
}
