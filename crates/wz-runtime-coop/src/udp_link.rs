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

use core::cell::{Cell, RefCell};
use core::ffi::c_int;
use core::fmt::Debug;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// The heap profile's forms (`Vec`, `HeapTx`) exist only in the heap profile: under `session-slot`
// the crate does not link `alloc` at all, which `lib.rs` keeps so that a use creeping back into the
// slot profile is a compile error and not a silent allocation.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use crate::link_cells::{CellRc, CountKind, OneTask};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

#[cfg(feature = "session-slot")]
use core::marker::PhantomData;

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use wz_session_core::bounded::{BoundedVec, Lent, OnUse, Storage};
use wz_session_core::byte_cells::ByteBuf;
#[cfg(feature = "session-slot")]
use wz_session_core::byte_cells::ByteSource;
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use wz_session_core::byte_cells::{CellFlag, LentByteCells};
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use wz_session_core::datagram_peer::is_init_syn;
use wz_session_core::datagram_peer::{ForeignCounts, PeerBinding};
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkEnds, LinkSendOutcome, TxSlot, TxSlotGrant,
    DEFAULT_LINK_MTU, SESSION_TX_SLOTS,
};
#[cfg(feature = "session-unicast-accept")]
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::HeapTx;
use crate::link_storage::{RxStore, TxLender, TxStore};
#[cfg(any(test, feature = "session-slot"))]
use crate::session_drive::Locator;
#[cfg(feature = "session-slot")]
use crate::session_drive::{Bind, DriverPump, LinkOpenError, SlotStack};
use crate::session_drive::{
    InputWaiter, IpLocator, LinkProto, SessionDatagramLink, WaitsInLoop, LONGEST_IP_LOCATOR_LEN,
};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::{LinkWaits, NoWaits, WaitOn};

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

    /// The waits of this platform's sockets ([`LinkWaits`]), which a stack of them waits on its
    /// links with ([`crate::session_drive::SessionLinks::waits`]): one value, made when the stack
    /// is asked for it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    type Waits: LinkWaits + Clone + Default + 'static;

    /// What a thread other than the link's waits on for this socket's input
    /// ([`SessionDatagramLink::input_wait`]); `None` when the platform gives none, and then a
    /// link over the socket waits in its own loop whatever it was asked.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }

    /// Whether every socket of this type names a wait its link's owner can make for its input
    /// (`input_wait` answers one for each socket opened). A constant, so that a link over such a
    /// socket, made by a stack whose owner waits for every link ([`InputWaiter`]), is compiled with
    /// no wait of its own. The provided answer is no: a link over the socket then asks it when the
    /// link is made.
    const NAMES_INPUT_WAIT: bool = false;

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

    /// Whether `error`, from a [`Self::bind`], says another socket holds the address: the open
    /// is `LinkOpenError::AddressInUse`, kept apart from a stack with no socket to give. The
    /// provided answer is that it never says so, for a platform whose error does not tell.
    fn address_in_use(error: &Self::Error) -> bool {
        let _ = error;
        false
    }

    /// Whether the platform answers a host name with the addresses it stands for
    /// ([`Self::resolve`]). A constant, so that the dial of a name over a platform without a
    /// resolver is refused where the endpoint is read, and an image over one carries no resolver.
    const RESOLVES: bool = false;

    /// The addresses the host `name` stands for on the platform's network, each at its port,
    /// written to the front of `found` in the order the platform's resolver answers them: how
    /// many. `0` when the resolver answers none or fails, and on a platform without one
    /// ([`Self::RESOLVES`]). The name is one `crate::locator_text::read_dial_target` read, so a
    /// resolver is handed it whole, with no byte a C string would end at. It blocks for as long
    /// as the resolver takes, so a link's dial asks it as it begins and nothing on a link's way
    /// does.
    fn resolve(name: &crate::locator_text::NamedHost<'_>, found: &mut [SocketAddr]) -> usize {
        let _ = (name, found);
        0
    }
}

/// A failed [`DatagramSocket::bind`] as the stack's refusal to open the link: permanent for an
/// address the socket can never have ([`DatagramSocket::refuses_address`]), an address another
/// socket holds ([`DatagramSocket::address_in_use`]), and otherwise a stack with no socket to
/// give; the last two are retried.
pub fn bind_refused<S: DatagramSocket>(error: S::Error) -> crate::session_drive::LinkOpenError {
    if S::refuses_address(&error) {
        crate::session_drive::LinkOpenError::Unsupported
    } else if S::address_in_use(&error) {
        crate::session_drive::LinkOpenError::AddressInUse
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

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    type Waits = NoWaits;

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

/// The datagram socket of a stack on a platform whose sockets are `U`, in a build that links no
/// datagram link: every `udp/` dial and listener is `LinkOpenError::Unsupported`, as on a stack
/// that carries none ([`NoDatagram`]), and no link over `U` is made, while the stack's other
/// links are waited on with `U`'s waits. There is no value of it.
pub struct NoDatagramOf<U> {
    never: core::convert::Infallible,
    _socket: core::marker::PhantomData<fn() -> U>,
}

impl<U: DatagramSocket> DatagramSocket for NoDatagramOf<U> {
    type Error = ();

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    type Waits = U::Waits;

    const CARRIED: bool = false;

    // A socket that opens nothing opens no IPv6 address either.
    const IPV6: bool = false;

    fn bind(_at: SocketAddr) -> Result<Self, ()> {
        Err(())
    }

    // No address is ever opened, so a refused bind is never one to try again.
    fn refuses_address(_error: &()) -> bool {
        true
    }

    // The platform resolves a name for the stack's other links, as its waits wait on them.
    const RESOLVES: bool = U::RESOLVES;

    fn resolve(name: &crate::locator_text::NamedHost<'_>, found: &mut [SocketAddr]) -> usize {
        U::resolve(name, found)
    }

    fn local(&self) -> SocketAddr {
        match self.never {}
    }

    fn send_to(&self, _to: SocketAddr, _bytes: &[u8]) -> Result<(), ()> {
        match self.never {}
    }

    fn wait_readable(&self, _timeout_ms: c_int) {
        match self.never {}
    }

    fn times_out(&self) -> bool {
        match self.never {}
    }

    fn recv_waiting(&self, _buf: &mut [u8]) -> Result<Option<Received>, ()> {
        match self.never {}
    }

    fn try_recv(&self, _buf: &mut [u8]) -> Result<Option<Received>, ()> {
        match self.never {}
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

/// Whether a link of `proto` from `local` to `peer` names both its ends in the pair of locators a
/// reader of the build keeps them in, held to
/// [`LinkEndpoints::BOUND`](wz_session_core::link::LinkEndpoints::BOUND): this engine refuses a
/// link that does not where it admits it, so no link stands with an end its reports would refuse.
/// A face's row holds an IP end as its address, so a build whose pair is of `String`s admits
/// every IP link.
pub fn ends_fit(proto: LinkProto, local: SocketAddr, peer: SocketAddr) -> bool {
    ends_fit_within(
        wz_session_core::link::LinkEndpoints::BOUND,
        proto,
        local,
        peer,
    )
}

/// Whether both ends of a link of `proto` from `local` to `peer` are written in at most `bound`
/// bytes each, every pair when there is no bound. Every IPv4 end fits a bound the build admits; a
/// bound that holds the longest IPv6 end answers at compile time, and only a shorter one writes the
/// ends to measure them.
fn ends_fit_within(
    bound: Option<usize>,
    proto: LinkProto,
    local: SocketAddr,
    peer: SocketAddr,
) -> bool {
    bound.is_none_or(|bound| {
        bound >= LONGEST_IP_LOCATOR_LEN
            || [local, peer]
                .into_iter()
                .all(|at| IpLocator { proto, at }.text().demanded() <= bound)
    })
}

/// Whether a datagram link over `socket` to `peer` names both its ends in the rows of the build
/// ([`ends_fit`]), asked of what the link is made of before it is made; `true` while the peer is
/// not known yet (an accepting link, which takes a peer only when its ends fit).
pub fn datagram_ends_fit<S: DatagramSocket>(socket: &S, peer: Option<SocketAddr>) -> bool {
    match peer {
        Some(peer) => ends_fit(LinkProto::Udp, socket.local(), peer),
        None => true,
    }
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
///
/// `W` is who waits for the link's input ([`InputWaiter`]), as the stack that made it says: a
/// link of a stack whose owner waits for every link, over a socket that always names its wait
/// ([`DatagramSocket::NAMES_INPUT_WAIT`]), has no wait of its own, and its service reads what is
/// queued and nothing else.
pub struct UdpDriver<S: DatagramSocket, B: RxStore, T: TxStore, W = WaitsInLoop> {
    socket: S,
    binding: PeerBinding<SocketAddr>,
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
    /// The datagrams the copying receive let go of for want of heap room, until the loop takes them.
    #[cfg(feature = "alloc")]
    rx_drops: crate::link_storage::RxDrops,
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
    /// Who waits for the link's input, as the stack that made it says.
    waiter: core::marker::PhantomData<fn() -> W>,
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
    /// reads as a bad frame. It lends its session the slots it needs, each of the
    /// receive buffer's length ([`HeapTx::for_link`]).
    pub fn acceptor_with_capacity(socket: S, rx_capacity: usize) -> Self {
        Self::acceptor_in(
            socket,
            vec![0u8; rx_capacity],
            HeapTx::for_link(0, 0, rx_capacity),
        )
    }

    /// [`Self::initiator`] with a receive buffer of `rx_capacity` bytes.
    pub fn initiator_with_capacity(socket: S, peer: SocketAddr, rx_capacity: usize) -> Self {
        Self::initiator_in(
            socket,
            peer,
            vec![0u8; rx_capacity],
            HeapTx::for_link(0, 0, rx_capacity),
        )
    }
}

impl<S: DatagramSocket, B: RxStore, T: TxStore> UdpDriver<S, B, T> {
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
}

impl<S: DatagramSocket, B: RxStore, T: TxStore, W: InputWaiter> UdpDriver<S, B, T, W> {
    /// [`UdpDriver::initiator_in`] when `peer` is known, [`UdpDriver::acceptor_in`] when it is
    /// not, its input waited for as `W` says: what a stack that opens both from one body asks.
    pub(crate) fn with_peer(socket: S, peer: Option<SocketAddr>, rx_buf: B, tx: T) -> Self {
        let mut place = core::mem::MaybeUninit::uninit();
        Self::with_peer_in(&mut place, socket, peer, rx_buf, tx);
        // SAFETY: `with_peer_in` wrote every field of the driver in `place`.
        unsafe { place.assume_init() }
    }

    /// [`Self::with_peer`] written field by field in `place`, where the link stays: a stack that
    /// opens the link in a cell writes it there, and no whole driver is built in its frame and
    /// moved into the cell.
    pub(crate) fn with_peer_in(
        place: &mut core::mem::MaybeUninit<Self>,
        socket: S,
        peer: Option<SocketAddr>,
        mut rx_buf: B,
        tx: T,
    ) -> &mut Self {
        // A field added to the driver and not written below would be read uninitialised. This
        // names every field with no `..`, so adding one without naming it here (and so without
        // writing it below) does not compile.
        let _every_field_is_written = |driver: &Self| {
            let Self {
                socket: _,
                binding: _,
                rx_buf: _,
                rx_len: _,
                tx: _,
                stash: _,
                kept: _,
                keeping: _,
                #[cfg(feature = "alloc")]
                    rx_drops: _,
                rx_error: _,
                idle_wait_ms: _,
                armed_wait_ms: _,
                owner_waits: _,
                waiter: _,
            } = driver;
        };
        let rx_len = rx_buf.capacity();
        let binding = match peer {
            Some(peer) => PeerBinding::dialled(peer),
            None => PeerBinding::accepting(),
        };
        let at = place.as_mut_ptr();
        // SAFETY: `at` is the place, aligned for the driver and this call's alone; each field is
        // written once, in place.
        unsafe {
            core::ptr::addr_of_mut!((*at).socket).write(socket);
            core::ptr::addr_of_mut!((*at).binding).write(binding);
            core::ptr::addr_of_mut!((*at).rx_buf).write(RefCell::new(rx_buf));
            core::ptr::addr_of_mut!((*at).rx_len).write(rx_len);
            core::ptr::addr_of_mut!((*at).tx).write(TxLender::new(tx));
            core::ptr::addr_of_mut!((*at).stash).write(Cell::new(None));
            core::ptr::addr_of_mut!((*at).kept).write(Cell::new(None));
            core::ptr::addr_of_mut!((*at).keeping).write(Cell::new(false));
            #[cfg(feature = "alloc")]
            core::ptr::addr_of_mut!((*at).rx_drops).write(crate::link_storage::RxDrops::new());
            core::ptr::addr_of_mut!((*at).rx_error).write(Cell::new(None));
            core::ptr::addr_of_mut!((*at).idle_wait_ms).write(SERVICE_WAIT_MS as u32);
            core::ptr::addr_of_mut!((*at).armed_wait_ms).write(Cell::new(SERVICE_WAIT_MS));
            core::ptr::addr_of_mut!((*at).owner_waits).write(false);
            core::ptr::addr_of_mut!((*at).waiter).write(core::marker::PhantomData);
        }
        // SAFETY: every field of the driver was written above.
        unsafe { place.assume_init_mut() }
    }

    /// The same link, waited on by its owner when its socket can be
    /// ([`SessionDatagramLink::input_wait`]): its loop then reads what is queued and does not
    /// wait, and its owner waits on the socket with nothing of the session held. A socket that
    /// gives no such wait keeps the link waiting in its loop.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.wait_by_owner();
        self
    }

    /// [`Self::waited_by_owner`] where the link lies: a stack that makes a link sets it there,
    /// so the link is not moved through a second value of its whole size.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    pub fn wait_by_owner(&mut self) {
        self.owner_waits = self.socket.input_wait().is_some();
    }

    /// Whether the link's owner waits on its socket, so its loop does not: always for a link of a
    /// stack whose owner waits for every link, over a socket that always names its wait, so no wait
    /// of the loop's is compiled into it; otherwise as the link was set when it was made
    /// (`wait_by_owner`).
    fn owner_waits_input(&self) -> bool {
        (W::OWNER && S::NAMES_INPUT_WAIT) || self.owner_waits
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
    // Out of line: the one body of both reads that take a datagram, the receive's
    // (`Self::next_admitted`) and the wait's that reads as it waits (`Self::wait_for_datagram`).
    #[inline(never)]
    fn admit(&self, from: SocketAddr, datagram: &[u8]) -> bool {
        // An accepting link takes the first `InitSyn`'s source as its peer: one whose locator the
        // build's pair of locators does not hold is not taken, so no session stands on a link it
        // cannot name.
        if self.binding.peer().is_none() && !ends_fit(LinkProto::Udp, self.socket.local(), from) {
            return false;
        }
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

impl<S, B, T, W> UdpDriver<S, B, T, W>
where
    S: DatagramSocket + 'static,
    B: RxStore + 'static,
    T: TxStore + 'static,
    W: InputWaiter,
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
        // A link of a pool that holds no buffer and finds none free waits by `poll` too.
        let Some(bytes) = buf.bytes() else {
            self.socket.wait_readable(SERVICE_WAIT_MS);
            return;
        };
        match self.socket.recv_waiting(bytes) {
            Ok(Some((len, from))) => {
                if self.admit(from, datagram_of(bytes, len)) {
                    self.stash.set(Some(len));
                }
            }
            Ok(None) => {}
            Err(e) => self.rx_error.set(Some(e)),
        }
        // A wait that left no datagram for the next receive leaves the buffer to its pool.
        if B::POOLED && self.stash.get().is_none() && self.kept.get().is_none() {
            buf.idle();
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

impl<S, B, T, W> BoxedLinkDriver for UdpDriver<S, B, T, W>
where
    S: DatagramSocket + 'static,
    B: RxStore + 'static,
    T: TxStore + 'static,
    W: InputWaiter,
{
    // The bytes are copied into a slot the link lends and sent as one, so the socket's send has
    // one caller. UDP is unreliable; the session's reliable channel recovers a drop.
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        let sent = crate::link_storage::copied_send(self, bytes, reliability, Priority::DEFAULT);
        // A datagram link keeps no slot past its send, so every slot out is with the session,
        // which holds one for each of its conduits at most: a link that lends the slots its
        // session needs has one more for this frame.
        debug_assert!(
            sent != LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
                || self.tx.slots() < SESSION_TX_SLOTS,
            "a datagram link that lends its session's slots had none for a frame"
        );
        sent
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

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_spare(&self) -> bool {
        self.tx.spare()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_claimable(&self) -> bool {
        self.tx.claimable()
    }

    // The socket takes a datagram whole and at once, so the link's room is its slots': a link of
    // a pool whose every slot another link holds is congested now, and does not wait under the
    // session's lock for the step that frees one.
    #[cfg(feature = "session-unicast-accept")]
    fn wait_for_room(&self, _priority: Priority, _wait: RoomWait) -> RoomAnswer {
        if self.tx.claimable() {
            RoomAnswer::at_once(LinkRoom::Free)
        } else {
            RoomAnswer::at_once(LinkRoom::Congested)
        }
    }

    fn open_blocking(&self) {}

    fn close_blocking(&self) {}

    // None until the peer is known: a dialled link's from its construction, an accepting one's
    // from the `InitSyn` that binds it. The addresses are lent as they are; a reader that reports
    // the link writes its locators, so a node that reports none writes no locator's text.
    fn link_ends(&self) -> Option<LinkEnds<'_>> {
        let peer = self.binding.peer()?;
        Some(LinkEnds::ip(
            LinkProto::Udp.kind(),
            self.socket.local(),
            peer,
        ))
    }

    #[cfg(feature = "alloc")]
    fn link_subject(&self) -> Option<&wz_session_core::link::LinkSubject> {
        Some(LinkProto::Udp.subject())
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

impl<S, B, T, W> SessionDatagramLink for UdpDriver<S, B, T, W>
where
    S: DatagramSocket + 'static,
    B: RxStore + 'static,
    T: TxStore + 'static,
    W: InputWaiter,
{
    fn service(&self) {
        // A link its owner waits on reads what is queued and does not wait here.
        if self.owner_waits_input() {
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
        if max_wait_ms == 0 || self.owner_waits_input() {
            return;
        }
        // The most this link may wait: what its session has due, and what its image allows. At
        // or below the tick it is the tick, which is every link that has not been given more.
        let want = max_wait_ms.min(u64::from(self.idle_wait_ms));
        if want > SERVICE_WAIT_MS as u64 && self.socket.times_out() {
            // The timeout is armed at the largest power of two not above `want`, so a wait never
            // ends after the deadline it was computed from, and re-arming (a system call) happens
            // only when the deadline moves to another power of two: a link whose deadlines are
            // seconds away arms once, and the approach to a deadline costs one wake per halving,
            // not one per tick.
            let armed = power_of_two_within(want);
            // `idle_wait_ms` is at most half of `c_int`'s range, so the power of two is inside it.
            if self.arm(armed as c_int) {
                self.wait_for_datagram();
                return;
            }
        }
        // A wait of the tick, and the fallback of a socket that would not be armed for longer:
        // one call of the tick's wait serves both.
        self.service();
    }

    // The datagram the lending receive hands over, copied out: one body reads the socket and the
    // binding for both receives, and the buffer is idle after it as after any datagram let go of.
    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        crate::link_storage::copied_receive(self, &self.rx_drops)
    }

    #[cfg(feature = "alloc")]
    fn take_rx_dropped(&self) -> usize {
        self.rx_drops.take()
    }

    fn holds_input(&self) -> bool {
        self.stash.get().is_some() || self.kept.get().is_some() || self.socket.holds_datagram()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        self.rx_buf.try_borrow().is_ok_and(|buf| buf.starved())
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
    fn input_wait(&self) -> Option<WaitOn> {
        if self.owner_waits_input() {
            self.socket.input_wait()
        } else {
            None
        }
    }

    // The datagram is lent out of the link's own receive buffer, which the
    // stack has just written: no heap copy of it. The buffer stays borrowed
    // while `f` runs; the session's sends go through the socket, not through
    // it, and a receive from inside `f` finds it lent and reads nothing.
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        let Ok(mut buf) = self.rx_buf.try_borrow_mut() else {
            return false;
        };
        // A link of a pool that holds no buffer and finds none free reads nothing: its datagrams
        // wait in the stack (`SessionDatagramLink::waits_for_buffer`).
        let Some(bytes) = buf.bytes() else {
            return false;
        };
        let len = match self.kept.take() {
            Some(len) => len,
            None => match self.next_admitted(bytes) {
                Ok(Some(len)) => len,
                Ok(None) => {
                    buf.idle();
                    return false;
                }
                Err(e) => {
                    self.rx_error.set(Some(e));
                    buf.idle();
                    return false;
                }
            },
        };
        self.keeping.set(false);
        f(datagram_of(bytes, len));
        if self.keeping.replace(false) {
            self.kept.set(Some(len));
        } else {
            // A datagram is whole: once lent and not kept, nothing of the link's own is left.
            buf.idle();
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
/// The port and the links of its peers are shared as the sessions of its stack count a link's
/// handles (`N`): by one task, through cells; across threads, through handles counted atomically
/// and the profile's lock around the book and the reads ([`CountKind::Local`]), so a link of the
/// port moves to whichever thread holds it. The peers it took and the datagrams it sorted for
/// them are kept in rows the stack's ports share ([`PortRows`]), in the memory the source `P`
/// gives ([`PortSource`]): what the session lent, or the heap's, counted to what the session
/// stated. `P` is the source of the links' kind ([`CountKind::Ports`]), named apart from `N`
/// because a kind that takes its links' memory on use counts what they share as the kind it wraps
/// does.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct UdpPort<
    S: DatagramSocket,
    N: CountKind = OneTask,
    P: PortSource<N::Flag> = <N as CountKind>::Ports,
> {
    socket: S,
    /// The number this port's rows carry in the book its stack's ports share.
    id: u32,
    book: SharedBook<N, P>,
    /// What each datagram is read into, what the datagrams sorted for a peer are held in, and
    /// what the reads dropped: one reader at a time, whichever link reads.
    reads: N::Local<PortReads<P::Rx>>,
}

/// What the reads of a [`UdpPort`] keep: `R` is where it reads and holds its datagrams.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
struct PortReads<R> {
    rx: R,
    /// Datagrams from a source with no link that were not an `InitSyn`.
    strays: u32,
    /// Datagrams dropped for a full backlog, for no row of the queue, or for no memory to hold
    /// them in.
    overflows: u32,
}

/// One peer a stack's udp ports took, while its link lasts: the port it came in on, its address,
/// and whether the listener has handed its link out yet. One row for each link a session may hold.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
#[derive(Debug, Clone, Copy)]
pub struct PortPeerRow {
    port: u32,
    peer: SocketAddr,
    fresh: bool,
    /// How many datagrams wait in the queue for this peer, so the backlog and the reads ask the
    /// row and not the queue. At most [`PORT_PEER_BACKLOG`]; it lies in the row's padding.
    queued: u16,
}

/// A datagram one of a stack's udp ports sorted for a peer, held in `H` until the peer's link
/// reads it. One row for each datagram the ports may hold at once.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct QueuedDatagram<H = LentHeld> {
    port: u32,
    peer: SocketAddr,
    held: H,
}

/// The rows a stack's udp ports keep their peers and the datagrams sorted for them in, which every
/// port of the stack shares: rows a session lent from the memory it reserved when it opened
/// (`P` [`Lent`], [`LentPorts`]), or rows the heap gives at the first peer and the first
/// datagram, counted to what the session stated (`P` [`OnUse`], [`HeapPorts`]); each datagram
/// held in `H`. A peer past the peers' rows, or a datagram past the queue's, is dropped and
/// counted, as a full socket buffer drops one. A peer's datagrams are read in the order they were
/// sorted, from the one queue of all the ports.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct PortRows<P: Storage = Lent, H = LentHeld> {
    peers: BoundedVec<PortPeerRow, { usize::MAX }, P>,
    queue: BoundedVec<QueuedDatagram<H>, { usize::MAX }, P>,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<H> PortRows<Lent, H> {
    /// The rows a session lent: `peers` for the peers its ports take, `queue` for the datagrams
    /// they sort.
    pub fn over(
        peers: BoundedVec<PortPeerRow, { usize::MAX }, Lent>,
        queue: BoundedVec<QueuedDatagram<H>, { usize::MAX }, Lent>,
    ) -> Self {
        Self { peers, queue }
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<H> PortRows<OnUse, H> {
    /// Rows for `peers` peers and `datagrams` datagrams waiting at once, which take their memory
    /// at the first peer and the first datagram, all of each count at once.
    fn counted(peers: usize, datagrams: usize) -> Self {
        Self {
            peers: BoundedVec::counted(peers),
            queue: BoundedVec::counted(datagrams),
        }
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<P: Storage, H> PortRows<P, H> {
    fn row_mut(&mut self, port: u32, peer: SocketAddr) -> Option<&mut PortPeerRow> {
        self.peers
            .iter_mut()
            .find(|row| row.port == port && row.peer == peer)
    }

    /// How many datagrams wait for `peer` of `port`, `None` for a peer the port did not take.
    fn queued_for(&self, port: u32, peer: SocketAddr) -> Option<usize> {
        self.peers
            .iter()
            .find(|row| row.port == port && row.peer == peer)
            .map(|row| usize::from(row.queued))
    }

    /// Queue `held` for `peer` of `port`, a peer the port took; `false`, the datagram let go of,
    /// when the queue is full or the heap refuses its rows.
    fn enqueue(&mut self, port: u32, peer: SocketAddr, held: H) -> bool {
        if self
            .queue
            .push(QueuedDatagram { port, peer, held })
            .is_err()
        {
            return false;
        }
        if let Some(row) = self.row_mut(port, peer) {
            row.queued = row.queued.saturating_add(1);
        }
        true
    }

    /// Take `peer` of `port`, whose `InitSyn` opened a link, with `held` its first datagram;
    /// `false`, nothing taken, when the peers' or the queue's rows are all held or the heap refuses
    /// them. Both tables' room is made before either is written, so a peer is never taken without
    /// its first datagram.
    fn take(&mut self, port: u32, peer: SocketAddr, held: H) -> bool {
        if !(self.peers.make_room() && self.queue.make_room()) {
            return false;
        }
        let row = PortPeerRow {
            port,
            peer,
            fresh: true,
            queued: 0,
        };
        self.peers.push(row).is_ok() && self.enqueue(port, peer, held)
    }

    fn take_fresh(&mut self, port: u32) -> Option<SocketAddr> {
        let row = self
            .peers
            .iter_mut()
            .find(|row| row.port == port && row.fresh)?;
        row.fresh = false;
        Some(row.peer)
    }

    // The queue is read only for a peer that has a datagram in it, which its row tells.
    fn take_for(&mut self, port: u32, peer: SocketAddr) -> Option<H> {
        let row = self.row_mut(port, peer)?;
        row.queued = row.queued.checked_sub(1)?;
        let at = self
            .queue
            .iter()
            .position(|row| row.port == port && row.peer == peer)?;
        Some(self.queue.remove(at).held)
    }

    fn holds_for(&self, port: u32, peer: SocketAddr) -> bool {
        self.queued_for(port, peer).is_some_and(|queued| queued > 0)
    }

    fn forget(&mut self, port: u32, peer: SocketAddr) {
        self.peers
            .retain(|row| !(row.port == port && row.peer == peer));
        self.queue
            .retain(|row| !(row.port == port && row.peer == peer));
    }

    fn forget_port(&mut self, port: u32) {
        self.peers.retain(|row| row.port != port);
        self.queue.retain(|row| row.port != port);
    }
}

/// Where a [`UdpPort`] reads each datagram and holds those it sorted for a peer until the peer's
/// link reads them: one store for each port, made by its stack's source ([`PortSource::rx`]).
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub trait PortStore {
    /// A datagram sorted for a peer, held until its link reads it: its bytes, exactly as long as
    /// the datagram the socket reported, cut to what it was read into.
    type Held: AsRef<[u8]>;

    /// What the next datagram is read into.
    fn read_into(&mut self) -> &mut [u8];

    /// The `len` bytes the last read reported, cut to what was read into.
    fn read(&self, len: usize) -> &[u8];

    /// The datagram of `len` bytes just read, held for a peer; `None` when there is no memory to
    /// hold it in, and the datagram is dropped.
    fn keep(&mut self, len: usize) -> Option<Self::Held>;

    /// `held`, read by its link, back to the store.
    fn give_back(&mut self, held: Self::Held);
}

/// The first `len` bytes of a slot a session lent: a datagram a port over lent slots holds
/// ([`LentRx`]), which gives the slot back to its table as it is dropped.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct LentHeld<F: CellFlag = Cell<bool>>(ByteBuf<F>, usize);

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<F: CellFlag> AsRef<[u8]> for LentHeld<F> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice().get(..self.1).unwrap_or_default()
    }
}

/// A port's reads over a table of slots its session lent: a slot read into, which a datagram
/// sorted for a peer keeps while the next read takes another; with none free the datagram is
/// dropped and counted, as a full socket buffer drops one, and the slot is read into again.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct LentRx<F: CellFlag = Cell<bool>> {
    table: LentByteCells<F>,
    read: ByteBuf<F>,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<F: CellFlag> PortStore for LentRx<F> {
    type Held = LentHeld<F>;

    fn read_into(&mut self) -> &mut [u8] {
        self.read.as_mut_slice()
    }

    fn read(&self, len: usize) -> &[u8] {
        datagram_of(self.read.as_slice(), len)
    }

    /// The datagram keeps the slot it was read into, and another is taken for the next read.
    fn keep(&mut self, len: usize) -> Option<LentHeld<F>> {
        let next = self.table.claim()?;
        let slot = core::mem::replace(&mut self.read, next);
        let len = len.min(slot.as_slice().len());
        Some(LentHeld(slot, len))
    }

    /// The slot goes back to its table as `_held` is dropped.
    fn give_back(&mut self, _held: LentHeld<F>) {}
}

/// A port's reads in memory of its own: a read buffer, and the buffers a peer's link gave back
/// once it read the datagram held in them, which the next datagram sorted is held in. A port whose
/// peers keep sending holds each datagram in a buffer it already has, and asks the heap only while
/// its backlog grows past any it held; a datagram the heap has no room for is dropped and counted.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct OwnRx {
    read: Vec<u8>,
    spare: Vec<Vec<u8>>,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl PortStore for OwnRx {
    type Held = Vec<u8>;

    fn read_into(&mut self) -> &mut [u8] {
        &mut self.read
    }

    fn read(&self, len: usize) -> &[u8] {
        datagram_of(&self.read, len)
    }

    /// The datagram copied into a buffer a link gave back, or a new one, exactly as long.
    fn keep(&mut self, len: usize) -> Option<Vec<u8>> {
        let datagram = datagram_of(&self.read, len);
        let mut held = self.spare.pop().unwrap_or_default();
        held.clear();
        held.try_reserve_exact(datagram.len()).ok()?;
        held.extend_from_slice(datagram);
        Some(held)
    }

    /// Kept for the next datagram sorted, up to as many as one peer's backlog, so a burst that is
    /// over leaves no more buffers than a backlog holds.
    fn give_back(&mut self, held: Vec<u8>) {
        if self.spare.len() < PORT_PEER_BACKLOG && self.spare.try_reserve(1).is_ok() {
            self.spare.push(held);
        }
    }
}

/// What a source gives the book of a stack's ports ([`PortSource::book`]): the rows the ports
/// share, stored as `S`, each datagram held in what the reads `R` hold it in, and `Reads`, what
/// makes each port's reads.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub type BookParts<S, R, Reads> = (PortRows<S, <R as PortStore>::Held>, Reads);

/// Where the udp ports of a stack whose links count their handles as a kind does keep their peers
/// and the datagrams sorted for them ([`CountKind::Ports`]), which a session hands the stack
/// once (`SessionLinks::lend_ports`): what it lent, or the heap, counted to what it stated. A
/// type, not only a value, so a kind whose sessions lend nothing makes its ports over the heap's
/// memory and names no lent table, and a kind whose sessions lend makes them over the lent one
/// and names no row of the heap. A source that gives no book (a session that lent nothing, or
/// sized nothing) refuses every port, so a port's memory is always bounded by its session's
/// statement.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub trait PortSource<F: CellFlag> {
    /// The storage of the book's rows.
    type Rows: Storage;

    /// What each port reads into and holds its peers' datagrams in.
    type Rx: PortStore;

    /// What the book keeps to make each port's reads ([`Self::rx`]).
    type Reads: Copy;

    /// The rows of the book the stack's ports share, and what makes each port's reads; `None`
    /// for a source that gives no port.
    fn book(self) -> Option<BookParts<Self::Rows, Self::Rx, Self::Reads>>;

    /// The reads of a port opened now; `None` when there is no memory for them, and the port is
    /// not opened.
    fn rx(reads: Self::Reads) -> Option<Self::Rx>;
}

/// The rows and the slots a session lent its udp ports from the memory it reserved when it opened:
/// a row for each peer and for each datagram held at once, and a slot for each datagram read or
/// held, which the ports share. What a kind whose sessions lend their links tables gives its
/// ports, `None` while nothing was lent.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub struct LentPorts<F: CellFlag = Cell<bool>> {
    rows: PortRows<Lent, LentHeld<F>>,
    slots: LentByteCells<F>,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<F: CellFlag> LentPorts<F> {
    /// The ports' `rows` and the `slots` each datagram is read into and held in.
    pub fn new(rows: PortRows<Lent, LentHeld<F>>, slots: LentByteCells<F>) -> Self {
        Self { rows, slots }
    }

    /// The slots the ports read their datagrams into.
    pub fn slots(&self) -> LentByteCells<F> {
        self.slots
    }
}

/// What a session lent, while it lent something: each port claims a slot to read into, and a port
/// the table has no slot free for is not opened; nothing lent, no port.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<F: CellFlag> PortSource<F> for Option<LentPorts<F>> {
    type Rows = Lent;
    type Rx = LentRx<F>;
    type Reads = LentByteCells<F>;

    fn book(self) -> Option<(PortRows<Lent, LentHeld<F>>, LentByteCells<F>)> {
        self.map(|lent| (lent.rows, lent.slots))
    }

    fn rx(table: LentByteCells<F>) -> Option<LentRx<F>> {
        let read = table.claim()?;
        Some(LentRx { table, read })
    }
}

/// The ports' memory taken from the heap as they use it, counted to what the session stated
/// (`Self::sized`): the rows of the peers and of the datagrams waiting at once, taken at the
/// first of each, and for each port a read buffer of the session's batch and the buffers its
/// datagrams are held in. What a kind whose sessions take their links' memory on use gives its
/// ports ([`OnHeap`](crate::link_cells::OnHeap)); unsized, as a stack holds it before a session
/// sizes it, no port.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapPorts {
    /// The peers, the datagrams waiting at once, and the bytes of a port's read buffer.
    sized: Option<(usize, usize, usize)>,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl HeapPorts {
    /// Rows for `peers` peers and `datagrams` datagrams waiting at once, and each port a read
    /// buffer of `bytes`, the largest datagram a link of the port receives whole: the counts a
    /// session's lent ports would have.
    pub const fn sized(peers: usize, datagrams: usize, bytes: usize) -> Self {
        Self {
            sized: Some((peers, datagrams, bytes)),
        }
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<F: CellFlag> PortSource<F> for HeapPorts {
    type Rows = OnUse;
    type Rx = OwnRx;
    type Reads = usize;

    fn book(self) -> Option<(PortRows<OnUse, Vec<u8>>, usize)> {
        let (peers, datagrams, bytes) = self.sized?;
        Some((PortRows::counted(peers, datagrams), bytes))
    }

    fn rx(bytes: usize) -> Option<OwnRx> {
        Some(OwnRx {
            read: crate::link_storage::zeroed_bytes(bytes)?,
            spare: Vec::new(),
        })
    }
}

/// The rows a stack's udp ports share, what makes each port's reads, and the number the next port
/// takes.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub(crate) struct PortBook<F: CellFlag, P: PortSource<F>> {
    rows: PortRows<P::Rows, <P::Rx as PortStore>::Held>,
    reads: P::Reads,
    next: u32,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<F: CellFlag, P: PortSource<F>> PortBook<F, P> {
    /// The reads of a port opened now and the number it carries; `None`, no number taken, when
    /// the source has no memory for them.
    fn open_port(&mut self) -> Option<(u32, P::Rx)> {
        let rx = P::rx(self.reads)?;
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        Some((id, rx))
    }
}

/// The book a stack's ports share, as the sessions of the stack count a link's handles (`N`),
/// over the memory of the source `P`.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub(crate) type SharedBook<N, P> =
    CellRc<<N as CountKind>::Local<PortBook<<N as CountKind>::Flag, P>>, N>;

/// The book of the ports of a stack whose sessions count a link's handles as `N` does, over what
/// `source` gives: `None` for a source that gives no port, and the bytes of the book's cell when
/// the heap refuses it, what the source gave let go of.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub(crate) fn shared_book<N: CountKind, P: PortSource<N::Flag>>(
    source: P,
) -> Result<Option<SharedBook<N, P>>, usize> {
    let Some((rows, reads)) = source.book() else {
        return Ok(None);
    };
    <SharedBook<N, P>>::in_cells_of(
        &crate::link_cells::HeapCells,
        N::new_local(PortBook {
            rows,
            reads,
            next: 0,
        }),
    )
    .map(Some)
    .map_err(|_| <SharedBook<N, P>>::cell_bytes_of())
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, P: PortSource<Cell<bool>>> UdpPort<S, OneTask, P> {
    /// The port of `socket` over a book of its own, made of what `source` gives: a program's one
    /// port, outside a stack. `None` when the source gives no port, the heap has no room for the
    /// book, or the source no memory for the port's reads.
    pub fn new(socket: S, source: P) -> Option<Self> {
        let book = shared_book::<OneTask, P>(source).ok().flatten()?;
        Self::in_book(socket, &book)
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, N: CountKind, P: PortSource<N::Flag>> UdpPort<S, N, P> {
    /// The port of `socket`, keeping its peers and their datagrams in `book`, which the stack's
    /// ports share, and reading through what the book's source gives it: `None` when the source
    /// has nothing for the port (a lent table with no slot free, a heap with no room for the read
    /// buffer).
    pub(crate) fn in_book(socket: S, book: &SharedBook<N, P>) -> Option<Self> {
        let (id, rx) = N::with_local::<PortBook<N::Flag, P>, _>(book, PortBook::open_port)?;
        Some(Self {
            socket,
            id,
            book: book.clone(),
            reads: N::new_local(PortReads {
                rx,
                strays: 0,
                overflows: 0,
            }),
        })
    }

    /// Run `f` on the book the stack's ports share.
    fn with_book<U>(&self, f: impl FnOnce(&mut PortBook<N::Flag, P>) -> U) -> U {
        N::with_local::<PortBook<N::Flag, P>, U>(&self.book, f)
    }

    /// [`Self::with_book`] unless a holder has the book now: `None` then, and `f` has not run.
    fn try_with_book<U>(&self, f: impl FnOnce(&mut PortBook<N::Flag, P>) -> U) -> Option<U> {
        N::try_with_local::<PortBook<N::Flag, P>, U>(&self.book, f)
    }

    /// Run `f` on what the port's reads keep.
    fn with_reads<U>(&self, f: impl FnOnce(&mut PortReads<P::Rx>) -> U) -> U {
        N::with_local::<PortReads<P::Rx>, U>(&self.reads, f)
    }

    /// [`Self::with_reads`] unless a holder has them now: `None` then, and `f` has not run.
    fn try_with_reads<U>(&self, f: impl FnOnce(&mut PortReads<P::Rx>) -> U) -> Option<U> {
        N::try_with_local::<PortReads<P::Rx>, U>(&self.reads, f)
    }

    /// The address and port the socket is bound to.
    pub fn local(&self) -> SocketAddr {
        self.socket.local()
    }

    /// What another thread waits on for the socket's input, when the platform gives one.
    pub fn input_wait(&self) -> Option<WaitOn> {
        self.socket.input_wait()
    }

    /// Datagrams from a source with no link that were not an `InitSyn`.
    pub fn strays(&self) -> u32 {
        self.with_reads(|reads| reads.strays)
    }

    /// Datagrams dropped because their peer had [`PORT_PEER_BACKLOG`] waiting already, because no
    /// row of the queue was free, or because there was no memory to hold them in or to read the
    /// next one into.
    pub fn overflows(&self) -> u32 {
        self.with_reads(|reads| reads.overflows)
    }

    /// The share of the port of the next source whose `InitSyn` opened a link, after the socket
    /// was read: what a listener takes. `Ok(None)` when no new source waits; the socket's error
    /// when the read failed and no new source waits either.
    pub fn take_fresh(port: &CellRc<Self, N>) -> Result<Option<PortPeer<S, N, P>>, S::Error> {
        let pumped = port.pump();
        let next = port.with_book(|book| book.rows.take_fresh(port.id));
        match next {
            Some(peer) => Ok(Some(PortPeer {
                port: port.clone(),
                peer,
            })),
            None => pumped.map(|()| None),
        }
    }

    /// Take everything the socket holds and sort it. A read that is already sorting (a link read
    /// from inside another's receive, or one on another thread) leaves the socket to it.
    fn pump(&self) -> Result<(), S::Error> {
        self.try_with_reads(|reads| -> Result<(), S::Error> {
            while let Some((len, from)) = self.socket.try_recv(reads.rx.read_into())? {
                self.sort(from, len, reads);
            }
            Ok(())
        })
        .unwrap_or(Ok(()))
    }

    /// Hand the datagram of `len` bytes the reads just read from `from` to the link of its peer,
    /// open a link for the source of an `InitSyn` that has none, and drop and count anything else.
    fn sort(&self, from: SocketAddr, len: usize, reads: &mut PortReads<P::Rx>) {
        let id = self.id;
        let PortReads {
            rx,
            strays,
            overflows,
        } = reads;
        let kept = self.with_book(|book| {
            let rows = &mut book.rows;
            if let Some(queued) = rows.queued_for(id, from) {
                queued < PORT_PEER_BACKLOG
                    && rx
                        .keep(len)
                        .is_some_and(|held| rows.enqueue(id, from, held))
            } else if is_init_syn(rx.read(len)) {
                rx.keep(len).is_some_and(|held| rows.take(id, from, held))
            } else {
                *strays = strays.saturating_add(1);
                true
            }
        });
        if !kept {
            *overflows = overflows.saturating_add(1);
        }
    }

    /// `held`, read by its link, back to the port's reads ([`PortStore::give_back`]). A port that
    /// is reading meanwhile lets it go instead, which gives a slot back to its table as well.
    fn give_back(&self, held: <P::Rx as PortStore>::Held) {
        self.try_with_reads(|reads| reads.rx.give_back(held));
    }

    /// The next datagram taken for `peer`.
    fn take_for(&self, peer: SocketAddr) -> Option<<P::Rx as PortStore>::Held> {
        self.with_book(|book| book.rows.take_for(self.id, peer))
    }

    /// Whether a datagram taken for `peer` waits to be read.
    fn holds_for(&self, peer: SocketAddr) -> bool {
        self.with_book(|book| book.rows.holds_for(self.id, peer))
    }

    /// `peer`'s link is gone: what was taken for it goes, and its next `InitSyn` opens a link.
    fn forget(&self, peer: SocketAddr) {
        self.try_with_book(|book| book.rows.forget(self.id, peer));
    }
}

/// A port that goes takes its peers' rows and their datagrams with it, so the rows it held serve
/// the stack's next port.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, N: CountKind, P: PortSource<N::Flag>> Drop for UdpPort<S, N, P> {
    fn drop(&mut self) {
        self.try_with_book(|book| book.rows.forget_port(self.id));
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
pub struct PortPeer<
    S: DatagramSocket,
    N: CountKind = OneTask,
    P: PortSource<N::Flag> = <N as CountKind>::Ports,
> {
    port: CellRc<UdpPort<S, N, P>, N>,
    peer: SocketAddr,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, N: CountKind, P: PortSource<N::Flag>> PortPeer<S, N, P> {
    /// The peer this share reads and sends for.
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, N: CountKind, P: PortSource<N::Flag>> Drop for PortPeer<S, N, P> {
    fn drop(&mut self) {
        self.port.forget(self.peer);
    }
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, N: CountKind, P: PortSource<N::Flag>> DatagramSocket for PortPeer<S, N, P> {
    type Error = PortPeerError<S::Error>;

    type Waits = S::Waits;

    const CARRIED: bool = S::CARRIED;

    const IPV6: bool = S::IPV6;

    // The wait it names is its port's socket's.
    const NAMES_INPUT_WAIT: bool = S::NAMES_INPUT_WAIT;

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
        if let Some(held) = self.port.take_for(self.peer) {
            let datagram = held.as_ref();
            // Cut to the buffer, as the stack cuts a datagram longer than the read.
            let len = datagram.len().min(buf.len());
            if let (Some(to), Some(from)) = (buf.get_mut(..len), datagram.get(..len)) {
                to.copy_from_slice(from);
            }
            self.port.give_back(held);
            return Ok(Some((len, self.peer)));
        }
        pumped.map(|()| None).map_err(PortPeerError::Socket)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.port.input_wait()
    }

    fn holds_datagram(&self) -> bool {
        self.port.holds_for(self.peer)
    }
}

/// The socket of a datagram link of a stack that listens on `udp/`: a socket of the link's own (a
/// dial's, an acceptor's bound to its port) or its peer's share of a port ([`PortPeer`]), over
/// the memory `P` the port's kind keeps ([`PortSource`]). Every
/// datagram link of such a stack holds one, so the driver over it is one body whichever kind a
/// link holds ([`UdpDriver`] is generic over its socket, and a type of socket for each kind would
/// be a copy of the driver for each); each call is a match on the kind, and none adds a call.
///
/// The constants are the platform socket's: a share has no receive timeout of its own and says so
/// when asked (`set_receive_timeout`), and the link then waits the tick as it would over the share.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
pub enum LinkSocket<
    S: DatagramSocket,
    N: CountKind = OneTask,
    P: PortSource<N::Flag> = <N as CountKind>::Ports,
> {
    /// A socket of the link's own.
    Own(S),
    /// The link's peer's share of a port.
    Port(PortPeer<S, N, P>),
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<S: DatagramSocket, N: CountKind, P: PortSource<N::Flag>> DatagramSocket
    for LinkSocket<S, N, P>
{
    type Error = PortPeerError<S::Error>;

    type Waits = S::Waits;

    const CARRIED: bool = S::CARRIED;

    const IPV6: bool = S::IPV6;

    const NAMES_INPUT_WAIT: bool = S::NAMES_INPUT_WAIT;

    const CAN_SET_RECEIVE_TIMEOUT: bool = S::CAN_SET_RECEIVE_TIMEOUT;

    const RESOLVES: bool = S::RESOLVES;

    /// A socket of its own: a share is made by its port's listener and never bound.
    fn bind(at: SocketAddr) -> Result<Self, Self::Error> {
        S::bind(at).map(Self::Own).map_err(PortPeerError::Socket)
    }

    fn refuses_address(error: &Self::Error) -> bool {
        match error {
            PortPeerError::Socket(error) => S::refuses_address(error),
            PortPeerError::Unbound => false,
        }
    }

    fn address_in_use(error: &Self::Error) -> bool {
        match error {
            PortPeerError::Socket(error) => S::address_in_use(error),
            PortPeerError::Unbound => false,
        }
    }

    fn resolve(name: &crate::locator_text::NamedHost<'_>, found: &mut [SocketAddr]) -> usize {
        S::resolve(name, found)
    }

    fn local(&self) -> SocketAddr {
        match self {
            Self::Own(socket) => socket.local(),
            Self::Port(share) => share.local(),
        }
    }

    fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), Self::Error> {
        match self {
            Self::Own(socket) => socket.send_to(to, bytes).map_err(PortPeerError::Socket),
            Self::Port(share) => share.send_to(to, bytes),
        }
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        match self {
            Self::Own(socket) => socket.wait_readable(timeout_ms),
            Self::Port(share) => share.wait_readable(timeout_ms),
        }
    }

    fn times_out(&self) -> bool {
        match self {
            Self::Own(socket) => socket.times_out(),
            Self::Port(share) => share.times_out(),
        }
    }

    fn set_receive_timeout(&self, ms: c_int) -> bool {
        match self {
            Self::Own(socket) => socket.set_receive_timeout(ms),
            Self::Port(share) => share.set_receive_timeout(ms),
        }
    }

    fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        match self {
            Self::Own(socket) => socket.recv_waiting(buf).map_err(PortPeerError::Socket),
            Self::Port(share) => share.recv_waiting(buf),
        }
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, Self::Error> {
        match self {
            Self::Own(socket) => socket.try_recv(buf).map_err(PortPeerError::Socket),
            Self::Port(share) => share.try_recv(buf),
        }
    }

    fn input_wait(&self) -> Option<WaitOn> {
        match self {
            Self::Own(socket) => socket.input_wait(),
            Self::Port(share) => share.input_wait(),
        }
    }

    fn holds_datagram(&self) -> bool {
        match self {
            Self::Own(socket) => socket.holds_datagram(),
            Self::Port(share) => share.holds_datagram(),
        }
    }
}

/// The rows and the slots of a stack's ports over memory leaked for a test, as a session's arena
/// lends them: `peers` peer rows, `slots` slots of `bytes` and as many queue rows, and the table
/// of the slots, to read which are held.
#[cfg(all(test, feature = "udp-listen", not(feature = "session-slot")))]
pub(crate) fn leaked_ports(peers: usize, slots: usize, bytes: usize) -> (LentPorts, LentByteCells) {
    use wz_session_core::bounded::{Arena, ARENA_ALIGN};

    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block([u8; ARENA_ALIGN]);

    let size = Arena::byte_cells_bytes(bytes, slots)
        .and_then(|cells| Arena::table_bytes::<PortPeerRow>(peers).map(|rows| cells + rows))
        .and_then(|lent| Arena::table_bytes::<QueuedDatagram>(slots).map(|queue| lent + queue))
        .expect("within the address space");
    let region: &'static mut [Block] =
        alloc::vec![Block([0; ARENA_ALIGN]); size.div_ceil(ARENA_ALIGN)].leak();
    // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `size` bytes, and is leaked,
    // so nothing else uses it and it outlives every slot and row lent from it.
    let mut arena = unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), size) };
    let table = arena
        .lend_byte_cells(bytes, slots)
        .expect("the ports' slots");
    let rows = PortRows::over(
        arena.lend(peers).expect("the peers' rows"),
        arena.lend(slots).expect("the queue's rows"),
    );
    (LentPorts::new(rows, table), table)
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
        if !ends_fit(LinkProto::Udp, socket.local(), peer) {
            return Err(LinkOpenError::Unsupported);
        }
        Ok(UdpDriver::initiator_in(socket, peer, rx, tx).with_idle_wait_ms(self.idle_wait_ms))
    }
}

#[cfg(feature = "session-slot")]
impl<S: DatagramSocket + 'static> Bind<FixedUdpDriver<S>> for UdpStack<S> {
    const IPV6: bool = S::IPV6;

    fn bind(&mut self, to: Locator) -> Result<FixedUdpDriver<S>, LinkOpenError> {
        let Some(ip) = to.as_ip() else {
            return Err(LinkOpenError::Unsupported);
        };
        match ip.proto {
            LinkProto::Udp => self.bind_initiator(ip.at),
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
    use wz_session_core::link::LinkEndsText;

    /// A datagram sorted for a peer's link is held in a buffer the port keeps once the link read
    /// it, so a peer that keeps sending datagrams of one length is held in the same buffer each
    /// time and costs no allocation after its first. The datagram the listener's look takes off
    /// the socket waits there for the link, as it did before.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_port_holds_each_datagram_in_a_buffer_a_read_gave_back() {
        let port = shared(
            HeapPort::new(Loop::default(), HeapPorts::sized(1, 4, 64)).expect("the heap has room"),
        );
        queued(&port.socket, SYN);
        let peer = UdpPort::take_fresh(&port)
            .expect("the socket reads")
            .expect("the share of the peer whose InitSyn came");
        let mut buf = [0u8; 64];
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((SYN.len(), PEER))));
        assert_eq!(spare(&port).len(), 1, "the read gave its buffer back");
        let mut held = None;
        for round in 0..3 {
            queued(&port.socket, b"put");
            // The listener's look takes the datagram off the socket and holds it for the link.
            assert!(UdpPort::take_fresh(&port)
                .expect("the socket reads")
                .is_none());
            assert!(
                spare(&port).is_empty(),
                "round {round}: the datagram is held in the spare buffer"
            );
            assert_eq!(peer.try_recv(&mut buf), Ok(Some((3, PEER))));
            assert_eq!(&buf[..3], b"put");
            let at = spare(&port)[0];
            assert_eq!(
                *held.get_or_insert(at),
                at,
                "round {round}: the same buffer"
            );
        }
    }

    /// A port of the test's socket over a source the test lent.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    type LentPort = UdpPort<Loop, OneTask, Option<LentPorts>>;

    /// A port of the test's socket over the heap's memory.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    type HeapPort = UdpPort<Loop, OneTask, HeapPorts>;

    /// The buffers of its own a port keeps for the next datagram, by where each lies.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    fn spare(port: &HeapPort) -> Vec<*const u8> {
        port.with_reads(|reads| {
            reads
                .rx
                .spare
                .iter()
                .map(|buffer| buffer.as_ptr())
                .collect()
        })
    }

    /// A heap with no room for the book a port keeps its peers in is answered: the book is the
    /// bytes of its cell, and a port of its own is none, and the program goes on. Turned red by a
    /// book made over a cell the heap cannot refuse, which ends the process, or by a refusal
    /// that names other bytes than the book's cell.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_book_the_heap_has_no_room_for_is_refused_and_named() {
        let source = HeapPorts::sized(1, 1, 64);
        let refused =
            crate::table_tests::refused(|| shared_book::<OneTask, HeapPorts>(source).err());
        assert_eq!(
            refused,
            Some(<SharedBook<OneTask, HeapPorts>>::cell_bytes_of())
        );
        let socket = Loop::default();
        let port = crate::table_tests::refused(|| HeapPort::new(socket, source).is_none());
        assert!(port, "a port with no book is no port");
        assert!(
            matches!(shared_book::<OneTask, HeapPorts>(source), Ok(Some(_))),
            "CONTROL: a heap with room makes the book"
        );
    }

    /// A source no session sized, and one a session lent nothing, give no book and no port, so a
    /// port's memory is always what a session stated. Turned red by a book made for an unsized
    /// source, which would hold rows and buffers no session counted. The CONTROL is the heap's
    /// source sized, which gives a port.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_source_no_session_sized_or_lent_gives_no_port() {
        assert!(matches!(
            shared_book::<OneTask, HeapPorts>(HeapPorts::default()),
            Ok(None)
        ));
        assert!(HeapPort::new(Loop::default(), HeapPorts::default()).is_none());
        assert!(matches!(
            shared_book::<OneTask, Option<LentPorts>>(None),
            Ok(None)
        ));
        assert!(LentPort::new(Loop::default(), None).is_none());
        assert!(
            HeapPort::new(Loop::default(), HeapPorts::sized(1, 1, 64)).is_some(),
            "CONTROL: a sized source gives a port"
        );
    }

    /// `port` behind its first handle, as a listener holds it.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    fn shared<S: DatagramSocket, P: PortSource<Cell<bool>>>(
        port: UdpPort<S, OneTask, P>,
    ) -> CellRc<UdpPort<S, OneTask, P>> {
        CellRc::try_on_heap(port).expect("the heap has room")
    }

    /// A port whose stack counts a link's handles across threads is shared, with the links of its
    /// peers, by handles another thread may hold, given a socket another thread may use, over
    /// lent memory and the heap's alike. Turned red by a port whose book or reads are cells
    /// whatever its count (an `Rc<RefCell<..>>`), or whose slots are flagged as cells.
    #[cfg(all(
        feature = "udp-listen",
        not(feature = "session-slot"),
        target_has_atomic = "8"
    ))]
    #[test]
    fn a_port_counted_across_threads_is_shared_by_handles_that_cross_threads() {
        use crate::link_cells::Atomic;
        fn crosses<T: Send + Sync>() {}
        crosses::<CellRc<UdpPort<NoDatagram, Atomic>, Atomic>>();
        crosses::<PortPeer<NoDatagram, Atomic>>();
        crosses::<SharedBook<Atomic, <Atomic as CountKind>::Ports>>();
        crosses::<CellRc<UdpPort<NoDatagram, Atomic, HeapPorts>, Atomic>>();
        crosses::<PortPeer<NoDatagram, Atomic, HeapPorts>>();
        crosses::<SharedBook<Atomic, HeapPorts>>();
    }

    /// A port over slots its session lent reads each datagram into one and holds it there for its
    /// peer's link, the next read taking another slot; with none free it drops the datagram and
    /// counts it, and reads into the same slot again. A slot the link read goes back to the table,
    /// and a port the table has no slot free for is not opened. The CONTROL is the same datagrams
    /// over the heap's memory, which holds both.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_port_over_lent_slots_drops_a_datagram_it_has_no_slot_for() {
        let mut buf = [0u8; 64];

        let own = shared(
            HeapPort::new(Loop::default(), HeapPorts::sized(1, 2, 64)).expect("the heap has room"),
        );
        queued(&own.socket, SYN);
        let peer = UdpPort::take_fresh(&own)
            .expect("the socket reads")
            .expect("the share of the peer");
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((SYN.len(), PEER))));
        queued(&own.socket, b"one");
        queued(&own.socket, b"two");
        assert!(UdpPort::take_fresh(&own)
            .expect("the socket reads")
            .is_none());
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((3, PEER))));
        assert_eq!(&buf[..3], b"one");
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((3, PEER))));
        assert_eq!(&buf[..3], b"two", "CONTROL: held in buffers of the heap");
        assert_eq!(own.overflows(), 0);

        let (ports, table) = leaked_ports(1, 2, 64);
        let book = shared_book::<OneTask, Option<LentPorts>>(Some(ports))
            .expect("the heap has room")
            .expect("a book over what was lent");
        let lent = shared(LentPort::in_book(Loop::default(), &book).expect("a slot to read into"));
        assert_eq!(table.in_use(), 1, "the slot read into");
        queued(&lent.socket, SYN);
        let peer = UdpPort::take_fresh(&lent)
            .expect("the socket reads")
            .expect("the share of the peer");
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((SYN.len(), PEER))));
        assert_eq!(
            table.in_use(),
            1,
            "the slot the InitSyn was held in went back"
        );
        queued(&lent.socket, b"one");
        queued(&lent.socket, b"two");
        assert!(UdpPort::take_fresh(&lent)
            .expect("the socket reads")
            .is_none());
        assert_eq!(table.in_use(), 2, "one held, one read into");
        assert_eq!(lent.overflows(), 1, "no slot was free to hold the second");
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((3, PEER))));
        assert_eq!(&buf[..3], b"one");
        assert_eq!(table.in_use(), 1, "the slot read went back");
        assert_eq!(peer.try_recv(&mut buf), Ok(None), "the second was dropped");

        let _last = table.claim().expect("the table's last slot");
        assert!(
            LentPort::in_book(Loop::default(), &book).is_none(),
            "a table with no slot free gives no port"
        );
    }

    /// A peer's row counts the datagrams that wait for it: each one queued, a peer the port took
    /// or not, and each one read, in the order they came; the reads and the backlog ask the row.
    /// Turned red by a count the queue does not move, or a read that takes another peer's.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_peers_row_counts_what_waits_for_it() {
        let other = SocketAddr::from(([192, 0, 2, 9], 7447));
        let mut rows = PortRows::<OnUse, Vec<u8>>::counted(2, 4);
        assert_eq!(
            rows.queued_for(0, PEER),
            None,
            "CONTROL: a peer the port did not take"
        );
        assert!(!rows.holds_for(0, PEER));
        assert!(rows.take(0, PEER, b"syn".to_vec()));
        assert!(rows.take(0, other, b"theirs".to_vec()));
        assert!(rows.enqueue(0, PEER, b"two".to_vec()));
        assert_eq!(rows.queued_for(0, PEER), Some(2));
        assert_eq!(
            rows.queued_for(1, PEER),
            None,
            "the same peer on another port"
        );
        assert_eq!(rows.take_for(0, PEER).as_deref(), Some(&b"syn"[..]));
        assert_eq!(rows.take_for(0, PEER).as_deref(), Some(&b"two"[..]));
        assert_eq!(rows.queued_for(0, PEER), Some(0));
        assert!(!rows.holds_for(0, PEER));
        assert_eq!(rows.take_for(0, PEER), None);
        assert!(
            rows.holds_for(0, other),
            "the other peer's datagram waits still"
        );
        rows.forget(0, other);
        assert_eq!(rows.queued_for(0, other), None);
        assert_eq!(rows.take_for(0, other), None);
    }

    /// Rows counted for the heap take no memory until the first peer, then all of each count at
    /// once, and refuse a peer or a datagram past it as lent rows past theirs do. Turned red by
    /// rows that take their memory with the book, or that grow past what the session stated.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn heap_rows_take_their_counts_at_the_first_peer_and_no_more() {
        let other = SocketAddr::from(([192, 0, 2, 9], 7447));
        let mut rows = PortRows::<OnUse, Vec<u8>>::counted(1, 2);
        assert!(
            !rows.peers.holds_rows() && !rows.queue.holds_rows(),
            "no memory before a peer"
        );
        assert!(rows.take(0, PEER, b"syn".to_vec()));
        assert!(rows.peers.holds_rows() && rows.queue.holds_rows());
        assert!(
            !rows.take(0, other, b"theirs".to_vec()),
            "a peer past the count"
        );
        assert!(rows.enqueue(0, PEER, b"two".to_vec()));
        assert!(
            !rows.enqueue(0, PEER, b"three".to_vec()),
            "a datagram past the count"
        );
        assert_eq!(rows.queued_for(0, PEER), Some(2));
    }

    /// A heap that refuses the memory to hold a datagram in has the port drop it and count it,
    /// and the program goes on: the next `InitSyn`, with room, opens the link. Turned red by a
    /// buffer the heap cannot refuse, which ends the process.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_datagram_the_heap_has_no_room_for_is_dropped_and_counted() {
        let port = shared(
            HeapPort::new(Loop::default(), HeapPorts::sized(1, 2, 64)).expect("the heap has room"),
        );
        queued(&port.socket, SYN);
        let taken =
            crate::table_tests::refused(|| UdpPort::take_fresh(&port).map(|peer| peer.is_none()));
        assert_eq!(taken, Ok(true), "no memory to hold the InitSyn in");
        assert_eq!(port.overflows(), 1);
        queued(&port.socket, SYN);
        assert!(
            UdpPort::take_fresh(&port)
                .expect("the socket reads")
                .is_some(),
            "CONTROL: the heap has room again"
        );
    }

    /// The allocations each of three rounds makes in which a peer sends two datagrams that its
    /// port sorts and its link reads, after the peer's `InitSyn` was taken and read.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    fn rounds_made<P: PortSource<Cell<bool>>>(
        port: &CellRc<UdpPort<Loop, OneTask, P>>,
    ) -> [usize; 3] {
        use crate::table_tests::allocations;

        let mut buf = [0u8; 64];
        queued(&port.socket, SYN);
        let peer = UdpPort::take_fresh(port)
            .expect("the socket reads")
            .expect("the share of the peer whose InitSyn came");
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((SYN.len(), PEER))));
        let mut made = [0; 3];
        for (round, made) in made.iter_mut().enumerate() {
            // The test's socket keeps what it is given on the heap: queued outside the count.
            queued(&port.socket, b"one");
            queued(&port.socket, b"two");
            let (fresh, sorted) = allocations(|| UdpPort::take_fresh(port).map(|p| p.is_none()));
            assert_eq!(fresh, Ok(true), "round {round}: no new peer");
            let (first, read_first) = allocations(|| peer.try_recv(&mut buf));
            assert_eq!(first, Ok(Some((3, PEER))));
            assert_eq!(&buf[..3], b"one", "round {round}: in the order they came");
            let (second, read_second) = allocations(|| peer.try_recv(&mut buf));
            assert_eq!(second, Ok(Some((3, PEER))));
            assert_eq!(&buf[..3], b"two", "round {round}: in the order they came");
            *made = sorted + read_first + read_second;
        }
        assert_eq!(port.overflows(), 0, "every datagram was held");
        made
    }

    /// A port over the slots and the rows its session lent reads, sorts and hands a peer's link its
    /// datagrams with no allocation, every round from the first after the peer's `InitSyn`: each
    /// datagram is read into a slot and held there, its row is a row of the lent queue, and the
    /// slot goes back to the table as the link reads it. The CONTROL is the same rounds over the
    /// heap's memory, whose first round allocates while the peer's backlog grows past the one
    /// buffer the `InitSyn`'s read gave back, so the count sees what a port allocates.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn a_port_over_lent_memory_sorts_a_peers_datagrams_without_the_heap() {
        let (ports, table) = leaked_ports(1, 3, 64);
        let book = shared_book::<OneTask, Option<LentPorts>>(Some(ports))
            .expect("the heap has room")
            .expect("a book over what was lent");
        let lent = shared(LentPort::in_book(Loop::default(), &book).expect("a slot to read into"));
        assert_eq!(
            rounds_made(&lent),
            [0; 3],
            "a port over lent slots and rows costs the heap nothing"
        );
        assert_eq!(table.in_use(), 1, "only the slot the next read goes into");

        let own = shared(
            HeapPort::new(Loop::default(), HeapPorts::sized(1, 4, 64)).expect("the heap has room"),
        );
        assert!(
            rounds_made(&own)[0] > 0,
            "CONTROL: a backlog past the buffers a port of its own kept allocates"
        );
    }

    /// Two ports of one stack over `source`, which holds one peer: a peer of the second port is
    /// not taken while the first port's peer holds the row, its `InitSyn` counted as an overflow,
    /// and is taken once that peer's link goes.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    fn one_peer_row_serves_two_ports<P: PortSource<Cell<bool>>>(source: P) {
        let book = shared_book::<OneTask, P>(source)
            .expect("the heap has room")
            .expect("a book");
        let first =
            shared(UdpPort::<Loop, OneTask, P>::in_book(Loop::default(), &book).expect("reads"));
        let second =
            shared(UdpPort::<Loop, OneTask, P>::in_book(Loop::default(), &book).expect("reads"));
        let mut buf = [0u8; 64];

        queued(&first.socket, SYN);
        let peer = UdpPort::take_fresh(&first)
            .expect("the socket reads")
            .expect("the one peer the rows hold");
        queued_from(&second.socket, SYN, Sender::Stranger);
        assert!(
            UdpPort::take_fresh(&second)
                .expect("the socket reads")
                .is_none(),
            "no row left for a peer of the other port"
        );
        assert_eq!(second.overflows(), 1);
        assert_eq!(peer.try_recv(&mut buf), Ok(Some((SYN.len(), PEER))));
        drop(peer);
        queued_from(&second.socket, SYN, Sender::Stranger);
        assert!(
            UdpPort::take_fresh(&second)
                .expect("the socket reads")
                .is_some(),
            "the row the first peer held"
        );
    }

    /// The ports of one stack share the rows of its book, lent or counted on the heap, and take no
    /// peer past them, the row a peer held serving the next once its link goes. The CONTROL is a
    /// book of two peers, which takes the second.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn ports_share_their_rows_and_take_no_peer_past_them() {
        let (ports, _slots) = leaked_ports(1, 4, 64);
        one_peer_row_serves_two_ports(Some(ports));
        one_peer_row_serves_two_ports(HeapPorts::sized(1, 4, 64));

        let own = shared(
            HeapPort::new(Loop::default(), HeapPorts::sized(2, 4, 64)).expect("the heap has room"),
        );
        queued(&own.socket, SYN);
        let _first = UdpPort::take_fresh(&own)
            .expect("the socket reads")
            .expect("a peer");
        queued_from(&own.socket, SYN, Sender::Stranger);
        assert!(
            UdpPort::take_fresh(&own)
                .expect("the socket reads")
                .is_some(),
            "CONTROL: rows of two peers take a second"
        );
    }

    /// A link over a socket of its own and one over a port's peer's share are one driver type
    /// (`LinkSocket`), each kind reading its own datagrams: the own socket's off the socket, the
    /// share's as its port sorted them. A share answers for itself where the port's socket would
    /// answer otherwise: it has no blocking read and no receive timeout of its own, so its link
    /// waits the tick and the port's socket is never armed for it. Turned red by a kind that reads
    /// through the other's path, or by a share that forwards a timeout to its port's socket.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    #[test]
    fn one_driver_reads_a_socket_of_its_own_and_a_ports_share_alike() {
        fn link(socket: LinkSocket<Loop>) -> UdpDriver<LinkSocket<Loop>, Vec<u8>, HeapTx> {
            UdpDriver::initiator_with_buffers(socket, PEER, 64, HeapTx::new(2, 32))
        }

        fn armable() -> Loop {
            Loop {
                timeouts: true,
                can_arm: true,
                ..Loop::default()
            }
        }

        let socket = armable();
        queued(&socket, b"own");
        let own = link(LinkSocket::Own(socket));
        assert_eq!(received(&own).as_deref(), Some(&b"own"[..]));
        assert!(own.socket.times_out(), "the socket's own answer");
        assert!(own.socket.set_receive_timeout(8), "the socket's own answer");

        let (ports, _slots) = leaked_ports(1, 4, 64);
        let book = shared_book::<OneTask, Option<LentPorts>>(Some(ports))
            .expect("the heap has room")
            .expect("a book over what was lent");
        let port = shared(LentPort::in_book(armable(), &book).expect("a slot to read into"));
        queued(&port.socket, SYN);
        let share = UdpPort::take_fresh(&port)
            .expect("the socket reads")
            .expect("the share of the peer whose InitSyn came");
        let shared_link = link(LinkSocket::Port(share));
        assert_eq!(received(&shared_link).as_deref(), Some(SYN));
        queued(&port.socket, b"put");
        assert_eq!(received(&shared_link).as_deref(), Some(&b"put"[..]));
        assert!(
            !shared_link.socket.times_out(),
            "a share reads what was sorted"
        );
        assert!(!shared_link.socket.set_receive_timeout(8));
        assert!(
            !port.socket.arms.borrow().contains(&8),
            "the port's socket is not armed for one peer"
        );
    }

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
                let locator = Locator::ip(proto, at);
                let printed = std::format!("{}/{at}", proto.scheme());
                assert_eq!(locator.text().finish(), Ok(printed.as_str()));
                assert_eq!(std::format!("{locator}"), printed);
            }
        }
        let ends = LinkEnds::ip(
            LinkProto::Udp.kind(),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 4000)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 7447)),
        )
        .endpoints()
        .expect("a short IPv6 pair is held");
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
            let v4 = std::format!("{}", Locator::ip(proto, widest_v4));
            let v6 = std::format!("{}", Locator::ip(proto, widest_v6));
            assert_eq!(v4.len(), LONGEST_IPV4_LOCATOR_LEN, "{v4}");
            assert_eq!(v6.len(), LONGEST_IP_LOCATOR_LEN, "{v6}");
            assert_eq!(
                Locator::ip(proto, widest_v4).text().finish(),
                Ok(v4.as_str())
            );
        }
        let ends = LinkEnds::ip(LinkProto::Udp.kind(), widest_v4, widest_v4)
            .endpoints()
            .expect("every IPv4 pair is held");
        assert_eq!(ends.dst.as_str(), "udp/255.255.255.255:65535");
    }

    /// The text of every IP locator is written whole, the longest IPv6 end too, and a link is
    /// admitted exactly when the bound of the build's pair of locators holds both its ends: every
    /// link where the pair states no bound, and under a bound every IPv4 link and an IPv6 one as
    /// its text's length says (the widest one refused under a bound below it). Turned red by a
    /// text that cuts an end, by a bound applied where the pair states none (a build of a short
    /// `MAX_LOCATOR_LEN` without `session-slot` refusing the widest IPv6 link), or by an
    /// admission that answers otherwise than the length.
    #[test]
    fn a_link_is_admitted_exactly_when_its_pairs_bound_holds_both_ends() {
        use crate::session_drive::LONGEST_IP_LOCATOR_LEN;
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
        let short_v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 7447));
        for proto in [LinkProto::Udp, LinkProto::Tcp, LinkProto::Tls] {
            let v6 = Locator::ip(proto, widest_v6).text();
            assert_eq!(v6.finish().map(str::len), Ok(LONGEST_IP_LOCATOR_LEN));
            assert!(
                ends_fit_within(None, proto, widest_v6, widest_v6),
                "no bound"
            );
            let short = Some(LONGEST_IP_LOCATOR_LEN - 1);
            assert!(
                ends_fit_within(short, proto, widest_v4, widest_v4),
                "every IPv4 link"
            );
            assert!(ends_fit_within(short, proto, short_v6, short_v6));
            assert!(!ends_fit_within(short, proto, widest_v4, widest_v6));
            assert!(!ends_fit_within(short, proto, widest_v6, widest_v4));
            assert!(ends_fit_within(
                Some(LONGEST_IP_LOCATOR_LEN),
                proto,
                widest_v6,
                widest_v6
            ));
            let fits = wz_session_core::link::LinkEndpoints::BOUND
                .is_none_or(|bound| LONGEST_IP_LOCATOR_LEN <= bound);
            assert!(ends_fit(proto, widest_v4, widest_v4), "every IPv4 link");
            assert_eq!(ends_fit(proto, widest_v4, widest_v6), fits);
            assert_eq!(ends_fit(proto, widest_v6, widest_v4), fits);
        }
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

        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        type Waits = crate::session_drive::NoWaits;

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

    /// The copying receive hands over what the lending one would, a datagram the last lend kept
    /// first, and holds nothing once it has read the queue out. Turned red by a copying receive
    /// that passes over a kept datagram or leaves it kept.
    #[cfg(feature = "alloc")]
    #[test]
    fn the_copying_receive_reads_what_the_lending_one_would() {
        let link = driver(Loop::default());
        queued(&link.socket, b"first");
        queued(&link.socket, b"second");
        assert!(link.recv_with(&mut |datagram| {
            assert_eq!(datagram, b"first");
            link.keep();
        }));
        assert!(link.holds_input(), "the lent datagram is kept");
        let kept = link.try_recv().expect("the kept datagram");
        assert_eq!(&kept.bytes[..], b"first");
        let next = link.try_recv().expect("the next datagram");
        assert_eq!(&next.bytes[..], b"second");
        assert!(link.try_recv().is_none(), "nothing is left to read");
        assert!(!link.holds_input(), "nothing is kept after the copy");
    }

    /// A receive asked from inside the lend finds the buffer lent and reads nothing, and the next
    /// datagram waits for the next receive. Turned red by a receive that borrows its buffer with
    /// `borrow_mut`, which panics there.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_receive_from_inside_the_lend_reads_nothing() {
        let link = driver(Loop::default());
        queued(&link.socket, b"first");
        queued(&link.socket, b"second");
        let mut inner = None;
        assert!(link.recv_with(&mut |_| inner = Some(received(&link))));
        assert_eq!(inner, Some(None), "the inner receive reads nothing");
        assert_eq!(received(&link).as_deref(), Some(&b"second"[..]));
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

    /// A datagram handed over as bytes is copied into a slot the link lends and sent from there:
    /// refused as one the link lends no slot for while the session holds every slot, refused as
    /// oversize past a slot with the slot given back, and sent once a slot is free. Turned red by a
    /// byte send that writes to the socket without a slot, or keeps the slot of an oversize one.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_datagram_of_bytes_is_sent_from_a_slot_the_link_lends() {
        let link = UdpDriver::initiator_with_buffers(Loop::default(), PEER, 64, HeapTx::new(1, 8));
        let held = link.tx_slot_acquire(4, Priority::Data).expect("the slot");
        assert_eq!(
            link.send_blocking(b"init", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        link.tx_slot_abort(held.slot);
        assert_eq!(
            link.send_blocking(b"nine bytes", Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::Oversize)
        );
        assert!(link.socket.sent.borrow().is_empty(), "nothing sent yet");
        assert_eq!(
            link.send_blocking(b"init", Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            link.socket.sent.borrow().as_slice(),
            &[(PEER, b"init".to_vec())]
        );
        assert!(
            link.tx_slot_acquire(4, Priority::Data).is_some(),
            "the slot is back once it is sent"
        );
    }

    /// A driver given no storage lends its session the slots it needs, each as long as what its
    /// buffer receives, and none past them while they are out. Turned red by a driver that lends
    /// fewer (`HeapTx::for_link` without its `max`).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_driver_given_no_storage_lends_its_sessions_slots_of_what_its_buffer_receives() {
        let link = UdpDriver::acceptor_with_capacity(Loop::default(), 64);
        let held = [(); SESSION_TX_SLOTS].map(|()| {
            link.tx_slot_acquire(10, Priority::Data)
                .expect("a slot its session needs")
        });
        for grant in &held {
            assert_eq!(link.tx_slot_storage(grant.slot).1, 64);
        }
        assert!(
            link.tx_slot_acquire(10, Priority::Data).is_none(),
            "none past them while they are out"
        );
        for grant in held {
            link.tx_slot_abort(grant.slot);
        }
        assert_eq!(link.link_mtu(), 64, "the bound is the slot");
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

    /// A link of a stack whose owner waits for every link, over a socket that always names its
    /// wait, waits in no loop of its own though nothing was set on it when it was made: its service
    /// and its service within a deadline leave the socket unasked, and it names its owner the
    /// socket's wait. The CONTROL is the same link of a stack whose links wait in their own loop,
    /// whose service waits the tick on its socket and which names its owner no wait. Turned red by
    /// a link that reads its stack's type as a loop's (`owner_waits_input` without
    /// `W::OWNER && S::NAMES_INPUT_WAIT`).
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_link_of_a_stack_its_owner_waits_for_has_no_wait_of_its_own() {
        use crate::session_drive::WaitedByOwner;

        /// The test's queues, as a socket that always names its wait for its link's owner.
        struct Named(Loop);

        impl DatagramSocket for Named {
            type Error = Refused;
            type Waits = crate::session_drive::NoWaits;
            const NAMES_INPUT_WAIT: bool = true;
            const CAN_SET_RECEIVE_TIMEOUT: bool = true;
            fn bind(_at: SocketAddr) -> Result<Self, Refused> {
                Ok(Named(Loop::default()))
            }
            fn local(&self) -> SocketAddr {
                self.0.local()
            }
            fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), Refused> {
                self.0.send_to(to, bytes)
            }
            fn wait_readable(&self, timeout_ms: c_int) {
                self.0.wait_readable(timeout_ms);
            }
            fn times_out(&self) -> bool {
                self.0.times_out()
            }
            fn set_receive_timeout(&self, ms: c_int) -> bool {
                self.0.set_receive_timeout(ms)
            }
            fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, Refused> {
                self.0.recv_waiting(buf)
            }
            fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, Refused> {
                self.0.try_recv(buf)
            }
            fn input_wait(&self) -> Option<WaitOn> {
                Some(WaitOn::Socket(5))
            }
        }

        let waiting = Loop {
            timeouts: true,
            can_arm: true,
            ..Loop::default()
        };
        let waited = UdpDriver::<_, Vec<u8>, HeapTx, WaitedByOwner>::with_peer(
            Named(waiting),
            Some(PEER),
            vec![0u8; 64],
            HeapTx::new(2, 32),
        )
        .with_idle_wait_ms(1000);
        waited.service();
        waited.service_within(1000);
        assert_eq!(waited.socket.0.waits.get(), 0, "no wait on the socket");
        assert_eq!(waited.socket.0.waiting_reads.get(), 0, "no read that waits");
        assert!(waited.socket.0.arms.borrow().is_empty(), "no timeout armed");
        assert!(
            matches!(waited.input_wait(), Some(WaitOn::Socket(5))),
            "the owner waits on the socket"
        );

        let looped = UdpDriver::<_, Vec<u8>, HeapTx, WaitsInLoop>::with_peer(
            Named(Loop::default()),
            Some(PEER),
            vec![0u8; 64],
            HeapTx::new(2, 32),
        );
        looped.service();
        assert_eq!(
            looped.socket.0.waits.get(),
            1,
            "CONTROL: a link of a stack whose links wait in their loop waits the tick"
        );
        assert!(
            looped.input_wait().is_none(),
            "CONTROL: and names its owner no wait"
        );
    }

    /// A link written where it lies is the link a value of it is, at the place it was handed: its
    /// peer, the datagram it receives whole, its tick and its loop's wait are those of a link made
    /// by value. Turned red by a field `with_peer_in` writes otherwise than `with_peer` did, or a
    /// driver answered from elsewhere than its place.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_link_written_where_it_lies_is_the_link_a_value_is() {
        let mut place = core::mem::MaybeUninit::<UdpDriver<Loop, Vec<u8>, HeapTx>>::uninit();
        let at = place.as_ptr();
        let link = UdpDriver::with_peer_in(
            &mut place,
            Loop::default(),
            Some(PEER),
            vec![0u8; 64],
            HeapTx::new(2, 32),
        );
        assert!(core::ptr::eq(link, at), "the link lies where it was handed");
        assert_eq!(link.peer(), Some(PEER));
        assert_eq!(link.link_rx_capacity(), 64);
        assert!(
            !link.uses_wake_budget(),
            "the tick, as a link made by value"
        );
        assert!(link.input_wait().is_none(), "its loop waits, not its owner");
        link.service();
        assert_eq!(link.socket.waits.get(), 1, "the loop's wait of the tick");
        // SAFETY: `with_peer_in` wrote the driver whole in `place`, dropped once, here.
        unsafe { place.assume_init_drop() };
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
