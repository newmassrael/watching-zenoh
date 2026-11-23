// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A platform's datagram and stream sockets as ONE network stack: a dial to `udp/...` opens the
//! datagram link (`udp_link`), a dial to `tcp/...` the stream link (`stream_link`), a dial to
//! `tls/...` the stream link over the secure channel the stack was given (`with_tls`; without one
//! it is unsupported). On the slot profile each is an [`IpDriver`], so a session slot holds one type
//! for all; on the heap profile each is the driver itself behind its own table (`HeapLink`).
//!
//! On the slot profile the stack is `IpStack`, whose links claim their buffers from the image's
//! tables and live in the session slots. On the heap profile it is `IpLinks`, the session shell's
//! `SessionLinks` over the same two sockets, whose links allocate their buffers when they open, or
//! claim them from the tables a session lays out in the memory it reserved when it opened
//! (`SessionLinks::lend_buffers`).
//!
//! A platform with both sockets (the host's) uses this stack; one with datagram sockets only uses
//! the datagram stack alone, which refuses a `tcp/` dial as unsupported. Which links an image can
//! dial is then the stack it names, not a flag beside it.

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::boxed::Box;
// The port a stack listens on is shared by its links.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use alloc::rc::Rc;
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use core::net::{IpAddr, SocketAddr};

use wz_session_core::byte_cells::ByteBuf;
#[cfg(feature = "session-slot")]
use wz_session_core::byte_cells::ByteSource;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::link::{
    BoxedLinkDriver, LinkEndpoints, LinkSendOutcome, LostCause, RoomAnswer, RoomWait, TxSlot,
    TxSlotGrant,
};
#[cfg(feature = "alloc")]
use wz_session_core::link::{LinkSubject, RxFrame};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
#[cfg(feature = "session-slot")]
use wz_session_core::session_slot::SlotDriver;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::group_transport::{GroupJoiner, GroupTransport, NoGroups};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_cells::CellRc;
use crate::link_storage::TxStore;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::{heap_link_buffers, LinkTables, RxBuffer, TxBuffer};
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
use crate::session_drive::RxLease;
use crate::session_drive::SessionDatagramLink;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::WaitOn;
#[cfg(feature = "session-slot")]
use crate::session_drive::{Accept, Bind, DriverPump, SlotStack};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::{Dialled, LinkListener, OpenedLink, PendingDial, SessionLinks};
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::session_drive::{LinkOpenError, LinkProto, Locator};
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::stream_link::link_over;
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::stream_link::NoDial;
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::stream_link::StreamDial;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::stream_link::StreamLink;
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::stream_link::StreamListen;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::stream_link::STREAM_RX_CAPACITY;
use crate::stream_link::{NoStream, StreamSocket};
#[cfg(feature = "session-slot")]
use crate::udp_link::UdpStack;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::udp_link::{bind_refused, dial_bind, UDP_RX_CAPACITY};
use crate::udp_link::{DatagramSocket, UdpDriver};
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
use crate::udp_link::{PortPeer, UdpPort};

/// The link of one session over a platform's datagram sockets `U`, its plain streams `T` and its
/// secure-channel streams `L`: a datagram, a stream or a secure stream link, as its dial named.
/// A stream link is the one its stream names ([`StreamSocket::Link`]), so on a stack that carries
/// no secure channel, whose `L` is [`NoStream`], the `tls/` case holds nothing. `B` holds its
/// receive buffer and `X` the memory it encodes its frames into, the image's byte tables by
/// default. The slot profile's link, a value in a session slot; the heap profile holds each driver
/// behind its own table instead ([`HeapLink`]).
// On a stack with no stream the `tcp/` and `tls/` cases are values of no size that cannot be
// made, so the enum is its `udp/` case alone; clippy weighs the variants by size and calls that a
// large difference. Boxing the datagram case would put the one live link on a heap the slot
// profile does not have.
#[allow(clippy::large_enum_variant)]
pub enum IpDriver<
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
    L: StreamSocket + 'static = NoStream,
    B: crate::link_storage::RxStore + 'static = ByteBuf,
    X: TxStore + 'static = ByteBuf,
> {
    /// A `udp/` link.
    Udp(UdpDriver<U, B, X>),
    /// A `tcp/` link.
    Tcp(T::Link<B, X>),
    /// A `tls/` link: the stream link over a secure channel.
    Tls(L::Link<B, X>),
}

/// A link of the heap profile's stack ([`IpLinks`]), as the session shell holds it: the datagram
/// or stream driver the dial named, behind one pointer, each call going through the driver's own
/// table and nothing else. The heap profile's sessions already reach their link through a table
/// (`Rc<dyn BoxedLinkDriver>`), so the slot profile's one type for every link, [`IpDriver`], would
/// be a second dispatch under the first there.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub type HeapLink = crate::link_cells::CellRc<dyn SessionDatagramLink>;

/// `driver` opened as the session shell holds a link: the session's actions send through it and
/// its loop pumps it, the one object behind both.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub(crate) fn heap_link<K>(
    cells: Option<&LentByteCells>,
    driver: K,
) -> Result<OpenedLink<HeapLink>, LinkOpenError>
where
    K: BoxedLinkDriver + SessionDatagramLink + 'static,
{
    // A session that lent its links cells places each in one: past them the link is refused, as
    // one past the session's buffers is, and none is placed on the heap.
    let driver =
        crate::link_cells::CellRc::in_cells(cells, driver).map_err(|_| LinkOpenError::Exhausted)?;
    Ok(OpenedLink {
        sink: driver.clone().into_sink(),
        pump: driver.into_link(),
    })
}

/// Every method of the three links, answered by the one this driver is.
macro_rules! either {
    ($self:ident, $link:ident => $body:expr) => {
        match $self {
            IpDriver::Udp($link) => $body,
            IpDriver::Tcp($link) => $body,
            IpDriver::Tls($link) => $body,
        }
    };
}

impl<U, T, L, B, X> BoxedLinkDriver for IpDriver<U, T, L, B, X>
where
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
    L: StreamSocket + 'static,
    B: crate::link_storage::RxStore + 'static,
    X: TxStore + 'static,
{
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        either!(self, link => link.send_blocking(bytes, reliability))
    }

    // Forwarded, or every session over this driver would find room on a stream that has none.
    fn wait_for_room(&self, priority: Priority, wait: RoomWait) -> RoomAnswer {
        either!(self, link => link.wait_for_room(priority, wait))
    }

    fn tx_slot_acquire(&self, want: usize, priority: Priority) -> Option<TxSlotGrant> {
        either!(self, link => link.tx_slot_acquire(want, priority))
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        either!(self, link => link.tx_slot_storage(slot))
    }

    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        reliability: Reliability,
        priority: Priority,
    ) -> LinkSendOutcome {
        either!(self, link => link.tx_slot_send(slot, start, len, reliability, priority))
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        either!(self, link => link.tx_slot_abort(slot))
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_spare(&self) -> bool {
        either!(self, link => link.tx_slot_spare())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn tx_slot_claimable(&self) -> bool {
        either!(self, link => link.tx_slot_claimable())
    }

    fn open_blocking(&self) {
        either!(self, link => link.open_blocking())
    }

    fn close_blocking(&self) {
        either!(self, link => link.close_blocking())
    }

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        either!(self, link => link.link_endpoints())
    }

    /// The kind of link it is, which a connectivity plane reports (whether the link is streamed,
    /// and how reliable). The NICs its address sits on are not resolved here, so they read as
    /// undetermined and not as none: an answer a link that does not ask the platform cannot give.
    #[cfg(feature = "alloc")]
    fn link_subject(&self) -> Option<&LinkSubject> {
        either!(self, link => link.link_subject())
    }

    fn peer_credential_zid(
        &self,
    ) -> Option<[u8; wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES]> {
        either!(self, link => link.peer_credential_zid())
    }

    fn batch_length_prefixed(&self) -> bool {
        either!(self, link => link.batch_length_prefixed())
    }

    fn link_mtu(&self) -> usize {
        either!(self, link => link.link_mtu())
    }

    fn link_rx_capacity(&self) -> usize {
        either!(self, link => link.link_rx_capacity())
    }
}

impl<U, T, L, B, X> SessionDatagramLink for IpDriver<U, T, L, B, X>
where
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
    L: StreamSocket + 'static,
    B: crate::link_storage::RxStore + 'static,
    X: TxStore + 'static,
{
    fn service(&self) {
        either!(self, link => link.service())
    }

    fn service_within(&self, max_wait_ms: u64) {
        either!(self, link => link.service_within(max_wait_ms))
    }

    fn uses_wake_budget(&self) -> bool {
        either!(self, link => link.uses_wake_budget())
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        either!(self, link => link.try_recv())
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        either!(self, link => link.recv_with(f))
    }

    fn lost(&self) -> Option<LostCause> {
        either!(self, link => link.lost())
    }

    fn holds_input(&self) -> bool {
        either!(self, link => link.holds_input())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        either!(self, link => link.waits_for_buffer())
    }

    fn owes_write(&self) -> bool {
        either!(self, link => link.owes_write())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        either!(self, link => link.write_owed_now())
    }

    fn takes_input(&self) -> bool {
        either!(self, link => link.takes_input())
    }

    fn keeps_input(&self) -> bool {
        either!(self, link => link.keeps_input())
    }

    fn keep(&self) {
        either!(self, link => link.keep())
    }

    fn lends_until_next_receive(&self) -> bool {
        either!(self, link => link.lends_until_next_receive())
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        either!(self, link => link.input_wait())
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn room_wait(&self) -> Option<WaitOn> {
        either!(self, link => link.room_wait())
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn lend_rx(&self) -> Option<RxLease> {
        either!(self, link => link.lend_rx())
    }

    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn land_rx(&self, lease: RxLease) {
        either!(self, link => link.land_rx(lease))
    }
}

/// A platform's datagram sockets `U` and the streams its dial `D` opens as the session shell's
/// links on the heap profile: what a node dials opens the link of the protocol it names, and what
/// it accepts on is a datagram link (a stream listener is not written yet). Each link allocates
/// its receive buffer when it opens, a datagram link's sized to the largest datagram and a stream
/// link's to the largest batch with its length, and lends the session `tx_slots` buffers of
/// `tx_capacity` bytes to encode its frames into (none by default: the session then builds each
/// frame in a buffer of its own). A session that lends the stack its tables
/// ([`SessionLinks::lend_buffers`]) has every link claim its buffers there instead, and none
/// allocate. A multicast group is joined by the host's joiner `G` ([`IpLinks::with_groups`]);
/// links given none join no group.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct IpLinks<U, D, L = NoDial, G = NoGroups> {
    local: IpAddr,
    dial: D,
    tls: L,
    groups: G,
    shape: LinkShape,
    datagrams: core::marker::PhantomData<fn() -> U>,
}

/// What every link of a stack is given besides its socket: the buffers its frames are encoded
/// into and whether its owner waits for its input. Held by the stack and copied to its listeners,
/// so a link taken off a port is shaped as one dialled.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
#[derive(Debug, Clone, Copy)]
struct LinkShape {
    tx_slots: usize,
    tx_capacity: usize,
    owner_waits: bool,
    /// The receive buffer of a datagram link: the largest datagram until the stack is told the
    /// largest batch its sessions receive ([`IpLinks::with_rx_capacity`]).
    datagram_rx: usize,
    /// The tables of the session the links serve, when it lent the stack some
    /// ([`SessionLinks::lend_buffers`]): every link claims its buffers there, and none allocates.
    lent: Option<LinkTables>,
    /// The cells of the session the links serve, when it lent the stack some
    /// ([`SessionLinks::lend_cells`]): every link is placed in one, and none on the heap.
    cells: Option<LentByteCells>,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl Default for LinkShape {
    fn default() -> Self {
        Self {
            tx_slots: 0,
            tx_capacity: 0,
            owner_waits: false,
            datagram_rx: UDP_RX_CAPACITY,
            lent: None,
            cells: None,
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl LinkShape {
    /// The buffers of a link that opens now, its own receive buffer `rx` bytes long: claimed from
    /// the session's tables when it lent some, and [`LinkOpenError::Exhausted`] when they have none
    /// left, so a session whose tables are full opens no link; allocated otherwise.
    fn buffers(&self, rx: usize) -> Result<(RxBuffer, TxBuffer), LinkOpenError> {
        heap_link_buffers(self.lent.as_ref(), rx, self.tx_slots, self.tx_capacity)
    }

    /// The stream link over the connected `socket`, over the buffers `rx` and `tx`, as the stack
    /// opens it: waited on by its owner when the shape says so.
    fn stream<S: StreamSocket + 'static>(
        &self,
        socket: S,
        rx: RxBuffer,
        tx: TxBuffer,
    ) -> S::Link<RxBuffer, TxBuffer> {
        let link = link_over(socket, rx, tx);
        if self.owner_waits {
            link.waited_by_owner()
        } else {
            link
        }
    }

    /// A datagram link as the stack opens it: waited on by its owner when the shape says so.
    fn datagram<U: DatagramSocket>(
        &self,
        link: UdpDriver<U, RxBuffer, TxBuffer>,
    ) -> UdpDriver<U, RxBuffer, TxBuffer> {
        if self.owner_waits {
            link.waited_by_owner()
        } else {
            link
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U, D> IpLinks<U, D>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
{
    /// Links bound on the node's own address `local` (the unspecified address of a family for
    /// every interface of the host), whose `tcp/` links run over the streams `dial` opens, and
    /// which carry no `tls/` link until [`IpLinks::with_tls`] gives them one. A dial to a peer of
    /// the other family binds the unspecified address of the peer's (`udp_link::dial_bind`).
    pub fn new(local: impl Into<IpAddr>, dial: D) -> Self {
        Self {
            local: local.into(),
            dial,
            tls: NoDial,
            groups: NoGroups,
            shape: LinkShape::default(),
            datagrams: core::marker::PhantomData,
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U, D, L, G> IpLinks<U, D, L, G>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
    G: GroupJoiner,
{
    /// The same links, whose `tls/` links run over the secure channels `tls` opens.
    pub fn with_tls<S: StreamDial>(self, tls: S) -> IpLinks<U, D, S, G> {
        IpLinks {
            local: self.local,
            dial: self.dial,
            tls,
            groups: self.groups,
            shape: self.shape,
            datagrams: self.datagrams,
        }
    }

    /// The same links, which join the multicast groups `groups` joins
    /// ([`SessionLinks::open_group`]).
    pub fn with_groups<J: GroupJoiner>(self, groups: J) -> IpLinks<U, D, L, J> {
        IpLinks {
            local: self.local,
            dial: self.dial,
            tls: self.tls,
            groups,
            shape: self.shape,
            datagrams: self.datagrams,
        }
    }

    /// Links whose owner waits for their input ([`SessionDatagramLink::input_wait`]): what holds a
    /// session behind a lock and waits for it outside the lock. Each link whose socket can be
    /// waited on that way does not wait in its loop; one whose socket cannot still does.
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.shape.owner_waits = true;
        self
    }

    /// Links that lend the session `slots` buffers of `bytes` each to encode its frames into, as
    /// a datagram stack's do: `bytes` is the batch the sessions negotiate, and a session that
    /// batches holds one slot open while it encodes into another, so it needs two.
    #[must_use]
    pub fn with_tx_buffers(mut self, slots: usize, bytes: usize) -> Self {
        self.shape.tx_slots = slots;
        self.shape.tx_capacity = bytes;
        self
    }

    /// Links whose datagram links receive into buffers of `bytes` each, in place of the largest
    /// datagram: the batch the sessions advertise, which no peer's batch exceeds once the two
    /// have negotiated, as zenoh-pico's UDP link reads into a buffer of its own batch size. A node
    /// with a small heap pays its batch a link and not 64 KiB. The figure is taken between one byte
    /// and the largest datagram; a stream link keeps the largest batch with its length, which its
    /// framing needs before the batch is known.
    #[must_use]
    pub fn with_rx_capacity(mut self, bytes: usize) -> Self {
        self.shape.datagram_rx = bytes.clamp(1, UDP_RX_CAPACITY);
        self
    }

    /// The receive buffer each datagram link of these links opens with.
    pub fn datagram_rx_capacity(&self) -> usize {
        self.shape.datagram_rx
    }

    /// The link of a dial to `to`, before it is shared. A stack that cannot make a socket, or
    /// whose session's tables have no buffers left, is [`LinkOpenError::Exhausted`]; a connection
    /// the other end does not take is [`LinkOpenError::Refused`]; a protocol the links do not
    /// carry (a `tls/` dial on links given no secure channel) is [`LinkOpenError::Unsupported`],
    /// before any buffer is claimed; buffers claimed before a refusal go back with it.
    pub fn dial(&self, to: Locator) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
        match to.proto {
            LinkProto::Udp if !U::CARRIED => Err(LinkOpenError::Unsupported),
            LinkProto::Udp => {
                let (rx, tx) = self.shape.buffers(self.shape.datagram_rx)?;
                // Port 0 has the stack choose a free one, one per initiator session.
                let socket = U::bind(dial_bind(self.local, to.at)).map_err(bind_refused::<U>)?;
                heap_link(
                    self.shape.cells.as_ref(),
                    self.shape
                        .datagram(UdpDriver::initiator_in(socket, to.at, rx, tx)),
                )
            }
            LinkProto::Tcp if !D::CARRIED => Err(LinkOpenError::Unsupported),
            LinkProto::Tcp => {
                let (rx, tx) = self.shape.buffers(STREAM_RX_CAPACITY)?;
                let socket = self.dial.dial(to.at)?;
                heap_link(self.shape.cells.as_ref(), self.shape.stream(socket, rx, tx))
            }
            LinkProto::Tls if !L::CARRIED => Err(LinkOpenError::Unsupported),
            LinkProto::Tls => {
                let (rx, tx) = self.shape.buffers(STREAM_RX_CAPACITY)?;
                let channel = self.tls.dial(to.at)?;
                heap_link(
                    self.shape.cells.as_ref(),
                    self.shape.stream(channel, rx, tx),
                )
            }
        }
    }
}

/// Whether a stack of datagram sockets `U`, plain streams `D` and secure channels `L` opens a
/// link to an IPv6 end: one protocol it carries does. What `Bind::IPV6` and `SessionLinks::IPV6`
/// answer for it.
#[cfg(any(feature = "session-slot", feature = "alloc"))]
const fn opens_ipv6<U: DatagramSocket, D: StreamDial, L: StreamDial>() -> bool {
    (U::CARRIED && U::IPV6) || (D::CARRIED && D::IPV6) || (L::CARRIED && L::IPV6)
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U, D, L, G> SessionLinks for IpLinks<U, D, L, G>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
    G: GroupJoiner,
{
    type Pump = HeapLink;

    type Dial = IpDial<D::Stream, L::Stream>;

    const IPV6: bool = opens_ipv6::<U, D, L>();

    // The waits of the platform whose sockets these are: its streams, the secure channels over
    // them and its groups name handles of the same platform as its datagram sockets do.
    type Waits = U::Waits;

    fn waits(&self) -> U::Waits {
        U::Waits::default()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        let (rx, tx) = self.shape.buffers(self.shape.datagram_rx)?;
        // The peer is whoever opens a session first; the driver is bound by its InitSyn.
        let socket = U::bind(SocketAddr::new(self.local, port)).map_err(bind_refused::<U>)?;
        heap_link(
            self.shape.cells.as_ref(),
            self.shape.datagram(UdpDriver::acceptor_in(socket, rx, tx)),
        )
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        self.dial(to)
    }

    /// Every link these links open from now on, dialled or taken off a port that is listened on
    /// after this, claims its buffers from `tables`.
    fn lend_buffers(&mut self, tables: LinkTables) {
        self.shape.lent = Some(tables);
    }

    /// The largest cell any link of these takes: a datagram link, a link of a `udp/` port's
    /// peer, a plain stream's and a secure channel's.
    fn link_cell_bytes(&self) -> usize {
        let datagram = CellRc::<UdpDriver<U, RxBuffer, TxBuffer>>::cell_bytes();
        #[cfg(feature = "udp-listen")]
        let datagram =
            datagram.max(CellRc::<UdpDriver<PortPeer<U>, RxBuffer, TxBuffer>>::cell_bytes());
        datagram
            .max(CellRc::<
                <D::Stream as StreamSocket>::Link<RxBuffer, TxBuffer>,
            >::cell_bytes())
            .max(CellRc::<
                <L::Stream as StreamSocket>::Link<RxBuffer, TxBuffer>,
            >::cell_bytes())
    }

    /// Every link these links open from now on, dialled or taken off a port that is listened on
    /// after this, is placed in a cell of `cells`.
    fn lend_cells(&mut self, cells: LentByteCells) {
        self.shape.cells = Some(cells);
    }

    /// A `tcp/` dial begins its connection and a `tls/` one its channel's (the connection under
    /// it, then its handshake), and each is asked for its stream later (`PendingStream`); a
    /// datagram link has no connection to wait for. A stream link's buffers are claimed as a
    /// dial's are, before the connection is begun, and held by the dial until its link is made: a
    /// refused or abandoned dial gives them back.
    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        match to.proto {
            LinkProto::Tcp if D::CARRIED => {
                let buffers = self.shape.buffers(STREAM_RX_CAPACITY)?;
                let socket = self.dial.dial_started(to.at)?;
                Ok(IpDial(IpDialing::Tcp(PendingStream {
                    socket: Some(socket),
                    buffers: Some(buffers),
                    shape: self.shape,
                })))
            }
            LinkProto::Tls if L::CARRIED => {
                let buffers = self.shape.buffers(STREAM_RX_CAPACITY)?;
                let channel = self.tls.dial_started(to.at)?;
                Ok(IpDial(IpDialing::Tls(PendingStream {
                    socket: Some(channel),
                    buffers: Some(buffers),
                    shape: self.shape,
                })))
            }
            _ => self.open_initiator(to).map(IpDial::from),
        }
    }

    /// A `tcp/` listener over the stack's stream dial, a `tls/` one over its secure channel's
    /// (the channel's own listening half, which completes each handshake before the link sees the
    /// connection), or, with `udp-listen`, a `udp/` one over one datagram socket, whose peers are
    /// told apart by the address each datagram came from (`UdpPort`).
    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<Self::Pump>>, LinkOpenError> {
        match at.proto {
            #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
            LinkProto::Udp if U::CARRIED => {
                let socket = U::bind(at.at).map_err(bind_refused::<U>)?;
                Ok(Box::new(IpUdpListener {
                    port: Rc::new(UdpPort::new(socket, self.shape.datagram_rx)),
                    shape: self.shape,
                }))
            }
            LinkProto::Tcp if D::CARRIED => {
                let listener = self.dial.listen(at.at)?;
                Ok(Box::new(IpListener {
                    listener,
                    shape: self.shape,
                }))
            }
            LinkProto::Tls if L::CARRIED => {
                let listener = self.tls.listen(at.at)?;
                Ok(Box::new(IpTlsListener {
                    listener,
                    shape: self.shape,
                }))
            }
            _ => Err(LinkOpenError::Unsupported),
        }
    }

    /// The group `endpoint` names, joined by the host's joiner the links were given
    /// ([`IpLinks::with_groups`]); links given none refuse it as unsupported.
    fn open_group(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        self.groups.join(endpoint)
    }

    /// A link of these is shared already: the pump is the handle the sink is a clone of.
    fn share_pump(pump: Self::Pump) -> crate::link_cells::CellRc<dyn SessionDatagramLink> {
        pump
    }
}

/// A dial of [`IpLinks`] ([`SessionLinks::begin_initiator`]): a link made when it was begun, or a
/// `tcp/` (`S`) or `tls/` (`T`) stream still being made.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct IpDial<S, T>(IpDialing<S, T>)
where
    S: StreamSocket + 'static,
    T: StreamSocket + 'static;

/// Where an [`IpDial`] stands: its link made, or a stream of either protocol being made.
// A dial is held by value in its face's link, a place the session's face table reserved, so a
// stream being made is not boxed to bring the made link's variant to its size: that would be an
// allocation for each dial.
#[allow(clippy::large_enum_variant)]
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
enum IpDialing<S, T>
where
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
{
    Made(Dialled<HeapLink>),
    Tcp(PendingStream<S>),
    Tls(PendingStream<T>),
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<S, T> PendingDial<HeapLink> for IpDial<S, T>
where
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink>, LinkOpenError>> {
        match &mut self.0 {
            IpDialing::Made(made) => made.poll(),
            IpDialing::Tcp(stream) => stream.poll(),
            IpDialing::Tls(stream) => stream.poll(),
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<S, T> From<OpenedLink<HeapLink>> for IpDial<S, T>
where
    S: StreamSocket + 'static,
    T: StreamSocket + 'static,
{
    fn from(opened: OpenedLink<HeapLink>) -> Self {
        Self(IpDialing::Made(Dialled::new(opened)))
    }
}

/// A stream dial whose stream `P` is being made (a `tcp/` connection, or a `tls/` channel's
/// connection and handshake): the link is made over the stream and the buffers claimed for it once
/// the stream says it is, shaped as the stack's links are.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
struct PendingStream<P: StreamSocket + 'static> {
    socket: Option<P>,
    buffers: Option<(RxBuffer, TxBuffer)>,
    shape: LinkShape,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<P: StreamSocket + 'static> PendingDial<HeapLink> for PendingStream<P> {
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink>, LinkOpenError>> {
        match self.socket.as_mut()?.connected() {
            Ok(false) => None,
            // The stack's own answer to the connect, or the channel's to its handshake: the other
            // end did not take the link.
            Err(_) => {
                self.socket = None;
                self.buffers = None;
                Some(Err(LinkOpenError::Refused))
            }
            Ok(true) => {
                let socket = self.socket.take()?;
                let (rx, tx) = self.buffers.take()?;
                Some(heap_link(
                    self.shape.cells.as_ref(),
                    self.shape.stream(socket, rx, tx),
                ))
            }
        }
    }
}

/// The accepting end of the `udp/` port a stack listens on: the one socket every peer that opens
/// a session sends to ([`UdpPort`]), which yields a link for each source whose `InitSyn` it takes,
/// shaped as the stack's links are and run as an acceptor's. The link's socket is the peer's share
/// of the port, so the session reads that peer's datagrams alone and its replies leave by the port
/// the peer sent to. Each link's buffers are claimed as a dialled link's are, from the session's
/// tables when it lent the stack some; the port's own read buffer and the datagrams it sorts for
/// each peer are the heap's either way.
#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
struct IpUdpListener<U: DatagramSocket> {
    port: Rc<UdpPort<U>>,
    shape: LinkShape,
}

#[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
impl<U: DatagramSocket + 'static> LinkListener<HeapLink> for IpUdpListener<U> {
    fn local(&self) -> Locator {
        Locator::udp(self.port.local())
    }

    /// A socket that failed to read is looked at again on the next call, as a stack with no
    /// buffer for a connection is: UDP has no connection to lose, and a datagram the next read
    /// takes is sorted as any other.
    fn accept(&self) -> Result<Option<OpenedLink<HeapLink>>, LinkOpenError> {
        let Some(share) = UdpPort::take_fresh(&self.port).map_err(|_| LinkOpenError::Exhausted)?
        else {
            return Ok(None);
        };
        // The port told this source apart from the others, so the link's remote end is known from
        // the start, as a dialled link's is; the session over it still runs as the acceptor.
        let peer = share.peer();
        // As the `tcp/` listener's: the source is off the port before the buffers are claimed, so
        // one the session's tables have none left for is let go of, not left waiting.
        let (rx, tx) = self.shape.buffers(self.shape.datagram_rx)?;
        heap_link(
            self.shape.cells.as_ref(),
            self.shape
                .datagram(UdpDriver::initiator_in(share, peer, rx, tx)),
        )
        .map(Some)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.port.input_wait()
    }
}

/// The accepting end of the `tls/` port a stack listens on: what [`IpListener`] is for `tcp/`,
/// over the secure channel's streams `T`. A connection it yields has completed its handshake, so
/// the link above runs the session's own handshake over a stream whose peer the channel accepted.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
struct IpTlsListener<T: StreamSocket> {
    listener: Box<dyn StreamListen<Stream = T>>,
    shape: LinkShape,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<T: StreamSocket + 'static> LinkListener<HeapLink> for IpTlsListener<T> {
    fn local(&self) -> Locator {
        Locator::tls(self.listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink>>, LinkOpenError> {
        let Some(channel) = self.listener.accept()? else {
            return Ok(None);
        };
        // As the `tcp/` listener's: the connection is off the port before the buffers are claimed,
        // so one the session's tables have none left for is closed, not left queued.
        let (rx, tx) = self.shape.buffers(STREAM_RX_CAPACITY)?;
        heap_link(
            self.shape.cells.as_ref(),
            self.shape.stream(channel, rx, tx),
        )
        .map(Some)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.listener.input_wait()
    }
}

/// The accepting end of the `tcp/` port a stack listens on: the connections on its streams `S`
/// yield the same link a dial does, shaped as the stack's links are, so a session opened over one
/// is run as one over a dialled link, and the acceptor's role is the handshake's alone.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
struct IpListener<S: StreamSocket> {
    listener: Box<dyn StreamListen<Stream = S>>,
    shape: LinkShape,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<S: StreamSocket + 'static> LinkListener<HeapLink> for IpListener<S> {
    fn local(&self) -> Locator {
        Locator::tcp(self.listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink>>, LinkOpenError> {
        let Some(stream) = self.listener.accept()? else {
            return Ok(None);
        };
        // The connection is off the port before the buffers are claimed, so one the session's
        // tables have none left for is closed, not left queued, as `IpAcceptor` closes it.
        let (rx, tx) = self.shape.buffers(STREAM_RX_CAPACITY)?;
        heap_link(self.shape.cells.as_ref(), self.shape.stream(stream, rx, tx)).map(Some)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.listener.input_wait()
    }
}

/// A platform's datagram sockets `U` and the streams its dial `D` opens as one stack of the slot
/// profile's session host. Each link it opens claims its receive buffer and the buffer its frames
/// are encoded into from the two tables the image declares, whichever protocol it speaks: a
/// stream link's receive buffer holds a batch with its length, so the tables are sized for that.
#[cfg(feature = "session-slot")]
pub struct IpStack<U, D, L = NoDial> {
    udp: UdpStack<U>,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    dial: D,
    tls: L,
}

// Not derived: a derive would ask `U: Clone`, and the stack holds no socket.
#[cfg(feature = "session-slot")]
impl<U, D: Copy, L: Copy> Clone for IpStack<U, D, L> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "session-slot")]
impl<U, D: Copy, L: Copy> Copy for IpStack<U, D, L> {}

#[cfg(feature = "session-slot")]
impl<U, D> IpStack<U, D>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
{
    /// The stack of a node whose own address is `local`, whose links take their receive buffers
    /// from `rx` and their frame buffers from `tx`, whose `tcp/` links run over the streams `dial`
    /// opens, and which carries no `tls/` link until [`IpStack::with_tls`] gives it one.
    pub const fn new(
        local: IpAddr,
        rx: &'static dyn ByteSource,
        tx: &'static dyn ByteSource,
        dial: D,
    ) -> Self {
        Self {
            udp: UdpStack::new(local, rx, tx),
            rx,
            tx,
            dial,
            tls: NoDial,
        }
    }
}

#[cfg(feature = "session-slot")]
impl<U, D, L> IpStack<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
{
    /// The same stack, whose `tls/` links run over the secure channels `tls` opens.
    pub fn with_tls<S: StreamDial>(self, tls: S) -> IpStack<U, D, S> {
        IpStack {
            udp: self.udp,
            rx: self.rx,
            tx: self.tx,
            dial: self.dial,
            tls,
        }
    }

    /// Let the datagram links of this stack wait up to `ms` milliseconds when their session has
    /// nothing due sooner (`UdpStack::with_idle_wait_ms`). A stream link waits the loop's tick.
    #[must_use]
    pub const fn with_idle_wait_ms(mut self, ms: u32) -> Self {
        self.udp = self.udp.with_idle_wait_ms(ms);
        self
    }

    /// The link of a dial to `to`. A table with no buffer free is [`LinkOpenError::Exhausted`]; a
    /// connection the other end does not take is [`LinkOpenError::Refused`]; a `tls/` dial on a
    /// stack given no secure channel is [`LinkOpenError::Unsupported`], before any buffer is
    /// claimed; whatever was claimed before a refusal goes back with it.
    pub fn bind_initiator(
        &self,
        to: Locator,
    ) -> Result<IpDriver<U, D::Stream, L::Stream>, LinkOpenError> {
        let mut out = core::mem::MaybeUninit::uninit();
        self.bind_initiator_in(to, &mut out)?;
        // SAFETY: `bind_initiator_in` answered `Ok`, so it wrote `out`.
        Ok(unsafe { out.assume_init() })
    }

    /// [`Self::bind_initiator`], written into `out`, the place the driver is kept: `out` is
    /// written exactly when `Ok` is answered, and the driver is built there, so a stream link's
    /// (its buffers' handles and the frames it owes its stream) is no value of the caller's
    /// frame, beneath which a `tls/` dial runs its handshake.
    pub fn bind_initiator_in(
        &self,
        to: Locator,
        out: &mut core::mem::MaybeUninit<IpDriver<U, D::Stream, L::Stream>>,
    ) -> Result<(), LinkOpenError> {
        match to.proto {
            LinkProto::Udp if !U::CARRIED => return Err(LinkOpenError::Unsupported),
            LinkProto::Udp => {
                out.write(IpDriver::Udp(self.udp.bind_initiator(to.at)?));
            }
            LinkProto::Tcp => {
                let (rx, tx) = self.claim()?;
                let socket = self.dial.dial(to.at)?;
                out.write(IpDriver::Tcp(link_over(socket, rx, tx)));
            }
            LinkProto::Tls if !L::CARRIED => return Err(LinkOpenError::Unsupported),
            LinkProto::Tls => {
                let (rx, tx) = self.claim()?;
                let channel = self.tls.dial(to.at)?;
                out.write(IpDriver::Tls(link_over(channel, rx, tx)));
            }
        }
        Ok(())
    }

    /// A stream link's receive buffer and frame buffer from the image's tables.
    fn claim(&self) -> Result<(ByteBuf, ByteBuf), LinkOpenError> {
        let rx = self.rx.claim().ok_or(LinkOpenError::Exhausted)?;
        let tx = self.tx.claim().ok_or(LinkOpenError::Exhausted)?;
        Ok((rx, tx))
    }
}

#[cfg(feature = "session-slot")]
impl<U, D, L> Bind<IpDriver<U, D::Stream, L::Stream>> for IpStack<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
{
    const IPV6: bool = opens_ipv6::<U, D, L>();

    fn bind(&mut self, to: Locator) -> Result<IpDriver<U, D::Stream, L::Stream>, LinkOpenError> {
        self.bind_initiator(to)
    }

    fn bind_in(
        &mut self,
        to: Locator,
        out: &mut core::mem::MaybeUninit<IpDriver<U, D::Stream, L::Stream>>,
    ) -> Result<(), LinkOpenError> {
        self.bind_initiator_in(to, out)
    }
}

/// The listening half of an [`IpStack`]: the port a node accepts `tcp/` connections on, and the
/// tables each accepted link takes its buffers from. It is made by [`IpStack::acceptor`] and
/// yields the same [`IpDriver`] a dial does, over the stream the listener accepted.
#[cfg(feature = "session-slot")]
pub struct IpAcceptor<A, U, L = NoStream> {
    listener: A,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    refused: u32,
    stack: core::marker::PhantomData<fn() -> (U, L)>,
}

#[cfg(feature = "session-slot")]
impl<A, U, L> IpAcceptor<A, U, L> {
    /// Connections taken off the port and closed at once because the tables had no buffer left
    /// for a link: the node was full.
    pub const fn refused(&self) -> u32 {
        self.refused
    }

    /// The address and port the listener is bound to.
    pub fn local(&self) -> SocketAddr
    where
        A: StreamListen,
    {
        self.listener.local()
    }
}

#[cfg(feature = "session-slot")]
impl<A, U, L> Accept<IpDriver<U, A::Stream, L>> for IpAcceptor<A, U, L>
where
    A: StreamListen,
    A::Stream: 'static,
    U: DatagramSocket + 'static,
    L: StreamSocket + 'static,
{
    fn accept(&mut self) -> Result<Option<IpDriver<U, A::Stream, L>>, LinkOpenError> {
        // The connection comes off the port before the buffers are claimed, so a node with a full
        // table closes it rather than leave it queued: its peer sees the close, not a handshake
        // that never starts, and a poll that finds no connection claims nothing.
        let Some(stream) = self.listener.accept()? else {
            return Ok(None);
        };
        let (Some(rx), Some(tx)) = (self.rx.claim(), self.tx.claim()) else {
            self.refused = self.refused.saturating_add(1);
            return Err(LinkOpenError::Exhausted);
        };
        Ok(Some(IpDriver::Tcp(link_over(stream, rx, tx))))
    }
}

/// The listening half of an [`IpStack`] for `tls/` connections: the port a node accepts secure
/// channels on. It is made by [`IpStack::tls_acceptor`] over a listener whose accept completes the
/// channel's handshake (`wz-tls-mbedtls`'s `TlsListener`), so a stream it yields is a secure
/// channel whose peer has proved its key, and it yields the stack's `tls/` link, which is what a
/// `tls/` dial opens. [`IpAcceptor`] is its plain twin.
#[cfg(feature = "session-slot")]
pub struct IpTlsAcceptor<A, U, T = NoStream> {
    listener: A,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    refused: u32,
    stack: core::marker::PhantomData<fn() -> (U, T)>,
}

#[cfg(feature = "session-slot")]
impl<A, U, T> IpTlsAcceptor<A, U, T> {
    /// Connections taken off the port and closed at once because the tables had no buffer left
    /// for a link: the node was full.
    pub const fn refused(&self) -> u32 {
        self.refused
    }

    /// The address and port the listener is bound to.
    pub fn local(&self) -> SocketAddr
    where
        A: StreamListen,
    {
        self.listener.local()
    }
}

#[cfg(feature = "session-slot")]
impl<A, U, T> Accept<IpDriver<U, T, A::Stream>> for IpTlsAcceptor<A, U, T>
where
    A: StreamListen,
    A::Stream: 'static,
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
{
    fn accept(&mut self) -> Result<Option<IpDriver<U, T, A::Stream>>, LinkOpenError> {
        // As [`IpAcceptor`]: the connection comes off the port before the buffers are claimed, so
        // a full node closes it, and a poll that finds none claims nothing.
        let Some(stream) = self.listener.accept()? else {
            return Ok(None);
        };
        let (Some(rx), Some(tx)) = (self.rx.claim(), self.tx.claim()) else {
            self.refused = self.refused.saturating_add(1);
            return Err(LinkOpenError::Exhausted);
        };
        Ok(Some(IpDriver::Tls(link_over(stream, rx, tx))))
    }
}

#[cfg(feature = "session-slot")]
impl<U, D, L> IpStack<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
{
    /// The acceptor of the connections `listener` takes, whose links claim their buffers from the
    /// tables of this stack. The stream a listener yields is the stream a dial does, so a link
    /// over it is the one a dial opens and the session host runs it unchanged.
    pub fn acceptor<A>(&self, listener: A) -> IpAcceptor<A, U, L::Stream>
    where
        A: StreamListen<Stream = D::Stream>,
    {
        IpAcceptor {
            listener,
            rx: self.rx,
            tx: self.tx,
            refused: 0,
            stack: core::marker::PhantomData,
        }
    }

    /// The acceptor of the secure channels `listener` completes, whose links claim their buffers
    /// from the tables of this stack. The stream such a listener yields is the stream the stack's
    /// secure dial does, so a link over it is the `tls/` link a dial opens, and carries the zid
    /// the peer's key proved (`StreamSocket::peer_credential_zid`).
    pub fn tls_acceptor<A>(&self, listener: A) -> IpTlsAcceptor<A, U, D::Stream>
    where
        A: StreamListen<Stream = L::Stream>,
    {
        IpTlsAcceptor {
            listener,
            rx: self.rx,
            tx: self.tx,
            refused: 0,
            stack: core::marker::PhantomData,
        }
    }
}

#[cfg(feature = "session-slot")]
impl<U, D, L> SlotStack for IpStack<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial + 'static,
    D::Stream: 'static,
    L: StreamDial + 'static,
    L::Stream: 'static,
{
    type Driver = IpDriver<U, D::Stream, L::Stream>;
    type Pump = DriverPump<IpDriver<U, D::Stream, L::Stream>>;
    type Lane = ();

    fn pump(
        &self,
        driver: SlotDriver<IpDriver<U, D::Stream, L::Stream>>,
        _lane: Option<()>,
    ) -> Self::Pump {
        DriverPump(driver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_int;
    #[cfg(feature = "session-slot")]
    use wz_session_core::byte_cells::ByteCells;

    use core::net::{Ipv4Addr, Ipv6Addr};

    use crate::udp_link::Received;

    /// A datagram socket that takes everything and has nothing to read, bound where it was asked
    /// to be (port 0: 40001). `V6` false is a stack without IPv6, whose bind of an IPv6 address is
    /// refused for its family ([`DatagramSocket::refuses_address`]).
    struct Datagrams<const V6: bool = true>(SocketAddr);

    /// Why a [`Datagrams`] bind failed: the address was IPv6 and the stack has none.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct NoIpv6;

    impl<const V6: bool> DatagramSocket for Datagrams<V6> {
        type Error = NoIpv6;
        #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
        type Waits = crate::session_drive::NoWaits;
        const IPV6: bool = V6;
        fn bind(at: SocketAddr) -> Result<Self, NoIpv6> {
            if at.is_ipv6() && !V6 {
                return Err(NoIpv6);
            }
            let port = if at.port() == 0 { 40_001 } else { at.port() };
            Ok(Self(SocketAddr::new(at.ip(), port)))
        }
        fn local(&self) -> SocketAddr {
            self.0
        }
        fn send_to(&self, _to: SocketAddr, _bytes: &[u8]) -> Result<(), NoIpv6> {
            Ok(())
        }
        // The one failure this socket has is the family it lacks.
        fn refuses_address(error: &NoIpv6) -> bool {
            let NoIpv6 = *error;
            true
        }
        fn wait_readable(&self, _timeout_ms: c_int) {}
        fn times_out(&self) -> bool {
            false
        }
        fn recv_waiting(&self, _buf: &mut [u8]) -> Result<Option<Received>, NoIpv6> {
            Ok(None)
        }
        fn try_recv(&self, _buf: &mut [u8]) -> Result<Option<Received>, NoIpv6> {
            Ok(None)
        }
    }

    /// A stream connected to `peer`, which takes everything and has nothing to read.
    struct Stream(SocketAddr);

    /// A dial that connects to any port but [`REFUSING`].
    #[derive(Clone, Copy)]
    struct Dial;

    const REFUSING: u16 = 9;

    impl StreamDial for Dial {
        type Stream = Stream;
        fn dial(&self, to: SocketAddr) -> Result<Stream, LinkOpenError> {
            if to.port() == REFUSING {
                Err(LinkOpenError::Refused)
            } else {
                Ok(Stream(to))
            }
        }
    }

    impl StreamSocket for Stream {
        type Error = ();

        type Link<
            B: crate::link_storage::RxStore + 'static,
            X: crate::link_storage::TxStore + 'static,
        >
            = crate::stream_link::StreamDriver<Self, B, X>
        where
            Self: 'static;

        /// The node's own end, of the peer's family.
        fn local(&self) -> SocketAddr {
            match self.0 {
                SocketAddr::V4(_) => SocketAddr::from(([10, 0, 0, 2], 40_002)),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, 40_002)),
            }
        }
        fn peer(&self) -> SocketAddr {
            self.0
        }
        fn send_parts(&self, _parts: &[&[u8]]) -> Result<(), ()> {
            Ok(())
        }
        fn wait_readable(&self, _timeout_ms: c_int) {}
        fn try_read(&self, _buf: &mut [u8]) -> Result<Option<usize>, ()> {
            Ok(None)
        }
        fn shutdown(&self) {}
    }

    /// A secure channel over a [`Stream`], as far as the stack sees one: a stream that names
    /// itself `tls/`.
    struct Channel(Stream);

    /// The dial of [`Channel`]s.
    #[derive(Clone, Copy)]
    struct ChannelDial;

    impl StreamDial for ChannelDial {
        type Stream = Channel;
        fn dial(&self, to: SocketAddr) -> Result<Channel, LinkOpenError> {
            Dial.dial(to).map(Channel)
        }
    }

    impl StreamSocket for Channel {
        type Error = ();

        type Link<
            B: crate::link_storage::RxStore + 'static,
            X: crate::link_storage::TxStore + 'static,
        >
            = crate::stream_link::StreamDriver<Self, B, X>
        where
            Self: 'static;

        const PROTO: LinkProto = LinkProto::Tls;
        fn local(&self) -> SocketAddr {
            self.0.local()
        }
        fn peer(&self) -> SocketAddr {
            self.0.peer()
        }
        fn send_parts(&self, parts: &[&[u8]]) -> Result<(), ()> {
            self.0.send_parts(parts)
        }
        fn wait_readable(&self, timeout_ms: c_int) {
            self.0.wait_readable(timeout_ms)
        }
        fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
            self.0.try_read(buf)
        }
        fn shutdown(&self) {
            self.0.shutdown()
        }
        fn peer_credential_zid(&self) -> Option<[u8; 16]> {
            Some(PROVEN)
        }
    }

    /// The zid of the key every [`Channel`]'s peer proved.
    const PROVEN: [u8; 16] = [0x5e; 16];

    const ROUTER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7447);

    /// The same router's port at an IPv6 address.
    const ROUTER_V6: SocketAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)), 7447);

    /// The node's own IPv4 address.
    const NODE: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    /// A port on the router that refuses every connection.
    const fn refusing() -> SocketAddr {
        SocketAddr::new(ROUTER.ip(), REFUSING)
    }

    /// The constant a stack's endpoints are read by, through a function so that the assertions
    /// below are on its answer and not on a constant.
    #[cfg(feature = "session-slot")]
    fn bind_opens_ipv6<D, B: Bind<D>>() -> bool {
        B::IPV6
    }

    /// A stack opens a link to an IPv6 end when one protocol it carries does, and a stack of
    /// sockets without IPv6 does not: an endpoint read for it is read as IPv4 alone.
    #[cfg(any(feature = "session-slot", feature = "alloc"))]
    #[test]
    fn a_stack_opens_ipv6_when_a_protocol_it_carries_does() {
        assert!(opens_ipv6::<Datagrams<true>, NoDial, NoDial>());
        assert!(!opens_ipv6::<Datagrams<false>, NoDial, NoDial>());
        assert!(
            opens_ipv6::<Datagrams<false>, Dial, NoDial>(),
            "its plain streams reach IPv6 where its datagrams do not"
        );
        assert!(
            !opens_ipv6::<crate::udp_link::NoDatagram, NoDial, NoDial>(),
            "a stack that carries nothing opens nothing"
        );
        #[cfg(feature = "session-slot")]
        {
            assert!(!bind_opens_ipv6::<
                IpDriver<Datagrams<false>, NoStream>,
                IpStack<Datagrams<false>, NoDial>,
            >());
            assert!(bind_opens_ipv6::<
                IpDriver<Datagrams<false>, Stream>,
                IpStack<Datagrams<false>, Dial>,
            >());
            // A stack of datagram sockets alone answers as its socket does.
            assert!(bind_opens_ipv6::<
                crate::udp_link::FixedUdpDriver<Datagrams<true>>,
                UdpStack<Datagrams<true>>,
            >());
            assert!(!bind_opens_ipv6::<
                crate::udp_link::FixedUdpDriver<Datagrams<false>>,
                UdpStack<Datagrams<false>>,
            >());
        }
    }

    #[cfg(feature = "session-slot")]
    static TLS_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static TLS_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_tls_dial_opens_the_stream_link_over_the_channel_the_stack_was_given() {
        let mut stack =
            IpStack::<Datagrams, Dial>::new(NODE, &TLS_RX, &TLS_TX, Dial).with_tls(ChannelDial);
        let tls = stack
            .bind(Locator::tls(ROUTER))
            .expect("a secure stream link");
        assert!(matches!(tls, IpDriver::Tls(_)));
        assert!(
            tls.batch_length_prefixed(),
            "the channel carries the stream framing"
        );
        let ends = tls.link_endpoints().expect("a connection knows both ends");
        assert_eq!(ends.dst.as_str(), "tls/10.0.0.1:7447");
        assert_eq!(ends.src.as_str(), "tls/10.0.0.2:40002");
        assert_eq!(
            tls.peer_credential_zid(),
            Some(PROVEN),
            "the session reads the key the channel's peer proved"
        );
        drop(tls);
        let tcp = stack
            .bind(Locator::tcp(ROUTER))
            .expect("a plain stream link");
        assert_eq!(
            tcp.peer_credential_zid(),
            None,
            "a plain connection proves nobody"
        );
    }

    #[cfg(feature = "session-slot")]
    static IN_PLACE_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static IN_PLACE_TX: ByteCells<34, 1> = ByteCells::new();

    /// A dial written into the place it is kept is the link a returned dial is; one the tables
    /// refuse leaves the place unwritten, and the place is written once the buffers come back.
    #[cfg(feature = "session-slot")]
    #[test]
    fn a_dial_written_in_place_is_the_link_a_returned_dial_is() {
        let mut stack = IpStack::<Datagrams, Dial>::new(NODE, &IN_PLACE_RX, &IN_PLACE_TX, Dial)
            .with_tls(ChannelDial);
        let mut place = core::mem::MaybeUninit::uninit();
        stack
            .bind_in(Locator::tls(ROUTER), &mut place)
            .expect("a secure stream link");
        // SAFETY: `bind_in` answered `Ok`, so it wrote the place.
        let tls = unsafe { place.assume_init() };
        assert!(matches!(tls, IpDriver::Tls(_)));
        assert_eq!(tls.peer_credential_zid(), Some(PROVEN));
        let mut next = core::mem::MaybeUninit::uninit();
        assert!(
            matches!(
                stack.bind_in(Locator::tcp(ROUTER), &mut next),
                Err(LinkOpenError::Exhausted)
            ),
            "the one receive buffer is the secure link's"
        );
        drop(tls);
        stack
            .bind_in(Locator::tcp(ROUTER), &mut next)
            .expect("the buffers came back with the link");
        // SAFETY: as above.
        let tcp = unsafe { next.assume_init() };
        assert!(matches!(tcp, IpDriver::Tcp(_)));
    }

    #[cfg(feature = "session-slot")]
    static PLAIN_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static PLAIN_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_stack_given_no_channel_refuses_tls_as_unsupported_even_with_its_tables_full() {
        let mut stack = IpStack::<Datagrams, Dial>::new(NODE, &PLAIN_RX, &PLAIN_TX, Dial);
        let held = stack
            .bind(Locator::tcp(ROUTER))
            .expect("the one stream link");
        assert!(
            matches!(
                stack.bind(Locator::tls(ROUTER)),
                Err(LinkOpenError::Unsupported)
            ),
            "permanent for the endpoint, not a full table to retry"
        );
        drop(held);
        assert!(matches!(
            stack.bind(Locator::tls(ROUTER)),
            Err(LinkOpenError::Unsupported)
        ));
    }

    #[cfg(feature = "session-slot")]
    static RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_dial_opens_the_link_of_the_protocol_it_names() {
        let mut stack = IpStack::<Datagrams, Dial>::new(NODE, &RX, &TX, Dial);
        let udp = stack.bind(Locator::udp(ROUTER)).expect("a datagram link");
        assert!(matches!(udp, IpDriver::Udp(_)));
        assert!(!udp.batch_length_prefixed());
        assert_eq!(
            udp.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("udp/10.0.0.1:7447")
        );
        drop(udp);
        let tcp = stack.bind(Locator::tcp(ROUTER)).expect("a stream link");
        assert!(matches!(tcp, IpDriver::Tcp(_)));
        assert!(tcp.batch_length_prefixed(), "a stream frames its batches");
        assert_eq!(
            tcp.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("tcp/10.0.0.1:7447")
        );
        assert_eq!(tcp.link_rx_capacity(), 66);
        assert_eq!(
            tcp.link_mtu(),
            34,
            "a whole slot: the length is counted in the batch"
        );
    }

    #[cfg(feature = "session-slot")]
    static V6_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static V6_TX: ByteCells<34, 1> = ByteCells::new();

    /// The slot profile's dial to an IPv6 locator: a datagram link over a socket of the peer's
    /// family, a stream link to the same end, each naming its ends in brackets; a stack without
    /// IPv6 refuses it as unsupported and gives back what it claimed.
    #[cfg(feature = "session-slot")]
    #[test]
    fn a_dial_to_an_ipv6_locator_opens_a_socket_of_its_family() {
        let mut stack = IpStack::<Datagrams, Dial>::new(NODE, &V6_RX, &V6_TX, Dial);
        let udp = stack
            .bind(Locator::udp(ROUTER_V6))
            .expect("a datagram link");
        let ends = udp
            .link_endpoints()
            .expect("a dialled link knows both ends");
        assert_eq!(ends.src.as_str(), "udp/[::]:40001");
        assert_eq!(ends.dst.as_str(), "udp/[fd00::1]:7447");
        drop(udp);
        let tcp = stack.bind(Locator::tcp(ROUTER_V6)).expect("a stream link");
        assert_eq!(
            tcp.link_endpoints().map(|ends| ends.src.as_str()),
            Some("tcp/[::1]:40002")
        );
        drop(tcp);

        let mut v4_only = IpStack::<Datagrams<false>, Dial>::new(NODE, &V6_RX, &V6_TX, Dial);
        assert!(matches!(
            v4_only.bind(Locator::udp(ROUTER_V6)),
            Err(LinkOpenError::Unsupported)
        ));
        assert!(
            v4_only.bind(Locator::udp(ROUTER)).is_ok(),
            "the refused dial gave both buffers back"
        );
    }

    #[cfg(feature = "session-slot")]
    static REFUSED_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static REFUSED_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_refused_connection_is_refused_and_gives_its_buffers_back() {
        let mut stack = IpStack::<Datagrams, Dial>::new(NODE, &REFUSED_RX, &REFUSED_TX, Dial);
        assert!(matches!(
            stack.bind(Locator::tcp(refusing())),
            Err(LinkOpenError::Refused)
        ));
        let open = stack
            .bind(Locator::tcp(ROUTER))
            .expect("both buffers came back");
        assert!(matches!(
            stack.bind(Locator::udp(ROUTER)),
            Err(LinkOpenError::Exhausted)
        ));
        drop(open);
    }

    /// A listener with `waiting` connections queued, each from `peer`, or one that is broken.
    #[cfg(feature = "session-slot")]
    struct Listener {
        waiting: core::cell::Cell<u8>,
        peer: SocketAddr,
        broken: bool,
    }

    /// Where a [`Listener`] listens.
    #[cfg(feature = "session-slot")]
    const LISTENING: SocketAddr = SocketAddr::new(NODE, 7447);

    #[cfg(feature = "session-slot")]
    impl Listener {
        fn with_waiting(waiting: u8) -> Self {
            Self {
                waiting: core::cell::Cell::new(waiting),
                peer: SocketAddr::from(([10, 0, 0, 7], 52_000)),
                broken: false,
            }
        }
    }

    #[cfg(feature = "session-slot")]
    impl StreamListen for Listener {
        type Stream = Stream;
        fn local(&self) -> SocketAddr {
            LISTENING
        }
        fn accept(&self) -> Result<Option<Stream>, LinkOpenError> {
            if self.broken {
                return Err(LinkOpenError::Unsupported);
            }
            match self.waiting.get() {
                0 => Ok(None),
                left => {
                    self.waiting.set(left - 1);
                    Ok(Some(Stream(self.peer)))
                }
            }
        }
    }

    #[cfg(feature = "session-slot")]
    static ACCEPT_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static ACCEPT_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn an_accepted_connection_is_the_stream_link_a_dial_opens() {
        let stack = IpStack::<Datagrams, Dial>::new(NODE, &ACCEPT_RX, &ACCEPT_TX, Dial);
        let mut acceptor = stack.acceptor(Listener::with_waiting(1));
        assert_eq!(acceptor.local(), LISTENING);
        let link: IpDriver<Datagrams, Stream, NoStream> = acceptor
            .accept()
            .expect("the port is sound")
            .expect("a connection waited");
        assert!(matches!(link, IpDriver::Tcp(_)));
        assert!(link.batch_length_prefixed(), "a stream frames its batches");
        let ends = link.link_endpoints().expect("a connection knows both ends");
        assert_eq!(ends.dst.as_str(), "tcp/10.0.0.7:52000");
        assert_eq!(ends.src.as_str(), "tcp/10.0.0.2:40002");
        assert_eq!(link.link_rx_capacity(), 66);
        assert_eq!(acceptor.refused(), 0);
    }

    #[cfg(feature = "session-slot")]
    static SECURE_ACCEPT_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static SECURE_ACCEPT_TX: ByteCells<34, 1> = ByteCells::new();

    /// The secure listener's connection is the stack's `tls/` link, not its `tcp/` one: the
    /// session host runs the driver the stack names, and that is the variant a `tls/` dial opens.
    #[cfg(feature = "session-slot")]
    #[test]
    fn an_accepted_secure_channel_is_the_tls_link_a_dial_opens() {
        let stack =
            IpStack::<Datagrams, Dial>::new(NODE, &SECURE_ACCEPT_RX, &SECURE_ACCEPT_TX, Dial)
                .with_tls(Dial);
        let mut acceptor = stack.tls_acceptor(Listener::with_waiting(2));
        assert_eq!(acceptor.local(), LISTENING);
        let link: IpDriver<Datagrams, Stream, Stream> = acceptor
            .accept()
            .expect("the port is sound")
            .expect("a connection waited");
        assert!(matches!(link, IpDriver::Tls(_)));
        assert!(link.batch_length_prefixed(), "a stream frames its batches");
        assert_eq!(link.link_rx_capacity(), 66);
        assert_eq!(acceptor.refused(), 0);
        let full: Result<Option<IpDriver<Datagrams, Stream, Stream>>, _> = acceptor.accept();
        assert!(
            matches!(full, Err(LinkOpenError::Exhausted)),
            "one buffer pair, and the first link holds it"
        );
        assert_eq!(
            acceptor.refused(),
            1,
            "a full node counts the one it closed"
        );
        drop(link);
        let quiet: Result<Option<IpDriver<Datagrams, Stream, Stream>>, _> = acceptor.accept();
        assert!(
            matches!(quiet, Ok(None)),
            "the refused connection was taken off the port, not left queued"
        );
    }

    #[cfg(feature = "session-slot")]
    static IDLE_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static IDLE_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_poll_that_finds_no_connection_claims_no_buffer() {
        let mut stack = IpStack::<Datagrams, Dial>::new(NODE, &IDLE_RX, &IDLE_TX, Dial);
        let mut acceptor = stack.acceptor(Listener::with_waiting(0));
        for _ in 0..3 {
            let none: Result<Option<IpDriver<Datagrams, Stream, NoStream>>, _> = acceptor.accept();
            assert!(matches!(none, Ok(None)));
        }
        let open = stack
            .bind(Locator::tcp(ROUTER))
            .expect("the polls left both buffers in the tables");
        drop(open);
    }

    #[cfg(feature = "session-slot")]
    static FULL_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static FULL_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_connection_with_no_buffer_for_it_is_taken_off_the_port_and_counted() {
        let stack = IpStack::<Datagrams, Dial>::new(NODE, &FULL_RX, &FULL_TX, Dial);
        let mut acceptor = stack.acceptor(Listener::with_waiting(3));
        let held: IpDriver<Datagrams, Stream, NoStream> = acceptor
            .accept()
            .expect("a free table")
            .expect("a connection waited");
        let second: Result<Option<IpDriver<Datagrams, Stream, NoStream>>, _> = acceptor.accept();
        assert!(
            matches!(second, Err(LinkOpenError::Exhausted)),
            "the table is full"
        );
        assert_eq!(acceptor.refused(), 1);
        drop(held);
        let third: IpDriver<Datagrams, Stream, NoStream> = acceptor
            .accept()
            .expect("the buffers came back")
            .expect("the third connection still waited, the second was not left queued");
        assert!(matches!(third, IpDriver::Tcp(_)));
        assert_eq!(
            acceptor.refused(),
            1,
            "an accepted connection is not a refusal"
        );
    }

    #[cfg(feature = "session-slot")]
    static BROKEN_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static BROKEN_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_broken_listener_is_reported_as_it_is() {
        let stack = IpStack::<Datagrams, Dial>::new(NODE, &BROKEN_RX, &BROKEN_TX, Dial);
        let mut acceptor = stack.acceptor(Listener {
            broken: true,
            ..Listener::with_waiting(1)
        });
        let broken: Result<Option<IpDriver<Datagrams, Stream, NoStream>>, _> = acceptor.accept();
        assert!(matches!(broken, Err(LinkOpenError::Unsupported)));
        assert_eq!(acceptor.refused(), 0);
    }

    /// The kind of link a heap stack opened, as the link names it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn kind(
        link: &crate::link_cells::CellRc<dyn BoxedLinkDriver>,
    ) -> Option<wz_session_core::link::LinkKind> {
        link.link_subject().and_then(|subject| subject.kind)
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_dial_opens_the_link_of_the_protocol_it_names() {
        let links = IpLinks::<Datagrams, Dial>::new(NODE, Dial).with_tx_buffers(2, 34);
        let udp = links
            .open_initiator(Locator::udp(ROUTER))
            .expect("a datagram link")
            .sink;
        assert_eq!(kind(&udp), Some(wz_session_core::link::LinkKind::Udp));
        assert!(!udp.batch_length_prefixed());
        assert_eq!(
            udp.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("udp/10.0.0.1:7447")
        );
        let tcp = links
            .open_initiator(Locator::tcp(ROUTER))
            .expect("a stream link")
            .sink;
        assert_eq!(kind(&tcp), Some(wz_session_core::link::LinkKind::Tcp));
        assert!(tcp.batch_length_prefixed(), "a stream frames its batches");
        assert_eq!(
            tcp.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("tcp/10.0.0.1:7447")
        );
        assert_eq!(
            tcp.link_mtu(),
            34,
            "a whole lent buffer: the length is counted in the batch"
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_dial_the_other_end_refuses_is_refused() {
        let links = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        assert!(matches!(
            links.open_initiator(Locator::tcp(refusing())),
            Err(LinkOpenError::Refused)
        ));
    }

    /// A stack that joins no group answers a group endpoint as unsupported, the seam's default,
    /// which is the refusal a session over it names the group by.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_that_join_no_group_refuse_a_group_endpoint() {
        let links = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        assert!(matches!(
            links.open_group("udp/239.1.2.3:7447#iface=lo"),
            Err(LinkOpenError::Unsupported)
        ));
    }

    /// Links given a joiner hand it the group endpoint as the config states it and answer what it
    /// answers: the group it joined, or its refusal. The secure channel given after it keeps it.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_given_a_joiner_join_the_group_it_joins() {
        use alloc::string::String;
        use alloc::vec::Vec;
        use core::cell::RefCell;

        /// A group that carries nothing, for the joiner below to hand out.
        struct Quiet;
        impl GroupTransport for Quiet {
            fn open(&mut self) -> bool {
                true
            }
            fn close(&mut self) {}
            fn service(&self) {}
            fn carrier_up(&self) -> bool {
                true
            }
            fn send_to_group(&mut self, _datagram: &[u8]) {}
            fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
                false
            }
        }

        /// Joins the one group it names, and records every endpoint it was asked for.
        struct Joiner {
            asked: RefCell<Vec<String>>,
        }
        impl GroupJoiner for Joiner {
            fn join(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
                self.asked.borrow_mut().push(endpoint.into());
                if endpoint.starts_with("udp/239.1.2.3:7447") {
                    Ok(Box::new(Quiet))
                } else {
                    Err(LinkOpenError::Refused)
                }
            }
        }

        let links = IpLinks::<Datagrams, Dial>::new(NODE, Dial)
            .with_groups(Joiner {
                asked: RefCell::new(Vec::new()),
            })
            .with_tls(Dial);
        let mut joined = links
            .open_group("udp/239.1.2.3:7447#iface=lo")
            .expect("the joiner joins the group it names");
        assert!(joined.open());
        assert!(matches!(
            links.open_group("udp/239.9.9.9:7447#iface=lo"),
            Err(LinkOpenError::Refused)
        ));
        assert_eq!(
            *links.groups.asked.borrow(),
            ["udp/239.1.2.3:7447#iface=lo", "udp/239.9.9.9:7447#iface=lo"],
            "each endpoint reaches the joiner as written"
        );
    }

    /// An IPv6 locator dials over a socket of its family on a node whose own address is IPv4:
    /// the datagram link binds the unspecified IPv6 address and names its ends in brackets, the
    /// stream link names its peer the same way. A stack without IPv6 refuses the datagram dial as
    /// unsupported, permanent for the locator, and not as a socket it has none of now.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_dial_to_an_ipv6_locator_opens_a_socket_of_its_family() {
        let links = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        let udp = links
            .open_initiator(Locator::udp(ROUTER_V6))
            .expect("a datagram link")
            .sink;
        let ends = udp
            .link_endpoints()
            .expect("a dialled link knows both ends");
        assert_eq!(ends.src.as_str(), "udp/[::]:40001");
        assert_eq!(ends.dst.as_str(), "udp/[fd00::1]:7447");
        let tcp = links
            .open_initiator(Locator::tcp(ROUTER_V6))
            .expect("a stream link")
            .sink;
        assert_eq!(
            tcp.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("tcp/[fd00::1]:7447")
        );

        let v4_only = IpLinks::<Datagrams<false>, Dial>::new(NODE, Dial);
        assert!(matches!(
            v4_only.open_initiator(Locator::udp(ROUTER_V6)),
            Err(LinkOpenError::Unsupported)
        ));
        assert!(
            v4_only.open_initiator(Locator::udp(ROUTER)).is_ok(),
            "the family it has still dials"
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_dial_tls_only_over_the_channel_they_were_given() {
        let plain = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        assert!(matches!(
            plain.open_initiator(Locator::tls(ROUTER)),
            Err(LinkOpenError::Unsupported)
        ));
        let secure = plain.with_tls(ChannelDial);
        let tls = secure
            .open_initiator(Locator::tls(ROUTER))
            .expect("a secure stream link")
            .sink;
        assert_eq!(kind(&tls), Some(wz_session_core::link::LinkKind::Tls));
        assert_eq!(
            tls.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("tls/10.0.0.1:7447")
        );
        assert_eq!(tls.peer_credential_zid(), Some(PROVEN));
    }

    /// A `tls/` dial is begun and asked, never waited for: while the channel is still opening the
    /// begun dial answers nothing however often it is asked, and holds the link's buffers; once
    /// the channel is made it answers the secure stream link, once; a channel whose opening fails
    /// is refused and gives its buffers back. The channel's waiting dial is never called.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_tls_dial_is_begun_and_asked_never_waited_for() {
        use alloc::rc::Rc;
        use core::cell::Cell;
        use wz_session_core::bounded::{Arena, ARENA_ALIGN};

        /// A secure channel whose opening the test answers: still opening while `answer` is
        /// `None`, made at `Some(true)`, failed at `Some(false)`.
        struct Handshaking {
            channel: Channel,
            answer: Rc<Cell<Option<bool>>>,
        }

        impl StreamSocket for Handshaking {
            type Error = ();

            type Link<
                B: crate::link_storage::RxStore + 'static,
                X: crate::link_storage::TxStore + 'static,
            >
                = crate::stream_link::StreamDriver<Self, B, X>
            where
                Self: 'static;

            const PROTO: LinkProto = LinkProto::Tls;
            fn local(&self) -> SocketAddr {
                self.channel.local()
            }
            fn peer(&self) -> SocketAddr {
                self.channel.peer()
            }
            fn send_parts(&self, parts: &[&[u8]]) -> Result<(), ()> {
                self.channel.send_parts(parts)
            }
            fn wait_readable(&self, timeout_ms: c_int) {
                self.channel.wait_readable(timeout_ms)
            }
            fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ()> {
                self.channel.try_read(buf)
            }
            fn connected(&mut self) -> Result<bool, ()> {
                match self.answer.get() {
                    None => Ok(false),
                    Some(true) => Ok(true),
                    Some(false) => Err(()),
                }
            }
            fn shutdown(&self) {
                self.channel.shutdown()
            }
            fn peer_credential_zid(&self) -> Option<[u8; 16]> {
                self.channel.peer_credential_zid()
            }
        }

        /// The dial of [`Handshaking`] channels; its waiting dial counts each call.
        struct HandshakingDial {
            answer: Rc<Cell<Option<bool>>>,
            waited: Rc<Cell<usize>>,
        }

        impl StreamDial for HandshakingDial {
            type Stream = Handshaking;
            fn dial(&self, to: SocketAddr) -> Result<Handshaking, LinkOpenError> {
                self.waited.set(self.waited.get() + 1);
                self.dial_started(to)
            }
            fn dial_started(&self, to: SocketAddr) -> Result<Handshaking, LinkOpenError> {
                ChannelDial.dial(to).map(|channel| Handshaking {
                    channel,
                    answer: self.answer.clone(),
                })
            }
        }

        #[derive(Clone, Copy)]
        #[repr(C, align(16))]
        struct Block([u8; ARENA_ALIGN]);

        let (rx_len, slot_len) = (66, 34);
        let bytes = Arena::byte_cells_bytes(rx_len, 1)
            .and_then(|rx| Arena::byte_cells_bytes(2 * slot_len, 1).map(|tx| rx + tx))
            .expect("within the address space");
        let region: &'static mut [Block] =
            alloc::vec![Block([0; ARENA_ALIGN]); bytes.div_ceil(ARENA_ALIGN)].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every link that claims from it.
        let mut arena =
            unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), bytes) };
        let tables = LinkTables::new(
            arena.lend_byte_cells(rx_len, 1).expect("the receive table"),
            arena
                .lend_byte_cells(2 * slot_len, 1)
                .expect("the outbound table"),
            slot_len,
        );

        let answer = Rc::new(Cell::new(None));
        let waited = Rc::new(Cell::new(0));
        let mut links = IpLinks::<Datagrams, Dial>::new(NODE, Dial).with_tls(HandshakingDial {
            answer: answer.clone(),
            waited: waited.clone(),
        });
        links.lend_buffers(tables);

        let mut pending = links
            .begin_initiator(Locator::tls(ROUTER))
            .expect("the dial begins");
        for _ in 0..3 {
            assert!(pending.poll().is_none(), "the channel is still opening");
        }
        assert_eq!(tables.in_use(), 1, "the dial holds its link's buffers");
        answer.set(Some(true));
        let tls = pending
            .poll()
            .expect("the dial answered")
            .expect("the channel is made")
            .sink;
        assert_eq!(kind(&tls), Some(wz_session_core::link::LinkKind::Tls));
        assert_eq!(
            tls.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("tls/10.0.0.1:7447")
        );
        assert_eq!(tls.peer_credential_zid(), Some(PROVEN));
        assert!(pending.poll().is_none(), "a dial answers once");
        drop(tls);
        assert_eq!(tables.in_use(), 0);

        answer.set(Some(false));
        let mut failing = links
            .begin_initiator(Locator::tls(ROUTER))
            .expect("the dial begins");
        assert_eq!(tables.in_use(), 1);
        assert!(matches!(failing.poll(), Some(Err(LinkOpenError::Refused))));
        assert_eq!(tables.in_use(), 0, "a refused dial gives its buffers back");
        assert_eq!(waited.get(), 0, "no dial waited for its channel");
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_told_their_batch_receive_datagrams_into_that_and_no_more() {
        let whole = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        assert_eq!(whole.datagram_rx_capacity(), UDP_RX_CAPACITY);
        let dialled = whole
            .open_initiator(Locator::udp(ROUTER))
            .expect("a datagram link")
            .sink;
        assert_eq!(dialled.link_rx_capacity(), UDP_RX_CAPACITY);

        let sized = IpLinks::<Datagrams, Dial>::new(NODE, Dial).with_rx_capacity(2048);
        let dialled = sized
            .open_initiator(Locator::udp(ROUTER))
            .expect("a datagram link")
            .sink;
        assert_eq!(dialled.link_rx_capacity(), 2048);
        let accepting = sized.open_acceptor(7447).expect("an accepting link").sink;
        assert_eq!(accepting.link_rx_capacity(), 2048);
        let stream = sized
            .open_initiator(Locator::tcp(ROUTER))
            .expect("a stream link")
            .sink;
        assert_ne!(
            stream.link_rx_capacity(),
            2048,
            "a stream link keeps the largest batch its framing reads"
        );

        assert_eq!(
            IpLinks::<Datagrams, Dial>::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Dial)
                .with_rx_capacity(0)
                .datagram_rx_capacity(),
            1,
            "a buffer of no bytes is refused for one"
        );
        assert_eq!(
            IpLinks::<Datagrams, Dial>::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Dial)
                .with_rx_capacity(usize::MAX)
                .datagram_rx_capacity(),
            UDP_RX_CAPACITY,
            "and none is larger than the largest datagram"
        );
    }

    /// Links lent their session's tables claim every link's buffers there, a dial's and an
    /// accepting link's alike, as many links as the tables hold: one past them is refused as
    /// exhausted and never allocated, a protocol the links do not carry is still refused for good,
    /// and the buffers are back once the link goes.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_lent_tables_claim_every_links_buffers_there() {
        use wz_session_core::bounded::{Arena, ARENA_ALIGN};

        #[derive(Clone, Copy)]
        #[repr(C, align(16))]
        struct Block([u8; ARENA_ALIGN]);

        let (rx_len, slot_len) = (66, 34);
        let bytes = Arena::byte_cells_bytes(rx_len, 1)
            .and_then(|rx| Arena::byte_cells_bytes(2 * slot_len, 1).map(|tx| rx + tx))
            .expect("within the address space");
        let region: &'static mut [Block] =
            alloc::vec![Block([0; ARENA_ALIGN]); bytes.div_ceil(ARENA_ALIGN)].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every link that claims from it.
        let mut arena =
            unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), bytes) };
        let tables = LinkTables::new(
            arena.lend_byte_cells(rx_len, 1).expect("the receive table"),
            arena
                .lend_byte_cells(2 * slot_len, 1)
                .expect("the outbound table"),
            slot_len,
        );

        let mut links = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        links.lend_buffers(tables);
        let stream = links
            .open_initiator(Locator::tcp(ROUTER))
            .expect("a stream link over the tables' buffers")
            .sink;
        assert_eq!(stream.link_rx_capacity(), rx_len);
        assert_eq!(
            stream.link_mtu(),
            slot_len,
            "its frames are the tables' slots"
        );
        assert_eq!(tables.in_use(), 1);
        assert!(matches!(
            links.open_initiator(Locator::udp(ROUTER)),
            Err(LinkOpenError::Exhausted)
        ));
        assert!(matches!(
            links.open_acceptor(7447),
            Err(LinkOpenError::Exhausted)
        ));
        assert!(
            matches!(
                links.open_initiator(Locator::tls(ROUTER)),
                Err(LinkOpenError::Unsupported)
            ),
            "a protocol the links do not carry is refused before any buffer is asked for"
        );
        drop(stream);
        assert_eq!(tables.in_use(), 0);
        let datagram = links
            .open_initiator(Locator::udp(ROUTER))
            .expect("a datagram link once the buffers are back")
            .sink;
        assert_eq!(datagram.link_rx_capacity(), rx_len);
    }

    /// Links lent cells place every link they open in one: a link past the cells is refused as
    /// exhausted, and a link that goes gives its cell back for the next. The CONTROL is the same
    /// links lent none, which open each link on the heap whatever the count.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_lent_cells_place_every_link_there() {
        use wz_session_core::bounded::{Arena, ARENA_ALIGN};

        #[derive(Clone, Copy)]
        #[repr(C, align(16))]
        struct Block([u8; ARENA_ALIGN]);

        let mut links = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        let size = links.link_cell_bytes();
        assert!(size > 0, "the links' drivers have a size");
        let bytes = Arena::byte_cells_bytes(size, 1).expect("within the address space");
        let region: &'static mut [Block] =
            alloc::vec![Block([0; ARENA_ALIGN]); bytes.div_ceil(ARENA_ALIGN)].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
        // leaked, so nothing else uses it and it outlives every link placed in it.
        let mut arena =
            unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), bytes) };
        let cells = arena.lend_byte_cells(size, 1).expect("one cell");
        links.lend_cells(cells);

        let stream = links
            .open_initiator(Locator::tcp(ROUTER))
            .expect("a stream link in the cell");
        assert_eq!(cells.in_use(), 1, "the link took the cell");
        assert!(
            matches!(
                links.open_initiator(Locator::udp(ROUTER)),
                Err(LinkOpenError::Exhausted)
            ),
            "a link past the cells is refused"
        );
        drop(stream);
        assert_eq!(cells.in_use(), 0, "the link that went gave its cell back");
        let datagram = links
            .open_initiator(Locator::udp(ROUTER))
            .expect("a datagram link in the cell given back");
        assert_eq!(cells.in_use(), 1);
        drop(datagram);

        let heap = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        let first = heap.open_initiator(Locator::udp(ROUTER));
        let second = heap.open_initiator(Locator::udp(ROUTER));
        assert!(
            first.is_ok() && second.is_ok(),
            "CONTROL: links lent no cells open each link on the heap"
        );
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_acceptor_is_a_datagram_link_with_no_peer_yet() {
        let links = IpLinks::<Datagrams, Dial>::new(NODE, Dial);
        let accepting = links.open_acceptor(7447).expect("an accepting link").sink;
        assert_eq!(kind(&accepting), Some(wz_session_core::link::LinkKind::Udp));
        assert!(
            accepting.link_endpoints().is_none(),
            "no peer until an InitSyn names one"
        );
    }

    /// The `udp/` listener of the heap profile against a socket whose datagrams the test queues.
    #[cfg(all(feature = "udp-listen", not(feature = "session-slot")))]
    mod udp_listener {
        use super::*;
        use alloc::collections::VecDeque;
        use alloc::vec;
        use alloc::vec::Vec;
        use core::cell::RefCell;

        type Queue = Rc<RefCell<VecDeque<(Vec<u8>, SocketAddr)>>>;
        type Sent = Rc<RefCell<Vec<(SocketAddr, Vec<u8>)>>>;

        /// A socket that hands out what the test queued, in order, and keeps what it sends.
        struct Inbox {
            queued: Queue,
            sent: Sent,
        }

        impl DatagramSocket for Inbox {
            type Error = ();
            #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
            type Waits = crate::session_drive::NoWaits;
            fn bind(_at: SocketAddr) -> Result<Self, ()> {
                Ok(Self {
                    queued: Queue::default(),
                    sent: Sent::default(),
                })
            }
            fn local(&self) -> SocketAddr {
                LISTENING
            }
            fn send_to(&self, to: SocketAddr, bytes: &[u8]) -> Result<(), ()> {
                self.sent.borrow_mut().push((to, bytes.to_vec()));
                Ok(())
            }
            fn wait_readable(&self, _timeout_ms: c_int) {}
            fn times_out(&self) -> bool {
                false
            }
            fn recv_waiting(&self, buf: &mut [u8]) -> Result<Option<Received>, ()> {
                self.try_recv(buf)
            }
            fn try_recv(&self, buf: &mut [u8]) -> Result<Option<Received>, ()> {
                Ok(self.queued.borrow_mut().pop_front().map(|(bytes, from)| {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    (bytes.len(), from)
                }))
            }
        }

        const LISTENING: SocketAddr = SocketAddr::new(NODE, 7447);
        const PEER_A: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 50_001);
        const PEER_B: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8)), 50_002);
        /// An `InitSyn` header and a byte: what opens a session.
        const SYN: &[u8] = &[0x01, 0x09];

        /// A listener over a fresh [`Inbox`], with the queue the test fills and what was sent.
        fn listener() -> (IpUdpListener<Inbox>, Queue, Sent) {
            let queued = Queue::default();
            let sent = Sent::default();
            let socket = Inbox {
                queued: Rc::clone(&queued),
                sent: Rc::clone(&sent),
            };
            let listener = IpUdpListener {
                port: Rc::new(UdpPort::new(socket, 2048)),
                shape: LinkShape::default(),
            };
            (listener, queued, sent)
        }

        /// Everything `link` reads now, a datagram at a time.
        fn read_all(link: &OpenedLink<HeapLink>) -> Vec<Vec<u8>> {
            let mut got = Vec::new();
            while link.pump.recv_with(&mut |bytes| got.push(bytes.to_vec())) {}
            got
        }

        /// Each source whose `InitSyn` reaches the port is given a link of its own, which reads that
        /// source's datagrams alone, in the order they came, whoever took them off the socket; a
        /// datagram read for another link waits as input its owner steps at once; and a link's
        /// sends leave by the port, to its peer.
        #[test]
        fn each_source_that_opens_a_session_gets_a_link_of_its_own() {
            let (listener, queued, sent) = listener();
            assert_eq!(listener.local(), Locator::udp(LISTENING));
            assert!(listener.accept().expect("a readable port").is_none());
            for (bytes, from) in [
                (SYN, PEER_A),
                (SYN, PEER_B),
                (&[0x05, 0xa1][..], PEER_A),
                (&[0x05, 0xb1][..], PEER_B),
            ] {
                queued.borrow_mut().push_back((bytes.to_vec(), from));
            }
            let a = listener
                .accept()
                .expect("a readable port")
                .expect("A's link");
            let b = listener
                .accept()
                .expect("a readable port")
                .expect("B's link");
            assert!(
                listener.accept().expect("a readable port").is_none(),
                "two sources, two links"
            );
            assert_eq!(kind(&a.sink), Some(wz_session_core::link::LinkKind::Udp));
            assert!(
                b.pump.holds_input(),
                "what the listener took for B waits as B's input"
            );

            assert_eq!(read_all(&a), [SYN.to_vec(), vec![0x05, 0xa1]]);
            assert_eq!(read_all(&b), [SYN.to_vec(), vec![0x05, 0xb1]]);
            assert!(!b.pump.holds_input());

            queued.borrow_mut().push_back((vec![0x05, 0xb2], PEER_B));
            assert!(
                read_all(&a).is_empty(),
                "A's read takes B's datagram off the socket and does not read it"
            );
            assert_eq!(read_all(&b), [vec![0x05, 0xb2]]);

            assert!(matches!(
                b.sink.send_blocking(b"to-b", Reliability::BestEffort),
                LinkSendOutcome::Sent
            ));
            assert_eq!(*sent.borrow(), [(PEER_B, b"to-b".to_vec())]);
        }

        /// A datagram from a source with no link that opens no session is dropped and counted, and
        /// a link that is let go of frees its source: what it sends next is a stray until its next
        /// `InitSyn`, which opens a new link.
        #[test]
        fn a_stray_opens_no_link_and_a_link_let_go_of_frees_its_source() {
            let (listener, queued, _sent) = listener();
            queued.borrow_mut().push_back((vec![0x05, 0xc1], PEER_A));
            assert!(listener.accept().expect("a readable port").is_none());
            assert_eq!(listener.port.strays(), 1);

            queued.borrow_mut().push_back((SYN.to_vec(), PEER_A));
            let a = listener
                .accept()
                .expect("a readable port")
                .expect("A's link");
            drop(a);
            queued.borrow_mut().push_back((vec![0x05, 0xa2], PEER_A));
            assert!(listener.accept().expect("a readable port").is_none());
            assert_eq!(
                listener.port.strays(),
                2,
                "the source of a link let go of is no peer of the port"
            );

            queued.borrow_mut().push_back((SYN.to_vec(), PEER_A));
            let again = listener
                .accept()
                .expect("a readable port")
                .expect("A's new link");
            assert_eq!(read_all(&again), [SYN.to_vec()]);
        }

        /// A peer that sends more than its link reads has the excess dropped and counted, and the
        /// datagrams kept are the first ones.
        #[test]
        fn a_peer_past_its_backlog_has_the_excess_dropped() {
            let (listener, queued, _sent) = listener();
            queued.borrow_mut().push_back((SYN.to_vec(), PEER_A));
            let a = listener
                .accept()
                .expect("a readable port")
                .expect("A's link");
            for n in 0..crate::udp_link::PORT_PEER_BACKLOG {
                queued.borrow_mut().push_back((vec![0x05, n as u8], PEER_A));
            }
            assert!(listener.accept().expect("a readable port").is_none());
            assert_eq!(
                listener.port.overflows(),
                1,
                "the InitSyn and the backlog fill it"
            );
            let read = read_all(&a);
            assert_eq!(read.len(), crate::udp_link::PORT_PEER_BACKLOG);
            assert_eq!(read[0], SYN.to_vec());
        }

        /// A listener whose session lent the stack its tables claims each link's buffers there: a
        /// source past the tables' one link is let go of with the tables exhausted, and the next
        /// `InitSyn` of that source opens a link once the first link's buffers are back.
        #[test]
        fn a_listened_link_claims_its_buffers_from_the_sessions_tables() {
            use wz_session_core::bounded::{Arena, ARENA_ALIGN};

            #[derive(Clone, Copy)]
            #[repr(C, align(16))]
            struct Block([u8; ARENA_ALIGN]);

            let (rx_len, slot_len) = (66, 34);
            let bytes = Arena::byte_cells_bytes(rx_len, 1)
                .and_then(|rx| Arena::byte_cells_bytes(2 * slot_len, 1).map(|tx| rx + tx))
                .expect("within the address space");
            let region: &'static mut [Block] =
                vec![Block([0; ARENA_ALIGN]); bytes.div_ceil(ARENA_ALIGN)].leak();
            // SAFETY: the region is aligned to `ARENA_ALIGN`, holds at least `bytes` bytes, and is
            // leaked, so nothing else uses it and it outlives every link that claims from it.
            let mut arena =
                unsafe { Arena::over(core::ptr::NonNull::from(region).cast::<u8>(), bytes) };
            let tables = LinkTables::new(
                arena.lend_byte_cells(rx_len, 1).expect("the receive table"),
                arena
                    .lend_byte_cells(2 * slot_len, 1)
                    .expect("the outbound table"),
                slot_len,
            );
            let (mut listener, queued, _sent) = listener();
            listener.shape.lent = Some(tables);
            queued.borrow_mut().push_back((SYN.to_vec(), PEER_A));
            queued.borrow_mut().push_back((SYN.to_vec(), PEER_B));
            let a = listener
                .accept()
                .expect("a readable port")
                .expect("A's link");
            assert_eq!(a.sink.link_rx_capacity(), rx_len, "the tables' buffer");
            assert_eq!(tables.in_use(), 1);
            assert!(matches!(listener.accept(), Err(LinkOpenError::Exhausted)));
            drop(a);
            assert_eq!(tables.in_use(), 0);
            queued.borrow_mut().push_back((SYN.to_vec(), PEER_B));
            let b = listener
                .accept()
                .expect("a readable port")
                .expect("B's link once the buffers are back");
            assert_eq!(b.sink.link_rx_capacity(), rx_len);
            assert_eq!(tables.in_use(), 1);
        }

        /// A stack listens on `udp/` where its datagram socket binds, at the port the socket chose,
        /// and a stack that carries no datagram refuses it as unsupported.
        #[test]
        fn a_stack_listens_on_udp_where_it_carries_datagrams() {
            let links = IpLinks::<Datagrams<true>, Dial>::new(NODE, Dial);
            let listener = links
                .open_listener(Locator::udp(SocketAddr::new(NODE, 0)))
                .unwrap_or_else(|_| panic!("a datagram socket binds"));
            assert_eq!(
                listener.local(),
                Locator::udp(SocketAddr::new(NODE, 40_001))
            );
            let none = IpLinks::<crate::udp_link::NoDatagram, Dial>::new(NODE, Dial);
            assert!(matches!(
                none.open_listener(Locator::udp(SocketAddr::new(NODE, 0))),
                Err(LinkOpenError::Unsupported)
            ));
        }
    }

    /// A stream names the link a stack holds over it, and the stream there is none of names
    /// itself: the `tls/` case of a stack that carries no secure channel holds a value of no size
    /// that cannot be made, so no stream link is made for it.
    #[test]
    fn a_stream_names_its_link_and_the_stream_there_is_none_of_names_none() {
        // Each binding compiles only while the stream names that link.
        let none: fn(<NoStream as StreamSocket>::Link<ByteBuf, ByteBuf>) -> NoStream =
            core::convert::identity;
        type StreamLinkOf = <Stream as StreamSocket>::Link<ByteBuf, ByteBuf>;
        type StreamDriverOf = crate::stream_link::StreamDriver<Stream, ByteBuf, ByteBuf>;
        let some: fn(StreamLinkOf) -> StreamDriverOf = core::convert::identity;
        let _ = (none, some);
        assert_eq!(
            core::mem::size_of::<<NoStream as StreamSocket>::Link<ByteBuf, ByteBuf>>(),
            0
        );
        assert!(
            core::mem::size_of::<IpDriver<Datagrams, Stream, NoStream>>()
                <= core::mem::size_of::<IpDriver<Datagrams, Stream, Stream>>()
        );
    }
}
