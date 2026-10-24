// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A platform's datagram and stream sockets as ONE network stack: a dial to `udp/...` opens the
//! datagram link (`udp_link`), a dial to `tcp/...` the stream link (`stream_link`), a dial to
//! `tls/...` the stream link over the secure channel the stack was given (`with_tls`; without one
//! it is unsupported), and each is an [`IpDriver`], so whatever holds a session's link holds one
//! type for all.
//!
//! On the slot profile the stack is `IpStack`, whose links claim their buffers from the image's
//! tables and live in the session slots. On the heap profile it is `IpLinks`, the session shell's
//! `SessionLinks` over the same two sockets, whose links allocate their buffers when they open.
//!
//! A platform with both sockets (the host's) uses this stack; one with datagram sockets only uses
//! the datagram stack alone, which refuses a `tcp/` dial as unsupported. Which links an image can
//! dial is then the stack it names, not a flag beside it.

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::rc::Rc;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

use wz_session_core::byte_cells::ByteBuf;
#[cfg(feature = "session-slot")]
use wz_session_core::byte_cells::ByteSource;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkEndpoints, LinkSendOutcome, LostCause, TxSlot, TxSlotGrant,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
#[cfg(feature = "session-slot")]
use wz_session_core::session_slot::SlotDriver;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::link_storage::HeapTx;
use crate::link_storage::TxStore;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::LinkReadiness;
use crate::session_drive::SessionDatagramLink;
#[cfg(feature = "session-slot")]
use crate::session_drive::{Bind, DriverPump, SlotStack};
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::session_drive::{LinkOpenError, LinkProto, Locator};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::{OpenedLink, SessionLinks};
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::stream_link::NoDial;
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::stream_link::StreamDial;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::stream_link::STREAM_RX_CAPACITY;
use crate::stream_link::{NoStream, StreamDriver, StreamSocket};
#[cfg(feature = "session-slot")]
use crate::udp_link::UdpStack;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::udp_link::UDP_RX_CAPACITY;
use crate::udp_link::{DatagramSocket, UdpDriver};

/// The link of one session over a platform's datagram sockets `U`, its plain streams `T` and its
/// secure-channel streams `L`: a datagram, a stream or a secure stream link, as its dial named.
/// `L` is [`NoStream`] on a stack that carries no secure channel. `B` holds its receive buffer and
/// `X` the memory it encodes its frames into: the image's byte tables on the slot profile (the
/// defaults), a `Vec<u8>` and `HeapTx` on the heap profile (`HeapIpDriver`, which a slot build has
/// not).
pub enum IpDriver<
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
    L: StreamSocket + 'static = NoStream,
    B: AsMut<[u8]> + 'static = ByteBuf,
    X: TxStore + 'static = ByteBuf,
> {
    /// A `udp/` link.
    Udp(UdpDriver<U, B, X>),
    /// A `tcp/` link.
    Tcp(StreamDriver<T, B, X>),
    /// A `tls/` link: the stream link over a secure channel.
    Tls(StreamDriver<L, B, X>),
}

/// The heap profile's [`IpDriver`]: each link allocates its buffers when it opens.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub type HeapIpDriver<U, T, L = NoStream> = IpDriver<U, T, L, Vec<u8>, HeapTx>;

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
    B: AsMut<[u8]> + 'static,
    X: TxStore + 'static,
{
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        either!(self, link => link.send_blocking(bytes, reliability))
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

    fn open_blocking(&self) {
        either!(self, link => link.open_blocking())
    }

    fn close_blocking(&self) {
        either!(self, link => link.close_blocking())
    }

    fn link_endpoints(&self) -> Option<&LinkEndpoints> {
        either!(self, link => link.link_endpoints())
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
    B: AsMut<[u8]> + 'static,
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

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        either!(self, link => link.readiness())
    }
}

/// A platform's datagram sockets `U` and the streams its dial `D` opens as the session shell's
/// links on the heap profile: what a node dials opens the link of the protocol it names, and what
/// it accepts on is a datagram link (a stream listener is not written yet). Each link allocates
/// its receive buffer when it opens, a datagram link's sized to the largest datagram and a stream
/// link's to the largest batch with its length, and lends the session `tx_slots` buffers of
/// `tx_capacity` bytes to encode its frames into (none by default: the session then builds each
/// frame in a buffer of its own).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct IpLinks<U, D, L = NoDial> {
    local: [u8; 4],
    dial: D,
    tls: L,
    tx_slots: usize,
    tx_capacity: usize,
    owner_waits: bool,
    datagrams: core::marker::PhantomData<fn() -> U>,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U, D> IpLinks<U, D>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
{
    /// Links bound on the node's own address `local` (`[0; 4]` for every interface of the host),
    /// whose `tcp/` links run over the streams `dial` opens, and which carry no `tls/` link until
    /// [`IpLinks::with_tls`] gives them one.
    pub fn new(local: [u8; 4], dial: D) -> Self {
        Self {
            local,
            dial,
            tls: NoDial,
            tx_slots: 0,
            tx_capacity: 0,
            owner_waits: false,
            datagrams: core::marker::PhantomData,
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U, D, L> IpLinks<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
{
    /// The same links, whose `tls/` links run over the secure channels `tls` opens.
    pub fn with_tls<S: StreamDial>(self, tls: S) -> IpLinks<U, D, S> {
        IpLinks {
            local: self.local,
            dial: self.dial,
            tls,
            tx_slots: self.tx_slots,
            tx_capacity: self.tx_capacity,
            owner_waits: self.owner_waits,
            datagrams: self.datagrams,
        }
    }

    /// Links whose owner waits for their input ([`SessionDatagramLink::readiness`]): what holds a
    /// session behind a lock and waits for it outside the lock. Each link whose socket can be
    /// waited on that way does not wait in its loop; one whose socket cannot still does.
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.owner_waits = true;
        self
    }

    /// A stream link as these links open it: waited on by its owner when they are.
    fn opened_stream<S: StreamSocket>(
        &self,
        link: StreamDriver<S, Vec<u8>, HeapTx>,
    ) -> StreamDriver<S, Vec<u8>, HeapTx> {
        if self.owner_waits {
            link.waited_by_owner()
        } else {
            link
        }
    }

    /// A datagram link as these links open it: waited on by its owner when they are.
    fn opened_datagram(
        &self,
        link: UdpDriver<U, Vec<u8>, HeapTx>,
    ) -> UdpDriver<U, Vec<u8>, HeapTx> {
        if self.owner_waits {
            link.waited_by_owner()
        } else {
            link
        }
    }

    /// Links that lend the session `slots` buffers of `bytes` each to encode its frames into, as
    /// a datagram stack's do: `bytes` is the batch the sessions negotiate, and a session that
    /// batches holds one slot open while it encodes into another, so it needs two.
    #[must_use]
    pub fn with_tx_buffers(mut self, slots: usize, bytes: usize) -> Self {
        self.tx_slots = slots;
        self.tx_capacity = bytes;
        self
    }

    fn tx(&self) -> HeapTx {
        HeapTx::new(self.tx_slots, self.tx_capacity)
    }

    /// The link of a dial to `to`, before it is shared. A stack that cannot make a socket is
    /// [`LinkOpenError::Exhausted`]; a connection the other end does not take is
    /// [`LinkOpenError::Refused`]; a `tls/` dial on links given no secure channel is
    /// [`LinkOpenError::Unsupported`].
    pub fn dial(
        &self,
        to: Locator,
    ) -> Result<HeapIpDriver<U, D::Stream, L::Stream>, LinkOpenError> {
        match to.proto {
            LinkProto::Udp => {
                // Port 0 has the stack choose a free one, one per initiator session.
                let socket = U::bind(self.local, 0).map_err(|_| LinkOpenError::Exhausted)?;
                Ok(IpDriver::Udp(self.opened_datagram(
                    UdpDriver::initiator_with_buffers(
                        socket,
                        (to.at.addr, to.at.port),
                        UDP_RX_CAPACITY,
                        self.tx(),
                    ),
                )))
            }
            LinkProto::Tcp => {
                let socket = self.dial.dial(to.at.addr, to.at.port)?;
                Ok(IpDriver::Tcp(self.opened_stream(
                    StreamDriver::with_buffers(socket, STREAM_RX_CAPACITY, self.tx()),
                )))
            }
            LinkProto::Tls => {
                let channel = self.tls.dial(to.at.addr, to.at.port)?;
                Ok(IpDriver::Tls(self.opened_stream(
                    StreamDriver::with_buffers(channel, STREAM_RX_CAPACITY, self.tx()),
                )))
            }
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U, D, L> SessionLinks for IpLinks<U, D, L>
where
    U: DatagramSocket + 'static,
    D: StreamDial,
    D::Stream: 'static,
    L: StreamDial,
    L::Stream: 'static,
{
    type Pump = Rc<HeapIpDriver<U, D::Stream, L::Stream>>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The peer is whoever opens a session first; the driver is bound by its InitSyn.
        let socket = U::bind(self.local, port).map_err(|_| LinkOpenError::Exhausted)?;
        let driver = Rc::new(IpDriver::Udp(self.opened_datagram(
            UdpDriver::acceptor_with_buffers(socket, UDP_RX_CAPACITY, self.tx()),
        )));
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        let driver = Rc::new(self.dial(to)?);
        Ok(OpenedLink {
            sink: driver.clone(),
            pump: driver,
        })
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
        local: [u8; 4],
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
        match to.proto {
            LinkProto::Udp => self.udp.bind_initiator(to.at).map(IpDriver::Udp),
            LinkProto::Tcp => {
                let (rx, tx) = self.claim()?;
                let socket = self.dial.dial(to.at.addr, to.at.port)?;
                Ok(IpDriver::Tcp(StreamDriver::over(socket, rx, tx)))
            }
            LinkProto::Tls if !L::CARRIED => Err(LinkOpenError::Unsupported),
            LinkProto::Tls => {
                let (rx, tx) = self.claim()?;
                let channel = self.tls.dial(to.at.addr, to.at.port)?;
                Ok(IpDriver::Tls(StreamDriver::over(channel, rx, tx)))
            }
        }
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
    fn bind(&mut self, to: Locator) -> Result<IpDriver<U, D::Stream, L::Stream>, LinkOpenError> {
        self.bind_initiator(to)
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

    use crate::session_drive::IpEndpoint;
    use crate::udp_link::Received;

    /// A datagram socket that takes everything and has nothing to read.
    struct Datagrams;

    impl DatagramSocket for Datagrams {
        type Error = ();
        fn bind(_addr: [u8; 4], _port: u16) -> Result<Self, ()> {
            Ok(Datagrams)
        }
        fn local(&self) -> ([u8; 4], u16) {
            ([10, 0, 0, 2], 40_001)
        }
        fn send_to(&self, _addr: [u8; 4], _port: u16, _bytes: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        fn wait_readable(&self, _timeout_ms: c_int) {}
        fn times_out(&self) -> bool {
            false
        }
        fn recv_waiting(&self, _buf: &mut [u8]) -> Result<Option<Received>, ()> {
            Ok(None)
        }
        fn try_recv(&self, _buf: &mut [u8]) -> Result<Option<Received>, ()> {
            Ok(None)
        }
    }

    /// A stream connected to `(addr, port)`, which takes everything and has nothing to read.
    struct Stream([u8; 4], u16);

    /// A dial that connects to any port but [`REFUSING`].
    #[derive(Clone, Copy)]
    struct Dial;

    const REFUSING: u16 = 9;

    impl StreamDial for Dial {
        type Stream = Stream;
        fn dial(&self, addr: [u8; 4], port: u16) -> Result<Stream, LinkOpenError> {
            if port == REFUSING {
                Err(LinkOpenError::Refused)
            } else {
                Ok(Stream(addr, port))
            }
        }
    }

    impl StreamSocket for Stream {
        type Error = ();
        fn local(&self) -> ([u8; 4], u16) {
            ([10, 0, 0, 2], 40_002)
        }
        fn peer(&self) -> ([u8; 4], u16) {
            (self.0, self.1)
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
        fn dial(&self, addr: [u8; 4], port: u16) -> Result<Channel, LinkOpenError> {
            Dial.dial(addr, port).map(Channel)
        }
    }

    impl StreamSocket for Channel {
        type Error = ();
        const PROTO: LinkProto = LinkProto::Tls;
        fn local(&self) -> ([u8; 4], u16) {
            self.0.local()
        }
        fn peer(&self) -> ([u8; 4], u16) {
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

    const ROUTER: IpEndpoint = IpEndpoint {
        addr: [10, 0, 0, 1],
        port: 7447,
    };

    #[cfg(feature = "session-slot")]
    static TLS_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static TLS_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_tls_dial_opens_the_stream_link_over_the_channel_the_stack_was_given() {
        let mut stack = IpStack::<Datagrams, Dial>::new([10, 0, 0, 2], &TLS_RX, &TLS_TX, Dial)
            .with_tls(ChannelDial);
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
    static PLAIN_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static PLAIN_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_stack_given_no_channel_refuses_tls_as_unsupported_even_with_its_tables_full() {
        let mut stack = IpStack::<Datagrams, Dial>::new([10, 0, 0, 2], &PLAIN_RX, &PLAIN_TX, Dial);
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
        let mut stack = IpStack::<Datagrams, Dial>::new([10, 0, 0, 2], &RX, &TX, Dial);
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
    static REFUSED_RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static REFUSED_TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_refused_connection_is_refused_and_gives_its_buffers_back() {
        let mut stack =
            IpStack::<Datagrams, Dial>::new([10, 0, 0, 2], &REFUSED_RX, &REFUSED_TX, Dial);
        let refusing = IpEndpoint {
            port: REFUSING,
            ..ROUTER
        };
        assert!(matches!(
            stack.bind(Locator::tcp(refusing)),
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

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_dial_opens_the_link_of_the_protocol_it_names() {
        let links = IpLinks::<Datagrams, Dial>::new([10, 0, 0, 2], Dial).with_tx_buffers(2, 34);
        let udp = links
            .open_initiator(Locator::udp(ROUTER))
            .expect("a datagram link")
            .pump;
        assert!(matches!(*udp, IpDriver::Udp(_)));
        assert!(!udp.batch_length_prefixed());
        assert_eq!(
            udp.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("udp/10.0.0.1:7447")
        );
        let tcp = links
            .open_initiator(Locator::tcp(ROUTER))
            .expect("a stream link")
            .pump;
        assert!(matches!(*tcp, IpDriver::Tcp(_)));
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
        let links = IpLinks::<Datagrams, Dial>::new([10, 0, 0, 2], Dial);
        let refusing = IpEndpoint {
            port: REFUSING,
            ..ROUTER
        };
        assert!(matches!(
            links.open_initiator(Locator::tcp(refusing)),
            Err(LinkOpenError::Refused)
        ));
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn heap_links_dial_tls_only_over_the_channel_they_were_given() {
        let plain = IpLinks::<Datagrams, Dial>::new([10, 0, 0, 2], Dial);
        assert!(matches!(
            plain.open_initiator(Locator::tls(ROUTER)),
            Err(LinkOpenError::Unsupported)
        ));
        let secure = plain.with_tls(ChannelDial);
        let tls = secure
            .open_initiator(Locator::tls(ROUTER))
            .expect("a secure stream link")
            .pump;
        assert!(matches!(*tls, IpDriver::Tls(_)));
        assert_eq!(
            tls.link_endpoints().map(|ends| ends.dst.as_str()),
            Some("tls/10.0.0.1:7447")
        );
        assert_eq!(tls.peer_credential_zid(), Some(PROVEN));
    }

    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_acceptor_is_a_datagram_link_with_no_peer_yet() {
        let links = IpLinks::<Datagrams, Dial>::new([10, 0, 0, 2], Dial);
        let accepting = links.open_acceptor(7447).expect("an accepting link").pump;
        assert!(matches!(*accepting, IpDriver::Udp(_)));
        assert!(
            accepting.link_endpoints().is_none(),
            "no peer until an InitSyn names one"
        );
    }
}
