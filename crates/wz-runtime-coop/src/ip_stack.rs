// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A platform's datagram and stream sockets as ONE network stack: a dial to `udp/...` opens the
//! datagram link (`udp_link`), a dial to `tcp/...` the stream link (`stream_link`), and either is
//! an [`IpDriver`], so whatever holds a session's link holds one type for both.
//!
//! On the slot profile the stack is `IpStack`, whose links claim their buffers from the image's
//! tables and live in the session slots. On the heap profile it is `IpLinks`, the session shell's
//! `SessionLinks` over the same two sockets, whose links allocate their buffers when they open.
//!
//! A platform with both sockets (the host's) uses this stack; one with datagram sockets only uses
//! the datagram stack alone, which refuses a `tcp/` dial as unsupported. Which links an image can
//! dial is then the stack it names, not a flag beside it.

#[cfg(feature = "session-slot")]
use core::marker::PhantomData;

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
use crate::session_drive::SessionDatagramLink;
#[cfg(feature = "session-slot")]
use crate::session_drive::{Bind, DriverPump, SlotStack};
#[cfg(any(feature = "session-slot", feature = "alloc"))]
use crate::session_drive::{LinkOpenError, LinkProto, Locator};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::session_drive::{OpenedLink, SessionLinks};
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::stream_link::STREAM_RX_CAPACITY;
use crate::stream_link::{StreamDriver, StreamSocket};
#[cfg(feature = "session-slot")]
use crate::udp_link::UdpStack;
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use crate::udp_link::UDP_RX_CAPACITY;
use crate::udp_link::{DatagramSocket, UdpDriver};

/// The link of one session over a platform's datagram sockets `U` and stream sockets `T`: a
/// datagram link or a stream link, as its dial named. `B` holds its receive buffer and `X` the
/// memory it encodes its frames into: the image's byte tables on the slot profile (the defaults),
/// a `Vec<u8>` and `HeapTx` on the heap profile (`HeapIpDriver`, which a slot build has not).
pub enum IpDriver<
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
    B: AsMut<[u8]> + 'static = ByteBuf,
    X: TxStore + 'static = ByteBuf,
> {
    /// A `udp/` link.
    Udp(UdpDriver<U, B, X>),
    /// A `tcp/` link.
    Tcp(StreamDriver<T, B, X>),
}

/// The heap profile's [`IpDriver`]: each link allocates its buffers when it opens.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub type HeapIpDriver<U, T> = IpDriver<U, T, Vec<u8>, HeapTx>;

/// Every method of the two links, answered by the one this driver is.
macro_rules! either {
    ($self:ident, $link:ident => $body:expr) => {
        match $self {
            IpDriver::Udp($link) => $body,
            IpDriver::Tcp($link) => $body,
        }
    };
}

impl<U, T, B, X> BoxedLinkDriver for IpDriver<U, T, B, X>
where
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
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

impl<U, T, B, X> SessionDatagramLink for IpDriver<U, T, B, X>
where
    U: DatagramSocket + 'static,
    T: StreamSocket + 'static,
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
}

/// A platform's datagram sockets `U` and stream sockets `T` as the session shell's links on the
/// heap profile: what a node dials opens the link of the protocol it names, and what it accepts on
/// is a datagram link (a stream listener is not written yet). Each link allocates its receive
/// buffer when it opens, a datagram link's sized to the largest datagram and a stream link's to
/// the largest batch with its length, and lends the session `tx_slots` buffers of `tx_capacity`
/// bytes to encode its frames into (none by default: the session then builds each frame in a
/// buffer of its own).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct IpLinks<U, T> {
    local: [u8; 4],
    tx_slots: usize,
    tx_capacity: usize,
    sockets: core::marker::PhantomData<fn() -> (U, T)>,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> IpLinks<U, T> {
    /// Links bound on the node's own address `local` (`[0; 4]` for every interface of the host).
    pub fn new(local: [u8; 4]) -> Self {
        Self {
            local,
            tx_slots: 0,
            tx_capacity: 0,
            sockets: core::marker::PhantomData,
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
    /// [`LinkOpenError::Refused`].
    pub fn dial(&self, to: Locator) -> Result<HeapIpDriver<U, T>, LinkOpenError> {
        match to.proto {
            LinkProto::Udp => {
                // Port 0 has the stack choose a free one, one per initiator session.
                let socket = U::bind(self.local, 0).map_err(|_| LinkOpenError::Exhausted)?;
                Ok(IpDriver::Udp(UdpDriver::initiator_with_buffers(
                    socket,
                    (to.at.addr, to.at.port),
                    UDP_RX_CAPACITY,
                    self.tx(),
                )))
            }
            LinkProto::Tcp => {
                let socket =
                    T::connect(to.at.addr, to.at.port).map_err(|_| LinkOpenError::Refused)?;
                Ok(IpDriver::Tcp(StreamDriver::with_buffers(
                    socket,
                    STREAM_RX_CAPACITY,
                    self.tx(),
                )))
            }
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> SessionLinks for IpLinks<U, T> {
    type Pump = Rc<HeapIpDriver<U, T>>;

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError> {
        // The peer is whoever opens a session first; the driver is bound by its InitSyn.
        let socket = U::bind(self.local, port).map_err(|_| LinkOpenError::Exhausted)?;
        let driver = Rc::new(IpDriver::Udp(UdpDriver::acceptor_with_buffers(
            socket,
            UDP_RX_CAPACITY,
            self.tx(),
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

/// A platform's datagram sockets `U` and stream sockets `T` as one stack of the slot profile's
/// session host. Each link it opens claims its receive buffer and the buffer its frames are
/// encoded into from the two tables the image declares, whichever protocol it speaks: a stream
/// link's receive buffer holds a batch with its length, so the tables are sized for that.
#[cfg(feature = "session-slot")]
pub struct IpStack<U, T> {
    udp: UdpStack<U>,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    stream: PhantomData<fn() -> T>,
}

// Not derived: a derive would ask `U: Clone` and `T: Clone`, and the stack holds no socket.
#[cfg(feature = "session-slot")]
impl<U, T> Clone for IpStack<U, T> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "session-slot")]
impl<U, T> Copy for IpStack<U, T> {}

#[cfg(feature = "session-slot")]
impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> IpStack<U, T> {
    /// The stack of a node whose own address is `local`, whose links take their receive buffers
    /// from `rx` and their frame buffers from `tx`.
    pub const fn new(
        local: [u8; 4],
        rx: &'static dyn ByteSource,
        tx: &'static dyn ByteSource,
    ) -> Self {
        Self {
            udp: UdpStack::new(local, rx, tx),
            rx,
            tx,
            stream: PhantomData,
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
    /// connection the other end does not take is [`LinkOpenError::Refused`]; whatever was claimed
    /// before a refusal goes back with it.
    pub fn bind_initiator(&self, to: Locator) -> Result<IpDriver<U, T>, LinkOpenError> {
        match to.proto {
            LinkProto::Udp => self.udp.bind_initiator(to.at).map(IpDriver::Udp),
            LinkProto::Tcp => {
                let rx = self.rx.claim().ok_or(LinkOpenError::Exhausted)?;
                let tx = self.tx.claim().ok_or(LinkOpenError::Exhausted)?;
                let socket =
                    T::connect(to.at.addr, to.at.port).map_err(|_| LinkOpenError::Refused)?;
                Ok(IpDriver::Tcp(StreamDriver::over(socket, rx, tx)))
            }
        }
    }
}

#[cfg(feature = "session-slot")]
impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> Bind<IpDriver<U, T>>
    for IpStack<U, T>
{
    fn bind(&mut self, to: Locator) -> Result<IpDriver<U, T>, LinkOpenError> {
        self.bind_initiator(to)
    }
}

#[cfg(feature = "session-slot")]
impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> SlotStack for IpStack<U, T> {
    type Driver = IpDriver<U, T>;
    type Pump = DriverPump<IpDriver<U, T>>;
    type Lane = ();

    fn pump(&self, driver: SlotDriver<IpDriver<U, T>>, _lane: Option<()>) -> Self::Pump {
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

    /// A stream socket that connects to any port but [`REFUSING`].
    struct Stream([u8; 4], u16);

    const REFUSING: u16 = 9;

    impl StreamSocket for Stream {
        type Error = ();
        fn connect(addr: [u8; 4], port: u16) -> Result<Self, ()> {
            if port == REFUSING {
                Err(())
            } else {
                Ok(Stream(addr, port))
            }
        }
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

    const ROUTER: IpEndpoint = IpEndpoint {
        addr: [10, 0, 0, 1],
        port: 7447,
    };

    #[cfg(feature = "session-slot")]
    static RX: ByteCells<66, 1> = ByteCells::new();
    #[cfg(feature = "session-slot")]
    static TX: ByteCells<34, 1> = ByteCells::new();

    #[cfg(feature = "session-slot")]
    #[test]
    fn a_dial_opens_the_link_of_the_protocol_it_names() {
        let mut stack = IpStack::<Datagrams, Stream>::new([10, 0, 0, 2], &RX, &TX);
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
        let mut stack = IpStack::<Datagrams, Stream>::new([10, 0, 0, 2], &REFUSED_RX, &REFUSED_TX);
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
        let links = IpLinks::<Datagrams, Stream>::new([10, 0, 0, 2]).with_tx_buffers(2, 34);
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
        let links = IpLinks::<Datagrams, Stream>::new([10, 0, 0, 2]);
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
    fn a_heap_acceptor_is_a_datagram_link_with_no_peer_yet() {
        let links = IpLinks::<Datagrams, Stream>::new([10, 0, 0, 2]);
        let accepting = links.open_acceptor(7447).expect("an accepting link").pump;
        assert!(matches!(*accepting, IpDriver::Udp(_)));
        assert!(
            accepting.link_endpoints().is_none(),
            "no peer until an InitSyn names one"
        );
    }
}
