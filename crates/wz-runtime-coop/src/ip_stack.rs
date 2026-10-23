// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A platform's datagram and stream sockets as ONE stack of the slot profile's session host: a
//! dial to `udp/...` opens the datagram link (`udp_link`), a dial to `tcp/...` the stream link
//! (`stream_link`), and both live in the same session slots, because the slot table holds one
//! driver type and that type is [`IpDriver`], either link.
//!
//! A platform with both sockets (the host's) uses this stack; one with datagram sockets only uses
//! `udp_link::UdpStack`, which refuses a `tcp/` dial as unsupported. Which links an image can dial
//! is then the stack it names, not a flag beside it.

use core::marker::PhantomData;

use wz_session_core::byte_cells::ByteSource;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::link::{
    BoxedLinkDriver, LinkEndpoints, LinkSendOutcome, LostCause, TxSlot, TxSlotGrant,
};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;
use wz_session_core::session_slot::SlotDriver;

use crate::session_drive::{
    Bind, DriverPump, LinkOpenError, LinkProto, Locator, SessionDatagramLink, SlotStack,
};
use crate::stream_link::{FixedStreamDriver, StreamDriver, StreamSocket};
use crate::udp_link::{DatagramSocket, FixedUdpDriver, UdpStack};

/// The link of one session of an [`IpStack`]: a datagram link or a stream link, as its dial named.
pub enum IpDriver<U: DatagramSocket + 'static, T: StreamSocket + 'static> {
    /// A `udp/` link.
    Udp(FixedUdpDriver<U>),
    /// A `tcp/` link.
    Tcp(FixedStreamDriver<T>),
}

/// Every method of the two links, answered by the one this driver is.
macro_rules! either {
    ($self:ident, $link:ident => $body:expr) => {
        match $self {
            IpDriver::Udp($link) => $body,
            IpDriver::Tcp($link) => $body,
        }
    };
}

impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> BoxedLinkDriver for IpDriver<U, T> {
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

impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> SessionDatagramLink
    for IpDriver<U, T>
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

/// A platform's datagram sockets `U` and stream sockets `T` as one stack of the slot profile's
/// session host. Each link it opens claims its receive buffer and the buffer its frames are
/// encoded into from the two tables the image declares, whichever protocol it speaks: a stream
/// link's receive buffer holds a batch with its length, so the tables are sized for that.
pub struct IpStack<U, T> {
    udp: UdpStack<U>,
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    stream: PhantomData<fn() -> T>,
}

// Not derived: a derive would ask `U: Clone` and `T: Clone`, and the stack holds no socket.
impl<U, T> Clone for IpStack<U, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<U, T> Copy for IpStack<U, T> {}

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

impl<U: DatagramSocket + 'static, T: StreamSocket + 'static> Bind<IpDriver<U, T>>
    for IpStack<U, T>
{
    fn bind(&mut self, to: Locator) -> Result<IpDriver<U, T>, LinkOpenError> {
        self.bind_initiator(to)
    }
}

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

    static RX: ByteCells<66, 1> = ByteCells::new();
    static TX: ByteCells<34, 1> = ByteCells::new();

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

    static REFUSED_RX: ByteCells<66, 1> = ByteCells::new();
    static REFUSED_TX: ByteCells<34, 1> = ByteCells::new();

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
}
