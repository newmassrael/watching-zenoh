// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Two network stacks as one: the links of a session that opens over whichever of two stacks its
//! open chose, as one stack type, so the engine over them is built once.
//!
//! A library that opens a session either over the host's sockets or over a transport the program
//! supplies would otherwise build an engine for each stack's type, every function of the engine
//! twice, and reach the one a session opened through a table of the engine's functions.
//! [`EitherLinks`] is one stack whose value is one of the two: every link, dial, listener and wait
//! it makes is the chosen stack's, carried in an enum of the same two sides, so a session never
//! mixes the two and a call on it is one match, resolved when the build is made.

use alloc::boxed::Box;

use wz_session_core::group_locator::GroupLocator;
use wz_session_core::link::{LostCause, RxFrame};

use crate::group_transport::GroupTransport;
use crate::link_cells::{CellRc, CountKind};
use crate::session_drive::{
    LinkListener, LinkOpenError, LinkWait, LinkWaits, Locator, OpenedLink, PendingDial,
    SessionDatagramLink, SessionLinks, StackWake, WaitOn,
};

/// One of two network stacks, the one a session opens over: every link it opens is that stack's.
pub enum EitherLinks<A, B> {
    /// The first stack.
    Left(A),
    /// The second stack.
    Right(B),
}

/// A link of [`EitherLinks`]: the pump of the stack that opened it.
pub enum EitherPump<P, Q> {
    /// A link the first stack opened.
    Left(P),
    /// A link the second stack opened.
    Right(Q),
}

/// A dial of [`EitherLinks`] under way: the dial of the stack that began it.
pub enum EitherDial<D, E> {
    /// A dial the first stack began.
    Left(D),
    /// A dial the second stack began.
    Right(E),
}

/// The waits of [`EitherLinks`]: the chosen stack's, which every handle its links name is one of.
#[derive(Clone)]
pub enum EitherWaits<V, W> {
    /// The first stack's waits.
    Left(V),
    /// The second stack's waits.
    Right(W),
}

/// A listener of [`EitherLinks`]: the chosen stack's, each link it yields marked as that stack's.
enum EitherListener<P, Q, N: CountKind> {
    Left(Box<dyn LinkListener<P, N>>),
    Right(Box<dyn LinkListener<Q, N>>),
}

/// `opened`, a link of the first stack.
fn left_link<P, Q, N: CountKind>(opened: OpenedLink<P, N>) -> OpenedLink<EitherPump<P, Q>, N> {
    OpenedLink {
        sink: opened.sink,
        pump: EitherPump::Left(opened.pump),
    }
}

/// `opened`, a link of the second stack.
fn right_link<P, Q, N: CountKind>(opened: OpenedLink<Q, N>) -> OpenedLink<EitherPump<P, Q>, N> {
    OpenedLink {
        sink: opened.sink,
        pump: EitherPump::Right(opened.pump),
    }
}

/// `$body` on whichever side `$value` of the enum `$either` holds, bound to `$side`.
macro_rules! on_side {
    ($either:ident, $value:expr, $side:ident => $body:expr) => {
        match $value {
            $either::Left($side) => $body,
            $either::Right($side) => $body,
        }
    };
}

impl<P: SessionDatagramLink, Q: SessionDatagramLink> SessionDatagramLink for EitherPump<P, Q> {
    fn service(&self) {
        on_side!(EitherPump, self, link => link.service())
    }

    fn service_within(&self, max_wait_ms: u64) {
        on_side!(EitherPump, self, link => link.service_within(max_wait_ms))
    }

    fn uses_wake_budget(&self) -> bool {
        on_side!(EitherPump, self, link => link.uses_wake_budget())
    }

    fn try_recv(&self) -> Option<RxFrame> {
        on_side!(EitherPump, self, link => link.try_recv())
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        on_side!(EitherPump, self, link => link.recv_with(f))
    }

    fn lost(&self) -> Option<LostCause> {
        on_side!(EitherPump, self, link => link.lost())
    }

    fn take_rx_dropped(&self) -> usize {
        on_side!(EitherPump, self, link => link.take_rx_dropped())
    }

    fn holds_input(&self) -> bool {
        on_side!(EitherPump, self, link => link.holds_input())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        on_side!(EitherPump, self, link => link.waits_for_buffer())
    }

    fn owes_write(&self) -> bool {
        on_side!(EitherPump, self, link => link.owes_write())
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        on_side!(EitherPump, self, link => link.write_owed_now())
    }

    fn takes_input(&self) -> bool {
        on_side!(EitherPump, self, link => link.takes_input())
    }

    fn keeps_input(&self) -> bool {
        on_side!(EitherPump, self, link => link.keeps_input())
    }

    fn keep(&self) {
        on_side!(EitherPump, self, link => link.keep())
    }

    fn lends_until_next_receive(&self) -> bool {
        on_side!(EitherPump, self, link => link.lends_until_next_receive())
    }

    fn input_wait(&self) -> Option<WaitOn> {
        on_side!(EitherPump, self, link => link.input_wait())
    }

    fn room_wait(&self) -> Option<WaitOn> {
        on_side!(EitherPump, self, link => link.room_wait())
    }
}

impl<P, Q, N: CountKind, D: PendingDial<P, N>, E: PendingDial<Q, N>>
    PendingDial<EitherPump<P, Q>, N> for EitherDial<D, E>
{
    fn poll(&mut self) -> Option<Result<OpenedLink<EitherPump<P, Q>, N>, LinkOpenError>> {
        match self {
            Self::Left(dial) => dial.poll().map(|made| made.map(left_link)),
            Self::Right(dial) => dial.poll().map(|made| made.map(right_link)),
        }
    }
}

/// A link made at once is a dial of the stack that made it.
impl<P, Q, N: CountKind, D: From<OpenedLink<P, N>>, E: From<OpenedLink<Q, N>>>
    From<OpenedLink<EitherPump<P, Q>, N>> for EitherDial<D, E>
{
    fn from(opened: OpenedLink<EitherPump<P, Q>, N>) -> Self {
        let OpenedLink { sink, pump } = opened;
        match pump {
            EitherPump::Left(pump) => Self::Left(D::from(OpenedLink { sink, pump })),
            EitherPump::Right(pump) => Self::Right(E::from(OpenedLink { sink, pump })),
        }
    }
}

impl<V: LinkWaits, W: LinkWaits> LinkWaits for EitherWaits<V, W> {
    fn wait(&self, on: &[LinkWait], timeout_ms: u32) {
        on_side!(EitherWaits, self, waits => waits.wait(on, timeout_ms))
    }

    fn wait_ready(&self, on: &mut [LinkWait], timeout_ms: u32) -> usize {
        on_side!(EitherWaits, self, waits => waits.wait_ready(on, timeout_ms))
    }

    fn wait_room(&self, on: WaitOn, timeout_us: u64) -> bool {
        on_side!(EitherWaits, self, waits => waits.wait_room(on, timeout_us))
    }

    fn wake(&self) -> Option<StackWake> {
        on_side!(EitherWaits, self, waits => waits.wake())
    }
}

impl<P, Q, N: CountKind> LinkListener<EitherPump<P, Q>, N> for EitherListener<P, Q, N> {
    fn local(&self) -> Locator {
        on_side!(EitherListener, self, listener => listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<EitherPump<P, Q>, N>>, LinkOpenError> {
        match self {
            Self::Left(listener) => listener.accept().map(|taken| taken.map(left_link)),
            Self::Right(listener) => listener.accept().map(|taken| taken.map(right_link)),
        }
    }

    fn input_wait(&self) -> Option<WaitOn> {
        on_side!(EitherListener, self, listener => listener.input_wait())
    }

    fn asked_when_ready(&self) -> bool {
        on_side!(EitherListener, self, listener => listener.asked_when_ready())
    }
}

/// Either side serves the sessions whose handles are counted as `N` counts them, when both do.
impl<N: CountKind, A: SessionLinks<N>, B: SessionLinks<N>> SessionLinks<N> for EitherLinks<A, B> {
    type Pump = EitherPump<A::Pump, B::Pump>;

    type Dial = EitherDial<A::Dial, B::Dial>;

    // A constant of the type and not of the value: a reader of IPv6 text is linked when either
    // stack may open to an IPv6 end, and the chosen stack refuses a family it does not carry.
    const IPV6: bool = A::IPV6 || B::IPV6;

    // A name is resolved by the chosen stack, so either may answer it; the chosen one that has no
    // resolver answers none.
    const RESOLVES: bool = A::RESOLVES || B::RESOLVES;

    // A cell of either stack's holds a link of the one chosen; the chosen value answers its own
    // (`link_cell_bytes`), so a session's cells are laid out for it alone.
    const LINK_CELL_BYTES: usize =
        crate::link_cells::larger_cell(A::LINK_CELL_BYTES, B::LINK_CELL_BYTES);

    fn resolve(
        &self,
        name: &crate::locator_text::NamedHost<'_>,
        found: &mut [core::net::SocketAddr],
    ) -> usize {
        on_side!(EitherLinks, self, links => links.resolve(name, found))
    }

    type Waits = EitherWaits<A::Waits, B::Waits>;

    fn waits(&self) -> Self::Waits {
        match self {
            Self::Left(links) => EitherWaits::Left(links.waits()),
            Self::Right(links) => EitherWaits::Right(links.waits()),
        }
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump, N>, LinkOpenError> {
        match self {
            Self::Left(links) => links.open_acceptor(port).map(left_link),
            Self::Right(links) => links.open_acceptor(port).map(right_link),
        }
    }

    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump, N>, LinkOpenError> {
        match self {
            Self::Left(links) => links.open_initiator(to).map(left_link),
            Self::Right(links) => links.open_initiator(to).map(right_link),
        }
    }

    fn lend_buffers(&mut self, tables: N::Buffers) {
        on_side!(EitherLinks, self, links => links.lend_buffers(tables))
    }

    fn link_cell_bytes(&self) -> usize {
        on_side!(EitherLinks, self, links => links.link_cell_bytes())
    }

    fn lend_cells(&mut self, cells: N::Cells) {
        on_side!(EitherLinks, self, links => links.lend_cells(cells))
    }

    #[cfg(feature = "udp-listen")]
    fn lend_port_rows(
        &mut self,
        rows: crate::udp_link::PortRows<wz_session_core::bounded::Lent, N::Flag>,
        slots: Option<wz_session_core::byte_cells::LentByteCells<N::Flag>>,
    ) -> Result<(), usize> {
        on_side!(EitherLinks, self, links => links.lend_port_rows(rows, slots))
    }

    fn lend_group_rx(&mut self, buffers: wz_session_core::byte_cells::LentByteCells) {
        on_side!(EitherLinks, self, links => links.lend_group_rx(buffers))
    }

    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        match self {
            Self::Left(links) => links.begin_initiator(to).map(EitherDial::Left),
            Self::Right(links) => links.begin_initiator(to).map(EitherDial::Right),
        }
    }

    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<Self::Pump, N>>, LinkOpenError> {
        let listener = match self {
            Self::Left(links) => EitherListener::Left(links.open_listener(at)?),
            Self::Right(links) => EitherListener::Right(links.open_listener(at)?),
        };
        Ok(Box::new(listener))
    }

    fn open_group(
        &self,
        endpoint: &str,
        group: &GroupLocator,
    ) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        on_side!(EitherLinks, self, links => links.open_group(endpoint, group))
    }

    // Each side shares its pump as its own stack does, so a stack whose pump is already a shared
    // handle hands that handle back and its link stays behind one pointer.
    fn share_pump(pump: Self::Pump) -> Option<CellRc<dyn SessionDatagramLink, N>> {
        match pump {
            EitherPump::Left(pump) => A::share_pump(pump),
            EitherPump::Right(pump) => B::share_pump(pump),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use wz_session_core::link::{BoxedLinkDriver, LinkSendOutcome};
    use wz_session_core::reliability::Reliability;

    use crate::link_cells::heap_sink;
    use crate::session_drive::Dialled;

    const AT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 7447);
    const LEFT: u8 = 1;
    const RIGHT: u8 = 2;

    /// A sink that takes everything.
    struct Null;
    impl BoxedLinkDriver for Null {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    /// A link that has nothing to read and holds input exactly when the first stack opened it,
    /// so a test reads which stack's link it was handed through any handle on it.
    struct Tagged(u8);
    impl SessionDatagramLink for Tagged {
        fn service(&self) {}
        fn try_recv(&self) -> Option<RxFrame> {
            None
        }
        fn holds_input(&self) -> bool {
            self.0 == LEFT
        }
        fn take_rx_dropped(&self) -> usize {
            usize::from(self.0)
        }
    }

    /// What a link dropped is asked of the side that holds it, and of the link a shared handle
    /// names. Turned red by a pump or a handle that answers it itself (the trait's provided form)
    /// instead of passing the question on.
    #[test]
    fn a_pump_answers_what_the_link_of_its_side_dropped() {
        let left: EitherPump<Tagged, Tagged> = EitherPump::Left(Tagged(LEFT));
        let right: EitherPump<Tagged, Tagged> = EitherPump::Right(Tagged(RIGHT));
        assert_eq!(left.take_rx_dropped(), usize::from(LEFT));
        assert_eq!(right.take_rx_dropped(), usize::from(RIGHT));
        let shared: SharedPump = CellRc::try_boxed(Tagged(LEFT))
            .expect("the heap has room")
            .into_link();
        assert_eq!(shared.take_rx_dropped(), usize::from(LEFT));
    }

    fn opened<P>(pump: P) -> OpenedLink<P> {
        OpenedLink {
            sink: heap_sink(Null).expect("the heap has room"),
            pump,
        }
    }

    /// Waits that find room exactly when `ROOM`.
    #[derive(Clone, Copy)]
    struct Room<const ROOM: bool>;
    impl<const ROOM: bool> LinkWaits for Room<ROOM> {
        fn wait(&self, _on: &[LinkWait], _timeout_ms: u32) {}
        fn wait_room(&self, _on: WaitOn, _timeout_us: u64) -> bool {
            ROOM
        }
    }

    type SharedPump = CellRc<dyn SessionDatagramLink>;

    /// The first stack: its links are shared handles already, as the host's are; it dials
    /// `udp/` alone, takes no port and listens on nothing.
    struct Shared;
    impl SessionLinks for Shared {
        type Pump = SharedPump;
        type Dial = Dialled<SharedPump>;
        const IPV6: bool = false;
        type Waits = Room<true>;
        fn waits(&self) -> Room<true> {
            Room
        }
        fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<SharedPump>, LinkOpenError> {
            Err(LinkOpenError::AddressInUse)
        }
        fn open_initiator(&self, to: Locator) -> Result<OpenedLink<SharedPump>, LinkOpenError> {
            let Some(ip) = to.as_ip() else {
                return Err(LinkOpenError::Unsupported);
            };
            match ip.proto {
                crate::session_drive::LinkProto::Udp => Ok(opened(
                    CellRc::try_boxed(Tagged(LEFT))
                        .expect("the heap has room")
                        .into_link(),
                )),
                _ => Err(LinkOpenError::Unsupported),
            }
        }
        const LINK_CELL_BYTES: usize = 64;
        fn share_pump(pump: SharedPump) -> Option<SharedPump> {
            Some(pump)
        }
    }

    /// The second stack: its pumps are values its stack shares by the provided form; it refuses
    /// every dial, takes any port and listens with [`OneLink`].
    struct Owned<const V6: bool>;
    impl<const V6: bool> SessionLinks for Owned<V6> {
        type Pump = Tagged;
        type Dial = Dialled<Tagged>;
        const IPV6: bool = V6;
        type Waits = Room<false>;
        fn waits(&self) -> Room<false> {
            Room
        }
        fn open_acceptor(&self, _port: u16) -> Result<OpenedLink<Tagged>, LinkOpenError> {
            Ok(opened(Tagged(RIGHT)))
        }
        fn open_initiator(&self, _to: Locator) -> Result<OpenedLink<Tagged>, LinkOpenError> {
            Err(LinkOpenError::Refused)
        }
        const LINK_CELL_BYTES: usize = 128;
        fn open_listener(
            &self,
            at: Locator,
        ) -> Result<Box<dyn LinkListener<Tagged>>, LinkOpenError> {
            Ok(Box::new(OneLink(at, Cell::new(true))))
        }
    }

    /// A listener bound where it was asked, with one connection waiting.
    struct OneLink(Locator, Cell<bool>);
    impl LinkListener<Tagged> for OneLink {
        fn local(&self) -> Locator {
            self.0
        }
        fn accept(&self) -> Result<Option<OpenedLink<Tagged>>, LinkOpenError> {
            Ok(self.1.replace(false).then(|| opened(Tagged(RIGHT))))
        }
    }

    type Both = EitherLinks<Shared, Owned<true>>;

    fn left() -> Both {
        EitherLinks::Left(Shared)
    }

    fn right() -> Both {
        EitherLinks::Right(Owned)
    }

    #[test]
    fn a_dial_is_made_and_refused_by_the_chosen_stack_alone() {
        let made = left()
            .open_initiator(Locator::udp(AT))
            .expect("the first stack dials udp/");
        assert!(matches!(made.pump, EitherPump::Left(_)));
        assert!(made.pump.holds_input(), "the first stack's link answers");
        // The first stack would have dialled it: the refusal is the second's, with no fallback.
        assert!(matches!(
            right().open_initiator(Locator::udp(AT)),
            Err(LinkOpenError::Refused)
        ));
        assert!(matches!(
            left().open_initiator(Locator::tcp(AT)),
            Err(LinkOpenError::Unsupported)
        ));
    }

    #[test]
    fn a_port_is_taken_by_the_chosen_stack_alone() {
        assert!(matches!(
            left().open_acceptor(7447),
            Err(LinkOpenError::AddressInUse)
        ));
        let taken = right()
            .open_acceptor(7447)
            .expect("the second stack takes any port");
        assert!(matches!(taken.pump, EitherPump::Right(Tagged(RIGHT))));
        assert!(!taken.pump.holds_input());
    }

    #[test]
    fn a_begun_dial_answers_on_the_side_that_began_it() {
        let mut dial = left()
            .begin_initiator(Locator::udp(AT))
            .expect("the first stack dials udp/");
        assert!(matches!(dial, EitherDial::Left(_)));
        let made = dial
            .poll()
            .expect("a dial made at once answers")
            .expect("and answers its link");
        assert!(matches!(made.pump, EitherPump::Left(_)));
        assert!(dial.poll().is_none(), "a dial answers once");
        assert!(matches!(
            right().begin_initiator(Locator::udp(AT)),
            Err(LinkOpenError::Refused)
        ));
    }

    #[test]
    fn a_link_made_at_once_is_a_dial_of_its_own_stack() {
        let mut dial: <Both as SessionLinks>::Dial =
            EitherDial::from(opened(EitherPump::<SharedPump, Tagged>::Right(Tagged(
                RIGHT,
            ))));
        assert!(matches!(dial, EitherDial::Right(_)));
        let made = dial
            .poll()
            .expect("the dial answers")
            .expect("with its link");
        assert!(matches!(made.pump, EitherPump::Right(Tagged(RIGHT))));
    }

    #[test]
    fn a_pump_is_shared_as_its_own_stack_shares_it() {
        let made = left()
            .open_initiator(Locator::udp(AT))
            .expect("the first stack dials udp/");
        let EitherPump::Left(inner) = &made.pump else {
            panic!("the first stack's link");
        };
        let before = CellRc::as_ptr(inner);
        let shared = Both::share_pump(made.pump).expect("the heap has room");
        // The first stack hands its handle back: the same link, behind no second pointer.
        assert!(core::ptr::addr_eq(CellRc::as_ptr(&shared), before));
        assert!(shared.holds_input());
        let other = Both::share_pump(EitherPump::Right(Tagged(RIGHT))).expect("the heap has room");
        assert!(
            !other.holds_input(),
            "the second stack's link, shared by its own form"
        );
    }

    #[test]
    fn waits_and_cells_are_the_chosen_stacks() {
        assert!(left().waits().wait_room(WaitOn::Socket(3), 0));
        assert!(!right().waits().wait_room(WaitOn::Socket(3), 0));
        assert!(left().waits().wake().is_none());
        assert_eq!(
            [left().link_cell_bytes(), right().link_cell_bytes()],
            [64, 128]
        );
    }

    /// The type's cells are the larger of its two stacks', so a cell laid out by the type alone
    /// holds a link of either; each value still answers its chosen stack's. Turned red by a
    /// constant read off one stack only.
    #[test]
    fn the_types_cells_hold_a_link_of_either_stack() {
        assert_eq!(
            [
                <EitherLinks<Shared, Owned<true>> as SessionLinks>::LINK_CELL_BYTES,
                <EitherLinks<Owned<true>, Shared> as SessionLinks>::LINK_CELL_BYTES,
            ],
            [128, 128]
        );
    }

    #[test]
    fn ipv6_is_opened_when_either_stack_opens_it() {
        assert_eq!(
            [
                <EitherLinks<Shared, Owned<true>> as SessionLinks>::IPV6,
                <EitherLinks<Shared, Owned<false>> as SessionLinks>::IPV6,
            ],
            [true, false]
        );
    }

    #[test]
    fn a_listener_yields_the_links_of_its_own_stack() {
        let at = Locator::tcp(AT);
        let listener = right().open_listener(at).expect("the second stack listens");
        assert_eq!(listener.local(), at);
        assert!(listener.input_wait().is_none());
        let taken = listener
            .accept()
            .expect("the listener is whole")
            .expect("one connection waits");
        assert!(matches!(taken.pump, EitherPump::Right(Tagged(RIGHT))));
        assert!(matches!(listener.accept(), Ok(None)));
        assert!(matches!(
            left().open_listener(at),
            Err(LinkOpenError::Unsupported)
        ));
        let group = "udp/239.1.2.3:7447#iface=lo";
        let read = wz_session_core::group_locator::parse_group_locator(group).expect("a group");
        assert!(matches!(
            left().open_group(group, &read),
            Err(LinkOpenError::Unsupported)
        ));
    }
}
