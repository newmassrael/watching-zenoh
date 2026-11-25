// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The WebSocket links of a stack of the heap profile: the dial, which connects and sends the
//! opening request, the listener, which answers the requests of the connections it accepts, and
//! [`WsLinks`], which puts both beside the links of another stack. The opening handshake runs
//! in the buffers of the link it makes, so what the peer sent behind its head is the link's first
//! bytes, and the link is handed over the moment the handshake ends.
//!
//! zenoh's link opens with `tokio_tungstenite::connect_async` and accepts with `accept_async`
//! (`io/zenoh-links/zenoh-link-ws/src/unicast.rs` @ `let stream = match accept_async(`); an
//! accept whose handshake fails is let go and the listener goes on
//! (@ `tracing::trace!("Error when creating the WebSocket session: {e}");`), as here. Upstream
//! gives a handshake no time limit; here one not done in [`OPEN_WAIT_US`] is let go, so a peer
//! that connects and says nothing holds no buffer for good. Upstream answers one request at a
//! time and leaves the next connection queued on its port; here as many handshakes run at once as
//! the table the listener reserves when it opens has rows ([`WsLinks::new`]), and while every row
//! holds one the port is not asked for another, so the next connection waits queued on it as
//! upstream's does.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ffi::c_int;

use wz_session_core::byte_cells::{CellFlag, LentByteCells};
use wz_session_core::group_locator::GroupLocator;
use wz_session_core::ws_link::{MaskKeys, KEY_LEN, MAX_HEAD_LEN};

use super::handshake::{answer_request, client_keys, read_answer, send_request, OPEN_WAIT_US};
use super::{WsFraming, WsSource, WS_MTU};
use crate::group_transport::GroupTransport;
use crate::ip_stack::HeapLink;
use crate::link_cells::{CellRc, CountKind, OneTask};
use crate::link_storage::{heap_link_buffers, LinkBuffers, LinkTables, RxBuffer, TxBuffer};
use crate::session_drive::{
    LinkListener, LinkOpenError, Locator, OpenedLink, PendingDial, SessionDatagramLink,
    SessionLinks, WaitOn, WsLocator,
};
use crate::stream_link::{stream_ends_fit, StreamDial, StreamDriver, StreamListen, StreamSocket};
use crate::udp_link::SERVICE_WAIT_MS;

/// The receive buffer of a WebSocket link: the largest batch zenoh's link sends behind the
/// longest header a frame has.
pub const WS_RX_CAPACITY: usize = WS_MTU + MAX_HEAD_LEN;

/// How a stack opens the TCP connections its `ws/` links run over, beside the clock and the
/// entropy every stack's `ws/` links draw on ([`WsSource`]): a value the stack holds.
pub trait WsOpen: WsSource {
    /// The dial of the connections.
    type Dial: StreamDial;

    /// The dial the stack's `ws/` links connect and listen with.
    fn stream_dial(&self) -> &Self::Dial;
}

/// The stream a `ws/` link of `O` runs over.
type Stream<O> = <<O as WsOpen>::Dial as StreamDial>::Stream;

/// What every WebSocket link of a [`WsLinks`] is given besides its connection: the session's
/// tables and cells when it lent them, the slots its frames are encoded into, and whether its
/// owner waits.
struct WsShape<N: CountKind> {
    lent: Option<LinkTables<N::Flag>>,
    cells: Option<LentByteCells<N::Flag>>,
    owner_waits: bool,
    tx_slots: usize,
    tx_capacity: usize,
}

// Not derived: a derive would ask `N: Clone` and `N: Default` of a kind of count.
impl<N: CountKind> Clone for WsShape<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<N: CountKind> Copy for WsShape<N> {}

impl<N: CountKind> Default for WsShape<N> {
    fn default() -> Self {
        Self {
            lent: None,
            cells: None,
            owner_waits: false,
            tx_slots: 0,
            tx_capacity: 0,
        }
    }
}

impl<N: CountKind> WsShape<N> {
    /// The buffers of one link, claimed as every link's of the stack are.
    fn buffers(&self) -> Result<LinkBuffers<N::Flag>, LinkOpenError> {
        heap_link_buffers(
            self.lent.as_ref(),
            WS_RX_CAPACITY,
            self.tx_slots,
            self.tx_capacity,
        )
    }

    /// The link over `stream`, whose handshake left `held` bytes of its first frames at the front
    /// of `rx`, made in a cell as the stack's links are: [`LinkOpenError::Unsupported`] when the
    /// rows of the build cannot name its ends (a `ws/` text is shorter than the `tcp/` one the
    /// question is asked of), [`LinkOpenError::Exhausted`] when no cell is free.
    fn link<P: StreamSocket + 'static>(
        &self,
        stream: P,
        rx: RxBuffer<N::Flag>,
        held: usize,
        tx: TxBuffer<N::Flag>,
        framing: WsFraming,
    ) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        if !stream_ends_fit(&stream) {
            return Err(LinkOpenError::Unsupported);
        }
        let owner_waits = self.owner_waits;
        let link = CellRc::<_, N>::claim_of(self.cells.as_ref())
            .ok_or(LinkOpenError::Exhausted)?
            .made(|place| {
                let link = place.write(StreamDriver::framed(stream, rx, held, tx, framing));
                if owner_waits {
                    link.wait_by_owner();
                }
                link
            })
            .ok_or(LinkOpenError::Exhausted)?;
        Ok(OpenedLink {
            sink: link.clone().into_sink(),
            pump: link.into_link(),
        })
    }
}

/// A `ws/` dial under way: its connection being made, then its request written and the
/// server's answer read into the buffer of the link it makes.
struct WsDialing<P, F: CellFlag> {
    stream: P,
    at: WsLocator,
    rx: RxBuffer<F>,
    tx: TxBuffer<F>,
    key: [u8; KEY_LEN],
    keys: MaskKeys,
    /// The bytes of the answer read, once the request is written.
    filled: Option<usize>,
}

impl<P: StreamSocket, F: CellFlag> WsDialing<P, F> {
    /// One step of the dial, without waiting: what followed the server's head once it upgraded
    /// the connection, `None` while it has not answered.
    fn step(&mut self) -> Option<Result<usize, LinkOpenError>> {
        if self.filled.is_none() {
            match self.stream.connected() {
                Ok(false) => return None,
                Err(_) => return Some(Err(LinkOpenError::Refused)),
                Ok(true) => {}
            }
            if let Err(refused) = send_request(&self.stream, self.at.at, &self.key) {
                return Some(Err(refused));
            }
            self.filled = Some(0);
        }
        let mut filled = self.filled.unwrap_or(0);
        let read = read_answer(&self.stream, &mut self.rx, &mut filled, &self.key);
        self.filled = Some(filled);
        read
    }
}

/// A `ws/` dial ([`SessionLinks::begin_initiator`]): asked at each poll, without waiting, until
/// the server answers its request.
pub struct WsDial<O: WsOpen, N: CountKind = OneTask> {
    dialing: Option<WsDialing<Stream<O>, N::Flag>>,
    opener: O,
    shape: WsShape<N>,
}

impl<O: WsOpen, N: CountKind> PendingDial<HeapLink<N>, N> for WsDial<O, N>
where
    Stream<O>: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        let made = self.dialing.as_mut()?.step()?;
        let dialing = self.dialing.take()?;
        Some(made.and_then(|held| {
            self.shape.link(
                dialing.stream,
                dialing.rx,
                held,
                dialing.tx,
                WsFraming::client(dialing.keys),
            )
        }))
    }
}

impl<O: WsOpen, N: CountKind> WsDial<O, N>
where
    Stream<O>: 'static,
{
    /// The dial, waited out: asked again each time its connection can be written or read, until
    /// the server answers or [`OPEN_WAIT_US`] has passed on the opener's clock, which refuses it
    /// as an open worth trying later.
    fn wait(mut self) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        let deadline = self.opener.now_us().saturating_add(OPEN_WAIT_US);
        loop {
            if let Some(made) = self.poll() {
                return made;
            }
            let now = self.opener.now_us();
            let dialing = self.dialing.as_ref().ok_or(LinkOpenError::Refused)?;
            if now >= deadline {
                return Err(LinkOpenError::Refused);
            }
            let wait_ms = deadline
                .saturating_sub(now)
                .div_ceil(1_000)
                .min(u64::try_from(SERVICE_WAIT_MS).unwrap_or(u64::MAX));
            if dialing.filled.is_none() {
                dialing.stream.wait_writable(wait_ms.saturating_mul(1_000));
            } else {
                dialing
                    .stream
                    .wait_readable(c_int::try_from(wait_ms).unwrap_or(c_int::MAX));
            }
        }
    }
}

/// A dial of [`WsLinks`]: the stack's, or a WebSocket one.
pub enum WsLinksDial<D, O: WsOpen, N: CountKind = OneTask> {
    /// A dial of the stack the WebSocket links stand beside.
    Links(D),
    /// A `ws/` dial.
    Ws(WsDial<O, N>),
}

impl<D: PendingDial<HeapLink<N>, N>, O: WsOpen, N: CountKind> PendingDial<HeapLink<N>, N>
    for WsLinksDial<D, O, N>
where
    Stream<O>: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink<N>, N>, LinkOpenError>> {
        match self {
            Self::Links(dial) => dial.poll(),
            Self::Ws(dial) => dial.poll(),
        }
    }
}

/// A link made at once is the stack's: a WebSocket link is made by its handshake.
impl<D: From<OpenedLink<HeapLink<N>, N>>, O: WsOpen, N: CountKind> From<OpenedLink<HeapLink<N>, N>>
    for WsLinksDial<D, O, N>
{
    fn from(opened: OpenedLink<HeapLink<N>, N>) -> Self {
        Self::Links(D::from(opened))
    }
}

/// A connection accepted and its request not yet answered.
struct WsAccepting<P, F: CellFlag> {
    stream: P,
    rx: RxBuffer<F>,
    tx: TxBuffer<F>,
    filled: usize,
    since_us: u64,
}

impl<P: StreamSocket, F: CellFlag> WsAccepting<P, F> {
    /// One step of the server's handshake, without waiting: what followed the client's head
    /// once its request is read and answered, `None` while it has not all arrived.
    fn step(&mut self) -> Option<Result<usize, LinkOpenError>> {
        answer_request(&self.stream, &mut self.rx, &mut self.filled)
    }
}

/// The accepting end of a `ws/` port: the stream listener of the stack's dial, and the
/// connections it accepted whose requests are still to be answered, in a table of `handshakes`
/// rows reserved when it opened.
struct WsListener<O: WsOpen, N: CountKind> {
    listener: Box<dyn StreamListen<Stream = Stream<O>>>,
    opener: O,
    shape: WsShape<N>,
    /// Never longer than `handshakes`, which its capacity holds, so it never grows after the open.
    accepting: RefCell<Vec<WsAccepting<Stream<O>, N::Flag>>>,
    handshakes: usize,
}

impl<O: WsOpen, N: CountKind> WsListener<O, N> {
    /// Whether a row of the table is free for the next connection.
    fn has_room(&self) -> bool {
        self.accepting.borrow().len() < self.handshakes
    }
}

impl<O: WsOpen, N: CountKind> LinkListener<HeapLink<N>, N> for WsListener<O, N>
where
    Stream<O>: 'static,
{
    fn local(&self) -> Locator {
        Locator::ws(self.listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink<N>, N>>, LinkOpenError> {
        // A table with no row free leaves the next connection queued on the port until one is.
        let next = if self.has_room() {
            self.listener.accept()?
        } else {
            None
        };
        if let Some(stream) = next {
            let (rx, tx) = self.shape.buffers()?;
            self.accepting.borrow_mut().push(WsAccepting {
                stream,
                rx,
                tx,
                filled: 0,
                since_us: self.opener.now_us(),
            });
        }
        let now = self.opener.now_us();
        let mut accepting = self.accepting.borrow_mut();
        let mut next = 0;
        while let Some(one) = accepting.get_mut(next) {
            match one.step() {
                None if now.saturating_sub(one.since_us) < OPEN_WAIT_US => next += 1,
                // A handshake that failed or ran out of time is let go, its connection closed.
                None | Some(Err(_)) => {
                    accepting.swap_remove(next);
                }
                Some(Ok(held)) => {
                    let one = accepting.swap_remove(next);
                    drop(accepting);
                    return match self.shape.link(
                        one.stream,
                        one.rx,
                        held,
                        one.tx,
                        WsFraming::server(),
                    ) {
                        Ok(link) => Ok(Some(link)),
                        Err(LinkOpenError::Unsupported) => Ok(None),
                        Err(refused) => Err(refused),
                    };
                }
            }
        }
        Ok(None)
    }

    // A connection whose request is still to come is read at the node's own pace: the
    // listener's handle tells only of the next connection, which a table with no row free does
    // not take.
    fn input_wait(&self) -> Option<WaitOn> {
        if self.accepting.borrow().is_empty() && self.has_room() {
            self.listener.input_wait()
        } else {
            None
        }
    }
}

/// The links of the stack `S` and WebSocket links beside them, over the connections `O` opens: a
/// `ws/` locator is dialled and listened on here, any other is the stack's. WebSocket links take
/// their buffers and cells from what the session lends the stack, and are placed and waited on as
/// the stack's links of the heap profile are ([`HeapLink`]). `N` is how the sessions they serve
/// count the handles on a link, as `S`'s sessions do.
pub struct WsLinks<S, O, N: CountKind = OneTask> {
    links: S,
    opener: O,
    shape: WsShape<N>,
    handshakes: usize,
}

impl<S, O: WsOpen> WsLinks<S, O> {
    /// The links of `links`, and WebSocket links over the connections `opener` opens, whose
    /// listeners each answer as many as `handshakes` requests at once (a session's
    /// `accept_pending`), each in a row of a table a listener reserves when it opens.
    pub fn new(links: S, opener: O, handshakes: usize) -> Self {
        Self {
            links,
            opener,
            shape: WsShape::default(),
            handshakes,
        }
    }
}

impl<S, O: WsOpen, N: CountKind> WsLinks<S, O, N> {
    /// The same links, for sessions that count the handles on a link as `M` does, over `links`,
    /// the stack's links counted so: asked before a session is opened over them, which is when it
    /// lends them its cells.
    pub fn counted_by<M: CountKind, T>(self, links: T) -> WsLinks<T, O, M> {
        debug_assert!(
            self.shape.cells.is_none() && self.shape.lent.is_none(),
            "cells and buffers are lent after the links are made"
        );
        WsLinks {
            links,
            opener: self.opener,
            shape: WsShape {
                lent: None,
                cells: None,
                owner_waits: self.shape.owner_waits,
                tx_slots: self.shape.tx_slots,
                tx_capacity: self.shape.tx_capacity,
            },
            handshakes: self.handshakes,
        }
    }

    /// WebSocket links whose owner waits for their input, as the stack's links that are told so.
    #[must_use]
    pub fn waited_by_owner(mut self) -> Self {
        self.shape.owner_waits = true;
        self
    }

    /// WebSocket links that lend the session `slots` buffers of `bytes` each to encode its
    /// frames into; by default a slot holds the largest batch behind its header.
    #[must_use]
    pub fn with_tx_buffers(mut self, slots: usize, bytes: usize) -> Self {
        self.shape.tx_slots = slots;
        self.shape.tx_capacity = bytes;
        self
    }

    /// A dial of `at`: the connection begun, the link's buffers claimed and the client's key and
    /// mask keys drawn, so what the server answers is read into the link's buffer.
    fn dial_ws(&self, at: WsLocator) -> Result<WsDial<O, N>, LinkOpenError>
    where
        O: Clone,
    {
        if !<O::Dial as StreamDial>::CARRIED || (at.at.is_ipv6() && !<O::Dial as StreamDial>::IPV6)
        {
            return Err(LinkOpenError::Unsupported);
        }
        let (key, keys) = client_keys(&self.opener)?;
        let (rx, tx) = self.shape.buffers()?;
        let stream = self.opener.stream_dial().dial_started(at.at)?;
        Ok(WsDial {
            dialing: Some(WsDialing {
                stream,
                at,
                rx,
                tx,
                key,
                keys,
                filled: None,
            }),
            opener: self.opener.clone(),
            shape: self.shape,
        })
    }
}

impl<S, O, N: CountKind> SessionLinks<N> for WsLinks<S, O, N>
where
    S: SessionLinks<N, Pump = HeapLink<N>>,
    O: WsOpen + Clone + 'static,
    Stream<O>: 'static,
{
    type Pump = HeapLink<N>;

    type Dial = WsLinksDial<S::Dial, O, N>;

    const IPV6: bool = S::IPV6;

    // A name is resolved by the network the stack's IP links are opened on.
    const RESOLVES: bool = S::RESOLVES;

    // A `ws/` host is refused: its request names the address it reached
    // (`send_request`), which a dial of a name has not chosen when the request is made.
    fn begin_named(
        &self,
        name: &crate::locator_text::NamedHost<'_>,
    ) -> Result<Self::Dial, LinkOpenError> {
        match name.link() {
            crate::locator_text::NamedLink::Ws => Err(LinkOpenError::Unsupported),
            crate::locator_text::NamedLink::Ip(_) => {
                self.links.begin_named(name).map(WsLinksDial::Links)
            }
        }
    }

    type Waits = S::Waits;

    fn waits(&self) -> S::Waits {
        self.links.waits()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        self.links.open_acceptor(port)
    }

    // A WebSocket link is made by its handshake, which waits for the server: a caller that opens
    // and does not ask again (a node's dialer over an endpoint its config names) is held until
    // the server answers, as a waiting open of a serial line is.
    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<HeapLink<N>, N>, LinkOpenError> {
        match to.as_ws() {
            Some(at) => self.dial_ws(at)?.wait(),
            None => self.links.open_initiator(to),
        }
    }

    fn lend_buffers(&mut self, tables: LinkTables<N::Flag>) {
        self.shape.lent = Some(tables);
        self.links.lend_buffers(tables);
    }

    // A stack that places its links on the heap has the WebSocket links placed there too.
    fn link_cell_bytes(&self) -> usize {
        match self.links.link_cell_bytes() {
            0 => 0,
            links => links.max(CellRc::<
                StreamDriver<Stream<O>, RxBuffer<N::Flag>, TxBuffer<N::Flag>, WsFraming>,
            >::cell_bytes()),
        }
    }

    fn lend_cells(&mut self, cells: LentByteCells<N::Flag>) {
        self.shape.cells = Some(cells);
        self.links.lend_cells(cells);
    }

    #[cfg(feature = "udp-listen")]
    fn lend_port_rows(
        &mut self,
        rows: crate::udp_link::PortRows<wz_session_core::bounded::Lent, N::Flag>,
    ) -> Result<(), usize> {
        self.links.lend_port_rows(rows)
    }

    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        match to.as_ws() {
            Some(at) => self.dial_ws(at).map(WsLinksDial::Ws),
            None => self.links.begin_initiator(to).map(WsLinksDial::Links),
        }
    }

    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<HeapLink<N>, N>>, LinkOpenError> {
        let Some(at) = at.as_ws() else {
            return self.links.open_listener(at);
        };
        let listener = self.opener.stream_dial().listen(at.at)?;
        Ok(Box::new(WsListener {
            listener,
            opener: self.opener.clone(),
            shape: self.shape,
            accepting: RefCell::new(Vec::with_capacity(self.handshakes)),
            handshakes: self.handshakes,
        }))
    }

    fn open_group(
        &self,
        endpoint: &str,
        group: &GroupLocator,
    ) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        self.links.open_group(endpoint, group)
    }

    fn share_pump(pump: HeapLink<N>) -> Option<CellRc<dyn SessionDatagramLink, N>> {
        S::share_pump(pump)
    }
}

#[cfg(test)]
mod tests;
