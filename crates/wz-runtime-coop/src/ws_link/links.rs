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
//! the table the listener reserves when it opens holds ([`WsLinks::with_handshakes`]), and a
//! connection that finds it full is closed at once and counted
//! ([`WsLinks::handshakes_refused`]), as a link past `accept_pending` is.

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ffi::c_int;

use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::entropy::EntropyUnavailable;
use wz_session_core::ws_link::{
    client_key, read_request, read_response, write_request, write_response, MaskKeys, RequestRead,
    UpgradeRead, KEY_LEN, MASK_SEED_LEN, MAX_HEAD_LEN,
};

use super::{WsFraming, WS_MTU};
use crate::group_transport::GroupTransport;
use crate::ip_stack::HeapLink;
use crate::link_cells::CellRc;
use crate::link_storage::{heap_link_buffers, LinkTables, RxBuffer, RxStore, TxBuffer};
use crate::session_drive::{
    LinkListener, LinkOpenError, Locator, OpenedLink, PendingDial, SessionDatagramLink,
    SessionLinks, WaitOn, WsLocator,
};
use crate::stream_link::{stream_ends_fit, StreamDial, StreamDriver, StreamListen, StreamSocket};
use crate::udp_link::SERVICE_WAIT_MS;

/// The longest an opening handshake takes, in microseconds: the connect timeout of a zenoh-pico
/// session, which a waiting open of a serial line is held to as well.
const OPEN_WAIT_US: u64 = 10_000_000;

/// The room an opening request or answer is written in: the longest, a request to a scoped IPv6
/// end, is some two hundred bytes.
const HEAD_ROOM: usize = 256;

/// The bytes of the nonce a client's key is the base64 of.
const KEY_NONCE_LEN: usize = 16;

/// The receive buffer of a WebSocket link: the largest batch zenoh's link sends behind the
/// longest header a frame has.
pub const WS_RX_CAPACITY: usize = WS_MTU + MAX_HEAD_LEN;

/// How a stack opens the TCP connections its `ws/` links run over, keeps time and draws the
/// entropy of its clients' keys and masks: a value the stack holds.
pub trait WsOpen {
    /// The dial of the connections.
    type Dial: StreamDial;

    /// The dial the stack's `ws/` links connect and listen with.
    fn stream_dial(&self) -> &Self::Dial;

    /// The platform's monotonic clock, in microseconds: what a handshake is timed on.
    fn now_us(&self) -> u64;

    /// Fill `out` with entropy: a client's key and the seed of its mask keys.
    fn fill_entropy(&self, out: &mut [u8]) -> Result<(), EntropyUnavailable>;
}

/// The stream a `ws/` link of `O` runs over.
type Stream<O> = <<O as WsOpen>::Dial as StreamDial>::Stream;

/// What every WebSocket link of a [`WsLinks`] is given besides its connection: the session's
/// tables and cells when it lent them, the slots its frames are encoded into, and whether its
/// owner waits.
#[derive(Clone, Copy, Default)]
struct WsShape {
    lent: Option<LinkTables>,
    cells: Option<LentByteCells>,
    owner_waits: bool,
    tx_slots: usize,
    tx_capacity: usize,
}

impl WsShape {
    /// The buffers of one link, claimed as every link's of the stack are.
    fn buffers(&self) -> Result<(RxBuffer, TxBuffer), LinkOpenError> {
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
        rx: RxBuffer,
        held: usize,
        tx: TxBuffer,
        framing: WsFraming,
    ) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
        if !stream_ends_fit(&stream) {
            return Err(LinkOpenError::Unsupported);
        }
        let owner_waits = self.owner_waits;
        let link = CellRc::claim(self.cells.as_ref())
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

/// Read what `stream` has queued behind the `filled` bytes at the front of `rx` until `head`
/// finds the head of a handshake whole in them: the bytes read so far while it has not, and once
/// it has, what `head` made of it with what followed the head moved to the front of the buffer,
/// and how many bytes that is. A stream that ended or failed, a buffer the head does not fit, or
/// a head `head` refuses is `Err`.
fn read_handshake<P: StreamSocket, A>(
    stream: &P,
    rx: &mut RxBuffer,
    filled: &mut usize,
    head: impl Fn(&[u8]) -> Option<Result<(usize, A), ()>>,
) -> Option<Result<(A, usize), LinkOpenError>> {
    let Some(bytes) = rx.bytes() else {
        return Some(Err(LinkOpenError::Exhausted));
    };
    loop {
        match head(bytes.get(..*filled).unwrap_or_default()) {
            Some(Ok((head_len, answer))) => {
                bytes.copy_within(head_len..*filled, 0);
                return Some(Ok((answer, filled.saturating_sub(head_len))));
            }
            Some(Err(())) => return Some(Err(LinkOpenError::Refused)),
            None => {}
        }
        let room = bytes.get_mut(*filled..).unwrap_or_default();
        if room.is_empty() {
            return Some(Err(LinkOpenError::Refused));
        }
        match stream.try_read(room) {
            Ok(Some(0)) | Err(_) => return Some(Err(LinkOpenError::Refused)),
            Ok(None) => return None,
            Ok(Some(read)) => *filled = filled.saturating_add(read),
        }
    }
}

/// A `ws/` dial under way: its connection being made, then its request written and the
/// server's answer read into the buffer of the link it makes.
struct WsDialing<P> {
    stream: P,
    at: WsLocator,
    rx: RxBuffer,
    tx: TxBuffer,
    key: [u8; KEY_LEN],
    keys: MaskKeys,
    /// The bytes of the answer read, once the request is written.
    filled: Option<usize>,
}

impl<P: StreamSocket> WsDialing<P> {
    /// One step of the dial, without waiting: what followed the server's head once it upgraded
    /// the connection, `None` while it has not answered.
    fn step(&mut self) -> Option<Result<usize, LinkOpenError>> {
        if self.filled.is_none() {
            match self.stream.connected() {
                Ok(false) => return None,
                Err(_) => return Some(Err(LinkOpenError::Refused)),
                Ok(true) => {}
            }
            let mut request = [0u8; HEAD_ROOM];
            let Some(len) = write_request(&mut request, self.at.at, &self.key) else {
                return Some(Err(LinkOpenError::Unsupported));
            };
            if self
                .stream
                .write_all(request.get(..len).unwrap_or_default())
                .is_err()
            {
                return Some(Err(LinkOpenError::Refused));
            }
            self.filled = Some(0);
        }
        let mut filled = self.filled.unwrap_or(0);
        let key = self.key;
        let read =
            read_handshake(
                &self.stream,
                &mut self.rx,
                &mut filled,
                |held| match read_response(held, &key) {
                    UpgradeRead::Partial => None,
                    UpgradeRead::Upgraded { head_len } => Some(Ok((head_len, ()))),
                    UpgradeRead::Refused => Some(Err(())),
                },
            );
        self.filled = Some(filled);
        read.map(|made| made.map(|((), held)| held))
    }
}

/// A `ws/` dial ([`SessionLinks::begin_initiator`]): asked at each poll, without waiting, until
/// the server answers its request.
pub struct WsDial<O: WsOpen> {
    dialing: Option<WsDialing<Stream<O>>>,
    opener: O,
    shape: WsShape,
}

impl<O: WsOpen> PendingDial<HeapLink> for WsDial<O>
where
    Stream<O>: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink>, LinkOpenError>> {
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

impl<O: WsOpen> WsDial<O>
where
    Stream<O>: 'static,
{
    /// The dial, waited out: asked again each time its connection can be written or read, until
    /// the server answers or [`OPEN_WAIT_US`] has passed on the opener's clock, which refuses it
    /// as an open worth trying later.
    fn wait(mut self) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
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
pub enum WsLinksDial<D, O: WsOpen> {
    /// A dial of the stack the WebSocket links stand beside.
    Links(D),
    /// A `ws/` dial.
    Ws(WsDial<O>),
}

impl<D: PendingDial<HeapLink>, O: WsOpen> PendingDial<HeapLink> for WsLinksDial<D, O>
where
    Stream<O>: 'static,
{
    fn poll(&mut self) -> Option<Result<OpenedLink<HeapLink>, LinkOpenError>> {
        match self {
            Self::Links(dial) => dial.poll(),
            Self::Ws(dial) => dial.poll(),
        }
    }
}

/// A link made at once is the stack's: a WebSocket link is made by its handshake.
impl<D: From<OpenedLink<HeapLink>>, O: WsOpen> From<OpenedLink<HeapLink>> for WsLinksDial<D, O> {
    fn from(opened: OpenedLink<HeapLink>) -> Self {
        Self::Links(D::from(opened))
    }
}

/// A connection accepted and its request not yet answered.
struct WsAccepting<P> {
    stream: P,
    rx: RxBuffer,
    tx: TxBuffer,
    filled: usize,
    since_us: u64,
}

impl<P: StreamSocket> WsAccepting<P> {
    /// One step of the server's handshake, without waiting: what followed the client's head
    /// once its request is read and answered, `None` while it has not all arrived.
    fn step(&mut self) -> Option<Result<usize, LinkOpenError>> {
        let read =
            read_handshake(
                &self.stream,
                &mut self.rx,
                &mut self.filled,
                |held| match read_request(held) {
                    RequestRead::Partial => None,
                    RequestRead::Upgrade { head_len, accept } => Some(Ok((head_len, accept))),
                    RequestRead::Refused => Some(Err(())),
                },
            )?;
        Some(read.and_then(|(accept, held)| {
            let mut answer = [0u8; HEAD_ROOM];
            let len = write_response(&mut answer, &accept).ok_or(LinkOpenError::Unsupported)?;
            self.stream
                .write_all(answer.get(..len).unwrap_or_default())
                .map_err(|_| LinkOpenError::Refused)?;
            Ok(held)
        }))
    }
}

/// The accepting end of a `ws/` port: the stream listener of the stack's dial, and the
/// connections it accepted whose requests are still to be answered, in a table of `handshakes`
/// rows reserved when it opened.
struct WsListener<O: WsOpen> {
    listener: Box<dyn StreamListen<Stream = Stream<O>>>,
    opener: O,
    shape: WsShape,
    /// Never longer than `handshakes`, which its capacity holds, so it never grows after the open.
    accepting: RefCell<Vec<WsAccepting<Stream<O>>>>,
    handshakes: usize,
    refused: Rc<Cell<u32>>,
}

impl<O: WsOpen> LinkListener<HeapLink> for WsListener<O>
where
    Stream<O>: 'static,
{
    fn local(&self) -> Locator {
        Locator::ws(self.listener.local())
    }

    fn accept(&self) -> Result<Option<OpenedLink<HeapLink>>, LinkOpenError> {
        if let Some(stream) = self.listener.accept()? {
            if self.accepting.borrow().len() < self.handshakes {
                let (rx, tx) = self.shape.buffers()?;
                self.accepting.borrow_mut().push(WsAccepting {
                    stream,
                    rx,
                    tx,
                    filled: 0,
                    since_us: self.opener.now_us(),
                });
            } else {
                // The connection, dropped here, is closed unanswered: its peer learns from the
                // close that the node is full, where one left queued would wait for an answer.
                self.refused.set(self.refused.get().saturating_add(1));
            }
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
    // listener's handle tells only of the next connection.
    fn input_wait(&self) -> Option<WaitOn> {
        if self.accepting.borrow().is_empty() {
            self.listener.input_wait()
        } else {
            None
        }
    }
}

/// The links of the stack `S` and WebSocket links beside them, over the connections `O` opens: a
/// `ws/` locator is dialled and listened on here, any other is the stack's. WebSocket links take
/// their buffers and cells from what the session lends the stack, and are placed and waited on as
/// the stack's links of the heap profile are ([`HeapLink`]).
pub struct WsLinks<S, O> {
    links: S,
    opener: O,
    shape: WsShape,
    handshakes: usize,
    refused: Rc<Cell<u32>>,
}

impl<S, O: WsOpen> WsLinks<S, O> {
    /// The links of `links`, and WebSocket links over the connections `opener` opens.
    pub fn new(links: S, opener: O) -> Self {
        Self {
            links,
            opener,
            shape: WsShape::default(),
            handshakes: 1,
            refused: Rc::new(Cell::new(0)),
        }
    }

    /// WebSocket listeners that answer as many as `handshakes` requests at once, each in a row
    /// of a table a listener reserves when it opens: a session's `accept_pending`. By default
    /// one, as upstream's listener answers one at a time
    /// (`io/zenoh-links/zenoh-link-ws/src/unicast.rs` @
    /// `let stream = match accept_async(MaybeTlsStream::Plain(stream)).await {`).
    #[must_use]
    pub fn with_handshakes(mut self, handshakes: usize) -> Self {
        self.handshakes = handshakes;
        self
    }

    /// The connections the stack's WebSocket listeners closed unanswered because each row of
    /// their tables held a handshake under way.
    pub fn handshakes_refused(&self) -> u32 {
        self.refused.get()
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
    fn dial_ws(&self, at: WsLocator) -> Result<WsDial<O>, LinkOpenError>
    where
        O: Clone,
    {
        if !<O::Dial as StreamDial>::CARRIED || (at.at.is_ipv6() && !<O::Dial as StreamDial>::IPV6)
        {
            return Err(LinkOpenError::Unsupported);
        }
        let mut seed = [0u8; KEY_NONCE_LEN + MASK_SEED_LEN];
        self.opener
            .fill_entropy(&mut seed)
            .map_err(|_| LinkOpenError::Refused)?;
        let (nonce, mask_seed) = seed.split_at(KEY_NONCE_LEN);
        let (Ok(nonce), Ok(mask_seed)) = (
            <&[u8; KEY_NONCE_LEN]>::try_from(nonce),
            <&[u8; MASK_SEED_LEN]>::try_from(mask_seed),
        ) else {
            return Err(LinkOpenError::Refused);
        };
        let (rx, tx) = self.shape.buffers()?;
        let stream = self.opener.stream_dial().dial_started(at.at)?;
        Ok(WsDial {
            dialing: Some(WsDialing {
                stream,
                at,
                rx,
                tx,
                key: client_key(nonce),
                keys: MaskKeys::seeded(mask_seed),
                filled: None,
            }),
            opener: self.opener.clone(),
            shape: self.shape,
        })
    }
}

impl<S, O> SessionLinks for WsLinks<S, O>
where
    S: SessionLinks<Pump = HeapLink>,
    O: WsOpen + Clone + 'static,
    Stream<O>: 'static,
{
    type Pump = HeapLink;

    type Dial = WsLinksDial<S::Dial, O>;

    const IPV6: bool = S::IPV6;

    type Waits = S::Waits;

    fn waits(&self) -> S::Waits {
        self.links.waits()
    }

    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
        self.links.open_acceptor(port)
    }

    // A WebSocket link is made by its handshake, which waits for the server: a caller that opens
    // and does not ask again (a node's dialer over an endpoint its config names) is held until
    // the server answers, as a waiting open of a serial line is.
    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<HeapLink>, LinkOpenError> {
        match to.as_ws() {
            Some(at) => self.dial_ws(at)?.wait(),
            None => self.links.open_initiator(to),
        }
    }

    fn lend_buffers(&mut self, tables: LinkTables) {
        self.shape.lent = Some(tables);
        self.links.lend_buffers(tables);
    }

    // A stack that places its links on the heap has the WebSocket links placed there too.
    fn link_cell_bytes(&self) -> usize {
        match self.links.link_cell_bytes() {
            0 => 0,
            links => links.max(CellRc::<
                StreamDriver<Stream<O>, RxBuffer, TxBuffer, WsFraming>,
            >::cell_bytes()),
        }
    }

    fn lend_cells(&mut self, cells: LentByteCells) {
        self.shape.cells = Some(cells);
        self.links.lend_cells(cells);
    }

    #[cfg(feature = "udp-listen")]
    fn lend_port_rows(&mut self, rows: crate::udp_link::PortRows) {
        self.links.lend_port_rows(rows);
    }

    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        match to.as_ws() {
            Some(at) => self.dial_ws(at).map(WsLinksDial::Ws),
            None => self.links.begin_initiator(to).map(WsLinksDial::Links),
        }
    }

    fn open_listener(&self, at: Locator) -> Result<Box<dyn LinkListener<HeapLink>>, LinkOpenError> {
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
            refused: Rc::clone(&self.refused),
        }))
    }

    fn open_group(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, LinkOpenError> {
        self.links.open_group(endpoint)
    }

    fn share_pump(pump: HeapLink) -> CellRc<dyn SessionDatagramLink> {
        S::share_pump(pump)
    }
}

#[cfg(test)]
mod tests;
